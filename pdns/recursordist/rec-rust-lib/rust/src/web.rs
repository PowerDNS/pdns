/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
TODO
- Table based routing?
- Ripping out yahttp stuff, providing some basic classes only. ATM we do use a few yahttp include files (but no .cc)
- Some classes (NetmaskGroup, ComboAddress) need a UniquePtr Wrapper to keep them opaque (iputils
  cannot be included without big headaches in bridge.hh at the moment). We could separate
  NetmaskGroup, but I expect ComboAddress to not work as it is union.
- Avoid unsafe? Can it be done?
*/

use std::net::SocketAddr;

use base64::prelude::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::task::JoinSet;

use crate::misc::rustmisc;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type MyResult<T> = std::result::Result<T, GenericError>;
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

static NOTFOUND: &[u8] = b"Not Found";

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

type Func = fn(&rustweb::Request, &mut rustweb::Response) -> Result<(), cxx::Exception>;

fn compare_authorization(ctx: &Context, reqheaders: &header::HeaderMap) -> bool {
    let mut auth_ok = false;
    if !ctx.password_ch.is_null() {
        if let Some(authorization) = reqheaders.get("authorization") {
            let mut lcase = authorization.as_bytes().to_owned();
            lcase.make_ascii_lowercase();
            if lcase.starts_with(b"basic ") {
                let cookie = &authorization.as_bytes()[6..];
                if let Ok(plain) = BASE64_STANDARD.decode(cookie) {
                    let mut split = plain.split(|i| *i == b':');
                    if split.next().is_some() {
                        if let Some(split) = split.next() {
                            cxx::let_cxx_string!(s = &split);
                            auth_ok = ctx.password_ch.as_ref().unwrap().matches(&s);
                        }
                    }
                }
            }
        }
    } else {
        auth_ok = true;
    }
    auth_ok
}

fn unauthorized(response: &mut rustweb::Response, headers: &mut header::HeaderMap, auth: &str) {
    let status = StatusCode::UNAUTHORIZED;
    response.status = status.as_u16();
    let val = format!("{} realm=\"PowerDNS\"", auth);
    headers.insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&val).unwrap(),
    );
    response.body = status.canonical_reason().unwrap().as_bytes().to_vec();
}

fn nonapi_wrapper(
    ctx: &Context,
    handler: Func,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
    reqheaders: &header::HeaderMap,
    headers: &mut header::HeaderMap,
) {
    let auth_ok = compare_authorization(ctx, reqheaders);
    if !auth_ok {
        rustmisc::log(
            request.logger,
            rustweb::Priority::Debug,
            "Authentication failed",
            &vec![rustmisc::KeyValue {
                key: "urlpath".to_string(),
                value: request.uri.to_owned(),
            }],
        );
        unauthorized(response, headers, "Basic");
        return;
    }
    match handler(request, response) {
        Ok(_) => {}
        Err(_) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY; // 422
            response.status = status.as_u16();
            response.body = status.canonical_reason().unwrap().as_bytes().to_vec();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn file_wrapper(
    ctx: &Context,
    handler: FileFunc,
    method: &Method,
    path: &str,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
    reqheaders: &header::HeaderMap,
    headers: &mut header::HeaderMap,
) {
    let auth_ok = compare_authorization(ctx, reqheaders);
    if !auth_ok {
        rustmisc::log(
            request.logger,
            rustweb::Priority::Debug,
            "Authentication failed",
            &vec![rustmisc::KeyValue {
                key: "urlpath".to_string(),
                value: request.uri.to_owned(),
            }],
        );
        unauthorized(response, headers, "Basic");
        return;
    }
    handler(method, path, request, response);
}

#[allow(clippy::too_many_arguments)]
fn api_wrapper(
    logger: &cxx::SharedPtr<rustweb::Logger>,
    ctx: &Context,
    handler: Func,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
    reqheaders: &header::HeaderMap,
    headers: &mut header::HeaderMap,
    allow_password: bool,
) {
    // security headers
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    if ctx.api_ch.is_null() {
        rustmisc::log(
            logger,
            rustweb::Priority::Error,
            "Authentication failed, API Key missing in config",
            &vec![rustmisc::KeyValue {
                key: "urlpath".to_string(),
                value: request.uri.to_owned(),
            }],
        );
        unauthorized(response, headers, "X-API-Key");
        return;
    }

    // XXX AUDIT!
    let mut auth_ok = false;

    if let Some(api) = reqheaders.get("x-api-key") {
        cxx::let_cxx_string!(s = &api.as_bytes());
        auth_ok = ctx.api_ch.as_ref().unwrap().matches(&s);
    }
    if !auth_ok {
        for kv in &request.vars {
            cxx::let_cxx_string!(s = &kv.value);
            if kv.key == "api-key" && ctx.api_ch.as_ref().unwrap().matches(&s) {
                auth_ok = true;
                break;
            }
        }
    }
    if !auth_ok && allow_password {
        auth_ok = compare_authorization(ctx, reqheaders);
        if !auth_ok {
            rustmisc::log(
                logger,
                rustweb::Priority::Debug,
                "Authentication failed",
                &vec![rustmisc::KeyValue {
                    key: "urlpath".to_string(),
                    value: request.uri.to_owned(),
                }],
            );
            unauthorized(response, headers, "Basic");
            return;
        }
    }
    if !auth_ok {
        rustmisc::log(
            logger,
            rustweb::Priority::Error,
            "Authentication failed",
            &vec![rustmisc::KeyValue {
                key: "urlpath".to_string(),
                value: request.uri.to_owned(),
            }],
        );
        unauthorized(response, headers, "X-API-Key");
        return;
    }
    response.status = StatusCode::OK.as_u16(); // 200;

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("deny"),
    );
    headers.insert(
        header::HeaderName::from_static("x-permitted-cross-domain-policies"),
        header::HeaderValue::from_static("none"),
    );
    headers.insert(
        header::X_XSS_PROTECTION,
        header::HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'"),
    );

    // This calls into C++
    match handler(request, response) {
        Ok(_) => {}
        Err(_) => {
            let status = StatusCode::UNPROCESSABLE_ENTITY; // 422
            response.status = status.as_u16();
            response.body = status.canonical_reason().unwrap().as_bytes().to_vec();
        }
    }
}

// Data used by requests handlers, if you add a r/w variable, make sure it's safe for concurrent access!
struct Context {
    password_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    api_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    acl: cxx::UniquePtr<rustmisc::NetmaskGroup>,
    logger: cxx::SharedPtr<rustmisc::Logger>,
    loglevel: rustmisc::LogLevel,
}

// Serve a file
fn file(
    method: &Method,
    path: &str,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
) {
    // This calls into C++
    if rustweb::serveStuff(request, response).is_err() {
        // Return 404 not found response.
        response.status = StatusCode::NOT_FOUND.as_u16();
        response.body = NOTFOUND.to_vec();
        rustmisc::log(
            request.logger,
            rustweb::Priority::Debug,
            "Not found",
            &vec![
                rustmisc::KeyValue {
                    key: "method".to_string(),
                    value: method.to_string(),
                },
                rustmisc::KeyValue {
                    key: "path".to_string(),
                    value: path.to_string(),
                },
            ],
        );
    }
}

type FileFunc = fn(
    method: &Method,
    path: &str,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
);

// Match a request and return the function that implements it, this should probably be table based.
fn matcher(
    method: &Method,
    path: &str,
    apifunc: &mut Option<Func>,
    rawfunc: &mut Option<Func>,
    filefunc: &mut Option<FileFunc>,
    allow_password: &mut bool,
    request: &mut rustweb::Request,
) {
    let path: Vec<_> = path.split('/').skip(1).collect();
    match (method, &*path) {
        (&Method::GET, ["jsonstat"]) => {
            *allow_password = true;
            *apifunc = Some(rustweb::jsonstat);
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "cache", "flush"]) => {
            *apifunc = Some(rustweb::apiServerCacheFlush)
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "config", "allow-from"]) => {
            *apifunc = Some(rustweb::apiServerConfigAllowFromPUT)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "config", "allow-from"]) => {
            *apifunc = Some(rustweb::apiServerConfigAllowFromGET)
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "config", "allow-notify-from"]) => {
            *apifunc = Some(rustweb::apiServerConfigAllowNotifyFromPUT)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "config", "allow-notify-from"]) => {
            *apifunc = Some(rustweb::apiServerConfigAllowNotifyFromGET)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "config"]) => {
            *apifunc = Some(rustweb::apiServerConfig)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "rpzstatistics"]) => {
            *apifunc = Some(rustweb::apiServerRPZStats)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "search-data"]) => {
            *apifunc = Some(rustweb::apiServerSearchData)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue {
                key: String::from("id"),
                value: String::from(*id),
            });
            *apifunc = Some(rustweb::apiServerZoneDetailGET);
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue {
                key: String::from("id"),
                value: String::from(*id),
            });
            *apifunc = Some(rustweb::apiServerZoneDetailPUT);
        }
        (&Method::DELETE, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue {
                key: String::from("id"),
                value: String::from(*id),
            });
            *apifunc = Some(rustweb::apiServerZoneDetailDELETE);
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "statistics"]) => {
            *allow_password = true;
            *apifunc = Some(rustweb::apiServerStatistics);
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "zones"]) => {
            *apifunc = Some(rustweb::apiServerZonesGET)
        }
        (&Method::POST, ["api", "v1", "servers", "localhost", "zones"]) => {
            *apifunc = Some(rustweb::apiServerZonesPOST)
        }
        (&Method::GET, ["api", "v1", "servers", "localhost"]) => {
            *allow_password = true;
            *apifunc = Some(rustweb::apiServerDetail);
        }
        (&Method::GET, ["api", "v1", "servers"]) => *apifunc = Some(rustweb::apiServer),
        (&Method::GET, ["api", "v1"]) => *apifunc = Some(rustweb::apiDiscoveryV1),
        (&Method::GET, ["api"]) => *apifunc = Some(rustweb::apiDiscovery),
        (&Method::GET, ["metrics"]) => *rawfunc = Some(rustweb::prometheusMetrics),
        _ => *filefunc = Some(file),
    }
}

// This constructs the answer to an OPTIONS query
fn collect_options(
    path: &str,
    response: &mut rustweb::Response,
    my_logger: &cxx::SharedPtr<rustmisc::Logger>,
) {
    let mut methods = vec![];
    for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
        let mut apifunc: Option<Func> = None;
        let mut rawfunc: Option<_> = None;
        let mut filefunc: Option<_> = None;
        let mut allow_password = false;
        let mut request = rustweb::Request {
            body: vec![],
            uri: String::from(""),
            vars: vec![],
            parameters: vec![],
            logger: my_logger,
        };
        matcher(
            &method,
            path,
            &mut apifunc,
            &mut rawfunc,
            &mut filefunc,
            &mut allow_password,
            &mut request,
        );
        if apifunc.is_some() || rawfunc.is_some()
        /* || filefunc.is_some() */
        {
            methods.push(method.to_string());
        }
    }
    if methods.is_empty() {
        response.status = 404;
        return;
    }
    response.status = 200;
    methods.push(Method::OPTIONS.to_string());
    response.headers.push(rustweb::KeyValue {
        key: String::from("access-control-allow-origin"),
        value: String::from("*"),
    });
    response.headers.push(rustweb::KeyValue {
        key: String::from("access-control-allow-headers"),
        value: String::from("Content-Type, X-API-Key"),
    });
    response.headers.push(rustweb::KeyValue {
        key: String::from("access-control-max-age"),
        value: String::from("3600"),
    });
    response.headers.push(rustweb::KeyValue {
        key: String::from("access-control-allow-methods"),
        value: methods.join(", "),
    });
    response.headers.push(rustweb::KeyValue {
        key: String::from("content-type"),
        value: String::from("text/plain"),
    });
}

fn log_request(loglevel: rustmisc::LogLevel, request: &rustweb::Request, remote: SocketAddr) {
    if loglevel != rustmisc::LogLevel::Detailed {
        return;
    }
    let body = std::str::from_utf8(&request.body).unwrap_or("error: body is not utf8");
    let mut vec = vec![
        rustmisc::KeyValue {
            key: "remote".to_string(),
            value: remote.to_string(),
        },
        rustmisc::KeyValue {
            key: "body".to_string(),
            value: body.to_string(),
        },
    ];
    let mut first = true;
    let mut str = "".to_string();
    for var in &request.vars {
        if !first {
            str.push(' ');
        }
        first = false;
        let snippet = var.key.to_owned() + "=" + &var.value;
        str.push_str(&snippet);
    }
    vec.push(rustmisc::KeyValue {
        key: "getVars".to_string(),
        value: str.to_string(),
    });
    rustmisc::log(
        request.logger,
        rustmisc::Priority::Info,
        "Request details",
        &vec,
    );
}

fn log_response(
    loglevel: rustmisc::LogLevel,
    logger: &cxx::SharedPtr<rustmisc::Logger>,
    response: &rustweb::Response,
    remote: SocketAddr,
) {
    if loglevel != rustmisc::LogLevel::Detailed {
        return;
    }
    let body = std::str::from_utf8(&response.body).unwrap_or("error: body is not utf8");
    let mut vec = vec![
        rustmisc::KeyValue {
            key: "remote".to_string(),
            value: remote.to_string(),
        },
        rustmisc::KeyValue {
            key: "body".to_string(),
            value: body.to_string(),
        },
    ];
    let mut first = true;
    let mut str = "".to_string();
    for var in &response.headers {
        if !first {
            str.push(' ');
        }
        first = false;
        let snippet = var.key.to_owned() + "=" + &var.value;
        str.push_str(&snippet);
    }
    vec.push(rustmisc::KeyValue {
        key: "headers".to_string(),
        value: str.to_string(),
    });
    rustmisc::log(logger, rustmisc::Priority::Info, "Response details", &vec);
}

// Main entry point after a request arrived
async fn process_request(
    rust_request: Request<IncomingBody>,
    ctx: Arc<Context>,
    remote: SocketAddr,
) -> MyResult<Response<BoxBody>> {
    let unique = rustmisc::getUUID();
    let my_logger = rustmisc::withValue(&ctx.logger, "uniqueid", &unique);

    // Convert  query part of URI into vars table
    let mut vars: Vec<rustweb::KeyValue> = vec![];
    if let Some(query) = rust_request.uri().query() {
        for (k, v) in form_urlencoded::parse(query.as_bytes()) {
            if k == "_" {
                // jQuery cache buster
                continue;
            }
            let kv = rustweb::KeyValue {
                key: k.to_string(),
                value: v.to_string(),
            };
            vars.push(kv);
        }
    }

    // Fill request and response structs wih default values.
    let mut request = rustweb::Request {
        body: vec![],
        uri: rust_request.uri().to_string(),
        vars,
        parameters: vec![],
        logger: &my_logger,
    };

    log_request(ctx.loglevel, &request, remote);

    let mut response = rustweb::Response {
        status: 0,
        body: vec![],
        headers: vec![],
    };
    let mut apifunc: Option<Func> = None;
    let mut rawfunc: Option<_> = None;
    let mut filefunc: Option<_> = None;
    let method = rust_request.method().to_owned();
    let mut allow_password = false;
    let mut rust_response = Response::builder();

    let path = rust_request.uri().path().to_owned();
    let version = rust_request.version().to_owned();

    if method == Method::OPTIONS {
        collect_options(&path, &mut response, &my_logger);
    } else {
        // Find the right function implementing what the request wants
        let mut matchmethod = method.clone();
        if method == Method::HEAD {
            matchmethod = Method::GET;
        }
        matcher(
            &matchmethod,
            &path,
            &mut apifunc,
            &mut rawfunc,
            &mut filefunc,
            &mut allow_password,
            &mut request,
        );

        if let Some(func) = apifunc {
            let reqheaders = rust_request.headers().clone();
            if rust_request.method() == Method::POST || rust_request.method() == Method::PUT {
                request.body = rust_request.collect().await?.to_bytes().to_vec();
            }
            // This calls indirectly into C++
            api_wrapper(
                &my_logger,
                &ctx,
                func,
                &request,
                &mut response,
                &reqheaders,
                rust_response.headers_mut().expect("no headers?"),
                allow_password,
            );
        } else if let Some(func) = rawfunc {
            // Non-API func
            let reqheaders = rust_request.headers().clone();
            nonapi_wrapper(
                &ctx,
                func,
                &request,
                &mut response,
                &reqheaders,
                rust_response.headers_mut().expect("no headers?"),
            );
        } else if let Some(func) = filefunc {
            // Server static file
            let reqheaders = rust_request.headers().clone();
            file_wrapper(
                &ctx,
                func,
                &method,
                rust_request.uri().path(),
                &request,
                &mut response,
                &reqheaders,
                rust_response.headers_mut().expect("no headers?"),
            );
        }
    }

    let mut len = response.body.len();
    if method == Method::HEAD {
        len = 0;
    }
    log_response(ctx.loglevel, &my_logger, &response, remote);
    // Throw away body for HEAD call
    let mut body = full(response.body);
    if method == Method::HEAD {
        body = full(vec![]);
    }

    // Construct response based on what C++ gave us
    let mut rust_response = rust_response
        .status(StatusCode::from_u16(response.status).unwrap())
        .body(body)?;
    for kv in response.headers {
        rust_response.headers_mut().insert(
            header::HeaderName::from_bytes(kv.key.as_bytes()).unwrap(),
            header::HeaderValue::from_str(kv.value.as_str()).unwrap(),
        );
    }

    rust_response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_str("close").unwrap(),
    );
    if ctx.loglevel != rustmisc::LogLevel::None {
        let version = format!("{:?}", version);
        rustmisc::log(
            &my_logger,
            rustweb::Priority::Notice,
            "Request",
            &vec![
                rustmisc::KeyValue {
                    key: "remote".to_string(),
                    value: remote.to_string(),
                },
                rustmisc::KeyValue {
                    key: "method".to_string(),
                    value: method.to_string(),
                },
                rustmisc::KeyValue {
                    key: "urlpath".to_string(),
                    value: path.to_string(),
                },
                rustmisc::KeyValue {
                    key: "HTTPVersion".to_string(),
                    value: version,
                },
                rustmisc::KeyValue {
                    key: "status".to_string(),
                    value: response.status.to_string(),
                },
                rustmisc::KeyValue {
                    key: "respsize".to_string(),
                    value: len.to_string(),
                },
            ],
        );
    }

    Ok(rust_response)
}

async fn serveweb_async(
    listener: TcpListener,
    config: crate::web::rustweb::IncomingTLS,
    ctx: Arc<Context>,
) -> MyResult<()> {
    if !config.certificate.is_empty() {
        let certs = load_certs(&config.certificate)?;
        let key = load_private_key(&config.key)?;
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec(), b"http/1.0".to_vec()]; // b"h2".to_vec()
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        // We start a loop to continuously accept incoming connections
        loop {
            let ctx = Arc::clone(&ctx);
            let (stream, _) = listener.accept().await?;

            let address;
            match stream.peer_addr() {
                Ok(addr) => {
                    address = addr;
                    let combo = rustmisc::comboaddress(&address.to_string());
                    if !rustmisc::matches(&ctx.acl, &combo) {
                        rustmisc::log(
                            &ctx.logger,
                            rustweb::Priority::Debug,
                            "No ACL match",
                            &vec![rustmisc::KeyValue {
                                key: "address".to_string(),
                                value: address.to_string(),
                            }],
                        );
                        continue;
                    }
                }
                Err(err) => {
                    rustmisc::error(
                        &ctx.logger,
                        rustweb::Priority::Error,
                        &err.to_string(),
                        "Can't get peer address",
                        &vec![],
                    );
                    continue; // If we can't determine the peer address, don't
                }
            }
            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let tls_acceptor = tls_acceptor.clone();
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(err) => {
                    rustmisc::error(
                        &ctx.logger,
                        rustweb::Priority::Notice,
                        &err.to_string(),
                        "Failed to perform TLS handshake",
                        &vec![],
                    );
                    continue;
                }
            };
            let io = TokioIo::new(tls_stream);
            let my_logger = rustmisc::withValue(&ctx.logger, "tls", "true");
            let fut = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| {
                    let ctx = Arc::clone(&ctx);
                    process_request(req, ctx, address)
                }),
            );

            // Spawn a tokio task to serve the request
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `process_request` service
                if let Err(err) = fut.await {
                    rustmisc::error(
                        &my_logger,
                        rustweb::Priority::Notice,
                        &err.to_string(),
                        "Error serving web connection",
                        &vec![],
                    );
                }
            });
        }
    } else {
        // We start a loop to continuously accept incoming connections
        loop {
            let ctx = Arc::clone(&ctx);
            let (stream, _) = listener.accept().await?;

            let address;
            match stream.peer_addr() {
                Ok(addr) => {
                    address = addr;
                    let combo = rustmisc::comboaddress(&address.to_string());
                    if !rustmisc::matches(&ctx.acl, &combo) {
                        rustmisc::log(
                            &ctx.logger,
                            rustweb::Priority::Debug,
                            "No ACL match",
                            &vec![rustmisc::KeyValue {
                                key: "address".to_string(),
                                value: address.to_string(),
                            }],
                        );
                        continue;
                    }
                }
                Err(err) => {
                    rustmisc::error(
                        &ctx.logger,
                        rustmisc::Priority::Error,
                        &err.to_string(),
                        "Can't get peer address",
                        &vec![],
                    );
                    continue; // If we can't determine the peer address, don't
                }
            }
            let io = TokioIo::new(stream);
            let my_logger = rustmisc::withValue(&ctx.logger, "tls", "false");
            let fut = http1::Builder::new().serve_connection(
                io,
                service_fn(move |req| {
                    let ctx = Arc::clone(&ctx);
                    process_request(req, ctx, address)
                }),
            );

            // Spawn a tokio task to serve the request
            tokio::task::spawn(async move {
                // Finally, we bind the incoming connection to our `process_request` service
                if let Err(err) = fut.await {
                    rustmisc::error(
                        &my_logger,
                        rustmisc::Priority::Notice,
                        &err.to_string(),
                        "Error serving web connection",
                        &vec![],
                    );
                }
            });
        }
    }
}

pub fn serveweb(
    incoming: &Vec<rustweb::IncomingWSConfig>,
    password_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    api_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    acl: cxx::UniquePtr<rustmisc::NetmaskGroup>,
    logger: cxx::SharedPtr<rustmisc::Logger>,
    loglevel: rustmisc::LogLevel,
) -> Result<(), std::io::Error> {
    // Context, atomically reference counted
    let ctx = Arc::new(Context {
        password_ch,
        api_ch,
        acl,
        logger,
        loglevel,
    });

    // We use a single thread to handle all the requests, letting the runtime abstracts from this
    let runtime = Builder::new_current_thread()
        .worker_threads(1)
        .thread_name("rec/web")
        .enable_io()
        .build()?;

    // For each listening address we spawn a tokio handler and then a single Posix thread is created that
    // waits (forever) for all of them to complete by joining them all.
    let mut set = JoinSet::new();
    for config in incoming {
        for addr_str in &config.addresses {
            let addr = match SocketAddr::from_str(addr_str) {
                Ok(val) => val,
                Err(err) => {
                    let msg = format!("`{}' is not a IP:port combination: {}", addr_str, err);
                    return Err(std::io::Error::other(msg));
                }
            };

            let listener = runtime.block_on(async { TcpListener::bind(addr).await });
            let ctx = Arc::clone(&ctx);
            match listener {
                Ok(val) => {
                    let mut tls_enabled = false;
                    let tls = crate::web::rustweb::IncomingTLS {
                        certificate: config.tls.certificate.clone(),
                        key: config.tls.key.clone(),
                        // password: config.tls.password.clone(), not supported (yet), rusttls does not handle it
                    };
                    if !tls.certificate.is_empty() {
                        tls_enabled = true;
                    }
                    rustmisc::log(
                        &ctx.logger,
                        rustweb::Priority::Info,
                        "Web service listening",
                        &vec![
                            rustmisc::KeyValue {
                                key: "address".to_string(),
                                value: addr.to_string(),
                            },
                            rustmisc::KeyValue {
                                key: "tls".to_string(),
                                value: tls_enabled.to_string(),
                            },
                        ],
                    );
                    set.spawn_on(serveweb_async(val, tls, ctx), runtime.handle());
                }
                Err(err) => {
                    rustmisc::error(
                        &ctx.logger,
                        rustweb::Priority::Error,
                        &err.to_string(),
                        "Unable to bind to web socket",
                        &vec![rustmisc::KeyValue {
                            key: "address".to_string(),
                            value: addr.to_string(),
                        }],
                    );
                    let msg = format!("Unable to bind web socket: {}", err);
                    return Err(std::io::Error::other(msg));
                }
            }
        }
    }
    std::thread::Builder::new()
        .name(String::from("rec/rustweb"))
        .spawn(move || {
            runtime.block_on(async {
                while let Some(res) = set.join_next().await {
                    let msg = match res {
                        Ok(Err(wrapped)) => format!("{:?}", wrapped),
                        _ => format!("{:?}", res)
                    };
                    rustmisc::error(
                        &ctx.logger,
                        rustmisc::Priority::Error,
                        &msg,
                        "Rustweb thread exited",
                        &vec![],
                    );
                }
            });
        })?;
    Ok(())
}

// Load public certificate from file.
fn load_certs(filename: &str) -> std::io::Result<Vec<pki_types::CertificateDer<'static>>> {
    // Open certificate file.
    let certfile = std::fs::File::open(filename).map_err(|e| {
        std::io::Error::other(
            format!("Failed to open {}: {}", filename, e),
        )
    })?;
    let mut reader = std::io::BufReader::new(certfile);

    // Load and return certificate.
    rustls_pemfile::certs(&mut reader).collect()
}

// Load private key from file.
fn load_private_key(filename: &str) -> std::io::Result<pki_types::PrivateKeyDer<'static>> {
    // Open keyfile.
    let keyfile = std::fs::File::open(filename).map_err(|e| {
        std::io::Error::other(
            format!("Failed to open {}: {}", filename, e),
        )
    })?;
    let mut reader = std::io::BufReader::new(keyfile);

    // Load and return a single private key.
    match rustls_pemfile::private_key(&mut reader) {
        Ok(Some(pkey)) => Ok(pkey),
        Ok(None) => Err(
            std::io::Error::other(
                format!("Failed to parse private key from {}", filename),
            )),
        Err(e) => Err(e)
    }
}

// impl below needed because the classes are used in the Context, which gets passed around.
unsafe impl Send for rustweb::CredentialsHolder {}
unsafe impl Sync for rustweb::CredentialsHolder {}
unsafe impl Send for rustmisc::NetmaskGroup {}
unsafe impl Sync for rustmisc::NetmaskGroup {}
unsafe impl Send for rustmisc::Logger {}
unsafe impl Sync for rustmisc::Logger {}

#[cxx::bridge(namespace = "pdns::rust::web::rec")]
#[allow(clippy::needless_lifetimes)] // Needed to avoid clippy warning for Request
mod rustweb {
    extern "C++" {
        type CredentialsHolder;
        #[namespace = "pdns::rust::misc"]
        type NetmaskGroup = crate::misc::rustmisc::NetmaskGroup;
        #[namespace = "pdns::rust::misc"]
        type Priority = crate::misc::rustmisc::Priority;
        #[namespace = "pdns::rust::misc"]
        type LogLevel = crate::misc::rustmisc::LogLevel;
        #[namespace = "pdns::rust::misc"]
        type Logger = crate::misc::rustmisc::Logger;
    }

    pub struct IncomingTLS {
        certificate: String,
        key: String,
        // password: String, Not currently supported, as rusttls does not support that out of the box
    }

    struct IncomingWSConfig {
        addresses: Vec<String>,
        tls: IncomingTLS,
    }
    /*
     * Functions callable from C++
     */
    extern "Rust" {
        // The main entry point, This function will return, but will setup thread(s) and tokio runtime to handle requests.
        fn serveweb(
            incoming: &Vec<IncomingWSConfig>,
            pwch: UniquePtr<CredentialsHolder>,
            apikeych: UniquePtr<CredentialsHolder>,
            acl: UniquePtr<NetmaskGroup>,
            logger: SharedPtr<Logger>,
            loglevel: LogLevel,
        ) -> Result<()>;
    }

    struct KeyValue {
        key: String,
        value: String,
    }

    // Clippy does not seem to understand what cxx does and complains about needless_lifetimes
    // The warning is silenced above
    struct Request<'a> {
        body: Vec<u8>,
        uri: String,
        vars: Vec<KeyValue>,
        parameters: Vec<KeyValue>,
        logger: &'a SharedPtr<Logger>,
    }

    struct Response {
        status: u16,
        body: Vec<u8>,
        headers: Vec<KeyValue>,
    }

    /*
     * Functions callable from Rust
     */
    unsafe extern "C++" {
        include!("bridge.hh");
        fn matches(self: &CredentialsHolder, str: &CxxString) -> bool;
        fn apiDiscovery(request: &Request, response: &mut Response) -> Result<()>;
        fn apiDiscoveryV1(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServer(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerCacheFlush(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfig(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowFromGET(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowFromPUT(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowNotifyFromGET(
            request: &Request,
            response: &mut Response,
        ) -> Result<()>;
        fn apiServerConfigAllowNotifyFromPUT(
            request: &Request,
            response: &mut Response,
        ) -> Result<()>;
        fn apiServerDetail(requst: &Request, response: &mut Response) -> Result<()>;
        fn apiServerRPZStats(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerSearchData(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerStatistics(requst: &Request, response: &mut Response) -> Result<()>;
        fn apiServerZoneDetailDELETE(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerZoneDetailGET(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerZoneDetailPUT(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerZonesGET(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerZonesPOST(requst: &Request, response: &mut Response) -> Result<()>;
        fn jsonstat(request: &Request, response: &mut Response) -> Result<()>;
        fn prometheusMetrics(request: &Request, response: &mut Response) -> Result<()>;
        fn serveStuff(request: &Request, response: &mut Response) -> Result<()>;
    }
}
