/*
TODO

- Logging
- Table based routing including OPTIONS request handling
- ACLs of webserver
- ACL handling; thread local does not work, see how domains are done
- Authorization: metrics and plain files (and more?) are not subject to password auth
- Allow multipe listen addreses in settings (singlevalued right now)
- TLS?
- Code is now in settings dir. It's only possible to split the modules into separate Rust libs if we
  use shared libs (in theory, I did not try). Currently all CXX using Rust cargo's must be compiled
  as one and refer to a single static Rust runtime
- Ripping out yahttp stuff, providing some basic classees only
*/

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming as IncomingBody, header, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::task::JoinSet;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use base64::prelude::*;

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

fn compare_authorization(ctx: &Context, reqheaders: &header::HeaderMap) -> bool
{
    let mut auth_ok = false;
    if !ctx.password_ch.is_null() {
        if let Some(authorization) = reqheaders.get("authorization") {
            let mut lcase = authorization.as_bytes().to_owned();
            lcase.make_ascii_lowercase();
            if lcase.starts_with(b"basic ") {
                let cookie = &authorization.as_bytes()[6..];
                if let Ok(plain) = BASE64_STANDARD.decode(cookie) {
                    println!("plain {:?}", plain);
                    let mut split = plain.split(|i| *i == b':');
                    println!("split {:?}", split);
                    if split.next().is_some() {
                        println!("split {:?}", split);
                        if let Some(split) = split.next() {
                            println!("split {:?}", split);
                            cxx::let_cxx_string!(s = &split);
                            auth_ok = ctx.password_ch.as_ref().unwrap().matches(&s);
                            println!("OK4 {}", auth_ok);
                        }
                    }
                }
            }
        }
        println!("OK5 {}", auth_ok);
    } else {
        auth_ok = true;
    }
    auth_ok
}

fn unauthorized(response: &mut rustweb::Response, headers: &mut header::HeaderMap, auth: &str)
{
    // XXX log
    let status =  StatusCode::UNAUTHORIZED;
    response.status = status.as_u16();
    let val = format!("{} realm=\"PowerDNS\"", auth);
    headers.insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_str(&val).unwrap(),
    );
    response.body = status.canonical_reason().unwrap().as_bytes().to_vec();
}

fn api_wrapper(
    ctx: &Context,
    handler: Func,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
    reqheaders: &header::HeaderMap,
    headers: &mut header::HeaderMap,
    allow_password: bool
) {

    // security headers
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
    if ctx.api_ch.is_null() {
        unauthorized(response, headers, "X-API-Key");
        return;
    }

    // XXX AUDIT!
    let mut auth_ok = false;
    println!("OK0 {}", auth_ok);
    if let Some(api) = reqheaders.get("x-api-key") {
        cxx::let_cxx_string!(s = &api.as_bytes());
        auth_ok = ctx.api_ch.as_ref().unwrap().matches(&s);
        println!("OK1 {}", auth_ok);
    }
    if !auth_ok {
        for kv in &request.vars {
            cxx::let_cxx_string!(s = &kv.value);
            if kv.key == "x-api-key" && ctx.api_ch.as_ref().unwrap().matches(&s) {
                auth_ok = true;
                println!("OK2 {}", auth_ok);
                break;
            }
        }
    }
    println!("OK3 {}", auth_ok);
    if !auth_ok && allow_password {
        auth_ok = compare_authorization(ctx, reqheaders);
        if !auth_ok {
            unauthorized(response, headers, "Basic");
            return;
        }
    }
    if !auth_ok {
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

    match handler(request, response) {
        Ok(_) => {}
        Err(_) => {
            let status =  StatusCode::UNPROCESSABLE_ENTITY; // 422
            response.status = status.as_u16();
            response.body = status.canonical_reason().unwrap().as_bytes().to_vec();
        }
    }
}

struct Context {
    urls: Vec<String>,
    password_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    api_ch: cxx::UniquePtr<rustweb::CredentialsHolder>,
    counter: Mutex<u32>,
}

async fn hello(
    rust_request: Request<IncomingBody>,
    ctx: Arc<Context>
) -> MyResult<Response<BoxBody>> {
    {
        let mut counter = ctx.counter.lock().await;
        *counter += 1;
    }
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
    let mut request = rustweb::Request {
        body: vec![],
        uri: rust_request.uri().to_string(),
        vars,
        parameters: vec![],
    };
    let mut response = rustweb::Response {
        status: 0,
        body: vec![],
        headers: vec![],
    };
    let mut apifunc: Option<Func> = None;
    let method = rust_request.method().to_owned();
    let path: Vec<_> = rust_request.uri().path().split('/').skip(1).collect();
    let mut allow_password = false;
    match (&method, &*path) {
        (&Method::GET, ["jsonstat"]) => {
            allow_password = true;
            apifunc = Some(rustweb::jsonstat);
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "cache", "flush"]) =>
            apifunc = Some(rustweb::apiServerCacheFlush),
        (&Method::PUT, ["api", "v1", "servers", "localhost", "config", "allow-from"]) =>
            apifunc = Some(rustweb::apiServerConfigAllowFromPUT),
        (&Method::GET, ["api", "v1", "servers", "localhost", "config", "allow-from"]) =>
            apifunc = Some(rustweb::apiServerConfigAllowFromGET),
        (&Method::PUT, ["api", "v1", "servers", "localhost", "config", "allow-notify-from"]) =>
            apifunc = Some(rustweb::apiServerConfigAllowNotifyFromPUT),
        (&Method::GET, ["api", "v1", "servers", "localhost", "config", "allow-notify-from"]) =>
            apifunc = Some(rustweb::apiServerConfigAllowNotifyFromGET),
        (&Method::GET, ["api", "v1", "servers", "localhost", "config"]) =>
            apifunc = Some(rustweb::apiServerConfig),
        (&Method::GET, ["api", "v1", "servers", "localhost", "rpzstatistics"]) =>
            apifunc = Some(rustweb::apiServerRPZStats),
        (&Method::GET, ["api", "v1", "servers", "localhost", "search-data"]) =>
            apifunc = Some(rustweb::apiServerSearchData),
        (&Method::GET, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue{key: String::from("id"), value: String::from(*id)});
            apifunc = Some(rustweb::apiServerZoneDetailGET);
        }
        (&Method::PUT, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue{key: String::from("id"), value: String::from(*id)});
            apifunc = Some(rustweb::apiServerZoneDetailPUT);
        }
        (&Method::DELETE, ["api", "v1", "servers", "localhost", "zones", id]) => {
            request.parameters.push(rustweb::KeyValue{key: String::from("id"), value: String::from(*id)});
            apifunc = Some(rustweb::apiServerZoneDetailDELETE);
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "statistics"]) => {
            allow_password = true;
            apifunc = Some(rustweb::apiServerStatistics);
        }
        (&Method::GET, ["api", "v1", "servers", "localhost", "zones"]) =>
            apifunc = Some(rustweb::apiServerZonesGET),
        (&Method::POST, ["api", "v1", "servers", "localhost", "zones"]) =>
            apifunc = Some(rustweb::apiServerZonesPOST),
        (&Method::GET, ["api", "v1", "servers", "localhost"]) => {
            allow_password = true;
            apifunc = Some(rustweb::apiServerDetail);
        }
        (&Method::GET, ["api", "v1", "servers"]) =>
            apifunc = Some(rustweb::apiServer),
        (&Method::GET, ["api", "v1"]) =>
            apifunc = Some(rustweb::apiDiscoveryV1),
        (&Method::GET, ["api"]) =>
            apifunc = Some(rustweb::apiDiscovery),
        (&Method::GET, ["metrics"]) =>
            rustweb::prometheusMetrics(&request, &mut response).unwrap(),
        _ => {
            let mut uripath = rust_request.uri().path();
            if uripath == "/" {
                uripath = "/index.html";
            }
            let pos = ctx.urls.iter().position(|x| String::from("/") + x == uripath);
            if pos.is_none() {
                eprintln!("{} {} not found", rust_request.method(), uripath);
            }
            if rustweb::serveStuff(&request, &mut response).is_err() {
                // Return 404 not found response.
                response.status = StatusCode::NOT_FOUND.as_u16();
                response.body = NOTFOUND.to_vec();
                eprintln!("{} {} not found case 2", rust_request.method(), uripath);
            }
        }
    }
    let mut rust_response = Response::builder();

    if let Some(func) = apifunc {
        let reqheaders = rust_request.headers().clone();
        if rust_request.method()== Method::POST || rust_request.method() == Method::PUT {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
        }
        api_wrapper(
            &ctx,
            func,
            &request,
            &mut response,
            &reqheaders,
            rust_response.headers_mut().expect("no headers?"),
            allow_password,
        );
    }

    let mut body = full(response.body);
    if method == Method::HEAD {
        body = full(vec!());
    }

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
    Ok(rust_response)
}

async fn serveweb_async(listener: TcpListener, ctx: Arc<Context>) -> MyResult<()> {

    // We start a loop to continuously accept incoming connections
    loop {
        let ctx = Arc::clone(&ctx);
        let ctx2 = Arc::clone(&ctx);
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);
        let fut =
            http1::Builder::new().serve_connection(io, service_fn(move |req| {
                let ctx = Arc::clone(&ctx);
                hello(req, ctx)
            }));

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = fut.await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
        eprintln!("{}", ctx2.counter.lock().await);
    }
}

pub fn serveweb(addresses: &Vec<String>, urls: &[String], password_ch: cxx::UniquePtr<rustweb::CredentialsHolder>, api_ch: cxx::UniquePtr<rustweb::CredentialsHolder>) -> Result<(), std::io::Error> {
    // Context (R/O for now)
    let ctx = Arc::new(Context {
        urls: urls.to_vec(),
        password_ch,
        api_ch,
        counter: Mutex::new(0),
    });

    let runtime = Builder::new_current_thread()
        .worker_threads(1)
        .thread_name("rec/web")
        .enable_io()
        .build()?;

    let mut set = JoinSet::new();

    for addr_str in addresses {
        // Socket create and bind should happen here
        //let addr = SocketAddr::from_str(addr_str);
        let addr = match SocketAddr::from_str(addr_str) {
            Ok(val) => val,
            Err(err) => {
                let msg = format!("`{}' is not a IP:port combination: {}", addr_str, err);
                return Err(std::io::Error::new(ErrorKind::Other, msg));
            }
        };

        let listener = runtime.block_on(async { TcpListener::bind(addr).await });
        let ctx = Arc::clone(&ctx);
        match listener {
            Ok(val) => {
                println!("Listening on {}", addr);
                set.spawn_on(serveweb_async(val, ctx), runtime.handle());
            }
            Err(err) => {
                let msg = format!("Unable to bind web socket: {}", err);
                return Err(std::io::Error::new(ErrorKind::Other, msg));
            }
        }
    }
    std::thread::Builder::new()
        .name(String::from("rec/rustweb"))
        .spawn(move || {
            runtime.block_on(async {
                while let Some(res) = set.join_next().await {
                    println!("{:?}", res);
                }
            });
        })?;
    Ok(())
}

unsafe impl Send for rustweb::CredentialsHolder {}
unsafe impl Sync for rustweb::CredentialsHolder {}

#[cxx::bridge(namespace = "pdns::rust::web::rec")]
mod rustweb {
    extern "C++" {
      type CredentialsHolder;
    }

    /*
     * Functions callable from C++
     */
    extern "Rust" {
        fn serveweb(addreses: &Vec<String>, urls: &[String], pwch: UniquePtr<CredentialsHolder>, apikeych: UniquePtr<CredentialsHolder>) -> Result<()>;
    }

    struct KeyValue {
        key: String,
        value: String,
    }

    struct Request {
        body: Vec<u8>,
        uri: String,
        vars: Vec<KeyValue>,
        parameters: Vec<KeyValue>,
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
        fn apiDiscovery(request: &Request, response: &mut Response) -> Result<()>;
        fn apiDiscoveryV1(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServer(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerCacheFlush(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfig(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowFromGET(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowFromPUT(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowNotifyFromGET(request: &Request, response: &mut Response) -> Result<()>;
        fn apiServerConfigAllowNotifyFromPUT(request: &Request, response: &mut Response) -> Result<()>;
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

        fn matches(self: &CredentialsHolder, str: &CxxString) -> bool;
    }
}
