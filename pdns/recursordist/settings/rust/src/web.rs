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

fn api_wrapper(
    handler: Func,
    request: &rustweb::Request,
    response: &mut rustweb::Response,
    headers: &mut header::HeaderMap,
) {
    response.status = StatusCode::OK.as_u16(); // 200;
                                               // security headers
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_static("*"),
    );
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
            response.status = StatusCode::UNPROCESSABLE_ENTITY.as_u16(); // 422
        }
    }
}

async fn hello(
    rust_request: Request<IncomingBody>,
    urls: &[String],
) -> MyResult<Response<BoxBody>> {
    let mut rust_response = Response::builder();
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
    };
    let mut response = rustweb::Response {
        status: 0,
        body: vec![],
        headers: vec![],
    };
    let headers = rust_response.headers_mut().expect("no headers?");
    match (rust_request.method(), rust_request.uri().path()) {
        (&Method::GET, "/jsonstat") => {
            api_wrapper(
                rustweb::jsonstat as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::PUT, "/api/v1/servers/localhost/cache/flush") => {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
            api_wrapper(
                rustweb::apiServerCacheFlush as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::PUT, "/api/v1/servers/localhost/config/allow-from") => {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
            api_wrapper(
                rustweb::apiServerConfigAllowFromPUT as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/config/allow-from") => {
            api_wrapper(
                rustweb::apiServerConfigAllowFromGET as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::PUT, "/api/v1/servers/localhost/config/allow-notify-from") => {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
            api_wrapper(
                rustweb::apiServerConfigAllowNotifyFromPUT as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/config/allow-notify-from") => {
            api_wrapper(
                rustweb::apiServerConfigAllowNotifyFromGET as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/config") => {
            api_wrapper(
                rustweb::apiServerConfig as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/rpzstatistics") => {
            api_wrapper(
                rustweb::apiServerRPZStats as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/search-data") => {
            api_wrapper(
                rustweb::apiServerSearchData as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/zones/") => {
            api_wrapper(
                rustweb::apiServerZoneDetailGET as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::PUT, "/api/v1/servers/localhost/zones/") => {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
            api_wrapper(
                rustweb::apiServerZoneDetailPUT as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::DELETE, "/api/v1/servers/localhost/zones/") => {
            api_wrapper(
                rustweb::apiServerZoneDetailDELETE as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/statistics") => {
            api_wrapper(
                rustweb::apiServerStatistics as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost/zones") => {
            api_wrapper(
                rustweb::apiServerZonesGET as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::POST, "/api/v1/servers/localhost/zones") => {
            request.body = rust_request.collect().await?.to_bytes().to_vec();
            api_wrapper(
                rustweb::apiServerZonesPOST as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers/localhost") => {
            api_wrapper(
                rustweb::apiServerDetail as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1/servers") => {
            api_wrapper(
                rustweb::apiServer as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api/v1") => {
            api_wrapper(
                rustweb::apiDiscoveryV1 as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/api") => {
            api_wrapper(
                rustweb::apiDiscovery as Func,
                &request,
                &mut response,
                headers,
            );
        }
        (&Method::GET, "/metrics") => {
            rustweb::prometheusMetrics(&request, &mut response).unwrap();
        }
        _ => {
            let mut path = rust_request.uri().path();
            if path == "/" {
                path = "/index.html";
            }
            let pos = urls.iter().position(|x| String::from("/") + x == path);
            if pos.is_none() {
                println!("{} not found", path);
            }
            if rustweb::serveStuff(&request, &mut response).is_err() {
                // Return 404 not found response.
                response.status = StatusCode::NOT_FOUND.as_u16();
                response.body = NOTFOUND.to_vec();
                println!("{} not found case 2", path);
            }
        }
    }
    let mut rust_response = rust_response
        .status(StatusCode::from_u16(response.status).unwrap())
        .body(full(response.body))?;
    for kv in response.headers {
        rust_response.headers_mut().insert(
            header::HeaderName::from_bytes(kv.key.as_bytes()).unwrap(),
            header::HeaderValue::from_str(kv.value.as_str()).unwrap(),
        );
    }
    Ok(rust_response)
}

async fn serveweb_async(listener: TcpListener, urls: &'static [String]) -> MyResult<()> {
    //let request_counter = Arc::new(AtomicUsize::new(0));
    /*
        let fut = http1::Builder::new()
            .serve_connection(move || {
                service_fn(move |req| hello(req))
    });
        */
    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);
        let fut =
            http1::Builder::new().serve_connection(io, service_fn(move |req| hello(req, urls)));

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = /* http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                    .serve_connection(io, service_fn(|req| hello(req)))
                    */
                fut.await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

pub fn serveweb(addresses: &Vec<String>, urls: &'static [String]) -> Result<(), std::io::Error> {
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

        match listener {
            Ok(val) => {
                println!("Listening on {}", addr);
                set.spawn_on(serveweb_async(val, urls), runtime.handle());
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

#[cxx::bridge(namespace = "pdns::rust::web::rec")]
/*
 * Functions callable from C++
 */
mod rustweb {

    extern "Rust" {
        fn serveweb(addreses: &Vec<String>, urls: &'static [String]) -> Result<()>;
    }

    struct KeyValue {
        key: String,
        value: String,
    }

    struct Request {
        body: Vec<u8>,
        uri: String,
        vars: Vec<KeyValue>,
    }

    struct Response {
        status: u16,
        body: Vec<u8>,
        headers: Vec<KeyValue>,
    }

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
    }
}
