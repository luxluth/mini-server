use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::iter::zip;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[macro_use]
mod macros;
pub mod worker;

/// `CRLF` represents the Carriage Return (CR) and Line Feed (LF)
/// characters combined ("\r\n"). It is commonly used as the
/// end-of-line sequence in HTTP requests and responses.
///
/// `CRLF` is utilized to signify the end of a line in HTTP messages,
/// ensuring compatibility with the HTTP protocol.
///
/// ```rust
/// use mini_server::CRLF;
///
/// let http_line = format!("--- boundry{}{}", CRLF, CRLF);
/// ```
pub const CRLF: &str = "\r\n";

/// `MAX_BUFFER` defines the maximum size, in bytes, for a request
/// in your web server. Requests exceeding this size may be rejected or
/// handled differently based on your server's implementation.
///
/// ## Determining the appropriate buffer size
///
/// Determining an appropriate value for `MAX_BUFFER` depends on several
/// factors, including the typical size of requests the web server
/// expects to handle, the available system resources, and the desired
/// trade-off between memory usage and potential denial-of-service (DoS)
/// protection.
///
/// Here are some considerations:
///
/// 1. Resource Constraints:
///     Consider the available system memory. Setting MAX_BUFFER too high
///     might lead to excessive memory usage, especially if the
///     server handles a large number of concurrent requests.
///
/// 2. Denial-of-Service (DoS) Protection:
///     A smaller MAX_BUFFER can provide a level of protection against
///     certain types of DoS attacks that involve sending large,
///     resource-consuming requests. However, it's essential to strike
///     a balance to avoid false positives or impacting legitimate
///     requests.
///
/// ## Note
/// > The max_buffer is configurable when configurating a new server instance
/// > It is only used in the [TcpServer]
pub const MAX_BUFFER: usize = 16384;

/// The `HTTPRequest` struct represents an HTTP request received by
/// the web server. It encapsulates various components of an HTTP request,
/// including the HTTP method, request path, headers, and body.
#[derive(Debug, Clone)]
pub struct HTTPRequest {
    /// The HTTP method used in the request (e.g., GET, POST).
    pub method: HTTPMethod,
    /// The decoded path portion of the request URL.
    pub path: String,
    /// The raw, percent-encoded path from the request URL.
    pub raw_path: String,
    /// A collection of URL parameters parsed from the request.
    pub params: URLSearchParams,
    /// The version of the HTTP protocol used in the request (e.g., "1.1").
    pub http_version: String,
    /// A collection of HTTP headers included in the request.
    pub headers: Headers,
    /// The body of the HTTP request. (Note: Consider changing body to a sequence of bytes (***`Vec<u8>`***)
    /// for more flexibility and efficiency.)
    pub body: Vec<u8>,
}

impl Default for HTTPRequest {
    fn default() -> Self {
        Self {
            method: HTTPMethod::GET,
            path: String::from("/"),
            raw_path: String::new(),
            params: HashMap::new(),
            http_version: String::from("1.1"),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }
}

/// The `URLSearchParams` type alias represents a collection of URL parameters parsed from an HTTP request's
/// query string. It is implemented as a HashMap<String, String> where keys are parameter names, and values
/// are parameter values.
pub type URLSearchParams = HashMap<String, String>;

/// The `Headers` type alias represents a collection of HTTP headers in key-value pairs. It is implemented
/// as a HashMap<String, String>, where keys are header names, and values are header values.
pub type Headers = HashMap<String, String>;

/// The parse_path function takes a string representing an HTTP request path and extracts the path and URL
/// parameters (if any) from it. It returns a tuple containing the path and a URLSearchParams
/// `(HashMap<String, String>)` representing the parsed URL parameters.
fn parse_path(data: &str) -> (String, URLSearchParams) {
    let split_data = data.split_once('?');
    if split_data.is_none() {
        (data.into(), HashMap::new())
    } else {
        let (ph, pr) = split_data.unwrap();
        let params: URLSearchParams = pr
            .split('&')
            .filter_map(|param| {
                let mut parts = param.split('=');
                let key = parts.next()?.to_string();
                let value = parts.next()?.to_string();
                Some((key, value))
            })
            .collect();

        (ph.to_string(), params)
    }
}

fn get_method(raw: Option<&str>) -> HTTPMethod {
    if let Some(raw) = raw {
        match raw {
            "GET" => HTTPMethod::GET,
            "HEAD" => HTTPMethod::HEAD,
            "POST" => HTTPMethod::POST,
            "PUT" => HTTPMethod::PUT,
            "DELETE" => HTTPMethod::DELETE,
            "CONNECT" => HTTPMethod::CONNECT,
            "OPTIONS" => HTTPMethod::OPTIONS,
            "TRACE" => HTTPMethod::TRACE,
            "PATCH" => HTTPMethod::PATCH,
            _ => HTTPMethod::GET,
        }
    } else {
        HTTPMethod::GET
    }
}

fn get_version(v: Option<u8>) -> String {
    if let Some(v) = v {
        if v == 1 {
            return "1.1".into();
        } else {
            return "1.2".into();
        }
    } else {
        "1.1".into()
    }
}

/// The `HTTPResponse` struct represents an HTTP response that the web server can send to clients.
/// It encapsulates various components of an HTTP response, including the response body, headers,
/// status code, status text, and the HTTP version.
///
/// ```rust
/// use mini_server::{HTTPResponse, Headers};
///
/// fn create_http_response() -> HTTPResponse {
///     let mut headers = Headers::new();
///     headers.insert("Content-Type".into(), "text/plain".into());
///
///     HTTPResponse {
///         body: b"Hello, World!".to_vec(),
///         headers,
///         status: 200,
///         status_text: "OK".to_string(),
///         http_version: "1.1".to_string(),
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HTTPResponse {
    /// The response body as a vector of bytes.
    pub body: Vec<u8>,
    /// A collection of HTTP headers included in the response.
    pub headers: Headers,
    ///  The HTTP status code indicating the outcome of the request.
    pub status: u16,
    /// The human-readable status text associated with the status code.
    pub status_text: String,
    /// The version of the HTTP protocol used for the response.
    pub http_version: String,
}

fn default_headers() -> Headers {
    let mut h = Headers::new();
    h.insert("Server".into(), "miniserver".into());
    h
}

impl Default for HTTPResponse {
    fn default() -> Self {
        HTTPResponse {
            body: Vec::new(),
            headers: default_headers(),
            status: 200,
            status_text: String::from("OK"),
            http_version: String::from("1.1"),
        }
    }
}

response_from_for!(&[u8]);
response_from_for!(&str);
response_from_for!(Vec<u8>);
response_from_for!(String);

impl HTTPResponse {
    /// Get a new HTTPResponse struct
    pub fn new() -> Self {
        HTTPResponse::default()
    }

    /// Allows updating the body of an HTTPResponse instance
    /// with a new vector of bytes (`Vec<u8>`). Additionally, it automatically
    /// updates the "Content-Length" header to reflect the length of the new body.
    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
        self.headers
            .insert("Content-Length".to_string(), self.body.len().to_string());
    }

    /// Update the headers of an HTTPResponse instance with a new set of headers
    /// provided as a Headers collection.
    pub fn set_headers(&mut self, headers: Headers) {
        for (key, value) in headers {
            self.headers.insert(key, value);
        }
    }

    /// Insert/Update the `HTTPResponse` header
    pub fn set_header(&mut self, k: &str, v: &str) {
        self.headers.insert(k.into(), v.into());
    }

    fn apply_status(&mut self, status: u16, text: &str) {
        self.status = status;
        self.status_text = text.to_string();
    }

    /// The set_status method allows setting the HTTP status code for an HTTPResponse instance.
    /// It updates both the numeric status code (status) and the associated human-readable
    /// status text.
    pub fn set_status(&mut self, status: u16) {
        match status {
            100 => self.apply_status(status, "Continue"),
            101 => self.apply_status(status, "Switching Protocols"),
            102 => self.apply_status(status, "Processing"),
            103 => self.apply_status(status, "Early Hints"),

            200 => self.apply_status(status, "OK"),
            201 => self.apply_status(status, "Created"),
            202 => self.apply_status(status, "Accepted"),
            203 => self.apply_status(status, "Non-Authoritative Information"),
            204 => self.apply_status(status, "No Content"),
            205 => self.apply_status(status, "Reset Content"),
            206 => self.apply_status(status, "Partial Content"),
            207 => self.apply_status(status, "Multi-Status"),
            208 => self.apply_status(status, "Already Reported"),
            226 => self.apply_status(status, "IM Used"),

            300 => self.apply_status(status, "Multiple Choices"),
            301 => self.apply_status(status, "Moved Permanently"),
            302 => self.apply_status(status, "Found"),
            303 => self.apply_status(status, "See Other"),
            304 => self.apply_status(status, "Not Modified"),
            305 => self.apply_status(status, "Use Proxy"),
            306 => self.apply_status(status, "Switch Proxy"),
            307 => self.apply_status(status, "Temporary Redirect"),
            308 => self.apply_status(status, "Permanent Redirect"),

            400 => self.apply_status(status, "Bad Request"),
            401 => self.apply_status(status, "Unauthorized"),
            402 => self.apply_status(status, "Payment Required"),
            403 => self.apply_status(status, "Forbidden"),
            404 => self.apply_status(status, "Not Found"),
            405 => self.apply_status(status, "Method Not Allowed"),
            406 => self.apply_status(status, "Not Acceptable"),
            407 => self.apply_status(status, "Proxy Authentication Required"),
            408 => self.apply_status(status, "Request Timeout"),
            409 => self.apply_status(status, "Conflict"),
            410 => self.apply_status(status, "Gone"),
            411 => self.apply_status(status, "Length Required"),
            412 => self.apply_status(status, "Precondition Failed"),
            413 => self.apply_status(status, "Payload Too Large"),
            414 => self.apply_status(status, "URI Too Long"),
            415 => self.apply_status(status, "Unsupported Media Type"),
            416 => self.apply_status(status, "Range Not Satisfiable"),
            417 => self.apply_status(status, "Expectation Failed"),
            418 => self.apply_status(status, "I'm a teapot"),
            421 => self.apply_status(status, "Misdirected Request"),
            422 => self.apply_status(status, "Unprocessable Entity"),
            423 => self.apply_status(status, "Locked"),
            424 => self.apply_status(status, "Failed Dependency"),
            425 => self.apply_status(status, "Too Early"),
            426 => self.apply_status(status, "Upgrade Required"),
            428 => self.apply_status(status, "Precondition Required"),
            429 => self.apply_status(status, "Too Many Requests"),
            431 => self.apply_status(status, "Request Header Fields Too Large"),
            451 => self.apply_status(status, "Unavailable For Legal Reasons"),

            500 => self.apply_status(status, "Internal Server Error"),
            501 => self.apply_status(status, "Not Implemented"),
            502 => self.apply_status(status, "Bad Gateway"),
            503 => self.apply_status(status, "Service Unavailable"),
            504 => self.apply_status(status, "Gateway Timeout"),
            505 => self.apply_status(status, "HTTP Version Not Supported"),
            506 => self.apply_status(status, "Variant Also Negotiates"),
            507 => self.apply_status(status, "Insufficient Storage"),
            508 => self.apply_status(status, "Loop Detected"),
            510 => self.apply_status(status, "Not Extended"),
            511 => self.apply_status(status, "Network Authentication Required"),

            _ => self.apply_status(500, "Internal Server Error"),
        }
    }

    /// Set the HTTPResponse version (e.g. '1.1')
    pub fn set_version(&mut self, version: String) {
        self.http_version = version;
    }

    fn format_header(&self) -> String {
        let mut headers = String::new();
        for (key, value) in &self.headers {
            headers.push_str(format!("{}: {}{}", key, value, CRLF).as_str());
        }
        headers
    }

    /// The raw method generates the raw representation of an HTTP response, including
    /// the status line, headers, and body. It returns the
    /// formatted HTTP response as a vector of bytes (`Vec<u8>`).
    /// ```rust
    /// use mini_server::HTTPResponse;
    /// fn get_raw_response(response: &mut HTTPResponse) -> Vec<u8> {
    ///     let raw_response = response.raw();
    ///
    ///     // Accessing the raw HTTP response
    ///     println!("Raw Response: {:?}", raw_response);
    ///     raw_response
    /// }
    /// ```
    pub fn raw(&mut self) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/{version} {status} {status_text}{CRLF}{headers}{CRLF}",
            version = self.http_version,
            status = self.status,
            status_text = self.status_text,
            CRLF = CRLF,
            headers = self.format_header(),
        )
        .as_bytes()
        .to_vec();

        bytes.extend(self.body.iter());

        bytes
    }
}

/// Get the value of a path dynamic variable
/// ```rust
/// use mini_server::*;
/// let mut app = HTTPServer::new("localhost:4221");
///
/// app.get("/hello/@name/#age", |_, exprs| {
///     let name = expand!(exprs, "name", PathExpr::String);
///     let age = expand!(exprs, "age", PathExpr::Number);
///
///     format!("Hello {name}, you are {age}!").into()
/// });
/// ```
#[macro_export]
macro_rules! expand {
    ($exprs: expr, $name: expr, $against: path) => {
        match $exprs.get(&String::from($name)).unwrap() {
            $against(value) => value,
            _ => unreachable!(),
        }
    };
}

/// An hash map of `PathExpr`
pub type PathMap = HashMap<String, PathExpr>;

/// RequestHandler type is a function type that defines the signature for handling HTTP requests.
/// It takes `HTTPRequest` and `HashMap<String, PathExpr>` as a parameter and returns an `HTTPResponse`
pub struct RequestHandler(
    Arc<Box<dyn Fn(HTTPRequest, PathMap) -> HTTPResponse + Send + Sync + 'static>>,
);

impl Clone for RequestHandler {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// EventHandler type is a function type that defines the signature for handling events triggered
/// by HTTP requests. It takes references to an `HTTPRequest` and a mutable `HTTPResponse` as parameters.
pub struct EventHandler(Arc<Box<dyn Fn(&HTTPRequest, &mut HTTPResponse) + Send + Sync + 'static>>);

impl Clone for EventHandler {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct SimpleEventHandler(
    Arc<Box<dyn Fn(&mut TcpStream, Request) -> Option<Response> + Send + Sync + 'static>>,
);

impl Clone for SimpleEventHandler {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// The SoftEventHandler type is a function type that defines the signature for handling soft events,
/// typically without specific request or response parameters.
pub struct SoftEventHandler(Arc<Box<dyn Fn() + Send + Sync + 'static>>);

impl Clone for SoftEventHandler {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub struct ErrorEventHandler(Arc<Box<dyn Fn(RunError) + Send + Sync + 'static>>);

impl Clone for ErrorEventHandler {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
/// The HTTPMethod enum represents the HTTP methods that can be used in HTTP requests.
/// Each variant corresponds to a standard HTTP method.
#[derive(Debug, PartialEq, Clone)]
pub enum HTTPMethod {
    /// Used to establish a network connection to a resource.
    CONNECT,
    /// Requests that a resource be removed.
    DELETE,
    /// Requests a representation of a resource.
    GET,
    /// Requests the headers of a resource without the body.
    HEAD,
    /// Describes the communication options for the target resource.
    OPTIONS,
    /// Applies partial modifications to a resource.
    PATCH,
    /// Submits data to be processed to a specified resource.
    POST,
    /// Updates a resource or creates a new resource if it does not exist.
    PUT,
    /// Performs a message loop-back test along the path to the target resource.
    TRACE,
}

/// A path expression represent a dynamic variable of a path
#[derive(Debug, Clone)]
pub enum PathExpr {
    String(String),
    Number(i32),
}

pub struct Path {
    pub expr: String,
    pub handler: RequestHandler,
    pub method: HTTPMethod,
}

impl Clone for Path {
    fn clone(&self) -> Self {
        Self {
            expr: self.expr.clone(),
            handler: self.handler.clone(),
            method: self.method.clone(),
        }
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.r#match(other.expr.clone()) && self.method == other.method
    }
}

pub struct Listener {
    handler: EventHandler,
}

impl Clone for Listener {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

pub struct SoftListener {
    handler: SoftEventHandler,
}

impl Clone for SoftListener {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

pub struct ErrorListener {
    handler: ErrorEventHandler,
}

impl Clone for ErrorListener {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
        }
    }
}

impl Path {
    pub fn new<T>(expr: &str, handler: T, method: HTTPMethod) -> Self
    where
        T: Fn(HTTPRequest, PathMap) -> HTTPResponse + Send + Sync + 'static,
    {
        Path {
            expr: expr.to_string(),
            handler: RequestHandler(Arc::new(Box::new(handler))),
            method,
        }
    }

    fn parse(&self, expr: String) -> PathMap {
        let mut exprs = PathMap::new();
        if self.r#match(expr.clone()) {
            let other_part: Vec<_> = expr.split('/').filter(|x| !x.is_empty()).collect();
            let self_part: Vec<_> = self.expr.split('/').filter(|x| !x.is_empty()).collect();

            for (o_chunck, s_chunck) in zip(other_part, self_part) {
                if s_chunck.starts_with('#') {
                    let name = s_chunck.strip_prefix('#').unwrap().to_string();
                    let value = o_chunck.parse::<i32>().unwrap();
                    exprs.insert(name, PathExpr::Number(value));
                } else if s_chunck.starts_with('@') {
                    let name = s_chunck.strip_prefix('@').unwrap().to_string();
                    let value = o_chunck.to_string();
                    exprs.insert(name, PathExpr::String(value));
                } else {
                    continue;
                }
            }
        }

        exprs
    }

    fn r#match(&self, expr: String) -> bool {
        if expr == self.expr {
            true
        } else {
            let other_part: Vec<_> = expr.split('/').filter(|x| !x.is_empty()).collect();
            let self_part: Vec<_> = self.expr.split('/').filter(|x| !x.is_empty()).collect();

            if other_part.len() != self_part.len() {
                false
            } else {
                for (o_chunck, s_chunck) in zip(other_part, self_part) {
                    if s_chunck.starts_with('#') {
                        if o_chunck.parse::<i32>().is_ok() {
                            continue;
                        } else {
                            return false;
                        }
                    } else if s_chunck.starts_with('@') {
                        continue;
                    } else if o_chunck != s_chunck {
                        return false;
                    }
                }

                true
            }
        }
    }

    fn handle_request(&self, request: HTTPRequest) -> HTTPResponse {
        let exprs = self.parse(request.path.clone());
        (self.handler.0)(request, exprs)
    }
}

impl Listener {
    pub fn new<T>(handler: T) -> Self
    where
        T: Fn(&HTTPRequest, &mut HTTPResponse) + Send + Sync + 'static,
    {
        Listener {
            handler: EventHandler(Arc::new(Box::new(handler))),
        }
    }

    pub fn notify(&self, req: &HTTPRequest, res: &mut HTTPResponse) {
        (self.handler.0)(req, res)
    }
}

impl SoftListener {
    pub fn new<T>(handler: T) -> Self
    where
        T: Fn() + Send + Sync + 'static,
    {
        SoftListener {
            handler: SoftEventHandler(Arc::new(Box::new(handler))),
        }
    }

    pub fn notify(&self) {
        (self.handler.0)()
    }
}

impl ErrorListener {
    pub fn new<T>(handler: T) -> Self
    where
        T: Fn(RunError) + Send + Sync + 'static,
    {
        Self {
            handler: ErrorEventHandler(Arc::new(Box::new(handler))),
        }
    }

    pub fn notify(&self, error: RunError) {
        (self.handler.0)(error)
    }
}

pub trait Server<U, V> {
    fn handle_request(&self, stream: U, req: V);
    fn run(&self);
}

/// `Vec<u8>`
pub type Request = Vec<u8>;
/// `Vec<u8>`
pub type Response = Vec<u8>;

/// This struct provide a simple http server
/// that handle many of the use cases
///
/// ## Example
///
/// ```rust
/// use mini_server::*;
///
/// let mut app = HTTPServer::default();
///
/// app.get("/", |_, _| {
///     "Hello World!".into()
/// });
///
/// ```
///
/// ## Path
///
/// The path is an expression that can contains dynamic variables.
/// - Basic paths: `/`, `/this/is/a/path`, ...
/// - Dynamic path: `/this/is/a/@varibale`, `/this/is/another/#variable`
///
/// `#` and `@` are prefixes for dynamic values. `#` for denoting numbers
/// and `@` for strings
pub struct HTTPServer {
    pub addr: Vec<SocketAddr>,
    pub paths: Vec<Path>,
    pub listeners: Vec<Listener>,
    pub on_ready: Option<SoftListener>,
    pub on_shutdown: Option<SoftListener>, // TODO: Implement on_shutdown
    pub on_error: Option<ErrorListener>,
    pub thread_pool: worker::ThreadPool,
    pub should_shutdown: ShutdownWrapper,
}

pub struct ShutdownWrapper(AtomicBool);

impl Default for HTTPServer {
    fn default() -> Self {
        Self {
            addr: vec![SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4221,
            )],
            paths: vec![],
            listeners: vec![],
            on_ready: None,
            on_shutdown: None,
            on_error: None,
            thread_pool: worker::ThreadPool::new(14),
            should_shutdown: ShutdownWrapper(AtomicBool::new(false)),
        }
    }
}

impl Clone for HTTPServer {
    fn clone(&self) -> Self {
        let new_should_shutdown = self.should_shutdown.0.load(Ordering::Relaxed);

        Self {
            addr: self.addr.clone(),
            paths: self.paths.clone(),
            listeners: self.listeners.clone(),
            on_ready: self.on_ready.clone(),
            on_shutdown: self.on_shutdown.clone(),
            on_error: self.on_error.clone(),
            thread_pool: worker::EMPTY_POOL,
            should_shutdown: ShutdownWrapper(AtomicBool::new(new_should_shutdown)),
        }
    }
}

pub enum RunError {
    CannotBindToAddr(Vec<SocketAddr>),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::CannotBindToAddr(addr) => {
                write!(f, "Unable to bind to those addresses: {addr:?}")
            }
        }
    }
}

impl Server<&mut TcpStream, HTTPRequest> for HTTPServer {
    fn handle_request(&self, stream: &mut TcpStream, req: HTTPRequest) {
        let mut handled = false;
        for path in &self.paths {
            if path.method == req.method && path.r#match(req.path.clone()) {
                let mut response = path.handle_request(req.clone());
                for listener in &self.listeners {
                    listener.notify(&req, &mut response);
                }
                let _ = stream.write(response.raw().as_slice());
                handled = true;
                break;
            }
        }
        if !handled {
            let mut response = HTTPResponse::default();
            response.set_status(404);

            let data: String = format!(
                "Unreachable path `{:?} - {}`. Resource NOT FOUND",
                req.method, req.path
            );

            let data_bytes: Vec<u8> = data.into_bytes();
            response.set_body(data_bytes);
            for listener in &self.listeners {
                listener.notify(&req, &mut response);
            }
            let _ = stream.write(response.raw().as_slice());
        }
    }

    fn run(&self) {
        if let Ok(listener) = TcpListener::bind(self.addr.as_slice()) {
            if let Some(ready_fn) = &self.on_ready {
                ready_fn.notify();
            }

            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let self_clone = Arc::new(self.clone());
                        self.thread_pool.execute(move || {
                            let s = self_clone.clone();
                            let mut st = stream;
                            s.handle_connection(&mut st);
                        });
                    }
                    Err(e) => {
                        eprintln!("{e}")
                    }
                }
            }
        } else {
            if let Some(onerror) = &self.on_error {
                onerror.notify(RunError::CannotBindToAddr(self.addr.clone()));
            }
        }
    }
}

macro_rules! define_all_route_methods {
    ($($name:ident => $method:expr),* $(,)?) => {
        impl HTTPServer {
            $(
                pub fn $name<T>(&mut self, path: &'static str, handler: T)
                where
                    T: Fn(HTTPRequest, PathMap) -> HTTPResponse + Send + Sync + 'static,
                {
                    self.add_path(Path::new(path, handler, $method));
                }
            )*
        }
    };
}

define_all_route_methods! {
    get => HTTPMethod::GET,
    post => HTTPMethod::POST,
    put => HTTPMethod::PUT,
    delete => HTTPMethod::DELETE,
    patch => HTTPMethod::PATCH,
    options => HTTPMethod::OPTIONS,
    head => HTTPMethod::HEAD,
    trace => HTTPMethod::TRACE,
    connect => HTTPMethod::CONNECT,
}

impl HTTPServer {
    pub fn new<A>(addr: A) -> Self
    where
        A: std::net::ToSocketAddrs,
    {
        Self {
            addr: addr.to_socket_addrs().unwrap().collect(),
            paths: Vec::new(),
            listeners: Vec::new(),
            on_ready: None,
            on_shutdown: None,
            on_error: None,
            thread_pool: worker::ThreadPool::new(14),
            should_shutdown: ShutdownWrapper(AtomicBool::new(false)),
        }
    }

    pub fn on_ready<T>(&mut self, handler: T)
    where
        T: Fn() + Send + Sync + 'static,
    {
        self.on_ready = Some(SoftListener::new(handler));
    }

    pub fn shutdown(&self) {
        self.should_shutdown.0.store(true, Ordering::Relaxed)
    }

    pub fn on_shutdown<T>(&mut self, handler: T)
    where
        T: Fn() + Send + Sync + 'static,
    {
        self.on_shutdown = Some(SoftListener::new(handler));
    }

    pub fn on_error<T>(&mut self, handler: T)
    where
        T: Fn(RunError) + Send + Sync + 'static,
    {
        self.on_error = Some(ErrorListener::new(handler));
    }

    fn add_path(&mut self, path: Path) {
        let path_name = path.expr.clone();
        if !self.paths.contains(&path) {
            self.paths.push(path);
        } else {
            eprintln!(
                "..warn `{}` path redefinition is not allowed. Only the first definition matter",
                path_name
            );
        }
    }

    fn handle_connection(&self, stream: &mut TcpStream) {
        match stream.try_clone() {
            Ok(s) => {
                let mut reader = std::io::BufReader::new(s);
                let mut head = String::new();
                'read_req_head: loop {
                    let mut temp = String::new();
                    let _ = reader.read_line(&mut temp);

                    if temp.trim().is_empty() {
                        break 'read_req_head;
                    } else {
                        head.push_str(&temp);
                    }
                }

                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);
                let is_complete = req.parse(&head.as_bytes()).unwrap().is_complete();
                let raw_path = match req.path {
                    Some(p) => p.to_string(),
                    None => String::from("/"),
                };
                let (path, params) = parse_path(&raw_path);

                let mut parsed_headers: HashMap<String, String> = HashMap::new();
                for field in req.headers {
                    parsed_headers.insert(
                        field.name.to_lowercase(),
                        String::from_utf8(field.value.to_vec()).unwrap(),
                    );
                }

                let body_len: Option<usize> =
                    if let Some(len) = parsed_headers.get("content-length") {
                        Some(len.parse().unwrap())
                    } else {
                        None
                    };

                let method = get_method(req.method);

                if let Some(body_size) = body_len {
                    let mut body_buf = vec![0; body_size];
                    let _ = reader.read_exact(&mut body_buf);
                    if is_complete {
                        self.handle_request(
                            stream,
                            HTTPRequest {
                                method,
                                path,
                                raw_path,
                                params,
                                http_version: if req.version.unwrap() == 1 {
                                    "1.1".into()
                                } else {
                                    "1.2".into()
                                },
                                headers: parsed_headers,
                                body: body_buf,
                            },
                        );
                    };
                } else {
                    let request = HTTPRequest {
                        method,
                        path,
                        raw_path,
                        params,
                        http_version: get_version(req.version),
                        headers: parsed_headers,
                        body: vec![],
                    };
                    self.handle_request(stream, request);
                }
            }
            Err(e) => {
                eprintln!("{e}");
            }
        }
    }

    pub fn on_any<T>(&mut self, handler: T)
    where
        T: Fn(&HTTPRequest, &mut HTTPResponse) + Send + Sync + 'static,
    {
        self.listeners.push(Listener::new(handler));
    }
}

pub struct TcpServer {
    pub addr: Vec<SocketAddr>,
    listeners: Vec<SimpleEventHandler>,
    on_ready: Option<SoftListener>,
    on_shutdown: Option<SoftListener>, // TODO: Implement on_shutdown
    max_buffer: Option<usize>,
}

impl Default for TcpServer {
    fn default() -> Self {
        Self {
            addr: vec![SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                4221,
            )],
            listeners: vec![],
            on_ready: None,
            on_shutdown: None,
            max_buffer: None,
        }
    }
}

impl Server<&mut TcpStream, Request> for TcpServer {
    fn handle_request(&self, stream: &mut TcpStream, req: Request) {
        for listener in &self.listeners {
            if let Some(response) = listener.0(stream, req.clone()) {
                let _ = stream.write(&response);
            }
        }
    }

    fn run(&self) {
        let listener = TcpListener::bind(self.addr.as_slice()).unwrap();
        if let Some(ready_fn) = &self.on_ready {
            ready_fn.notify();
        }

        for stream in listener.incoming() {
            let mut max_buffer = MAX_BUFFER;
            if let Some(mxb) = self.max_buffer {
                max_buffer = mxb;
            }
            match stream {
                Ok(mut stream) => {
                    let mut data = vec![0; max_buffer];
                    let _ = stream.read(&mut data);
                    self.handle_request(&mut stream, data);
                }
                Err(e) => {
                    eprintln!("{e}")
                }
            }
        }
    }
}

impl TcpServer {
    pub fn new<A>(addr: A) -> Self
    where
        A: std::net::ToSocketAddrs,
    {
        Self {
            addr: addr.to_socket_addrs().unwrap().collect(),
            on_ready: None,
            listeners: Vec::new(),
            on_shutdown: None,
            max_buffer: None,
        }
    }

    pub fn on_ready<T>(&mut self, handler: T)
    where
        T: Fn() + Send + Sync + 'static,
    {
        self.on_ready = Some(SoftListener::new(handler));
    }

    pub fn on_shutdown<T>(&mut self, handler: T)
    where
        T: Fn() + Send + Sync + 'static,
    {
        self.on_shutdown = Some(SoftListener::new(handler));
    }

    pub fn set_buffer_to(&mut self, size: usize) {
        self.max_buffer = Some(size);
    }
}
