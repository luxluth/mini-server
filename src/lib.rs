use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::iter::zip;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::u8;

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
fn parse_path(data: String) -> (String, URLSearchParams) {
    let split_data = data.split_once('?');
    if split_data.is_none() {
        (data, HashMap::new())
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

/// The parse_http_req function takes a string representing an entire HTTP request and parses
/// it into a `HTTPRequest` struct, extracting information such as the HTTP method, path,
/// headers, and body.
fn parse_http_req(body: Vec<u8>, head: String) -> HTTPRequest {
    let mut req = HTTPRequest {
        body,
        ..Default::default()
    };

    for chunck in head.lines() {
        if chunck.starts_with("GET")
            || chunck.starts_with("HEAD")
            || chunck.starts_with("POST")
            || chunck.starts_with("PUT")
            || chunck.starts_with("DELETE")
            || chunck.starts_with("CONNECT")
            || chunck.starts_with("OPTIONS")
            || chunck.starts_with("TRACE")
            || chunck.starts_with("PATCH")
        {
            let head: Vec<&str> = chunck.split_whitespace().collect();
            req.method = get_method(head[0]);
            req.raw_path = head[1].to_string();
            let (path, params) = parse_path(head[1].to_string());
            req.path = path;
            req.params = params;
            let version: Vec<&str> = head[2].split('/').collect();
            req.http_version = version[1].to_string();
            continue;
        }

        if let Some((field, value)) = chunck.split_once(':') {
            let value = value.trim().to_string();
            req.headers.insert(field.to_string().to_lowercase(), value);
        }
    }
    req
}

fn get_body_len(head: String) -> Option<usize> {
    for chunck in head.lines() {
        if chunck.starts_with("GET")
            || chunck.starts_with("HEAD")
            || chunck.starts_with("POST")
            || chunck.starts_with("PUT")
            || chunck.starts_with("DELETE")
            || chunck.starts_with("CONNECT")
            || chunck.starts_with("OPTIONS")
            || chunck.starts_with("TRACE")
            || chunck.starts_with("PATCH")
        {
            continue;
        }

        if let Some((field, value)) = chunck.split_once(':') {
            if field.to_lowercase().trim() == "content-length" {
                return Some(value.trim().parse().unwrap());
            }
        }
    }

    None
}

fn get_method(raw: &str) -> HTTPMethod {
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
#[derive(Debug)]
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
/// let mut app = http_server!("localhost", 4221);
///
/// app.get("/hello/@name/#age", |_, exprs| {
///     let name = expand!(exprs, "name", PathExpr::String);
///     let age = expand!(exprs, "age", PathExpr::Number);
///
///     let mut response = HTTPResponse::default();
///     response.set_body(
///         format!("Hello {name}, you are {age}!")
///             .as_bytes()
///             .to_vec(),
///     );
///
///     response
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
pub type RequestHandler = fn(HTTPRequest, PathMap) -> HTTPResponse;

/// EventHandler type is a function type that defines the signature for handling events triggered
/// by HTTP requests. It takes references to an `HTTPRequest` and a mutable `HTTPResponse` as parameters.
pub type EventHandler = fn(&HTTPRequest, &mut HTTPResponse);

pub type SimpleEventHandler = fn(&mut TcpStream, Request) -> Option<Response>;

/// The SoftEventHandler type is a function type that defines the signature for handling soft events,
/// typically without specific request or response parameters.
pub type SoftEventHandler = fn();

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

#[derive(Clone)]
struct Path {
    pub expr: String,
    pub handler: RequestHandler,
    pub method: HTTPMethod,
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.r#match(other.expr.clone()) && self.method == other.method
    }
}

#[derive(Clone)]
struct Listener {
    handler: EventHandler,
}

#[derive(Clone)]
struct SoftListener {
    handler: SoftEventHandler,
}

impl Path {
    pub fn new(expr: &str, handler: RequestHandler, method: HTTPMethod) -> Self {
        Path {
            expr: expr.to_string(),
            handler,
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
        (self.handler)(request, exprs)
    }
}

impl Listener {
    pub fn new(handler: EventHandler) -> Self {
        Listener { handler }
    }

    pub fn notify(&self, req: &HTTPRequest, res: &mut HTTPResponse) {
        (self.handler)(req, res)
    }
}

impl SoftListener {
    pub fn new(handler: SoftEventHandler) -> Self {
        SoftListener { handler }
    }

    pub fn notify(&self) {
        (self.handler)()
    }
}

pub enum ServerKind {
    TCP,
    HTTP,
    // TODO: UDP,
    // TODO: WEBSOCKET,
}

pub struct MiniServer {}

pub trait Server<U, V> {
    fn handle_request(&mut self, stream: U, req: V);
    fn run(&mut self);
    fn on_ready(&mut self, handler: SoftEventHandler);
    fn on_shutdown(&mut self, handler: SoftEventHandler);
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
/// let mut app = http_server!("localhost", 4221);
///
/// app.get("/", |_, _| {
///     let mut response = HTTPResponse::default();
///     response.set_body(b"Hello World!".to_vec());
///
///     response
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
#[derive(Clone)]
pub struct HTTPServer {
    pub addr: &'static str,
    pub port: u32,
    paths: Vec<Path>,
    listeners: Vec<Listener>,
    on_ready: Option<SoftListener>,
    on_shutdown: Option<SoftListener>, // TODO: Implement on_shutdown
}

impl Server<&mut TcpStream, HTTPRequest> for HTTPServer {
    fn on_ready(&mut self, handler: SoftEventHandler) {
        self.on_ready = Some(SoftListener::new(handler));
    }

    fn on_shutdown(&mut self, handler: SoftEventHandler) {
        self.on_shutdown = Some(SoftListener::new(handler));
    }

    fn handle_request(&mut self, stream: &mut TcpStream, req: HTTPRequest) {
        let mut handled = false;
        for path in &self.paths {
            if path.method == req.method && path.r#match(req.path.clone()) {
                let mut response = path.handle_request(req.clone());
                for listener in &self.listeners {
                    listener.notify(&req, &mut response);
                }
                let _ = stream.write(response.raw().as_slice());
                self.log(&req, &response);
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
            self.log(&req, &response);
        }
    }

    fn run(&mut self) {
        let listener = TcpListener::bind(format!("{}:{}", self.addr, self.port)).unwrap();
        if let Some(ready_fn) = &self.on_ready {
            ready_fn.notify();
        }

        eprintln!("=== miniserver on http://{}:{}", self.addr, self.port);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // let mut data = vec![0; max_buffer];
                    // let _ = stream.read(&mut data);
                    // let request = parse_http_req(data);
                    // self.handle_request(&mut stream, request);
                    let mut self_clone = self.clone();
                    thread::spawn(move || {
                        self_clone.handle_connection(&mut stream);
                    });
                }
                Err(e) => {
                    eprintln!("..error: {e}")
                }
            }
        }
    }
}

impl HTTPServer {
    pub fn new(addr: &'static str, port: u32) -> Self {
        Self {
            addr,
            port,
            paths: Vec::new(),
            listeners: Vec::new(),
            on_ready: None,
            on_shutdown: None,
        }
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

    fn handle_connection(&mut self, stream: &mut TcpStream) {
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        'read_req_head: loop {
            let mut temp = String::new();
            reader.read_line(&mut temp).unwrap();

            if temp.trim().is_empty() {
                break 'read_req_head;
            } else {
                head.push_str(&temp);
            }
        }

        if let Some(body_size) = get_body_len(head.clone()) {
            let mut body_buf = vec![0; body_size];
            let _ = reader.read_exact(&mut body_buf);
            let request = parse_http_req(body_buf, head);
            self.handle_request(stream, request);
        } else {
            let request = parse_http_req(vec![], head);
            self.handle_request(stream, request);
        }
    }

    pub fn connect(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::CONNECT));
    }

    pub fn delete(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::DELETE));
    }

    pub fn get(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::GET));
    }

    pub fn head(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::HEAD));
    }

    pub fn options(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::OPTIONS));
    }

    pub fn patch(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::PATCH));
    }

    pub fn post(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::POST));
    }

    pub fn put(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::PUT));
    }

    pub fn trace(&mut self, path: &'static str, handler: RequestHandler) {
        self.add_path(Path::new(path, handler, HTTPMethod::TRACE));
    }

    fn log(&mut self, req: &HTTPRequest, resp: &HTTPResponse) {
        eprintln!(
            "..{:?} {} {} - {}",
            req.method, resp.status, resp.status_text, req.raw_path
        );
    }

    pub fn on_any(&mut self, handler: EventHandler) {
        self.listeners.push(Listener::new(handler));
    }
}

pub struct TcpServer {
    pub addr: &'static str,
    pub port: u32,
    listeners: Vec<SimpleEventHandler>,
    on_ready: Option<SoftListener>,
    on_shutdown: Option<SoftListener>, // TODO: Implement on_shutdown
    max_buffer: Option<usize>,
}

impl Server<&mut TcpStream, Request> for TcpServer {
    fn handle_request(&mut self, stream: &mut TcpStream, req: Request) {
        for listener in &self.listeners {
            if let Some(response) = listener(stream, req.clone()) {
                let _ = stream.write(&response);
            }
        }
    }

    fn run(&mut self) {
        let listener = TcpListener::bind(format!("{}:{}", self.addr, self.port)).unwrap();
        if let Some(ready_fn) = &self.on_ready {
            ready_fn.notify();
        }

        eprintln!("=== miniserver on tcp://{}:{}", self.addr, self.port);

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
                    eprintln!("..error: {e}")
                }
            }
        }
    }

    fn on_ready(&mut self, handler: SoftEventHandler) {
        self.on_ready = Some(SoftListener::new(handler));
    }

    fn on_shutdown(&mut self, handler: SoftEventHandler) {
        self.on_shutdown = Some(SoftListener::new(handler));
    }
}

impl TcpServer {
    pub fn new(addr: &'static str, port: u32) -> Self {
        Self {
            addr,
            port,
            on_ready: None,
            listeners: Vec::new(),
            on_shutdown: None,
            max_buffer: None,
        }
    }

    pub fn on_request(&mut self, handler: SimpleEventHandler) {
        self.listeners.push(handler);
    }

    pub fn set_buffer_to(&mut self, size: usize) {
        self.max_buffer = Some(size);
    }
}

pub enum MatchingServer {
    HTTP(HTTPServer),
    TCP(TcpServer),
}

/// Iniitialize a new http server
/// ```rust
/// use mini_server::*;
///
/// let mut app = http_server!("localhost", 4221);
/// ```
#[macro_export]
macro_rules! http_server {
    ($domain: expr, $port: expr) => {
        match mini_server::MiniServer::init($domain, $port, mini_server::ServerKind::HTTP) {
            mini_server::MatchingServer::HTTP(v) => v,
            _ => unreachable!(),
        }
    };
}

/// Iniitialize a new tcp server
/// ```rust
/// use mini_server::*;
///
/// let mut app = http_server!("localhost", 4221);
/// ```
#[macro_export]
macro_rules! tcp_server {
    ($domain: expr, $port: expr) => {
        match mini_server::MiniServer::init($domain, $port, mini_server::ServerKind::TCP) {
            mini_server::MatchingServer::TCP(v) => v,
            _ => unreachable!(),
        }
    };
}

impl MiniServer {
    pub fn init(addr: &'static str, port: u32, kind: ServerKind) -> MatchingServer {
        match kind {
            ServerKind::TCP => MatchingServer::TCP(TcpServer::new(addr, port)),
            ServerKind::HTTP => MatchingServer::HTTP(HTTPServer::new(addr, port)),
        }
    }
}
