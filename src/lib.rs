use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

pub const CRLF: &str = "\r\n";
pub const MAX_BUFFER: usize = 16384;

#[derive(Debug, Clone)]
pub struct HTTPRequest {
    pub method: HTTPMethod,
    pub path: String,
    pub raw_path: String,
    pub params: URLSearchParams,
    pub http_version: String,
    pub headers: Headers,
    pub body: String,
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
            body: String::new(),
        }
    }
}

pub type URLSearchParams = HashMap<String, String>;
pub type Headers = HashMap<String, String>;

pub fn parse_path(data: String) -> (String, URLSearchParams) {
    let mut params = HashMap::new();

    let split_data = data.split_once('?');
    if split_data.is_none() {
        (data, params)
    } else {
        let (ph, pr) = split_data.unwrap();
        let all_params: Vec<&str> = pr.split('&').collect();
        for elem in all_params {
            if let Some((field, value)) = elem.split_once('=') {
                params.insert(field.to_string(), value.to_string());
            }
        }

        (ph.to_string(), params)
    }
}

pub fn parse_http_req(data: String) -> HTTPRequest {
    // let mut req_raw_map = HashMap::<String, String>::new();
    let mut req = HTTPRequest::default();
    let data: Vec<&str> = data.split(CRLF).collect();
    let mut is_body = false;
    for chunck in data {
        let chunck = chunck.replace(CRLF, "");
        if chunck.is_empty() {
            is_body = true;
            continue;
        }

        if is_body {
            req.body += chunck.as_str();
            continue;
        }

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
            req.headers.insert(field.to_string(), value);
        }
    }
    req
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

pub fn vec_to_string(bytes: Vec<u8>) -> String {
    if let Ok(utf8_string) = String::from_utf8(bytes) {
        utf8_string
    } else {
        println!("..error: Unable to convert to utf8");
        String::new()
    }
}

#[derive(Debug)]
pub struct HTTPResponse {
    pub body: Vec<u8>,
    pub headers: Headers,
    pub status: u16,
    pub status_text: String,
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
    pub fn new() -> Self {
        HTTPResponse::default()
    }

    pub fn set_body(&mut self, body: Vec<u8>) {
        self.body = body;
        self.headers
            .insert("Content-Length".to_string(), self.body.len().to_string());
    }

    pub fn set_headers(&mut self, headers: Headers) {
        for (key, value) in headers {
            self.headers.insert(key, value);
        }
    }

    fn apply_status(&mut self, status: u16, text: &str) {
        self.status = status;
        self.status_text = text.to_string();
    }

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

    pub fn raw(&mut self) -> Vec<u8> {
        let mut bytes = format!(
            "HTTP/{version} {status} {status_text}{CRLF}{headers}{CRLF}", // dont forget {body}{CRLF}
            version = self.http_version,
            status = self.status,
            status_text = self.status_text,
            CRLF = CRLF,
            headers = self.format_header(),
        )
        .as_bytes()
        .to_vec();

        bytes.extend(self.body.iter());
        bytes.extend(CRLF.as_bytes().to_vec().iter());

        bytes
    }
}

type RequestHandler = fn(HTTPRequest) -> HTTPResponse;
type EventHandler = fn(&HTTPRequest, &mut HTTPResponse);
type SoftEventHandler = fn();

#[derive(Debug, PartialEq, Clone)]
pub enum HTTPMethod {
    CONNECT,
    DELETE,
    GET,
    HEAD,
    OPTIONS,
    PATCH,
    POST,
    PUT,
    TRACE,
}

pub struct Path {
    name: &'static str,
    handler: RequestHandler,
    method: HTTPMethod,
}

pub struct Listener {
    handler: EventHandler,
}

pub struct SoftListener {
    handler: SoftEventHandler,
}

impl Path {
    pub fn new(name: &'static str, handler: RequestHandler, method: HTTPMethod) -> Self {
        Path {
            name,
            handler,
            method,
        }
    }

    pub fn handle_request(&self, request: HTTPRequest) -> HTTPResponse {
        (self.handler)(request)
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

pub struct MiniServer {
    addr: &'static str,
    port: u32,
    paths: Vec<Path>,
    listeners: Vec<Listener>,
    on_ready: Option<SoftListener>,
    on_shutdown: Option<SoftListener>, // TODO(#1): Implement on_shutdown
}

impl Default for MiniServer {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1",
            port: 6969,
            paths: Vec::new(),
            listeners: Vec::new(),
            on_ready: None,
            on_shutdown: None,
        }
    }
}

impl MiniServer {
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

    pub fn get(&mut self, path: &'static str, handler: RequestHandler) {
        self.paths.push(Path::new(path, handler, HTTPMethod::GET));
    }

    pub fn post(&mut self, path: &'static str, handler: RequestHandler) {
        self.paths.push(Path::new(path, handler, HTTPMethod::POST));
    }

    fn log(&mut self, req: &HTTPRequest, resp: &HTTPResponse) {
        println!(
            "..{:?} {} {} - {}",
            req.method, resp.status, resp.status_text, req.raw_path
        );
    }

    pub fn on_any(&mut self, handler: EventHandler) {
        self.listeners.push(Listener::new(handler));
    }

    pub fn on_ready(&mut self, handler: SoftEventHandler) {
        self.on_ready = Some(SoftListener::new(handler));
    }

    pub fn on_shutdown(&mut self, handler: SoftEventHandler) {
        self.on_shutdown = Some(SoftListener::new(handler));
    }

    fn handle_request(&mut self, mut stream: TcpStream, req: HTTPRequest) {
        let mut handled = false;
        for path in &self.paths {
            if path.method == req.method && req.path == path.name {
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

    pub fn run(&mut self) {
        let listener = TcpListener::bind(format!("{}:{}", self.addr, self.port)).unwrap();
        if let Some(ready_fn) = &self.on_ready {
            ready_fn.notify();
        }

        println!("=== miniserver on http://{}:{}", self.addr, self.port);

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut data = vec![0; MAX_BUFFER];
                    let _ = stream.read(&mut data);
                    let request = parse_http_req(vec_to_string(data));
                    self.handle_request(stream, request)
                }
                Err(e) => {
                    println!("..error: {e}")
                }
            }
        }
    }
}
