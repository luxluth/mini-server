use mini_server::*;
use std::{path::PathBuf, str::FromStr};

fn get_file_content(path: &PathBuf) -> String {
    let content = std::fs::read_to_string(path);
    match content {
        Ok(c) => c,
        Err(e) => {
            format!(
                "..error: {e} '{p}'",
                e = e,
                p = path.to_str().unwrap_or("unknown path")
            )
        }
    }
}

fn index(_: HTTPRequest) -> HTTPResponse {
    let mut response = HTTPResponse::default();
    response.set_header("Content-Type", "text/html");
    let html_content = get_file_content(&PathBuf::from_str("./examples/index.html").unwrap());
    response.set_body(html_content.into_bytes());

    response
}

fn main() {
    let server = MiniServer::init("localhost", 4221, ServerKind::HTTP);
    if let MatchingServer::HTTP(mut app) = server {
        app.get("/", index);
        app.get("/index.html", index);

        app.run();
    }
}
