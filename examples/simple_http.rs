use mini_server::*;

fn index(_: HTTPRequest) -> HTTPResponse {
    let mut response = HTTPResponse::default();
    response.set_header("Content-Type", "text/html");
    let html_content = include_str!("./index.html").to_string();
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
