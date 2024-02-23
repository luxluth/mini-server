use mini_server::*;

fn index(_: HTTPRequest) -> HTTPResponse {
    let mut response = HTTPResponse::default();
    response.set_header("Content-Type", "text/html");
    let html_content = include_bytes!("./index.html");
    response.set_body(html_content.into());

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
