use mini_server::*;

const INDEX_JS: &[u8] = include_bytes!("./js/index.js");

fn index(_: HTTPRequest, _: &PathMap) -> HTTPResponse {
    let mut response = HTTPResponse::default();
    response.set_header("Content-Type", "text/html");
    let html_content = include_bytes!("./index.html");
    response.set_body(html_content.into());

    response
}

fn main() {
    let mut app = http_server!("localhost", 4221);

    app.get("/", index);
    app.get("/index.html", index);

    app.get("/js/@filename", |_, exprs| {
        let filename = expand!(exprs, "filename", PathExpr::String);
        let mut response = HTTPResponse::default();
        if filename == "index.js" {
            response.set_header("Content-Type", "application/javascript");
            response.set_body(INDEX_JS.into());
        } else {
            response.set_status(404);
        }

        response
    });

    app.run();
}
