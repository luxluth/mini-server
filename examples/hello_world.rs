use mini_server::*;

fn main() {
    let mut app = HTTPServer::default();

    app.get("/", |_, _| {
        let mut response = HTTPResponse::default();
        response.set_body(b"Hello World!".to_vec());

        response
    });

    app.run();
}
