use mini_server::*;

fn main() {
    let mut app = http_server!("localhost", 4221);

    app.get("/", |_, _| {
        let mut response = HTTPResponse::default();
        response.set_body(b"Hello World!".to_vec());

        response
    });

    app.run();
}
