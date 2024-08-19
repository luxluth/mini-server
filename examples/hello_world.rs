use mini_server::worker::ThreadPool;
use mini_server::*;
fn main() {
    let mut app = HTTPServer {
        thread_pool: ThreadPool::new(4),
        ..Default::default()
    };

    app.get("/", |_, _| {
        let mut response = HTTPResponse::default();
        response.set_body(b"Hello World!".to_vec());

        response
    });

    app.run();
}
