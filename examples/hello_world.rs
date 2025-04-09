use mini_server::worker::ThreadPool;
use mini_server::*;
fn main() {
    let mut app = HTTPServer {
        thread_pool: ThreadPool::new(4),
        ..Default::default()
    };

    let addr = app.addr.clone()[0];

    app.get("/", |_, _| "Hello World!".into());

    app.on_ready(move || {
        eprintln!("Running on {addr}");
    });

    app.run();
}
