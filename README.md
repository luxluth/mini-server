# mini-server

The mini web server

## Example

```rust
use mini_server::*;

fn hello(_req: HTTPRequest) -> HTTPResponse {
    let mut response = HTTPResponse::default();
    response.set_body("Hello World!".into());

    response
}

fn main() {
    let mut app = MiniServer::new("localhost", 4221);
    app.get("/", hello);
    app.run();
}
```
