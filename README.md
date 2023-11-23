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
    let server = MiniServer::init("localhost", 4221, ServerKind::HTTP);
    if let MatchingServer::HTTP(mut app) = server {
        app.get("/", idx);
        app.run();
    }
}
```
