# mini-server

The mini server

## Example

```rust
use mini_server::*;

fn main() {
    let server = MiniServer::init("localhost", 4221, ServerKind::HTTP);
    if let MatchingServer::HTTP(mut app) = server {
        app.get("/", |_| {
            let mut response = HTTPResponse::default();
            response.set_body("Hello World!".into());

            response
        });

        app.run();
    }
}
```
