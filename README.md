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
    let server = MiniServer::init("localhost", 8000, ServerKind::HTTP);
    match server {
        MatchingServer::HTTP(mut app) => {
            app.get("/", hello);
            app.run();
        }
         _ => {}
    }
}
```
