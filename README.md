# mini-server

The mini rust server

```bash
cargo add mini-server
```

## Basic server

```rust
use mini_server::*;

fn main() {
    let server = MiniServer::init("localhost", 4221, ServerKind::HTTP);
    if let MatchingServer::HTTP(mut app) = server {
        app.get("/", |_| {
            let mut response = HTTPResponse::default();
            response.set_body(b"Hello World!".to_vec());

            response
        });

        app.run();
    }
}
```

## Examples

To run an example:

```bash
cargo run --example $name
```
