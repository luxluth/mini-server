# mini-server

The mini rust server

```bash
cargo add mini-server
```

## HTTP server

```rust
use mini_server::*;

fn main() {
    let mut app = HTTPServer::default();

    app.get("/", |_, _| {
        "Hello World!".into()
    });

    app.run();
}
```

## Dynamic paths

The path is an expression that can contains dynamic variables.

- Basic paths: `/`, `/this/is/a/path`, ...
- Dynamic path: `/this/is/a/@varibale`, `/this/is/another/#variable`

`#` and `@` are prefixes for dynamic values. `#` for denoting numbers
and `@` for strings

```rust
use mini_server::*;

fn main() {
  let mut app = HTTPServer::default();

  app.get("/hello/@name/#age", |_, exprs| {
    let name = expand!(exprs, "name", PathExpr::String);
    let age = expand!(exprs, "age", PathExpr::Number);

    format!("Hello {name}, you are {age}!").into()

  });
}
```

## Examples

To run an example:

```bash
cargo run --example $name
```
