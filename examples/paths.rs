use mini_server::*;

fn main() {
    let mut app = http_server!("localhost", 4221);

    app.get("/", |_, _| {
        let mut response = HTTPResponse::default();
        response.set_body(b"Hello World!".to_vec());

        response
    });

    app.get("/opa", |_, _| {
        let mut response = HTTPResponse::default();
        response.set_body(b"Hello!".to_vec());

        response
    });

    app.get("/opa/@name", |_, exprs| {
        let name = expand!(exprs, "name", PathExpr::String);

        let mut response = HTTPResponse::default();
        response.set_body(format!("Hello opa {name}!").as_bytes().to_vec());

        response
    });

    app.get("/opa/@name/#age", |_, exprs| {
        let name = expand!(exprs, "name", PathExpr::String);
        let age = expand!(exprs, "age", PathExpr::Number);

        let mut response = HTTPResponse::default();
        response.set_body(
            format!("Hello opa {name}, you are {age}!")
                .as_bytes()
                .to_vec(),
        );

        response
    });

    app.run();
}
