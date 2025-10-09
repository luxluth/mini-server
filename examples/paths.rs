use mini_server::*;

fn main() {
    let mut app = HTTPServer::default();

    app.get("/", |_, _| "Hello World!".into());

    app.get("/opa", |_, _| "Hello!".into());

    app.get("/opa/@name", |_, exprs| {
        let name = expand!(exprs, "name", PathExpr::String);
        format!("Hello opa {name}!").into()
    });

    app.get("/opa/@name/#age", |_, exprs| {
        let name = expand!(exprs, "name", PathExpr::String);
        let age = expand!(exprs, "age", PathExpr::Number);

        format!("Hello opa {name}, you are {age}!").into()
    });

    app.get("/format/#Flocation", |_, exprs| {
        eprintln!("{exprs:?}");
        let location = expand!(exprs, "location", PathExpr::Float);

        format!("LOACTION = {location}").into()
    });

    app.run();
}
