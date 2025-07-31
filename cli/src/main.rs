use rex::cli;

#[tokio::main]
async fn main() {
    let _ = cli::start().await.inspect_err(|err| {
        eprintln!("\x1b[31;1mError:\x1b[0m execution failed: {err:?}");
        std::process::exit(1);
    });
}
