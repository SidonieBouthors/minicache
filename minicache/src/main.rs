use clap::Parser;
mod server;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = server::Opt::parse();
    server::run(opt).await
}
