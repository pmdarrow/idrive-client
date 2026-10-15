//! Upload/download benchmark command-line tool.
#[path = "idrive-bench/runner.rs"]
mod runner;

use idrive_core::{Credentials, native::discover};
use serde::Deserialize;
use std::{io::Read, path::Path, sync::Arc};

const USAGE: &str = "idrive-bench FIXTURE REMOTE_DIRECTORY OUTPUT_DIRECTORY [REPEATS] [CONCURRENCIES_CSV] [JOBS]\n\nDefaults: 3 repeats, concurrency levels 1,2,4,8, and 8 files per sample.\nProvide {username,password,private_key?} as JSON on stdin. Credentials are never command-line arguments.\nUploads generated files to REMOTE_DIRECTORY and verifies each download with SHA-256. Remote fixtures are retained; successful local downloads are removed.";

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
    private_key: Option<String>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "help" | "-h" | "--help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !(3..=6).contains(&args.len()) {
        return Err(format!("expected 3 to 6 arguments\n{USAGE}").into());
    }
    let settings = runner::Settings {
        repeats: args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(3),
        concurrency_levels: args
            .get(4)
            .map(String::as_str)
            .unwrap_or("1,2,4,8")
            .split(',')
            .map(str::parse)
            .collect::<Result<Vec<usize>, _>>()?,
        jobs: args.get(5).map(|s| s.parse()).transpose()?.unwrap_or(8),
    };
    settings.validate()?;
    let mut input = zeroize::Zeroizing::new(String::new());
    std::io::stdin().take(65536).read_to_string(&mut input)?;
    let login: Login = serde_json::from_str(&input)?;
    let credentials = Arc::new(Credentials::new(
        login.username,
        login.password,
        login.private_key,
    ));
    let endpoints = discover(&credentials).await?;
    runner::run(
        &endpoints,
        credentials,
        Path::new(&args[0]),
        &args[1],
        Path::new(&args[2]),
        &settings,
    )
    .await?;
    Ok(())
}
