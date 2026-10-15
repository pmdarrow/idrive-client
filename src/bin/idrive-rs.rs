use idrive_core::{
    Credentials,
    native::{Session, discover},
};
use serde::Deserialize;
use std::{io::Read, sync::Arc, time::Instant};

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
    let operation = std::env::args().nth(1).unwrap_or_else(|| "help".into());
    if matches!(operation.as_str(), "help" | "-h" | "--help") {
        println!(
            "idrive-rs discover|handshake\n  list [REMOTE_DIRECTORY]\n  mkdir REMOTE_DIRECTORY\n  upload LOCAL_FILE REMOTE_FILE\n  download REMOTE_FILE LOCAL_FILE\n\nProvide {{username,password,private_key?}} as JSON on stdin. Credentials are never command-line arguments. Downloads refuse to overwrite local files."
        );
        return Ok(());
    }
    match operation.as_str() {
        "discover" | "handshake" | "mkdir" | "download" | "upload" | "devices" | "list" => {}
        _ => return Err("unknown command".into()),
    }
    let mut input = zeroize::Zeroizing::new(String::new());
    std::io::stdin().take(65536).read_to_string(&mut input)?;
    let login: Login = serde_json::from_str(&input)?;
    let credentials = Arc::new(Credentials::new(
        login.username,
        login.password,
        login.private_key,
    ));
    let start = Instant::now();
    let endpoints = discover(&credentials).await?;
    match operation.as_str() {
        "mkdir" => {
            let path = std::env::args().nth(2).ok_or("remote path required")?;
            Session::mkdir(&endpoints, credentials, &path).await?;
            println!("{}", serde_json::json!({"created":true}));
        }
        "download" => {
            let remote = std::env::args().nth(2).ok_or("remote path required")?;
            let local = std::env::args().nth(3).ok_or("local path required")?;
            let size = Session::download(
                &endpoints,
                credentials,
                &remote,
                std::path::Path::new(&local),
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({"bytes":size,"elapsed_seconds":start.elapsed().as_secs_f64()})
            );
        }
        "upload" => {
            let local = std::env::args().nth(2).ok_or("local path required")?;
            let remote = std::env::args().nth(3).ok_or("remote path required")?;
            let size = Session::upload(
                &endpoints,
                credentials,
                std::path::Path::new(&local),
                &remote,
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({"bytes":size,"elapsed_seconds":start.elapsed().as_secs_f64()})
            );
        }
        "discover" => println!(
            "{}",
            serde_json::json!({"discovered":true,"elapsed_seconds":start.elapsed().as_secs_f64()})
        ),
        "handshake" => {
            let _ = Session::connect(&endpoints, credentials, 21).await?;
            println!(
                "{}",
                serde_json::json!({"authenticated":true,"elapsed_seconds":start.elapsed().as_secs_f64()})
            );
        }
        "devices" | "list" => {
            let devices = Session::list(
                &endpoints,
                credentials,
                &std::env::args().nth(2).unwrap_or_else(|| "/".into()),
            )
            .await?;
            println!(
                "{}",
                serde_json::json!({"entries":devices,"elapsed_seconds":start.elapsed().as_secs_f64()})
            );
        }
        _ => return Err("unknown command".into()),
    }
    Ok(())
}
