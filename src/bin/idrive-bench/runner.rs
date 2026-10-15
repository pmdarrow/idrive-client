//! Transfer benchmark with per-file SHA-256 verification.
use idrive_core::{
    Credentials, Error, Result,
    native::{Endpoints, Session},
};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Instant};
use tokio::{io::AsyncReadExt, sync::Semaphore, task::JoinSet};

async fn sha256(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buffer = vec![0; 1024 * 1024];
    let mut hash = Sha256::new();
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub struct Settings {
    pub repeats: usize,
    pub concurrency_levels: Vec<usize>,
    pub jobs: usize,
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        if !(1..=10).contains(&self.repeats) {
            return Err(Error::Frame("benchmark repeats must be 1..10"));
        }
        if self.concurrency_levels.is_empty()
            || self
                .concurrency_levels
                .iter()
                .any(|n| !(1..=32).contains(n) || *n > self.jobs)
            || !(1..=64).contains(&self.jobs)
        {
            return Err(Error::Frame("invalid benchmark concurrency or job count"));
        }
        Ok(())
    }
}

pub async fn run(
    endpoints: &Endpoints,
    credentials: Arc<Credentials>,
    fixture: &Path,
    remote: &str,
    output: &Path,
    settings: &Settings,
) -> Result<()> {
    settings.validate()?;
    let repeats = settings.repeats;
    let levels = &settings.concurrency_levels;
    let jobs = settings.jobs;
    let size = tokio::fs::metadata(fixture).await?.len();
    let expected = sha256(fixture).await?;
    tokio::fs::create_dir_all(output).await?;
    Session::mkdir(endpoints, credentials.clone(), remote).await?;
    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Frame("invalid system time"))?
        .as_millis();
    println!(
        "{}",
        serde_json::json!({"event":"benchmark_start","run_id":run_id,"fixture_bytes":size,"fixture_sha256":expected,"jobs":jobs,"concurrency_levels":levels,"repeats":repeats,"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"available_parallelism":std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1),"version":env!("CARGO_PKG_VERSION"),"timing":"includes per-file authentication and completion, excludes discovery and SHA256 verification"})
    );
    for repeat in 0..repeats {
        let mut order = levels.to_vec();
        if repeat % 2 == 1 {
            order.reverse();
        }
        for concurrency in order {
            let mut complete = false;
            for attempt in 0..3 {
                let mut local_paths = Vec::new();
                let mut remote_paths = Vec::new();
                for index in 0..jobs {
                    let name =
                        format!("r{run_id}-p{repeat}-c{concurrency}-a{attempt}-f{index}.bin");
                    remote_paths.push(format!("{}/{name}", remote.trim_end_matches('/')));
                    local_paths.push(output.join(name));
                }
                let mut failed = false;
                for direction in ["upload", "download"] {
                    let permits = Arc::new(Semaphore::new(concurrency));
                    let start = Instant::now();
                    let mut tasks = JoinSet::new();
                    for index in 0..jobs {
                        let permits = permits.clone();
                        let endpoints = endpoints.clone();
                        let credentials = credentials.clone();
                        let local = if direction == "upload" {
                            fixture.to_path_buf()
                        } else {
                            local_paths[index].clone()
                        };
                        let remote = remote_paths[index].clone();
                        tasks.spawn(async move {
                            let _permit =
                                permits.acquire_owned().await.map_err(|_| Error::Closed)?;
                            if direction == "upload" {
                                Session::upload(&endpoints, credentials, &local, &remote).await
                            } else {
                                Session::download(&endpoints, credentials, &remote, &local).await
                            }
                        });
                    }
                    let mut bytes = 0u64;
                    let mut errors = Vec::new();
                    while let Some(result) = tasks.join_next().await {
                        match result {
                            Ok(Ok(n)) => bytes += n,
                            Ok(Err(e)) => errors.push(e.to_string()),
                            Err(_) => errors.push("worker failed".to_owned()),
                        }
                    }
                    let seconds = start.elapsed().as_secs_f64();
                    if !errors.is_empty() || bytes != size * jobs as u64 {
                        println!(
                            "{}",
                            serde_json::json!({"event":"measurement_failure","run_id":run_id,"repeat":repeat,"attempt":attempt,"direction":direction,"concurrency":concurrency,"successful_bytes":bytes,"seconds":seconds,"errors":errors})
                        );
                        failed = true;
                        break;
                    }
                    if direction == "download" {
                        for path in &local_paths {
                            if sha256(path).await? != expected {
                                return Err(Error::Frame("benchmark SHA256 mismatch"));
                            }
                        }
                    }
                    println!(
                        "{}",
                        serde_json::json!({"event":"measurement","run_id":run_id,"repeat":repeat,"attempt":attempt,"direction":direction,"concurrency":concurrency,"files":jobs,"bytes":bytes,"seconds":seconds,"mib_per_second":bytes as f64/1048576.0/seconds,"sha256_verified":direction=="download"})
                    );
                }
                for path in &local_paths {
                    match tokio::fs::remove_file(path).await {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if !failed {
                    complete = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500 * (attempt + 1) as u64))
                    .await;
            }
            if !complete {
                return Err(Error::Frame(
                    "benchmark wave failed three attempts; see failure records",
                ));
            }
        }
    }
    println!(
        "{}",
        serde_json::json!({"event":"benchmark_complete","run_id":run_id,"all_downloads_sha256_verified":true})
    );
    Ok(())
}
