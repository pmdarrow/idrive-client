//! Local codec throughput without networking, credentials, or disk I/O.
use idrive_core::crypto::CommandCipher;
use std::{hint::black_box, time::Instant};
fn main() {
    let cipher = CommandCipher::greeting();
    let payload = vec![0x5a; 32768];
    let iterations = std::env::args()
        .nth(1)
        .map(|v| v.parse::<usize>().expect("iteration count"))
        .unwrap_or(8192);
    let mut encrypted = Vec::new();
    let start = Instant::now();
    for _ in 0..iterations {
        encrypted = black_box(cipher.encrypt_bytes(black_box(&payload)));
    }
    let encrypt_seconds = start.elapsed().as_secs_f64();
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(cipher.decrypt_bytes(black_box(&encrypted)).unwrap());
    }
    let decrypt_seconds = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({"bytes_per_direction":payload.len()*iterations,"encrypt_seconds":encrypt_seconds,"decrypt_seconds":decrypt_seconds,"encrypt_mib_per_second":(payload.len()*iterations) as f64/1048576.0/encrypt_seconds,"decrypt_mib_per_second":(payload.len()*iterations) as f64/1048576.0/decrypt_seconds})
    );
}
