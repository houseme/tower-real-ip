use axum::{Router, routing::get};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_real_ip::{RealIp, RealIpLayer, TrustedProxyConfig};

/// Simulate environment variables
fn set_mock_env() {
    // Allow local loopbacks, allow 10.0.0.0/8 intranets, allow a segment of Cloudflare
    // Format: Semicolon splitting, supports CIDR and single IP
    unsafe {
        std::env::set_var("TRUSTED_PROXIES", "127.0.0.1;10.0.0.0/8;192.168.1.50");
    }
}

async fn handler(
    // Extracted directly as a parameter for Axum
    RealIp(ip): RealIp,
    // Get the original connection information for comparison
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> String {
    format!(
        "🔒 Verified Real IP: {:?}\n🔌 Raw Connection IP: {:?}",
        ip,
        addr.ip()
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    set_mock_env();

    // 1. Initialize the configuration
    let config =
        TrustedProxyConfig::from_env("TRUSTED_PROXIES").expect("Failed to parse trusted proxies");

    println!("Config loaded successfully.");

    // 2. Build apps
    let app = Router::new()
        .route("/", get(handler))
        // 3. Register middleware
        .layer(RealIpLayer::new(config));

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("🚀 Server running on http://0.0.0.0:3000");

    // 4. Start the service (connect_info must be turned on)
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
