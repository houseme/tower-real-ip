//! # Tower Real IP
//!
//! A robust middleware for extracting the real client IP address from HTTP requests,
//! designed for environments behind trusted proxies (Load Balancers, CDNs, Nginx).
//!
//! ## Features
//! - Supports `X-Forwarded-For` parsing (Right-to-Left security traversal).
//! - Supports CIDR ranges (IPv4 & IPv6).
//! - Auto-configuration from Environment Variables (split by `;`).
//! - Axum 0.8 Extractor support.

use axum::extract::{ConnectInfo, FromRequestParts};
use http::{Request, Response, request::Parts};
use ipnetwork::IpNetwork;
use std::{
    env,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{debug, warn};

// ============================================================================
//  1. Configuration Logic
// ============================================================================

/// Configuration holding the list of trusted networks.
#[derive(Clone, Debug)]
pub struct TrustedProxyConfig {
    trusted_networks: Arc<Vec<IpNetwork>>,
}

impl TrustedProxyConfig {
    /// Creates a new config from a list of IP networks.
    pub fn new(networks: Vec<IpNetwork>) -> Self {
        Self {
            trusted_networks: Arc::new(networks),
        }
    }

    /// Loads configuration from an environment variable.
    ///
    /// Expected format: "127.0.0.1;10.0.0.0/8;::1"
    pub fn from_env(env_key: &str) -> Result<Self, String> {
        let val =
            env::var(env_key).map_err(|_| format!("Environment variable {} not found", env_key))?;
        Self::parse_str(&val)
    }

    /// Parses a string separated by `;` into trusted networks.
    pub fn parse_str(input: &str) -> Result<Self, String> {
        let mut networks = Vec::new();
        for part in input.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            // Try parsing as CIDR first, then as single IP
            match part.parse::<IpNetwork>() {
                Ok(net) => networks.push(net),
                Err(_) => match part.parse::<IpAddr>() {
                    Ok(ip) => networks.push(IpNetwork::from(ip)),
                    Err(_) => return Err(format!("Invalid IP or CIDR: {}", part)),
                },
            }
        }

        debug!("Loaded {} trusted proxy networks", networks.len());
        Ok(Self::new(networks))
    }

    /// Checks if an IP is trusted.
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.trusted_networks.iter().any(|net| net.contains(*ip))
    }
}

// ============================================================================
//  2. The Result Struct (What the user gets)
// ============================================================================

/// The resolved real IP address of the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealIp(pub IpAddr);

// ============================================================================
//  3. Tower Middleware Implementation
// ============================================================================

#[derive(Clone)]
pub struct RealIpLayer {
    config: TrustedProxyConfig,
}

impl RealIpLayer {
    pub fn new(config: TrustedProxyConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for RealIpLayer {
    type Service = RealIpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RealIpService {
            inner,
            config: self.config.clone(),
        }
    }
}

#[derive(Clone)]
pub struct RealIpService<S> {
    inner: S,
    config: TrustedProxyConfig,
}

impl<S, B> Service<Request<B>> for RealIpService<S>
where
    S: Service<Request<B>, Response = Response<B>> + Send + Clone + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        // 1. Extract the direct connection IP (Peer Address)
        // Axum/Tower usually provides this via ConnectInfo extension
        let remote_addr = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip());

        let config = self.config.clone();
        let headers = req.headers().clone(); // Clone headers to use in async block

        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut resolved_ip = remote_addr.unwrap_or_else(|| {
                // Fallback if no underlying TCP info is present (shouldn't happen in normal HTTP serving)
                IpAddr::from([0, 0, 0, 0])
            });

            // 2. The Core Algorithm: Trusted Proxy Traversal
            if let Some(peer_ip) = remote_addr {
                // Only attempt to parse headers if the direct peer is trusted
                if config.is_trusted(&peer_ip)
                    && let Some(xff_val) = headers.get("x-forwarded-for")
                    && let Ok(xff_str) = xff_val.to_str()
                {
                    // Parse the comma-separated list
                    // List: Client, Proxy1, Proxy2
                    // We reverse iterate: Proxy2 -> Proxy1 -> Client
                    let ips: Vec<&str> = xff_str.split(',').map(|s| s.trim()).collect();

                    for ip_str in ips.iter().rev() {
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            if !config.is_trusted(&ip) {
                                // Found the first untrusted IP (looking backwards)
                                // This is the Client.
                                resolved_ip = ip;
                                break;
                            }
                            // If trusted, continue strictly to the left
                        } else {
                            warn!("Skipping invalid IP in X-Forwarded-For: {}", ip_str);
                        }
                    }
                    // Edge case: If all IPs in header are trusted, the loop finishes.
                    // The `resolved_ip` remains the last trusted one (or peer),
                    // but technically if strictly all are trusted, the request originates
                    // from your internal network. We keep the peer or last logic.
                }
            }

            // 3. Inject the result into extensions
            req.extensions_mut().insert(RealIp(resolved_ip));

            // 4. Forward request
            inner.call(req).await
        })
    }
}

// ============================================================================
//  4. Axum Extractor Support
// ============================================================================

/// Allows using `RealIp` directly in Axum handlers arguments.
///
/// Example:
/// `async fn handler(RealIp(ip): RealIp) -> ...`
impl<S> FromRequestParts<S> for RealIp
where
    S: Send + Sync,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<RealIp>().cloned().ok_or((
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "RealIp middleware is not configured correctly. Missing RealIp extension.",
        ))
    }
}
