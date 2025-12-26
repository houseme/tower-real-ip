# tower-real-ip

A Tower middleware for extracting the real client IP address from various headers.

## installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tower-real-ip = "0.1"
```

## usage

```rust
use tower_real_ip::RealIpLayer;
use tower::ServiceBuilder;

let service = ServiceBuilder::new()
.layer(RealIpLayer::new())
.service(your_service);
```

## license

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details