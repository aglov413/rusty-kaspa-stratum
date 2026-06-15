//! HTTP listener, request routing, and server entrypoints.
//!
//! **Threat model:** binds via [`crate::net_utils::bind_addr_for_operator_http`] (typically loopback).
//! Meant for a trusted LAN or VPN, not a public multi-tenant API. `POST /api/config` is disabled unless
//! [`config_write_allowed`] is true. JSON responses include `X-Content-Type-Options` and `Referrer-Policy`
//! without changing bodies or `Access-Control-Allow-Origin` behavior used by dashboards.
//!
//! Optional hardening for `/api/config` is in [`super::ops_access`] (bearer token, CSRF header, localhost-only,
//! POST rate limit). **TLS:** terminate HTTPS in front of the bridge (reverse proxy or load balancer).

use super::super::metrics::{filter_metric_families_for_instance, init_metrics};
use super::config_api::{
    config_write_allowed, get_config_json, get_web_status_config, update_config_from_json,
};
use super::ops_access::{ConfigRouteDeny, check_config_route_access};
use super::static_files::{content_type_for_path, try_read_static_file};
use super::stats_json::{get_stats_json, get_stats_json_all};
use crate::host_metrics::{geoip_effective, get_host_snapshot, host_metrics_compiled};
use crate::kaspaapi::node_status_for_api;
use crate::net_utils::bind_addr_for_operator_http;
use serde::Serialize;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;

/// Max time to wait for a client to send an HTTP request after connecting.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
struct WebStatusResponse {
    kaspad_address: String,
    /// Duplicates `node.serverVersion` for backward compatibility with older dashboards.
    kaspad_version: String,
    instances: usize,
    web_bind: String,
    /// Whether the binary was built with `rkstratum_host_metrics`.
    host_metrics_enabled: bool,
    /// Geo-IP lookup is active (`rkstratum_geoip` + `approximate_geo_lookup` enabled via config, CLI, or API).
    geoip_enabled: bool,
    node: crate::kaspaapi::NodeStatusApi,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<crate::host_metrics::HostSnapshot>,
}

#[derive(Clone, Debug)]
pub(crate) enum HttpMode {
    Aggregated {
        web_bind: String,
    },
    Instance {
        instance_id: String,
        web_bind: String,
    },
}

fn json_ok_headers(content_len: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
        content_len
    )
}

fn json_forbidden_headers(content_len: usize) -> String {
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n",
        content_len
    )
}

fn json_deny_response(deny: ConfigRouteDeny) -> String {
    let body = deny.json_body();
    let status = match deny.status_code() {
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        429 => "429 Too Many Requests",
        _ => "403 Forbidden",
    };
    format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
        status,
        body.len(),
        body
    )
}

async fn write_response(
    mut stream: tokio::net::TcpStream,
    response: String,
    body_bytes: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(response.as_bytes()).await?;
    if let Some(body) = body_bytes {
        stream.write_all(&body).await?;
    }
    let _ = stream.shutdown().await;
    Ok(())
}

async fn send_response(
    mut stream: tokio::net::TcpStream,
    response: impl AsRef<[u8]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;
    stream.write_all(response.as_ref()).await?;
    let _ = stream.shutdown().await;
    Ok(())
}

pub(crate) async fn handle_http_request(
    stream: tokio::net::TcpStream,
    request: &str,
    mode: &HttpMode,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let path = path.split('?').next().unwrap_or(path);
    let path = path.split('#').next().unwrap_or(path);

    if request.starts_with("GET /") && path == "/metrics" {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let metric_families = match mode {
            HttpMode::Aggregated { .. } => prometheus::gather(),
            HttpMode::Instance { instance_id, .. } => {
                filter_metric_families_for_instance(prometheus::gather(), instance_id)
            }
        };
        let mut buf = Vec::new();
        encoder.encode(&metric_families, &mut buf)?;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nContent-Length: {}\r\n\r\n{}",
            buf.len(),
            String::from_utf8_lossy(&buf)
        );
        send_response(stream, response).await?;
        return Ok(());
    }

    if request.starts_with("GET /api/status") {
        let node = node_status_for_api();
        let kaspad_version = node
            .server_version
            .clone()
            .unwrap_or_else(|| "-".to_string());
        let status_cfg = get_web_status_config();
        let web_bind = match mode {
            HttpMode::Aggregated { web_bind } => web_bind.clone(),
            HttpMode::Instance { web_bind, .. } => web_bind.clone(),
        };

        let host = get_host_snapshot();
        let status = WebStatusResponse {
            kaspad_address: status_cfg.kaspad_address,
            kaspad_version,
            instances: status_cfg.instances,
            web_bind,
            host_metrics_enabled: host_metrics_compiled(),
            geoip_enabled: geoip_effective(),
            node,
            host,
        };
        let json = serde_json::to_string(&status).unwrap_or_else(|_| "{}".to_string());
        let response = format!("{}{}", json_ok_headers(json.len()), json);
        send_response(stream, response).await?;
        return Ok(());
    }

    if request.starts_with("GET /api/host") {
        let body = match get_host_snapshot() {
            Some(h) => serde_json::to_string(&h).unwrap_or_else(|_| "{}".to_string()),
            None => r#"{"available":false,"message":"Host metrics disabled (minimal build: omit --no-default-features or add --features rkstratum_host_metrics) or not yet collected"}"#.to_string(),
        };
        let response = format!("{}{}", json_ok_headers(body.len()), body);
        send_response(stream, response).await?;
        return Ok(());
    }

    if request.starts_with("GET /api/stats") {
        let stats = match mode {
            HttpMode::Aggregated { .. } => get_stats_json_all().await,
            HttpMode::Instance { instance_id, .. } => get_stats_json(instance_id).await,
        };
        let json = serde_json::to_string(&stats).unwrap_or_else(|_| "{}".to_string());
        let response = format!("{}{}", json_ok_headers(json.len()), json);
        send_response(stream, response).await?;
        return Ok(());
    }

    if matches!(mode, HttpMode::Instance { .. }) && request.starts_with("GET /api/config") {
        if let Err(deny) = check_config_route_access(request, peer.ip(), false) {
            let response = json_deny_response(deny);
            send_response(stream, response).await?;
            return Ok(());
        }
        let config_json = get_config_json().await;
        let response = format!("{}{}", json_ok_headers(config_json.len()), config_json);
        send_response(stream, response).await?;
        return Ok(());
    }

    if matches!(mode, HttpMode::Instance { .. }) && request.starts_with("POST /api/config") {
        if let Err(deny) = check_config_route_access(request, peer.ip(), true) {
            let response = json_deny_response(deny);
            send_response(stream, response).await?;
            return Ok(());
        }
        if !config_write_allowed() {
            let json_response = r#"{"success": false, "message": "Config write disabled. Set RKSTRATUM_ALLOW_CONFIG_WRITE=1 to enable."}"#;
            let response = format!(
                "{}{}",
                json_forbidden_headers(json_response.len()),
                json_response
            );
            send_response(stream, response).await?;
            return Ok(());
        }

        let body_start = request.find("\r\n\r\n").unwrap_or(request.len());
        let body = &request[body_start + 4..];
        let result = update_config_from_json(body).await;
        let json_response = if result.is_ok() {
            r#"{"success": true, "message": "Config updated successfully. Bridge restart required for changes to take effect."}"#
        } else {
            r#"{"success": false, "message": "Failed to update config"}"#
        };
        let response = format!("{}{}", json_ok_headers(json_response.len()), json_response);
        send_response(stream, response).await?;
        return Ok(());
    }

    if request.starts_with("GET /") {
        if let Some((rel, bytes)) = try_read_static_file(path) {
            let ct = content_type_for_path(&rel);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                ct,
                bytes.len()
            );
            write_response(stream, response, Some(bytes)).await?;
        } else {
            send_response(stream, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n").await?;
        }
        return Ok(());
    }

    send_response(stream, "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n").await?;
    Ok(())
}

async fn handle_one_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    mode: HttpMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncReadExt;

    let started = std::time::Instant::now();
    let mut buffer = [0u8; 8192];

    match timeout(READ_TIMEOUT, stream.read(&mut buffer)).await {
        Ok(Ok(0)) => return Ok(()),
        Ok(Ok(n)) => {
            let request = String::from_utf8_lossy(&buffer[..n]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");
            handle_http_request(stream, &request, &mode, peer).await?;
            tracing::debug!(
                "Dashboard {} from {} handled in {:?}",
                path,
                peer,
                started.elapsed()
            );
        }
        Ok(Err(e)) => {
            tracing::debug!("Read error from {}: {}", peer, e);
        }
        Err(_) => {
            tracing::debug!(
                "Read timeout from {} after {:?} — closing stale connection",
                peer,
                READ_TIMEOUT
            );
        }
    }

    Ok(())
}

async fn serve_http_loop(
    listener: tokio::net::TcpListener,
    mode: HttpMode,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("TCP accept error on web dashboard: {}", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };

        let mode = mode.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one_connection(stream, peer, mode).await {
                tracing::debug!("Dashboard connection from {} ended with: {}", peer, e);
            }
        });
    }
}

pub async fn start_web_server_all(
    port: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    init_metrics();
    crate::host_metrics::spawn_host_metrics_task();

    let addr_str = bind_addr_for_operator_http(port);
    let addr: SocketAddr = addr_str.parse()?;
    let listener = TcpListener::bind(addr).await?;
    let web_bind_for_status = addr_str.clone();

    tracing::debug!("Hosting aggregated web stats on {}/", addr);
    serve_http_loop(
        listener,
        HttpMode::Aggregated {
            web_bind: web_bind_for_status,
        },
    )
    .await
}

/// Start Prometheus metrics server
pub async fn start_prom_server(
    port: &str,
    instance_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    init_metrics();
    crate::host_metrics::spawn_host_metrics_task();

    let instance_id = instance_id.to_string();

    let addr_str = bind_addr_for_operator_http(port);

    let addr: SocketAddr = addr_str.parse()?;
    let listener = TcpListener::bind(addr).await?;

    tracing::debug!("Hosting prom stats on {}/metrics", addr);
    serve_http_loop(
        listener,
        HttpMode::Instance {
            instance_id,
            web_bind: addr_str,
        },
    )
    .await
}
