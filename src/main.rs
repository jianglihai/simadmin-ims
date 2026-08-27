//! simadmin-ims: standalone IMS/VoLTE daemon beside SimAdmin.
use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};

async fn handle(stream: &mut TcpStream) {
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n == 0 => return,
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    let (status, body) = if line.contains("/api/ims/status")
        || line.contains("/") && !line.contains("/assets") {
        ("200 OK", r#"{"status":"ok","registered":false,"daemon":"simadmin-ims v0.1"}"#)
    } else { ("404 Not Found", "{}") };
    let resp = format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}", body.len(), body);
    let _ = stream.write_all(resp.as_bytes()).await;
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    info!("simadmin-ims starting");
    let bind = std::env::var("IMS_BIND").unwrap_or_else(|_| "[::]:3001".to_string());
    let listener = TcpListener::bind(&bind).await?;
    info!("listening on {:?}", listener.local_addr());
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => { error!("accept: {e}"); continue }
        };
        tokio::spawn(async move { handle(&mut stream).await; });
    }
}
