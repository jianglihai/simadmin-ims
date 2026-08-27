//! simadmin-ims: standalone IMS/VoLTE daemon beside SimAdmin.
use anyhow::Result;
use std::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    let bind = std::env::var("IMS_BIND").unwrap_or_else(|_| "[::]:3001".to_string());
    let listener = TcpListener::bind(&bind).await?;
    eprintln!("[simadmin-ims] listening on {:?}", listener.local_addr());
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => { error!("accept: {e}"); continue }
        };
        tokio::spawn(async move { handle(&mut stream).await; });
    }
}

async fn handle(stream: &mut TcpStream) {
    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n == 0 => return,
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let line = req.lines().next().unwrap_or("");
    let mut path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    if let Some(q) = path.find('?') { path = path[..q].to_string(); }
    let (code, ctype, body) = match path.as_str() {
        "/api/ims/status" => {
            ("200 OK", "application/json", r#"{"status":"ok","registered":false,"registering":false,"daemon":true,"ims_domain":"ims.mnc001.mcc460.gprs","log":"pending: IMS bring-up not yet implemented","version":"simadmin-ims v0.2"}"#)
        }
        "/api/ims/register" => {
            ("200 OK", "application/json", r#"{"ok":false,"msg":"pending: IMS bring-up not yet implemented"}"#)
        }
        "/api/ims/unregister" => {
            ("200 OK", "application/json", r#"{"ok":false,"msg":"pending"}"#)
        }
        "/ims.html" | "/" => ("200 OK", "text/html; charset=utf-8", include_str!("../www/ims.html")),
        _ => ("200 OK", "text/html; charset=utf-8", include_str!("../www/ims.html")),
    };
    // if it's an .js request return a stub until we bundle; serve ims.js inline placeholder
    let (ctype, body) = if path.ends_with(".js") {
        ("application/javascript", include_str!("../www/ims.js"))
    } else {
        (ctype, body)
    };
    let resp = format!("HTTP/1.1 {code}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n{}", body.len(), body);
    let _ = stream.write_all(resp.as_bytes()).await;
}
