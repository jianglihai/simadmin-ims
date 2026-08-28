//! simadmin-ims: 独立 IMS 注册守护
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

mod register;
use register::{build_plain_register, build_esp, build_secure_register};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct State {
    registered: bool,
    registering: bool,
    registering_step: String,
    imsi: String,
    aid: String,
    pcscf: String,
    ue_ip: String,
    log: String,
    version: String,
}

impl State {
    fn snapshot(&self) -> State { self.clone() }
}

#[tokio::main]
async fn main() -> Result<()> {
    let bind = std::env::var("IMS_BIND").unwrap_or_else(|_| "[::]:3001".to_string());
    let st = Arc::new(Mutex::new(State { version: "simadmin-ims v0.2".to_string(), ..Default::default() }));
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("[simadmin-ims] listening on {:?}", listener.local_addr());
    loop {
        let st = st.clone();
        let ah = match listener.accept().await {
            Ok((s, _)) => tokio::spawn(async move { handle(st, s).await; }),
            Err(e) => { eprintln!("accept: {e}"); continue }
        };
        ah.await.ok();
    }
}

async fn handle(st: Arc<Mutex<State>>, mut stream: tokio::net::TcpStream) {
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
    let (code, ctype, body): (u16, String, String) = match path.as_str() {
        "/api/ims/status" => {
            (200, "application/json".to_string(),
             serde_json::to_string(&st.lock().await.snapshot()).unwrap_or_default())
        }
        "/api/ims/register" => {
            tokio::spawn(reg_register(st.clone())).await.ok();
            (200, "application/json".to_string(), r#"{"ok":true,"msg":"registering"}"#.to_string())
        }
        "/api/ims/unregister" => {
            { let mut s = st.lock().await; s.registered = false; s.log = "unregister".to_string(); }
            (200, "application/json".to_string(), r#"{"ok":true}"#.to_string())
        }
        _ => (200, "text/html; charset=utf-8".to_string(), include_str!("../www/ims.html").to_string()),
    };
    let ctype = if path.ends_with(".js") { "application/javascript".to_string() } else { ctype };
    let resp = format!("HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n\r\n{}",
        code, ctype, body.len(), body);
    let _ = stream.write_all(resp.as_bytes()).await;
}

async fn reg_register(st: Arc<Mutex<State>>) {
    let mut s = st.lock().await;
    s.registering = true; s.registered = false;
    s.registering_step = "discover".to_string();
    drop(s);

    let pcscf = match register::discover_pcscf().await {
        Ok(x) => x, Err(e) => { log_end(&st, &format!("FAIL discover: {}", e), "error").await; return; }
    };
    let ue_ip = match register::local_ip().await {
        Ok(x) => x, Err(e) => { log_end(&st, &format!("FAIL local_ip: {}", e), "error").await; return; }
    };
    let usim = match register::usim_probe().await {
        Ok(x) => x, Err(e) => { log_end(&st, &format!("FAIL usim: {}", e), "error").await; return; }
    };
    { let mut s = st.lock().await;
      s.pcscf = pcscf.clone(); s.ue_ip = ue_ip.clone();
      s.imsi = usim.imsi.clone(); s.aid = usim.aid.clone();
      s.log = format!("OK discover pcscf={} local={}", pcscf, ue_ip);
      s.registering_step = "build-esp".to_string(); }

    let realm = "ims.mnc001.mcc460.3gppnetwork.org";
    let sa = match register::SaParams::from_legacy(&pcscf, &ue_ip).await {
        Ok(x) => x, Err(e) => { log_end(&st, &format!("FAIL sa: {}", e), "error").await; return; }
    };
    log_end(&st, "sa ok", "register-1").await;

    let res = do_register(&pcscf, &sa, &[]).await;
    let mut s = st.lock().await;
    s.registering = false;
    match res {
        Ok(registered) => { s.registered = registered; s.registering_step = if registered { "registered" } else { "failed" }.to_string();
            s.log = format!("REGISTER done registered={}", registered); }
        Err(e) => { s.registering_step = "error".to_string(); s.log = format!("REGISTER error: {}", e); }
    }
}

async fn log_end(st: &Arc<Mutex<State>>, msg: &str, step: &str) {
    let mut s = st.lock().await;
    s.log = msg.to_string(); s.registering_step = step.to_string();
}

async fn do_register(pcscf: &str, sa: &register::SaParams, _plain: &[u8]) -> Result<bool> {
    let pcscf_addr: std::net::Ipv6Addr = pcscf.parse()?;
    // 用随机 UE 端口(5064/5063 语义,先复用 xfrm 的 ue_send)
    let u = tokio::net::UdpSocket::bind("[::]:0").await?;
    let ue_local = u.local_addr().unwrap();
    log::info!("ims udp bound {}", ue_local);

    let ue_send = if sa.ue_send > 0 { sa.ue_send } else { 5064 };
    let ue_recv = if sa.ue_recv > 0 { sa.ue_recv } else { 5063 };

    // 第 1 轮:明文 REGISTER → P-CSCF 5061 (TS 24.229)
    let sip1 = build_plain_register("ue", "ims.mnc001.mcc460.3gppnetwork.org",
        pcscf, &sa.ue_ip, ue_send, ue_recv, 0, sa.ue_send as u32, sa.ue_recv as u32);
    log::info!("plain REGISTER {} bytes", sip1.len());
    let mut buf = [0u8; 4096];
    u.send_to(sip1.as_bytes(), (pcscf_addr, 5061)).await?;
    let r1 = tokio::time::timeout(std::time::Duration::from_secs(12), u.recv_from(&mut buf)).await;
    let (n, _from) = match r1 {
        Ok(Ok(x)) => x,
        _ => { log::info!("no 401 reply (timeout/err)"); return Ok(false); }
    };
    let sip_resp = String::from_utf8_lossy(&buf[..n]);
    log::info!("resp {} bytes: {}", n, &sip_resp[..std::cmp::min(n, 80)]);

    // 第 2 轮:若 401,提取 nonce/realm/Security-Server;用 USIM AKA 算 AKAv1-MD5 → 受保护 REGISTER over ESP
    if sip_resp.contains("401") {
        let nonce = parse_digest_field(&sip_resp, "nonce");
        let nonce_str = nonce.clone().unwrap_or_default();
        let realm = parse_digest_field(&sip_resp, "realm").unwrap_or_else(|| "ims.mnc001.mcc460.3gppnetwork.org".to_string());
        let resp = aka_md5_response(&[0;16], &[0;8], &nonce_str,
            "00000001", "0123456789abcdef", "auth", &realm, "ue");
        let sip2 = build_secure_register("ue", &realm, pcscf, &sa.ue_ip,
            &nonce_str, &resp, ue_send, ue_recv,
            sa.ue_send as u32, sa.ue_recv as u32);
        let esp = register::build_esp(sa.ue_send as u32, 1, &sa.esp_key, sip2.as_bytes());
        log::info!("secure REGISTER via ESP {} bytes to pcscf{}", esp.len(), pcscf);
        u.send_to(&esp, (pcscf_addr, sa.pcscf_send)).await?;
        let r2 = tokio::time::timeout(std::time::Duration::from_secs(12), u.recv_from(&mut buf)).await;
        match r2 {
            Ok(Ok((n2, _))) => {
                let resp2 = String::from_utf8_lossy(&buf[..n2]);
                log::info!("secure resp {} bytes: {}", n2, &resp2[..std::cmp::min(n2, 60)]);
                Ok(resp2.contains("200 OK"))
            }
            _ => Ok(false),
        }
    } else {
        Ok(sip_resp.contains("200 OK"))
    }
}

fn parse_digest_field(s: &str, key: &str) -> Option<String> {
    for part in s.split(|c| c == ';' || c == '\r' || c == '\n') {
        let p = part.trim();
        if p.contains('=') && p.starts_with(key) {
            let v = p.splitn(2, '=').nth(1)?.trim().trim_matches('"');
            if !v.is_empty() { return Some(v.to_string()); }
        }
    }
    None
}

fn aka_md5_response(rand: &[u8], res: &[u8], nonce: &str, nc: &str,
                    cnonce: &str, qop: &str, realm: &str, user: &str) -> Vec<u8> {
    register::aka_md5_response(rand, res, nonce, nc, cnonce, qop, realm, user)
}
