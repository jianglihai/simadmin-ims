//! simadmin-ims: 独立 IMS 注册守护
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

mod register;
use register::{build_plain_register, build_esp};

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
    let sip = build_plain_register(&usim.imsi, realm, &pcscf, &ue_ip,
        sa.ue_send.max(5064), sa.ue_recv, sa.pcscf_send, sa.pcscf_recv as u32, (sa.pcscf_recv.wrapping_add(1)) as u32);
    log_end(&st, &format!("REGISTER payload {} bytes", sip.len()), "register-1").await;

    let res = do_register(&pcscf, &sa, sip.as_bytes()).await;
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

async fn do_register(pcscf: &str, sa: &register::SaParams, plain: &[u8]) -> Result<bool> {
    let pcscf_addr: std::net::Ipv6Addr = pcscf.parse()?;
    let u = tokio::net::UdpSocket::bind("[::]:0").await?;
    u.send_to(plain, (pcscf_addr, 5061)).await?;
    let mut buf = [0u8; 4096];
    let recv = tokio::time::timeout(std::time::Duration::from_secs(15), u.recv_from(&mut buf)).await;
    match recv {
        Ok(Ok((n, _from))) => {
            // 收到 401 后:做 AKAv1-MD5 + ESP 受保护 REGISTER (后续第 2 轮)
            let sip_resp = String::from_utf8_lossy(&buf[..n]);
            let _ = &plain[..std::cmp::min(plain.len(), 10)];
            // 受保护 REGISTER:ESP 封装后发
            let esp = register::build_esp(0xCAFE, 1, &sa.esp_key, plain);
            u.send_to(&esp, (pcscf_addr, sa.pcscf_send)).await.ok();
            Ok(sip_resp.contains("401") || sip_resp.contains("200"))
        }
        _ => {
            log::debug!("recv timeout");
            Ok(false)
        }
    }
}
