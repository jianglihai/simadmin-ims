//! simadmin-ims: 独立 IMS 注册守护
use anyhow::{anyhow, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

mod register;
use register::{build_esp};

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
      s.registering_step = "init-bearer".to_string(); }

    // IMS bearer: keep qmicli attached to at0 (raw-ip) so wwan1 stays UP.
    // qmicli holds the PDP; if it exits the bearer dies (1.1.6 pattern).
    let bearer = register::bearer_start("at0").await;
    if !bearer {
        log_end(&st, "FAIL bearer: wwan1 not up", "error").await; return;
    }
    log_end(&st, "bearer ok wwan1 UP", "init-bearer").await;

    let realm = "ims.mnc001.mcc460.3gppnetwork.org";
    let sa = match register::SaParams::from_live(&pcscf, &ue_ip).await {
        Ok(x) => x, Err(e) => { log_end(&st, &format!("FAIL sa: {}", e), "error").await; return; }
    };
    log_end(&st, "sa ok", "register-1").await;

    let res = do_register(&pcscf, &sa).await;
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

async fn do_register(pcscf: &str, sa: &register::SaParams) -> Result<bool> {
    let pcscf_addr: std::net::Ipv6Addr = pcscf.parse()?;
    let ts = || std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let realm = "ims.mnc001.mcc460.3gppnetwork.org";
    let ue_send = if sa.ue_send > 0 { sa.ue_send } else { 5064 };
    let ue_recv = if sa.ue_recv > 0 { sa.ue_recv } else { 5063 };
    let mut spi_c = sa.ue_send as u32; let mut spi_s = sa.ue_recv as u32;
    eprintln!("[ims] REGISTER ue_send={} ue_recv={} spi={}/{}", ue_send, ue_recv, spi_c, spi_s);

    // 第 1 轮:TCP/5060 明文 REGISTER,只带 Supported: sec-agree(TS 24.229)
    let t1 = ts();
    let plain = format!(
        "REGISTER sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/TCP [{}]:5063;branch=z9hG4bK{}\r\n\
         From: <sip:ue@{}>;tag=ue{}\r\n\
         To: <sip:ue@{}>\r\n\
         Call-ID: ims-{}@{}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:ue@{}:5063;transport=tcp>;ob\r\n\
         Supported: sec-agree\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        realm, sa.ue_ip, t1, realm, t1, realm, t1, sa.ue_ip, sa.ue_ip);
    eprintln!("[ims] plain REGISTER {} bytes", plain.len());
    let resp1 = match do_tcp(pcscf_addr, 5060, plain.as_bytes(), 12).await? {
        Some(r) => r, None => { eprintln!("[ims] no reply to plain"); return Ok(false); }
    };
    eprintln!("[ims] r1 len={} head={}", resp1.len(),
        String::from_utf8_lossy(&resp1[..std::cmp::min(resp1.len(), 60)]));

    if resp1.starts_with(b"SIP/2.0 200") { return Ok(true); }
    if !resp1.starts_with(b"SIP/2.0 401") {
        eprintln!("[ims] unexpected r1"); return Ok(false);
    }
    // 第 2 轮:解析 nonce + Security-Server,AKAv1-MD5 → 受保护 REGISTER
    let nonce = extract(&resp1, "nonce").unwrap_or_default();
    let sec_srv = extract(&resp1, "Security-Server").unwrap_or_default();
    let nonce_str = String::from_utf8_lossy(&nonce).to_string();
    let sec_srv_str = String::from_utf8_lossy(&sec_srv).trim().to_string();
    eprintln!("[ims] nonce={} sec-srv={}", nonce_str,
        sec_srv_str[..std::cmp::min(sec_srv_str.len(), 80)].to_string());

    // IMS AKA:nonce = base64(RAND || AUTN)。解出 RAND/AUTN 后交 USIM 算 RES/CK/IK。
    let chal = base64::engine::general_purpose::STANDARD
        .decode(nonce_str.trim().trim_matches('"'))
        .map_err(|e| anyhow!("nonce base64 解码失败: {}", e))?;
    if chal.len() < 32 { return Err(anyhow!("AKA 挑战长度异常: {} 字节", chal.len())); }
    let mut rand = [0u8; 16]; let mut autn = [0u8; 16];
    rand.copy_from_slice(&chal[..16]); autn.copy_from_slice(&chal[16..32]);
    let (xres, _ck, _ik) = register::usim_aka(&rand, &autn).await
        .map_err(|e| anyhow!("USIM AKA 失败(设备 QMI 未开放 AKA?): {}", e))?;
    eprintln!("[ims] AKA ok res_len={}", xres.len());
    let resp_digest = aka_md5_response(&rand, &xres, &nonce_str, "00000001",
        "0123456789abcdef", "auth", realm, "ue");
    let resp_hex: String = resp_digest.iter().map(|b| format!("{:02x}", b)).collect();
    let t2 = ts();
    let esp_key = sa.esp_key.clone();
    let protected = format!(
        "REGISTER sip:{} SIP/2.0\r\n\
         Via: SIP/2.0/TCP [{}]:5063;branch=z9hG4bK{}\r\n\
         From: <sip:ue@{}>;tag=ue{}\r\n\
         To: <sip:ue@{}>\r\n\
         Call-ID: ims-{}@{}\r\n\
         CSeq: 2 REGISTER\r\n\
         Contact: <sip:ue@{}:5063;transport=tcp>;ob\r\n\
         Authorization: Digest realm=\"{}\",username=\"ue\",nonce=\"{}\",uri=\"sip:{pcscf}\",algorithm=AKAv1-MD5,response=\"{rh}\",qop=auth,cnonce=\"0123456789abcdef\",nc=00000001\r\n\
         Security-Client: ipsec-3gpp; prot=esp; mod=trans; spi-c={spic}; spi-s={spis}; port-c={pc}; port-s=5063; alg=hmac-md5-96; ealg=null\r\n\
         Security-Verify: {sv}\r\n\
         Supported: sec-agree\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n",
        realm, sa.ue_ip, t2, realm, t2, realm, t2, sa.ue_ip, sa.ue_ip,
        realm, nonce_str, rh = resp_hex, spic = spi_c, spis = spi_s,
        pc = ue_send, sv = sec_srv_str);
    eprintln!("[ims] protected REGISTER {} bytes", protected.len());
    let esp = register::build_esp(spi_c, 1, &esp_key, protected.as_bytes());
    let r2 = do_tcp(pcscf_addr, sa.pcscf_send.max(5060), &esp, 12).await?;
    match r2 {
        Some(r) => { eprintln!("[ims] r2 len={} head={}", r.len(),
            String::from_utf8_lossy(&r[..std::cmp::min(r.len(), 60)]));
            Ok(r.starts_with(b"SIP/2.0 200")) }
        None => Ok(false),
    }
}

async fn do_tcp(dest: std::net::Ipv6Addr, port: u16, payload: &[u8], to: u64) -> Result<Option<Vec<u8>>> {
    let mut c = tokio::net::TcpStream::connect((dest, port)).await?;
    c.write_all(payload).await?;
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    let end = std::time::Instant::now() + std::time::Duration::from_secs(to);
    loop {
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() { break; }
        tokio::time::sleep(left).await;
        match c.try_read(&mut buf) {
            Ok(n) if n > 0 => {
                out.extend_from_slice(&buf[..n]);
                if out.ends_with(b"\r\n\r\n") { break; }
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await
            }
            Err(e) => { eprintln!("[ims] tcp read err {}", e); return Ok(Some(out)); }
        }
        if out.len() >= 8192 { break; }
    }
    Ok(Some(out))
}

fn extract(body: &[u8], key: &str) -> Option<Vec<u8>> {
    let s = String::from_utf8_lossy(body);
    let k = format!("{}=", key);
    s.find(&k).and_then(|i| {
        let sub = &s[i + k.len()..];
        let end = sub.find(|c| c == ';' || c == '\r' || c == '\n').unwrap_or(sub.len());
        Some(sub[..end].trim_matches('"').trim().as_bytes().to_vec())
    })
}

fn aka_md5_response(rand: &[u8], res: &[u8], nonce: &str, nc: &str,
                    cnonce: &str, qop: &str, realm: &str, user: &str) -> Vec<u8> {
    register::aka_md5_response(rand, res, nonce, nc, cnonce, qop, realm, user)
}
