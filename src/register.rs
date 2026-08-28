use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::process::Command;

async fn qmicli(args: &[&str]) -> Result<String> {
    let out = tokio::time::timeout(Duration::from_secs(12),
        Command::new("qmicli").args(args).output()).await
        .map_err(|_| anyhow!("qmicli timeout"))??;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let e = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        let clean: String = e.lines()
            .filter(|l| !l.starts_with("[")).filter(|l| !l.contains("Warning"))
            .collect::<Vec<_>>().join("\n");
        if !clean.is_empty() { return Err(anyhow!("qmicli({:?}): {}", args, clean)); }
    }
    Ok(s)
}

async fn ip(args: &[&str]) -> Result<String> {
    let out = tokio::time::timeout(Duration::from_secs(6),
        Command::new("ip").args(args).output()).await
        .map_err(|_| anyhow!("ip timeout"))??;
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() {
        let e = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("ip({:?}): {}", args, e.trim()));
    }
    Ok(s)
}

pub async fn discover_pcscf() -> Result<String> {
    let tbl = ip(&["-6", "route"]).await?;
    tbl.lines().find_map(|l| {
        if l.contains("dev wwan1") && l.contains("2408:8142") {
            Some(l.split_whitespace().next().unwrap_or("").to_string())
        } else { None }
    }).ok_or_else(|| anyhow!("P-CSCF route via wwan1 not found"))
}

pub async fn local_ip() -> Result<String> {
    let a = ip(&["-6", "addr", "show", "wwan1"]).await?;
    a.lines().find_map(|l| {
        if l.contains("scope global") && l.contains("nodad") {
            let v = l.split_whitespace().nth(1)?;
            Some(v.split('/').next()?.to_string())
        } else { None }
    }).ok_or_else(|| anyhow!("local IPv6 (wwan1) not found"))
}

#[derive(Debug, Default)]
pub struct UsimInfo { pub imsi: String, pub aid: String, }

pub async fn usim_probe() -> Result<UsimInfo> {
    let imsi = read_imsi().await.unwrap_or_else(|_| "?".to_string());
    let aid = read_usim_aid().await.unwrap_or_default();
    Ok(UsimInfo { imsi, aid })
}

async fn read_usim_aid() -> Result<String> {
    let s = qmicli(&["-d", "/dev/wwan0at2", "--device-open-qmi", "-p", "--uim-get-card-status"]).await?;
    s.lines().find(|l| l.contains("A0:"))
        .map(|l| l.trim().trim_matches('`').replace(" ", ""))
        .ok_or_else(|| anyhow!("USIM AID not found"))
}

async fn read_imsi() -> Result<String> {
    let s = qmicli(&["-d", "/dev/wwan0at2", "--device-open-qmi", "-p", "--dms-get-imsi"]).await?;
    s.lines().find_map(|l| {
        if let Some(v) = l.split(':').nth(1) {
            let v = v.trim();
            if !v.is_empty() { Some(v.to_string()) } else { None }
        } else { None }
    }).ok_or_else(|| anyhow!("IMSI unreadable"))
}

#[derive(Debug)]
pub struct SaParams {
    pub ue_ip: String, pub pcscf: String,
    pub ue_send: u16, pub ue_recv: u16,
    pub pcscf_send: u16, pub pcscf_recv: u16,
    pub esp_key: Vec<u8>,
}
impl SaParams {
    pub async fn from_legacy(pcscf: &str, ue_ip: &str) -> Result<Self> {
        let st = ip(&["xfrm", "state"]).await?;
        let pl = ip(&["xfrm", "policy"]).await?;
        parse_legacy(&st, &pl, pcscf, ue_ip)
    }
}

fn parse_legacy(state: &str, policy: &str, pcscf: &str, ue_ip: &str) -> Result<SaParams> {
    let esp_key_hex = state.lines().find_map(|l| {
        l.split("hmac(md5)").nth(1).and_then(|t| t.split_whitespace().next())
            .and_then(|w| w.strip_prefix("0x").or(w.strip_prefix("0X")).or(Some(w)))
    }).ok_or_else(|| anyhow!("ESP auth key not found"))?;
    let esp_key = hex::decode(esp_key_hex)?;
    // 端口:policy 段 out 行 sport=ue_send,dport=pcscf_send;in 行 sport=pcscf_recv,dport=ue_recv
    let mut ue_send = 0u16; let mut ue_recv = 0u16; let mut pcscf_send = 0u16; let mut pcscf_recv = 0u16;
    for line in policy.lines() {
        if !line.contains(ue_ip) || !line.contains(pcscf) { continue; }
        let parts: Vec<&str> = line.split_whitespace().collect();
        for i in 0..parts.len().saturating_sub(5) {
            if parts[i] == "dir" && parts[i+1] == "out" {
                if let Some(j) = parts[i+2..].iter().position(|&w| w == "sport") {
                    ue_send = parts[i+2+j+1].parse().unwrap_or(0);
                }
                if let Some(j) = parts[i+2..].iter().position(|&w| w == "dport") {
                    pcscf_send = parts[i+2+j+1].parse().unwrap_or(0);
                }
            }
            if parts[i] == "dir" && parts[i+1] == "in" {
                if let Some(j) = parts[i+2..].iter().position(|&w| w == "sport") {
                    pcscf_recv = parts[i+2+j+1].parse().unwrap_or(0);
                }
                if let Some(j) = parts[i+2..].iter().position(|&w| w == "dport") {
                    ue_recv = parts[i+2+j+1].parse().unwrap_or(0);
                }
            }
        }
    }
    Ok(SaParams {
        ue_ip: ue_ip.to_string(), pcscf: pcscf.to_string(),
        ue_send, ue_recv, pcscf_send, pcscf_recv, esp_key,
    })
}

use digest::Digest;
use hmac::{Hmac, Mac as MacT};
type HmacMd5 = Hmac<md5::Md5>;

pub fn aka_md5_response(rand: &[u8], res: &[u8], nonce: &str, nc: &str,
                        cnonce: &str, qop: &str, realm: &str, user: &str) -> Vec<u8> {
    let mut d = md5::Md5::new();
    d.update(res); d.update(nonce.as_bytes()); d.update(nc.as_bytes());
    d.update(cnonce.as_bytes()); d.update(qop.as_bytes());
    d.update(format!("auth:{}:{}", realm, user).as_bytes());
    let step_a = d.finalize().to_vec();
    let mut d2 = md5::Md5::new();
    d2.update(rand); d2.update(&step_a);
    d2.finalize().to_vec()
}

pub fn compute_icv(key: &[u8], spi: u32, seq: u32, iv: &[u8], ct: &[u8]) -> Vec<u8> {
    let mut inbuf = Vec::new();
    inbuf.extend_from_slice(&spi.to_be_bytes());
    inbuf.extend_from_slice(&seq.to_be_bytes());
    inbuf.extend_from_slice(iv);
    inbuf.extend_from_slice(ct);
    let mut mac = HmacMd5::new_from_slice(key).unwrap();
    mac.update(&inbuf);
    let out: Vec<u8> = mac.finalize().into_bytes().to_vec();
    out[..12].to_vec()
}

pub fn build_esp(spi: u32, seq: u32, key: &[u8], payload: &[u8]) -> Vec<u8> {
    let iv = [0u8; 16];
    let mut frame = Vec::with_capacity(4 + 4 + 16 + payload.len() + 12);
    frame.extend_from_slice(&spi.to_be_bytes());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(&iv);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&compute_icv(key, spi, seq, &iv, payload));
    frame
}

pub fn build_plain_register(user: &str, realm: &str, _pcscf: &str, ue_ip: &str,
                            ue_send: u16, _ue_recv: u16, _pcscf_send: u16,
                            spi_c: u32, spi_s: u32) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let nonce = ts % 1_000_000;
    format!(
        "REGISTER sip:{realm} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {ue_ip}:5063;branch=z9hG4bK{nonce}\r\n\
         Max-Forwards: 70\r\n\
         To: <sip:{user}@{realm}>\r\n\
         From: <sip:{user}@{realm}>;tag=ue{nonce}\r\n\
         Call-ID: ims-{nonce}@{ue_ip}\r\n\
         CSeq: 1 REGISTER\r\n\
         Contact: <sip:{user}@{ue_ip}:5063;transport=udp>\r\n\
         Supported: sec-agree\r\n\
         Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;prot=esp;mod=trans;spi-c={spi_c};spi-s={spi_s};port-c={ue_send};port-s=5063\r\n\
         Content-Length: 0\r\n\r\n"
    )
}
