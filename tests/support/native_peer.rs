//! Synthetic peers only. Compile explicitly with the project's cached serde_json.
//! The TLS endpoint uses an already installed OpenSSL as a TLS terminator;
//! protocol decisions and pre-effect snapshot observations are Rust.
//! Never point this peer at real identity/state or provider credentials.
use serde_json::{Value, json};
use std::{
    env, fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn load(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn publish(path: &Path, value: &Value) -> Result<()> {
    let tmp = path.with_extension("fixture-tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(value)?)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}
fn note(root: &Path, value: Value) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(root.join("observations.jsonl"))?;
    writeln!(f, "{value}")?;
    f.sync_all()?;
    Ok(())
}
fn id(seq: u64) -> String {
    format!("00000000-0000-4000-8000-{seq:012x}")
}
fn event(seq: u64) -> Value {
    let own = seq == 80;
    let directed = seq == 1 || seq == 150;
    json!({"schema":"tolight-event/1","seq":seq,"event_id":id(seq),"kind":"agent_message","created_at":"2000-01-01T00:00:00Z","retracted":false,"agent":{"agent_id":if own{"fixture-agent"}else if directed{"fixture-peer"}else{"fixture-noise"},"display_name":"Synthetic participant"},"text":if own{"answer"}else if directed{"A new unread question"}else{"Unrelated public traffic"},"reply_to":if own{json!({"event_id":id(1),"seq":1})}else{Value::Null},"mentions":if own{json!([{"agent_id":"fixture-peer","display_name":"Fixture Peer"}])}else if directed{json!([{"agent_id":"fixture-agent","display_name":"Fixture Agent"}])}else{json!([])},"from_self":own,"mentions_you":directed})
}
fn self_value() -> Value {
    json!({"spec_version":"tolight-participant/0.1","agent_id":"fixture-agent","display_name":"Fixture Agent","bio":"Synthetic identity only","state":"ACTIVE","timeline":"public","mute":null,"room_paused":false,"limits":{"max_text_scalars":2000}})
}
fn query<'a>(url: &'a str, key: &str) -> Option<&'a str> {
    url.split_once('?')?
        .1
        .split('&')
        .filter_map(|p| p.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}
fn serve(root: &Path, openssl: &str, port: u16, version: &str) -> Result<()> {
    if !matches!(version, "-tls1_2" | "-tls1_3") {
        return Err("unsupported fixture TLS version".into());
    }
    let mut tls = Command::new(openssl)
        .args([
            "s_server",
            "-quiet",
            version,
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-cert",
        ])
        .arg(root.join("ca.pem"))
        .arg("-key")
        .arg(root.join("tls.key"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    loop {
        if tls.try_wait()?.is_some() {
            return Err("native TLS terminator exited before listening".into());
        }
        if TcpStream::connect_timeout(&addr, Duration::from_millis(100)).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            return Err("TLS fixture startup timeout".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    publish(
        &root.join("ready.json"),
        &json!({"ready":true,"port":port,"role":"rust-synthetic-protocol-peer"}),
    )?;
    let mut reader = BufReader::new(tls.stdout.take().ok_or("TLS stdout missing")?);
    let mut writer = tls.stdin.take().ok_or("TLS stdin missing")?;
    let mut head = 15u64;
    let mut posts = 0u64;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Err("TLS fixture closed unexpectedly".into());
        }
        if !line.starts_with("GET ") && !line.starts_with("POST ") {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 3 {
            return Err("bad synthetic HTTP request".into());
        }
        let method = parts[0].to_owned();
        let url = parts[1].to_owned();
        let mut length = 0usize;
        let mut signed = false;
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            if line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse()?;
                }
                if name.eq_ignore_ascii_case("tolight-signature") {
                    signed = true;
                }
            }
        }
        if length > 32768 {
            return Err("synthetic API requires bounded requests".into());
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        let endpoint = url.split('?').next().unwrap_or("");
        let (status, value) = if !signed && method == "GET" && endpoint.ends_with("/self") {
            (401, json!({"error":{"code":"unauthorized"}}))
        } else if !signed {
            return Err("synthetic participant request was not signed".into());
        } else if method == "GET" && endpoint.ends_with("/self") {
            (200, self_value())
        } else if method == "GET" && endpoint.ends_with("/agents") {
            (
                200,
                json!({"timeline":"public","agents":[{"agent_id":"fixture-agent","display_name":"Fixture Agent"},{"agent_id":"fixture-peer","display_name":"Fixture Peer"},{"agent_id":"fixture-noise","display_name":"Fixture Noise"}]}),
            )
        } else if method == "GET" && endpoint.ends_with("/events") {
            let limit = query(&url, "limit").unwrap_or("50").parse::<u64>()?;
            let after = query(&url, "after")
                .map(|c| {
                    c.strip_prefix("server-cursor-")
                        .ok_or("foreign fixture cursor")
                        .and_then(|n| n.parse::<u64>().map_err(|_| "bad fixture cursor"))
                })
                .transpose()?;
            let start = after.unwrap_or(head.saturating_sub(limit));
            let end = if limit == 0 {
                head
            } else {
                head.min(start + limit)
            };
            let events: Vec<Value> = if limit == 0 {
                vec![]
            } else {
                ((start + 1)..=end).map(event).collect()
            };
            (
                200,
                json!({"timeline":"public","cursor_reset":false,"head_seq":head,"next_cursor":format!("server-cursor-{end}"),"has_more":end<head,"notice":null,"events":events}),
            )
        } else if method == "POST" && endpoint.ends_with("/messages") {
            let home = PathBuf::from(
                load(&root.join("client-home.json"))?["home"]
                    .as_str()
                    .ok_or("client home missing")?,
            );
            let disk = load(&home.join("state.json"))?;
            let body_value: Value = serde_json::from_slice(&body)?;
            if disk["pending"]["body"] != body_value
                || disk["pending"]["verification_cursor"] != "server-cursor-15"
                || disk["pending"]["attempts"] != 1
                || disk["model_budget"]["used"] != 1
                || !disk["rust_generation"].is_null()
            {
                return Err("POST crossed an uncommitted state boundary".into());
            }
            posts += 1;
            if posts != 1 {
                return Err("duplicate synthetic POST".into());
            }
            head = 200;
            note(
                root,
                json!({"observed":"post_after_durable_outbox_and_anchor","client_message_id":body_value["client_message_id"],"synthetic":true,"latest_window_excludes_accepted":true}),
            )?;
            (201, json!({"event_id":id(80),"seq":80}))
        } else {
            return Err(format!("unexpected fixture route: {method} {endpoint}").into());
        };
        note(
            root,
            json!({"observed":"http_request","method":method,"url":url,"synthetic":true}),
        )?;
        let bytes = serde_json::to_vec(&value)?;
        write!(
            writer,
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        )?;
        writer.write_all(&bytes)?;
        writer.flush()?;
    }
}
fn synthetic_model(args: &[String]) -> Result<()> {
    let value = |flag: &str| -> Result<&str> {
        let pos = args
            .iter()
            .position(|a| a == flag)
            .ok_or("missing model flag")?;
        args.get(pos + 1)
            .map(String::as_str)
            .ok_or_else(|| "flag value missing".into())
    };
    if !args.iter().any(|a| a == "--safe-mode")
        || !args.iter().any(|a| a == "--ignore-rules")
        || value("--toolsets")? != ""
        || value("--provider")? != "fixture-provider"
        || value("--model")? != "fixture-model"
    {
        return Err("model capability/configuration flags not forwarded".into());
    }
    let prompt = value("--oneshot")?;
    let payload: Value =
        serde_json::from_str(prompt.rsplit_once('\n').ok_or("model JSON missing")?.1)?;
    if !prompt.contains("native fixture role")
        || prompt.contains("你是全知")
        || payload["identity"]["agent_id"] != "fixture-agent"
    {
        return Err("role or GET-self identity not forwarded".into());
    }
    let home = env::current_dir()?;
    let disk = load(&home.join("state.json"))?;
    if disk["rust_generation"]["intent"]["trigger_id"] != payload["trigger"]["event_id"]
        || disk["model_budget"]["used"] != 1
        || disk["cursor"] != "server-cursor-15"
        || disk["inbox"][0]["status"] != "generating"
    {
        return Err("model started before receipt/cursor/budget/marker commit".into());
    }
    publish(
        &home.join("native-model-observed.json"),
        &json!({"observed":"before_synthetic_model","generation_id":disk["rust_generation"]["generation_id"],"synthetic":true,"real_provider_called":false}),
    )?;
    println!("answer");
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.first().is_some_and(|v| v == "tls-server") {
        if args.len() != 4 && args.len() != 5 {
            return Err("tls-server ROOT OPENSSL PORT [-tls1_2|-tls1_3]".into());
        }
        serve(
            Path::new(&args[1]),
            &args[2],
            args[3].parse()?,
            args.get(4).map(String::as_str).unwrap_or("-tls1_3"),
        )
    } else {
        synthetic_model(&args)
    }
}
