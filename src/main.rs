mod addressing;
mod diagnostics;
mod journal;
mod platform;
mod process;
mod runtime;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs,
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn host(authority: &str, scheme: &str) -> Result<String> {
    require(
        !authority.is_empty()
            && authority.is_ascii()
            && !authority
                .chars()
                .any(|c| c.is_whitespace() || "@/?#%".contains(c)),
        "invalid authority",
    )?;
    let (name, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or("invalid IPv6 authority")?;
        let ip: Ipv6Addr = authority[1..end].parse()?;
        let expanded = ip.segments().map(|s| format!("{s:04x}")).join(":");
        let tail = &authority[end + 1..];
        (
            format!("[{expanded}]"),
            if tail.is_empty() {
                None
            } else {
                Some(tail.strip_prefix(':').ok_or("invalid port")?)
            },
        )
    } else {
        let (name, port) = match authority.split_once(':') {
            Some((n, p)) => (n, Some(p)),
            None => (authority, None),
        };
        require(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c)),
            "invalid hostname",
        )?;
        let name = if name.bytes().all(|c| c.is_ascii_digit() || c == b'.') {
            name.parse::<Ipv4Addr>()?.to_string()
        } else {
            name.to_ascii_lowercase()
        };
        (name, port)
    };
    let default = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err("unsupported scheme".into()),
    };
    match port {
        None => Ok(name),
        Some(p) => {
            require(
                !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()),
                "invalid port",
            )?;
            let n: u16 = p.parse()?;
            require(n != 0, "invalid port")?;
            Ok(if n == default {
                name
            } else {
                format!("{name}:{n}")
            })
        }
    }
}
fn signing(
    method: &str,
    host: &str,
    path: &str,
    query: &str,
    timestamp: &str,
    body: &[u8],
) -> String {
    format!(
        "tolight-participant-v1\n{method}\n{host}\n{path}\n{query}\n{timestamp}\n{}",
        sha(body)
    )
}
fn key_from_bytes(raw: &[u8]) -> Result<SigningKey> {
    let seed = URL_SAFE_NO_PAD.decode(std::str::from_utf8(raw)?.trim())?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| "seed must contain 32 bytes")?;
    Ok(SigningKey::from_bytes(&seed))
}
fn key(path: &Path) -> Result<SigningKey> {
    key_from_bytes(&platform::read_key(path)?)
}
fn vectors(path: &Path) -> Result<()> {
    let data: Value = serde_json::from_slice(&fs::read(path)?)?;
    require(
        data["scheme"] == "tolight-participant-v1",
        "wrong signing scheme",
    )?;
    let rows = data["vectors"].as_array().ok_or("missing vectors")?;
    require(!rows.is_empty(), "empty vector set")?;
    for v in rows {
        let field = |name: &str| -> Result<&str> {
            v[name]
                .as_str()
                .ok_or_else(|| format!("missing {name}").into())
        };
        let k = key_from_bytes(field("seed")?.as_bytes())?;
        let body = URL_SAFE_NO_PAD.decode(field("body_base64url")?)?;
        let (scheme, rest) = field("url")?
            .split_once("://")
            .ok_or("invalid vector URL")?;
        let authority = rest.split('/').next().ok_or("missing authority")?;
        let canonical = host(authority, scheme)?;
        require(
            canonical == field("host")? && authority == field("authority")?,
            "vector authority mismatch",
        )?;
        if let Some(equivalents) = v["equivalent_authorities"].as_array() {
            for a in equivalents {
                require(
                    host(a.as_str().ok_or("bad authority")?, scheme)? == canonical,
                    "equivalent authority mismatch",
                )?;
            }
        }
        require(
            URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes()) == field("public_key")?,
            "vector public key mismatch",
        )?;
        require(sha(&body) == field("body_sha256")?, "vector body mismatch")?;
        let message = signing(
            field("method")?,
            &canonical,
            field("path")?,
            field("query")?,
            field("timestamp")?,
            &body,
        );
        require(
            message == field("string_to_sign")?,
            "vector signing bytes mismatch",
        )?;
        require(
            URL_SAFE_NO_PAD.encode(k.sign(message.as_bytes()).to_bytes()) == field("signature")?,
            "vector signature mismatch",
        )?;
        println!("PASS {}", field("name")?);
    }
    println!("{} signing vectors passed", rows.len());
    Ok(())
}
struct WireResponse {
    status: u16,
    retry_after: Option<u64>,
    complete: bool,
    value: Option<Value>,
    tls_fatal: bool,
}
#[cfg(windows)]
fn require_windows_curl_header_support(path: &Path) -> Result<()> {
    let mut command = Command::new(path);
    command.args(["--disable", "--version"]);
    let out = runtime::capture(command, b"", 5, true)?;
    let version = std::str::from_utf8(&out.stdout).ok().and_then(|banner| {
        let mut words = banner.lines().next()?.split_ascii_whitespace();
        if words.next()? != "curl" {
            return None;
        }
        let mut numbers = words.next()?.split('.');
        let major = numbers.next()?.parse::<u32>().ok()?;
        let minor = numbers.next()?.parse::<u32>().ok()?;
        let patch = numbers.next()?.parse::<u32>().ok()?;
        (numbers.next().is_none()).then_some((major, minor, patch))
    });
    require(
        out.status.success() && version.is_some_and(|v| v >= (8, 10, 0)),
        "Windows requires curl 8.10.0 or later to preserve Retry-After; no request sent",
    )
}
fn wire(
    base: &str,
    ca: &Path,
    signing_key: Option<&SigningKey>,
    endpoint: &str,
    query: &str,
    body: Option<&[u8]>,
    curl_path: &Path,
) -> Result<WireResponse> {
    let rest = base.strip_prefix("https://").ok_or("API requires HTTPS")?;
    let (authority, prefix) = rest.split_once('/').ok_or("full API base path required")?;
    require(
        prefix == "participant/v1/",
        "expected /participant/v1/ base path",
    )?;
    let canonical = host(authority, "https")?;
    require(
        matches!(endpoint, "self" | "agents" | "events" | "messages"),
        "unsupported endpoint",
    )?;
    let method = if body.is_some() { "POST" } else { "GET" };
    let path = format!("/participant/v1/{endpoint}");
    require(
        body.is_none_or(|raw| raw.len() <= 32768),
        "request body exceeds 32 KiB",
    )?;
    // A Windows curl before 8.10 treats `%` as a file name. Check the
    // configured executable before each request, including after replacement.
    #[cfg(windows)]
    require_windows_curl_header_support(curl_path)?;
    #[cfg(windows)]
    let headers_destination = "%";
    #[cfg(not(windows))]
    let headers_destination = "/dev/stderr";
    let mut command = Command::new(curl_path);
    command
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--proto",
            "=https",
            "--tlsv1.3",
            "--max-redirs",
            "0",
            "--path-as-is",
            "--globoff",
            "--http1.1",
            "--connect-timeout",
            "5",
            "--max-time",
            "40",
            "--max-filesize",
            "4194304",
            "--dump-header",
            headers_destination,
            "--write-out",
            "\n%{http_code}",
            "--request",
            method,
            "--cacert",
        ])
        .arg(ca);
    if let Some(k) = signing_key {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let message = signing(
            method,
            &canonical,
            &path,
            query,
            &timestamp,
            body.unwrap_or_default(),
        );
        command.arg("--header").arg(format!(
            "Tolight-Key: {}",
            URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes())
        ));
        command
            .arg("--header")
            .arg(format!("Tolight-Timestamp: {timestamp}"));
        command.arg("--header").arg(format!(
            "Tolight-Signature: {}",
            URL_SAFE_NO_PAD.encode(k.sign(message.as_bytes()).to_bytes())
        ));
    }
    if body.is_some() {
        command.args([
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
        ]);
    }
    let suffix = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    command.arg(format!("{base}{endpoint}{suffix}"));
    let output = runtime::capture(command, body.unwrap_or_default(), 45, false)?;
    require(
        output.status.code() != Some(4),
        "configured curl cannot enforce TLS 1.3; choose a capable installed curl_executable; no automatic fallback",
    )?;
    let headers = String::from_utf8_lossy(&output.stderr);
    let retry = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(k, v)| {
            if k.eq_ignore_ascii_case("retry-after") {
                v.trim().parse::<u64>().ok()
            } else {
                None
            }
        });

    let split = output
        .stdout
        .iter()
        .rposition(|&c| c == b'\n')
        .ok_or("missing HTTP status")?;
    let status: u16 = std::str::from_utf8(&output.stdout[split + 1..])?.parse()?;
    let value = serde_json::from_slice(&output.stdout[..split]).ok();
    Ok(WireResponse {
        status,
        retry_after: retry,
        complete: output.status.success(),
        value,
        tls_fatal: matches!(output.status.code(), Some(51 | 58 | 60 | 77)),
    })
}
fn request(
    base: &str,
    ca: &Path,
    key_path: Option<&Path>,
    endpoint: &str,
    body: Option<&[u8]>,
    curl_path: &Path,
) -> Result<(u16, Value)> {
    let signing_key = key_path.map(key).transpose()?;
    let response = wire(
        base,
        ca,
        signing_key.as_ref(),
        endpoint,
        "",
        body,
        curl_path,
    )?;
    if let Some(seconds) = response.retry_after {
        eprintln!("Retry-After: {seconds}; this command does not retry");
    }
    require(
        response.complete,
        "HTTPS response incomplete; no automatic retry",
    )?;
    Ok((
        response.status,
        response.value.ok_or("invalid JSON response")?,
    ))
}
fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version"] => {
            let info = diagnostics::build_info();
            println!(
                "tolink {} (revision {}; {}/{})",
                info["version"].as_str().unwrap(),
                info["source_revision"].as_str().unwrap(),
                info["os"].as_str().unwrap(),
                info["arch"].as_str().unwrap()
            );
            Ok(())
        }
        ["validate", file] => {
            let report = diagnostics::validate_path(Path::new(file))?;
            println!("{report}");
            require(
                report["valid"] == true,
                "invalid configuration; see sanitized report",
            )
        }
        ["doctor", home] => {
            let report = diagnostics::doctor(Path::new(home))?;
            println!("{report}");
            require(
                report["attention_required"] == false,
                "offline diagnosis requires attention; runtime was not verified",
            )
        }
        ["vectors", file] => vectors(Path::new(file)),
        ["run", home] => runtime::run(Path::new(home)),
        ["self", home] => runtime::fresh_self(Path::new(home)),
        ["status", home] => runtime::status(Path::new(home)),
        ["inspect", home] => runtime::inspect(Path::new(home)),
        ["recover", home, generation, action, "--confirm", confirm]
            if matches!(*action, "discard" | "retry") =>
        {
            runtime::recover(Path::new(home), generation, action, None, confirm)
        }
        [
            "recover",
            home,
            generation,
            "import",
            file,
            "--confirm",
            confirm,
        ] => runtime::recover(
            Path::new(home),
            generation,
            "import",
            Some(Path::new(file)),
            confirm,
        ),
        ["speak", home, recipient, topic, request_id] => {
            runtime::speak(Path::new(home), recipient, topic, request_id)
        }
        ["model-check", home] => runtime::model_check(Path::new(home)),

        ["probe", base, ca] => probe(base, ca, platform::default_curl()),
        ["probe", base, ca, curl] => probe(base, ca, curl),

        _ => {
            eprintln!(
                "tolink --version\ntolink validate CONFIG_JSON\ntolink doctor STATE_DIRECTORY\ntolink run STATE_DIRECTORY\ntolink self STATE_DIRECTORY\ntolink status STATE_DIRECTORY\ntolink inspect STATE_DIRECTORY\ntolink recover STATE_DIRECTORY GENERATION_ID discard|retry --confirm GENERATION_ID\ntolink recover STATE_DIRECTORY GENERATION_ID import RESULT_JSON --confirm GENERATION_ID\ntolink speak STATE_DIRECTORY RECIPIENT TOPIC OWNER_REQUEST_ID\ntolink model-check STATE_DIRECTORY\ntolink vectors FILE\ntolink probe HTTPS_BASE CA [CURL_EXECUTABLE]\nvalidate/doctor/status/inspect are offline and read-only. validate checks structure only. doctor reports metadata, not verified runtime health. recover requires the writer stopped and exact ID confirmation. run is a foreground worker. model-check shares the finite daily budget and does not publish. self uses the worker's single request lane. speak requires a normal stop first. No registration, scheduler or boot-service commands."
            );
            Err("invalid command".into())
        }
    }
}
fn probe(base: &str, ca: &str, curl: &str) -> Result<()> {
    let (status, _) = request(base, Path::new(ca), None, "self", None, Path::new(curl))?;
    require(status == 401, "expected unsigned self to be unauthorized")?;
    println!(
        "{}",
        json!({"https_ca_and_target_verified": true, "minimum_tls":"1.3", "curl_executable":curl, "unsigned_self_status": status, "authenticated": false, "application_submitted": false})
    );
    Ok(())
}
