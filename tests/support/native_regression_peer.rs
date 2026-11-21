//! Standalone std-only regression peer; no network or provider implementation.
//! Compiled by publication_tests.rs into its private synthetic fixture directory.
use std::{
    env, fs,
    io::{self, Read},
    path::Path,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn model_input(args: &[String], raw: &[u8], home: &Path) -> Result<(String, String)> {
    let expected = [
        "--safe-mode",
        "--ignore-rules",
        "--toolsets",
        "",
        "--provider",
        "fixture-provider",
        "--model",
        "fixture-model",
        "--reasoning",
        "fixture-reasoning",
        "--usage-file",
    ];
    if args.len() != expected.len() + 6
        || args[..expected.len()]
            .iter()
            .map(String::as_str)
            .ne(expected)
        || args[expected.len() + 1..].iter().map(String::as_str).ne([
            "chat",
            "--oneshot",
            "--quiet",
            "--query-file",
            "-",
        ])
    {
        return Err("synthetic peer requires restricted native chat/UTF-8-stdin flags".into());
    }
    let usage = &args[expected.len()];
    let usage_path = Path::new(usage);
    if !usage_path.is_absolute()
        || usage_path
            .file_name()
            .is_none_or(|name| name != "rust-model-usage.json")
        || fs::canonicalize(usage_path.parent().ok_or("usage parent missing")?)? != home
    {
        return Err("usage file must be absolute and directly inside the fixture home".into());
    }
    if raw.is_empty() || raw.len() > 100_000 {
        return Err("synthetic prompt outside the bounded stdin contract".into());
    }
    let prompt = std::str::from_utf8(raw)?.to_owned();
    let expected_text = fs::read_to_string(home.join("synthetic-model-expected.txt"))?;
    if expected_text.is_empty() || !prompt.contains(&expected_text) {
        return Err("synthetic UTF-8 trigger did not reach stdin intact".into());
    }
    Ok((usage.clone(), prompt))
}

fn main() -> Result<()> {
    let executable = env::current_exe()?;
    let args: Vec<String> = env::args().skip(1).collect();
    let role = executable.file_stem().and_then(|name| name.to_str());
    if matches!(role, Some("synthetic-curl-old" | "synthetic-curl-current")) {
        if args == ["--disable", "--version"] {
            let version = if role == Some("synthetic-curl-old") {
                "8.9.1"
            } else {
                "8.10.0"
            };
            println!("curl {version} (synthetic; no network)");
            return Ok(());
        }
        fs::write(
            executable.with_extension("requested"),
            b"synthetic request reached",
        )?;
        if !args.windows(2).any(|args| args == ["--dump-header", "%"]) {
            return Err("Windows curl header routing is missing".into());
        }
        // Before 8.10, the same flag combination puts headers in a file.
        if role == Some("synthetic-curl-current") {
            eprint!("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 123\r\n\r\n");
        }
        print!("{{\"error\":{{\"code\":\"rate_limited\"}}}}\n429");
        return Ok(());
    }
    if role == Some("synthetic-false-transport") {
        if args == ["--disable", "--version"] {
            println!("curl 8.10.0 (synthetic; no network)");
            return Ok(());
        }
        // A controlled failed transport, not a missing executable or a real curl.
        std::process::exit(1);
    }
    let mut raw = Vec::new();
    io::stdin().lock().take(100_001).read_to_end(&mut raw)?;
    let home = fs::canonicalize(env::current_dir()?)?;
    let (usage, _) = model_input(&args, &raw, &home)?;
    let report = b"{\"synthetic\":true,\"stdin_utf8\":true}\n";
    #[cfg(windows)]
    {
        use std::io::Write;
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(usage)?
            .write_all(report)?;
    }
    #[cfg(not(windows))]
    fs::write(usage, report)?;
    println!("[SILENT]");
    Ok(())
}
