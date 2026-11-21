// Pre-publication corrections; only synthetic state and compiled native peers.
fn publication_peer(home: &Path, role: &str) -> PathBuf {
    let filename = format!("{role}{}", env::consts::EXE_SUFFIX);
    let peer = home.join(&filename);
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/native_regression_peer.rs");
    // Keep the verbatim path for execution, but do not hand it to MinGW ld.
    #[cfg(windows)]
    let compiler_dir = match home.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(path) if path.as_bytes().get(1) == Some(&b':') => Path::new(path),
        _ => home,
    };
    #[cfg(not(windows))]
    let compiler_dir = home;
    let output = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .current_dir(compiler_dir)
        .args([
            "--edition=2024",
            "--crate-name",
            "tolink_synthetic_regression_peer",
        ])
        .arg(source)
        .arg("-o")
        .arg(filename)
        .output()
        .expect("compile the std-only native synthetic peer");
    assert!(
        output.status.success(),
        "native fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    peer
}
fn publication_relative_fixture() -> Client {
    // A drive-relative test must not depend on TMPDIR sharing the checkout's
    // volume. Keep just this fixture in the ignored local build directory.
    let parent = env::current_dir().unwrap().join("target");
    fs::create_dir_all(&parent).unwrap();
    fixture_client_in(&parent)
}
fn publication_persist_identity(c: &Client) {
    let ca = c.home.join("public-fixture-ca");
    fs::write(&ca, b"synthetic public CA bytes").unwrap();
    let seed = c.home.join("synthetic-private-seed");
    let mut file = crate::platform::open_private_new(&seed).unwrap();
    file.write_all(URL_SAFE_NO_PAD.encode(c.key.to_bytes()).as_bytes())
        .unwrap();
    let mut config = c.config.clone();
    config["base_url"] = json!("https://192.0.2.10:8443/participant/v1/");
    config["authority"] = json!("192.0.2.10:8443");
    config["key_file"] = json!(seed);
    config["ca_file"] = json!(ca);
    config["ca_sha256"] = json!(sha(b"synthetic public CA bytes"));
    // An accidental first request is an immediate local error, never a socket.
    config["curl_executable"] = json!(publication_peer(&c.home, "synthetic-false-transport"));
    config["model_daily_limit"] = json!(20);
    save(&c.home.join("config.json"), &config).unwrap();
    c.save().unwrap();
}
fn publication_relative(path: &Path) -> PathBuf {
    let cwd = fs::canonicalize(env::current_dir().unwrap()).unwrap();
    let path = fs::canonicalize(path).unwrap();
    let ancestor = cwd
        .ancestors()
        .find(|base| path.starts_with(base))
        .expect("relative-path fixtures and checkout must share a filesystem volume");
    let mut relative = PathBuf::new();
    for _ in cwd.strip_prefix(ancestor).unwrap().components() {
        relative.push("..");
    }
    relative.push(path.strip_prefix(ancestor).unwrap());
    assert!(
        relative.is_relative(),
        "control unexpectedly produced an absolute path"
    );
    relative
}
#[test]
fn publication_outreach_dedupe_survives_terminal_pruning_and_restart() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    let request = "synthetic-stable-owner-request";
    let id = format!("owner-{}", sha(request.as_bytes()));
    journal::add_receipt(
        &mut c.state,
        json!({"event_id":id,"kind":"outreach","timeline":"public","status":"received"}),
    )
    .unwrap();
    journal::decision(&mut c.state, &id, "silent", "synthetic-decision").unwrap();
    for n in 0..513 {
        let next = format!("later-directed-{n}");
        journal::add_receipt(
            &mut c.state,
            json!({"event_id":next,"kind":"reply","status":"received"}),
        )
        .unwrap();
        journal::decision(&mut c.state, &next, "silent", "synthetic-decision").unwrap();
    }
    journal::prune(&mut c.state).unwrap();
    assert!(!contains(&c.state, "handled", &id));
    assert!(
        !journal::receipts(&c.state)
            .unwrap()
            .iter()
            .any(|r| r["event_id"] == id)
    );
    publication_persist_identity(&c);
    let home = c.home.clone();
    let before = fs::read(home.join("state.json")).unwrap();
    drop(c);
    let error = operations::speak(&home, "fixture-peer", "synthetic topic", request).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Owner outreach already recorded"),
        "pruned outreach reached transport instead of dedupe: {error}"
    );
    assert_eq!(before, fs::read(home.join("state.json")).unwrap());
    let control = operations::speak(
        &home,
        "fixture-peer",
        "synthetic topic",
        "different-owner-request",
    )
    .unwrap_err();
    assert!(
        control.to_string().contains("missing HTTP status"),
        "new request did not reach native failed-transport control: {control}"
    );
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn publication_outreach_dedupe_backfills_retained_legacy_evidence() {
    let mut c = fixture_client();
    let ids: Vec<String> = (0..5)
        .map(|n| format!("owner-{}", sha(format!("retained-{n}").as_bytes())))
        .collect();
    c.state["rust_journal_version"] = json!(1);
    c.state["handled"] = json!([ids[0]]);
    c.state["inbox"] = json!([{"event_id":ids[1],"kind":"outreach","status":"silent"}]);
    c.state["generation_history"] = json!([{"trigger_id":ids[2]}]);
    c.state["verifications"] = json!([{"trigger_id":ids[3],"state":"verified"}]);
    c.state["pending"] = json!({"trigger_id":ids[4],"allowed_mentions":[],"body":{"mentions":[]}});
    journal::prepare(&mut c.state).unwrap();
    for id in &ids {
        assert!(
            contains(&c.state, "outreach_request_ids", id),
            "retained legacy outreach not indexed"
        );
    }
    let before = c.state["outreach_request_ids"].clone();
    journal::prepare(&mut c.state).unwrap();
    assert_eq!(before, c.state["outreach_request_ids"]);
    cleanup_regression_fixture(c);
}
#[test]
fn publication_relative_state_home_is_canonical_on_open() {
    let c = publication_relative_fixture();
    publication_persist_identity(&c);
    let home = fs::canonicalize(&c.home).unwrap();
    drop(c);
    let reopened = Client::open(&publication_relative(&home)).unwrap();
    assert_eq!(
        reopened.home, home,
        "client retained a relative state directory"
    );
    drop(reopened);
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn publication_relative_model_home_uses_absolute_usage_path() {
    let c = publication_relative_fixture();
    let home = fs::canonicalize(&c.home).unwrap();
    let peer = publication_peer(&home, "synthetic-model-peer");
    fs::write(
        home.join("synthetic-model-expected.txt"),
        "synthetic path check",
    )
    .unwrap();
    let config = json!({"hermes_executable":peer,"model_provider":"fixture-provider","model_name":"fixture-model","model_reasoning":"fixture-reasoning"});
    let payload = json!({"max_text_scalars":200,"trigger":{"text":"synthetic path check"}});
    assert_eq!(model(&home, &config, &payload).unwrap(), "[SILENT]");
    let usage = home.join("rust-model-usage.json");
    assert_eq!(load(&usage).unwrap()["synthetic"], true);
    fs::remove_file(&usage).unwrap();
    assert_eq!(
        model(&publication_relative(&home), &config, &payload)
            .expect("relative home produced a repeated relative usage path"),
        "[SILENT]"
    );
    assert_eq!(load(&usage).unwrap()["synthetic"], true);
    assert_eq!(load(&usage).unwrap()["stdin_utf8"], true);
    cleanup_regression_fixture(c);
}

#[test]
fn publication_model_uses_utf8_stdin_beyond_windows_command_line_limit() {
    let c = fixture_client();
    let home = fs::canonicalize(&c.home).unwrap();
    let peer = publication_peer(&home, "synthetic-model-peer");
    let text = "synthetic question 问题 ".repeat(2000);
    assert!(
        text.encode_utf16().count() > 32_767,
        "counterexample must exceed Windows argv limit"
    );
    assert!(
        text.len() < 90_000,
        "control must fit the model input byte bound"
    );
    fs::write(home.join("synthetic-model-expected.txt"), &text).unwrap();
    let config = json!({"hermes_executable":peer,"model_provider":"fixture-provider","model_name":"fixture-model","model_reasoning":"fixture-reasoning"});
    let payload = json!({"max_text_scalars":200,"trigger":{"text":text}});
    assert_eq!(model(&home, &config, &payload).unwrap(), "[SILENT]");
    let usage = load(&home.join("rust-model-usage.json")).unwrap();
    assert_eq!(usage["synthetic"], true);
    assert_eq!(usage["stdin_utf8"], true);
    cleanup_regression_fixture(c);
}

#[cfg(windows)]
#[test]
fn publication_model_usage_does_not_truncate_an_existing_link() {
    let c = fixture_client();
    let home = fs::canonicalize(&c.home).unwrap();
    let peer = publication_peer(&home, "synthetic-model-peer");
    let original = home.join("fixture-protected.json");
    save(&original, &json!({"untouched":true})).unwrap();
    let usage = home.join("rust-model-usage.json");
    fs::hard_link(&original, &usage).unwrap();
    let prompt = "synthetic file safety check";
    fs::write(home.join("synthetic-model-expected.txt"), prompt).unwrap();
    let config = json!({"hermes_executable":peer,"model_provider":"fixture-provider","model_name":"fixture-model","model_reasoning":"fixture-reasoning"});
    let payload = json!({"max_text_scalars":200,"trigger":{"text":prompt}});
    assert_eq!(model(&home, &config, &payload).unwrap(), "[SILENT]");
    let actual = load(&original).unwrap();
    let recorded = load(&usage).unwrap();
    cleanup_regression_fixture(c);
    assert_eq!(actual, json!({"untouched":true}));
    assert_eq!(recorded["synthetic"], true);
}

#[cfg(windows)]
#[test]
fn publication_curl_checks_header_routing_before_any_request() {
    let c = fixture_client();
    let base = "https://192.0.2.10/participant/v1/";
    let ca = c.home.join("unused-fixture-ca.pem");
    let old = publication_peer(&c.home, "synthetic-curl-old");
    let rejection = wire(base, &ca, None, "self", "", None, &old);
    assert!(
        matches!(rejection, Err(ref error) if error.to_string().contains("curl 8.10.0")),
        "old curl must be rejected before its request loses Retry-After"
    );
    assert!(!old.with_extension("requested").exists());
    let current = publication_peer(&c.home, "synthetic-curl-current");
    let response = wire(base, &ca, None, "self", "", None, &current).unwrap();
    assert!(current.with_extension("requested").exists());
    assert_eq!(response.status, 429);
    assert_eq!(response.retry_after, Some(123));
    cleanup_regression_fixture(c);
}
