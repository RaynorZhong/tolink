// Pre-publication corrections; only synthetic state and a local shell peer.
fn publication_persist_identity(c: &Client) {
    let ca = c.home.join("public-fixture-ca");
    fs::write(&ca, b"synthetic public CA bytes").unwrap();
    let seed = c.home.join("synthetic-private-seed");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&seed)
        .unwrap();
    file.write_all(URL_SAFE_NO_PAD.encode(c.key.to_bytes()).as_bytes())
        .unwrap();
    let mut config = c.config.clone();
    config["base_url"] = json!("https://192.0.2.10:8443/participant/v1/");
    config["authority"] = json!("192.0.2.10:8443");
    config["key_file"] = json!(seed);
    config["ca_file"] = json!(ca);
    config["ca_sha256"] = json!(sha(b"synthetic public CA bytes"));
    // An accidental first request is an immediate local error, never a socket.
    config["curl_executable"] = json!("/usr/bin/false");
    config["model_daily_limit"] = json!(20);
    save(&c.home.join("config.json"), &config).unwrap();
    c.save().unwrap();
}
fn publication_relative(path: &Path) -> PathBuf {
    let mut relative = PathBuf::new();
    for _ in env::current_dir().unwrap().components().skip(1) {
        relative.push("..");
    }
    relative.join(path.strip_prefix("/").unwrap())
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
        "new request did not reach local false transport control: {control}"
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
    fs::remove_dir_all(&c.home).unwrap();
}
#[test]
fn publication_relative_state_home_is_canonical_on_open() {
    let c = fixture_client();
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
    let c = fixture_client();
    let home = fs::canonicalize(&c.home).unwrap();
    let peer = home.join("synthetic-model-peer.sh");
    fs::write(&peer, b"#!/bin/sh\nusage=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = --usage-file ]; then shift; usage=$1; fi\n  shift\ndone\ncase \"$usage\" in /*) ;; *) exit 41 ;; esac\n[ \"${usage%/*}\" = \"$PWD\" ] || exit 42\nprintf '{\"synthetic\":true}\\n' > \"$usage\" || exit 43\nprintf '[SILENT]\\n'\n").unwrap();
    fs::set_permissions(&peer, fs::Permissions::from_mode(0o700)).unwrap();
    let config = json!({"hermes_executable":peer});
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
    fs::remove_dir_all(home).unwrap();
}
