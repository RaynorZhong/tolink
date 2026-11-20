// Native CLI fixture: no Hermes install, credentials, or network access.
fn gateway_admission_fixture(verdict: &str) -> Client {
    let mut c = fixture_client();
    let home = fs::canonicalize(&c.home).unwrap();
    let compiler_dir = home.to_str().unwrap().trim_start_matches(r"\\?\");
    let source = r#"
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args != ["gateway", "attach", "--json"] {
        std::fs::write("unexpected-chat", "model must not run").unwrap();
        std::process::exit(99);
    }
    let mut input = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut input).unwrap();
    assert!(input.is_empty());
    std::fs::write("attach-observed", "attach only").unwrap();
    eprintln!("SYNTHETIC-SENSITIVE-STDERR");
    print!("{}", std::fs::read_to_string("attach-verdict.json").unwrap());
    if std::path::Path::new("attach-fail").exists() {
        std::process::exit(5);
    }
}
"#;
    fs::write(home.join("gateway_fixture.rs"), source).unwrap();
    let compiled = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .current_dir(compiler_dir)
        .args([
            "--edition=2024",
            "gateway_fixture.rs",
            "-o",
            "gateway_fixture.exe",
        ])
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    fs::write(home.join("attach-verdict.json"), verdict).unwrap();
    c.config["hermes_executable"] = json!(home.join("gateway_fixture.exe"));
    c.config["model_daily_limit"] = json!(1);
    c
}

#[test]
fn cold_gateway_leaves_diagnostic_budget_and_journal_unchanged() {
    let c = gateway_admission_fixture(r#"{"state":"absent","endpoint":null}"#);
    fs::write(c.home.join("attach-fail"), []).unwrap();
    save(&c.home.join("config.json"), &c.config).unwrap();
    c.save().unwrap();
    let home = c.home.clone();
    let path = home.join("state.json");
    let before = fs::read(&path).unwrap();
    drop(c);
    let error = operations::model_check(&home).unwrap_err().to_string();
    assert!(
        fs::read(&path).unwrap() == before,
        "cold gateway charged a diagnostic attempt"
    );
    assert!(home.join("attach-observed").is_file());
    assert!(!home.join("unexpected-chat").exists());
    assert!(error.contains("gateway is not ready"), "{error}");
    assert!(!error.contains("SYNTHETIC"));
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn cold_gateway_leaves_directed_receipt_eligible_without_charging() {
    let mut c = gateway_admission_fixture(r#"{"state":"absent","endpoint":null}"#);
    fs::write(c.home.join("attach-fail"), []).unwrap();
    c.page(&old_directed_page(false), true).unwrap();
    let receipt = c.state["inbox"][0].clone();
    let path = c.home.join("state.json");
    let before = fs::read(&path).unwrap();
    c.script = Some(Script::new(vec![(
        "agents",
        "",
        response(200, json!({"timeline":"public","agents":[]})),
    )]));

    let result = c.generate_receipt(&receipt, &fixture_self());
    assert!(
        fs::read(&path).unwrap() == before,
        "cold gateway charged a directed receipt"
    );
    assert!(c.home.join("attach-observed").is_file());
    assert_eq!(c.state["inbox"][0]["status"], "received");
    assert_eq!(c.script.as_ref().unwrap().generation_calls, 0);
    assert!(matches!(result, Err(ref e) if e.to_string().contains("gateway is not ready")));

    // An after-turn restart can mint a ticket with exit 0 but is not ready for new work.
    fs::remove_file(c.home.join("attach-fail")).unwrap();
    fs::write(
        c.home.join("attach-verdict.json"),
        r#"{"state":"draining","reason_code":"restart_wait","ticket":"SYNTHETIC-TICKET"}"#,
    )
    .unwrap();
    let error = check_model_gateway(&c.home, &c.config)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("SYNTHETIC"));

    // Once the same profile is ready, journal reservation still precedes the model.
    fs::write(
        c.home.join("attach-verdict.json"),
        r#"{"state":"ready","ticket":"SYNTHETIC-TICKET"}"#,
    )
    .unwrap();
    c.script = Some(Script::new(vec![(
        "agents",
        "",
        response(200, json!({"timeline":"public","agents":[]})),
    )]));
    c.generate_receipt(&receipt, &fixture_self()).unwrap();
    assert_eq!(c.script.as_ref().unwrap().generation_calls, 1);
    assert_eq!(load(&path).unwrap()["model_budget"]["used"], 1);
    assert!(
        !fs::read_to_string(path)
            .unwrap()
            .contains("SYNTHETIC-TICKET")
    );
    cleanup_regression_fixture(c);
}
