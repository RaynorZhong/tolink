// v0.2.1 regressions. Synthetic fixtures only; no real provider or room fallback.
fn patch_pending_self() -> Value {
    let mut value = fixture_self();
    value["state"] = json!("PENDING");
    value["timeline"] = json!("conformance");
    value
}
#[test]
fn patch_admission_refreshes_stale_self_before_discarding_public_receipts() {
    let mut c = fixture_client();
    c.state["self"] = patch_pending_self();
    c.state["timeline"] = json!("conformance");
    c.script = Some(Script::new(vec![(
        "self",
        "",
        response(200, fixture_self()),
    )]));
    c.page(
        &json!({"timeline":"public","cursor_reset":true,"next_cursor":"public-start","events":[]}),
        true,
    )
    .unwrap();
    c.page(&old_directed_page(false), true).unwrap();
    let disk = load(&c.home.join("state.json")).unwrap();
    assert_eq!(
        disk["inbox"][0]["status"], "received",
        "stale PENDING permanently consumed a new public reminder"
    );
    assert_eq!(disk["self"]["state"], "ACTIVE");
    assert_eq!(disk["cursor"], "fixture-after");
    assert_eq!(c.script.as_ref().unwrap().calls.len(), 1);
    cleanup_regression_fixture(c);
}
#[test]
fn patch_deferred_admission_refresh_preserves_receipts_and_refresh_obligation() {
    let mut c = fixture_client();
    c.state["self"] = patch_pending_self();
    c.state["timeline"] = json!("conformance");
    c.request_gate = Instant::now() + Duration::from_secs(60);
    c.script = Some(Script::new(vec![]));
    c.page(
        &json!({"timeline":"public","cursor_reset":true,"next_cursor":"public-start","events":[]}),
        true,
    )
    .unwrap();
    c.page(&old_directed_page(false), true).unwrap();
    let disk = load(&c.home.join("state.json")).unwrap();
    assert_eq!(
        disk["inbox"][0]["status"], "received",
        "deferred fresh self lost the receipt"
    );
    assert_eq!(disk["self_refresh_required"], true);
    assert!(c.script.as_ref().unwrap().calls.is_empty());
    c.request_gate = Instant::now();
    c.script = Some(Script::new(vec![(
        "self",
        "",
        response(200, fixture_self()),
    )]));
    c.refresh_self().unwrap().unwrap();
    assert_eq!(c.state["self_refresh_required"], false);
    assert_eq!(c.state["inbox"][0]["status"], "received");
    cleanup_regression_fixture(c);
}
#[test]
fn patch_old_invalid_topic_finishes_before_network_or_budget_and_unblocks_queue() {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(20);
    journal::prepare(&mut c.state).unwrap();
    let bad = json!({"event_id":"owner-bad-topic","kind":"outreach","timeline":"public","recipient_id":"fixture-peer","owner_topic":"x".repeat(100_000),"event":{"kind":"owner_outreach","event_id":"owner-bad-topic"},"status":"received"});
    journal::add_receipt(&mut c.state, bad.clone()).unwrap();
    c.save().unwrap();
    c.script = Some(Script::new(vec![(
        "agents",
        "",
        response(
            200,
            json!({"timeline":"public","agents":[{"agent_id":"fixture-peer"}]}),
        ),
    )]));
    c.generate_receipt(&bad, &fixture_self())
        .expect("invalid saved topic must finish rather than poison the worker");
    assert_eq!(c.state["inbox"][0]["status"], "discarded");
    assert_eq!(c.state["inbox"][0]["reason"], "invalid_owner_topic");
    assert_eq!(c.state["model_invocations"], 0);
    assert!(c.state["rust_generation"].is_null());
    assert!(c.script.as_ref().unwrap().calls.is_empty());
    c.page(&old_directed_page(false), true).unwrap();
    let mut script = Script::new(vec![
        ("self", "", response(200, fixture_self())),
        (
            "agents",
            "",
            response(
                200,
                json!({"timeline":"public","agents":[{"agent_id":"fixture-peer"}]}),
            ),
        ),
    ]);
    script.model_reply = "[SILENT]".into();
    c.script = Some(script);
    c.generate_one().unwrap();
    assert_eq!(c.state["inbox"][1]["status"], "silent");
    assert_eq!(c.state["model_invocations"], 1);
    cleanup_regression_fixture(c);
}
#[test]
fn patch_new_oversized_speak_is_refused_before_client_open() {
    let c = fixture_client();
    let absent = c.home.join("must-remain-absent");
    let error = operations::speak(
        &absent,
        "fixture-peer",
        &"x".repeat(4097),
        "synthetic-request",
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("Owner topic"),
        "oversized topic reached client open: {error}"
    );
    assert!(!absent.exists());
    let control = operations::speak(
        &absent,
        "fixture-peer",
        &"x".repeat(4096),
        "synthetic-request",
    )
    .unwrap_err();
    assert!(
        !control.to_string().contains("Owner topic"),
        "valid topic did not reach ordinary missing-home control"
    );
    cleanup_regression_fixture(c);
}
fn patch_retry_fixture() -> Client {
    let mut c = batch_fixture("answer", true);
    c.config["reply_batch_max"] = json!(2);
    c.generate_one().unwrap();
    assert_eq!(
        c.state["rust_generation"]["intent"]["trigger_id"],
        "batch-2"
    );
    let id = c.state["rust_generation"]["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        c.state["rust_generation"]["intent"]["trigger_ids"],
        json!(["batch-1", "batch-2"])
    );
    journal::recover(&mut c.state, &id, "retry", None, "patch-now", "unused").unwrap();
    c.save().unwrap();
    c.state = load(&c.home.join("state.json")).unwrap();
    c
}
#[test]
fn patch_retry_membership_survives_restart_and_new_batch_limit() {
    let mut c = patch_retry_fixture();
    c.config["reply_batch_max"] = json!(3);
    let mut script = Script::new(vec![
        ("self", "", response(200, fixture_self())),
        (
            "agents",
            "",
            response(
                200,
                json!({"timeline":"public","agents":[{"agent_id":"fixture-peer"}]}),
            ),
        ),
    ]);
    script.model_trigger = "*".into();
    script.model_reply = "answer".into();
    c.script = Some(script);
    c.generate_one().unwrap();
    assert_eq!(
        c.state["pending"]["trigger_ids"],
        json!(["batch-1", "batch-2"]),
        "retry silently admitted an unrelated receipt"
    );
    assert_eq!(c.state["pending"]["body"]["reply_to_event_id"], "batch-2");
    assert_eq!(c.state["inbox"][2]["status"], "received");
    assert_eq!(c.state["model_budget"]["used"], 2);
    cleanup_regression_fixture(c);
}
#[test]
fn patch_retry_nonprimary_withdrawal_blocks_the_saved_group_before_model() {
    let mut c = patch_retry_fixture();
    c.config["reply_batch_max"] = json!(1);
    c.merge_retractions(
        &json!({"events":[{"kind":"event_retracted","target":{"event_id":"batch-1","seq":1}}]}),
    )
    .unwrap();
    let mut script = Script::new(vec![
        ("self", "", response(200, fixture_self())),
        (
            "agents",
            "",
            response(
                200,
                json!({"timeline":"public","agents":[{"agent_id":"fixture-peer"}]}),
            ),
        ),
    ]);
    script.model_trigger = "*".into();
    script.model_reply = "[SILENT]".into();
    c.script = Some(script);
    c.generate_one().unwrap();
    assert_eq!(
        c.script.as_ref().unwrap().generation_calls,
        0,
        "a partial retry ran after a nonprimary trigger was retracted"
    );
    assert_eq!(c.state["inbox"][0]["status"], "retracted");
    assert_eq!(c.state["inbox"][1]["status"], "discarded");
    assert_eq!(c.state["inbox"][2]["status"], "received");
    assert_eq!(c.state["model_budget"]["used"], 1);
    cleanup_regression_fixture(c);
}
#[test]
fn patch_invalid_model_path_is_rejected_before_admission() {
    let mut c = batch_fixture("[SILENT]", false);
    c.config["hermes_executable"] = json!("relative/hermes");
    let result = c.generate_one();
    assert_eq!(
        c.state["model_invocations"], 0,
        "deterministic invalid model path consumed budget"
    );
    assert!(result.is_err());
    assert!(c.state["rust_generation"].is_null());
    assert_eq!(c.state["inbox"][0]["status"], "received");
    cleanup_regression_fixture(c);
}
