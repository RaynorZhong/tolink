// Included in runtime::tests. No real model or wire fallback is admitted.
fn batch_fixture(reply: &str, fail: bool) -> Client {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(20);
    c.config["reply_batch_max"] = json!(3);
    let mut page = old_directed_page(false);
    let first = page["events"][0].clone();
    let mut events = vec![];
    for n in 1..=4 {
        let mut event = first.clone();
        event["event_id"] = json!(format!("batch-{n}"));
        event["seq"] = json!(n);
        event["text"] = json!(format!("Specific public question {n}"));
        events.push(event);
    }
    page["events"] = json!(events);
    c.page(&page, true).unwrap();
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
    script.model_reply = reply.into();
    script.model_trigger = "*".into();
    script.model_failure = fail;
    c.script = Some(script);
    c
}
#[test]
fn capability_same_page_three_receipts_share_one_admission() {
    let mut c = batch_fixture("answer", false);
    c.generate_one().unwrap();
    let state = c.state.clone();
    let model_calls = c.script.as_ref().unwrap().generation_calls;
    cleanup_regression_fixture(c);
    assert_eq!(model_calls, 1);
    assert_eq!(state["model_invocations"], 1);
    assert_eq!(
        state["pending"]["trigger_ids"],
        json!(["batch-1", "batch-2", "batch-3"]),
        "one page was not batched into one durable generation"
    );
    assert_eq!(state["pending"]["body"]["reply_to_event_id"], "batch-3");
    for index in 0..3 {
        assert_eq!(state["inbox"][index]["status"], "draft");
    }
    assert_eq!(state["inbox"][3]["status"], "received");
}
#[test]
fn capability_silent_batch_decides_only_selected_receipts() {
    let mut c = batch_fixture("[SILENT]", false);
    c.generate_one().unwrap();
    let state = c.state.clone();
    cleanup_regression_fixture(c);
    assert_eq!(state["model_budget"]["used"], 1);
    for index in 0..3 {
        assert_eq!(state["inbox"][index]["status"], "silent");
    }
    assert_eq!(state["inbox"][3]["status"], "received");
    assert!(state["pending"].is_null());
}
#[test]
fn capability_unknown_batch_retry_keeps_all_receipts_and_does_not_refund() {
    let mut c = batch_fixture("answer", true);
    c.generate_one().unwrap();
    let generation = c.state["rust_generation"]["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    for index in 0..3 {
        assert_eq!(c.state["inbox"][index]["status"], "generation_unknown");
    }
    assert_eq!(c.state["inbox"][3]["status"], "received");
    journal::recover(
        &mut c.state,
        &generation,
        "retry",
        None,
        "fixture-now",
        "unused",
    )
    .unwrap();
    let state = c.state.clone();
    cleanup_regression_fixture(c);
    for index in 0..4 {
        assert_eq!(state["inbox"][index]["status"], "received");
    }
    assert_eq!(state["model_budget"]["used"], 1);
    assert_eq!(state["model_invocations"], 1);
}

#[test]
fn capability_batch_respects_page_and_distinct_recipient_limits() {
    for limit in 1..=3 {
        let mut c = batch_fixture("answer", false);
        let mut current = fixture_self();
        current["limits"]["max_mentions_per_message"] = json!(limit);
        for n in 0..3 {
            c.state["inbox"][n]["event"]["agent"]["agent_id"] = json!(format!("peer-{n}"));
        }
        c.state["inbox"][3]["source_cursor"] = json!("another-page");
        let mut script = Script::new(vec![(
            "agents",
            "",
            response(
                200,
                json!({"timeline":"public","agents":[{"agent_id":"peer-0"},{"agent_id":"peer-1"},{"agent_id":"peer-2"}]}),
            ),
        )]);
        script.model_reply = "answer".into();
        script.model_trigger = "*".into();
        c.script = Some(script);
        let first = c.state["inbox"][0].clone();
        c.generate_receipt(&first, &current).unwrap();
        assert_eq!(
            c.state["pending"]["trigger_ids"].as_array().unwrap().len(),
            limit
        );
        assert_eq!(
            c.state["pending"]["body"]["mentions"]
                .as_array()
                .unwrap()
                .len(),
            limit - 1
        );
        assert_eq!(c.state["inbox"][3]["status"], "received");
        for n in limit..3 {
            assert_eq!(c.state["inbox"][n]["status"], "received");
        }
        assert_eq!(c.state["model_budget"]["used"], 1);
        cleanup_regression_fixture(c);
    }
}

#[test]
fn capability_nonprimary_batch_withdrawal_or_reset_blocks_both_recovery_paths() {
    for reset in [false, true] {
        let mut c = batch_fixture("answer", true);
        c.generate_one().unwrap();
        let id = c.state["rust_generation"]["generation_id"]
            .as_str()
            .unwrap()
            .to_owned();
        if reset {
            c.page(&json!({"timeline":"public","cursor_reset":true,"next_cursor":"reset-page","events":[]}), true).unwrap();
        } else {
            c.merge_retractions(&json!({"events":[{"kind":"event_retracted","target":{"event_id":"batch-2","seq":2}}]})).unwrap();
        }
        let before = c.state.clone();
        for action in ["retry", "import"] {
            let imported = json!({"generation_id":id,"text":"answer"});
            assert!(
                journal::recover(
                    &mut c.state,
                    &id,
                    action,
                    Some(&imported),
                    "fixture-now",
                    "unused"
                )
                .is_err()
            );
            assert_eq!(c.state, before, "refused batch recovery mutated state");
        }
        journal::recover(&mut c.state, &id, "discard", None, "fixture-now", "unused").unwrap();
        assert!(c.state["rust_generation"].is_null());
        assert!(c.state["pending"].is_null());
        assert_eq!(c.state["model_budget"]["used"], 1);
        cleanup_regression_fixture(c);
    }
}

#[test]
fn capability_unknown_batch_import_finishes_exactly_selected_receipts() {
    let mut c = batch_fixture("answer", true);
    c.generate_one().unwrap();
    let id = c.state["rust_generation"]["generation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    journal::recover(
        &mut c.state,
        &id,
        "import",
        Some(&json!({"generation_id":id,"text":"answer"})),
        "fixture-now",
        "stable-batch-message",
    )
    .unwrap();
    assert!(c.state["rust_generation"].is_null());
    assert_eq!(
        c.state["pending"]["trigger_ids"],
        json!(["batch-1", "batch-2", "batch-3"])
    );
    for n in 0..3 {
        assert_eq!(c.state["inbox"][n]["status"], "draft");
    }
    assert_eq!(c.state["inbox"][3]["status"], "received");
    assert_eq!(c.state["model_budget"]["used"], 1);
    assert_eq!(c.script.as_ref().unwrap().generation_calls, 1);
    cleanup_regression_fixture(c);
}

#[test]
fn capability_nonprimary_draft_retraction_cancels_whole_batch_before_post() {
    let mut c = batch_fixture("answer", false);
    c.generate_one().unwrap();
    c.merge_retractions(
        &json!({"events":[{"kind":"event_retracted","target":{"event_id":"batch-2","seq":2}}]}),
    )
    .unwrap();
    c.save().unwrap();
    c.send_pending().unwrap();
    assert!(c.state["pending"].is_null());
    assert_eq!(
        c.state["verifications"][0]["state"],
        "cancelled_before_attempt"
    );
    assert_eq!(c.state["inbox"][3]["status"], "received");
    assert!(contains(&c.state, "retracted_event_ids", "batch-2"));
    assert!(
        !c.script
            .as_ref()
            .unwrap()
            .calls
            .iter()
            .any(|(ep, _, _)| ep == "messages")
    );
    cleanup_regression_fixture(c);
}

#[test]
fn capability_batch_readback_requires_explicit_recipients_not_optional_reply_author() {
    let mut c = batch_fixture("answer", false);
    c.generate_one().unwrap();
    c.state["pending"]["body"]["mentions"] = json!(["fixture-peer"]);
    journal::accept(
        &mut c.state,
        &json!({"event_id":"our-fixture-event","seq":80}),
        "fixture-now",
    )
    .unwrap();
    let job = c.state["verifications"][0].clone();
    let mut event = accepted_event();
    event["reply_to"] = json!({"event_id":"batch-3"});
    for (mentions, expected) in [
        (json!([{"agent_id":"fixture-peer"}]), "verified"),
        (json!([]), "mismatch"),
    ] {
        let mut checked = job.clone();
        event["mentions"] = mentions;
        journal::verify_page(
            &mut checked,
            &json!({"timeline":"public","next_cursor":"readback","events":[event]}),
            "fixture-agent",
            "fixture-now",
        )
        .unwrap();
        assert_eq!(
            checked["state"], expected,
            "readback lost an explicit batch recipient"
        );
    }
    cleanup_regression_fixture(c);
}
