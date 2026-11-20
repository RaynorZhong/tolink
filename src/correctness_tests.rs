// Included inside runtime::tests; all fixtures are synthetic and effect-free outside scratch.
fn cleanup_regression_fixture(client: Client) {
    let home = client.home.clone();
    // Windows will not remove a directory containing a live single-writer lock.
    drop(client);
    fs::remove_dir_all(home).unwrap();
}

fn capability_paused_receipt(used: u64) -> (Client, Value, Value) {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(20);
    c.state["model_invocations"] = json!(used);
    c.page(&old_directed_page(false), true).unwrap();
    c.script = Some(Script::new(vec![]));
    let receipt = c.state["inbox"][0].clone();
    let mut current = fixture_self();
    current["room_paused"] = json!(true);
    (c, receipt, current)
}
#[test]
fn capability_paused_with_budget_control() {
    let (mut c, receipt, current) = capability_paused_receipt(0);
    c.generate_receipt(&receipt, &current).unwrap();
    let outcome = c.state["inbox"][0]["status"].clone();
    cleanup_regression_fixture(c);
    assert_eq!(outcome, "discarded");
}
#[test]
fn capability_pause_discard_precedes_exhausted_budget() {
    let (mut c, receipt, current) = capability_paused_receipt(20);
    c.generate_receipt(&receipt, &current).unwrap();
    let outcome = c.state["inbox"][0]["status"].clone();
    cleanup_regression_fixture(c);
    assert_eq!(
        outcome, "discarded",
        "pause policy was bypassed by exhausted budget"
    );
}
#[test]
fn capability_first_complete_rejection_is_not_delivery_unknown() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    c.save().unwrap();
    c.script = Some(Script::new(vec![
        ("self", "", response(200, fixture_self())),
        (
            "events",
            "limit=0",
            response(
                200,
                json!({"timeline":"public","next_cursor":"anchor","events":[]}),
            ),
        ),
        (
            "messages",
            "",
            response(
                422,
                json!({"error":{"code":"content_rejected","reason_code":"invalid_chars"}}),
            ),
        ),
    ]));
    c.send_pending().unwrap();
    let unknown = c.state["delivery_uncertainty"] == true;
    let outcome = c.state["verifications"][0]["state"].clone();
    cleanup_regression_fixture(c);
    assert!(!unknown, "conclusive first rejection became ambiguous");
    assert_eq!(outcome, "rejected");
}
#[test]
fn capability_unknown_post_error_propagates_and_retains_work() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    c.save().unwrap();
    c.script = Some(Script::new(vec![
        ("self", "", response(200, fixture_self())),
        (
            "events",
            "limit=0",
            response(
                200,
                json!({"timeline":"public","next_cursor":"anchor","events":[]}),
            ),
        ),
        (
            "messages",
            "",
            response(422, json!({"error":{"code":"fixture_unknown_error"}})),
        ),
    ]));
    let stopped = c.send_pending().is_err();
    let retained = c.state["pending"].is_object();
    cleanup_regression_fixture(c);
    assert!(stopped, "unknown error was swallowed");
    assert!(retained, "unknown outcome was silently consumed");
}
#[test]
fn capability_reset_import_cannot_revive_terminal_receipt() {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(20);
    c.page(&old_directed_page(false), true).unwrap();
    let generation = json!({"generation_id":"reset-generation","phase":"unknown","intent":{"kind":"reply","trigger_id":"fixture-question","timeline":"public","reply_to_event_id":"fixture-question","allowed_mentions":["fixture-peer"],"max_text_scalars":2000}});
    journal::reserve(&mut c.state, &c.config, "2026-11-19", generation).unwrap();
    c.state["inbox"][0]["status"] = json!("generation_unknown");
    let mut reset = old_directed_page(true);
    reset["events"] = json!([]);
    c.page(&reset, true).unwrap();
    let before = c.state.clone();
    let result = journal::recover(
        &mut c.state,
        "reset-generation",
        "import",
        Some(&json!({"generation_id":"reset-generation","text":"answer"})),
        "fixture-now",
        "new-message",
    );
    let after = c.state.clone();
    cleanup_regression_fixture(c);
    assert!(
        result.is_err(),
        "ordinary import revived reset-terminal work"
    );
    assert_eq!(after, before, "rejected import mutated the journal");
}
#[test]
fn capability_verification_uses_head_seq_not_fixture_has_more() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    c.state["pending"]["verification_cursor"] = json!("anchor");
    journal::accept(
        &mut c.state,
        &json!({"event_id":"ours","seq":80}),
        "fixture-now",
    )
    .unwrap();
    c.script = Some(Script::new(vec![(
        "events",
        "after=anchor&limit=50",
        response(
            200,
            json!({"timeline":"public","next_cursor":"page-two","head_seq":80,"events":[{"event_id":"noise","seq":50,"kind":"agent_joined"}]}),
        ),
    )]));
    c.verify_one().unwrap();
    let due = number(&c.state["verifications"][0], "next_check_epoch") <= now();
    cleanup_regression_fixture(c);
    assert!(
        due,
        "known backlog was delayed waiting for undefined has_more"
    );
}
#[test]
fn capability_due_verification_is_immediate_work_without_model_budget() {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(0);
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    journal::accept(
        &mut c.state,
        &json!({"event_id":"ours","seq":80}),
        "fixture-now",
    )
    .unwrap();
    let ready = c.immediate_work().unwrap();
    cleanup_regression_fixture(c);
    assert!(
        ready,
        "due reconciliation was hidden behind a 30-second receive wait"
    );
}
#[test]
fn capability_verification_prefers_longest_waiting_due_job() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    c.state["pending"]["verification_cursor"] = json!("anchor");
    journal::accept(
        &mut c.state,
        &json!({"event_id":"lost-before-restore","seq":100}),
        "fixture-now",
    )
    .unwrap();
    c.state["verifications"][0]["next_check_epoch"] = json!(now() - 1.0);
    c.state["pending"] = draft();
    c.state["pending"]["body"]["client_message_id"] = json!("newer-message");
    c.state["pending"]["verification_cursor"] = json!("anchor");
    journal::accept(
        &mut c.state,
        &json!({"event_id":"our-fixture-event","seq":11}),
        "fixture-now",
    )
    .unwrap();
    let mut event = accepted_event();
    event["seq"] = json!(11);
    c.script = Some(Script::new(vec![(
        "events",
        "after=anchor&limit=50",
        response(
            200,
            json!({"timeline":"public","next_cursor":"after-11","head_seq":11,"events":[event]}),
        ),
    )]));
    c.verify_one().unwrap();
    let outcome = c.state["verifications"][1]["state"].clone();
    cleanup_regression_fixture(c);
    assert_eq!(
        outcome, "verified",
        "older unresolved job took the newer job's overdue turn"
    );
}
#[test]
fn capability_page_discards_paused_receipts_without_budget_or_generation_slot() {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(0);
    let mut current = fixture_self();
    current["room_paused"] = json!(true);
    c.state["self"] = current;
    c.state["rust_generation"] = json!({"generation_id":"older-unknown","phase":"unknown","intent":{"trigger_id":"older-question","kind":"reply"}});
    c.page(&old_directed_page(false), true).unwrap();
    let outcome = c.state["inbox"][0]["status"].clone();
    cleanup_regression_fixture(c);
    assert_eq!(
        outcome, "discarded",
        "ineligible intake waited for a model slot or budget"
    );
}
#[test]
fn capability_refresh_pause_cancels_unattempted_draft_during_cooldown() {
    let mut c = fixture_client();
    journal::prepare(&mut c.state).unwrap();
    c.state["pending"] = draft();
    c.state["next_public_send_epoch"] = json!(now() + 60.0);
    let mut current = fixture_self();
    current["room_paused"] = json!(true);
    c.script = Some(Script::new(vec![("self", "", response(200, current))]));
    c.refresh_self().unwrap();
    let discarded = c.state["pending"].is_null();
    let uncertain = c.state["delivery_uncertainty"] == true;
    cleanup_regression_fixture(c);
    assert!(discarded, "observed pause left a cooldown draft queued");
    assert!(!uncertain);
}
#[test]
fn capability_reservation_resamples_day_after_roster() {
    let mut c = fixture_client();
    c.config["model_daily_limit"] = json!(20);
    c.state["model_invocations"] = json!(19);
    c.state["model_budget"] = json!({"utc_day":"2026-11-18","used":19,"legacy_carry":0});
    c.page(&old_directed_page(false), true).unwrap();
    let receipt = c.state["inbox"][0].clone();
    let mut script = Script::new(vec![(
        "agents",
        "",
        response(200, json!({"timeline":"public","agents":[]})),
    )]);
    script.budget_day = Some("2026-11-18".into());
    script.day_after_agents = Some("2026-11-19".into());
    script.model_reply = "[SILENT]".into();
    c.script = Some(script);
    c.generate_receipt(&receipt, &fixture_self()).unwrap();
    let budget = c.state["model_budget"].clone();
    let calls = c.script.as_ref().unwrap().generation_calls;
    cleanup_regression_fixture(c);
    assert_eq!(calls, 1);
    assert_eq!(
        budget["utc_day"], "2026-11-19",
        "reservation used the date sampled before roster work"
    );
    assert_eq!(budget["used"], 1);
}
#[cfg(windows)]
#[test]
fn capability_recovery_rejects_foreign_acl_on_state_or_import() {
    for filename in ["state.json", "fixture-import.json"] {
        let mut c = fixture_client();
        c.state["rust_generation"] = json!({"generation_id":"fixture-id","phase":"unknown","intent":{"kind":"diagnostic","timeline":"test-not-published","trigger_id":"fixture-trigger","allowed_mentions":[],"max_text_scalars":200}});
        c.save().unwrap();
        let home = c.home.clone();
        drop(c);
        let imported = home.join("fixture-import.json");
        save(
            &imported,
            &json!({"generation_id":"fixture-id","text":"fixture"}),
        )
        .unwrap();
        let original = fs::read(home.join("state.json")).unwrap();
        grant_foreign_read_write(&home.join(filename));
        let result =
            operations::recover(&home, "fixture-id", "import", Some(&imported), "fixture-id");
        let after = fs::read(home.join("state.json")).unwrap();
        fs::remove_dir_all(&home).unwrap();
        assert_eq!(
            result.unwrap_err().to_string(),
            "permission_denied",
            "allowed {filename}"
        );
        assert_eq!(original, after);
    }
}
fn capability_effect(case: &str, seconds: u64) -> Result<std::process::Output> {
    let c = fixture_client();
    c.save()?;
    let home = c.home.clone();
    drop(c);
    let mut command = Command::new(env::current_exe()?);
    command.args([
        "--ignored",
        "--exact",
        "runtime::tests::capability_effect_child",
        "--nocapture",
    ]);
    command
        .env("TOLINK_TEST_EFFECT_CASE", case)
        .env("TOLINK_TEST_EFFECT_HOME", &home);
    let stop = AtomicBool::new(false);
    let result = crate::process::capture(command, b"", seconds, false, &stop);
    fs::remove_dir_all(home)?;
    result
}
#[cfg(unix)]
#[test]
fn capability_save_recovers_after_own_precommit_write_failure() {
    let output = capability_effect("save", 5).unwrap();
    assert!(
        output.status.success(),
        "isolated save control failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[cfg(unix)]
#[test]
fn capability_fifo_import_is_refused_without_blocking() {
    let output =
        capability_effect("fifo", 1).expect("FIFO import blocked until the capture deadline");
    assert!(
        output.status.success(),
        "FIFO refusal failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[cfg(windows)]
#[test]
fn capability_save_recovers_after_windows_sharing_violation() {
    let output = capability_effect("sharing", 5).unwrap();
    assert!(
        output.status.success(),
        "isolated Windows replacement control failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[cfg(windows)]
#[test]
fn capability_named_pipe_import_is_refused_without_blocking() {
    let output = capability_effect("named-pipe", 1)
        .expect("named-pipe import blocked until the capture deadline");
    assert!(
        output.status.success(),
        "named-pipe refusal failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
#[ignore = "explicitly entered by isolated effect tests; never change test-runner rlimits"]
fn capability_effect_child() {
    let home = PathBuf::from(env::var_os("TOLINK_TEST_EFFECT_HOME").expect("isolated effect home"));
    match env::var("TOLINK_TEST_EFFECT_CASE").unwrap().as_str() {
        #[cfg(unix)]
        "save" => {
            let path = home.join("write-control.json");
            save(&path, &json!({"old":true})).unwrap();
            let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut original) },
                0
            );
            unsafe {
                libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            }
            let limited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: original.rlim_max,
            };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limited) }, 0);
            let first = save(&path, &json!({"new":true}));
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &original) }, 0);
            assert!(first.is_err(), "native failure control did not fail");
            assert_eq!(load(&path).unwrap(), json!({"old":true}));
            save(&path, &json!({"recovered":true})).expect("own leftover poisoned the next save");
            assert_eq!(load(&path).unwrap(), json!({"recovered":true}));
        }
        #[cfg(unix)]
        "fifo" => {
            let path = home.join("import.fifo");
            let raw = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(), 0o600) }, 0);
            let before = fs::read(home.join("state.json")).unwrap();
            assert!(
                operations::recover(&home, "synthetic", "import", Some(&path), "synthetic")
                    .is_err()
            );
            assert_eq!(fs::read(home.join("state.json")).unwrap(), before);
        }
        #[cfg(windows)]
        "sharing" => {
            use std::os::windows::fs::OpenOptionsExt;
            let path = home.join("write-control.json");
            save(&path, &json!({"old":true})).unwrap();
            // Share reads/writes, but not DELETE: replacing this destination must fail.
            let held = fs::OpenOptions::new()
                .read(true)
                .share_mode(0x1 | 0x2)
                .open(&path)
                .unwrap();
            let first = save(&path, &json!({"new":true}));
            assert!(
                first.is_err(),
                "Windows sharing-violation control did not fail"
            );
            assert_eq!(load(&path).unwrap(), json!({"old":true}));
            assert!(
                fs::read_dir(&home).unwrap().all(|entry| {
                    !entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains("rust-tmp-")
                }),
                "failed replacement leaked its own temporary file"
            );
            drop(held);
            save(&path, &json!({"recovered":true})).expect("own leftover poisoned the next save");
            assert_eq!(load(&path).unwrap(), json!({"recovered":true}));
        }
        #[cfg(windows)]
        "named-pipe" => {
            use std::ffi::c_void;
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn CreateNamedPipeW(
                    name: *const u16,
                    open_mode: u32,
                    pipe_mode: u32,
                    max_instances: u32,
                    out_size: u32,
                    in_size: u32,
                    default_timeout: u32,
                    security: *const c_void,
                ) -> *mut c_void;
                fn CloseHandle(handle: *mut c_void) -> i32;
            }
            let path = PathBuf::from(format!(
                r"\\.\pipe\tolink-synthetic-import-{}-{}",
                std::process::id(),
                token().unwrap()
            ));
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // An unconnected local pipe catches accidental blocking recovery opens.
            let pipe = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    0x1 | 0x80000,
                    0,
                    1,
                    4096,
                    4096,
                    0,
                    std::ptr::null(),
                )
            };
            assert_ne!(pipe as isize, -1, "{}", io::Error::last_os_error());
            let before = fs::read(home.join("state.json")).unwrap();
            let refused =
                operations::recover(&home, "synthetic", "import", Some(&path), "synthetic");
            assert_ne!(unsafe { CloseHandle(pipe) }, 0);
            assert!(refused.is_err(), "named-pipe import was admitted");
            assert_eq!(fs::read(home.join("state.json")).unwrap(), before);
        }
        _ => panic!("unknown isolated effect"),
    }
}
