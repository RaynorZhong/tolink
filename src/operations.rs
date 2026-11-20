//! Local Owner commands. Inspection/recovery do not read the identity seed or call a service.
use super::*;

fn key_guard(config: &Value) -> Result<Option<crate::platform::KeyMetadata>> {
    match config.get("key_file") {
        None => Ok(None),
        Some(value) => {
            let path = value
                .as_str()
                .filter(|p| !p.is_empty() && !p.contains('\0'))
                .ok_or("signing key path invalid; offline content reads refused")?;
            Ok(Some(crate::platform::key_metadata(Path::new(path))?))
        }
    }
}
fn offline_document(path: &Path, config: &Value) -> Result<Value> {
    let key = key_guard(config)?;
    let bytes = crate::platform::read_private_regular(path, u64::MAX, key.as_ref())
        .map_err(|code| io::Error::new(io::ErrorKind::InvalidData, code))?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn offline(home: &Path) -> Result<(Value, Value)> {
    let config = if home.join("config.json").exists() {
        load(&home.join("config.json"))?
    } else {
        json!({})
    };
    let mut state = offline_document(&home.join("state.json"), &config)?;
    journal::prepare(&mut state)?;
    Ok((config, state))
}
pub(crate) fn status(home: &Path) -> Result<()> {
    let (config, mut state) = offline(home)?;
    let budget = journal::budget(
        &mut state,
        &config,
        &OffsetDateTime::now_utc().date().to_string(),
    )?;
    let mut verification_states = std::collections::BTreeMap::<String, usize>::new();
    for job in state["verifications"]
        .as_array()
        .ok_or("verification journal missing")?
    {
        *verification_states
            .entry(job["state"].as_str().unwrap_or("invalid").to_owned())
            .or_default() += 1;
    }
    let verification_attention: usize = verification_states
        .iter()
        .filter(|(state, _)| {
            matches!(
                state.as_str(),
                "mismatch"
                    | "timeline_reset"
                    | "history_unavailable"
                    | "delivery_unknown_cancelled"
                    | "invalid"
            )
        })
        .map(|(_, count)| *count)
        .sum();
    let inbox = journal::receipts(&state)?;
    let process = if home.join("process.json").exists() {
        offline_document(&home.join("process.json"), &config)?
    } else {
        Value::Null
    };
    println!(
        "{}",
        json!({"offline":true,"read_only":true,"normalized_view_only":true,"build":crate::diagnostics::build_info(),"reported_process_unverified":process,"cursor_present":state["cursor"].is_string(),"timeline":state["timeline"],"pending":state["pending"].is_object(),"receipts_unresolved":inbox.iter().filter(|r|!journal::terminal_receipt(r["status"].as_str().unwrap_or(""))).count(),"generation":{"generation_id":state["rust_generation"]["generation_id"],"phase":state["rust_generation"]["phase"],"trigger_id":state["rust_generation"]["intent"]["trigger_id"].as_str().or(state["rust_generation"]["trigger_id"].as_str())},"verification_pending":state["verifications"].as_array().ok_or("verification journal missing")?.iter().filter(|j|j["state"]=="accepted").count(),"verification_states":verification_states,"verification_attention":verification_attention,"model_budget":budget,"model_attempts_total":state["model_invocations"],"owned_cleanup_unconfirmed":state["owned_cleanup_unconfirmed"]==true,"delivery_uncertainty":state["delivery_uncertainty"]==true})
    );
    Ok(())
}
pub(crate) fn inspect(home: &Path) -> Result<()> {
    let (_, state) = offline(home)?;
    println!(
        "{}",
        json!({"offline":true,"read_only":true,"normalized_view_only":true,"generation":state["rust_generation"],"pending":state["pending"],"inbox":state["inbox"],"verifications":state["verifications"],"generation_history":state["generation_history"]})
    );
    Ok(())
}
pub(crate) fn recover(
    home: &Path,
    id: &str,
    action: &str,
    import_path: Option<&Path>,
    confirm: &str,
) -> Result<()> {
    require(
        id == confirm,
        "confirmation must match the exact generation ID",
    )?;
    let directory = crate::platform::pin_private_dir(home)?;
    let home = directory.path.as_path();
    let _guard = lock(home)?;
    let (config, mut state) = offline(home)?;
    require(
        state["owned_cleanup_unconfirmed"] != true,
        "owned process cleanup is unconfirmed; inspect native processes before further operations; this command does not bypass that gate",
    )?;
    let imported = if let Some(path) = import_path {
        const LIMIT: u64 = 4 * 1024 * 1024;
        let key = key_guard(&config)?;
        let raw = crate::platform::read_private_regular(path, LIMIT, key.as_ref())
            .map_err(|code| io::Error::new(io::ErrorKind::InvalidData, code))?;
        Some(serde_json::from_slice(&raw)?)
    } else {
        None
    };
    journal::recover(
        &mut state,
        id,
        action,
        imported.as_ref(),
        &utc()?,
        &token()?,
    )?;
    save(&home.join("state.json"), &state)?;
    println!(
        "{}",
        json!({"resolved_generation_id":id,"action":action,"model_called":false,"published":false,"existing_budget_not_refunded":true,"pending_created":state["pending"].is_object()})
    );
    Ok(())
}
pub(crate) fn fresh_self(home: &Path) -> Result<()> {
    install_signals()?;
    match Client::open(home) {
        Ok(mut client) => {
            let current = client
                .refresh_self()?
                .ok_or("request deferred by durable backoff; inspect status and try later")?;
            println!("{current}");
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::WouldBlock) =>
        {
            let id = token()?;
            save(&home.join("self-request.json"), &json!({"request_id":id}))?;
            let deadline = Instant::now() + Duration::from_secs(240);
            while Instant::now() < deadline {
                require(!STOP.load(Ordering::Relaxed), "owner_stop")?;
                if home.join("last-self.json").exists() {
                    let snapshot = load(&home.join("last-self.json"))?;
                    if snapshot["request_id"] == id {
                        println!("{snapshot}");
                        return Ok(());
                    }
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err("fresh self timed out; no second request lane opened; status/inspect remain offline".into())
        }
        Err(error) => Err(error),
    }
}
pub(crate) fn speak(home: &Path, recipient: &str, topic: &str, request_id: &str) -> Result<()> {
    validate_owner_topic(topic)?;
    install_signals()?;
    let mut client = Client::open(home)?;
    require(
        client.state["pending"].is_null(),
        "existing outbox must be resolved first",
    )?;
    require(
        client.state["rust_generation"].is_null(),
        "unknown generation requires inspect/recover, not another model call",
    )?;
    let id = format!("owner-{}", sha(request_id.as_bytes()));
    require(
        !contains(&client.state, "outreach_request_ids", &id)
            && !contains(&client.state, "handled", &id)
            && !journal::receipts(&client.state)?
                .iter()
                .any(|r| r["event_id"] == id),
        "Owner outreach already recorded; use run to continue its saved work, not another speak",
    )?;
    let original_cursor = client.state["cursor"].clone();
    let current = client
        .refresh_self()?
        .ok_or("self deferred; no model call")?;
    require(
        current["state"] == "ACTIVE"
            && current["timeline"] == "public"
            && current["mute"].is_null()
            && current["room_paused"] == false,
        "public outreach currently unavailable",
    )?;
    let (status, roster) = client
        .call("agents", "", None)?
        .ok_or("roster deferred; no model call")?;
    require(
        status == 200 && roster["timeline"] == "public",
        "public roster unavailable",
    )?;
    let matches: Vec<&Value> = roster["agents"]
        .as_array()
        .ok_or("missing roster")?
        .iter()
        .filter(|a| a["agent_id"] == recipient || a["display_name"] == recipient)
        .collect();
    require(
        matches.len() == 1,
        "recipient must match exactly one current participant",
    )?;
    let recipient = matches[0].clone();
    let recipient_id = text(&recipient, "agent_id")?;
    require(
        crate::addressing::valid_id(recipient_id)
            && recipient_id != "examiner"
            && current["agent_id"] != recipient_id,
        "invalid/self recipient for outreach",
    )?;
    let (status, page) = client
        .call("events", "limit=50", None)?
        .ok_or("context deferred; no model call")?;
    require(
        status == 200 && page["timeline"] == "public",
        "public context unavailable",
    )?;
    client.merge_retractions(&page)?;
    client.state["context"] = json!(
        page["events"]
            .as_array()
            .ok_or("events missing")?
            .iter()
            .filter(|e| e["kind"] == "agent_message"
                && e["retracted"] != true
                && !contains(
                    &client.state,
                    "retracted_event_ids",
                    e["event_id"].as_str().unwrap_or("")
                ))
            .map(public_event)
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
    );
    let receipt = json!({"event_id":id,"kind":"outreach","event":{"kind":"owner_outreach","event_id":id},"timeline":"public","notice":page["notice"],"owner_topic":topic,"recipient_id":recipient_id,"received_at":utc()?,"status":"received"});
    journal::add_receipt(&mut client.state, receipt.clone())?;
    client.save()?;
    client.generate_receipt(&receipt, &current)?;
    require(
        client.state["rust_generation"].is_null(),
        "model result uncertain/rejected; use offline inspect/recover",
    )?;
    if client.state["pending"].is_null() {
        println!(
            "{}",
            json!({"published":false,"recorded_owner_request":id,"reason":"silent_or_budget_unavailable; saved work may be resumed with run","cursor_unchanged":client.state["cursor"]==original_cursor})
        );
        return Ok(());
    }
    let deadline = Instant::now() + Duration::from_secs(240);
    while Instant::now() < deadline && !client.state["pending"].is_null() {
        client.send_pending()?;
        if !client.state["pending"].is_null() {
            sleep(0.2)?;
        }
    }
    require(
        client.state["pending"].is_null(),
        "send still pending; original ID/body retained; run will resume",
    )?;
    let accepted = client.state["verifications"]
        .as_array()
        .ok_or("verification journal missing")?
        .iter()
        .find(|j| j["trigger_id"] == id)
        .cloned()
        .ok_or("outreach result missing")?;
    if accepted["state"] == "accepted" {
        client.verify_one()?;
    }
    let result = client.state["verifications"]
        .as_array()
        .ok_or("verification journal missing")?
        .iter()
        .find(|j| j["trigger_id"] == id)
        .ok_or("outreach result missing")?;
    println!(
        "{}",
        json!({"recipient":recipient,"accepted":result["accepted"].is_object(),"verification_state":result["state"],"event_id":result["accepted"]["event_id"],"seq":result["accepted"]["seq"],"cursor_unchanged":client.state["cursor"]==original_cursor,"published_and_read_back":result["state"]=="verified"})
    );
    Ok(())
}
pub(crate) fn model_check(home: &Path) -> Result<()> {
    install_signals()?;
    let directory = crate::platform::pin_private_dir(home)?;
    let home = directory.path.as_path();
    let _guard = lock(home)?;
    let (config, mut state) = offline(home)?;
    require(
        state["owned_cleanup_unconfirmed"] != true,
        "owned cleanup unconfirmed",
    )?;
    let id = format!("diagnostic-{}", token()?);
    let identity = if state["self"].is_object() {
        json!({"agent_id":state["self"]["agent_id"],"display_name":state["self"]["display_name"]})
    } else {
        json!({"agent_id":"diagnostic","display_name":"Nonpublished diagnostic"})
    };
    let payload = json!({"notice":"不发布的连接检查；合成公开问题。","identity":identity,"timeline":"test-not-published","participants":[],"context":[],"trigger":{"kind":"agent_message","text":"面对一次请求超时，为什么不能立即断定服务端没有完成操作？请用一句话回答。"},"max_text_scalars":200});
    model_executable(&config)?;
    let generation = json!({"generation_id":id,"started_at":utc()?,"phase":"started","intent":{"kind":"diagnostic","trigger_id":id,"timeline":"test-not-published","allowed_mentions":[],"max_text_scalars":200}});
    #[cfg(windows)]
    {
        require(
            state["rust_generation"].is_null(),
            "previous generation unresolved; no automatic retry",
        )?;
        let day = OffsetDateTime::now_utc().date().to_string();
        require(
            journal::budget(&mut state, &config, &day)?["reason"] == "available",
            "finite daily model budget unavailable",
        )?;
        if let Err(error) = check_model_gateway(home, &config) {
            if crate::process::cleanup_unconfirmed(error.as_ref()) {
                state["owned_cleanup_unconfirmed"] = json!(true);
                save(&home.join("state.json"), &state)?;
            }
            return Err(error);
        }
    }
    require(!STOP.load(Ordering::Relaxed), "owner_stop_before_model")?;
    journal::reserve(
        &mut state,
        &config,
        &OffsetDateTime::now_utc().date().to_string(),
        generation,
    )?;
    save(&home.join("state.json"), &state)?;
    match model(home, &config, &payload) {
        Ok(reply) => {
            if let Err(error) = journal::complete_generation(
                &mut state,
                &reply,
                &token()?,
                &utc()?,
                "native_hermes",
            ) {
                state["rust_generation"]["phase"] = json!("result_rejected");
                state["rust_generation"]["result"] = json!(reply);
                save(&home.join("state.json"), &state)?;
                return Err(error);
            }
            save(&home.join("state.json"), &state)?;
            println!(
                "{}",
                json!({"model_reply":reply,"published":false,"tools":0,"private_memory":false,"budget_charged":true})
            );
            Ok(())
        }
        Err(error) => {
            state["rust_generation"]["phase"] = json!("unknown");
            if crate::process::cleanup_unconfirmed(error.as_ref()) {
                state["owned_cleanup_unconfirmed"] = json!(true);
            }
            save(&home.join("state.json"), &state)?;
            Err(error)
        }
    }
}
