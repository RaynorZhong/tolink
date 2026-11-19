//! Durable local work decisions. No network or process effects live here.
use crate::{Result, Value, addressing, json, require, sha};
use std::collections::BTreeSet;

pub(crate) const VERSION: u64 = 3;
const OPTIONAL_ARRAYS: &[&str] = &[
    "inbox",
    "verifications",
    "generation_history",
    "retracted_event_ids",
    "outreach_request_ids",
];

/// Pure, redacted format checks shared by runtime admission and offline doctor.
pub(crate) fn validate_format(state: &Value) -> Result<()> {
    require(state.is_object(), "state must be an object")?;
    require(
        state["rust_journal_version"].is_null()
            || state["rust_journal_version"]
                .as_u64()
                .is_some_and(|v| (1..=VERSION).contains(&v)),
        "unsupported runtime journal",
    )?;
    for field in ["context", "handled", "own_event_ids"] {
        require(state[field].is_array(), &format!("{field}: expected array"))?;
    }
    for &field in OPTIONAL_ARRAYS {
        require(
            state[field].is_null() || state[field].is_array(),
            &format!("{field}: expected array when present"),
        )?;
    }
    for field in ["pending", "rust_generation"] {
        require(
            state[field].is_null() || state[field].is_object(),
            &format!("{field}: expected object or null"),
        )?;
    }
    for field in ["self_refresh_required"] {
        require(
            state[field].is_null() || state[field].is_boolean(),
            "invalid self refresh marker",
        )?;
    }
    if !state["pending"]["accepted"].is_null() {
        validate_ack(&state["pending"]["accepted"])?;
    }
    if let Some(receipts) = state["inbox"].as_array() {
        for receipt in receipts {
            let work = &receipt["retry_work"];
            if !work.is_null() {
                require(
                    work.is_object() && work["timeline"].is_string(),
                    "invalid saved retry group",
                )?;
                let ids = work_ids(work)?;
                require(
                    receipt["event_id"]
                        .as_str()
                        .is_some_and(|id| ids.iter().any(|v| v == id)),
                    "retry group does not contain its receipt",
                )?;
            }
        }
    }
    Ok(())
}
fn validate_ack(ack: &Value) -> Result<()> {
    string(ack, "event_id")?;
    require(
        ack["seq"].as_u64().is_some_and(|n| n > 0),
        "invalid accepted sequence",
    )
}

pub(crate) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("missing {key}").into())
}
pub(crate) fn append_id(
    state: &mut Value,
    key: &str,
    id: &str,
    bound: Option<usize>,
) -> Result<()> {
    let ids = state[key].as_array_mut().ok_or("missing ID array")?;
    if !ids.iter().any(|v| v.as_str() == Some(id)) {
        ids.push(json!(id));
    }
    if let Some(limit) = bound {
        if ids.len() > limit {
            ids.drain(..ids.len() - limit);
        }
    }
    Ok(())
}
pub(crate) fn contains(state: &Value, key: &str, id: &str) -> bool {
    state[key]
        .as_array()
        .is_some_and(|items| items.iter().any(|v| v.as_str() == Some(id)))
}
fn recipient_defaults(pending: &mut Value, context: &Value) {
    if !pending.is_object() || !pending["allowed_mentions"].is_null() {
        return;
    }
    let mut ids = pending["body"]["mentions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if let Some(event) = context.as_array().and_then(|items| {
        items
            .iter()
            .find(|e| e["event_id"] == pending["trigger_id"])
    }) {
        if let Some(author) = event["agent"]["agent_id"].as_str() {
            if !ids.iter().any(|v| v == author) {
                ids.push(json!(author));
            }
        }
    }
    pending["allowed_mentions"] = json!(ids);
    pending["required_recipient"] = if pending["body"]["reply_to_event_id"].is_null() {
        pending["body"]["mentions"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
}
pub(crate) fn prepare(state: &mut Value) -> Result<()> {
    validate_format(state)?;
    state["rust_journal_version"] = json!(VERSION);
    for &field in OPTIONAL_ARRAYS {
        if state[field].is_null() {
            state[field] = json!([]);
        }
    }
    if !state["rust_generation"].is_null() && state["rust_generation"]["generation_id"].is_null() {
        let id = format!(
            "legacy-{}",
            sha(&serde_json::to_vec(&state["rust_generation"])?)
        );
        state["rust_generation"]["generation_id"] = json!(id);
        state["rust_generation"]["phase"] = json!("unknown");
        // Legacy markers without an intent cannot safely be retried/imported.
    }
    let context = state["context"].clone();
    recipient_defaults(&mut state["pending"], &context);
    // Recover every retained Owner request before bounded history can be pruned.
    // Already-evicted pre-upgrade evidence cannot be reconstructed.
    let mut owner_ids = BTreeSet::new();
    let mut remember = |value: &Value| {
        if let Some(id) = value.as_str().filter(|id| id.starts_with("owner-")) {
            owner_ids.insert(id.to_owned());
        }
    };
    for id in state["handled"].as_array().ok_or("handled missing")? {
        remember(id);
    }
    for field in ["inbox", "verifications", "generation_history"] {
        for record in state[field].as_array().ok_or("journal array missing")? {
            remember(&record["event_id"]);
            remember(&record["trigger_id"]);
        }
    }
    remember(&state["pending"]["trigger_id"]);
    remember(&state["rust_generation"]["trigger_id"]);
    remember(&state["rust_generation"]["intent"]["trigger_id"]);
    for id in owner_ids {
        append_id(state, "outreach_request_ids", &id, None)?;
    }
    if !state["pending"]["accepted"].is_null() {
        let pending = state["pending"].clone();
        let ack = pending["accepted"].clone();
        accept(state, &ack, "legacy-upgrade")?;
    }
    Ok(())
}
pub(crate) fn receipts(state: &Value) -> Result<&Vec<Value>> {
    state["inbox"]
        .as_array()
        .ok_or_else(|| "missing inbox".into())
}
pub(crate) fn receipt_mut<'a>(state: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    state["inbox"]
        .as_array_mut()?
        .iter_mut()
        .find(|r| r["event_id"] == id)
}
pub(crate) fn add_receipt(state: &mut Value, receipt: Value) -> Result<()> {
    let id = string(&receipt, "event_id")?;
    let outreach = receipt["kind"] == "outreach";
    if outreach && contains(state, "outreach_request_ids", id) {
        return Ok(());
    }
    if contains(state, "handled", id) || receipts(state)?.iter().any(|r| r["event_id"] == id) {
        return Ok(());
    }
    // This index is committed with the receipt before any model/POST and never
    // expires with terminal history. Ordinary retry uses the existing receipt.
    if outreach {
        append_id(state, "outreach_request_ids", id, None)?;
    }
    state["inbox"]
        .as_array_mut()
        .ok_or("missing inbox")?
        .push(receipt);
    Ok(())
}
pub(crate) fn decision(state: &mut Value, id: &str, status: &str, reason: &str) -> Result<()> {
    if let Some(receipt) = receipt_mut(state, id) {
        receipt["status"] = json!(status);
        receipt["reason"] = json!(reason);
    }
    append_id(state, "handled", id, Some(512))?;
    Ok(())
}
pub(crate) fn work_ids(work: &Value) -> Result<Vec<String>> {
    let primary = string(work, "trigger_id")?;
    let ids = if work["trigger_ids"].is_null() {
        vec![primary.to_owned()]
    } else {
        work["trigger_ids"]
            .as_array()
            .ok_or("invalid trigger set")?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "invalid trigger ID".into())
            })
            .collect::<Result<Vec<String>>>()?
    };
    require(
        !ids.is_empty()
            && ids.len() <= 3
            && ids.iter().any(|id| id == primary)
            && ids.iter().collect::<BTreeSet<_>>().len() == ids.len(),
        "invalid trigger set",
    )?;
    Ok(ids)
}
pub(crate) fn decide_work(
    state: &mut Value,
    work: &Value,
    status: &str,
    reason: &str,
) -> Result<()> {
    for id in work_ids(work)? {
        decision(state, &id, status, reason)?;
    }
    Ok(())
}
fn recoverable_work(state: &Value, generation: &Value) -> Result<()> {
    require(
        !generation["phase"]
            .as_str()
            .is_some_and(|p| p.starts_with("blocked_")),
        "blocked generation cannot be resumed",
    )?;
    let intent = &generation["intent"];
    if intent["kind"] == "diagnostic" {
        return Ok(());
    }
    for id in work_ids(intent)? {
        let r = receipts(state)?
            .iter()
            .find(|r| r["event_id"] == id)
            .ok_or("generation receipt missing")?;
        require(
            matches!(
                r["status"].as_str(),
                Some("received" | "generating" | "generation_unknown")
            ) && !contains(state, "retracted_event_ids", &id),
            "terminal or retracted/reset trigger cannot be resumed",
        )?;
    }
    Ok(())
}
pub(crate) fn terminal_receipt(status: &str) -> bool {
    matches!(
        status,
        "silent" | "discarded" | "accepted" | "retracted" | "diagnostic_complete"
    )
}
pub(crate) fn prune(state: &mut Value) -> Result<()> {
    // Never evict unresolved work to make room. Terminal records have explicit reasons.
    for (field, limit) in [
        ("inbox", 512usize),
        ("verifications", 128),
        ("generation_history", 64),
    ] {
        let items = state[field].as_array_mut().ok_or("invalid journal")?;
        let mut terminal = items
            .iter()
            .filter(|r| {
                if field == "inbox" {
                    terminal_receipt(r["status"].as_str().unwrap_or(""))
                } else if field == "verifications" {
                    verification_terminal(r)
                } else {
                    true
                }
            })
            .count();
        items.retain(|r| {
            let done = if field == "inbox" {
                terminal_receipt(r["status"].as_str().unwrap_or(""))
            } else if field == "verifications" {
                verification_terminal(r)
            } else {
                true
            };
            if done && terminal > limit {
                terminal -= 1;
                false
            } else {
                true
            }
        });
    }
    Ok(())
}

pub(crate) fn budget(state: &mut Value, config: &Value, day: &str) -> Result<Value> {
    if state["model_budget"].is_null() {
        let legacy = state["model_invocations"]
            .as_u64()
            .ok_or("invalid invocation count")?;
        state["model_budget"] = json!({"utc_day":day,"used":legacy,"legacy_carry":legacy});
    }
    let stored = string(&state["model_budget"], "utc_day")?.to_owned();
    require(stored.len() == 10 && day.len() == 10, "invalid budget day")?;
    require(
        state["model_budget"]["used"].as_u64().is_some(),
        "invalid budget count",
    )?;
    // A backwards wall-clock adjustment must not refill today's budget.
    if day > stored.as_str() {
        state["model_budget"] = json!({"utc_day":day,"used":0,"legacy_carry":0});
    }
    let limit = config["model_daily_limit"].as_u64();
    let used = state["model_budget"]["used"]
        .as_u64()
        .ok_or("invalid budget count")?;
    let reason = if day < stored.as_str() {
        "clock_rollback_blocked"
    } else {
        match limit {
            None => "budget_not_configured",
            Some(0) => "model_disabled",
            Some(n) if used >= n => "daily_budget_exhausted",
            Some(_) => "available",
        }
    };
    Ok(
        json!({"utc_day":state["model_budget"]["utc_day"],"used":used,"limit":limit,"reason":reason,"legacy_carry":state["model_budget"]["legacy_carry"]}),
    )
}
pub(crate) fn reserve(
    state: &mut Value,
    config: &Value,
    day: &str,
    generation: Value,
) -> Result<()> {
    require(
        state["rust_generation"].is_null(),
        "previous generation unresolved; no automatic retry",
    )?;
    require(
        budget(state, config, day)?["reason"] == "available",
        "finite daily model budget unavailable",
    )?;
    let used = state["model_budget"]["used"]
        .as_u64()
        .ok_or("invalid budget")?
        .checked_add(1)
        .ok_or("budget overflow")?;
    let total = state["model_invocations"]
        .as_u64()
        .ok_or("invalid invocation total")?
        .checked_add(1)
        .ok_or("invocation overflow")?;
    require(
        generation["generation_id"].is_string() && generation["intent"].is_object(),
        "invalid generation intent",
    )?;
    let ids = work_ids(&generation["intent"])?;
    state["model_budget"]["used"] = json!(used);
    state["model_invocations"] = json!(total);
    for id in ids {
        if let Some(r) = receipt_mut(state, &id) {
            r["status"] = json!("generating");
            r.as_object_mut()
                .ok_or("invalid receipt")?
                .remove("retry_work");
        }
    }
    state["rust_generation"] = generation;
    Ok(())
}
fn allowed(intent: &Value) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    for id in intent["allowed_mentions"]
        .as_array()
        .ok_or("recipient intent missing")?
    {
        let id = id.as_str().ok_or("invalid intended recipient")?;
        require(addressing::valid_id(id), "invalid intended agent_id")?;
        result.insert(id.to_owned());
    }
    Ok(result)
}
pub(crate) fn validate_result(intent: &Value, reply: &str) -> Result<()> {
    let limit = intent["max_text_scalars"]
        .as_u64()
        .ok_or("missing text limit")?;
    require(
        reply.chars().count() as u64 <= limit,
        "model output too long; not truncated",
    )?;
    if reply.is_empty() || reply == "[SILENT]" {
        return Ok(());
    }
    let prefix = if intent["kind"] == "outreach" {
        Some(string(intent, "recipient_id")?)
    } else {
        None
    };
    addressing::validate_text(reply, &allowed(intent)?, prefix).map_err(Into::into)
}
pub(crate) fn complete_generation(
    state: &mut Value,
    reply: &str,
    message_id: &str,
    at: &str,
    provenance: &str,
) -> Result<()> {
    let generation = state["rust_generation"].clone();
    require(generation.is_object(), "no generation to complete")?;
    let intent = &generation["intent"];
    recoverable_work(state, &generation)?;
    if let Some(trigger) = intent["trigger_id"].as_str() {
        require(
            !contains(state, "retracted_event_ids", trigger),
            "retracted trigger cannot create another public draft",
        )?;
    }
    validate_result(intent, reply)?;
    let id = string(intent, "trigger_id")?.to_owned();
    if intent["kind"] == "diagnostic" {
        decide_work(
            state,
            intent,
            "diagnostic_complete",
            "nonpublished_model_check",
        )?;
    } else if reply.is_empty() || reply == "[SILENT]" {
        decide_work(
            state,
            intent,
            "silent",
            if reply.is_empty() {
                "empty_model_result"
            } else {
                "model_chose_silent"
            },
        )?;
    } else {
        require(
            state["pending"].is_null(),
            "existing outbox prevents another draft",
        )?;
        let mut body = json!({"client_message_id":message_id,"text":reply,"mentions":[]});
        if intent["kind"] == "outreach" {
            body["mentions"] = json!([intent["recipient_id"]]);
        } else {
            body["reply_to_event_id"] = intent["reply_to_event_id"].clone();
            body["mentions"] = intent["reply_mentions"]
                .as_array()
                .cloned()
                .map_or(json!([]), |ids| json!(ids));
        }
        state["pending"] = json!({"timeline":intent["timeline"],"trigger_id":id,"trigger_ids":work_ids(intent)?,"body":body,"allowed_mentions":intent["allowed_mentions"],"required_recipient":intent["recipient_id"],"generation_id":generation["generation_id"],"attempts":0,"verification_cursor":null});
        for selected in work_ids(intent)? {
            if let Some(r) = receipt_mut(state, &selected) {
                r["status"] = json!("draft");
                r["reason"] = json!("model_result_persisted");
            }
        }
    }
    let history = json!({"generation_id":generation["generation_id"],"trigger_id":id,"trigger_ids":work_ids(intent)?,"at":at,"outcome":if intent["kind"] == "diagnostic" {"diagnostic_complete"} else if reply.is_empty() || reply == "[SILENT]" {"silent"} else {"draft"},"provenance":provenance,"result_sha256":sha(reply.as_bytes())});
    state["generation_history"]
        .as_array_mut()
        .ok_or("missing generation history")?
        .push(history);
    state["rust_generation"] = Value::Null;
    prune(state)
}
pub(crate) fn recover(
    state: &mut Value,
    id: &str,
    action: &str,
    imported: Option<&Value>,
    at: &str,
    message_id: &str,
) -> Result<()> {
    require(
        state["rust_generation"]["generation_id"] == id,
        "generation ID differs or already resolved",
    )?;
    let generation = state["rust_generation"].clone();
    let trigger = generation["intent"]["trigger_id"]
        .as_str()
        .or_else(|| generation["trigger_id"].as_str())
        .ok_or("generation trigger missing")?
        .to_owned();
    match action {
        "import" => {
            let imported = imported.ok_or("result file required")?;
            require(
                imported["generation_id"] == id,
                "imported result belongs to another generation",
            )?;
            complete_generation(
                state,
                string(imported, "text")?,
                message_id,
                at,
                "owner_attested_model_result",
            )?;
        }
        "discard" => {
            let work = if generation["intent"].is_object() {
                &generation["intent"]
            } else {
                &generation
            };
            decide_work(
                state,
                work,
                "discarded",
                "owner_discarded_unknown_generation",
            )?;
            state["rust_generation"] = Value::Null;
        }
        "retry" => {
            require(
                generation["intent"].is_object() && receipt_mut(state, &trigger).is_some(),
                "legacy intent missing; retry cannot be reconstructed",
            )?;
            require(
                generation["intent"]["kind"] != "diagnostic",
                "discard diagnostic uncertainty, then explicitly run model-check",
            )?;
            recoverable_work(state, &generation)?;
            let ids = work_ids(&generation["intent"])?;
            let source_cursor = receipts(state)?
                .iter()
                .find(|r| r["event_id"] == trigger)
                .ok_or("receipt missing")?["source_cursor"]
                .clone();
            let work = json!({"trigger_id":trigger,"trigger_ids":ids,"timeline":generation["intent"]["timeline"],"source_cursor":source_cursor,"retry_of":id});
            for selected in work_ids(&work)? {
                let receipt = receipt_mut(state, &selected).ok_or("receipt missing")?;
                receipt["status"] = json!("received");
                receipt["reason"] = json!("owner_confirmed_new_billable_attempt");
                receipt["retry_work"] = work.clone();
            }
            state["rust_generation"] = Value::Null;
        }
        _ => return Err("unknown recovery action".into()),
    }
    state["generation_history"].as_array_mut().ok_or("missing generation history")?.push(json!({"generation_id":id,"trigger_id":trigger,"at":at,"outcome":format!("owner_{action}"),"previous_phase":generation["phase"]}));
    prune(state)
}

pub(crate) fn accept(state: &mut Value, ack: &Value, at: &str) -> Result<()> {
    let mut pending = state["pending"].clone();
    require(pending.is_object(), "no pending message")?;
    validate_ack(ack)?;
    let event_id = string(ack, "event_id")?;
    require(
        ack["seq"].as_u64().is_some_and(|n| n > 0),
        "invalid accepted sequence",
    )?;
    let trigger = string(&pending, "trigger_id")?.to_owned();
    pending["accepted"] = ack.clone();
    pending["state"] = json!("accepted");
    pending["accepted_at"] = json!(at);
    if pending["allowed_mentions"].is_null() {
        let mut ids = pending["body"]["mentions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if let Some(event) = state["context"]
            .as_array()
            .and_then(|a| a.iter().find(|e| e["event_id"] == trigger))
        {
            if let Some(author) = event["agent"]["agent_id"].as_str() {
                if !ids.iter().any(|v| v == author) {
                    ids.push(json!(author));
                }
            }
        }
        pending["allowed_mentions"] = json!(ids);
        pending["required_recipient"] = if pending["body"]["reply_to_event_id"].is_null() {
            pending["body"]["mentions"]
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
    }
    if pending["verification_cursor"].is_null() {
        pending["verification_cursor"] = state["cursor"].clone();
    }
    if pending["timeline"] == "public" {
        append_id(state, "own_event_ids", event_id, None)?;
    }
    state["verifications"]
        .as_array_mut()
        .ok_or("missing verification journal")?
        .push(pending);
    decide_work(
        state,
        &state["pending"].clone(),
        "accepted",
        "server_accepted_independent_verification_pending",
    )?;
    state["pending"] = Value::Null;
    prune(state)
}
pub(crate) fn verification_terminal(job: &Value) -> bool {
    job["state"] != "accepted"
}

pub(crate) fn verify_page(job: &mut Value, page: &Value, our_id: &str, at: &str) -> Result<()> {
    require(job["state"] == "accepted", "verification already terminal")?;
    job["checked_at"] = json!(at);
    if page["cursor_reset"] == true || page["timeline"] != job["timeline"] {
        job["state"] = json!("timeline_reset");
        job["reason"] = json!("accepted_but_original_timeline_no_longer_readable");
        return Ok(());
    }
    let events = page["events"]
        .as_array()
        .ok_or("verification events missing")?;
    let ack = job["accepted"].clone();
    if let Some(notice) = events
        .iter()
        .find(|e| e["kind"] == "event_retracted" && e["target"]["event_id"] == ack["event_id"])
    {
        job["state"] = json!(if notice["target"]["seq"] == ack["seq"] {
            "retracted"
        } else {
            "mismatch"
        });
        job["reason"] = json!("independent_retraction_notice_for_accepted_event");
        job["observed_retraction"] = notice.clone();
        return Ok(());
    }
    if let Some(event) = events
        .iter()
        .find(|event| event["event_id"] == ack["event_id"])
    {
        job["observed"] = json!({"event_id":event["event_id"],"seq":event["seq"],"agent":event["agent"],"reply_to":event["reply_to"],"mentions":event["mentions"],"retracted":event["retracted"],"text_sha256":event["text"].as_str().map(|t|sha(t.as_bytes()))});
        if event["seq"] != ack["seq"] || event["agent"]["agent_id"] != our_id {
            job["state"] = json!("mismatch");
            job["reason"] = json!("event_identity_mismatch");
            return Ok(());
        }
        if event["retracted"] == true {
            job["state"] = json!("retracted");
            job["reason"] = json!("accepted_event_now_retracted");
            return Ok(());
        }
        let actual: BTreeSet<String> = event["mentions"]
            .as_array()
            .ok_or("readback mentions missing")?
            .iter()
            .map(|v| string(v, "agent_id").map(str::to_owned))
            .collect::<Result<_>>()?;
        let explicit: BTreeSet<String> = job["body"]["mentions"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "invalid explicit recipient".into())
            })
            .collect::<Result<_>>()?;
        let required = job["required_recipient"].as_str();
        let expected = job["body"]["text"]
            .as_str()
            .ok_or("original accepted text missing")?
            .replace("\r\n", "\n");
        let expected_parent = &job["body"]["reply_to_event_id"];
        let actual_parent = &event["reply_to"]["event_id"];
        let cleared = !expected_parent.is_null() && actual_parent.is_null();
        if event["text"].as_str() != Some(expected.as_str())
            || (!cleared && actual_parent != expected_parent)
            || !explicit.is_subset(&actual)
            || !addressing::validate_readback(&actual, &allowed(job)?, required)
        {
            job["state"] = json!("mismatch");
            job["reason"] = json!("accepted_event_content_or_recipient_mismatch");
            return Ok(());
        }
        job["state"] = json!(if cleared {
            "verified_target_cleared"
        } else {
            "verified"
        });
        job["reason"] = json!(if cleared {
            "server_cleared_reply_to; message_itself_verified"
        } else {
            "independent_event_readback"
        });
        return Ok(());
    }
    let next = string(page, "next_cursor")?;
    let anchored = job["verification_cursor"].is_string();
    if !anchored {
        job["state"] = json!("history_unavailable");
        job["reason"] =
            json!("legacy_acceptance_had_no_pre_send_cursor; not_found_in_available_history");
    } else if events.iter().any(|e| {
        e["seq"]
            .as_u64()
            .zip(ack["seq"].as_u64())
            .is_some_and(|(a, b)| a >= b)
    }) {
        job["state"] = json!("history_unavailable");
        job["reason"] = json!("accepted_event_identity_missing_after_its_sequence");
    } else {
        job["verification_cursor"] = json!(next);
        job["reason"] = json!("accepted_waiting_for_independent_readback");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owner_selected_twenty_attempts_rejects_the_twenty_first() {
        let mut s = state();
        let cfg = json!({"model_daily_limit":20});
        for index in 0..20 {
            let mut g = generation("reply");
            g["generation_id"] = json!(format!("fixture-generation-{index}"));
            g["intent"]["trigger_id"] = json!(format!("fixture-trigger-{index}"));
            add_receipt(
                &mut s,
                json!({"event_id":g["intent"]["trigger_id"],"status":"received"}),
            )
            .unwrap();
            reserve(&mut s, &cfg, "2026-11-18", g).unwrap();
            complete_generation(&mut s, "[SILENT]", "unused", "fixture-now", "synthetic").unwrap();
        }
        assert_eq!(s["model_budget"]["used"], 20);
        assert_eq!(s["model_invocations"], 20);
        let before = s.clone();
        assert!(reserve(&mut s, &cfg, "2026-11-18", generation("reply")).is_err());
        assert_eq!(s, before);
    }
    fn state() -> Value {
        let mut s = json!({"context":[],"handled":[],"own_event_ids":[],"pending":null,"model_invocations":0});
        prepare(&mut s).unwrap();
        add_receipt(
            &mut s,
            json!({"event_id":"question","status":"received","timeline":"public","kind":"reply"}),
        )
        .unwrap();
        s
    }
    fn intent(kind: &str) -> Value {
        json!({"kind":kind,"trigger_id":"question","timeline":"public","reply_to_event_id":"question","allowed_mentions":["bob"],"max_text_scalars":2000})
    }
    fn generation(kind: &str) -> Value {
        json!({"generation_id":"generation-one","phase":"started","intent":intent(kind)})
    }
    fn job() -> Value {
        json!({"state":"accepted","timeline":"public","verification_cursor":"server-cursor-before-post","accepted":{"event_id":"ours","seq":80},"body":{"text":"answer","reply_to_event_id":"question"},"allowed_mentions":["bob"],"required_recipient":null})
    }
    fn page() -> Value {
        json!({"timeline":"public","next_cursor":"server-next","events":[{"event_id":"ours","seq":80,"agent":{"agent_id":"our-agent"},"text":"answer","reply_to":{"event_id":"question"},"mentions":[{"agent_id":"bob"}],"retracted":false}]})
    }
    #[test]
    fn budget_charges_silent_and_failed_attempts_before_new_work() {
        let mut s = state();
        let cfg = json!({"model_daily_limit":2});
        reserve(&mut s, &cfg, "2026-11-18", generation("reply")).unwrap();
        assert_eq!(s["model_budget"]["used"], 1);
        complete_generation(&mut s, "[SILENT]", "unused", "now", "native").unwrap();
        assert_eq!(s["inbox"][0]["status"], "silent");
        s["inbox"][0]["status"] = json!("received"); // Synthetic new-attempt budget control.
        reserve(&mut s, &cfg, "2026-11-18", generation("reply")).unwrap();
        s["rust_generation"]["phase"] = json!("unknown");
        recover(&mut s, "generation-one", "discard", None, "now", "unused").unwrap();
        assert_eq!(
            budget(&mut s, &cfg, "2026-11-18").unwrap()["reason"],
            "daily_budget_exhausted"
        );
        assert!(reserve(&mut s, &cfg, "2026-11-18", generation("reply")).is_err());
        assert_eq!(s["model_invocations"], 2);
    }
    #[test]
    fn budget_rollover_not_clock_rollback_or_missing_limit() {
        let mut s = state();
        s["model_invocations"] = json!(13);
        let cfg = json!({"model_daily_limit":20});
        assert_eq!(budget(&mut s, &cfg, "2026-11-18").unwrap()["used"], 13);
        assert_eq!(budget(&mut s, &cfg, "2026-11-19").unwrap()["used"], 0);
        assert_eq!(
            budget(&mut s, &cfg, "2026-11-18").unwrap()["reason"],
            "clock_rollback_blocked"
        );
        assert_eq!(
            budget(&mut s, &cfg, "2026-11-19").unwrap()["reason"],
            "available"
        );
        s["model_budget"]["used"] = json!(20);
        assert_eq!(
            budget(&mut s, &cfg, "2026-11-18").unwrap()["reason"],
            "clock_rollback_blocked"
        );
        assert_eq!(
            budget(&mut s, &json!({}), "2026-11-19").unwrap()["reason"],
            "budget_not_configured"
        );
        assert_eq!(
            budget(&mut s, &json!({"model_daily_limit":0}), "2026-11-19").unwrap()["reason"],
            "model_disabled"
        );
    }
    #[test]
    fn recovery_binds_exact_marker_and_never_refunds() {
        let mut s = state();
        reserve(
            &mut s,
            &json!({"model_daily_limit":2}),
            "2026-11-18",
            generation("reply"),
        )
        .unwrap();
        let before = s.clone();
        assert!(recover(&mut s, "wrong", "discard", None, "now", "unused").is_err());
        assert_eq!(s, before);
        let wrong = json!({"generation_id":"another","text":"answer"});
        assert!(
            recover(
                &mut s,
                "generation-one",
                "import",
                Some(&wrong),
                "now",
                "unused"
            )
            .is_err()
        );
        assert_eq!(s, before);
        recover(
            &mut s,
            "generation-one",
            "import",
            Some(&json!({"generation_id":"generation-one","text":"answer"})),
            "now",
            "stable-message",
        )
        .unwrap();
        assert_eq!(s["pending"]["body"]["client_message_id"], "stable-message");
        assert!(s["rust_generation"].is_null());
        assert_eq!(s["model_budget"]["used"], 1);
        assert!(recover(&mut s, "generation-one", "discard", None, "now", "unused").is_err());
    }
    #[test]
    fn acceptance_releases_outbox_before_verification_and_migrates_legacy() {
        let mut s = state();
        s["cursor"] = json!("actual-server-cursor");
        s["pending"] = json!({"timeline":"public","trigger_id":"question","body":{"client_message_id":"stable","text":"answer","mentions":[]},"accepted":{"event_id":"ours","seq":80}});
        prepare(&mut s).unwrap();
        assert!(s["pending"].is_null());
        assert_eq!(s["verifications"][0]["state"], "accepted");
        assert_eq!(
            s["verifications"][0]["verification_cursor"],
            "actual-server-cursor"
        );
        assert!(contains(&s, "own_event_ids", "ours"));
        prepare(&mut s).unwrap();
        assert_eq!(s["verifications"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn verification_pages_from_its_own_cursor_not_latest_window() {
        let mut j = job();
        let first = json!({"timeline":"public","next_cursor":"actual-page-two","events":[{"seq":79,"event_id":"different"}]});
        verify_page(&mut j, &first, "our-agent", "now").unwrap();
        assert_eq!(j["state"], "accepted");
        assert_eq!(j["verification_cursor"], "actual-page-two");
        verify_page(&mut j, &page(), "our-agent", "later").unwrap();
        assert_eq!(j["state"], "verified");
    }
    #[test]
    fn legal_cleared_target_retraction_and_timeline_reset_are_distinct() {
        let mut cleared = page();
        cleared["events"][0]["reply_to"] = Value::Null;
        cleared["events"][0]["mentions"] = json!([]);
        let mut j = job();
        verify_page(&mut j, &cleared, "our-agent", "now").unwrap();
        assert_eq!(j["state"], "verified_target_cleared");
        let mut withdrawn = page();
        withdrawn["events"][0]["retracted"] = json!(true);
        withdrawn["events"][0]["text"] = Value::Null;
        withdrawn["events"][0]["mentions"] = json!([]);
        let mut j = job();
        verify_page(&mut j, &withdrawn, "our-agent", "now").unwrap();
        assert_eq!(j["state"], "retracted");
        let mut reset = page();
        reset["cursor_reset"] = json!(true);
        let mut j = job();
        verify_page(&mut j, &reset, "our-agent", "now").unwrap();
        assert_eq!(j["state"], "timeline_reset");
    }
    #[test]
    fn unexpected_recipient_never_reports_verified() {
        let mut p = page();
        p["events"][0]["mentions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"agent_id":"bobby"}));
        let mut j = job();
        verify_page(&mut j, &p, "our-agent", "now").unwrap();
        assert_eq!(j["state"], "mismatch");
        let mut j = job();
        verify_page(&mut j, &page(), "our-agent", "now").unwrap();
        assert_eq!(j["state"], "verified");
    }
}
