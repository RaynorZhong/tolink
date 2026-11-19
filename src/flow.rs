//! Sequential effects: commit work before model/POST; reconciliation gets one page per turn.
use super::*;

impl Client {
    pub(super) fn ready(&self, sending: bool) -> bool {
        let (epoch, monotonic) = if sending {
            (
                number(&self.state, "next_public_send_epoch"),
                self.send_gate,
            )
        } else {
            (number(&self.state, "blocked_until"), self.request_gate)
        };
        now() >= epoch && Instant::now() >= monotonic
    }
    pub(super) fn call(
        &mut self,
        endpoint: &str,
        query: &str,
        payload: Option<&Value>,
    ) -> Result<Option<(u16, Value)>> {
        require(!STOP.load(Ordering::Relaxed), "owner_stop")?;
        if !self.ready(false) {
            return Ok(None);
        }
        let body = payload.map(serde_json::to_vec).transpose()?;
        let response_result = (|| -> Result<WireResponse> {
            #[cfg(test)]
            if let Some(script) = self.script.as_mut() {
                return script.request(&self.home, endpoint, query, payload);
            }
            super::super::wire(
                text(&self.config, "base_url")?,
                Path::new(text(&self.config, "ca_file")?),
                Some(&self.key),
                endpoint,
                query,
                body.as_deref(),
                Path::new(text(&self.config, "curl_executable")?),
            )
        })();
        let response = match response_result {
            Ok(response) => response,
            Err(error) => {
                if crate::process::cleanup_unconfirmed(error.as_ref()) {
                    self.state["owned_cleanup_unconfirmed"] = json!(true);
                    self.save()?;
                }
                return Err(error);
            }
        };
        let status = response.status;
        if let Some(seconds) = response.retry_after {
            self.block(seconds as f64, "Retry-After")?;
        }
        require(
            !response.tls_fatal,
            "TLS verification or local CA failed; no bypass",
        )?;
        require(
            status != 429 || response.retry_after.is_some(),
            "429 without valid Retry-After; stopped",
        )?;
        if !(response.complete && status < 500) {
            require(
                !(400..500).contains(&status) || status == 429,
                "incomplete client-error response; stopped",
            )?;
            if !self.state["http_failures"].is_object() {
                self.state["http_failures"] = json!({});
            }
            let failures = self.state["http_failures"][endpoint]
                .as_u64()
                .unwrap_or(0)
                .saturating_add(1);
            self.state["http_failures"][endpoint] = json!(failures);
            if response.retry_after.is_none() {
                let mut jitter = [0u8; 1];
                File::open("/dev/urandom")?.read_exact(&mut jitter)?;
                self.block(
                    ((1u64 << failures.saturating_sub(1).min(6)) as f64
                        * (1.0 + jitter[0] as f64 / 512.0))
                        .min(60.0),
                    "transport_or_5xx",
                )?;
            } else {
                self.save()?;
            }
            return Ok(None);
        }
        require(!(300..400).contains(&status), "redirect refused")?;
        let value = response.value.ok_or("invalid complete JSON response")?;
        let code = value["error"]["code"].as_str().unwrap_or("");
        if status == 429 && matches!(code, "rate_limited" | "message_limit") {
            return Ok(None);
        }
        if status == 401 && code == "clock_skew" {
            self.log(
                "clock_skew",
                json!({"server_time":value["error"]["server_time"]}),
            )?;
            self.block(5.0, "clock_skew")?;
            return Ok(None);
        }
        require(
            status != 401,
            "401 unauthorized: stopped, identity unchanged",
        )?;
        require(status != 421, "wrong signing authority")?;
        if !self.state["http_failures"].is_object() {
            self.state["http_failures"] = json!({});
        }
        self.state["http_failures"][endpoint] = json!(0);
        Ok(Some((status, value)))
    }
    fn discard_ineligible(&mut self, current: &Value) -> Result<()> {
        if !current.is_object() {
            return Ok(());
        }
        let invalid = |timeline: &Value| {
            current["timeline"] != *timeline
                || (timeline == "public"
                    && (current["state"] != "ACTIVE"
                        || !current["mute"].is_null()
                        || current["room_paused"] != false))
        };
        let ids: Vec<String> = journal::receipts(&self.state)?
            .iter()
            .filter(|r| {
                !journal::terminal_receipt(r["status"].as_str().unwrap_or(""))
                    && invalid(&r["timeline"])
            })
            .filter_map(|r| r["event_id"].as_str().map(str::to_owned))
            .collect();
        for id in ids {
            journal::decision(
                &mut self.state,
                &id,
                "discarded",
                "observed_self_ineligible",
            )?;
            let generation = &self.state["rust_generation"];
            let work = if generation["intent"].is_object() {
                &generation["intent"]
            } else {
                generation
            };
            if generation.is_object() && journal::work_ids(work)?.contains(&id) {
                self.state["rust_generation"]["phase"] = json!("blocked_ineligible");
            }
        }
        if self.state["pending"].is_object() && invalid(&self.state["pending"]["timeline"]) {
            self.cancel_pending("observed_self_ineligible")?;
        }
        Ok(())
    }
    pub(super) fn refresh_self(&mut self) -> Result<Option<Value>> {
        let Some((status, value)) = self.call("self", "", None)? else {
            return Ok(None);
        };
        require(
            status == 200 && value["spec_version"] == "tolight-participant/0.1",
            "self/spec mismatch",
        )?;
        require(
            value["agent_id"] == self.config["application"]["agent_id"],
            "identity mismatch",
        )?;
        require(
            value["state"] == "ACTIVE" || value["state"] == "PENDING",
            "rejected or unknown state",
        )?;
        let request = self.home.join("self-request.json");
        let request_id = if request.exists() {
            load(&request)?["request_id"].clone()
        } else {
            Value::Null
        };
        save(
            &self.home.join("last-self.json"),
            &json!({"checked_at":utc()?,"request_id":request_id,"http_status":status,"self":value}),
        )?;
        self.state["self"] = value.clone();
        self.state["self_refresh_required"] = json!(false);
        self.state["self_checked_epoch"] = json!(now());
        self.discard_ineligible(&value)?;
        self.save()?;
        Ok(Some(value))
    }
    pub(super) fn cancel_pending(&mut self, reason: &str) -> Result<()> {
        self.finish_pending(reason, false)
    }
    fn finish_pending(&mut self, reason: &str, conclusive_rejection: bool) -> Result<()> {
        if self.state["pending"].is_null() {
            return Ok(());
        }
        let mut pending = self.state["pending"].clone();
        let trigger = text(&pending, "trigger_id")?.to_owned();
        // A complete known rejection differs from cancelling an ambiguous attempt.
        let uncertain = !conclusive_rejection && pending["attempts"].as_u64().is_none_or(|n| n > 0);
        pending["state"] = json!(if conclusive_rejection {
            "rejected"
        } else if uncertain {
            "delivery_unknown_cancelled"
        } else {
            "cancelled_before_attempt"
        });
        pending["reason"] = json!(reason);
        pending["checked_at"] = json!(utc()?);
        if uncertain {
            self.state["delivery_uncertainty"] = json!(true);
        }
        self.state["verifications"]
            .as_array_mut()
            .ok_or("missing verification journal")?
            .push(pending.clone());
        journal::decide_work(&mut self.state, &pending, "discarded", reason)?;
        self.state["pending"] = Value::Null;
        journal::prune(&mut self.state)?;
        self.save()?;
        self.log(
            "message_cancelled",
            json!({"trigger_id":trigger,"reason":reason,"delivery_unknown":uncertain}),
        )
    }
    pub(super) fn send_pending(&mut self) -> Result<()> {
        if self.state["pending"].is_null() || !self.ready(false) {
            return Ok(());
        }
        if self.state["pending"]["timeline"] == "public" && !self.ready(true) {
            return Ok(());
        }
        let Some(current) = self.refresh_self()? else {
            return Ok(());
        };
        let pending = self.state["pending"].clone();
        if pending["timeline"] == "public"
            && !pending["body"]["reply_to_event_id"].is_null()
            && self.config["owner_authorization"]["allow_public_replies"] != true
        {
            return self.cancel_pending("public_replies_not_authorized");
        }
        let allowed = if pending["timeline"] == "public" {
            current["state"] == "ACTIVE"
                && current["mute"].is_null()
                && current["room_paused"] == false
        } else {
            current["state"] == "PENDING" && current["conformance"]["passed_at"].is_null()
        };
        if current["timeline"] != pending["timeline"] || !allowed {
            return self.cancel_pending("self_state_changed_before_send");
        }
        for id in journal::work_ids(&pending)? {
            if contains(&self.state, "retracted_event_ids", &id) {
                return self.cancel_pending("trigger_retracted_before_send");
            }
            if journal::receipts(&self.state)?
                .iter()
                .find(|r| r["event_id"] == id)
                .is_some_and(|r| r["status"] != "draft")
            {
                return self.cancel_pending("trigger_no_longer_eligible_before_send");
            }
        }
        let validation_intent = json!({"kind":if pending["required_recipient"].is_string(){"outreach"}else{"reply"},"recipient_id":pending["required_recipient"],"allowed_mentions":pending["allowed_mentions"],"max_text_scalars":current["limits"]["max_text_scalars"]});
        if journal::validate_result(&validation_intent, text(&pending["body"], "text")?).is_err() {
            return self.cancel_pending("draft_recipient_or_length_invalid_before_post");
        }
        // Acquire the anchor once, BEFORE the first POST. Keep it across ambiguous retries.
        if pending["verification_cursor"].is_null() {
            let Some((status, page)) = self.call("events", "limit=0", None)? else {
                return Ok(());
            };
            require(
                status == 200 && page["timeline"] == pending["timeline"],
                "verification anchor unavailable",
            )?;
            self.state["pending"]["verification_cursor"] = json!(text(&page, "next_cursor")?);
            self.save()?;
        }
        if !self.ready(false) {
            return Ok(());
        }
        let pending = self.state["pending"].clone();
        if pending["timeline"] == "public" {
            let interval = self.config["public_send_interval_seconds"]
                .as_u64()
                .ok_or("send interval missing")?;
            require(interval > 0, "invalid send interval")?;
            self.state["next_public_send_epoch"] = json!(now() + interval as f64);
            self.send_gate = Instant::now() + Duration::from_secs(interval);
        }
        self.state["pending"]["attempts"] = json!(
            pending["attempts"]
                .as_u64()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or("attempt overflow")?
        );
        self.save()?;
        let Some((status, ack)) = self.call("messages", "", Some(&pending["body"]))? else {
            return Ok(());
        };
        if !matches!(status, 200 | 201) {
            let code = ack["error"]["code"]
                .as_str()
                .unwrap_or("unknown")
                .to_owned();
            let known = matches!(
                (status, code.as_str()),
                (400, "bad_request")
                    | (413, "too_large")
                    | (
                        422,
                        "content_rejected" | "invalid_mention" | "too_many_mentions"
                    )
                    | (409, "room_paused")
                    | (403, "agent_muted" | "agent_not_active")
            );
            require(
                known,
                "unknown POST status/error; original pending retained; stopped",
            )?;
            let first_attempt = self.state["pending"]["attempts"] == 1;
            // Public 422 replay is conclusive too; other state errors may follow an earlier lost ACK.
            let conclusive = first_attempt || (pending["timeline"] == "public" && status == 422);
            self.finish_pending(&format!("server_rejected:{code}"), conclusive)?;
            return Ok(());
        }
        self.state["last_message_result"] = json!({"at":utc()?,"http_status":status,"response":ack,"client_message_id":pending["body"]["client_message_id"],"timeline":pending["timeline"]});
        journal::accept(&mut self.state, &ack, &utc()?)?;
        self.save()?;
        self.log("message_accepted",json!({"event_id":ack["event_id"],"seq":ack["seq"],"client_message_id":pending["body"]["client_message_id"],"verification":"independent_pending"}))
    }
    pub(super) fn verify_one(&mut self) -> Result<()> {
        let index = self.state["verifications"]
            .as_array()
            .ok_or("missing verification journal")?
            .iter()
            .enumerate()
            .filter(|(_, j)| j["state"] == "accepted" && number(j, "next_check_epoch") <= now())
            .min_by(|(_, a), (_, b)| {
                number(a, "next_check_epoch").total_cmp(&number(b, "next_check_epoch"))
            })
            .map(|(index, _)| index);
        let Some(index) = index else { return Ok(()) };
        let job = self.state["verifications"][index].clone();
        let query = if let Some(cursor) = job["verification_cursor"].as_str() {
            format!("after={}&limit=50", encode(cursor))
        } else {
            "limit=50".to_owned()
        };
        let Some((status, page)) = self.call("events", &query, None)? else {
            return Ok(());
        };
        if status != 200 {
            self.state["verifications"][index]["last_error"] =
                json!(format!("verification_http_{status}"));
            self.state["verifications"][index]["next_check_epoch"] = json!(now() + 30.0);
            self.save()?;
            return Ok(());
        }
        if !page["events"].is_array() {
            self.state["verifications"][index]["last_error"] =
                json!("malformed_verification_events");
            self.state["verifications"][index]["next_check_epoch"] = json!(now() + 30.0);
            self.save()?;
            return Ok(());
        }
        self.merge_retractions(&page)?;
        let mut checked = job;
        let result = journal::verify_page(
            &mut checked,
            &page,
            text(&self.config["application"], "agent_id")?,
            &utc()?,
        );
        if result.is_err() {
            checked["last_error"] = json!("malformed_or_unusable_verification_page");
        }
        let observed = page["events"]
            .as_array()
            .and_then(|events| events.iter().filter_map(|e| e["seq"].as_u64()).max());
        let backlog = page["head_seq"]
            .as_u64()
            .zip(observed)
            .is_some_and(|(head, seen)| seen < head);
        checked["next_check_epoch"] = json!(if backlog { now() } else { now() + 30.0 });
        let outcome = checked["state"].clone();
        let id = checked["accepted"]["event_id"].clone();
        let index = self.state["verifications"]
            .as_array()
            .ok_or("verification journal missing")?
            .iter()
            .position(|j| {
                j["accepted"]["event_id"] == checked["accepted"]["event_id"]
                    && j["body"]["client_message_id"] == checked["body"]["client_message_id"]
            })
            .ok_or("active verification lost during retraction merge")?;
        self.state["verifications"][index] = checked;
        journal::prune(&mut self.state)?;
        self.save()?;
        self.log(
            "verification_progress",
            json!({"event_id":id,"state":outcome,"page_usable":result.is_ok()}),
        )
    }
    pub(super) fn merge_retractions(&mut self, page: &Value) -> Result<()> {
        let events = page["events"].as_array().ok_or("events missing")?;
        let targets: Vec<String> = events
            .iter()
            .filter_map(|event| {
                if event["kind"] == "event_retracted" {
                    event["target"]["event_id"].as_str()
                } else if event["kind"] == "agent_message" && event["retracted"] == true {
                    event["event_id"].as_str()
                } else {
                    None
                }
            })
            .map(str::to_owned)
            .collect();
        for id in targets {
            append_id(&mut self.state, "retracted_event_ids", &id, None)?;
            self.state["context"]
                .as_array_mut()
                .ok_or("context missing")?
                .retain(|e| e["event_id"] != id);
            if let Some(r) = journal::receipt_mut(&mut self.state, &id) {
                r["event"]["text"] = Value::Null;
            }
            journal::decision(&mut self.state, &id, "retracted", "trigger_retracted")?;
            if self.state["pending"].is_object()
                && journal::work_ids(&self.state["pending"])?.contains(&id)
            {
                self.cancel_pending("trigger_retracted_before_send")?;
            }
            let generation = &self.state["rust_generation"];
            let work = if generation["intent"].is_object() {
                &generation["intent"]
            } else {
                generation
            };
            if generation.is_object() && journal::work_ids(work)?.contains(&id) {
                self.state["rust_generation"]["phase"] = json!("blocked_retracted");
            }
        }
        Ok(())
    }
    pub(super) fn page(&mut self, page: &Value, had_cursor: bool) -> Result<()> {
        journal::prepare(&mut self.state)?;
        let timeline = text(page, "timeline")?.to_owned();
        require(
            matches!(timeline.as_str(), "public" | "conformance"),
            "unknown timeline",
        )?;
        let cursor = text(page, "next_cursor")?.to_owned();
        let events = page["events"].as_array().ok_or("missing events")?;
        let history = !had_cursor || page["cursor_reset"] == true;
        if page["cursor_reset"] == true || self.state["timeline"] != timeline {
            self.state["context"] = json!([]);
            let ids: Vec<String> = journal::receipts(&self.state)?
                .iter()
                .filter(|r| !journal::terminal_receipt(r["status"].as_str().unwrap_or("")))
                .filter_map(|r| r["event_id"].as_str().map(str::to_owned))
                .collect();
            for id in ids {
                journal::decision(&mut self.state, &id, "discarded", "timeline_reset")?;
            }
            if !self.state["pending"].is_null() {
                self.cancel_pending("timeline_reset")?;
            }
            if !self.state["rust_generation"].is_null() {
                self.state["rust_generation"]["phase"] = json!("blocked_timeline_reset");
            }
            for job in self.state["verifications"]
                .as_array_mut()
                .ok_or("missing verification journal")?
            {
                if job["state"] == "accepted" {
                    job["state"] = json!("timeline_reset");
                    job["reason"] = json!("main_receive_timeline_reset");
                }
            }
        }
        self.state["timeline"] = json!(timeline);
        self.merge_retractions(page)?;
        for event in events {
            let Some(id) = event["event_id"].as_str() else {
                continue;
            };
            if timeline == "public"
                && event["kind"] == "agent_message"
                && event["agent"]["agent_id"] == self.config["application"]["agent_id"]
            {
                append_id(&mut self.state, "own_event_ids", id, None)?;
            }
            let withdrawn = contains(&self.state, "retracted_event_ids", id);
            let context = self.state["context"]
                .as_array_mut()
                .ok_or("context missing")?;
            if event["kind"] == "agent_message" {
                context.retain(|e| e["event_id"] != id);
                if event["retracted"] != true && !withdrawn {
                    context.push(public_event(event));
                }
            }
            if context.len() > 30 {
                context.drain(..context.len() - 30);
            }
            if !withdrawn && replyable(event, history, &timeline, &self.state) {
                let permitted = timeline != "public"
                    || self.config["owner_authorization"]["allow_public_replies"] == true;
                journal::add_receipt(
                    &mut self.state,
                    json!({"event_id":id,"kind":"reply","timeline":timeline,"event":public_event(event),"notice":page["notice"],"received_at":utc()?,"source_cursor":cursor,"status":"received"}),
                )?;
                if !permitted {
                    journal::decision(
                        &mut self.state,
                        id,
                        "discarded",
                        "public_replies_not_authorized",
                    )?;
                }
            }
        }
        let current = self.state["self"].clone();
        if current.is_object() && current["timeline"] != timeline {
            // The page contradicts the cache. Preserve work even if fresh self is deferred.
            self.state["self_refresh_required"] = json!(true);
        }
        if self.state["self_refresh_required"] != true {
            self.discard_ineligible(&current)?;
        }
        // One save commits ALL new receipts and the page's consumption cursor before a model call.
        self.state["cursor"] = json!(cursor);
        journal::prune(&mut self.state)?;
        self.save()?;
        if self.state["self_refresh_required"] == true {
            self.refresh_self()?;
        }
        if !events.is_empty() {
            self.log(
                "page",
                json!({"events":events.len(),"history_only":history,"timeline":timeline}),
            )?;
        }
        Ok(())
    }
    fn select_receipts(&self, first: &Value, current: &Value) -> Result<Vec<Value>> {
        if first["retry_work"].is_object() {
            return journal::work_ids(&first["retry_work"])?
                .iter()
                .map(|id| {
                    journal::receipts(&self.state)?
                        .iter()
                        .find(|r| r["event_id"] == *id)
                        .cloned()
                        .ok_or_else(|| "saved retry member missing".into())
                })
                .collect();
        }
        let limit = match self.config.get("reply_batch_max") {
            None => 3,
            Some(v) => v
                .as_u64()
                .filter(|n| (1..=3).contains(n))
                .ok_or("reply_batch_max must be 1..3")? as usize,
        };
        let mut selected = vec![first.clone()];
        if limit == 1
            || first["kind"] != "reply"
            || first["timeline"] != "public"
            || !first["source_cursor"].is_string()
        {
            return Ok(selected);
        }
        let max_people = current["limits"]["max_mentions_per_message"]
            .as_u64()
            .unwrap_or(1)
            .min(3) as usize;
        let mut people =
            std::collections::BTreeSet::from([
                text(&first["event"]["agent"], "agent_id")?.to_owned()
            ]);
        for receipt in journal::receipts(&self.state)? {
            if selected.len() >= limit {
                break;
            }
            if receipt["event_id"] == first["event_id"]
                || !receipt["retry_work"].is_null()
                || receipt["status"] != "received"
                || receipt["kind"] != "reply"
                || receipt["timeline"] != first["timeline"]
                || receipt["source_cursor"] != first["source_cursor"]
                || contains(
                    &self.state,
                    "retracted_event_ids",
                    text(receipt, "event_id")?,
                )
            {
                continue;
            }
            let author = text(&receipt["event"]["agent"], "agent_id")?;
            if !people.contains(author) && people.len() >= max_people {
                continue;
            }
            people.insert(author.to_owned());
            selected.push(receipt.clone());
        }
        selected.sort_by_key(|r| r["event"]["seq"].as_u64().unwrap_or(0));
        Ok(selected)
    }
    pub(super) fn generate_receipt(&mut self, receipt: &Value, current: &Value) -> Result<()> {
        if !self.state["rust_generation"].is_null() || !self.state["pending"].is_null() {
            return Ok(());
        }
        if !valid_outreach(receipt) {
            journal::decision(
                &mut self.state,
                text(receipt, "event_id")?,
                "discarded",
                "invalid_owner_topic",
            )?;
            self.save()?;
            return Ok(());
        }
        let retry = &receipt["retry_work"];
        if retry.is_object() {
            let ids = journal::work_ids(retry)?;
            let members: Vec<&Value> = journal::receipts(&self.state)?
                .iter()
                .filter(|r| {
                    r["event_id"]
                        .as_str()
                        .is_some_and(|id| ids.iter().any(|v| v == id))
                })
                .collect();
            let authors: std::collections::BTreeSet<&str> = members
                .iter()
                .filter_map(|r| r["event"]["agent"]["agent_id"].as_str())
                .collect();
            let max_people = current["limits"]["max_mentions_per_message"]
                .as_u64()
                .unwrap_or(1);
            let valid = members.len() == ids.len()
                && authors.len() as u64 <= max_people
                && members.iter().all(|r| {
                    r["status"] == "received"
                        && r["retry_work"] == *retry
                        && r["timeline"] == retry["timeline"]
                        && r["source_cursor"] == retry["source_cursor"]
                        && valid_outreach(r)
                        && !contains(
                            &self.state,
                            "retracted_event_ids",
                            r["event_id"].as_str().unwrap_or(""),
                        )
                });
            if !valid {
                for id in ids {
                    let live = journal::receipts(&self.state)?.iter().any(|r| {
                        r["event_id"] == id
                            && !journal::terminal_receipt(r["status"].as_str().unwrap_or(""))
                    });
                    if live {
                        journal::decision(
                            &mut self.state,
                            &id,
                            "discarded",
                            "retry_group_no_longer_eligible",
                        )?;
                    }
                }
                self.save()?;
                return Ok(());
            }
        }
        let selected = self.select_receipts(receipt, current)?;
        let receipt = if retry.is_object() {
            selected
                .iter()
                .find(|r| r["event_id"] == retry["trigger_id"])
                .ok_or("saved retry primary missing")?
        } else {
            selected.last().ok_or("empty selected work")?
        };
        let work = json!({"trigger_id":receipt["event_id"],"trigger_ids":selected.iter().map(|r|r["event_id"].clone()).collect::<Vec<_>>()});
        let receipt_id = text(receipt, "event_id")?;
        if contains(&self.state, "retracted_event_ids", receipt_id)
            || !journal::receipts(&self.state)?
                .iter()
                .any(|r| r["event_id"] == receipt_id && r["status"] == "received")
        {
            return Ok(());
        }
        if receipt["timeline"] == "public"
            && receipt["kind"] != "outreach"
            && self.config["owner_authorization"]["allow_public_replies"] != true
        {
            journal::decide_work(
                &mut self.state,
                &work,
                "discarded",
                "public_replies_not_authorized",
            )?;
            self.save()?;
            return Ok(());
        }
        let id = text(receipt, "event_id")?.to_owned();
        let timeline = text(receipt, "timeline")?;
        if current["timeline"] != timeline
            || (timeline == "public"
                && (current["state"] != "ACTIVE"
                    || !current["mute"].is_null()
                    || current["room_paused"] != false))
        {
            journal::decide_work(
                &mut self.state,
                &work,
                "discarded",
                "self_state_changed_before_generation",
            )?;
            self.save()?;
            return Ok(());
        }
        let day = self.budget_day();
        if journal::budget(&mut self.state, &self.config, &day)?["reason"] != "available" {
            self.save()?;
            return Ok(());
        }
        model_executable(&self.config)?;
        let Some((status, agents)) = self.call("agents", "", None)? else {
            return Ok(());
        };
        if status != 200 || agents["timeline"] != timeline {
            journal::decide_work(
                &mut self.state,
                &work,
                "discarded",
                "participant_timeline_changed",
            )?;
            self.save()?;
            return Ok(());
        }
        require(!STOP.load(Ordering::Relaxed), "owner_stop")?;
        let mut context = self.state["context"].clone();
        while serde_json::to_vec(&context)?.len() > 80_000 {
            context.as_array_mut().ok_or("bad context")?.remove(0);
        }
        let authors: std::collections::BTreeSet<String> = selected
            .iter()
            .filter_map(|r| r["event"]["agent"]["agent_id"].as_str().map(str::to_owned))
            .collect();
        let roster = agents["agents"].as_array().ok_or("roster missing")?;
        let essential = |a: &&Value| {
            a["agent_id"] == current["agent_id"]
                || a["agent_id"]
                    .as_str()
                    .is_some_and(|id| authors.contains(id))
        };
        let mut participants: Vec<Value> = roster
            .iter()
            .filter(essential)
            .map(|a| public_agent(a))
            .collect();
        participants.extend(
            roster
                .iter()
                .filter(|a| !essential(a))
                .take(32usize.saturating_sub(participants.len()))
                .map(public_agent),
        );
        let mut payload = json!({"notice":receipt["notice"],"identity":{"agent_id":current["agent_id"],"display_name":current["display_name"],"bio":current["bio"]},"timeline":timeline,"participants":participants,"context":context,"trigger":receipt["event"],"triggers":selected.iter().map(|r|r["event"].clone()).collect::<Vec<_>>(),"max_text_scalars":current["limits"]["max_text_scalars"]});
        let outreach = receipt["kind"] == "outreach";
        let target = if outreach {
            text(receipt, "recipient_id")?
        } else {
            text(&receipt["event"]["agent"], "agent_id")?
        };
        if outreach {
            let live = agents["agents"]
                .as_array()
                .ok_or("roster missing")?
                .iter()
                .find(|a| a["agent_id"] == target);
            let Some(recipient) = live else {
                journal::decision(
                    &mut self.state,
                    &id,
                    "discarded",
                    "outreach_recipient_no_longer_current",
                )?;
                self.save()?;
                return Ok(());
            };
            payload["recipient"] = recipient.clone();
            payload["owner_topic"] = receipt["owner_topic"].clone();
        }
        require(
            self.config["public_role"]
                .as_str()
                .is_none_or(|r| r.len() <= 4096),
            "public_role exceeds 4096 bytes",
        )?;
        while serde_json::to_vec(&payload)?.len() > 90_000 {
            let context = payload["context"]
                .as_array_mut()
                .ok_or("invalid model context")?;
            if context.is_empty() {
                return Err("bounded public model payload still exceeds admission limit".into());
            }
            context.remove(0);
        }
        let allowed: std::collections::BTreeSet<String> = if outreach {
            std::collections::BTreeSet::from([target.to_owned()])
        } else {
            authors
        };
        let reply_mentions: Vec<String> = if outreach {
            vec![]
        } else {
            allowed
                .iter()
                .filter(|id| {
                    id.as_str() != target && roster.iter().any(|a| a["agent_id"] == id.as_str())
                })
                .cloned()
                .collect()
        };
        let intent = json!({"kind":if outreach{"outreach"}else{"reply"},"trigger_id":id,"trigger_ids":work["trigger_ids"],"timeline":timeline,"reply_to_event_id":if outreach{Value::Null}else{json!(id)},"reply_mentions":reply_mentions,"recipient_id":if outreach{json!(target)}else{Value::Null},"allowed_mentions":allowed,"max_text_scalars":current["limits"]["max_text_scalars"]});
        let generation =
            json!({"generation_id":token()?,"started_at":utc()?,"phase":"started","intent":intent});
        let reservation_day = self.budget_day();
        journal::reserve(&mut self.state, &self.config, &reservation_day, generation)?;
        self.save()?;
        self.log("model_start",json!({"generation_id":self.state["rust_generation"]["generation_id"],"trigger_id":id,"tools":0,"model":self.config["model_name"].as_str().unwrap_or("gpt-6.1-sol-900k")}))?;
        #[cfg(test)]
        let result = if let Some(script) = self.script.as_mut() {
            script.generate(&self.home)
        } else {
            model(&self.home, &self.config, &payload)
        };
        #[cfg(not(test))]
        let result = model(&self.home, &self.config, &payload);
        match result {
            Ok(reply) => {
                if let Err(error) = journal::complete_generation(
                    &mut self.state,
                    &reply,
                    &token()?,
                    &utc()?,
                    "native_hermes",
                ) {
                    self.state["rust_generation"]["phase"] = json!("result_rejected");
                    self.state["rust_generation"]["result"] = json!(reply);
                    self.state["rust_generation"]["reason"] = json!(error.to_string());
                    for selected_id in journal::work_ids(&work)? {
                        if let Some(r) = journal::receipt_mut(&mut self.state, &selected_id) {
                            r["status"] = json!("generation_unknown");
                        }
                    }
                }
            }
            Err(error) => {
                self.state["rust_generation"]["phase"] = json!("unknown");
                self.state["rust_generation"]["reason"] = json!("native_model_failed_or_timed_out");
                for selected_id in journal::work_ids(&work)? {
                    if let Some(r) = journal::receipt_mut(&mut self.state, &selected_id) {
                        r["status"] = json!("generation_unknown");
                    }
                }
                self.save()?;
                // Process cleanup errors must never be followed by another owned invocation.
                if crate::process::cleanup_unconfirmed(error.as_ref()) {
                    self.state["owned_cleanup_unconfirmed"] = json!(true);
                    self.save()?;
                    return Err(error);
                }
            }
        }
        self.save()
    }
    pub(super) fn generate_one(&mut self) -> Result<()> {
        if !self.state["pending"].is_null() || !self.state["rust_generation"].is_null() {
            return Ok(());
        }
        let invalid: Vec<String> = journal::receipts(&self.state)?
            .iter()
            .filter(|r| r["status"] == "received" && !valid_outreach(r))
            .filter_map(|r| r["event_id"].as_str().map(str::to_owned))
            .collect();
        if !invalid.is_empty() {
            for id in invalid {
                journal::decision(&mut self.state, &id, "discarded", "invalid_owner_topic")?;
            }
            self.save()?;
        }
        let receipt = journal::receipts(&self.state)?
            .iter()
            .find(|r| r["status"] == "received")
            .cloned();
        let Some(receipt) = receipt else {
            return Ok(());
        };
        let Some(current) = self.refresh_self()? else {
            return Ok(());
        };
        self.generate_receipt(&receipt, &current)
    }
    pub(super) fn immediate_work(&mut self) -> Result<bool> {
        let budget = journal::budget(
            &mut self.state,
            &self.config,
            &OffsetDateTime::now_utc().date().to_string(),
        )?;
        let verification_due = self.state["verifications"].as_array().is_some_and(|jobs| {
            jobs.iter()
                .any(|j| j["state"] == "accepted" && number(j, "next_check_epoch") <= now())
        });
        Ok(verification_due
            || (!self.state["pending"].is_null() && self.ready(true))
            || (self.state["rust_generation"].is_null()
                && self.state["pending"].is_null()
                && budget["reason"] == "available"
                && journal::receipts(&self.state)?
                    .iter()
                    .any(|r| r["status"] == "received")))
    }
    pub(super) fn run(&mut self) -> Result<()> {
        self.save()?;
        save(
            &self.home.join("process.json"),
            &json!({"pid":std::process::id(),"started_at":utc()?,"state":"running","implementation":"rust","build":crate::diagnostics::build_info()}),
        )?;
        self.log("started",json!({"pid":std::process::id(),"agent_id":self.config["application"]["agent_id"],"interval_seconds":self.config["public_send_interval_seconds"],"proactive":false}))?;
        println!(
            "{}",
            json!({"started":true,"pid":std::process::id(),"implementation":"rust"})
        );
        loop {
            require(!STOP.load(Ordering::Relaxed), "owner_stop")?;
            if !self.ready(false) {
                sleep(0.2)?;
                continue;
            }
            let requested = self.home.join("self-request.json");
            let request_id = if requested.exists() {
                load(&requested)?["request_id"].clone()
            } else {
                Value::Null
            };
            let snapshot = if self.home.join("last-self.json").exists() {
                load(&self.home.join("last-self.json"))?
            } else {
                Value::Null
            };
            if self.state["self"].is_null()
                || self.state["self_refresh_required"] == true
                || now() - number(&self.state, "self_checked_epoch") >= 60.0
                || request_id != snapshot["request_id"]
            {
                if self.refresh_self()?.is_none() {
                    continue;
                }
            }
            if self.state["self"]["state"] == "PENDING"
                && self.state["self"]["conformance"]["last_run"]["passed"] == false
            {
                return Err("sandbox failed; no automatic rerun".into());
            }
            let immediate = self.immediate_work()?;
            let cursor = self.state["cursor"].as_str();
            let had_cursor = cursor.is_some();
            let query = if let Some(cursor) = cursor {
                format!(
                    "after={}&limit=50&wait={}",
                    encode(cursor),
                    if immediate { 0 } else { 30 }
                )
            } else {
                "limit=50".to_owned()
            };
            if let Some((status, page)) = self.call("events", &query, None)? {
                require(status == 200, "event read failed")?;
                self.page(&page, had_cursor)?;
                if had_cursor && !immediate && page["events"].as_array().is_some_and(Vec::is_empty)
                {
                    sleep(1.0)?;
                }
            }
            require(!STOP.load(Ordering::Relaxed), "owner_stop")?;
            self.send_pending()?;
            self.verify_one()?;
            self.generate_one()?;
            sleep(0.1)?;
        }
    }
}
