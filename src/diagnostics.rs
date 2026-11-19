//! Offline, redacted diagnostics. No client, writer lock, process execution or network.
use crate::{Result, Value, json};
use std::{
    fs::{self, Metadata},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const CONFIG_LIMIT: u64 = 1024 * 1024;
const LOCAL_LIMIT: u64 = 4 * 1024 * 1024;

fn configured_path(value: &Value) -> Option<&Path> {
    value
        .as_str()
        .filter(|s| !s.is_empty() && !s.contains('\0'))
        .map(Path::new)
}
fn absolute_path(value: &Value) -> Option<&Path> {
    configured_path(value).filter(|p| p.is_absolute())
}
fn validation(errors: Vec<String>, warnings: Vec<String>) -> Value {
    json!({"valid":errors.is_empty(),"errors":errors,"warnings":warnings,
        "referenced_paths_checked":false,"runtime_verified":false})
}

/// Structure only: neither this function nor validate_path opens referenced paths.
pub(crate) fn config_report(config: &Value) -> Value {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    if !config.is_object() {
        return validation(vec!["config: expected a JSON object".into()], warnings);
    }
    let base = config["base_url"]
        .as_str()
        .and_then(|s| s.strip_prefix("https://"))
        .and_then(|s| s.strip_suffix("/participant/v1/"))
        .and_then(|s| crate::host(s, "https").ok());
    if base.is_none() {
        errors.push("base_url: expected HTTPS authority and /participant/v1/ base path".into());
    }
    let authority = config["authority"]
        .as_str()
        .and_then(|s| crate::host(s, "https").ok())
        .filter(|s| Some(s.as_str()) == config["authority"].as_str());
    if authority.is_none() {
        errors.push("authority: expected a canonical signing authority".into());
    } else if base.is_some() && base != authority {
        errors.push("authority: does not match base_url".into());
    }
    for field in ["key_file", "ca_file", "curl_executable"] {
        match configured_path(&config[field]) {
            None => errors.push(format!(
                "{field}: expected a nonempty path without NUL bytes"
            )),
            Some(path) if !path.is_absolute() => warnings.push(format!(
                "{field}: relative path; prefer an absolute Owner-selected path"
            )),
            Some(_) => {}
        }
    }
    if config.get("hermes_executable").is_some() {
        if absolute_path(&config["hermes_executable"]).is_none() {
            errors.push("hermes_executable: expected an absolute path without NUL bytes".into());
        }
    } else {
        warnings.push(
            "hermes_executable: defaults to HOME/.local/bin/hermes; presence not checked".into(),
        );
    }
    let pin = config["ca_sha256"].as_str();
    if !pin.is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        errors.push("ca_sha256: expected 64 lowercase hexadecimal digits".into());
    } else if pin.is_some_and(|s| s.bytes().all(|b| b == b'0')) {
        warnings.push(
            "ca_sha256: nontrusted placeholder; replace with an independently verified CA digest"
                .into(),
        );
    }
    if !config["application"]["agent_id"]
        .as_str()
        .is_some_and(crate::addressing::valid_id)
    {
        errors.push("application.agent_id: expected a protocol agent ID".into());
    }
    match config["owner_authorization"]["allow_public_replies"].as_bool() {
        None => errors
            .push("owner_authorization.allow_public_replies: expected an explicit boolean".into()),
        Some(false) => warnings.push(
            "owner_authorization.allow_public_replies: public replies are not authorized".into(),
        ),
        Some(true) => {}
    }
    if !config["public_send_interval_seconds"]
        .as_u64()
        .is_some_and(|n| n > 0)
    {
        errors.push("public_send_interval_seconds: expected a positive integer".into());
    }
    match config["model_daily_limit"].as_u64() {
        None => errors.push("model_daily_limit: explicit finite nonnegative integer required for complete generation config".into()),
        Some(0) => warnings.push("model_daily_limit: generation is explicitly disabled".into()),
        Some(_) => {}
    }
    if config.get("reply_batch_max").is_some()
        && !config["reply_batch_max"]
            .as_u64()
            .is_some_and(|n| (1..=3).contains(&n))
    {
        errors.push(
            "reply_batch_max: expected an integer from 1 through 3; omission defaults to 3".into(),
        );
    }
    for field in [
        "model_provider",
        "model_name",
        "model_reasoning",
        "public_role",
    ] {
        if let Some(value) = config.get(field) {
            if !value.as_str().is_some_and(|s| {
                !s.contains('\0') && (field == "public_role" || !s.trim().is_empty())
            }) {
                errors.push(format!("{field}: expected a string without NUL bytes; model route strings must be nonempty"));
            }
        }
    }
    validation(errors, warnings)
}

fn io_status(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::NotFound => "missing",
        io::ErrorKind::PermissionDenied => "permission_denied",
        _ => "unreadable",
    }
}
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

// Reject special files before opening, then recheck the opened fd. O_NONBLOCK also
// protects the regular-file-to-FIFO race. Never follow a final-component symlink.
fn read_regular(
    path: &Path,
    limit: u64,
    key: Option<&Metadata>,
) -> std::result::Result<Vec<u8>, &'static str> {
    let before = fs::symlink_metadata(path).map_err(|e| io_status(&e))?;
    if !before.is_file() {
        return Err("not_regular");
    }
    if key.is_some_and(|k| same_file(k, &before)) {
        return Err("signing_key_read_refused");
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| io_status(&e))?;
    let meta = file.metadata().map_err(|e| io_status(&e))?;
    if !meta.is_file() {
        return Err("not_regular");
    }
    if key.is_some_and(|k| same_file(k, &meta)) {
        return Err("signing_key_read_refused");
    }
    if meta.len() > limit {
        return Err("too_large");
    }
    let mut raw = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| io_status(&e))?;
    if raw.len() as u64 > limit {
        return Err("too_large");
    }
    Ok(raw)
}

/// Input/parse failures are redacted diagnostic values, not raw OS/JSON errors.
pub(crate) fn validate_path(path: &Path) -> Result<Value> {
    Ok(match read_regular(path, CONFIG_LIMIT, None) {
        Ok(raw) => match serde_json::from_slice::<Value>(&raw) {
            Ok(config) => config_report(&config),
            Err(_) => validation(vec!["config: invalid_json".into()], vec![]),
        },
        Err(code) => validation(vec![format!("config: {code}")], vec![]),
    })
}

pub(crate) fn build_info() -> Value {
    json!({"version":env!("CARGO_PKG_VERSION"),
        "source_revision":option_env!("TOLINK_BUILD_REVISION").unwrap_or("unknown"),
        "os":std::env::consts::OS,"arch":std::env::consts::ARCH})
}
fn epoch_now() -> f64 {
    OffsetDateTime::now_utc().unix_timestamp_nanos() as f64 / 1_000_000_000.0
}
fn timestamp(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite()).or_else(|| {
        value
            .as_str()
            .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
            .map(|t| t.unix_timestamp_nanos() as f64 / 1_000_000_000.0)
    })
}
fn file_metadata(path: &Path) -> Value {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            json!({"status":if meta.is_file(){"regular"}else if meta.is_dir(){"directory"}else if meta.file_type().is_symlink(){"symlink"}else{"special"},
            "regular_file":meta.is_file(),"size_bytes":meta.len(),"mode":format!("{:03o}",meta.permissions().mode() & 0o777),
            "modified_age_seconds":meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|t|epoch_now()-t.as_secs_f64())})
        }
        Err(error) => json!({"status":io_status(&error),"regular_file":false}),
    }
}
fn document(path: &Path, limit: u64, key: Option<&Metadata>) -> (Option<Value>, Value) {
    let mut meta = file_metadata(path);
    let result = read_regular(path, limit, key).and_then(|raw| {
        let value: Value = serde_json::from_slice(&raw).map_err(|_| "invalid_json")?;
        if value.is_object() {
            Ok(value)
        } else {
            Err("expected_object")
        }
    });
    match result {
        Ok(value) => {
            meta["read_status"] = json!("ok");
            (Some(value), meta)
        }
        Err(code) => {
            meta["read_status"] = json!(code);
            (None, meta)
        }
    }
}
fn executable_metadata(path: Option<&Path>) -> Value {
    let Some(path) = path else {
        return json!({"status":"not_configured","execution_verified":false,"presence_only":true,"executable_bits_set":false});
    };
    let mut report = file_metadata(path);
    let target = fs::metadata(path).ok();
    report["target_regular_file"] = json!(target.as_ref().is_some_and(|m| m.is_file()));
    report["executable_bits_set"] = json!(
        target
            .as_ref()
            .is_some_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    );
    report["execution_verified"] = json!(false);
    report["presence_only"] = json!(true);
    report
}

fn journal_view(
    state: Option<&Value>,
    config: &Value,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Value {
    let Some(state) = state else {
        return json!({"available":false,"blockers":["state_unavailable"],"summary_only":true});
    };
    if let Err(error) = crate::journal::validate_format(state) {
        errors.push(format!("state.json: {error}"));
    }
    for field in ["pending", "rust_generation", "model_budget"] {
        if !state[field].is_null() && !state[field].is_object() {
            errors.push(format!("state.json:{field}: expected object or null"));
        }
    }
    for field in ["owned_cleanup_unconfirmed", "delivery_uncertainty"] {
        if !state[field].is_null() && !state[field].is_boolean() {
            errors.push(format!("state.json:{field}: expected boolean"));
        }
    }
    if !state["model_invocations"].is_u64() {
        errors.push("state.json:model_invocations: expected nonnegative integer".into());
    }
    let version = state["rust_journal_version"].as_u64();
    if !state["rust_journal_version"].is_null() && version.is_none() {
        errors.push("state.json:rust_journal_version: expected nonnegative integer".into());
    }
    if version.is_some_and(|v| v > crate::journal::VERSION) {
        warnings
            .push("journal: newer version; reporting known fields only, without upgrading".into());
    }
    let mut blockers = Vec::new();
    if state["self_refresh_required"] == true {
        blockers.push("self_refresh_required");
    }
    let pending = !state["pending"].is_null();
    let generation = !state["rust_generation"].is_null();
    if pending {
        blockers.push("outbox_pending");
    }
    if generation {
        blockers.push("generation_unresolved");
    }
    if state["owned_cleanup_unconfirmed"] == true {
        blockers.push("owned_cleanup_unconfirmed");
        errors.push("journal: owned_cleanup_unconfirmed".into());
    }
    if state["delivery_uncertainty"] == true {
        warnings.push("journal: prior delivery remains uncertain".into());
    }
    if config["owner_authorization"]["allow_public_replies"] != true {
        blockers.push("public_replies_not_authorized");
    }
    for (field, reason) in [
        ("blocked_until", "request_backoff"),
        ("next_public_send_epoch", "public_send_pacing"),
    ] {
        if !state[field].is_null() && state[field].as_f64().is_none() {
            errors.push(format!("state.json:{field}: expected numeric epoch"));
        }
        if state[field].as_f64().is_some_and(|n| n > epoch_now()) {
            blockers.push(reason);
        }
    }
    let receipts_unresolved = state["inbox"].as_array().map_or(0, |items| {
        items
            .iter()
            .filter(|r| {
                !matches!(
                    r["status"].as_str(),
                    Some("silent" | "discarded" | "accepted" | "retracted" | "diagnostic_complete")
                )
            })
            .count()
    });
    let verification_pending = state["verifications"].as_array().map_or(0, |items| {
        items.iter().filter(|j| j["state"] == "accepted").count()
    });
    let verification_attention = state["verifications"].as_array().map_or(0, |items| {
        items
            .iter()
            .filter(|j| {
                !matches!(
                    j["state"].as_str(),
                    Some(
                        "accepted"
                            | "verified"
                            | "verified_target_cleared"
                            | "retracted"
                            | "cancelled_before_attempt"
                            | "rejected"
                    )
                )
            })
            .count()
    });
    if verification_attention > 0 {
        warnings.push("journal: verification records require attention".into());
    }
    let budget = &state["model_budget"];
    let recorded_used = if budget.is_null() {
        state["model_invocations"].as_u64()
    } else {
        budget["used"].as_u64()
    };
    let today = OffsetDateTime::now_utc().date().to_string();
    let day = budget["utc_day"].as_str().filter(|s| {
        s.len() == 10 && OffsetDateTime::parse(&format!("{s}T00:00:00Z"), &Rfc3339).is_ok()
    });
    let invalid_budget = !budget.is_null() && (day.is_none() || recorded_used.is_none());
    if invalid_budget {
        errors.push("journal: invalid model budget metadata".into());
    }
    if budget.is_null() {
        warnings.push("journal: legacy model budget not initialized; lifetime count is conservatively carried, no write performed".into());
    }
    let rollover_due = day.is_some_and(|d| d < today.as_str());
    let effective_used = if rollover_due { Some(0) } else { recorded_used };
    let limit = config["model_daily_limit"].as_u64();
    let budget_status = match limit {
        None => "budget_not_configured",
        Some(0) => "model_disabled",
        Some(_) if invalid_budget || effective_used.is_none() => "budget_state_invalid",
        Some(_) if day.is_some_and(|d| d > today.as_str()) => "clock_rollback_blocked",
        Some(n) if effective_used.is_some_and(|u| u >= n) => "daily_budget_exhausted",
        Some(_) => "available_locally_only",
    };
    if budget_status != "available_locally_only" {
        blockers.push(budget_status);
    }
    json!({"available":true,"summary_only":true,"version":version,"pending":pending,"generation_unresolved":generation,
        "receipts_unresolved":receipts_unresolved,"verification_pending":verification_pending,"verification_attention":verification_attention,
        "blockers":blockers,"blocker_scope":"local admission gates; not a live runtime health assessment",
        "budget":{"limit":limit,"recorded_used":recorded_used,"effective_used":effective_used,"rollover_due":rollover_due,"status":budget_status}})
}

fn self_view(
    last: Option<&Value>,
    state: Option<&Value>,
    config: &Value,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
) -> Value {
    let (current, source, checked) = if let Some(last) = last.filter(|v| v["self"].is_object()) {
        (
            &last["self"],
            "last-self.json",
            timestamp(&last["checked_at"]),
        )
    } else if let Some(state) = state.filter(|v| v["self"].is_object()) {
        warnings
            .push("self_snapshot: using state cache; standalone self snapshot unavailable".into());
        (
            &state["self"],
            "state.json",
            timestamp(&state["self_checked_epoch"]),
        )
    } else {
        errors.push("self_snapshot: missing cached status; live state is unknown".into());
        return json!({"available":false,"source":"none","age_seconds":null,"state":"unknown","identity_matches_config":null});
    };
    let age = checked.map(|at| epoch_now() - at);
    match age {
        None => warnings.push("self_snapshot: age unavailable".into()),
        Some(n) if n < 0.0 => warnings.push("self_snapshot: timestamp is in the future".into()),
        Some(n) if n > 300.0 => {
            warnings.push("self_snapshot: stale cache; no fresh request was made".into())
        }
        Some(_) => {}
    }
    let status = match current["state"].as_str() {
        Some("ACTIVE") => "ACTIVE",
        Some("PENDING") => "PENDING",
        _ => "unknown",
    };
    if status == "unknown" {
        errors.push("self_snapshot: unknown cached admission state".into());
    }
    if status == "PENDING" {
        warnings
            .push("self_snapshot: cached identity is not admitted for public discussion".into());
    }
    let timeline = match current["timeline"].as_str() {
        Some("public") => "public",
        Some("conformance") => "conformance",
        _ => "unknown",
    };
    if timeline == "unknown" {
        errors.push("self_snapshot: missing or unknown cached timeline".into());
    }
    let identity_matches = current["agent_id"]
        .as_str()
        .zip(config["application"]["agent_id"].as_str())
        .map(|(a, b)| a == b);
    if identity_matches != Some(true) {
        errors.push("self_snapshot: cached identity missing or mismatches config".into());
    }
    let paused = current["room_paused"].as_bool();
    let muted = current.get("mute").map(|v| !v.is_null());
    if paused != Some(false) {
        warnings.push("self_snapshot: room pause is set or unknown".into());
    }
    if muted != Some(false) {
        warnings.push("self_snapshot: mute is set or unknown".into());
    }
    json!({"available":true,"source":source,"age_seconds":age,"state":status,"timeline":timeline,
        "identity_matches_config":identity_matches,"room_paused":paused,"muted":muted,"fresh_request_made":false})
}
fn process_view(process: Option<&Value>, warnings: &mut Vec<String>) -> Value {
    let process = process.unwrap_or(&Value::Null);
    let state = match process["state"].as_str() {
        Some("running") => "running",
        Some("stopped") => "stopped",
        _ => "unknown",
    };
    let pid = process["pid"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= i32::MAX as u64);
    // Signal zero checks existence/permission only: it delivers no signal and
    // cannot establish command identity, ownership of this state, or liveness.
    let exists = pid.and_then(|pid| {
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
            Some(true)
        } else {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::ESRCH) => Some(false),
                Some(libc::EPERM) => Some(true),
                _ => None,
            }
        }
    });
    if state == "unknown" {
        warnings.push("process: missing or unknown recorded status".into());
    }
    if state == "stopped" {
        warnings.push("process: recorded stopped; no running service is asserted".into());
    }
    if pid.is_none() {
        warnings.push("process: missing or invalid recorded PID".into());
    }
    if state == "running" && exists == Some(false) {
        warnings.push("process: recorded PID does not exist".into());
    }
    let build = process.get("build").filter(|v| v.is_object());
    let expected = build_info();
    let matches = build.map(|v| {
        ["version", "source_revision", "os", "arch"]
            .iter()
            .all(|k| v[*k] == expected[*k])
    });
    if build.is_none() {
        warnings.push("process: recorded build identity unavailable".into());
    }
    json!({"recorded_state":state,"recorded_pid":pid,"pid_exists":exists,"pid_command_or_identity_verified":false,
        "age_seconds":timestamp(&process[if state == "stopped" {"stopped_at"} else {"started_at"}]).map(|at|epoch_now()-at),
        "recorded_build_present":build.is_some(),"recorded_build_matches_current":matches,"build_comparison":"metadata only; not binary or running identity"})
}

/// Read-only local evidence, never proof of TLS, authentication, model access or
/// a running identity. No Client::open, journal upgrade, writer lock, or writes.
pub(crate) fn doctor(home: &Path) -> Result<Value> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let (config, config_file) = document(&home.join("config.json"), CONFIG_LIMIT, None);
    if config.is_none() {
        errors.push(format!(
            "config.json: {}",
            config_file["read_status"].as_str().unwrap_or("unavailable")
        ));
    }
    let config = config.unwrap_or(Value::Null);
    let report = config_report(&config);
    if report["valid"] != true {
        errors.push("config.json: invalid configuration; see sanitized config issues".into());
    }
    let key_path = configured_path(&config["key_file"]);
    let mut key_file = key_path
        .map(file_metadata)
        .unwrap_or(json!({"status":"not_configured","regular_file":false}));
    // Following a link for metadata also protects its target from CA/JSON alias
    // reads. The signing key itself must still be a private, nonsymlink file.
    let key_meta = key_path.and_then(|p| fs::metadata(p).ok());
    let private = key_meta
        .as_ref()
        .is_some_and(|m| m.permissions().mode() & 0o077 == 0);
    let owner = key_meta
        .as_ref()
        .is_some_and(|m| m.uid() == unsafe { libc::geteuid() });
    key_file["contents_read"] = json!(false);
    key_file["private_permissions"] = json!(private);
    key_file["owner_matches_current_user"] = json!(owner);
    if key_file["regular_file"] != true || !private || !owner {
        errors.push("key_file: missing, nonregular, symlinked, nonprivate or owned by another user; contents not read".into());
    }
    let (state, state_file) = document(&home.join("state.json"), LOCAL_LIMIT, key_meta.as_ref());
    let (last, self_file) = document(&home.join("last-self.json"), LOCAL_LIMIT, key_meta.as_ref());
    let (process, process_file) =
        document(&home.join("process.json"), CONFIG_LIMIT, key_meta.as_ref());
    if state.is_none() {
        errors.push(format!(
            "state.json: {}",
            state_file["read_status"].as_str().unwrap_or("unavailable")
        ));
    }
    if last.is_none() {
        warnings.push(format!(
            "last-self.json: {}",
            self_file["read_status"].as_str().unwrap_or("unavailable")
        ));
    }
    if process.is_none() {
        warnings.push(format!(
            "process.json: {}",
            process_file["read_status"]
                .as_str()
                .unwrap_or("unavailable")
        ));
    }
    let mut ca_file = configured_path(&config["ca_file"])
        .map(file_metadata)
        .unwrap_or(json!({"status":"not_configured"}));
    let ca = configured_path(&config["ca_file"])
        .ok_or("not_configured")
        .and_then(|p| read_regular(p, CONFIG_LIMIT, key_meta.as_ref()));
    match ca {
        Ok(raw) => {
            let digest = crate::sha(&raw);
            let matches = config["ca_sha256"].as_str().map(|pin| pin == digest);
            ca_file["read_status"] = json!("ok");
            ca_file["sha256"] = json!(digest);
            ca_file["pin_matches"] = json!(matches);
            if matches != Some(true) {
                errors.push("ca_file: bytes do not match configured pin".into());
            }
        }
        Err(code) => {
            ca_file["read_status"] = json!(code);
            errors.push(format!("ca_file: {code}"));
        }
    }
    ca_file["trust_verified"] = json!(false);
    let curl = executable_metadata(configured_path(&config["curl_executable"]));
    let default_hermes = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|p| p.join(".local/bin/hermes"));
    let hermes_path = if config.get("hermes_executable").is_some() {
        absolute_path(&config["hermes_executable"])
    } else {
        default_hermes.as_deref().filter(|p| p.is_absolute())
    };
    let hermes = executable_metadata(hermes_path);
    for (name, value) in [("curl_executable", &curl), ("hermes_executable", &hermes)] {
        if value["executable_bits_set"] != true {
            errors.push(format!(
                "{name}: executable regular file not found by metadata checks"
            ));
        }
    }
    let journal = journal_view(state.as_ref(), &config, &mut errors, &mut warnings);
    let cached_self = self_view(
        last.as_ref(),
        state.as_ref(),
        &config,
        &mut errors,
        &mut warnings,
    );
    let process = process_view(process.as_ref(), &mut warnings);
    let attention = !errors.is_empty()
        || !warnings.is_empty()
        || !report["warnings"].as_array().is_some_and(|a| a.is_empty())
        || !journal["blockers"].as_array().is_some_and(|a| a.is_empty());
    Ok(
        json!({"offline":true,"read_only":true,"runtime_verified":false,"attention_required":attention,
        "snapshot_consistency":"best effort without a writer lock",
        "not_verified":["tool_execution","TLS","authentication","model_access","signing_key_contents","process_command_or_identity"],
        "build":build_info(),"config":report,"errors":errors,"warnings":warnings,
        "files":{"home":file_metadata(home),"config":config_file,"state":state_file,"self_snapshot":self_file,"process":process_file,
            "key":key_file,"ca":ca_file,"curl_executable":curl,"hermes_executable":hermes},
        "journal":journal,"self_snapshot":cached_self,"process":process}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        ffi::CString,
        os::{
            fd::AsRawFd,
            unix::fs::{MetadataExt, PermissionsExt, symlink},
        },
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = PathBuf::from(std::env::var_os("TMPDIR").expect("test TMPDIR"));
            assert!(root.is_absolute());
            let path = root.join(format!(
                "tolink-diagnostics-{}-{}-{}",
                std::process::id(),
                OffsetDateTime::now_utc().unix_timestamp_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, raw: &[u8], mode: u32) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, raw).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            path
        }
        fn json(&self, name: &str, value: &Value) {
            self.write(name, &serde_json::to_vec(value).unwrap(), 0o600);
        }
        fn fifo(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            let c = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            path
        }
        fn populated() -> Self {
            let f = Self::new();
            let mut config = example();
            config["key_file"] = json!(f.write(
                "seed",
                b"private synthetic sentinel; not a real seed",
                0o600
            ));
            config["ca_file"] = json!(f.write("ca.pem", b"synthetic public CA bytes", 0o600));
            config["ca_sha256"] = json!(crate::sha(b"synthetic public CA bytes"));
            let executable = f.write(
                "never-execute",
                b"This is deliberately not an executable program.\n",
                0o700,
            );
            config["curl_executable"] = json!(executable);
            config["hermes_executable"] = config["curl_executable"].clone();
            config["owner_contact"] = json!("SECRET-CONTACT");
            config["prompt"] = json!("SECRET-PROMPT");
            f.json("config.json", &config);
            f.json("state.json", &json!({"rust_journal_version":2,"context":[],"handled":[],"own_event_ids":[],"model_invocations":0,"inbox":[],"verifications":[],"model_budget":{"utc_day":OffsetDateTime::now_utc().date().to_string(),"used":0},"private_extra":"SECRET-STATE"}));
            f.json("last-self.json", &json!({"checked_at":OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),"self":{"state":"ACTIVE","timeline":"public","agent_id":"replace-agent-id","mute":null,"room_paused":false,"display_name":"SECRET-NAME"}}));
            f.json("process.json", &json!({"pid":std::process::id(),"state":"running","started_at":OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),"build":build_info(),"reason":"SECRET-PROCESS"}));
            f
        }
        fn snapshot(&self) -> BTreeMap<String, (u64, u32, i64, i64, u64)> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let meta = fs::symlink_metadata(entry.path()).unwrap();
                    (
                        entry.file_name().to_string_lossy().into_owned(),
                        (
                            meta.len(),
                            meta.mode(),
                            meta.mtime(),
                            meta.mtime_nsec(),
                            meta.ino(),
                        ),
                    )
                })
                .collect()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn example() -> Value {
        serde_json::from_str(include_str!("../examples/config.example.json")).unwrap()
    }
    fn strings_contain(value: &Value, needle: &str) -> bool {
        value
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains(needle))
    }

    #[test]
    fn complete_example_is_syntax_valid_but_not_authorized_or_trusted() {
        let config = example();
        let report = config_report(&config);
        assert_eq!(report["valid"], true, "{report}");
        assert_eq!(report["referenced_paths_checked"], false);
        assert!(strings_contain(
            &report["warnings"],
            "nontrusted placeholder"
        ));
        assert!(strings_contain(&report["warnings"], "not authorized"));
        assert_eq!(config["reply_batch_max"], 3);
        assert_eq!(config["model_daily_limit"], 20);
        assert_eq!(config["public_send_interval_seconds"], 60);
        assert!(!report.to_string().contains("/absolute/path"));
    }

    #[test]
    fn validation_accumulates_sanitized_errors_and_ignores_legacy_extras() {
        let mut config = example();
        config["base_url"] = json!("SECRET-URL");
        config["application"]["agent_id"] = json!("SECRET-IDENTITY");
        config["owner_authorization"]["allow_public_replies"] = json!("SECRET-AUTH");
        config["public_send_interval_seconds"] = json!(0);
        config["model_daily_limit"] = json!("SECRET-LIMIT");
        config["reply_batch_max"] = json!(4);
        config["owner_contact"] = json!("SECRET-CONTACT");
        let report = config_report(&config);
        assert_eq!(report["valid"], false);
        assert!(report["errors"].as_array().unwrap().len() >= 6);
        assert!(!report.to_string().contains("SECRET"));
        let mut config = example();
        config.as_object_mut().unwrap().remove("reply_batch_max");
        config.as_object_mut().unwrap().remove("hermes_executable");
        config["owner_contact"] = json!({"legacy":"ignored"});
        config["key_file"] = json!("legacy-seed");
        config["ca_file"] = json!("legacy-ca.pem");
        config["curl_executable"] = json!("legacy-curl");
        config["model_daily_limit"] = json!(0);
        assert_eq!(config_report(&config)["valid"], true);
        for cap in [0, 1, 2, 3, 4] {
            config["reply_batch_max"] = json!(cap);
            assert_eq!(config_report(&config)["valid"], (1..=3).contains(&cap));
        }
    }

    #[test]
    fn validation_checks_runtime_shapes_without_opening_referenced_paths() {
        let f = Fixture::new();
        let mut config = example();
        for name in [
            "ca_file",
            "key_file",
            "curl_executable",
            "hermes_executable",
        ] {
            config[name] = json!(f.fifo(name));
        }
        f.json("config.json", &config);
        assert_eq!(
            validate_path(&f.0.join("config.json")).unwrap()["valid"],
            true
        );
        for (field, value) in [
            ("base_url", json!("http://192.0.2.10:8443/participant/v1/")),
            ("base_url", json!("https://192.0.2.10:8443/wrong/")),
            ("authority", json!("other.example:8443")),
            ("model_daily_limit", json!(-1)),
            ("model_daily_limit", json!(1.5)),
            ("public_send_interval_seconds", json!(0)),
            ("reply_batch_max", Value::Null),
            ("hermes_executable", json!("relative/hermes")),
            ("model_name", json!([])),
            ("public_role", json!(false)),
        ] {
            let mut bad = config.clone();
            bad[field] = value;
            assert_eq!(config_report(&bad)["valid"], false, "{field}");
        }
        let mut missing = config;
        missing.as_object_mut().unwrap().remove("model_daily_limit");
        assert_eq!(config_report(&missing)["valid"], false);
        assert_eq!(config_report(&json!([]))["valid"], false);
    }

    #[test]
    fn validation_input_is_bounded_regular_and_parse_errors_are_redacted() {
        let f = Fixture::new();
        let invalid = f.write("invalid", b"{\"SECRET-JSON\": SECRET-VALUE}", 0o600);
        let large = f.write("large", b"", 0o600);
        fs::OpenOptions::new()
            .write(true)
            .open(&large)
            .unwrap()
            .set_len(CONFIG_LIMIT + 1)
            .unwrap();
        let link = f.0.join("link");
        symlink(&invalid, &link).unwrap();
        for path in [
            f.0.clone(),
            f.0.join("missing"),
            f.fifo("fifo"),
            invalid,
            large,
            link,
        ] {
            let report = validate_path(&path).unwrap();
            assert_eq!(report["valid"], false, "{report}");
            assert!(!report["errors"].as_array().unwrap().is_empty());
            assert!(!report.to_string().contains("SECRET"));
            assert!(!report.to_string().contains(f.0.to_str().unwrap()));
        }
    }

    #[test]
    fn doctor_reports_missing_state_without_creating_anything() {
        let f = Fixture::new();
        let missing = f.0.join("absent");
        let report = doctor(&missing).unwrap();
        assert_eq!(report["attention_required"], true);
        assert_eq!(report["runtime_verified"], false);
        assert_eq!(report["files"]["config"]["read_status"], "missing");
        assert!(!report["errors"].as_array().unwrap().is_empty());
        assert!(!missing.exists());
    }

    #[test]
    fn doctor_is_read_only_lock_independent_and_presence_is_not_execution() {
        let f = Fixture::populated();
        let mut config: Value =
            serde_json::from_slice(&fs::read(f.0.join("config.json")).unwrap()).unwrap();
        config["owner_authorization"]["allow_public_replies"] = json!(true);
        f.json("config.json", &config);
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(f.0.join("client.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let before = f.snapshot();
        let report = doctor(&f.0).unwrap();
        assert_eq!(before, f.snapshot());
        assert_eq!(report["read_only"], true);
        assert_eq!(report["runtime_verified"], false);
        assert_eq!(
            report["attention_required"], false,
            "scope disclaimers must not masquerade as actionable problems: {report}"
        );
        assert_eq!(report["config"]["valid"], true);
        assert_eq!(report["files"]["key"]["contents_read"], false);
        assert_eq!(report["files"]["ca"]["pin_matches"], true);
        assert_eq!(
            report["files"]["curl_executable"]["executable_bits_set"],
            true
        );
        assert_eq!(
            report["files"]["curl_executable"]["execution_verified"],
            false
        );
        assert_eq!(report["process"]["pid_exists"], true);
        assert_eq!(report["process"]["pid_command_or_identity_verified"], false);
        assert_eq!(report["process"]["recorded_build_matches_current"], true);
        assert_eq!(report["self_snapshot"]["identity_matches_config"], true);
        assert!(report["self_snapshot"]["age_seconds"].as_f64().unwrap() >= 0.0);
        assert!(!report.to_string().contains("SECRET"));
        assert!(report["errors"].as_array().unwrap().is_empty(), "{report}");
    }

    #[test]
    fn doctor_surfaces_new_journal_blockers_without_upgrade_or_text_leaks() {
        let f = Fixture::populated();
        let state = json!({"rust_journal_version":73,"context":[],"handled":[],"own_event_ids":[],"model_invocations":20,"model_budget":{"utc_day":OffsetDateTime::now_utc().date().to_string(),"used":20},"inbox":[{"status":"received","event":{"text":"SECRET-MESSAGE"}}],"rust_generation":{"phase":"SECRET-PHASE","result":"SECRET-DRAFT","intent":{"trigger_ids":["one","two"]}},"pending":{"body":{"text":"SECRET-PENDING"}},"owned_cleanup_unconfirmed":true,"delivery_uncertainty":true,"verifications":[{"state":"accepted"},{"state":"delivery_unknown_cancelled"}]});
        f.json("state.json", &state);
        let before = fs::read(f.0.join("state.json")).unwrap();
        let report = doctor(&f.0).unwrap();
        assert_eq!(before, fs::read(f.0.join("state.json")).unwrap());
        assert_eq!(report["journal"]["version"], 73);
        assert_eq!(report["journal"]["receipts_unresolved"], 1);
        assert_eq!(report["journal"]["verification_pending"], 1);
        assert_eq!(report["journal"]["verification_attention"], 1);
        for reason in [
            "generation_unresolved",
            "owned_cleanup_unconfirmed",
            "daily_budget_exhausted",
        ] {
            assert!(
                strings_contain(&report["journal"]["blockers"], reason),
                "{report}"
            );
        }
        assert!(!report.to_string().contains("SECRET"));
    }

    #[test]
    fn doctor_never_reads_key_through_ca_or_snapshot_aliases() {
        let f = Fixture::populated();
        let mut config: Value =
            serde_json::from_slice(&fs::read(f.0.join("config.json")).unwrap()).unwrap();
        fs::remove_file(f.0.join("ca.pem")).unwrap();
        fs::hard_link(f.0.join("seed"), f.0.join("ca.pem")).unwrap();
        fs::remove_file(f.0.join("state.json")).unwrap();
        fs::hard_link(f.0.join("seed"), f.0.join("state.json")).unwrap();
        config["ca_sha256"] = json!("0".repeat(64));
        f.json("config.json", &config);
        let report = doctor(&f.0).unwrap();
        assert_eq!(
            report["files"]["ca"]["read_status"],
            "signing_key_read_refused"
        );
        assert_eq!(
            report["files"]["state"]["read_status"],
            "signing_key_read_refused"
        );
        assert_eq!(report["files"]["key"]["contents_read"], false);
    }

    #[test]
    fn doctor_checks_key_permissions_missing_executables_and_snapshot_health() {
        let f = Fixture::populated();
        fs::set_permissions(f.0.join("seed"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(f.0.join("never-execute")).unwrap();
        f.json("last-self.json", &json!({"checked_at":"2000-01-01T00:00:00Z","self":{"state":"SECRET-STATUS","timeline":"SECRET-TIMELINE","agent_id":"other-agent"}}));
        f.json("process.json", &json!({"state":"SECRET-PROCESS","pid":-1}));
        let report = doctor(&f.0).unwrap();
        assert_eq!(report["files"]["key"]["private_permissions"], false);
        assert_eq!(report["files"]["hermes_executable"]["status"], "missing");
        assert_eq!(report["self_snapshot"]["state"], "unknown");
        assert_eq!(report["self_snapshot"]["identity_matches_config"], false);
        assert_eq!(report["process"]["pid_exists"], Value::Null);
        assert!(report["self_snapshot"]["age_seconds"].as_f64().unwrap() > 300.0);
        assert!(strings_contain(&report["warnings"], "stale"));
        assert!(!report.to_string().contains("SECRET"));
    }

    #[test]
    fn doctor_rejects_special_files_and_never_opens_a_key_fifo() {
        let f = Fixture::populated();
        for name in ["seed", "ca.pem", "state.json"] {
            fs::remove_file(f.0.join(name)).unwrap();
            f.fifo(name);
        }
        let before = f.snapshot();
        let report = doctor(&f.0).unwrap();
        assert_eq!(before, f.snapshot());
        assert_eq!(report["files"]["key"]["status"], "special");
        assert_eq!(report["files"]["key"]["contents_read"], false);
        assert_eq!(report["files"]["ca"]["read_status"], "not_regular");
        assert_eq!(report["files"]["state"]["read_status"], "not_regular");
        assert_eq!(report["attention_required"], true);
    }

    #[test]
    fn doctor_reports_legacy_and_calendar_budget_gates_without_mutation() {
        let f = Fixture::populated();
        let mut state = json!({"context":[],"handled":[],"own_event_ids":[],"model_invocations":7,
            "self":{"state":"ACTIVE","timeline":"public","agent_id":"replace-agent-id","mute":null,"room_paused":false},"self_checked_epoch":epoch_now()});
        fs::remove_file(f.0.join("last-self.json")).unwrap();
        for (budget, status, effective_used) in [
            (Value::Null, "available_locally_only", Some(7)),
            (
                json!({"utc_day":"2000-01-01","used":100}),
                "available_locally_only",
                Some(0),
            ),
            (
                json!({"utc_day":"2999-01-01","used":0}),
                "clock_rollback_blocked",
                Some(0),
            ),
            (
                json!({"utc_day":OffsetDateTime::now_utc().date().to_string(),"used":20}),
                "daily_budget_exhausted",
                Some(20),
            ),
            (
                json!({"utc_day":"SECRET-DAY","used":0}),
                "budget_state_invalid",
                Some(0),
            ),
        ] {
            state["model_budget"] = budget;
            f.json("state.json", &state);
            let before = fs::read(f.0.join("state.json")).unwrap();
            let report = doctor(&f.0).unwrap();
            assert_eq!(before, fs::read(f.0.join("state.json")).unwrap());
            assert_eq!(report["self_snapshot"]["source"], "state.json");
            assert_eq!(report["journal"]["version"], Value::Null);
            assert_eq!(report["journal"]["budget"]["status"], status, "{report}");
            assert_eq!(
                report["journal"]["budget"]["effective_used"],
                json!(effective_used)
            );
            assert!(!report.to_string().contains("SECRET"));
        }
        state["blocked_until"] = json!(epoch_now() + 60.0);
        state["next_public_send_epoch"] = json!(epoch_now() + 60.0);
        state["model_budget"] = Value::Null;
        f.json("state.json", &state);
        let report = doctor(&f.0).unwrap();
        for reason in ["request_backoff", "public_send_pacing"] {
            assert!(strings_contain(&report["journal"]["blockers"], reason));
        }
    }

    #[test]
    fn patch_doctor_rejects_the_same_journal_formats_as_runtime() {
        let f = Fixture::populated();
        let mut config: Value =
            serde_json::from_slice(&fs::read(f.0.join("config.json")).unwrap()).unwrap();
        config["owner_authorization"]["allow_public_replies"] = json!(true);
        f.json("config.json", &config);
        assert_eq!(doctor(&f.0).unwrap()["attention_required"], false);
        let original: Value =
            serde_json::from_slice(&fs::read(f.0.join("state.json")).unwrap()).unwrap();
        for issue in ["zero_version", "bad_outreach_index"] {
            let mut state = original.clone();
            if issue == "zero_version" {
                state["rust_journal_version"] = json!(0);
            } else {
                state["outreach_request_ids"] = json!("not-an-array");
            }
            assert!(crate::journal::prepare(&mut state.clone()).is_err());
            f.json("state.json", &state);
            let before = fs::read(f.0.join("state.json")).unwrap();
            let report = doctor(&f.0).unwrap();
            assert!(
                !report["errors"].as_array().unwrap().is_empty(),
                "doctor falsely accepted {issue}"
            );
            assert_eq!(report["attention_required"], true);
            assert_eq!(before, fs::read(f.0.join("state.json")).unwrap());
        }
    }

    #[test]
    fn required_api_signatures_and_build_identity_are_exact() {
        let _: fn(&Value) -> Value = config_report;
        let _: fn(&Path) -> crate::Result<Value> = validate_path;
        let _: fn(&Path) -> crate::Result<Value> = doctor;
        let _: fn() -> Value = build_info;
        let info = build_info();
        assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(
            info["source_revision"],
            option_env!("TOLINK_BUILD_REVISION").unwrap_or("unknown")
        );
        assert_eq!(info["os"], std::env::consts::OS);
        assert_eq!(info["arch"], std::env::consts::ARCH);
    }
}
