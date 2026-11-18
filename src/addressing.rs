//! Protocol agent-id tokens, not string-prefix recipient matching.
use std::collections::BTreeSet;

pub(crate) fn valid_id(id: &str) -> bool {
    (3..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

fn id_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
}

pub(crate) fn mentions(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut ids = BTreeSet::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'@'
            || (at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'-'))
        {
            at += 1;
            continue;
        }
        let start = at + 1;
        at = start;
        while at < bytes.len() && id_byte(bytes[at]) {
            at += 1;
        }
        // Consume the complete token: never accept a valid prefix of a longer id.
        if valid_id(&text[start..at]) {
            ids.insert(text[start..at].to_owned());
        }
    }
    ids
}

pub(crate) fn validate_text(
    text: &str,
    allowed: &BTreeSet<String>,
    prefix: Option<&str>,
) -> Result<(), String> {
    if let Some(id) = prefix {
        if !valid_id(id) || !text.starts_with('@') {
            return Err("outreach requires a complete @recipient token".into());
        }
        let end = text.as_bytes()[1..]
            .iter()
            .position(|b| !id_byte(*b))
            .map_or(text.len(), |n| n + 1);
        if &text[1..end] != id {
            return Err(
                "outreach starts with a different recipient, not the requested full agent_id"
                    .into(),
            );
        }
    }
    if !mentions(text).is_subset(allowed) {
        return Err("draft would mention an agent outside its allowed recipient set".into());
    }
    Ok(())
}

pub(crate) fn validate_readback(
    actual: &BTreeSet<String>,
    allowed: &BTreeSet<String>,
    required: Option<&str>,
) -> bool {
    actual.is_subset(allowed) && required.is_none_or(|id| actual.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn allowed() -> BTreeSet<String> {
        BTreeSet::from(["bob".to_owned()])
    }
    #[test]
    fn exact_prefix_and_allowed_set_not_starts_with() {
        assert!(validate_text("@bob hello", &allowed(), Some("bob")).is_ok());
        assert!(validate_text("@bob，hello", &allowed(), Some("bob")).is_ok());
        assert!(validate_text("@bobby hello", &allowed(), Some("bob")).is_err());
        assert!(validate_text("@bob hello @bobby", &allowed(), Some("bob")).is_err());
        assert!(validate_text("@bob- hello", &allowed(), Some("bob")).is_err());
    }
    #[test]
    fn complete_tokens_are_not_truncated_to_valid_prefixes() {
        assert!(mentions("a@bob A@bob 1@bob -@bob").is_empty());
        assert_eq!(mentions("谢谢@bob"), allowed());
        assert!(mentions(&format!("@{}", "x".repeat(33))).is_empty());
        assert!(mentions("@-bob @bob- @ab").is_empty());
        assert_eq!(
            mentions("@bob @bob @bobby"),
            BTreeSet::from(["bob".into(), "bobby".into()])
        );
    }
    #[test]
    fn readback_requires_exact_outreach_set() {
        assert!(validate_readback(&allowed(), &allowed(), Some("bob")));
        assert!(!validate_readback(
            &BTreeSet::from(["bob".into(), "bobby".into()]),
            &allowed(),
            Some("bob")
        ));
        assert!(!validate_readback(
            &BTreeSet::new(),
            &allowed(),
            Some("bob")
        ));
        // A reply target's departed author may no longer receive an automatic reminder.
        assert!(validate_readback(&BTreeSet::new(), &allowed(), None));
    }
}
