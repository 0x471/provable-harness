//! Notary-signed session logs: what the notary saw for given sessions.
//!
//! A proof shows what happened in the runs the operator *delivered*. It cannot
//! show runs the operator started, disliked and abandoned (selective abort), or
//! never started. The notary saw every slot it handed out, so on request it
//! signs a log for a list of sessions: for each slot, the sequence of journal
//! events (`C` consumed, `D` attestation signed, `R` released after a non-200
//! model reply). A queried session with no entries means the notary never
//! handed out a slot for it.
//!
//! The verifier checks the signature against the pinned notary key and compares
//! the log with the eval report (`ph eval verify --notary-log`).

use serde::{Deserialize, Serialize};

use crate::hash::{domain, Digest, Hasher};
use crate::zktls::{NotaryKey, Slot};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotHistory {
    /// `Slot::to_text()`.
    pub slot: String,
    /// Journal events in order, e.g. "CD", "CDRCD" (a retried 529), "C" (aborted).
    pub events: String,
}

impl SlotHistory {
    /// The slot's final state.
    pub fn status(&self) -> SlotStatus {
        match self.events.as_bytes().last() {
            Some(b'D') => SlotStatus::Signed,
            Some(b'R') => SlotStatus::Released,
            _ => SlotStatus::Aborted,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotStatus {
    /// An attestation was signed (the run can use it).
    Signed,
    /// A non-200 model reply was notarized and the slot freed for a retry.
    Released,
    /// Consumed but never signed: the prover aborted (or the session is in progress).
    Aborted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLog {
    /// Notary public key (k256, compressed SEC1).
    pub notary_key: Vec<u8>,
    /// Notary clock when the log was produced (unix seconds).
    pub generated_at: u64,
    /// Sessions the log covers (hex), sorted. Absent from `slots` = never started.
    pub sessions: Vec<String>,
    /// Every slot of those sessions, sorted by slot text.
    pub slots: Vec<SlotHistory>,
    /// ECDSA secp256k1 / SHA-256 signature over `digest()`.
    pub signature: Vec<u8>,
}

impl SessionLog {
    /// What the notary signs (everything but the signature).
    pub fn digest(&self) -> Digest {
        let mut h = Hasher::new(domain::NOTARY_LOG);
        h.bytes(&self.notary_key)
            .u64(self.generated_at)
            .strs(&self.sessions)
            .u64(self.slots.len() as u64);
        for s in &self.slots {
            h.str(&s.slot).str(&s.events);
        }
        h.finish()
    }

    /// Check the signature against the pinned notary key and the log's shape.
    pub fn verify(&self, pinned: &NotaryKey) -> Result<(), String> {
        use k256::ecdsa::signature::Verifier as _;
        if pinned.alg != "k256" || pinned.key != self.notary_key {
            return Err("session log is not from the pinned notary".into());
        }
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&self.notary_key)
            .map_err(|_| "bad notary key".to_string())?;
        let sig = k256::ecdsa::Signature::from_slice(&self.signature)
            .map_err(|_| "malformed session log signature".to_string())?;
        vk.verify(&self.digest(), &sig)
            .map_err(|_| "session log signature does not verify".to_string())?;
        let mut sorted = self.sessions.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != self.sessions {
            return Err("session list must be sorted and unique".into());
        }
        for s in &self.slots {
            let slot = Slot::parse_text(&s.slot).ok_or("malformed slot in session log")?;
            if !self.sessions.contains(&crate::hash::to_hex(&slot.session)) {
                return Err("session log has a slot outside its session list".into());
            }
            if s.events.is_empty() || !s.events.bytes().all(|b| matches!(b, b'C' | b'D' | b'R')) {
                return Err("malformed slot history".into());
            }
        }
        Ok(())
    }

    /// The histories of one session's slots.
    pub fn session_slots<'a>(&'a self, session_hex: &'a str) -> impl Iterator<Item = (Slot, &'a SlotHistory)> + 'a {
        self.slots.iter().filter_map(move |h| {
            let s = Slot::parse_text(&h.slot)?;
            (crate::hash::to_hex(&s.session) == session_hex).then_some((s, h))
        })
    }
}

/// How one run of an eval compares with the notary's log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunVerdict {
    /// Delivered, and the notary signed exactly model steps 0..steps.
    Consistent,
    /// Delivered, but the log disagrees (the proof and the log cannot both be
    /// from honest parties, or the log is from another notary or journal).
    Inconsistent(String),
    /// Not delivered; the notary never handed out a slot for it.
    NeverStarted,
    /// Not delivered, although the notary signed every slot it handed out: the
    /// operator held real model replies for `signed` steps and withheld the run.
    Withheld { signed: u32 },
    /// Not delivered; the operator stopped during `slot` (after the notary
    /// consumed it, possibly after seeing the reply).
    Aborted { slot: String },
}

/// Compare one run with the log. `delivered_steps` is the proven claim's step
/// count (None for a missing run). `tool_slots_expected` is false when the run's
/// tools are answered in the proof (fixture worlds), so no tool slot may exist.
pub fn reconcile(
    log: &SessionLog,
    session_hex: &str,
    delivered_steps: Option<u32>,
    tool_slots_expected: bool,
) -> RunVerdict {
    use crate::zktls::SlotKind;
    let slots: Vec<(Slot, &SlotHistory)> = log.session_slots(session_hex).collect();
    let Some(steps) = delivered_steps else {
        if let Some((_, h)) = slots.iter().find(|(_, h)| h.status() == SlotStatus::Aborted) {
            return RunVerdict::Aborted { slot: h.slot.clone() };
        }
        if slots.is_empty() {
            return RunVerdict::NeverStarted;
        }
        let signed = slots
            .iter()
            .filter(|(s, h)| s.kind == SlotKind::Model && h.status() == SlotStatus::Signed)
            .count() as u32;
        return RunVerdict::Withheld { signed };
    };
    let mut model: Vec<(u64, SlotStatus)> = vec![];
    for (s, h) in &slots {
        match s.kind {
            SlotKind::Model => model.push((s.n, h.status())),
            SlotKind::Tool if !tool_slots_expected => {
                return RunVerdict::Inconsistent(format!("unexpected tool slot {}", h.slot));
            }
            SlotKind::Tool if h.status() != SlotStatus::Signed => {
                return RunVerdict::Inconsistent(format!("tool slot {} was not signed", h.slot));
            }
            SlotKind::Tool => {}
        }
    }
    model.sort_by_key(|m| m.0);
    let expected: Vec<(u64, SlotStatus)> = (0..steps as u64).map(|n| (n, SlotStatus::Signed)).collect();
    if model != expected {
        return RunVerdict::Inconsistent(format!(
            "notary log has model slots {:?}, the proven run used steps 0..{steps}, all signed",
            model.iter().map(|(n, st)| format!("{n}:{st:?}")).collect::<Vec<_>>()
        ));
    }
    RunVerdict::Consistent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::to_hex;

    fn log(entries: &[(Slot, &str)], sessions: &[[u8; 32]]) -> SessionLog {
        let mut sessions: Vec<String> = sessions.iter().map(|s| to_hex(s)).collect();
        sessions.sort();
        SessionLog {
            notary_key: vec![],
            generated_at: 0,
            sessions,
            slots: entries
                .iter()
                .map(|(s, e)| SlotHistory { slot: s.to_text(), events: e.to_string() })
                .collect(),
            signature: vec![],
        }
    }

    #[test]
    fn verdicts() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let ha = to_hex(&a);
        let l = |e: &[(Slot, &str)]| log(e, &[a, b]);
        let ok = l(&[(Slot::model(&a, 0), "CD"), (Slot::model(&a, 1), "CDRCD"), (Slot::model(&b, 0), "CD")]);
        assert_eq!(reconcile(&ok, &ha, Some(2), false), RunVerdict::Consistent);
        // One step too few or too many, a released or aborted step, a gap.
        assert!(matches!(reconcile(&ok, &ha, Some(1), false), RunVerdict::Inconsistent(_)));
        assert!(matches!(reconcile(&ok, &ha, Some(3), false), RunVerdict::Inconsistent(_)));
        for bad in ["CDR", "C", "CDRC"] {
            let x = l(&[(Slot::model(&a, 0), "CD"), (Slot::model(&a, 1), bad)]);
            assert!(matches!(reconcile(&x, &ha, Some(2), false), RunVerdict::Inconsistent(_)), "{bad}");
        }
        let gap = l(&[(Slot::model(&a, 0), "CD"), (Slot::model(&a, 2), "CD")]);
        assert!(matches!(reconcile(&gap, &ha, Some(2), false), RunVerdict::Inconsistent(_)));
        // Tool slots only where tools are notarized.
        let t = l(&[(Slot::model(&a, 0), "CD"), (Slot::tool(&a, 0), "CD")]);
        assert!(matches!(reconcile(&t, &ha, Some(1), false), RunVerdict::Inconsistent(_)));
        assert_eq!(reconcile(&t, &ha, Some(1), true), RunVerdict::Consistent);
        let t = l(&[(Slot::model(&a, 0), "CD"), (Slot::tool(&a, 0), "C")]);
        assert!(matches!(reconcile(&t, &ha, Some(1), true), RunVerdict::Inconsistent(_)));
        assert_eq!(reconcile(&l(&[]), &ha, None, false), RunVerdict::NeverStarted);
        assert_eq!(reconcile(&ok, &ha, None, false), RunVerdict::Withheld { signed: 2 });
        let ab = l(&[(Slot::model(&a, 0), "CD"), (Slot::model(&a, 1), "C")]);
        assert_eq!(
            reconcile(&ab, &ha, None, false),
            RunVerdict::Aborted { slot: Slot::model(&a, 1).to_text() }
        );
        // Other sessions' slots never count.
        assert_eq!(reconcile(&ok, &to_hex(&[3u8; 32]), None, false), RunVerdict::NeverStarted);
    }
}
