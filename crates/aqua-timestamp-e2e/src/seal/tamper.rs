//! The byte flips of the tamper step. Client side only: this module changes bytes and asks the
//! SDK for the links of what it changed; judging the result is the SDK reader's job.

use anyhow::{anyhow, bail, Context, Result};
use aqua_rs_sdk::primitives::{HashType, Method, RevisionLink};
use aqua_rs_sdk::schema::link::Anchor;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::AnyRevision;
use aqua_rs_sdk::verification::Linkable;
use base64::Engine as _;
use serde_json::{json, Value};

/// A revision's link, from the SDK.
pub fn link_of(r: &AnyRevision) -> Result<RevisionLink> {
    r.global_calculate_hash(HashType::Sha3_256)
        .map_err(|e| anyhow!("SDK link: {e:?}"))
}

/// The qTSA T with the last byte of its TimeStampResp flipped (`transaction_hash`, base64): the
/// last byte is inside the SignerInfo signature value, the last field of SignedData. Returns the
/// altered revision and a note for the log.
pub fn flip_tsa_token(t: &AnyRevision) -> Result<(AnyRevision, String)> {
    let mut v = serde_json::to_value(t)?;
    let b64 = v["payloads"]["transaction_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("qTSA T has no transaction_hash"))?
        .to_string();
    let eng = base64::engine::general_purpose::STANDARD;
    let mut der = eng.decode(&b64).context("base64 TimeStampResp")?;
    if der.is_empty() {
        bail!("transaction_hash decodes to nothing; flip not applied");
    }
    if eng.encode(&der) != b64 {
        bail!("transaction_hash is not canonical standard base64; flip not applied");
    }
    let last = der.len() - 1;
    let old = der[last];
    der[last] ^= 0x01;
    let note = format!(
        "TimeStampResp {} bytes, last byte {:#04x} -> {:#04x}",
        der.len(),
        old,
        der[last]
    );
    v["payloads"]["transaction_hash"] = json!(eng.encode(&der));
    Ok((serde_json::from_value(v)?, note))
}

/// A container whose qTSA T was flipped and relinked: T' replaces T, A' links T' and replaces A.
#[derive(Debug)]
pub struct RelinkedContainer {
    pub container: Tree,
    pub flipped: AnyRevision,
    pub flipped_link: RevisionLink,
    pub anchor_link: RevisionLink,
    /// A's structural links, sorted, as A' carries them.
    pub links: Vec<RevisionLink>,
    pub note: String,
}

/// The relinked qTSA tamper. `anchor` and `head` name A and H as the SDK read them (the seal's
/// genesis is an anchor revision too, so they are not searched for here); a revision under
/// `anchor` that does not follow `head` is an error, never a guess.
pub fn relink_flipped_token(
    container: &Tree,
    anchor: &RevisionLink,
    head: &RevisionLink,
    t_tsa: &RevisionLink,
    t_evm: &RevisionLink,
) -> Result<RelinkedContainer> {
    let a_rev = container
        .revisions
        .get(anchor)
        .ok_or_else(|| anyhow!("A {anchor} is not in the container"))?;
    if !matches!(a_rev, AnyRevision::Anchor(_)) {
        bail!("{anchor} is not an anchor revision");
    }
    if a_rev.get_previous_revision_hash().as_ref() != Some(head) {
        bail!("{anchor} does not follow the head {head}: it is not the seal's A");
    }
    let a_json = serde_json::to_value(a_rev)?;
    let method: Method =
        serde_json::from_value(a_json["method"].clone()).context("A has no method")?;
    let t = container
        .revisions
        .get(t_tsa)
        .ok_or_else(|| anyhow!("qTSA T {t_tsa} is not in the container"))?;
    let (flipped, note) = flip_tsa_token(t)?;
    let flipped_link = link_of(&flipped)?;
    let mut links = vec![t_evm.clone(), flipped_link.clone()];
    links.sort();
    let mut relinked = Anchor::new(head.clone(), method, links.clone());
    let anchor_link = relinked
        .calculate_link(HashType::Sha3_256)
        .map_err(|e| anyhow!("{e:?}"))?;
    relinked
        .populate_leaves(HashType::Sha3_256)
        .map_err(|e| anyhow!("{e:?}"))?;
    let mut out = container.clone();
    out.revisions.remove(t_tsa);
    out.revisions.remove(anchor);
    out.revisions.insert(flipped_link.clone(), flipped.clone());
    out.revisions
        .insert(anchor_link.clone(), AnyRevision::Anchor(relinked));
    Ok(RelinkedContainer {
        container: out,
        flipped,
        flipped_link,
        anchor_link,
        links,
        note,
    })
}

fn p_of<'a>(doc: &'a Value, p_key: &str) -> Result<&'a Value> {
    doc["revisions"]
        .get(p_key)
        .ok_or_else(|| anyhow!("P {p_key} is not in the attestation document"))
}

/// The document without P.
pub fn remove_p(doc: &Value, p_key: &str) -> Result<Value> {
    p_of(doc, p_key)?;
    let mut out = doc.clone();
    out["revisions"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("document has no revisions object"))?
        .remove(p_key);
    Ok(out)
}

/// P as JSON with the lowest bit of its signature's first byte flipped; the note names the
/// first bytes of the old and the new signature.
fn alter_signature(p: &Value) -> Result<(Value, String)> {
    let sig = p["signature"]["signature"]
        .as_str()
        .ok_or_else(|| anyhow!("P has no signature hex"))?;
    let first = sig
        .strip_prefix("0x")
        .and_then(|h| h.get(..2))
        .ok_or_else(|| anyhow!("P's signature is not 0x-prefixed hex"))?;
    let byte = u8::from_str_radix(first, 16)? ^ 0x01;
    let new_sig = format!("0x{byte:02x}{}", &sig[4..]);
    let note = format!(
        "signature {}.. -> {}..",
        sig.get(..10).unwrap_or(sig),
        new_sig.get(..10).unwrap_or(&new_sig)
    );
    let mut out = p.clone();
    out["signature"]["signature"] = json!(new_sig);
    Ok((out, note))
}

/// The document with P's signature altered and P's key kept: the SDK stops at addressing
/// (`not_addressed`) and never runs the signature check.
pub fn alter_p_key_kept(doc: &Value, p_key: &str) -> Result<(Value, String)> {
    let (p, note) = alter_signature(p_of(doc, p_key)?)?;
    let mut out = doc.clone();
    out["revisions"][p_key] = p;
    Ok((out, note))
}

/// A P whose signature is altered and which is re-keyed under the link the SDK computes for the
/// altered revision. It is addressed, so the SDK reader goes on to the signature check itself.
#[derive(Debug)]
pub struct RekeyedP {
    /// The document with the old P replaced by the re-keyed one.
    pub doc: Value,
    /// The re-keyed P's new key.
    pub key: RevisionLink,
    pub note: String,
}

/// See [`RekeyedP`].
pub fn rekey_bad_signature(doc: &Value, p_key: &str) -> Result<RekeyedP> {
    let (p, note) = alter_signature(p_of(doc, p_key)?)?;
    let revision: AnyRevision =
        serde_json::from_value(p.clone()).context("altered P is no revision")?;
    let key = link_of(&revision)?;
    let mut out = remove_p(doc, p_key)?;
    out["revisions"][key.to_string()] = p;
    Ok(RekeyedP {
        doc: out,
        key,
        note,
    })
}

/// The document holding only `p_key`'s revision: the whole reading can then be searched for a
/// DID, which the other P's verified attester would otherwise put there.
pub fn only_p(doc: &Value, p_key: &str) -> Result<Value> {
    let p = p_of(doc, p_key)?.clone();
    let mut out = doc.clone();
    out["revisions"] = json!({ p_key: p });
    Ok(out)
}
