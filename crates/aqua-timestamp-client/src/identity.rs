//! Server identity discovery and signature verification.
//!
//! Fetches `/.well-known/aqua-identity`, parses the response, verifies the
//! embedded `service_claim_server` Aqua-tree signs correctly under its
//! advertised DID, and (on subsequent connections) applies the caller's
//! rotation policy.

use aqua_rs_sdk::core::signature::verify_signature_sync;
use aqua_rs_sdk::schema::AnyRevision;
use serde::Deserialize;
use tracing::warn;

use crate::error::ClientError;
use crate::trust::{OnRotation, RotationDecision, ServerRotation};
use crate::types::ServerIdentity;

/// Shape of the well-known response. We accept only the fields we need;
/// extra fields are ignored to keep us forward-compatible.
#[derive(Debug, Deserialize)]
struct IdentityWire {
    server_did: String,
    #[serde(default)]
    ethereum_address: Option<String>,
    identity_claim: serde_json::Value,
}

/// Fetch and validate the server identity. Returns the resolved identity
/// together with any rotation that was accepted (caller observable via
/// `client.rotation_detected()`).
pub(crate) async fn discover(
    http: &reqwest::Client,
    base_url: &url::Url,
    prior: Option<&(String, OnRotation)>,
) -> Result<(ServerIdentity, Option<ServerRotation>), ClientError> {
    let url = base_url
        .join("/.well-known/aqua-identity")
        .map_err(ClientError::Url)?;

    let resp = http
        .get(url.as_str())
        .send()
        .await
        .map_err(|e| ClientError::IdentityDiscovery {
            base_url: base_url.as_str().to_string(),
            source: Box::new(e),
        })?;

    let status = resp.status();
    let body_text = resp
        .text()
        .await
        .map_err(|e| ClientError::IdentityDiscovery {
            base_url: base_url.as_str().to_string(),
            source: Box::new(e),
        })?;

    if !status.is_success() {
        return Err(ClientError::IdentityDiscovery {
            base_url: base_url.as_str().to_string(),
            source: format!("HTTP {status}: {body_text}").into(),
        });
    }

    let value: serde_json::Value =
        serde_json::from_str(&body_text).map_err(|e| ClientError::IdentityDiscovery {
            base_url: base_url.as_str().to_string(),
            source: Box::new(e),
        })?;

    let parsed: IdentityWire = serde_json::from_value(value.clone()).map_err(|e| {
        ClientError::IdentityDiscovery {
            base_url: base_url.as_str().to_string(),
            source: Box::new(e),
        }
    })?;

    verify_identity_claim(&parsed)?;

    let address = parsed
        .ethereum_address
        .clone()
        .unwrap_or_else(|| address_from_did(&parsed.server_did).unwrap_or_default());

    let identity = ServerIdentity {
        did: parsed.server_did.clone(),
        address,
        identity_response_json: value.clone(),
    };

    let rotation = apply_rotation_policy(&identity, prior)?;
    Ok((identity, rotation))
}

/// Validate the identity_claim tree internally. We walk its revisions,
/// find the signature, and verify it recovers to the advertised DID.
fn verify_identity_claim(parsed: &IdentityWire) -> Result<(), ClientError> {
    let tree = parsed.identity_claim.as_object().ok_or_else(|| {
        ClientError::IdentityDiscovery {
            base_url: String::new(),
            source: "identity_claim is not a JSON object".into(),
        }
    })?;

    let revisions = tree
        .get("revisions")
        .and_then(|v| v.as_object())
        .ok_or_else(|| ClientError::IdentityDiscovery {
            base_url: String::new(),
            source: "identity_claim has no `revisions` object".into(),
        })?;

    let mut signature_seen = false;
    let mut signature_verified = false;

    for (hash_str, rev_value) in revisions {
        let revision: AnyRevision = serde_json::from_value(rev_value.clone()).map_err(|e| {
            ClientError::IdentityDiscovery {
                base_url: String::new(),
                source: format!("revision {hash_str} did not parse as AnyRevision: {e}").into(),
            }
        })?;
        if let AnyRevision::Signature(sig) = &revision {
            signature_seen = true;
            if sig.signer() != parsed.server_did {
                return Err(ClientError::IdentityDiscovery {
                    base_url: String::new(),
                    source: format!(
                        "signature revision signer {} does not match advertised server_did {}",
                        sig.signer(),
                        parsed.server_did
                    )
                    .into(),
                });
            }
            let (ok, _logs) = verify_signature_sync(&revision, hash_str, None);
            if !ok {
                return Err(ClientError::IdentityDiscovery {
                    base_url: String::new(),
                    source: "identity_claim signature failed verification".into(),
                });
            }
            signature_verified = true;
        }
    }

    if !signature_seen {
        return Err(ClientError::IdentityDiscovery {
            base_url: String::new(),
            source: "identity_claim has no Signature revision".into(),
        });
    }
    if !signature_verified {
        // Should be unreachable, but explicit: belt-and-braces.
        return Err(ClientError::IdentityDiscovery {
            base_url: String::new(),
            source: "identity_claim signature was not verified".into(),
        });
    }
    Ok(())
}

fn apply_rotation_policy(
    identity: &ServerIdentity,
    prior: Option<&(String, OnRotation)>,
) -> Result<Option<ServerRotation>, ClientError> {
    let (prior_did, policy) = match prior {
        Some(p) => p,
        None => return Ok(None),
    };
    if prior_did == &identity.did {
        return Ok(None);
    }
    let rotation = ServerRotation {
        prior_did: prior_did.clone(),
        discovered_did: identity.did.clone(),
        discovered_identity_response: identity.identity_response_json.clone(),
    };
    match policy {
        OnRotation::Refuse => Err(ClientError::ServerIdentityRotated {
            prior: rotation.prior_did,
            discovered: rotation.discovered_did,
        }),
        OnRotation::Warn => {
            warn!(
                prior = %rotation.prior_did,
                discovered = %rotation.discovered_did,
                "aqua-timestamp server DID rotated"
            );
            Ok(Some(rotation))
        }
        OnRotation::Custom(cb) => match cb(&rotation) {
            RotationDecision::Accept => Ok(Some(rotation)),
            RotationDecision::Reject => Err(ClientError::ServerIdentityRotated {
                prior: rotation.prior_did,
                discovered: rotation.discovered_did,
            }),
        },
    }
}

/// Best-effort extraction of an EIP-55 address from a `did:pkh:eip155:1:0x...`
/// DID. Returns `None` for non-pkh-eip155 DIDs; the caller falls back to the
/// explicit `ethereum_address` field if the server provides one.
fn address_from_did(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:pkh:eip155:")?;
    let (_chain, addr) = rest.split_once(':')?;
    if addr.len() == 42 && addr.starts_with("0x") {
        Some(addr.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_eip155_address() {
        let did = "did:pkh:eip155:1:0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f";
        assert_eq!(
            address_from_did(did).as_deref(),
            Some("0x55Fcf9F8C1287cB462aa3c1C97E2298d221c634f")
        );
    }

    #[test]
    fn rejects_non_pkh() {
        assert!(address_from_did("did:key:zABC").is_none());
    }

    #[test]
    fn rejects_non_eip155() {
        assert!(address_from_did("did:pkh:ed25519:0xabcd").is_none());
    }
}
