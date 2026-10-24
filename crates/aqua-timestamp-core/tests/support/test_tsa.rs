//! Offline RFC 3161 token generator for the OW1.1 tests.
//!
//! Copied from aqua-rs-sdk `crates/aqua-tsa-provider/src/test_tsa.rs` at b8859a16 (a
//! `cfg(test)`-only module there, so not reachable as a dependency). Only the imports of the
//! crate-private ESS types changed. It mints tokens only; all verification stays in the SDK
//! (`aqua_tsa_provider::TsaWebHost`).
#![allow(dead_code)]
//! Test-only RFC 3161 token generator: a one-level ECDSA P-256 test PKI (root and
//! TSA leaf) that mints validly signed `TimeStampToken`s with controlled defects,
//! so each negative test isolates exactly one check. Nothing here is compiled
//! outside `cfg(test)`; it uses only crates already in the dependency graph.

use std::time::Duration;

use aqua_qualified_pki::EuTrustListValidator;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::asn1::{BitString, OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode, Tag};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use sha2::Digest;
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages,
    SubjectKeyIdentifier,
};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate, Version};

// ESS attribute types: `pub(crate)` in aqua-tsa-provider `src/verify.rs` (SDK b8859a16,
// lines 61-127), so they are restated here verbatim for the generator.
const OID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

#[derive(Clone, Debug, der::Sequence)]
pub struct SigningCertificate {
    pub certs: Vec<EssCertId>,
    #[asn1(optional = "true")]
    pub policies: Option<der::Any>,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct EssCertId {
    pub cert_hash: der::asn1::OctetString,
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct SigningCertificateV2 {
    pub certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    pub policies: Option<der::Any>,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct EssCertIdV2 {
    #[asn1(optional = "true")]
    pub hash_algorithm: Option<spki::AlgorithmIdentifierOwned>,
    pub cert_hash: der::asn1::OctetString,
    #[asn1(optional = "true")]
    pub issuer_serial: Option<IssuerSerial>,
}

#[derive(Clone, Debug, der::Sequence)]
pub struct IssuerSerial {
    pub issuer: x509_cert::ext::pkix::name::GeneralNames,
    pub serial_number: x509_cert::serial_number::SerialNumber,
}

const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
pub const OID_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
const OID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_EKU_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// genTime of the canonical generated token: 2026-09-21T12:39:57Z.
pub const GEN_TIME: i64 = 1_789_994_397;
pub const GEN_TIME_CANONICAL: &[u8] = b"20260921123957Z";
/// The imprint the default generated token is minted over.
pub const IMPRINT: [u8; 32] = [0x5a; 32];

/// Which ESS signing-certificate attributes the token carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ess {
    /// signingCertificateV2 over the signer cert (SHA-256, default algorithm).
    V2,
    /// signingCertificateV2 whose certHash does not match the signer cert.
    V2WrongHash,
    /// signingCertificateV2 with a correct hash but an issuerSerial naming a
    /// different serial number.
    V2IssuerSerialMismatch,
    /// Both attributes, as DigiCert emits them: a valid v2 plus a v1 without
    /// issuerSerial. The v1 certHash is filler; the verifier never computes it.
    V1AndV2,
    /// A valid v2 plus a v1 whose issuerSerial names a different serial.
    V2WithV1IssuerSerialMismatch,
    /// Only the v1 signingCertificate, with the given issuerSerial shape.
    V1Only(V1IssuerSerial),
    /// Neither attribute.
    Absent,
}

/// The issuerSerial of the first ESSCertID (v1) in [`Ess::V1Only`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1IssuerSerial {
    /// Names the signer certificate (its issuer and serial).
    Correct,
    /// Absent.
    Missing,
    /// The signer's issuer with the decoy's serial number.
    WrongSerial,
    /// The signer's serial with a different issuer Name.
    WrongIssuer,
    /// The correct directoryName followed by a second GeneralName.
    ExtraGeneralName,
}

#[derive(Clone, Debug)]
pub struct TokenSpec {
    pub imprint_alg: ObjectIdentifier,
    pub imprint: Vec<u8>,
    /// Raw GeneralizedTime content octets, so non-canonical forms can be minted.
    pub gen_time: Vec<u8>,
    pub ess: Ess,
    /// Serial number the SignerIdentifier names (the leaf's by default).
    pub sid_serial: u8,
    /// Also embed a decoy certificate (same issuer, different serial and key).
    pub decoy: bool,
    /// Also embed a twin certificate: same issuer and public key as the leaf,
    /// different serial, so the SignerIdentifier still selects only the leaf.
    pub same_key_twin: bool,
    /// `TSTInfo.policy` (A39: two tokens differing only in policy).
    pub policy: ObjectIdentifier,
}

impl Default for TokenSpec {
    fn default() -> Self {
        Self {
            imprint_alg: OID_SHA256,
            imprint: IMPRINT.to_vec(),
            gen_time: GEN_TIME_CANONICAL.to_vec(),
            ess: Ess::V2,
            sid_serial: LEAF_SERIAL,
            decoy: false,
            same_key_twin: false,
            policy: TEST_POLICY,
        }
    }
}

/// The default `TSTInfo.policy` of a minted token.
pub const TEST_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

const ROOT_SERIAL: u8 = 1;
/// The decoy sorts before the leaf in the DER SET OF certificates.
const DECOY_SERIAL: u8 = 2;
const LEAF_SERIAL: u8 = 3;
/// The twin carries the leaf's public key under another serial.
const TWIN_SERIAL: u8 = 4;

pub struct TestPki {
    pub root_der: Vec<u8>,
    pub leaf: Certificate,
    pub leaf_der: Vec<u8>,
    leaf_key: SigningKey,
    pub decoy: Certificate,
    pub twin: Certificate,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32].into()).expect("valid test scalar")
}

fn spki(k: &SigningKey) -> SubjectPublicKeyInfoOwned {
    let der = k
        .verifying_key()
        .to_public_key_der()
        .expect("encode test SPKI");
    SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).expect("decode test SPKI")
}

fn key_id(k: &SigningKey) -> OctetString {
    let digest = sha2::Sha256::digest(k.verifying_key().to_sec1_point(true).as_bytes());
    OctetString::new(digest[..20].to_vec()).expect("key id")
}

fn ext<T: Encode + AssociatedOid>(critical: bool, value: &T) -> Extension {
    Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().expect("encode ext")).expect("ext value"),
    }
}

fn ecdsa_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_ECDSA_SHA256,
        parameters: None,
    }
}

fn validity() -> Validity {
    // 2020-01-01T00:00:00Z .. 2040-01-01T00:00:00Z
    let t = |secs: u64| {
        Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(secs)).expect("utc"))
    };
    Validity {
        not_before: t(1_577_836_800),
        not_after: t(2_208_988_800),
    }
}

fn sign_cert(tbs: TbsCertificate, issuer_key: &SigningKey) -> Certificate {
    let sig: Signature = issuer_key.sign(&tbs.to_der().expect("tbs der"));
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_alg(),
        signature: BitString::from_bytes(sig.to_der().as_bytes()).expect("sig bits"),
    }
}

fn tsa_leaf(serial: u8, k: &SigningKey, root_key: &SigningKey, root_name: &Name) -> Certificate {
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: ecdsa_alg(),
        issuer: root_name.clone(),
        validity: validity(),
        subject: "CN=Aqua Test TSA".parse().expect("name"),
        subject_public_key_info: spki(k),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            ext(
                false,
                &AuthorityKeyIdentifier {
                    key_identifier: Some(key_id(root_key)),
                    authority_cert_issuer: None,
                    authority_cert_serial_number: None,
                },
            ),
            ext(false, &SubjectKeyIdentifier(key_id(k))),
            ext(true, &KeyUsage(KeyUsages::DigitalSignature.into())),
            ext(true, &ExtendedKeyUsage(vec![OID_EKU_TIMESTAMPING])),
        ]),
    };
    sign_cert(tbs, root_key)
}

pub fn pki() -> TestPki {
    let root_key = key(0x11);
    let root_name: Name = "CN=Aqua Test Root".parse().expect("name");
    let root_tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[ROOT_SERIAL]).expect("serial"),
        signature: ecdsa_alg(),
        issuer: root_name.clone(),
        validity: validity(),
        subject: root_name.clone(),
        subject_public_key_info: spki(&root_key),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(vec![
            ext(
                true,
                &BasicConstraints {
                    ca: true,
                    path_len_constraint: None,
                },
            ),
            ext(true, &KeyUsage(KeyUsages::KeyCertSign.into())),
            ext(false, &SubjectKeyIdentifier(key_id(&root_key))),
        ]),
    };
    let root = sign_cert(root_tbs, &root_key);
    let leaf_key = key(0x22);
    let leaf = tsa_leaf(LEAF_SERIAL, &leaf_key, &root_key, &root_name);
    let decoy = tsa_leaf(DECOY_SERIAL, &key(0x33), &root_key, &root_name);
    let twin = tsa_leaf(TWIN_SERIAL, &leaf_key, &root_key, &root_name);
    TestPki {
        twin,
        root_der: root.to_der().expect("root der"),
        leaf_der: leaf.to_der().expect("leaf der"),
        leaf,
        leaf_key,
        decoy,
    }
}

/// A validator whose only trust anchor is the test root.
pub fn validator(pki: &TestPki) -> EuTrustListValidator {
    EuTrustListValidator::builder()
        .no_bundled_roots()
        .add_root(pki.root_der.clone(), false, "Aqua Test Root".to_string())
        .build()
}

/// DER TLV with a definite length (short or long form).
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).expect("short length"));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let n = bytes.len() - skip;
        out.push(0x80 | u8::try_from(n).expect("length of length"));
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

/// TSTInfo assembled by hand so the genTime octets are exactly `spec.gen_time`.
fn tst_info(spec: &TokenSpec) -> Vec<u8> {
    let imprint = x509_tsp::MessageImprint {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: spec.imprint_alg,
            parameters: None,
        },
        hashed_message: OctetString::new(spec.imprint.clone()).expect("imprint"),
    };
    let mut body = Vec::new();
    body.extend_from_slice(&[0x02, 0x01, 0x01]); // version v1
    body.extend(spec.policy.to_der().expect("policy"));
    body.extend(imprint.to_der().expect("imprint der"));
    body.extend_from_slice(&[0x02, 0x01, 0x2a]); // serialNumber 42
    body.extend(tlv(0x18, &spec.gen_time));
    tlv(0x30, &body)
}

fn issuer_serial(cert: &Certificate, serial: u8) -> IssuerSerial {
    IssuerSerial {
        issuer: vec![GeneralName::DirectoryName(
            cert.tbs_certificate.issuer.clone(),
        )],
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
    }
}

fn attr<T: Encode>(oid: ObjectIdentifier, value: &T) -> Attribute {
    let value = Any::from_der(&value.to_der().expect("attr value der")).expect("attr value");
    Attribute {
        oid,
        values: SetOfVec::try_from(vec![value]).expect("attr set"),
    }
}

fn ess_attrs(pki: &TestPki, ess: Ess) -> Vec<Attribute> {
    let leaf_hash = sha2::Sha256::digest(&pki.leaf_der).to_vec();
    let v2 = |hash: Vec<u8>, issuer_serial: Option<IssuerSerial>| {
        attr(
            OID_SIGNING_CERTIFICATE_V2,
            &SigningCertificateV2 {
                certs: vec![EssCertIdV2 {
                    hash_algorithm: None, // DEFAULT sha256, as DigiCert encodes it
                    cert_hash: OctetString::new(hash).expect("hash"),
                    issuer_serial,
                }],
                policies: None,
            },
        )
    };
    // The v1 certHash is 20 filler bytes: the verifier never computes it.
    let v1 = |issuer_serial: Option<IssuerSerial>| {
        attr(
            OID_SIGNING_CERTIFICATE,
            &SigningCertificate {
                certs: vec![EssCertId {
                    cert_hash: OctetString::new(vec![0xab; 20]).expect("hash"),
                    issuer_serial,
                }],
                policies: None,
            },
        )
    };
    match ess {
        Ess::V2 => vec![v2(leaf_hash, None)],
        Ess::V2WrongHash => {
            let mut wrong = leaf_hash;
            wrong[0] ^= 0x01;
            vec![v2(wrong, None)]
        }
        Ess::V2IssuerSerialMismatch => {
            vec![v2(leaf_hash, Some(issuer_serial(&pki.leaf, DECOY_SERIAL)))]
        }
        Ess::V1AndV2 => vec![v1(None), v2(leaf_hash, None)],
        Ess::V2WithV1IssuerSerialMismatch => vec![
            v1(Some(issuer_serial(&pki.leaf, DECOY_SERIAL))),
            v2(leaf_hash, None),
        ],
        Ess::V1Only(shape) => {
            let is = match shape {
                V1IssuerSerial::Correct => Some(issuer_serial(&pki.leaf, LEAF_SERIAL)),
                V1IssuerSerial::Missing => None,
                V1IssuerSerial::WrongSerial => Some(issuer_serial(&pki.leaf, DECOY_SERIAL)),
                V1IssuerSerial::WrongIssuer => Some(IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(
                        "CN=Some Other Root".parse().expect("name"),
                    )],
                    serial_number: SerialNumber::new(&[LEAF_SERIAL]).expect("serial"),
                }),
                V1IssuerSerial::ExtraGeneralName => {
                    let mut is = issuer_serial(&pki.leaf, LEAF_SERIAL);
                    is.issuer.push(GeneralName::DirectoryName(
                        pki.leaf.tbs_certificate.issuer.clone(),
                    ));
                    Some(is)
                }
            };
            vec![v1(is)]
        }
        Ess::Absent => vec![],
    }
}

/// Mint a bare `ContentInfo(SignedData)` TimeStampToken per `spec`, validly
/// signed by the test TSA leaf.
pub fn token(pki: &TestPki, spec: &TokenSpec) -> Vec<u8> {
    let tst = tst_info(spec);

    let mut attrs = vec![
        attr(OID_CONTENT_TYPE, &OID_CT_TST_INFO),
        attr(
            OID_MESSAGE_DIGEST,
            &OctetString::new(sha2::Sha256::digest(&tst).to_vec()).expect("digest"),
        ),
    ];
    attrs.extend(ess_attrs(pki, spec.ess));
    let signed_attrs = SetOfVec::try_from(attrs).expect("signed attrs");
    let sig: Signature = pki
        .leaf_key
        .sign(&signed_attrs.to_der().expect("signed attrs der"));

    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: pki.leaf.tbs_certificate.issuer.clone(),
            serial_number: SerialNumber::new(&[spec.sid_serial]).expect("serial"),
        }),
        digest_alg: AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: None,
        },
        signed_attrs: Some(signed_attrs),
        signature_algorithm: ecdsa_alg(),
        signature: OctetString::new(sig.to_der().as_bytes().to_vec()).expect("sig"),
        unsigned_attrs: None,
    };

    let mut certs = vec![CertificateChoices::Certificate(pki.leaf.clone())];
    if spec.decoy {
        certs.push(CertificateChoices::Certificate(pki.decoy.clone()));
    }
    if spec.same_key_twin {
        certs.push(CertificateChoices::Certificate(pki.twin.clone()));
    }

    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::try_from(vec![AlgorithmIdentifierOwned {
            oid: OID_SHA256,
            parameters: None,
        }])
        .expect("digest algs"),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: OID_CT_TST_INFO,
            econtent: Some(Any::new(Tag::OctetString, tst).expect("econtent")),
        },
        certificates: Some(CertificateSet(SetOfVec::try_from(certs).expect("cert set"))),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![signer_info]).expect("signer infos")),
    };

    ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).expect("signed data"),
    }
    .to_der()
    .expect("content info")
}

/// Wrap a token in a `TimeStampResp` with the given PKIStatus.
pub fn time_stamp_resp(status: u8, token: &[u8]) -> Vec<u8> {
    let status_info = tlv(0x30, &[0x02, 0x01, status]);
    let mut body = status_info;
    body.extend_from_slice(token);
    tlv(0x30, &body)
}
