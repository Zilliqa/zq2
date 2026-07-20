//! Signature-verification tests for legacy Zilliqa (Scilla) transactions.
//!
//! Unlike Ethereum transactions, where the signer is *recovered* from the
//! signature, a [`SignedTransaction::Zilliqa`] carries the sender's public key
//! explicitly and the signer address is *derived* from that key:
//!
//! ```text
//! signer = SHA256(compressed_public_key)[12..32]
//! ```
//!
//! This means the public key (and therefore the signer address) is entirely
//! attacker-chosen data. The only thing that binds that key — and every other
//! field of the transaction — to a real private-key holder is the Schnorr
//! signature, which is computed over a protobuf encoding that *includes the
//! public key itself* (see `encode_zilliqa_transaction`).
//!
//! These tests assert that:
//!   * a correctly signed transaction recovers the expected signer (`verify`),
//!   * any tampering — with the signature, with a signed field, or an attempt
//!     to graft a victim's public key onto an attacker-signed transaction — is
//!     rejected by `verify` (the `!force` path),
//!   * `verify_bypass` (the `force` path) deliberately skips the signature
//!     check and therefore must only ever be fed already-trusted data.
//!
//! Together these guarantee there is no way to impersonate another account
//! that holds funds on chain through the normal (`verify`) path.

use alloy::primitives::{Address, U256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use prost::Message;
use sha2::{Digest, Sha256};
use zilliqa::{
    crypto::Hash,
    schnorr::{self, PublicKey, SecretKey},
    transaction::{ScillaGas, SignedTransaction, TxZilliqa, ZilAmount},
    zq1_proto::{Code, Data, Nonce, ProtoTransactionCoreInfo},
};

use crate::Network;

/// Chain id used for the fake transactions (the Scilla-side id, i.e. the eth
/// chain id minus `0x8000`).
const CHAIN_ID: u16 = 1;

/// Build a deterministic secret key from a single seed byte. Any value in
/// `1..=254` is a valid, in-range secp256k1 scalar, so these never fail.
fn secret_key(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).expect("seed is a valid scalar")
}

/// Derive the Zilliqa signer address from a public key, exactly as
/// `SignedTransaction::verify_inner` does internally.
fn address_of(public_key: &PublicKey) -> Address {
    let hashed = Sha256::digest(public_key.to_encoded_point(true).as_bytes());
    Address::from_slice(&hashed[12..])
}

/// A plain, well-formed sample transaction. `to_addr` intentionally points at a
/// different account so this looks like a normal value transfer.
fn sample_tx() -> TxZilliqa {
    TxZilliqa {
        chain_id: CHAIN_ID,
        nonce: 1,
        gas_price: ZilAmount::from_raw(1_000_000_000),
        gas_limit: ScillaGas(50),
        to_addr: Address::repeat_byte(0xAB),
        amount: ZilAmount::from_raw(500),
        code: String::new(),
        data: String::new(),
    }
}

/// Re-implementation of the crate-private `encode_zilliqa_transaction`, kept
/// byte-for-byte identical so that signatures we produce here validate against
/// the real verification code. If the production encoding ever changes, these
/// tests will start failing on the "valid signature" cases — which is the
/// intended early-warning behaviour.
fn encode_for_signing(tx: &TxZilliqa, public_key: &PublicKey) -> Vec<u8> {
    let oneof8 = (!tx.code.is_empty()).then(|| Code::Code(tx.code.clone().into_bytes()));
    let oneof9 = (!tx.data.is_empty()).then(|| Data::Data(tx.data.clone().into_bytes()));
    let proto = ProtoTransactionCoreInfo {
        version: ((tx.chain_id as u32) << 16) | 0x0001,
        toaddr: tx.to_addr.as_slice().to_vec(),
        senderpubkey: Some(public_key.to_sec1_bytes().into()),
        amount: Some(tx.amount.to_be_bytes().to_vec().into()),
        gasprice: Some(tx.gas_price.to_be_bytes().to_vec().into()),
        gaslimit: tx.gas_limit.0,
        oneof2: Some(Nonce::Nonce(tx.nonce)),
        oneof8,
        oneof9,
    };
    proto.encode_to_vec()
}

/// Sign `tx` with `key` and wrap it into a `SignedTransaction::Zilliqa`.
fn sign(tx: TxZilliqa, key: &SecretKey) -> SignedTransaction {
    let public_key = key.public_key();
    let sig = schnorr::sign(&encode_for_signing(&tx, &public_key), key);
    SignedTransaction::Zilliqa {
        tx,
        key: public_key,
        sig,
    }
}

/// A correctly signed transaction verifies, and the recovered signer is exactly
/// the address derived from the signer's public key.
#[test]
fn valid_signature_recovers_expected_signer() {
    let key = secret_key(0x11);
    let expected_signer = address_of(&key.public_key());

    let signed = sign(sample_tx(), &key);
    let verified = signed.verify().expect("valid signature must verify");

    assert_eq!(
        verified.signer, expected_signer,
        "recovered signer must match SHA256(pubkey)[12..]",
    );
    // The hash is derived from the transaction contents and must be non-zero.
    assert_ne!(verified.hash, Hash::ZERO);
}

/// Flipping the signature (here: a well-formed signature produced over
/// unrelated bytes) must be rejected by the `!force` path.
#[test]
fn tampered_signature_is_rejected() {
    let key = secret_key(0x11);
    let tx = sample_tx();
    let public_key = key.public_key();

    // A perfectly valid signature — but over different bytes, so it does not
    // authenticate this transaction.
    let wrong_sig = schnorr::sign(b"a completely different message", &key);
    let forged = SignedTransaction::Zilliqa {
        tx,
        key: public_key,
        sig: wrong_sig,
    };

    let err = forged.verify().expect_err("bad signature must be rejected");
    assert!(
        err.to_string().contains("invalid signature"),
        "unexpected error: {err}",
    );
}

/// Mutating a signed field after signing (the classic "change the amount /
/// recipient" attack) invalidates the signature, because the signed protobuf
/// encoding no longer matches the transaction being verified.
#[test]
fn tampering_with_signed_fields_is_rejected() {
    let key = secret_key(0x11);
    let public_key = key.public_key();

    // Sign the honest transaction...
    let honest = sample_tx();
    let sig = schnorr::sign(&encode_for_signing(&honest, &public_key), &key);

    // ...then splice that signature onto a transaction that pays the attacker
    // more and redirects the funds.
    let mut tampered = honest;
    tampered.amount = ZilAmount::from_raw(1_000_000_000);
    tampered.to_addr = Address::repeat_byte(0xEE);

    let forged = SignedTransaction::Zilliqa {
        tx: tampered,
        key: public_key,
        sig,
    };

    assert!(
        forged.verify().is_err(),
        "mutating a signed field must invalidate the signature",
    );
}

/// The core impersonation test.
///
/// An attacker wants to spend the victim's funds. They know the victim's
/// address, and therefore (or by observing any past transaction) the victim's
/// public key. They construct a transaction embedding the *victim's* public key
/// — which makes the derived signer the victim's address — but they can only
/// sign it with their *own* key, because they do not hold the victim's private
/// key. `verify` must reject this.
#[test]
fn cannot_impersonate_another_account() {
    let victim = secret_key(0x11);
    let attacker = secret_key(0x22);

    let victim_pubkey = victim.public_key();
    let victim_addr = address_of(&victim_pubkey);
    let attacker_addr = address_of(&attacker.public_key());
    assert_ne!(victim_addr, attacker_addr);

    // The attacker embeds the victim's public key so that the *derived* signer
    // would be the victim...
    let tx = sample_tx();
    // ...but signs with the attacker's key over that same (victim-keyed) payload.
    let attacker_sig = schnorr::sign(&encode_for_signing(&tx, &victim_pubkey), &attacker);

    let forged = SignedTransaction::Zilliqa {
        tx,
        key: victim_pubkey,
        sig: attacker_sig,
    };

    // Sanity check: the *only* defence here is the signature. If it were
    // skipped, this transaction would be attributed to the victim.
    assert_eq!(address_of(&victim_pubkey), victim_addr);

    let err = forged
        .verify()
        .expect_err("impersonation attempt must be rejected");
    assert!(
        err.to_string().contains("invalid signature"),
        "unexpected error: {err}",
    );
}

/// A well-formed but wrong-length / structurally different key cannot even be
/// smuggled in: the enum stores a real `PublicKey`, so the attacker is limited
/// to keys they can actually present. This test documents that swapping the key
/// to the attacker's own (so the signature *is* valid) correctly attributes the
/// transaction to the attacker — never to the victim.
#[test]
fn valid_signature_is_attributed_to_the_signing_key_only() {
    let attacker = secret_key(0x22);
    let attacker_addr = address_of(&attacker.public_key());

    // Attacker signs honestly with their own key. This verifies fine, but is
    // attributed to the attacker — they cannot make it appear to come from
    // anyone else while keeping a valid signature.
    let signed = sign(sample_tx(), &attacker);
    let verified = signed.verify().expect("attacker's own tx verifies");

    assert_eq!(verified.signer, attacker_addr);
}

/// `verify_bypass` (the `force` path) intentionally skips signature
/// verification: it is used when replaying transactions whose validity has
/// already been established (e.g. from a checkpoint or an already-validated
/// block). This test pins that behaviour: an *invalid* signature that `verify`
/// rejects is accepted by `verify_bypass`, and the signer is still derived from
/// the embedded key.
///
/// The security consequence — deliberately asserted here so it cannot be
/// forgotten — is that `verify_bypass` MUST NOT be fed untrusted input: doing so
/// would allow exactly the impersonation that `verify` prevents.
#[test]
fn force_bypass_skips_signature_check_and_must_only_see_trusted_data() {
    let victim = secret_key(0x11);
    let attacker = secret_key(0x22);
    let victim_pubkey = victim.public_key();
    let victim_addr = address_of(&victim_pubkey);

    let tx = sample_tx();
    // An invalid signature (attacker-signed over a victim-keyed payload).
    let bogus_sig = schnorr::sign(&encode_for_signing(&tx, &victim_pubkey), &attacker);
    let forged = SignedTransaction::Zilliqa {
        tx,
        key: victim_pubkey,
        sig: bogus_sig,
    };

    // The honest (`!force`) path rejects it...
    assert!(
        forged.clone().verify().is_err(),
        "verify must reject the bogus signature",
    );

    // ...but the trusted (`force`) path accepts it and attributes it to the
    // account owning the embedded key. `verify_bypass` also trusts the supplied
    // hash verbatim, so we can pass any placeholder here.
    let trusted_hash = Hash::builder().with(b"trusted").finalize();
    let verified = forged
        .verify_bypass(trusted_hash)
        .expect("force path skips signature verification");

    assert_eq!(
        verified.signer, victim_addr,
        "force path still derives the signer from the embedded key",
    );
    assert_eq!(
        verified.hash, trusted_hash,
        "force path uses the caller-supplied hash verbatim",
    );
}

/// Belt-and-braces: an EVM (Ethereum) transaction's signer really is recovered
/// from the signature, so a mismatched signature yields a *different* signer
/// rather than an error — but it can never yield an address the attacker did not
/// sign for. This guards the other transaction family against impersonation.
#[test]
fn evm_signer_is_bound_to_the_signature() {
    use alloy::{
        consensus::{SignableTransaction, TxLegacy},
        primitives::TxKind,
        signers::{SignerSync, local::PrivateKeySigner},
    };

    let signer = PrivateKeySigner::from_slice(&[0x11; 32]).unwrap();
    let expected = signer.address();

    let tx = TxLegacy {
        chain_id: Some(0x8001),
        nonce: 0,
        gas_price: 1,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0xAB)),
        value: U256::from(1u64),
        input: Default::default(),
    };
    let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = SignedTransaction::Legacy { tx, sig };

    let verified = signed.verify().expect("valid EVM signature verifies");
    assert_eq!(
        verified.signer, expected,
        "EVM signer must be the key that produced the signature",
    );
}

// ---------------------------------------------------------------------------
// Defence-in-depth regression tests
//
// The tests below lock in three properties an attacker would otherwise use to
// impersonate an account and drain funds, and which live *outside* the
// signature primitive itself:
//   1. the sync path only skips signature verification for legacy (pre-ZQ2)
//      blocks, never for current ones,
//   2. an unsigned `Intershard` transaction cannot be injected via the mempool,
//   3. "blessed" transactions do not get a signature-verification exemption.
// ---------------------------------------------------------------------------

/// `verify_in_synced_block` is the sync-path admission gate. It must verify
/// signatures normally for current (ZQ2) blocks, reject an unverifiable
/// transaction in a ZQ2 block, and fall back to the signature-skipping bypass
/// ONLY for pre-ZQ2 historical blocks (below the floor height).
///
/// This is what stops the legacy "ZQ1 bypass" from ever widening to current
/// blocks and letting an unsigned transaction spend from an arbitrary account.
#[test]
fn synced_block_verification_gates_the_zq1_bypass() {
    const FLOOR: u64 = 1000; // the first ZQ2 block height in this test

    // A genuinely signed transaction verifies in a current (ZQ2) block.
    let key = secret_key(0x11);
    let good = sign(sample_tx(), &key);
    let good_hash = good.calculate_hash();
    let verified = good
        .verify_in_synced_block(good_hash, FLOOR + 5, FLOOR)
        .expect("a validly signed tx verifies in a ZQ2 block");
    assert_eq!(verified.signer, address_of(&key.public_key()));

    // Forge an impersonating tx: the victim's key is embedded (so the derived
    // signer is the victim) but it is signed with the attacker's key.
    let victim = secret_key(0x11);
    let attacker = secret_key(0x22);
    let victim_pubkey = victim.public_key();
    let victim_addr = address_of(&victim_pubkey);
    let tx = sample_tx();
    let bogus_sig = schnorr::sign(&encode_for_signing(&tx, &victim_pubkey), &attacker);
    let forged = SignedTransaction::Zilliqa {
        tx,
        key: victim_pubkey,
        sig: bogus_sig,
    };
    let forged_hash = forged.calculate_hash();

    // In a current (ZQ2) block — at or above the floor — it is rejected.
    assert!(
        forged
            .clone()
            .verify_in_synced_block(forged_hash, FLOOR, FLOOR)
            .is_err(),
        "an unverifiable tx must be rejected in a ZQ2 block",
    );

    // Strictly below the floor (legacy ZQ1 history) the bypass applies and the
    // tx is admitted, attributed to the embedded key. This is the intended,
    // height-gated exception — and precisely why the height check must stay.
    let bypassed = forged
        .verify_in_synced_block(forged_hash, FLOOR - 1, FLOOR)
        .expect("pre-ZQ2 blocks fall back to the bypass");
    assert_eq!(bypassed.signer, victim_addr);
}

/// An `Intershard` transaction carries no signature — its `from` is trusted —
/// so it must never be admitted from the untrusted broadcast/mempool path.
/// `Consensus::handle_new_transactions` drops "foreign" Intershard transactions;
/// this asserts a spoofed one (claiming to originate from a victim) is discarded
/// rather than entering the mempool.
#[zilliqa_macros::test]
async fn foreign_intershard_transaction_is_dropped(network: Network) {
    use zilliqa::transaction::{EvmGas, TxIntershard};

    let victim = address_of(&secret_key(0x11).public_key());

    // Forge an Intershard tx that claims to originate from the victim.
    let forged = SignedTransaction::Intershard {
        tx: TxIntershard {
            chain_id: 700,
            bridge_nonce: 0,
            source_chain: 1,
            gas_price: 0,
            gas_limit: EvmGas(50_000),
            to_addr: Some(Address::repeat_byte(0xCC)),
            payload: vec![],
        },
        from: victim,
    }
    .verify()
    .expect("intershard verify() trusts `from` by construction");
    assert_eq!(forged.signer, victim, "sanity: derived signer is the victim");

    // Feed it through the exact entry point the mempool/broadcast path uses.
    let admitted = network
        .get_node(0)
        .consensus
        .write()
        .handle_new_transactions(vec![forged], true)
        .expect("handle_new_transactions should not error");

    assert!(
        admitted.is_empty(),
        "a foreign Intershard transaction must be dropped, not admitted: {admitted:?}",
    );
}

/// "Blessed" transactions bypass gas-price/nonce checks in `validate()` and
/// during execution — but NOT the signature check in `verify()`. Blessed status
/// is keyed by the whole-transaction hash, which commits to the signature, so:
///   * every hardcoded blessed entry is a genuine, validly signed transaction
///     whose recovered signer matches the recorded sender, and
///   * tampering with the signature changes the hash (losing blessed status)
///     and recovers a different signer.
/// There is therefore no way to inherit blessed treatment for a forged or
/// impersonating transaction.
#[test]
fn blessed_status_is_bound_to_a_genuine_signature() {
    use alloy::{
        consensus::{SignableTransaction, TxEnvelope},
        eips::eip2718::Decodable2718,
        signers::{SignerSync, local::PrivateKeySigner},
    };
    use zilliqa::exec::BLESSED_TRANSACTIONS;

    for blessed in BLESSED_TRANSACTIONS.iter() {
        // The raw payload is the RLP-encoded, signed legacy transaction.
        let envelope = TxEnvelope::decode_2718(&mut blessed.payload.as_ref())
            .expect("blessed payload decodes as a signed transaction");
        let TxEnvelope::Legacy(signed) = envelope else {
            panic!("blessed transactions are expected to be legacy transactions");
        };
        let genuine = SignedTransaction::Legacy {
            tx: signed.tx().clone(),
            sig: *signed.signature(),
        };

        // The genuine transaction has the recorded hash and recovers to the
        // recorded sender.
        assert_eq!(
            genuine.calculate_hash(),
            blessed.hash,
            "blessed hash must match the genuine transaction",
        );
        let verified = genuine
            .clone()
            .verify()
            .expect("the genuine blessed transaction has a valid signature");
        assert_eq!(
            verified.signer, blessed.sender,
            "blessed sender must be the signer of the genuine transaction",
        );

        // Re-sign the same transaction body with a different key. This is a
        // well-formed signature, but a *different* transaction: its hash is no
        // longer blessed and it recovers a different signer — so it can never be
        // attributed to the blessed sender while being treated as blessed.
        let attacker = PrivateKeySigner::from_slice(&[0x22; 32]).unwrap();
        let forged_sig = attacker
            .sign_hash_sync(&signed.tx().signature_hash())
            .unwrap();
        let forged = SignedTransaction::Legacy {
            tx: signed.tx().clone(),
            sig: forged_sig,
        };

        assert_ne!(
            forged.calculate_hash(),
            blessed.hash,
            "a re-signed transaction must not keep the blessed hash",
        );
        assert!(
            !BLESSED_TRANSACTIONS
                .iter()
                .any(|b| b.hash == forged.calculate_hash()),
            "a forged transaction must not appear in the blessed set",
        );
        let forged_signer = forged
            .verify()
            .expect("a well-formed signature recovers some signer")
            .signer;
        assert_ne!(
            forged_signer, blessed.sender,
            "a forgery must not recover the blessed sender",
        );
    }
}
