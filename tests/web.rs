//! Test suite for the WebAssembly interface of libsignal-wasm.
//!
//! Run with:
//! wasm-pack test --headless --chrome
//! or
//! wasm-pack test --headless --firefox

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use signal_wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn create_test_identity() -> (WasmIdentityKeyPair, u32) {
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key.get_public_key().unwrap();
    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    let registration_id = generate_registration_id();
    (identity_key_pair, registration_id)
}

/// Mint a caller-supplied distribution id (UUID string), as the TS domain does.
fn mint_distribution_id() -> String {
    uuid_to_string(&generate_uuid()).expect("Failed to mint distribution id")
}

/// Read the stable `code` property attached to a thrown JS error.
fn js_error_code(err: &JsValue) -> String {
    js_sys::Reflect::get(err, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

/// Read the `message` property of a thrown JS error.
fn js_error_message(err: &JsValue) -> String {
    js_sys::Reflect::get(err, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

#[wasm_bindgen_test]
async fn test_identity_key_generation() {
    init();
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key.get_public_key().expect("Failed to derive public key");

    assert!(!public_key.serialize().is_empty());

    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    assert_eq!(identity_key_pair.public_key().serialize(), public_key.serialize());
    assert_eq!(identity_key_pair.private_key().serialize(), private_key.serialize());

    // Round-trip serialization
    let serialized = identity_key_pair.serialize();
    let restored = WasmIdentityKeyPair::deserialize(&serialized).expect("Deserialization failed");
    assert_eq!(restored.public_key().serialize(), public_key.serialize());
    assert_eq!(restored.private_key().serialize(), private_key.serialize());
}

#[wasm_bindgen_test]
async fn test_protocol_address() {
    let addr = WasmProtocolAddress::new("alice_firebase_uid".to_string(), 1).unwrap();
    assert_eq!(addr.name(), "alice_firebase_uid");
    assert_eq!(addr.device_id(), 1);
}

#[wasm_bindgen_test]
async fn test_pinned_remote_identity_never_silently_replaces_a_key() {
    let (local_identity, local_registration_id) = create_test_identity();
    let mut store = WasmInMemIdentityKeyStore::new(&local_identity, local_registration_id);
    let address = WasmProtocolAddress::new(
        "00000000-0000-0000-0000-00000000000B".to_string(),
        1,
    )
    .unwrap();
    let (remote_identity, _) = create_test_identity();
    let remote_bytes = remote_identity.public_key().serialize();

    assert!(store
        .pin_remote_identity(&address, &remote_bytes)
        .await
        .expect("first pin must succeed"));
    assert!(!store
        .pin_remote_identity(&address, &remote_bytes)
        .await
        .expect("identical pin must be idempotent"));
    assert_eq!(
        store
            .pinned_remote_identity(&address)
            .await
            .expect("pinned identity lookup must succeed"),
        Some(remote_bytes.clone())
    );
    store
        .assert_pinned_remote_identity(&address, &remote_bytes)
        .await
        .expect("matching pin must be accepted");

    let (replacement_identity, _) = create_test_identity();
    let replacement_bytes = replacement_identity.public_key().serialize();
    let replace_error = store
        .pin_remote_identity(&address, &replacement_bytes)
        .await
        .expect_err("a pin replacement must be rejected");
    assert_eq!(js_error_code(&replace_error), "PinnedIdentityMismatch");
    let assert_error = store
        .assert_pinned_remote_identity(&address, &replacement_bytes)
        .await
        .expect_err("a non-matching pin must be rejected");
    assert_eq!(js_error_code(&assert_error), "PinnedIdentityMismatch");
}

#[wasm_bindgen_test]
async fn test_pre_key_generation() {
    let (_identity_key_pair, _registration_id) = create_test_identity();
    let mut prekey_store = WasmInMemPreKeyStore::new();

    let pre_keys = generate_pre_keys(1, 5, &mut prekey_store).await.expect("Failed to generate prekeys");
    assert_eq!(pre_keys.len(), 5);

    let first = &pre_keys[0];
    assert_eq!(first.id(), 1);
    assert!(!first.public_key().is_empty());
    assert!(!first.record().is_empty());

    // Store should contain the key
    let exported = prekey_store.export_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_signed_pre_key_generation() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut signed_prekey_store = WasmInMemSignedPreKeyStore::new();

    let spk = generate_signed_pre_key(1, &identity_key_pair, &mut signed_prekey_store)
        .await
        .expect("Failed to generate signed prekey");

    assert_eq!(spk.id(), 1);
    assert!(!spk.signature().is_empty());
    assert!(!spk.public_key().is_empty());

    let exported = signed_prekey_store.export_signed_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_kyber_pre_key_generation() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut kyber_prekey_store = WasmInMemKyberPreKeyStore::new();

    let kpk = generate_kyber_pre_key(1, &identity_key_pair, &mut kyber_prekey_store)
        .await
        .expect("Failed to generate kyber key");

    assert_eq!(kpk.id(), 1);
    assert!(!kpk.signature().is_empty());
    assert_eq!(kpk.public_key().len(), 1569); // Kyber1024 public key size

    let exported = kyber_prekey_store.export_kyber_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_session_establishment_and_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // --- Alice setup ---
    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    // --- Bob setup ---
    let (bob_identity, bob_reg_id) = create_test_identity();
    let mut bob_session_store = WasmInMemSessionStore::new();
    let mut bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // --- Bob Generates Keys ---
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store).await.unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store).await.unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store).await.unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk = WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    // --- Alice Establishes Session ---
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        Some(pk.id()),
        Some(pk.public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice failed to process bundle");

    // --- Messaging ---
    let message_body = b"Hello WASM World!";

    // 1. Alice Encrypts
    let ciphertext = encrypt_message(
        message_body,
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Encryption failed");

    assert_eq!(ciphertext.message_type(), 3); // PreKeyMessage initially

    // 2. Bob Decrypts
    let decrypted = decrypt_message(
        &ciphertext.body(),
        ciphertext.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut bob_prekey_store,
        &bob_signed_prekey_store,
        &mut bob_kyber_prekey_store,
    )
    .await
    .expect("Decryption failed");

    assert_eq!(decrypted, message_body);

    // 3. Bob Replies (Standard Message)
    let reply_body = b"Ack!";
    let reply_cipher = encrypt_message(
        reply_body,
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
    )
    .await
    .expect("Reply encryption failed");

    assert_eq!(reply_cipher.message_type(), 2); // SignalMessage now

    let reply_decrypted = decrypt_message(
        &reply_cipher.body(),
        reply_cipher.message_type(),
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
    .expect("Reply decryption failed");

    assert_eq!(reply_decrypted, reply_body);
}

#[wasm_bindgen_test]
async fn test_group_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";
    // Caller-minted distribution id (must be a UUID string since 0.4.0).
    let distribution_id = uuid_to_string(&generate_uuid()).expect("Failed to mint distribution id");

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (_bob_identity, _bob_reg_id) = create_test_identity();
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();
    let _bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // 1. Alice Creates Group (SenderKeyDistribution)
    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    // 2. Bob Processes Distribution
    process_sender_key_distribution(
        &alice_address,
        &dist_msg,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Bob failed to process distribution");

    // 3. Alice Encrypts to Group
    let plaintext = b"Group Hello";
    let group_cipher = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    // 4. Bob Decrypts
    let decrypted = decrypt_group_message(
        &alice_address,
        &group_cipher,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Group decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_roundtrip_caller_minted_distribution_id() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    // Caller-minted distribution id, threaded end-to-end.
    let distribution_id = mint_distribution_id();

    // 1. Alice creates the distribution under the caller-minted id.
    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    // 2. Export the record and hydrate a fresh store (persistence path).
    let exported = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export sender key")
        .expect("Sender key missing after create");

    let mut restored_sender_key_store = WasmInMemSenderKeyStore::new();
    restored_sender_key_store
        .import_sender_key(&alice_address, distribution_id.clone(), &exported)
        .await
        .expect("Failed to import sender key");

    // 3. Encrypt on Alice's store, decrypt on the restored store.
    let plaintext = b"Hydrated group round-trip";
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    let decrypted = decrypt_group_message(
        &alice_address,
        &ciphertext,
        &mut restored_sender_key_store,
    )
    .await
    .expect("Group decryption on restored store failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_decrypt_wrong_distribution_id_fails() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let known_distribution_id = mint_distribution_id();
    let unknown_distribution_id = mint_distribution_id();

    // Bob knows only `known_distribution_id`.
    let dist_msg = create_sender_key_distribution(
        &alice_address,
        known_distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    process_sender_key_distribution(
        &alice_address,
        &dist_msg,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Bob failed to process distribution");

    // Alice encrypts under a different distribution id; the ciphertext
    // therefore embeds an id Bob has no record for.
    create_sender_key_distribution(
        &alice_address,
        unknown_distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create second distribution");
    let ciphertext = encrypt_group_message(
        &alice_address,
        unknown_distribution_id.clone(),
        b"Wrong id",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    let err = decrypt_group_message(
        &alice_address,
        &ciphertext,
        &mut bob_sender_key_store,
    )
    .await
    .expect_err("Decryption with the wrong distribution id must fail");

    assert_eq!(js_error_code(&err), "NoSenderKeyState");
    assert!(js_error_message(&err).starts_with("SignalError:"));
}

#[wasm_bindgen_test]
async fn test_remove_sender_key_rotates_key_material() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let distribution_id = mint_distribution_id();

    // 1. Create and export the original key material.
    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    let original = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export sender key")
        .expect("Sender key missing after create");

    // 2. Remove: export must then return None, and a second remove is a no-op.
    let removed = alice_sender_key_store
        .remove_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to remove sender key");
    assert!(removed, "remove_sender_key should report a removed record");

    let after_remove = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export after remove");
    assert!(after_remove.is_none(), "export after remove must be None");

    let removed_again = alice_sender_key_store
        .remove_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Second remove failed");
    assert!(!removed_again, "second remove_sender_key should report no record");

    // 3. Re-create under the same distribution id: fresh key material.
    let new_dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to re-create distribution");
    let rotated = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export rotated sender key")
        .expect("Sender key missing after re-create");

    assert_ne!(
        original, rotated,
        "remove + re-create must produce fresh key material"
    );

    // 4. The rotated distribution is fully functional.
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();
    process_sender_key_distribution(
        &alice_address,
        &new_dist_msg,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Bob failed to process rotated distribution");

    let plaintext = b"Post-rotation message";
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Post-rotation encryption failed");
    let decrypted = decrypt_group_message(
        &alice_address,
        &ciphertext,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Post-rotation decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_decrypt_unknown_distribution_error_code() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let distribution_id = mint_distribution_id();

    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"Unknown to Bob",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    // Bob never processed any SKDM, so the record lookup misses.
    let mut fresh_sender_key_store = WasmInMemSenderKeyStore::new();
    let err = decrypt_group_message(
        &alice_address,
        &ciphertext,
        &mut fresh_sender_key_store,
    )
    .await
    .expect_err("Decryption with an unknown distribution id must fail");

    assert_eq!(js_error_code(&err), "NoSenderKeyState");
    assert!(js_error_message(&err).starts_with("SignalError:"));
}

#[wasm_bindgen_test]
async fn test_group_rejects_non_uuid_distribution_id() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let mut sender_key_store = WasmInMemSenderKeyStore::new();

    // The pre-0.4.0 hash path is gone: arbitrary group strings are rejected.
    let err = create_sender_key_distribution(
        &alice_address,
        "team:general-chat-1".to_string(),
        &mut sender_key_store,
    )
    .await
    .expect_err("Non-UUID distribution id must be rejected");
    assert_eq!(js_error_code(&err), "Generic");

    let err = encrypt_group_message(
        &alice_address,
        "not-a-uuid".to_string(),
        b"x",
        &mut sender_key_store,
    )
    .await
    .expect_err("Non-UUID distribution id must be rejected");
    assert_eq!(js_error_code(&err), "Generic");
}

#[wasm_bindgen_test]
async fn test_gv2_key_derivation() {
    let master_key = WasmGroupMasterKey::generate();
    assert_eq!(master_key.serialize().len(), 32);

    let group_id = master_key.derive_identifier();
    assert_eq!(group_id.serialize().len(), 32);

    let params = master_key.derive_secret_params();
    assert_eq!(params.serialize_master_key().len(), 32);

    let master_key_bytes = master_key.serialize();
    let master_key_2 = WasmGroupMasterKey::from_bytes(&master_key_bytes).unwrap();
    assert_eq!(master_key_2.serialize(), master_key_bytes);

    let group_id_2 = master_key_2.derive_identifier();
    assert_eq!(group_id_2.serialize(), group_id.serialize());
}

#[wasm_bindgen_test]
async fn test_persistence() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let mut bob_session_store = WasmInMemSessionStore::new();
    let mut bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // Bob generates keys
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store).await.unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store).await.unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store).await.unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk = WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    // Alice establishes session
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        Some(pk.id()),
        Some(pk.public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice failed to process bundle");

    // Alice sends a message
    let cipher1 = encrypt_message(
        b"Msg 1",
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .unwrap();

    decrypt_message(
        &cipher1.body(),
        cipher1.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut bob_prekey_store,
        &bob_signed_prekey_store,
        &mut bob_kyber_prekey_store,
    )
    .await
    .unwrap();

    // EXPORT SESSION (Alice)
    let alice_session_data = alice_session_store
        .export_session(&bob_address)
        .await
        .expect("Failed to export session")
        .expect("Session not found");
    assert!(!alice_session_data.is_empty());

    // RESTORE: Create Alice 2
    let mut alice2_session_store = WasmInMemSessionStore::new();
    let mut alice2_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);

    // Import the session we exported
    alice2_session_store
        .import_session(&bob_address, &alice_session_data)
        .await
        .expect("Failed to import session");

    // Alice 2 sends message to Bob (Should work if session persisted)
    let cipher2 = encrypt_message(
        b"Msg 2",
        &bob_address,
        &alice_address,
        &mut alice2_session_store,
        &mut alice2_identity_store,
    )
    .await
    .unwrap();

    let decrypted2 = decrypt_message(
        &cipher2.body(),
        cipher2.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
    .unwrap();

    assert_eq!(decrypted2, b"Msg 2");
}

#[wasm_bindgen_test]
async fn test_safety_numbers() {
    let (alice_identity, _) = create_test_identity();
    let (bob_identity, _) = create_test_identity();

    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // 1. Generate SN (Alice view of Bob)
    let sn_alice = generate_safety_number(
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Alice failed to gen SN");

    // 2. Generate SN (Bob view of Alice)
    let sn_bob = generate_safety_number(
        bob_uuid.to_string(),
        &bob_identity.public_key(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
    )
    .expect("Bob failed to gen SN");

    // 3. Compare (Should match)
    assert_eq!(sn_alice.displayable(), sn_bob.displayable());

    // 4. Verify Self-Consistency
    let valid = verify_safety_number(
        &sn_alice.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Verification failed");

    assert!(valid);
}

#[wasm_bindgen_test]
async fn test_registration_id_generation() {
    let reg_id = generate_registration_id();
    assert!(reg_id > 0);
    assert!(reg_id <= 16380);
}

#[wasm_bindgen_test]
async fn test_uuid_utilities() {
    let uuid_bytes = generate_uuid();
    assert_eq!(uuid_bytes.len(), 16);

    let uuid_str = uuid_to_string(&uuid_bytes).unwrap();
    let recovered = uuid_from_string(&uuid_str).unwrap();
    assert_eq!(recovered, uuid_bytes);
}

#[wasm_bindgen_test]
async fn test_scannable_fingerprint_cross_perspective() {
    let (alice_identity, _) = create_test_identity();
    let (bob_identity, _) = create_test_identity();

    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // Bob's QR code: Bob's view (local=Bob, remote=Alice).
    let sn_bob = generate_safety_number(
        bob_uuid.to_string(),
        &bob_identity.public_key(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
    )
    .expect("Bob failed to gen SN");

    // Positive: Alice scans Bob's QR and verifies against HER view.
    let valid = verify_scannable_fingerprint(
        &sn_bob.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Cross-perspective verify failed");
    assert!(valid, "A scanning B's QR must verify");

    // Negative: tampered payload must not verify.
    let mut tampered = sn_bob.scannable();
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    let result = verify_scannable_fingerprint(
        &tampered,
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    );
    match result {
        Ok(v) => assert!(!v, "Tampered payload must not verify"),
        Err(e) => assert_eq!(js_error_code(&e), "FingerprintParsingError"),
    }

    // Negative: wrong version throws FingerprintVersionMismatch.
    // CombinedFingerprints protobuf: field 1 (version) is a varint, so a v2
    // encoding starts with 0x08 0x02; rewriting the version byte to 1 gives a
    // well-formed payload with a mismatched version.
    let mut wrong_version = sn_bob.scannable();
    assert_eq!(&wrong_version[..2], &[0x08, 0x02], "expected v2 varint header");
    wrong_version[1] = 0x01;
    let err = verify_scannable_fingerprint(
        &wrong_version,
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect_err("Version mismatch must throw");
    assert_eq!(js_error_code(&err), "FingerprintVersionMismatch");

    // Negative: garbage payload throws FingerprintParsingError.
    let err = verify_scannable_fingerprint(
        &[0xFF, 0xFF, 0xFF],
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect_err("Garbage payload must throw");
    assert_eq!(js_error_code(&err), "FingerprintParsingError");

    // Negative: swapped identities (Alice verifies against the WRONG contact)
    // must not verify.
    let (mallory_identity, _) = create_test_identity();
    let valid = verify_scannable_fingerprint(
        &sn_bob.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        "00000000-0000-0000-0000-00000000000C".to_string(),
        &mallory_identity.public_key(),
    )
    .expect("verify should return false, not throw");
    assert!(!valid, "Wrong contact identity must not verify");
}

#[wasm_bindgen_test]
async fn test_identity_proof_of_possession() {
    let (identity, _) = create_test_identity();
    let message = b"re-key authorisation challenge 0123456789";

    // Round-trip.
    let signature = sign_with_identity_key(&identity.private_key(), message)
        .expect("signing failed");
    assert_eq!(signature.len(), 64, "XEdDSA signature is 64 bytes");
    assert!(verify_identity_signature(
        &identity.public_key(),
        message,
        &signature
    ));

    // Negative: wrong message.
    assert!(!verify_identity_signature(
        &identity.public_key(),
        b"different challenge",
        &signature
    ));

    // Negative: wrong key.
    let (other_identity, _) = create_test_identity();
    assert!(!verify_identity_signature(
        &other_identity.public_key(),
        message,
        &signature
    ));

    // Negative: malformed signature must return false, not throw.
    assert!(!verify_identity_signature(
        &identity.public_key(),
        message,
        &[0u8; 8]
    ));
}

#[wasm_bindgen_test]
async fn test_group_secret_params_master_key_getter() {
    // L1: the getter is explicitly the 32-byte master key, and it must agree
    // with the master key it was derived from.
    let master_key = WasmGroupMasterKey::generate();
    let params = master_key.derive_secret_params();
    let exported = params.serialize_master_key();
    assert_eq!(exported.len(), 32);
    assert_eq!(exported, master_key.serialize());
}
