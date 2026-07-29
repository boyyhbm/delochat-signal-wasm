//! libsignal WASM Bridge — Granular API
//!
//! Exposes cryptographic primitives, individual protocol stores, and standalone
//! protocol operations matching upstream libsignal's architecture.
//!
//! ## Design
//! - No monolithic client. Identity generation requires **no device ID**.
//! - `PrivateKey::generate()` → `getPublicKey()` → `IdentityKeyPair`
//! - Device IDs are used **only** in `ProtocolAddress`.
//! - Stores are first-class objects: `InMemSessionStore`, `InMemIdentityKeyStore`, etc.
//! - Protocol operations are standalone async functions that accept stores explicitly.

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]

use std::borrow::Cow;
use std::collections::HashMap;

use async_trait::async_trait;
use zkgroup::groups::{GroupMasterKey, GroupSecretParams};
use zkgroup::GroupIdentifierBytes;

use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;
use libsignal_protocol::{
    create_sender_key_distribution_message,
    group_decrypt,
    group_encrypt,
    kem,
    message_decrypt,
    message_encrypt,
    process_prekey_bundle,
    process_sender_key_distribution_message,
    CiphertextMessage,
    CiphertextMessageType,
    DeviceId,
    Fingerprint,
    FingerprintError,
    GenericSignedPreKey,
    IdentityKey,
    IdentityKeyPair,
    IdentityKeyStore,
    InMemIdentityKeyStore,
    InMemKyberPreKeyStore,
    InMemPreKeyStore,
    InMemSessionStore,
    InMemSignedPreKeyStore,
    KeyPair,
    KyberPreKeyRecord,
    KyberPreKeyStore,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    PreKeyStore,
    PrivateKey,
    ProtocolAddress,
    PublicKey,
    SenderKeyDistributionMessage,
    SenderKeyRecord,
    SenderKeyStore,
    SessionRecord,
    SessionStore,
    SignalMessage,
    SignalProtocolError,
    SignedPreKeyRecord,
    SignedPreKeyStore,
    Timestamp,
};

// ============================================================================
// SECTION 0: Constants
// ============================================================================

/// Signal Protocol fingerprint version.
const FINGERPRINT_VERSION: u32 = 2;
/// Signal Protocol fingerprint iteration count.
const FINGERPRINT_ITERATIONS: u32 = 5200;

/// Maximum valid device ID (Signal convention, though DeviceId allows 1-255).
const MAX_DEVICE_ID: u32 = 127;

/// Maximum registration ID value (inclusive).
const MAX_REGISTRATION_ID: u32 = 16380;

/// Maximum number of PreKeys that can be generated in a single batch.
const MAX_PREKEY_BATCH_SIZE: u32 = 500;

/// Maximum length for `generate_random_bytes` to prevent DoS via huge allocation.
const MAX_RANDOM_BYTES_LENGTH: usize = 1_048_576; // 1 MiB

/// Standard size of a Group Master Key.
const GROUP_MASTER_KEY_SIZE: usize = 32;

/// Standard size of an attachment encryption key.
const ATTACHMENT_KEY_SIZE: usize = 64;

// ============================================================================
// SECTION 1: Initialisation
// ============================================================================

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(debug_assertions)]
    {
        console_error_panic_hook::set_once();
        web_sys::console::log_1(&"[Signal WASM] Module initialised (Debug Mode)".into());
    }
}

/// Debug-only console logging helper. Not exported in release builds — a
/// production wasm artifact must not carry a debug logging backdoor.
#[cfg(debug_assertions)]
#[wasm_bindgen]
pub fn log_to_console(message: &str) {
    web_sys::console::log_1(&message.into());
}

// ============================================================================
// SECTION 2: Error Handling & Validation
// ============================================================================

/// Stable machine-readable code for a libsignal protocol error.
///
/// Codes are matched on the error **type**, never on the message string, so
/// they stay specific even in release builds where messages are flattened.
fn error_code(e: &SignalProtocolError) -> &'static str {
    match e {
        SignalProtocolError::NoSenderKeyState { .. } => "NoSenderKeyState",
        SignalProtocolError::DuplicatedMessage(..) => "DuplicatedMessage",
        SignalProtocolError::UntrustedIdentity(_) => "UntrustedIdentity",
        SignalProtocolError::InvalidKyberPreKeyId => "InvalidKyberPreKeyId",
        SignalProtocolError::InvalidPreKeyId => "InvalidPreKeyId",
        SignalProtocolError::InvalidSignedPreKeyId => "InvalidSignedPreKeyId",
        _ => "Generic",
    }
}

/// Build a JS `Error` with the given message and a stable own `code` property.
///
/// Catch sites reading `.message` see the same string as before; note that
/// `String(err)` now includes the standard `"Error: "` prefix because the
/// thrown value is a real `Error` rather than a bare string.
fn js_error_with_code(message: &str, code: &str) -> JsValue {
    let error = js_sys::Error::new(message);
    // A fresh Error object is extensible, so this cannot realistically fail.
    let _ = js_sys::Reflect::set(
        error.as_ref(),
        &JsValue::from_str("code"),
        &JsValue::from_str(code),
    );
    error.into()
}

/// Format the error message. Release builds flatten details to avoid leaking
/// protocol internals; the `code` property remains fully specific.
fn error_message<E: std::fmt::Display>(e: E) -> String {
    #[cfg(debug_assertions)]
    {
        format!("SignalError: {}", e)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = e;
        "SignalError: Operation failed".to_string()
    }
}

/// Convert a libsignal protocol error, preserving a typed `code`.
fn signal_error_to_js(e: SignalProtocolError) -> JsValue {
    let code = error_code(&e);
    js_error_with_code(&error_message(e), code)
}

/// Convert any other displayable error; always coded `Generic`.
fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    js_error_with_code(&error_message(e), "Generic")
}

/// A validation failure raised by the wrapper itself; always coded `Generic`.
fn validation_error(message: &str) -> JsValue {
    js_error_with_code(message, "Generic")
}

/// Stable machine-readable code for a fingerprint error.
///
/// `VersionMismatch` is the interesting case for QR-scan UX (the two parties
/// are on incompatible fingerprint versions); parse failures of the scanned
/// payload get their own code so callers can tell "bad QR" apart from
/// "mismatch".
fn fingerprint_error_code(e: &FingerprintError) -> &'static str {
    match e {
        FingerprintError::VersionMismatch { .. } => "FingerprintVersionMismatch",
        FingerprintError::ParsingError(_) => "FingerprintParsingError",
        FingerprintError::InvalidIterationCount(_) => "FingerprintParsingError",
    }
}

/// Convert a fingerprint error, preserving a typed `code`.
fn fingerprint_error_to_js(e: FingerprintError) -> JsValue {
    let code = fingerprint_error_code(&e);
    js_error_with_code(&error_message(e), code)
}

fn make_device_id(id: u32) -> Result<DeviceId, JsValue> {
    DeviceId::try_from(id).map_err(|_| {
        validation_error(&format!("Invalid device ID (must be 1-{})", MAX_DEVICE_ID))
    })
}

/// Parse a caller-minted distribution id.
///
/// libsignal keys sender-key records by `(sender, distribution_id)` where the
/// id is caller-chosen (`rust/protocol/src/storage/traits.rs:164`). Since
/// 0.4.0 the wrapper no longer derives ids internally: the value must be a
/// valid UUID string minted by the caller.
fn parse_distribution_id(id: &str) -> Result<uuid::Uuid, JsValue> {
    uuid::Uuid::parse_str(id).map_err(|_| {
        validation_error(&format!(
            "Invalid distribution id (must be a UUID string): {}",
            id
        ))
    })
}

fn now_system_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}

fn now_timestamp() -> Timestamp {
    Timestamp::from_epoch_millis(js_sys::Date::now() as u64)
}

// ============================================================================
// SECTION 3: Granular Crypto Types
// ============================================================================

/// PrivateKey — standalone asymmetric secret key.
///
/// Zeroization note: the inner libsignal `PrivateKey` is a `Copy` type over a
/// `[u8; 32]` that upstream does not zero on drop, so this wrapper cannot
/// guarantee erasure of the scalar itself. The wrapper does zeroise every
/// secret-bearing buffer it owns (serialized prekey records, group master-key
/// bytes). Bytes exported to JS (`serialize()`) are copies in JS memory,
/// subject to the browser's GC — they cannot be erased from Rust.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPrivateKey(PrivateKey);

#[wasm_bindgen]
impl WasmPrivateKey {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> WasmPrivateKey {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        WasmPrivateKey(keypair.private_key)
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> Result<WasmPublicKey, JsValue> {
        Ok(WasmPublicKey(self.0.public_key().map_err(to_js_error)?))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmPrivateKey, JsValue> {
        Ok(WasmPrivateKey(PrivateKey::deserialize(data).map_err(to_js_error)?))
    }
}

/// PublicKey — standalone asymmetric public key.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPublicKey(PublicKey);

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmPublicKey, JsValue> {
        Ok(WasmPublicKey(PublicKey::deserialize(data).map_err(to_js_error)?))
    }
}

/// IdentityKeyPair — wraps a (PublicKey, PrivateKey) pair used as the long-term identity.
#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmIdentityKeyPair {
    public_key: WasmPublicKey,
    private_key: WasmPrivateKey,
}

#[wasm_bindgen]
impl WasmIdentityKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: &WasmPublicKey, private_key: &WasmPrivateKey) -> WasmIdentityKeyPair {
        WasmIdentityKeyPair {
            public_key: WasmPublicKey(public_key.0),
            private_key: WasmPrivateKey(private_key.0),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> WasmPublicKey {
        WasmPublicKey(self.public_key.0)
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> WasmPrivateKey {
        WasmPrivateKey(self.private_key.0)
    }

    /// Serialize to the standard protobuf format used by libsignal.
    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        let pair = IdentityKeyPair::new(
            self.public_key.0.into(),
            self.private_key.0,
        );
        pair.serialize().into_vec()
    }

    /// Deserialize from standard protobuf format.
    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmIdentityKeyPair, JsValue> {
        let pair = IdentityKeyPair::try_from(data).map_err(signal_error_to_js)?;
        let pub_key = *pair.identity_key();
        let priv_key = *pair.private_key();
        Ok(WasmIdentityKeyPair {
            public_key: WasmPublicKey(pub_key.into()),
            private_key: WasmPrivateKey(priv_key),
        })
    }
}

// ============================================================================
// SECTION 4: Protocol Address
// ============================================================================

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmProtocolAddress(ProtocolAddress);

#[wasm_bindgen]
impl WasmProtocolAddress {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, device_id: u32) -> Result<WasmProtocolAddress, JsValue> {
        let device_id = make_device_id(device_id)?;
        Ok(WasmProtocolAddress(ProtocolAddress::new(name, device_id)))
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.0.name().to_string()
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> u32 {
        self.0.device_id().into()
    }
}

// ============================================================================
// SECTION 5: Individual Stores
// ============================================================================

#[wasm_bindgen]
pub struct WasmInMemIdentityKeyStore(InMemIdentityKeyStore);

#[wasm_bindgen]
impl WasmInMemIdentityKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(identity_key_pair: &WasmIdentityKeyPair, registration_id: u32) -> WasmInMemIdentityKeyStore {
        let pair = IdentityKeyPair::new(
            identity_key_pair.public_key.0.into(),
            identity_key_pair.private_key.0,
        );
        WasmInMemIdentityKeyStore(InMemIdentityKeyStore::new(pair, registration_id))
    }

    /// Return the identity key pinned for `address`, if one exists.
    ///
    /// The bytes are public key material.  They are deliberately exposed so a
    /// client can persist the complete trusted-identity set alongside its
    /// session records in an encrypted local vault.
    #[wasm_bindgen(js_name = pinnedRemoteIdentity)]
    pub async fn pinned_remote_identity(
        &self,
        address: &WasmProtocolAddress,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        self.0
            .get_identity(&address.0)
            .await
            .map(|identity| identity.map(|key| key.serialize().into_vec()))
            .map_err(signal_error_to_js)
    }

    /// Pin a remote public identity key using strict TOFU semantics.
    ///
    /// A key may be inserted once, or submitted again when it is byte-for-byte
    /// identical.  Replacing an existing key is rejected.  Applications must
    /// make identity rotation an explicit, user-approved flow that discards the
    /// old session before constructing a new identity store.
    ///
    /// Returns `true` when this call created a new pin and `false` for an
    /// identical, already-pinned key.
    #[wasm_bindgen(js_name = pinRemoteIdentity)]
    pub async fn pin_remote_identity(
        &mut self,
        address: &WasmProtocolAddress,
        identity_key: &[u8],
    ) -> Result<bool, JsValue> {
        let candidate = IdentityKey::decode(identity_key).map_err(signal_error_to_js)?;
        match self.0.get_identity(&address.0).await.map_err(signal_error_to_js)? {
            Some(existing) if existing != candidate => Err(js_error_with_code(
                "A different remote identity is already pinned for this address",
                "PinnedIdentityMismatch",
            )),
            Some(_) => Ok(false),
            None => {
                self.0
                    .save_identity(&address.0, &candidate)
                    .await
                    .map_err(signal_error_to_js)?;
                Ok(true)
            }
        }
    }

    /// Require a previously pinned remote identity to match `identity_key`.
    ///
    /// This is intentionally stricter than libsignal's normal first-use trust
    /// decision: a missing pin is an error, never implicit approval.
    #[wasm_bindgen(js_name = assertPinnedRemoteIdentity)]
    pub async fn assert_pinned_remote_identity(
        &self,
        address: &WasmProtocolAddress,
        identity_key: &[u8],
    ) -> Result<(), JsValue> {
        let expected = IdentityKey::decode(identity_key).map_err(signal_error_to_js)?;
        match self.0.get_identity(&address.0).await.map_err(signal_error_to_js)? {
            Some(existing) if existing == expected => Ok(()),
            Some(_) => Err(js_error_with_code(
                "The pinned remote identity does not match",
                "PinnedIdentityMismatch",
            )),
            None => Err(js_error_with_code(
                "No remote identity is pinned for this address",
                "PinnedIdentityMissing",
            )),
        }
    }
}

#[wasm_bindgen]
pub struct WasmInMemSessionStore(InMemSessionStore);

#[wasm_bindgen]
impl WasmInMemSessionStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSessionStore {
        WasmInMemSessionStore(InMemSessionStore::new())
    }

    #[wasm_bindgen]
    pub async fn has_session(&self, address: &WasmProtocolAddress) -> Result<bool, JsValue> {
        // Store errors are surfaced, not swallowed: a falsey "false" would be
        // indistinguishable from "no session" (L4).
        let session = self
            .0
            .load_session(&address.0)
            .await
            .map_err(signal_error_to_js)?;
        Ok(session.is_some())
    }

    #[wasm_bindgen]
    pub async fn archive_session(&mut self, address: &WasmProtocolAddress) -> Result<(), JsValue> {
        if let Some(mut session) = self.0.load_session(&address.0).await.map_err(signal_error_to_js)? {
            session.archive_current_state().map_err(signal_error_to_js)?;
            self.0.store_session(&address.0, &session).await.map_err(signal_error_to_js)?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_session(&self, address: &WasmProtocolAddress) -> Result<Option<Vec<u8>>, JsValue> {
        match self.0.load_session(&address.0).await.map_err(signal_error_to_js)? {
            Some(session) => Ok(Some(session.serialize().map_err(signal_error_to_js)?)),
            None => Ok(None),
        }
    }

    #[wasm_bindgen]
    pub async fn import_session(&mut self, address: &WasmProtocolAddress, session_bytes: &[u8]) -> Result<(), JsValue> {
        let session = SessionRecord::deserialize(session_bytes).map_err(signal_error_to_js)?;
        self.0.store_session(&address.0, &session).await.map_err(signal_error_to_js)?;
        Ok(())
    }
}

impl Default for WasmInMemSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct WasmInMemPreKeyStore(InMemPreKeyStore);

#[wasm_bindgen]
impl WasmInMemPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemPreKeyStore {
        WasmInMemPreKeyStore(InMemPreKeyStore::new())
    }

    #[wasm_bindgen]
    pub async fn import_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = PreKeyRecord::deserialize(record_bytes).map_err(signal_error_to_js)?;
        if u32::from(record.id().map_err(signal_error_to_js)?) != id {
            return Err(validation_error("PreKey ID mismatch"));
        }
        self.0.save_pre_key(id.into(), &record).await.map_err(signal_error_to_js)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        // `InvalidPreKeyId` means "not present" (inmem store convention);
        // any other store error is surfaced, not swallowed as `None` (L4).
        match self.0.get_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(signal_error_to_js)?)),
            Err(SignalProtocolError::InvalidPreKeyId) => Ok(None),
            Err(e) => Err(signal_error_to_js(e)),
        }
    }
}

impl Default for WasmInMemPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct WasmInMemSignedPreKeyStore(InMemSignedPreKeyStore);

#[wasm_bindgen]
impl WasmInMemSignedPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSignedPreKeyStore {
        WasmInMemSignedPreKeyStore(InMemSignedPreKeyStore::new())
    }

    #[wasm_bindgen]
    pub async fn import_signed_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = SignedPreKeyRecord::deserialize(record_bytes).map_err(signal_error_to_js)?;
        if u32::from(record.id().map_err(signal_error_to_js)?) != id {
            return Err(validation_error("Signed PreKey ID mismatch"));
        }
        self.0.save_signed_pre_key(id.into(), &record).await.map_err(signal_error_to_js)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        // See export_pre_key: only the not-found sentinel maps to `None`.
        match self.0.get_signed_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(signal_error_to_js)?)),
            Err(SignalProtocolError::InvalidSignedPreKeyId) => Ok(None),
            Err(e) => Err(signal_error_to_js(e)),
        }
    }
}

impl Default for WasmInMemSignedPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
pub struct WasmInMemKyberPreKeyStore(InMemKyberPreKeyStore);

#[wasm_bindgen]
impl WasmInMemKyberPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemKyberPreKeyStore {
        WasmInMemKyberPreKeyStore(InMemKyberPreKeyStore::new())
    }

    #[wasm_bindgen]
    pub async fn import_kyber_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = KyberPreKeyRecord::deserialize(record_bytes).map_err(signal_error_to_js)?;
        if u32::from(record.id().map_err(signal_error_to_js)?) != id {
            return Err(validation_error("Kyber PreKey ID mismatch"));
        }
        self.0.save_kyber_pre_key(id.into(), &record).await.map_err(signal_error_to_js)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        // See export_pre_key: only the not-found sentinel maps to `None`.
        match self.0.get_kyber_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(signal_error_to_js)?)),
            Err(SignalProtocolError::InvalidKyberPreKeyId) => Ok(None),
            Err(e) => Err(signal_error_to_js(e)),
        }
    }
}

impl Default for WasmInMemKyberPreKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory sender-key store with record removal.
///
/// Upstream `InMemSenderKeyStore` keeps its map private and offers no removal
/// API, and the `SenderKeyStore` trait itself is only `store_sender_key` +
/// `load_sender_key` (`rust/protocol/src/storage/inmem.rs:330`,
/// `rust/protocol/src/storage/traits.rs:164`). Group-key rotation requires
/// deleting the record for `(sender, distribution_id)` before re-creating it —
/// canonical clients do exactly this (Signal-Desktop
/// `sendToGroup.preload.ts:865-868`) — so the wrapper implements the public
/// trait over its own map and adds `remove`.
struct RemovableSenderKeyStore {
    // Cow keys mirror upstream: store owned values, compare by reference.
    keys: HashMap<(Cow<'static, ProtocolAddress>, uuid::Uuid), SenderKeyRecord>,
}

impl RemovableSenderKeyStore {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Delete the record for `(sender, distribution_id)`; `true` if one existed.
    ///
    /// Unlike lookups this builds an owned key: `HashMap::remove` borrows the
    /// map mutably (invariant), so a `Cow::Borrowed` temporary cannot be used.
    /// Removal is a rare rotation-time operation, so one clone is fine.
    fn remove(&mut self, sender: &ProtocolAddress, distribution_id: uuid::Uuid) -> bool {
        self.keys
            .remove(&(Cow::Owned(sender.clone()), distribution_id))
            .is_some()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for RemovableSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.keys
            .insert((Cow::Owned(sender.clone()), distribution_id), record.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: uuid::Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self
            .keys
            .get(&(Cow::Borrowed(sender), distribution_id))
            .cloned())
    }
}

#[wasm_bindgen]
pub struct WasmInMemSenderKeyStore(RemovableSenderKeyStore);

#[wasm_bindgen]
impl WasmInMemSenderKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSenderKeyStore {
        WasmInMemSenderKeyStore(RemovableSenderKeyStore::new())
    }

    #[wasm_bindgen]
    pub async fn export_sender_key(
        &mut self,
        address: &WasmProtocolAddress,
        distribution_id: String,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let dist_id = parse_distribution_id(&distribution_id)?;
        match self.0.load_sender_key(&address.0, dist_id).await.map_err(signal_error_to_js)? {
            Some(record) => Ok(Some(record.serialize().map_err(signal_error_to_js)?)),
            None => Ok(None),
        }
    }

    #[wasm_bindgen]
    pub async fn import_sender_key(
        &mut self,
        address: &WasmProtocolAddress,
        distribution_id: String,
        record_bytes: &[u8],
    ) -> Result<(), JsValue> {
        let dist_id = parse_distribution_id(&distribution_id)?;
        let record = SenderKeyRecord::deserialize(record_bytes).map_err(signal_error_to_js)?;
        self.0.store_sender_key(&address.0, dist_id, &record).await.map_err(signal_error_to_js)?;
        Ok(())
    }

    /// Delete the sender-key record for `(address, distribution_id)`.
    ///
    /// Rotation must delete the record before re-creating it, otherwise
    /// `createSenderKeyDistribution` reuses the existing chain and removed
    /// group members keep deriving future message keys. Returns `true` if a
    /// record was actually removed.
    #[wasm_bindgen]
    pub async fn remove_sender_key(
        &mut self,
        address: &WasmProtocolAddress,
        distribution_id: String,
    ) -> Result<bool, JsValue> {
        let dist_id = parse_distribution_id(&distribution_id)?;
        Ok(self.0.remove(&address.0, dist_id))
    }
}

impl Default for WasmInMemSenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SECTION 6: Exported Key / Message Types
// ============================================================================

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPreKey {
    id: u32,
    public_key: Vec<u8>,
    /// Serialized PreKeyRecord protobuf — contains the private half, so it is
    /// zeroised on drop.
    record: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.to_vec()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmSignedPreKey {
    id: u32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    /// Serialized SignedPreKeyRecord protobuf — contains the private half, so
    /// it is zeroised on drop.
    record: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmSignedPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.to_vec()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmKyberPreKey {
    id: u32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    /// Serialized KyberPreKeyRecord protobuf — contains the private half, so
    /// it is zeroised on drop.
    record: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmKyberPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.to_vec()
    }
}

#[wasm_bindgen]
pub struct WasmCiphertext {
    message_type: u8,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl WasmCiphertext {
    #[wasm_bindgen(getter)]
    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

#[wasm_bindgen]
pub struct WasmSafetyNumber {
    displayable: String,
    scannable: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSafetyNumber {
    #[wasm_bindgen(getter)]
    pub fn displayable(&self) -> String {
        self.displayable.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn scannable(&self) -> Vec<u8> {
        self.scannable.clone()
    }
}

// ============================================================================
// SECTION 7: Group Messaging v2 (GV2) Types
// ============================================================================

#[wasm_bindgen]
pub struct WasmGroupMasterKey {
    inner: GroupMasterKey,
    /// Raw master-key bytes — zeroised on drop.
    bytes: Zeroizing<[u8; GROUP_MASTER_KEY_SIZE]>,
}

#[wasm_bindgen]
impl WasmGroupMasterKey {
    #[wasm_bindgen]
    pub fn generate() -> WasmGroupMasterKey {
        let mut bytes = Zeroizing::new([0u8; GROUP_MASTER_KEY_SIZE]);
        let mut rng = rand::rng();
        rand::prelude::Rng::fill(&mut rng, bytes.as_mut());
        WasmGroupMasterKey {
            inner: GroupMasterKey::new(*bytes),
            bytes,
        }
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmGroupMasterKey, JsValue> {
        let array: [u8; GROUP_MASTER_KEY_SIZE] = bytes.try_into().map_err(|_| {
            validation_error(&format!("Invalid key length (must be {} bytes)", GROUP_MASTER_KEY_SIZE))
        })?;
        let array = Zeroizing::new(array);
        Ok(WasmGroupMasterKey {
            inner: GroupMasterKey::new(*array),
            bytes: array,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen]
    pub fn derive_secret_params(&self) -> WasmGroupSecretParams {
        WasmGroupSecretParams {
            inner: GroupSecretParams::derive_from_master_key(self.inner),
            master_key_bytes: self.bytes.clone(),
        }
    }

    #[wasm_bindgen]
    pub fn derive_identifier(&self) -> WasmGroupIdentifier {
        let params = GroupSecretParams::derive_from_master_key(self.inner);
        WasmGroupIdentifier {
            inner: params.get_group_identifier(),
        }
    }
}

#[wasm_bindgen]
pub struct WasmGroupIdentifier {
    inner: GroupIdentifierBytes,
}

#[wasm_bindgen]
impl WasmGroupIdentifier {
    #[wasm_bindgen(getter)]
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
}

#[wasm_bindgen]
pub struct WasmGroupSecretParams {
    inner: GroupSecretParams,
    /// Raw master-key bytes — zeroised on drop.
    master_key_bytes: Zeroizing<[u8; GROUP_MASTER_KEY_SIZE]>,
}

#[wasm_bindgen]
impl WasmGroupSecretParams {
    /// Returns the 32-byte **master key**, not the (289-byte) group secret
    /// params. Named explicitly so no future caller mistakes it for the full
    /// params encoding (see L1 in the 0.5.0 audit).
    #[wasm_bindgen(getter)]
    pub fn serialize_master_key(&self) -> Vec<u8> {
        self.master_key_bytes.to_vec()
    }

    #[wasm_bindgen]
    pub fn get_identifier(&self) -> WasmGroupIdentifier {
        WasmGroupIdentifier {
            inner: self.inner.get_group_identifier(),
        }
    }
}

// ============================================================================
// SECTION 8: Standalone Key Generation
// ============================================================================

/// Generate a batch of one-time PreKeys.
#[wasm_bindgen(js_name = generatePreKeys)]
pub async fn generate_pre_keys(
    start_id: u32,
    count: u32,
    prekey_store: &mut WasmInMemPreKeyStore,
) -> Result<Vec<WasmPreKey>, JsValue> {
    if count > MAX_PREKEY_BATCH_SIZE {
        return Err(validation_error(&format!(
            "Batch size {} exceeds maximum {}",
            count, MAX_PREKEY_BATCH_SIZE
        )));
    }
    let mut rng = rand::rng();
    let mut result = Vec::new();

    for i in 0..count {
        let id = start_id.wrapping_add(i) & 0x00FF_FFFF;
        let key_pair = KeyPair::generate(&mut rng);
        let prekey_record = PreKeyRecord::new(id.into(), &key_pair);
        let serialized = prekey_record.serialize().map_err(signal_error_to_js)?;

        prekey_store.0.save_pre_key(id.into(), &prekey_record)
            .await
            .map_err(signal_error_to_js)?;

        result.push(WasmPreKey {
            id,
            public_key: key_pair.public_key.serialize().to_vec(),
            record: Zeroizing::new(serialized),
        });
    }

    Ok(result)
}

/// Generate a signed PreKey.
#[wasm_bindgen(js_name = generateSignedPreKey)]
pub async fn generate_signed_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    signed_prekey_store: &mut WasmInMemSignedPreKeyStore,
) -> Result<WasmSignedPreKey, JsValue> {
    let mut rng = rand::rng();
    let key_pair = KeyPair::generate(&mut rng);
    let signature = identity_key_pair
        .private_key
        .0
        .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
        .map_err(to_js_error)?;

    let timestamp = now_timestamp();
    let signed_prekey_record = SignedPreKeyRecord::new(key_id.into(), timestamp, &key_pair, &signature);
    let serialized = signed_prekey_record.serialize().map_err(signal_error_to_js)?;

    signed_prekey_store
        .0
        .save_signed_pre_key(key_id.into(), &signed_prekey_record)
        .await
        .map_err(signal_error_to_js)?;

    Ok(WasmSignedPreKey {
        id: key_id,
        public_key: key_pair.public_key.serialize().to_vec(),
        signature: signature.to_vec(),
        timestamp: timestamp.epoch_millis(),
        record: Zeroizing::new(serialized),
    })
}

/// Generate a Kyber PreKey for post-quantum security.
#[wasm_bindgen(js_name = generateKyberPreKey)]
pub async fn generate_kyber_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    kyber_prekey_store: &mut WasmInMemKyberPreKeyStore,
) -> Result<WasmKyberPreKey, JsValue> {
    let mut rng = rand::rng();
    let key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let signature = identity_key_pair
        .private_key
        .0
        .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
        .map_err(to_js_error)?;
    let timestamp = now_timestamp();
    let kyber_record = KyberPreKeyRecord::new(key_id.into(), timestamp, &key_pair, &signature);
    let serialized = kyber_record.serialize().map_err(signal_error_to_js)?;

    let public_key = key_pair.public_key.serialize().to_vec();

    kyber_prekey_store
        .0
        .save_kyber_pre_key(key_id.into(), &kyber_record)
        .await
        .map_err(signal_error_to_js)?;

    Ok(WasmKyberPreKey {
        id: key_id,
        public_key,
        signature: signature.to_vec(),
        timestamp: timestamp.epoch_millis(),
        record: Zeroizing::new(serialized),
    })
}

/// Generate a registration ID using unbiased rejection sampling (1..=MAX_REGISTRATION_ID).
#[wasm_bindgen(js_name = generateRegistrationId)]
pub fn generate_registration_id() -> u32 {
    loop {
        let val = rand::random::<u32>();
        if val < (u32::MAX / MAX_REGISTRATION_ID) * MAX_REGISTRATION_ID {
            break (val % MAX_REGISTRATION_ID) + 1;
        }
    }
}

// ============================================================================
// SECTION 9: Standalone Protocol Operations
// ============================================================================

/// Process a PreKeyBundle to establish a session.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = processPreKeyBundle)]
pub async fn process_pre_key_bundle(
    recipient: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    registration_id: u32,
    identity_key: &WasmPublicKey,
    signed_prekey_id: u32,
    signed_prekey: &WasmPublicKey,
    signed_prekey_signature: &[u8],
    prekey_id: Option<u32>,
    prekey: Option<Vec<u8>>,
    kyber_prekey_id: u32,
    kyber_prekey: &[u8],
    kyber_prekey_signature: &[u8],
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<(), JsValue> {
    let identity_key_pub = identity_key.0;
    let signed_prekey_pub = signed_prekey.0;
    let kyber_prekey_pub = kem::PublicKey::deserialize(kyber_prekey).map_err(signal_error_to_js)?;

    let prekey_tuple = match (prekey_id, prekey) {
        (Some(id), Some(bytes)) => {
            let pk = PublicKey::deserialize(&bytes).map_err(to_js_error)?;
            Some((id.into(), pk))
        }
        _ => None,
    };

    let bundle = PreKeyBundle::new(
        registration_id,
        recipient.0.device_id(),
        prekey_tuple,
        signed_prekey_id.into(),
        signed_prekey_pub,
        signed_prekey_signature.to_vec(),
        kyber_prekey_id.into(),
        kyber_prekey_pub,
        kyber_prekey_signature.to_vec(),
        identity_key_pub.into(),
    )
    .map_err(signal_error_to_js)?;

    let mut rng = rand::rng();
    process_prekey_bundle(
        &recipient.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        &bundle,
        now_system_time(),
        &mut rng,
    )
    .await
    .map_err(signal_error_to_js)?;

    Ok(())
}

/// Encrypt a Signal message.
#[wasm_bindgen(js_name = encryptMessage)]
pub async fn encrypt_message(
    plaintext: &[u8],
    recipient: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<WasmCiphertext, JsValue> {
    let mut rng = rand::rng();
    let ciphertext = message_encrypt(
        plaintext,
        &recipient.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        now_system_time(),
        &mut rng,
    )
    .await
    .map_err(signal_error_to_js)?;

    Ok(WasmCiphertext {
        message_type: ciphertext.message_type() as u8,
        body: ciphertext.serialize().to_vec(),
    })
}

/// Decrypt a Signal message.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = decryptMessage)]
pub async fn decrypt_message(
    ciphertext: &[u8],
    message_type: u8,
    sender: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
    prekey_store: &mut WasmInMemPreKeyStore,
    signed_prekey_store: &WasmInMemSignedPreKeyStore,
    kyber_prekey_store: &mut WasmInMemKyberPreKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let mut rng = rand::rng();

    let msg_type = CiphertextMessageType::try_from(message_type).map_err(|_| {
        validation_error(&format!("Unknown message type: {}", message_type))
    })?;

    let ciphertext_msg: CiphertextMessage = match msg_type {
        CiphertextMessageType::Whisper => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext).map_err(signal_error_to_js)?,
        ),
        CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext).map_err(signal_error_to_js)?,
        ),
        _ => {
            return Err(validation_error(&format!(
                "Unsupported message type for decrypt: {:?}",
                msg_type
            )))
        }
    };

    let plaintext = message_decrypt(
        &ciphertext_msg,
        &sender.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        &mut prekey_store.0,
        &signed_prekey_store.0,
        &mut kyber_prekey_store.0,
        &mut rng,
    )
    .await
    .map_err(signal_error_to_js)?;

    Ok(plaintext)
}

/// Create a sender key distribution message.
///
/// `distribution_id` must be a caller-minted UUID string; since 0.4.0 the
/// wrapper no longer derives an id from arbitrary group strings.
#[wasm_bindgen(js_name = createSenderKeyDistribution)]
pub async fn create_sender_key_distribution(
    local_address: &WasmProtocolAddress,
    distribution_id: String,
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let dist_id = parse_distribution_id(&distribution_id)?;
    let mut rng = rand::rng();
    let skdm = create_sender_key_distribution_message(
        &local_address.0,
        dist_id,
        &mut sender_key_store.0,
        &mut rng,
    )
    .await
    .map_err(signal_error_to_js)?;

    Ok(skdm.serialized().to_vec())
}

/// Process a sender key distribution message.
///
/// The distribution id is read from the message itself, so no id parameter is
/// required here.
#[wasm_bindgen(js_name = processSenderKeyDistribution)]
pub async fn process_sender_key_distribution(
    sender_address: &WasmProtocolAddress,
    distribution_message: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<(), JsValue> {
    let skdm = SenderKeyDistributionMessage::try_from(distribution_message).map_err(signal_error_to_js)?;
    process_sender_key_distribution_message(&sender_address.0, &skdm, &mut sender_key_store.0)
        .await
        .map_err(signal_error_to_js)?;
    Ok(())
}

/// Encrypt a group message.
///
/// `distribution_id` must be the same caller-minted UUID string used for
/// `createSenderKeyDistribution`.
#[wasm_bindgen(js_name = encryptGroupMessage)]
pub async fn encrypt_group_message(
    local_address: &WasmProtocolAddress,
    distribution_id: String,
    plaintext: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let dist_id = parse_distribution_id(&distribution_id)?;
    let mut rng = rand::rng();
    let ciphertext = group_encrypt(
        &mut sender_key_store.0,
        &local_address.0,
        dist_id,
        plaintext,
        &mut rng,
    )
    .await
    .map_err(signal_error_to_js)?;

    Ok(ciphertext.serialized().to_vec())
}

/// Decrypt a group message.
///
/// The distribution id is embedded in the ciphertext, so the record lookup is
/// keyed automatically; an unknown id surfaces as a `NoSenderKeyState` error.
#[wasm_bindgen(js_name = decryptGroupMessage)]
pub async fn decrypt_group_message(
    sender_address: &WasmProtocolAddress,
    ciphertext: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let plaintext = group_decrypt(ciphertext, &mut sender_key_store.0, &sender_address.0)
        .await
        .map_err(signal_error_to_js)?;

    Ok(plaintext)
}

/// Build OUR combined fingerprint for `(local, contact)`, sorted internally by
/// libsignal's canonical ordering rules (`Fingerprint::new`).
fn build_fingerprint(
    local_uuid: &str,
    local_identity_key: &WasmPublicKey,
    contact_uuid: &str,
    contact_identity_key: &WasmPublicKey,
) -> Result<Fingerprint, JsValue> {
    let local_key: IdentityKey = local_identity_key.0.into();
    let contact_key: IdentityKey = contact_identity_key.0.into();

    Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        local_uuid.as_bytes(),
        &local_key,
        contact_uuid.as_bytes(),
        &contact_key,
    )
    .map_err(fingerprint_error_to_js)
}

/// Generate a safety number.
#[wasm_bindgen(js_name = generateSafetyNumber)]
pub fn generate_safety_number(
    local_uuid: String,
    local_identity_key: &WasmPublicKey,
    contact_uuid: String,
    contact_identity_key: &WasmPublicKey,
) -> Result<WasmSafetyNumber, JsValue> {
    let fingerprint = build_fingerprint(
        &local_uuid,
        local_identity_key,
        &contact_uuid,
        contact_identity_key,
    )?;

    Ok(WasmSafetyNumber {
        displayable: fingerprint.display.to_string(),
        scannable: fingerprint.scannable.serialize().map_err(fingerprint_error_to_js)?,
    })
}

/// Verify a scanned QR-code fingerprint against OUR view of the session.
///
/// This is the canonical cross-perspective check
/// (`ScannableFingerprint::compare`, libsignal
/// `rust/protocol/src/fingerprint.rs`): the scanned payload encodes the OTHER
/// party's CombinedFingerprints, so verification requires their.local ==
/// our.remote AND their.remote == our.local, enforced in constant time, with
/// version equality. A version mismatch throws with code
/// `FingerprintVersionMismatch`; an undecodable payload throws with code
/// `FingerprintParsingError`.
#[wasm_bindgen(js_name = verifyScannableFingerprint)]
pub fn verify_scannable_fingerprint(
    scanned: &[u8],
    local_uuid: String,
    local_identity_key: &WasmPublicKey,
    contact_uuid: String,
    contact_identity_key: &WasmPublicKey,
) -> Result<bool, JsValue> {
    let fingerprint = build_fingerprint(
        &local_uuid,
        local_identity_key,
        &contact_uuid,
        contact_identity_key,
    )?;

    fingerprint
        .scannable
        .compare(scanned)
        .map_err(fingerprint_error_to_js)
}

/// Verify a scanned safety number.
///
/// **Deprecated**: this recomputes OUR OWN fingerprint and byte-compares it
/// with the scanned payload, which can never validate a cross-perspective
/// scan (the scanned QR encodes the OTHER party's CombinedFingerprints with
/// local/remote swapped). Use `verifyScannableFingerprint`, which implements
/// the canonical `ScannableFingerprint::compare` semantics. Kept for API
/// compatibility only.
#[wasm_bindgen(js_name = verifySafetyNumber)]
pub fn verify_safety_number(
    scanned: &[u8],
    local_uuid: String,
    local_identity_key: &WasmPublicKey,
    contact_uuid: String,
    contact_identity_key: &WasmPublicKey,
) -> Result<bool, JsValue> {
    let expected = generate_safety_number(
        local_uuid,
        local_identity_key,
        contact_uuid,
        contact_identity_key,
    )?;

    let valid = scanned.ct_eq(&expected.scannable);
    Ok(valid.into())
}

// ============================================================================
// SECTION 9B: Identity Proof-of-Possession
// ============================================================================

/// Sign `message` with an identity private key (XEdDSA over the X25519
/// identity key, canonical `PrivateKey::calculate_signature`).
///
/// Intended for server-verifiable proof-of-possession of an identity key,
/// e.g. authorising a re-key. Returns the 64-byte signature.
#[wasm_bindgen(js_name = signWithIdentityKey)]
pub fn sign_with_identity_key(
    identity_private_key: &WasmPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let mut rng = rand::rng();
    let signature = identity_private_key
        .0
        .calculate_signature(message, &mut rng)
        .map_err(to_js_error)?;
    Ok(signature.into_vec())
}

/// Verify an identity-key signature produced by `signWithIdentityKey`
/// (canonical `PublicKey::verify_signature`, constant-time).
///
/// Returns `false` for a wrong key, wrong message, or malformed signature —
/// verification failure is data, not an error.
#[wasm_bindgen(js_name = verifyIdentitySignature)]
pub fn verify_identity_signature(
    identity_public_key: &WasmPublicKey,
    message: &[u8],
    signature: &[u8],
) -> bool {
    identity_public_key.0.verify_signature(message, signature)
}

// ============================================================================
// SECTION 10: Utility Functions
// ============================================================================

#[wasm_bindgen]
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    if length > MAX_RANDOM_BYTES_LENGTH {
        return Err(validation_error(&format!(
            "Requested length {} exceeds maximum allowed {} bytes",
            length, MAX_RANDOM_BYTES_LENGTH
        )));
    }
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes).map_err(|e| validation_error(&format!("CSPRNG error: {}", e)))?;
    Ok(bytes)
}

#[wasm_bindgen]
pub fn generate_attachment_key() -> Result<Vec<u8>, JsValue> {
    generate_random_bytes(ATTACHMENT_KEY_SIZE)
}

#[wasm_bindgen]
pub fn generate_uuid() -> Vec<u8> {
    uuid::Uuid::new_v4().as_bytes().to_vec()
}

#[wasm_bindgen]
pub fn uuid_to_string(bytes: &[u8]) -> Result<String, JsValue> {
    if bytes.len() != 16 {
        return Err(validation_error("UUID must be 16 bytes"));
    }
    let uuid = uuid::Uuid::from_slice(bytes).map_err(to_js_error)?;
    Ok(uuid.to_string())
}

#[wasm_bindgen]
pub fn uuid_from_string(s: &str) -> Result<Vec<u8>, JsValue> {
    let uuid = uuid::Uuid::parse_str(s).map_err(to_js_error)?;
    Ok(uuid.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn message_type_signal() -> u8 {
    CiphertextMessageType::Whisper as u8
}

#[wasm_bindgen]
pub fn message_type_pre_key() -> u8 {
    CiphertextMessageType::PreKey as u8
}

#[wasm_bindgen]
pub fn message_type_sender_key() -> u8 {
    CiphertextMessageType::SenderKey as u8
}
