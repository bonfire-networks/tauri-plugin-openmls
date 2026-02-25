//! Native OpenMLS backend for the Bonfire Tauri app.
//!
//! Provides a Tauri plugin ("openmls") that implements the same MLS backend interface as the WASM version (`mls-backend.js`), using SQLite for persistent storage.
//!
//! Usage: `.plugin(tauri_plugin_openmls::init())` in your Tauri builder.
//! JS calls: `invoke('plugin:openmls|command_name', { ... })`

use std::collections::HashMap;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use openmls::prelude::*;
use openmls::prelude::tls_codec::{
    Serialize as TlsSerializeTrait,
    Deserialize as TlsDeserializeTrait,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use serde::Serialize;
use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};
use tokio::sync::Mutex;

// ── JSON codec for SQLite storage ──────────────────────────────────

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

// ── Custom provider: RustCrypto + SQLite storage ───────────────────

pub struct TauriOpenMLSProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl TauriOpenMLSProvider {
    pub fn new(db_path: &PathBuf, user_id: &str) -> Result<Self, String> {
        let user_db = db_path.join(format!("mls_{}.db", sanitize_filename(user_id)));
        let conn = Connection::open(&user_db).map_err(|e| e.to_string())?;

        let mut storage = SqliteStorageProvider::new(conn);
        storage.run_migrations().map_err(|e| e.to_string())?;

        Ok(Self {
            crypto: RustCrypto::default(),
            storage,
        })
    }
}

impl OpenMlsProvider for TauriOpenMLSProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ── Managed state ──────────────────────────────────────────────────

pub struct MlsState {
    db_path: PathBuf,
    app_handle: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    providers: HashMap<String, TauriOpenMLSProvider>,
    credentials: HashMap<String, (CredentialWithKey, SignatureKeyPair)>,
    groups: HashMap<String, MlsGroup>,
}

impl MlsState {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            app_handle: None,
            providers: HashMap::new(),
            credentials: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    /// Show a native confirmation dialog. Returns true if confirmed.
    fn confirm(&self, title: &str, message: &str) -> bool {
        use tauri_plugin_dialog::MessageDialogButtons;
        if let Some(handle) = self.app_handle.as_ref()
            .and_then(|h| h.downcast_ref::<tauri::AppHandle<tauri::Wry>>())
        {
            handle.dialog()
                .message(message)
                .title(title)
                .kind(MessageDialogKind::Warning)
                .buttons(MessageDialogButtons::OkCancelCustom("Remove".into(), "Cancel".into()))
                .blocking_show()
        } else {
            true // no handle = skip confirmation
        }
    }
}

const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

// ── Helpers ────────────────────────────────────────────────────────

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// Debug: dump openmls_group_data summary for a user's DB.
fn debug_dump_group_data(db_path: &PathBuf, user_id: &str, label: &str) {
    let user_db = db_path.join(format!("mls_{}.db", sanitize_filename(user_id)));
    let Ok(conn) = rusqlite::Connection::open(&user_db) else { return };
    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM openmls_group_data", [], |r| r.get(0))
        .unwrap_or(-1);
    eprintln!("[MLS] {label}: openmls_group_data total rows={total}");
    if let Ok(mut stmt) = conn.prepare(
        "SELECT DISTINCT hex(group_id), COUNT(*) FROM openmls_group_data GROUP BY group_id"
    ) {
        if let Ok(rows) = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        }) {
            for row in rows.flatten() {
                eprintln!("[MLS] {label}:   group hex={}… entries={}", &row.0[..40.min(row.0.len())], row.1);
            }
        }
    };
}

/// Read the persisted public key for a user from a metadata table in their MLS SQLite DB.
fn load_persisted_public_key(db_path: &PathBuf, user_id: &str) -> Option<Vec<u8>> {
    let user_db = db_path.join(format!("mls_{}.db", sanitize_filename(user_id)));
    let conn = rusqlite::Connection::open(&user_db).ok()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS bonfire_mls_meta (user_id TEXT PRIMARY KEY, public_key BLOB NOT NULL)",
        [],
    ).ok()?;
    conn.query_row(
        "SELECT public_key FROM bonfire_mls_meta WHERE user_id = ?1",
        [user_id],
        |row| row.get(0),
    ).ok()
}

/// Persist the public key (not sensitive) for a user in a metadata table.
fn save_persisted_public_key(db_path: &PathBuf, user_id: &str, public_key: &[u8]) -> Result<(), String> {
    let user_db = db_path.join(format!("mls_{}.db", sanitize_filename(user_id)));
    let conn = rusqlite::Connection::open(&user_db)
        .map_err(|e| format!("Failed to open metadata DB: {e}"))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS bonfire_mls_meta (user_id TEXT PRIMARY KEY, public_key BLOB NOT NULL)",
        [],
    ).map_err(|e| format!("Failed to create metadata table: {e}"))?;
    conn.execute(
        "INSERT OR REPLACE INTO bonfire_mls_meta (user_id, public_key) VALUES (?1, ?2)",
        rusqlite::params![user_id, public_key],
    ).map_err(|e| format!("Failed to save public key: {e}"))?;
    Ok(())
}

fn generate_credential_with_key(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(signature_algorithm)
        .map_err(|e| format!("Error generating signature key pair: {e:?}"))?;

    signature_keys
        .store(provider.storage())
        .map_err(|e| format!("Error storing signature keys: {e:?}"))?;

    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.public().into(),
        },
        signature_keys,
    ))
}

// ── Tauri commands (plugin-namespaced, no mls_ prefix) ────────────

#[tauri::command]
async fn init_user(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    saved_state: Option<String>,
) -> Result<(), String> {
    eprintln!("[MLS] init_user called for: {user_id}");
    let _ = saved_state; // ignored — SQLite self-persists
    let mut s = state.lock().await;

    if s.providers.contains_key(&user_id) {
        eprintln!("[MLS] User already initialized: {user_id}");
        return Ok(());
    }

    eprintln!("[MLS] Creating provider at: {}", s.db_path.display());
    let provider = TauriOpenMLSProvider::new(&s.db_path, &user_id)?;

    // Try to reload persisted credentials from the SQLite DB
    let (credential_with_key, signer) =
        if let Some(public_key) = load_persisted_public_key(&s.db_path, &user_id) {
            eprintln!("[MLS] Found persisted public key for: {user_id}");
            if let Some(signer) = SignatureKeyPair::read(
                provider.storage(),
                &public_key,
                CIPHERSUITE.signature_algorithm(),
            ) {
                eprintln!("[MLS] Loaded signer from SQLite storage for: {user_id}");
                let credential_with_key = CredentialWithKey {
                    credential: BasicCredential::new(user_id.as_bytes().to_vec()).into(),
                    signature_key: signer.public().into(),
                };
                (credential_with_key, signer)
            } else {
                eprintln!("[MLS] Signer not found in storage, generating new credentials for: {user_id}");
                let (cred, sig) = generate_credential_with_key(
                    user_id.as_bytes().to_vec(),
                    CIPHERSUITE.signature_algorithm(),
                    &provider,
                )?;
                save_persisted_public_key(&s.db_path, &user_id, sig.public())?;
                (cred, sig)
            }
        } else {
            eprintln!("[MLS] No persisted credentials, generating new for: {user_id}");
            let (cred, sig) = generate_credential_with_key(
                user_id.as_bytes().to_vec(),
                CIPHERSUITE.signature_algorithm(),
                &provider,
            )?;
            save_persisted_public_key(&s.db_path, &user_id, sig.public())?;
            (cred, sig)
        };

    s.credentials
        .insert(user_id.clone(), (credential_with_key, signer));
    s.providers.insert(user_id.clone(), provider);

    eprintln!("[MLS] init_user complete for: {user_id}");
    Ok(())
}


#[tauri::command]
async fn create_group(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] create_group called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;

    let provider = s.providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (credential_with_key, signer) = s.credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;

    if let Some(group) = s.groups.get(&group_id) {
        let ratchet_tree = group
            .export_ratchet_tree()
            .tls_serialize_detached()
            .map_err(|e| format!("Serialization error: {e:?}"))?;
        return Ok(serde_json::json!({
            "ratchetTree": BASE64.encode(&ratchet_tree)
        }));
    }

    let group_id_bytes = group_id.as_bytes();
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();

    let group = MlsGroup::new_with_group_id(
        provider,
        signer,
        &mls_group_create_config,
        GroupId::from_slice(group_id_bytes),
        credential_with_key.clone(),
    )
    .map_err(|e| {
        eprintln!("[MLS] create_group FAILED (storage error?): {e:?}");
        format!("Failed to create group: {e:?}")
    })?;

    eprintln!("[MLS] create_group: MlsGroup created OK");
    debug_dump_group_data(&s.db_path, &user_id, "create_group");

    let ratchet_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    s.groups.insert(group_id, group);

    Ok(serde_json::json!({
        "ratchetTree": BASE64.encode(&ratchet_tree)
    }))
}

#[tauri::command]
async fn load_group(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
) -> Result<bool, String> {
    eprintln!("[MLS] load_group called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;

    if s.groups.contains_key(&group_id) {
        eprintln!("[MLS] load_group: already cached in memory");
        return Ok(true);
    }

    let provider = match s.providers.get(&user_id) {
        Some(p) => p, 
        None => {
            eprintln!("[MLS] load_group: user not initialized: {user_id}");
            return Err(format!("User not initialized: {user_id}"));
        }
    };

    debug_dump_group_data(&s.db_path, &user_id, "load_group");

    let mls_group_id = GroupId::from_slice(group_id.as_bytes());
    match MlsGroup::load(provider.storage(), &mls_group_id) {
        Ok(Some(group)) => {
            eprintln!("[MLS] load_group: loaded from SQLite OK");
            s.groups.insert(group_id, group);
            Ok(true)
        }
        Ok(None) => {
            eprintln!("[MLS] load_group: not found in SQLite (Ok(None))");
            Ok(false)
        }
        Err(e) => {
            eprintln!("[MLS] load_group: SQLite load error: {e:?}");
            Ok(false)
        }
    }
}

#[tauri::command]
async fn join_group(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    welcome_b64: String,
    ratchet_tree_b64: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] join_group called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;

    if s.groups.contains_key(&group_id) {
        return Ok(serde_json::json!({ "groupId": group_id }));
    }

    let provider = s.providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;

    let welcome_bytes = BASE64.decode(&welcome_b64)
        .map_err(|e| format!("Invalid base64 welcome: {e}"))?;
    let ratchet_tree_bytes = BASE64.decode(&ratchet_tree_b64)
        .map_err(|e| format!("Invalid base64 ratchet tree: {e}"))?;

    let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize welcome: {e:?}"))?;

    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(w) => w,
        _ => return Err("Expected Welcome message".into()),
    };

    let ratchet_tree = RatchetTreeIn::tls_deserialize(&mut ratchet_tree_bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize ratchet tree: {e:?}"))?;

    let staged = StagedWelcome::new_from_welcome(
        provider,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(ratchet_tree),
    )
    .map_err(|e| format!("Failed to create staged welcome: {e:?}"))?;

    let group = staged
        .into_group(provider)
        .map_err(|e| format!("Failed to join group: {e:?}"))?;

    // Use the MLS-internal group_id as the canonical key (sender's ULID)
    let actual_group_id = String::from_utf8(group.group_id().as_slice().to_vec())
        .map_err(|e| format!("Group ID is not valid UTF-8: {e}"))?;
    eprintln!("[MLS] join_group: MLS group_id={actual_group_id} (passed={group_id})");

    s.groups.insert(actual_group_id.clone(), group);
    Ok(serde_json::json!({ "groupId": actual_group_id }))
}

#[tauri::command]
async fn encrypt(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    plaintext: String,
) -> Result<String, String> {
    eprintln!("[MLS] encrypt called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;
    let MlsState { providers, credentials, groups, .. } = &mut *s;

    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (_, signer) = credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;
    let group = groups.get_mut(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let mls_message_out = group
        .create_message(provider, signer, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {e:?}"))?;

    let serialized = mls_message_out
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    Ok(BASE64.encode(&serialized))
}

#[tauri::command]
async fn decrypt(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    ciphertext_b64: String,
) -> Result<Option<String>, String> {
    eprintln!("[MLS] decrypt called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;
    let MlsState { providers, groups, .. } = &mut *s;

    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let group = groups.get_mut(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let ciphertext_bytes = BASE64.decode(&ciphertext_b64)
        .map_err(|e| format!("Invalid base64 ciphertext: {e}"))?;

    let mls_message_in = MlsMessageIn::tls_deserialize(&mut ciphertext_bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize message: {e:?}"))?;

    let protocol_message: ProtocolMessage = match mls_message_in.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m.into(),
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        _ => return Err("Unexpected message type".into()),
    };

    let processed = group
        .process_message(provider, protocol_message)
        .map_err(|e| {
            log::warn!("Decryption failed: {e:?}");
            format!("Decryption failed: {e:?}")
        })?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app_msg) => {
            let bytes = app_msg.into_bytes();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            Ok(Some(text))
        }
        ProcessedMessageContent::StagedCommitMessage(_) => {
            group.merge_pending_commit(provider)
                .map_err(|e| format!("Failed to merge commit: {e:?}"))?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

#[tauri::command]
async fn add_member(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    key_package_b64: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] add_member called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;
    let MlsState { providers, credentials, groups, .. } = &mut *s;

    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (_, signer) = credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;
    let group = groups.get_mut(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let kp_bytes = BASE64.decode(&key_package_b64)
        .map_err(|e| format!("Invalid base64 key package: {e}"))?;

    let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize key package: {e:?}"))?;

    let key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("Failed to validate key package: {e:?}"))?;

    let (_mls_message_out, welcome_out, _group_info) = group
        .add_members(provider, signer, &[key_package])
        .map_err(|e| format!("Failed to add member: {e:?}"))?;

    group.merge_pending_commit(provider)
        .map_err(|e| format!("Failed to merge pending commit: {e:?}"))?;

    let welcome_serialized = welcome_out
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    let ratchet_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    Ok(serde_json::json!({
        "welcome": BASE64.encode(&welcome_serialized),
        "ratchetTree": BASE64.encode(&ratchet_tree)
    }))
}

#[tauri::command]
async fn export_ratchet_tree(
    state: tauri::State<'_, Mutex<MlsState>>,
    _user_id: String,
    group_id: String,
) -> Result<String, String> {
    let s = state.lock().await;

    let group = s.groups.get(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let ratchet_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    Ok(BASE64.encode(&ratchet_tree))
}

#[tauri::command]
async fn create_key_package(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] create_key_package called for: {user_id}");
    let s = state.lock().await;

    let provider = s.providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (credential_with_key, signer) = s.credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;

    let bundle = KeyPackage::builder()
        .build(CIPHERSUITE, provider, signer, credential_with_key.clone())
        .map_err(|e| format!("Failed to create key package: {e:?}"))?;

    let serialized = bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;

    Ok(serde_json::json!({
        "keyPackageBytes": BASE64.encode(&serialized)
    }))
}

#[tauri::command]
async fn delete_group(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
) -> Result<(), String> {
    eprintln!("[MLS] delete_group called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;

    // Remove from in-memory cache first
    let cached = s.groups.remove(&group_id);

    let provider = s.providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;

    if let Some(mut group) = cached {
        group.delete(provider.storage())
            .map_err(|e| format!("Failed to delete group from storage: {e:?}"))?;
        eprintln!("[MLS] delete_group: removed from cache + storage");
    } else {
        // Not in cache — try loading from SQLite to delete it
        let group_id_bytes = group_id.as_bytes();
        if let Some(mut group) = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(group_id_bytes),
        ).map_err(|e| format!("Storage error: {e:?}"))? {
            group.delete(provider.storage())
                .map_err(|e| format!("Failed to delete group from storage: {e:?}"))?;
            eprintln!("[MLS] delete_group: loaded from SQLite and deleted");
        } else {
            eprintln!("[MLS] delete_group: group not found (nothing to delete)");
        }
    }

    Ok(())
}

// ── Emoji fingerprint table (350 emojis, 5 per fingerprint ≈ 42.3 bits) ──
// Based on Matrix SAS set + curated visually-distinct additions.

const FINGERPRINT_EMOJIS: [[&str; 2]; 350] = [
  ["🐶", "Dog"], ["🐱", "Cat"], ["🦁", "Lion"],
  ["🐎", "Horse"], ["🦄", "Unicorn"], ["🐷", "Pig"],
  ["🐘", "Elephant"], ["🐰", "Rabbit"], ["🐼", "Panda"],
  ["🐓", "Rooster"], ["🐧", "Penguin"], ["🐢", "Turtle"],
  ["🐟", "Fish"], ["🐙", "Octopus"], ["🦋", "Butterfly"],
  ["🌷", "Flower"], ["🌳", "Tree"], ["🌵", "Cactus"],
  ["🍄", "Mushroom"], ["🌏", "Globe"], ["🌙", "Moon"],
  ["☁️", "Cloud"], ["🔥", "Fire"], ["🍌", "Banana"],
  ["🍎", "Apple"], ["🍓", "Strawberry"], ["🌽", "Corn"],
  ["🍕", "Pizza"], ["🎂", "Cake"], ["❤️", "Heart"],
  ["😀", "Smiley"], ["🤖", "Robot"], ["🎩", "Hat"],
  ["👓", "Glasses"], ["🔧", "Spanner"], ["🎅", "Santa"],
  ["👍", "Thumbs Up"], ["☂️", "Umbrella"], ["⌛", "Hourglass"],
  ["⏰", "Clock"], ["🎁", "Gift"], ["💡", "Light Bulb"],
  ["📕", "Book"], ["✏️", "Pencil"], ["📎", "Paperclip"],
  ["✂️", "Scissors"], ["🔒", "Lock"], ["🔑", "Key"],
  ["🔨", "Hammer"], ["☎️", "Telephone"], ["🏁", "Flag"],
  ["🚂", "Train"], ["🚲", "Bicycle"], ["✈️", "Aeroplane"],
  ["🚀", "Rocket"], ["🏆", "Trophy"], ["⚽", "Ball"],
  ["🎸", "Guitar"], ["🎺", "Trumpet"], ["🔔", "Bell"],
  ["⚓", "Anchor"], ["🎧", "Headphones"], ["📁", "Folder"],
  ["📌", "Pin"], ["0️⃣", "Zero"], ["1️⃣", "One"],
  ["2️⃣", "Two"], ["3️⃣", "Three"], ["4️⃣", "Four"],
  ["5️⃣", "Five"], ["6️⃣", "Six"], ["7️⃣", "Seven"],
  ["8️⃣", "Eight"], ["9️⃣", "Nine"], ["♻️", "Recycle"],
  ["⚡", "Lightning"], ["💎", "Diamond"], ["🌈", "Rainbow"],
  ["❄️", "Snowflake"], ["🌊", "Wave"], ["🎲", "Dice"],
  ["🧲", "Magnet"], ["🪐", "Saturn"], ["🌋", "Volcano"],
  ["⭐", "Star"], ["🐬", "Dolphin"], ["🦊", "Fox"],
  ["🦉", "Owl"], ["🏔️", "Mountain"], ["🧊", "Ice"],
  ["🎯", "Target"], ["🛡️", "Shield"], ["⚙️", "Gear"],
  ["🔱", "Trident"], ["🦀", "Crab"], ["🦈", "Shark"],
  ["🐸", "Frog"], ["🦩", "Flamingo"], ["🦜", "Parrot"],
  ["🐍", "Snake"], ["🦞", "Lobster"], ["🐪", "Camel"],
  ["🦒", "Giraffe"], ["🐊", "Crocodile"], ["🍉", "Watermelon"],
  ["🍇", "Grapes"], ["🍒", "Cherry"], ["🥥", "Coconut"],
  ["🌶️", "Chilli"], ["🧀", "Cheese"], ["🍩", "Donut"],
  ["🧁", "Cupcake"], ["🍿", "Popcorn"], ["🏠", "House"],
  ["🏰", "Castle"], ["⛵", "Sailboat"], ["🚁", "Helicopter"],
  ["🛸", "UFO"], ["🎭", "Theatre"], ["🎪", "Circus"],
  ["🎈", "Balloon"], ["🧩", "Puzzle"], ["🪁", "Kite"],
  ["🏹", "Bow"], ["🪴", "Plant"], ["🌻", "Sunflower"],
  ["🌴", "Palm"], ["🍂", "Leaf"], ["🐚", "Shell"],
  ["🦎", "Lizard"], ["🦭", "Seal"], ["🦔", "Hedgehog"],
  ["🦚", "Peacock"], ["🐞", "Ladybug"], ["🕷️", "Spider"],
  ["🎱", "Billiards"], ["🛶", "Canoe"], ["🎻", "Violin"],
  ["🥁", "Drum"], ["🎤", "Microphone"], ["🔭", "Telescope"],
  ["🔬", "Microscope"], ["💊", "Pill"], ["🧬", "DNA"],
  ["🧪", "Test Tube"], ["🕯️", "Candle"], ["💰", "Money Bag"],
  ["👑", "Crown"], ["🪶", "Feather"], ["⛏️", "Pickaxe"],
  ["🪨", "Rock"], ["🏮", "Lantern"], ["🎀", "Ribbon"],
  ["🪵", "Log"], ["🛞", "Wheel"], ["🪜", "Ladder"],
  ["🧯", "Extinguisher"], ["🎓", "Graduation"], ["💍", "Ring"],
  ["🩺", "Stethoscope"], ["🪃", "Boomerang"], ["🏺", "Amphora"],
  ["🗿", "Moai"], ["🗽", "Liberty"], ["⛩️", "Shrine"],
  ["🕌", "Mosque"], ["🎡", "Ferris Wheel"], ["🎢", "Roller Coaster"],
  ["🚢", "Ship"], ["🛰️", "Satellite"], ["🌠", "Shooting Star"],
  ["🌀", "Cyclone"], ["🔮", "Crystal Ball"], ["🪩", "Mirror Ball"],
  ["🎵", "Music"], ["🕹️", "Joystick"], ["🖨️", "Printer"],
  ["💾", "Floppy"], ["🔋", "Battery"], ["📡", "Dish"],
  ["🏋️", "Weightlifter"], ["🤿", "Diving"], ["🛹", "Skateboard"],
  ["🧳", "Suitcase"], ["🪝", "Hook"], ["🧸", "Teddy Bear"],
  ["🎏", "Carp Streamer"], ["🏕️", "Camping"], ["🗺️", "World Map"],
  ["🧶", "Yarn"], ["🎐", "Wind Chime"], ["🦇", "Bat"],
  ["🛒", "Cart"], ["🦷", "Tooth"], ["🫀", "Heart Organ"],
  ["🧠", "Brain"], ["👁️", "Eye"], ["🦴", "Bone"],
  ["🪸", "Coral"], ["🐌", "Snail"], ["🦂", "Scorpion"],
  ["🕊️", "Dove"], ["🦙", "Llama"], ["🦘", "Kangaroo"],
  ["🦫", "Beaver"], ["🦦", "Otter"], ["🦥", "Sloth"],
  ["🍑", "Peach"], ["🥝", "Kiwi"], ["🥑", "Avocado"],
  ["🥕", "Carrot"], ["🥨", "Pretzel"], ["🥐", "Croissant"],
  ["🍭", "Lollipop"], ["🫐", "Blueberry"], ["🥦", "Broccoli"],
  ["🌰", "Chestnut"], ["🥜", "Peanut"], ["🍯", "Honey"],
  ["🧂", "Salt"], ["🫖", "Teapot"], ["🍵", "Tea"],
  ["🧃", "Juice Box"], ["🪘", "Long Drum"], ["🎷", "Saxophone"],
  ["🎹", "Piano"], ["🪗", "Accordion"], ["🏗️", "Crane"],
  ["🗼", "Tower"], ["⛲", "Fountain"], ["🎠", "Carousel"],
  ["🛥️", "Speedboat"], ["🚜", "Tractor"], ["🚒", "Fire Engine"],
  ["🚑", "Ambulance"], ["🛴", "Scooter"], ["🪂", "Parachute"],
  ["🏄", "Surfer"], ["⛷️", "Skier"], ["🏊", "Swimmer"],
  ["🛷", "Sled"], ["🧨", "Firecracker"], ["🎃", "Pumpkin"],
  ["🎳", "Bowling"], ["🏓", "Ping Pong"], ["🥊", "Boxing"],
  ["🏒", "Hockey"], ["🎿", "Ski"], ["🪀", "Yo-Yo"],
  ["🛼", "Roller Skate"], ["🧗", "Climber"], ["🏇", "Jockey"],
  ["🪈", "Flute"], ["📯", "Horn"], ["🎙️", "Studio Mic"],
  ["📻", "Radio"], ["📺", "Television"], ["🖥️", "Desktop"],
  ["💿", "CD"], ["🔦", "Flashlight"], ["🪫", "Low Battery"],
  ["🧰", "Toolbox"], ["🪚", "Saw"], ["🔩", "Nut & Bolt"],
  ["🧱", "Brick"], ["⛓️", "Chain"], ["🪣", "Bucket"],
  ["🪦", "Headstone"], ["🔗", "Link"], ["🪟", "Window"],
  ["🚪", "Door"], ["🛏️", "Bed"], ["🪑", "Chair"],
  ["🚿", "Shower"], ["🧴", "Lotion"], ["🧽", "Sponge"],
  ["🕶️", "Sunglasses"], ["🥾", "Boot"], ["👒", "Sun Hat"],
  ["🧤", "Gloves"], ["🧣", "Scarf"], ["👔", "Necktie"],
  ["👗", "Dress"], ["🩰", "Ballet"], ["🪭", "Fan"],
  ["💄", "Lipstick"], ["💈", "Barber Pole"], ["🔍", "Magnifier"],
  ["📿", "Prayer Beads"], ["🪬", "Hamsa"], ["♟️", "Chess Pawn"],
  ["🀄", "Mahjong"], ["🃏", "Joker"], ["🖼️", "Frame"],
  ["🪆", "Nesting Doll"], ["🏷️", "Label"], ["📮", "Postbox"],
  ["🗑️", "Wastebasket"], ["🚩", "Red Flag"], ["🏴‍☠️", "Pirate Flag"],
  ["🪧", "Placard"], ["📬", "Mailbox"], ["🪙", "Coin"],
  ["💳", "Credit Card"], ["📐", "Triangle Ruler"], ["🗓️", "Calendar"],
  ["📊", "Bar Chart"], ["🔖", "Bookmark"], ["🏵️", "Rosette"],
  ["🎗️", "Reminder Ribbon"], ["🪢", "Knot"], ["🩻", "X-Ray"],
  ["🪪", "ID Card"], ["🛗", "Elevator"], ["🚦", "Traffic Light"],
  ["⛽", "Fuel Pump"], ["🚧", "Construction"], ["🛟", "Ring Buoy"],
  ["🪔", "Diya Lamp"], ["🎑", "Moon Viewing"], ["🧧", "Red Envelope"],
  ["🎍", "Bamboo"], ["🪷", "Lotus"], ["🍁", "Maple Leaf"],
  ["☘️", "Shamrock"], ["🦠", "Microbe"], ["🪺", "Nest"],
  ["🧮", "Abacus"], ["📣", "Megaphone"], ["🏅", "Medal"],
  ["⛺", "Tent"], ["🫧", "Soap Bubble"], ["🏳️‍🌈", "Pride Flag"],
  ["🏳️‍⚧️", "Transgender Flag"], ["🏴", "Black Flag"], ["🇯🇵", "Japan"],
  ["🇧🇷", "Brazil"], ["🇨🇦", "Canada"], ["☀️", "Sun"],
  ["🌕", "Full Moon"], ["🔰", "Beginner"], ["♾️", "Infinity"],
  ["🏝️", "Island"], ["🌾", "Rice"], ["🫶", "Heart Hands"],
  ["🦤", "Dodo"], ["🫏", "Donkey"], ["🐉", "Dragon"],
  ["🦬", "Bison"], ["🪻", "Hyacinth"]
];

/// Convert a signature key to a 5-emoji fingerprint (~42.3 bits of entropy).
/// SHA-256 the key, use 2-byte windows modulo 350 for each of 5 emoji indices.
fn signature_key_to_emoji_fingerprint(sig_key: &[u8]) -> Vec<[&str; 2]> {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(sig_key);
    (0..5).map(|i| {
        let idx = u16::from_be_bytes([hash[i * 2], hash[i * 2 + 1]]) as usize
                  % 350;
        FINGERPRINT_EMOJIS[idx]
    }).collect()
}

/// Shared helper: remove leaves by index, merge commit, return serialized commit.
fn do_remove_leaves(
    provider: &TauriOpenMLSProvider,
    signer: &SignatureKeyPair,
    group: &mut MlsGroup,
    indexes: &[LeafNodeIndex],
) -> Result<(String, usize), String> {
    let count = indexes.len();
    let (commit, _welcome, _group_info) = group
        .remove_members(provider, signer, indexes)
        .map_err(|e| format!("Failed to remove members: {e:?}"))?;
    group.merge_pending_commit(provider)
        .map_err(|e| format!("Failed to merge commit: {e:?}"))?;
    let commit_bytes = commit
        .tls_serialize_detached()
        .map_err(|e| format!("Serialization error: {e:?}"))?;
    Ok((BASE64.encode(&commit_bytes), count))
}

/// Remove specific clients (leaf nodes) from a group by leaf index.
#[tauri::command]
async fn remove_group_member_client(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    leaf_indexes: Vec<u32>,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] remove_group_member_client called: user={user_id}, group={group_id}, indexes={leaf_indexes:?}");
    let mut s = state.lock().await;

    if !s.confirm("Remove Client", "Remove this client from the group?") {
        return Ok(serde_json::json!({ "cancelled": true }));
    }
    let MlsState { providers, credentials, groups, .. } = &mut *s;

    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (_, signer) = credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;
    let group = groups.get_mut(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let indexes: Vec<LeafNodeIndex> = leaf_indexes.iter()
        .map(|&i| LeafNodeIndex::new(i)).collect();

    let (commit_b64, count) = do_remove_leaves(provider, signer, group, &indexes)?;
    eprintln!("[MLS] remove_group_member_client: removed {count} leaf(s) from group {group_id}");
    Ok(serde_json::json!({ "commit": commit_b64 }))
}

/// Remove all clients of a given actor (member_id) from a group.
/// Resolves leaf indexes internally by matching member identity.
#[tauri::command]
async fn remove_group_member(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
    member_id: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] remove_group_member called: user={user_id}, group={group_id}, member={member_id}");
    let mut s = state.lock().await;

    if !s.confirm("Remove Member", &format!("Remove {member_id} and all their devices from this group?")) {
        return Ok(serde_json::json!({ "cancelled": true }));
    }
    let MlsState { providers, credentials, groups, .. } = &mut *s;

    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (_, signer) = credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;
    let group = groups.get_mut(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let indexes: Vec<LeafNodeIndex> = group.members()
        .filter(|m| {
            String::from_utf8(m.credential.serialized_content().to_vec())
                .unwrap_or_default() == member_id
        })
        .map(|m| m.index)
        .collect();

    if indexes.is_empty() {
        return Err(format!("Member not found in group: {member_id}"));
    }

    let (commit_b64, count) = do_remove_leaves(provider, signer, group, &indexes)?;
    eprintln!("[MLS] remove_group_member: removed {count} leaf(s) of {member_id} from group {group_id}");
    Ok(serde_json::json!({ "commit": commit_b64, "removedCount": count }))
}

/// Decommission a client (by signature key) from all loaded groups.
/// Shows a single native confirmation dialog, then removes the matching
/// leaf from every group. Returns a list of {groupId, commit} for the caller
/// to distribute.
#[tauri::command]
async fn decommission_client(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    signature_key: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] decommission_client called: user={user_id}, sig_key={}", &signature_key[..12.min(signature_key.len())]);
    let mut s = state.lock().await;

    let target_key = BASE64.decode(&signature_key)
        .map_err(|e| format!("Invalid base64 signature key: {e}"))?;

    // Find all groups containing a matching own-client leaf
    let group_ids: Vec<String> = s.groups.iter()
        .filter(|(_gid, group)| {
            group.members().any(|m| {
                let identity = String::from_utf8(m.credential.serialized_content().to_vec())
                    .unwrap_or_default();
                identity == user_id && m.signature_key.as_slice() == target_key.as_slice()
            })
        })
        .map(|(gid, _)| gid.clone())
        .collect();

    if group_ids.is_empty() {
        return Ok(serde_json::json!({ "results": [], "cancelled": false }));
    }

    if !s.confirm(
        "Decommission Device",
        &format!("Remove this device from {} group{}?", group_ids.len(), if group_ids.len() != 1 { "s" } else { "" }),
    ) {
        return Ok(serde_json::json!({ "cancelled": true }));
    }

    let MlsState { providers, credentials, groups, .. } = &mut *s;
    let provider = providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;
    let (_, signer) = credentials.get(&user_id)
        .ok_or_else(|| format!("No credentials for: {user_id}"))?;

    // Detect if the target is the current client (same signature key as our signer)
    let is_self = signer.public() == target_key.as_slice();

    let mut results = Vec::new();
    for gid in &group_ids {
        let group = match groups.get_mut(gid) {
            Some(g) => g,
            None => continue,
        };

        if is_self {
            // Can't use remove_members on self — use leave_group instead
            match group.leave_group(provider, signer) {
                Ok(msg) => {
                    match msg.tls_serialize_detached() {
                        Ok(bytes) => {
                            eprintln!("[MLS] decommission_client: left group {gid} (self-remove proposal)");
                            results.push(serde_json::json!({ "groupId": gid, "commit": BASE64.encode(&bytes), "isSelfRemove": true }));
                        }
                        Err(e) => {
                            eprintln!("[MLS] decommission_client: serialize failed for group {gid}: {e:?}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[MLS] decommission_client: leave_group failed for {gid}: {e:?}");
                }
            }
        } else {
            let indexes: Vec<LeafNodeIndex> = group.members()
                .filter(|m| {
                    let identity = String::from_utf8(m.credential.serialized_content().to_vec())
                        .unwrap_or_default();
                    identity == user_id && m.signature_key.as_slice() == target_key.as_slice()
                })
                .map(|m| m.index)
                .collect();
            if indexes.is_empty() { continue; }

            match do_remove_leaves(provider, signer, group, &indexes) {
                Ok((commit_b64, count)) => {
                    eprintln!("[MLS] decommission_client: removed {count} leaf(s) from group {gid}");
                    results.push(serde_json::json!({ "groupId": gid, "commit": commit_b64 }));
                }
                Err(e) => {
                    eprintln!("[MLS] decommission_client: failed for group {gid}: {e}");
                }
            }
        }
    }

    Ok(serde_json::json!({ "results": results, "cancelled": false }))
}

/// Decommission current client from all groups, back up and delete the MLS database.
/// Returns { results: [{groupId, commit, isSelfRemove}], cancelled: bool }
#[tauri::command]
async fn clear_all_data(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
) -> Result<serde_json::Value, String> {
    eprintln!("[MLS] clear_all_data called for: {user_id}");
    let mut s = state.lock().await;

    // Confirm with native dialog
    if !s.confirm(
        "Clear All Data",
        "This will remove your device from all groups and delete all encryption keys and message history. You will need to log in again.",
    ) {
        return Ok(serde_json::json!({ "results": [], "cancelled": true }));
    }

    // Decommission: leave all groups
    let mut results = Vec::new();
    let own_sig_key = s.credentials.get(&user_id)
        .map(|(_, sk)| sk.public().to_vec());

    if let Some(target_key) = &own_sig_key {
        let group_ids: Vec<String> = s.groups.keys().cloned().collect();

        let MlsState { providers, credentials, groups, .. } = &mut *s;
        if let (Some(provider), Some((_, signer))) = (providers.get(&user_id), credentials.get(&user_id)) {
            for gid in &group_ids {
                let group = match groups.get_mut(gid) {
                    Some(g) => g,
                    None => continue,
                };

                // Current client → leave_group (self-remove proposal)
                let is_self = signer.public() == target_key.as_slice();
                if is_self {
                    match group.leave_group(provider, signer) {
                        Ok(msg) => {
                            if let Ok(bytes) = msg.tls_serialize_detached() {
                                eprintln!("[MLS] clear_all_data: left group {gid}");
                                results.push(serde_json::json!({
                                    "groupId": gid, "commit": BASE64.encode(&bytes), "isSelfRemove": true
                                }));
                            }
                        }
                        Err(e) => eprintln!("[MLS] clear_all_data: leave failed for {gid}: {e:?}"),
                    }
                }
            }
        }
    }

    // Clear in-memory state
    s.providers.remove(&user_id);
    s.credentials.remove(&user_id);
    s.groups.clear();

    // Back up then delete the SQLite database file
    let user_db = s.db_path.join(format!("mls_{}.db", sanitize_filename(&user_id)));
    if user_db.exists() {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let backup = s.db_path.join(format!(
            "mls_{}.db.bak.{timestamp}", sanitize_filename(&user_id)
        ));
        std::fs::rename(&user_db, &backup)
            .map_err(|e| format!("Failed to back up MLS database: {e}"))?;
        eprintln!("[MLS] clear_all_data: backed up to {}", backup.display());
    }

    Ok(serde_json::json!({ "results": results, "cancelled": false }))
}

/// Get emoji fingerprints for all members in a group.
/// Returns [{identity, fingerprint, isOwn, index, signatureKey, isCurrentClient}]
#[tauri::command]
async fn get_group_fingerprints(
    state: tauri::State<'_, Mutex<MlsState>>,
    user_id: String,
    group_id: String,
) -> Result<Vec<serde_json::Value>, String> {
    let s = state.lock().await;

    let group = s.groups.get(&group_id)
        .ok_or_else(|| format!("Group not loaded: {group_id}"))?;

    let own_sig_key = s.credentials.get(&user_id)
        .map(|(_, sk)| sk.public().to_vec());

    let mut result = Vec::new();
    for member in group.members() {
        let identity = String::from_utf8(member.credential.serialized_content().to_vec())
            .unwrap_or_else(|_| BASE64.encode(member.credential.serialized_content()));
        let emojis = signature_key_to_emoji_fingerprint(member.signature_key.as_slice());
        let fingerprint: Vec<serde_json::Value> = emojis.into_iter()
            .map(|[emoji, desc]| serde_json::json!({ "emoji": emoji, "description": desc }))
            .collect();
        let is_own = identity == user_id;
        let member_sig_key = member.signature_key.as_slice();
        let is_current_client = is_own
            && own_sig_key.as_deref() == Some(member_sig_key);
        result.push(serde_json::json!({
            "identity": identity,
            "fingerprint": fingerprint,
            "isOwn": is_own,
            "index": member.index.u32(),
            "signatureKey": BASE64.encode(member.signature_key.as_slice()),
            "isCurrentClient": is_current_client,
        }));
    }

    Ok(result)
}

/// Extract the MLS group_id from a ciphertext blob without decrypting.
/// Works for PrivateMessage and PublicMessage (the group_id is in the framing header).
/// Returns null for Welcome messages (group_id is encrypted inside).
#[tauri::command]
async fn extract_group_id(
    message_b64: String,
) -> Result<Option<String>, String> {
    let bytes = BASE64.decode(&message_b64)
        .map_err(|e| format!("Invalid base64: {e}"))?;

    let mls_message_in = MlsMessageIn::tls_deserialize(&mut bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize MLS message: {e:?}"))?;

    match mls_message_in.extract() {
        MlsMessageBodyIn::PrivateMessage(m) => {
            let pm: ProtocolMessage = m.into();
            let gid = String::from_utf8(pm.group_id().as_slice().to_vec())
                .map_err(|e| format!("Group ID is not valid UTF-8: {e}"))?;
            Ok(Some(gid))
        }
        MlsMessageBodyIn::PublicMessage(m) => {
            let pm: ProtocolMessage = m.into();
            let gid = String::from_utf8(pm.group_id().as_slice().to_vec())
                .map_err(|e| format!("Group ID is not valid UTF-8: {e}"))?;
            Ok(Some(gid))
        }
        // Welcome messages don't expose group_id without processing
        _ => Ok(None),
    }
}

// ── Plugin entry point ─────────────────────────────────────────────

/// Initialize the OpenMLS plugin. Register with `.plugin(tauri_plugin_openmls::init())`.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::<R>::new("openmls")
        .invoke_handler(tauri::generate_handler![
            init_user,
            create_group,
            load_group,
            join_group,
            delete_group,
            encrypt,
            decrypt,
            add_member,
            remove_group_member_client,
            remove_group_member,
            decommission_client,
            clear_all_data,
            export_ratchet_tree,
            create_key_package,
            extract_group_id,
            get_group_fingerprints,
        ])
        .setup(|app, _api| {
            let db_path = app.path().app_data_dir()
                .expect("Failed to resolve app data dir");
            std::fs::create_dir_all(&db_path)
                .expect("Failed to create app data dir");
            eprintln!("[MLS] Plugin setup complete, db_path: {}", db_path.display());
            let mut state = MlsState::new(db_path);
            state.app_handle = Some(std::sync::Arc::new(app.clone()));
            app.manage(Mutex::new(state));
            Ok(())
        })
        .build()
}
