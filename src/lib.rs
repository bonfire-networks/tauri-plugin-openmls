//! Native OpenMLS backend for the Bonfire Tauri app.
//!
//! Provides a Tauri plugin ("openmls") that implements the same MLS backend
//! interface as the WASM version (`mls-backend.js`), using SQLite for
//! persistent storage.
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
    providers: HashMap<String, TauriOpenMLSProvider>,
    credentials: HashMap<String, (CredentialWithKey, SignatureKeyPair)>,
    groups: HashMap<String, MlsGroup>,
}

impl MlsState {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            db_path,
            providers: HashMap::new(),
            credentials: HashMap::new(),
            groups: HashMap::new(),
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
    .map_err(|e| format!("Failed to create group: {e:?}"))?;

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
        eprintln!("[MLS] load_group: already cached");
        return Ok(true);
    }

    let provider = s.providers.get(&user_id)
        .ok_or_else(|| format!("User not initialized: {user_id}"))?;

    let mls_group_id = GroupId::from_slice(group_id.as_bytes());
    match MlsGroup::load(provider.storage(), &mls_group_id) {
        Ok(Some(group)) => {
            s.groups.insert(group_id, group);
            Ok(true)
        }
        Ok(None) => Ok(false),
        Err(e) => {
            log::warn!("Failed to load group {group_id}: {e:?}");
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
) -> Result<(), String> {
    eprintln!("[MLS] join_group called: user={user_id}, group={group_id}");
    let mut s = state.lock().await;

    if s.groups.contains_key(&group_id) {
        return Ok(());
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

    s.groups.insert(group_id, group);
    Ok(())
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

// ── Plugin entry point ─────────────────────────────────────────────

/// Initialize the OpenMLS plugin. Register with `.plugin(tauri_plugin_openmls::init())`.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::<R>::new("openmls")
        .invoke_handler(tauri::generate_handler![
            init_user,
            create_group,
            load_group,
            join_group,
            encrypt,
            decrypt,
            add_member,
            export_ratchet_tree,
            create_key_package,
        ])
        .setup(|app, _api| {
            let db_path = app.path().app_data_dir()
                .expect("Failed to resolve app data dir");
            std::fs::create_dir_all(&db_path)
                .expect("Failed to create app data dir");
            eprintln!("[MLS] Plugin setup complete, db_path: {}", db_path.display());
            app.manage(Mutex::new(MlsState::new(db_path)));
            Ok(())
        })
        .build()
}
