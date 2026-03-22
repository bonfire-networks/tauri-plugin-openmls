const COMMANDS: &[&str] = &[
    "init_user",
    "create_group",
    "load_group",
    "join_group",
    "delete_group",
    "prepare_attachment_bytes",
    "prepare_attachment_file",
    "remove_attachment",
    "encrypt",
    "send_message",
    "discard_message",
    "serve_attachment",
    "decrypt",
    "add_member",
    "export_ratchet_tree",
    "create_key_package",
    "extract_group_id",
    "get_group_member_identities",
    "remove_self_from_group",
    "get_group_fingerprints",
    "remove_group_member_client",
    "remove_group_member",
    "decommission_client",
    "clear_all_data",
    "get_own_fingerprint",
    "get_key_package_fingerprint",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
