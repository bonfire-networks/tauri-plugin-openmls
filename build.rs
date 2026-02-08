const COMMANDS: &[&str] = &[
    "init_user",
    "create_group",
    "load_group",
    "join_group",
    "encrypt",
    "decrypt",
    "add_member",
    "export_ratchet_tree",
    "create_key_package",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS).build();
}
