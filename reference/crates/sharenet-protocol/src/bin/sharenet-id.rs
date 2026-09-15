//! `sharenet-id` — the ShareNet node identity tool (runtime path of R1-001).
//!
//! A real process performing real file I/O through the `sharenet_protocol::store` API.
//! Exit codes: 0 success, 1 operational failure, 2 usage error. All failures print an
//! actionable message to stderr. The seed is never printed.

use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_protocol::identity::SIGNATURE_LEN;
use sharenet_protocol::store::{load_identity_file, IdentityStore};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("error: {message}");
            code.into()
        }
    }
}

struct Flags {
    dir: Option<String>,
    name: Option<String>,
    payload: Option<PathBuf>,
    identity_file: Option<PathBuf>,
    signature: Option<PathBuf>,
    out: Option<PathBuf>,
}

impl Flags {
    fn new() -> Self {
        Flags {
            dir: None,
            name: None,
            payload: None,
            identity_file: None,
            signature: None,
            out: None,
        }
    }
}

fn run(argv: Vec<String>) -> Result<(), (u8, String)> {
    let mut it = argv.into_iter();
    let _prog = it.next();
    let subcommand = match it.next() {
        Some(s) => s,
        None => {
            usage();
            return Err((2, "a subcommand is required".into()));
        }
    };
    let expected: &[&str] = match subcommand.as_str() {
        "create" => &["--dir", "--name"],
        "show" | "verify" => &["--dir"],
        "sign" => &["--dir", "--payload", "--out"],
        "verify-signature" => &["--identity-file", "--payload", "--signature"],
        other => {
            usage();
            return Err((2, format!("unknown subcommand '{other}'")));
        }
    };

    let mut flags = Flags::new();
    let mut args = it.peekable();
    while let Some(arg) = args.next() {
        let (name, inline_value) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let supported = |f: &str| expected.iter().any(|e| e == &f);
        if !supported(&name) {
            usage();
            return Err((2, format!("unknown argument '{name}' for '{subcommand}'")));
        }
        let value = match inline_value {
            Some(v) => v,
            None => match args.next() {
                Some(v) => v,
                None => return Err((2, format!("'{name}' requires a value"))),
            },
        };
        let set = |slot: &mut Option<String>| -> Result<(), (u8, String)> {
            if slot.is_some() {
                return Err((2, format!("'{name}' given more than once")));
            }
            *slot = Some(value.clone());
            Ok(())
        };
        match name.as_str() {
            "--dir" => set(&mut flags.dir)?,
            "--name" => set(&mut flags.name)?,
            "--payload" => flags.payload = Some(PathBuf::from(value)),
            "--identity-file" => flags.identity_file = Some(PathBuf::from(value)),
            "--signature" => flags.signature = Some(PathBuf::from(value)),
            "--out" => flags.out = Some(PathBuf::from(value)),
            _ => unreachable!("checked against expected"),
        }
    }

    match subcommand.as_str() {
        "create" => cmd_create(flags),
        "show" => cmd_show(flags),
        "verify" => cmd_verify(flags),
        "sign" => cmd_sign(flags),
        "verify-signature" => cmd_verify_signature(flags),
        _ => unreachable!("validated above"),
    }
}

fn cmd_create(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'create' requires --dir".into()))?;
    let store = IdentityStore::new(&dir);
    let id = store
        .create(f.name.as_deref())
        .map_err(|e| (1, e.to_string()))?;
    println!("node_id: {}", id.node_id());
    println!("identity_file: {}", store.identity_path().display());
    println!("created identity at 0600 permissions (seed never displayed)");
    Ok(())
}

fn cmd_show(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'show' requires --dir".into()))?;
    let store = IdentityStore::new(&dir);
    let id = store.load().map_err(|e| (1, e.to_string()))?;
    let node = id.node_identity();
    println!("node_id: {}", id.node_id());
    println!(
        "public_key: {}",
        sharenet_protocol::identity::to_hex(&node.public_key_bytes())
    );
    println!(
        "scheme_version: {}",
        sharenet_protocol::identity::SCHEME_VERSION
    );
    println!("created_at_unix: {}", node.created_at_unix());
    println!("display_name: {}", node.display_name().unwrap_or("<none>"));
    Ok(())
}

fn cmd_verify(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'verify' requires --dir".into()))?;
    let store = IdentityStore::new(&dir);
    let id = store.load().map_err(|e| (1, e.to_string()))?;
    println!("identity file OK");
    println!("node_id: {}", id.node_id());
    Ok(())
}

fn cmd_sign(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'sign' requires --dir".into()))?;
    let payload_path = f.payload.ok_or((2, "'sign' requires --payload".into()))?;
    let store = IdentityStore::new(&dir);
    let id = store.load().map_err(|e| (1, e.to_string()))?;
    let payload = std::fs::read(&payload_path).map_err(|e| {
        (
            1,
            format!("failed to read payload {}: {e}", payload_path.display()),
        )
    })?;
    let sig = id.sign_detached(&payload);
    let sig_path = f.out.unwrap_or_else(|| {
        let mut p = payload_path.clone().into_os_string();
        p.push(".sig");
        PathBuf::from(p)
    });
    std::fs::write(&sig_path, sig).map_err(|e| {
        (
            1,
            format!("failed to write signature {}: {e}", sig_path.display()),
        )
    })?;
    println!("signature_file: {}", sig_path.display());
    println!("node_id: {}", id.node_id());
    println!("payload_bytes: {}", payload.len());
    println!("signature_bytes: {SIGNATURE_LEN}");
    Ok(())
}

fn cmd_verify_signature(f: Flags) -> Result<(), (u8, String)> {
    let identity_file = f
        .identity_file
        .ok_or((2, "'verify-signature' requires --identity-file".into()))?;
    let payload_path = f
        .payload
        .ok_or((2, "'verify-signature' requires --payload".into()))?;
    let sig_path = f
        .signature
        .ok_or((2, "'verify-signature' requires --signature".into()))?;
    let id = load_identity_file(&identity_file).map_err(|e| (1, e.to_string()))?;
    let payload = std::fs::read(&payload_path).map_err(|e| {
        (
            1,
            format!("failed to read payload {}: {e}", payload_path.display()),
        )
    })?;
    let sig = std::fs::read(&sig_path).map_err(|e| {
        (
            1,
            format!("failed to read signature {}: {e}", sig_path.display()),
        )
    })?;
    id.node_identity()
        .verify_detached(&payload, &sig)
        .map_err(|e| (1, format!("signature verification failed: {e}")))?;
    println!("signature OK");
    println!("node_id: {}", id.node_id());
    Ok(())
}

fn usage() {
    eprintln!(
        "sharenet-id — ShareNet node identity tool (protocol core R1-001)

USAGE:
    sharenet-id <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    create --dir <DIR> [--name <NAME>]
        Generate a fresh Ed25519 identity and write it to <DIR>/identity.cbor
        (atomic write, 0600). Refuses to overwrite an existing identity.

    show --dir <DIR>
        Print node_id, public key, created_at, display name. Never prints the seed.

    verify --dir <DIR>
        Strictly re-validate the identity file (fails closed on any tamper,
        corruption, or loose permissions).

    sign --dir <DIR> --payload <FILE> [--out <FILE>]
        Detached-sign the payload with the node key (Ed25519, RFC 8032).
        Default signature output: <payload>.sig. Prints the node_id.

    verify-signature --identity-file <FILE> --payload <FILE> --signature <FILE>
        Verify a detached signature against the identity file's public key.

EXIT CODES: 0 success, 1 operational failure, 2 usage error."
    );
}
