//! `sharenet-id` — the ShareNet node identity tool (runtime path of R1-001).
//!
//! A real process performing real file I/O through the `sharenet_protocol::store` API.
//! Exit codes: 0 success, 1 operational failure, 2 usage error. All failures print an
//! actionable message to stderr. The seed is never printed.
//!
//! `capabilities` / `verify-capabilities` (R1-004) are the signed-capability
//! runtime path: they build, sign and admit real `CapabilityStatement` objects
//! through the same protocol-core API the future daemon will use at startup.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use sharenet_protocol::capability::{admit, Capability, CapabilityStatement};
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
    // R1-004
    caps: Vec<String>,
    limits: Vec<String>,
    require: Vec<String>,
    validity_secs: Option<u64>,
    issued_at: Option<u64>,
    now: Option<u64>,
    public_key: Option<String>,
    statement: Option<String>,
    out_statement: Option<PathBuf>,
    out_signature: Option<PathBuf>,
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
            caps: Vec::new(),
            limits: Vec::new(),
            require: Vec::new(),
            validity_secs: None,
            issued_at: None,
            now: None,
            public_key: None,
            statement: None,
            out_statement: None,
            out_signature: None,
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
        "capabilities" => &[
            "--dir",
            "--capability",
            "--limit",
            "--validity-secs",
            "--issued-at",
            "--out-statement",
            "--out-signature",
        ],
        "verify-capabilities" => &[
            "--statement",
            "--signature",
            "--public-key",
            "--identity-file",
            "--now",
            "--require",
        ],
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
            "--capability" => flags.caps.push(value),
            "--limit" => flags.limits.push(value),
            "--require" => flags.require.push(value),
            "--validity-secs" => {
                flags.validity_secs = Some(
                    value
                        .parse()
                        .map_err(|_| (2, format!("--validity-secs must be a number: {value}")))?,
                )
            }
            "--issued-at" => {
                flags.issued_at = Some(
                    value
                        .parse()
                        .map_err(|_| (2, format!("--issued-at must be a unix timestamp: {value}")))?,
                )
            }
            "--now" => {
                flags.now = Some(
                    value
                        .parse()
                        .map_err(|_| (2, format!("--now must be a unix timestamp: {value}")))?,
                )
            }
            "--public-key" => flags.public_key = Some(value),
            "--statement" => flags.statement = Some(value),
            "--out-statement" => flags.out_statement = Some(PathBuf::from(value)),
            "--out-signature" => flags.out_signature = Some(PathBuf::from(value)),
            _ => unreachable!("checked against expected"),
        }
    }

    match subcommand.as_str() {
        "create" => cmd_create(flags),
        "show" => cmd_show(flags),
        "verify" => cmd_verify(flags),
        "sign" => cmd_sign(flags),
        "verify-signature" => cmd_verify_signature(flags),
        "capabilities" => cmd_capabilities(flags),
        "verify-capabilities" => cmd_verify_capabilities(flags),
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

fn cmd_capabilities(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'capabilities' requires --dir".into()))?;
    if f.caps.is_empty() {
        return Err((
            2,
            "'capabilities' requires at least one --capability \
             (gateway|relay|dtn_custodian|infrastructure)"
                .into(),
        ));
    }
    let mut caps = Vec::with_capacity(f.caps.len());
    for c in &f.caps {
        caps.push(parse_capability(c)?);
    }
    let mut limits = BTreeMap::new();
    for l in &f.limits {
        let (k, v) = l
            .split_once('=')
            .ok_or_else(|| (2, format!("--limit must be key=value, got {l:?}")))?;
        let v: i64 = v
            .parse()
            .map_err(|_| (2, format!("--limit value must be an integer: {v}")))?;
        limits.insert(k.to_string(), v);
    }
    let store = IdentityStore::new(&dir);
    let id = store.load().map_err(|e| (1, e.to_string()))?;
    let issued_at = f.issued_at.unwrap_or_else(now_unix);
    let validity = f.validity_secs.unwrap_or(86_400);
    if validity == 0 {
        return Err((2, "--validity-secs must be at least 1".into()));
    }
    let expires_at = issued_at
        .checked_add(validity)
        .filter(|e| *e <= i64::MAX as u64)
        .ok_or((2, "validity window overflows the canonical integer range".into()))?;
    let statement = CapabilityStatement::new(
        id.node_id(),
        &caps,
        issued_at,
        expires_at,
        if limits.is_empty() { None } else { Some(limits) },
    )
    .map_err(|e| (1, format!("cannot build statement: {e}")))?;
    let signed = statement
        .sign(&id)
        .map_err(|e| (1, format!("cannot sign: {e}")))?;

    let wire_hex = sharenet_protocol::identity::to_hex(signed.statement_bytes());
    let sig_hex = sharenet_protocol::identity::to_hex(signed.signature());
    match (&f.out_statement, &f.out_signature) {
        (Some(sp), Some(sg)) => {
            std::fs::write(sp, signed.statement_bytes()).map_err(|e| {
                (1, format!("failed to write statement {}: {e}", sp.display()))
            })?;
            std::fs::write(sg, signed.signature()).map_err(|e| {
                (1, format!("failed to write signature {}: {e}", sg.display()))
            })?;
            println!("statement_file: {}", sp.display());
            println!("signature_file: {}", sg.display());
        }
        (None, None) => {
            println!("statement_hex: {wire_hex}");
            println!("signature_hex: {sig_hex}");
        }
        _ => {
            return Err((
                2,
                "--out-statement and --out-signature must be given together".into(),
            ))
        }
    }
    println!("node_id: {}", id.node_id());
    println!("capabilities: {}", f.caps.join(","));
    println!("issued_at_unix: {issued_at}");
    println!("expires_at_unix: {expires_at}");
    if let Some(l) = statement.limits() {
        for (k, v) in l {
            println!("limit {k}={v}");
        }
    }
    Ok(())
}

fn cmd_verify_capabilities(f: Flags) -> Result<(), (u8, String)> {
    let statement_loc = f
        .statement
        .ok_or((2, "'verify-capabilities' requires --statement".into()))?;
    let signature_loc = f
        .signature
        .as_ref()
        .and_then(|p| p.to_str())
        .map(|s| s.to_string())
        .ok_or((2, "'verify-capabilities' requires --signature".into()))?;
    let public_key: [u8; 32] = if let Some(pk) = &f.public_key {
        hex_to_32(pk).map_err(|e| (2, format!("--public-key: {e}")))?
    } else if let Some(idf) = &f.identity_file {
        load_identity_file(idf)
            .map_err(|e| (1, e.to_string()))?
            .node_identity()
            .public_key_bytes()
    } else {
        return Err((
            2,
            "'verify-capabilities' requires --public-key HEX or --identity-file FILE".into(),
        ));
    };
    let statement_bytes = load_bytes_or_hex(&statement_loc, "--statement")?;
    let signature = load_bytes_or_hex(&signature_loc, "--signature")?;
    let now = f.now.unwrap_or_else(now_unix);
    let mut required = Vec::with_capacity(f.require.len());
    for r in &f.require {
        required.push(parse_capability(r)?);
    }
    match admit(&statement_bytes, &signature, &public_key, now, &required) {
        Ok(admitted) => {
            let st = admitted.statement();
            println!("admission OK");
            println!("node_id: {}", st.node_id());
            let held: Vec<&str> = st.capabilities().iter().map(|c| c.wire_text()).collect();
            println!("capabilities: {}", held.join(","));
            println!("valid: {} .. {} (now {now})", st.issued_at_unix(), st.expires_at_unix());
            if let Some(l) = st.limits() {
                for (k, v) in l {
                    println!("limit {k}={v}");
                }
            }
            Ok(())
        }
        Err(e) => Err((1, format!("admission refused: {e}"))),
    }
}

fn parse_capability(s: &str) -> Result<Capability, (u8, String)> {
    match s {
        "gateway" => Ok(Capability::Gateway),
        "relay" => Ok(Capability::Relay),
        "dtn_custodian" => Ok(Capability::DtnCustodian),
        "infrastructure" => Ok(Capability::Infrastructure),
        other => Err((
            2,
            format!(
                "unknown capability {other:?} (expected gateway|relay|dtn_custodian|infrastructure)"
            ),
        )),
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("expected 64 hex characters (32 bytes)".into());
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => unreachable!("checked"),
        }
    };
    for i in 0..32 {
        out[i] = (nib(bytes[2 * i]) << 4) | nib(bytes[2 * i + 1]);
    }
    Ok(out)
}

/// Accept a filesystem path (preferred) or an inline hex string.
fn load_bytes_or_hex(loc: &str, flag: &str) -> Result<Vec<u8>, (u8, String)> {
    let path = PathBuf::from(loc);
    if path.is_file() {
        return std::fs::read(&path).map_err(|e| {
            (1, format!("failed to read {flag} file {}: {e}", path.display()))
        });
    }
    if loc.chars().all(|c| c.is_ascii_hexdigit()) && !loc.is_empty() && loc.len() % 2 == 0 {
        let mut out = Vec::with_capacity(loc.len() / 2);
        let bytes = loc.as_bytes();
        let nib = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => unreachable!("checked"),
            }
        };
        for pair in bytes.chunks(2) {
            out.push((nib(pair[0]) << 4) | nib(pair[1]));
        }
        return Ok(out);
    }
    Err((
        2,
        format!("{flag} must be an existing file or an even-length hex string"),
    ))
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

    capabilities --dir <DIR> --capability <CAP> [--capability <CAP>...]
                 [--limit <KEY>=<INT>]... [--validity-secs <N>] [--issued-at <UNIX>]
                 [--out-statement <FILE> --out-signature <FILE>]
        Build and Ed25519-sign a CapabilityStatement bound to the stored
        identity's node_id. CAP is one of gateway|relay|dtn_custodian|
        infrastructure. Default validity: 86400s from now. Without --out
        flags the statement/signature are printed as hex.

    verify-capabilities --statement <FILE|HEX> --signature <FILE|HEX>
                       (--public-key <HEX> | --identity-file <FILE>)
                       [--now <UNIX>] [--require <CAP>...]
        Run the full admission check (parse + node_id binding + strict
        signature + validity window + capability lookup). Default --now is
        the process clock.

EXIT CODES: 0 success, 1 operational failure, 2 usage error."
    );
}
