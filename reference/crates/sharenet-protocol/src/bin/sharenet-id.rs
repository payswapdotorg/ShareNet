//! `sharenet-id` — production CLI for ShareNet node identities (R1-001).
//!
//! This binary is the real runtime path for identity management today and
//! demonstrates the exact API the future ShareNet daemon will call at node
//! startup (`sharenet_protocol::store::IdentityStore::load_or_create`).
//!
//! Subcommands:
//!
//! ```text
//! sharenet-id create --dir <DIR> [--name <NAME>]
//! sharenet-id show --dir <DIR>
//! sharenet-id verify --dir <DIR>
//! sharenet-id sign --dir <DIR> --payload <FILE> [--out <FILE>]
//! sharenet-id verify-signature --identity-file <FILE> --payload <FILE> --signature <FILE>
//! ```
//!
//! Exit codes: 0 = success, 1 = operation failure, 2 = usage error. All
//! failures print an actionable message to stderr. The seed is never
//! printed or written anywhere except the 0600 identity file.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_protocol::store::IdentityStore;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        if args.is_empty() {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    match parse_args(&args) {
        Ok(cmd) => match run(cmd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("usage error: {e}\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

fn usage() -> String {
    "\
sharenet-id — ShareNet node identity tool

USAGE:
    sharenet-id <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    create             Create (or load an existing) node identity in --dir.
                       Options: --dir <DIR> [--name <NAME>]
    show               Print the node_id, public key, created_at and name.
                       Never prints the seed.
                       Options: --dir <DIR>
    verify             Re-validate the identity file (fail closed).
                       Options: --dir <DIR>
    sign               Produce a detached Ed25519 signature of a payload file
                       using the node key. Prints the node_id.
                       Options: --dir <DIR> --payload <FILE> [--out <FILE>]
                       (default output: <PAYLOAD>.sig)
    verify-signature   Strictly verify a detached signature against an
                       identity file.
                       Options: --identity-file <FILE> --payload <FILE>
                                --signature <FILE>

EXIT CODES:
    0 success, 1 failure, 2 usage error
"
    .to_string()
}

#[derive(Debug)]
enum Command {
    Create { dir: PathBuf, name: Option<String> },
    Show { dir: PathBuf },
    Verify { dir: PathBuf },
    Sign {
        dir: PathBuf,
        payload: PathBuf,
        out: Option<PathBuf>,
    },
    VerifySignature {
        identity_file: PathBuf,
        payload: PathBuf,
        signature: PathBuf,
    },
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let mut it = args.iter().cloned();
    let sub = it.next().ok_or_else(|| "missing subcommand".to_string())?;

    let mut dir: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut payload: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut identity_file: Option<PathBuf> = None;
    let mut signature: Option<PathBuf> = None;

    fn next_value(flag: &str, it: &mut impl Iterator<Item = String>) -> Result<String, String> {
        it.next().ok_or_else(|| format!("flag {flag} requires a value"))
    }

    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(next_value("--dir", &mut it)?)),
            "--name" => name = Some(next_value("--name", &mut it)?),
            "--payload" => payload = Some(PathBuf::from(next_value("--payload", &mut it)?)),
            "--out" => out = Some(PathBuf::from(next_value("--out", &mut it)?)),
            "--identity-file" => {
                identity_file = Some(PathBuf::from(next_value("--identity-file", &mut it)?))
            }
            "--signature" => signature = Some(PathBuf::from(next_value("--signature", &mut it)?)),
            other => return Err(format!("unknown flag '{other}'")),
        }
    }

    let required = |v: Option<PathBuf>, flag: &str| -> Result<PathBuf, String> {
        v.ok_or_else(|| format!("missing required flag {flag}"))
    };

    match sub.as_str() {
        "create" => Ok(Command::Create {
            dir: required(dir, "--dir")?,
            name,
        }),
        "show" => Ok(Command::Show {
            dir: required(dir, "--dir")?,
        }),
        "verify" => Ok(Command::Verify {
            dir: required(dir, "--dir")?,
        }),
        "sign" => Ok(Command::Sign {
            dir: required(dir, "--dir")?,
            payload: required(payload, "--payload")?,
            out,
        }),
        "verify-signature" => Ok(Command::VerifySignature {
            identity_file: required(identity_file, "--identity-file")?,
            payload: required(payload, "--payload")?,
            signature: required(signature, "--signature")?,
        }),
        other => Err(format!("unknown subcommand '{other}'")),
    }
}

fn run(cmd: Command) -> Result<(), String> {
    match cmd {
        Command::Create { dir, name } => {
            let (loaded, created_new) =
                IdentityStore::load_or_create(&dir, name.as_deref())
                    .map_err(|e| e.to_string())?;
            let id = loaded.identity();
            println!("status: {}", if created_new { "created" } else { "loaded existing" });
            println!("node_id: {}", id.node_id_hex());
            println!("public_key: {}", id.public_key_hex());
            println!("created_at_unix: {}", id.created_at_unix());
            println!("display_name: {}", id.display_name().unwrap_or("-"));
            println!("identity_file: {}", IdentityStore::identity_path(&dir).display());
            Ok(())
        }
        Command::Show { dir } => {
            let loaded = IdentityStore::load(&dir).map_err(|e| e.to_string())?;
            let id = loaded.identity();
            println!("node_id: {}", id.node_id_hex());
            println!("public_key: {}", id.public_key_hex());
            println!("created_at_unix: {}", id.created_at_unix());
            println!("display_name: {}", id.display_name().unwrap_or("-"));
            println!("scheme_version: {}", id.scheme_version());
            Ok(())
        }
        Command::Verify { dir } => {
            let path = IdentityStore::identity_path(&dir);
            let id = IdentityStore::verify_file(&path).map_err(|e| e.to_string())?;
            println!("identity file OK: {}", path.display());
            println!("node_id: {}", id.node_id_hex());
            Ok(())
        }
        Command::Sign { dir, payload, out } => {
            let loaded = IdentityStore::load(&dir).map_err(|e| e.to_string())?;
            let payload_bytes = std::fs::read(&payload)
                .map_err(|e| format!("reading payload {}: {e}", payload.display()))?;
            let signature = loaded.sign(&payload_bytes);
            let sig_path = out.unwrap_or_else(|| {
                let mut p = payload.clone().into_os_string();
                p.push(".sig");
                PathBuf::from(p)
            });
            std::fs::write(&sig_path, signature)
                .map_err(|e| format!("writing signature {}: {e}", sig_path.display()))?;
            println!("node_id: {}", loaded.node_id_hex());
            println!("signature_file: {}", sig_path.display());
            Ok(())
        }
        Command::VerifySignature {
            identity_file,
            payload,
            signature,
        } => {
            // Full fail-closed validation of the identity file first.
            let id = IdentityStore::verify_file(&identity_file)
                .map_err(|e| e.to_string())?;
            let payload_bytes = std::fs::read(&payload)
                .map_err(|e| format!("reading payload {}: {e}", payload.display()))?;
            let signature_bytes = std::fs::read(&signature)
                .map_err(|e| format!("reading signature {}: {e}", signature.display()))?;
            sharenet_protocol::identity::verify_detached(
                id.public_key(),
                &payload_bytes,
                &signature_bytes,
            )
            .map_err(|e| e.to_string())?;
            println!("signature valid");
            println!("node_id: {}", id.node_id_hex());
            Ok(())
        }
    }
}
