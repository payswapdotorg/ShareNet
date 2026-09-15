//! `sharenet-route` — ShareNet route commitment tool (runtime path of
//! R3-004). A real process performing real file I/O through the protocol
//! API: multi-party route formation (propose → accept per hop → commit →
//! verify) with commitment-derived route IDs (caller-selected IDs are
//! impossible by construction).
//!
//! Exit codes: 0 success, 1 operational failure, 2 usage error.

use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_protocol::identity::Identity;
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteError, RouteProposal, SignedEnvelope,
};
use sharenet_protocol::store::IdentityStore;

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

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(argv: Vec<String>) -> Result<(), (u8, String)> {
    let mut it = argv.into_iter();
    let _prog = it.next();
    let sub = it
        .next()
        .ok_or((2u8, "a subcommand is required".to_string()))?;
    // repeated flags (e.g. --hop) accumulate in order
    let mut flags: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    let mut path_args: Vec<String> = Vec::new();
    let mut args = it.peekable();
    while let Some(arg) = args.next() {
        if let Some((name, value)) = arg.split_once('=') {
            flags
                .entry(name.to_string())
                .or_default()
                .push(value.to_string());
        } else if arg.starts_with("--") {
            let value = args
                .next()
                .ok_or((2u8, format!("'{arg}' requires a value")))?;
            flags.entry(arg).or_default().push(value);
        } else {
            path_args.push(arg);
        }
    }
    let one = |name: &str| -> Option<String> { flags.get(name).and_then(|v| v.first().cloned()) };
    let dir = one("--dir").ok_or((2u8, "requires --dir <IDENTITY_DIR>".to_string()))?;
    let identity = {
        let store = IdentityStore::new(&dir);
        store.load().map_err(|e| (1u8, e.to_string()))?
    };
    match sub.as_str() {
        "propose" => {
            // sharenet-route propose --dir D --hop NODEID_HEX... --out FILE
            //   [--service live] [--validity-secs N] [--nonce-hex HEX]
            // the path ALWAYS includes the proposer (the route's source);
            // additional --hop node ids name the other committed members
            let mut path: Vec<[u8; 32]> = vec![*identity.node_id().as_bytes()];
            for hop in flags.get("--hop").cloned().unwrap_or_default() {
                path.push(parse_node_id(&hop)?);
            }
            let service = one("--service").unwrap_or_else(|| "live".into());
            let validity: u64 = one("--validity-secs")
                .and_then(|v| v.parse().ok())
                .unwrap_or(600);
            let nonce = match one("--nonce-hex") {
                Some(h) => parse_32(&h, "nonce")?,
                None => random_nonce()?,
            };
            let proposal = RouteProposal::new(&identity, path, service, now_unix(), validity, nonce)
                .map_err(|e| (1u8, e.to_string()))?;
            let signed = proposal
                .sign(&identity)
                .map_err(|e| (1u8, e.to_string()))?;
            let out = PathBuf::from(
                one("--out").ok_or((2u8, "propose requires --out FILE".to_string()))?,
            );
            std::fs::write(&out, signed.to_envelope_bytes())
                .map_err(|e| (1u8, format!("write {}: {e}", out.display())))?;
            println!("proposal_file: {}", out.display());
            println!(
                "proposal_id: {}",
                hex(&derive_proposal_id(signed.bytes()))
            );
            println!(
                "path_len: {}",
                proposal.path().len()
            );
            Ok(())
        }
        "accept" => {
            // sharenet-route accept --dir D --proposal FILE --out FILE
            let proposal_env_path =
                one("--proposal").ok_or((2u8, "accept requires --proposal FILE".to_string()))?;
            let env_bytes = std::fs::read(&proposal_env_path)
                .map_err(|e| (1u8, format!("read {proposal_env_path}: {e}")))?;
            let env = SignedEnvelope::from_envelope_bytes(&env_bytes)
                .map_err(|e| (1u8, e.to_string()))?;
            let proposal = RouteProposal::from_wire_bytes(env.bytes())
                .map_err(|e| (1u8, e.to_string()))?;
            // our position in the (sorted) path
            let me = identity.node_id();
            let position = proposal
                .path()
                .iter()
                .position(|p| p == me.as_bytes())
                .ok_or((
                    1u8,
                    "this identity is not on the proposed path (every path member must accept)"
                        .to_string(),
                ))?;
            let proposal_id = derive_proposal_id(env.bytes());
            let acceptance = RouteAcceptance::new(
                &identity,
                proposal_id,
                position as u64,
                now_unix(),
                600,
            )
            .map_err(|e| (1u8, e.to_string()))?;
            let signed = acceptance
                .sign(&identity)
                .map_err(|e| (1u8, e.to_string()))?;
            let out = PathBuf::from(
                one("--out").ok_or((2u8, "accept requires --out FILE".to_string()))?,
            );
            std::fs::write(&out, signed.to_envelope_bytes())
                .map_err(|e| (1u8, format!("write {}: {e}", out.display())))?;
            println!("acceptance_file: {}", out.display());
            println!("position: {position}");
            Ok(())
        }
        "commit" => {
            // sharenet-route commit --dir D --proposal FILE --acceptance A [A...] --out FILE
            let proposal_env_path =
                one("--proposal").ok_or((2u8, "commit requires --proposal FILE".to_string()))?;
            let env = read_envelope(&proposal_env_path)?;
            let mut acceptances = Vec::new();
            for path in &path_args {
                acceptances.push(read_envelope(path)?);
            }
            let commitment = RouteCommitment::build(now_unix(), env, acceptances)
                .map_err(|e| (1u8, e.to_string()))?;
            let out =
                PathBuf::from(one("--out").ok_or((2u8, "commit requires --out FILE".to_string()))?);
            std::fs::write(&out, commitment.to_wire_bytes())
                .map_err(|e| (1u8, format!("write {}: {e}", out.display())))?;
            println!("commitment_file: {}", out.display());
            println!("commitment_root: {}", hex(commitment.commitment_root()));
            println!("route_id: {}", hex(commitment.route_id()));
            Ok(())
        }
        "verify" => {
            // sharenet-route verify --dir D --commitment FILE
            let path =
                one("--commitment").ok_or((2u8, "verify requires --commitment FILE".to_string()))?;
            let bytes = std::fs::read(&path)
                .map_err(|e| (1u8, format!("read {path}: {e}")))?;
            let commitment = RouteCommitment::from_wire_bytes(&bytes)
                .map_err(|e| (1u8, e.to_string()))?;
            let verified = commitment
                .verify(now_unix())
                .map_err(|e| (1u8, e.to_string()))?;
            println!("route OK");
            println!("route_id: {}", hex(&verified.route_id));
            println!("commitment_root: {}", hex(&verified.commitment_root));
            println!("service_class: {}", verified.proposal.service_class());
            println!("path_len: {}", verified.proposal.path().len());
            Ok(())
        }
        other => Err((2, format!("unknown subcommand '{other}'"))),
    }
}

fn parse_node_id(s: &str) -> Result<[u8; 32], (u8, String)> {
    parse_32(s, "node id")
}

fn parse_32(s: &str, what: &str) -> Result<[u8; 32], (u8, String)> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((2u8, format!("{what} must be 64 hex characters")));
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        }
    };
    for i in 0..32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
    }
    Ok(out)
}

fn read_envelope(path: &str) -> Result<SignedEnvelope, (u8, String)> {
    let bytes = std::fs::read(path).map_err(|e| (1u8, format!("read {path}: {e}")))?;
    SignedEnvelope::from_envelope_bytes(&bytes).map_err(|e| (1u8, e.to_string()))
}

fn random_nonce() -> Result<[u8; 32], (u8, String)> {
    use std::io::Read;
    let mut buf = [0u8; 32];
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|_| (1u8, "entropy unavailable".to_string()))?;
    f.read_exact(&mut buf)
        .map_err(|e| (1u8, format!("entropy: {e}")))?;
    Ok(buf)
}

