//! End-to-end runtime tests for the `sharenet-id` binary (R1-001 runtime
//! path): real process, real files, real exit codes. This exercises the
//! exact production path a node operator (and later the daemon) uses.

#![forbid(unsafe_code)]

use std::process::Command;

struct RunResult {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> RunResult {
    let output = Command::new(env!("CARGO_BIN_EXE_sharenet-id"))
        .args(args)
        .output()
        .expect("spawn sharenet-id");
    RunResult {
        code: output.status.code().expect("process exited normally"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn field<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("stdout missing '{key}':\n{stdout}"))
        .trim()
}

#[test]
fn cli_full_lifecycle_on_real_files() {
    let workdir = tempfile::tempdir().unwrap();
    let id_dir = workdir.path().join("nodeA");
    let id_dir_str = id_dir.to_str().unwrap();
    let identity_file = id_dir.join("node.sharenet-identity");
    let identity_file_str = identity_file.to_str().unwrap();

    // Usage errors: no args -> exit 2 with usage on stderr.
    let r = run(&[]);
    assert_eq!(r.code, 2);
    assert!(!r.stderr.is_empty());
    let r = run(&["bogus-subcommand"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("unknown subcommand"));
    let r = run(&["show"]);
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("missing required flag --dir"));

    // Help exits 0.
    let r = run(&["--help"]);
    assert_eq!(r.code, 0);
    assert!(r.stdout.contains("sharenet-id"));

    // create
    let r = run(&["create", "--dir", id_dir_str, "--name", "nodeA"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(field(&r.stdout, "status:"), "created");
    let node_id = field(&r.stdout, "node_id:").to_string();
    assert_eq!(node_id.len(), 64, "node_id is 32-byte hex");
    assert!(
        node_id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "node_id is lowercase hex"
    );
    assert_eq!(field(&r.stdout, "display_name:"), "nodeA");
    assert!(!r.stdout.to_lowercase().contains("seed"));

    // The identity file exists, is exactly 0600, and is strict canonical
    // CBOR of the documented shape.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&identity_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o7777, 0o600, "identity file must be 0600");
    }
    let raw = std::fs::read(&identity_file).unwrap();
    let value = sharenet_protocol::cbor::decode(&raw)
        .expect("identity file is strict canonical CBOR");
    assert!(value.get_by_int(1).unwrap().as_bytes().unwrap().len() == 32);
    assert!(value.get_by_int(2).unwrap().as_map().is_some());

    // create again: loads the existing identity, does NOT recreate.
    let r = run(&["create", "--dir", id_dir_str, "--name", "nodeB-ignored"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(field(&r.stdout, "status:"), "loaded existing");
    assert_eq!(field(&r.stdout, "node_id:"), node_id);
    assert_eq!(field(&r.stdout, "display_name:"), "nodeA", "name is durable metadata");

    // show: prints node_id/created_at/name, never the seed.
    let r = run(&["show", "--dir", id_dir_str]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(field(&r.stdout, "node_id:"), node_id);
    assert!(!r.stdout.to_lowercase().contains("seed"));
    let created_at: u64 = field(&r.stdout, "created_at_unix:").parse().unwrap();
    assert!(created_at > 0);

    // verify
    let r = run(&["verify", "--dir", id_dir_str]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("identity file OK"));
    assert!(r.stdout.contains(&node_id));

    // sign a payload
    let payload = workdir.path().join("payload.bin");
    std::fs::write(&payload, b"sharenet runtime demo payload\n").unwrap();
    let r = run(&[
        "sign",
        "--dir",
        id_dir_str,
        "--payload",
        payload.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(field(&r.stdout, "node_id:"), node_id);
    let default_sig = workdir.path().join("payload.bin.sig");
    let sig = std::fs::read(&default_sig).unwrap();
    assert_eq!(sig.len(), 64, "detached Ed25519 signature is 64 bytes");

    // verify-signature (positive)
    let r = run(&[
        "verify-signature",
        "--identity-file",
        identity_file_str,
        "--payload",
        payload.to_str().unwrap(),
        "--signature",
        default_sig.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert!(r.stdout.contains("signature valid"));

    // sign to an explicit --out path
    let explicit_sig = workdir.path().join("explicit.sig");
    let r = run(&[
        "sign",
        "--dir",
        id_dir_str,
        "--payload",
        payload.to_str().unwrap(),
        "--out",
        explicit_sig.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_eq!(std::fs::read(&explicit_sig).unwrap(), sig, "deterministic signing");

    // verify-signature against a DIFFERENT payload: exit 1, message on stderr.
    let other_payload = workdir.path().join("other.bin");
    std::fs::write(&other_payload, b"a different payload\n").unwrap();
    let r = run(&[
        "verify-signature",
        "--identity-file",
        identity_file_str,
        "--payload",
        other_payload.to_str().unwrap(),
        "--signature",
        default_sig.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1);
    assert!(!r.stderr.is_empty());

    // verify-signature with a tampered signature: exit 1.
    let mut tampered_sig = sig.clone();
    tampered_sig[0] ^= 0x01;
    let tampered_path = workdir.path().join("tampered.sig");
    std::fs::write(&tampered_path, &tampered_sig).unwrap();
    let r = run(&[
        "verify-signature",
        "--identity-file",
        identity_file_str,
        "--payload",
        payload.to_str().unwrap(),
        "--signature",
        tampered_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1);
    assert!(!r.stderr.is_empty());

    // verify-signature with an oversized signature file: exit 1.
    let oversized_path = workdir.path().join("oversized.sig");
    std::fs::write(&oversized_path, [0u8; 65]).unwrap();
    let r = run(&[
        "verify-signature",
        "--identity-file",
        identity_file_str,
        "--payload",
        payload.to_str().unwrap(),
        "--signature",
        oversized_path.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 1);

    // Tamper the identity file (flip a seed byte) and verify fail-closed
    // behavior with non-zero exit and stderr — never silent recreation.
    let pristine = raw.clone();
    let mut tampered = pristine.clone();
    tampered[4] ^= 0xFF; // first seed byte
    std::fs::write(&identity_file, &tampered).unwrap();
    let r = run(&["verify", "--dir", id_dir_str]);
    assert_eq!(r.code, 1);
    assert!(!r.stderr.is_empty());
    let r = run(&["create", "--dir", id_dir_str]);
    assert_eq!(
        r.code, 1,
        "load_or_create must NEVER silently recreate a corrupt identity"
    );
    assert!(!r.stderr.is_empty());

    // Restore; everything works again.
    std::fs::write(&identity_file, &pristine).unwrap();
    let r = run(&["verify", "--dir", id_dir_str]);
    assert_eq!(r.code, 0);
}

#[test]
fn cli_loose_permissions_fail_closed() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let workdir = tempfile::tempdir().unwrap();
        let id_dir_str = workdir.path().join("nodeB");
        let r = run(&["create", "--dir", id_dir_str.to_str().unwrap()]);
        assert_eq!(r.code, 0, "stderr: {}", r.stderr);

        let identity_file = id_dir_str.join("node.sharenet-identity");
        std::fs::set_permissions(&identity_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = run(&["show", "--dir", id_dir_str.to_str().unwrap()]);
        assert_eq!(r.code, 1, "loose perms must fail closed");
        assert!(r.stderr.contains("0600"), "error must be actionable: {}", r.stderr);
    }
}
