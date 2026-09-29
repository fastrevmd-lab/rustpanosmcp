//! SIGHUP audit log reopen. Unix-only.
//!
//! Verifies that sending SIGHUP to a running server with `--audit-log-file`
//! configured reopens the sink in place: a rename-then-signal rotation loses
//! nothing written before the rename and routes everything written after it
//! to the fresh inode at the same path. Also verifies that a reopen which
//! cannot succeed (the path is no longer usable) does not take down the
//! server or the token/inventory reload that shares the same handler.
#![cfg(unix)]

use rust_panosmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use serde_json::{Value, json};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A PAN-OS device inventory with one device plus a wildcard-scoped bearer
/// token. `list_devices` (used below to emit an audit record) never contacts
/// the device, so the API key file need not hold a live secret -- it only
/// has to exist and parse, since `Inventory::load` resolves every configured
/// key at startup.
///
/// Real bearer auth, not `--allow-no-auth`: this repo's HTTP `authorize()`
/// refuses any HTTP request with no `CallerCtx` in extensions, and the
/// unauthenticated transport config installs no bearer middleware to put one
/// there, so a `tools/call` over `--allow-no-auth` streamable-http is
/// rejected with "authenticated HTTP transport requires a valid bearer
/// token" -- intentional fail-closed behavior (see
/// `authorize_denies_http_without_caller_but_allows_stdio` in `lib.rs`), not
/// a gap, so this fixture issues a wildcard token and every request below
/// carries it instead.
struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    tokens_file: std::path::PathBuf,
    bearer: String,
}

fn write_inventory() -> Fixture {
    let directory = tempfile::tempdir().expect("temp dir");
    let key_path = directory.path().join("panos-api-key");
    std::fs::write(&key_path, "not-a-live-key").expect("write API key fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod API key fixture");
    }
    let path = directory.path().join("devices.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"version":1,"devices":[{{"name":"lab-fw","endpoint":"https://fw.example.test","api_key":{{"type":"file","path":"{}"}}}}]}}"#,
            key_path.display()
        ),
    )
    .expect("write inventory");

    let tokens_file = directory.path().join("tokens.json");
    let known = KnownNames {
        devices: None,
        tools: rust_panosmcp_auth::KNOWN_TOOLS,
    };
    let bearer = TokenStoreFile::add(
        &tokens_file,
        "sighup-test",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();

    Fixture {
        _directory: directory,
        path,
        tokens_file,
        bearer,
    }
}

fn pick_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

fn wait_for_port(port: u16, deadline: Instant) {
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "server never opened port {port}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(
    inventory_path: &std::path::Path,
    tokens_file: &std::path::Path,
    audit_log_file: &std::path::Path,
) -> Server {
    spawn_with_stderr(inventory_path, tokens_file, audit_log_file, Stdio::null())
}

fn spawn_with_stderr(
    inventory_path: &std::path::Path,
    tokens_file: &std::path::Path,
    audit_log_file: &std::path::Path,
    stderr: Stdio,
) -> Server {
    let port = pick_port();
    let child = Command::new(env!("CARGO_BIN_EXE_rust-panosmcp"))
        .args([
            "--device-mapping",
            inventory_path.to_str().expect("inventory path is UTF-8"),
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--tokens-file",
            tokens_file.to_str().expect("tokens path is UTF-8"),
            "--audit-format",
            "json",
            "--audit-log-file",
            audit_log_file.to_str().expect("audit path is UTF-8"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("spawn rust-panosmcp");
    wait_for_port(port, Instant::now() + Duration::from_secs(5));
    Server { child, port }
}

fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

async fn post(
    port: u16,
    bearer: &str,
    session_id: Option<&str>,
    body: &Value,
) -> (u16, Option<String>) {
    install_crypto_provider();
    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("http://127.0.0.1:{port}/mcp"))
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .body(serde_json::to_string(body).expect("serialize body"));
    if let Some(sid) = session_id {
        request = request.header("Mcp-Session-Id", sid);
    }
    let response = request.send().await.expect("HTTP request");
    let status = response.status().as_u16();
    let sid = response
        .headers()
        .get("Mcp-Session-Id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (status, sid)
}

/// `initialize` + `notifications/initialized`, returning the session id.
async fn initialize(port: u16, bearer: &str) -> String {
    let init_body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "sighup-audit-test", "version": "1"}
        }
    });
    let (status, session_id) = post(port, bearer, None, &init_body).await;
    assert_eq!(status, 200, "initialize failed");
    let session_id = session_id.expect("server did not return Mcp-Session-Id");

    let (status, _) = post(
        port,
        bearer,
        Some(&session_id),
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )
    .await;
    assert!(
        status == 200 || status == 202,
        "initialized notification rejected: {status}"
    );
    session_id
}

/// Calls `list_devices`, which never contacts a PAN-OS device. Emits two
/// `target="audit"` records: a preflight line (`"action":"transport"`) and a
/// completion line (`"action":"list"`) — callers that need to observe the
/// full record must wait for the completion line specifically, not just any
/// substring naming the tool, since the two lines land as separate writes.
async fn emit_audit_record(port: u16, bearer: &str, session_id: &str, id: i64) {
    let (status, _) = post(
        port,
        bearer,
        Some(session_id),
        &json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": "list_devices", "arguments": {}}
        }),
    )
    .await;
    assert_eq!(status, 200, "list_devices failed");
}

fn sighup(pid: u32) {
    let pid = rustix::process::Pid::from_raw(pid as i32).expect("valid PID");
    rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("kill(SIGHUP)");
}

/// Marks the completion audit line for a `list_devices` call
/// (`"action":"list"`), as opposed to its preflight line
/// (`"action":"transport"`), which is written first and also names the tool.
/// Waiting on this rather than on `"list_devices"` avoids two races: the
/// preflight line landing before the completion line has been flushed, and
/// `main.rs`'s own startup diagnostic (`"validated PAN-OS runtime"`), whose
/// field evaluation itself calls `list_devices`, transiently satisfying a
/// looser needle before this test's own call has landed.
const LIST_COMPLETION_NEEDLE: &str = "\"action\":\"list\"";

/// Polls until `path` contains `needle`.
fn wait_for_content_containing(path: &std::path::Path, needle: &str, deadline: Instant) -> String {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && contents.contains(needle)
        {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "{} never contained {needle:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[tokio::test]
async fn sighup_reopens_audit_log_after_rename() {
    let inventory = write_inventory();
    let directory = tempfile::tempdir().expect("temp dir");
    let audit_path = directory.path().join("audit.jsonl");

    let server = spawn(&inventory.path, &inventory.tokens_file, &audit_path);
    let session_id = initialize(server.port, &inventory.bearer).await;

    // First record lands in the original inode.
    emit_audit_record(server.port, &inventory.bearer, &session_id, 2).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = wait_for_content_containing(&audit_path, LIST_COMPLETION_NEEDLE, deadline);

    // Rotate the way logrotate's rename-mode fragment does: move the file
    // aside, then signal the process.
    let rotated = directory.path().join("audit.jsonl.1");
    std::fs::rename(&audit_path, &rotated).expect("rename audit log");
    sighup(server.child.id());

    // Second record must land at the same path, in a fresh inode, once the
    // reopen has completed. Poll rather than sleep a fixed amount: the
    // reopen races SIGHUP delivery.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        emit_audit_record(server.port, &inventory.bearer, &session_id, 3).await;
        if let Ok(contents) = std::fs::read_to_string(&audit_path)
            && contents.contains(LIST_COMPLETION_NEEDLE)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second record never appeared at {} within 5s after SIGHUP",
            audit_path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let rotated_contents = std::fs::read_to_string(&rotated).expect("read rotated file");
    assert_eq!(
        rotated_contents, before,
        "the rotated-away file must keep exactly what was written before the rename, losing nothing"
    );
}

/// Drains the child's stderr into a shared buffer so the test can wait for a
/// specific log line without blocking the server on a full pipe.
fn capture_stderr(child: &mut Child) -> std::sync::Arc<std::sync::Mutex<String>> {
    use std::io::BufRead;
    let buffer = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr = child.stderr.take().expect("stderr was piped");
    let sink = buffer.clone();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let mut guard = sink.lock().expect("stderr buffer mutex");
            guard.push_str(&line);
            guard.push('\n');
        }
    });
    buffer
}

#[tokio::test]
async fn sighup_audit_reopen_failure_keeps_server_and_other_reloads_alive() {
    let inventory = write_inventory();
    let directory = tempfile::tempdir().expect("temp dir");
    let audit_path = directory.path().join("audit.jsonl");

    let mut server = spawn_with_stderr(
        &inventory.path,
        &inventory.tokens_file,
        &audit_path,
        Stdio::piped(),
    );
    let stderr = capture_stderr(&mut server.child);
    let session_id = initialize(server.port, &inventory.bearer).await;

    emit_audit_record(server.port, &inventory.bearer, &session_id, 2).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    wait_for_content_containing(&audit_path, LIST_COMPLETION_NEEDLE, deadline);

    // Make the reopen fail: replace the path with a directory, so
    // `OpenOptions::create().append()` on it returns EISDIR. The server's
    // existing (now-unlinked) descriptor keeps working regardless.
    std::fs::remove_file(&audit_path).expect("remove audit file");
    std::fs::create_dir(&audit_path).expect("create directory in its place");

    // Issue a second token before the signal. It only becomes valid if the
    // token/inventory reload that shares the SIGHUP handler still runs after
    // the audit reopen has failed -- a handler that bailed out (`?`, panic,
    // early return) on the reopen error would leave it unknown to the server.
    let known = rust_panosmcp_auth::KnownNames {
        devices: None,
        tools: rust_panosmcp_auth::KNOWN_TOOLS,
    };
    let reloaded_bearer = TokenStoreFile::add(
        &inventory.tokens_file,
        "sighup-test-after-reload",
        ScopeSet::Wildcard,
        ScopeSet::Wildcard,
        &known,
    )
    .expect("token add")
    .expose_secret()
    .to_owned();

    sighup(server.child.id());

    // The reopen-failure path must actually have been taken; otherwise the
    // assertions below prove nothing about it.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !stderr
        .lock()
        .expect("stderr buffer mutex")
        .contains("audit log reopen failed")
    {
        assert!(
            Instant::now() < deadline,
            "server never logged the failed audit reopen; stderr:\n{}",
            stderr.lock().expect("stderr buffer mutex")
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // The server must keep serving, and the reload must have run: the token
    // issued just before SIGHUP now authenticates.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "sighup-audit-test", "version": "1"}
            }
        });
        let (status, _) = post(server.port, &reloaded_bearer, None, &body).await;
        if status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "token issued before SIGHUP never became valid after a failed audit reopen (last status {status})"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        server.child.try_wait().expect("poll child").is_none(),
        "server exited after a failed audit reopen"
    );
}
