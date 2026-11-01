//! Where the compressed dump comes from: an SSH child process whose stdout is
//! the zstd stream. The host key is pinned; nothing is ever learned.

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dump::MAX_LOAD_SECS;

pub trait DumpSource: Send + Sync {
    /// A fresh stream of the zstd-compressed dump; dropping it ends the transfer.
    fn open(&self) -> io::Result<Box<dyn Read + Send>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key: PathBuf,
    pub known_hosts: PathBuf,
    pub host_key_alias: String,
}

pub struct SshSource {
    cfg: SshConfig,
    program: PathBuf,
    /// A stream still open after this long is killed (a stalled ssh session).
    kill_after: Duration,
}

impl SshSource {
    pub fn new(cfg: SshConfig) -> Self {
        Self::with_program(cfg, PathBuf::from("ssh"))
    }

    pub fn with_program(cfg: SshConfig, program: PathBuf) -> Self {
        Self {
            cfg,
            program,
            kill_after: Duration::from_secs(MAX_LOAD_SECS + 60),
        }
    }

    /// Overrides the watchdog limit (tests).
    pub fn with_kill_after(mut self, limit: Duration) -> Self {
        self.kill_after = limit;
        self
    }

    /// The ssh invocation: no remote command (the account's forced command
    /// streams the file), a pinned host key, no agent, no forwarding.
    pub fn command(&self) -> Command {
        let c = &self.cfg;
        let mut cmd = Command::new(&self.program);
        // A clean environment: nothing of the service's own reaches ssh.
        cmd.env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin");
        cmd.args(["-F", "/dev/null", "-n", "-T"]);
        let opts = [
            "BatchMode=yes".to_string(),
            "IdentitiesOnly=yes".to_string(),
            format!("IdentityFile={}", c.key.display()),
            "StrictHostKeyChecking=yes".to_string(),
            format!("UserKnownHostsFile={}", c.known_hosts.display()),
            "GlobalKnownHostsFile=/dev/null".to_string(),
            format!("HostKeyAlias={}", c.host_key_alias),
            "LogLevel=ERROR".to_string(),
            "ConnectTimeout=20".to_string(),
            "ServerAliveInterval=15".to_string(),
            "ServerAliveCountMax=4".to_string(),
            "ControlMaster=no".to_string(),
            "ControlPath=none".to_string(),
            "ClearAllForwardings=yes".to_string(),
            "ForwardAgent=no".to_string(),
        ];
        for o in opts {
            cmd.arg("-o").arg(o);
        }
        cmd.arg("-p")
            .arg(c.port.to_string())
            .arg(format!("{}@{}", c.user, c.host));
        cmd
    }
}

impl DumpSource for SshSource {
    fn open(&self) -> io::Result<Box<dyn Read + Send>> {
        let mut child = self
            .command()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("child has no stdout"))?;
        let child = Arc::new(Mutex::new(child));
        let fired = Arc::new(AtomicBool::new(false));
        let (alive, watch) = mpsc::channel::<()>();
        let (wd_child, wd_fired, limit) = (child.clone(), fired.clone(), self.kill_after);
        std::thread::spawn(move || {
            // Disconnected = the stream was dropped; Timeout = it is stalled.
            if let Err(RecvTimeoutError::Timeout) = watch.recv_timeout(limit) {
                wd_fired.store(true, Ordering::SeqCst);
                // Closing the child's stdout unblocks the pending read.
                let _ = wd_child.lock().map(|mut c| c.kill());
            }
        });
        Ok(Box::new(ChildStream {
            child,
            stdout,
            fired,
            _alive: alive,
        }))
    }
}

/// The child's stdout; the child is killed and reaped when this is dropped.
struct ChildStream {
    child: Arc<Mutex<Child>>,
    stdout: ChildStdout,
    /// Set when the watchdog killed the child.
    fired: Arc<AtomicBool>,
    /// Dropped with the stream, which ends the watchdog.
    _alive: Sender<()>,
}

impl Read for ChildStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.stdout.read(buf);
        if self.fired.load(Ordering::SeqCst) && !matches!(r, Ok(n) if n > 0) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the dump stream stalled and was killed",
            ));
        }
        r
    }
}

impl Drop for ChildStream {
    fn drop(&mut self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dump::{self, LoadError, PROOF_PIECE_SIZE};
    use crate::known::KnownFile;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/mini.ndjson");

    fn cfg() -> SshConfig {
        SshConfig {
            host: "203.0.113.9".into(),
            port: 2222,
            user: "reader".into(),
            key: "/run/muninn/id_ed25519".into(),
            known_hosts: "/run/muninn/known_hosts".into(),
            host_key_alias: "muninn".into(),
        }
    }

    fn known() -> KnownFile {
        KnownFile {
            size: FIXTURE.len() as u64,
            sha256: Sha256::digest(FIXTURE).into(),
            chunk_size: 10,
            chunks: FIXTURE
                .chunks(10)
                .map(|c| <[u8; 32]>::from(Sha256::digest(c)))
                .collect(),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("urban-source-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn script(dir: &std::path::Path, body: &str) -> PathBuf {
        let p = dir.join("fake-ssh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn command_pins_the_host_key_and_never_learns_one() {
        let cmd = SshSource::new(cfg()).command();
        assert_eq!(cmd.get_program(), "ssh");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let expected = [
            "-F",
            "/dev/null",
            "-n",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityFile=/run/muninn/id_ed25519",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=/run/muninn/known_hosts",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlias=muninn",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=20",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=4",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-p",
            "2222",
            "reader@203.0.113.9",
        ];
        assert_eq!(args, expected);
        assert!(!args
            .iter()
            .any(|a| a.contains("accept-new") || a.contains("StrictHostKeyChecking=no")));
    }

    #[test]
    fn a_child_process_stream_loads() {
        let dir = scratch("loads");
        let data = dir.join("words.zst");
        std::fs::write(&data, zstd::encode_all(FIXTURE, 3).unwrap()).unwrap();
        let prog = script(&dir, &format!("exec cat \"{}\"", data.display()));
        let stream = SshSource::with_program(cfg(), prog).open().unwrap();
        let r = dump::load(stream, &known(), PROOF_PIECE_SIZE, far());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(r.is_ok());
    }

    #[test]
    fn a_stalled_child_is_killed_at_the_limit() {
        let dir = scratch("stalled");
        let prog = script(&dir, "exec sleep 60");
        let stream = SshSource::with_program(cfg(), prog)
            .with_kill_after(Duration::from_secs(1))
            .open()
            .unwrap();
        let started = Instant::now();
        let r = dump::load(stream, &known(), PROOF_PIECE_SIZE, far());
        let elapsed = started.elapsed();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(r, Err(LoadError::TimedOut)));
        assert!(elapsed < Duration::from_secs(10), "took {elapsed:?}");
    }

    #[test]
    fn ssh_gets_only_a_path() {
        let cmd = SshSource::new(cfg()).command();
        let envs: Vec<_> = cmd.get_envs().collect();
        assert_eq!(
            envs,
            [(
                std::ffi::OsStr::new("PATH"),
                Some(std::ffi::OsStr::new("/usr/local/bin:/usr/bin:/bin"))
            )]
        );
    }

    #[test]
    fn a_failing_child_is_a_short_stream() {
        let dir = scratch("fails");
        let prog = script(&dir, "exit 255");
        let stream = SshSource::with_program(cfg(), prog).open().unwrap();
        let r = dump::load(stream, &known(), PROOF_PIECE_SIZE, far());
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(matches!(
            r,
            Err(LoadError::Source(_) | LoadError::WrongFile)
        ));
    }
}
