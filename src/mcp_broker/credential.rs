//! cplt's credential mechanisms (design section 7).

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::PROBE_TIMEOUT;
use super::spec::Spec;

/// cplt's credential mechanisms (design section 7). Hand-kept; tool policy is
/// never here. `gh-token` is served by [`crate::github_mcp`], not by specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Credential {
    /// nais reads its own keychain item; cplt never touches it.
    NaisKeychain,
    /// No credential.
    None,
}

impl Credential {
    pub(crate) fn parse(name: &str) -> Result<Self, String> {
        match name {
            "nais-keychain" => Ok(Self::NaisKeychain),
            "none" => Ok(Self::None),
            "gh-token" => Err(
                "credential gh-token is served by cplt's built-in GitHub MCP proxy, not by a broker spec"
                    .into(),
            ),
            other => Err(format!(
                "credential {:?} is not a cplt mechanism (nais-keychain, none)",
                other.escape_debug().to_string()
            )),
        }
    }

    /// The only command this mechanism runs, if it fixes one.
    pub(crate) fn command(self) -> Option<&'static [&'static str]> {
        match self {
            Self::NaisKeychain => Some(&["nais", "alpha", "mcp", "serve"]),
            Self::None => None,
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::NaisKeychain => "nais-keychain",
            Self::None => "none",
        }
    }
}

/// The mechanism's status probe, without printing anything it outputs.
/// `None` when the mechanism has none.
pub fn credential_ok(spec: &Spec) -> Option<bool> {
    match spec.credential {
        Credential::None => None,
        Credential::NaisKeychain => {
            #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load
            let mut child = Command::new(&spec.program)
                .args(["auth", "print-access-token"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            let start = Instant::now();
            loop {
                if let Ok(Some(status)) = child.try_wait() {
                    return Some(status.success());
                }
                if start.elapsed() > PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Some(false);
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
