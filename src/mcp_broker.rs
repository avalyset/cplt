//! Host-side MCP broker for local stdio servers (phase 1 of
//! `docs/design/mcp-host-broker.md`, #824). macOS only; Linux refuses.
//!
//! nav-pilot writes one broker spec per server into
//! `$XDG_CONFIG_HOME/cplt/mcp/`: a standard MCP `server.json` plus the
//! `_meta["io.github.navikt/broker"]` extension. cplt validates each spec
//! against the design's invariants, and for each one it accepts it points the
//! client's entry at `cplt mcp-stdio <id>`. That shim runs in the sandbox and
//! pipes stdio over a per-session Unix socket to this broker, which spawns the
//! server on the host (env cleared, egress through cplt's proxy) and applies
//! the spec's tool policy to every JSON-RPC message.
//!
//! Authority: as for the worktree broker, the socket lives outside every
//! granted root and the sandbox may connect to that one path. There is no
//! secret: the client is the sandboxed agent, and it can only name a server
//! the user's spec already declares.

// Linux builds the policy and client code but never starts the runtime (1b).
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// The `_meta` key of the broker extension.
pub const META_KEY: &str = "io.github.navikt/broker";
/// Extension versions this cplt reads, reported by `cplt mcp status --json`.
pub const SCHEMA_VERSIONS: &[u64] = &[1];
/// Version of the `cplt mcp status --json` document itself.
pub const STATUS_VERSION: u64 = 1;
/// The variable naming the socket to `cplt mcp-stdio`. Set in the client's
/// server entry, not the agent's environment.
pub const SOCKET_ENV: &str = "CPLT_MCP_SOCKET";
/// MCP versions that carry one JSON-RPC message per line on stdio.
const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-11-25"];
const SPEC_LIMIT: u64 = 256 * 1024;
const CONFIG_LIMIT: u64 = 1024 * 1024;
/// Message cap, each way.
const MAX_MESSAGE: u64 = 4 * 1024 * 1024;
const MAX_IN_FLIGHT: usize = 8;
const SPAWNS_PER_MINUTE: usize = 3;
const KILL_GRACE: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// JSON-RPC error code for a request the broker refuses.
const DENIED: i64 = -32001;
/// Notifications a client may send through.
const CLIENT_NOTIFICATIONS: &[&str] = &[
    "notifications/initialized",
    "notifications/cancelled",
    "notifications/roots/list_changed",
];

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
    fn parse(name: &str) -> Result<Self, String> {
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
    fn command(self) -> Option<&'static [&'static str]> {
        match self {
            Self::NaisKeychain => Some(&["nais", "alpha", "mcp", "serve"]),
            Self::None => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::NaisKeychain => "nais-keychain",
            Self::None => "none",
        }
    }
}

/// A spec that passed every check.
#[derive(Clone, Debug)]
pub struct Spec {
    pub id: String,
    /// The spec file it was read from (set by [`load`]).
    pub file: PathBuf,
    pub credential: Credential,
    /// `command` as written, for finding the user's own client entry.
    pub command: Vec<String>,
    /// `command[0]` resolved in the trusted dirs.
    pub program: PathBuf,
    pub egress_hosts: Vec<String>,
    pub allow: BTreeSet<String>,
    /// Tools whose `query` argument must pass [`graphql_read_only`].
    pub graphql: BTreeSet<String>,
    pub login: Option<String>,
}

impl Spec {
    /// The client entry name when the user has none: the id's last segment.
    fn short_name(&self) -> &str {
        self.id.rsplit('/').next().unwrap_or(&self.id)
    }

    /// The whole id as an entry name (`/` as `__`, as in the file name).
    fn full_name(&self) -> String {
        self.id.replace('/', "__")
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Rejected {
    pub file: String,
    pub reason: String,
    pub fix: String,
}

impl Rejected {
    /// For a terminal: every field escaped, since a file name in a spec dir
    /// the agent could reach may carry control sequences.
    pub fn line(&self) -> String {
        let e = |s: &str| s.escape_debug().to_string();
        format!(
            "{}: broker spec rejected: {}. Fix: {}",
            e(&self.file),
            e(&self.reason),
            e(&self.fix)
        )
    }
}

/// Drop every spec whose file, or any entry on the way to it, the final
/// sandbox policy makes writable (`writable` asks the policy about one
/// path). Returns the newly rejected, already printed.
pub fn drop_writable(found: &mut Detected, writable: impl Fn(&Path) -> Option<PathBuf>) {
    let mut kept = Vec::new();
    for spec in std::mem::take(&mut found.specs) {
        match writable(&spec.file) {
            None => kept.push(spec),
            Some(tree) => {
                let r = Rejected {
                    file: spec.file.display().to_string(),
                    reason: format!("{} is writable in the sandbox", tree.display()),
                    fix: format!(
                        "move XDG_CONFIG_HOME (or the spec) out of {}, or drop that write grant",
                        tree.display()
                    ),
                };
                found.rejected.push(r);
            }
        }
    }
    found.specs = kept;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Ext {
    #[serde(rename = "v")]
    _v: u64,
    credential: String,
    #[serde(default)]
    command: Vec<String>,
    #[serde(default)]
    egress_hosts: Vec<String>,
    tools: Tools,
    #[serde(default)]
    write_consent: bool,
    #[serde(default)]
    arg_checks: BTreeMap<String, String>,
    #[serde(default)]
    login: Option<Login>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tools {
    allow: Vec<String>,
    #[serde(default)]
    classes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    #[serde(default)]
    run: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

/// `$XDG_CONFIG_HOME/cplt/mcp`, the directory nav-pilot writes specs to.
pub fn spec_dir(home: &Path) -> PathBuf {
    crate::opencode_v2::xdg_base("XDG_CONFIG_HOME", home, ".config")
        .join("cplt")
        .join("mcp")
}

/// The spec file name for `id`.
pub fn file_name(id: &str) -> String {
    format!("{}.json", id.replace('/', "__"))
}

/// Validate one spec (invariants 1-6 of design section 5.3). `resolve` finds a
/// bare command name in the trusted dirs.
pub fn validate(
    text: &str,
    file: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
) -> Result<Spec, String> {
    let root: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    let id = root
        .get("name")
        .and_then(Value::as_str)
        .ok_or("server.json has no name")?
        .to_string();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))
    {
        return Err("name must be a reverse-DNS server name".into());
    }
    if file != file_name(&id) {
        return Err(format!("file name must be {}", file_name(&id)));
    }
    let ext = root
        .pointer(&format!("/_meta/{}", META_KEY.replace('/', "~1")))
        .ok_or_else(|| format!("no _meta[\"{META_KEY}\"] extension"))?;
    let v = ext
        .get("v")
        .and_then(Value::as_u64)
        .ok_or("extension has no v")?;
    if !SCHEMA_VERSIONS.contains(&v) {
        return Err(format!(
            "extension v{v} is not supported by this cplt (reads {SCHEMA_VERSIONS:?})"
        ));
    }
    let ext: Ext = serde_json::from_value(ext.clone()).map_err(|e| format!("extension: {e}"))?;
    let remotes = root.get("remotes").cloned().unwrap_or(Value::Null);
    let packages = root.get("packages").cloned().unwrap_or(Value::Null);

    // 2 and 6: no secret values and no credential placeholders. Credentials
    // come from cplt's mechanism table only, never from the spec.
    let mut strings = Vec::new();
    for v in [&remotes, &packages] {
        collect_strings(v, &mut strings);
    }
    strings.extend(ext.command.iter().map(String::as_str));
    strings.extend(ext.egress_hosts.iter().map(String::as_str));
    for s in &strings {
        if looks_like_secret(s) {
            return Err("the spec holds what looks like a secret value".into());
        }
        if s.contains('{') || s.contains("$(") || s.contains("${") {
            return Err(format!(
                "credential placeholder in {:?}: the credential comes from cplt, not the spec",
                s.escape_debug().to_string()
            ));
        }
    }
    let secret_env = packages
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("environmentVariables")?.as_array())
        .flatten()
        .any(|e| e.get("isSecret") == Some(&Value::Bool(true)));
    if secret_env {
        return Err("environmentVariables with isSecret: no cplt mechanism supplies them".into());
    }

    // 1: the mechanism exists and fixes what may run.
    let credential = Credential::parse(&ext.credential)?;
    // 4: https upstreams only; phase 1 brokers host commands only.
    for r in remotes.as_array().into_iter().flatten() {
        let url = r.get("url").and_then(Value::as_str).unwrap_or_default();
        if !url.starts_with("https://") {
            return Err("remote upstreams must be https".into());
        }
    }
    if remotes.as_array().is_some_and(|a| !a.is_empty()) {
        return Err("remote upstreams are not brokered yet; only a host command".into());
    }
    if ext.command.is_empty() {
        return Err("no command".into());
    }
    if let Some(fixed) = credential.command()
        && ext.command != fixed
    {
        return Err(format!(
            "credential {} runs only `{}`",
            credential.name(),
            fixed.join(" ")
        ));
    }
    if ext.command.iter().any(|a| a.chars().any(char::is_control)) {
        return Err("control characters in command".into());
    }
    let name = &ext.command[0];
    if name.contains('/') {
        return Err("command[0] must be a bare name, resolved in the trusted dirs".into());
    }
    let program = resolve(name).ok_or_else(|| format!("{name} is not in the trusted dirs"))?;

    for host in &ext.egress_hosts {
        check_host(host)?;
    }

    // 3: write and external tools need consent; host-exec never.
    for (tool, class) in &ext.tools.classes {
        match class.as_str() {
            "read" => {}
            "host-exec" => {
                return Err(format!("tool {tool} is host-exec, which is never brokered"));
            }
            "write" | "external" if ext.tools.allow.contains(tool) && !ext.write_consent => {
                return Err(format!(
                    "tool {tool} is {class} and allowed without writeConsent"
                ));
            }
            "write" | "external" => {}
            other => return Err(format!("tool {tool} has unknown class {other}")),
        }
    }
    // 5: tool policy comes only from the spec.
    if let Some(t) = ext
        .tools
        .allow
        .iter()
        .find(|t| t.is_empty() || t.chars().any(char::is_control))
    {
        return Err(format!("bad tool name {:?}", t.escape_debug().to_string()));
    }
    let mut graphql = BTreeSet::new();
    for (tool, check) in &ext.arg_checks {
        if check != "graphql-read-only" {
            return Err(format!("unknown argCheck {check}"));
        }
        graphql.insert(tool.clone());
    }
    let login = ext.login.and_then(|l| {
        let _ = l.status;
        l.run
    });
    if login
        .as_deref()
        .is_some_and(|l| l.chars().any(char::is_control))
    {
        return Err("control characters in login.run".into());
    }
    Ok(Spec {
        id,
        file: PathBuf::new(),
        credential,
        command: ext.command,
        program,
        egress_hosts: ext.egress_hosts,
        allow: ext.tools.allow.into_iter().collect(),
        graphql,
        login,
    })
}

fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|v| collect_strings(v, out)),
        Value::Object(m) => m.values().for_each(|v| collect_strings(v, out)),
        _ => {}
    }
}

/// A conservative token sniff: common vendor prefixes, bearer values, JWTs.
fn looks_like_secret(s: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "AKIA",
        "sk-",
        "eyJ",
    ];
    let s = s.trim();
    let lower = s.to_ascii_lowercase();
    PREFIXES
        .iter()
        .any(|p| s.starts_with(p) && s.len() >= p.len() + 8)
        || ["bearer ", "token ", "basic "]
            .iter()
            .any(|p| lower.starts_with(p) && s.len() > p.len())
}

/// A bare public hostname: no scheme, port, IP literal, wildcard or
/// localhost.
fn check_host(host: &str) -> Result<(), String> {
    let bad = || {
        Err(format!(
            "egressHosts entry {:?} is not a bare public hostname",
            host.escape_debug().to_string()
        ))
    };
    let labels: Vec<&str> = host.split('.').collect();
    if host.len() > 253
        || labels.len() < 2
        || host != crate::proxy::normalize_hostname(host)
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()))
        || labels.iter().any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        return bad();
    }
    Ok(())
}

/// What launch detection found.
#[derive(Default)]
pub struct Detected {
    pub specs: Vec<Spec>,
    pub rejected: Vec<Rejected>,
    /// Skipped by `--no-mcp-broker`.
    pub disabled: Vec<String>,
}

/// Load every spec in `dir`. A file in `writable` (a tree the sandbox can
/// write), a symlink, or a spec that fails validation is rejected, never
/// loaded. No directory means no specs.
pub fn load(dir: &Path, writable: &[PathBuf], disabled: &[String]) -> Detected {
    let mut out = Detected::default();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let canon = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let real_dir = canon(dir);
    let dir_link = dir
        .symlink_metadata()
        .is_ok_and(|m| m.file_type().is_symlink());
    let mut files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    let mut seen = BTreeSet::new();
    for path in files {
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let tree = writable
            .iter()
            .find(|w| real_dir.starts_with(canon(w)) || canon(&path).starts_with(canon(w)));
        let file_link = path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink());
        // (reason, fix): the fix matches the cause; only a bad spec is
        // nav-pilot's to rewrite.
        let result = if dir_link {
            Err((
                format!("{} is a symlink", dir.display()),
                format!(
                    "replace the symlink {} with a real directory",
                    dir.display()
                ),
            ))
        } else if let Some(tree) = tree {
            Err((
                format!("{} is writable in the sandbox", tree.display()),
                format!(
                    "move XDG_CONFIG_HOME (or the spec) out of {}, or drop that write grant",
                    tree.display()
                ),
            ))
        } else if file_link {
            Err((
                "the spec is a symlink".into(),
                format!(
                    "replace the symlink {} with the file itself",
                    path.display()
                ),
            ))
        } else {
            let enable = || {
                let id = file.trim_end_matches(".json").replace("__", "/");
                format!("nav-pilot mcp enable {id}")
            };
            match crate::untrusted::read_untrusted(&path, SPEC_LIMIT) {
                Ok(Some(text)) => {
                    validate(&text, &file, crate::git::trusted_binary).map_err(|r| (r, enable()))
                }
                Ok(None) => Err(("not a regular file, or too large".into(), enable())),
                Err(e) => Err((format!("cannot read ({e})"), enable())),
            }
        };
        match result {
            Ok(spec) if disabled.contains(&spec.id) => out.disabled.push(spec.id),
            Ok(spec) if !seen.insert(spec.id.clone()) => {}
            Ok(mut spec) => {
                spec.file.clone_from(&path);
                out.specs.push(spec);
            }
            Err((reason, fix)) => {
                out.rejected.push(Rejected {
                    file: path.display().to_string(),
                    reason,
                    fix,
                });
            }
        }
    }
    out
}

/// Launch detection: load, print one line per rejected spec. The launch
/// always continues.
pub fn detect(home: &Path, writable: &[PathBuf], disabled: &[String]) -> Detected {
    let mut found = load(&spec_dir(home), writable, disabled);
    for r in &found.rejected {
        crate::ui::warn(&r.line());
    }
    if !cfg!(target_os = "macos") && !found.specs.is_empty() {
        crate::ui::warn(&format!(
            "the MCP broker runs on macOS only for now: {} left as configured.",
            found
                .specs
                .iter()
                .map(|s| s.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        found.specs.clear();
    }
    found
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

/// `cplt mcp status --json`.
pub fn status_json(found: &Detected, enabled: bool, probe: bool) -> Value {
    let mut servers: Vec<Value> = found
        .specs
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "state": if enabled { "brokered" } else { "off" },
                "transport": "unix",
                "credential": s.credential,
                "credential_ok": if probe { credential_ok(s) } else { None },
                "tools_allowed": s.allow.len(),
                "clients": ["opencode", "copilot"],
            })
        })
        .collect();
    servers.extend(
        found
            .disabled
            .iter()
            .map(|id| json!({"id": id, "state": "off"})),
    );
    json!({
        "version": STATUS_VERSION,
        "schema": SCHEMA_VERSIONS,
        "platform_supported": cfg!(target_os = "macos"),
        "servers": servers,
        "rejected": found.rejected,
    })
}

// ---------------------------------------------------------------------------
// GraphQL

#[derive(Debug, PartialEq)]
enum Tok {
    Name(String),
    Punct(char),
    /// A string, number or `...`: never a definition keyword.
    Other,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let cs: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        let c = cs[i];
        match c {
            ' ' | '\t' | '\n' | '\r' | ',' | '\u{feff}' => i += 1,
            '#' => {
                while i < cs.len() && cs[i] != '\n' && cs[i] != '\r' {
                    i += 1;
                }
            }
            '"' if cs.get(i + 1) == Some(&'"') && cs.get(i + 2) == Some(&'"') => {
                i += 3;
                loop {
                    match cs.get(i) {
                        None => return Err("unterminated block string".into()),
                        Some('\\') if cs[i..].starts_with(&['\\', '"', '"', '"']) => i += 4,
                        Some('"') if cs[i..].starts_with(&['"', '"', '"']) => {
                            i += 3;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Other);
            }
            '"' => {
                i += 1;
                loop {
                    match cs.get(i) {
                        None | Some('\n' | '\r') => return Err("unterminated string".into()),
                        Some('\\') => i += 2,
                        Some('"') => {
                            i += 1;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
                out.push(Tok::Other);
            }
            '.' if cs[i..].starts_with(&['.', '.', '.']) => {
                i += 3;
                out.push(Tok::Other);
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '_') {
                    i += 1;
                }
                out.push(Tok::Name(cs[start..i].iter().collect()));
            }
            c if c.is_ascii_digit() || c == '-' => {
                i += 1;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || ".+-".contains(cs[i])) {
                    i += 1;
                }
                out.push(Tok::Other);
            }
            '!' | '$' | '&' | '(' | ')' | '[' | ']' | '{' | '}' | ':' | '=' | '@' | '|' => {
                i += 1;
                out.push(Tok::Punct(c));
            }
            _ => return Err(format!("unexpected character {c:?}")),
        }
    }
    Ok(out)
}

/// Skip from a definition's start to just past its selection set. Braces
/// inside parentheses (object values in variable defaults or directive
/// arguments) are counted but do not open the selection set.
fn skip_definition(toks: &[Tok], mut i: usize) -> Result<usize, String> {
    let mut parens = 0usize;
    let mut braces = 0usize;
    let mut opened = false;
    while let Some(t) = toks.get(i) {
        i += 1;
        match t {
            Tok::Punct('(') => parens += 1,
            Tok::Punct(')') => parens = parens.checked_sub(1).ok_or("unbalanced )")?,
            Tok::Punct('{') => {
                if parens == 0 {
                    opened = true;
                }
                braces += 1;
            }
            Tok::Punct('}') => {
                braces = braces.checked_sub(1).ok_or("unbalanced }")?;
                if opened && braces == 0 && parens == 0 {
                    return Ok(i);
                }
            }
            _ => {}
        }
    }
    Err("unterminated definition".into())
}

/// The broker's `graphql-read-only` check (design 6.2): every definition in
/// the document, fragments included, must be a query or a fragment, with
/// exactly one operation. Anything it cannot read is refused.
pub fn graphql_read_only(doc: &str) -> Result<(), String> {
    let toks = lex(doc)?;
    let mut ops = 0;
    let mut i = 0;
    while let Some(t) = toks.get(i) {
        match t {
            Tok::Punct('{') => ops += 1,
            Tok::Name(n) if n == "query" => ops += 1,
            Tok::Name(n) if n == "fragment" => {}
            Tok::Name(n) if n == "mutation" || n == "subscription" => {
                return Err(format!("{n} operations are not allowed; only query"));
            }
            _ => return Err("not an executable GraphQL document".into()),
        }
        i = skip_definition(&toks, i)?;
    }
    match ops {
        1 => Ok(()),
        0 => Err("no operation in the document".into()),
        n => Err(format!("{n} operations in one document; send one query")),
    }
}

// ---------------------------------------------------------------------------
// Policy on the JSON-RPC stream

/// What to do with one line.
#[derive(Debug, PartialEq)]
pub enum Action {
    /// Pass this (possibly rewritten) line on.
    Forward(String),
    /// Answer the sender with this line instead; log the second part.
    Reply(String, Option<String>),
    /// Swallow it.
    Drop,
}

/// Requests from the client awaiting a server response: id → method.
#[derive(Default)]
pub struct Pending(HashMap<String, String>);

fn error_line(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// A message from the client, on its way to the server.
pub fn on_client(line: &str, spec: &Spec, pending: &mut Pending) -> Action {
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Action::Reply(error_line(&Value::Null, -32700, "parse error"), None),
    };
    if msg.is_array() {
        return Action::Reply(
            error_line(
                &Value::Null,
                -32600,
                "cplt: JSON-RPC batches are not supported",
            ),
            Some("batch → DENIED".into()),
        );
    }
    let Some(obj) = msg.as_object() else {
        return Action::Reply(error_line(&Value::Null, -32600, "invalid request"), None);
    };
    if let Err(key) = unambiguous(&msg) {
        return Action::Reply(
            error_line(
                obj.get("id").unwrap_or(&Value::Null),
                -32600,
                "cplt: ambiguous field name",
            ),
            Some(format!(
                "→ DENIED ambiguous key {:?}",
                key.escape_debug().to_string()
            )),
        );
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        // A response to a server request; those are not delivered (D13), so
        // there is nothing for it to answer.
        return Action::Drop;
    };
    let Some(id) = obj.get("id") else {
        // Notifications: only the ones a client sends, never a method that
        // policy checks (a server may answer an id-less call anyway).
        return if CLIENT_NOTIFICATIONS.contains(&method) {
            Action::Forward(msg.to_string())
        } else {
            Action::Drop
        };
    };
    if pending.0.contains_key(&id.to_string()) {
        return Action::Reply(
            error_line(id, DENIED, "cplt: request id already in flight"),
            Some(format!("{method} → DENIED duplicate id")),
        );
    }
    let deny = |why: String| {
        Action::Reply(
            error_line(id, DENIED, &format!("cplt: {why}")),
            Some(format!("{method} → DENIED {why}")),
        )
    };
    match method {
        "initialize" => {
            let v = msg
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str);
            if !v.is_some_and(|v| PROTOCOL_VERSIONS.contains(&v)) {
                return deny(format!(
                    "MCP protocol {} is not supported; use one of {PROTOCOL_VERSIONS:?}",
                    v.unwrap_or("(none)")
                ));
            }
        }
        "tools/call" => {
            let tool = msg
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !spec.allow.contains(tool) {
                return deny(format!(
                    "tool {:?} is not allowed for {}. Fix: nav-pilot mcp enable {}",
                    tool.escape_debug().to_string(),
                    spec.id,
                    spec.id
                ));
            }
            if spec.graphql.contains(tool) {
                // A server that folds case would see another key as `query`.
                let shadow = msg
                    .pointer("/params/arguments")
                    .and_then(Value::as_object)
                    .is_some_and(|a| {
                        a.keys()
                            .any(|k| k != "query" && k.eq_ignore_ascii_case("query"))
                    });
                if shadow {
                    return deny(format!("{tool}: an argument key folds to query"));
                }
                let query = msg
                    .pointer("/params/arguments/query")
                    .and_then(Value::as_str);
                if let Err(e) = query
                    .ok_or("no query argument".to_string())
                    .and_then(graphql_read_only)
                {
                    return deny(format!("{tool}: {e}"));
                }
            }
        }
        _ => {}
    }
    if pending.0.len() >= MAX_IN_FLIGHT {
        return Action::Reply(
            error_line(id, DENIED, "cplt: too many requests in flight; retry"),
            Some(format!("{method} → DENIED in-flight cap")),
        );
    }
    pending.0.insert(id.to_string(), method.to_string());
    // Re-serialized: the server parses exactly what was checked, whatever
    // its JSON parser does with duplicate keys or odd escapes.
    Action::Forward(msg.to_string())
}

/// Go's `encoding/json` (nais) matches struct fields case-insensitively,
/// with Unicode folding, so `"Name"` or `"nameſ"`-style keys would be read as
/// a field this broker checked under its exact spelling. In the envelope,
/// `params` and `params.arguments`, refuse two keys that fold together, and
/// any key that folds to a checked field without being spelt exactly so.
fn unambiguous(msg: &Value) -> Result<(), String> {
    const CHECKED: &[&str] = &[
        "jsonrpc",
        "id",
        "method",
        "params",
        "name",
        "arguments",
        "query",
        "protocolVersion",
    ];
    let fold = |k: &str| -> String {
        k.chars()
            .flat_map(char::to_lowercase)
            .map(|c| if c == '\u{17f}' { 's' } else { c })
            .collect()
    };
    let objects = [
        msg.as_object(),
        msg.get("params").and_then(Value::as_object),
        msg.pointer("/params/arguments").and_then(Value::as_object),
    ];
    for m in objects.into_iter().flatten() {
        let mut seen = BTreeSet::new();
        for k in m.keys() {
            let f = fold(k);
            if !seen.insert(f.clone()) || CHECKED.iter().any(|c| fold(c) == f && c != k) {
                return Err(k.clone());
            }
        }
    }
    Ok(())
}

/// A message from the server, on its way to the client.
pub fn on_server(line: &str, spec: &Spec, pending: &mut Pending) -> Action {
    let Ok(Value::Object(mut obj)) = serde_json::from_str::<Value>(line) else {
        return Action::Drop;
    };
    if let Some(method) = obj.get("method").and_then(Value::as_str) {
        // Server-initiated: not delivered (D13). A request gets an error so
        // the server does not wait on it.
        return match obj.get("id") {
            Some(id) => Action::Reply(
                error_line(id, -32601, &format!("cplt: {method} is not delivered")),
                None,
            ),
            None => Action::Drop,
        };
    }
    let Some(method) = obj
        .get("id")
        .and_then(|id| pending.0.remove(&id.to_string()))
    else {
        return Action::Drop;
    };
    // Filtered whatever the request was: an id cannot smuggle a tool list.
    let _ = method;
    if let Some(Value::Array(tools)) = obj.get_mut("result").and_then(|r| r.get_mut("tools")) {
        tools.retain(|t| {
            t.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| spec.allow.contains(n))
        });
    }
    Action::Forward(Value::Object(obj).to_string())
}

/// An auth failure in a server response, for mirroring to cplt's output.
fn auth_error(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("unauthenticated") || l.contains("not logged in") || l.contains("please log in")
}

// ---------------------------------------------------------------------------
// Runtime

/// Where broker lines go: cplt's terminal output and the `--proxy-log` file.
#[derive(Clone)]
pub struct Log {
    pub file: Option<PathBuf>,
}

impl Log {
    /// Every line (DENIED, auth, restart budget) reaches the terminal (D12)
    /// and the log file.
    fn line(&self, id: &str, text: &str) {
        let id = id.escape_debug().to_string();
        let text = text.escape_debug().to_string();
        eprintln!(
            "{}[mcp:{id}]{} {} {text}",
            crate::ui::color(crate::ui::YELLOW),
            crate::ui::color(crate::ui::RESET),
            crate::proxy::chrono_now()
        );
        if let Some(path) = &self.file
            && let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
        {
            let _ = writeln!(f, "{} [mcp:{id}] {text}", crate::proxy::iso_now());
        }
    }
}

struct Server {
    spec: Spec,
    /// The live child, if a client is connected. One per server.
    child: Mutex<Option<Arc<Mutex<Child>>>>,
    spawns: Mutex<VecDeque<Instant>>,
    /// This server's own CONNECT proxy, allowing only its `egressHosts`.
    egress_port: u16,
}

struct Shared {
    servers: BTreeMap<String, Server>,
    home: PathBuf,
    log: Log,
    stop: AtomicBool,
    /// Open connections (socket clients and egress tunnels together).
    open: Arc<AtomicUsize>,
}

/// Connections served at once; past this an accepted one is closed at once,
/// before any thread is spawned. Each holds a thread until it ends, and a
/// stalled handshake ends after its 10 s read timeout.
const MAX_CONNECTIONS: usize = 32;

/// A connection slot, released on drop.
struct Permit(Arc<AtomicUsize>);

impl Permit {
    #[allow(deprecated)] // `try_update` is not in the pinned 1.94 toolchain
    fn take(open: &Arc<AtomicUsize>) -> Option<Self> {
        open.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < MAX_CONNECTIONS).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(open)))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The running broker. Dropping it stops every child and removes the socket.
pub struct Broker {
    socket: PathBuf,
    #[cfg(target_os = "macos")]
    _dir: crate::scratch::PlaywrightSocketDir,
    shared: Arc<Shared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Broker {
    /// Bind the socket and serve `specs`. The child's egress goes through the
    /// proxy on `proxy_port`, whose allowlist already holds the specs' hosts.
    #[cfg(target_os = "macos")]
    pub fn start(specs: Vec<Spec>, home: &Path, log: Log) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::scratch::PlaywrightSocketDir::create()?;
        let socket = dir.path().join("m");
        let listener = std::os::unix::net::UnixListener::bind(&socket)
            .map_err(|e| format!("cannot bind {}: {e}", socket.display()))?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot restrict {}: {e}", socket.display()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot poll {}: {e}", socket.display()))?;
        let mut egress = Vec::new();
        let mut servers = BTreeMap::new();
        for spec in specs {
            let l = std::net::TcpListener::bind("127.0.0.1:0")
                .and_then(|l| l.set_nonblocking(true).map(|()| l))
                .map_err(|e| format!("cannot start the egress proxy: {e}"))?;
            let egress_port = l.local_addr().map_err(|e| e.to_string())?.port();
            egress.push((spec.id.clone(), l));
            let server = Server {
                spec,
                child: Mutex::new(None),
                spawns: Mutex::new(VecDeque::new()),
                egress_port,
            };
            servers.insert(server.spec.id.clone(), server);
        }
        let shared = Arc::new(Shared {
            servers,
            home: home.to_path_buf(),
            log,
            stop: AtomicBool::new(false),
            open: Arc::new(AtomicUsize::new(0)),
        });
        for (id, l) in egress {
            let s = Arc::clone(&shared);
            std::thread::spawn(move || {
                let Some(server) = s.servers.get(&id) else {
                    return;
                };
                while !s.stop.load(Ordering::Acquire) {
                    match l.accept() {
                        Ok((stream, _)) => {
                            let Some(permit) = Permit::take(&s.open) else {
                                continue;
                            };
                            let hosts = server.spec.egress_hosts.clone();
                            let (log, id) = (s.log.clone(), id.clone());
                            std::thread::spawn(move || {
                                let _permit = permit;
                                egress_tunnel(stream, &hosts, &log, &id);
                            });
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            });
        }
        let s = Arc::clone(&shared);
        let thread = std::thread::spawn(move || {
            while !s.stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let Some(permit) = Permit::take(&s.open) else {
                            continue;
                        };
                        let s = Arc::clone(&s);
                        std::thread::spawn(move || {
                            let _permit = permit;
                            serve(&s, stream);
                        });
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Self {
            socket,
            _dir: dir,
            shared,
            thread: Some(thread),
        })
    }

    /// Linux needs a bwrap bind for the socket first (phase 1b).
    #[cfg(not(target_os = "macos"))]
    pub fn start(_: Vec<Spec>, _: &Path, _: Log) -> Result<Self, String> {
        Err("the MCP broker runs on macOS only for now".into())
    }

    /// The socket path the sandbox profile grants connect to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub fn specs(&self) -> impl Iterator<Item = &Spec> {
        self.shared.servers.values().map(|s| &s.spec)
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for server in self.shared.servers.values() {
            let child = server.child.lock().ok().and_then(|mut c| c.take());
            if let Some(child) = child {
                kill(&child);
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// SIGTERM, a short grace, SIGKILL, then reap.
fn kill(child: &Mutex<Child>) {
    let Ok(mut child) = child.lock() else { return };
    // Reaped (or unknown): its pid may belong to someone else now.
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: kill(2) on our own child, which try_wait just saw unreaped
        // and which nothing else reaps (we hold its lock).
        unsafe { libc::kill(pid, libc::SIGTERM) };
    }
    let start = Instant::now();
    while start.elapsed() < KILL_GRACE {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Still unreaped under our lock, so the pid is still ours.
    let _ = child.kill();
    let _ = child.wait();
}

fn read_line(r: &mut impl BufRead, limit: u64) -> Option<String> {
    let mut buf = Vec::new();
    let n = r.take(limit + 1).read_until(b'\n', &mut buf).ok()?;
    if n == 0 || buf.len() as u64 > limit {
        return None;
    }
    String::from_utf8(buf)
        .ok()
        .map(|s| s.trim_end_matches(['\n', '\r']).to_string())
}

fn write_line(w: &Mutex<impl Write>, line: &str) -> bool {
    let Ok(mut w) = w.lock() else { return false };
    w.write_all(line.as_bytes())
        .and_then(|()| w.write_all(b"\n"))
        .and_then(|()| w.flush())
        .is_ok()
}

fn spawn_child(shared: &Shared, server: &Server) -> std::io::Result<Child> {
    let spec = &server.spec;
    let proxy = format!("http://127.0.0.1:{}", server.egress_port);
    #[allow(clippy::disallowed_methods)] // resolved in the trusted dirs at load
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.command[1..])
        .env_clear()
        .env("HOME", &shared.home)
        .env("PATH", crate::git::TRUSTED_BIN_DIRS.join(":"))
        .env("TMPDIR", std::env::temp_dir())
        .env("HTTPS_PROXY", &proxy)
        .env("HTTP_PROXY", &proxy)
        .env("https_proxy", &proxy)
        .env("http_proxy", &proxy)
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        // Never the agent-writable project: `python3 -m x` imports from cwd.
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // ponytail: stderr dropped; route it to the proxy log, bounded and
        // redacted, when a server's own diagnostics are needed.
        .stderr(Stdio::null());
    if let Some(lang) = std::env::var_os("LANG") {
        cmd.env("LANG", lang);
    }
    cmd.spawn()
}

/// The egress decision for a CONNECT target: port 443 only, host equal to
/// or a subdomain of an `egressHosts` entry. Returns the host to dial.
pub fn egress_allowed(target: &str, hosts: &[String]) -> Result<String, String> {
    let (host, port) = target.rsplit_once(':').ok_or("no port")?;
    if port != "443" {
        return Err(format!("port {port}"));
    }
    let host = crate::proxy::normalize_hostname(host);
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("not a hostname".into());
    }
    if hosts
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
    {
        Ok(host)
    } else {
        Err(format!("{host} is not in egressHosts"))
    }
}

/// A public address: the child must not be steered at loopback or the LAN
/// through a name it is allowed.
fn public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            !(v.is_loopback()
                || v.is_private()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.octets()[0] == 100 && v.octets()[1] & 0xc0 == 64)
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80)
                && v.to_ipv4_mapped().is_none_or(|m| public_ip(m.into()))
        }
    }
}

/// One child connection to its egress proxy: a CONNECT head, the policy
/// check, then bytes both ways. Anything else gets 403.
fn egress_tunnel(client: std::net::TcpStream, hosts: &[String], log: &Log, id: &str) {
    use std::net::{TcpStream, ToSocketAddrs};
    let _ = client.set_nonblocking(false);
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(read_half) = client.try_clone() else {
        return;
    };
    let mut r = BufReader::new(read_half);
    let Some(first) = read_line(&mut r, 2048) else {
        return;
    };
    // Skip the rest of the head.
    loop {
        match read_line(&mut r, 8192) {
            Some(l) if l.is_empty() => break,
            Some(_) => {}
            None => return,
        }
    }
    let mut w = &client;
    let mut parts = first.split(' ');
    let decision = match (parts.next(), parts.next()) {
        (Some("CONNECT"), Some(target)) => egress_allowed(target, hosts),
        _ => Err("only CONNECT is proxied".into()),
    };
    let upstream = decision.and_then(|host| {
        let addrs: Vec<_> = (host.as_str(), 443)
            .to_socket_addrs()
            .map_err(|e| format!("{host}: {e}"))?
            .filter(|a| public_ip(a.ip()))
            .collect();
        let mut last = String::from("no public address");
        for a in &addrs {
            match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
                Ok(s) => return Ok(s),
                Err(e) => last = format!("{a}: {e}"),
            }
        }
        Err(format!("CONNECT-FAIL {host} ({last})"))
    });
    let upstream = match upstream {
        Ok(u) => u,
        Err(why) => {
            log.line(id, &format!("egress → DENIED {why}"));
            let _ = w.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return;
        }
    };
    if w.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    let _ = client.set_read_timeout(None);
    let (Ok(mut up_w), Ok(mut down_w)) = (upstream.try_clone(), client.try_clone()) else {
        return;
    };
    // Bytes the head reader buffered past the blank line go first.
    let buffered = r.buffer().to_vec();
    let mut r = r.into_inner();
    let up = std::thread::spawn(move || {
        if up_w.write_all(&buffered).is_ok() {
            let _ = std::io::copy(&mut r, &mut up_w);
        }
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    let mut upstream = upstream;
    let _ = std::io::copy(&mut upstream, &mut down_w);
    let _ = down_w.shutdown(std::net::Shutdown::Both);
    let _ = up.join();
}

/// One client connection: the id line, then JSON-RPC lines both ways until
/// either side ends. The child lives exactly as long as the connection: an
/// MCP stdio session cannot be resumed, so the client reconnects and
/// re-initializes against a fresh child.
fn serve(shared: &Shared, stream: UnixStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let client = Arc::new(Mutex::new(stream));
    let refuse = |msg: &str| {
        write_line(
            &client,
            &error_line(&Value::Null, DENIED, &format!("cplt: {msg}")),
        );
    };
    let Some(id) = read_line(&mut reader, 512) else {
        return;
    };
    let Some(server) = shared.servers.get(&id) else {
        refuse("no brokered MCP server with that id");
        return;
    };
    let spec = &server.spec;
    if let Ok(s) = client.lock() {
        let _ = s.set_read_timeout(None);
    }
    let child = {
        let Ok(mut slot) = server.child.lock() else {
            return;
        };
        // Under the slot lock: Drop sets `stop` before scanning the slots,
        // so either it sees this child or no child is started.
        if shared.stop.load(Ordering::Acquire) {
            return;
        }
        if slot.is_some() {
            // ponytail: one client per server; multiplexing needs id rewriting.
            refuse("this MCP server already has a client in this session");
            return;
        }
        let Ok(mut spawns) = server.spawns.lock() else {
            return;
        };
        while spawns
            .front()
            .is_some_and(|t| t.elapsed() > Duration::from_secs(60))
        {
            spawns.pop_front();
        }
        if spawns.len() >= SPAWNS_PER_MINUTE {
            shared.log.line(
                &spec.id,
                &format!(
                    "stopped after {SPAWNS_PER_MINUTE} restarts in a minute; see the proxy log"
                ),
            );
            refuse("server stopped after too many restarts");
            return;
        }
        spawns.push_back(Instant::now());
        match spawn_child(shared, server) {
            Ok(c) => {
                let c = Arc::new(Mutex::new(c));
                *slot = Some(Arc::clone(&c));
                c
            }
            Err(e) => {
                shared
                    .log
                    .line(&spec.id, &format!("FAIL cannot start: {e}"));
                refuse("cannot start the server");
                return;
            }
        }
    };
    let (stdin, stdout) = {
        let Ok(mut c) = child.lock() else { return };
        (c.stdin.take(), c.stdout.take())
    };
    let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
        return;
    };
    let stdin: Arc<Mutex<ChildStdin>> = Arc::new(Mutex::new(stdin));
    let pending = Arc::new(Mutex::new(Pending::default()));

    // Server → client. On child exit, close the client's socket.
    let out = {
        let (client, stdin, pending) = (
            Arc::clone(&client),
            Arc::clone(&stdin),
            Arc::clone(&pending),
        );
        let spec = spec.clone();
        let log = shared.log.clone();
        std::thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            while let Some(line) = read_line(&mut r, MAX_MESSAGE) {
                if auth_error(&line) {
                    let fix = spec
                        .login
                        .as_deref()
                        .map(|l| format!(" Fix: {l}"))
                        .unwrap_or_default();
                    log.line(&spec.id, &format!("FAIL not logged in on the host.{fix}"));
                }
                let action = match pending.lock() {
                    Ok(mut p) => on_server(&line, &spec, &mut p),
                    Err(_) => break,
                };
                match action {
                    Action::Forward(l) => {
                        if !write_line(&client, &l) {
                            break;
                        }
                    }
                    Action::Reply(l, _) => {
                        write_line(&stdin, &l);
                    }
                    Action::Drop => {}
                }
            }
            if let Ok(c) = client.lock() {
                let _ = c.shutdown(std::net::Shutdown::Both);
            }
        })
    };

    // Client → server.
    while let Some(line) = read_line(&mut reader, MAX_MESSAGE) {
        let action = match pending.lock() {
            Ok(mut p) => on_client(&line, spec, &mut p),
            Err(_) => break,
        };
        match action {
            Action::Forward(l) => {
                if !write_line(&stdin, &l) {
                    break;
                }
            }
            Action::Reply(l, log) => {
                if let Some(text) = log {
                    shared.log.line(&spec.id, &text);
                }
                if !write_line(&client, &l) {
                    break;
                }
            }
            Action::Drop => {}
        }
    }
    // Client gone (or the socket was closed): end the child.
    drop(stdin);
    if let Ok(mut slot) = server.child.lock()
        && slot.as_ref().is_some_and(|c| Arc::ptr_eq(c, &child))
    {
        *slot = None;
    }
    kill(&child);
    let _ = out.join();
}

// ---------------------------------------------------------------------------
// Client side

/// `cplt mcp-stdio <id>`, inside the sandbox: copy stdio to the broker.
pub fn run_stdio(id: &str) -> ExitCode {
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!("cplt mcp-stdio: {SOCKET_ENV} is not set; run inside a cplt session");
        return ExitCode::FAILURE;
    };
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cplt mcp-stdio: cannot reach the broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    if writeln!(stream, "{id}").is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(mut up) = stream.try_clone() else {
        return ExitCode::FAILURE;
    };
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut stream, &mut std::io::stdout().lock());
    ExitCode::SUCCESS
}

/// Does a client entry's command run `spec`'s command?
fn runs(spec: &Spec, argv: &[&str]) -> bool {
    let Some((first, rest)) = argv.split_first() else {
        return false;
    };
    Path::new(first).file_name().and_then(|f| f.to_str()) == Some(spec.command[0].as_str())
        && rest.starts_with(
            &spec.command[1..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
}

fn str_array(v: Option<&Value>) -> Vec<&str> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// The user's OpenCode config files (the same set as
/// [`crate::github_mcp::configured_servers`]), parsed.
pub fn opencode_configs(home: &Path, content: Option<&str>) -> Vec<Value> {
    let mut dirs =
        vec![crate::opencode_v2::xdg_base("XDG_CONFIG_HOME", home, ".config").join("opencode")];
    dirs.extend(
        std::env::var_os("OPENCODE_CONFIG_DIR")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute()),
    );
    let mut texts: Vec<String> = dirs
        .iter()
        .flat_map(|d| ["config.json", "opencode.json", "opencode.jsonc"].map(|f| d.join(f)))
        .filter_map(|f| {
            crate::untrusted::read_untrusted(&f, CONFIG_LIMIT)
                .ok()
                .flatten()
        })
        .collect();
    texts.extend(content.map(str::to_string));
    texts
        .iter()
        .filter_map(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .collect()
}

/// `OPENCODE_CONFIG_CONTENT` with each brokered server's entry pointed at
/// `cplt mcp-stdio <id>`. The user's entries that run the spec's command are
/// overlaid in place (v2 `mcp.servers.<n>` or legacy `mcp.<n>`); with none, an
/// entry named after the id is added. `None` when `existing` is not a JSON
/// object.
pub fn opencode_overlay(
    existing: Option<&str>,
    configs: &[Value],
    specs: &[&Spec],
    socket: &Path,
) -> Option<String> {
    let mut root = match existing.map(str::trim).filter(|s| !s.is_empty()) {
        None => Map::new(),
        Some(s) => match serde_json::from_str(s).ok()? {
            Value::Object(m) => m,
            _ => return None,
        },
    };
    // Every name the user's files or this overlay already use: a fallback
    // must never land on one.
    let mut used: BTreeSet<String> = configs
        .iter()
        .flat_map(|c| [c.pointer("/mcp/servers"), c.get("mcp")])
        .chain([
            root.get("mcp").and_then(|m| m.get("servers")),
            root.get("mcp"),
        ])
        .filter_map(|m| m.and_then(Value::as_object))
        .flat_map(|m| m.keys().cloned())
        .collect();
    for spec in specs {
        let mut names: Vec<(bool, String)> = Vec::new();
        for c in configs {
            for (v2, map) in [(true, c.pointer("/mcp/servers")), (false, c.get("mcp"))] {
                for (name, s) in map.and_then(Value::as_object).into_iter().flatten() {
                    if runs(spec, &str_array(s.get("command"))) {
                        names.push((v2, name.clone()));
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        if names.is_empty() {
            names.push((true, free_name(spec, &mut used, true)));
        }
        for (v2, name) in names {
            let mut parent = object_at(&mut root, "mcp")?;
            if v2 {
                parent = object_at(parent, "servers")?;
            }
            // Wholesale, so nothing of a same-named entry in this value
            // survives. OpenCode still deep-merges keys from the files.
            parent.insert(
                name,
                json!({
                    "type": "local",
                    "command": ["cplt", "mcp-stdio", spec.id],
                    "environment": {SOCKET_ENV: socket.display().to_string()},
                }),
            );
        }
    }
    Some(Value::Object(root).to_string())
}

/// A name no user entry or earlier spec has: the short name (when
/// `short_first`), then the full id, then the full id with a counter.
fn free_name(spec: &Spec, used: &mut BTreeSet<String>, short_first: bool) -> String {
    let full = spec.full_name();
    let mut name = if short_first {
        spec.short_name().to_string()
    } else {
        full.clone()
    };
    let mut n = 1;
    while used.contains(&name) {
        name = if n == 1 {
            full.clone()
        } else {
            format!("{full}-{n}")
        };
        n += 1;
    }
    used.insert(name.clone());
    name
}

fn object_at<'a>(map: &'a mut Map<String, Value>, key: &str) -> Option<&'a mut Map<String, Value>> {
    map.entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
}

/// Copilot CLI args: `--disable-mcp-server` for each user entry that runs a
/// spec's command under another name, and one `--additional-mcp-config` with
/// the brokered entries. The first matching user entry keeps its name, so its
/// tool names and approvals stay the same.
pub fn copilot_args(mcp_config: Option<&str>, specs: &[&Spec], socket: &Path) -> Vec<String> {
    let user: Value = mcp_config
        .and_then(|t| serde_json::from_str(&crate::agent::strip_jsonc(t)).ok())
        .unwrap_or(Value::Null);
    let mut args = Vec::new();
    let mut servers = Map::new();
    let mut used: BTreeSet<String> = user
        .get("mcpServers")
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    for spec in specs {
        let mut matching: Vec<&String> = user
            .get("mcpServers")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, s)| {
                let mut argv = vec![s.get("command").and_then(Value::as_str).unwrap_or("")];
                argv.extend(str_array(s.get("args")));
                runs(spec, &argv)
            })
            .map(|(n, _)| n)
            .collect();
        matching.sort();
        // Its own name: whether --additional-mcp-config wins over a
        // same-named user entry is not documented, so never share one.
        let name = free_name(spec, &mut used, false);
        for other in &matching {
            args.push("--disable-mcp-server".into());
            args.push((*other).clone());
        }
        servers.insert(
            name,
            json!({
                "type": "local",
                "command": "cplt",
                "args": ["mcp-stdio", spec.id],
                "env": {SOCKET_ENV: socket.display().to_string()},
                "tools": ["*"],
            }),
        );
    }
    if !servers.is_empty() {
        args.push("--additional-mcp-config".into());
        args.push(json!({"mcpServers": servers}).to_string());
    }
    args
}

/// Point OpenCode v2 at the broker: merge the overlay into the session's
/// `OPENCODE_CONFIG_CONTENT` (which the GitHub MCP proxy may already have
/// set), else the host's when it reaches the session.
pub fn opencode(
    env: &mut Vec<(String, String)>,
    home: &Path,
    broker: &Broker,
    deny_env: &[String],
    host_reaches: bool,
) {
    const VAR: &str = "OPENCODE_CONFIG_CONTENT";
    if deny_env.iter().any(|d| d == VAR) {
        crate::ui::warn(
            "deny.env names OPENCODE_CONFIG_CONTENT: brokered MCP servers left as configured in OpenCode.",
        );
        return;
    }
    let pos = env.iter().position(|(k, _)| k == VAR);
    let existing = match pos {
        Some(i) => Some(env[i].1.clone()),
        None => host_reaches.then(|| std::env::var(VAR).ok()).flatten(),
    };
    let specs: Vec<&Spec> = broker.specs().collect();
    let configs = opencode_configs(home, existing.as_deref());
    match opencode_overlay(existing.as_deref(), &configs, &specs, broker.socket()) {
        Some(value) => match pos {
            Some(i) => env[i].1 = value,
            None => env.push((VAR.into(), value)),
        },
        None => crate::ui::warn(
            "OPENCODE_CONFIG_CONTENT is not a JSON object: brokered MCP servers left as configured.",
        ),
    }
}

/// The Copilot CLI args for the broker, from the user's
/// `~/.copilot/mcp-config.json`.
pub fn copilot(home: &Path, broker: &Broker) -> Vec<String> {
    let text =
        crate::untrusted::read_untrusted(&home.join(".copilot/mcp-config.json"), CONFIG_LIMIT)
            .ok()
            .flatten();
    let specs: Vec<&Spec> = broker.specs().collect();
    copilot_args(text.as_deref(), &specs, broker.socket())
}

/// `cplt mcp status [--json]`. Reads the specs as a launch from the current
/// directory would, without starting anything.
pub fn run_status(as_json: bool, home: &Path, found: &Detected, enabled: bool) -> ExitCode {
    let status = status_json(found, enabled && cfg!(target_os = "macos"), true);
    if as_json {
        println!("{status}");
        return ExitCode::SUCCESS;
    }
    println!("MCP broker specs in {}", spec_dir(home).display());
    for s in status["servers"].as_array().into_iter().flatten() {
        println!(
            "  {}  {}  credential_ok: {}",
            s["id"].as_str().unwrap_or("").escape_debug(),
            s["state"].as_str().unwrap_or(""),
            s["credential_ok"]
        );
    }
    for r in &found.rejected {
        println!("  {}", r.line());
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_json(ext: Value) -> String {
        json!({"name": "io.github.nais/nais-mcp", "version": "7.0.1", "_meta": {META_KEY: ext}})
            .to_string()
    }

    fn base() -> Value {
        json!({
            "v": 1,
            "credential": "nais-keychain",
            "command": ["nais", "alpha", "mcp", "serve"],
            "egressHosts": ["console.nav.cloud.nais.io"],
            "tools": {"allow": ["get_nais_context", "execute_graphql"], "classes": {}},
            "argChecks": {"execute_graphql": "graphql-read-only"},
            "login": {"run": "nais login -n", "status": "nais auth print-access-token"}
        })
    }

    const FILE: &str = "io.github.nais__nais-mcp.json";

    fn check(ext: Value) -> Result<Spec, String> {
        validate(&spec_json(ext), FILE, |n| {
            Some(PathBuf::from("/opt/homebrew/bin").join(n))
        })
    }

    fn with(mut v: Value, ptr: &str, x: Value) -> Value {
        *v.pointer_mut(ptr).unwrap() = x;
        v
    }

    #[test]
    fn accepts_the_nais_spec() {
        let s = check(base()).unwrap();
        assert_eq!(s.id, "io.github.nais/nais-mcp");
        assert_eq!(s.program, PathBuf::from("/opt/homebrew/bin/nais"));
        assert!(s.graphql.contains("execute_graphql"));
        assert_eq!(s.login.as_deref(), Some("nais login -n"));
    }

    #[test]
    fn rejects_unknown_version_unknown_fields_and_wrong_file() {
        assert!(
            check(with(base(), "/v", json!(2)))
                .unwrap_err()
                .contains("v2")
        );
        let mut v = base();
        v["extra"] = json!(1);
        assert!(check(v).is_err());
        assert!(
            validate(&spec_json(base()), "x.json", |_| None)
                .unwrap_err()
                .contains("file name")
        );
    }

    #[test]
    fn invariant_1_mechanism_and_command() {
        assert!(check(with(base(), "/credential", json!("aws"))).is_err());
        assert!(
            check(with(base(), "/credential", json!("gh-token")))
                .unwrap_err()
                .contains("built-in")
        );
        assert!(
            check(with(
                base(),
                "/command",
                json!(["nais", "alpha", "mcp", "serve", "--x"])
            ))
            .is_err()
        );
        assert!(check(with(base(), "/command", json!(["bash", "-c", "x"]))).is_err());
        let none = with(base(), "/credential", json!("none"));
        assert!(check(with(none, "/command", json!(["uvx", "srv"]))).is_ok());
    }

    #[test]
    fn invariant_2_no_secrets() {
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["packages"] = json!([{"environmentVariables": [{"name": "K", "isSecret": true}]}]);
        assert!(validate(&root.to_string(), FILE, |_| Some("/bin/x".into())).is_err());
        let none = with(base(), "/credential", json!("none"));
        let cmd = with(none, "/command", json!(["srv", "ghp_abcdefghijklmnop"]));
        assert!(check(cmd).unwrap_err().contains("secret"));
    }

    #[test]
    fn invariant_3_classes() {
        let hx = with(base(), "/tools/classes", json!({"run": "host-exec"}));
        assert!(check(hx).unwrap_err().contains("host-exec"));
        let w = with(
            base(),
            "/tools/classes",
            json!({"execute_graphql": "write"}),
        );
        assert!(check(w.clone()).unwrap_err().contains("writeConsent"));
        let mut ok = w;
        ok["writeConsent"] = json!(true);
        assert!(check(ok).is_ok());
        // A write tool that is not allowed needs no consent.
        assert!(check(with(base(), "/tools/classes", json!({"other": "write"}))).is_ok());
    }

    #[test]
    fn invariant_4_https_and_trusted_dirs() {
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["remotes"] = json!([{"type": "streamable-http", "url": "http://x.example"}]);
        assert!(
            validate(&root.to_string(), FILE, |_| Some("/bin/x".into()))
                .unwrap_err()
                .contains("https")
        );
        assert!(
            validate(&spec_json(base()), FILE, |_| None)
                .unwrap_err()
                .contains("trusted")
        );
        let none = with(base(), "/credential", json!("none"));
        assert!(
            check(with(none, "/command", json!(["/tmp/x"])))
                .unwrap_err()
                .contains("bare")
        );
        for h in [
            "localhost",
            "1.2.3.4",
            "x.example:443",
            "https://x.example",
            "*.example.com",
            "X.example",
        ] {
            assert!(
                check(with(base(), "/egressHosts", json!([h]))).is_err(),
                "{h}"
            );
        }
    }

    #[test]
    fn invariant_5_policy_only_from_the_spec() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |t: &str| {
            json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":t,"arguments":{}}})
                .to_string()
        };
        assert!(matches!(
            on_client(&call("delete_app"), &s, &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call("get_nais_context"), &s, &mut p),
            Action::Forward(_)
        ));
        assert!(check(with(base(), "/argChecks", json!({"x": "regex"}))).is_err());
    }

    #[test]
    fn invariant_6_no_placeholders() {
        let none = with(base(), "/credential", json!("none"));
        assert!(
            check(with(
                none.clone(),
                "/command",
                json!(["srv", "--token", "${TOKEN}"])
            ))
            .is_err()
        );
        assert!(check(with(none, "/command", json!(["srv", "{api_key}"]))).is_err());
        let mut root: Value = serde_json::from_str(&spec_json(base())).unwrap();
        root["remotes"] = json!([{"url": "https://x.example", "headers": [{"name": "Authorization", "value": "Bearer {token}"}]}]);
        assert!(validate(&root.to_string(), FILE, |_| Some("/bin/x".into())).is_err());
    }

    #[test]
    fn load_refuses_symlinks_and_writable_trees() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        std::fs::write(&real, spec_json(base())).unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join(FILE)).unwrap();
        let found = load(dir.path(), &[], &[]);
        assert!(found.specs.is_empty());
        let r = found
            .rejected
            .iter()
            .find(|r| r.reason.contains("symlink"))
            .unwrap();
        assert!(r.fix.starts_with("replace the symlink"), "{r:?}");
        std::fs::remove_file(dir.path().join(FILE)).unwrap();
        std::fs::rename(&real, dir.path().join(FILE)).unwrap();
        let found = load(dir.path(), &[dir.path().to_path_buf()], &[]);
        assert!(
            found.specs.is_empty() && found.rejected[0].reason.contains("writable in the sandbox")
        );
        assert!(
            load(&dir.path().join("missing"), &[], &[])
                .rejected
                .is_empty()
        );
    }

    #[test]
    fn graphql_checker() {
        for ok in [
            "{ me { name } }",
            "query Q($a: In = {x: 1}) @d(v: {y: 2}) { a(b: \"mutation {\") { ...F } }\nfragment F on T { c }",
            "# mutation\nquery mutation { mutation }",
            "query { a(s: \"\"\"block \\\"\"\" mutation\"\"\") }",
        ] {
            assert_eq!(graphql_read_only(ok), Ok(()), "{ok}");
        }
        for bad in [
            "mutation { delete }",
            "subscription { s }",
            "query A { a } query B { b }",
            "{ a } mutation M { m }",
            "fragment F on T { a }",
            "fragment F on T { a } mutation { m }",
            "query { a ",
            "query { a(s: \"x) }",
            "type Query { a: Int }",
            "query { a } }",
            "",
            "query { a ^ }",
        ] {
            assert!(graphql_read_only(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn graphql_arg_check_on_tools_call() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let call = |q: Value| {
            json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_graphql","arguments":{"query":q}}}).to_string()
        };
        assert!(matches!(
            on_client(&call(json!("mutation { x }")), &s, &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call(json!(1)), &s, &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&call(json!("{ me { id } }")), &s, &mut p),
            Action::Forward(_)
        ));
    }

    #[test]
    fn batch_and_protocol_rejected() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        assert!(matches!(
            on_client(r#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#, &s, &mut p),
            Action::Reply(..)
        ));
        let init = |v: &str| {
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":v}})
                .to_string()
        };
        assert!(matches!(
            on_client(&init("2025-03-26"), &s, &mut p),
            Action::Reply(..)
        ));
        assert!(matches!(
            on_client(&init("2025-11-25"), &s, &mut p),
            Action::Forward(_)
        ));
    }

    #[test]
    fn tools_list_is_filtered_and_unsolicited_dropped() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let list = r#"{"jsonrpc":"2.0","id":"a","method":"tools/list"}"#;
        assert!(matches!(on_client(list, &s, &mut p), Action::Forward(_)));
        let resp = r#"{"jsonrpc":"2.0","id":"a","result":{"tools":[{"name":"get_nais_context"},{"name":"delete_app"}]}}"#;
        let Action::Forward(out) = on_server(resp, &s, &mut p) else {
            panic!()
        };
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["result"]["tools"], json!([{"name": "get_nais_context"}]));
        // Same id again: no longer pending.
        assert_eq!(on_server(resp, &s, &mut p), Action::Drop);
        assert_eq!(
            on_server(
                r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
                &s,
                &mut p
            ),
            Action::Drop
        );
        assert!(matches!(
            on_server(
                r#"{"jsonrpc":"2.0","id":9,"method":"roots/list"}"#,
                &s,
                &mut p
            ),
            Action::Reply(..)
        ));
    }

    #[test]
    fn in_flight_cap() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for i in 0..MAX_IN_FLIGHT {
            let l = json!({"jsonrpc":"2.0","id":i,"method":"ping"}).to_string();
            assert!(matches!(on_client(&l, &s, &mut p), Action::Forward(_)));
        }
        assert!(matches!(
            on_client(r#"{"jsonrpc":"2.0","id":99,"method":"ping"}"#, &s, &mut p),
            Action::Reply(..)
        ));
    }

    #[test]
    fn client_overlays() {
        let s = check(base()).unwrap();
        let sock = Path::new("/private/tmp/x/m");
        let user = json!({"mcp": {"servers": {"nais": {"type": "local", "command": ["/opt/homebrew/bin/nais", "alpha", "mcp", "serve"]}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[user], &[&s], sock).unwrap()).unwrap();
        assert_eq!(
            out["mcp"]["servers"]["nais"]["command"],
            json!(["cplt", "mcp-stdio", "io.github.nais/nais-mcp"])
        );
        let out: Value =
            serde_json::from_str(&opencode_overlay(Some(r#"{"a":1}"#), &[], &[&s], sock).unwrap())
                .unwrap();
        assert_eq!(out["a"], 1);
        assert_eq!(out["mcp"]["servers"]["nais-mcp"]["type"], "local");
        assert!(opencode_overlay(Some("[]"), &[], &[&s], sock).is_none());

        let cfg = r#"{"mcpServers":{"b":{"command":"nais","args":["alpha","mcp","serve"]},"a":{"command":"nais","args":["alpha","mcp","serve"]},"c":{"command":"x"}}}"#;
        let args = copilot_args(Some(cfg), &[&s], sock);
        assert_eq!(
            args[..5],
            [
                "--disable-mcp-server",
                "a",
                "--disable-mcp-server",
                "b",
                "--additional-mcp-config"
            ]
        );
        let v: Value = serde_json::from_str(&args[5]).unwrap();
        assert_eq!(
            v["mcpServers"]["io.github.nais__nais-mcp"]["args"],
            json!(["mcp-stdio", "io.github.nais/nais-mcp"])
        );
        assert!(copilot_args(None, &[], sock).is_empty());
    }

    #[test]
    fn id_less_calls_never_pass() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for m in [
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_app"}}"#,
            r#"{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"1999"}}"#,
            r#"{"jsonrpc":"2.0","method":"tools/list"}"#,
        ] {
            assert_eq!(on_client(m, &s, &mut p), Action::Drop, "{m}");
        }
        let ok = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(matches!(on_client(ok, &s, &mut p), Action::Forward(_)));
    }

    #[test]
    fn forwards_what_it_checked() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        // serde keeps the last duplicate; the server must see the same.
        let dup = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_app","name":"get_nais_context"}}"#;
        let Action::Forward(out) = on_client(dup, &s, &mut p) else {
            panic!()
        };
        assert!(!out.contains("delete_app"), "{out}");
        let fold = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_graphql","arguments":{"query":"{ a }","Query":"mutation { x }"}}}).to_string();
        assert!(matches!(on_client(&fold, &s, &mut p), Action::Reply(..)));
    }

    #[test]
    fn duplicate_ids_and_smuggled_tool_lists() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        let ping = r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#;
        assert!(matches!(on_client(ping, &s, &mut p), Action::Forward(_)));
        let list = r#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#;
        assert!(matches!(on_client(list, &s, &mut p), Action::Reply(..)));
        let resp = r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"delete_app"}]}}"#;
        let Action::Forward(out) = on_server(resp, &s, &mut p) else {
            panic!()
        };
        assert!(!out.contains("delete_app"), "{out}");
    }

    #[test]
    fn egress_policy() {
        let hosts = vec!["console.nav.cloud.nais.io".to_string()];
        assert!(egress_allowed("console.nav.cloud.nais.io:443", &hosts).is_ok());
        assert!(egress_allowed("x.console.nav.cloud.nais.io:443", &hosts).is_ok());
        assert!(egress_allowed("console.nav.cloud.nais.io:80", &hosts).is_err());
        assert!(egress_allowed("evilconsole.nav.cloud.nais.io:443", &hosts).is_err());
        assert!(egress_allowed("example.com:443", &hosts).is_err());
        assert!(!public_ip("127.0.0.1".parse().unwrap()));
        assert!(!public_ip("10.1.2.3".parse().unwrap()));
        assert!(!public_ip("::ffff:192.168.0.1".parse().unwrap()));
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn kill_terminates_and_never_signals_a_reaped_child() {
        #[allow(clippy::disallowed_methods)]
        let c = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let c = Mutex::new(c);
        let start = Instant::now();
        kill(&c);
        assert!(start.elapsed() < KILL_GRACE + Duration::from_secs(1));
        assert!(matches!(c.lock().unwrap().try_wait(), Ok(Some(_))));
        kill(&c); // already reaped: returns at once, no signal
        // SIGTERM ignored: SIGKILL after the grace.
        #[allow(clippy::disallowed_methods)]
        let c = Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let c = Mutex::new(c);
        kill(&c);
        assert!(matches!(c.lock().unwrap().try_wait(), Ok(Some(_))));
    }

    #[test]
    fn overlay_names_never_collide() {
        let s = check(base()).unwrap();
        let sock = Path::new("/private/tmp/x/m");
        let other = json!({"mcp": {"servers": {"nais-mcp": {"type": "remote", "url": "https://x.example"}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[other], &[&s], sock).unwrap()).unwrap();
        assert!(out["mcp"]["servers"].get("nais-mcp").is_none(), "{out}");
        assert_eq!(
            out["mcp"]["servers"]["io.github.nais__nais-mcp"]["type"],
            "local"
        );
        let existing = r#"{"mcp":{"servers":{"nais":{"command":["nais","alpha","mcp","serve"],"oauth":true}}}}"#;
        let user: Value = serde_json::from_str(existing).unwrap();
        let out: Value =
            serde_json::from_str(&opencode_overlay(Some(existing), &[user], &[&s], sock).unwrap())
                .unwrap();
        assert!(
            out["mcp"]["servers"]["nais"].get("oauth").is_none(),
            "wholesale: {out}"
        );
    }

    #[cfg(target_os = "macos")]
    fn cat_broker() -> Broker {
        let mut spec = check(base()).unwrap();
        spec.command = vec!["cat".into()];
        spec.program = "/bin/cat".into();
        Broker::start(vec![spec], Path::new("/tmp"), Log { file: None }).unwrap()
    }

    #[cfg(target_os = "macos")]
    fn connect(b: &Broker) -> (UnixStream, BufReader<UnixStream>) {
        let mut s = UnixStream::connect(b.socket()).unwrap();
        writeln!(s, "io.github.nais/nais-mcp").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let r = BufReader::new(s.try_clone().unwrap());
        (s, r)
    }

    #[cfg(target_os = "macos")]
    fn wait_free(b: &Broker) {
        let server = &b.shared.servers["io.github.nais/nais-mcp"];
        let start = Instant::now();
        while server.child.lock().unwrap().is_some() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "child slot never freed"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_second_client_is_refused() {
        let b = cat_broker();
        let (mut a, mut ra) = connect(&b);
        // A round trip proves the child is up and bound to `a`.
        writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        let (_b2, mut rb) = connect(&b);
        let mut l = String::new();
        rb.read_line(&mut l).unwrap();
        assert!(l.contains("already has a client"), "{l}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_restart_budget_stops_respawns() {
        let b = cat_broker();
        for _ in 0..SPAWNS_PER_MINUTE {
            let (mut a, mut ra) = connect(&b);
            writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
            let mut l = String::new();
            ra.read_line(&mut l).unwrap();
            drop((a, ra));
            wait_free(&b);
        }
        let (_a, mut ra) = connect(&b);
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        assert!(l.contains("too many restarts"), "{l}");
    }

    #[test]
    fn file_level_write_grants_and_policy_rejections() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join(FILE);
        // `sh`, not `nais`: load resolves the command in the real trusted
        // dirs, and CI has no nais.
        let none = with(base(), "/credential", json!("none"));
        std::fs::write(&f, spec_json(with(none, "/command", json!(["sh"])))).unwrap();
        let found = load(dir.path(), std::slice::from_ref(&f), &[]);
        assert!(
            found.specs.is_empty() && found.rejected[0].reason.contains("writable in the sandbox")
        );
        let mut found = load(dir.path(), &[], &[]);
        assert_eq!(found.specs.len(), 1);
        assert_eq!(found.specs[0].file, f);
        drop_writable(&mut found, |p| (p == f).then(|| PathBuf::from("/grant")));
        assert!(found.specs.is_empty());
        assert!(found.rejected[0].reason.contains("/grant"));
    }

    #[test]
    fn rejected_lines_are_escaped() {
        let r = Rejected {
            file: "a\u{1b}[2Jb.json".into(),
            reason: "x\ny".into(),
            fix: "f".into(),
        };
        let l = r.line();
        assert!(!l.contains('\u{1b}') && !l.contains('\n'), "{l}");
    }

    #[test]
    fn ambiguous_keys_are_refused() {
        let s = check(base()).unwrap();
        let mut p = Pending::default();
        for m in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_nais_context","Name":"execute_graphql"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"execute_graphql"}}"#,
            r#"{"jsonrpc":"2.0","ID":1,"method":"notifications/initialized"}"#,
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"execute_graphql\",\"arguments\":{\"query\":\"{ a }\",\"querſ\":1,\"Query\":\"mutation { x }\"}}}",
        ] {
            assert!(matches!(on_client(m, &s, &mut p), Action::Reply(..)), "{m}");
        }
        let ok = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"Name":"x"}}}"#;
        assert!(matches!(on_client(ok, &s, &mut p), Action::Forward(_)));
    }

    #[test]
    fn connection_permits_are_bounded() {
        let open = Arc::new(AtomicUsize::new(0));
        let held: Vec<Permit> = (0..MAX_CONNECTIONS)
            .map(|_| Permit::take(&open).unwrap())
            .collect();
        assert!(Permit::take(&open).is_none());
        drop(held);
        assert!(Permit::take(&open).is_some());
    }

    #[test]
    fn fallback_names_never_collide() {
        let one = Spec {
            id: "io.example.one/server".into(),
            ..check(with(base(), "/credential", json!("none"))).unwrap()
        };
        let two = Spec {
            id: "io.example.two/server".into(),
            ..one.clone()
        };
        let sock = Path::new("/s");
        let user = json!({"mcp": {"servers": {"io.example.one__server": {"type": "remote"}}}});
        let out: Value =
            serde_json::from_str(&opencode_overlay(None, &[user], &[&one, &two], sock).unwrap())
                .unwrap();
        let names: Vec<&String> = out["mcp"]["servers"].as_object().unwrap().keys().collect();
        assert_eq!(names, ["io.example.two__server", "server"], "{out}");
        let cfg = r#"{"mcpServers":{"io.example.two__server":{"command":"x"}}}"#;
        let args = copilot_args(Some(cfg), &[&one, &two], sock);
        let v: Value = serde_json::from_str(args.last().unwrap()).unwrap();
        let names: Vec<&String> = v["mcpServers"].as_object().unwrap().keys().collect();
        assert_eq!(
            names,
            ["io.example.one__server", "io.example.two__server-2"]
        );
    }

    #[cfg(target_os = "macos")]
    fn sh_broker(script: &str) -> Broker {
        let mut spec = check(base()).unwrap();
        spec.command = vec!["sh".into(), "-c".into(), script.into()];
        spec.program = "/bin/sh".into();
        Broker::start(vec![spec], Path::new("/tmp"), Log { file: None }).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_child_runs_in_root_with_a_cleared_env() {
        let b = sh_broker(
            r#"read l; printf '{"jsonrpc":"2.0","id":1,"result":{"cwd":"%s","pp":"%s"}}\n' "$PWD" "${PYTHONPATH:-none}"; cat >/dev/null"#,
        );
        let (mut a, mut ra) = connect(&b);
        writeln!(a, r#"{{"jsonrpc":"2.0","id":1,"method":"ping"}}"#).unwrap();
        let mut l = String::new();
        ra.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["result"]["cwd"], "/", "{l}");
        assert_eq!(v["result"]["pp"], "none", "{l}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn no_child_after_stop() {
        let b = cat_broker();
        b.shared.stop.store(true, Ordering::Release);
        // The accept loop may already be gone (connect or write then fails)
        // or may still accept: either way no child may start.
        if let Ok(mut s) = UnixStream::connect(b.socket()) {
            let _ = writeln!(s, "io.github.nais/nais-mcp");
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut l = String::new();
            let _ = BufReader::new(s).read_line(&mut l);
            assert!(l.is_empty(), "closed without serving: {l}");
        }
        assert!(
            b.shared.servers["io.github.nais/nais-mcp"]
                .child
                .lock()
                .unwrap()
                .is_none()
        );
    }

    /// nav-pilot's own OPENCODE_CONFIG_CONTENT (policy, plugins, providers,
    /// agent model, its other servers) survives; only the broker's entry is
    /// added, and an entry under the short name that does not run the spec's
    /// command (here disabled) is left alone, so the broker takes another name.
    #[test]
    fn opencode_overlay_keeps_existing_content() {
        let s = check(base()).unwrap();
        let existing = json!({
            "permission": {"bash": "ask"},
            "plugin": ["nav-pilot-hooks"],
            "enabled_providers": ["github-copilot"],
            "agent": {"build": {"model": "github-copilot/x"}},
            "mcp": {"servers": {
                "aksel": {"type": "remote", "url": "https://aksel.example"},
                "nais-mcp": {"type": "local", "command": ["other"], "enabled": false}
            }}
        });
        let out = opencode_overlay(
            Some(&existing.to_string()),
            std::slice::from_ref(&existing),
            &[&s],
            Path::new("/s"),
        )
        .unwrap();
        let mut out: Value = serde_json::from_str(&out).unwrap();
        let added = out["mcp"]["servers"]
            .as_object_mut()
            .unwrap()
            .remove("io.github.nais__nais-mcp")
            .unwrap();
        assert_eq!(
            added["command"],
            json!(["cplt", "mcp-stdio", "io.github.nais/nais-mcp"])
        );
        assert_eq!(out, existing, "everything else unchanged");
    }

    #[test]
    fn the_fix_matches_the_cause() {
        let dir = tempfile::tempdir().unwrap();
        let none = with(base(), "/credential", json!("none"));
        std::fs::write(
            dir.path().join(FILE),
            spec_json(with(none, "/command", json!(["sh"]))),
        )
        .unwrap();
        let r = &load(dir.path(), &[dir.path().to_path_buf()], &[]).rejected[0];
        assert!(r.fix.starts_with("move XDG_CONFIG_HOME"), "{r:?}");
        assert!(
            r.fix
                .contains(&*std::fs::canonicalize(dir.path()).unwrap().to_string_lossy())
                || r.fix.contains(&*dir.path().to_string_lossy()),
            "names the tree: {r:?}"
        );
        let link = tempfile::tempdir().unwrap();
        let ln = link.path().join("mcp");
        std::os::unix::fs::symlink(dir.path(), &ln).unwrap();
        let r = &load(&ln, &[], &[]).rejected[0];
        assert!(
            r.fix.starts_with("replace the symlink") && r.fix.contains("real directory"),
            "{r:?}"
        );
        // A bad spec is still nav-pilot's to rewrite.
        std::fs::write(dir.path().join(FILE), "{").unwrap();
        let r = &load(dir.path(), &[], &[]).rejected[0];
        assert_eq!(r.fix, "nav-pilot mcp enable io.github.nais/nais-mcp");
    }
}
