//! Keeping an OpenCode v2 session's UI state across runs.
//!
//! A v2 session runs with a private `XDG_STATE_HOME` (see `opencode_v2`), so
//! the host service's registration is never found. The same dir holds the
//! favorite models, prompt history and TUI tabs, and removing the scratch dir
//! at exit took those with it.
//!
//! The state dir stays private. cplt, running outside the sandbox, copies an
//! allowlist of data files into it before the launch and copies them back after
//! the agent exits. Nothing is shared live, so the registration (`service.json`)
//! and `locks/` never cross, and neither does any file not named here.
//!
//! The agent writes the scratch copies, so each one is read as hostile:
//! opened without following a symlink or blocking on a FIFO, size-capped, and
//! parsed against a strict schema of the shape OpenCode writes. A file that
//! fails is dropped with a warning and the host copy is left alone. The host
//! state dir is writable from the sandbox too, so it is read the same way.
//! Only data OpenCode treats as data crosses: nothing that names a command, a
//! URL or a path to run.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Model,
    History,
    Tabs,
    Highlights,
    Kv,
}

struct Spec {
    rel: &'static str,
    kind: Kind,
    cap: u64,
}

const FILES: [Spec; 5] = [
    Spec {
        rel: "model.json",
        kind: Kind::Model,
        cap: 1 << 20,
    },
    Spec {
        rel: "prompt-history.jsonl",
        kind: Kind::History,
        cap: 8 << 20,
    },
    Spec {
        rel: "kv.json",
        kind: Kind::Kv,
        cap: 1 << 20,
    },
    Spec {
        rel: "latest/tui/tabs.json",
        kind: Kind::Tabs,
        cap: 1 << 20,
    },
    Spec {
        rel: "latest/tui/highlights.json",
        kind: Kind::Highlights,
        cap: 1 << 16,
    },
];

/// History entries kept. Older ones are dropped from the front.
const MAX_HISTORY_LINES: usize = 1000;
const MAX_HISTORY_LINE: usize = 128 << 10;

/// One session's copy-in and copy-back of the allowlisted files.
pub struct Persist {
    host: PathBuf,
    own: PathBuf,
    /// What was copied in, per `rel`: a file left as seeded is not written
    /// back, so a change made on the host meanwhile is not overwritten.
    seeded: HashMap<&'static str, String>,
}

impl Persist {
    /// Seed the session's private state dir from the host's. Returns the
    /// warnings; a failure never stops the launch.
    pub fn begin(home: &Path, scratch: &Path) -> (Self, Vec<String>) {
        let host = crate::opencode_v2::xdg_base("XDG_STATE_HOME", home, ".local/state")
            .join("opencode");
        let own = crate::opencode_v2::session_state(scratch).join("opencode");
        Self::with_roots(host, own)
    }

    fn with_roots(host: PathBuf, own: PathBuf) -> (Self, Vec<String>) {
        let mut p = Self {
            host,
            own,
            seeded: HashMap::new(),
        };
        let mut warnings = Vec::new();
        for spec in &FILES {
            if let Err(w) = p.seed_one(spec) {
                warnings.push(w);
            }
        }
        (p, warnings)
    }

    fn seed_one(&mut self, spec: &Spec) -> Result<(), String> {
        let src = self.host.join(spec.rel);
        let fail = |why: &str| {
            format!(
                "OpenCode state: not restoring {} ({why}); it starts empty this session.",
                spec.rel
            )
        };
        match real_chain(&self.host, spec.rel, false) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(e) => return Err(fail(&e.to_string())),
        }
        let text = match crate::untrusted::read_untrusted(&src, spec.cap) {
            Ok(Some(t)) => t,
            Ok(None) => return Err(fail("not a plain file within the size limit")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(fail(&e.to_string())),
        };
        let Some(clean) = sanitize(spec.kind, &text) else {
            return Err(fail("it does not have the shape OpenCode writes"));
        };
        real_chain(&self.own, spec.rel, true).map_err(|e| fail(&e.to_string()))?;
        write_new(&self.own.join(spec.rel), &clean).map_err(|e| fail(&e.to_string()))?;
        self.seeded.insert(spec.rel, clean);
        Ok(())
    }

    /// Copy the files the session changed back to the host state dir. Call it
    /// after the agent has exited and before the scratch dir is removed.
    pub fn finish(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for spec in &FILES {
            if let Err(w) = self.finish_one(spec) {
                warnings.push(w);
            }
        }
        warnings
    }

    fn finish_one(&self, spec: &Spec) -> Result<(), String> {
        let fail = |why: &str| {
            format!(
                "OpenCode state: kept the saved {} unchanged ({why}).",
                spec.rel
            )
        };
        match real_chain(&self.own, spec.rel, false) {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(e) => return Err(fail(&e.to_string())),
        }
        let text = match crate::untrusted::read_untrusted(&self.own.join(spec.rel), spec.cap) {
            Ok(Some(t)) => t,
            Ok(None) => return Err(fail("the session's copy is not a plain file or too big")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(fail(&e.to_string())),
        };
        let seeded = self.seeded.get(spec.rel);
        if seeded.is_some_and(|s| *s == text) {
            return Ok(());
        }
        let body = if spec.kind == Kind::History {
            let host_now = match real_chain(&self.host, spec.rel, false) {
                Ok(true) => match crate::untrusted::read_untrusted(
                    &self.host.join(spec.rel),
                    spec.cap,
                ) {
                    Ok(t) => t.unwrap_or_default(),
                    Err(_) => String::new(),
                },
                _ => String::new(),
            };
            match merge_history(seeded.map_or("", String::as_str), &text, &host_now) {
                Some(b) => b,
                None => return Ok(()),
            }
        } else {
            sanitize(spec.kind, &text)
                .ok_or_else(|| fail("the session's copy does not have the shape OpenCode writes"))?
        };
        real_chain(&self.host, spec.rel, true).map_err(|e| fail(&e.to_string()))?;
        write_atomic(&self.host.join(spec.rel), &body).map_err(|e| fail(&e.to_string()))
    }
}

/// Walk `root` and the parent dirs of `rel` below it, refusing a symlink or a
/// non-dir at any step: the agent can write the host state dir, and a link
/// there would send cplt's write somewhere else. `Ok(false)` when a step is
/// missing and `create` is off.
fn real_chain(root: &Path, rel: &str, create: bool) -> std::io::Result<bool> {
    let mut dir = root.to_path_buf();
    let steps = std::iter::once("").chain(
        Path::new(rel)
            .parent()
            .into_iter()
            .flat_map(|p| p.iter().filter_map(|c| c.to_str())),
    );
    for step in steps {
        if !step.is_empty() {
            dir.push(step);
        }
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => {
                return Err(std::io::Error::other(format!(
                    "{} is not a plain directory",
                    dir.display()
                )));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !create {
                    return Ok(false);
                }
                std::fs::create_dir_all(&dir)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

fn write_new(dest: &Path, body: &str) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)
        .and_then(|mut f| f.write_all(body.as_bytes()))
}

/// Write to a temp file beside `dest`, then rename over it, so a reader never
/// sees half a file. A rename replaces a symlink at `dest` and does not follow it.
fn write_atomic(dest: &Path, body: &str) -> std::io::Result<()> {
    let name = dest.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let tmp = dest.with_file_name(format!(".cplt-{name}.{}.tmp", std::process::id()));
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(body.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, dest));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// `text` if it has the shape OpenCode writes for `kind`, else `None`. A
/// history file is filtered line by line instead.
fn sanitize(kind: Kind, text: &str) -> Option<String> {
    if kind == Kind::History {
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| history_line_ok(l, false))
            .collect();
        let start = lines.len().saturating_sub(MAX_HISTORY_LINES);
        return join_lines(&lines[start..]);
    }
    let v: Value = serde_json::from_str(text).ok()?;
    let ok = match kind {
        Kind::Model => model_ok(&v),
        Kind::Tabs => tabs_ok(&v),
        Kind::Highlights => highlights_ok(&v),
        Kind::Kv => kv_ok(&v),
        Kind::History => false,
    };
    ok.then(|| text.to_string())
}

fn join_lines(lines: &[&str]) -> Option<String> {
    (!lines.is_empty()).then(|| {
        let mut s = lines.join("\n");
        s.push('\n');
        s
    })
}

/// The host's current history plus the entries the session added, which are
/// the lines of `scratch` that were not in what was copied in. New entries
/// must be plain text: a file attachment could point anywhere.
fn merge_history(seeded: &str, scratch: &str, host_now: &str) -> Option<String> {
    let mut left: HashMap<&str, usize> = HashMap::new();
    for l in seeded.lines() {
        *left.entry(l).or_default() += 1;
    }
    let mut added = Vec::new();
    for l in scratch.lines().filter(|l| !l.is_empty()) {
        match left.get_mut(l) {
            Some(n) if *n > 0 => *n -= 1,
            _ if history_line_ok(l, true) => added.push(l),
            _ => {}
        }
    }
    if added.is_empty() {
        return None;
    }
    let mut all: Vec<&str> = host_now
        .lines()
        .filter(|l| history_line_ok(l, false))
        .collect();
    all.extend(added);
    let start = all.len().saturating_sub(MAX_HISTORY_LINES);
    join_lines(&all[start..])
}

/// A history entry is `{"input": str, "parts": [..], "mode": str}`.
fn history_line_ok(line: &str, plain_only: bool) -> bool {
    if line.is_empty() || line.len() > MAX_HISTORY_LINE {
        return false;
    }
    let Ok(Value::Object(o)) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    o.iter().all(|(k, v)| match k.as_str() {
        "input" => v.as_str().is_some_and(|s| clean(s, MAX_HISTORY_LINE, true)),
        "mode" => v.as_str().is_some_and(|s| clean(s, 32, false)),
        "parts" => v
            .as_array()
            .is_some_and(|a| a.len() <= 64 && (!plain_only || a.is_empty())),
        _ => false,
    }) && o.get("input").is_some()
}

/// No control characters (a terminal escape in a title or a model name would
/// reach the user's terminal), and a bounded length.
fn clean(s: &str, max: usize, multiline: bool) -> bool {
    s.len() <= max
        && s
            .chars()
            .all(|c| !c.is_control() || (multiline && matches!(c, '\n' | '\t' | '\r')))
}

fn short(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| clean(s, max, false))
}

fn model_ref_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.len() == 2
            && o.get("providerID").is_some_and(|v| short(v, 256))
            && o.get("modelID").is_some_and(|v| short(v, 256))
    })
}

fn model_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, v)| match k.as_str() {
            "recent" | "favorite" => v
                .as_array()
                .is_some_and(|a| a.len() <= 256 && a.iter().all(model_ref_ok)),
            "variant" => v.as_object().is_some_and(|m| {
                m.len() <= 1024 && m.iter().all(|(k, v)| clean(k, 512, false) && short(v, 128))
            }),
            _ => false,
        })
    })
}

fn session_id_ok(s: &str) -> bool {
    s.len() <= 64
        && s.strip_prefix("ses_")
            .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_alphanumeric()))
}

fn bucket_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, v)| match k.as_str() {
            "tabs" => v.as_array().is_some_and(|a| {
                a.len() <= 256
                    && a.iter().all(|t| {
                        t.as_object().is_some_and(|t| {
                            t.get("sessionID")
                                .and_then(Value::as_str)
                                .is_some_and(session_id_ok)
                                && t.iter().all(|(k, v)| match k.as_str() {
                                    "sessionID" => true,
                                    "title" => short(v, 1024),
                                    _ => false,
                                })
                        })
                    })
            }),
            "unread" => v.as_object().is_some_and(|u| {
                u.len() <= 1024
                    && u.iter().all(|(k, v)| {
                        clean(k, 128, false)
                            && (v.is_boolean() || v.is_number() || short(v, 128))
                    })
            }),
            _ => false,
        })
    })
}

fn tabs_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, v)| match k.as_str() {
            "global" => bucket_ok(v),
            "cwd" => v.as_object().is_some_and(|m| {
                m.len() <= 1024
                    && m.iter().all(|(dir, b)| {
                        dir.starts_with('/') && clean(dir, 4096, false) && bucket_ok(b)
                    })
            }),
            _ => false,
        })
    })
}

fn highlights_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, v)| {
            k == "seen"
                && v.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.len() <= 32
                        && s.chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
                })
        })
    })
}

/// `kv.json` is the TUI's flat settings (theme, sidebar, ...): scalars only.
fn kv_ok(v: &Value) -> bool {
    v.as_object().is_some_and(|o| {
        o.len() <= 256
            && o.iter().all(|(k, v)| {
                !k.is_empty()
                    && k.len() <= 64
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                    && (v.is_boolean() || v.is_number() || short(v, 256))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::untrusted::tests::{bounded, mkfifo};
    use std::os::unix::fs::symlink;

    const MODEL: &str = r#"{"recent":[{"providerID":"p","modelID":"m"}],"favorite":[{"providerID":"p","modelID":"m"}],"variant":{"p/m":"low"}}"#;
    const TABS: &str = r#"{"global":{"tabs":[],"unread":{}},"cwd":{"/a/b":{"tabs":[{"sessionID":"ses_abc123","title":"t"}],"unread":{}}}}"#;
    const KV: &str = r#"{"theme":"nightowl","animations_enabled":true}"#;
    const HIGH: &str = r#"{"seen":"2.1.0"}"#;
    const H1: &str = r#"{"input":"one","parts":[],"mode":"normal"}"#;
    const H2: &str = r#"{"input":"two","parts":[],"mode":"normal"}"#;

    struct Fx {
        _t: tempfile::TempDir,
        host: PathBuf,
        own: PathBuf,
    }

    fn fx() -> Fx {
        let t = tempfile::tempdir().unwrap();
        let host = t.path().join("host/opencode");
        let own = t.path().join("scratch/opencode");
        std::fs::create_dir_all(&host).unwrap();
        std::fs::create_dir_all(&own).unwrap();
        Fx { _t: t, host, own }
    }

    fn put(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn get(root: &Path, rel: &str) -> Option<String> {
        std::fs::read_to_string(root.join(rel)).ok()
    }

    fn begin(f: &Fx) -> (Persist, Vec<String>) {
        Persist::with_roots(f.host.clone(), f.own.clone())
    }

    #[test]
    fn seeds_every_allowlisted_file_and_nothing_else() {
        let f = fx();
        put(&f.host, "model.json", MODEL);
        put(&f.host, "kv.json", KV);
        put(&f.host, "prompt-history.jsonl", &format!("{H1}\n{H2}\n"));
        put(&f.host, "latest/tui/tabs.json", TABS);
        put(&f.host, "latest/tui/highlights.json", HIGH);
        put(&f.host, "service.json", r#"{"password":"x"}"#);
        put(&f.host, "locks/a", "x");
        put(&f.host, "claude-config/hooks.json", "{}");
        let (_, warnings) = begin(&f);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(get(&f.own, "model.json").as_deref(), Some(MODEL));
        assert_eq!(get(&f.own, "kv.json").as_deref(), Some(KV));
        assert_eq!(get(&f.own, "latest/tui/tabs.json").as_deref(), Some(TABS));
        assert_eq!(get(&f.own, "latest/tui/highlights.json").as_deref(), Some(HIGH));
        assert_eq!(
            get(&f.own, "prompt-history.jsonl").as_deref(),
            Some(format!("{H1}\n{H2}\n").as_str())
        );
        for no in ["service.json", "locks/a", "claude-config/hooks.json"] {
            assert!(!f.own.join(no).exists(), "{no} must not be seeded");
        }
    }

    #[test]
    fn a_favorite_set_in_the_session_reaches_the_host() {
        let f = fx();
        put(&f.host, "model.json", r#"{"favorite":[]}"#);
        let (p, _) = begin(&f);
        std::fs::write(f.own.join("model.json"), MODEL).unwrap();
        let w = p.finish();
        assert!(w.is_empty(), "{w:?}");
        assert_eq!(get(&f.host, "model.json").as_deref(), Some(MODEL));
    }

    #[test]
    fn a_first_run_creates_the_host_files_and_dirs() {
        let f = fx();
        std::fs::remove_dir_all(&f.host).unwrap();
        let (p, _) = begin(&f);
        std::fs::write(f.own.join("model.json"), MODEL).unwrap();
        put(&f.own, "latest/tui/tabs.json", TABS);
        assert!(p.finish().is_empty());
        assert_eq!(get(&f.host, "model.json").as_deref(), Some(MODEL));
        assert_eq!(get(&f.host, "latest/tui/tabs.json").as_deref(), Some(TABS));
    }

    #[test]
    fn registration_and_locks_never_go_back() {
        let f = fx();
        let (p, _) = begin(&f);
        put(&f.own, "service.json", r#"{"port":1,"password":"p"}"#);
        put(&f.own, "locks/x", "1");
        put(&f.own, "latest/locks/y", "1");
        put(&f.own, "claude-config/settings.json", "{}");
        put(&f.own, "model.json", MODEL);
        assert!(p.finish().is_empty());
        for no in ["service.json", "locks", "latest/locks", "claude-config"] {
            assert!(!f.host.join(no).exists(), "{no} leaked to the host");
        }
        assert!(f.host.join("model.json").exists());
    }

    #[test]
    fn an_unchanged_file_does_not_overwrite_a_host_change() {
        let f = fx();
        put(&f.host, "model.json", MODEL);
        let (p, _) = begin(&f);
        put(&f.host, "model.json", r#"{"favorite":[]}"#);
        assert!(p.finish().is_empty());
        assert_eq!(get(&f.host, "model.json").as_deref(), Some(r#"{"favorite":[]}"#));
    }

    #[test]
    fn bad_shapes_are_refused_and_the_host_file_stays() {
        let bad = [
            ("model.json", "not json"),
            ("model.json", r#"{"favorite":[],"command":"rm -rf /"}"#),
            ("model.json", r#"{"favorite":[{"providerID":"p","modelID":"m","x":1}]}"#),
            ("model.json", r#"{"favorite":[{"providerID":"p","modelID":"\u001b[2J"}]}"#),
            ("model.json", r#"{"variant":{"a":1}}"#),
            ("kv.json", r#"{"theme":{"a":"b"}}"#),
            ("kv.json", r#"{"bad key":true}"#),
            ("latest/tui/tabs.json", r#"{"cwd":{"relative":{"tabs":[]}}}"#),
            ("latest/tui/tabs.json", r#"{"global":{"tabs":[{"sessionID":"../../x"}]}}"#),
            ("latest/tui/tabs.json", r#"{"global":{"tabs":[{"sessionID":"ses_a","cmd":"x"}]}}"#),
            ("latest/tui/highlights.json", r#"{"seen":"1.0; rm"}"#),
            ("latest/tui/highlights.json", r#"{"other":"1.0"}"#),
        ];
        for (rel, body) in bad {
            let f = fx();
            let (p, _) = begin(&f);
            put(&f.host, rel, "{}");
            put(&f.own, rel, body);
            let w = p.finish();
            assert_eq!(w.len(), 1, "{rel} {body}: {w:?}");
            assert_eq!(get(&f.host, rel).as_deref(), Some("{}"), "{rel} {body}");
        }
    }

    #[test]
    fn oversize_and_invalid_host_files_are_not_seeded() {
        let f = fx();
        put(&f.host, "model.json", &" ".repeat((1 << 20) + 1));
        put(&f.host, "kv.json", r#"{"a":{"b":1}}"#);
        let (_, w) = begin(&f);
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(!f.own.join("model.json").exists());
        assert!(!f.own.join("kv.json").exists());
    }

    #[test]
    fn history_keeps_host_entries_and_adds_new_plain_ones() {
        let f = fx();
        put(&f.host, "prompt-history.jsonl", &format!("{H1}\n"));
        let (p, _) = begin(&f);
        // the session appends H2 and a repeat of H1; a host session adds one
        put(&f.own, "prompt-history.jsonl", &format!("{H1}\n{H2}\n{H1}\n"));
        let h3 = r#"{"input":"three","parts":[],"mode":"normal"}"#;
        put(&f.host, "prompt-history.jsonl", &format!("{H1}\n{h3}\n"));
        assert!(p.finish().is_empty());
        assert_eq!(
            get(&f.host, "prompt-history.jsonl").unwrap(),
            format!("{H1}\n{h3}\n{H2}\n{H1}\n")
        );
    }

    #[test]
    fn history_drops_planted_and_attachment_lines() {
        let f = fx();
        let (p, _) = begin(&f);
        let attach =
            r#"{"input":"x","parts":[{"type":"file","url":"file:///etc/passwd"}],"mode":"normal"}"#;
        let extra = r#"{"input":"x","parts":[],"mode":"normal","cmd":"rm"}"#;
        put(
            &f.own,
            "prompt-history.jsonl",
            &format!("{H1}\n{attach}\n{extra}\nnot json\n{{\"parts\":[]}}\n"),
        );
        assert!(p.finish().is_empty());
        assert_eq!(get(&f.host, "prompt-history.jsonl").unwrap(), format!("{H1}\n"));
    }

    #[test]
    fn history_with_attachments_survives_the_round_trip() {
        let f = fx();
        let attach = r#"{"input":"x","parts":[{"type":"file"}],"mode":"normal"}"#;
        put(&f.host, "prompt-history.jsonl", &format!("{attach}\n"));
        let (p, _) = begin(&f);
        let mut now = get(&f.own, "prompt-history.jsonl").unwrap();
        assert!(now.contains("file"), "seeded from the host");
        now.push_str(&format!("{H2}\n"));
        put(&f.own, "prompt-history.jsonl", &now);
        assert!(p.finish().is_empty());
        assert_eq!(
            get(&f.host, "prompt-history.jsonl").unwrap(),
            format!("{attach}\n{H2}\n")
        );
    }

    #[test]
    fn history_is_capped() {
        let f = fx();
        let (p, _) = begin(&f);
        let body: String = (0..MAX_HISTORY_LINES + 50)
            .map(|i| format!("{{\"input\":\"{i}\",\"parts\":[]}}\n"))
            .collect();
        put(&f.own, "prompt-history.jsonl", &body);
        assert!(p.finish().is_empty());
        let out = get(&f.host, "prompt-history.jsonl").unwrap();
        assert_eq!(out.lines().count(), MAX_HISTORY_LINES);
        assert!(out.lines().last().unwrap().contains(&format!("{}", MAX_HISTORY_LINES + 49)));
    }

    #[test]
    fn a_planted_symlink_in_the_session_is_not_followed() {
        let f = fx();
        let secret = f.own.parent().unwrap().join("secret.json");
        std::fs::write(&secret, MODEL).unwrap();
        let (p, _) = begin(&f);
        symlink(&secret, f.own.join("model.json")).unwrap();
        let tui = f.own.join("latest");
        std::fs::create_dir_all(&tui).unwrap();
        symlink(f.own.parent().unwrap(), tui.join("tui")).unwrap();
        put(f.own.parent().unwrap(), "tabs.json", TABS);
        let w = p.finish();
        assert!(!f.host.join("model.json").exists(), "{w:?}");
        assert!(!f.host.join("latest/tui/tabs.json").exists(), "{w:?}");
        assert_eq!(w.len(), 3, "{w:?}");
    }

    #[test]
    fn a_planted_fifo_in_the_session_does_not_hang() {
        let f = fx();
        let (p, _) = begin(&f);
        mkfifo(&f.own.join("model.json"));
        mkfifo(&f.own.join("prompt-history.jsonl"));
        let w = bounded(move || p.finish());
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(!f.host.join("model.json").exists());
    }

    #[test]
    fn a_planted_fifo_or_symlink_on_the_host_is_not_seeded() {
        let f = fx();
        let secret = f.host.parent().unwrap().join("secret");
        std::fs::write(&secret, MODEL).unwrap();
        symlink(&secret, f.host.join("model.json")).unwrap();
        mkfifo(&f.host.join("kv.json"));
        let (f2, f3) = (f.host.clone(), f.own.clone());
        let (_, w) = bounded(move || Persist::with_roots(f2, f3));
        assert_eq!(w.len(), 2, "{w:?}");
        assert!(!f.own.join("model.json").exists());
        assert!(!f.own.join("kv.json").exists());
    }

    #[test]
    fn a_symlinked_host_dir_is_not_written_through() {
        let f = fx();
        let elsewhere = f.host.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::remove_dir_all(&f.host).unwrap();
        symlink(&elsewhere, &f.host).unwrap();
        let (p, w) = begin(&f);
        assert!(!w.is_empty(), "seeding through the link is refused: {w:?}");
        put(&f.own, "model.json", MODEL);
        let w = p.finish();
        assert!(!w.is_empty());
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn a_symlink_at_a_host_subdir_is_not_written_through() {
        let f = fx();
        let elsewhere = f.host.parent().unwrap().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        symlink(&elsewhere, f.host.join("latest")).unwrap();
        let (p, _) = begin(&f);
        put(&f.own, "latest/tui/tabs.json", TABS);
        assert_eq!(p.finish().len(), 1);
        assert!(std::fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn a_symlink_at_the_host_file_is_replaced_not_followed() {
        let f = fx();
        let (p, _) = begin(&f);
        let victim = f.host.parent().unwrap().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        symlink(&victim, f.host.join("model.json")).unwrap();
        put(&f.own, "model.json", MODEL);
        assert!(p.finish().is_empty());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(get(&f.host, "model.json").as_deref(), Some(MODEL));
    }

    #[test]
    fn a_failed_write_leaves_no_temp_file() {
        let f = fx();
        let (p, _) = begin(&f);
        std::fs::create_dir(f.host.join("model.json")).unwrap();
        put(&f.own, "model.json", MODEL);
        assert_eq!(p.finish().len(), 1);
        let stray: Vec<_> = std::fs::read_dir(&f.host)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(stray.is_empty());
    }

    #[test]
    fn the_real_shapes_validate() {
        assert!(model_ok(&serde_json::from_str(MODEL).unwrap()));
        assert!(tabs_ok(&serde_json::from_str(TABS).unwrap()));
        assert!(kv_ok(&serde_json::from_str(r#"{"theme":"nightowl","sidebar":"auto","thinking_mode":"hide","tool_details_visibility":true,"scrollbar_visible":false,"skipped_version":"2.0.32"}"#).unwrap()));
        assert!(history_line_ok(H1, true));
    }
}
