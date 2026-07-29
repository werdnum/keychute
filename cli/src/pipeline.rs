//! Best-effort shell pipeline capture (DESIGN §1, tier-2 caveat).
//!
//! Walks parent processes' command lines so the approval page can show what
//! the secret is being piped into. This runs inside the agent's container and
//! is agent-influenceable: the result is *agent-asserted* context, never
//! verified fact. All failures are silently ignored.

use std::collections::HashMap;

/// One row of `ps` output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsRow {
    pub ppid: u32,
    /// Process group. A shell runs every member of one pipeline in the same
    /// group, so "same pgid as us" is exactly "our pipeline peers".
    pub pgid: u32,
    pub command: String,
}

/// `ps` output: pid -> row.
pub type PsTable = HashMap<u32, PsRow>;

/// Parse `ps -o pid=,ppid=,pgid=,command= -ax` output. Unparsable lines are
/// skipped.
pub fn parse_ps(text: &str) -> PsTable {
    let mut table = PsTable::new();
    for line in text.lines() {
        let Some((pid_s, rest)) = split_field(line) else {
            continue;
        };
        let Some((ppid_s, rest)) = split_field(rest) else {
            continue;
        };
        let Some((pgid_s, command)) = split_field(rest) else {
            continue;
        };
        let (Ok(pid), Ok(ppid), Ok(pgid)) = (
            pid_s.parse::<u32>(),
            ppid_s.parse::<u32>(),
            pgid_s.parse::<u32>(),
        ) else {
            continue;
        };
        let command = command.trim_end();
        if command.is_empty() {
            continue;
        }
        table.insert(
            pid,
            PsRow {
                ppid,
                pgid,
                command: command.to_string(),
            },
        );
    }
    table
}

fn split_field(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let idx = s.find(char::is_whitespace)?;
    Some((&s[..idx], s[idx..].trim_start()))
}

/// Walk from `start` up the parent chain, collecting at most `max_levels`
/// command lines (starting with `start` itself).
#[cfg_attr(not(test), allow(dead_code))]
pub fn walk(table: &PsTable, start: u32, max_levels: usize) -> Vec<String> {
    walk_pids(table, start, max_levels)
        .into_iter()
        .map(|(_, command)| command)
        .collect()
}

/// Like [`walk`], but keeps the pids alongside the command lines.
fn walk_pids(table: &PsTable, start: u32, max_levels: usize) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut pid = start;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..max_levels {
        if !seen.insert(pid) {
            break; // cycle guard
        }
        let Some(row) = table.get(&pid) else {
            break;
        };
        out.push((pid, row.command.clone()));
        if row.ppid == 0 || row.ppid == pid {
            break;
        }
        pid = row.ppid;
    }
    out
}

/// True when a command line looks like a shell (`-zsh`, `/bin/bash`, `sh -c`).
/// A fixed name list avoids false positives such as `ssh`.
fn looks_like_shell(command: &str) -> bool {
    const SHELLS: &[&str] = &[
        "sh", "bash", "zsh", "ksh", "dash", "ash", "csh", "tcsh", "fish",
    ];
    let first = command.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    SHELLS.contains(&base.trim_start_matches('-'))
}

/// Best-effort pipeline capture: ancestor command lines plus, when a shell
/// ancestor is found, that shell's other children FROM OUR OWN PROCESS GROUP
/// — the actual pipeline peers (e.g. the consumer after the `|`). The pgid
/// filter is what keeps this from becoming an argv dragnet: a shell's other
/// children include unrelated background jobs whose command lines can carry
/// somebody else's credentials (`mysql -p…`, `curl -H "Authorization: …"`),
/// and those must never be collected and shipped to the server. Agent-asserted
/// context only; the snapshot is agent-influenceable and never verified.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Capture {
    pub ancestors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub siblings: Vec<String>,
}

/// Analyze one `ps` snapshot. Returns `None` when nothing was captured.
pub fn analyze(table: &PsTable, start: u32, max_levels: usize) -> Option<Capture> {
    let chain = walk_pids(table, start, max_levels);
    if chain.is_empty() {
        return None;
    }
    let chain_pids: std::collections::HashSet<u32> = chain.iter().map(|(p, _)| *p).collect();
    let own_pgid = table.get(&start).map(|r| r.pgid);
    // First shell in the ancestor chain (excluding ourselves at index 0).
    let shell_pid = chain
        .iter()
        .skip(1)
        .find(|(pid, _)| table.get(pid).is_some_and(|r| looks_like_shell(&r.command)))
        .map(|(pid, _)| *pid);
    let mut siblings: Vec<(u32, String)> = match (shell_pid, own_pgid) {
        (Some(shell), Some(pgid)) => table
            .iter()
            .filter(|(pid, row)| row.ppid == shell && row.pgid == pgid && !chain_pids.contains(pid))
            .map(|(pid, row)| (*pid, row.command.clone()))
            .collect(),
        _ => Vec::new(),
    };
    siblings.sort(); // deterministic order (by pid)
    Some(Capture {
        ancestors: chain.into_iter().map(|(_, cmd)| cmd).collect(),
        siblings: siblings.into_iter().map(|(_, cmd)| cmd).collect(),
    })
}

/// Capture the invoking pipeline for the current process. Best-effort:
/// returns `None` on any failure or when nothing was captured.
#[cfg(unix)]
pub fn capture() -> Option<Capture> {
    let out = std::process::Command::new("ps")
        .args(["-o", "pid=,ppid=,pgid=,command=", "-ax"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let table = parse_ps(&text);
    analyze(&table, std::process::id(), 5)
}

#[cfg(not(unix))]
pub fn capture() -> Option<Capture> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ppid: u32, pgid: u32, command: &str) -> PsRow {
        PsRow {
            ppid,
            pgid,
            command: command.to_string(),
        }
    }

    // pid ppid pgid command. keychute (789) and kubeseal (790) share pipeline
    // group 789; the shell's unrelated background job (791) has its own group.
    const CANNED: &str = "\
    1     0     1 /sbin/launchd
  400     1   400 /usr/bin/login -f agent
  456   400   456 -zsh
  789   456   789 keychute request my-service-api-key --reason seal
  790   456   789 kubeseal --format yaml
  791   456   791 curl -H secret-header https://internal
  bad   456   456 not-a-pid
  801       \n";

    #[test]
    fn parses_canned_ps_output() {
        let table = parse_ps(CANNED);
        assert_eq!(table.len(), 6);
        assert_eq!(
            table.get(&789),
            Some(&row(
                456,
                789,
                "keychute request my-service-api-key --reason seal"
            ))
        );
        assert_eq!(table.get(&456), Some(&row(400, 456, "-zsh")));
        // pid 1 has ppid 0
        assert_eq!(table.get(&1), Some(&row(0, 1, "/sbin/launchd")));
    }

    #[test]
    fn walks_parent_chain_from_self() {
        let table = parse_ps(CANNED);
        let chain = walk(&table, 789, 5);
        assert_eq!(
            chain,
            vec![
                "keychute request my-service-api-key --reason seal",
                "-zsh",
                "/usr/bin/login -f agent",
                "/sbin/launchd",
            ]
        );
    }

    #[test]
    fn walk_respects_max_levels() {
        let table = parse_ps(CANNED);
        let chain = walk(&table, 789, 2);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1], "-zsh");
    }

    #[test]
    fn analyze_includes_only_own_process_group_siblings() {
        let table = parse_ps(CANNED);
        let cap = analyze(&table, 789, 5).unwrap();
        assert_eq!(
            cap.ancestors,
            vec![
                "keychute request my-service-api-key --reason seal",
                "-zsh",
                "/usr/bin/login -f agent",
                "/sbin/launchd",
            ]
        );
        // kubeseal (pid 790) shares the -zsh parent AND our process group: it
        // is the downstream pipeline peer.
        assert_eq!(cap.siblings, vec!["kubeseal --format yaml"]);
        // The shell's unrelated background job (791, its own pgid) is NOT
        // captured — its argv can carry somebody else's credential.
        assert!(!cap.siblings.iter().any(|s| s.contains("curl")));
    }

    #[test]
    fn analyze_without_shell_ancestor_has_no_siblings() {
        // launchd -> keychute directly: no shell in the chain.
        let mut table = PsTable::new();
        table.insert(1, row(0, 1, "/sbin/launchd"));
        table.insert(50, row(1, 50, "keychute request x"));
        table.insert(51, row(1, 50, "other-child"));
        let cap = analyze(&table, 50, 5).unwrap();
        assert_eq!(cap.ancestors, vec!["keychute request x", "/sbin/launchd"]);
        assert!(cap.siblings.is_empty());
        // Nothing captured at all -> None.
        assert!(analyze(&table, 99999, 5).is_none());
    }

    #[test]
    fn shell_detection() {
        for s in ["-zsh", "/bin/bash", "sh -c 'x | y'", "/usr/bin/fish"] {
            assert!(looks_like_shell(s), "{s:?}");
        }
        for s in [
            "kubeseal --format yaml",
            "/usr/bin/login -f agent",
            "ssh host",
        ] {
            assert!(!looks_like_shell(s), "{s:?}");
        }
    }

    #[test]
    fn walk_handles_missing_pid_and_cycles() {
        let table = parse_ps(CANNED);
        assert!(walk(&table, 99999, 5).is_empty());
        // Self-parent cycle terminates.
        let mut cyclic = PsTable::new();
        cyclic.insert(7, row(7, 7, "self-parent"));
        assert_eq!(walk(&cyclic, 7, 5), vec!["self-parent"]);
        // Two-node cycle terminates via the seen-set.
        let mut two = PsTable::new();
        two.insert(1, row(2, 1, "a"));
        two.insert(2, row(1, 1, "b"));
        assert_eq!(walk(&two, 1, 5), vec!["a", "b"]);
    }
}
