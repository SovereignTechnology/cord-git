//! Thin wrapper over the system `git` binary for object packing/unpacking and
//! ref management (git-remote-gcrypt style — no native git library).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};

/// Run `git -C <dir> <args>` feeding `stdin` (if any); return stdout bytes.
/// Errors include stderr for diagnosis.
fn run_git(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(dir).args(args);
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn git")?;
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("no git stdin"))?
            .write_all(bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Initialize a fresh non-bare repo at `dir` (created if absent).
pub fn init(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    run_git(dir, &["init", "--quiet"], None)?;
    Ok(())
}

/// True if `dir` is inside a git work tree / repo.
pub fn is_repo(dir: &Path) -> bool {
    run_git(dir, &["rev-parse", "--git-dir"], None).is_ok()
}

/// Map of local branch refs → object id.
pub fn branch_refs(dir: &Path) -> Result<BTreeMap<String, String>> {
    let out = run_git(
        dir,
        &[
            "for-each-ref",
            "--format=%(refname) %(objectname)",
            "refs/heads",
        ],
        None,
    )?;
    let text = String::from_utf8_lossy(&out);
    let mut map = BTreeMap::new();
    for line in text.lines() {
        if let Some((name, oid)) = line.split_once(' ') {
            map.insert(name.to_string(), oid.to_string());
        }
    }
    Ok(map)
}

/// Current HEAD symbolic ref (e.g. "refs/heads/main"), if any.
pub fn head_symref(dir: &Path) -> Option<String> {
    run_git(dir, &["symbolic-ref", "HEAD"], None)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Pack every object reachable from all refs into a single pack (stdout bytes).
/// Uses the canonical `rev-list --objects --all | pack-objects --stdout` pipe.
pub fn pack_all(dir: &Path) -> Result<Vec<u8>> {
    let names = run_git(dir, &["rev-list", "--objects", "--all"], None)?;
    run_git(dir, &["pack-objects", "--stdout"], Some(&names))
}

/// Unpack a pack (loose objects) into the repo at `dir`.
pub fn unpack(dir: &Path, pack: &[u8]) -> Result<()> {
    run_git(dir, &["unpack-objects", "-q"], Some(pack))?;
    Ok(())
}

/// Point a ref at an object id.
pub fn update_ref(dir: &Path, refname: &str, oid: &str) -> Result<()> {
    run_git(dir, &["update-ref", refname, oid], None)?;
    Ok(())
}

/// Set HEAD to a symbolic ref.
pub fn set_head(dir: &Path, refname: &str) -> Result<()> {
    run_git(dir, &["symbolic-ref", "HEAD", refname], None)?;
    Ok(())
}

/// Materialize the working tree from the current HEAD (after refs are set).
pub fn checkout_head(dir: &Path) -> Result<()> {
    run_git(dir, &["checkout", "--quiet", "--force"], None)?;
    Ok(())
}

/// Resolve a ref/committish to its object id.
pub fn rev_parse(dir: &Path, refish: &str) -> Result<String> {
    let out = run_git(dir, &["rev-parse", refish], None)?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

/// Produce one mail-formatted patch per commit in `range` (e.g. `main..feature`
/// or `HEAD~3..HEAD`), oldest first — the raw material for a `#collab` patch
/// series (NIP-34 kind-1617). Each element is a standalone `git format-patch`
/// output for a single commit. Empty ranges yield an empty vec.
pub fn format_patch_range(dir: &Path, range: &str) -> Result<Vec<String>> {
    let shas_out = run_git(dir, &["rev-list", "--reverse", range], None)?;
    let shas: Vec<String> = String::from_utf8_lossy(&shas_out)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let mut patches = Vec::with_capacity(shas.len());
    for sha in &shas {
        let out = run_git(dir, &["format-patch", "-1", "--stdout", sha], None)?;
        patches.push(String::from_utf8_lossy(&out).to_string());
    }
    Ok(patches)
}
