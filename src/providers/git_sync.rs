use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs};
use anyhow::anyhow;
use chrono::Utc;
use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;
use indoc::formatdoc;
use log::debug;
use thiserror::Error;
use validator::Validate;

use crate::calling_app_name;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SyncError {
    #[error("git binary not found in PATH")]
    GitNotFound,

    #[error("git authentication failed (check SSH key / token): {source}")]
    AuthFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("network error during git sync: {source}")]
    Network {
        #[source]
        source: anyhow::Error,
    },

    #[error("git configuration error: {message}")]
    Config { message: String },

    #[error("git command failed: {message}")]
    GitCommandFailed { message: String },

    #[error("I/O error during sync: {0}")]
    Io(#[from] io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

type SyncResult<T> = std::result::Result<T, SyncError>;

#[derive(Debug, Validate, Clone)]
pub struct SyncOpts<'a> {
    #[validate(required)]
    pub remote_url: &'a Option<String>,
    #[validate(required)]
    pub branch: &'a Option<String>,
    pub user_name: &'a Option<String>,
    pub user_email: &'a Option<String>,
    pub git_executable: &'a Option<PathBuf>,
}

pub fn sync_and_push(opts: &SyncOpts<'_>) -> SyncResult<()> {
    debug!("Syncing with git: {:?}", opts);
    opts.validate().map_err(|e| SyncError::Config {
        message: format!("invalid git sync options: {}", e),
    })?;
    let commit_message = format!("chore: sync @ {}", Utc::now().to_rfc3339());
    let config_dir = confy::get_configuration_file_path(&calling_app_name(), "vault")
        .map_err(|e| SyncError::Config {
            message: format!("get config dir: {}", e),
        })?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| SyncError::Config {
            message: "Failed to determine config dir".to_string(),
        })?;

    let remote_url = opts.remote_url.as_ref().expect("no remote url defined");
    let repo_name = repo_name_from_url(remote_url);
    let repo_dir = config_dir.join(format!(".{}", repo_name));
    fs::create_dir_all(&repo_dir)?;

    let default_vault = confy::get_configuration_file_path(&calling_app_name(), "vault")
        .map_err(|e| SyncError::Config {
            message: format!("get default vault path: {}", e),
        })?;
    let repo_vault = repo_dir.join("vault.yml");
    if default_vault.exists() && !repo_vault.exists() {
        fs::rename(&default_vault, &repo_vault)?;
    } else if !repo_vault.exists() {
        fs::write(&repo_vault, "{}\n")?;
    }

    let git = resolve_git(opts.git_executable.as_ref())?;
    ensure_git_available(&git)?;

    let username = resolve_git_username(&git, opts.user_name.as_ref())?
        .trim()
        .to_string();
    let email = resolve_git_email(&git, opts.user_email.as_ref())?
        .trim()
        .to_string();
    let branch = opts.branch.as_ref().expect("no target branch defined");

    debug!(
        "{}",
        formatdoc!(
            r#"
			Using repo dir: {}
			git executable: {}
			git user: {}
			git user email: {}
			git remote: {}"#,
            repo_dir.display(),
            git.display(),
            username,
            email,
            remote_url
        )
    );

    init_repo_if_needed(&git, &repo_dir, branch)?;
    set_local_identity(&git, &repo_dir, username, email)?;
    checkout_branch(&git, &repo_dir, branch)?;
    set_origin(&git, &repo_dir, remote_url)?;

    fetch_and_pull(&git, &repo_dir, branch)?;

    stage_vault_only(&git, &repo_dir)?;

    commit_now(&git, &repo_dir, &commit_message)?;

    run_git_push(&git, &repo_dir, branch)?;

    run_git(&git, &repo_dir, &["remote", "set-head", "origin", "-a"])
}

fn resolve_git_username(git: &Path, name: Option<&String>) -> SyncResult<String> {
    debug!("Resolving git username");

    if let Some(name) = name {
        return Ok(name.to_string());
    }

    default_git_username(git).map_err(|_| SyncError::Config {
        message: "git user.name not configured".to_string(),
    })
}

fn resolve_git_email(git: &Path, email: Option<&String>) -> SyncResult<String> {
    debug!("Resolving git user email");
    if let Some(email) = email {
        return Ok(email.to_string());
    }

    default_git_email(git).map_err(|_| SyncError::Config {
        message: "git user.email not configured".to_string(),
    })
}

pub(in crate::providers) fn resolve_git(
    override_path: Option<&PathBuf>,
) -> SyncResult<PathBuf> {
    debug!("Resolving git executable");
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Ok(s) = env::var("GIT_EXECUTABLE") {
        return Ok(PathBuf::from(s));
    }
    Ok(PathBuf::from("git"))
}

pub(in crate::providers) fn default_git_username(git: &Path) -> SyncResult<String> {
    debug!("Checking for default git username");
    run_git_config_capture(git, &["config", "user.name"]).map_err(|e| SyncError::Config {
        message: format!("unable to determine git user name: {}", e),
    })
}

pub(in crate::providers) fn default_git_email(git: &Path) -> SyncResult<String> {
    debug!("Checking for default git username");
    run_git_config_capture(git, &["config", "user.email"]).map_err(|e| SyncError::Config {
        message: format!("unable to determine git user email: {}", e),
    })
}

pub(in crate::providers) fn ensure_git_available(git: &Path) -> SyncResult<()> {
    let ok = Command::new(git)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| SyncError::GitNotFound)?
        .success();
    if !ok {
        Err(SyncError::GitNotFound)
    } else {
        Ok(())
    }
}

fn run_git(git: &Path, repo: &Path, args: &[&str]) -> SyncResult<()> {
    let out = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()?;

    if !out.status.success() {
        return Err(SyncError::GitCommandFailed {
            message: format!(
                "git {} (exit {}): {}",
                args.join(" "),
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }

    Ok(())
}

fn run_git_push(git: &Path, repo: &Path, branch: &str) -> SyncResult<()> {
    let out = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["push", "-u", "origin", "--force", branch])
        .output()?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let lc = stderr.to_lowercase();
        let source = anyhow!("git push failed: {}", stderr.trim());
        if lc.contains("authentication failed") || lc.contains("permission denied") {
            return Err(SyncError::AuthFailed { source });
        }

        return Err(SyncError::Network { source });
    }

    Ok(())
}

fn run_git_fetch(git: &Path, repo: &Path) -> SyncResult<()> {
    let out = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["fetch", "origin", "--prune"])
        .output()?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let lc = stderr.to_lowercase();
        let source = anyhow!("git fetch failed: {}", stderr.trim());

        if lc.contains("authentication failed") || lc.contains("permission denied") {
            return Err(SyncError::AuthFailed { source });
        }

        return Err(SyncError::Network { source });
    }

    Ok(())
}

fn run_git_config_capture(git: &Path, args: &[&str]) -> SyncResult<String> {
    let out = Command::new(git).args(args).output()?;

    if !out.status.success() {
        return Err(SyncError::GitCommandFailed {
            message: format!(
                "git {} (exit {}): {}",
                args.join(" "),
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn init_repo_if_needed(git: &Path, repo: &Path, branch: &str) -> SyncResult<()> {
    let inside = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--git-dir"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !inside {
        run_git(
            git,
            repo,
            &["-c", &format!("init.defaultBranch={branch}"), "init"],
        )?;
    } else {
        let _ = run_git(
            git,
            repo,
            &["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")],
        );
    }
    Ok(())
}

fn set_local_identity(
    git: &Path,
    repo: &Path,
    username: String,
    email: String,
) -> SyncResult<()> {
    run_git(git, repo, &["config", "user.name", &username]).map_err(|e| SyncError::Config {
        message: format!("failed to set git user.name: {}", e),
    })?;
    run_git(git, repo, &["config", "user.email", &email]).map_err(|e| SyncError::Config {
        message: format!("failed to set git user.email: {}", e),
    })?;

    Ok(())
}

fn checkout_branch(git: &Path, repo: &Path, branch: &str) -> SyncResult<()> {
    run_git(git, repo, &["checkout", "-B", branch])?;
    Ok(())
}

fn set_origin(git: &Path, repo: &Path, url: &str) -> SyncResult<()> {
    let has_origin = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if has_origin {
        run_git(git, repo, &["remote", "set-url", "origin", url])?;
    } else if Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(format!(
            "Have you already created the remote origin '{url}' on the Git host so we can push to it?"
        ))
        .default(false)
        .interact()
        .map_err(|e| SyncError::Config {
            message: format!("prompt failed: {}", e),
        })?
    {
        run_git(git, repo, &["remote", "add", "origin", url])?;
    } else {
        return Err(SyncError::Config {
            message:
                "Remote origin does not yet exist. Please create remote origin before synchronizing, then try again"
                    .to_string(),
        });
    }
    Ok(())
}

fn stage_vault_only(git: &Path, repo: &Path) -> SyncResult<()> {
    run_git(git, repo, &["add", "vault.yml"])?;
    Ok(())
}

fn fetch_and_pull(git: &Path, repo: &Path, branch: &str) -> SyncResult<()> {
    run_git_fetch(git, repo)?;

    let origin_ref = format!("origin/{branch}");
    let remote_has_branch = has_remote_branch(git, repo, branch);

    if !has_head(git, repo) {
        if remote_has_branch {
            run_git(git, repo, &["checkout", "-f", "-B", branch, &origin_ref])?;
            run_git(git, repo, &["reset", "--hard", &origin_ref])?;
            run_git(git, repo, &["clean", "-fd"])?;
        }
        return Ok(());
    }

    if remote_has_branch {
        run_git(git, repo, &["merge", "--ff-only", &origin_ref])?;
    }
    Ok(())
}

fn has_remote_branch(git: &Path, repo: &Path, branch: &str) -> bool {
    Command::new(git)
        .arg("-C")
        .arg(repo)
        .args([
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/remotes/origin/{}", branch),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn has_head(git: &Path, repo: &Path) -> bool {
    Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "HEAD"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn commit_now(git: &Path, repo: &Path, msg: &str) -> SyncResult<()> {
    let staged_changed = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["diff", "--cached", "--quiet", "--exit-code"])
        .status()?
        .code()
        .map(|c| c == 1)
        .unwrap_or(false);

    if staged_changed {
        run_git(git, repo, &["commit", "-m", msg])?;
        return Ok(());
    }

    let unborn = !has_head(git, repo);

    if unborn {
        run_git(
            git,
            repo,
            &["commit", "--allow-empty", "-m", "initial sync commit"],
        )?;
        return Ok(());
    }

    Ok(())
}

pub fn repo_name_from_url(url: &str) -> String {
    let mut s = url;
    if let Some(idx) = s.rfind('/') {
        s = &s[idx + 1..];
    } else if let Some(idx) = s.rfind(':') {
        s = &s[idx + 1..];
    }
    s.trim_end_matches(".git").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_opts_validation_ok() {
        let remote = Some("git@github.com:user/repo.git".to_string());
        let branch = Some("main".to_string());
        let opts = SyncOpts {
            remote_url: &remote,
            branch: &branch,
            user_name: &None,
            user_email: &None,
            git_executable: &None,
        };
        assert!(opts.validate().is_ok());
    }

    #[test]
    fn sync_opts_validation_missing_fields() {
        let remote = None;
        let branch = None;
        let opts = SyncOpts {
            remote_url: &remote,
            branch: &branch,
            user_name: &None,
            user_email: &None,
            git_executable: &None,
        };
        assert!(opts.validate().is_err());
    }

    #[test]
    fn resolve_git_prefers_override_and_env() {
        let override_path = Some(PathBuf::from("/custom/git"));
        let got = resolve_git(override_path.as_ref()).unwrap();
        assert_eq!(got, PathBuf::from("/custom/git"));

        unsafe {
            env::set_var("GIT_EXECUTABLE", "/env/git");
        }
        let got_env = resolve_git(None).unwrap();
        assert_eq!(got_env, PathBuf::from("/env/git"));
        unsafe {
            env::remove_var("GIT_EXECUTABLE");
        }
    }

    #[test]
    fn test_repo_name_from_url() {
        assert_eq!(repo_name_from_url("git@github.com:user/vault.git"), "vault");
        assert_eq!(
            repo_name_from_url("https://github.com/user/test-vault.git"),
            "test-vault"
        );
        assert_eq!(repo_name_from_url("ssh://git@example.com/x/y/z.git"), "z");
        assert_eq!(repo_name_from_url("git@example.com:ns/repo"), "repo");
    }
}
