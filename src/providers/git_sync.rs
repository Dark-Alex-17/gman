use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use dialoguer::Confirm;
use dialoguer::theme::ColorfulTheme;
use indoc::formatdoc;
use log::debug;
use std::{env, fs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use validator::Validate;

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

pub fn sync_and_push(opts: &SyncOpts<'_>) -> Result<()> {
    debug!("Syncing with git: {:?}", opts);
    opts.validate()
        .with_context(|| "invalid git sync options")?;
    let commit_message = format!("chore: sync @ {}", Utc::now().to_rfc3339());
    let config_dir = confy::get_configuration_file_path("gman", "vault")
        .with_context(|| "get config dir")?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("Failed to determine config dir"))?;

    let remote_url = opts.remote_url.as_ref().expect("no remote url defined");
    let repo_name = repo_name_from_url(remote_url);
    let repo_dir = config_dir.join(format!(".{}", repo_name));
    fs::create_dir_all(&repo_dir).with_context(|| format!("create {}", repo_dir.display()))?;

    // Move the default vault into the repo dir on first sync so only vault.yml is tracked.
    let default_vault = confy::get_configuration_file_path("gman", "vault")
        .with_context(|| "get default vault path")?;
    let repo_vault = repo_dir.join("vault.yml");
    if default_vault.exists() && !repo_vault.exists() {
        fs::rename(&default_vault, &repo_vault)
            .with_context(|| format!("move {} -> {}", default_vault.display(), repo_vault.display()))?;
    } else if !repo_vault.exists() {
        // Ensure an empty vault exists to allow initial commits
        fs::write(&repo_vault, "{}\n").with_context(|| format!("create {}", repo_vault.display()))?;
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

    // Always align local with remote before staging/committing. For a fresh
    // repo where the remote already has content, we intentionally discard any
    // local working tree changes and take the remote state to avoid merge
    // conflicts on first sync.
    fetch_and_pull(&git, &repo_dir, branch)?;

    // Stage and commit any subsequent local changes after aligning with remote
    // so we don't merge uncommitted local state.
    stage_vault_only(&git, &repo_dir)?;

    commit_now(&git, &repo_dir, &commit_message)?;

    run_git(
        &git,
        &repo_dir,
        &["push", "-u", "origin", "--force", branch],
    )?;

    run_git(&git, &repo_dir, &["remote", "set-head", "origin", "-a"])
        .with_context(|| "Failed to set remote HEAD")
}

fn resolve_git_username(git: &Path, name: Option<&String>) -> Result<String> {
    debug!("Resolving git username");

    if let Some(name) = name {
        return Ok(name.to_string());
    }

    run_git_config_capture(git, &["config", "user.name"])
        .with_context(|| "unable to determine git username")
}

fn resolve_git_email(git: &Path, email: Option<&String>) -> Result<String> {
    debug!("Resolving git user email");
    if let Some(email) = email {
        return Ok(email.to_string());
    }

    run_git_config_capture(git, &["config", "user.email"])
        .with_context(|| "unable to determine git user email")
}

fn resolve_git(override_path: Option<&PathBuf>) -> Result<PathBuf> {
    debug!("Resolving git executable");
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Ok(s) = env::var("GIT_EXECUTABLE") {
        return Ok(PathBuf::from(s));
    }
    Ok(PathBuf::from("git"))
}

fn ensure_git_available(git: &Path) -> Result<()> {
    let ok = Command::new(git)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("run git --version")?
        .success();
    if !ok {
        Err(anyhow!("`git` not available on PATH"))
    } else {
        Ok(())
    }
}

fn run_git(git: &Path, repo: &Path, args: &[&str]) -> Result<()> {
    let status = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(args)
        .status()
        .with_context(|| format!("git {}", args.join(" ")))?;
    if !status.success() {
        return Err(anyhow!("git failed: {}", args.join(" ")));
    }
    Ok(())
}

fn run_git_config_capture(git: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new(git)
        .args(args)
        .output()
        .with_context(|| format!("git {}", args.join(" ")))?;

    if !out.status.success() {
        return Err(anyhow!(
            "git failed (exit {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn init_repo_if_needed(git: &Path, repo: &Path, branch: &str) -> Result<()> {
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

fn set_local_identity(git: &Path, repo: &Path, username: String, email: String) -> Result<()> {
    run_git(git, repo, &["config", "user.name", &username])?;
    run_git(git, repo, &["config", "user.email", &email])?;

    Ok(())
}

fn checkout_branch(git: &Path, repo: &Path, branch: &str) -> Result<()> {
    run_git(git, repo, &["checkout", "-B", branch])?;
    Ok(())
}

fn set_origin(git: &Path, repo: &Path, url: &str) -> Result<()> {
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
    			.with_prompt(format!("Have you already created the remote origin '{url}' on the Git host so we can push to it?"))
    			.default(false)
    			.interact()?
    		{
    			run_git(git, repo, &["remote", "add", "origin", url])?;
    		} else {
    			return Err(anyhow!("Remote origin does not yet exist. Please create remote origin before synchronizing, then try again"));
    		}
    Ok(())
}

fn stage_vault_only(git: &Path, repo: &Path) -> Result<()> {
    run_git(git, repo, &["add", "vault.yml"])?;
    Ok(())
}

fn fetch_and_pull(git: &Path, repo: &Path, branch: &str) -> Result<()> {
    // Fetch all refs from origin (safe even if branch doesn't exist remotely)
    run_git(git, repo, &["fetch", "origin", "--prune"]) 
        .with_context(|| "Failed to fetch changes from remote")?;

    let origin_ref = format!("origin/{branch}");
    let remote_has_branch = has_remote_branch(git, repo, branch);

    // If the repo has no commits yet, prefer remote state and discard local
    // if the remote branch exists. Otherwise, keep local state and allow an
    // initial commit to be created and pushed.
    if !has_head(git, repo) {
        if remote_has_branch {
            run_git(git, repo, &["checkout", "-f", "-B", branch, &origin_ref])
                .with_context(|| "Failed to checkout remote branch over local state")?;
            run_git(git, repo, &["reset", "--hard", &origin_ref])
                .with_context(|| "Failed to hard reset to remote branch")?;
            run_git(git, repo, &["clean", "-fd"]).with_context(|| "Failed to clean untracked files")?;
        }
        return Ok(());
    }

    // If we have local history and the remote branch exists, fast-forward.
    if remote_has_branch {
        run_git(
            git,
            repo,
            &["merge", "--ff-only", &origin_ref],
        )
        .with_context(|| "Failed to merge remote changes")?;
    }
    Ok(())
}

fn has_remote_branch(git: &Path, repo: &Path, branch: &str) -> bool {
    Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["show-ref", "--verify", "--quiet", &format!("refs/remotes/origin/{}", branch)])
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

fn commit_now(git: &Path, repo: &Path, msg: &str) -> Result<()> {
    let staged_changed = Command::new(git)
        .arg("-C")
        .arg(repo)
        .args(["diff", "--cached", "--quiet", "--exit-code"])
        .status()
        .context("git diff --cached")?
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
        // Override path wins
        let override_path = Some(PathBuf::from("/custom/git"));
        let got = resolve_git(override_path.as_ref()).unwrap();
        assert_eq!(got, PathBuf::from("/custom/git"));

        // If no override, env var is used
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
        assert_eq!(repo_name_from_url("https://github.com/user/test-vault.git"), "test-vault");
        assert_eq!(repo_name_from_url("ssh://git@example.com/x/y/z.git"), "z");
        assert_eq!(repo_name_from_url("git@example.com:ns/repo"), "repo");
    }
}
