use anyhow::Result;
use validator::Validate;

// Redefining the struct here for testing purposes
pub struct SyncOpts<'a> {
    pub remote_url: &'a Option<String>,
    pub branch: &'a Option<String>,
}

impl<'a> Validate for SyncOpts<'a> {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        if self.remote_url.is_none() {
            return Err(validator::ValidationErrors::new());
        }
        if self.branch.is_none() {
            return Err(validator::ValidationErrors::new());
        }
        Ok(())
    }
}

#[test]
fn test_sync_opts_validation_valid() {
    let remote_url = Some("https://github.com/user/repo.git".to_string());
    let branch = Some("main".to_string());
    let opts = SyncOpts {
        remote_url: &remote_url,
        branch: &branch,
    };
    assert!(opts.validate().is_ok());
}

#[test]
fn test_sync_opts_validation_missing_remote_url() {
    let remote_url = None;
    let branch = Some("main".to_string());
    let opts = SyncOpts {
        remote_url: &remote_url,
        branch: &branch,
    };
    assert!(opts.validate().is_err());
}

#[test]
fn test_sync_opts_validation_missing_branch() {
    let remote_url = Some("https://github.com/user/repo.git".to_string());
    let branch = None;
    let opts = SyncOpts {
        remote_url: &remote_url,
        branch: &branch,
    };
    assert!(opts.validate().is_err());
}
