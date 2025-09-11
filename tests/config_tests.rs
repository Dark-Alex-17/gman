#[cfg(test)]
mod tests {
    use gman::config::{Config, RunConfig};
    use gman::providers::SupportedProvider;
    use gman::providers::local::LocalProvider;
    use pretty_assertions::{assert_eq, assert_str_eq};

    use validator::Validate;

    #[test]
    fn test_run_config_valid() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: None,
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_ok());
    }

    #[test]
    fn test_run_config_missing_name() {
        let run_config = RunConfig {
            name: None,
            secrets: Some(vec!["secret1".to_string()]),
            flag: None,
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_run_config_missing_secrets() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: None,
            flag: None,
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_run_config_invalid_flag_position() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: Some("--test-flag".to_string()),
            flag_position: Some(0),
            arg_format: Some("{{key}}={{value}}".to_string()),
            files: None,
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_run_config_flags_or_none_all_some() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: Some("--test-flag".to_string()),
            flag_position: Some(1),
            arg_format: Some("{{key}}={{value}}".to_string()),
            files: None,
        };
        assert!(run_config.validate().is_ok());
    }

    #[test]
    fn test_run_config_flags_or_none_all_none() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: None,
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_ok());
    }

    #[test]
    fn test_run_config_flags_or_none_partial_some() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: Some("--test-flag".to_string()),
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_run_config_flags_or_none_missing_placeholder() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: Some("--test-flag".to_string()),
            flag_position: Some(1),
            arg_format: Some("key=value".to_string()),
            files: None,
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_run_config_flags_or_files_all_none() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: None,
            flag_position: None,
            arg_format: None,
            files: None,
        };
        assert!(run_config.validate().is_ok());
    }

    #[test]
    fn test_run_config_flags_or_files_files_is_some() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: None,
            flag_position: None,
            arg_format: None,
            files: Some(Vec::new()),
        };
        assert!(run_config.validate().is_ok());
    }

    #[test]
    fn test_run_config_flags_or_files_all_some() {
        let run_config = RunConfig {
            name: Some("test".to_string()),
            secrets: Some(vec!["secret1".to_string()]),
            flag: Some("--test-flag".to_string()),
            flag_position: Some(1),
            arg_format: Some("{{key}}={{value}}".to_string()),
            files: Some(Vec::new()),
        };
        assert!(run_config.validate().is_err());
    }

    #[test]
    fn test_config_valid() {
        let config = Config {
            provider: SupportedProvider::Local(LocalProvider),
            password_file: None,
            git_branch: None,
            git_remote_url: None,
            git_user_name: None,
            git_user_email: Some("test@example.com".to_string()),
            git_executable: None,
            run_configs: None,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_email() {
        let config = Config {
            provider: SupportedProvider::Local(LocalProvider),
            password_file: None,
            git_branch: None,
            git_remote_url: None,
            git_user_name: None,
            git_user_email: Some("test".to_string()),
            git_executable: None,
            run_configs: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.provider, SupportedProvider::Local(LocalProvider));
        assert_eq!(config.git_branch, Some("main".to_string()));
    }

    #[test]
    fn test_config_extract_provider() {
        let config = Config::default();
        let provider = config.extract_provider();
        assert_str_eq!(provider.name(), "LocalProvider");
    }

    #[test]
    fn test_config_local_provider_password_file() {
        let path = Config::local_provider_password_file();
        let expected_path = dirs::home_dir().map(|p| p.join(".gman_password"));
        if let Some(p) = &expected_path {
            if !p.exists() {
                assert_eq!(path, None);
            } else {
                assert_eq!(path, expected_path);
            }
        } else {
            assert_eq!(path, None);
        }
    }
}
