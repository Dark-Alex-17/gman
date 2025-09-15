#[cfg(test)]
mod tests {
	use gman::config::{Config, ProviderConfig, RunConfig};
    use pretty_assertions::assert_eq;

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
    fn test_provider_config_default() {
        let config = ProviderConfig::default();

        assert_eq!(config.name, Some("local".to_string()));
    }

    #[test]
    fn test_config_valid() {
        let config = Config {
            default_provider: Some("local".into()),
            providers: vec![ProviderConfig::default()],
            run_configs: None,
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_default_provider() {
        let config = Config {
            default_provider: Some("nonexistent".into()),
            providers: vec![ProviderConfig::default()],
            run_configs: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_no_providers() {
        let config = Config {
            default_provider: Some("local".into()),
            providers: vec![],
            run_configs: None,
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(config.default_provider, Some("local".to_string()));
        assert_eq!(config.providers, vec![ProviderConfig::default()]);
        assert_eq!(config.run_configs, None);
    }

    #[test]
    fn test_config_extract_provider() {
        let config = Config::default();
        let provider = config.extract_provider_config(None).unwrap();

        assert_eq!(provider.name, Some("local".to_string()));
    }

    #[test]
    fn test_config_extract_provider_with_name() {
        let mut config = Config::default();
        config.providers.push(ProviderConfig {
            name: Some("custom".to_string()),
            ..Default::default()
        });
        let provider = config
            .extract_provider_config(Some("custom".into()))
            .unwrap();

        assert_eq!(provider.name, Some("custom".to_string()));
    }

    #[test]
    fn test_config_extract_provider_not_found() {
        let config = Config::default();
        let result = config.extract_provider_config(Some("nonexistent".into()));

        assert!(result.is_err());
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

    #[test]
    fn test_config_duplicate_provider_names_is_invalid() {
			let name = Some("dup".into());
        let p1 = ProviderConfig {
					name: name.clone(),
					..Default::default()
				};
        let p2 = ProviderConfig {
					name,
					..Default::default()
				};

        let cfg = Config {
            default_provider: Some("dup".into()),
            providers: vec![p1, p2],
            run_configs: None,
        };

        assert!(cfg.validate().is_err());
    }
}
