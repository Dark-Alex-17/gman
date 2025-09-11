use gman::providers::SupportedProvider;
use gman::providers::local::LocalProvider;
use pretty_assertions::assert_eq;

#[test]
fn test_provider_kind_from() {
    enum ProviderKind {
        Local,
    }

    impl From<ProviderKind> for SupportedProvider {
        fn from(k: ProviderKind) -> Self {
            match k {
                ProviderKind::Local => SupportedProvider::Local(LocalProvider),
            }
        }
    }

    let provider_kind = ProviderKind::Local;
    let supported_provider: SupportedProvider = provider_kind.into();
    assert_eq!(supported_provider, SupportedProvider::Local(LocalProvider));
}
