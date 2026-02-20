use std::collections::HashMap;

use super::traits::OAuthProvider;

/// Registry of available OAuth providers, keyed by provider ID.
pub struct ProviderRegistry {
    providers: HashMap<String, Box<dyn OAuthProvider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
        }
    }

    /// Register a new provider.
    pub fn register(&mut self, provider: Box<dyn OAuthProvider>) {
        let id = provider.id().to_string();
        self.providers.insert(id, provider);
    }

    /// Get a provider by ID.
    pub fn get(&self, id: &str) -> Option<&dyn OAuthProvider> {
        self.providers.get(id).map(|p| p.as_ref())
    }

    /// List all registered provider IDs.
    pub fn list(&self) -> Vec<&str> {
        self.providers.keys().map(|k| k.as_str()).collect()
    }

    /// Number of registered providers.
    pub fn count(&self) -> usize {
        self.providers.len()
    }
}
