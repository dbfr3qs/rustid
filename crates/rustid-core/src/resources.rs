//! Identity resources, API scopes and API resources, in the fixture format
//! (camelCase JSON).

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct IdentityResource {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub required: bool,
    pub emphasize: bool,
    pub show_in_discovery_document: bool,
    pub user_claims: Vec<String>,
    /// The string-typed extended properties (`Properties`).
    pub properties: std::collections::BTreeMap<String, String>,
}

impl Default for IdentityResource {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: None,
            description: None,
            enabled: true,
            required: false,
            emphasize: false,
            show_in_discovery_document: true,
            user_claims: Vec::new(),
            properties: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiScope {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub required: bool,
    pub emphasize: bool,
    pub show_in_discovery_document: bool,
    pub user_claims: Vec<String>,
    /// The string-typed extended properties (`Properties`).
    pub properties: std::collections::BTreeMap<String, String>,
}

impl Default for ApiScope {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: None,
            description: None,
            enabled: true,
            required: false,
            emphasize: false,
            show_in_discovery_document: true,
            user_claims: Vec::new(),
            properties: Default::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ApiResource {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub show_in_discovery_document: bool,
    pub scopes: Vec<String>,
    pub user_claims: Vec<String>,
    /// Access tokens for this API must be signed with one of these.
    pub allowed_access_token_signing_algorithms: Vec<String>,
    /// Only issued when the request names this resource (RFC 8707).
    pub require_resource_indicator: bool,
    /// Secrets the API uses at the introspection endpoint.
    pub api_secrets: Vec<crate::clients::Secret>,
    /// The string-typed extended properties (`Properties`).
    pub properties: std::collections::BTreeMap<String, String>,
}

impl Default for ApiResource {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: None,
            description: None,
            enabled: true,
            show_in_discovery_document: true,
            scopes: Vec::new(),
            user_claims: Vec::new(),
            allowed_access_token_signing_algorithms: Vec::new(),
            require_resource_indicator: false,
            api_secrets: Vec::new(),
            properties: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, serde::Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Resources {
    pub identity_resources: Vec<IdentityResource>,
    pub api_scopes: Vec<ApiScope>,
    pub api_resources: Vec<ApiResource>,
}

#[derive(Debug, thiserror::Error)]
pub enum ResourcesError {
    #[error("reading resources file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing resources file {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    /// The in memory resources store refuses duplicate names within each list.
    #[error("resources file {path}: {kind}s must not contain duplicate names ({name})")]
    Duplicate {
        path: String,
        kind: &'static str,
        name: String,
    },
    /// Accepting these at startup would fail every request that touches
    /// them (and discovery) with "Found identity scopes and API scopes that
    /// use the same names"; they are rejected at load instead.
    #[error(
        "resources file {path}: identity resources and API scopes must not share names ({names})"
    )]
    Overlap { path: String, names: String },
}

impl Resources {
    pub fn load(path: &Path) -> Result<Self, ResourcesError> {
        let display = path.display().to_string();
        let json = std::fs::read_to_string(path).map_err(|source| ResourcesError::Read {
            path: display.clone(),
            source,
        })?;
        let resources: Resources =
            serde_json::from_str(&json).map_err(|source| ResourcesError::Parse {
                path: display.clone(),
                source,
            })?;
        if let Some((kind, name)) = resources.first_duplicate() {
            return Err(ResourcesError::Duplicate {
                path: display,
                kind,
                name: name.to_owned(),
            });
        }
        let overlap = resources.overlapping_scope_names();
        if !overlap.is_empty() {
            return Err(ResourcesError::Overlap {
                path: display,
                names: overlap.join(", "),
            });
        }
        Ok(resources)
    }

    /// Names used by both an identity resource and an API scope.
    pub fn overlapping_scope_names(&self) -> Vec<&str> {
        self.identity_resources
            .iter()
            .map(|r| r.name.as_str())
            .filter(|name| self.api_scopes.iter().any(|s| s.name == *name))
            .collect()
    }

    /// The first name repeated within one list, with the list's kind.
    pub fn first_duplicate(&self) -> Option<(&'static str, &str)> {
        fn first<'a>(names: impl Iterator<Item = &'a str>) -> Option<&'a str> {
            let mut seen = std::collections::HashSet::new();
            names.into_iter().find(|n| !seen.insert(*n))
        }
        first(self.identity_resources.iter().map(|r| r.name.as_str()))
            .map(|n| ("identity resource", n))
            .or_else(|| {
                first(self.api_scopes.iter().map(|r| r.name.as_str())).map(|n| ("API scope", n))
            })
            .or_else(|| {
                first(self.api_resources.iter().map(|r| r.name.as_str()))
                    .map(|n| ("API resource", n))
            })
    }

    /// Disabled entries removed.
    pub fn enabled(&self) -> Resources {
        Resources {
            identity_resources: self
                .identity_resources
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect(),
            api_scopes: self
                .api_scopes
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect(),
            api_resources: self
                .api_resources
                .iter()
                .filter(|r| r.enabled)
                .cloned()
                .collect(),
        }
    }
}
