mod errors;

use std::collections::HashMap;
use errors::{GitHubOIDCError, GitHubOIDCClaimsTimeError};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

/// Represents a JSON Web Key (JWK) used for token validation.
///
/// A JWK is a digital secure key used in secure web communications.
/// It contains all the important details about the key, such as what it's for
/// and how it works. This information helps websites verify users.
#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    /// Key type (e.g., "RSA")
    pub kty: String,
    /// Intended use of the key (e.g., "sig" for signature)
    pub use_: Option<String>,
    /// Unique identifier for the key
    pub kid: String,
    /// Algorithm used with this key (e.g., "RS256")
    pub alg: Option<String>,
    /// RSA public key modulus (base64url-encoded)
    pub n: String,
    /// RSA public key exponent (base64url-encoded)
    pub e: String,
    /// X.509 certificate chain (optional)
    pub x5c: Option<Vec<String>>,
    /// X.509 certificate SHA-1 thumbprint (optional)
    pub x5t: Option<String>,
    /// X.509 certificate SHA-256 thumbprint (optional)
    pub x5t_s256: Option<String>,
}

/// Represents a set of JSON Web Keys (JWKS) used for GitHub token validation.
///
/// This structure is crucial for GitHub Actions authentication because:
///
/// 1. GitHub Key Rotation: GitHub rotates its keys for security,
///    and having multiple keys allows your application to validate
///    tokens continuously during these changes.
///
/// 2. Multiple Environments: Different GitHub environments (like production and development)
///    might use different keys. A set of keys allows your app to work across these environments.
///
/// 3. Fallback Mechanism: If one key fails for any reason, your app can try others in the set.
///
/// Think of it like a key ring for a building manager. They don't just carry one key,
/// but a set of keys for different doors or areas.
#[derive(Debug, Serialize, Deserialize)]
pub struct GithubJWKS {
    /// Vector of JSON Web Keys
    pub keys: Vec<JWK>,
}

/// Represents the claims contained in a GitHub Actions JWT (JSON Web Token).
///
/// When a GitHub Actions workflow runs, it receives a token with these claims.
/// This struct helps decode and access the information from that token.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GitHubClaims {
    /// The ID of the token.
    pub jti: String,

    /// The subject of the token (e.g the GitHub Actions runner ID).
    pub sub: String,

    /// The intended audience of the token, typically the repository owner.
    #[serde(rename = "aud")]
    pub audience: String,

    /// The SHA of the commit that caused the token to be created.
    pub sha: Option<String>,

    /// The full name of the repository.
    pub repository: String,

    /// The ID of the repository.
    pub repository_id: u64,

    /// The owner of the repository.
    pub repository_owner: String,

    /// The ID of the owner of the repository.
    pub repository_owner_id: u64,

    /// The ID of the workflow run that created the token.
    pub run_id: Option<u64>,

    /// The number  of the workflow run that created the token.
    pub run_number: Option<u64>,

    /// The attempt of the workflow run that created the token.
    pub run_attempt: Option<u64>,

    /// The name of the workflow.
    pub workflow: Option<String>,

    /// The reference to the specific workflow.
    pub workflow_ref: Option<String>,

    /// The SHA hash of the workflow run.
    pub workflow_sha: Option<String>,

    /// A reference to the specific job and workflow.
    pub job_workflow_ref: String,

    /// The SHA hash to the commit of the specific job and workflow.
    pub job_workflow_sha: String,

    /// The environment that was targeted by the workflow run.
    pub environment: Option<String>,

    /// The name of the enterprise owning the repository.
    pub enterprise: Option<String>,

    /// The ID of the enterprise owning the repository.
    pub enterprise_id: Option<u64>,

    /// The timestamp when the token was issued.
    pub iat: u64,

    /// The timestamp when the token expires.
    #[serde(rename = "exp")]
    pub expires_at: u64,

    /// The timestamp after which the token is valid.
    #[serde(rename = "nbf")]
    pub not_before: u64,

    /// Captures extra fields.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl GitHubClaims {
    /// Validates whether the token is valid given the provided SystemTime.
    ///
    /// This function checks if the current time is between `not_before` (nbf) and `expires_at` (exp),
    /// ensuring the token is valid for use. It also ensures that the `iat` (issued at) time is in the past.
    ///
    /// # Arguments
    ///
    /// * `time` - The `SystemTime` to validate the token against.
    ///
    /// # Returns
    ///
    /// Returns `Result<(), GitHubOIDCClaimsTimeError>` with `Ok(())` if the token is valid,
    /// or an appropriate error if the token is invalid or expired.
    fn validate_time(&self, time: std::time::SystemTime) -> Result<(), GitHubOIDCClaimsTimeError> {
        let current_timestamp = time
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| GitHubOIDCClaimsTimeError::InvalidTime)?
            .as_secs();

        if self.not_before > 0 && self.expires_at > 0 && self.not_before > self.expires_at {
            return Err(GitHubOIDCClaimsTimeError::InvalidTimeWindow);
        }
        
        if self.iat > current_timestamp {
            return Err(GitHubOIDCClaimsTimeError::TokenIssuedInFuture);
        }

        if self.not_before > 0 && current_timestamp < self.not_before {
            return Err(GitHubOIDCClaimsTimeError::TokenNotYetValid);
        }

        if self.expires_at > 0 && current_timestamp > self.expires_at {
            return Err(GitHubOIDCClaimsTimeError::TokenExpired);
        }
        
        Ok(())
    }
}

/// Default URL for fetching GitHub OIDC tokens
pub const DEFAULT_GITHUB_OIDC_URL: &str = "https://token.actions.githubusercontent.com";

/// Fetches the JSON Web Key Set (JWKS) from the specified OIDC URL.
///
/// # Arguments
///
/// * `oidc_url` - The base URL of the OpenID Connect provider (GitHub by default)
///
/// # Returns
///
/// * `Result<GithubJWKS, GitHubOIDCError>` - A Result containing the fetched JWKS if successful,
///   or an error if the fetch or parsing fails
///
/// # Example
///
/// ```
/// use github_oidc::{fetch_jwks, DEFAULT_GITHUB_OIDC_URL};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let jwks = fetch_jwks(DEFAULT_GITHUB_OIDC_URL).await?;
///     println!("JWKS: {:?}", jwks);
///     Ok(())
/// }
/// ```
pub async fn fetch_jwks(oidc_url: &str) -> Result<GithubJWKS, GitHubOIDCError> {
    info!("Fetching JWKS from {}", oidc_url);
    let client = reqwest::Client::new();
    let jwks_url = format!("{}/.well-known/jwks", oidc_url);
    match client.get(&jwks_url).send().await {
        Ok(response) => match response.json::<GithubJWKS>().await {
            Ok(jwks) => {
                info!("JWKS fetched successfully");
                Ok(jwks)
            }
            Err(e) => {
                error!("Failed to parse JWKS response: {:?}", e);
                Err(GitHubOIDCError::JWKSParseError(e.to_string()))
            }
        },
        Err(e) => {
            error!("Failed to fetch JWKS: {:?}", e);
            Err(GitHubOIDCError::JWKSFetchError(e.to_string()))
        }
    }
}

/// Configuration options for GitHub OIDC token validation
#[derive(Debug, Clone, Default)]
pub struct GitHubOIDCConfig {
    /// Expected audience for the token
    pub audience: Option<String>,
    /// Expected repository for the token
    pub repository: Option<String>,
    /// Expected repository owner for the token
    pub repository_owner: Option<String>,
}

impl GithubJWKS {
    /// Validates a GitHub OIDC token against the provided JSON Web Key Set (JWKS).
    ///
    /// This method performs several checks:
    /// 1. Verifies the token format.
    /// 2. Decodes the token header to find the key ID (kid).
    /// 3. Locates the corresponding key in the JWKS.
    /// 4. Validates the token signature and claims.
    /// 5. Optionally checks the token's audience.
    /// 6. Verifies the token's organization and repository claims against environment variables.
    ///
    /// # Arguments
    ///
    /// * `token` - The GitHub OIDC token to validate.
    /// * `jwks` - An `Arc<RwLock<GithubJWKS>>` containing the JSON Web Key Set.
    /// * `config` - A `GitHubOIDCConfig` struct containing validation options.
    /// * `expected_audience` - An optional expected audience for the token.
    ///
    /// # Returns
    ///
    /// Returns a `Result<GitHubClaims, GitHubOIDCError>` containing the validated claims if successful,
    /// or an error if validation fails.
    ///
    pub fn validate_github_token(
        &self,
        token: &str,
        config: &GitHubOIDCConfig,
    ) -> Result<GitHubClaims, GitHubOIDCError> {
        debug!("Starting token validation");
        if !token.starts_with("eyJ") {
            warn!("Invalid token format received");
            return Err(GitHubOIDCError::InvalidTokenFormat);
        }

        debug!("JWKS loaded");

        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            GitHubOIDCError::HeaderDecodingError(format!(
                "Failed to decode header: {}. Make sure you're using a valid JWT, not a PAT.",
                e
            ))
        })?;

        let decoding_key = if let Some(kid) = header.kid {
            let key = self
                .keys
                .iter()
                .find(|k| k.kid == kid)
                .ok_or(GitHubOIDCError::KeyNotFound)?;

            let modulus = key.n.as_str();
            let exponent = key.e.as_str();

            DecodingKey::from_rsa_components(modulus, exponent)
                .map_err(|e| GitHubOIDCError::DecodingKeyCreationError(e.to_string()))?
        } else {
            DecodingKey::from_secret("your_secret_key".as_ref())
        };

        let mut validation = Validation::new(Algorithm::RS256);
        if let Some(audience) = &config.audience {
            validation.set_audience(&[audience]);
        }

        let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| GitHubOIDCError::TokenDecodingError(e.to_string()))?;

        let claims = token_data.claims;
        claims.validate_time(std::time::SystemTime::now())?;

        if let Some(expected_owner) = &config.repository_owner {
            if claims.repository_owner != *expected_owner {
                warn!(
                    "Token organization mismatch. Expected: {}, Found: {}",
                    expected_owner, claims.repository_owner
                );
                return Err(GitHubOIDCError::OrganizationMismatch);
            }
        }

        if let Some(expected_repo) = &config.repository {
            debug!(
                "Comparing repositories - Expected: {}, Found: {}",
                expected_repo, claims.repository
            );
            if claims.repository != *expected_repo {
                warn!(
                    "Token repository mismatch. Expected: {}, Found: {}",
                    expected_repo, claims.repository
                );
                return Err(GitHubOIDCError::RepositoryMismatch);
            }
        }

        debug!("Token validation completed successfully");
        Ok(claims)
    }
}


#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deserialize_github_claims() {
        let claims_json = json!({
            "job_workflow_ref": "example/workflow@sha",
            "job_workflow_sha": "abc123def456",
            "environment": "production",
            "enterprise": "ExampleCorp",
            "enterprise_id": 42,
            "iat": 1691986810,
            "exp": 1691990410,
            "nbf": 1691986410,
            "extra_field": "extra_value"
        });

        let claims: GitHubClaims = serde_json::from_value(claims_json).expect("Failed to deserialize claims");

        assert_eq!(claims.job_workflow_ref, "example/workflow@sha");
        assert_eq!(claims.job_workflow_sha, "abc123def456");
        assert_eq!(claims.environment.unwrap(), "production");
        assert_eq!(claims.enterprise.unwrap(), "ExampleCorp");
        assert_eq!(claims.enterprise_id.unwrap(), 42);
        assert_eq!(claims.iat, 1691986810);
        assert_eq!(claims.expires_at, 1691990410);
        assert_eq!(claims.not_before, 1691986410);
        assert_eq!(claims.extra.get("extra_field").unwrap(), "extra_value");
    }
    

    #[test]
    fn test_token_validation_before_nbf_timestamp() {
        let claims = GitHubClaims {
            iat: 1691986810, // Issued At
            expires_at: 1691990410,
            not_before: 1691987000,
            ..Default::default()
        };

        let result = claims.validate_time(UNIX_EPOCH + Duration::from_secs(1691986810));
        assert_eq!(result, Err(GitHubOIDCClaimsTimeError::TokenNotYetValid));
    }

    #[test]
    fn test_token_expired() {
        let claims = GitHubClaims {
            iat: 1691986810,
            expires_at: 1691990410,
            not_before: 1691986410,
            ..Default::default()
        };

        let result = claims.validate_time(UNIX_EPOCH + Duration::from_secs(1691990500));
        assert_eq!(result, Err(GitHubOIDCClaimsTimeError::TokenExpired));
    }

    #[test]
    fn test_token_issued_in_future() {
        let claims_with_future_iat = GitHubClaims {
            iat: 1700000000, // Issued At in the future
            expires_at: 1700003600,
            not_before: 1691986410,
            ..Default::default()
        };
        let result = claims_with_future_iat.validate_time(UNIX_EPOCH + Duration::from_secs(1691990000));
        assert_eq!(result, Err(GitHubOIDCClaimsTimeError::TokenIssuedInFuture));
    }

    #[test]
    fn test_token_invalid_time_constraint() {
        let claims_with_invalid_nbf_exp = GitHubClaims {
            iat: 1691986810,
            expires_at: 1691987000, // Expiration time is before `nbf`
            not_before: 1691987100,
            ..Default::default()
        };
        let result = claims_with_invalid_nbf_exp.validate_time(UNIX_EPOCH + Duration::from_secs(1691987200));
        assert_eq!(result, Err(GitHubOIDCClaimsTimeError::InvalidTimeWindow));
    }
}