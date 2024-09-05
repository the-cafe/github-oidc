use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
pub struct JWK {
    pub kty: String,
    pub use_: Option<String>,
    pub kid: String,
    pub alg: Option<String>,
    pub n: String,
    pub e: String,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,
    pub x5t_s256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GithubJWKS {
    pub keys: Vec<JWK>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubClaims {
    sub: String,
    repository: String,
    repository_owner: String,
    job_workflow_ref: String,
    iat: u64,
}

pub async fn fetch_jwks(oidc_url: &str) -> Result<GithubJWKS> {
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
                Err(anyhow!("Failed to parse JWKS"))
            }
        },
        Err(e) => {
            error!("Failed to fetch JWKS: {:?}", e);
            Err(anyhow!("Failed to fetch JWKS"))
        }
    }
}

impl GithubJWKS {
    pub async fn validate_github_token(
        token: &str,
        jwks: Arc<RwLock<GithubJWKS>>,
        expected_audience: Option<&str>,
    ) -> Result<GitHubClaims> {
        debug!("Starting token validation");
        if !token.starts_with("eyJ") {
            warn!("Invalid token format received");
            return Err(anyhow!("Invalid token format. Expected a JWT."));
        }

        let jwks = jwks.read().await;
        debug!("JWKS loaded");

        let header = jsonwebtoken::decode_header(token).map_err(|e| {
            anyhow!(
                "Failed to decode header: {}. Make sure you're using a valid JWT, not a PAT.",
                e
            )
        })?;

        let decoding_key = if let Some(kid) = header.kid {
            let key = jwks
                .keys
                .iter()
                .find(|k| k.kid == kid)
                .ok_or_else(|| anyhow!("Matching key not found in JWKS"))?;

            let modulus = key.n.as_str();
            let exponent = key.e.as_str();

            DecodingKey::from_rsa_components(modulus, exponent)
                .map_err(|e| anyhow!("Failed to create decoding key: {}", e))?
        } else {
            DecodingKey::from_secret("your_secret_key".as_ref())
        };

        let mut validation = Validation::new(Algorithm::RS256);
        if let Some(audience) = expected_audience {
            validation.set_audience(&[audience]);
        }

        let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| anyhow!("Failed to decode token: {}", e))?;

        let claims = token_data.claims;

        if let Ok(org) = std::env::var("GITHUB_ORG") {
            if claims.repository_owner != org {
                warn!(
                    "Token organization mismatch. Expected: {}, Found: {}",
                    org, claims.repository_owner
                );
                return Err(anyhow!("Token is not from the expected organization"));
            }
        }

        if let Ok(repo) = std::env::var("GITHUB_REPO") {
            debug!(
                "Comparing repositories - Expected: {}, Found: {}",
                repo, claims.repository
            );
            if claims.repository != repo {
                warn!(
                    "Token repository mismatch. Expected: {}, Found: {}",
                    repo, claims.repository
                );
                return Err(anyhow!("Token is not from the expected repository"));
            }
        }

        debug!("Token validation completed successfully");
        Ok(claims)
    }
}

pub async fn validate_github_token(
    token: &str,
    jwks: Arc<RwLock<GithubJWKS>>,
    expected_audience: Option<&str>,
) -> Result<GitHubClaims> {
    GithubJWKS::validate_github_token(token, jwks, expected_audience).await
}
