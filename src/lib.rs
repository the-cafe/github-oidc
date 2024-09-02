use color_eyre::eyre::{eyre, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use reqwest;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;
use log::{error, info, warn, debug};

#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubClaims {
    sub: String,
    repository: String,
    repository_owner: String,
    job_workflow_ref: String,
    iat: u64,
}


pub async fn fetch_jwks(oidc_url: &str) -> Result<Value> {
    info!("Fetching JWKS from {}", oidc_url);
    let client = reqwest::Client::new();
    let jwks_url = format!("{}/.well-known/jwks", oidc_url);
    match client.get(&jwks_url).send().await {
        Ok(response) => {
            match response.json().await {
                Ok(jwks) => {
                    info!("JWKS fetched successfully");
                    Ok(jwks)
                }
                Err(e) => {
                    error!("Failed to parse JWKS response: {:?}", e);
                    Err(eyre!("Failed to parse JWKS"))
                }
            }
        }
        Err(e) => {
            error!("Failed to fetch JWKS: {:?}", e);
            Err(eyre!("Failed to fetch JWKS"))
        }
    }
}



pub async fn validate_github_token(token: &str, jwks: Arc<RwLock<Value>>, expected_audience: &str) -> Result<GitHubClaims> {
    debug!("Starting token validation");
    if !token.starts_with("eyJ") {
        warn!("Invalid token format received");
        return Err(eyre!("Invalid token format. Expected a JWT."));
    }

    let jwks = jwks.read().await;
    debug!("JWKS loaded");

    let header = jsonwebtoken::decode_header(token).map_err(|e| {
        eyre!(
            "Failed to decode header: {}. Make sure you're using a valid JWT, not a PAT.",
            e
        )
    })?;

    let decoding_key = if let Some(kid) = header.kid {
        let key = jwks["keys"]
            .as_array()
            .ok_or_else(|| eyre!("Invalid JWKS format"))?
            .iter()
            .find(|k| k["kid"].as_str() == Some(&kid))
            .ok_or_else(|| eyre!("Matching key not found in JWKS"))?;

        let modulus = key["n"].as_str().ok_or_else(|| eyre!("No 'n' in JWK"))?;
        let exponent = key["e"].as_str().ok_or_else(|| eyre!("No 'e' in JWK"))?;

        DecodingKey::from_rsa_components(modulus, exponent)
            .map_err(|e| eyre!("Failed to create decoding key: {}", e))?
    } else {
        DecodingKey::from_secret("your_secret_key".as_ref())
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[expected_audience]);

    let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
        .map_err(|e| eyre!("Failed to decode token: {}", e))?;

    let claims = token_data.claims;

    if let Ok(org) = std::env::var("GITHUB_ORG") {
        if claims.repository_owner != org {
            warn!("Token organization mismatch. Expected: {}, Found: {}", org, claims.repository_owner);
            return Err(eyre!("Token is not from the expected organization"));
        }
    }

    if let Ok(repo) = std::env::var("GITHUB_REPO") {
        debug!("Comparing repositories - Expected: {}, Found: {}", repo, claims.repository);
        if claims.repository != repo {
            warn!("Token repository mismatch. Expected: {}, Found: {}", repo, claims.repository);
            return Err(eyre!("Token is not from the expected repository"));
        }
    }

    debug!("Token validation completed successfully");
    Ok(claims)
}
