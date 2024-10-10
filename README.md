# 🔐 github-oidc

[<img alt="github" src="https://img.shields.io/badge/github-the--cafe/github--oidc-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/the-cafe/github-oidc)
[<img alt="crates.io" src="https://img.shields.io/crates/v/github-oidc.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/github-oidc)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-github--oidc-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/github-oidc)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/dtolnay/anyhow/ci.yml?branch=master&style=for-the-badge" height="20">](https://github.com/dtolnay/anyhow/actions?query=branch%3Amaster)

TL;DR

- Rust crate for validating GitHub [OIDC tokens](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- Fetches JWKS and verifies token claims for GitHub Actions
- No more long-lived credentials in your repository

## 🚀 Installation

`cargo add github-oidc`
 
 or add the dependency to your Cargo.toml
 ```toml
 [dependencies]
 github-oidc = "insert_latest_version_here" # e.g. 0.1.4
 ```

## 🎯 Ideal Use Case: Secure CI/CD Pipeline for Sensitive Operations

github-oidc enables secure, credential-free authentication for custom GitHub Actions workflow integrations.

Here's the perfect ideal scenario:
1. Your Github Actions Workflow needs to interact with protected resources (e.g., production databases, cloud services, or internal APIs).
2. You set up a custom OIDC provider service (e.g., using [railway.app](https://railway.app)) to handle authentication for your GitHub Actions.
3. In your GitHub Actions workflow:
   - The job requests an OIDC token from GitHub.
   - This token is sent to your custom OIDC provider service.
   - Your service uses `github-oidc` to validate the token and check the github claims (e.g., repository name, workflow, ref).
   - If valid, your custom OIDC provider service generates short-lived, scoped credentials for the specific task.
4. The GitHub Action uses these temporary credentials to perform the you desired operations.
5. Credentials expire shortly after the job completes.


## ⚙️ Usage

### Example Custom OIDC Provider Service in Rust
```rust
use github_oidc::{GithubJWKS, validate_github_token};
use std::sync::Arc;
use tokio::sync::RwLock;

async fn custom_endpoint(
    token_request: web::Json<TokenRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let jwks = data.jwks.clone();
    match validate_github_token(&token_request.token, jwks, Some("https://github.com/your-username")).await {
        Ok(claims) => {
            log::info!("Token validated successfully");
            HttpResponse::Ok().json(claims)
        }
        Err(e) => {
            log::error!("Token validation error: {:?}", e);
            HttpResponse::BadRequest().body(format!("Invalid token: {}", e))
        }
    }
}    

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(Env::default().default_filter_or("debug"));
    color_eyre::install()?;

    let github_oidc_url = "your_oidc_server_url"
    let jwks = Arc::new(RwLock::new(fetch_jwks(github_oidc_url).await?));

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState { jwks: jwks.clone() }))
            .route("/token", web::post().to(custom_endpoint))
    })
    .bind("0.0.0.0:3000")?
    .run()
    .await?;

    Ok(())
}


```

### Example GitHub Actions Workflow that uses OIDC URL Server
```yaml
name: Get and Validate JWT

on:
  workflow_dispatch:

jobs:
  get_and_validate_jwt:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - name: Get JWT
        id: get_token
        uses: actions/github-script@v6
        with:
          script: |
            const token = await core.getIDToken()
            core.setOutput('token', token)

      - name: Validate JWT
        env:
          OIDC_SERVICE_URL: ${{ secrets.OIDC_SERVICE_URL }}
        run: |
          TOKEN="${{ steps.get_token.outputs.token }}"
          RESPONSE=$(curl -s -X POST $OIDC_SERVICE_URL \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"$TOKEN\"}")
          echo "OIDC Service Response: $RESPONSE"
          
          if [[ $RESPONSE == *"Invalid token"* ]]; then
            echo "::error::Token validation failed: $RESPONSE"
            exit 1
          elif [[ $RESPONSE == *"error"* ]]; then
            echo "::warning::Unexpected error occurred: $RESPONSE"
            exit 1
          elif [[ -z "$RESPONSE" ]]; then
            echo "::error::Empty response from OIDC service"
            exit 1
          else
            echo "::notice::Token validated successfully"
            echo "$RESPONSE" | jq .
          fi
```
