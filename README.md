# 🔐 git-oidc

[![Crates.io](https://img.shields.io/crates/v/git-oidc)](https://crates.io/crates/git-oidc)


TL;DR

- Rust library for validating GitHub [OIDC tokens](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- Fetches JWKS and verifies token claims for GitHub Actions
- No more long-lived credentials in your repository

## 🚀 Installation

`cargo add git-oidc`


## 🤔 Use Case Scenario

git-oidc enables secure, credential-free authentication for custom GitHub integrations:

1. Set up a custom OIDC provider service (e.g., [railway.app](https://railway.app)).
2. GitHub Actions generates an OIDC token for your Github Actions.
3. Your custom OIDC provider service uses git-oidc to validate the token.
4. Validation can be used for any Github Actions workflow


## ⚙️ Usage

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
