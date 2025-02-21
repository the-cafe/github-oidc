use thiserror::Error;

#[derive(Error, Debug)]
pub enum GitHubOIDCError {
    #[error("Invalid token format. Expected a JWT.")]
    InvalidTokenFormat,

    #[error("Failed to decode header: {0}")]
    HeaderDecodingError(String),

    #[error("Matching key not found in JWKS")]
    KeyNotFound,

    #[error("Failed to create decoding key: {0}")]
    DecodingKeyCreationError(String),

    #[error("Failed to decode token: {0}")]
    TokenDecodingError(String),

    #[error("Token is not from the expected organization")]
    OrganizationMismatch,

    #[error("Token is not from the expected repository")]
    RepositoryMismatch,

    #[error("Failed to fetch JWKS: {0}")]
    JWKSFetchError(String),

    #[error("Failed to parse JWKS: {0}")]
    JWKSParseError(String),

    #[error("Token validation failed: {0}")]
    InvalidTime(#[from] GitHubOIDCClaimsTimeError)
}

#[derive(Error, Debug, PartialEq)]
#[non_exhaustive]
pub enum GitHubOIDCClaimsTimeError {
    #[error("The provided time was invalid")]
    InvalidTime,
    #[error("The token has invalid time constraints")]
    InvalidTimeWindow,
    #[error("The token was issued in the future")]
    TokenIssuedInFuture,
    #[error("The token is not yet valid")]
    TokenNotYetValid,
    #[error("The token has expired")]
    TokenExpired,
}