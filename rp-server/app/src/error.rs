use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
pub enum WebAuthnError {
    InvalidRpIdHash { expected: Vec<u8>, got: Vec<u8> },
    InvalidSignature,
    InvalidChallenge,
    ExpiredChallenge,
    ReplayAttack { current: u32, previous: u32 },
    CredentialNotFound,
    InvalidCredentialId,
    InvalidType,
    InvalidOrigin { origin: String },
    UserNotPresent,
    ParseError(String),
    DatabaseError(String),
    InvalidFormat(String),
    UnsupportedAlgorithm(String),
    MissingParameter(String),
}

impl Display for WebAuthnError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            WebAuthnError::InvalidRpIdHash { expected, got } => {
                write!(
                    f,
                    "rpIdHash does not match. Expected: {:?}, Got: {:?}",
                    expected, got
                )
            }
            WebAuthnError::InvalidSignature => write!(f, "Invalid signature"),
            WebAuthnError::InvalidChallenge => write!(f, "Challenge does not match"),
            WebAuthnError::ExpiredChallenge => write!(f, "Challenge has expired"),
            WebAuthnError::ReplayAttack { current, previous } => write!(
                f,
                "Potential replay attack detected. Current sign count: {}, Previous: {}",
                current, previous
            ),
            WebAuthnError::CredentialNotFound => write!(f, "Credential not found"),
            WebAuthnError::InvalidCredentialId => write!(f, "Credential ID does not match"),
            WebAuthnError::InvalidType => write!(f, "Invalid assertion type"),
            WebAuthnError::InvalidOrigin { origin } => {
                write!(f, "Origin '{}' is not in the allowed list", origin)
            }
            WebAuthnError::UserNotPresent => write!(f, "User is not present"),
            WebAuthnError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            WebAuthnError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            WebAuthnError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            WebAuthnError::UnsupportedAlgorithm(alg) => {
                write!(f, "Unsupported algorithm: {}", alg)
            }
            WebAuthnError::MissingParameter(param) => write!(f, "Missing parameter: {}", param),
        }
    }
}

impl Error for WebAuthnError {}
