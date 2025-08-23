// Challenge Management
pub const CHALLENGE_TIMEOUT_SECONDS: i64 = 300; // 5分
pub const DEFAULT_CHALLENGE_TIMEOUT_SECONDS: i64 = 60; // 1分

// WebAuthn Configuration
pub const ALLOWED_ORIGINS: [&str; 2] = ["http://localhost:5173", "http://example.com"];
pub const WEBAUTHN_GET_TYPE: &str = "webauthn.get";
pub const WEBAUTHN_CREATE_TYPE: &str = "webauthn.create";

// FIDO2 User Verification Settings
pub const UV_REQUIRED: &str = "required";
pub const UV_PREFERRED: &str = "preferred";
pub const UV_DISCOURAGED: &str = "discouraged";

// Response Codes
pub const SUCCESS_STATUS: &str = "0";
pub const ERROR_STATUS: &str = "1";

// MongoDB Collection Names
pub const CHALLENGE_COLLECTION: &str = "challenges";
pub const USER_CREDENTIAL_COLLECTION: &str = "user_credentials";

// Security Settings
pub const MIN_AUTHENTICATOR_DATA_LENGTH: usize = 37; // rpIdHash(32) + flags(1) + signCount(4)
pub const MIN_CREDENTIAL_ID_LENGTH: usize = 16;
pub const MAX_CREDENTIAL_ID_LENGTH: usize = 1023;
