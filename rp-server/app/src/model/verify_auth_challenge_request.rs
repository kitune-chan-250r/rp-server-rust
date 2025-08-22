use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
pub struct ChallengeRequest {
    #[serde(rename = "credentialIdB64")]
    pub credential_id_b64: String,
    #[serde(rename = "authenticatorDataB64")]
    pub authenticator_data_b64: String,
    #[serde(rename = "clientDataJSON_B64")]
    pub client_data_json_b64: String,
    #[serde(rename = "signatureB64")]
    pub signature_b64: String,
    #[serde(rename = "userHandleB64")]
    pub user_handle_b64: String,
}

#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
pub struct VerifyAuthChallengeRequest {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub challenge: ChallengeRequest,
}
