use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
pub struct Fido2Options {
    #[serde(rename = "relyingPartyId")]
    pub relying_party_id: String,
    pub challenge: String,
    pub user_verification: String,
    pub timeout: Option<i64>,
}
