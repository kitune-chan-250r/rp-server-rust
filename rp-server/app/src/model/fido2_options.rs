use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
pub struct Fido2Options {
    #[serde(rename = "relyingPartyId")]
    relying_party_id: String,
    challenge: String,
    user_verification: String,
    timeout: Option<i64>,
}
