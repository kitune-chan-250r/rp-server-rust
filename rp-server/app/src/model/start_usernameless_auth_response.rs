use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
#[builder(setter(into))]
pub struct StartUsernamelessAuthResponse {
    pub challenge: String,
    pub timeout: Option<i64>,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}
