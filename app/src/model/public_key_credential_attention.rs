use serde::{Deserialize, Serialize};
use serde_bytes;

#[allow(dead_code)]
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct PublicKeyCredentialAttention {
    pub fmt: String,
    #[serde(rename = "authData", with = "serde_bytes")]
    pub auth_data: Vec<u8>,
}
