use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
#[builder(setter(into))]
pub struct CollectionUserCredential {
    pub pk: String, // user uuid
    pub sk: String, // credential id
    pub user_id: String,
    pub credential_id: String,
    pub jwk: serde_json::Value,
    pub sign_count: u32,
    pub friendly_name: String,
    pub flag_user_verified: bool,
    pub flag_backup_eligibility: bool,
    pub flag_backup_state: bool,
    pub aaguid: Vec<u8>,
    pub transports: Vec<String>,
    pub rp_id: String,
    pub created_at: String,
}
