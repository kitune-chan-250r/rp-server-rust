use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub struct AttestationObject {
    pub rp_id_hash: Vec<u8>,
    pub flag_user_present: bool,
    pub flag_reserved_future_use1: bool,
    pub flag_user_verified: bool,
    pub flag_backup_eligibility: bool,
    pub flag_backup_state: bool,
    pub flag_reserved_future_use2: bool,
    pub flag_attested_credential_data: bool,
    pub flag_extension_data_included: bool,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub credential_public_key: serde_json::Value,
}
