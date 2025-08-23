pub struct AuthenticatorData {
    pub rp_id_hash: Vec<u8>, // In the original TypeScript, this is base64url encoded.
    pub flag_user_present: bool,
    pub flag_reserved_future_use1: bool,
    pub flag_user_verified: bool,
    pub flag_backup_eligibility: u8,
    pub flag_backup_state: u8,
    pub flag_reserved_future_use2: bool,
    pub flag_attested_credential_data: bool,
    pub flag_extension_data_included: bool,
    pub sign_count: u32,
}
