use crate::model::public_key_credential_parameters;
use crate::model::public_key_credential_rp_entity;
use crate::model::public_key_credential_user_entity;
use derive_builder::Builder;
use serde::Deserialize;
use serde::Serialize;

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Serialize, Deserialize, Clone)]
#[builder(setter(into))]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: public_key_credential_rp_entity::PublicKeyCredentialRpEntity,
    pub user: public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    pub challenge: String,
    pub timeout: Option<i64>,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<public_key_credential_parameters::PublicKeyCredentialParameters>,
}
