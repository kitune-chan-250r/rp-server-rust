use derive_builder::Builder;
use serde::{Deserialize, Serialize};

use crate::model::public_key_credential_creation_options::PublicKeyCredentialCreationOptions;

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
#[builder(setter(into))]
pub struct CollectionChallenge {
    pub pk: String, // user uuid
    pub sk: String, // challenge
    #[builder(default)]
    pub options: PublicKeyCredentialCreationOptions,
    pub exp: Option<i64>,
}
