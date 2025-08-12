use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Clone, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct PublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}
