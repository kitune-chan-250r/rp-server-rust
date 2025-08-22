use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Clone, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct PublicKeyCredentialRpEntity {
    pub id: String,
    pub name: String,
}
