use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Serialize, Clone, Deserialize)]
#[builder(setter(into))]
pub struct CollectionAuthChallenge {
    pub pk: String, // user uuid
    pub sk: String, // challenge
    pub exp: Option<i64>,
}
