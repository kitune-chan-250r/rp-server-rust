use derive_builder::Builder;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicKeyCredentialType {}

#[allow(dead_code)]
impl PublicKeyCredentialType {
    pub const PUBLIC_KEY: &'static str = "public-key";
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct COSEAlgorithmIdentifier {
    // pub value: i32,
}

#[allow(dead_code)]
impl COSEAlgorithmIdentifier {
    pub const RS1: i32 = -65535;
    pub const ES256: i32 = -7;
    pub const RS256: i32 = -257;
    pub const RS384: i32 = -258;
    pub const RS512: i32 = -259;
    pub const ES384: i32 = -35;
    pub const ES512: i32 = -36;
}

#[allow(dead_code)]
#[derive(Debug, Default, Builder, Clone, Serialize, Deserialize)]
#[builder(setter(into))]
pub struct PublicKeyCredentialParameters {
    pub r#type: String,
    pub alg: i32,
}
