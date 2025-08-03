use serde::{Deserialize, Serialize};

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential {
    #[serde(rename = "rawId")]
    pub raw_id: String,
    pub r#type: String,
    pub response: Response,
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Response {
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(rename = "clientData")]
    pub client_data: String,
    pub transports: Vec<String>,
}
