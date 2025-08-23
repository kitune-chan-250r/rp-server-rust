use std::error::Error;

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use rsa::pkcs1v15::Pkcs1v15Sign;
use serde_json::Value;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::constants::ALLOWED_ORIGINS;
use crate::constants::WEBAUTHN_GET_TYPE;
use crate::error::WebAuthnError;
use crate::model::authenticator_data::AuthenticatorData;

pub fn verify_credential_id(
    credential_id_b64: &str,
    stored_credential_id: &str,
) -> Result<(), Box<dyn Error>> {
    let decoded_credential = BASE64_URL_SAFE_NO_PAD.decode(credential_id_b64)?;
    let decoded_stored = BASE64_URL_SAFE_NO_PAD.decode(stored_credential_id)?;

    if decoded_credential.eq(&decoded_stored).into() {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidCredentialId))
    }
}

pub fn verify_challenge(
    challenge: &String,
    expected_challenge: &String,
) -> Result<(), Box<dyn Error>> {
    if challenge.eq(expected_challenge) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidChallenge))
    }
}

pub fn verify_origin(origin: &String) -> Result<(), Box<dyn Error>> {
    if ALLOWED_ORIGINS.contains(&origin.as_str()) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidOrigin {
            origin: origin.clone(),
        }))
    }
}

pub fn verify_type(type_field: &String) -> Result<(), Box<dyn Error>> {
    if type_field.eq(WEBAUTHN_GET_TYPE) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidType))
    }
}

pub fn verify_rp_id_hash(
    rp_id_hash: &Vec<u8>,
    stored_rp_id: &String,
) -> Result<(), Box<dyn Error>> {
    let expected_rp_id_hash = Sha256::digest(stored_rp_id.as_bytes());

    if rp_id_hash == expected_rp_id_hash.as_slice() {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidRpIdHash {
            expected: expected_rp_id_hash.to_vec(),
            got: rp_id_hash.clone(),
        }))
    }
}

pub fn verify_sign_count(sign_count: u32, stored_sign_count: u32) -> Result<(), Box<dyn Error>> {
    if sign_count > stored_sign_count {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::ReplayAttack {
            current: sign_count,
            previous: stored_sign_count,
        }))
    }
}

pub fn verify_authenticator_data(
    authenticator_data_b64: &String,
) -> Result<AuthenticatorData, Box<dyn Error>> {
    let authenticator_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(authenticator_data_b64)?;

    if authenticator_data_bytes.len() < 37 {
        return Err("Authenticator data is too short".to_string().into());
    }

    let rp_id_hash = authenticator_data_bytes[0..32].to_vec();

    let flags = authenticator_data_bytes[32];
    let flag_user_present = (flags & 0b1) != 0;
    let flag_reserved_future_use1 = ((flags >> 1) & 0b1) != 0;
    let flag_user_verified = ((flags >> 2) & 0b1) != 0;
    let flag_backup_eligibility = ((flags >> 3) & 0b1) as u8;
    let flag_backup_state = ((flags >> 4) & 0b1) as u8;
    let flag_reserved_future_use2 = ((flags >> 5) & 0b1) != 0;
    let flag_attested_credential_data = ((flags >> 6) & 0b1) != 0;
    let flag_extension_data_included = ((flags >> 7) & 0b1) != 0;

    let sign_count_bytes: [u8; 4] = authenticator_data_bytes[33..37]
        .try_into()
        .map_err(|_| "Failed to convert sign_count bytes to array".to_string())?;
    let sign_count = u32::from_be_bytes(sign_count_bytes);

    Ok(AuthenticatorData {
        rp_id_hash,
        flag_user_present,
        flag_reserved_future_use1,
        flag_user_verified,
        flag_backup_eligibility,
        flag_backup_state,
        flag_reserved_future_use2,
        flag_attested_credential_data,
        flag_extension_data_included,
        sign_count,
    })
}

pub fn verify_signature(
    jwk: Value,
    signature_b64: &str,
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
) -> Result<(), Box<dyn Error>> {
    let kty = jwk["kty"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("kty".to_string()))?;

    let signature_byte = BASE64_URL_SAFE_NO_PAD.decode(signature_b64)?;
    let authenticator_data = BASE64_URL_SAFE_NO_PAD.decode(authenticator_data_b64)?;
    let client_data_json = BASE64_URL_SAFE_NO_PAD.decode(client_data_json_b64)?;

    let mut hasher = Sha256::new();
    hasher.update(&client_data_json);
    let client_data_hash = hasher.finalize();

    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&authenticator_data);
    verification_data.extend_from_slice(&client_data_hash);

    match kty {
        "EC" => verify_ecdsa_signature(&jwk, &signature_byte, &verification_data)?,
        "RSA" => verify_rsa_signature(&jwk, &signature_byte, &verification_data)?,
        _ => {
            return Err(Box::new(WebAuthnError::UnsupportedAlgorithm(
                kty.to_string(),
            )))
        }
    }

    Ok(())
}

fn verify_ecdsa_signature(
    jwk: &Value,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let x_b64 = jwk["x"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("x".to_string()))?;
    let y_b64 = jwk["y"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("y".to_string()))?;

    let x_coord = BASE64_URL_SAFE_NO_PAD.decode(x_b64)?;
    let y_coord = BASE64_URL_SAFE_NO_PAD.decode(y_b64)?;

    let x_array = GenericArray::clone_from_slice(&x_coord);
    let y_array = GenericArray::clone_from_slice(&y_coord);

    let encoded_point = p256::EncodedPoint::from_affine_coordinates(&x_array, &y_array, false);
    let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;

    let signature_array = GenericArray::from_slice(signature);
    let signature = p256::ecdsa::Signature::from_bytes(signature_array)?;

    verifying_key.verify(verification_data, &signature)?;
    Ok(())
}

fn verify_rsa_signature(
    jwk: &Value,
    signature: &[u8],
    verification_data: &[u8],
) -> Result<(), Box<dyn Error>> {
    let n_b64 = jwk["n"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("n".to_string()))?;
    let e_b64 = jwk["e"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("e".to_string()))?;
    let alg = jwk["alg"]
        .as_str()
        .ok_or(WebAuthnError::MissingParameter("alg".to_string()))?;

    let n = BASE64_URL_SAFE_NO_PAD.decode(n_b64)?;
    let e = BASE64_URL_SAFE_NO_PAD.decode(e_b64)?;

    let public_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(&n),
        rsa::BigUint::from_bytes_be(&e),
    )?;

    let hashed_msg = match alg {
        "RS256" => {
            let mut hasher = Sha256::new();
            hasher.update(verification_data);
            hasher.finalize().to_vec()
        }
        "RS384" => {
            let mut hasher = Sha384::new();
            hasher.update(verification_data);
            hasher.finalize().to_vec()
        }
        "RS512" => {
            let mut hasher = Sha512::new();
            hasher.update(verification_data);
            hasher.finalize().to_vec()
        }
        _ => {
            return Err(Box::new(WebAuthnError::UnsupportedAlgorithm(
                alg.to_string(),
            )))
        }
    };

    let padding_scheme = match alg {
        "RS256" => Pkcs1v15Sign::new::<Sha256>(),
        "RS384" => Pkcs1v15Sign::new::<Sha384>(),
        "RS512" => Pkcs1v15Sign::new::<Sha512>(),
        _ => {
            return Err(Box::new(WebAuthnError::UnsupportedAlgorithm(
                alg.to_string(),
            )))
        }
    };

    public_key.verify(padding_scheme, &hashed_msg, signature)?;
    Ok(())
}
