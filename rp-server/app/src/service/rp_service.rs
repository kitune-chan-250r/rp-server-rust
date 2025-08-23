use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{CHALLENGE_TIMEOUT_SECONDS, DEFAULT_CHALLENGE_TIMEOUT_SECONDS};
use crate::error::WebAuthnError;
use crate::model::attestation_object::AttestationObject;
use crate::model::authenticator_data::AuthenticatorData;
use crate::model::client_data::ClientData;
use crate::model::collection_auth_challenge::CollectionAuthChallengeBuilder;
use crate::model::collection_challenge::CollectionChallenge;
use crate::model::collection_challenge::CollectionChallengeBuilder;
use crate::model::collection_user_credential::CollectionUserCredential;
use crate::model::collection_user_credential::CollectionUserCredentialBuilder;
use crate::model::fido2_options::Fido2Options;
use crate::model::fido2_options::Fido2OptionsBuilder;
use crate::model::public_key_credential_attention::PublicKeyCredentialAttention;
use crate::model::public_key_credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::model::public_key_credential_creation_options::PublicKeyCredentialCreationOptionsBuilder;
use crate::model::public_key_credential_parameters::COSEAlgorithmIdentifier;
use crate::model::public_key_credential_parameters::PublicKeyCredentialParametersBuilder;
use crate::model::public_key_credential_parameters::PublicKeyCredentialType;
use crate::model::public_key_credential_response::PublicKeyCredential;
use crate::model::public_key_credential_rp_entity::PublicKeyCredentialRpEntityBuilder;
use crate::model::public_key_credential_user_entity::PublicKeyCredentialUserEntityBuilder;
use crate::model::start_usernameless_auth_response::StartUsernamelessAuthResponse;
use crate::model::start_usernameless_auth_response::StartUsernamelessAuthResponseBuilder;
use crate::model::verify_auth_challenge_request::ChallengeRequest;
use crate::model::verify_auth_challenge_request::VerifyAuthChallengeRequest;
use actix_session::Session;
use actix_web::web;
use actix_web::HttpRequest;
use base64::alphabet::URL_SAFE;
use base64::engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use log::info;
use log::log;
use mongodb::bson::doc;
use mongodb::change_stream::session;
use mongodb::Collection;
use p256::ecdsa::signature::Verifier;
use rsa::pkcs1v15;
use rsa::Pkcs1v15Sign;
// Verifierトレイトをインポート
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use serde_json::json;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256, Sha384, Sha512};
use uuid::Uuid;

pub fn hello() -> String {
    return "Hello, world!".to_string();
}

pub fn generate_challenge() -> Uuid {
    let uuid = Uuid::new_v4();
    return uuid;
}

#[allow(dead_code)]
pub async fn create_challenge_options(
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
) -> PublicKeyCredentialCreationOptions {
    let binding = Uuid::new_v4();
    let id = binding.to_string();

    let rp = PublicKeyCredentialRpEntityBuilder::default()
        .id("localhost")
        .name("manji_rp")
        .build()
        .unwrap();

    let param = PublicKeyCredentialParametersBuilder::default()
        .alg(COSEAlgorithmIdentifier::RS256)
        .r#type(PublicKeyCredentialType::PUBLIC_KEY.to_string())
        .build()
        .unwrap();

    let param2 = PublicKeyCredentialParametersBuilder::default()
        .alg(COSEAlgorithmIdentifier::ES256)
        .r#type(PublicKeyCredentialType::PUBLIC_KEY.to_string())
        .build()
        .unwrap();

    let pub_key_credential_params = vec![param, param2];

    let user = PublicKeyCredentialUserEntityBuilder::default()
        .id(id)
        .name("manji@example.com")
        .display_name("manji")
        .build()
        .unwrap();

    let challenge = generate_challenge().to_string();

    let creation_options = PublicKeyCredentialCreationOptionsBuilder::default()
        .rp(rp)
        .user(user)
        .challenge(challenge)
        .pub_key_cred_params(pub_key_credential_params)
        .timeout(Some(5))
        .build()
        .unwrap();

    let challenge_data = CollectionChallengeBuilder::default()
        .pk(creation_options.user.id.clone())
        .sk(creation_options.challenge.clone())
        .options(creation_options.clone())
        .exp(creation_options.timeout.clone())
        .build()
        .unwrap();

    println!("user.id: {}", creation_options.clone().user.id);

    // mongoDbに保存
    let insert_result = challenge_collection
        .insert_one(challenge_data)
        .await
        .expect("insert error");

    log::info!("{:#?}", insert_result);
    return creation_options;
}

// 次にバックエンドに実装するapiの参考
// handleCredentialsResponse
#[allow(dead_code)]
pub async fn verify_response(
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
    user_credential_collection: web::Data<Collection<CollectionUserCredential>>,
    req: HttpRequest,
    public_key_credential: web::Json<PublicKeyCredential>,
) -> Result<String, Box<dyn Error>> {
    // let mut challenge_value: String = String::new();
    // if let Some(challenge_value) = req.headers().get("Challenge") {
    //     // HeaderValueを文字列に変換（失敗する可能性があるのでResultを扱います）
    //     if let Ok(challenge_str) = challenge_value.to_str() {
    //         println!("Challenge header: {}", challenge_str);
    //         // 必要に応じてchallenge_strを利用した処理を実装
    //         // challenge_value = String::from(challenge_str);
    //         let stored_challenge = challenge_collection.find_one(
    //             doc! {"pk": public_key_credential.clone().raw_id, "sk": challenge_str.to_string()},
    //         ).await;
    //     }
    // }

    let challenge_value = req
        .headers()
        .get("Challenge")
        .ok_or("header::Challenge is not found")?
        .to_str()?;

    let user_id = req
        .headers()
        .get("UserId")
        .ok_or("header::UserId is not found")?
        .to_str()?;

    // TODO: 保存されたチャレンジと一致するかの確認が必要？もしかするとsessionに保存したもので検証する必要があるかもしれない

    // println!(
    //     "public key credential2: {}",
    //     public_key_credential.clone().raw_id
    // );
    // clientDataJSONをbase64urlデコードする
    let client_data = deserialize_client_data(public_key_credential.clone().response.client_data);
    info!("client data: {:#?}", client_data);

    // originの検証
    info!(
        "attestationObject: {:#?}",
        public_key_credential
            .clone()
            .response
            .attestation_object
            .trim_matches('\"')
            .to_string()
    );
    // attestationObjectをcborデコードする
    let attestation = deserialize_attestation_object(
        public_key_credential
            .clone()
            .response
            .attestation_object
            .trim_matches('\"')
            .to_string(),
    );
    info!("attestation: {:#?}", attestation);
    // attenstation.authDataをparseAuthenticatorDataでパースしなきゃいけない、本当に面倒な処理

    // attestation.authDataから何出てくるか知らんがパースする
    let auth_data = parse_attestation_object_auth_data_ai_generated(attestation.auth_data);

    let credential_id_string = BASE64_URL_SAFE_NO_PAD.encode(auth_data.credential_id);
    let rp_id_string = BASE64_URL_SAFE_NO_PAD.encode(auth_data.rp_id_hash);

    // 保存用のユーザー認証情報を作成
    let user_credential = CollectionUserCredentialBuilder::default()
        .pk(user_id)
        .sk(&public_key_credential.raw_id)
        .user_id(user_id)
        .jwk(auth_data.credential_public_key)
        .sign_count(auth_data.sign_count)
        .friendly_name("body-kara-get")
        .flag_user_verified(auth_data.flag_user_verified)
        .flag_backup_eligibility(auth_data.flag_backup_eligibility)
        .flag_backup_state(auth_data.flag_backup_state)
        .aaguid(auth_data.aaguid)
        .transports(public_key_credential.clone().response.transports)
        .credential_id(credential_id_string)
        .rp_id(rp_id_string)
        .created_at("currentdateisostring")
        .build()
        .unwrap();

    let insert_result = user_credential_collection
        .insert_one(user_credential)
        .await
        .expect("user_credential insert err.");

    info!("{:#?}", insert_result);

    return Ok(public_key_credential.clone().raw_id);
}

// varidation methods

// originの検証
// clientData.originが許可origin一覧の配列に含まれるかを検証する。

// clientDataのデコード、JSON文字列への変換、デシリアライズ
pub fn deserialize_client_data(client_data: String) -> ClientData {
    let decoded_bytes = BASE64_URL_SAFE_NO_PAD.decode(client_data).unwrap();

    // 2. バイト列をUTF-8文字列に変換
    let json_str = String::from_utf8(decoded_bytes).unwrap();

    // 3. JSON文字列からstructにデシリアライズ
    let client_data: ClientData = serde_json::from_str(&json_str).unwrap();

    return client_data;
}

// attestationObjectをcborデコードする
pub fn deserialize_attestation_object(attestation_object: String) -> PublicKeyCredentialAttention {
    let decoded_bytes = engine::general_purpose::URL_SAFE_NO_PAD.decode(attestation_object);

    match decoded_bytes {
        Ok(bytes) => {
            let decoded_cbor: PublicKeyCredentialAttention =
                serde_cbor::from_slice(&bytes).unwrap();

            return decoded_cbor;
        }
        Err(e) => panic!("Failed to decode attestation object: {}", e),
    }

    // let decoded_cbor: PublicKeyCredentialAttention =
    //     serde_cbor::from_slice(&decoded_bytes).unwrap();

    // return decoded_cbor;
}

// pub fn parse_attestation_object_auth_data(auth_data: Vec<u8>) -> AttestationObject {
//     let rp_id_hash = &auth_data[..32];
//     let flags = &auth_data[32];
//     let flag_user_present = (flags & 0x1) != 0;
//     let flag_reserved_future_use1 = ((flags >> 1) & 0x1) != 0;
//     let flag_user_verified = ((flags >> 2) & 0x1) != 0;
//     let flag_backup_eligibility = ((flags >> 3) & 0x1) != 0;
//     let flag_backup_state = ((flags >> 4) & 0x1) != 0;
//     let flag_reserved_future_use2 = ((flags >> 5) & 0x1) != 0;
//     let flag_attested_credential_data = ((flags >> 6) & 0x1) != 0;
//     let flag_extension_data_included = ((flags >> 7) & 0x1) != 0;
//     let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());
//     let aaguid = &auth_data[37..53];
//     let credential_id_length = u16::from_be_bytes(auth_data[53..55].try_into().unwrap()) as usize;

//     // info!("credential_id_length: {:?}", credential_id_length);
//     if auth_data.len() < 55 + credential_id_length {
//         panic!("Invalid credential ID length");
//     }

//     let credential_id = &auth_data[55..55 + credential_id_length];
//     let credential_public_key = &auth_data[55 + credential_id_length..];

//     // info!("credential_public_key {:?}", credential_public_key);

//     AttestationObject {
//         rp_id_hash: rp_id_hash.to_vec(),
//         flag_user_present,
//         flag_reserved_future_use1,
//         flag_user_verified,
//         flag_backup_eligibility,
//         flag_backup_state,
//         flag_reserved_future_use2,
//         flag_attested_credential_data,
//         flag_extension_data_included,
//         sign_count,
//         aaguid: aaguid.to_vec(),
//         credential_id: credential_id.to_vec(),
//         credential_public_key: decode_credential_puglic_key(credential_public_key.to_vec()),
//     }
// }

pub fn parse_attestation_object_auth_data_ai_generated(auth_data: Vec<u8>) -> AttestationObject {
    // authDataは最低でも rpIdHash (32) + flags (1) + signCount (4) = 37バイト必要
    if auth_data.len() < 37 {
        // return Err("Authenticator data too short".into());
    }

    // 1. 最初の32バイトは rpIdHash
    let rp_id_hash: [u8; 32] = auth_data[0..32].try_into().unwrap();

    // 2. 次の1バイトは flags
    let flags = auth_data[32];

    // 3. その次の4バイトは signCount（ネットワークバイトオーダー：Big Endian）
    let sign_count = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());

    // 4. flagsの特定ビット（例：0x40）が立っていれば attestedCredentialData が含まれている
    let mut offset = 37;
    // let attested_credential_data = if flags & 0x40 != 0 {
    // attestedCredentialData には AAGUID (16バイト) が含まれる
    if auth_data.len() < offset + 16 + 2 {
        // return Err("Attested credential data truncated".into());
    }
    let aaguid: [u8; 16] = auth_data[offset..offset + 16].try_into().unwrap();
    offset += 16;

    // 次の2バイトは credentialId の長さ（uint16, Big Endian）
    let cred_id_len = u16::from_be_bytes(auth_data[offset..offset + 2].try_into().unwrap());
    offset += 2;

    // credentialId のバイト列を抽出
    if auth_data.len() < offset + (cred_id_len as usize) {
        // return Err("Credential ID truncated".into());
    }
    let credential_id = auth_data[offset..offset + (cred_id_len as usize)].to_vec();
    offset += cred_id_len as usize;

    // 残りの部分は credentialPublicKey のCBORエンコードされたデータである
    let credential_public_key_slice = &auth_data[offset..];
    // let credential_public_key: Value = serde_cbor::from_slice(credential_public_key_slice)?;

    let flag_user_present = (flags & 0x1) != 0;
    let flag_reserved_future_use1 = ((flags >> 1) & 0x1) != 0;
    let flag_user_verified = ((flags >> 2) & 0x1) != 0;
    let flag_backup_eligibility = ((flags >> 3) & 0x1) != 0;
    let flag_backup_state = ((flags >> 4) & 0x1) != 0;
    let flag_reserved_future_use2 = ((flags >> 5) & 0x1) != 0;
    let flag_attested_credential_data = ((flags >> 6) & 0x1) != 0;
    let flag_extension_data_included = ((flags >> 7) & 0x1) != 0;

    // Some(AttestationObject {
    //     rp_id_hash: rp_id_hash.to_vec(),
    //     flag_user_present,
    //     flag_reserved_future_use1,
    //     flag_user_verified,
    //     flag_backup_eligibility,
    //     flag_backup_state,
    //     flag_reserved_future_use2,
    //     flag_attested_credential_data,
    //     flag_extension_data_included,
    //     sign_count,
    //     aaguid: aaguid.to_vec(),
    //     credential_id: credential_id.to_vec(),
    //     credential_public_key: credential_public_key_slice.to_vec(),
    // })
    // } else {
    //     None
    // };

    AttestationObject {
        rp_id_hash: rp_id_hash.to_vec(),
        flag_user_present,
        flag_reserved_future_use1,
        flag_user_verified,
        flag_backup_eligibility,
        flag_backup_state,
        flag_reserved_future_use2,
        flag_attested_credential_data,
        flag_extension_data_included,
        sign_count,
        aaguid: aaguid.to_vec(),
        credential_id: credential_id.to_vec(),
        credential_public_key: decode_credential_puglic_key(credential_public_key_slice.to_vec()),
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
enum PublicKeyValue {
    Integer(i32),
    // CBORのBytesはVec<u8>としてデコードされるため、ここではVec<u8>としています。
    Bytes(Vec<u8>),
}

pub fn decode_credential_puglic_key(credential_public_key: Vec<u8>) -> serde_json::Value {
    // 1. CBORバイト列をserde_cbor::Valueとしてデコードする
    let cbor_value: serde_cbor::Value = serde_cbor::from_slice(&credential_public_key).unwrap();
    // 2. デコード結果がマップ形式であることを確認
    let map = match cbor_value {
        serde_cbor::Value::Map(m) => m,
        _ => panic!("CBORバイト列はマップ形式である必要があります"),
    };
    // 3. COSEキーのパラメータは整数キーで格納されているため、HashMap<i64, &serde_cbor::Value>に変換する
    let mut cose_params = HashMap::new();
    for (key, value) in &map {
        if let serde_cbor::Value::Integer(n) = key {
            cose_params.insert(*n, value);
        }
    }

    // 4. オプションのkid（キー識別子）をキー "2" から抽出する
    //    kidは、複数の認証器が存在する場合に各公開鍵を一意に識別するためのヒントとして利用されると推測される
    let kid = match cose_params.get(&2) {
        Some(serde_cbor::Value::Text(s)) => Some(s.clone()),
        Some(serde_cbor::Value::Bytes(b)) => Some(String::from_utf8(b.clone()).unwrap()),
        _ => None,
    };

    // 5. kty (キータイプ)を抽出（2: EC, 3: RSA）
    let kty = match cose_params.get(&1) {
        Some(serde_cbor::Value::Integer(n)) => *n,
        _ => return panic!("ktyは整数キーで格納されている必要があります"),
    };

    // 6. alg (アルゴリズム)を抽出
    let alg = match cose_params.get(&3) {
        Some(serde_cbor::Value::Integer(n)) => *n,
        _ => return panic!("algは整数キーで格納されている必要があります"),
    };

    match kty {
        2 => {
            // EC2の場合
            // 6. crv (楕円曲線)を抽出
            let crv = match cose_params.get(&-1) {
                Some(serde_cbor::Value::Integer(n)) => *n,
                _ => return panic!("crvは整数キーで格納されている必要があります"),
            };

            // 7. x座標を抽出（バイト列として格納されているはず）
            let x = match cose_params.get(&-2) {
                Some(serde_cbor::Value::Bytes(b)) => b,
                _ => return panic!("Missing or invalid  'x' parameter"),
            };

            // 8. y座標を抽出（バイト列として格納されているはず）
            let y = match cose_params.get(&-3) {
                Some(serde_cbor::Value::Bytes(b)) => b,
                _ => return panic!("Missing or invalid   'y' parameter"),
            };

            // 9. COSEで定義される楕円曲線の識別子をJWKで用いる曲線名に変換する
            //    (例: 1 -> "P-256", 2 -> "P-384", 3 -> "P-521")
            let crv_name = match crv {
                1 => "P-256",
                2 => "P-384",
                3 => "P-521",
                _ => return panic!("Unsupported curve: {}", crv),
            };

            // 10. COSEアルゴリズム識別子をJWKのalgに対応する値に変換する
            //     (例: -7 -> "ES256", -35 -> "ES384", -36 -> "ES512")
            let alg_name = match alg {
                -7 => "ES256",
                -35 => "ES384",
                -36 => "ES512",
                _ => return panic!("Unsupported algorithm: {}", alg),
            };

            // 11. x, y座標をBase64URLエンコードする（パディングなし）
            let x_b64 = BASE64_URL_SAFE_NO_PAD.encode(x);
            let y_b64 = BASE64_URL_SAFE_NO_PAD.encode(y);

            let mut jwk = json!({
                "kty": "EC",
                "alg": alg_name,
                "crv": crv_name,
                "x": x_b64.as_str(),
                "y": y_b64.as_str()
            });
            if let Some(kid_value) = kid {
                jwk["kid"] = serde_json::Value::String(kid_value);
            }
            info!("{:?}", jwk);
            return jwk;
        }
        3 => {
            // RSAの場合
            // n (モジュラス)を抽出
            let n = match cose_params.get(&-1) {
                Some(Value::Bytes(b)) => b,
                _ => return panic!("Missing or invalid  'n' parameter"),
            };

            // e (公開指数)を抽出
            let e = match cose_params.get(&-2) {
                Some(Value::Bytes(b)) => b,
                _ => return panic!("Missing or invalid   'e' parameter"),
            };

            // アルゴリズム識別子をJWKのalgに変換
            let alg_name = match alg {
                -257 => "RS256",
                -258 => "RS384",
                -259 => "RS512",
                _ => return panic!("Invalid alg value"),
            };

            // n, eをBase64URLエンコード
            let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(n);
            let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(e);

            // JWKオブジェクトを生成
            let mut jwk = json!({
                "kty": "RSA",
                "alg": alg_name,
                "n": n_b64,
                "e": e_b64,
            });
            if let Some(kid_value) = kid {
                jwk["kid"] = serde_json::Value::String(kid_value);
            }
            info!("{:?}", jwk);
            return jwk;
        }
        _ => {
            panic!("ktyが予期された値から外れています")
        }
    }
}

// {
//     "authenticatorAttachment": "platform",
//     "clientExtensionResults": {},
//     "id": "1ICsqXgZJs18fR6VtEry4sJtWC-giwRJ6bqsc46ccns",
//     "rawId": "1ICsqXgZJs18fR6VtEry4sJtWC-giwRJ6bqsc46ccns",
//     "response": {
//       "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACDUgKypeBkmzXx9HpW0SvLiwm1YL6CLBEnpuqxzjpxye6QBAwM5AQAgWQEA3I4vbF0ontT8EtCYUNLDjPsyv4liVvh6FzF9TlcTml8eVEcv-5Dple8Njz11f-BHZPjGjHjQhSqXtyo0bMEuD9nQvbGD7TOTkgLG3kPPdHVtoSXNLy85Ik2-J1nDCGOn_n3Uu6-EED2pIKCIfUoZx--dzvQBhtHCFy-HonTqfAYn4wajQIpYvjk_iItWxtR-cmm5afr9M7DMy-7kHEzlOETLn-WUcW8qrkFt1uVRXCVacYWg3yz7EV5y4nM9Q_VslWUji57CRxxvt5ogxpHWSqnv_k6Z61Wean8JZDsed9UhKYXLAWkgNScni-9YYJKL953o5iMezfCrsGFFNmtrXyFDAQAB",
//       "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAINSArKl4GSbNfH0elbRK8uLCbVgvoIsESem6rHOOnHJ7pAEDAzkBACBZAQDcji9sXSie1PwS0JhQ0sOM-zK_iWJW-HoXMX1OVxOaXx5URy_7kOmV7w2PPXV_4Edk-MaMeNCFKpe3KjRswS4P2dC9sYPtM5OSAsbeQ890dW2hJc0vLzkiTb4nWcMIY6f-fdS7r4QQPakgoIh9ShnH753O9AGG0cIXL4eidOp8BifjBqNAili-OT-Ii1bG1H5yablp-v0zsMzL7uQcTOU4RMuf5ZRxbyquQW3W5VFcJVpxhaDfLPsRXnLicz1D9WyVZSOLnsJHHG-3miDGkdZKqe_-TpnrVZ5qfwlkOx531SEphcsBaSA1JyeL71hgkov3nejmIx7N8KuwYUU2a2tfIUMBAAE",
//       "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYmY4NWU0OTAtZDY2YS00ODM4LWJiNzUtMWI4OGIxYjJmZjhmIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo1MTczIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
//       "publicKey": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3I4vbF0ontT8EtCYUNLDjPsyv4liVvh6FzF9TlcTml8eVEcv-5Dple8Njz11f-BHZPjGjHjQhSqXtyo0bMEuD9nQvbGD7TOTkgLG3kPPdHVtoSXNLy85Ik2-J1nDCGOn_n3Uu6-EED2pIKCIfUoZx--dzvQBhtHCFy-HonTqfAYn4wajQIpYvjk_iItWxtR-cmm5afr9M7DMy-7kHEzlOETLn-WUcW8qrkFt1uVRXCVacYWg3yz7EV5y4nM9Q_VslWUji57CRxxvt5ogxpHWSqnv_k6Z61Wean8JZDsed9UhKYXLAWkgNScni-9YYJKL953o5iMezfCrsGFFNmtrXwIDAQAB",
//       "publicKeyAlgorithm": -257,
//       "transports": [
//         "internal"
//       ]
//     },
//     "type": "public-key"
//   }

// 認証チャレンジを作成し、永続化とフロントへ返す
pub async fn start_usernameless_authenticate(
    session: Session,
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
) -> Result<StartUsernamelessAuthResponse, Box<dyn Error>> {
    // チャレンジの文字列を作成
    let challenge = generate_challenge().to_string();
    let user_verification = String::from("preferred"); // `required` | `preferred` | `discouraged`
    let timeout = Some(DEFAULT_CHALLENGE_TIMEOUT_SECONDS);

    // チャレンジの有効期限を設定（現在のUNIX時間 + タイムアウト秒数）
    let exp_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + CHALLENGE_TIMEOUT_SECONDS;

    let auth_challenge = CollectionChallengeBuilder::default()
        .pk(challenge.clone())
        .sk("USERNAMELESS_SIGN_IN")
        .exp(Some(exp_time))
        .build()?;

    // 永続化
    let result = challenge_collection.insert_one(auth_challenge).await;

    // セッションにも保存(verifyで利用する)
    let fido2_options = Fido2OptionsBuilder::default()
        .challenge(challenge.clone())
        .user_verification(user_verification.clone())
        .relying_party_id("localhost".to_string())
        .timeout(Some(CHALLENGE_TIMEOUT_SECONDS))
        .build()?;
    session.insert("fido2Options", fido2_options)?;

    match result {
        Ok(_) => info!("Challenge saved successfully"),
        Err(e) => return Err(Box::new(e)),
    }

    let response = StartUsernamelessAuthResponseBuilder::default()
        .challenge(challenge)
        .timeout(timeout)
        .user_verification(user_verification)
        .build()?;

    Ok(response)
}

/**
 * フロントで署名されて戻ってきた認証情報を検証する
 *
 * ここで一つでもエラーが発生すれば認証エラーとなる
 * custom-auth/fido2.ts::verifyChallenge()
 */
pub async fn verify_challenge(
    session: Session,
    answer: web::Json<ChallengeRequest>,
    user_credential_collection: web::Data<Collection<CollectionUserCredential>>,
) -> Result<u32, Box<dyn Error>> {
    info!("Received answer: {:#?}", answer);
    // MongoDBからuser_handleを元に認証情報を取得する この処理でuser_handleの検証とみなす
    let stored_credential =
        get_stored_credential(&answer.user_handle_b64, &user_credential_collection).await?;

    // credentialIdの検証
    credential_id_verifier(&answer.credential_id_b64, &stored_credential.credential_id)?;

    // client data jsonをシリアライズ
    let client_data_json = BASE64_URL_SAFE_NO_PAD.decode(&answer.client_data_json_b64)?;
    let client_data: ClientData = serde_json::from_slice(&client_data_json)?;

    // セッションに保存されたチャレンジを取得
    let expected_challenge = session
        .get::<Fido2Options>("fido2Options")?
        .ok_or(WebAuthnError::InvalidChallenge)?;

    // チャレンジの有効期限チェック
    // let current_time = SystemTime::now()
    //     .duration_since(UNIX_EPOCH)
    //     .unwrap()
    //     .as_secs() as i64;

    // if current_time
    //     > expected_challenge
    //         .timeout
    //         .unwrap_or(DEFAULT_CHALLENGE_TIMEOUT_SECONDS)
    // {
    //     return Err(Box::new(WebAuthnError::ExpiredChallenge));
    // }

    info!("Expected challenge: {:#?}", expected_challenge);
    // チャレンジの検証
    challenge_verifier(&client_data.challenge, &expected_challenge.challenge)?;

    // originの検証
    origin_verifier(&client_data.origin)?;

    // typeの検証
    type_verifier(&client_data.r#type)?;

    // authenticator dataのパース
    let authenticator_data = parse_authenticator_data(&answer.authenticator_data_b64)?;

    // rpIdHashの検証
    rp_id_hash_verifier(&authenticator_data.rp_id_hash, &stored_credential.rp_id)?;

    // user presentフラグの検証
    if !authenticator_data.flag_user_present {
        return Err(Box::new(WebAuthnError::UserNotPresent));
    }

    // signCountの検証（リプレイ攻撃対策）
    sign_count_verifier(authenticator_data.sign_count, stored_credential.sign_count)?;

    // 署名の検証
    signature_verifyer(
        stored_credential.jwk.clone(),
        &answer.signature_b64,
        &answer.authenticator_data_b64,
        &answer.client_data_json_b64,
    )?;

    info!("All verifications passed successfully");
    // 全ての検証が成功した場合、新しいsign_countを返す
    Ok(authenticator_data.sign_count)
}

/**
 * mongoDBからユーザー認証情報を取得する
 */
async fn get_stored_credential(
    user_handle: &str,
    user_credential_collection: &Collection<CollectionUserCredential>,
) -> Result<CollectionUserCredential, Box<dyn Error>> {
    let filter = doc! {"pk": user_handle};
    let credential = user_credential_collection
        .find_one(filter)
        .await?
        .ok_or(WebAuthnError::CredentialNotFound)?;
    Ok(credential)
}

// credential_idの検証
fn credential_id_verifier(
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

// challengeの検証
fn challenge_verifier(
    challenge: &String,
    expected_challenge: &String,
) -> Result<(), Box<dyn Error>> {
    if challenge.eq(expected_challenge) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidChallenge))
    }
}

// originの検証
fn origin_verifier(origin: &String) -> Result<(), Box<dyn Error>> {
    let allowed_origins = vec!["http://localhost:5173", "http://example.com"];

    if allowed_origins.contains(&origin.as_str()) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidOrigin {
            origin: origin.clone(),
        }))
    }
}

fn type_verifier(type_field: &String) -> Result<(), Box<dyn Error>> {
    let allowed_type = "webauthn.get";
    if type_field.eq(allowed_type) {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::InvalidType))
    }
}

fn parse_authenticator_data(
    authenticator_data_b64: &String,
) -> Result<AuthenticatorData, Box<dyn Error>> {
    // 認証器データのパース処理を実装
    // ここでは、rpIdHash、flags、signCountなどを抽出する認証器データの形式に応じて必要な情報を抽出する
    let authenticator_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(authenticator_data_b64)?;

    // Authenticator Dataの最小長は37バイト (RP ID Hash 32 + Flags 1 + Sign Count 4)
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

// rpIdHashの検証を行う
fn rp_id_hash_verifier(rp_id_hash: &Vec<u8>, stored_rp_id: &String) -> Result<(), Box<dyn Error>> {
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

// signCountの検証を行う
fn sign_count_verifier(sign_count: u32, stored_sign_count: u32) -> Result<(), Box<dyn Error>> {
    if sign_count > stored_sign_count {
        Ok(())
    } else {
        Err(Box::new(WebAuthnError::ReplayAttack {
            current: sign_count,
            previous: stored_sign_count,
        }))
    }
}

// 署名の検証
fn signature_verifyer(
    jwk: serde_json::Value,
    signature_b64: &str,
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
) -> Result<(), Box<dyn Error>> {
    // JWKのktyを取得
    let kty = jwk["kty"].as_str().ok_or("Missing kty")?;

    // 1. 署名とデータのデコード
    let signature_byte = BASE64_URL_SAFE_NO_PAD.decode(signature_b64)?;
    let authenticator_data = BASE64_URL_SAFE_NO_PAD.decode(authenticator_data_b64)?;
    let client_data_json = BASE64_URL_SAFE_NO_PAD.decode(client_data_json_b64)?;

    // 2. 検証対象メッセージの生成
    // authenticatorData || sha256(clientDataJSON)
    let mut hasher = Sha256::new();
    hasher.update(&client_data_json);
    let client_data_hash = hasher.finalize();

    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(&authenticator_data);
    verification_data.extend_from_slice(&client_data_hash);

    match kty {
        "EC" => {
            // ECDSA検証
            // x, y座標を取得
            let x_b64 = jwk["x"].as_str().ok_or("Missing x coordinate")?;
            let y_b64 = jwk["y"].as_str().ok_or("Missing y coordinate")?;

            // Base64デコード
            let x_coord = BASE64_URL_SAFE_NO_PAD.decode(x_b64)?;
            let y_coord = BASE64_URL_SAFE_NO_PAD.decode(y_b64)?;

            // signature_verifyerメソッド内の該当部分を修正
            let x_array = GenericArray::clone_from_slice(&x_coord);
            let y_array = GenericArray::clone_from_slice(&y_coord);

            let encoded_point =
                p256::EncodedPoint::from_affine_coordinates(&x_array, &y_array, false);

            let verifying_key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;

            // 署名をSignature型に変換
            let signature_array = GenericArray::from_slice(&signature_byte);
            let signature = p256::ecdsa::Signature::from_bytes(signature_array)?;

            // 署名検証
            verifying_key.verify(&verification_data, &signature)?;
        }
        "RSA" => {
            // RSA検証
            // モジュラスと公開指数を取得
            let n_b64 = jwk["n"].as_str().ok_or("Missing modulus")?;
            let e_b64 = jwk["e"].as_str().ok_or("Missing exponent")?;

            // Base64デコード
            let n = BASE64_URL_SAFE_NO_PAD.decode(n_b64)?;
            let e = BASE64_URL_SAFE_NO_PAD.decode(e_b64)?;
            let alg = jwk["alg"].as_str().ok_or("Missing algorithm (alg)")?;

            // RSA公開キーを作成
            let public_key = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n),
                rsa::BigUint::from_bytes_be(&e),
            )?;

            // 4. アルゴリズムに基づいてハッシュ関数を選択
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
                _ => return Err("Unsupported RSA algorithm".into()),
            };

            // 5. 署名スキームを設定し検証を実行
            let padding_scheme = match alg {
                "RS256" => Pkcs1v15Sign::new::<Sha256>(),
                "RS384" => Pkcs1v15Sign::new::<Sha384>(),
                "RS512" => Pkcs1v15Sign::new::<Sha512>(),
                _ => return Err("Unsupported RSA algorithm".into()),
            };

            // 署名検証
            // public_key.verify(&hashed_msg, &signature)?;
            public_key.verify(padding_scheme, &hashed_msg, &signature_byte)?;
        }
        _ => return Err("Unsupported key type".into()),
    }
    Ok(())
}
