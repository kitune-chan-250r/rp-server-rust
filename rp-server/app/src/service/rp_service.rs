use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;

use crate::model::attestation_object::AttestationObject;
use crate::model::client_data::ClientData;
use crate::model::collection_challenge::CollectionChallenge;
use crate::model::collection_challenge::CollectionChallengeBuilder;
use crate::model::collection_user_credential::CollectionUserCredential;
use crate::model::collection_user_credential::CollectionUserCredentialBuilder;
use crate::model::public_key_credential_attention::PublicKeyCredentialAttention;
use crate::model::public_key_credential_creation_options::PublicKeyCredentialCreationOptions;
use crate::model::public_key_credential_creation_options::PublicKeyCredentialCreationOptionsBuilder;
use crate::model::public_key_credential_parameters::COSEAlgorithmIdentifier;
use crate::model::public_key_credential_parameters::PublicKeyCredentialParametersBuilder;
use crate::model::public_key_credential_parameters::PublicKeyCredentialType;
use crate::model::public_key_credential_response::PublicKeyCredential;
use crate::model::public_key_credential_rp_entity::PublicKeyCredentialRpEntityBuilder;
use crate::model::public_key_credential_user_entity::PublicKeyCredentialUserEntityBuilder;
use actix_web::web;
use actix_web::HttpRequest;
use base64::alphabet::URL_SAFE;
use base64::engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use log::info;
use log::log;
use mongodb::Collection;
use serde::{Deserialize, Serialize};
use serde_cbor::Value;
use serde_json::json;
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
) -> String {
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
    let challenge_value = "somechallengevalue".to_string();

    // println!(
    //     "public key credential2: {}",
    //     public_key_credential.clone().raw_id
    // );
    // clientDataJSONをbase64urlデコードする
    let client_data = deserialize_client_data(public_key_credential.clone().response.client_data);
    // info!("client data: {:#?}", client_data);

    // originの検証
    // info!(
    //     "attestationObject: {:#?}",
    //     public_key_credential.clone().response.attestation_object
    // );
    // attestationObjectをcborデコードする
    let attestation =
        deserialize_attestation_object(public_key_credential.clone().response.attestation_object);
    // info!("attestation: {:#?}", attestation);
    // attenstation.authDataをparseAuthenticatorDataでパースしなきゃいけない、本当に面倒な処理

    // attestation.authDataから何出てくるか知らんがパースする
    let auth_data = parse_attestation_object_auth_data_ai_generated(attestation.auth_data);

    let credential_id_string = BASE64_URL_SAFE_NO_PAD.encode(auth_data.credential_id);
    let rp_id_string = BASE64_URL_SAFE_NO_PAD.encode(auth_data.rp_id_hash);

    // 保存用のユーザー認証情報を作成
    let user_credential = CollectionUserCredentialBuilder::default()
        .pk(public_key_credential.clone().raw_id)
        .sk(challenge_value)
        .user_id(public_key_credential.clone().raw_id)
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

    return public_key_credential.clone().raw_id;
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
    let decoded_bytes = engine::general_purpose::URL_SAFE
        .decode(attestation_object)
        .unwrap();
    let decoded_cbor: PublicKeyCredentialAttention =
        serde_cbor::from_slice(&decoded_bytes).unwrap();

    return decoded_cbor;
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
