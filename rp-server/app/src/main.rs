extern crate env_logger;
use actix_cors::Cors;
use actix_session::{storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, middleware::Logger, web, App, HttpServer};
mod controller;
use controller::rp_controller;
use log::info;
use model::collection_user_credential::CollectionUserCredential;
use rand::Rng;
mod model;
mod service;
use crate::model::collection_challenge::CollectionChallenge;
use mongodb::{
    bson::doc,
    change_stream::session,
    options::{ClientOptions, Credential, IndexOptions},
    Client, Collection, IndexModel,
};

const DB_NAME: &str = "fido-db";
const CHALLENGE_COLLECTION_NAME: &str = "challenges";
const USER_CREDENTIAL_COLLECTION_NAME: &str = "user_credentials";

// コレクション(テーブル？)の作成
// このコレクションに対して、PublicKeyCredentialCreationOptionsのフィールドchallengeが一意なインデックスを作成
// mongoDbのイニシャライズ処理の一部
async fn create_challenge_index(client: &Client) {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! {"pk": 1, "sk": -1}) // 複合インデックス
        .options(options)
        .build();
    client
        .database(&DB_NAME)
        .collection::<CollectionChallenge>(&CHALLENGE_COLLECTION_NAME)
        .create_index(model)
        .await
        .expect("Failed to create index on challenge field");
}

async fn create_user_credential_index(client: &Client) {
    let options = IndexOptions::builder().unique(true).build();
    let model = IndexModel::builder()
        .keys(doc! {"pk": 1, "sk": -1}) // 複合インデックス
        .options(options)
        .build();
    client
        .database(&DB_NAME)
        .collection::<CollectionUserCredential>(&USER_CREDENTIAL_COLLECTION_NAME)
        .create_index(model)
        .await
        .expect("Failed to create index on user_credential field");
}

/**
 * session管理に用いるredisのセットアップ
 */
async fn redis_setup() -> RedisSessionStore {
    // Redisへの接続文字列
    let redis_uri = "redis://redis:6379";

    // Redisセッションストアを初期化
    // .await が必要なので、main関数内で初期化する
    let redis_store = match RedisSessionStore::new(redis_uri).await {
        Ok(store) => store,
        Err(e) => {
            // サーバー起動時にRedisに接続できない場合はパニックさせる
            panic!("Failed to connect to Redis: {}", e);
        }
    };
    info!("Connected to Redis");
    redis_store
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // ログ出力の設定
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // mongoDbのイニシャライズ処理
    // 後で別ファイルにしたい
    let mut client_options = ClientOptions::parse("mongodb://mongo-db:27017")
        .await
        .expect("Failed to parse MongoDB URI");
    let default_cred = Credential::builder()
        .username("admin".to_string())
        .password("password".to_string())
        .source("admin".to_string())
        .build();
    client_options.credential = Some(default_cred);
    let client = Client::with_options(client_options).expect("Failed to connect to MongoDB");
    info!("Connected to MongoDB");
    create_challenge_index(&client).await;
    create_user_credential_index(&client).await;

    let challenge_collection: Collection<CollectionChallenge> = client
        .database(&DB_NAME)
        .collection(&CHALLENGE_COLLECTION_NAME);
    let user_credential_collection: Collection<CollectionUserCredential> = client
        .database(&DB_NAME)
        .collection(&USER_CREDENTIAL_COLLECTION_NAME);

    // 秘密鍵の生成
    let secret_key = Key::from(&rand::rng().random::<[u8; 64]>());
    // セッション管理を行うredisのセットアップ
    let redis_session_store = redis_setup().await;

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allow_any_header()
                    .allow_any_method(),
            )
            .wrap(SessionMiddleware::new(
                redis_session_store.clone(),
                secret_key.clone(),
            ))
            // .app_data(web::Data::new(client.clone()))
            .app_data(web::Data::new(challenge_collection.clone()))
            .app_data(web::Data::new(user_credential_collection.clone()))
            .service(rp_controller::create_challenge_options)
            .service(rp_controller::hello_world)
            .service(rp_controller::verify_response)
            .service(rp_controller::start_usernameless_authenticate)
            .service(rp_controller::verify_usernameless_challenge)
    })
    .bind("rust:9000")?
    .run()
    .await
}
