use crate::model::collection_user_credential::CollectionUserCredential;
use crate::model::{
    collection_challenge::CollectionChallenge, public_key_credential_response::PublicKeyCredential,
};
use crate::service::rp_service;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use mongodb::Collection;

#[get("/hello")]
pub async fn hello_world() -> impl Responder {
    let result = rp_service::hello();
    HttpResponse::Ok().body(result)
}

#[get("/rp/create")]
pub async fn create_challenge_options(
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
) -> impl Responder {
    let options = rp_service::create_challenge_options(challenge_collection);
    HttpResponse::Ok().json(options.await)
}

#[post("/rp/verify")]
pub async fn verify_response(
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
    user_credential_collection: web::Data<Collection<CollectionUserCredential>>,
    req: HttpRequest,
    public_key_credential: web::Json<PublicKeyCredential>,
) -> impl Responder {
    println!(
        "public key credential1: {}",
        public_key_credential.clone().raw_id
    );
    let result = rp_service::verify_response(
        challenge_collection,
        user_credential_collection,
        req,
        public_key_credential,
    )
    .await;
    HttpResponse::Ok().json(result)
}
