use crate::model::collection_user_credential::CollectionUserCredential;
use crate::model::verify_auth_challenge_request::{ChallengeRequest, VerifyAuthChallengeRequest};
use crate::model::{
    collection_challenge::CollectionChallenge, public_key_credential_response::PublicKeyCredential,
};
use crate::service::rp_service;
use actix_session::Session;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use log::error;
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

    match result {
        Ok(success) => HttpResponse::Ok().json(success),
        Err(failed) => {
            error!("Failed to verify response: {}", failed);
            HttpResponse::BadRequest().json("verify response failed")
        }
    }
}

#[post("/rp/usernameless/challenge")]
pub async fn start_usernameless_authenticate(
    session: Session,
    challenge_collection: web::Data<Collection<CollectionChallenge>>,
) -> impl Responder {
    let result = rp_service::start_usernameless_authenticate(session, challenge_collection).await;
    match result {
        Ok(success) => HttpResponse::Ok().json(success),
        Err(failed) => {
            error!("Failed to start usernameless authentication: {}", failed);
            HttpResponse::BadRequest().json("create challenge failed")
        }
    }
}

#[post("/rp/usernameless/verify")]
pub async fn verify_usernameless_challenge(
    session: Session,
    answer: web::Json<ChallengeRequest>,
    user_credential_collection: web::Data<Collection<CollectionUserCredential>>,
) -> impl Responder {
    let result = rp_service::verify_challenge(session, answer, user_credential_collection).await;
    match result {
        Ok(_) => HttpResponse::Ok().json("0"),
        Err(failed) => {
            error!("Failed to verify usernameless challenge: {}", failed);
            HttpResponse::BadRequest().json("verify challenge failed")
        }
    }
}
