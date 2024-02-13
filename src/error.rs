use serde::Serialize;
use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, Rejection, Reply};


#[derive(Debug,Error)]
pub enum  Error {
    #[error("Wrong credentials")]
    WrongCredentialsError,
    #[error("jwt token creation error!")]
    JWTTokenCreationError,
    #[error("JWT token not valid!")]
    JWTTokenError,
    #[error("no auth header")]
    NoAuthHeaderError,
    #[error("No permission")]
    NoPermisionError,
    #[error("Invalid auth error!")]
    InvalidAuthHeaderError,
}

#[derive(Serialize,Debug)]
struct  ErrorResponse {
    messsage: String,
    status: String,
}

impl  warp::reject::Reject for Error {
    
}

pub async fn handle_rejection(err: Rejection) ->std::result::Result<impl Reply, Infallible> {
    let (code, messsage) = if err.is_not_found(){
        (StatusCode::NOT_FOUND,"Not Found".to_string())
    }else if let Some(e) = err.find::<Error>(){
        match e {
            Error::WrongCredentialsError => (StatusCode::FORBIDDEN, e.to_string()),
            Error::NoPermisionError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::JWTTokenError => (StatusCode::UNAUTHORIZED, e.to_string()),
            Error::JWTTokenCreationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error".to_string(),
            ),
            _ => (StatusCode::BAD_REQUEST, e.to_string()),
        }
    }else if err.find::<warp::reject::MethodNotAllowed>().is_some(){
        (
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not allowed!".to_string(),
        )
    }else{
        eprintln!("unhandled error!: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server Error".to_string(),
        )
    };

    let json = warp::reply::json(&ErrorResponse{
        status: code.to_string(),
        messsage,
    });
    Ok(warp::reply::with_status(json, code))
}