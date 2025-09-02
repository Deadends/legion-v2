use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    timeout::TimeoutLayer,
};
use tracing::{info, Level};
use tracing_subscriber;

mod prover;
use prover::{
    service::{LegionService, LegionConfig},
    host_wrapper::AuthRequest,
    final_circuit::SecurityLevel,
};

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Deserialize)]
struct AuthRequestDto {
    username: String,
    password: String,
    timestamp: u64,
    server_pubkey: [u8; 32],
    ip_address: Option<String>,
}

#[derive(Serialize)]
struct AuthResponse {
    proof: String,
    success: bool,
}

type AppState = Arc<LegionService>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    let config = LegionConfig {
        security_level: SecurityLevel::Production,
        max_concurrent_proofs: 1000,
        enable_metrics: true,
    };

    let service = Arc::new(LegionService::new(config));

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/auth", post(authenticate))
        .route("/auth/batch", post(batch_authenticate))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(TimeoutLayer::new(std::time::Duration::from_secs(30)))
        )
        .with_state(service);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    info!("Legion server starting on 0.0.0.0:8080");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn authenticate(
    State(service): State<AppState>,
    Json(req): Json<AuthRequestDto>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let auth_req = AuthRequest {
        username: req.username,
        password: req.password,
        timestamp: req.timestamp,
        server_pubkey: req.server_pubkey,
        ip_address: req.ip_address,
    };

    match service.authenticate(auth_req).await {
        Ok(proof) => Ok(Json(AuthResponse {
            proof: hex::encode(proof),
            success: true,
        })),
        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn batch_authenticate(
    State(service): State<AppState>,
    Json(requests): Json<Vec<AuthRequestDto>>,
) -> Result<Json<Vec<AuthResponse>>, StatusCode> {
    let auth_requests: Vec<AuthRequest> = requests
        .into_iter()
        .map(|req| AuthRequest {
            username: req.username,
            password: req.password,
            timestamp: req.timestamp,
            server_pubkey: req.server_pubkey,
            ip_address: req.ip_address,
        })
        .collect();

    match service.batch_authenticate(auth_requests).await {
        Ok(proofs) => {
            let responses = proofs
                .into_iter()
                .map(|proof| AuthResponse {
                    proof: hex::encode(proof),
                    success: true,
                })
                .collect();
            Ok(Json(responses))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}