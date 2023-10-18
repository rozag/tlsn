use notary_server::{
    service, CliFields, NotarizationSessionRequest, NotaryGlobals, NotaryServerError,
    NotaryServerProperties, NotarySignatureProperties,
};

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{Request, Response, StatusCode},
    response::IntoResponse,
    routing, Router, Server,
};
use eyre::{eyre, Result};
use futures_util::{future, SinkExt, StreamExt};
use hyper::server::{accept::Accept, conn::AddrIncoming};
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use structopt::StructOpt;
use tokio::net::TcpListener;
use tower::MakeService;
use tracing::{debug, error, info};

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments which contains the config file location
    let cli_fields: CliFields = CliFields::from_args();
    let config_file = &cli_fields.config_file;
    let config: NotaryServerProperties = notary_server::parse_config_file(config_file)?;

    // Set up tracing for logging
    notary_server::init_tracing(&config).map_err(|err| eyre!("failed to set up tracing: {err}"))?;

    debug!(?config, "server config loaded");

    // Run the server
    run_ws_server(&config).await
}

#[tracing::instrument(skip(config))]
async fn run_ws_server(config: &NotaryServerProperties) -> Result<(), NotaryServerError> {
    if let Some(_) = &config.tls_signature {
        return Err(NotaryServerError::Unexpected(eyre!(
            "TLS support is not yet implemented for notary_server_ws"
        )));
    }

    // Load the private key for notarized transcript signing from fixture folder — can be swapped
    // out when we use proper ephemeral signing key
    let notary_signing_key = load_notary_signing_key(&config.notary_signature).await?;

    let notary_address = SocketAddr::new(
        IpAddr::V4(config.server.host.parse().map_err(|err| {
            eyre!("failed to parse notary host address from server config: {err}")
        })?),
        config.server.port,
    );

    info!(?notary_address, "starting notary server");

    let notary_globals = NotaryGlobals::new(notary_signing_key, config.notarization.clone());
    let router = Router::new()
        .route(
            "/healthcheck",
            routing::get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        .route("/ws", routing::get(ws_handler))
        .with_state(notary_globals);
    Server::bind(&notary_address)
        .serve(router.into_make_service())
        .await
        .map_err(|err| eyre!("ws notary server run failed: {err}"))?;

    Ok(())
}

/// Temporary function to load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySignatureProperties) -> Result<SigningKey> {
    debug!("loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("failed to load notary signing key for notarization: {err}"))?;

    debug!("successfully loaded notary server's signing key");
    Ok(notary_signing_key)
}

async fn ws_handler(ws: WebSocketUpgrade, state: State<NotaryGlobals>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: State<NotaryGlobals>) {
    info!("received new websocket connection");

    let msg = socket.next().await;
    if let None = msg {
        error!("websocket connection closed before receiving any message");
        return;
    }

    let msg = msg.unwrap();
    if let Err(e) = msg {
        error!("failed to receive message from websocket: {e}");
        return;
    }

    let session_req_json_str = match msg.unwrap() {
        Message::Text(text) => text,
        Message::Binary(bytes) => match String::from_utf8(bytes) {
            Err(e) => {
                error!("failed to parse json str from websocket: {e}");
                return;
            }
            Ok(text) => text,
        },
        other => {
            error!("received unexpected message type from websocket: {other:?}");
            return;
        }
    };

    let session_req = serde_json::from_str::<NotarizationSessionRequest>(&session_req_json_str);
    if let Err(e) = session_req {
        error!("failed to parse session request json from websocket: {e}");
        return;
    }

    let session_req = session_req.unwrap();

    debug!(?session_req, "received session request from websocket");

    // ...
    // service::initialize()
}
