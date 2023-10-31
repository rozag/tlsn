use notary_server::{
    service,
    service::axum_websocket::{Message, WebSocket},
    service::websocket,
    service::ProtocolUpgrade,
    CliFields, NotarizationRequestQuery, NotarizationSessionRequest, NotaryGlobals,
    NotaryServerError, NotaryServerProperties, NotarySignatureProperties,
};

use std::net::{IpAddr, SocketAddr};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing, Router, Server};
use eyre::{eyre, Result};
use futures_util::StreamExt;
use hyper::body::HttpBody;
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use structopt::StructOpt;
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
    if config.tls_signature.is_some() {
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

async fn ws_handler(
    protocol_upgrade: ProtocolUpgrade,
    state: State<NotaryGlobals>,
) -> impl IntoResponse {
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => ws.on_upgrade(move |socket| handle_socket(socket, state)),
        ProtocolUpgrade::Tcp(_) => NotaryServerError::BadProverRequest(
            "notary_server_ws can only upgrade connection to websocket".to_string(),
        )
        .into_response(),
    }
}

async fn handle_socket(mut socket: WebSocket, state: State<NotaryGlobals>) {
    info!("received new websocket connection");

    let session_req: NotarizationSessionRequest = match parse_msg_from_ws(&mut socket).await {
        Ok(notarization_req) => notarization_req,
        Err(e) => {
            error!("failed to parse session request from websocket: {e}");
            return;
        }
    };

    debug!(?session_req, "received session request from websocket");

    let body_bytes = service::initialize(state.clone(), Ok(session_req.into()))
        .await
        .into_response()
        .into_body()
        .data()
        .await;
    if body_bytes.is_none() {
        error!("failed to deconstruct response option from initialize");
        return;
    }

    let body_bytes = body_bytes.unwrap();
    if let Err(e) = body_bytes {
        error!("failed to deconstruct response result from initialize: {e}");
        return;
    }

    let body_bytes = body_bytes.unwrap().to_vec();

    if let Err(e) = socket.send(Message::Binary(body_bytes.clone())).await {
        error!("failed to send session response to websocket: {e}");
        return;
    }

    debug!(
        "successfully sent session response to websocket: {:?}",
        String::from_utf8(body_bytes)
    );

    let notarization_req: NotarizationRequestQuery = match parse_msg_from_ws(&mut socket).await {
        Ok(notarization_req) => notarization_req,
        Err(e) => {
            error!("failed to parse notarization request from websocket: {e}");
            return;
        }
    };

    debug!(
        ?notarization_req,
        "received notarization request from websocket"
    );

    // Fetch the configuration data from the store using the session_id
    let session_id = notarization_req.session_id;
    let State(notary_globals) = state;
    let max_transcript_size = match notary_globals.store.lock().await.get(&session_id) {
        Some(max_transcript_size) => max_transcript_size.to_owned(),
        None => {
            error!("Session id {session_id} does not exist");
            return;
        }
    };

    // Start the actual notarization session
    websocket::websocket_notarize(socket, notary_globals, session_id, max_transcript_size).await;
}

async fn parse_msg_from_ws<T>(socket: &mut WebSocket) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let msg = socket.next().await;
    if msg.is_none() {
        return Err(eyre!("no messages in websocket"));
    }

    let msg = msg.unwrap();
    if let Err(e) = msg {
        return Err(eyre!("error in websocket: {e}"));
    }

    let json_str = match msg.unwrap() {
        Message::Text(text) => text,
        Message::Binary(bytes) => match String::from_utf8(bytes) {
            Err(e) => {
                return Err(eyre!("failed to parse json str from websocket: {e}"));
            }
            Ok(text) => text,
        },
        other => {
            return Err(eyre!(
                "received unexpected message type from websocket: {other:?}"
            ));
        }
    };

    let parsed = serde_json::from_str::<T>(&json_str);
    if let Err(e) = parsed {
        return Err(eyre!(
            "failed to parse session request json from websocket: {e}"
        ));
    }

    Ok(parsed.unwrap())
}
