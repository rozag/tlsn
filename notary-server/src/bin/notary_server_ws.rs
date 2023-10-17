use notary_server::{
    CliFields, NotaryGlobals, NotaryServerError, NotaryServerProperties, NotarySignatureProperties,
};

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
};

use axum::{
    http::{Request, StatusCode},
    response::IntoResponse,
    routing, Router,
};
use eyre::{eyre, Result};
use futures_util::future;
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

    let listener = TcpListener::bind(notary_address)
        .await
        .map_err(|err| eyre!("failed to bind server address to tcp listener: {err}"))?;
    let mut listener = AddrIncoming::from_listener(listener)
        .map_err(|err| eyre!("failed to build hyper tcp listener: {err}"))?;

    let notary_globals = NotaryGlobals::new(notary_signing_key, config.notarization.clone());
    let router = Router::new()
        .route(
            "/healthcheck",
            routing::get(|| async move { (StatusCode::OK, "Ok").into_response() }),
        )
        // .route("/session", post(initialize))
        // .route("/notarize", get(upgrade_protocol))
        .with_state(notary_globals);
    let mut app = router.into_make_service();

    loop {
        // Poll and await for any incoming connection, ensure that all operations inside are
        // infallible to prevent bringing down the server
        let (prover_address, stream) =
            match future::poll_fn(|cx| Pin::new(&mut listener).poll_accept(cx)).await {
                Some(Ok(connection)) => (connection.remote_addr(), connection),
                Some(Err(err)) => {
                    error!("{}", NotaryServerError::Connection(err.to_string()));
                    continue;
                }
                None => unreachable!("the poll_accept method should never return None"),
            };
        debug!(?prover_address, "received a prover's TCP connection");

        // let protocol = protocol.clone();
        let service = MakeService::<_, Request<hyper::Body>>::make_service(&mut app, &stream);

        // Spawn a new async task to handle the new connection
        tokio::spawn(async move {
            info!(
                ?prover_address,
                "accepted prover's raw (without TLS) TCP connection",
            );
            // Serve different requests using the same hyper protocol and axum router
            // let _ = protocol
            //     // Can unwrap because it's infallible
            //     .serve_connection(stream, service.await.unwrap())
            //     // use with_upgrades to upgrade connection to websocket for websocket clients
            //     // and to extract tcp connection for tcp clients
            //     .with_upgrades()
            //     .await;
        });
    }
}

/// Temporary function to load notary signing key from static file
async fn load_notary_signing_key(config: &NotarySignatureProperties) -> Result<SigningKey> {
    debug!("loading notary server's signing key");

    let notary_signing_key = SigningKey::read_pkcs8_pem_file(&config.private_key_pem_path)
        .map_err(|err| eyre!("failed to load notary signing key for notarization: {err}"))?;

    debug!("successfully loaded notary server's signing key");
    Ok(notary_signing_key)
}
