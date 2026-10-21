use consulrs::{
    api::{
        features::{ConsistencyMode, Features},
        kv::requests::ReadKeyRequest,
    },
    client::{ConsulClient, ConsulClientSettings},
    error::ClientError,
    kv,
};
use std::{convert::TryInto, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{rustls, TlsAcceptor};

fn settings(address: String) -> ConsulClientSettings {
    ConsulClientSettings {
        address,
        ca_certs: vec![],
        client_cert: None,
        client_key: None,
        token: Some("test-token".into()),
        verify: true,
        version: 1,
    }
}

fn assert_request_target(request: &[u8], method: &str, path: &str) {
    let request = String::from_utf8_lossy(request);
    let mut parts = request.lines().next().unwrap().split_whitespace();
    assert_eq!(parts.next(), Some(method));
    let uri: http::Uri = parts.next().unwrap().parse().unwrap();
    assert_eq!(uri.path(), path);
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut socket: S, response: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut request = Vec::new();
        loop {
            if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |value| value.trim().parse::<usize>().unwrap());
                if request.len() >= end + 4 + length {
                    break;
                }
            }
            request.push(socket.read_u8().await.unwrap());
        }
        socket.write_all(response).await.unwrap();
        request
    })
    .await
    .expect("HTTP exchange timed out")
}

async fn serve(response: Vec<u8>) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        exchange(socket, &response).await
    });
    (address, server)
}

#[tokio::test]
async fn reqwest_013_client_preserves_middleware_and_response_metadata() {
    let body = br#"[{"Key":"a/b","Value":"aGVsbG8=","CreateIndex":1,"ModifyIndex":2,"LockIndex":0,"Flags":0}]"#;
    let mut response = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Consul-Index: 42\r\nX-Consul-KnownLeader: true\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(body);
    let (address, server) = serve(response).await;
    let mut client = ConsulClient::new(settings(address)).unwrap();
    // This assignment also checks that the public client uses Reqwest 0.13.
    client.http.http = reqwest::Client::builder().no_proxy().build().unwrap();
    let features = Features {
        mode: Some(ConsistencyMode::CONSISTENT),
        ..Features::default()
    };
    let result = kv::read(
        &client,
        "a/b",
        Some(ReadKeyRequest::builder().features(features)),
    )
    .await
    .unwrap();
    assert_eq!(result.index.as_deref(), Some("42"));
    assert_eq!(result.known_leader.as_deref(), Some("true"));
    let value: Vec<u8> = result.response[0]
        .value
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(value, b"hello");
    let request = String::from_utf8(server.await.unwrap()).unwrap();
    let first = request.lines().next().unwrap();
    assert!(first.starts_with("GET /v1/kv/a/b?consistent"), "{}", first);
    assert!(request
        .to_ascii_lowercase()
        .contains("x-consul-token: test-token\r\n"));
}

#[tokio::test]
async fn raw_write_bodies_and_api_errors_survive_the_upgrade() {
    let (address, server) =
        serve(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntrue".to_vec())
            .await;
    let client = ConsulClient::new(settings(address)).unwrap();
    assert!(
        kv::set(&client, "key", &[0, 255, b'\n'], None)
            .await
            .unwrap()
            .response
    );
    let request = server.await.unwrap();
    assert_request_target(&request, "PUT", "/v1/kv/key");
    assert!(request.ends_with(&[0, 255, b'\n']));

    let (address, server) = serve(
        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied".to_vec(),
    )
    .await;
    let client = ConsulClient::new(settings(address)).unwrap();
    match kv::read(&client, "key", None).await.unwrap_err() {
        ClientError::APIError { code, message } => {
            assert_eq!(code, 403);
            assert_eq!(message.as_deref(), Some("denied"));
        }
        error => panic!("unexpected error: {}", error),
    }
    server.await.unwrap();
}

struct CertificateFile(std::path::PathBuf);
impl Drop for CertificateFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn tls_trusts_configured_ca_and_rejects_untrusted_certificates() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let address = format!("https://localhost:{}", port);
    let certificate_file = CertificateFile(std::env::temp_dir().join(format!(
        "consulrs-ca-{}-{}.pem",
        std::process::id(),
        port
    )));
    std::fs::write(&certificate_file.0, certificate.cert.pem()).unwrap();
    let server = tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let (socket, _) = listener.accept().await.unwrap();
        assert!(
            acceptor.accept(socket).await.is_err(),
            "an untrusted certificate was accepted"
        );
        let (socket, _) = listener.accept().await.unwrap();
        let socket = acceptor.accept(socket).await.unwrap();
        exchange(
            socket,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
        )
        .await
    });
    let untrusted = ConsulClient::new(settings(address.clone())).unwrap();
    assert!(kv::read(&untrusted, "key", None).await.is_err());
    let mut trusted_settings = settings(address);
    trusted_settings
        .ca_certs
        .push(certificate_file.0.to_str().unwrap().into());
    let trusted = ConsulClient::new(trusted_settings).unwrap();
    assert!(kv::read(&trusted, "key", None)
        .await
        .unwrap()
        .response
        .is_empty());
    let request = String::from_utf8(server.await.unwrap()).unwrap();
    assert_request_target(request.as_bytes(), "GET", "/v1/kv/key");
}

#[tokio::test]
async fn tls_sends_the_configured_client_certificate() {
    let server_certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client_params = rcgen::CertificateParams::new(vec!["client.test".into()]).unwrap();
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params.signed_by(&client_key, &issuer).unwrap();
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(ca_certificate.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
        .build()
        .unwrap();
    let server_key =
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_certificate.signing_key.serialize_der());
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_certificate.cert.der().clone()],
            server_key.into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let file = |suffix| {
        CertificateFile(std::env::temp_dir().join(format!(
            "consulrs-mtls-{}-{}-{}",
            std::process::id(),
            port,
            suffix
        )))
    };
    let server_ca = file("server.pem");
    let client_cert = file("client.pem");
    let client_pem_key = file("client-key.pem");
    std::fs::write(&server_ca.0, server_certificate.cert.pem()).unwrap();
    std::fs::write(&client_cert.0, client_certificate.pem()).unwrap();
    std::fs::write(&client_pem_key.0, client_key.serialize_pem()).unwrap();
    let expected_certificate = client_certificate.der().clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let socket = TlsAcceptor::from(Arc::new(config))
            .accept(socket)
            .await
            .unwrap();
        assert_eq!(
            socket.get_ref().1.peer_certificates().unwrap()[0],
            expected_certificate
        );
        exchange(
            socket,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]",
        )
        .await
    });
    let mut settings = settings(format!("https://localhost:{}", port));
    settings.ca_certs.push(server_ca.0.to_str().unwrap().into());
    settings.client_cert = Some(client_cert.0.to_str().unwrap().into());
    settings.client_key = Some(client_pem_key.0.to_str().unwrap().into());
    let client = ConsulClient::new(settings).unwrap();
    assert!(kv::read(&client, "key", None)
        .await
        .unwrap()
        .response
        .is_empty());
    assert_request_target(&server.await.unwrap(), "GET", "/v1/kv/key");
}
