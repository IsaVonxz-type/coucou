use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex as AsyncMutex};

use crate::chatgpt_store;

const ISSUER: &str = "https://auth.openai.com";
const AUTHORIZE: &str = "https://auth.openai.com/api/accounts/authorize";
const TOKEN: &str = "https://auth.openai.com/api/accounts/oauth/token";
const REVOKE: &str = "https://auth.openai.com/api/accounts/oauth/revoke";
const JWKS: &str = "https://auth.openai.com/.well-known/jwks.json";
const RESOURCE: &str = "https://api.openai.com/v1";
const PLAN_SCOPE: &str = "chatgpt.tokens.use.direct";
const SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";

#[derive(Default)]
pub struct Auth {
    operation: AsyncMutex<()>,
    pending: Mutex<Option<watch::Sender<bool>>>,
}

#[derive(Default, Serialize, Deserialize)]
struct Store {
    host_id: String,
    active_client_id: Option<String>,
    accounts: Vec<Account>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Account {
    client_id: String,
    subject: String,
    email: Option<String>,
    session: Option<Session>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    access_token: String,
    refresh_token: String,
    id_token: String,
    expires_at: u64,
    scopes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub pending: bool,
    pub active_client_id: Option<String>,
    pub accounts: Vec<AccountStatus>,
    pub message: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    client_id: String,
    email: Option<String>,
    connected: bool,
    plan_enabled: bool,
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Claims {
    sub: String,
    email: Option<String>,
    nonce: Option<String>,
    azp: Option<String>,
    aud: serde_json::Value,
}

struct Attempt {
    state: String,
    nonce: String,
    verifier: String,
    redirect_uri: String,
    client_id: Option<String>,
}

struct Callback {
    code: String,
    client_id: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_bytes(length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; length];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "Could not generate secure OAuth randomness.".to_string())?;
    Ok(bytes)
}

pub(crate) fn random_hex(length: usize) -> Result<String, String> {
    Ok(random_bytes(length)?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn host_id() -> Result<String, String> {
    let mut bytes = random_bytes(16)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn client() -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "Could not create the ChatGPT connection.".into())
}

fn status_from(store: Store, pending: bool, message: Option<String>) -> Status {
    Status {
        pending,
        active_client_id: store.active_client_id,
        accounts: store
            .accounts
            .into_iter()
            .map(|account| AccountStatus {
                connected: account.session.is_some(),
                plan_enabled: account
                    .session
                    .as_ref()
                    .is_some_and(|session| session.scopes.iter().any(|scope| scope == PLAN_SCOPE)),
                expires_at: account.session.as_ref().map(|session| session.expires_at),
                client_id: account.client_id,
                email: account.email,
            })
            .collect(),
        message,
    }
}

impl Auth {
    pub fn status(&self) -> Result<Status, String> {
        let pending = self.pending.lock().unwrap().is_some();
        Ok(status_from(chatgpt_store::load()?, pending, None))
    }

    pub fn cancel(&self) {
        if let Some(sender) = self.pending.lock().unwrap().as_ref() {
            let _ = sender.send(true);
        }
    }

    pub async fn login(&self, client_id: Option<String>) -> Result<Status, String> {
        let _operation = self
            .operation
            .try_lock()
            .map_err(|_| "Another ChatGPT connection operation is in progress.".to_string())?;
        let mut store: Store = chatgpt_store::load()?;
        if store.host_id.is_empty() {
            store.host_id = host_id()?;
            chatgpt_store::save(&store)?;
        }
        let account = client_id
            .as_ref()
            .map(|id| {
                store
                    .accounts
                    .iter()
                    .find(|account| &account.client_id == id)
                    .cloned()
                    .ok_or_else(|| "Unknown ChatGPT account registration.".to_string())
            })
            .transpose()?;
        let (sender, mut cancelled) = watch::channel(false);
        *self.pending.lock().unwrap() = Some(sender);
        let result = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(300), authorize(&store, account.as_ref())) => {
                result.map_err(|_| "ChatGPT sign-in timed out. Try again.".to_string()).and_then(|value| value)
            }
            _ = cancelled.changed() => Err("ChatGPT sign-in cancelled.".to_string()),
        };
        *self.pending.lock().unwrap() = None;
        let account = result?;
        let id = account.client_id.clone();
        if let Some(existing) = store
            .accounts
            .iter_mut()
            .find(|existing| existing.client_id == id)
        {
            *existing = account;
        } else {
            store.accounts.push(account);
        }
        store.active_client_id = Some(id);
        chatgpt_store::save(&store)?;
        Ok(status_from(
            store,
            false,
            Some("Connected. ChatGPT chat support is the next step.".into()),
        ))
    }

    pub async fn select(&self, client_id: String) -> Result<Status, String> {
        let _operation = self
            .operation
            .try_lock()
            .map_err(|_| "Another ChatGPT connection operation is in progress.".to_string())?;
        let mut store: Store = chatgpt_store::load()?;
        if !store
            .accounts
            .iter()
            .any(|account| account.client_id == client_id)
        {
            return Err("Unknown ChatGPT account registration.".into());
        }
        store.active_client_id = Some(client_id);
        chatgpt_store::save(&store)?;
        Ok(status_from(store, false, None))
    }

    pub async fn refresh(&self) -> Result<Status, String> {
        let _operation = self
            .operation
            .try_lock()
            .map_err(|_| "Another ChatGPT connection operation is in progress.".to_string())?;
        let mut store: Store = chatgpt_store::load()?;
        let index = active_index(&store)?;
        let account = &store.accounts[index];
        let previous = account
            .session
            .as_ref()
            .ok_or_else(|| "Sign in to ChatGPT first.".to_string())?;
        let response = client()?
            .post(TOKEN)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", account.client_id.as_str()),
                ("refresh_token", previous.refresh_token.as_str()),
                ("resource", RESOURCE),
            ])
            .send()
            .await
            .map_err(|_| "Could not renew ChatGPT session. Check your connection.".to_string())?;
        let status = response.status();
        if !status.is_success() {
            let error: serde_json::Value = response.json().await.unwrap_or_default();
            if error.get("error").and_then(|value| value.as_str()) == Some("invalid_grant") {
                store.accounts[index].session = None;
                chatgpt_store::save(&store)?;
                return Err("ChatGPT session expired or was revoked. Sign in again.".into());
            }
            return Err(format!(
                "ChatGPT session renewal failed (HTTP {}). Try again later.",
                status.as_u16()
            ));
        }
        let tokens: Tokens = response
            .json()
            .await
            .map_err(|_| "ChatGPT returned an invalid token response.".to_string())?;
        if let Some(id_token) = tokens.id_token.as_deref() {
            let keys = signing_keys(&client()?).await?;
            let claims = validate_identity(id_token, &keys, &account.client_id, None)?;
            if claims.sub != account.subject {
                return Err(
                    "ChatGPT session renewal returned a different identity. Sign in again.".into(),
                );
            }
        }
        let session = session_from(tokens, Some(previous))?;
        store.accounts[index].session = Some(session);
        chatgpt_store::save(&store)?;
        Ok(status_from(
            store,
            false,
            Some("ChatGPT session renewed.".into()),
        ))
    }

    pub async fn logout(&self) -> Result<Status, String> {
        let _operation = self
            .operation
            .try_lock()
            .map_err(|_| "Another ChatGPT connection operation is in progress.".to_string())?;
        let mut store: Store = chatgpt_store::load()?;
        let index = active_index(&store)?;
        let account = &store.accounts[index];
        let mut revoked = true;
        if let Some(session) = account.session.as_ref() {
            revoked = false;
            for attempt in 0..3 {
                let response = client()?
                    .post(REVOKE)
                    .form(&[
                        ("token", session.refresh_token.as_str()),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", account.client_id.as_str()),
                    ])
                    .send()
                    .await;
                match response {
                    Ok(response) if response.status() == reqwest::StatusCode::OK => {
                        revoked = true;
                        break;
                    }
                    Ok(response) if !response.status().is_server_error() => break,
                    _ => {}
                }
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(250 << attempt)).await;
                }
            }
        }
        store.accounts[index].session = None;
        chatgpt_store::save(&store)?;
        let message = if revoked {
            "Signed out of ChatGPT."
        } else {
            "Signed out locally. Remote revocation could not be confirmed; disconnect Coucou in ChatGPT Settings."
        };
        Ok(status_from(store, false, Some(message.into())))
    }
}

fn active_index(store: &Store) -> Result<usize, String> {
    store
        .accounts
        .iter()
        .position(|account| Some(&account.client_id) == store.active_client_id.as_ref())
        .ok_or_else(|| "Select a ChatGPT account first.".to_string())
}

fn authorization_url(store: &Store, account: Option<&Account>, attempt: &Attempt) -> Url {
    let mut url = Url::parse(AUTHORIZE).unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(attempt.verifier.as_bytes()));
    {
        let mut query = url.query_pairs_mut();
        query.append_pair(
            "client_id",
            attempt
                .client_id
                .as_deref()
                .unwrap_or("dynamic_agent_client"),
        );
        if attempt.client_id.is_none() {
            query.append_pair("agent_name_hint", "Coucou");
        }
        query
            .append_pair("ext_agent_host_id", &store.host_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", &attempt.redirect_uri)
            .append_pair("scope", SCOPES)
            .append_pair("resource", RESOURCE)
            .append_pair("state", &attempt.state)
            .append_pair("nonce", &attempt.nonce)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge);
        if let Some(account) = account {
            if let Some(session) = &account.session {
                query.append_pair("id_token_hint", &session.id_token);
            }
            if let Some(email) = &account.email {
                query.append_pair("login_hint", email);
            }
        }
    }
    url
}

async fn authorize(store: &Store, existing: Option<&Account>) -> Result<Account, String> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|_| "Could not open the local ChatGPT callback listener.".to_string())?;
    let port = listener
        .local_addr()
        .map_err(|_| "Could not read callback port.".to_string())?
        .port();
    let attempt = Attempt {
        state: URL_SAFE_NO_PAD.encode(random_bytes(32)?),
        nonce: URL_SAFE_NO_PAD.encode(random_bytes(32)?),
        verifier: URL_SAFE_NO_PAD.encode(random_bytes(32)?),
        redirect_uri: format!("http://127.0.0.1:{port}/auth/callback"),
        client_id: existing.map(|account| account.client_id.clone()),
    };
    crate::open_browser(authorization_url(store, existing, &attempt).as_str())?;
    let callback = receive_callback(&listener, &attempt).await?;
    let client = client()?;
    let response = client
        .post(TOKEN)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", callback.client_id.as_str()),
            ("code", callback.code.as_str()),
            ("code_verifier", attempt.verifier.as_str()),
            ("redirect_uri", attempt.redirect_uri.as_str()),
            ("resource", RESOURCE),
        ])
        .send()
        .await
        .map_err(|_| "Could not finish ChatGPT sign-in. Check your connection.".to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "ChatGPT sign-in failed (HTTP {}). Start a new sign-in attempt.",
            response.status().as_u16()
        ));
    }
    let tokens: Tokens = response
        .json()
        .await
        .map_err(|_| "ChatGPT returned an invalid token response.".to_string())?;
    let id_token = tokens
        .id_token
        .as_deref()
        .ok_or_else(|| "ChatGPT did not return an identity token.".to_string())?;
    let keys = signing_keys(&client).await?;
    let claims = validate_identity(id_token, &keys, &callback.client_id, Some(&attempt.nonce))?;
    if existing.is_some_and(|account| account.subject != claims.sub) {
        return Err("The signed-in account differs from the selected registration. Add it as a new account.".into());
    }
    let session = session_from(tokens, None)?;
    Ok(Account {
        client_id: callback.client_id,
        subject: claims.sub,
        email: claims.email,
        session: Some(session),
    })
}

async fn signing_keys(client: &Client) -> Result<JwkSet, String> {
    let response = client
        .get(JWKS)
        .send()
        .await
        .map_err(|_| "Could not verify ChatGPT identity. Check your connection.".to_string())?;
    if !response.status().is_success() {
        return Err("Could not retrieve ChatGPT signing keys.".into());
    }
    response
        .json()
        .await
        .map_err(|_| "ChatGPT returned invalid signing keys.".into())
}

fn validate_identity(
    token: &str,
    keys: &JwkSet,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<Claims, String> {
    let error = || "ChatGPT identity verification failed.".to_string();
    let header = decode_header(token).map_err(|_| error())?;
    if header.alg != Algorithm::RS256 {
        return Err(error());
    }
    let key = keys
        .find(header.kid.as_deref().ok_or_else(error)?)
        .ok_or_else(error)?;
    let key = DecodingKey::from_jwk(key).map_err(|_| error())?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[client_id]);
    validation.set_issuer(&[ISSUER]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.leeway = 5;
    let claims = decode::<Claims>(token, &key, &validation)
        .map_err(|_| error())?
        .claims;
    if claims.sub.is_empty()
        || nonce.is_some_and(|nonce| claims.nonce.as_deref() != Some(nonce))
        || claims.azp.as_deref().is_some_and(|azp| azp != client_id)
        || (claims.aud.as_array().is_some_and(|aud| aud.len() > 1)
            && claims.azp.as_deref() != Some(client_id))
    {
        return Err(error());
    }
    Ok(claims)
}

fn session_from(tokens: Tokens, previous: Option<&Session>) -> Result<Session, String> {
    let scopes: Vec<String> = tokens
        .scope
        .map(|scope| scope.split_whitespace().map(str::to_string).collect())
        .or_else(|| previous.map(|session| session.scopes.clone()))
        .unwrap_or_default();
    if tokens.access_token.is_empty()
        || !tokens.token_type.eq_ignore_ascii_case("Bearer")
        || tokens.expires_in == 0
        || !scopes.iter().any(|scope| scope == PLAN_SCOPE)
        || !scopes.iter().any(|scope| scope == "resource.invoke")
    {
        return Err("ChatGPT plan usage was not authorized. Check account eligibility and consent, then sign in again.".into());
    }
    let refresh_token = tokens
        .refresh_token
        .or_else(|| previous.map(|session| session.refresh_token.clone()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ChatGPT did not grant a renewable session.".to_string())?;
    let id_token = tokens
        .id_token
        .or_else(|| previous.map(|session| session.id_token.clone()))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "ChatGPT did not return an identity token.".to_string())?;
    Ok(Session {
        access_token: tokens.access_token,
        refresh_token,
        id_token,
        scopes,
        expires_at: now()
            .checked_add(tokens.expires_in)
            .ok_or_else(|| "ChatGPT returned an invalid token expiry.".to_string())?,
    })
}

fn parse_callback(target: &str, attempt: &Attempt) -> Result<Callback, String> {
    if !target.starts_with("/auth/callback?") {
        return Err("Invalid callback path.".into());
    }
    let url = Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|_| "Invalid callback URL.".to_string())?;
    let mut params = std::collections::HashMap::new();
    for (key, value) in url.query_pairs() {
        if params.insert(key.to_string(), value.to_string()).is_some() {
            return Err("Duplicate OAuth callback parameter.".into());
        }
    }
    if params.get("state") != Some(&attempt.state) {
        return Err("OAuth state mismatch.".into());
    }
    if params.contains_key("error") {
        return Err(
            "ChatGPT sign-in was declined or unavailable. Check account eligibility and try again."
                .into(),
        );
    }
    let client_id = match (&attempt.client_id, params.get("client_id")) {
        (Some(expected), Some(actual)) if expected != actual => {
            return Err("OAuth client mismatch.".into())
        }
        (Some(expected), _) => expected.clone(),
        (None, Some(actual)) if !actual.is_empty() && actual != "dynamic_agent_client" => {
            actual.clone()
        }
        _ => return Err("ChatGPT did not return an issued client ID.".into()),
    };
    let code = params
        .remove("code")
        .filter(|code| !code.is_empty())
        .ok_or_else(|| "ChatGPT did not return an authorization code.".to_string())?;
    Ok(Callback { code, client_id })
}

async fn receive_callback(listener: &TcpListener, attempt: &Attempt) -> Result<Callback, String> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .map_err(|_| "Local ChatGPT callback listener failed.".to_string())?;
        let request = tokio::time::timeout(Duration::from_secs(5), read_request(&mut stream)).await;
        let Ok(Ok(request)) = request else { continue };
        let mut parts = request
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace();
        let method = parts.next();
        let target = parts.next().unwrap_or_default();
        let expected_host = Url::parse(&attempt.redirect_uri).unwrap().port().unwrap();
        let host = request
            .lines()
            .skip(1)
            .filter_map(|line| line.split_once(':'))
            .find(|(key, _)| key.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim());
        if method != Some("GET") || host != Some(format!("127.0.0.1:{expected_host}").as_str()) {
            let _ = respond(&mut stream, false).await;
            continue;
        }
        let result = parse_callback(target, attempt);
        let state_matches = Url::parse(&format!("http://127.0.0.1{target}"))
            .ok()
            .is_some_and(|url| {
                url.query_pairs()
                    .any(|(key, value)| key == "state" && value == attempt.state)
            });
        let _ = respond(&mut stream, result.is_ok()).await;
        if result.is_ok() || state_matches {
            return result;
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<String, String> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    while bytes.len() < 8192 {
        let count = stream
            .read(&mut buffer)
            .await
            .map_err(|_| "Callback read failed.".to_string())?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return String::from_utf8(bytes).map_err(|_| "Invalid callback encoding.".into());
        }
    }
    Err("Invalid callback request.".into())
}

async fn respond(stream: &mut TcpStream, ok: bool) -> std::io::Result<()> {
    let status = if ok { "200 OK" } else { "400 Bad Request" };
    let body = if ok {
        "Authorization received. Return to Coucou to check whether sign-in completed."
    } else {
        "This sign-in callback could not be accepted. Return to Coucou."
    };
    let response = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n{body}", body.len());
    tokio::time::timeout(
        Duration::from_secs(2),
        stream.write_all(response.as_bytes()),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Callback write timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_JWKS: &str = r#"{"keys":[{"kty":"RSA","n":"mXTn1DuGDOBw3Gs6fJiPjJ2DgUSQY5IxCQF4R69hem2N8zkFcsyDLowY-qBTha7ccK3b-WqS_-n7G6JHPKOJbE2f7B1YRp9ssW86E80WY79yQ1sRwbDiCK8DUNoXsG9KAUmgWC-6nv7NE660Q573Spdb4EpOq2T-7LS251Hhj5w_JBxWa8EIfFAJWJwAn-CqjVQCNLk8CRq3-uQBhvzXdlBWDMnnIdi7a6J2AX6LwiHXW81QWIcGQgLc4QXBiMcSJKl-2OhJ6mHo4ix2CxjihKWAkgwSj6Axx0Ntw8MyuBNhgqOkvU-Nod4_W3Bc2IEvaQvCTX7C7mf06PgdemYneQ","e":"AQAB","kid":"coucou-test-key","alg":"RS256","use":"sig"}]}"#;
    const TEST_ID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNvdWNvdS10ZXN0LWtleSJ9.eyJpc3MiOiJodHRwczovL2F1dGgub3BlbmFpLmNvbSIsImF1ZCI6ImNvdWNvdS10ZXN0LWNsaWVudCIsInN1YiI6InRlc3QtdXNlciIsIm5vbmNlIjoidGVzdC1ub25jZSIsImVtYWlsIjoidGVzdEBleGFtcGxlLmludmFsaWQiLCJleHAiOjQxMDI0NDQ4MDB9.V76pEmfxGjyAbg8_OpQ74GYq8aaSGRKCbDv60tGVK_UFmRspCoFmxDrDx93m-4bLx8ByeSb0TzOMEBhZu7f24Qq3hNlK88pMBNaHQRPwizYNNk-jPm1CDIZAYvD_JbN_71XFu-mzOcEAgCrw1xoREaWTvQDYr2Y_aY9255CLFL2MtysCbG8dmT1yfCc-3rQmoXKGr9Et28pC2txUu4za8a-pjqSthMrI3gE0jOk9J2T2OJi5nyb0fi5CLU7MIWCW4Gai8qG9UOy6rrHm9wG41Etws-bPlT-teYYaElw53as0rRb4bC0jwMrwGuuD3X9t35w19Up2OjKcLfduZXzMMw";

    fn attempt(client_id: Option<&str>) -> Attempt {
        Attempt {
            state: "test-state".into(),
            nonce: "test-nonce".into(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
            redirect_uri: "http://127.0.0.1:54321/auth/callback".into(),
            client_id: client_id.map(str::to_string),
        }
    }

    fn tokens() -> Tokens {
        Tokens {
            access_token: "test-access".into(),
            refresh_token: Some("test-refresh".into()),
            id_token: Some(TEST_ID_TOKEN.into()),
            token_type: "Bearer".into(),
            expires_in: 3600,
            scope: Some(SCOPES.into()),
        }
    }

    #[test]
    fn authorization_uses_pkce_and_stable_host_with_dynamic_registration() {
        let store = Store {
            host_id: "urn:uuid:test-host".into(),
            ..Store::default()
        };
        let url = authorization_url(&store, None, &attempt(None));
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], "dynamic_agent_client");
        assert_eq!(params["agent_name_hint"], "Coucou");
        assert_eq!(params["ext_agent_host_id"], "urn:uuid:test-host");
        assert_eq!(
            params["redirect_uri"],
            "http://127.0.0.1:54321/auth/callback"
        );
        assert_eq!(
            params["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(!params.contains_key("code_verifier"));
    }

    #[test]
    fn reauthorization_uses_issued_client_without_registration_name() {
        let url = authorization_url(&Store::default(), None, &attempt(Some("issued-client")));
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["client_id"], "issued-client");
        assert!(!params.contains_key("agent_name_hint"));
    }

    #[test]
    fn callback_requires_state_and_issued_client_and_rejects_duplicates() {
        let valid = "/auth/callback?state=test-state&code=test-code&client_id=issued-client";
        assert_eq!(
            parse_callback(valid, &attempt(None)).unwrap().client_id,
            "issued-client"
        );
        for target in [
            "/auth/callback?state=other&code=test-code&client_id=issued-client",
            "/auth/callback?state=test-state&code=test-code",
            "/auth/callback?state=test-state&code=test-code&client_id=dynamic_agent_client",
            "/auth/callback?state=test-state&state=other&code=test-code&client_id=issued-client",
            "/auth/callback?state=test-state&error=access_denied",
            "/callback?state=test-state&code=test-code&client_id=issued-client",
        ] {
            assert!(parse_callback(target, &attempt(None)).is_err());
        }
    }

    #[test]
    fn callback_reauthorization_reuses_client_and_refuses_switch() {
        let callback = parse_callback(
            "/auth/callback?state=test-state&code=test-code",
            &attempt(Some("issued-client")),
        )
        .unwrap();
        assert_eq!(callback.client_id, "issued-client");
        assert!(parse_callback(
            "/auth/callback?state=test-state&code=test-code&client_id=other",
            &attempt(Some("issued-client"))
        )
        .is_err());
    }

    #[test]
    fn signed_identity_requires_expected_audience_and_nonce() {
        let keys: JwkSet = serde_json::from_str(TEST_JWKS).unwrap();
        let claims = validate_identity(
            TEST_ID_TOKEN,
            &keys,
            "coucou-test-client",
            Some("test-nonce"),
        )
        .unwrap();
        assert_eq!(claims.sub, "test-user");
        assert!(
            validate_identity(TEST_ID_TOKEN, &keys, "other-client", Some("test-nonce")).is_err()
        );
        assert!(validate_identity(
            TEST_ID_TOKEN,
            &keys,
            "coucou-test-client",
            Some("other-nonce")
        )
        .is_err());
        let modified = TEST_ID_TOKEN.replace("V76p", "A76p");
        assert!(
            validate_identity(&modified, &keys, "coucou-test-client", Some("test-nonce")).is_err()
        );
    }

    #[test]
    fn plan_permission_is_required_and_secret_tokens_are_not_in_status() {
        let mut response = tokens();
        response.scope = Some("openid email".into());
        assert!(session_from(response, None).is_err());
        let session = session_from(tokens(), None).unwrap();
        let store = Store {
            active_client_id: Some("issued-client".into()),
            accounts: vec![Account {
                client_id: "issued-client".into(),
                subject: "test-user".into(),
                email: Some("test@example.invalid".into()),
                session: Some(session),
            }],
            ..Store::default()
        };
        let json = serde_json::to_string(&status_from(store, false, None)).unwrap();
        assert!(!json.contains("test-access"));
        assert!(!json.contains("test-refresh"));
        assert!(!json.contains(TEST_ID_TOKEN));
        assert!(json.contains("\"planEnabled\":true"));
    }

    #[test]
    fn refresh_rotates_tokens_and_retains_omitted_scope_and_identity() {
        let previous = session_from(tokens(), None).unwrap();
        let mut response = tokens();
        response.access_token = "new-access".into();
        response.refresh_token = Some("new-refresh".into());
        response.id_token = None;
        response.scope = None;
        let refreshed = session_from(response, Some(&previous)).unwrap();
        assert_eq!(refreshed.access_token, "new-access");
        assert_eq!(refreshed.refresh_token, "new-refresh");
        assert_eq!(refreshed.id_token, previous.id_token);
        assert_eq!(refreshed.scopes, previous.scopes);
    }

    #[tokio::test]
    async fn listener_ignores_unrelated_request_and_accepts_matching_callback() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let mut attempt = attempt(None);
        attempt.redirect_uri = format!("http://{address}/auth/callback");
        let server = tokio::spawn(async move { receive_callback(&listener, &attempt).await });
        for (state, expected_status) in [("unrelated", "400 Bad Request"), ("test-state", "200 OK")]
        {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(format!("GET /auth/callback?state={state}&code=test-code&client_id=issued-client HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()).await.unwrap();
            let mut response = String::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.contains(expected_status));
            assert!(!response.contains("test-code"));
        }
        let callback = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(callback.code, "test-code");
    }
}
