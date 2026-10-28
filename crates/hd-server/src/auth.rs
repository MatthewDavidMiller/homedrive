//! Accounts and authentication.
//!
//! **Accounts** come from the users file (a Podman secret), read once at
//! startup: `{"version":1,"users":[{"name","password","admin","quota_gb"}]}`
//! (`admin` and `quota_gb` optional). A
//! password is never kept: each is replaced at load by an HMAC under a
//! random key made for this process, and checked in constant time.
//! Removing someone from the file stops them signing in; their drive stays
//! untouched.
//!
//! **Devices** sign in with a token (`hd1_<id>_<secret>`), of which the
//! store keeps only SHA-256 of the secret. A token is accepted only while
//! its account is still in the users file.
//!
//! **Throttling**: past [`FAILURE_LIMIT`] failed sign-ins in
//! [`FAILURE_WINDOW`] from one client address, that address is refused
//! until the window passes. The address is the connection's, or the
//! right-most `X-Forwarded-For` entry when the connection comes from a
//! trusted proxy (Traefik).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hd_common::json::Value;
use hd_common::{Error, Result};
use hd_http::Request;
use hd_store::Store;
use hd_store::model::validate_user;

pub const MAX_USERS_FILE: usize = 1024 * 1024;
pub const MAX_USERS: usize = 50;
pub const FAILURE_LIMIT: usize = 10;
pub const FAILURE_WINDOW: Duration = Duration::from_mins(15);
const MAX_TRACKED_CLIENTS: usize = 10_000;

#[derive(Clone)]
pub struct Account {
    pub name: String,
    pub admin: bool,
    /// The most the drive may hold, in bytes (see
    /// `Namespace::stored_bytes`); `None` for no limit.
    pub quota: Option<u64>,
    /// HMAC of the password under the process key.
    check: [u8; 32],
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Account({}{})", self.name, if self.admin { ", admin" } else { "" })
    }
}

pub struct Accounts {
    key: [u8; 32],
    by_name: BTreeMap<String, Account>,
}

impl std::fmt::Debug for Accounts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.by_name.values()).finish()
    }
}

impl Drop for Accounts {
    fn drop(&mut self) {
        hd_crypto::cleanse(&mut self.key);
    }
}

fn password_check(key: &[u8; 32], password: &str) -> Result<[u8; 32]> {
    hd_crypto::hmac_sha256(key, password.as_bytes()).map_err(|_| Error::new("HMAC failed"))
}

impl Accounts {
    /// Parses and validates the users file. Any problem refuses the whole
    /// file: a server with half its accounts would lock people out.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let doc = hd_common::json::parse(bytes).map_err(|e| {
            Error::new(format!("the users file is not valid JSON: {}", e.message()))
        })?;
        if !doc.only_keys(&["version", "users"]) {
            return Err(Error::new("the users file has unknown fields"));
        }
        if doc.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(Error::new("the users file must say \"version\": 1"));
        }
        let list = doc
            .get("users")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::new("the users file needs a \"users\" list"))?;
        if list.is_empty() || list.len() > MAX_USERS {
            return Err(Error::new(format!("the users file must list 1 to {MAX_USERS} accounts")));
        }
        let key = hd_crypto::random_array::<32>().map_err(|_| Error::new("randomness failed"))?;
        let mut by_name = BTreeMap::new();
        for (i, u) in list.iter().enumerate() {
            let n = i + 1;
            if !u.only_keys(&["name", "password", "admin", "quota_gb"]) {
                return Err(Error::new(format!("account {n} has unknown fields")));
            }
            let name = u.get("name").and_then(Value::as_str).unwrap_or("");
            validate_user(name).map_err(|_| {
                Error::new(format!("account {n}: names are 1-64 of A-Z a-z 0-9 . _ -"))
            })?;
            let password = u.get("password").and_then(Value::as_str).unwrap_or("");
            let chars = password.chars().count();
            if !(8..=128).contains(&chars) {
                return Err(Error::new(format!("account {name}: passwords are 8-128 characters")));
            }
            let admin = match u.get("admin") {
                None => false,
                Some(v) => v.as_bool().ok_or_else(|| {
                    Error::new(format!("account {name}: admin must be true or false"))
                })?,
            };
            let quota = match u.get("quota_gb") {
                None => None,
                Some(v) => Some(
                    v.as_u64().filter(|g| (1..=1_000_000).contains(g)).ok_or_else(|| {
                        Error::new(format!(
                            "account {name}: quota_gb is a whole number of GiB, 1 to 1000000"
                        ))
                    })? << 30,
                ),
            };
            let account = Account {
                name: name.to_owned(),
                admin,
                quota,
                check: password_check(&key, password)?,
            };
            if by_name.insert(name.to_owned(), account).is_some() {
                return Err(Error::new(format!("account {name} is listed twice")));
            }
        }
        if !by_name.values().any(|a| a.admin) {
            return Err(Error::new("the users file needs at least one admin"));
        }
        Ok(Self { key, by_name })
    }

    pub fn get(&self, name: &str) -> Option<&Account> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> impl Iterator<Item = &String> {
        self.by_name.keys()
    }

    /// The account, if `password` is right. An unknown name costs the same
    /// as a wrong password.
    pub fn verify_password(&self, name: &str, password: &str) -> Option<&Account> {
        let given = password_check(&self.key, password).ok()?;
        if let Some(a) = self.by_name.get(name) {
            hd_crypto::ct_equal(&a.check, &given).then_some(a)
        } else {
            let dummy = [0_u8; 32];
            let _ = hd_crypto::ct_equal(&dummy, &given);
            None
        }
    }
}

/// Who a request is from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Who {
    pub user: String,
    pub admin: bool,
    /// Set when signed in with a device token.
    pub device: Option<(u64, String)>,
}

impl Who {
    /// The name recorded on versions this request makes.
    pub fn device_name(&self) -> String {
        self.device.as_ref().map_or_else(|| "web".to_owned(), |(_, n)| n.clone())
    }
}

/// Checks a device token against the store and the accounts.
pub fn verify_token(store: &Store, accounts: &Accounts, token: &str) -> Option<Who> {
    let (device_id, secret) = hd_api::parse_token(token)?;
    let hash = hd_crypto::sha256(&secret).ok()?;
    let (user, name) = store.read(|state| {
        state.users.iter().find_map(|(user, ns)| {
            let d = ns.device(device_id)?;
            hd_crypto::ct_equal(&d.token_hash, &hash).then(|| (user.clone(), d.name.clone()))
        })
    })?;
    let account = accounts.get(&user)?;
    Some(Who { user, admin: account.admin, device: Some((device_id, name)) })
}

/// The user and password of a Basic `Authorization` header.
pub fn basic_credentials(request: &Request<'_, '_>) -> Option<(String, String)> {
    let value = request.header("authorization")?;
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = hd_common::base64::decode(encoded.trim().as_bytes())?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    Some((user.to_owned(), password.to_owned()))
}

pub fn bearer_token<'r>(request: &'r Request<'_, '_>) -> Option<&'r str> {
    let value = request.header("authorization")?;
    let (scheme, token) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
}

/// Basic credentials, where the password may also be one of the user's
/// device tokens (rclone and phone apps store a token, not the password).
pub fn verify_basic(store: &Store, accounts: &Accounts, user: &str, password: &str) -> Option<Who> {
    if password.starts_with("hd1_") {
        return verify_token(store, accounts, password).filter(|w| w.user == user);
    }
    let account = accounts.verify_password(user, password)?;
    Some(Who { user: account.name.clone(), admin: account.admin, device: None })
}

/// The address requests are throttled by.
pub fn client_ip(request: &Request<'_, '_>, trusted: &[IpAddr]) -> IpAddr {
    if trusted.contains(&request.peer)
        && let Some(forwarded) = request.header("x-forwarded-for")
        && let Some(last) = forwarded.rsplit(',').next()
        && let Ok(ip) = last.trim().parse()
    {
        return ip;
    }
    request.peer
}

/// Failed sign-ins per client address over a sliding window.
#[derive(Debug)]
pub struct Throttle {
    limit: usize,
    window: Duration,
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl Throttle {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self { limit, window, failures: Mutex::new(HashMap::new()) }
    }

    /// Whether `ip` is refused for now.
    pub fn blocked(&self, ip: IpAddr) -> bool {
        let mut map = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let Some(q) = map.get_mut(&ip) else { return false };
        while q.front().is_some_and(|t| now.duration_since(*t) > self.window) {
            q.pop_front();
        }
        q.len() >= self.limit
    }

    pub fn fail(&self, ip: IpAddr) {
        let mut map = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        if map.len() >= MAX_TRACKED_CLIENTS && !map.contains_key(&ip) {
            let window = self.window;
            map.retain(|_, q| q.back().is_some_and(|t| now.duration_since(*t) <= window));
            if map.len() >= MAX_TRACKED_CLIENTS {
                return;
            }
        }
        let q = map.entry(ip).or_default();
        q.push_back(now);
        while q.len() > self.limit {
            q.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(users: &str) -> String {
        format!(r#"{{"version":1,"users":[{users}]}}"#)
    }

    #[test]
    fn users_files_are_validated_whole() {
        let ok = file(
            r#"{"name":"alice","password":"correct horse","admin":true},{"name":"bob","password":"battery staple"}"#,
        );
        let a = Accounts::parse(ok.as_bytes()).unwrap();
        assert!(a.verify_password("alice", "correct horse").unwrap().admin);
        assert!(!a.verify_password("bob", "battery staple").unwrap().admin);
        assert!(a.verify_password("alice", "battery staple").is_none());
        assert!(a.verify_password("carol", "anything at all").is_none());
        assert!(!format!("{a:?}").contains("horse"));
        assert_eq!(a.get("alice").unwrap().quota, None);
        let q = file(r#"{"name":"alice","password":"long enough","admin":true,"quota_gb":5}"#);
        assert_eq!(
            Accounts::parse(q.as_bytes()).unwrap().get("alice").unwrap().quota,
            Some(5 << 30)
        );
        for bad in [
            file(r#"{"name":"alice","password":"short","admin":true}"#),
            file(r#"{"name":"al ice","password":"long enough","admin":true}"#),
            file(r#"{"name":"alice","password":"long enough"}"#),
            file(
                r#"{"name":"a","password":"long enough","admin":true},{"name":"a","password":"long enough"}"#,
            ),
            file(r#"{"name":"alice","password":"long enough","admin":"yes"}"#),
            file(r#"{"name":"alice","password":"long enough","admin":true,"x":1}"#),
            file(r#"{"name":"alice","password":"long enough","admin":true,"quota_gb":0}"#),
            file(r#"{"name":"alice","password":"long enough","admin":true,"quota_gb":"5"}"#),
            file(""),
            r#"{"version":2,"users":[]}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert!(Accounts::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn throttling() {
        let t = Throttle::new(3, Duration::from_secs(60));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 {
            assert!(!t.blocked(ip));
            t.fail(ip);
        }
        assert!(t.blocked(ip));
        assert!(!t.blocked(other));
        let quick = Throttle::new(1, Duration::from_millis(1));
        quick.fail(ip);
        std::thread::sleep(Duration::from_millis(5));
        assert!(!quick.blocked(ip));
    }
}
