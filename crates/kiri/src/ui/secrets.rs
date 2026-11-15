//! Passwords the window keeps for servers (remote.rs), where the person
//! chose: the system's own store (the Mac's Keychain, Secret Service on
//! Linux), or Kiri's encrypted file.
//!
//! The file is ~/.kiri/secrets.enc: each secret sealed with AES-256-GCM
//! under a random key in ~/.kiri/secrets.key, both readable by this account
//! only. That keeps passwords out of servers.json, backups and screenshares
//! of the folder; anyone who can read the account's files can read both, so
//! the system's store is the stronger choice and the default.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

/// Where a secret is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    System,
    File,
}

impl Store {
    pub fn parse(s: &str) -> Option<Store> {
        match s {
            "keychain" | "system" => Some(Store::System),
            "file" => Some(Store::File),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Store::System => "keychain",
            Store::File => "file",
        }
    }
}

/// The service name items are kept under in the system's store.
const SERVICE: &str = "Kiri SSH";

pub fn save(store: Store, account: &str, secret: &str) -> io::Result<()> {
    match store {
        Store::System => os::set(account, secret),
        Store::File => file::set(account, Some(secret)),
    }
}

pub fn load(store: Store, account: &str) -> Option<String> {
    match store {
        Store::System => os::get(account),
        Store::File => file::get(account),
    }
}

/// Forgets `account` in both stores.
pub fn delete(account: &str) {
    os::delete(account);
    let _ = file::set(account, None);
}

/// A test's own folder, so tests running together don't share one.
#[cfg(test)]
static TEST_DIR: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

fn dir() -> io::Result<PathBuf> {
    #[cfg(test)]
    if let Some(d) = TEST_DIR.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Ok(d);
    }
    super::state_dir().ok_or_else(|| io::Error::other("HOME is not set"))
}

mod file {
    use super::*;
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};

    fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?.write_all(bytes)?;
        }
        #[cfg(not(unix))]
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(tmp, path)
    }

    /// The file's key, made the first time a secret is kept.
    fn key(make: bool) -> io::Result<Option<LessSafeKey>> {
        let path = dir()?.join("secrets.key");
        let raw = match std::fs::read(&path) {
            Ok(b) if b.len() == 32 => b,
            Ok(_) => return Err(io::Error::other("~/.kiri/secrets.key is damaged")),
            Err(e) if e.kind() == io::ErrorKind::NotFound && make => {
                let mut b = vec![0u8; 32];
                SystemRandom::new().fill(&mut b).map_err(|_| io::Error::other("no randomness"))?;
                std::fs::create_dir_all(dir()?)?;
                write_private(&path, &b)?;
                b
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let k = UnboundKey::new(&AES_256_GCM, &raw).map_err(|_| io::Error::other("bad key"))?;
        Ok(Some(LessSafeKey::new(k)))
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Option<Vec<u8>> {
        (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect()
    }

    fn all() -> BTreeMap<String, String> {
        dir().ok().and_then(|d| std::fs::read(d.join("secrets.enc")).ok()).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// Each secret is sealed with its account as associated data, so one
    /// can't be moved under another's name.
    pub fn set(account: &str, secret: Option<&str>) -> io::Result<()> {
        let mut map = all();
        match secret {
            None => {
                if map.remove(account).is_none() {
                    return Ok(());
                }
            }
            Some(s) => {
                let key = key(true)?.ok_or_else(|| io::Error::other("no key"))?;
                let mut nonce = [0u8; NONCE_LEN];
                SystemRandom::new().fill(&mut nonce).map_err(|_| io::Error::other("no randomness"))?;
                let mut sealed = s.as_bytes().to_vec();
                key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(account.as_bytes()), &mut sealed)
                    .map_err(|_| io::Error::other("couldn't encrypt"))?;
                map.insert(account.to_owned(), format!("{}{}", hex(&nonce), hex(&sealed)));
            }
        }
        write_private(&dir()?.join("secrets.enc"), &serde_json::to_vec_pretty(&map)?)
    }

    pub fn get(account: &str) -> Option<String> {
        let raw = unhex(all().get(account)?)?;
        if raw.len() < NONCE_LEN {
            return None;
        }
        let key = key(false).ok()??;
        let (nonce, sealed) = raw.split_at(NONCE_LEN);
        let mut buf = sealed.to_vec();
        let open = key.open_in_place(Nonce::try_assume_unique_for_key(nonce).ok()?, Aad::from(account.as_bytes()), &mut buf).ok()?;
        String::from_utf8(open.to_vec()).ok()
    }
}

/// The login keychain: a generic password per account, under "Kiri SSH",
/// through the Security framework's item calls (as logins.rs keeps registry
/// sign-ins), so Keychain Access lists them by that name.
#[cfg(target_os = "macos")]
mod os {
    use std::ffi::c_void;
    use std::io;
    use std::ptr::null;

    use super::SERVICE;

    type Ref = *const c_void;
    const UTF8: u32 = 0x0800_0100;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: u8;
        static kCFTypeDictionaryValueCallBacks: u8;
        static kCFBooleanTrue: Ref;
        fn CFDictionaryCreate(alloc: Ref, keys: *const Ref, values: *const Ref, n: isize, kcb: *const u8, vcb: *const u8) -> Ref;
        fn CFStringCreateWithBytes(alloc: Ref, bytes: *const u8, n: isize, encoding: u32, external: u8) -> Ref;
        fn CFDataCreate(alloc: Ref, bytes: *const u8, n: isize) -> Ref;
        fn CFDataGetLength(d: Ref) -> isize;
        fn CFDataGetBytePtr(d: Ref) -> *const u8;
        fn CFGetTypeID(r: Ref) -> usize;
        fn CFDataGetTypeID() -> usize;
        fn CFRelease(r: Ref);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecClass: Ref;
        static kSecClassGenericPassword: Ref;
        static kSecAttrService: Ref;
        static kSecAttrAccount: Ref;
        static kSecAttrLabel: Ref;
        static kSecValueData: Ref;
        static kSecReturnData: Ref;
        static kSecMatchLimit: Ref;
        static kSecMatchLimitOne: Ref;
        fn SecItemAdd(attributes: Ref, result: *mut Ref) -> i32;
        fn SecItemCopyMatching(query: Ref, result: *mut Ref) -> i32;
        fn SecItemDelete(query: Ref) -> i32;
    }

    struct Cf(Ref);

    impl Drop for Cf {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: an object this code created or was given to own.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn string(s: &str) -> Cf {
        // SAFETY: the bytes and their length, UTF-8.
        Cf(unsafe { CFStringCreateWithBytes(null(), s.as_ptr(), s.len() as isize, UTF8, 0) })
    }

    fn data(b: &[u8]) -> Cf {
        // SAFETY: the bytes and their length; CFData copies them.
        Cf(unsafe { CFDataCreate(null(), b.as_ptr(), b.len() as isize) })
    }

    fn dict(pairs: &[(Ref, Ref)]) -> Cf {
        let keys: Vec<Ref> = pairs.iter().map(|p| p.0).collect();
        let values: Vec<Ref> = pairs.iter().map(|p| p.1).collect();
        // SAFETY: two arrays of n CF objects, with the CFType callbacks.
        Cf(unsafe {
            CFDictionaryCreate(null(), keys.as_ptr(), values.as_ptr(), pairs.len() as isize, &raw const kCFTypeDictionaryKeyCallBacks, &raw const kCFTypeDictionaryValueCallBacks)
        })
    }

    /// The item's identity: the service and the account.
    fn base(service: &Cf, account: &Cf) -> Vec<(Ref, Ref)> {
        // SAFETY: reading the framework's constant keys.
        unsafe { vec![(kSecClass, kSecClassGenericPassword), (kSecAttrService, service.0), (kSecAttrAccount, account.0)] }
    }

    pub fn get(account: &str) -> Option<String> {
        let (service, acct) = (string(SERVICE), string(account));
        let mut pairs = base(&service, &acct);
        // SAFETY: reading the framework's constant keys.
        pairs.extend(unsafe { [(kSecReturnData, kCFBooleanTrue), (kSecMatchLimit, kSecMatchLimitOne)] });
        let query = dict(&pairs);
        let mut out: Ref = null();
        // SAFETY: a query dictionary and a place for the result, which we then own.
        if unsafe { SecItemCopyMatching(query.0, &mut out) } != 0 {
            return None;
        }
        let out = Cf(out);
        // SAFETY: type-checked before use as a CFData.
        unsafe {
            if out.0.is_null() || CFGetTypeID(out.0) != CFDataGetTypeID() {
                return None;
            }
            let n = CFDataGetLength(out.0) as usize;
            String::from_utf8(std::slice::from_raw_parts(CFDataGetBytePtr(out.0), n).to_vec()).ok()
        }
    }

    pub fn set(account: &str, secret: &str) -> io::Result<()> {
        delete(account);
        let (service, acct, label, value) = (string(SERVICE), string(account), string(&format!("{SERVICE} ({account})")), data(secret.as_bytes()));
        let mut pairs = base(&service, &acct);
        // SAFETY: reading the framework's constant keys.
        pairs.extend(unsafe { [(kSecAttrLabel, label.0), (kSecValueData, value.0)] });
        let attrs = dict(&pairs);
        // SAFETY: an attributes dictionary; no result asked for.
        match unsafe { SecItemAdd(attrs.0, std::ptr::null_mut()) } {
            0 => Ok(()),
            s => Err(io::Error::other(format!("the Keychain refused it (error {s})"))),
        }
    }

    pub fn delete(account: &str) {
        let (service, acct) = (string(SERVICE), string(account));
        let query = dict(&base(&service, &acct));
        // SAFETY: a query dictionary.
        unsafe { SecItemDelete(query.0) };
    }
}

/// Linux: the desktop's Secret Service (GNOME Keyring, KWallet), through
/// `secret-tool`, the secret on its standard input, never in its arguments.
#[cfg(not(target_os = "macos"))]
mod os {
    use std::io::{self, Write};
    use std::process::{Command, Stdio};

    use super::SERVICE;

    pub fn get(account: &str) -> Option<String> {
        let out = Command::new("secret-tool").args(["lookup", "service", SERVICE, "account", account]).stderr(Stdio::null()).output().ok()?;
        out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim_end_matches('\n').to_owned()).filter(|s| !s.is_empty())
    }

    pub fn set(account: &str, secret: &str) -> io::Result<()> {
        let mut child = Command::new("secret-tool")
            .args(["store", "--label", &format!("{SERVICE} ({account})"), "service", SERVICE, "account", account])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| if e.kind() == io::ErrorKind::NotFound { io::Error::other("secret-tool isn't installed (package libsecret-tools)") } else { e })?;
        child.stdin.take().ok_or_else(|| io::Error::other("no stdin"))?.write_all(secret.as_bytes())?;
        let out = child.wait_with_output()?;
        if out.status.success() { Ok(()) } else { Err(io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_owned())) }
    }

    pub fn delete(account: &str) {
        let _ = Command::new("secret-tool").args(["clear", "service", SERVICE, "account", account]).stderr(Stdio::null()).status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_keeps_secrets_sealed_and_bound_to_their_account() {
        let dir = std::env::temp_dir().join(format!("kiri-secrets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        *TEST_DIR.lock().unwrap() = Some(dir.clone());
        save(Store::File, "s1", "hunter2 ü").unwrap();
        save(Store::File, "s1:jump", "other").unwrap();
        assert_eq!(load(Store::File, "s1").as_deref(), Some("hunter2 ü"));
        assert_eq!(load(Store::File, "s1:jump").as_deref(), Some("other"));
        let on_disk = std::fs::read_to_string(dir.join("secrets.enc")).unwrap();
        assert!(!on_disk.contains("hunter2"));
        // A sealed secret moved under another account doesn't open.
        let mut map: BTreeMap<String, String> = serde_json::from_str(&on_disk).unwrap();
        let moved = map["s1"].clone();
        map.insert("s2".into(), moved);
        std::fs::write(dir.join("secrets.enc"), serde_json::to_vec(&map).unwrap()).unwrap();
        assert_eq!(load(Store::File, "s2"), None);
        #[cfg(unix)]
        assert_eq!(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(dir.join("secrets.key")).unwrap().permissions()) & 0o777, 0o600);
        file::set("s1", None).unwrap();
        assert_eq!(load(Store::File, "s1"), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
