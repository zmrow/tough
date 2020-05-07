use crate::error::{self, Result};
use crate::key_source::KeySource;
use crate::schema::decoded::{Decoded, Hex};
use crate::schema::{Root, Signed};
use crate::sign::Sign;
use ring::digest::{SHA256, SHA256_OUTPUT_LEN};
use snafu::ensure;
use snafu::ResultExt;
use std::collections::HashMap;
use std::path::PathBuf;

pub type RootKeys = HashMap<Decoded<Hex>, Box<dyn Sign>>;

/// Represents a loaded root.json file along with its sha256 digest and size in bytes
#[derive(Debug)]
pub struct RootDigest {
    /// The loaded Root object
    pub root: Root,
    /// The sha256 digest of the root.json file
    pub digest: [u8; SHA256_OUTPUT_LEN],
    /// The size (in bytes) of the root.json
    pub size: u64,
}

impl RootDigest {
    /// Constructs a `RootDigest` object by parsing a `root.json` file
    pub fn load(path: &PathBuf) -> Result<Self> {
        let root_buf = std::fs::read(path).context(error::FileRead { path })?;
        let root = serde_json::from_slice::<Signed<Root>>(&root_buf)
            .context(error::FileParseJson { path })?
            .signed;
        let mut digest = [0; SHA256_OUTPUT_LEN];
        digest.copy_from_slice(ring::digest::digest(&SHA256, &root_buf).as_ref());
        let size = root_buf.len() as u64;
        Ok(RootDigest { root, digest, size })
    }

    /// Searches `KeySources` to match them with the keys that are designated in the `root.json`
    /// file.
    pub fn load_keys(&self, keys: &[Box<dyn KeySource>]) -> Result<RootKeys> {
        let mut map = HashMap::new();
        for source in keys {
            let key_pair = source.as_sign().context(error::KeyPairFromKeySource)?;
            if let Some((keyid, _)) = self
                .root
                .keys
                .iter()
                .find(|(_, key)| key_pair.tuf_key() == **key)
            {
                map.insert(keyid.clone(), key_pair);
            }
        }
        ensure!(!map.is_empty(), error::KeysNotFoundInRoot {});
        Ok(map)
    }
}
