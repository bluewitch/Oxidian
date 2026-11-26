use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{Error, Result};

/// JSON documents stored under one directory. Keys are single filenames.
pub struct DiskCache {
    root: PathBuf,
}

impl DiskCache {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        if root
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(Error::Cache);
        }
        std::fs::create_dir_all(&root).map_err(|_| Error::Cache)?;
        Ok(Self { root })
    }

    pub fn store_json<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let path = self.path(name)?;
        let bytes = serde_json::to_vec_pretty(value).map_err(|_| Error::Parse)?;
        std::fs::write(path, bytes).map_err(|_| Error::Cache)
    }

    pub fn load_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        let path = self.path(name)?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(path).map_err(|_| Error::Cache)?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Error::Parse)
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if !safe_key(name) {
            return Err(Error::Cache);
        }
        Ok(self.root.join(name))
    }
}

fn safe_key(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && Path::new(name).components().count() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Sample {
        ok: bool,
    }

    #[test]
    fn round_trip_and_reject_traversal() {
        let dir = std::env::temp_dir().join(format!("oxidian-cache-{}", std::process::id()));
        let cache = DiskCache::open(&dir).unwrap();
        cache.store_json("kev.json", &Sample { ok: true }).unwrap();
        let loaded: Sample = cache.load_json("kev.json").unwrap().unwrap();
        assert_eq!(loaded, Sample { ok: true });
        assert!(cache.load_json::<Sample>("missing.json").unwrap().is_none());
        assert!(cache
            .store_json("../kev.json", &Sample { ok: true })
            .is_err());
        assert!(cache.store_json("a/b.json", &Sample { ok: true }).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
