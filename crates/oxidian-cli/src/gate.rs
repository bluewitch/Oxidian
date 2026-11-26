use std::path::Path;

use oxidian_core::{Allowlist, Config};

pub fn load(path: &Path) -> anyhow::Result<(Config, Allowlist)> {
    let config = Config::from_path(path)?;
    let allow = config.allowlist()?;
    Ok((config, allow))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_is_authorized() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/lab.toml");
        let (config, allow) = load(&path).unwrap();
        assert_eq!(config.project.name, "lab");
        assert!(allow.admits_domain("www.example.com"));
        assert!(allow.admits("192.0.2.10"));
    }

    #[test]
    fn empty_allowlist_refuses_to_run() {
        let dir = std::env::temp_dir().join(format!("oxidian-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("empty.toml");
        std::fs::write(
            &path,
            "[project]\nname = \"lab\"\n[allowlist]\ndomains = []\ncidrs = []\n",
        )
        .unwrap();
        let err = load(&path).unwrap_err();
        assert!(err.to_string().contains("allowlist"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_refuses_to_run() {
        let err = load(Path::new("/tmp/oxidian-missing-config.toml")).unwrap_err();
        assert!(err.to_string().contains("config"));
    }
}
