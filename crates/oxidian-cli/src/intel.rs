use oxidian_core::Config;
use oxidian_intel::{sync_feeds, DiskCache};

pub async fn sync(config: &Config) -> anyhow::Result<()> {
    let (kev, epss) = sync_feeds(
        &config.intel.kev_url,
        &config.intel.epss_url,
        config.intel.epss_limit,
    )
    .await?;
    let cache = DiskCache::open(&config.intel.cache_dir)?;
    cache.store_json("kev.json", &kev)?;
    cache.store_json("epss.json", &epss)?;
    println!(
        "synced {} KEV entries and {} EPSS scores",
        kev.len(),
        epss.len()
    );
    println!("NVD bulk sync is not part of v1; the client fetches one CVE at a time");
    Ok(())
}
