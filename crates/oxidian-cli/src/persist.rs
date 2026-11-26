use oxidian_core::{Asset, Finding, Service};
use oxidian_store::Store;
use uuid::Uuid;

pub async fn store_assets(assets: &[Asset]) -> anyhow::Result<()> {
    let Some(url) = database_url() else {
        return Ok(());
    };
    let store = Store::connect(&url).await?;
    store.migrate().await?;
    for asset in assets {
        store.record_asset(asset).await?;
    }
    Ok(())
}

pub async fn store_services(services: &[Service]) -> anyhow::Result<Vec<(Uuid, Service)>> {
    let Some(url) = database_url() else {
        return Ok(Vec::new());
    };
    let store = Store::connect(&url).await?;
    store.migrate().await?;
    let mut stored = Vec::with_capacity(services.len());
    for service in services {
        let id = store.record_service(service).await?;
        stored.push((id, service.clone()));
    }
    Ok(stored)
}

pub async fn store_findings(pairs: &[(Uuid, &Finding)]) -> anyhow::Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let Some(url) = database_url() else {
        return Ok(());
    };
    let store = Store::connect(&url).await?;
    store.migrate().await?;
    for (service_id, finding) in pairs {
        store.record_finding(*service_id, finding).await?;
    }
    Ok(())
}

fn database_url() -> Option<String> {
    std::env::var("OXIDIAN_DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}
