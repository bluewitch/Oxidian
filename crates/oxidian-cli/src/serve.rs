use std::net::SocketAddr;
use std::sync::Arc;

use oxidian_api::AppState;
use oxidian_core::{Config, Inventory};
use oxidian_store::Store;

pub async fn run(config: &Config) -> anyhow::Result<()> {
    let token = std::env::var("OXIDIAN_API_TOKEN")
        .map_err(|_| anyhow::anyhow!("OXIDIAN_API_TOKEN is not set"))?;
    let database = std::env::var("OXIDIAN_DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("OXIDIAN_DATABASE_URL is not set"))?;
    if database.trim().is_empty() {
        anyhow::bail!("OXIDIAN_DATABASE_URL is not set");
    }
    let store = Store::connect(database.trim()).await?;
    store.migrate().await?;
    let inventory: Arc<dyn Inventory> = Arc::new(store);
    let state = AppState::new(token, inventory)?;
    let bind: SocketAddr = config
        .api
        .bind
        .parse()
        .map_err(|_| anyhow::anyhow!("api.bind is not a socket address"))?;
    oxidian_api::serve(state, bind).await?;
    Ok(())
}
