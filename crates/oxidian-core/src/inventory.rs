use async_trait::async_trait;

use crate::error::InventoryError;
use crate::model::{Asset, Finding};

/// Read-only view of the inventory used by the API.
#[async_trait]
pub trait Inventory: Send + Sync {
    async fn list_assets(&self) -> Result<Vec<Asset>, InventoryError>;
    async fn list_findings(&self) -> Result<Vec<Finding>, InventoryError>;
}
