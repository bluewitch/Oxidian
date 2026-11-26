//! Postgres inventory. Queries are runtime-checked so the crate builds
//! without a live database.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::str::FromStr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use oxidian_core::{
    Asset, AssetKind, Finding, Inventory, InventoryError, Protocol, Service, Severity,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

/// A database call failed. Messages never include a connection URL.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database request failed")]
    Database,
    #[error("stored row could not be read")]
    BadRow,
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Store {
    pool: sqlx::PgPool,
}

impl Store {
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect(database_url)
            .await
            .map_err(hide)?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|_| Error::Database)
    }

    pub async fn record_asset(&self, asset: &Asset) -> Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO assets (id, name, kind, address, source, first_seen, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (name, kind, address)
            DO UPDATE SET source = EXCLUDED.source, last_seen = EXCLUDED.last_seen
            RETURNING id
            "#,
        )
        .bind(asset.id)
        .bind(&asset.name)
        .bind(asset.kind.as_str())
        .bind(address_text(asset.address))
        .bind(&asset.source)
        .bind(asset.first_seen)
        .bind(asset.last_seen)
        .fetch_one(&self.pool)
        .await
        .map_err(hide)?;
        Ok(id)
    }

    pub async fn record_service(&self, service: &Service) -> Result<Uuid> {
        let asset = asset_for_service(service);
        let asset_id = self.record_asset(&asset).await?;
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO services (
                id, asset_id, port, protocol, product, version, banner, observed_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (asset_id, port, protocol)
            DO UPDATE SET
                product = EXCLUDED.product,
                version = EXCLUDED.version,
                banner = EXCLUDED.banner,
                observed_at = EXCLUDED.observed_at
            RETURNING id
            "#,
        )
        .bind(service.id)
        .bind(asset_id)
        .bind(i32::from(service.port))
        .bind(service.protocol.as_str())
        .bind(&service.product)
        .bind(&service.version)
        .bind(&service.banner)
        .bind(service.observed_at)
        .fetch_one(&self.pool)
        .await
        .map_err(hide)?;
        Ok(id)
    }

    pub async fn record_finding(&self, service_id: Uuid, finding: &Finding) -> Result<Uuid> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO findings (
                id, service_id, cve_id, asset_name, address, port, protocol, product, version,
                severity, kev, epss, cvss, rank_score, summary, created_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16
            )
            ON CONFLICT (service_id, cve_id)
            DO UPDATE SET
                severity = EXCLUDED.severity,
                kev = EXCLUDED.kev,
                epss = EXCLUDED.epss,
                cvss = EXCLUDED.cvss,
                rank_score = EXCLUDED.rank_score,
                summary = EXCLUDED.summary
            RETURNING id
            "#,
        )
        .bind(finding.id)
        .bind(service_id)
        .bind(&finding.cve_id)
        .bind(&finding.asset_name)
        .bind(address_text(finding.address))
        .bind(i32::from(finding.port))
        .bind(finding.protocol.as_str())
        .bind(&finding.product)
        .bind(&finding.version)
        .bind(finding.severity.as_str())
        .bind(finding.kev)
        .bind(finding.epss)
        .bind(finding.cvss)
        .bind(finding.rank_score)
        .bind(&finding.summary)
        .bind(finding.created_at)
        .fetch_one(&self.pool)
        .await
        .map_err(hide)?;
        Ok(id)
    }

    pub async fn fetch_assets(&self) -> Result<Vec<Asset>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, kind, address, source, first_seen, last_seen
            FROM assets
            ORDER BY name, kind, address
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(hide)?;
        rows.iter().map(asset_from_row).collect()
    }

    pub async fn fetch_findings(&self) -> Result<Vec<Finding>> {
        let rows = sqlx::query(
            r#"
            SELECT id, cve_id, asset_name, address, port, protocol, product, version,
                   severity, kev, epss, cvss, rank_score, summary, created_at
            FROM findings
            ORDER BY rank_score DESC, cve_id, asset_name, port
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(hide)?;
        rows.iter().map(finding_from_row).collect()
    }
}

#[async_trait]
impl Inventory for Store {
    async fn list_assets(&self) -> std::result::Result<Vec<Asset>, InventoryError> {
        self.fetch_assets().await.map_err(InventoryError::from)
    }

    async fn list_findings(&self) -> std::result::Result<Vec<Finding>, InventoryError> {
        self.fetch_findings().await.map_err(InventoryError::from)
    }
}

impl From<Error> for InventoryError {
    fn from(err: Error) -> Self {
        InventoryError::new(err.to_string())
    }
}

fn hide(_err: sqlx::Error) -> Error {
    Error::Database
}

fn address_text(address: Option<IpAddr>) -> String {
    address.map(|ip| ip.to_string()).unwrap_or_default()
}

fn parse_address(text: &str) -> Result<Option<IpAddr>> {
    if text.is_empty() {
        Ok(None)
    } else {
        text.parse::<IpAddr>().map(Some).map_err(|_| Error::BadRow)
    }
}

fn asset_for_service(service: &Service) -> Asset {
    match (service.address, service.asset_name.parse::<IpAddr>().ok()) {
        (Some(address), Some(_)) | (Some(address), None) if service.asset_name.is_empty() => {
            Asset::address(address, "scan")
        }
        (Some(address), Some(parsed)) if parsed == address => Asset::address(address, "scan"),
        (Some(address), _) => Asset::host(service.asset_name.clone(), address, "scan"),
        (None, _) => Asset::domain(service.asset_name.clone(), "scan"),
    }
}

fn asset_from_row(row: &sqlx::postgres::PgRow) -> Result<Asset> {
    let kind: String = row.try_get("kind").map_err(|_| Error::BadRow)?;
    let address: String = row.try_get("address").map_err(|_| Error::BadRow)?;
    Ok(Asset {
        id: row.try_get("id").map_err(|_| Error::BadRow)?,
        name: row.try_get("name").map_err(|_| Error::BadRow)?,
        kind: AssetKind::from_str(&kind).map_err(|_| Error::BadRow)?,
        address: parse_address(&address)?,
        source: row.try_get("source").map_err(|_| Error::BadRow)?,
        first_seen: row.try_get("first_seen").map_err(|_| Error::BadRow)?,
        last_seen: row.try_get("last_seen").map_err(|_| Error::BadRow)?,
    })
}

fn finding_from_row(row: &sqlx::postgres::PgRow) -> Result<Finding> {
    let protocol: String = row.try_get("protocol").map_err(|_| Error::BadRow)?;
    let severity: String = row.try_get("severity").map_err(|_| Error::BadRow)?;
    let address: String = row.try_get("address").map_err(|_| Error::BadRow)?;
    let port: i32 = row.try_get("port").map_err(|_| Error::BadRow)?;
    let port = u16::try_from(port).map_err(|_| Error::BadRow)?;
    Ok(Finding {
        id: row.try_get("id").map_err(|_| Error::BadRow)?,
        cve_id: row.try_get("cve_id").map_err(|_| Error::BadRow)?,
        asset_name: row.try_get("asset_name").map_err(|_| Error::BadRow)?,
        address: parse_address(&address)?,
        port,
        protocol: Protocol::parse(&protocol).ok_or(Error::BadRow)?,
        product: row.try_get("product").map_err(|_| Error::BadRow)?,
        version: row.try_get("version").map_err(|_| Error::BadRow)?,
        severity: Severity::from_str(&severity).map_err(|_| Error::BadRow)?,
        kev: row.try_get("kev").map_err(|_| Error::BadRow)?,
        epss: row.try_get("epss").map_err(|_| Error::BadRow)?,
        cvss: row.try_get("cvss").map_err(|_| Error::BadRow)?,
        rank_score: row.try_get("rank_score").map_err(|_| Error::BadRow)?,
        summary: row.try_get("summary").map_err(|_| Error::BadRow)?,
        created_at: row
            .try_get::<DateTime<Utc>, _>("created_at")
            .map_err(|_| Error::BadRow)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_declares_the_inventory_tables() {
        let sql = include_str!("../migrations/0001_init.sql");
        assert!(sql.contains("CREATE TABLE assets"));
        assert!(sql.contains("CREATE TABLE services"));
        assert!(sql.contains("CREATE TABLE findings"));
        assert!(sql.contains("ON DELETE CASCADE"));
        let _embedded = sqlx::migrate!("./migrations");
    }

    #[test]
    fn service_with_a_name_becomes_a_host_asset() {
        let service = Service::observed(
            "www.example.com",
            Some("192.0.2.10".parse().unwrap()),
            80,
            Protocol::Tcp,
            Some("nginx".to_owned()),
            Some("1.24.0".to_owned()),
        );
        let asset = asset_for_service(&service);
        assert_eq!(asset.kind, AssetKind::Host);
        assert_eq!(asset.name, "www.example.com");
    }

    #[tokio::test]
    async fn round_trip_when_database_present() {
        let Ok(url) = std::env::var("OXIDIAN_DATABASE_URL") else {
            return;
        };
        if url.trim().is_empty() {
            return;
        }
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let asset = Asset::domain("example.com", "test");
        store.record_asset(&asset).await.expect("asset");
        let assets = store.fetch_assets().await.expect("list");
        assert!(assets.iter().any(|item| item.name == "example.com"));
    }
}
