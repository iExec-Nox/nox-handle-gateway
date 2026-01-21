use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    query_as,
};

#[derive(Deserialize, Serialize, sqlx::FromRow)]
pub struct HandleEntry {
    pub handle: String,
    pub ciphertext: String,
    pub public_key: String,
    pub nonce: String,
    pub owner: String,
    pub created_at: NaiveDateTime,
}

#[derive(Clone)]
pub struct DataRepository {
    pool: PgPool,
}

impl DataRepository {
    pub async fn new(url: &str) -> Result<Self, sqlx::error::Error> {
        let pool = PgPoolOptions::new().max_connections(5).connect(url).await?;
        Ok(Self { pool })
    }

    pub async fn create_handle(
        &self,
        entry: &HandleEntry,
    ) -> Result<HandleEntry, sqlx::error::Error> {
        let result = query_as::<_, HandleEntry>(
            "INSERT INTO handles (handle, ciphertext, public_key, nonce, owner) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(&entry.handle)
        .bind(&entry.ciphertext)
        .bind(&entry.public_key)
        .bind(&entry.nonce)
        .bind(&entry.owner)
        .fetch_one(&self.pool)
        .await?;
        Ok(result)
    }

    pub async fn fetch_handle(&self, id: &String) -> Result<HandleEntry, sqlx::error::Error> {
        let handle = query_as::<_, HandleEntry>("SELECT * FROM handles WHERE handle = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(handle)
    }
}
