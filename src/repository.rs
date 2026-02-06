use chrono::NaiveDateTime;
use futures::stream::StreamExt;
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
        let mut transaction = self.pool.begin().await?;
        let result = self
            .create_handle_in_transaction(&mut transaction, entry)
            .await?;
        transaction.commit().await?;
        Ok(result)
    }

    pub async fn create_handles(
        &self,
        entries: Vec<HandleEntry>,
    ) -> Result<Vec<HandleEntry>, sqlx::error::Error> {
        let mut transaction = self.pool.begin().await?;
        let mut results = Vec::new();
        for entry in entries {
            results.push(
                self.create_handle_in_transaction(&mut transaction, &entry)
                    .await?,
            );
        }
        transaction.commit().await?;
        Ok(results)
    }

    async fn create_handle_in_transaction(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        entry: &HandleEntry,
    ) -> Result<HandleEntry, sqlx::error::Error> {
        let result = query_as::<_, HandleEntry>(
            "INSERT INTO handles (handle, ciphertext, public_key, nonce) VALUES ($1, $2, $3, $4) RETURNING *",
        )
        .bind(&entry.handle)
        .bind(&entry.ciphertext)
        .bind(&entry.public_key)
        .bind(&entry.nonce)
        .fetch_one(&mut **transaction)
        .await?;
        Ok(result)
    }

    pub async fn fetch_handle(&self, id: &str) -> Result<HandleEntry, sqlx::error::Error> {
        let handle = query_as::<_, HandleEntry>("SELECT * FROM handles WHERE handle = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(handle)
    }

    pub async fn read_handles(&self, ids: &Vec<String>) -> Vec<HandleEntry> {
        let mut stream =
            sqlx::query_as::<_, HandleEntry>("SELECT * FROM handles WHERE handle = ANY($1)")
                .bind(ids)
                .fetch(&self.pool);
        let mut results: Vec<HandleEntry> = Vec::new();
        while let Some(handle) = stream.next().await {
            match handle {
                Ok(item) => results.push(item),
                Err(_) => eprintln!("too bad"),
            }
        }
        results
    }
}
