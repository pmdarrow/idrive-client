//! Application-facing client. Clone it to share credentials without copying passwords.
use crate::{
    Credentials, Result,
    native::{Endpoints, RemoteEntry, Session, discover},
};
use std::{path::Path, sync::Arc};

#[derive(Clone)]
pub struct Client {
    endpoints: Endpoints,
    credentials: Arc<Credentials>,
    slots: Arc<tokio::sync::Semaphore>,
}
impl Client {
    pub async fn login(credentials: Credentials) -> Result<Self> {
        Self::login_with_parallelism(credentials, 16).await
    }
    pub async fn login_with_parallelism(
        credentials: Credentials,
        parallelism: usize,
    ) -> Result<Self> {
        if !(1..=32).contains(&parallelism) {
            return Err(crate::Error::Frame("parallelism must be 1..32"));
        }
        let credentials = Arc::new(credentials);
        let endpoints = discover(&credentials).await?;
        Session::connect(&endpoints, credentials.clone(), 21).await?;
        Ok(Self {
            endpoints,
            credentials,
            slots: Arc::new(tokio::sync::Semaphore::new(parallelism)),
        })
    }
    pub async fn list(&self, path: &str) -> Result<Vec<RemoteEntry>> {
        Session::list(&self.endpoints, self.credentials.clone(), path).await
    }
    pub async fn mkdir(&self, path: &str) -> Result<()> {
        Session::mkdir(&self.endpoints, self.credentials.clone(), path).await
    }
    pub async fn upload(&self, local: &Path, remote: &str) -> Result<u64> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| crate::Error::Closed)?;
        Session::upload(&self.endpoints, self.credentials.clone(), local, remote).await
    }
    pub async fn download(&self, remote: &str, local: &Path) -> Result<u64> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| crate::Error::Closed)?;
        Session::download(&self.endpoints, self.credentials.clone(), remote, local).await
    }
    pub async fn download_to<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        remote: &str,
        output: &mut W,
    ) -> Result<u64> {
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| crate::Error::Closed)?;
        Session::download_to(&self.endpoints, self.credentials.clone(), remote, output).await
    }
}
