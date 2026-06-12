#[async_trait::async_trait]
pub trait NetworkService {
    type TError: std::error::Error;
    async fn start_server(&self, index: usize) -> Result<(), Self::TError>;
    async fn client_sign(&self, message: String, threshold: usize) -> Result<(), Self::TError>;
}
