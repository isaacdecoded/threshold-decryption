use std::{ error::Error, time::{ SystemTime, UNIX_EPOCH } };
use ring::signature::{ Ed25519KeyPair, KeyPair };
use amqprs::{
    callbacks::{ DefaultChannelCallback, DefaultConnectionCallback },
    channel::{
        BasicConsumeArguments,
        BasicPublishArguments,
        ExchangeDeclareArguments,
        QueueBindArguments,
        QueueDeclareArguments,
    },
    connection::{ Connection, OpenConnectionArguments },
    consumer::AsyncConsumer,
    BasicProperties,
};
use tokio::time::{ timeout, Duration };
use serde::{ Deserialize, Serialize };
use tokio::sync::mpsc::{ Sender, Receiver, channel as tokio_channel };
use std::collections::HashMap;
use async_trait::async_trait;
use thiserror::Error;
use threshold_crypto::{
    serde_impl::SerdeSecret,
    Ciphertext,
    DecryptionShare,
    PublicKeySet,
    SecretKeySet,
    SecretKeyShare,
};
use crate::domain::services::cryptography_service::{
    CryptographyService,
    CryptographyServiceError,
};

#[derive(Error, Debug)]
pub enum PairingCryptographyServiceError {
    #[error("Unable to initialize instance. {0}")] InvalidInitialization(String),
}

#[derive(Serialize, Deserialize, Debug)]
struct PartialDecryption {
    id: usize,
    decryption_share: DecryptionShare,
}

struct DecryptionConsumer {
    sender: Sender<(usize, DecryptionShare)>,
}

#[async_trait::async_trait]
impl AsyncConsumer for DecryptionConsumer {
    async fn consume(
        &mut self,
        _channel: &amqprs::channel::Channel,
        _deliver: amqprs::Deliver,
        _basic_properties: BasicProperties,
        content: Vec<u8>
    ) {
        let message: PartialDecryption = bincode::deserialize(&content).unwrap();
        self.sender.send((message.id, message.decryption_share)).await.unwrap();
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptionServerMessage {
    cipher_text: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    secret_key_share: Option<Vec<u8>>,
    timestamp: Option<u64>,
}

pub struct PairingCryptographyService {
    connection: Connection,
    n_servers: usize,
    threshold: usize,
    secret_key_set: SecretKeySet,
    public_key_set: PublicKeySet,
    key_pair: Ed25519KeyPair,
}

impl PairingCryptographyService {
    pub async fn new(
        n_servers: usize,
        threshold: usize
    ) -> Result<Self, PairingCryptographyServiceError> {
        if n_servers <= threshold {
            return Err(
                PairingCryptographyServiceError::InvalidInitialization(
                    "Number of servers must be greater by one to the threshold.".to_string()
                )
            );
        }
        let queue_name = "decryption_service";
        let exchange_name = "partials_exchange";
        let connection = Connection::open(
            OpenConnectionArguments::new("localhost", 5672, "guest", "guest").heartbeat(30)
        ).await.map_err(|e| {
            PairingCryptographyServiceError::InvalidInitialization(e.to_string())
        })?;
        connection
            .register_callback(DefaultConnectionCallback).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        let channel = connection
            .open_channel(None).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel
            .register_callback(DefaultChannelCallback).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel
            .queue_declare(QueueDeclareArguments::durable_client_named(&queue_name)).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel
            .exchange_declare(
                ExchangeDeclareArguments::new(exchange_name, "direct").durable(true).to_owned()
            ).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel
            .queue_bind(QueueBindArguments::new(&queue_name, exchange_name, "*")).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel.close().await.unwrap();
        let mut rng = rand::thread_rng();
        let secret_key_set = SecretKeySet::random(threshold, &mut rng);
        let public_key_set = secret_key_set.public_keys();

        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        Ok(Self {
            connection,
            n_servers,
            threshold,
            secret_key_set,
            public_key_set,
            key_pair,
        })
    }

    async fn combine_decryption_shares(
        &self,
        shares: &HashMap<usize, DecryptionShare>,
        ciphertext: &Ciphertext
    ) -> Result<Vec<u8>, CryptographyServiceError> {
        self.public_key_set
            .decrypt(shares, ciphertext)
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })
    }

    pub async fn propagate_keys(&self) -> Result<(), Box<dyn Error + Send + Sync>> {
        let exchange_name = "secrets_exchange";
        let channel = self.connection
            .open_channel(None).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        channel
            .register_callback(DefaultChannelCallback).await
            .map_err(|e| {
                PairingCryptographyServiceError::InvalidInitialization(e.to_string())
            })?;
        for id in 0..self.n_servers {
            let secret_key_share: SecretKeyShare = self.secret_key_set.secret_key_share(id);
            let serde_secret = SerdeSecret(secret_key_share.clone());
            let serialized_serde_secret: Vec<u8> = bincode::serialize(&serde_secret).unwrap();
            let properties = BasicProperties::default();
            let content = DecryptionServerMessage {
                cipher_text: None,
                public_key: Some(self.key_pair.public_key().as_ref().to_vec()),
                secret_key_share: Some(serialized_serde_secret),
                timestamp: None,
            };
            let serialized_content = bincode::serialize(&content).unwrap();
            channel
                .basic_publish(
                    properties.clone(),
                    serialized_content,
                    BasicPublishArguments::new(&exchange_name, &format!("server_{}_secret", id))
                ).await
                .map_err(|e| {
                    PairingCryptographyServiceError::InvalidInitialization(e.to_string())
                })?;
        }
        channel.close().await.unwrap();
        Ok(())
    }
}

#[async_trait]
impl CryptographyService for PairingCryptographyService {
    async fn share_public_key(&self) -> Result<Vec<u8>, CryptographyServiceError> {
        Ok(self.public_key_set.public_key().to_bytes().to_vec())
    }

    async fn encrypt_message(&self, message: String) -> Result<Vec<u8>, CryptographyServiceError> {
        bincode
            ::serialize(&self.public_key_set.public_key().encrypt(&message))
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })
    }

    async fn decrypt_message(&self, message: Vec<u8>) -> Result<Vec<u8>, CryptographyServiceError> {
        let queue_name = "decryption_service";
        let exchange_name = "decryptions_exchange";
        let encrypted_message: Ciphertext = bincode
            ::deserialize(&message)
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })?;
        let channel = self.connection
            .open_channel(None).await
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })?;
        channel
            .register_callback(DefaultChannelCallback).await
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })?;
        let properties = BasicProperties::default();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let message = DecryptionServerMessage {
            cipher_text: Some(message),
            public_key: None,
            secret_key_share: None,
            timestamp: Some(timestamp),
        };
        let serialized_message = bincode::serialize(&message).unwrap();
        let message_signature = self.key_pair.sign(&serialized_message);
        let mut signed_message = Vec::new();
        signed_message.extend_from_slice(message_signature.as_ref());
        signed_message.extend_from_slice(&serialized_message);
        channel
            .basic_publish(
                properties.clone(),
                signed_message,
                BasicPublishArguments::new(exchange_name, "*")
            ).await
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })?;

        let (sender, mut receiver): (
            Sender<(usize, DecryptionShare)>,
            Receiver<(usize, DecryptionShare)>,
        ) = tokio_channel(self.n_servers);
        let consume_args = BasicConsumeArguments::new(&queue_name, "*").manual_ack(false).finish();
        let consumer = DecryptionConsumer { sender };
        channel.basic_consume(consumer, consume_args).await.unwrap();

        let mut received_shares = HashMap::new();
        let timeout_duration = Duration::from_secs(10);
        while received_shares.len() < self.threshold + 1 {
            match timeout(timeout_duration, receiver.recv()).await {
                Ok(Some((id, decryption_share))) => {
                    received_shares.insert(id, decryption_share);
                }
                Ok(None) => {
                    break;
                }
                Err(_) => {
                    return Err(
                        CryptographyServiceError::DecryptionError(
                            "Not enough available Decryption Servers.".to_string()
                        )
                    );
                }
            }
        }
        channel.close().await.unwrap();

        let decrypted_message = self
            .combine_decryption_shares(&received_shares, &encrypted_message).await
            .map_err(|e| { CryptographyServiceError::DecryptionError(e.to_string()) })?;

        Ok(decrypted_message)
    }
}
