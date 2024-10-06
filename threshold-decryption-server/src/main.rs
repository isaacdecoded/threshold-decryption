use tokio::sync::Notify;
use ring::signature::{ UnparsedPublicKey, ED25519 };
use std::{ env, time::{ SystemTime, UNIX_EPOCH } };
use amqprs::{
    callbacks::{ DefaultChannelCallback, DefaultConnectionCallback },
    channel::{
        BasicConsumeArguments,
        BasicPublishArguments,
        Channel,
        ExchangeDeclareArguments,
        QueueBindArguments,
        QueueDeclareArguments,
    },
    connection::{ Connection, OpenConnectionArguments },
    consumer::AsyncConsumer,
    BasicProperties,
};
use serde::{ Deserialize, Serialize };
use threshold_crypto::{ serde_impl::SerdeSecret, Ciphertext, DecryptionShare, SecretKeyShare };

#[derive(Serialize, Deserialize, Debug)]
struct PartialDecryption {
    id: usize,
    decryption_share: DecryptionShare,
}

#[derive(Serialize, Deserialize, Debug)]
struct DecryptionServerMessage {
    cipher_text: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    secret_key_share: Option<Vec<u8>>,
    timestamp: Option<u64>,
}

struct DecryptionServer {
    id: usize,
    signature_public_key: Option<Vec<u8>>,
    secret_key_share: Option<SecretKeyShare>,
}

#[async_trait::async_trait]
impl AsyncConsumer for DecryptionServer {
    async fn consume(
        &mut self,
        channel: &amqprs::channel::Channel,
        _deliver: amqprs::Deliver,
        _basic_properties: BasicProperties,
        content: Vec<u8>
    ) {
        let mut message = DecryptionServerMessage {
            cipher_text: None,
            public_key: None,
            secret_key_share: None,
            timestamp: None,
        };
        if self.signature_public_key.is_none() && self.secret_key_share.is_none() {
            message = bincode::deserialize(&content).unwrap_or(message);
        } else {
            let (signature, signed_message) = content.split_at(64);
            let public_key = UnparsedPublicKey::new(
                &ED25519,
                self.signature_public_key.as_ref().unwrap()
            );
            if public_key.verify(signed_message, signature).is_ok() {
                message = bincode::deserialize(&signed_message).unwrap_or(message);
            } else {
                println!("Server {}: Unrecognized sender signature", self.id);
            }
        }
        match
            (message.cipher_text, message.public_key, message.secret_key_share, message.timestamp)
        {
            (Some(cipher_text), None, None, Some(timestamp)) => {
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                let acceptable_range_in_secs = 10;
                if timestamp < current_time - acceptable_range_in_secs {
                    println!("Server {}: Message too old", self.id);
                    return;
                }
                match &self.secret_key_share {
                    Some(secret_key_share) => {
                        let encrypted_message: Ciphertext = bincode
                            ::deserialize(&cipher_text)
                            .unwrap();
                        let decryption_share = secret_key_share
                            .decrypt_share(&encrypted_message)
                            .unwrap();
                        let partial_decryption = PartialDecryption {
                            id: self.id,
                            decryption_share,
                        };
                        let serialized_partial_decryption = bincode
                            ::serialize(&partial_decryption)
                            .unwrap();
                        let properties = BasicProperties::default();
                        channel
                            .basic_publish(
                                properties.clone(),
                                serialized_partial_decryption,
                                BasicPublishArguments::new("partials_exchange", "*")
                            ).await
                            .unwrap();
                        println!("Server {}: Partial decryption sent", self.id);
                    }
                    None => {
                        println!("Server {}: Secret key share not available", self.id);
                    }
                }
            }
            (None, Some(public_key), Some(secret_key_share), None) => {
                let deserialized_secret_key_share: SerdeSecret<SecretKeyShare> = bincode
                    ::deserialize(&secret_key_share)
                    .unwrap();
                self.secret_key_share = Some(deserialized_secret_key_share.inner().to_owned());
                self.signature_public_key = Some(public_key);
                println!("Server {}: Keys synced", self.id);
            }
            _ => {
                println!("Server {}: Invalid message received", self.id);
            }
        }
    }
}

async fn setup_decryption_exchange(channel: &Channel, queue_name: &str) {
    let exchange_name = "decryptions_exchange";
    channel
        .exchange_declare(
            ExchangeDeclareArguments::new(exchange_name, "fanout").durable(true).to_owned()
        ).await
        .unwrap();
    channel.queue_bind(QueueBindArguments::new(&queue_name, exchange_name, "*")).await.unwrap();
}

async fn setup_secret_exchange(channel: &Channel, queue_name: &str, id: &usize) {
    let exchange_name = "secrets_exchange";
    let routing_key = format!("server_{}_secret", id);
    channel
        .exchange_declare(
            ExchangeDeclareArguments::new(exchange_name, "direct").durable(true).to_owned()
        ).await
        .unwrap();
    channel
        .queue_bind(QueueBindArguments::new(&queue_name, exchange_name, &routing_key)).await
        .unwrap();
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let id: usize = env::var("SERVER_ID").unwrap().parse().unwrap();
    let decryption_server = DecryptionServer {
        id,
        signature_public_key: None,
        secret_key_share: None,
    };
    let queue_name = format!("decryption_server_{}", id);

    let connection = Connection::open(
        OpenConnectionArguments::new("localhost", 5672, "guest", "guest").heartbeat(30)
    ).await.unwrap();
    connection.register_callback(DefaultConnectionCallback).await.unwrap();

    let channel = connection.open_channel(None).await.unwrap();
    channel.register_callback(DefaultChannelCallback).await.unwrap();
    channel.queue_declare(QueueDeclareArguments::durable_client_named(&queue_name)).await.unwrap();
    setup_decryption_exchange(&channel, &queue_name).await;
    setup_secret_exchange(&channel, &queue_name, &id).await;

    let consume_args = BasicConsumeArguments::new(&queue_name, &format!("server_{}_consumer", id))
        .manual_ack(false)
        .finish();
    channel.basic_consume(decryption_server, consume_args).await.unwrap();
    println!("Server {}: RabbitMQ connection established", id);
    let guard = Notify::new();
    guard.notified().await;
}
