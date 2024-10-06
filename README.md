# Threshold-based decryption monorepo

This is a monorepo for a _threshold-based decryption services_ which includes:
1. The API Threshold Decryption Service
2. The distributed Threshold Decryption Server for Partial Decryptions

These services require a RabbitMQ instance in order to communicate asynchronously:
```bash
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
```

Finally, the services are prepared firstly by running the _Threshold Decryption Servers_:

```bash
SERVER_ID=n cargo run
# Note: where n = 0,1...n
```

Then, running the _Threshold Decryption Service_:
```bash
cargo run
# Note: the main.rs file specify the threshold value and the desired number of distributed servers when instantiating the PairingCryptographyService
```