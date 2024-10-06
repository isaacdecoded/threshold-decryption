# Threshold-based Decryption Service

This is a decryption service supported by threshold public key encryption scheme. At a detail implementation level, this is using the [threshold_crypto](https://github.com/poanetwork/threshold_crypto) crate which is based on the [pairing](https://crates.io/crates/pairing) elliptic curve library.

### Requirements

- [Rust](https://www.rust-lang.org/tools/install)

### Scripts

You can execute it by using Cargo (already included in Rust installation):

```bash
EXAMPLE_MESSAGE='Hello World!' cargo run
```

Or you can run it on Docker by using the included docker-compose file:

```bash
docker-compose -f ops/docker/docker-compose.yml up --build
```

And run tests by:

```bash
cargo test
```

### API Reference

The Threshold Decryption Service exposes two endpoints:

1. GET /public-key - Returns the service's public encryption key represented in bytes.

#### Example request:

```bash
curl http://localhost:3000/public-key
```

#### Example response:

```json
{
  "publicKey": [
    181, 142, 210, 168, 1, 171, 8, 223, 175, 198, 133, 22, 128, 97, 71, 160, 81,
    152, 50, 42, 137, 44, 176, 33, 223, 100, 209, 132, 56, 248, 125, 140, 122,
    21, 116, 119, 101, 112, 204, 74, 254, 114, 152, 114, 130, 40, 39, 114
  ]
}
```

2. POST /decrypt-message - Given an encrypted message represented in bytes, it returns its decryption in plaintext.

#### Example request:

```bash
curl -X POST http://localhost:3000/decrypt-message \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer my-fake-token" \
     -d '{"message": [
    181, 142, 210, 168, 1, 171, 8, 223, 175, 198, 133, 22, 128, 97, 71, 160, 81,
    152, 50, 42, 137, 44, 176, 33, 223, 100, 209, 132, 56, 248, 125, 140, 122,
    21, 116, 119, 101, 112, 204, 74, 254, 114, 152, 114, 130, 40, 39, 114
  ]}'
```

#### Example response:

```json
{ "decryptedMessage": "Hello World!" }
```

# Solution

## Architectural aspects

In terms of Software Engineering, the code is based on the Rust programming language structured in a layered architecture closely aligned with the Clean Architecture approach and adhering to SOLID principles. This structure allows for the distribution of software components across the following layers, according to their roles in the Threshold Decryption Service (from inner to outer):

1. **Domain Layer:** This layer contains a cryptography service component definition for the encryption mechanism abstraction. It adheres to the _Interface Segregation Principle_ by defining a `trait` that exposes two entry points that will be used by other components at the application layer.

2. **Application Layer:** This layer contains the service's Business Logic, expressed as use cases organized using _Command-Query Responsibility Segregation (CQRS)_ terminology into _queries_ and _commands_. These are `struct` definitions that encapsulate the logic necessary to meet the challenge requirements: retrieving the encryption public key and decrypting a message.

3. **Infrastructure Layer:** Finally, this layer includes the implementation detail of the cryptography service which is based on the pairing-based threshold cryptosystem from the `threshold_crypto` library. It also contains other implementation details like routes and guards for the API server based on the [Rocket](https://rocket.rs/) library.

This outer layer includes the implementation details of the cryptography service, based on the pairing-based threshold cryptosystem from the [threshold_crypto](https://github.com/poanetwork/) library. It also contains other implementation details, such as routes and guards for the API server, which is built using the [Rocket](https://rocket.rs/) library.

## Approach explanation

As previously mentioned, the approach of this solution is grounded in software architecture concepts, such as structuring components into different layers. This structure is supported by the _Dependency Injection Principle_ to ensure non-circular dependencies between components, along with other SOLID principles and design patterns.

### Implementation details

Regarding the chosen "threshold-supporting public key encryption scheme" implementation, we can focus on the `/infrastructure/PairingCryptographyService` component which uses [Elliptic Curve Pairings](https://medium.com/@VitalikButerin/exploring-elliptic-curve-pairings-c73c1864e627) for encryption through the implementation of the `threshold_crypto` crate.

The `PairingCryptographyService` component initialize a _Secret Key Set_ and its corresponding _Public Key Set_, then simulate a predetermined number of _Servers_ where each one will hold the i-th _Shared Secret Key_ required for the decryption process.

### API end-points

The API server is supported on the [Rocket](https://rocket.rs/) web framework which facilitates the implementation of the following components:

1. Authorization guard: validates the presence of authorization header in a given request to private endpoints.

2. Rate limiter guard: together with the [Governor](https://github.com/boinkor-net/governor) crate, this component controls access to the service endpoints.

3. Health check, Decrypt message and Get public key routes: prepares the endpoints that allow the user to interact with the service via HTTP network protocol.

4. Swagger UI: an OpenAPI documentation is available visiting the `/swagger-ui` path which is automatically generated by the [rust-okapi](https://github.com/GREsau/okapi) crate

**IMPORTANT:** For the authorization access token, you can use any string (e.g., "my-fake-token"), as this service does not validate the token but only checks for its presence in the request header.

### Tools

This Rust application is built on top of the Tokio Runtime for asynchronous executions and implements other general-purpose crates like `async-trait`, `thiserror`, `serde`, etc.

### Test

This solution includes some unit tests, which evaluate successful executions naively. To run them, execute the `cargo test` command.

