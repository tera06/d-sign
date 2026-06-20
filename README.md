# d-sign

A distributed threshold signature system built with Rust, LibP2P, and Threshold Crypto.

The project demonstrates how a message can be signed collaboratively by multiple nodes without reconstructing the private key on a single machine.

## Features

- Threshold signature scheme
- Distributed signing over P2P network
- Peer discovery using mDNS
- Encrypted storage of public keys and secret key shares
- Threshold signature verification
- End-to-end integration test

## Architecture

### Components

| Component                | Responsibility                                  |
| ------------------------ | ----------------------------------------------- |
| KeyService               | Key generation, signing, signature verification |
| P2pNetworkService        | Peer discovery, request/response communication  |
| PublicKeyRepository      | Stores encrypted public key                     |
| SecretKeyShareRepository | Stores encrypted secret key shares              |
| KeyGenerator             | Generates threshold key sets                    |
| DigestGenerator          | Generates message digests                       |
| AppRunner                | Application entry point                         |

### Technologies

- Rust
- Tokio
- LibP2P
- Threshold Crypto
- AES-256-GCM
- Bincode
- Serde
- Clap
- Mockall

---

# Build

```bash
cargo build
```

---

# Environment Variable

The repositories encrypt stored key material using AES-256-GCM.

Set a 32-byte master key encoded in Base64:

```bash
export DSIGN_MASTER_KEY=$(python -c "import base64; print(base64.b64encode(bytes([1]*32)).decode())")
```

Example value:

```text
AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
```

---

# Usage

## Initialize Keys

Generate a threshold key set and split the secret key into shares.

```bash
d-sign init <threshold> <number_of_nodes>
```

Example:

```bash
d-sign init 2 3
```

This creates:

- 1 public key
- 3 secret key shares
- threshold = 2

Meaning any 2 of the 3 shares can generate a valid signature.

---

## Start Signing Servers

Start one server process per secret key share.

### Node 0

```bash
d-sign server 0
```

### Node 1

```bash
d-sign server 1
```

### Node 2

```bash
d-sign server 2
```

The servers discover each other automatically through mDNS.

---

## Request a Signature

```bash
d-sign client <message> <threshold>
```

Example:

```bash
d-sign client hello 2
```

The client:

1. Discovers peers.
2. Sends signing requests.
3. Collects signature shares.
4. Combines shares.
5. Verifies the resulting signature.

If verification succeeds:

```text
---
Message: hello
---
```

---

# End-to-End Test

An end-to-end integration test is provided.

The test performs:

1. Key initialization (`init 2 3`)
2. Launches three signing servers
3. Sends a signing request
4. Collects threshold signature shares
5. Verifies the signature
6. Terminates all server processes

## Run E2E Tests

```bash
cargo test --test e2e_test
```

or

```bash
cargo test
```

---

# Example Test Flow

```text
+---------+
| Client  |
+----+----+
     |
     | Sign Request
     |
+----v----+    +---------+    +---------+
| Node 0  |    | Node 1  |    | Node 2  |
+----+----+    +----+----+    +----+----+
     |              |              |
     +--------------+--------------+
                    |
                    | Signature Shares
                    |
               +----v----+
               | Client  |
               +---------+
                    |
                    | Combine Shares
                    |
                    v
             Signature Verification
```

---

# Running All Tests

```bash
cargo test
```



---

# Project Status

This project is intended as a learning and experimental implementation of distributed threshold signatures using LibP2P and Threshold Crypto.

It is not currently intended for production use.