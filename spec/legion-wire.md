# LEGION Wire Protocol Specification v3.0

## Message Types

### 1. Handshake Messages

#### ClientHello
```
struct ClientHello {
    protocol_version: u16 = 0x0300,
    ciphersuite: u16,
    client_random: [u8; 32],
    extensions: Vec<Extension>,
}
```

#### ServerHello  
```
struct ServerHello {
    protocol_version: u16 = 0x0300,
    ciphersuite: u16,
    server_random: [u8; 32],
    session_id: [u8; 32],
    extensions: Vec<Extension>,
}
```

#### ProofMessage
```
struct ProofMessage {
    proof_data: Vec<u8>,
    public_inputs: Vec<[u8; 32]>,
    signature: [u8; 64],
    timestamp: u64,
}
```

### 2. Record Layer

#### Record Format
```
struct Record {
    content_type: u8,
    epoch: u32,
    sequence: u64,
    length: u16,
    encrypted_data: Vec<u8>,
}
```

## Transcript Hash Construction

### Handshake Transcript
```
transcript = BLAKE3(
    "LEGION_HANDSHAKE_V3" ||
    client_hello ||
    server_hello ||
    proof_message ||
    timestamp_le_bytes
)
```

## HKDF Labels

### Key Derivation
```
master_secret = HKDF-Extract(salt, shared_secret)
client_key = HKDF-Expand(master_secret, "LEGION_CLIENT_KEY" || transcript_hash, 32)
server_key = HKDF-Expand(master_secret, "LEGION_SERVER_KEY" || transcript_hash, 32)
```

### Per-Epoch Keys
```
epoch_salt = HKDF-Expand(master_secret, "LEGION_EPOCH_SALT" || epoch_le_bytes, 32)
c2s_key = HKDF-Expand(epoch_salt, "CLIENT_TO_SERVER" || transcript_hash, 32)
s2c_key = HKDF-Expand(epoch_salt, "SERVER_TO_CLIENT" || transcript_hash, 32)
```

## AAD Format

### AEAD Additional Authenticated Data
```
aad = session_id || epoch_le_bytes || direction || transcript_hash || sequence_le_bytes
```

Where:
- `session_id`: 32 bytes
- `epoch`: 4 bytes little-endian
- `direction`: "C2S" or "S2C" (3 bytes)
- `transcript_hash`: 32 bytes
- `sequence`: 8 bytes little-endian

## Nonce Format

### Deterministic Nonce (96-bit)
```
nonce = epoch_le_bytes || sequence_le_bytes || direction_byte
```

Where:
- `epoch`: 4 bytes little-endian
- `sequence`: 7 bytes little-endian  
- `direction`: 1 byte (0x01=C2S, 0x02=S2C)

## Ciphersuite IDs

```
0x0001: X25519 + Ed25519 + ChaCha20Poly1305
0x0002: ML-KEM-1024 + ML-DSA-87 + ChaCha20Poly1305
0x0003: Hybrid (X25519+ML-KEM-1024) + (Ed25519+ML-DSA-87) + ChaCha20Poly1305
```

## Test Vectors

### HKDF Test Vector
```
Input:
  salt = 0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
  ikm = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
  info = "LEGION_CLIENT_KEY" || 0x1234567890abcdef...
  
Expected:
  okm = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
```

### Nonce Test Vector
```
Input:
  epoch = 0x00000001
  sequence = 0x0000000000000042
  direction = 0x01 (C2S)
  
Expected:
  nonce = 0x010000004200000000000001
```

### AAD Test Vector  
```
Input:
  session_id = 0x1234567890abcdef...
  epoch = 0x00000001
  direction = "C2S"
  transcript_hash = 0xabcdef1234567890...
  sequence = 0x0000000000000042
  
Expected:
  aad = session_id || 0x01000000 || "C2S" || transcript_hash || 0x4200000000000000
```