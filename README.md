# blerpc-protocol-rn

BLE RPC protocol library for TypeScript/React Native.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

TypeScript implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)
- **Encryption layer** — E2E encryption with X25519 key exchange, Ed25519 signatures, and AES-128-GCM

No external crypto dependencies beyond `@noble` libraries.

## Installation

```
npm install @blerpc/protocol-rn
```

## Encryption

The library provides E2E encryption using a 4-step key exchange protocol (X25519 ECDH + Ed25519 signatures) and AES-128-GCM session encryption.

```typescript
import { centralPerformKeyExchange, BlerpcCryptoSession } from '@blerpc/protocol-rn';

// Perform key exchange (central side)
const session = await centralPerformKeyExchange(bleSend, bleReceive);

// Encrypt outgoing commands
const ciphertext = session.encrypt(plaintext);

// Decrypt incoming commands
const plaintext = session.decrypt(ciphertext);
```

## Requirements

- Node.js 18+
- TypeScript 5.0+
- React Native 0.71+

## License

[Apache-2.0](LICENSE)
