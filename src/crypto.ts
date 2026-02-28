// E2E encryption for blerpc using X25519, Ed25519, AES-128-GCM, HKDF-SHA256.

import { x25519 } from "@noble/curves/ed25519";
import { ed25519 } from "@noble/curves/ed25519";
import { gcm } from "@noble/ciphers/aes";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

// Direction bytes for nonce construction
export const DIRECTION_C2P = 0x00;
export const DIRECTION_P2C = 0x01;

// Confirmation plaintexts
const encoder = new TextEncoder();
export const CONFIRM_CENTRAL = encoder.encode("BLERPC_CONFIRM_C");
export const CONFIRM_PERIPHERAL = encoder.encode("BLERPC_CONFIRM_P");

// Key exchange step constants
export const KEY_EXCHANGE_STEP1 = 0x01;
export const KEY_EXCHANGE_STEP2 = 0x02;
export const KEY_EXCHANGE_STEP3 = 0x03;
export const KEY_EXCHANGE_STEP4 = 0x04;

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function uint8ArrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Cryptographic operations for blerpc E2E encryption. */
export class BlerpcCrypto {
  /** Generate an X25519 key pair. Returns [privateKey(32), publicKey(32)]. */
  static generateX25519KeyPair(): [Uint8Array, Uint8Array] {
    const privateKey = randomBytes(32);
    const publicKey = x25519.getPublicKey(privateKey);
    return [privateKey, publicKey];
  }

  /** Get the raw 32-byte public key from a private key. */
  static x25519PublicKey(privateKey: Uint8Array): Uint8Array {
    return x25519.getPublicKey(privateKey);
  }

  /** Compute X25519 shared secret (32 bytes). */
  static x25519SharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Uint8Array {
    return x25519.getSharedSecret(privateKey, peerPublicKey);
  }

  /**
   * Derive 16-byte AES-128 session key using HKDF-SHA256.
   *
   * salt = centralPubkey || peripheralPubkey (64 bytes)
   * info = "blerpc-session-key"
   */
  static deriveSessionKey(
    sharedSecret: Uint8Array,
    centralPubkey: Uint8Array,
    peripheralPubkey: Uint8Array,
  ): Uint8Array {
    const salt = concatBytes(centralPubkey, peripheralPubkey);
    const info = encoder.encode("blerpc-session-key");
    return hkdf(sha256, sharedSecret, salt, info, 16);
  }

  /** Generate an Ed25519 key pair. Returns [privateKey(32), publicKey(32)]. */
  static generateEd25519KeyPair(): [Uint8Array, Uint8Array] {
    const privateKey = randomBytes(32);
    const publicKey = ed25519.getPublicKey(privateKey);
    return [privateKey, publicKey];
  }

  /** Get the raw 32-byte public key from an Ed25519 private key. */
  static ed25519PublicKey(privateKey: Uint8Array): Uint8Array {
    return ed25519.getPublicKey(privateKey);
  }

  /** Sign a message with Ed25519. Returns 64-byte signature. */
  static ed25519Sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
    return ed25519.sign(message, privateKey);
  }

  /** Verify an Ed25519 signature. Returns true if valid. */
  static ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
    try {
      return ed25519.verify(signature, message, publicKey);
    } catch {
      return false;
    }
  }

  /** Build 12-byte AES-GCM nonce: counter(4B LE) || direction(1B) || zeros(7B). */
  private static _buildNonce(counter: number, direction: number): Uint8Array {
    const buf = new ArrayBuffer(12);
    const view = new DataView(buf);
    view.setUint32(0, counter, true);
    view.setUint8(4, direction);
    // bytes 5-11 are already zero
    return new Uint8Array(buf);
  }

  /**
   * Encrypt a command payload.
   *
   * Returns: [counter:4BLE][ciphertext:NB][tag:16B]
   */
  static encryptCommand(
    sessionKey: Uint8Array,
    counter: number,
    direction: number,
    plaintext: Uint8Array,
  ): Uint8Array {
    const nonce = BlerpcCrypto._buildNonce(counter, direction);
    const aes = gcm(sessionKey, nonce);
    const sealed = aes.encrypt(plaintext); // ciphertext + tag appended
    // counter(4) + sealed (ciphertext + tag)
    const counterBytes = new Uint8Array(4);
    new DataView(counterBytes.buffer).setUint32(0, counter, true);
    return concatBytes(counterBytes, sealed);
  }

  /**
   * Decrypt a command payload.
   *
   * Input: [counter:4BLE][ciphertext:NB][tag:16B]
   * Returns: [counter, plaintext]
   */
  static decryptCommand(
    sessionKey: Uint8Array,
    direction: number,
    data: Uint8Array,
  ): [number, Uint8Array] {
    if (data.length < 20) {
      throw new Error(`Encrypted payload too short: ${data.length}`);
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const counter = view.getUint32(0, true);
    const sealed = data.slice(4); // ciphertext + tag
    const nonce = BlerpcCrypto._buildNonce(counter, direction);
    const aes = gcm(sessionKey, nonce);
    const plaintext = aes.decrypt(sealed);
    return [counter, plaintext];
  }

  /**
   * Encrypt a confirmation message for key exchange step 3/4.
   *
   * Returns: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
   */
  static encryptConfirmation(sessionKey: Uint8Array, message: Uint8Array): Uint8Array {
    const nonce = randomBytes(12);
    const aes = gcm(sessionKey, nonce);
    const sealed = aes.encrypt(message); // ciphertext + tag
    return concatBytes(nonce, sealed);
  }

  /**
   * Decrypt a confirmation message from key exchange step 3/4.
   *
   * Input: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
   * Returns: plaintext (16 bytes)
   */
  static decryptConfirmation(sessionKey: Uint8Array, data: Uint8Array): Uint8Array {
    if (data.length < 44) {
      throw new Error(`Confirmation too short: ${data.length}`);
    }
    const nonce = data.slice(0, 12);
    const sealed = data.slice(12); // ciphertext + tag
    const aes = gcm(sessionKey, nonce);
    return aes.decrypt(sealed);
  }

  /** Build KEY_EXCHANGE step 1 payload (33 bytes). [step:u8=0x01][central_x25519_pubkey:32B] */
  static buildStep1Payload(centralX25519Pubkey: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([KEY_EXCHANGE_STEP1]), centralX25519Pubkey);
  }

  /** Parse KEY_EXCHANGE step 1 payload. Returns central_x25519_pubkey (32 bytes). */
  static parseStep1Payload(data: Uint8Array): Uint8Array {
    if (data.length < 33 || data[0] !== KEY_EXCHANGE_STEP1) {
      throw new Error("Invalid step 1 payload");
    }
    return data.slice(1, 33);
  }

  /**
   * Build KEY_EXCHANGE step 2 payload (129 bytes).
   * [step:u8=0x02][peripheral_x25519_pubkey:32B][ed25519_signature:64B][peripheral_ed25519_pubkey:32B]
   */
  static buildStep2Payload(
    peripheralX25519Pubkey: Uint8Array,
    ed25519Signature: Uint8Array,
    peripheralEd25519Pubkey: Uint8Array,
  ): Uint8Array {
    return concatBytes(
      new Uint8Array([KEY_EXCHANGE_STEP2]),
      peripheralX25519Pubkey,
      ed25519Signature,
      peripheralEd25519Pubkey,
    );
  }

  /** Parse KEY_EXCHANGE step 2 payload. Returns [peripheral_x25519_pubkey, signature, peripheral_ed25519_pubkey]. */
  static parseStep2Payload(data: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
    if (data.length < 129 || data[0] !== KEY_EXCHANGE_STEP2) {
      throw new Error("Invalid step 2 payload");
    }
    return [data.slice(1, 33), data.slice(33, 97), data.slice(97, 129)];
  }

  /** Build KEY_EXCHANGE step 3 payload (45 bytes). [step:u8=0x03][nonce:12B][ciphertext:16B][tag:16B] */
  static buildStep3Payload(confirmationEncrypted: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([KEY_EXCHANGE_STEP3]), confirmationEncrypted);
  }

  /** Parse KEY_EXCHANGE step 3 payload. Returns the encrypted confirmation (44 bytes). */
  static parseStep3Payload(data: Uint8Array): Uint8Array {
    if (data.length < 45 || data[0] !== KEY_EXCHANGE_STEP3) {
      throw new Error("Invalid step 3 payload");
    }
    return data.slice(1, 45);
  }

  /** Build KEY_EXCHANGE step 4 payload (45 bytes). [step:u8=0x04][nonce:12B][ciphertext:16B][tag:16B] */
  static buildStep4Payload(confirmationEncrypted: Uint8Array): Uint8Array {
    return concatBytes(new Uint8Array([KEY_EXCHANGE_STEP4]), confirmationEncrypted);
  }

  /** Parse KEY_EXCHANGE step 4 payload. Returns the encrypted confirmation (44 bytes). */
  static parseStep4Payload(data: Uint8Array): Uint8Array {
    if (data.length < 45 || data[0] !== KEY_EXCHANGE_STEP4) {
      throw new Error("Invalid step 4 payload");
    }
    return data.slice(1, 45);
  }
}

/** Encrypt/decrypt with counter management and replay detection. */
export class BlerpcCryptoSession {
  private readonly _sessionKey: Uint8Array;

  /** TX counter, visible for testing. */
  txCounter = 0;
  private _rxCounter = 0;
  private _rxFirstDone = false;
  private readonly _txDirection: number;
  private readonly _rxDirection: number;

  constructor(sessionKey: Uint8Array, isCentral: boolean) {
    this._sessionKey = sessionKey;
    this._txDirection = isCentral ? DIRECTION_C2P : DIRECTION_P2C;
    this._rxDirection = isCentral ? DIRECTION_P2C : DIRECTION_C2P;
  }

  /** Encrypt plaintext with auto-incrementing TX counter. */
  encrypt(plaintext: Uint8Array): Uint8Array {
    if (this.txCounter >= 0xffffffff) {
      throw new Error("TX counter overflow: session must be rekeyed");
    }
    const encrypted = BlerpcCrypto.encryptCommand(
      this._sessionKey,
      this.txCounter,
      this._txDirection,
      plaintext,
    );
    this.txCounter++;
    return encrypted;
  }

  /** Decrypt data with replay detection on RX counter. */
  decrypt(data: Uint8Array): Uint8Array {
    const [counter, plaintext] = BlerpcCrypto.decryptCommand(
      this._sessionKey,
      this._rxDirection,
      data,
    );
    if (this._rxFirstDone && counter <= this._rxCounter) {
      throw new Error(`Replay detected: counter=${counter}`);
    }
    this._rxCounter = counter;
    this._rxFirstDone = true;
    return plaintext;
  }
}

/**
 * Central-side key exchange state machine.
 *
 * Usage:
 *   const kx = new CentralKeyExchange();
 *   const step1 = kx.start();           // send to peripheral
 *   const step3 = kx.processStep2(s2);  // send to peripheral
 *   const session = kx.finish(s4);      // BlerpcCryptoSession
 */
export class CentralKeyExchange {
  private _x25519PrivKey: Uint8Array | null = null;
  private _x25519Pubkey: Uint8Array | null = null;
  private _sessionKey: Uint8Array | null = null;
  private _state = 0;

  /** Generate ephemeral X25519 keypair and return step 1 payload. */
  start(): Uint8Array {
    if (this._state !== 0) throw new Error("Invalid state for start()");
    const [priv, pub] = BlerpcCrypto.generateX25519KeyPair();
    this._x25519PrivKey = priv;
    this._x25519Pubkey = pub;
    this._state = 1;
    return BlerpcCrypto.buildStep1Payload(pub);
  }

  /** Parse step 2, verify signature, derive session key, return step 3 payload. */
  processStep2(step2Payload: Uint8Array, verifyKeyCb?: (key: Uint8Array) => boolean): Uint8Array {
    if (this._state !== 1) throw new Error("Invalid state for processStep2()");

    const [periphX25519Pub, signature, periphEd25519Pub] =
      BlerpcCrypto.parseStep2Payload(step2Payload);

    const signMsg = concatBytes(this._x25519Pubkey!, periphX25519Pub);
    const valid = BlerpcCrypto.ed25519Verify(periphEd25519Pub, signMsg, signature);
    if (!valid) {
      throw new Error("Ed25519 signature verification failed");
    }

    if (verifyKeyCb && !verifyKeyCb(periphEd25519Pub)) {
      throw new Error("Peripheral key rejected by verify callback");
    }

    const sharedSecret = BlerpcCrypto.x25519SharedSecret(this._x25519PrivKey!, periphX25519Pub);
    this._sessionKey = BlerpcCrypto.deriveSessionKey(
      sharedSecret,
      this._x25519Pubkey!,
      periphX25519Pub,
    );

    const encryptedConfirm = BlerpcCrypto.encryptConfirmation(this._sessionKey, CONFIRM_CENTRAL);
    this._state = 2;
    return BlerpcCrypto.buildStep3Payload(encryptedConfirm);
  }

  /** Parse step 4, verify peripheral confirmation, return session. */
  finish(step4Payload: Uint8Array): BlerpcCryptoSession {
    if (this._state !== 2) throw new Error("Invalid state for finish()");
    const encryptedPeriph = BlerpcCrypto.parseStep4Payload(step4Payload);
    const plaintext = BlerpcCrypto.decryptConfirmation(this._sessionKey!, encryptedPeriph);
    if (!uint8ArrayEquals(plaintext, CONFIRM_PERIPHERAL)) {
      throw new Error("Peripheral confirmation mismatch");
    }
    return new BlerpcCryptoSession(this._sessionKey!, true);
  }
}

/**
 * Peripheral-side key exchange state machine.
 *
 * Usage:
 *   const kx = new PeripheralKeyExchange(ed25519PrivKey, ed25519PubKey);
 *   const step2 = kx.processStep1(s1);           // send to central
 *   const [step4, session] = kx.processStep3(s3); // send + session
 */
export class PeripheralKeyExchange {
  private readonly _ed25519PrivKey: Uint8Array;
  private readonly _ed25519PubKey: Uint8Array;
  private _sessionKey: Uint8Array | null = null;
  private _state = 0;

  constructor(ed25519PrivKey: Uint8Array, ed25519PubKey: Uint8Array) {
    this._ed25519PrivKey = ed25519PrivKey;
    this._ed25519PubKey = ed25519PubKey;
  }

  /** Visible for testing. */
  get sessionKey(): Uint8Array | null {
    return this._sessionKey;
  }

  /** Parse step 1, generate ephemeral X25519 keypair, sign, derive session key, return step 2 payload. */
  processStep1(step1Payload: Uint8Array): Uint8Array {
    if (this._state !== 0) throw new Error("Invalid state for processStep1()");
    const centralX25519Pub = BlerpcCrypto.parseStep1Payload(step1Payload);

    const [x25519Priv, x25519Pub] = BlerpcCrypto.generateX25519KeyPair();

    const signMsg = concatBytes(centralX25519Pub, x25519Pub);
    const signature = BlerpcCrypto.ed25519Sign(this._ed25519PrivKey, signMsg);

    const sharedSecret = BlerpcCrypto.x25519SharedSecret(x25519Priv, centralX25519Pub);
    this._sessionKey = BlerpcCrypto.deriveSessionKey(sharedSecret, centralX25519Pub, x25519Pub);

    this._state = 1;
    return BlerpcCrypto.buildStep2Payload(x25519Pub, signature, this._ed25519PubKey);
  }

  /** Parse step 3, verify confirmation, return [step4Payload, session]. */
  processStep3(step3Payload: Uint8Array): [Uint8Array, BlerpcCryptoSession] {
    if (this._state !== 1) throw new Error("Invalid state for processStep3()");
    const encrypted = BlerpcCrypto.parseStep3Payload(step3Payload);
    const plaintext = BlerpcCrypto.decryptConfirmation(this._sessionKey!, encrypted);
    if (!uint8ArrayEquals(plaintext, CONFIRM_CENTRAL)) {
      throw new Error("Central confirmation mismatch");
    }

    const encryptedConfirm = BlerpcCrypto.encryptConfirmation(
      this._sessionKey!,
      CONFIRM_PERIPHERAL,
    );
    const step4 = BlerpcCrypto.buildStep4Payload(encryptedConfirm);
    const session = new BlerpcCryptoSession(this._sessionKey!, false);

    return [step4, session];
  }

  /**
   * Dispatch a key exchange payload by step byte.
   * Returns [responsePayload, sessionOrNull].
   */
  handleStep(payload: Uint8Array): [Uint8Array, BlerpcCryptoSession | null] {
    if (payload.length === 0) {
      throw new Error("Empty key exchange payload");
    }

    const step = payload[0];
    if (step === KEY_EXCHANGE_STEP1) {
      if (this._state !== 0) throw new Error("Invalid state for step 1");
      const response = this.processStep1(payload);
      return [response, null];
    } else if (step === KEY_EXCHANGE_STEP3) {
      if (this._state !== 1) throw new Error("Invalid state for step 3");
      const [step4, session] = this.processStep3(payload);
      return [step4, session];
    } else {
      throw new Error(`Invalid key exchange step: 0x${step.toString(16).padStart(2, "0")}`);
    }
  }

  /** Reset key exchange state for new connection. */
  reset(): void {
    this._state = 0;
    this._sessionKey = null;
  }
}

/** Perform the 4-step central key exchange using send/receive callbacks. */
export async function centralPerformKeyExchange(options: {
  send: (payload: Uint8Array) => Promise<void>;
  receive: () => Promise<Uint8Array>;
  verifyKeyCb?: (key: Uint8Array) => boolean;
}): Promise<BlerpcCryptoSession> {
  const kx = new CentralKeyExchange();

  // Step 1: Send central's ephemeral public key
  const step1 = kx.start();
  await options.send(step1);

  // Step 2: Receive peripheral's response
  const step2 = await options.receive();

  // Step 2 -> Step 3: Verify and produce confirmation
  const step3 = kx.processStep2(step2, options.verifyKeyCb);
  await options.send(step3);

  // Step 4: Receive peripheral's confirmation
  const step4 = await options.receive();

  return kx.finish(step4);
}
