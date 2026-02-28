import {
  ControlCmd,
  makeKeyExchange,
  Container,
  makeCapabilitiesRequest,
  makeCapabilitiesResponse,
  CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
  BlerpcCrypto,
  BlerpcCryptoSession,
  CentralKeyExchange,
  PeripheralKeyExchange,
  centralPerformKeyExchange,
  DIRECTION_C2P,
  DIRECTION_P2C,
  CONFIRM_CENTRAL,
  CONFIRM_PERIPHERAL,
  KEY_EXCHANGE_STEP1,
  KEY_EXCHANGE_STEP2,
  KEY_EXCHANGE_STEP3,
  KEY_EXCHANGE_STEP4,
} from "../src";

describe("ControlCmd KEY_EXCHANGE", () => {
  test("enum value", () => {
    expect(ControlCmd.KEY_EXCHANGE).toBe(0x6);
  });

  test("make key exchange container", () => {
    const payload = new Uint8Array([0x01, ...new Array(32).fill(0x00)]);
    const c = makeKeyExchange(5, payload);
    expect(c.controlCmd).toBe(ControlCmd.KEY_EXCHANGE);
    expect(c.payload).toEqual(payload);
  });

  test("key exchange roundtrip", () => {
    const payload = new Uint8Array([0x02, ...new Array(128).fill(0xaa)]);
    const c = makeKeyExchange(10, payload);
    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.controlCmd).toBe(ControlCmd.KEY_EXCHANGE);
    expect(c2.payload).toEqual(payload);
  });
});

describe("Capabilities flags", () => {
  test("encryption flag constant", () => {
    expect(CAPABILITY_FLAG_ENCRYPTION_SUPPORTED).toBe(0x0001);
  });

  test("capabilities request 6 bytes", () => {
    const c = makeCapabilitiesRequest(1, {
      maxRequestPayloadSize: 1024,
      maxResponsePayloadSize: 2048,
      flags: CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
    });
    expect(c.payload.length).toBe(6);
    const bd = new DataView(c.payload.buffer, c.payload.byteOffset, c.payload.byteLength);
    expect(bd.getUint16(0, true)).toBe(1024);
    expect(bd.getUint16(2, true)).toBe(2048);
    expect(bd.getUint16(4, true)).toBe(CAPABILITY_FLAG_ENCRYPTION_SUPPORTED);
  });

  test("capabilities response 6 bytes", () => {
    const c = makeCapabilitiesResponse(2, {
      maxRequestPayloadSize: 4096,
      maxResponsePayloadSize: 65535,
      flags: CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
    });
    expect(c.payload.length).toBe(6);
    const bd = new DataView(c.payload.buffer, c.payload.byteOffset, c.payload.byteLength);
    expect(bd.getUint16(0, true)).toBe(4096);
    expect(bd.getUint16(2, true)).toBe(65535);
    expect(bd.getUint16(4, true)).toBe(1);
  });

  test("capabilities request default flags zero", () => {
    const c = makeCapabilitiesRequest(3);
    const bd = new DataView(c.payload.buffer, c.payload.byteOffset, c.payload.byteLength);
    expect(bd.getUint16(4, true)).toBe(0);
  });

  test("capabilities response default flags zero", () => {
    const c = makeCapabilitiesResponse(4, {
      maxRequestPayloadSize: 100,
      maxResponsePayloadSize: 200,
    });
    const bd = new DataView(c.payload.buffer, c.payload.byteOffset, c.payload.byteLength);
    expect(bd.getUint16(4, true)).toBe(0);
  });
});

describe("X25519", () => {
  test("keygen produces 32-byte keys", () => {
    const [priv, pubkey] = BlerpcCrypto.generateX25519KeyPair();
    const pubBytes = BlerpcCrypto.x25519PublicKey(priv);
    expect(pubkey.length).toBe(32);
    expect(pubBytes.length).toBe(32);
    expect(pubkey).toEqual(pubBytes);
  });

  test("shared secret agreement", () => {
    const [privA, pubA] = BlerpcCrypto.generateX25519KeyPair();
    const [privB, pubB] = BlerpcCrypto.generateX25519KeyPair();

    const secretA = BlerpcCrypto.x25519SharedSecret(privA, pubB);
    const secretB = BlerpcCrypto.x25519SharedSecret(privB, pubA);

    expect(secretA.length).toBe(32);
    expect(secretA).toEqual(secretB);
  });

  test("different keys different secrets", () => {
    const [privA] = BlerpcCrypto.generateX25519KeyPair();
    const [, pubB] = BlerpcCrypto.generateX25519KeyPair();
    const [, pubC] = BlerpcCrypto.generateX25519KeyPair();

    const secretAB = BlerpcCrypto.x25519SharedSecret(privA, pubB);
    const secretAC = BlerpcCrypto.x25519SharedSecret(privA, pubC);

    expect(secretAB).not.toEqual(secretAC);
  });
});

describe("Ed25519", () => {
  test("sign verify roundtrip", () => {
    const [privkey, pubkey] = BlerpcCrypto.generateEd25519KeyPair();
    const message = new TextEncoder().encode("test message");
    const signature = BlerpcCrypto.ed25519Sign(privkey, message);

    expect(signature.length).toBe(64);
    expect(BlerpcCrypto.ed25519Verify(pubkey, message, signature)).toBe(true);
  });

  test("verify wrong message fails", () => {
    const [privkey, pubkey] = BlerpcCrypto.generateEd25519KeyPair();
    const signature = BlerpcCrypto.ed25519Sign(
      privkey,
      new TextEncoder().encode("correct message"),
    );
    expect(
      BlerpcCrypto.ed25519Verify(pubkey, new TextEncoder().encode("wrong message"), signature),
    ).toBe(false);
  });

  test("verify wrong key fails", () => {
    const [priv1, pub1] = BlerpcCrypto.generateEd25519KeyPair();
    const [, pub2] = BlerpcCrypto.generateEd25519KeyPair();

    const message = new TextEncoder().encode("test");
    const signature = BlerpcCrypto.ed25519Sign(priv1, message);
    expect(BlerpcCrypto.ed25519Verify(pub1, message, signature)).toBe(true);
    expect(BlerpcCrypto.ed25519Verify(pub2, message, signature)).toBe(false);
  });

  test("public key from private key", () => {
    const [privkey, pubkey] = BlerpcCrypto.generateEd25519KeyPair();
    const derived = BlerpcCrypto.ed25519PublicKey(privkey);
    expect(derived).toEqual(pubkey);
  });
});

describe("Session key derivation", () => {
  test("derive produces 16 bytes", () => {
    const shared = new Uint8Array(32).fill(0x42);
    const cPub = new Uint8Array(32).fill(0xaa);
    const pPub = new Uint8Array(32).fill(0xbb);
    const key = BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
    expect(key.length).toBe(16);
  });

  test("same inputs same key", () => {
    const shared = new Uint8Array(32).fill(0x42);
    const cPub = new Uint8Array(32).fill(0xaa);
    const pPub = new Uint8Array(32).fill(0xbb);
    const key1 = BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
    const key2 = BlerpcCrypto.deriveSessionKey(shared, cPub, pPub);
    expect(key1).toEqual(key2);
  });

  test("different pubkeys different key", () => {
    const shared = new Uint8Array(32).fill(0x42);
    const cPubA = new Uint8Array(32).fill(0xaa);
    const cPubB = new Uint8Array(32).fill(0xcc);
    const pPub = new Uint8Array(32).fill(0xbb);
    const key1 = BlerpcCrypto.deriveSessionKey(shared, cPubA, pPub);
    const key2 = BlerpcCrypto.deriveSessionKey(shared, cPubB, pPub);
    expect(key1).not.toEqual(key2);
  });
});

describe("AES-GCM encrypt/decrypt", () => {
  test("encrypt decrypt command roundtrip", () => {
    const key = new Uint8Array(16).fill(0x01);
    const plaintext = new TextEncoder().encode("Hello, blerpc!");
    const encrypted = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_C2P, plaintext);

    expect(encrypted.length).toBe(4 + plaintext.length + 16);

    const [counter, decrypted] = BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, encrypted);
    expect(counter).toBe(0);
    expect(decrypted).toEqual(plaintext);
  });

  test("different directions produce different ciphertext", () => {
    const key = new Uint8Array(16).fill(0x01);
    const plaintext = new TextEncoder().encode("test");
    const encC2P = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_C2P, plaintext);
    const encP2C = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_P2C, plaintext);
    expect(encC2P).not.toEqual(encP2C);
  });

  test("wrong direction fails decrypt", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encrypted = BlerpcCrypto.encryptCommand(
      key,
      0,
      DIRECTION_C2P,
      new TextEncoder().encode("test"),
    );
    expect(() => BlerpcCrypto.decryptCommand(key, DIRECTION_P2C, encrypted)).toThrow();
  });

  test("wrong key fails decrypt", () => {
    const key1 = new Uint8Array(16).fill(0x01);
    const key2 = new Uint8Array(16).fill(0x02);
    const encrypted = BlerpcCrypto.encryptCommand(
      key1,
      0,
      DIRECTION_C2P,
      new TextEncoder().encode("test"),
    );
    expect(() => BlerpcCrypto.decryptCommand(key2, DIRECTION_C2P, encrypted)).toThrow();
  });

  test("counter embedded in output", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encrypted = BlerpcCrypto.encryptCommand(
      key,
      42,
      DIRECTION_C2P,
      new TextEncoder().encode("data"),
    );
    const bd = new DataView(encrypted.buffer, encrypted.byteOffset, encrypted.byteLength);
    expect(bd.getUint32(0, true)).toBe(42);
  });

  test("empty plaintext", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encrypted = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_C2P, new Uint8Array(0));
    const [counter, decrypted] = BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, encrypted);
    expect(counter).toBe(0);
    expect(decrypted.length).toBe(0);
  });

  test("large plaintext", () => {
    const key = new Uint8Array(16).fill(0x01);
    const plaintext = new Uint8Array(10000).fill(0xff);
    const encrypted = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_C2P, plaintext);
    const [, decrypted] = BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, encrypted);
    expect(decrypted).toEqual(plaintext);
  });

  test("decrypt too short raises", () => {
    const key = new Uint8Array(16).fill(0x01);
    expect(() => BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, new Uint8Array(19))).toThrow(
      /too short/,
    );
  });
});

describe("Confirmation", () => {
  test("encrypt decrypt confirmation roundtrip", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encrypted = BlerpcCrypto.encryptConfirmation(key, CONFIRM_CENTRAL);
    expect(encrypted.length).toBe(44);

    const plaintext = BlerpcCrypto.decryptConfirmation(key, encrypted);
    expect(plaintext).toEqual(CONFIRM_CENTRAL);
  });

  test("different messages different output", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encC = BlerpcCrypto.encryptConfirmation(key, CONFIRM_CENTRAL);
    const encP = BlerpcCrypto.encryptConfirmation(key, CONFIRM_PERIPHERAL);
    expect(encC).not.toEqual(encP);
  });

  test("wrong key fails", () => {
    const key1 = new Uint8Array(16).fill(0x01);
    const key2 = new Uint8Array(16).fill(0x02);
    const encrypted = BlerpcCrypto.encryptConfirmation(key1, CONFIRM_CENTRAL);
    expect(() => BlerpcCrypto.decryptConfirmation(key2, encrypted)).toThrow();
  });
});

describe("Step payloads", () => {
  test("step1 build parse", () => {
    const pubkey = new Uint8Array(32).fill(0xaa);
    const payload = BlerpcCrypto.buildStep1Payload(pubkey);
    expect(payload.length).toBe(33);
    expect(payload[0]).toBe(KEY_EXCHANGE_STEP1);
    const parsed = BlerpcCrypto.parseStep1Payload(payload);
    expect(parsed).toEqual(pubkey);
  });

  test("step2 build parse", () => {
    const x25519Pub = new Uint8Array(32).fill(0xaa);
    const signature = new Uint8Array(64).fill(0xbb);
    const ed25519Pub = new Uint8Array(32).fill(0xcc);
    const payload = BlerpcCrypto.buildStep2Payload(x25519Pub, signature, ed25519Pub);
    expect(payload.length).toBe(129);
    expect(payload[0]).toBe(KEY_EXCHANGE_STEP2);
    const [pX25519, pSig, pEd25519] = BlerpcCrypto.parseStep2Payload(payload);
    expect(pX25519).toEqual(x25519Pub);
    expect(pSig).toEqual(signature);
    expect(pEd25519).toEqual(ed25519Pub);
  });

  test("step3 build parse", () => {
    const encrypted = new Uint8Array(44).fill(0xdd);
    const payload = BlerpcCrypto.buildStep3Payload(encrypted);
    expect(payload.length).toBe(45);
    expect(payload[0]).toBe(KEY_EXCHANGE_STEP3);
    const parsed = BlerpcCrypto.parseStep3Payload(payload);
    expect(parsed).toEqual(encrypted);
  });

  test("step4 build parse", () => {
    const encrypted = new Uint8Array(44).fill(0xee);
    const payload = BlerpcCrypto.buildStep4Payload(encrypted);
    expect(payload.length).toBe(45);
    expect(payload[0]).toBe(KEY_EXCHANGE_STEP4);
    const parsed = BlerpcCrypto.parseStep4Payload(payload);
    expect(parsed).toEqual(encrypted);
  });

  test("step1 invalid short", () => {
    expect(() =>
      BlerpcCrypto.parseStep1Payload(new Uint8Array([0x01, ...new Array(10).fill(0x00)])),
    ).toThrow(/Invalid step 1/);
  });

  test("step1 invalid step byte", () => {
    expect(() =>
      BlerpcCrypto.parseStep1Payload(new Uint8Array([0x02, ...new Array(32).fill(0x00)])),
    ).toThrow(/Invalid step 1/);
  });

  test("step2 invalid short", () => {
    expect(() =>
      BlerpcCrypto.parseStep2Payload(new Uint8Array([0x02, ...new Array(50).fill(0x00)])),
    ).toThrow(/Invalid step 2/);
  });
});

describe("Full key exchange flow", () => {
  test("full handshake", () => {
    // Peripheral's long-term keys
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();
    const [periphXPriv, periphXPub] = BlerpcCrypto.generateX25519KeyPair();

    // Step 1: Central generates ephemeral keypair
    const [centralXPriv, centralXPub] = BlerpcCrypto.generateX25519KeyPair();
    const step1 = BlerpcCrypto.buildStep1Payload(centralXPub);
    const parsedCentralPub = BlerpcCrypto.parseStep1Payload(step1);
    expect(parsedCentralPub).toEqual(centralXPub);

    // Step 2: Peripheral signs and responds
    const signMsg = new Uint8Array([...centralXPub, ...periphXPub]);
    const signature = BlerpcCrypto.ed25519Sign(periphEdPriv, signMsg);
    const step2 = BlerpcCrypto.buildStep2Payload(periphXPub, signature, periphEdPub);

    // Central parses and verifies
    const [pXPub, pSig, pEdPub] = BlerpcCrypto.parseStep2Payload(step2);
    expect(pXPub).toEqual(periphXPub);
    expect(BlerpcCrypto.ed25519Verify(pEdPub, signMsg, pSig)).toBe(true);

    // Both derive shared secret and session key
    const sharedC = BlerpcCrypto.x25519SharedSecret(centralXPriv, periphXPub);
    const sharedP = BlerpcCrypto.x25519SharedSecret(periphXPriv, centralXPub);
    expect(sharedC).toEqual(sharedP);

    const sessionKeyC = BlerpcCrypto.deriveSessionKey(sharedC, centralXPub, periphXPub);
    const sessionKeyP = BlerpcCrypto.deriveSessionKey(sharedP, centralXPub, periphXPub);
    expect(sessionKeyC).toEqual(sessionKeyP);

    // Step 3: Central sends confirmation
    const encConfirmC = BlerpcCrypto.encryptConfirmation(sessionKeyC, CONFIRM_CENTRAL);
    const step3 = BlerpcCrypto.buildStep3Payload(encConfirmC);
    const parsedEnc = BlerpcCrypto.parseStep3Payload(step3);
    const decConfirmC = BlerpcCrypto.decryptConfirmation(sessionKeyP, parsedEnc);
    expect(decConfirmC).toEqual(CONFIRM_CENTRAL);

    // Step 4: Peripheral sends confirmation
    const encConfirmP = BlerpcCrypto.encryptConfirmation(sessionKeyP, CONFIRM_PERIPHERAL);
    const step4 = BlerpcCrypto.buildStep4Payload(encConfirmP);
    const parsedEnc4 = BlerpcCrypto.parseStep4Payload(step4);
    const decConfirmP = BlerpcCrypto.decryptConfirmation(sessionKeyC, parsedEnc4);
    expect(decConfirmP).toEqual(CONFIRM_PERIPHERAL);
  });

  test("encrypted command after handshake", () => {
    const key = new Uint8Array(16).fill(0x01);

    // Central sends encrypted command (C->P)
    const plaintext = new TextEncoder().encode("echo request data");
    const encrypted = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_C2P, plaintext);

    // Peripheral decrypts
    const [counter, decrypted] = BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, encrypted);
    expect(counter).toBe(0);
    expect(decrypted).toEqual(plaintext);

    // Peripheral sends encrypted response (P->C)
    const respPlaintext = new TextEncoder().encode("echo response data");
    const respEncrypted = BlerpcCrypto.encryptCommand(key, 0, DIRECTION_P2C, respPlaintext);

    // Central decrypts
    const [respCounter, respDecrypted] = BlerpcCrypto.decryptCommand(
      key,
      DIRECTION_P2C,
      respEncrypted,
    );
    expect(respCounter).toBe(0);
    expect(respDecrypted).toEqual(respPlaintext);
  });

  test("counter monotonic increase", () => {
    const key = new Uint8Array(16).fill(0x01);
    const encoder = new TextEncoder();

    for (let i = 0; i < 5; i++) {
      const encrypted = BlerpcCrypto.encryptCommand(
        key,
        i,
        DIRECTION_C2P,
        encoder.encode(`msg${i}`),
      );
      const [counter, decrypted] = BlerpcCrypto.decryptCommand(key, DIRECTION_C2P, encrypted);
      expect(counter).toBe(i);
      expect(decrypted).toEqual(encoder.encode(`msg${i}`));
    }
  });
});

describe("BlerpcCryptoSession", () => {
  test("encrypt decrypt roundtrip", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);
    const peripheral = new BlerpcCryptoSession(key, false);

    const plaintext = new TextEncoder().encode("Hello, blerpc!");
    const encrypted = central.encrypt(plaintext);
    const decrypted = peripheral.decrypt(encrypted);
    expect(decrypted).toEqual(plaintext);
  });

  test("bidirectional", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);
    const peripheral = new BlerpcCryptoSession(key, false);
    const encoder = new TextEncoder();

    // Central -> Peripheral
    const enc1 = central.encrypt(encoder.encode("request"));
    expect(peripheral.decrypt(enc1)).toEqual(encoder.encode("request"));

    // Peripheral -> Central
    const enc2 = peripheral.encrypt(encoder.encode("response"));
    expect(central.decrypt(enc2)).toEqual(encoder.encode("response"));
  });

  test("counter auto increment", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);
    const peripheral = new BlerpcCryptoSession(key, false);
    const encoder = new TextEncoder();

    for (let i = 0; i < 5; i++) {
      const enc = central.encrypt(encoder.encode(`msg${i}`));
      const bd = new DataView(enc.buffer, enc.byteOffset, enc.byteLength);
      expect(bd.getUint32(0, true)).toBe(i);
      expect(peripheral.decrypt(enc)).toEqual(encoder.encode(`msg${i}`));
    }
  });

  test("replay detection", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);
    const peripheral = new BlerpcCryptoSession(key, false);
    const encoder = new TextEncoder();

    const enc0 = central.encrypt(encoder.encode("msg0"));
    const enc1 = central.encrypt(encoder.encode("msg1"));

    peripheral.decrypt(enc0);
    peripheral.decrypt(enc1);

    // Replaying enc0 should fail
    expect(() => peripheral.decrypt(enc0)).toThrow(/Replay/);
  });

  test("counter zero replay attack", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);
    const peripheral = new BlerpcCryptoSession(key, false);
    const encoder = new TextEncoder();

    const enc0 = central.encrypt(encoder.encode("msg0"));
    peripheral.decrypt(enc0);

    // Replaying counter-0 message should fail
    expect(() => peripheral.decrypt(enc0)).toThrow(/Replay/);
  });

  test("wrong direction fails", () => {
    const key = new Uint8Array(16).fill(0x01);
    const central = new BlerpcCryptoSession(key, true);

    const enc = central.encrypt(new TextEncoder().encode("test"));
    expect(() => central.decrypt(enc)).toThrow();
  });
});

describe("CentralKeyExchange", () => {
  function makePeripheralKeys(): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
    const [xPriv, xPub] = BlerpcCrypto.generateX25519KeyPair();
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    return [xPriv, xPub, edPriv, edPub];
  }

  test("start produces step1", () => {
    const kx = new CentralKeyExchange();
    const step1 = kx.start();
    expect(step1.length).toBe(33);
    expect(step1[0]).toBe(KEY_EXCHANGE_STEP1);
  });

  test("processStep2 verifies signature", () => {
    const kx = new CentralKeyExchange();
    const step1 = kx.start();
    const centralPub = BlerpcCrypto.parseStep1Payload(step1);

    const [, xPub, edPriv, edPub] = makePeripheralKeys();

    const signMsg = new Uint8Array([...centralPub, ...xPub]);
    const signature = BlerpcCrypto.ed25519Sign(edPriv, signMsg);
    const step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

    const step3 = kx.processStep2(step2);
    expect(step3.length).toBe(45);
    expect(step3[0]).toBe(KEY_EXCHANGE_STEP3);
  });

  test("processStep2 bad signature raises", () => {
    const kx = new CentralKeyExchange();
    kx.start();

    const [, xPub, , edPub] = makePeripheralKeys();
    const badSig = new Uint8Array(64);
    const step2 = BlerpcCrypto.buildStep2Payload(xPub, badSig, edPub);

    expect(() => kx.processStep2(step2)).toThrow(/signature/);
  });

  test("verify key callback reject", () => {
    const kx = new CentralKeyExchange();
    const step1 = kx.start();
    const centralPub = BlerpcCrypto.parseStep1Payload(step1);

    const [, xPub, edPriv, edPub] = makePeripheralKeys();
    const signMsg = new Uint8Array([...centralPub, ...xPub]);
    const signature = BlerpcCrypto.ed25519Sign(edPriv, signMsg);
    const step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

    expect(() => kx.processStep2(step2, () => false)).toThrow(/rejected/);
  });

  test("verify key callback accept", () => {
    const kx = new CentralKeyExchange();
    const step1 = kx.start();
    const centralPub = BlerpcCrypto.parseStep1Payload(step1);

    const [, xPub, edPriv, edPub] = makePeripheralKeys();
    const signMsg = new Uint8Array([...centralPub, ...xPub]);
    const signature = BlerpcCrypto.ed25519Sign(edPriv, signMsg);
    const step2 = BlerpcCrypto.buildStep2Payload(xPub, signature, edPub);

    let receivedKey: Uint8Array | null = null;
    const step3 = kx.processStep2(step2, (k) => {
      receivedKey = k;
      return true;
    });
    expect(receivedKey).toEqual(edPub);
    expect(step3.length).toBe(45);
  });
});

describe("PeripheralKeyExchange", () => {
  test("processStep1 produces step2", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    const [, centralXPub] = BlerpcCrypto.generateX25519KeyPair();
    const step1 = BlerpcCrypto.buildStep1Payload(centralXPub);

    const step2 = kx.processStep1(step1);
    expect(step2.length).toBe(129);
    expect(step2[0]).toBe(KEY_EXCHANGE_STEP2);
  });

  test("processStep3 bad confirmation raises", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    const [, centralXPub] = BlerpcCrypto.generateX25519KeyPair();
    const step1 = BlerpcCrypto.buildStep1Payload(centralXPub);
    kx.processStep1(step1);

    // Build a step 3 with wrong confirmation text
    const badEncrypted = BlerpcCrypto.encryptConfirmation(
      kx.sessionKey!,
      new TextEncoder().encode("WRONG_CONFIRM_XX"),
    );
    const badStep3 = BlerpcCrypto.buildStep3Payload(badEncrypted);

    expect(() => kx.processStep3(badStep3)).toThrow(/confirmation/);
  });
});

describe("Key exchange integration", () => {
  test("full handshake and session", () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();

    const centralKx = new CentralKeyExchange();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const step1 = centralKx.start();
    const step2 = periphKx.processStep1(step1);
    const step3 = centralKx.processStep2(step2);
    const [step4, periphSession] = periphKx.processStep3(step3);
    const centralSession = centralKx.finish(step4);

    const encoder = new TextEncoder();

    // Bidirectional encrypted communication
    const encReq = centralSession.encrypt(encoder.encode("echo request"));
    expect(periphSession.decrypt(encReq)).toEqual(encoder.encode("echo request"));

    const encResp = periphSession.encrypt(encoder.encode("echo response"));
    expect(centralSession.decrypt(encResp)).toEqual(encoder.encode("echo response"));
  });

  test("handshake with verify callback", () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();

    const centralKx = new CentralKeyExchange();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const step1 = centralKx.start();
    const step2 = periphKx.processStep1(step1);

    const seenKeys: Uint8Array[] = [];
    const step3 = centralKx.processStep2(step2, (k) => {
      seenKeys.push(k);
      return true;
    });
    expect(seenKeys[0]).toEqual(periphEdPub);

    const [step4, periphSession] = periphKx.processStep3(step3);
    const centralSession = centralKx.finish(step4);

    const encoder = new TextEncoder();
    const enc = centralSession.encrypt(encoder.encode("test"));
    expect(periphSession.decrypt(enc)).toEqual(encoder.encode("test"));
  });

  test("multiple messages after handshake", () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();

    const centralKx = new CentralKeyExchange();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const step1 = centralKx.start();
    const step2 = periphKx.processStep1(step1);
    const step3 = centralKx.processStep2(step2);
    const [step4, periphSession] = periphKx.processStep3(step3);
    const centralSession = centralKx.finish(step4);

    const encoder = new TextEncoder();
    for (let i = 0; i < 20; i++) {
      const msg = encoder.encode(`c2p_${i}`);
      const enc = centralSession.encrypt(msg);
      expect(periphSession.decrypt(enc)).toEqual(msg);

      const resp = encoder.encode(`p2c_${i}`);
      const encResp = periphSession.encrypt(resp);
      expect(centralSession.decrypt(encResp)).toEqual(resp);
    }
  });
});

describe("Peripheral handleStep", () => {
  test("handle step 1", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    const [, centralXPub] = BlerpcCrypto.generateX25519KeyPair();
    const step1 = BlerpcCrypto.buildStep1Payload(centralXPub);

    const [response, session] = kx.handleStep(step1);
    expect(response[0]).toBe(KEY_EXCHANGE_STEP2);
    expect(response.length).toBe(129);
    expect(session).toBeNull();
  });

  test("handle step 3", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    const centralKx = new CentralKeyExchange();

    const step1 = centralKx.start();
    const [step2, session1] = kx.handleStep(step1);
    expect(session1).toBeNull();

    const step3 = centralKx.processStep2(step2);
    const [step4, session2] = kx.handleStep(step3);
    expect(step4[0]).toBe(KEY_EXCHANGE_STEP4);
    expect(step4.length).toBe(45);
    expect(session2).not.toBeNull();
  });

  test("handle step invalid", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    expect(() => kx.handleStep(new Uint8Array([0x02, ...new Array(128).fill(0x00)]))).toThrow(
      /Invalid/,
    );
  });

  test("handle step empty payload", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    expect(() => kx.handleStep(new Uint8Array(0))).toThrow(/Empty/);
  });
});

describe("centralPerformKeyExchange", () => {
  test("full handshake", async () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const payloads: Uint8Array[] = [];

    async function mockSend(payload: Uint8Array) {
      const [response] = periphKx.handleStep(payload);
      payloads.push(response);
    }

    async function mockReceive() {
      return payloads.shift()!;
    }

    const session = await centralPerformKeyExchange({
      send: mockSend,
      receive: mockReceive,
    });

    // Verify session works
    const periphSession = new BlerpcCryptoSession(periphKx.sessionKey!, false);
    const enc = session.encrypt(new TextEncoder().encode("test"));
    expect(periphSession.decrypt(enc)).toEqual(new TextEncoder().encode("test"));
  });

  test("verify callback reject", async () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const payloads: Uint8Array[] = [];

    async function mockSend(payload: Uint8Array) {
      const [response] = periphKx.handleStep(payload);
      payloads.push(response);
    }

    async function mockReceive() {
      return payloads.shift()!;
    }

    await expect(
      centralPerformKeyExchange({
        send: mockSend,
        receive: mockReceive,
        verifyKeyCb: () => false,
      }),
    ).rejects.toThrow(/rejected/);
  });

  test("verify callback accept", async () => {
    const [periphEdPriv, periphEdPub] = BlerpcCrypto.generateEd25519KeyPair();
    const periphKx = new PeripheralKeyExchange(periphEdPriv, periphEdPub);

    const payloads: Uint8Array[] = [];
    const seenKeys: Uint8Array[] = [];

    async function mockSend(payload: Uint8Array) {
      const [response] = periphKx.handleStep(payload);
      payloads.push(response);
    }

    async function mockReceive() {
      return payloads.shift()!;
    }

    const session = await centralPerformKeyExchange({
      send: mockSend,
      receive: mockReceive,
      verifyKeyCb: (k) => {
        seenKeys.push(k);
        return true;
      },
    });
    expect(session).toBeTruthy();
    expect(seenKeys[0]).toEqual(periphEdPub);
  });
});

describe("Key exchange state validation", () => {
  test("central processStep2 before start raises", () => {
    const kx = new CentralKeyExchange();
    expect(() => kx.processStep2(new Uint8Array([0x02, ...new Array(128).fill(0x00)]))).toThrow();
  });

  test("central finish before processStep2 raises", () => {
    const kx = new CentralKeyExchange();
    kx.start();
    expect(() => kx.finish(new Uint8Array([0x04, ...new Array(44).fill(0x00)]))).toThrow();
  });

  test("central double start raises", () => {
    const kx = new CentralKeyExchange();
    kx.start();
    expect(() => kx.start()).toThrow();
  });

  test("peripheral processStep3 before step1 raises", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    expect(() => kx.processStep3(new Uint8Array([0x03, ...new Array(44).fill(0x00)]))).toThrow();
  });

  test("peripheral handleStep3 before step1 raises", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    expect(() => kx.handleStep(new Uint8Array([0x03, ...new Array(44).fill(0x00)]))).toThrow();
  });

  test("peripheral double step1 raises", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);
    const centralKx = new CentralKeyExchange();
    const step1 = centralKx.start();
    kx.processStep1(step1);
    expect(() => kx.processStep1(step1)).toThrow();
  });

  test("peripheral reset allows new handshake", () => {
    const [edPriv, edPub] = BlerpcCrypto.generateEd25519KeyPair();
    const kx = new PeripheralKeyExchange(edPriv, edPub);

    const centralKx = new CentralKeyExchange();
    const step1 = centralKx.start();
    kx.processStep1(step1);

    kx.reset();

    const centralKx2 = new CentralKeyExchange();
    const step1b = centralKx2.start();
    const step2 = kx.processStep1(step1b);
    expect(step2.length).toBe(129);
  });
});

describe("CryptoSession counter overflow", () => {
  test("encrypt at max counter raises", () => {
    const key = new Uint8Array(16).fill(0x01);
    const session = new BlerpcCryptoSession(key, true);
    session.txCounter = 0xffffffff;
    expect(() => session.encrypt(new TextEncoder().encode("test"))).toThrow(/overflow/);
  });

  test("encrypt below max counter works", () => {
    const key = new Uint8Array(16).fill(0x01);
    const session = new BlerpcCryptoSession(key, true);
    session.txCounter = 0xfffffffe;
    const encrypted = session.encrypt(new TextEncoder().encode("test"));
    expect(encrypted.length).toBeGreaterThan(0);
  });
});
