// Factory functions for control containers.

import { Container } from "./container";
import { ContainerType, ControlCmd } from "./containerTypes";

/** Create a timeout request control container (Central -> Peripheral). */
export function makeTimeoutRequest(transactionId: number, sequenceNumber = 0): Container {
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.TIMEOUT,
  });
}

/** Create a timeout response control container (Peripheral -> Central). */
export function makeTimeoutResponse(
  transactionId: number,
  timeoutMs: number,
  sequenceNumber = 0,
): Container {
  const payload = new Uint8Array(2);
  const view = new DataView(payload.buffer);
  view.setUint16(0, timeoutMs, true);
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.TIMEOUT,
    payload,
  });
}

/** Create stream end container (Central -> Peripheral). */
export function makeStreamEndC2P(transactionId: number, sequenceNumber = 0): Container {
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.STREAM_END_C2P,
  });
}

/** Create stream end container (Peripheral -> Central). */
export function makeStreamEndP2C(transactionId: number, sequenceNumber = 0): Container {
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.STREAM_END_P2C,
  });
}

/**
 * Create a capabilities request control container (Central -> Peripheral).
 *
 * 6-byte payload: [max_req:u16LE][max_resp:u16LE][flags:u16LE]
 */
export function makeCapabilitiesRequest(
  transactionId: number,
  options: {
    maxRequestPayloadSize?: number;
    maxResponsePayloadSize?: number;
    flags?: number;
    sequenceNumber?: number;
  } = {},
): Container {
  const payload = new Uint8Array(6);
  const view = new DataView(payload.buffer);
  view.setUint16(0, options.maxRequestPayloadSize ?? 0, true);
  view.setUint16(2, options.maxResponsePayloadSize ?? 0, true);
  view.setUint16(4, options.flags ?? 0, true);
  return new Container({
    transactionId,
    sequenceNumber: options.sequenceNumber ?? 0,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.CAPABILITIES,
    payload,
  });
}

/**
 * Create a capabilities response control container (Peripheral -> Central).
 *
 * 6-byte payload: [max_req:u16LE][max_resp:u16LE][flags:u16LE]
 */
export function makeCapabilitiesResponse(
  transactionId: number,
  options: {
    maxRequestPayloadSize: number;
    maxResponsePayloadSize: number;
    flags?: number;
    sequenceNumber?: number;
  },
): Container {
  const payload = new Uint8Array(6);
  const view = new DataView(payload.buffer);
  view.setUint16(0, options.maxRequestPayloadSize, true);
  view.setUint16(2, options.maxResponsePayloadSize, true);
  view.setUint16(4, options.flags ?? 0, true);
  return new Container({
    transactionId,
    sequenceNumber: options.sequenceNumber ?? 0,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.CAPABILITIES,
    payload,
  });
}

/** Create an error control container (Peripheral -> Central). */
export function makeErrorResponse(
  transactionId: number,
  errorCode: number,
  sequenceNumber = 0,
): Container {
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.ERROR,
    payload: new Uint8Array([errorCode]),
  });
}

/** Create a key exchange control container. */
export function makeKeyExchange(
  transactionId: number,
  payload: Uint8Array,
  sequenceNumber = 0,
): Container {
  return new Container({
    transactionId,
    sequenceNumber,
    containerType: ContainerType.CONTROL,
    controlCmd: ControlCmd.KEY_EXCHANGE,
    payload,
  });
}
