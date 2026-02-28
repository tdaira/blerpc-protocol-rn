// Container types, control commands, and protocol constants for blerpc.

/** Container type field (2 bits in flags byte). */
export enum ContainerType {
  FIRST = 0x00,
  SUBSEQUENT = 0x01,
  CONTROL = 0x03,
}

export function containerTypeFromValue(v: number): ContainerType {
  switch (v) {
    case 0x00:
      return ContainerType.FIRST;
    case 0x01:
      return ContainerType.SUBSEQUENT;
    case 0x03:
      return ContainerType.CONTROL;
    default:
      throw new Error(`Unknown ContainerType: ${v}`);
  }
}

/** Control command field (4 bits in flags byte). */
export enum ControlCmd {
  NONE = 0x0,
  TIMEOUT = 0x1,
  STREAM_END_C2P = 0x2,
  STREAM_END_P2C = 0x3,
  CAPABILITIES = 0x4,
  ERROR = 0x5,
  KEY_EXCHANGE = 0x6,
}

export function controlCmdFromValue(v: number): ControlCmd {
  switch (v) {
    case 0x0:
      return ControlCmd.NONE;
    case 0x1:
      return ControlCmd.TIMEOUT;
    case 0x2:
      return ControlCmd.STREAM_END_C2P;
    case 0x3:
      return ControlCmd.STREAM_END_P2C;
    case 0x4:
      return ControlCmd.CAPABILITIES;
    case 0x5:
      return ControlCmd.ERROR;
    case 0x6:
      return ControlCmd.KEY_EXCHANGE;
    default:
      throw new Error(`Unknown ControlCmd: ${v}`);
  }
}

// Error codes for ControlCmd.ERROR
export const BLERPC_ERROR_RESPONSE_TOO_LARGE = 0x01;
export const BLERPC_ERROR_BUSY = 0x02;

// Capabilities flags (bit field)
export const CAPABILITY_FLAG_ENCRYPTION_SUPPORTED = 0x0001;

// Header sizes
/** txnId(1) + seq(1) + flags(1) + totalLen(2) + payloadLen(1) */
export const FIRST_HEADER_SIZE = 6;
/** txnId(1) + seq(1) + flags(1) + payloadLen(1) */
export const SUBSEQUENT_HEADER_SIZE = 4;
/** txnId(1) + seq(1) + flags(1) + payloadLen(1) */
export const CONTROL_HEADER_SIZE = 4;

// ATT header bytes subtracted from MTU
export const ATT_OVERHEAD = 3;
