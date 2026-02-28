// Pure TypeScript protocol library for blerpc — container, command, and encryption
// layers for BLE RPC.

export {
  ContainerType,
  containerTypeFromValue,
  ControlCmd,
  controlCmdFromValue,
  BLERPC_ERROR_RESPONSE_TOO_LARGE,
  BLERPC_ERROR_BUSY,
  CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
  FIRST_HEADER_SIZE,
  SUBSEQUENT_HEADER_SIZE,
  CONTROL_HEADER_SIZE,
  ATT_OVERHEAD,
} from "./containerTypes";

export { packFlags, unpackFlags, Container } from "./container";

export { ContainerSplitter } from "./containerSplitter";

export { ContainerAssembler } from "./containerAssembler";

export { CommandType, CommandPacket } from "./commandPacket";

export {
  makeTimeoutRequest,
  makeTimeoutResponse,
  makeStreamEndC2P,
  makeStreamEndP2C,
  makeCapabilitiesRequest,
  makeCapabilitiesResponse,
  makeErrorResponse,
  makeKeyExchange,
} from "./controlContainers";

export {
  DIRECTION_C2P,
  DIRECTION_P2C,
  CONFIRM_CENTRAL,
  CONFIRM_PERIPHERAL,
  KEY_EXCHANGE_STEP1,
  KEY_EXCHANGE_STEP2,
  KEY_EXCHANGE_STEP3,
  KEY_EXCHANGE_STEP4,
  BlerpcCrypto,
  BlerpcCryptoSession,
  CentralKeyExchange,
  PeripheralKeyExchange,
  centralPerformKeyExchange,
} from "./crypto";
