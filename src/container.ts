// Container serialize/deserialize for blerpc.
//
// Container format (bits):
// | transaction_id(8) | sequence_number(8) | type(2)|control_cmd(4)|reserved(2) |
// | total_length(16 or 0) | payload_len(8) | payload(variable) |
//
// type=0b00 (FIRST): has total_length, header = 6 bytes
// type=0b01 (SUBSEQUENT): no total_length, header = 4 bytes
// type=0b11 (CONTROL): no total_length, header = 4 bytes
//
// All multi-byte fields are little-endian.

import {
  ContainerType,
  ControlCmd,
  containerTypeFromValue,
  controlCmdFromValue,
  FIRST_HEADER_SIZE,
  SUBSEQUENT_HEADER_SIZE,
} from "./containerTypes";

/** Pack type(2) | control_cmd(4) | reserved(2) into a single byte. */
export function packFlags(type: ContainerType, cmd: ControlCmd = ControlCmd.NONE): number {
  return ((type & 0x03) << 6) | ((cmd & 0x0f) << 2);
}

/** Unpack flags byte into [type, controlCmd]. */
export function unpackFlags(flagsByte: number): [ContainerType, ControlCmd] {
  const type = containerTypeFromValue((flagsByte >> 6) & 0x03);
  const cmd = controlCmdFromValue((flagsByte >> 2) & 0x0f);
  return [type, cmd];
}

/** A single container packet. */
export class Container {
  readonly transactionId: number;
  readonly sequenceNumber: number;
  readonly containerType: ContainerType;
  readonly controlCmd: ControlCmd;
  readonly totalLength: number;
  readonly payload: Uint8Array;

  constructor(params: {
    transactionId: number;
    sequenceNumber: number;
    containerType: ContainerType;
    controlCmd?: ControlCmd;
    totalLength?: number;
    payload?: Uint8Array;
  }) {
    this.transactionId = params.transactionId;
    this.sequenceNumber = params.sequenceNumber;
    this.containerType = params.containerType;
    this.controlCmd = params.controlCmd ?? ControlCmd.NONE;
    this.totalLength = params.totalLength ?? 0;
    this.payload = params.payload ?? new Uint8Array(0);
  }

  /** Serialize container to bytes. */
  serialize(): Uint8Array {
    const flags = packFlags(this.containerType, this.controlCmd);

    if (this.containerType === ContainerType.FIRST) {
      const buf = new ArrayBuffer(FIRST_HEADER_SIZE + this.payload.length);
      const view = new DataView(buf);
      const bytes = new Uint8Array(buf);
      view.setUint8(0, this.transactionId);
      view.setUint8(1, this.sequenceNumber);
      view.setUint8(2, flags);
      view.setUint16(3, this.totalLength, true); // little-endian
      view.setUint8(5, this.payload.length);
      bytes.set(this.payload, FIRST_HEADER_SIZE);
      return bytes;
    } else {
      const buf = new ArrayBuffer(SUBSEQUENT_HEADER_SIZE + this.payload.length);
      const view = new DataView(buf);
      const bytes = new Uint8Array(buf);
      view.setUint8(0, this.transactionId);
      view.setUint8(1, this.sequenceNumber);
      view.setUint8(2, flags);
      view.setUint8(3, this.payload.length);
      bytes.set(this.payload, SUBSEQUENT_HEADER_SIZE);
      return bytes;
    }
  }

  /** Deserialize bytes into a Container. */
  static deserialize(data: Uint8Array): Container {
    if (data.length < 4) {
      throw new Error(`Container too short: ${data.length} bytes`);
    }

    const transactionId = data[0];
    const sequenceNumber = data[1];
    const [containerType, controlCmd] = unpackFlags(data[2]);

    if (containerType === ContainerType.FIRST) {
      if (data.length < FIRST_HEADER_SIZE) {
        throw new Error(`FIRST container too short: ${data.length} bytes`);
      }
      const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const totalLength = view.getUint16(3, true);
      const payloadLen = data[5];
      const payload = data.slice(FIRST_HEADER_SIZE, FIRST_HEADER_SIZE + payloadLen);
      return new Container({
        transactionId,
        sequenceNumber,
        containerType,
        controlCmd,
        totalLength,
        payload,
      });
    } else {
      const payloadLen = data[3];
      const payload = data.slice(SUBSEQUENT_HEADER_SIZE, SUBSEQUENT_HEADER_SIZE + payloadLen);
      return new Container({
        transactionId,
        sequenceNumber,
        containerType,
        controlCmd,
        payload,
      });
    }
  }
}
