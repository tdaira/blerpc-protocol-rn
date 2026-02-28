// Command encode/decode layer for blerpc.
//
// Command format (bits):
// | type(1) | reserved(7) | cmd_name_len(8) | cmd_name(N*8) |
// | data_len(16) | data(data_len*8) |
//
// - type: 0=request, 1=response
// - cmd_name: ASCII command name
// - data_len: little-endian uint16
// - data: protobuf-encoded bytes

/** Command type: REQUEST or RESPONSE. */
export enum CommandType {
  REQUEST = 0,
  RESPONSE = 1,
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("ascii");

/** A single command packet. */
export class CommandPacket {
  readonly cmdType: CommandType;
  readonly cmdName: string;
  readonly data: Uint8Array;

  constructor(params: { cmdType: CommandType; cmdName: string; data?: Uint8Array }) {
    this.cmdType = params.cmdType;
    this.cmdName = params.cmdName;
    this.data = params.data ?? new Uint8Array(0);
  }

  /** Serialize command to bytes. */
  serialize(): Uint8Array {
    const nameBytes = textEncoder.encode(this.cmdName);
    if (nameBytes.length > 255) {
      throw new Error(`cmd_name too long: ${nameBytes.length} > 255`);
    }
    if (this.data.length > 65535) {
      throw new Error(`data too long: ${this.data.length} > 65535`);
    }

    // Byte 0: type in MSB (bit 7), reserved bits 6-0 = 0
    const byte0 = (this.cmdType & 0x01) << 7;
    const totalLen = 1 + 1 + nameBytes.length + 2 + this.data.length;
    const buf = new ArrayBuffer(totalLen);
    const view = new DataView(buf);
    const bytes = new Uint8Array(buf);
    let offset = 0;

    view.setUint8(offset++, byte0);
    view.setUint8(offset++, nameBytes.length);
    bytes.set(nameBytes, offset);
    offset += nameBytes.length;
    view.setUint16(offset, this.data.length, true); // little-endian
    offset += 2;
    bytes.set(this.data, offset);

    return bytes;
  }

  /** Deserialize bytes into a CommandPacket. */
  static deserialize(data: Uint8Array): CommandPacket {
    if (data.length < 2) {
      throw new Error(`Command packet too short: ${data.length} bytes`);
    }

    // Byte 0: type in MSB
    const cmdType = ((data[0] >> 7) & 0x01) === 0 ? CommandType.REQUEST : CommandType.RESPONSE;
    const cmdNameLen = data[1];

    let offset = 2;
    if (data.length < offset + cmdNameLen + 2) {
      throw new Error("Command packet truncated");
    }

    const cmdName = textDecoder.decode(data.slice(offset, offset + cmdNameLen));
    offset += cmdNameLen;

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const dataLen = view.getUint16(offset, true);
    offset += 2;

    const payload = data.slice(offset, offset + dataLen);
    return new CommandPacket({
      cmdType,
      cmdName,
      data: payload,
    });
  }
}
