import { CommandPacket, CommandType } from "../src";

describe("CommandPacket serialize", () => {
  test("serialize request", () => {
    const cmd = new CommandPacket({
      cmdType: CommandType.REQUEST,
      cmdName: "echo",
      data: new Uint8Array([0x01, 0x02]),
    });
    const raw = cmd.serialize();
    // Byte 0: type=0 in MSB => 0x00
    expect(raw[0]).toBe(0x00);
    // Byte 1: cmd_name_len = 4
    expect(raw[1]).toBe(4);
    // Bytes 2-5: "echo"
    const encoder = new TextEncoder();
    expect(raw.slice(2, 6)).toEqual(encoder.encode("echo"));
    // Bytes 6-7: data_len = 2 (little-endian)
    const bd = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    expect(bd.getUint16(6, true)).toBe(2);
    // Bytes 8-9: data
    expect(raw.slice(8, 10)).toEqual(new Uint8Array([0x01, 0x02]));
  });

  test("serialize response", () => {
    const cmd = new CommandPacket({
      cmdType: CommandType.RESPONSE,
      cmdName: "echo",
      data: new Uint8Array([0x03]),
    });
    const raw = cmd.serialize();
    // Byte 0: type=1 in MSB => 0x80
    expect(raw[0]).toBe(0x80);
  });

  test("roundtrip request", () => {
    const original = new CommandPacket({
      cmdType: CommandType.REQUEST,
      cmdName: "flash_read",
      data: new Uint8Array([0xaa, 0xbb, 0xcc]),
    });
    const raw = original.serialize();
    const decoded = CommandPacket.deserialize(raw);
    expect(decoded.cmdType).toBe(CommandType.REQUEST);
    expect(decoded.cmdName).toBe("flash_read");
    expect(decoded.data).toEqual(new Uint8Array([0xaa, 0xbb, 0xcc]));
  });

  test("roundtrip response", () => {
    const encoder = new TextEncoder();
    const original = new CommandPacket({
      cmdType: CommandType.RESPONSE,
      cmdName: "echo",
      data: encoder.encode("hello"),
    });
    const raw = original.serialize();
    const decoded = CommandPacket.deserialize(raw);
    expect(decoded.cmdType).toBe(CommandType.RESPONSE);
    expect(decoded.cmdName).toBe("echo");
    expect(decoded.data).toEqual(encoder.encode("hello"));
  });

  test("ASCII cmd_name", () => {
    const cmd = new CommandPacket({
      cmdType: CommandType.REQUEST,
      cmdName: "test_cmd_123",
    });
    const raw = cmd.serialize();
    const decoded = CommandPacket.deserialize(raw);
    expect(decoded.cmdName).toBe("test_cmd_123");
  });

  test("empty data", () => {
    const cmd = new CommandPacket({
      cmdType: CommandType.REQUEST,
      cmdName: "ping",
    });
    const raw = cmd.serialize();
    const decoded = CommandPacket.deserialize(raw);
    expect(decoded.data.length).toBe(0);
    // data_len should be 0
    const nameLen = raw[1];
    const bd = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    expect(bd.getUint16(2 + nameLen, true)).toBe(0);
  });

  test("data_len little endian", () => {
    const data = new Uint8Array(300);
    const cmd = new CommandPacket({
      cmdType: CommandType.REQUEST,
      cmdName: "x",
      data,
    });
    const raw = cmd.serialize();
    // cmd_name_len=1, cmd_name="x"(1 byte), data_len at offset 3
    const dataLenBytes = raw.slice(3, 5);
    const expected = new Uint8Array(2);
    new DataView(expected.buffer).setUint16(0, 300, true);
    expect(dataLenBytes).toEqual(expected);
  });

  test("deserialize too short", () => {
    expect(() => CommandPacket.deserialize(new Uint8Array([0x00]))).toThrow();
  });
});
