import {
  Container,
  ContainerType,
  ControlCmd,
  FIRST_HEADER_SIZE,
  SUBSEQUENT_HEADER_SIZE,
} from "../src";

describe("Container serialize/deserialize", () => {
  test("FIRST container roundtrip", () => {
    const c = new Container({
      transactionId: 42,
      sequenceNumber: 0,
      containerType: ContainerType.FIRST,
      totalLength: 100,
      payload: new Uint8Array([0x01, 0x02, 0x03]),
    });
    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.transactionId).toBe(42);
    expect(c2.sequenceNumber).toBe(0);
    expect(c2.containerType).toBe(ContainerType.FIRST);
    expect(c2.totalLength).toBe(100);
    expect(c2.payload).toEqual(new Uint8Array([0x01, 0x02, 0x03]));
  });

  test("SUBSEQUENT container roundtrip", () => {
    const c = new Container({
      transactionId: 7,
      sequenceNumber: 3,
      containerType: ContainerType.SUBSEQUENT,
      payload: new Uint8Array([0xaa, 0xbb]),
    });
    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.transactionId).toBe(7);
    expect(c2.sequenceNumber).toBe(3);
    expect(c2.containerType).toBe(ContainerType.SUBSEQUENT);
    expect(c2.payload).toEqual(new Uint8Array([0xaa, 0xbb]));
  });

  test("CONTROL container roundtrip", () => {
    const payload = new Uint8Array(2);
    new DataView(payload.buffer).setUint16(0, 500, true);
    const c = new Container({
      transactionId: 1,
      sequenceNumber: 0,
      containerType: ContainerType.CONTROL,
      controlCmd: ControlCmd.TIMEOUT,
      payload,
    });
    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.containerType).toBe(ContainerType.CONTROL);
    expect(c2.controlCmd).toBe(ControlCmd.TIMEOUT);
    const bd = new DataView(c2.payload.buffer, c2.payload.byteOffset, c2.payload.byteLength);
    expect(bd.getUint16(0, true)).toBe(500);
  });

  test("flags byte encoding", () => {
    // type=0b11 in bits 7-6 => 0xC0, control_cmd=0x2 in bits 5-2 => 0x08
    const c = new Container({
      transactionId: 0,
      sequenceNumber: 0,
      containerType: ContainerType.CONTROL,
      controlCmd: ControlCmd.STREAM_END_C2P,
    });
    const data = c.serialize();
    expect(data[2]).toBe(0xc0 | 0x08); // 0xC8
  });

  test("deserialize too short", () => {
    expect(() => Container.deserialize(new Uint8Array([0x00, 0x01]))).toThrow();
  });

  test("FIRST container header size", () => {
    const c = new Container({
      transactionId: 0,
      sequenceNumber: 0,
      containerType: ContainerType.FIRST,
      totalLength: 0,
    });
    const data = c.serialize();
    expect(data.length).toBe(FIRST_HEADER_SIZE);
  });

  test("SUBSEQUENT container header size", () => {
    const c = new Container({
      transactionId: 0,
      sequenceNumber: 0,
      containerType: ContainerType.SUBSEQUENT,
    });
    const data = c.serialize();
    expect(data.length).toBe(SUBSEQUENT_HEADER_SIZE);
  });
});
