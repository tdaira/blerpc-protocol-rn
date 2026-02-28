import {
  Container,
  ContainerType,
  ControlCmd,
  makeTimeoutRequest,
  makeTimeoutResponse,
  makeStreamEndC2P,
  makeStreamEndP2C,
  makeErrorResponse,
  BLERPC_ERROR_RESPONSE_TOO_LARGE,
} from "../src";

describe("Control containers", () => {
  test("timeout request", () => {
    const c = makeTimeoutRequest(5);
    expect(c.containerType).toBe(ContainerType.CONTROL);
    expect(c.controlCmd).toBe(ControlCmd.TIMEOUT);
    expect(c.payload.length).toBe(0);
  });

  test("timeout response", () => {
    const c = makeTimeoutResponse(5, 200);
    expect(c.containerType).toBe(ContainerType.CONTROL);
    expect(c.controlCmd).toBe(ControlCmd.TIMEOUT);
    const bd = new DataView(c.payload.buffer, c.payload.byteOffset, c.payload.byteLength);
    expect(bd.getUint16(0, true)).toBe(200);
  });

  test("stream end C2P roundtrip", () => {
    const c = makeStreamEndC2P(3);
    expect(c.controlCmd).toBe(ControlCmd.STREAM_END_C2P);
    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.controlCmd).toBe(ControlCmd.STREAM_END_C2P);
  });

  test("stream end P2C", () => {
    const c = makeStreamEndP2C(3);
    expect(c.controlCmd).toBe(ControlCmd.STREAM_END_P2C);
  });

  test("error response", () => {
    const c = makeErrorResponse(10, BLERPC_ERROR_RESPONSE_TOO_LARGE);
    expect(c.containerType).toBe(ContainerType.CONTROL);
    expect(c.controlCmd).toBe(ControlCmd.ERROR);
    expect(c.payload).toEqual(new Uint8Array([0x01]));

    const data = c.serialize();
    const c2 = Container.deserialize(data);
    expect(c2.containerType).toBe(ContainerType.CONTROL);
    expect(c2.controlCmd).toBe(ControlCmd.ERROR);
    expect(c2.payload).toEqual(new Uint8Array([BLERPC_ERROR_RESPONSE_TOO_LARGE]));
  });
});
