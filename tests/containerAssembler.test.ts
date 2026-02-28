import { Container, ContainerAssembler, ContainerType, makeTimeoutRequest } from "../src";

describe("ContainerAssembler", () => {
  test("single container assembly", () => {
    const assembler = new ContainerAssembler();
    const c = new Container({
      transactionId: 0,
      sequenceNumber: 0,
      containerType: ContainerType.FIRST,
      totalLength: 5,
      payload: new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]),
    });
    const result = assembler.feed(c);
    expect(result).toEqual(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]));
  });

  test("multi container assembly", () => {
    const assembler = new ContainerAssembler();
    const c1 = new Container({
      transactionId: 1,
      sequenceNumber: 0,
      containerType: ContainerType.FIRST,
      totalLength: 8,
      payload: new Uint8Array([0x68, 0x65, 0x6c, 0x6c]),
    });
    const c2 = new Container({
      transactionId: 1,
      sequenceNumber: 1,
      containerType: ContainerType.SUBSEQUENT,
      payload: new Uint8Array([0x6f, 0x20, 0x77, 0x6f]),
    });
    expect(assembler.feed(c1)).toBeNull();
    const result = assembler.feed(c2);
    expect(result).toEqual(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f]));
  });

  test("sequence gap discards transaction", () => {
    const assembler = new ContainerAssembler();
    const c1 = new Container({
      transactionId: 2,
      sequenceNumber: 0,
      containerType: ContainerType.FIRST,
      totalLength: 10,
      payload: new Uint8Array([0x61, 0x62, 0x63]),
    });
    const cBad = new Container({
      transactionId: 2,
      sequenceNumber: 2, // Gap: expected 1
      containerType: ContainerType.SUBSEQUENT,
      payload: new Uint8Array([0x64, 0x65, 0x66]),
    });
    expect(assembler.feed(c1)).toBeNull();
    const result = assembler.feed(cBad);
    expect(result).toBeNull();
    expect(assembler.hasTransaction(2)).toBe(false);
  });

  test("control container ignored", () => {
    const assembler = new ContainerAssembler();
    const c = makeTimeoutRequest(0);
    expect(assembler.feed(c)).toBeNull();
  });

  test("subsequent without first ignored", () => {
    const assembler = new ContainerAssembler();
    const c = new Container({
      transactionId: 99,
      sequenceNumber: 1,
      containerType: ContainerType.SUBSEQUENT,
      payload: new Uint8Array([0x6f, 0x72, 0x70, 0x68]),
    });
    expect(assembler.feed(c)).toBeNull();
  });
});
