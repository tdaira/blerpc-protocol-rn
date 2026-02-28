import { ContainerSplitter, ContainerAssembler, Container } from "../src";

describe("Split-then-assemble roundtrip", () => {
  test("roundtrip small", () => {
    const splitter = new ContainerSplitter(247);
    const assembler = new ContainerAssembler();
    const payload = new TextEncoder().encode("hello world");

    const containers = splitter.split(payload, 0);
    let result: Uint8Array | null = null;
    for (const c of containers) {
      const serialized = c.serialize();
      const deserialized = Container.deserialize(serialized);
      result = assembler.feed(deserialized);
    }
    expect(result).toEqual(payload);
  });

  test("roundtrip large", () => {
    const splitter = new ContainerSplitter(27);
    const assembler = new ContainerAssembler();
    const payload = new Uint8Array(1024);
    for (let i = 0; i < 1024; i++) payload[i] = i % 256;

    const containers = splitter.split(payload, 10);
    let result: Uint8Array | null = null;
    for (const c of containers) {
      const serialized = c.serialize();
      const deserialized = Container.deserialize(serialized);
      result = assembler.feed(deserialized);
    }
    expect(result).toEqual(payload);
  });

  test("roundtrip large payload (60KB)", () => {
    const splitter = new ContainerSplitter(247);
    const assembler = new ContainerAssembler();
    const payload = new Uint8Array(60000).fill(0xab);

    const containers = splitter.split(payload, 0);
    expect(containers.length).toBeGreaterThan(200);
    let result: Uint8Array | null = null;
    for (const c of containers) {
      const serialized = c.serialize();
      const deserialized = Container.deserialize(serialized);
      result = assembler.feed(deserialized);
    }
    expect(result).toEqual(payload);
  });

  test("payload too large raises", () => {
    const splitter = new ContainerSplitter(27);
    const payload = new Uint8Array(10000);
    expect(() => splitter.split(payload, 0)).toThrow(/sequence_number/);
  });

  test("roundtrip empty", () => {
    const splitter = new ContainerSplitter(247);
    const assembler = new ContainerAssembler();
    const payload = new Uint8Array(0);

    const containers = splitter.split(payload, 0);
    let result: Uint8Array | null = null;
    for (const c of containers) {
      const serialized = c.serialize();
      const deserialized = Container.deserialize(serialized);
      result = assembler.feed(deserialized);
    }
    expect(result).toEqual(payload);
  });
});
