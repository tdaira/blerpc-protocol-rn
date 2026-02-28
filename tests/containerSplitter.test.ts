import {
  ContainerSplitter,
  ContainerType,
  ATT_OVERHEAD,
  FIRST_HEADER_SIZE,
  SUBSEQUENT_HEADER_SIZE,
} from "../src";

describe("ContainerSplitter", () => {
  test("small payload single container", () => {
    const splitter = new ContainerSplitter(247);
    const containers = splitter.split(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]), 0);
    expect(containers.length).toBe(1);
    expect(containers[0].containerType).toBe(ContainerType.FIRST);
    expect(containers[0].totalLength).toBe(5);
    expect(containers[0].payload).toEqual(new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]));
  });

  test("large payload multiple containers", () => {
    const mtu = 27;
    const splitter = new ContainerSplitter(mtu);
    const effective = mtu - ATT_OVERHEAD; // 24
    const firstPayloadMax = effective - FIRST_HEADER_SIZE; // 18
    const subsequentPayloadMax = effective - SUBSEQUENT_HEADER_SIZE; // 20

    const payload = new Uint8Array(512);
    for (let i = 0; i < 512; i++) payload[i] = i % 256;
    const containers = splitter.split(payload, 5);

    expect(containers[0].containerType).toBe(ContainerType.FIRST);
    expect(containers[0].totalLength).toBe(512);
    expect(containers[0].payload.length).toBe(firstPayloadMax);

    for (let i = 1; i < containers.length; i++) {
      expect(containers[i].containerType).toBe(ContainerType.SUBSEQUENT);
      expect(containers[i].payload.length).toBeLessThanOrEqual(subsequentPayloadMax);
    }

    // Verify all data is accounted for
    const reassembled: number[] = [];
    for (const c of containers) {
      reassembled.push(...c.payload);
    }
    expect(new Uint8Array(reassembled)).toEqual(payload);
  });

  test("boundary payload exactly first max", () => {
    const mtu = 30;
    const splitter = new ContainerSplitter(mtu);
    const effective = mtu - ATT_OVERHEAD; // 27
    const firstMax = effective - FIRST_HEADER_SIZE; // 21

    const payload = new Uint8Array(firstMax).fill(0x41);
    const containers = splitter.split(payload, 0);
    expect(containers.length).toBe(1);
    expect(containers[0].payload).toEqual(payload);
  });

  test("boundary payload one byte over first max", () => {
    const mtu = 30;
    const splitter = new ContainerSplitter(mtu);
    const effective = mtu - ATT_OVERHEAD;
    const firstMax = effective - FIRST_HEADER_SIZE;

    const payload = new Uint8Array(firstMax + 1).fill(0x41);
    const containers = splitter.split(payload, 0);
    expect(containers.length).toBe(2);
    expect(containers[0].payload.length).toBe(firstMax);
    expect(containers[1].payload.length).toBe(1);
  });

  test("empty payload", () => {
    const splitter = new ContainerSplitter(247);
    const containers = splitter.split(new Uint8Array(0), 0);
    expect(containers.length).toBe(1);
    expect(containers[0].totalLength).toBe(0);
    expect(containers[0].payload.length).toBe(0);
  });

  test("transaction ID auto increment", () => {
    const splitter = new ContainerSplitter(247);
    const c1 = splitter.split(new Uint8Array([0x61]));
    const c2 = splitter.split(new Uint8Array([0x62]));
    expect(c1[0].transactionId).toBe(0);
    expect(c2[0].transactionId).toBe(1);
  });

  test("transaction ID wraps at 256", () => {
    const splitter = new ContainerSplitter(247);
    // Advance counter to 255
    for (let i = 0; i < 255; i++) {
      splitter.nextTransactionId();
    }
    const c1 = splitter.split(new Uint8Array([0x61]));
    const c2 = splitter.split(new Uint8Array([0x62]));
    expect(c1[0].transactionId).toBe(255);
    expect(c2[0].transactionId).toBe(0);
  });
});
