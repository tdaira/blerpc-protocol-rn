// Splits a payload into MTU-sized containers.

import { Container } from "./container";
import {
  ContainerType,
  ATT_OVERHEAD,
  FIRST_HEADER_SIZE,
  SUBSEQUENT_HEADER_SIZE,
} from "./containerTypes";

/** Splits a payload into containers respecting MTU. */
export class ContainerSplitter {
  private readonly _mtu: number;
  private _transactionCounter = 0;

  constructor(mtu = 247) {
    this._mtu = mtu;
  }

  /** Usable bytes per BLE packet (MTU - ATT overhead). */
  get effectiveMtu(): number {
    return this._mtu - ATT_OVERHEAD;
  }

  /** Get next transaction ID (auto-increments, wraps at 256). */
  nextTransactionId(): number {
    const tid = this._transactionCounter;
    this._transactionCounter = (this._transactionCounter + 1) & 0xff;
    return tid;
  }

  /**
   * Split payload into a list of containers.
   *
   * Throws if payload is too large for 8-bit sequence_number (>255 containers) or > 65535 bytes.
   */
  split(payload: Uint8Array, transactionId?: number): Container[] {
    transactionId = transactionId ?? this.nextTransactionId();

    const totalLength = payload.length;
    if (totalLength > 65535) {
      throw new Error(`Payload too large: ${totalLength} > 65535`);
    }

    const containers: Container[] = [];

    // First container
    const firstMaxPayload = this.effectiveMtu - FIRST_HEADER_SIZE;
    const firstEnd = firstMaxPayload < totalLength ? firstMaxPayload : totalLength;
    const firstPayload = payload.slice(0, firstEnd);
    containers.push(
      new Container({
        transactionId,
        sequenceNumber: 0,
        containerType: ContainerType.FIRST,
        totalLength,
        payload: firstPayload,
      }),
    );

    let offset = firstPayload.length;
    let seq = 1;

    // Subsequent containers
    const subsequentMaxPayload = this.effectiveMtu - SUBSEQUENT_HEADER_SIZE;
    while (offset < totalLength) {
      if (seq > 255) {
        throw new Error(
          `Payload requires more than 256 containers (seq=${seq}), ` +
            `exceeding 8-bit sequence_number limit`,
        );
      }
      const chunkEnd =
        offset + subsequentMaxPayload < totalLength ? offset + subsequentMaxPayload : totalLength;
      const chunk = payload.slice(offset, chunkEnd);
      containers.push(
        new Container({
          transactionId,
          sequenceNumber: seq,
          containerType: ContainerType.SUBSEQUENT,
          payload: chunk,
        }),
      );
      offset += chunk.length;
      seq++;
    }

    return containers;
  }
}
