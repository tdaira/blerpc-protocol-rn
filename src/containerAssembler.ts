// Reassembles containers into a complete payload.

import { Container } from "./container";
import { ContainerType } from "./containerTypes";

interface AssemblyState {
  totalLength: number;
  expectedSeq: number;
  fragments: Uint8Array[];
  receivedLength: number;
}

/** Reassembles containers into a complete payload. */
export class ContainerAssembler {
  private _transactions = new Map<number, AssemblyState>();

  /** Feed a container. Returns complete payload when done, else null. */
  feed(container: Container): Uint8Array | null {
    if (container.containerType === ContainerType.CONTROL) {
      return null; // Control containers are handled separately
    }

    const tid = container.transactionId;

    if (container.containerType === ContainerType.FIRST) {
      this._transactions.set(tid, {
        totalLength: container.totalLength,
        expectedSeq: 1,
        fragments: [container.payload],
        receivedLength: container.payload.length,
      });
    } else if (this._transactions.has(tid)) {
      const state = this._transactions.get(tid)!;
      if (container.sequenceNumber !== state.expectedSeq) {
        // Sequence gap — discard entire transaction
        this._transactions.delete(tid);
        return null;
      }
      state.fragments.push(container.payload);
      state.receivedLength += container.payload.length;
      state.expectedSeq += 1;
    } else {
      // Subsequent without a FIRST — ignore
      return null;
    }

    const state = this._transactions.get(tid)!;
    if (state.receivedLength >= state.totalLength) {
      // Combine fragments and trim to totalLength
      const combined = new Uint8Array(state.receivedLength);
      let offset = 0;
      for (const f of state.fragments) {
        combined.set(f, offset);
        offset += f.length;
      }
      this._transactions.delete(tid);
      return combined.slice(0, state.totalLength);
    }

    return null;
  }

  /** Clear all pending assembly state. */
  reset(): void {
    this._transactions.clear();
  }

  /** Visible for testing: check if a transaction is tracked. */
  hasTransaction(tid: number): boolean {
    return this._transactions.has(tid);
  }
}
