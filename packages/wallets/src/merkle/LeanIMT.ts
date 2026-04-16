import { Fr } from "@aztec/foundation/fields";
import { Poseidon } from "../crypto/Poseidon.js";

export class LeanIMT {
  private readonly zeroValue: Fr = new Fr(0n);
  public levels: Fr[][];
  public nextLeafIndex: number = 0;
  private currentRoot: Fr = new Fr(0n);

  constructor(public readonly depth: number) {
    if (depth < 1 || depth > 32) {
      throw new Error("Invalid depth");
    }
    this.levels = Array.from({ length: depth }, () => []);
  }

  public async insert(leaf: Fr): Promise<Fr> {
    const leafIndex = this.nextLeafIndex;
    const capacity = BigInt(2) ** BigInt(this.depth);
    if (BigInt(leafIndex) >= capacity) {
      throw new Error("Tree is full");
    }

    this.levels[0].push(leaf);
    this.nextLeafIndex++;

    let currentComputedNode = leaf;
    let currentIndexInLevel = leafIndex;

    for (let level = 0; level < this.depth; ++level) {
      const siblingIndex = currentIndexInLevel ^ 1;
      const siblingNode =
        siblingIndex < this.levels[level].length
          ? this.levels[level][siblingIndex]
          : this.zeroValue;

      const left =
        (currentIndexInLevel & 1) === 0 ? currentComputedNode : siblingNode;
      const right =
        (currentIndexInLevel & 1) === 0 ? siblingNode : currentComputedNode;

      if (left.equals(this.zeroValue) && right.equals(this.zeroValue)) {
        currentComputedNode = this.zeroValue;
      } else if (right.equals(this.zeroValue)) {
        currentComputedNode = left;
      } else if (left.equals(this.zeroValue)) {
        currentComputedNode = right;
      } else {
        currentComputedNode = await Poseidon.hash([left, right]);
      }

      const parentIndex = Math.floor(currentIndexInLevel / 2);

      if (level < this.depth - 1) {
        if (parentIndex >= this.levels[level + 1].length) {
          this.levels[level + 1].push(currentComputedNode);
        } else {
          this.levels[level + 1][parentIndex] = currentComputedNode;
        }
      }
      currentIndexInLevel = parentIndex;
    }

    this.currentRoot = currentComputedNode;
    return currentComputedNode;
  }

  public getRoot(): Fr {
    return this.currentRoot;
  }

  public getMerklePath(index: number): Fr[] {
    if (index >= this.nextLeafIndex) {
      throw new Error("Index out of bounds");
    }

    const path: Fr[] = [];
    let currentIndex = index;

    for (let level = 0; level < this.depth; level++) {
      const siblingIndex = currentIndex ^ 1;

      if (siblingIndex < this.levels[level].length) {
        path.push(this.levels[level][siblingIndex]);
      } else {
        path.push(this.zeroValue);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return path;
  }
}
