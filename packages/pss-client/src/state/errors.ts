export class PssStateError extends Error {
  constructor(detail: string) {
    super(`PSS state: ${detail}`);
    this.name = "PssStateError";
  }
}

export class PssRollbackError extends Error {
  public readonly floor: number;
  public readonly offered: number;

  constructor(collection: string, floor: number, offered: number) {
    super(
      `PSS rollback refused: ${collection} version ${offered} is below the highest version ` +
        `this install has already accepted (${floor})`,
    );
    this.name = "PssRollbackError";
    this.floor = floor;
    this.offered = offered;
  }
}

export class PssSchemaError extends Error {
  public readonly seen: number;
  public readonly supported: number;

  constructor(seen: number, supported: number) {
    super(
      `PSS payload schema ${seen} is newer than this build understands (${supported}); ` +
        `refusing it rather than dropping fields a newer client wrote`,
    );
    this.name = "PssSchemaError";
    this.seen = seen;
    this.supported = supported;
  }
}
