export class AdaptorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdaptorError";
  }
}
