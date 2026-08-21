export class DownstreamExecutionError extends Error {
  readonly retryable: boolean;

  constructor(message = "downstream request failed", retryable = false) {
    super(message);
    this.name = "DownstreamExecutionError";
    this.retryable = retryable;
  }
}

/** The side effect may have committed; callers must reconcile, never retry. */
export class DownstreamTimeoutError extends DownstreamExecutionError {
  readonly ambiguous = true;

  constructor() {
    super("downstream result is ambiguous", false);
    this.name = "DownstreamTimeoutError";
  }
}

export class DownstreamAudienceMismatchError extends DownstreamExecutionError {
  constructor() {
    super("downstream audience mismatch", false);
    this.name = "DownstreamAudienceMismatchError";
  }
}

export class TokenExchangeError extends Error {
  constructor(message = "token exchange failed") {
    super(message);
    this.name = "TokenExchangeError";
  }
}

export class TokenExchangeAudienceMismatchError extends TokenExchangeError {
  constructor() {
    super("exchanged token audience mismatch");
    this.name = "TokenExchangeAudienceMismatchError";
  }
}
