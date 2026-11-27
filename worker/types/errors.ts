import type { ContentfulStatusCode } from "hono/utils/http-status";

export class AppError extends Error {
  readonly status: ContentfulStatusCode;
  readonly code: string;

  constructor(message: string, status: ContentfulStatusCode = 400, code?: string) {
    super(message);
    this.name = "AppError";
    this.status = status;
    this.code = code ?? AppError.resolveDefaultCode(status);
  }

  private static resolveDefaultCode(status: ContentfulStatusCode): string {
    switch (status) {
      case 400:
        return "BAD_REQUEST";
      case 401:
        return "UNAUTHORIZED";
      case 403:
        return "FORBIDDEN";
      case 404:
        return "NOT_FOUND";
      case 409:
        return "CONFLICT";
      case 422:
        return "UNPROCESSABLE_ENTITY";
      case 429:
        return "TOO_MANY_REQUESTS";
      default:
        return status >= 500 ? "INTERNAL_ERROR" : "REQUEST_ERROR";
    }
  }
}
