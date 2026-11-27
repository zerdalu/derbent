import * as v from "valibot";

export type ApiClientResult<T> =
  | { readonly ok: true; readonly data: T }
  | { readonly ok: false; readonly code: string; readonly message: string; readonly status: number };

const ApiSuccessEnvelopeSchema = v.object({
  success: v.literal(true),
  data: v.unknown(),
});

const ApiErrorEnvelopeSchema = v.object({
  success: v.literal(false),
  error: v.object({
    code: v.string(),
    message: v.string(),
  }),
});

export async function apiGet<TSchema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
  url: string,
  dataSchema: TSchema,
): Promise<ApiClientResult<v.InferOutput<TSchema>>> {
  return executeApiRequest(url, dataSchema, { method: "GET" });
}

export async function apiPost<TSchema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>, TBody>(
  url: string,
  body: TBody,
  dataSchema: TSchema,
): Promise<ApiClientResult<v.InferOutput<TSchema>>> {
  return executeApiRequest(url, dataSchema, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function executeApiRequest<TSchema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
  url: string,
  dataSchema: TSchema,
  init: RequestInit,
): Promise<ApiClientResult<v.InferOutput<TSchema>>> {
  try {
    const response = await fetch(url, {
      ...init,
      credentials: "same-origin",
    });

    let rawBody: unknown;
    try {
      rawBody = await response.json();
    } catch {
      return {
        ok: false,
        code: response.ok ? "INVALID_RESPONSE" : "SERVER_ERROR",
        message: response.ok
          ? "Unexpected response format from server."
          : "The server returned an unexpected error. Please try again.",
        status: response.status,
      };
    }

    const parsedEnvelope = v.safeParse(ApiSuccessEnvelopeSchema, rawBody);
    if (parsedEnvelope.success) {
      const parsedData = v.safeParse(dataSchema, parsedEnvelope.output.data);
      if (parsedData.success) {
        return { ok: true, data: parsedData.output };
      }
      return {
        ok: false,
        code: "INVALID_RESPONSE",
        message: "Response payload did not match expected schema.",
        status: response.status,
      };
    }

    const parsedError = v.safeParse(ApiErrorEnvelopeSchema, rawBody);
    if (parsedError.success) {
      return {
        ok: false,
        code: parsedError.output.error.code,
        message: parsedError.output.error.message,
        status: response.status,
      };
    }

    return {
      ok: false,
      code: "INVALID_RESPONSE",
      message: "Unexpected response format from server.",
      status: response.status,
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Network request failed.";
    return {
      ok: false,
      code: "NETWORK_ERROR",
      message,
      status: 0,
    };
  }
}
