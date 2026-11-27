import * as v from "valibot";

export type JsonPrimitive = string | number | boolean | null;

export interface JsonObject {
  readonly [key: string]: JsonValue;
}

export type JsonValue = JsonPrimitive | readonly JsonValue[] | JsonObject;

export const JsonPrimitiveSchema: v.GenericSchema<JsonPrimitive> = v.union([
  v.string(),
  v.number(),
  v.boolean(),
  v.null(),
]);

export const JsonValueSchema: v.GenericSchema<JsonValue> = v.lazy(() =>
  v.union([JsonPrimitiveSchema, v.array(JsonValueSchema), JsonObjectSchema]),
);

export const JsonObjectSchema: v.GenericSchema<JsonObject> = v.lazy(() => v.record(v.string(), JsonValueSchema));
