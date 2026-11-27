import { SessionSchema, type Session } from "@shared/schemas/auth";
import * as v from "valibot";

const SESSION_KEY_PREFIX = "session:";
const VALID_SESSION_ID_REGEX = /^[a-zA-Z0-9-]+$/;
const LEGACY_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isSafeSessionId(sessionId: string): boolean {
  return sessionId.length >= 16 && sessionId.length <= 128 && VALID_SESSION_ID_REGEX.test(sessionId);
}

export class SessionRepository {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  private getKey(sessionId: string): string {
    return `${SESSION_KEY_PREFIX}${sessionId}`;
  }

  async create(sessionId: string, session: Session, ttlSeconds = 86400): Promise<void> {
    if (!isSafeSessionId(sessionId)) {
      throw new Error("Invalid session ID format");
    }
    await this.kv.put(this.getKey(sessionId), JSON.stringify(session), { expirationTtl: ttlSeconds });
  }

  async get(sessionId: string): Promise<Session | null> {
    if (!isSafeSessionId(sessionId)) {
      return null;
    }

    let data = await this.kv.get(this.getKey(sessionId));
    if (!data && LEGACY_UUID_REGEX.test(sessionId)) {
      data = await this.kv.get(sessionId);
    }
    if (!data) {
      return null;
    }

    try {
      const rawParsed: unknown = JSON.parse(data);
      const result = v.safeParse(SessionSchema, rawParsed);
      return result.success ? result.output : null;
    } catch {
      return null;
    }
  }

  async delete(sessionId: string): Promise<void> {
    if (!isSafeSessionId(sessionId)) {
      return;
    }

    await this.kv.delete(this.getKey(sessionId));
    if (LEGACY_UUID_REGEX.test(sessionId)) {
      await this.kv.delete(sessionId);
    }
  }
}
