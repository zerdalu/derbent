import { SessionSchema, type Session } from "@shared/schemas/auth";
import * as v from "valibot";

export class SessionRepository {
  private readonly kv: KVNamespace;

  constructor(kv: KVNamespace) {
    this.kv = kv;
  }

  async create(sessionId: string, session: Session, ttlSeconds = 86400): Promise<void> {
    await this.kv.put(sessionId, JSON.stringify(session), { expirationTtl: ttlSeconds });
  }

  async get(sessionId: string): Promise<Session | null> {
    const data = await this.kv.get(sessionId);
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
    await this.kv.delete(sessionId);
  }
}
