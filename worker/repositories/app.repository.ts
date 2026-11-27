import type { AppRecord } from "@worker/types/models";

export class AppRepository {
  private readonly db: D1Database;

  constructor(db: D1Database) {
    this.db = db;
  }

  async findAll(): Promise<readonly AppRecord[]> {
    const { results } = await this.db.prepare("SELECT * FROM apps ORDER BY created_at ASC").all<AppRecord>();
    return results || [];
  }

  async findById(id: string): Promise<AppRecord | null> {
    return await this.db.prepare("SELECT * FROM apps WHERE id = ?").bind(id).first<AppRecord>();
  }

  async create(app: Omit<AppRecord, "created_at" | "updated_at">): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO apps (id, name, description, icon, prod_url, dev_url, allow_signups, allow_logins)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(app.id, app.name, app.description, app.icon, app.prod_url, app.dev_url, app.allow_signups, app.allow_logins)
      .run();
  }

  async update(
    id: string,
    data: Partial<Omit<AppRecord, "id" | "created_at" | "updated_at">>,
  ): Promise<AppRecord | null> {
    const updates: string[] = [];
    const params: (string | number | null)[] = [];

    if (data.name !== undefined) {
      updates.push("name = ?");
      params.push(data.name);
    }
    if (data.description !== undefined) {
      updates.push("description = ?");
      params.push(data.description);
    }
    if (data.icon !== undefined) {
      updates.push("icon = ?");
      params.push(data.icon);
    }
    if (data.prod_url !== undefined) {
      updates.push("prod_url = ?");
      params.push(data.prod_url);
    }
    if (data.dev_url !== undefined) {
      updates.push("dev_url = ?");
      params.push(data.dev_url);
    }
    if (data.allow_signups !== undefined) {
      updates.push("allow_signups = ?");
      params.push(data.allow_signups);
    }
    if (data.allow_logins !== undefined) {
      updates.push("allow_logins = ?");
      params.push(data.allow_logins);
    }

    if (updates.length > 0) {
      params.push(id);
      const query = `UPDATE apps SET ${updates.join(", ")}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`;
      await this.db
        .prepare(query)
        .bind(...params)
        .run();
    }

    return this.findById(id);
  }

  async delete(id: string): Promise<void> {
    await this.db.prepare("DELETE FROM apps WHERE id = ?").bind(id).run();
  }
}
