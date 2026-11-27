import {
  AdminCreateAppSchema,
  AdminForcePasswordSchema,
  AdminLockAccountSchema,
  AdminUpdateAppSchema,
  AdminUpdateSettingsSchema,
  AdminUpdateUserSchema,
  type AdminAppView,
  type AdminAuditLogView,
  type AdminSettingsMap,
  type AdminStatsData,
  type AdminUserView,
  type PaginatedResult,
} from "@shared/schemas/admin";
import type { ApiResponse } from "@shared/types/api-response";
import type { HonoEnv } from "@worker/types/hono-env";
import { handleApiError, readJsonBody } from "@worker/utils/runtime";
import type { Context } from "hono";
import * as v from "valibot";

function parsePositiveInt(raw: string | undefined, fallback: number, max?: number): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    return fallback;
  }
  return max !== undefined ? Math.min(parsed, max) : parsed;
}

function validationFailure(c: Context<HonoEnv>, message: string): Response {
  const response: ApiResponse<never> = {
    success: false,
    error: {
      code: "VALIDATION_ERROR",
      message,
    },
  };
  return c.json(response, 400);
}

export class AdminHandler {
  static async getSettings(c: Context<HonoEnv>): Promise<Response> {
    try {
      const enrichedConfig = await c.get("adminService").getSettings(c.get("config"));
      const response: ApiResponse<AdminSettingsMap> = {
        success: true,
        data: enrichedConfig,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async updateSettings(c: Context<HonoEnv>): Promise<Response> {
    const masterKey = c.env.DERBENT_API_KEY;
    if (!masterKey) {
      const response: ApiResponse<never> = {
        success: false,
        error: {
          code: "INTERNAL_ERROR",
          message: "Admin API master key (DERBENT_API_KEY) is not configured.",
        },
      };
      return c.json(response, 500);
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminUpdateSettingsSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      await c.get("adminService").updateSettings(result.output, masterKey);
      const response: ApiResponse<{ readonly updated: boolean }> = {
        success: true,
        data: { updated: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getStats(c: Context<HonoEnv>): Promise<Response> {
    try {
      const stats = await c.get("adminService").getDashboardStats();
      const response: ApiResponse<AdminStatsData> = {
        success: true,
        data: stats,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getUsers(c: Context<HonoEnv>): Promise<Response> {
    try {
      const page = parsePositiveInt(c.req.query("page"), 1);
      const limit = parsePositiveInt(c.req.query("limit"), 20, 100);
      const search = c.req.query("search");

      const data = await c.get("adminService").getUsers(page, limit, search);
      const response: ApiResponse<PaginatedResult<AdminUserView>> = {
        success: true,
        data,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getUser(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      const user = await c.get("adminService").getUser(id);
      const response: ApiResponse<AdminUserView> = {
        success: true,
        data: user,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async updateUser(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminUpdateUserSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      const user = await c.get("adminService").updateUser(id, result.output);
      const response: ApiResponse<AdminUserView> = {
        success: true,
        data: user,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async forceResetPassword(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminForcePasswordSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      await c.get("adminService").forceResetPassword(id, result.output.newPassword);
      const response: ApiResponse<{ readonly reset: boolean }> = {
        success: true,
        data: { reset: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async disable2FA(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      await c.get("adminService").disable2FA(id);
      const response: ApiResponse<{ readonly disabled: boolean }> = {
        success: true,
        data: { disabled: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async deleteUser(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      await c.get("adminService").deleteUser(id);
      const response: ApiResponse<{ readonly deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async revokeSessions(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      await c.get("adminService").revokeAllSessions(id);
      const response: ApiResponse<{ readonly revoked: boolean }> = {
        success: true,
        data: { revoked: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async lockAccount(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminLockAccountSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      await c.get("adminService").setAccountLockStatus(id, result.output.locked);
      const response: ApiResponse<{ readonly locked: boolean }> = {
        success: true,
        data: { locked: result.output.locked },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getAuditLogs(c: Context<HonoEnv>): Promise<Response> {
    try {
      const page = parsePositiveInt(c.req.query("page"), 1);
      const limit = parsePositiveInt(c.req.query("limit"), 50, 100);
      const action = c.req.query("action");

      const data = await c.get("adminService").getAuditLogs(page, limit, action);
      const response: ApiResponse<PaginatedResult<AdminAuditLogView>> = {
        success: true,
        data,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getUserAuditLogs(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing user ID.");
    }

    try {
      const page = parsePositiveInt(c.req.query("page"), 1);
      const limit = parsePositiveInt(c.req.query("limit"), 20, 100);

      const data = await c.get("adminService").getUserAuditLogs(id, page, limit);
      const response: ApiResponse<PaginatedResult<AdminAuditLogView>> = {
        success: true,
        data,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getApps(c: Context<HonoEnv>): Promise<Response> {
    try {
      const apps = await c.get("adminService").getApps();
      const response: ApiResponse<readonly AdminAppView[]> = {
        success: true,
        data: apps,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async getApp(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing app ID.");
    }

    try {
      const app = await c.get("adminService").getApp(id);
      const response: ApiResponse<AdminAppView> = {
        success: true,
        data: app,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async createApp(c: Context<HonoEnv>): Promise<Response> {
    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminCreateAppSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      await c.get("adminService").createApp({
        id: result.output.id,
        name: result.output.name,
        description: result.output.description ?? null,
        icon: result.output.icon?.trim() ? result.output.icon.trim() : null,
        prod_url: result.output.prod_url,
        dev_url: result.output.dev_url,
        allow_signups: result.output.allow_signups,
        allow_logins: result.output.allow_logins,
      });

      const response: ApiResponse<{ readonly id: string }> = {
        success: true,
        data: { id: result.output.id },
      };
      return c.json(response, 201);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async updateApp(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing app ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminUpdateAppSchema, body);
      if (!result.success) {
        return validationFailure(c, result.issues[0]?.message ?? "Validation failed.");
      }

      const app = await c.get("adminService").updateApp(id, result.output);
      const response: ApiResponse<AdminAppView> = {
        success: true,
        data: app,
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }

  static async deleteApp(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationFailure(c, "Missing app ID.");
    }

    try {
      await c.get("adminService").deleteApp(id);
      const response: ApiResponse<{ readonly deleted: boolean }> = {
        success: true,
        data: { deleted: true },
      };
      return c.json(response, 200);
    } catch (error: unknown) {
      return handleApiError(c, error);
    }
  }
}
