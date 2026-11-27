import {
  AdminCreateAppSchema,
  AdminUpdateAppSchema,
  AdminUpdateSettingsSchema,
  type AdminAppView,
  type AdminAuditLogView,
  type AdminSettingsMap,
  type AdminStatsData,
  type PaginatedResult,
} from "@shared/schemas/admin";
import type { ApiResponse } from "@shared/types/api-response";
import { parsePositiveInt, validationError } from "@worker/handlers/http.utils";
import type { HonoEnv } from "@worker/types/hono-env";
import { handleApiError, readJsonBody } from "@worker/utils/runtime";
import type { Context } from "hono";
import * as v from "valibot";

export class AdminHandler {
  static async getSettings(c: Context<HonoEnv>): Promise<Response> {
    try {
      const useDynamicConfig = c.env.USE_DYNAMIC_CONFIG === "true";
      const enrichedConfig = await c.get("adminService").getSettings(c.get("config"), useDynamicConfig);
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
    if (c.env.USE_DYNAMIC_CONFIG !== "true") {
      const response: ApiResponse<never> = {
        success: false,
        error: {
          code: "DYNAMIC_CONFIG_DISABLED",
          message: "Dynamic configuration is disabled on this instance.",
        },
      };
      return c.json(response, 400);
    }

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
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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
      return validationError(c, "Missing app ID.");
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
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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
      return validationError(c, "Missing app ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminUpdateAppSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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
      return validationError(c, "Missing app ID.");
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
