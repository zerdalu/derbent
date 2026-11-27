import {
  AdminForcePasswordSchema,
  AdminLockAccountSchema,
  AdminUpdateUserSchema,
  type AdminAuditLogView,
  type AdminUserView,
  type PaginatedResult,
} from "@shared/schemas/admin";
import type { ApiResponse } from "@shared/types/api-response";
import { parsePositiveInt, validationError } from "@worker/handlers/http.utils";
import type { HonoEnv } from "@worker/types/hono-env";
import { handleApiError, readJsonBody } from "@worker/utils/runtime";
import type { Context } from "hono";
import * as v from "valibot";

export class AdminUserHandler {
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
      return validationError(c, "Missing user ID.");
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
      return validationError(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminUpdateUserSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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
      return validationError(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminForcePasswordSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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
      return validationError(c, "Missing user ID.");
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
      return validationError(c, "Missing user ID.");
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
      return validationError(c, "Missing user ID.");
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
      return validationError(c, "Missing user ID.");
    }

    try {
      const body = await readJsonBody(c);
      const result = v.safeParse(AdminLockAccountSchema, body);
      if (!result.success) {
        return validationError(c, result.issues[0]?.message ?? "Validation failed.");
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

  static async getUserAuditLogs(c: Context<HonoEnv>): Promise<Response> {
    const id = c.req.param("id");
    if (!id) {
      return validationError(c, "Missing user ID.");
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
}
