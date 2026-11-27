import type { AppRepository } from "@worker/repositories/app.repository";
import type { AdminService } from "@worker/services/admin.service";
import type { AuthService } from "@worker/services/auth.service";
import type { DerbentConfig } from "@worker/types/models";
import type { Logger } from "@worker/utils/logger";

export interface HonoEnv {
  Bindings: CloudflareBindings;
  Variables: {
    adminService: AdminService;
    authService: AuthService;
    appRepo: AppRepository;
    config: DerbentConfig;
    logger: Logger;
  };
}
