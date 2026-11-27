import { bindings, defineConfig, triggers } from "cf/config";

export default defineConfig({
  worker: {
    name: "derbent",
    compatibilityDate: "2026-10-30",
    compatibilityFlags: ["nodejs_compat", "global_fetch_strictly_public"],
    entrypoint: "./worker/index.ts",
    workersDev: false,
    previewUrls: false,
    observability: {
      enabled: true,
    },
    assets: {
      htmlHandling: "auto-trailing-slash",
      notFoundHandling: "single-page-application",
      runWorkerFirst: ["/api", "/api/*", "/auth/*"],
    },
    domains: ["derbent.zerdalu.com"],
    triggers: [
      triggers.scheduled({
        schedule: "0 0 * * *",
      }),
      triggers.queue({
        maxBatchSize: 10,
        maxBatchTimeout: 5,
        maxRetries: 3,
        name: "derbent-email-queue",
      }),
    ],
    env: {
      ASSETS: bindings.assets(),
      APP_ENV: bindings.text("production"),
      LOG_LEVEL: bindings.text("warn"),
      APP_NAME: bindings.text("Derbent"),
      BASE_URL: bindings.text("https://derbent.zerdalu.com"),
      USE_DYNAMIC_CONFIG: bindings.text("true"),
      PBKDF2_ITERATIONS: bindings.text("100000"),
      AUDIT_LOG_RETENTION_DAYS: bindings.text("30"),
      COOKIE_DOMAIN: bindings.text(".zerdalu.com"),
      RESEND_DOMAIN: bindings.text("destek.zerdalu.com"),
      RESEND_API_KEY: bindings.secret(),
      DERBENT_API_KEY: bindings.secret(),
      GITHUB_CLIENT_ID: bindings.secret(),
      GITHUB_CLIENT_SECRET: bindings.secret(),
      GOOGLE_CLIENT_ID: bindings.secret(),
      GOOGLE_CLIENT_SECRET: bindings.secret(),
      DB: bindings.d1({
        name: "db-derbent",
        id: "59207b81-f785-4e47-928a-57aa3b2c91f7",
      }),
      KV: bindings.kv({
        id: "9d246b1506f54a38ad9df1cf165eb18f",
      }),
      EMAIL_QUEUE: bindings.queue({
        name: "derbent-email-queue",
      }),
      AUTH_LIMITER: bindings.rateLimit({
        namespace: "1001",
        simple: {
          limit: 10,
          period: 60,
        },
      }),
    },
  },
});
