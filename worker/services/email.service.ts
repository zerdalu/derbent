import type { EmailQueueMessage } from "@worker/types/models";
import type { Logger } from "@worker/utils/logger";
import * as v from "valibot";

const EMAIL_FETCH_TIMEOUT_MS = 10000;

const ResendEmailResponseSchema = v.object({
  id: v.string(),
});

export const EmailQueueMessageSchema: v.GenericSchema<EmailQueueMessage> = v.variant("type", [
  v.object({
    type: v.literal("verify_email"),
    to: v.string(),
    token: v.string(),
    appId: v.optional(v.string()),
    redirect: v.optional(v.string()),
  }),
  v.object({
    type: v.literal("reset_password"),
    to: v.string(),
    token: v.string(),
  }),
  v.object({
    type: v.literal("magic_link"),
    to: v.string(),
    token: v.string(),
    appId: v.string(),
    redirect: v.string(),
  }),
]);

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export class EmailService {
  private readonly isDev: boolean;
  private readonly appName: string;
  private readonly baseUrl: string;
  private readonly resendApiKey: string;
  private readonly fromEmail: string;
  private readonly queue: Queue<EmailQueueMessage> | undefined;
  private readonly logger: Logger | undefined;

  constructor(
    isDev: boolean,
    appName: string,
    baseUrl: string,
    resendApiKey: string,
    resendDomain: string,
    queue?: Queue<EmailQueueMessage>,
    logger?: Logger,
  ) {
    this.isDev = isDev;
    this.appName = appName;
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.resendApiKey = resendApiKey;
    this.fromEmail = `noreply@${resendDomain}`;
    this.queue = queue;
    this.logger = logger;
  }

  private getTestSafeTo(to: string): string {
    return this.isDev ? "delivered@resend.dev" : to;
  }

  private getTestSafeSubject(subject: string, originalTo: string): string {
    return this.isDev ? `[TEST for ${originalTo}] ${subject}` : subject;
  }

  async sendVerificationEmail(to: string, token: string, appId?: string, redirect?: string): Promise<void> {
    if (this.queue) {
      await this.queue.send({ type: "verify_email", to, token, appId, redirect });
      return;
    }
    await this.processVerificationEmail(to, token, appId, redirect);
  }

  async sendPasswordResetEmail(to: string, token: string): Promise<void> {
    if (this.queue) {
      await this.queue.send({ type: "reset_password", to, token });
      return;
    }
    await this.processPasswordResetEmail(to, token);
  }

  async sendMagicLinkEmail(to: string, token: string, appId: string, redirect: string): Promise<void> {
    if (this.queue) {
      await this.queue.send({ type: "magic_link", to, token, appId, redirect });
      return;
    }
    await this.processMagicLinkEmail(to, token, appId, redirect);
  }

  async processMessage(msg: EmailQueueMessage): Promise<void> {
    switch (msg.type) {
      case "verify_email":
        await this.processVerificationEmail(msg.to, msg.token, msg.appId, msg.redirect);
        break;
      case "reset_password":
        await this.processPasswordResetEmail(msg.to, msg.token);
        break;
      case "magic_link":
        await this.processMagicLinkEmail(msg.to, msg.token, msg.appId, msg.redirect);
        break;
      default: {
        const _exhaustive: never = msg;
        throw new Error(`Unhandled email queue message: ${JSON.stringify(_exhaustive)}`);
      }
    }
  }

  private async sendViaResend(to: string, subject: string, html: string, actionUrl?: string): Promise<void> {
    if (this.isDev) {
      const linkInfo = actionUrl ? ` | Action URL: ${actionUrl}` : "";
      this.logger?.info(`[DEV EMAIL] To: ${to} | Subject: ${subject}${linkInfo}`);
      if (!this.resendApiKey.trim()) {
        return;
      }
    }

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.resendApiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from: `${this.appName} <${this.fromEmail}>`,
        to: this.getTestSafeTo(to),
        subject: this.getTestSafeSubject(subject, to),
        html,
      }),
      signal: AbortSignal.timeout(EMAIL_FETCH_TIMEOUT_MS),
    });

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`Email provider error: ${errorData}`);
    }

    const rawBody: unknown = await response.json();
    const parsed = v.safeParse(ResendEmailResponseSchema, rawBody);
    if (parsed.success) {
      this.logger?.debug(`Dispatched email ${parsed.output.id}`);
    }
  }

  private async processVerificationEmail(to: string, token: string, appId?: string, redirect?: string): Promise<void> {
    const qs = new URLSearchParams({ token });
    if (appId) qs.set("app_id", appId);
    if (redirect) qs.set("redirect", redirect);

    const verificationUrl = `${this.baseUrl}/verify-email?${qs.toString()}`;
    const safeUrl = escapeHtml(verificationUrl);

    await this.sendViaResend(
      to,
      "Verify your email address",
      `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Confirm your email</h2>
          <p>Click the button below to verify your account. This link expires in 15 minutes.</p>
          <a href="${safeUrl}" style="background: #18181b; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0;">Verify Email</a>
          <p style="color: #71717a; font-size: 12px;">If you didn't create an account, you can safely ignore this email.</p>
        </div>
      `,
      verificationUrl,
    );
  }

  private async processPasswordResetEmail(to: string, token: string): Promise<void> {
    const qs = new URLSearchParams({ token }).toString();
    const resetUrl = `${this.baseUrl}/reset-password?${qs}`;
    const safeUrl = escapeHtml(resetUrl);

    await this.sendViaResend(
      to,
      "Reset your password",
      `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Password Reset Request</h2>
          <p>Click the link below to set a new password. This link expires in 15 minutes.</p>
          <p><a href="${safeUrl}">${safeUrl}</a></p>
          <p style="color: #71717a; font-size: 12px;">If you didn't request this, you can ignore this email.</p>
        </div>
      `,
      resetUrl,
    );
  }

  private async processMagicLinkEmail(to: string, token: string, appId: string, redirect: string): Promise<void> {
    const qs = new URLSearchParams({ token, app_id: appId, redirect }).toString();
    const magicLinkUrl = `${this.baseUrl}/verify-magic-link?${qs}`;
    const safeUrl = escapeHtml(magicLinkUrl);
    const targetLabel = escapeHtml(appId === "sso" ? this.appName : appId);

    await this.sendViaResend(
      to,
      `Sign in to ${this.appName}`,
      `
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>Sign in securely</h2>
          <p>Click the button below to sign in to your account. This link expires in 15 minutes.</p>
          <a href="${safeUrl}" style="background: #18181b; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0;">Sign In to ${targetLabel}</a>
          <p style="color: #71717a; font-size: 12px;">If you didn't request this link, you can safely ignore this email.</p>
        </div>
      `,
      magicLinkUrl,
    );
  }
}
