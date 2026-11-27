export const LogLevels = {
  Debug: "debug",
  Info: "info",
  Warn: "warn",
  Error: "error",
  Silent: "silent",
} as const;

export type LogLevel = (typeof LogLevels)[keyof typeof LogLevels];

const LOG_LEVEL_WEIGHTS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  silent: 4,
};

function parseLogLevel(raw: string): LogLevel {
  switch (raw.toLowerCase()) {
    case LogLevels.Debug:
      return LogLevels.Debug;
    case LogLevels.Info:
      return LogLevels.Info;
    case LogLevels.Warn:
      return LogLevels.Warn;
    case LogLevels.Error:
      return LogLevels.Error;
    case LogLevels.Silent:
      return LogLevels.Silent;
    default:
      return LogLevels.Info;
  }
}

export class Logger {
  private readonly levelValue: number;

  constructor(level: string = LogLevels.Info) {
    this.levelValue = LOG_LEVEL_WEIGHTS[parseLogLevel(level)];
  }

  debug(message: string, ...args: readonly unknown[]): void {
    if (this.levelValue <= LOG_LEVEL_WEIGHTS.debug) {
      console.debug(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: readonly unknown[]): void {
    if (this.levelValue <= LOG_LEVEL_WEIGHTS.info) {
      console.info(`[INFO] ${message}`, ...args);
    }
  }

  warn(message: string, ...args: readonly unknown[]): void {
    if (this.levelValue <= LOG_LEVEL_WEIGHTS.warn) {
      console.warn(`[WARN] ${message}`, ...args);
    }
  }

  error(message: string, ...args: readonly unknown[]): void {
    if (this.levelValue <= LOG_LEVEL_WEIGHTS.error) {
      console.error(`[ERROR] ${message}`, ...args);
    }
  }
}
