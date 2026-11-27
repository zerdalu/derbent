function hasControlCharacter(input: string): boolean {
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if ((code >= 0 && code <= 31) || code === 127) {
      return true;
    }
  }
  return false;
}

/**
 * Validates and sanitizes a redirect target to prevent open redirect vulnerabilities.
 */
export function sanitizeRedirect(rawRedirect: unknown, allowedOrigins: readonly string[] = []): string {
  if (typeof rawRedirect !== "string") {
    return "/";
  }

  const trimmed = rawRedirect.trim();
  if (trimmed.length === 0 || hasControlCharacter(trimmed)) {
    return "/";
  }

  // Safe relative path: starts with a single '/' and not '//' or '/\'
  if (trimmed.startsWith("/") && !trimmed.startsWith("//") && !trimmed.startsWith("/\\")) {
    return trimmed;
  }

  // Absolute URL: must parse and match an allowed origin
  try {
    const parsedUrl = new URL(trimmed);
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      return "/";
    }

    const isOriginAllowed = allowedOrigins.some((allowed) => {
      try {
        return parsedUrl.origin === new URL(allowed).origin;
      } catch {
        return false;
      }
    });

    return isOriginAllowed ? trimmed : "/";
  } catch {
    return "/";
  }
}
