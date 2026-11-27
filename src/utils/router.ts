import { useSyncExternalStore } from "react";
import { flushSync } from "react-dom";

export interface RouterLocation {
  readonly pathname: string;
  readonly search: string;
}

export interface NavigateOptions {
  readonly replace?: boolean;
}

const listeners = new Set<() => void>();
let isPopstateRegistered = false;

function notifyListeners(): void {
  for (const listener of listeners) {
    listener();
  }
}

function runWithViewTransition(update: () => void): void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    update();
    return;
  }

  const prefersReducedMotion =
    typeof window.matchMedia === "function" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  if (
    !prefersReducedMotion &&
    "startViewTransition" in document &&
    typeof document.startViewTransition === "function"
  ) {
    document.startViewTransition(() => {
      flushSync(() => {
        update();
      });
    });
    return;
  }

  update();
}

function ensurePopstateListener(): void {
  if (typeof window === "undefined" || isPopstateRegistered) {
    return;
  }
  isPopstateRegistered = true;
  window.addEventListener("popstate", () => {
    runWithViewTransition(() => {
      notifyListeners();
    });
  });
}

function subscribe(listener: () => void): () => void {
  ensurePopstateListener();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

let cachedHref = "";
let cachedSnapshot: RouterLocation = { pathname: "/", search: "" };

function getSnapshot(): RouterLocation {
  if (typeof window === "undefined") {
    return cachedSnapshot;
  }

  const pathname = window.location.pathname || "/";
  const nextHref = `${pathname}${window.location.search}`;
  if (nextHref !== cachedHref) {
    cachedHref = nextHref;
    cachedSnapshot = {
      pathname,
      search: window.location.search,
    };
  }

  return cachedSnapshot;
}

export function stripSearchParam(search: string, paramName: string): string {
  const params = new URLSearchParams(search);
  params.delete(paramName);
  return params.toString();
}

export function scrubSearchParam(paramName: string): void {
  if (typeof window === "undefined") {
    return;
  }

  const currentParams = new URLSearchParams(window.location.search);
  if (!currentParams.has(paramName)) {
    return;
  }

  currentParams.delete(paramName);
  const nextSearch = currentParams.toString();
  const normalizedSearch = nextSearch ? `?${nextSearch}` : "";
  const pathname = window.location.pathname || "/";
  const nextUrl = `${pathname}${normalizedSearch}`;

  window.history.replaceState(null, "", nextUrl);
  cachedHref = nextUrl;
  cachedSnapshot = {
    pathname,
    search: normalizedSearch,
  };
  notifyListeners();
}

export function navigate(to: string, options: NavigateOptions = {}): void {
  if (typeof window === "undefined") {
    return;
  }

  if (to.startsWith("http://") || to.startsWith("https://")) {
    if (options.replace) {
      window.location.replace(to);
    } else {
      window.location.assign(to);
    }
    return;
  }

  const currentHref = `${window.location.pathname || "/"}${window.location.search}`;
  if (to === currentHref) {
    return;
  }

  runWithViewTransition(() => {
    if (options.replace) {
      window.history.replaceState(null, "", to);
    } else {
      window.history.pushState(null, "", to);
    }
    notifyListeners();
  });
  window.scrollTo({ top: 0, behavior: "auto" });
}

export function useRouterLocation(): RouterLocation {
  return useSyncExternalStore(subscribe, getSnapshot, getSnapshot);
}

export function buildAuthQuery(appId: string, redirect: string): string {
  return new URLSearchParams({ app_id: appId, redirect }).toString();
}
