const ALLOWED_SVG_TAGS = new Set([
  "svg",
  "g",
  "path",
  "circle",
  "ellipse",
  "line",
  "polyline",
  "polygon",
  "rect",
  "defs",
  "lineargradient",
  "radialgradient",
  "stop",
  "clippath",
  "mask",
  "pattern",
  "symbol",
  "title",
  "desc",
]);

const ALLOWED_SVG_ATTRIBUTES = new Set([
  "xmlns",
  "xmlns:xlink",
  "version",
  "viewbox",
  "width",
  "height",
  "x",
  "y",
  "x1",
  "y1",
  "x2",
  "y2",
  "cx",
  "cy",
  "r",
  "rx",
  "ry",
  "d",
  "points",
  "fill",
  "fill-rule",
  "fill-opacity",
  "stroke",
  "stroke-width",
  "stroke-linecap",
  "stroke-linejoin",
  "stroke-miterlimit",
  "stroke-dasharray",
  "stroke-dashoffset",
  "stroke-opacity",
  "opacity",
  "transform",
  "gradientunits",
  "gradienttransform",
  "spreadmethod",
  "offset",
  "stop-color",
  "stop-opacity",
  "clip-path",
  "clip-rule",
  "mask",
  "maskunits",
  "maskcontentunits",
  "patternunits",
  "patterncontentunits",
  "patterntransform",
  "id",
  "class",
  "preserveaspectratio",
  "vector-effect",
  "color",
  "display",
  "visibility",
  "overflow",
  "shape-rendering",
  "aria-hidden",
  "aria-label",
  "role",
  "focusable",
]);

const ATTRIBUTE_PAIR_REGEX = /^\s+([a-zA-Z_:][a-zA-Z0-9_.:-]*)\s*=\s*(?:"([^"<>]*)"|'([^'<>]*)')/;

function stripControlAndWhitespace(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code > 32 && code !== 127) {
      out += input[i] ?? "";
    }
  }
  return out;
}

function hasUnsafeAttributeValue(attrName: string, rawValue: string): boolean {
  const normalized = stripControlAndWhitespace(rawValue).toLowerCase();

  if (normalized.includes("javascript:") || normalized.includes("vbscript:") || normalized.includes("data:")) {
    return true;
  }

  // Disallow HTML character entity encoding in URI or functional attributes
  if ((attrName === "xmlns" || normalized.includes("url(")) && /&(?:#[0-9]+|#x[0-9a-f]+|[a-z0-9]+);/i.test(rawValue)) {
    return true;
  }

  // Only allow local fragment references in url(#...)
  const urlMatches = rawValue.match(/url\([^)]*\)/gi);
  if (urlMatches) {
    for (const match of urlMatches) {
      if (!/^url\(\s*['"]?#[a-zA-Z0-9_.-]+['"]?\s*\)$/i.test(match.trim())) {
        return true;
      }
    }
  }

  return false;
}

function validateAttributes(rawAttrs: string): boolean {
  let remaining = rawAttrs;
  if (remaining.trim().length === 0) {
    return true;
  }

  // Attributes must be separated from the tag name by whitespace (blocks <svg/onload=...>)
  if (!/^\s/.test(remaining)) {
    return false;
  }

  while (remaining.trim().length > 0) {
    const match = ATTRIBUTE_PAIR_REGEX.exec(remaining);
    if (!match) {
      return false;
    }

    const attrName = (match[1] ?? "").toLowerCase();
    const attrValue = match[2] ?? match[3] ?? "";

    if (attrName.startsWith("on") || !ALLOWED_SVG_ATTRIBUTES.has(attrName)) {
      return false;
    }

    if (hasUnsafeAttributeValue(attrName, attrValue)) {
      return false;
    }

    remaining = remaining.slice(match[0].length);
  }

  return true;
}

/**
 * Validates SVG markup against malicious payloads (Stored XSS) using a strict tag and attribute allowlist.
 */
export function isSafeSvg(rawSvg: string): boolean {
  const trimmed = rawSvg.trim();
  if (trimmed.length === 0) {
    return false;
  }

  if (!/^<svg\b[\s\S]*<\/svg>$/i.test(trimmed)) {
    return false;
  }

  // Disallow comments, CDATA, doctype, entities, and processing instructions
  if (/<!|<!--|<\?/i.test(trimmed)) {
    return false;
  }

  const tagRegex = /<([^<>]+)>/g;
  const tagStack: string[] = [];
  let lastIndex = 0;
  let match: RegExpExecArray | null = tagRegex.exec(trimmed);

  while (match !== null) {
    const betweenText = trimmed.slice(lastIndex, match.index);
    if (betweenText.includes("<") || betweenText.includes(">")) {
      return false;
    }

    if (betweenText.trim().length > 0) {
      const currentParent = tagStack[tagStack.length - 1];
      if (currentParent !== "title" && currentParent !== "desc") {
        return false;
      }
    }

    const inner = (match[1] ?? "").trim();
    if (inner.length === 0) {
      return false;
    }

    if (inner.startsWith("/")) {
      const closeMatch = /^\/([a-zA-Z][a-zA-Z0-9-]*)\s*$/.exec(inner);
      if (!closeMatch) {
        return false;
      }
      const closeTag = (closeMatch[1] ?? "").toLowerCase();
      if (!ALLOWED_SVG_TAGS.has(closeTag)) {
        return false;
      }

      const expectedTag = tagStack.pop();
      if (expectedTag !== closeTag) {
        return false;
      }

      // Root <svg> cannot close before the end of the document
      if (tagStack.length === 0 && tagRegex.lastIndex !== trimmed.length) {
        return false;
      }
    } else {
      const openMatch = /^([a-zA-Z][a-zA-Z0-9-]*)([\s\S]*?)(\/?)$/.exec(inner);
      if (!openMatch) {
        return false;
      }

      const openTag = (openMatch[1] ?? "").toLowerCase();
      const attrPart = openMatch[2] ?? "";
      const isSelfClosing = openMatch[3] === "/";

      if (!ALLOWED_SVG_TAGS.has(openTag)) {
        return false;
      }

      if (lastIndex === 0 && openTag !== "svg") {
        return false;
      }

      if (!validateAttributes(attrPart)) {
        return false;
      }

      if (!isSelfClosing) {
        tagStack.push(openTag);
      } else if (openTag === "svg" && tagRegex.lastIndex !== trimmed.length) {
        return false;
      }
    }

    lastIndex = tagRegex.lastIndex;
    match = tagRegex.exec(trimmed);
  }

  return lastIndex === trimmed.length && tagStack.length === 0;
}

export function sanitizeSvg(rawSvg: string | null | undefined): string | null {
  if (!rawSvg) {
    return null;
  }

  if (!isSafeSvg(rawSvg)) {
    return null;
  }

  return rawSvg.trim();
}
