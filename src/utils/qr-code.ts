/**
 * ISO/IEC 18004 QR Code matrix encoder (Byte mode, Error Correction Level M, Versions 1-12).
 */

export interface QrCodeMatrix {
  readonly size: number;
  readonly modules: readonly (readonly boolean[])[];
}

interface QrVersionSpec {
  readonly version: number;
  readonly totalCodewords: number;
  readonly ecPerBlock: number;
  readonly group1Blocks: number;
  readonly group1Data: number;
  readonly group2Blocks: number;
  readonly group2Data: number;
  readonly alignmentCoords: readonly number[];
}

// EC Level M specifications for Versions 1-12
const VERSION_SPECS: readonly QrVersionSpec[] = [
  {
    version: 1,
    totalCodewords: 26,
    ecPerBlock: 10,
    group1Blocks: 1,
    group1Data: 16,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [],
  },
  {
    version: 2,
    totalCodewords: 44,
    ecPerBlock: 16,
    group1Blocks: 1,
    group1Data: 28,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 18],
  },
  {
    version: 3,
    totalCodewords: 70,
    ecPerBlock: 26,
    group1Blocks: 1,
    group1Data: 44,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 22],
  },
  {
    version: 4,
    totalCodewords: 100,
    ecPerBlock: 18,
    group1Blocks: 2,
    group1Data: 32,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 26],
  },
  {
    version: 5,
    totalCodewords: 134,
    ecPerBlock: 24,
    group1Blocks: 2,
    group1Data: 43,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 30],
  },
  {
    version: 6,
    totalCodewords: 172,
    ecPerBlock: 16,
    group1Blocks: 4,
    group1Data: 27,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 34],
  },
  {
    version: 7,
    totalCodewords: 196,
    ecPerBlock: 18,
    group1Blocks: 4,
    group1Data: 31,
    group2Blocks: 0,
    group2Data: 0,
    alignmentCoords: [6, 22, 38],
  },
  {
    version: 8,
    totalCodewords: 242,
    ecPerBlock: 22,
    group1Blocks: 2,
    group1Data: 38,
    group2Blocks: 2,
    group2Data: 39,
    alignmentCoords: [6, 24, 42],
  },
  {
    version: 9,
    totalCodewords: 292,
    ecPerBlock: 22,
    group1Blocks: 3,
    group1Data: 36,
    group2Blocks: 2,
    group2Data: 37,
    alignmentCoords: [6, 26, 46],
  },
  {
    version: 10,
    totalCodewords: 346,
    ecPerBlock: 26,
    group1Blocks: 4,
    group1Data: 43,
    group2Blocks: 1,
    group2Data: 44,
    alignmentCoords: [6, 28, 50],
  },
  {
    version: 11,
    totalCodewords: 404,
    ecPerBlock: 30,
    group1Blocks: 1,
    group1Data: 50,
    group2Blocks: 4,
    group2Data: 51,
    alignmentCoords: [6, 30, 54],
  },
  {
    version: 12,
    totalCodewords: 466,
    ecPerBlock: 22,
    group1Blocks: 6,
    group1Data: 36,
    group2Blocks: 2,
    group2Data: 37,
    alignmentCoords: [6, 32, 58],
  },
];

// GF(256) lookup tables with primitive polynomial 0x11d
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

{
  let value = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = value;
    GF_LOG[value] = i;
    value <<= 1;
    if ((value & 0x100) !== 0) {
      value ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255] ?? 0;
  }
}

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) {
    return 0;
  }
  const logSum = (GF_LOG[a] ?? 0) + (GF_LOG[b] ?? 0);
  return GF_EXP[logSum] ?? 0;
}

function buildRsGenerator(ecCount: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < ecCount; i++) {
    const next = new Uint8Array(poly.length + 1);
    const factor = GF_EXP[i] ?? 1;
    for (let j = 0; j < poly.length; j++) {
      const coeff = poly[j] ?? 0;
      next[j] = (next[j] ?? 0) ^ coeff;
      next[j + 1] = (next[j + 1] ?? 0) ^ gfMul(coeff, factor);
    }
    poly = next;
  }
  return poly;
}

function computeReedSolomon(data: Uint8Array, ecCount: number): Uint8Array {
  const generator = buildRsGenerator(ecCount);
  const remainder = new Uint8Array(ecCount);

  for (let i = 0; i < data.length; i++) {
    const factor = (data[i] ?? 0) ^ (remainder[0] ?? 0);
    remainder.copyWithin(0, 1);
    remainder[ecCount - 1] = 0;

    if (factor !== 0) {
      for (let j = 0; j < ecCount; j++) {
        remainder[j] = (remainder[j] ?? 0) ^ gfMul(generator[j + 1] ?? 0, factor);
      }
    }
  }

  return remainder;
}

function getTotalDataCodewords(spec: QrVersionSpec): number {
  return spec.group1Blocks * spec.group1Data + spec.group2Blocks * spec.group2Data;
}

function selectVersion(byteLength: number): QrVersionSpec {
  for (const spec of VERSION_SPECS) {
    const countBits = spec.version <= 9 ? 8 : 16;
    const dataBitsCapacity = getTotalDataCodewords(spec) * 8;
    const requiredBits = 4 + countBits + byteLength * 8;
    if (requiredBits <= dataBitsCapacity) {
      return spec;
    }
  }
  throw new Error("QR code payload exceeds maximum supported capacity.");
}

function pushBits(bits: number[], value: number, bitLength: number): void {
  for (let i = bitLength - 1; i >= 0; i--) {
    bits.push((value >>> i) & 1);
  }
}

function encodeDataCodewords(payload: Uint8Array, spec: QrVersionSpec): Uint8Array {
  const totalDataCodewords = getTotalDataCodewords(spec);
  const capacityBits = totalDataCodewords * 8;
  const countBits = spec.version <= 9 ? 8 : 16;

  const bits: number[] = [];
  // Byte mode indicator: 0100
  pushBits(bits, 0b0100, 4);
  pushBits(bits, payload.length, countBits);
  for (let i = 0; i < payload.length; i++) {
    pushBits(bits, payload[i] ?? 0, 8);
  }

  const terminatorLength = Math.min(4, capacityBits - bits.length);
  for (let i = 0; i < terminatorLength; i++) {
    bits.push(0);
  }

  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const codewords = new Uint8Array(totalDataCodewords);
  let byteIdx = 0;
  for (let i = 0; i < bits.length; i += 8) {
    let byteVal = 0;
    for (let b = 0; b < 8; b++) {
      byteVal = (byteVal << 1) | (bits[i + b] ?? 0);
    }
    codewords[byteIdx++] = byteVal;
  }

  let padToggle = true;
  while (byteIdx < totalDataCodewords) {
    codewords[byteIdx++] = padToggle ? 0xec : 0x11;
    padToggle = !padToggle;
  }

  return codewords;
}

function interleaveCodewords(dataCodewords: Uint8Array, spec: QrVersionSpec): Uint8Array {
  const blocks: { readonly data: Uint8Array; readonly ec: Uint8Array }[] = [];
  let offset = 0;

  for (let i = 0; i < spec.group1Blocks; i++) {
    const slice = dataCodewords.slice(offset, offset + spec.group1Data);
    offset += spec.group1Data;
    blocks.push({ data: slice, ec: computeReedSolomon(slice, spec.ecPerBlock) });
  }

  for (let i = 0; i < spec.group2Blocks; i++) {
    const slice = dataCodewords.slice(offset, offset + spec.group2Data);
    offset += spec.group2Data;
    blocks.push({ data: slice, ec: computeReedSolomon(slice, spec.ecPerBlock) });
  }

  const maxDataLen = Math.max(spec.group1Data, spec.group2Data);
  const result = new Uint8Array(spec.totalCodewords);
  let writeIdx = 0;

  for (let col = 0; col < maxDataLen; col++) {
    for (const block of blocks) {
      if (col < block.data.length) {
        result[writeIdx++] = block.data[col] ?? 0;
      }
    }
  }

  for (let col = 0; col < spec.ecPerBlock; col++) {
    for (const block of blocks) {
      result[writeIdx++] = block.ec[col] ?? 0;
    }
  }

  return result;
}

function createBoolGrid(size: number): boolean[][] {
  return Array.from({ length: size }, () => Array<boolean>(size).fill(false));
}

function setModule(modules: boolean[][], reserved: boolean[][], row: number, col: number, dark: boolean): void {
  const modRow = modules[row];
  const resRow = reserved[row];
  if (modRow && resRow) {
    modRow[col] = dark;
    resRow[col] = true;
  }
}

function placeFinderPattern(modules: boolean[][], reserved: boolean[][], top: number, left: number): void {
  const size = modules.length;
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = top + dr;
      const c = left + dc;
      if (r < 0 || r >= size || c < 0 || c >= size) {
        continue;
      }
      const inOuterRing = dr === 0 || dr === 6 || dc === 0 || dc === 6;
      const inInnerSquare = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
      const inPattern = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
      const dark = inPattern && (inOuterRing || inInnerSquare);
      setModule(modules, reserved, r, c, dark);
    }
  }
}

function placeAlignmentPattern(
  modules: boolean[][],
  reserved: boolean[][],
  centerRow: number,
  centerCol: number,
): void {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const dark = Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
      setModule(modules, reserved, centerRow + dr, centerCol + dc, dark);
    }
  }
}

function placeFunctionPatterns(modules: boolean[][], reserved: boolean[][], spec: QrVersionSpec): void {
  const size = modules.length;

  // Finder patterns and separators
  placeFinderPattern(modules, reserved, 0, 0);
  placeFinderPattern(modules, reserved, 0, size - 7);
  placeFinderPattern(modules, reserved, size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i++) {
    const dark = i % 2 === 0;
    if (!(reserved[6]?.[i] ?? false)) {
      setModule(modules, reserved, 6, i, dark);
    }
    if (!(reserved[i]?.[6] ?? false)) {
      setModule(modules, reserved, i, 6, dark);
    }
  }

  // Alignment patterns
  const coords = spec.alignmentCoords;
  for (let i = 0; i < coords.length; i++) {
    for (let j = 0; j < coords.length; j++) {
      const row = coords[i] ?? 0;
      const col = coords[j] ?? 0;
      const isTopLeft = i === 0 && j === 0;
      const isTopRight = i === 0 && j === coords.length - 1;
      const isBottomLeft = i === coords.length - 1 && j === 0;
      if (isTopLeft || isTopRight || isBottomLeft) {
        continue;
      }
      placeAlignmentPattern(modules, reserved, row, col);
    }
  }

  // Dark module
  setModule(modules, reserved, size - 8, 8, true);

  // Reserve format info strips (filled later per mask)
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      setModule(modules, reserved, 8, i, false);
      setModule(modules, reserved, i, 8, false);
    }
  }
  for (let i = size - 8; i < size; i++) {
    setModule(modules, reserved, 8, i, false);
  }
  for (let i = size - 7; i < size; i++) {
    setModule(modules, reserved, i, 8, false);
  }

  // Version info for V7+
  if (spec.version >= 7) {
    let rem = spec.version << 12;
    for (let i = 5; i >= 0; i--) {
      if ((rem & (1 << (i + 12))) !== 0) {
        rem ^= 0x1f25 << i;
      }
    }
    const versionBits = (spec.version << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const dark = ((versionBits >>> i) & 1) === 1;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setModule(modules, reserved, a, b, dark);
      setModule(modules, reserved, b, a, dark);
    }
  }
}

function writeFormatInfo(modules: boolean[][], maskPattern: number): void {
  const size = modules.length;
  // EC Level M = 00
  const data = maskPattern & 0b111;
  let rem = data << 10;
  for (let i = 4; i >= 0; i--) {
    if ((rem & (1 << (i + 10))) !== 0) {
      rem ^= 0x537 << i;
    }
  }
  const format = ((data << 10) | rem) ^ 0x5412;

  const setRaw = (row: number, col: number, bitIndex: number): void => {
    const dark = ((format >>> bitIndex) & 1) === 1;
    const modRow = modules[row];
    if (modRow) {
      modRow[col] = dark;
    }
  };

  // Top-left copy
  for (let i = 0; i <= 5; i++) {
    setRaw(8, i, 14 - i);
  }
  setRaw(8, 7, 8);
  setRaw(8, 8, 7);
  setRaw(7, 8, 6);
  for (let i = 0; i <= 5; i++) {
    setRaw(5 - i, 8, 5 - i);
  }

  // Split bottom-left / top-right copy
  for (let i = 0; i < 7; i++) {
    setRaw(size - 1 - i, 8, 14 - i);
  }
  for (let i = 0; i < 8; i++) {
    setRaw(8, size - 8 + i, 7 - i);
  }
}

function isMasked(maskPattern: number, row: number, col: number): boolean {
  switch (maskPattern) {
    case 0:
      return (row + col) % 2 === 0;
    case 1:
      return row % 2 === 0;
    case 2:
      return col % 3 === 0;
    case 3:
      return (row + col) % 3 === 0;
    case 4:
      return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5:
      return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6:
      return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    case 7:
      return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
    default:
      return false;
  }
}

function placeDataModules(
  modules: boolean[][],
  reserved: boolean[][],
  codewords: Uint8Array,
  maskPattern: number,
): void {
  const size = modules.length;
  const totalBits = codewords.length * 8;
  let bitIndex = 0;
  let goingUp = true;

  for (let rightCol = size - 1; rightCol >= 1; rightCol -= 2) {
    if (rightCol === 6) {
      rightCol--;
    }

    for (let step = 0; step < size; step++) {
      const row = goingUp ? size - 1 - step : step;
      for (let dc = 0; dc < 2; dc++) {
        const col = rightCol - dc;
        if (reserved[row]?.[col] ?? false) {
          continue;
        }

        let dark = false;
        if (bitIndex < totalBits) {
          const byteVal = codewords[bitIndex >>> 3] ?? 0;
          dark = ((byteVal >>> (7 - (bitIndex & 7))) & 1) === 1;
          bitIndex++;
        }

        if (isMasked(maskPattern, row, col)) {
          dark = !dark;
        }

        const modRow = modules[row];
        if (modRow) {
          modRow[col] = dark;
        }
      }
    }

    goingUp = !goingUp;
  }
}

function scoreLineRuns(line: readonly boolean[]): number {
  let penalty = 0;
  let runLength = 0;
  let prev = false;

  for (let i = 0; i < line.length; i++) {
    const cell = line[i] ?? false;
    if (i > 0 && cell === prev) {
      runLength++;
    } else {
      if (runLength >= 5) {
        penalty += 3 + (runLength - 5);
      }
      runLength = 1;
      prev = cell;
    }
  }
  if (runLength >= 5) {
    penalty += 3 + (runLength - 5);
  }
  return penalty;
}

function matchesFinderPattern(line: readonly boolean[], start: number): boolean {
  const p1 =
    (line[start] ?? false) &&
    !(line[start + 1] ?? false) &&
    (line[start + 2] ?? false) &&
    (line[start + 3] ?? false) &&
    (line[start + 4] ?? false) &&
    !(line[start + 5] ?? false) &&
    (line[start + 6] ?? false) &&
    !(line[start + 7] ?? false) &&
    !(line[start + 8] ?? false) &&
    !(line[start + 9] ?? false) &&
    !(line[start + 10] ?? false);

  const p2 =
    !(line[start] ?? false) &&
    !(line[start + 1] ?? false) &&
    !(line[start + 2] ?? false) &&
    !(line[start + 3] ?? false) &&
    (line[start + 4] ?? false) &&
    !(line[start + 5] ?? false) &&
    (line[start + 6] ?? false) &&
    (line[start + 7] ?? false) &&
    (line[start + 8] ?? false) &&
    !(line[start + 9] ?? false) &&
    (line[start + 10] ?? false);

  return p1 || p2;
}

function evaluatePenalty(modules: readonly (readonly boolean[])[]): number {
  const size = modules.length;
  let penalty = 0;

  // Rule 1 & Rule 3 (horizontal & vertical)
  const colBuffer = Array.from({ length: size }, () => false);
  for (let r = 0; r < size; r++) {
    const row = modules[r];
    if (row) {
      penalty += scoreLineRuns(row);
      for (let c = 0; c <= size - 11; c++) {
        if (matchesFinderPattern(row, c)) {
          penalty += 40;
        }
      }
    }
  }

  for (let c = 0; c < size; c++) {
    for (let r = 0; r < size; r++) {
      colBuffer[r] = modules[r]?.[c] ?? false;
    }
    penalty += scoreLineRuns(colBuffer);
    for (let r = 0; r <= size - 11; r++) {
      if (matchesFinderPattern(colBuffer, r)) {
        penalty += 40;
      }
    }
  }

  // Rule 2: 2x2 blocks
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const a = modules[r]?.[c] ?? false;
      const b = modules[r]?.[c + 1] ?? false;
      const d = modules[r + 1]?.[c] ?? false;
      const e = modules[r + 1]?.[c + 1] ?? false;
      if (a === b && a === d && a === e) {
        penalty += 3;
      }
    }
  }

  // Rule 4: Dark proportion
  let darkCount = 0;
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r]?.[c]) {
        darkCount++;
      }
    }
  }
  const percent = (darkCount * 100) / (size * size);
  const prevMultiple = Math.floor(percent / 5) * 5;
  const nextMultiple = prevMultiple + 5;
  penalty += Math.min(Math.abs(prevMultiple - 50) / 5, Math.abs(nextMultiple - 50) / 5) * 10;

  return penalty;
}

export function encodeQrMatrix(text: string): QrCodeMatrix {
  const payload = new TextEncoder().encode(text);
  const spec = selectVersion(payload.length);
  const dataCodewords = encodeDataCodewords(payload, spec);
  const interleaved = interleaveCodewords(dataCodewords, spec);
  const size = 17 + spec.version * 4;

  let bestMask = 0;
  let bestPenalty = Number.POSITIVE_INFINITY;
  let bestModules: boolean[][] | null = null;

  for (let mask = 0; mask < 8; mask++) {
    const modules = createBoolGrid(size);
    const reserved = createBoolGrid(size);
    placeFunctionPatterns(modules, reserved, spec);
    placeDataModules(modules, reserved, interleaved, mask);
    writeFormatInfo(modules, mask);

    const penalty = evaluatePenalty(modules);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
      bestModules = modules;
    }
  }

  if (!bestModules) {
    const fallback = createBoolGrid(size);
    const reserved = createBoolGrid(size);
    placeFunctionPatterns(fallback, reserved, spec);
    placeDataModules(fallback, reserved, interleaved, bestMask);
    writeFormatInfo(fallback, bestMask);
    return { size, modules: fallback };
  }

  return { size, modules: bestModules };
}
