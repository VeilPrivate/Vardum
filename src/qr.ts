/**
 * b199 (owner, Oct 16): a small, dependency-free QR encoder for the Veil ID
 * QR. Byte mode, error-correction level M, versions 1–10 (up to 213 bytes —
 * an add link is ~50). Pure TypeScript: no native module, so it runs over
 * Metro on the current dev build. Verified module-for-module against the
 * `qrcode` npm library in repro/b199_qr.test.ts.
 */

// [ecc codewords per block, [blocks, data codewords per block][]] for level M
const EC_M: [number, [number, number][]][] = [
  [10, [[1, 16]]],
  [16, [[1, 28]]],
  [26, [[1, 44]]],
  [18, [[2, 32]]],
  [24, [[2, 43]]],
  [16, [[4, 27]]],
  [18, [[4, 31]]],
  [22, [[2, 38], [2, 39]]],
  [22, [[3, 36], [2, 37]]],
  [26, [[4, 43], [1, 44]]],
];

const ALIGN: number[][] = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

// GF(256) with the QR polynomial 0x11d
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x; LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const gfMul = (a: number, b: number) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data: Uint8Array, degree: number): Uint8Array {
  const gen = rsGenerator(degree);
  const buf = new Uint8Array(data.length + degree);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = buf[i];
    if (coef === 0) continue;
    for (let j = 0; j < gen.length; j++) buf[i + j] ^= gfMul(gen[j], coef);
  }
  return buf.slice(data.length);
}

function bchDigit(n: number): number {
  let d = 0;
  while (n !== 0) { d++; n >>>= 1; }
  return d;
}

function formatBits(mask: number): number {
  const data = (0b00 << 3) | mask; // level M = 00
  let d = data << 10;
  while (bchDigit(d) - bchDigit(0x537) >= 0) d ^= 0x537 << (bchDigit(d) - bchDigit(0x537));
  return ((data << 10) | d) ^ 0x5412;
}

function versionBits(version: number): number {
  let d = version << 12;
  while (bchDigit(d) - bchDigit(0x1f25) >= 0) d ^= 0x1f25 << (bchDigit(d) - bchDigit(0x1f25));
  return (version << 12) | d;
}

const MASKS: ((i: number, j: number) => boolean)[] = [
  (i, j) => (i + j) % 2 === 0,
  (i) => i % 2 === 0,
  (_i, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i * j) % 3) + ((i + j) % 2)) % 2 === 0,
];

class Matrix {
  readonly size: number;
  readonly dark: Uint8Array;
  readonly reserved: Uint8Array;
  constructor(size: number) {
    this.size = size;
    this.dark = new Uint8Array(size * size);
    this.reserved = new Uint8Array(size * size);
  }
  set(r: number, c: number, v: boolean, reserve: boolean) {
    this.dark[r * this.size + c] = v ? 1 : 0;
    if (reserve) this.reserved[r * this.size + c] = 1;
  }
  get(r: number, c: number) { return this.dark[r * this.size + c] === 1; }
  isReserved(r: number, c: number) { return this.reserved[r * this.size + c] === 1; }
}

function placeFinder(m: Matrix, row: number, col: number) {
  for (let r = -1; r <= 7; r++) {
    if (row + r <= -1 || m.size <= row + r) continue;
    for (let c = -1; c <= 7; c++) {
      if (col + c <= -1 || m.size <= col + c) continue;
      const on = (r >= 0 && r <= 6 && (c === 0 || c === 6)) || (c >= 0 && c <= 6 && (r === 0 || r === 6)) || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
      m.set(row + r, col + c, on, true);
    }
  }
}

function placeFormat(m: Matrix, mask: number) {
  const size = m.size;
  const bits = formatBits(mask);
  for (let i = 0; i < 15; i++) {
    const on = ((bits >> i) & 1) === 1;
    if (i < 6) m.set(i, 8, on, true);
    else if (i < 8) m.set(i + 1, 8, on, true);
    else m.set(size - 15 + i, 8, on, true);
    if (i < 8) m.set(8, size - i - 1, on, true);
    else if (i < 9) m.set(8, 15 - i - 1 + 1, on, true);
    else m.set(8, 15 - i - 1, on, true);
  }
  m.set(size - 8, 8, true, true); // dark module
}

function applyMask(m: Matrix, mask: number) {
  const f = MASKS[mask];
  for (let r = 0; r < m.size; r++) {
    for (let c = 0; c < m.size; c++) {
      if (m.isReserved(r, c)) continue;
      if (f(r, c)) m.dark[r * m.size + c] ^= 1;
    }
  }
}

function penalty(m: Matrix): number {
  const n = m.size;
  const d = (r: number, c: number) => m.dark[r * n + c];
  let p = 0;
  // N1: runs of 5+ in rows and columns
  for (let r = 0; r < n; r++) {
    let sameR = 0, sameC = 0, lastR = -1, lastC = -1;
    for (let c = 0; c < n; c++) {
      let v = d(r, c);
      if (v === lastR) sameR++; else { if (sameR >= 5) p += 3 + (sameR - 5); lastR = v; sameR = 1; }
      v = d(c, r);
      if (v === lastC) sameC++; else { if (sameC >= 5) p += 3 + (sameC - 5); lastC = v; sameC = 1; }
    }
    if (sameR >= 5) p += 3 + (sameR - 5);
    if (sameC >= 5) p += 3 + (sameC - 5);
  }
  // N2: 2x2 blocks
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const s = d(r, c) + d(r, c + 1) + d(r + 1, c) + d(r + 1, c + 1);
      if (s === 4 || s === 0) p += 3;
    }
  }
  // N3: finder-like 1:1:3:1:1 patterns
  for (let r = 0; r < n; r++) {
    let bitsR = 0, bitsC = 0;
    for (let c = 0; c < n; c++) {
      bitsR = ((bitsR << 1) & 0x7ff) | d(r, c);
      if (c >= 10 && (bitsR === 0x5d0 || bitsR === 0x05d)) p += 40;
      bitsC = ((bitsC << 1) & 0x7ff) | d(c, r);
      if (c >= 10 && (bitsC === 0x5d0 || bitsC === 0x05d)) p += 40;
    }
  }
  // N4: dark/light balance
  let darkCount = 0;
  for (let i = 0; i < m.dark.length; i++) darkCount += m.dark[i];
  p += Math.abs(Math.ceil((darkCount * 100 / m.dark.length) / 5) - 10) * 10;
  return p;
}

/** Encode text (UTF-8, byte mode, level M). Returns rows of dark (true) / light modules. */
export function qrMatrix(text: string): boolean[][] {
  const bytes = new TextEncoder().encode(text);
  let version = 0;
  for (let v = 1; v <= 10; v++) {
    const [, groups] = EC_M[v - 1];
    const dataCap = groups.reduce((n, [b, k]) => n + b * k, 0);
    const bits = 4 + (v < 10 ? 8 : 16) + bytes.length * 8;
    if (bits <= dataCap * 8) { version = v; break; }
  }
  if (!version) throw new Error('QR: text too long');
  const [eccPerBlock, groups] = EC_M[version - 1];
  const dataCap = groups.reduce((n, [b, k]) => n + b * k, 0);

  // bit stream: mode, count, data, terminator, pad
  const bits: number[] = [];
  const put = (val: number, len: number) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  put(0b0100, 4);
  put(bytes.length, version < 10 ? 8 : 16);
  for (const b of bytes) put(b, 8);
  for (let i = 0; i < 4 && bits.length < dataCap * 8; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const data = new Uint8Array(dataCap);
  for (let i = 0; i < bits.length / 8; i++) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
    data[i] = v;
  }
  for (let i = bits.length / 8, pad = 0; i < dataCap; i++, pad++) data[i] = pad % 2 === 0 ? 0xec : 0x11;

  // split into blocks, add RS, interleave
  const dataBlocks: Uint8Array[] = [];
  const eccBlocks: Uint8Array[] = [];
  let off = 0;
  for (const [count, k] of groups) {
    for (let b = 0; b < count; b++) {
      const blk = data.slice(off, off + k);
      off += k;
      dataBlocks.push(blk);
      eccBlocks.push(rsRemainder(blk, eccPerBlock));
    }
  }
  const maxData = Math.max(...dataBlocks.map((b) => b.length));
  const codewords: number[] = [];
  for (let i = 0; i < maxData; i++) for (const b of dataBlocks) if (i < b.length) codewords.push(b[i]);
  for (let i = 0; i < eccPerBlock; i++) for (const b of eccBlocks) codewords.push(b[i]);

  // function patterns
  const size = version * 4 + 17;
  const m = new Matrix(size);
  placeFinder(m, 0, 0);
  placeFinder(m, size - 7, 0);
  placeFinder(m, 0, size - 7);
  for (let i = 8; i < size - 8; i++) {
    m.set(i, 6, i % 2 === 0, true);
    m.set(6, i, i % 2 === 0, true);
  }
  const al = ALIGN[version - 1];
  for (const r of al) {
    for (const c of al) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const on = dr === -2 || dr === 2 || dc === -2 || dc === 2 || (dr === 0 && dc === 0);
          m.set(r + dr, c + dc, on, true);
        }
      }
    }
  }
  if (version >= 7) {
    const vb = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const row = Math.floor(i / 3);
      const col = (i % 3) + size - 8 - 3;
      const on = ((vb >> i) & 1) === 1;
      m.set(row, col, on, true);
      m.set(col, row, on, true);
    }
  }
  placeFormat(m, 0); // reserve the format areas before data placement

  // data placement (zigzag)
  let inc = -1, row = size - 1, bitIndex = 7, byteIndex = 0;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (;;) {
      for (let c = 0; c < 2; c++) {
        if (!m.isReserved(row, col - c)) {
          let on = false;
          if (byteIndex < codewords.length) on = ((codewords[byteIndex] >>> bitIndex) & 1) === 1;
          m.set(row, col - c, on, false);
          bitIndex--;
          if (bitIndex === -1) { byteIndex++; bitIndex = 7; }
        }
      }
      row += inc;
      if (row < 0 || size <= row) { row -= inc; inc = -inc; break; }
    }
  }

  // choose the mask with the lowest penalty
  let best = 0, bestScore = Infinity;
  for (let p = 0; p < 8; p++) {
    placeFormat(m, p);
    applyMask(m, p);
    const score = penalty(m);
    applyMask(m, p);
    if (score < bestScore) { bestScore = score; best = p; }
  }
  applyMask(m, best);
  placeFormat(m, best);

  const out: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const line: boolean[] = [];
    for (let c = 0; c < size; c++) line.push(m.get(r, c));
    out.push(line);
  }
  return out;
}

/** The link a Veil QR carries: the public Veil ID only — no keys, no account. */
export function veilAddLink(veilId: string): string {
  return `https://tryveil.app/?add=${encodeURIComponent(veilId)}`;
}

/** Pull a Veil ID out of a scanned/tapped add link (or a bare ID); null if none. */
export function parseVeilAddLink(raw: string): string | null {
  const m = String(raw || '').match(/[?&]add=([1-9A-HJ-NP-Za-km-z]{8,64})(?:[&#]|$)/);
  return m ? m[1] : null;
}
