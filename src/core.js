import { Buffer } from 'node:buffer';

/**
 * STUN magic cookie as defined in RFC 5389 §1.
 * 0x2112A442 — baked into every modern STUN message and used as the XOR mask
 * for the XOR-MAPPED-ADDRESS attribute's address/port fields.
 */
const MAGIC_COOKIE = 0x2112a442;

/**
 * Attribute type codes from RFC 5389 §15.
 * Only the ones we actively handle are listed; every other type flows through
 * the generic TLV path untouched.
 */
export const ATTR_TYPE = Object.freeze({
  XOR_MAPPED_ADDRESS: 0x0020,
  MAPPED_ADDRESS: 0x0001,
});

/**
 * Generic STUN attribute: type, length, and raw value bytes.
 *
 * The `type` and `length` fields intentionally mirror the on-wire names so a
 * reader with RFC 5389 in hand sees no surprises.
 */
export class Attribute {
  /** @param {number} type 16-bit attribute type code */
  /** @param {Buffer} value attribute value bytes (length already validated as ≤ 0xffff) */
  constructor(type, value) {
    if (!Number.isInteger(type) || type < 0 || type > 0xffff) {
      throw new RangeError(`attribute type must fit uint16, got ${type}`);
    }
    if (!(value instanceof Buffer)) {
      throw new TypeError('attribute value must be a Buffer');
    }
    if (value.length > 0xffff) {
      throw new RangeError(`attribute value length ${value.length} exceeds uint16`);
    }
    this.type = type;
    this.value = value;
    /** On-wire length of the value field (excludes the 4-byte header). */
    this.length = value.length;
  }

  /**
   * Encodes this attribute as a 4-byte header + value, padded to a 4-byte
   * boundary per RFC 5389 §15.1 (attributes are always padded).
   * @returns {Buffer}
   */
  toBytes() {
    const paddedLength = (this.length + 3) & ~0x3;
    const buf = Buffer.alloc(4 + paddedLength);
    buf.writeUInt16BE(this.type, 0);
    buf.writeUInt16BE(this.length, 2);
    this.value.copy(buf, 4);
    // Padding bytes default to 0 from Buffer.alloc and MUST be ignored on read,
    // so they're left zeroed rather than guessed at.
    return buf;
  }
}

/**
 * Reads a little-endian 16-bit integer. Used to keep every `===` comparison in
 * the codebase against integers, never against the raw byte pattern, which
 * makes port-comparison assertions read clearly.
 */
function readUint16LE(buf, off) {
  return buf.readUInt16LE(off);
}

/**
 * Parses the XOR-MAPPED-ADDRESS attribute payload into {family, port, address}.
 *
 * The port and address are XOR'd with the STUN magic cookie (RFC 5389 §15.2).
 * For IPv6 the cookie is concatenated with the 96-bit transaction ID from the
 * STUN header, so this function takes `txId` (Buffer of exactly 12 bytes) to
 * build the full 128-bit mask. IPv4 uses only the 32-bit cookie and ignores
 * `txId`, but we still require it for signature uniformity.
 *
 * Only IPv4 and IPv6 are supported; other families throw.
 *
 * @param {Buffer} attrValue raw attribute value bytes
 * @param {Buffer} txId 12-byte transaction ID from the STUN header
 * @returns {{family: 0x01 | 0x02, port: number, address: string}}
 */
export function parseXorMappedAddress(attrValue, txId) {
  if (!(attrValue instanceof Buffer)) {
    throw new TypeError('attrValue must be a Buffer');
  }
  if (!(txId instanceof Buffer) || txId.length !== 12) {
    throw new TypeError('txId must be a 12-byte Buffer');
  }
  if (attrValue.length < 4) {
    throw new RangeError('xor-mapped-address value too short (need ≥4 bytes)');
  }

  // First byte is reserved; second is the address family.
  const family = attrValue.readUInt8(1);
  if (family !== 0x01 && family !== 0x02) {
    throw new RangeError(`unsupported address family 0x${family.toString(16).padStart(2, '0')}`);
  }

  // Port is always 16-bit XOR'd with the top 16 bits of the magic cookie.
  const xorPort = attrValue.readUInt16BE(2);
  const port = xorPort ^ (MAGIC_COOKIE >>> 16);

  if (family === 0x01) {
    // IPv4: 4 bytes of address XOR'd with the 32-bit cookie.
    if (attrValue.length < 8) {
      throw new RangeError('ipv4 xor-mapped-address truncated');
    }
    const xorAddr = attrValue.readUInt32BE(4);
    const addr = xorAddr ^ MAGIC_COOKIE;
    return { family: 0x01, port, address: ipv4ToString(addr) };
  }

  // IPv6: 16 bytes of address XOR'd with (cookie || txId).
  if (attrValue.length < 20) {
    throw new RangeError('ipv6 xor-mapped-address truncated');
  }
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(MAGIC_COOKIE, 0);
  txId.copy(mask, 4);
  const xorAddr = attrValue.subarray(4, 20);
  const addr = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    addr[i] = xorAddr[i] ^ mask[i];
  }
  return { family: 0x02, port, address: ipv6ToString(addr) };
}

/**
 * Serializes a {family, port, address} into the XOR-MAPPED-ADDRESS value bytes.
 *
 * @param {object} parsed {family, port, address}
 * @param {Buffer} txId 12-byte transaction ID (required for IPv6 mask)
 * @returns {Buffer}
 */
export function encodeXorMappedAddress(parsed, txId) {
  if (!parsed || typeof parsed !== 'object') {
    throw new TypeError('parsed must be an object');
  }
  if (!(txId instanceof Buffer) || txId.length !== 12) {
    throw new TypeError('txId must be a 12-byte Buffer');
  }
  const { family, port, address } = parsed;
  if (family !== 0x01 && family !== 0x02) {
    throw new RangeError(`unsupported address family ${family}`);
  }
  if (!Number.isInteger(port) || port < 0 || port > 0xffff) {
    throw new RangeError('port must fit uint16');
  }

  const xorPort = (port ^ (MAGIC_COOKIE >>> 16)) & 0xffff;

  if (family === 0x01) {
    const ipInt = parseIPv4(address);
    const xorAddr = (ipInt ^ MAGIC_COOKIE) >>> 0;
    const buf = Buffer.alloc(8);
    buf.writeUInt8(0, 0); // reserved
    buf.writeUInt8(0x01, 1);
    buf.writeUInt16BE(xorPort, 2);
    buf.writeUInt32BE(xorAddr, 4);
    return buf;
  }

  // IPv6
  const ipBuf = parseIPv6(address);
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(MAGIC_COOKIE, 0);
  txId.copy(mask, 4);
  const buf = Buffer.alloc(20);
  buf.writeUInt8(0, 0);
  buf.writeUInt8(0x02, 1);
  buf.writeUInt16BE(xorPort, 2);
  for (let i = 0; i < 16; i++) {
    buf[4 + i] = ipBuf[i] ^ mask[i];
  }
  return buf;
}

/**
 * Converts a uint32 (host byte order) to dotted-quad string.
 * Implemented by hand rather than reaching for `ipaddr.js` so the library stays
 * dependency-free.
 */
function ipv4ToString(n) {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join('.');
}

/** Parses a dotted-quad string into a uint32 in host byte order. */
function parseIPv4(str) {
  if (typeof str !== 'string') {
    throw new TypeError('ipv4 address must be a string');
  }
  const parts = str.split('.');
  if (parts.length !== 4) {
    throw new RangeError(`invalid ipv4 address: ${str}`);
  }
  let n = 0;
  for (const part of parts) {
    if (!/^[0-9]{1,3}$/.test(part)) {
      throw new RangeError(`invalid ipv4 octet: ${part}`);
    }
    const oct = Number.parseInt(part, 10);
    if (oct > 255) {
      throw new RangeError(`ipv4 octet out of range: ${part}`);
    }
    n = (n << 8) | oct;
  }
  return n >>> 0;
}

/**
 * Converts 16 raw address bytes into canonical RFC 5952 compressed form.
 * We implement the compression ourselves — splitting on `::` requires locating
 * the longest run of zero 16-bit groups, then joining the non-zero groups with
 * `::` between them. This avoids pulling in a dependency.
 */
function ipv6ToString(buf) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(buf.readUInt16BE(i));
  }

  // RFC 5952 §4.2.2: compress only a single run of consecutive zero groups,
  // and only if it's at least two groups long. Pick the longest; ties go to
  // the first occurrence per §4.2.3.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen++;
      }
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    // No compression possible.
    return groups.map((g) => g.toString(16)).join(':');
  }

  const left = groups.slice(0, bestStart).map((g) => g.toString(16));
  const right = groups.slice(bestStart + bestLen).map((g) => g.toString(16));
  // Special case: all-zero address collapses to "::".
  if (left.length === 0 && right.length === 0) {
    return '::';
  }
  return `${left.join(':')}::${right.join(':')}`;
}

/** Parses a canonical or mixed-case IPv6 string into 16 bytes. */
function parseIPv6(str) {
  if (typeof str !== 'string') {
    throw new TypeError('ipv6 address must be a string');
  }
  // Reject embedded IPv4 — kept out of scope deliberately. The README notes
  // this; handling it would double the parser for a form STUN peers basically
  // never emit.
  if (str.includes('.')) {
    throw new RangeError('ipv4-mapped ipv6 notation not supported');
  }
  const parts = str.split('::');
  if (parts.length > 2) {
    throw new RangeError(`invalid ipv6 address: ${str}`);
  }
  const buf = Buffer.alloc(16);
  let groups;
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(':') : [];
    const right = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0) {
      throw new RangeError(`ipv6 address too long: ${str}`);
    }
    groups = [...left, ...Array(missing).fill('0'), ...right];
  } else {
    groups = parts[0].split(':');
  }
  if (groups.length !== 8) {
    throw new RangeError(`ipv6 address must have 8 groups, got ${groups.length}`);
  }
  for (let i = 0; i < 8; i++) {
    const g = groups[i];
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
      throw new RangeError(`invalid ipv6 group: ${g}`);
    }
    buf.writeUInt16BE(Number.parseInt(g, 16), i * 2);
  }
  return buf;
}

/**
 * Parses a sequence of zero or more STUN attributes from a Buffer.
 *
 * The buffer is expected to start at the first attribute (i.e. caller has
 * already consumed the 20-byte STUN header). `txId` is the 12-byte transaction
 * ID from that header; it's threaded through so XOR-MAPPED-ADDRESS can be
 * decoded for IPv6, where it forms part of the XOR mask.
 *
 * Returns an array of generic {@link Attribute} objects. Attributes whose type
 * is XOR-MAPPED-ADDRESS are NOT auto-decoded here — call parseXorMappedAddress
 * on their value if you need the decoded address. Keeping the two concerns
 * separate makes round-trip tests trivial.
 *
 * Unknown attributes are preserved as-is (RFC 5389 §3 says ignore unknown
 * attributes, but we surface them so the caller can decide).
 *
 * @param {Buffer} buf
 * @param {Buffer} txId 12-byte transaction ID (required for IPv6 XOR decode)
 * @returns {Attribute[]}
 */
export function parseAttributes(buf, txId) {
  if (!(buf instanceof Buffer)) {
    throw new TypeError('buf must be a Buffer');
  }
  if (!(txId instanceof Buffer) || txId.length !== 12) {
    throw new TypeError('txId must be a 12-byte Buffer');
  }

  const attrs = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const type = buf.readUInt16BE(off);
    const length = buf.readUInt16BE(off + 2);
    off += 4;
    if (off + length > buf.length) {
      throw new RangeError(
        `attribute 0x${type.toString(16).padStart(4, '0')} declares length ${length} but only ${buf.length - off} bytes remain`,
      );
    }
    const value = Buffer.from(buf.subarray(off, off + length));
    attrs.push(new Attribute(type, value));
    // Skip the value and any padding to the next 4-byte boundary.
    off += (length + 3) & ~0x3;
  }
  // Any trailing 1-3 bytes are malformed padding; RFC 5389 forbids them, so we
  // surface the error rather than silently dropping.
  if (off !== buf.length) {
    throw new RangeError(`trailing ${buf.length - off} byte(s) after last attribute`);
  }
  return attrs;
}

/**
 * Serializes an array of Attribute objects back into a contiguous Buffer.
 *
 * @param {Attribute[]} attrs
 * @returns {Buffer}
 */
export function encodeAttributes(attrs) {
  if (!Array.isArray(attrs)) {
    throw new TypeError('attrs must be an array');
  }
  const parts = [];
  for (const attr of attrs) {
    if (!(attr instanceof Attribute)) {
      throw new TypeError('every element must be an Attribute');
    }
    parts.push(attr.toBytes());
  }
  return parts.length === 0 ? Buffer.alloc(0) : Buffer.concat(parts);
}
