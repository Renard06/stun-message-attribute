import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';

import {
  parseAttributes,
  encodeAttributes,
  parseXorMappedAddress,
  encodeXorMappedAddress,
  Attribute,
} from '../src/index.js';

// 0x2112A442 — the magic cookie XOR mask for STUN. Inlined here so tests don't
// reach into the source for a constant that's part of the protocol, not the API.
const MAGIC_COOKIE = 0x2112a442;
// A fixed 12-byte transaction ID used across every test. Real STUN clients use
// random bytes; we pin one so the IPv6 mask is deterministic.
const TX_ID = Buffer.from([
  0x28, 0x6a, 0x9c, 0x0d, 0x6e, 0x67, 0x4f, 0x89,
  0x82, 0x53, 0x3c, 0x32,
]);

test('Attribute.toBytes rounds a generic attribute through unchanged', () => {
  const value = Buffer.from([0x01, 0x02, 0x03]);
  const attr = new Attribute(0x0006, value);
  // 4-byte header + 1 byte of value + 3 bytes of padding.
  assert.equal(attr.toBytes().length, 8);
  assert.deepEqual(
    Array.from(attr.toBytes()),
    [0x00, 0x06, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00],
  );
});

test('Attribute rejects values that exceed the uint16 length limit', () => {
  const huge = Buffer.alloc(0x10000);
  assert.throws(() => new Attribute(0x0001, huge), RangeError);
});

test('Attribute rejects out-of-range or non-integer type codes', () => {
  assert.throws(() => new Attribute(-1, Buffer.alloc(0)), RangeError);
  assert.throws(() => new Attribute(0x10000, Buffer.alloc(0)), RangeError);
  assert.throws(() => new Attribute(1.5, Buffer.alloc(0)), RangeError);
});

test('parseAttributes + encodeAttributes round-trip multiple attributes', () => {
  const a = new Attribute(0x0006, Buffer.from([0xff]));
  const b = new Attribute(0x8028, Buffer.from([0x10, 0x20, 0x30, 0x40]));
  const encoded = encodeAttributes([a, b]);
  const decoded = parseAttributes(encoded, TX_ID);
  assert.equal(decoded.length, 2);
  assert.equal(decoded[0].type, 0x0006);
  assert.deepEqual(Array.from(decoded[0].value), [0xff]);
  assert.equal(decoded[1].type, 0x8028);
  assert.deepEqual(Array.from(decoded[1].value), [0x10, 0x20, 0x30, 0x40]);
});

test('parseAttributes honours 4-byte padding on a 1-byte value', () => {
  // type=0x0001, length=1, value=0xAB, then 3 padding bytes.
  const buf = Buffer.from([0x00, 0x01, 0x00, 0x01, 0xab, 0x00, 0x00, 0x00]);
  const attrs = parseAttributes(buf, TX_ID);
  assert.equal(attrs.length, 1);
  assert.equal(attrs[0].length, 1);
  assert.deepEqual(Array.from(attrs[0].value), [0xab]);
});

test('parseAttributes throws on a truncated attribute value', () => {
  // Declares 10 bytes of value but only 4 follow.
  const buf = Buffer.from([0x00, 0x01, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04]);
  assert.throws(() => parseAttributes(buf, TX_ID), RangeError);
});

test('parseAttributes throws on trailing bytes that are not a full header', () => {
  // One complete 4-byte attribute + 1 stray byte.
  const buf = Buffer.from([0x00, 0x01, 0x00, 0x00, 0xff]);
  assert.throws(() => parseAttributes(buf, TX_ID), RangeError);
});

test('parseAttributes accepts an empty buffer', () => {
  const attrs = parseAttributes(Buffer.alloc(0), TX_ID);
  assert.deepEqual(attrs, []);
});

test('parseAttributes rejects a non-12-byte transaction ID', () => {
  assert.throws(
    () => parseAttributes(Buffer.alloc(0), Buffer.alloc(11)),
    TypeError,
  );
});

test('encodeAttributes rejects non-Attribute elements', () => {
  assert.throws(() => encodeAttributes([{ type: 1, value: Buffer.alloc(0) }]), TypeError);
});

test('parseXorMappedAddress decodes an IPv4 address and port', () => {
  // Hand-build the XOR-MAPPED-ADDRESS value so the test exercises the decoder,
  // not the encoder. Address 192.0.2.1, port 32853.
  const port = 32853;
  const ip = (192 << 24) | (0 << 16) | (2 << 8) | 1;
  const xorPort = port ^ (MAGIC_COOKIE >>> 16);
  const xorIp = (ip ^ MAGIC_COOKIE) >>> 0;
  const val = Buffer.alloc(8);
  val.writeUInt8(0, 0);
  val.writeUInt8(0x01, 1);
  val.writeUInt16BE(xorPort, 2);
  val.writeUInt32BE(xorIp, 4);

  const parsed = parseXorMappedAddress(val, TX_ID);
  assert.equal(parsed.family, 0x01);
  assert.equal(parsed.port, port);
  assert.equal(parsed.address, '192.0.2.1');
});

test('encodeXorMappedAddress + parseXorMappedAddress round-trip IPv4', () => {
  const parsed = { family: 0x01, port: 49920, address: '203.0.113.77' };
  const encoded = encodeXorMappedAddress(parsed, TX_ID);
  const decoded = parseXorMappedAddress(encoded, TX_ID);
  assert.deepEqual(decoded, parsed);
});

test('parseXorMappedAddress rejects an unsupported address family', () => {
  const val = Buffer.alloc(8);
  val.writeUInt8(0x09, 1); // bogus family
  assert.throws(() => parseXorMappedAddress(val, TX_ID), RangeError);
});

test('parseXorMappedAddress rejects a truncated IPv4 value', () => {
  const val = Buffer.from([0x00, 0x01, 0x00, 0x00]);
  assert.throws(() => parseXorMappedAddress(val, TX_ID), RangeError);
});

test('parseXorMappedAddress decodes an IPv6 address using cookie || txId', () => {
  // Use the documented TEST-NET address 2001:db8::1 so no real network is
  // implied. Build expected bytes manually.
  const ipBuf = Buffer.alloc(16);
  ipBuf.writeUInt16BE(0x2001, 0);
  ipBuf.writeUInt16BE(0x0db8, 2);
  ipBuf.writeUInt16BE(0x0001, 14);
  const mask = Buffer.alloc(16);
  mask.writeUInt32BE(MAGIC_COOKIE, 0);
  TX_ID.copy(mask, 4);
  const port = 32853;
  const xorPort = port ^ (MAGIC_COOKIE >>> 16);
  const val = Buffer.alloc(20);
  val.writeUInt8(0, 0);
  val.writeUInt8(0x02, 1);
  val.writeUInt16BE(xorPort, 2);
  for (let i = 0; i < 16; i++) {
    val[4 + i] = ipBuf[i] ^ mask[i];
  }

  const parsed = parseXorMappedAddress(val, TX_ID);
  assert.equal(parsed.family, 0x02);
  assert.equal(parsed.port, port);
  assert.equal(parsed.address, '2001:db8::1');
});

test('encodeXorMappedAddress + parseXorMappedAddress round-trip IPv6', () => {
  const parsed = { family: 0x02, port: 50000, address: '2001:db8:85a3::8a2e:370:7334' };
  const encoded = encodeXorMappedAddress(parsed, TX_ID);
  const decoded = parseXorMappedAddress(encoded, TX_ID);
  assert.deepEqual(decoded, parsed);
});

test('encodeXorMappedAddress rejects an out-of-range port', () => {
  assert.throws(
    () => encodeXorMappedAddress({ family: 0x01, port: 0x10000, address: '10.0.0.1' }, TX_ID),
    RangeError,
  );
});

test('parseAttributes preserves an unknown attribute type', () => {
  // Type 0x8000 — not in our ATTR_TYPE table, should pass through untouched.
  const value = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const encoded = encodeAttributes([new Attribute(0x8000, value)]);
  const decoded = parseAttributes(encoded, TX_ID);
  assert.equal(decoded.length, 1);
  assert.equal(decoded[0].type, 0x8000);
  assert.deepEqual(Array.from(decoded[0].value), [0xde, 0xad, 0xbe, 0xef]);
});
