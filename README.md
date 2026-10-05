# STUN Message Attribute

A small, dependency-free TypeScript library for parsing and serializing STUN
attribute type-length-value (TLV) pairs, including the XOR-MAPPED-ADDRESS
attribute used in NAT traversal.

## Usage

```typescript
import {
  parseAttributes,
  encodeAttributes,
  parseXorMappedAddress,
  encodeXorMappedAddress,
  Attribute,
} from 'stun-message-attribute';

const txId = Buffer.from([
  0x28, 0x6a, 0x9c, 0x0d, 0x6e, 0x67, 0x4f, 0x89,
  0x82, 0x53, 0x3c, 0x32,
]);

// Encode attributes into a contiguous TLV block.
const attrs = [
  new Attribute(0x0006, Buffer.from([0xff])),
  new Attribute(0x0020, encodeXorMappedAddress(
    { family: 0x01, port: 49920, address: '203.0.113.77' },
    txId,
  )),
];
const wire = encodeAttributes(attrs);

// Parse them back.
const decoded = parseAttributes(wire, txId);
for (const a of decoded) {
  if (a.type === 0x0020) {
    const { port, address } = parseXorMappedAddress(a.value, txId);
    console.log(`NAT-reflexive endpoint: ${address}:${port}`);
  }
}
```

## Why this exists

STUN messages are a flat sequence of TLV attributes padded to 4-byte
boundaries. Most STUN libraries ship a full message parser, transport layer,
and message-integrity handling — useful, but heavy when the only job is walking
an attribute block and decoding the one attribute NAT-traversal tooling
genuinely cares about, XOR-MAPPED-ADDRESS.

This library does only that. The trade-off: you bring your own 20-byte header
parse and your own transaction ID. In return you get a small surface that's easy
to audit and trivial to test.

## Edge cases

- **IPv6 XOR-MAPPED-ADDRESS requires the transaction ID.** The 128-bit XOR mask
  is `magic-cookie || transaction-id`, so both `parseXorMappedAddress` and
  `encodeXorMappedAddress` take a 12-byte `txId` Buffer even for IPv4 (where
  it's unused). Pass the wrong length and you get a `TypeError`.
- **Unknown attribute types are preserved**, not dropped. RFC 5389 says ignore
  them; this library surfaces them so the caller decides what to do.
- **IPv4-mapped IPv6 notation** (`::ffff:192.0.2.1`) is not supported by the
  IPv6 parser. STUN peers overwhelmingly emit hex groups; if you need that
  form, expand it before calling `encodeXorMappedAddress`.
- **Trailing bytes** after the last attribute cause `parseAttributes` to throw.
  RFC 5389 forbids them, and silently dropping them masks real framing bugs.

## API

All exports come from the package root.

- `Attribute` — class. Constructor `(type: number, value: Buffer)`. Fields:
  `type`, `value`, `length`. Method `toBytes(): Buffer`.
- `parseAttributes(buf: Buffer, txId: Buffer): Attribute[]` — parses a TLV
  block (everything after the 20-byte STUN header).
- `encodeAttributes(attrs: Attribute[]): Buffer` — serializes an array back to a
  contiguous, padded block.
- `parseXorMappedAddress(attrValue: Buffer, txId: Buffer): { family, port, address }`
  — decodes the XOR-MAPPED-ADDRESS value. `family` is `0x01` for IPv4 or `0x02`
  for IPv6; `address` is a canonical string.
- `encodeXorMappedAddress(parsed, txId: Buffer): Buffer` — inverse of the above.

## Development

```
node --test
```

All tests run under Node's built-in test runner with no network access.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

