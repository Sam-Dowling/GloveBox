'use strict';
// ════════════════════════════════════════════════════════════════════════════
// protobuf-reader.js — Minimal protobuf wire-format reader
//
// Protobuf is the wire format for the CRX v3 `CrxFileHeader`
// (github.com/chromium/chromium → components/crx_file/crx3.proto). We only
// need to surface the fields Loupe cares about (declared extension ID +
// public keys) without pulling in a 200 KB schema compiler. The message
// layout is simple — every field is a varint-tagged key (field_number × 8 +
// wire_type) followed by the payload — and we explicitly stop short of
// implementing packed repeated fields, ZigZag sint decoding, and proto3
// default-value semantics we don't need.
//
// Supported wire types:
//   0  varint           → BigInt / Number
//   1  fixed64          → 8-byte Uint8Array (raw)
//   2  length-delimited → Uint8Array
//   5  fixed32          → 4-byte Uint8Array (raw)
// Any other wire type aborts the read (start-group / end-group are
// deprecated and we never expect to encounter them in CRX headers or any
// other surface Loupe targets).
//
// Returned shape is a plain `{ fieldNumber → value | value[] }` map, with
// repeated fields collapsed into arrays automatically. Nested messages are
// returned as raw bytes — call decode() recursively to drill in.
//
// This module is intentionally self-contained: it has zero dependencies and
// throws only on truncated / malformed input, so callers can wrap it in a
// narrow try/catch and fall back to "envelope present but unparsable".
// ════════════════════════════════════════════════════════════════════════════

const ProtobufReader = {

  // Decode a single varint starting at `offset`.
  // Returns { value: Number (safe) | BigInt (>2^53-1), next: offset after varint }.
  _readVarint(bytes, offset) {
    let result = 0n;
    let shift = 0n;
    let pos = offset;
    while (pos < bytes.length) {
      const b = bytes[pos++];
      result |= BigInt(b & 0x7F) << shift;
      if ((b & 0x80) === 0) {
        // Return Number for values that fit safely, BigInt otherwise.
        const asNum = Number(result);
        const value = (result <= 0xFFFFFFFFFFFFn && Number.isSafeInteger(asNum)) ? asNum : result;
        return { value, next: pos };
      }
      shift += 7n;
      if (shift > 63n) throw new Error('varint overflow');
    }
    throw new Error('truncated varint');
  },

  // Decode a whole protobuf message payload (raw bytes) into a field map.
  // Repeated fields are collapsed into arrays; non-repeated fields land as a
  // single value. Callers can inspect `Array.isArray(x)` to disambiguate.
  decode(bytes) {
    if (!bytes || !bytes.length) return {};
    const fields = Object.create(null);
    let offset = 0;

    const push = (fieldNumber, value) => {
      const existing = fields[fieldNumber];
      if (existing === undefined) {
        fields[fieldNumber] = value;
      } else if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        fields[fieldNumber] = [existing, value];
      }
    };

    while (offset < bytes.length) {
      const tag = this._readVarint(bytes, offset);
      offset = tag.next;
      const tagNum = typeof tag.value === 'bigint' ? Number(tag.value) : tag.value;
      const wireType = tagNum & 0x07;
      const fieldNumber = tagNum >>> 3;

      switch (wireType) {
        case 0: { // varint
          const v = this._readVarint(bytes, offset);
          offset = v.next;
          push(fieldNumber, v.value);
          break;
        }
        case 1: { // fixed64 — 8 raw bytes
          if (offset + 8 > bytes.length) throw new Error('truncated fixed64');
          push(fieldNumber, bytes.subarray(offset, offset + 8));
          offset += 8;
          break;
        }
        case 2: { // length-delimited
          const len = this._readVarint(bytes, offset);
          offset = len.next;
          const lenNum = typeof len.value === 'bigint' ? Number(len.value) : len.value;
          if (offset + lenNum > bytes.length) throw new Error('truncated length-delimited');
          push(fieldNumber, bytes.subarray(offset, offset + lenNum));
          offset += lenNum;
          break;
        }
        case 5: { // fixed32 — 4 raw bytes
          if (offset + 4 > bytes.length) throw new Error('truncated fixed32');
          push(fieldNumber, bytes.subarray(offset, offset + 4));
          offset += 4;
          break;
        }
        default:
          throw new Error('unsupported wire type ' + wireType);
      }
    }
    return fields;
  },

  // Convenience: always return an array for `fieldNumber`, even when absent
  // or when only one occurrence was found. Makes repeated-field iteration
  // loops shorter at the call site.
  asArray(value) {
    if (value === undefined) return [];
    return Array.isArray(value) ? value : [value];
  },
};
