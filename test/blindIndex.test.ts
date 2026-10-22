import { createHmac } from 'node:crypto';
import { describe, expect, test } from 'bun:test';
import { cipher, createBlindIndex, length, normalize } from '../src/index.js';

const key = cipher.generateKey();
const bi = createBlindIndex<'email' | 'firstName-prefix' | 'email-prefix'>({ key });

describe('blindIndex', () => {
  test('ค่าเดียวกันได้ HMAC เดียวกัน (deterministic) และตรงกับสูตรเดิม HMAC-SHA256("<label>:<value>")', () => {
    expect(bi.index('email', 'a@b.co')).toBe(bi.index('email', 'a@b.co'));
    expect(bi.index('email', 'a@b.co')).toBe(createHmac('sha256', key).update('email:a@b.co').digest('base64url'));
  });

  test('label ต่างกัน หรือ key ต่างกัน → HMAC ต่างกัน', () => {
    expect(bi.index('email-prefix', 'som')).not.toBe(bi.index('firstName-prefix', 'som'));
    const other = createBlindIndex({ key: cipher.generateKey() });
    expect(other.index('email', 'a@b.co')).not.toBe(bi.index('email', 'a@b.co'));
  });

  test('prefixes ตัดตาม code point 3–5 ตัว', () => {
    expect(bi.prefixes('สมชาย')).toEqual(['สมช', 'สมชา', 'สมชาย']);
    expect(bi.prefixes('abcdefg')).toEqual(['abc', 'abcd', 'abcde']);
    expect(bi.prefixes('ab')).toEqual([]);
    expect(bi.prefixQuery('abcdefg')).toBe('abcde');
  });

  test('กำหนดช่วง prefix เองได้', () => {
    const custom = createBlindIndex({ key, prefixMin: 2, prefixMax: 3 });
    expect(custom.prefixes('abcd')).toEqual(['ab', 'abc']);
    expect(custom.PREFIX_MAX).toBe(3);
  });

  test('ปฏิเสธ key สั้นและช่วง prefix ผิด', () => {
    expect(() => createBlindIndex({ key: Buffer.alloc(16) })).toThrow();
    expect(() => createBlindIndex({ key, prefixMin: 4, prefixMax: 3 })).toThrow();
  });

  test('normalize', () => {
    expect(normalize.email('  A@B.Co ')).toBe('a@b.co');
    expect(normalize.digits('1-2345-67890-12-3')).toBe('1234567890123');
    expect(normalize.text(' Somchai ')).toBe('somchai');
    expect(length('สมชาย')).toBe(5);
  });
});
