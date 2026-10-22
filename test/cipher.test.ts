import { describe, expect, test } from 'bun:test';
import { cipher } from '../src/index.js';

const key = cipher.generateKey();

describe('cipher', () => {
  test('encrypt → decrypt ได้ค่าเดิม รวมภาษาไทยและ emoji', () => {
    for (const plaintext of ['', 'hello', 'สมชาย ใจดี', '👍 1234']) {
      expect(cipher.decrypt(key, cipher.encrypt(key, plaintext, 'u1:firstName'), 'u1:firstName')).toBe(plaintext);
    }
  });

  test('รูปแบบ "v1.<base64>" และ IV สุ่มทุกครั้ง', () => {
    const a = cipher.encrypt(key, 'same', 'aad');
    const b = cipher.encrypt(key, 'same', 'aad');
    expect(a).toMatch(/^v1\.[A-Za-z0-9+/]+=*$/);
    expect(a).not.toBe(b);
  });

  test('AAD ไม่ตรง (สลับ ciphertext ข้าม user/field) → throw', () => {
    const ct = cipher.encrypt(key, 'secret', 'u1:email');
    expect(() => cipher.decrypt(key, ct, 'u2:email')).toThrow();
    expect(() => cipher.decrypt(key, ct, 'u1:phone')).toThrow();
  });

  test('key ผิด → throw', () => {
    const ct = cipher.encrypt(key, 'secret', 'aad');
    expect(() => cipher.decrypt(cipher.generateKey(), ct, 'aad')).toThrow();
  });

  test('ciphertext ถูกแก้ → throw (GCM auth tag)', () => {
    const raw = cipher.encryptBytes(key, Buffer.from('secret'), 'aad');
    raw[raw.length - 1]! ^= 1;
    expect(() => cipher.decryptBytes(key, raw, 'aad')).toThrow();
  });

  test('รูปแบบไม่รู้จักหรือสั้นเกิน → throw', () => {
    expect(() => cipher.decrypt(key, 'v2.abc', 'aad')).toThrow('Unsupported ciphertext format');
    expect(() => cipher.decrypt(key, 'no-dot', 'aad')).toThrow('Unsupported ciphertext format');
    expect(() => cipher.decryptBytes(key, Buffer.alloc(10), 'aad')).toThrow('Ciphertext too short');
  });

  test('decodeKey รับเฉพาะ 32 bytes', () => {
    expect(cipher.decodeKey(key.toString('base64'), 'K').equals(key)).toBe(true);
    expect(() => cipher.decodeKey(Buffer.alloc(16).toString('base64'), 'K')).toThrow('K must be 32 bytes');
  });

  test('ถอดรหัสข้อมูลที่เข้ารหัสด้วยรูปแบบเดิมของ pdpa-poc-api ได้ (iv|tag|ct, AES-256-GCM)', async () => {
    const { createCipheriv } = await import('node:crypto');
    const iv = Buffer.alloc(12, 1);
    const c = createCipheriv('aes-256-gcm', key, iv);
    c.setAAD(Buffer.from('u1:email', 'utf8'));
    const ct = Buffer.concat([c.update('a@b.co', 'utf8'), c.final()]);
    const legacy = `v1.${Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64')}`;
    expect(cipher.decrypt(key, legacy, 'u1:email')).toBe('a@b.co');
  });
});
