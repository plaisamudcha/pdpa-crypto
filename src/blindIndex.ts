import { createHmac } from 'node:crypto';

/**
 * Blind index = HMAC-SHA256(key, "<label>:<normalized value>")
 * ใช้ค้นหา/ทำ unique index บน field ที่ถูก encrypt
 * ต้องใช้ HMAC ที่มี secret key — ห้ามใช้ SHA256 เปล่า เพราะเลขบัตร 13 หลัก brute force ได้
 * key นี้ต้องแยกจาก KEK/DEK
 */
export type BlindIndexOptions = {
  key: Buffer;
  /** ความยาว prefix ที่ทำ index (นับเป็น code point) — ค่าเริ่มต้น 3–5 */
  prefixMin?: number;
  prefixMax?: number;
};

export const normalize = {
  email: (v: string) => v.trim().toLowerCase(),
  digits: (v: string) => v.replace(/\D/g, ''),
  text: (v: string) => v.trim().normalize('NFC').toLowerCase(),
};

/** ความยาวนับเป็น code point (ภาษาไทยสระ/วรรณยุกต์นับเป็น 1 ตัว) */
export const length = (v: string) => Array.from(v).length;

/**
 * L = label แยกประเภท token ที่แต่ละโปรเจกต์กำหนดเอง — ค่าเดียวกันแต่คนละ label จะได้ HMAC ต่างกัน
 * (เช่น prefix "som" ของอีเมล กับ prefix "som" ของชื่อ)
 */
export function createBlindIndex<L extends string = string>({ key, prefixMin = 3, prefixMax = 5 }: BlindIndexOptions) {
  if (key.length < 32) throw new Error('Blind index key must be at least 32 bytes');
  if (prefixMin < 1 || prefixMax < prefixMin) throw new Error('Invalid prefix range');

  /** HMAC ของค่าที่ normalize แล้ว */
  function index(label: L, normalized: string): string {
    return createHmac('sha256', key).update(`${label}:${normalized}`).digest('base64url');
  }

  /** "สมชาย" → ["สมช", "สมชา", "สมชาย"] — ตัดตาม code point */
  function prefixes(normalized: string): string[] {
    const chars = Array.from(normalized);
    const out: string[] = [];
    for (let len = prefixMin; len <= Math.min(prefixMax, chars.length); len += 1) {
      out.push(chars.slice(0, len).join(''));
    }
    return out;
  }

  /** ตัดคำค้นให้ยาวไม่เกิน prefixMax (เพราะ index เก็บไว้แค่นั้น) */
  function prefixQuery(normalized: string): string {
    return Array.from(normalized).slice(0, prefixMax).join('');
  }

  return { index, prefixes, prefixQuery, normalize, length, PREFIX_MIN: prefixMin, PREFIX_MAX: prefixMax };
}

export type BlindIndex<L extends string = string> = ReturnType<typeof createBlindIndex<L>>;
