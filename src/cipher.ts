import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// AES-256-GCM: ได้ทั้ง confidentiality และ integrity (ตรวจจับการแก้ไข ciphertext ได้)
const ALG = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const VERSION = 'v1';

/** เข้ารหัส bytes → iv(12) | tag(16) | ciphertext */
function encryptBytes(key: Buffer, data: Buffer, aad: string): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALG, key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

/** ถอดรหัส iv | tag | ciphertext — throw ถ้า key, aad หรือ ciphertext ไม่ตรง */
function decryptBytes(key: Buffer, raw: Buffer, aad: string): Buffer {
  if (raw.length < IV_LEN + TAG_LEN) throw new Error('Ciphertext too short');
  const iv = raw.subarray(0, IV_LEN);
  const tag = raw.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = raw.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/**
 * Encrypt string → "v1.<base64(iv|tag|ciphertext)>"
 * aad (Additional Authenticated Data) ผูก ciphertext กับเจ้าของ + field (เช่น "<userId>:<field>")
 * กันการเอา ciphertext ของคนอื่น/field อื่นมาสลับใส่
 */
function encrypt(key: Buffer, plaintext: string, aad: string): string {
  return `${VERSION}.${encryptBytes(key, Buffer.from(plaintext, 'utf8'), aad).toString('base64')}`;
}

function decrypt(key: Buffer, payload: string, aad: string): string {
  const [version, b64] = payload.split('.');
  if (version !== VERSION || !b64) throw new Error('Unsupported ciphertext format');
  return decryptBytes(key, Buffer.from(b64, 'base64'), aad).toString('utf8');
}

/** แปลง key base64 จาก env/secret store เป็น Buffer และตรวจว่ายาว 32 bytes */
function decodeKey(b64: string, name: string): Buffer {
  const key = Buffer.from(b64, 'base64');
  if (key.length !== KEY_LEN) throw new Error(`${name} must be 32 bytes (base64)`);
  return key;
}

/** สุ่ม key 32 bytes (ใช้เป็น DEK หรือสร้าง key ใส่ .env ตอน dev) */
function generateKey(): Buffer {
  return randomBytes(KEY_LEN);
}

export default { encrypt, decrypt, encryptBytes, decryptBytes, decodeKey, generateKey };
