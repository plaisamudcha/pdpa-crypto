import cipher from './cipher.js';

/**
 * KEK (Key Encryption Key) provider
 * LocalKeyProvider ใช้ KEK จาก env — เหมาะกับ dev/POC
 * Production ให้ implement interface เดียวกันนี้ด้วย AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault Transit
 * โดย KEK จะไม่ออกจาก KMS เลย — ส่วนอื่นของระบบไม่ต้องแก้
 */
export interface KeyProvider {
  currentVersion(): string;
  wrap(dek: Buffer, context: string): Promise<{ wrapped: Buffer; kekVersion: string }>;
  unwrap(wrapped: Buffer, kekVersion: string, context: string): Promise<Buffer>;
}

export class LocalKeyProvider implements KeyProvider {
  private readonly keks: Map<string, Buffer>;

  private readonly current: string;

  /** keks = { v1: "<base64>", v2: Buffer } — เก็บเวอร์ชันเก่าไว้จนกว่า rewrapAll เสร็จ */
  constructor(keks: Record<string, string | Buffer>, current: string) {
    this.keks = new Map(
      Object.entries(keks).map(([version, key]) => [version, typeof key === 'string' ? cipher.decodeKey(key, `KEK_${version.toUpperCase()}`) : key]),
    );
    this.current = current;
    if (!this.keks.has(current)) throw new Error(`KEK ${current} not configured`);
  }

  currentVersion() {
    return this.current;
  }

  async wrap(dek: Buffer, context: string) {
    return { wrapped: cipher.encryptBytes(this.keks.get(this.current)!, dek, context), kekVersion: this.current };
  }

  async unwrap(wrapped: Buffer, kekVersion: string, context: string) {
    const kek = this.keks.get(kekVersion);
    if (!kek) throw new Error(`KEK ${kekVersion} not available`);
    return cipher.decryptBytes(kek, wrapped, context);
  }
}
