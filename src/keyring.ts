import cipher from './cipher.js';
import type { KeyProvider } from './kms.js';

/** DEK ที่ wrap ด้วย KEK แล้ว — 1 เจ้าของข้อมูล = 1 record */
export type DataKeyRecord = {
  id: string;
  wrappedDek: string; // base64(iv|tag|ciphertext)
  kekVersion: string;
};

/**
 * ที่เก็บ DEK — แต่ละโปรเจกต์ implement กับ DB ของตัวเอง (MongoDB, Postgres, ...)
 * Production: แยกไปอยู่ DB/cluster อื่น จำกัดสิทธิ์ และตั้ง backup retention ให้สั้นกว่าข้อมูลหลัก
 */
export interface DataKeyStore {
  insert(record: DataKeyRecord): Promise<void>;
  find(id: string): Promise<DataKeyRecord | null>;
  delete(id: string): Promise<void>;
  /** สำหรับ KEK rotation — record ที่ยังไม่ได้ใช้ kekVersion นี้ */
  listNotOnVersion(kekVersion: string): AsyncIterable<DataKeyRecord>;
  updateWrapped(id: string, wrappedDek: string, kekVersion: string): Promise<void>;
}

/** context ที่ผูกกับ DEK ตอน wrap — กันการเอา DEK ของคนหนึ่งไปใช้แทนอีกคน */
export const dekContext = (id: string) => `dek:${id}`;

/**
 * Envelope encryption: สร้าง/อ่าน/ทำลาย DEK ต่อเจ้าของข้อมูล
 * DEK ที่คืนให้เป็น plaintext — ใช้แล้วทิ้ง อย่าเก็บลง DB หรือ log
 */
export function createKeyring({ kms, store }: { kms: KeyProvider; store: DataKeyStore }) {
  /** สร้าง DEK ใหม่แล้วเก็บแบบ wrap — คืน DEK (plaintext) ไว้ใช้ encrypt ต่อทันที */
  async function create(id: string): Promise<Buffer> {
    const dek = cipher.generateKey();
    const { wrapped, kekVersion } = await kms.wrap(dek, dekContext(id));
    await store.insert({ id, wrappedDek: wrapped.toString('base64'), kekVersion });
    return dek;
  }

  /**
   * คืน DEK (plaintext) หรือ null ถ้าถูกทำลายไปแล้ว
   * ถ้าใช้ KMS จริง: ควร cache DEK ใน memory (TTL สั้น) เพื่อลด latency/ค่าใช้จ่าย
   */
  async function getDek(id: string): Promise<Buffer | null> {
    const record = await store.find(id);
    if (!record) return null;
    return kms.unwrap(Buffer.from(record.wrappedDek, 'base64'), record.kekVersion, dekContext(id));
  }

  /** Crypto-shredding: ลบ DEK ทิ้ง ciphertext ทุกที่ (รวม backup) จะอ่านไม่ได้อีก */
  async function destroy(id: string): Promise<void> {
    await store.delete(id);
  }

  /** KEK rotation: re-wrap DEK ทุกตัวที่ยังใช้ KEK เก่า ด้วย KEK ปัจจุบัน (ข้อมูลไม่ต้อง re-encrypt) */
  async function rewrapAll(): Promise<number> {
    const target = kms.currentVersion();
    let count = 0;

    for await (const record of store.listNotOnVersion(target)) {
      const dek = await kms.unwrap(Buffer.from(record.wrappedDek, 'base64'), record.kekVersion, dekContext(record.id));
      const { wrapped, kekVersion } = await kms.wrap(dek, dekContext(record.id));
      await store.updateWrapped(record.id, wrapped.toString('base64'), kekVersion);
      count += 1;
    }

    return count;
  }

  return { create, getDek, destroy, rewrapAll };
}

export type Keyring = ReturnType<typeof createKeyring>;

/** DataKeyStore ใน memory — ใช้กับ test หรือ dev เท่านั้น (restart แล้วข้อมูลหาย = อ่าน ciphertext ไม่ได้อีก) */
export class MemoryDataKeyStore implements DataKeyStore {
  private readonly records = new Map<string, DataKeyRecord>();

  async insert(record: DataKeyRecord) {
    if (this.records.has(record.id)) throw new Error(`Data key ${record.id} already exists`);
    this.records.set(record.id, { ...record });
  }

  async find(id: string) {
    const record = this.records.get(id);
    return record ? { ...record } : null;
  }

  async delete(id: string) {
    this.records.delete(id);
  }

  async *listNotOnVersion(kekVersion: string) {
    for (const record of [...this.records.values()]) {
      if (record.kekVersion !== kekVersion) yield { ...record };
    }
  }

  async updateWrapped(id: string, wrappedDek: string, kekVersion: string) {
    const record = this.records.get(id);
    if (record) this.records.set(id, { ...record, wrappedDek, kekVersion });
  }
}
