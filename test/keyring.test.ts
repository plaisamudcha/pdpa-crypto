import { describe, expect, test } from 'bun:test';
import { cipher, createKeyring, dekContext, LocalKeyProvider, MemoryDataKeyStore } from '../src/index.js';

const kek1 = cipher.generateKey().toString('base64');
const kek2 = cipher.generateKey().toString('base64');

describe('LocalKeyProvider', () => {
  test('wrap → unwrap ได้ DEK เดิม และ context ไม่ตรง → throw', async () => {
    const kms = new LocalKeyProvider({ v1: kek1 }, 'v1');
    const dek = cipher.generateKey();
    const { wrapped, kekVersion } = await kms.wrap(dek, dekContext('u1'));
    expect(kekVersion).toBe('v1');
    expect((await kms.unwrap(wrapped, 'v1', dekContext('u1'))).equals(dek)).toBe(true);
    await expect(kms.unwrap(wrapped, 'v1', dekContext('u2'))).rejects.toThrow();
  });

  test('KEK ปัจจุบันไม่มีในรายการ หรือ unwrap ด้วยเวอร์ชันที่ไม่มี → throw', async () => {
    expect(() => new LocalKeyProvider({ v1: kek1 }, 'v2')).toThrow('KEK v2 not configured');
    const kms = new LocalKeyProvider({ v1: kek1 }, 'v1');
    await expect(kms.unwrap(Buffer.alloc(40), 'v9', 'x')).rejects.toThrow('KEK v9 not available');
  });
});

describe('keyring', () => {
  test('create → getDek ได้ DEK เดิม, store เก็บเฉพาะแบบ wrap', async () => {
    const store = new MemoryDataKeyStore();
    const keyring = createKeyring({ kms: new LocalKeyProvider({ v1: kek1 }, 'v1'), store });
    const dek = await keyring.create('u1');
    expect((await keyring.getDek('u1'))!.equals(dek)).toBe(true);

    const record = (await store.find('u1'))!;
    expect(record.kekVersion).toBe('v1');
    expect(Buffer.from(record.wrappedDek, 'base64').includes(dek)).toBe(false);
  });

  test('สร้าง DEK ซ้ำ id เดิม → throw', async () => {
    const keyring = createKeyring({ kms: new LocalKeyProvider({ v1: kek1 }, 'v1'), store: new MemoryDataKeyStore() });
    await keyring.create('u1');
    await expect(keyring.create('u1')).rejects.toThrow();
  });

  test('crypto-shredding: destroy แล้ว getDek = null และสร้าง DEK ใหม่ให้ id เดิมก็ถอดรหัสข้อมูลเก่าไม่ได้', async () => {
    const keyring = createKeyring({ kms: new LocalKeyProvider({ v1: kek1 }, 'v1'), store: new MemoryDataKeyStore() });
    const dek = await keyring.create('u1');
    const ct = cipher.encrypt(dek, 'secret', 'u1:email');
    await keyring.destroy('u1');
    expect(await keyring.getDek('u1')).toBeNull();

    const newDek = await keyring.create('u1');
    expect(() => cipher.decrypt(newDek, ct, 'u1:email')).toThrow();
  });

  test('KEK rotation: rewrapAll ย้าย DEK ไป KEK ใหม่ ข้อมูลเดิมยังถอดรหัสได้ และถอด KEK เก่าออกได้', async () => {
    const store = new MemoryDataKeyStore();
    const before = createKeyring({ kms: new LocalKeyProvider({ v1: kek1 }, 'v1'), store });
    const dek = await before.create('u1');
    await before.create('u2');
    const ct = cipher.encrypt(dek, 'secret', 'u1:email');

    const during = createKeyring({ kms: new LocalKeyProvider({ v1: kek1, v2: kek2 }, 'v2'), store });
    expect(await during.rewrapAll()).toBe(2);
    expect(await during.rewrapAll()).toBe(0);
    expect((await store.find('u1'))!.kekVersion).toBe('v2');

    const after = createKeyring({ kms: new LocalKeyProvider({ v2: kek2 }, 'v2'), store });
    expect(cipher.decrypt((await after.getDek('u1'))!, ct, 'u1:email')).toBe('secret');
  });
});
