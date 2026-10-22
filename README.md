# @pdpa/crypto

Library เข้ารหัสข้อมูลส่วนบุคคลราย field สำหรับระบบที่ต้องทำตาม PDPA — แยกออกมาจาก `pdpa-poc-api` ให้โปรเจกต์อื่นใช้ซ้ำได้

- **AES-256-GCM** + AAD ผูก ciphertext กับเจ้าของ/field (สลับ ciphertext ข้าม user หรือ field แล้วถอดไม่ได้)
- **Envelope encryption** — 1 เจ้าของข้อมูล = 1 DEK, DEK ถูก wrap ด้วย KEK (เปลี่ยน KEK ได้โดยไม่ต้อง re-encrypt ข้อมูล)
- **Crypto-shredding** — ลบ DEK = ข้อมูลทุกที่รวม backup อ่านไม่ได้อีก
- **Blind index** — HMAC สำหรับค้นหา/unique index บน field ที่ถูก encrypt (ตรงตัว และ prefix)

ไม่ผูกกับ framework หรือ DB — การเก็บ DEK ทำผ่าน interface `DataKeyStore` ที่แต่ละโปรเจกต์ implement เอง
ไม่มี dependency นอกจาก `node:crypto` ใช้ได้ทั้ง Bun และ Node ≥ 20

---

## ติดตั้ง

ติดตั้งผ่าน git โดยปักเวอร์ชันด้วย tag (Bun อ่าน `src/` ตรงๆ ไม่ต้อง build)

```jsonc
// package.json ของโปรเจกต์ที่ใช้
"dependencies": {
  "@pdpa/crypto": "github:plaisamudcha/pdpa-crypto#v0.1.0"
}
```

ระหว่างยังไม่มี remote ใช้ path ในเครื่องแทน: `"@pdpa/crypto": "file:../pdpa-crypto"`

ถ้าใช้ TypeScript ให้เพิ่มใน `tsconfig.json` ของโปรเจกต์ (ให้ TS อ่าน type จาก `src/` เหมือน Bun):

```json
{ "compilerOptions": { "moduleResolution": "bundler", "customConditions": ["bun"] } }
```

Node (ไม่ใช่ Bun) ต้องใช้ `dist/` — ต้อง `bun run build` ก่อน ซึ่งการติดตั้งผ่าน git ไม่ได้ build ให้ ถ้ามีโปรเจกต์ Node มาใช้ ควรเปลี่ยนไป publish ขึ้น registry

---

## เริ่มใช้งาน

```ts
import { cipher, createBlindIndex, createKeyring, LocalKeyProvider, type DataKeyStore } from '@pdpa/crypto';

// 1. KEK — dev ใช้ LocalKeyProvider (อ่านจาก env), production ให้ implement KeyProvider กับ KMS
const kms = new LocalKeyProvider({ v1: process.env.KEK_V1! }, 'v1');

// 2. ที่เก็บ DEK — implement กับ DB ของโปรเจกต์ (ดูตัวอย่าง MongoDB ด้านล่าง)
const store: DataKeyStore = myDataKeyStore;
const keyring = createKeyring({ kms, store });

// 3. Blind index — key แยกจาก KEK, label กำหนดเองตามโปรเจกต์
const blindIndex = createBlindIndex<'email' | 'name-prefix'>({ key: cipher.decodeKey(process.env.BLIND_INDEX_KEY!, 'BLIND_INDEX_KEY') });
```

### สร้างข้อมูล

```ts
const dek = await keyring.create(userId); // DEK plaintext — ใช้แล้วทิ้ง อย่าเก็บ/log
const doc = {
  _id: userId,
  pii: { email: cipher.encrypt(dek, email, `${userId}:email`) }, // AAD = "<เจ้าของ>:<field>"
  searchIdx: {
    email: blindIndex.index('email', blindIndex.normalize.email(email)),
    namePrefix: blindIndex.prefixes(blindIndex.normalize.text(name)).map((p) => blindIndex.index('name-prefix', p)),
  },
};
```

### อ่าน / ค้นหา / ลบ

```ts
const dek = await keyring.getDek(userId); // null = ถูกลบไปแล้ว
const email = cipher.decrypt(dek!, doc.pii.email, `${userId}:email`);

// ค้นหาด้วยค่าตรงตัว หรือ prefix — คำนวณ HMAC ของคำค้นแล้ว query กับ searchIdx
db.users.find({ 'searchIdx.email': blindIndex.index('email', blindIndex.normalize.email(input)) });
db.users.find({ 'searchIdx.namePrefix': blindIndex.index('name-prefix', blindIndex.prefixQuery(blindIndex.normalize.text(input))) });

await keyring.destroy(userId); // crypto-shredding
```

### เปลี่ยน KEK (key rotation)

1. เพิ่ม KEK ใหม่และตั้งเป็นเวอร์ชันปัจจุบัน โดยเก็บเวอร์ชันเก่าไว้: `new LocalKeyProvider({ v1, v2 }, 'v2')`
2. `await keyring.rewrapAll()` — re-wrap DEK ทุกตัวที่ยังใช้ v1 (ข้อมูลไม่ต้อง re-encrypt) คืนจำนวนที่ทำ
3. เมื่อคืน 0 แล้ว จึงถอด v1 ออก

---

## API

| export | ใช้ทำอะไร |
|---|---|
| `cipher.encrypt(key, plaintext, aad)` / `decrypt` | string ↔ `"v1.<base64(iv\|tag\|ciphertext)>"` — throw ถ้า key/aad ผิดหรือถูกแก้ |
| `cipher.encryptBytes` / `decryptBytes` | แบบ Buffer (ใช้ wrap DEK) |
| `cipher.decodeKey(b64, name)` / `generateKey()` | อ่าน key 32 bytes จาก base64 / สุ่ม key ใหม่ |
| `createBlindIndex<L>({ key, prefixMin = 3, prefixMax = 5 })` | `index(label, value)`, `prefixes(value)`, `prefixQuery(value)`, `normalize`, `length` |
| `KeyProvider` / `LocalKeyProvider` | interface สำหรับ KMS / ตัวที่อ่าน KEK จาก env |
| `createKeyring({ kms, store })` | `create(id)`, `getDek(id)`, `destroy(id)`, `rewrapAll()` |
| `DataKeyStore` / `MemoryDataKeyStore` | interface ที่เก็บ DEK / ตัวใน memory สำหรับ test |
| `dekContext(id)` | context ตอน wrap DEK (`"dek:<id>"`) |

### Implement `DataKeyStore` (ตัวอย่าง Mongoose)

```ts
const store: DataKeyStore = {
  insert: async ({ id, wrappedDek, kekVersion }) => void (await DataKey.create({ _id: id, wrappedDek, kekVersion })),
  find: async (id) => {
    const doc = await DataKey.findById(id).lean();
    return doc ? { id: doc._id, wrappedDek: doc.wrappedDek, kekVersion: doc.kekVersion } : null;
  },
  delete: async (id) => void (await DataKey.deleteOne({ _id: id })),
  async *listNotOnVersion(kekVersion) {
    for await (const doc of DataKey.find({ kekVersion: { $ne: kekVersion } }).lean().cursor()) {
      yield { id: doc._id, wrappedDek: doc.wrappedDek, kekVersion: doc.kekVersion };
    }
  },
  updateWrapped: async (id, wrappedDek, kekVersion) => void (await DataKey.updateOne({ _id: id }, { $set: { wrappedDek, kekVersion } })),
};
```

`insert` ต้อง throw ถ้า id ซ้ำ (เช่น unique index) — กันการเขียนทับ DEK เดิมซึ่งทำให้ข้อมูลเก่าอ่านไม่ได้
ตัวที่ใช้จริงอยู่ที่ `pdpa-poc-api/src/repositories/dataKey/store.ts`

---

## ข้อควรระวัง

- **AAD ต้องคงที่ตลอดอายุข้อมูล** — เปลี่ยนรูปแบบ AAD (เช่น เปลี่ยนชื่อ field) = ต้อง re-encrypt ข้อมูลเดิม
- **Blind index key / label / normalize เปลี่ยนไม่ได้** โดยไม่สร้าง index ใหม่ทั้งหมด
- ไม่ทำ blind index กับข้อมูลอ่อนไหว (มาตรา 26) — ข้อมูลกลุ่มนี้ไม่ควรค้นหาได้
- prefix สั้น + ค่าที่เป็นไปได้น้อย (เช่น เลข 4 ตัวท้าย) เดาได้จากความถี่ — ใช้เท่าที่จำเป็น
- KEK หาย = ข้อมูลหายทั้งหมด → backup KEK แยกจากข้อมูล; `data_keys` ควรอยู่คนละ DB และมี backup retention สั้นกว่าข้อมูลหลัก (ไม่งั้น restore แล้ว DEK ที่ shred ไปจะกลับมา)
- `LocalKeyProvider` ปลอดภัยเท่ากับ server — production ควรใช้ KMS และ cache DEK ระยะสั้น

---

## พัฒนา

```bash
bun test          # unit test
bun run check     # typecheck
bun run build     # สร้าง dist/ (ESM + .d.ts) สำหรับ Node
```

Bun ใช้ `src/` ตรงๆ ผ่าน export condition `bun`; Node ใช้ `dist/`

### ออกเวอร์ชันใหม่

1. แก้ `version` ใน `package.json` ตาม semver — เปลี่ยนรูปแบบ ciphertext / AAD / blind index = major
2. `bun test && bun run check` แล้ว commit
3. `git tag v<version> && git push --tags`
4. โปรเจกต์ที่ใช้ bump tag ใน dependency แล้ว `bun install`
