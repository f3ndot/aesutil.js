import crypto from "crypto";

export const ALGORITHM = "aes-256-gcm";
export const IV_BYTE_LEN = 12; // per NIST 800-38D
export const AESUTIL_JS_AES_ENCRYPTION_KEY =
  process.env.AESUTIL_JS_AES_ENCRYPTION_KEY;
export const KEY_BYTE_LEN = 32; // 256-bit means a 32 byte key

const getCipherKey = () => {
  if (!AESUTIL_JS_AES_ENCRYPTION_KEY) {
    throw new Error(
      "AESUTIL_JS_AES_ENCRYPTION_KEY environment variable not set"
    );
  }
  const expectedBase64Length = Buffer.from("a".repeat(KEY_BYTE_LEN)).toString(
    "base64"
  ).length;
  if (
    !new RegExp(`^[a-zA-Z0-9+/=]{${expectedBase64Length}}$`, "g").test(
      AESUTIL_JS_AES_ENCRYPTION_KEY
    )
  ) {
    throw new Error(
      `AESUTIL_JS_AES_ENCRYPTION_KEY must be a Base64-encoded ${KEY_BYTE_LEN}-byte string`
    );
  }
  const keyBytes = Buffer.from(AESUTIL_JS_AES_ENCRYPTION_KEY, "base64");
  if (keyBytes.length !== KEY_BYTE_LEN) {
    throw new Error(
      `AESUTIL_JS_AES_ENCRYPTION_KEY must contain ${KEY_BYTE_LEN} bytes when Base64-decoded`
    );
  }
  return keyBytes;
};

const getRandomIV = () => {
  return crypto.randomBytes(IV_BYTE_LEN);
};

/**
 * Returns the provided encrypted value.
 *
 * @param value - The value to encrypt.
 * @param associatedData - The specific associated data to optionally tie to ciphertext (AEAD)
 * @returns The encrypted value with cipher IV and auth tag.
 */
export const encryptValue = (
  value: string,
  associatedData?: string,
  iv?: Buffer
) => {
  const _iv = iv || getRandomIV();
  if (_iv.byteLength != IV_BYTE_LEN) {
    throw new Error(`IV must be ${IV_BYTE_LEN} bytes long`);
  }
  const key = getCipherKey();
  const cipher = crypto.createCipheriv(ALGORITHM, key, _iv);
  if (associatedData) {
    cipher.setAAD(Buffer.from(associatedData));
  }
  const encrypted =
    cipher.update(value, "utf8", "base64") + cipher.final("base64");
  const authTagString = cipher.getAuthTag().toString("base64");
  return `${_iv.toString("base64")}.${authTagString}.${encrypted}`;
};

/**
 * Returns the provided decrypted value.
 *
 * @param value - The value to decrypt.
 * @param associatedData - The associated data tied to ciphertext (if supplied during encryption)
 * @returns The decrypted value.
 */
export const decryptValue = (value: string, associatedData?: string) => {
  const [ivString, authTagString, ciphertextString] = value.split(".");

  const iv = Buffer.from(ivString, "base64");
  const authTag = Buffer.from(authTagString, "base64");
  const key = getCipherKey();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  if (associatedData) {
    decipher.setAAD(Buffer.from(associatedData));
  }
  return (
    decipher.update(ciphertextString, "base64", "utf8") + decipher.final("utf8")
  );
};
