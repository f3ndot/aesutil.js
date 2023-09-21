import crypto from "crypto";

export const ALGORITHM = "aes-256-gcm";
export const IV_BYTE_LEN = 12; // per NIST 800-38D
export const AESUTIL_JS_AES_ENCRYPTION_KEY =
  process.env.AESUTIL_JS_AES_ENCRYPTION_KEY;
export const KEY_BYTE_LEN = 32; // 256-bit means a 32 byte key

const base64RegEx = new RegExp(/^[a-zA-Z0-9+/=]+$/);

const getCipherKey = (providedKey?: string | Buffer) => {
  const keyCandidate = providedKey || AESUTIL_JS_AES_ENCRYPTION_KEY;
  let keyBytes: Buffer;

  if (!keyCandidate) {
    throw new Error(
      "Key not provided and AESUTIL_JS_AES_ENCRYPTION_KEY environment variable not set"
    );
  }

  if (typeof keyCandidate === "string") {
    if (!base64RegEx.test(keyCandidate)) {
      throw new Error(`Key must be a Base64-encoded string`);
    }

    keyBytes = Buffer.from(keyCandidate, "base64");
  } else {
    keyBytes = keyCandidate;
  }

  if (keyBytes.length !== KEY_BYTE_LEN) {
    throw new Error(`Key must be ${KEY_BYTE_LEN} bytes when Base64-decoded`);
  }

  return keyBytes;
};

const getIv = (providedIv?: string | Buffer) => {
  if (typeof providedIv === "string") {
    if (!base64RegEx.test(providedIv)) {
      throw new Error(`Provided IV must be Base64-encoded if string`);
    }
    providedIv = Buffer.from(providedIv, "base64");
  }
  if (providedIv && providedIv.byteLength != IV_BYTE_LEN) {
    throw new Error(`Provided IV must be ${IV_BYTE_LEN} bytes long`);
  }
  return providedIv || crypto.randomBytes(IV_BYTE_LEN);
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
  key?: Buffer | string,
  iv?: Buffer | string
) => {
  const _iv = getIv(iv);
  const _key = getCipherKey(key);
  const cipher = crypto.createCipheriv(ALGORITHM, _key, _iv);
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
export const decryptValue = (
  value: string,
  associatedData?: string,
  key?: Buffer | string
) => {
  const [ivString, authTagString, ciphertextString] = value.split(".");

  const iv = Buffer.from(ivString, "base64");
  const authTag = Buffer.from(authTagString, "base64");
  const _key = getCipherKey(key);
  const decipher = crypto.createDecipheriv("aes-256-gcm", _key, iv);
  decipher.setAuthTag(authTag);
  if (associatedData) {
    decipher.setAAD(Buffer.from(associatedData));
  }
  return (
    decipher.update(ciphertextString, "base64", "utf8") + decipher.final("utf8")
  );
};
