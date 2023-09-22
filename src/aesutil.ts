import crypto from "crypto";
import type { CiphertextParts } from "./types";

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

export class AesUtil {
  readonly algorithm = "aes-256-gcm";

  readonly key: Buffer;

  constructor();
  constructor(providedKey: string | Buffer);
  constructor(providedKey?: string | Buffer) {
    this.key = getCipherKey(providedKey);
  }

  static getIv(): Buffer {
    return crypto.randomBytes(IV_BYTE_LEN);
  }

  /**
   * Returns the provided encrypted value.
   *
   * @param plaintext - The string to encrypt.
   * @param associatedData - The specific associated data to optionally tie to ciphertext (AEAD)
   * @returns The encrypted value with cipher IV and auth tag.
   */
  encrypt(plaintext: string, associatedData?: string): string {
    const iv = AesUtil.getIv();
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    if (associatedData) {
      cipher.setAAD(Buffer.from(associatedData));
    }
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();
    return this.encodeOutput({ ciphertext, iv, authTag });
  }

  /**
   * Returns the provided decrypted value.
   *
   * Optionally provide a `key` encryption key otherwise `AESUTIL_JS_AES_ENCRYPTION_KEY` env is used
   *
   * @param value - The value to decrypt.
   * @param associatedData - The associated data tied to ciphertext (if supplied during encryption)
   * @param key - The encryption key used as a byte array or a Base64-encoded string
   * @returns The decrypted value.
   */
  decrypt(encrypted: string, associatedData?: string): string {
    const parts = this.decodeInput(encrypted);

    const decipher = crypto.createDecipheriv("aes-256-gcm", this.key, parts.iv);
    decipher.setAuthTag(parts.authTag);
    if (associatedData) {
      decipher.setAAD(Buffer.from(associatedData));
    }
    return (
      decipher.update(parts.ciphertext, undefined, "utf8") +
      decipher.final("utf8")
    );
  }

  private encodeOutput(parts: CiphertextParts): string {
    return `${parts.iv.toString("base64")}.${parts.authTag.toString(
      "base64"
    )}.${parts.ciphertext.toString("base64")}`;
  }

  private decodeInput(encrypted: string): CiphertextParts {
    const [ivString, authTagString, ciphertextString] = encrypted.split(".");
    const iv = Buffer.from(ivString, "base64");
    const authTag = Buffer.from(authTagString, "base64");
    const ciphertext = Buffer.from(ciphertextString, "base64");
    return {
      iv,
      authTag,
      ciphertext,
    };
  }
}

export const decryptValue = (
  value: string,
  associatedData?: string,
  key?: Buffer | string
) => (key ? new AesUtil(key) : new AesUtil()).decrypt(value, associatedData);

export const encryptValue = (
  value: string,
  associatedData?: string,
  key?: Buffer | string
) => (key ? new AesUtil(key) : new AesUtil()).encrypt(value, associatedData);
