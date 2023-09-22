import crypto from "crypto";
import type { ICiphertextParts, IAesUtilParams } from "./types";

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
  readonly binaryMode: boolean = false;
  readonly plaintextEncoding: BufferEncoding = "utf8";

  constructor();
  constructor(providedKey: string | Buffer);
  constructor(params: IAesUtilParams);
  constructor(arg?: string | Buffer | IAesUtilParams) {
    // check if `arg` is `providedKey` or empty constructor
    if (arg instanceof Buffer || typeof arg === "string" || arg === undefined) {
      this.key = getCipherKey(arg);
      return;
    }

    // `arg` is now `params`
    this.key = getCipherKey(arg.providedKey);
    if (arg.binaryMode) this.binaryMode = arg.binaryMode;
    if (arg.plaintextEncoding) this.plaintextEncoding = arg.plaintextEncoding;
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
      cipher.update(plaintext, this.plaintextEncoding),
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
      decipher.update(parts.ciphertext, undefined, this.plaintextEncoding) +
      decipher.final(this.plaintextEncoding)
    );
  }

  private encodeOutput(parts: ICiphertextParts): string {
    const orderedParts = [parts.iv, parts.authTag, parts.ciphertext];

    return this.binaryMode
      ? Buffer.concat(orderedParts).toString("binary")
      : orderedParts.map((part) => part.toString("base64")).join(".");
  }

  private decodeInput(encrypted: string): ICiphertextParts {
    if (this.binaryMode) {
      const encryptedBytes = Buffer.from(encrypted, "binary");
      // Assumes future versions will never deviate from using 12-byte IV and
      // gold-standard 16-byte auth tag. If so, wasteful fallback attempts will
      // have to be made. Could've added a custom header describing part
      // locations but meh
      return {
        iv: encryptedBytes.subarray(0, IV_BYTE_LEN),
        authTag: encryptedBytes.subarray(IV_BYTE_LEN, IV_BYTE_LEN + 16),
        ciphertext: encryptedBytes.subarray(IV_BYTE_LEN + 16),
      };
    }

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
