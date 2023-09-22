export interface CiphertextParts {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}
