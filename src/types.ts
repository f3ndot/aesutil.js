export interface ICiphertextParts {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export interface IAesUtilParams {
  providedKey?: string | Buffer;
  plaintextEncoding?: BufferEncoding;
  binaryMode?: boolean;
}
