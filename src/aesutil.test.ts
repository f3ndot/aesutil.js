import { describe, expect, test } from "@jest/globals";
import { encryptValue, decryptValue } from "./aesutil";

describe("aesutil.js Tests", () => {
  test("decrypting encrypted output returns original input", () => {
    expect(decryptValue(encryptValue("some secret"))).toBe("some secret");
  });

  describe("encryptValue", () => {
    test("encrypts correctly", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue("some secret", undefined, undefined, ivBytes);
      expect(actual).toBe(
        "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
      );
    });

    test("output is formatted correctly", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue("hi", undefined, undefined, ivBytes);
      const [ivString, authTagString, cipherTextString] = actual.split(".");
      expect(Buffer.from(ivString, "base64").toString()).toBe(
        ivBytes.toString()
      );
      expect(Buffer.from(authTagString, "base64")).toHaveLength(16);
      expect(Buffer.from(cipherTextString, "base64")).toHaveLength(2);
    });

    test("two ciphertexts differ with same inputs (diff IVs)", () => {
      expect(encryptValue("some secret")).not.toBe(encryptValue("some secret"));
    });

    test("random IV generated if not provided", () => {
      const firstEncodedIv = encryptValue("some secret").split(".")[0];
      const secondEncodedIv = encryptValue("some secret").split(".")[0];
      expect(firstEncodedIv).not.toBe(secondEncodedIv);
    });

    test("AESUTIL_JS_AES_ENCRYPTION_KEY used if key not provided", () => {
      expect(() =>
        decryptValue(
          encryptValue("some secret"),
          undefined,
          process.env.AESUTIL_JS_AES_ENCRYPTION_KEY
        )
      ).not.toThrowError();
    });

    test("encrypts with a provided key", () => {
      const providedKey = Buffer.from("b".repeat(32));

      expect(() =>
        decryptValue(
          encryptValue("some secret", undefined, providedKey),
          undefined,
          providedKey
        )
      ).not.toThrowError();
    });

    test("encrypts with an encoded provided key", () => {
      const providedKey = Buffer.from("b".repeat(32));
      const providedEncodedKey = providedKey.toString("base64");

      expect(() =>
        decryptValue(
          encryptValue("some secret", undefined, providedEncodedKey),
          undefined,
          providedKey
        )
      ).not.toThrowError();
    });

    test("throws if provided key string is not Base64-encoded", () => {
      const providedKey = "!".repeat(32);

      expect(() =>
        encryptValue("some secret", undefined, providedKey)
      ).toThrowError(Error("Key must be a Base64-encoded string"));
    });

    test("throws if provided key string is invalid length", () => {
      const providedKey = Buffer.from("b".repeat(42));

      expect(() =>
        encryptValue("some secret", undefined, providedKey)
      ).toThrowError(Error("Key must be 32 bytes when Base64-decoded"));
    });

    test("encrypts with an encoded IV", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const encodedIv = ivBytes.toString("base64");

      expect(() =>
        decryptValue(
          encryptValue("some secret", undefined, undefined, encodedIv)
        )
      ).not.toThrowError();
      expect(
        encryptValue("some secret", undefined, undefined, encodedIv).split(
          "."
        )[0]
      ).toBe(encodedIv);
    });

    test("throws if invalid IV length", () => {
      const ivBytes = Buffer.from("a".repeat(24));

      expect(() =>
        encryptValue("some secret", undefined, undefined, ivBytes)
      ).toThrowError(Error("Provided IV must be 12 bytes long"));
    });

    test("throws if IV string not Base64-encoded", () => {
      const iv = "!".repeat(12);

      expect(() =>
        encryptValue("some secret", undefined, undefined, iv)
      ).toThrowError(Error("Provided IV must be Base64-encoded if string"));
    });

    test("encrypts with associated data", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue(
        "some secret",
        "with assoc data",
        undefined,
        ivBytes
      );
      expect(actual).toMatch(
        "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY="
      );
    });
  });

  describe("decryptValue", () => {
    test("decrypts correctly", () => {
      const actual = decryptValue(
        "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
      );
      expect(actual).toBe("some secret");
    });

    test("AESUTIL_JS_AES_ENCRYPTION_KEY used if key not provided", () => {
      expect(() =>
        decryptValue(
          encryptValue(
            "some secret",
            undefined,
            process.env.AESUTIL_JS_AES_ENCRYPTION_KEY
          )
        )
      ).not.toThrowError();
    });

    test("decrypts with a provided key", () => {
      const providedKey = Buffer.from("c".repeat(32));

      const actual = decryptValue(
        "SwzXVdv5Gb3czS77.nYS/fv33widGKqeWC0Ci9g==.OQZQK37REbbo4n8=",
        undefined,
        providedKey
      );
      expect(actual).toBe("some secret");
    });

    test("decrypts with an encoded provided key", () => {
      const providedKey = Buffer.from("c".repeat(32));
      const providedEncodedKey = providedKey.toString("base64");

      const actual = decryptValue(
        "SwzXVdv5Gb3czS77.nYS/fv33widGKqeWC0Ci9g==.OQZQK37REbbo4n8=",
        undefined,
        providedEncodedKey
      );
      expect(actual).toBe("some secret");
    });

    test("throws if provided key string is not Base64-encoded", () => {
      const providedKey = "!".repeat(32);

      expect(() =>
        decryptValue(
          "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY=",
          undefined,
          providedKey
        )
      ).toThrowError(Error("Key must be a Base64-encoded string"));
    });

    test("throws if provided key is invalid length", () => {
      const providedKey = Buffer.from("a".repeat(24));

      expect(() =>
        decryptValue(
          "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY=",
          undefined,
          providedKey
        )
      ).toThrowError(Error("Key must be 32 bytes when Base64-decoded"));
    });

    test("throws if wrong key", () => {
      const encKey = Buffer.from("b".repeat(32));

      expect(() =>
        decryptValue(
          "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY=",
          undefined,
          encKey
        )
      ).toThrowError(Error("Unsupported state or unable to authenticate data"));
    });

    test("decrypts with associated data", () => {
      const actual = decryptValue(
        "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY=",
        "with assoc data"
      );
      expect(actual).toBe("some secret");
    });

    test("throws if wrong associated data", () => {
      expect(() =>
        decryptValue(
          "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY=",
          "differing data"
        )
      ).toThrowError(Error("Unsupported state or unable to authenticate data"));
    });
  });
});
