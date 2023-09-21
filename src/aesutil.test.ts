import { describe, expect, test } from "@jest/globals";
import { encryptValue, decryptValue } from "./aesutil";

describe("aesutil.js Tests", () => {
  test("decrypting encrypted output returns original input", () => {
    expect(decryptValue(encryptValue("some secret"))).toBe("some secret");
  });

  describe("encryptValue", () => {
    test("encrypts correctly", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue("some secret", undefined, ivBytes);
      expect(actual).toBe(
        "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
      );
    });

    test("output is formatted correctly", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue("hi", undefined, ivBytes);
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

    test("encrypts with associated data", () => {
      const ivBytes = Buffer.from("a".repeat(12));

      const actual = encryptValue("some secret", "with assoc data", ivBytes);
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

    xtest("throws if wrong key", () => {
      jest.resetModules();
      const enc_key = Buffer.from("b".repeat(32)).toString("base64");
      process.env = { AESUTIL_JS_AES_ENCRYPTION_KEY: enc_key };

      expect(() =>
        decryptValue(
          "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
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
