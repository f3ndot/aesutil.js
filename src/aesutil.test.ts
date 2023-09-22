import { describe, expect, test } from "@jest/globals";
import { AesUtil, encryptValue, decryptValue } from "./aesutil";

describe("encryptValue", () => {
  const aesUtil = new AesUtil();

  beforeAll(() => {
    const ivBytes = Buffer.from("a".repeat(12));
    const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);
  });

  afterAll(() => jest.restoreAllMocks());

  test("calls new AesUtil().encrypt(input) when no key", () => {
    expect(encryptValue("foo")).toBe(new AesUtil().encrypt("foo"));
  });

  test("calls new AesUtil().encrypt(input, associatedData) when assoc data", () => {
    expect(encryptValue("foo", "bar")).toBe(
      new AesUtil().encrypt("foo", "bar")
    );
  });

  test("calls new AesUtil(key).encrypt when provided key", () => {
    const providedKey = Buffer.from("z".repeat(32));

    expect(encryptValue("foo", undefined, providedKey)).toBe(
      new AesUtil(providedKey).encrypt("foo")
    );
  });
});

describe("decryptValue", () => {
  const aesUtil = new AesUtil();

  beforeAll(() => {
    const ivBytes = Buffer.from("a".repeat(12));
    const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);
  });

  afterAll(() => jest.restoreAllMocks());

  test("calls new AesUtil().decrypt(input) when no key", () => {
    const output = new AesUtil().encrypt("foo");

    expect(decryptValue(output)).toBe("foo");
  });

  test("calls new AesUtil().decrypt(input, associatedData) when assoc data", () => {
    const output = new AesUtil().encrypt("foo", "bar");

    expect(decryptValue(output, "bar")).toBe("foo");
  });

  test("calls new AesUtil(key).encrypt when provided key", () => {
    const providedKey = Buffer.from("z".repeat(32));
    const output = new AesUtil(providedKey).encrypt("foo");

    expect(decryptValue(output, undefined, providedKey)).toBe("foo");
  });
});

describe("AesUtil", () => {
  const aesUtil = new AesUtil();

  afterEach(() => jest.restoreAllMocks());

  test("decrypting encrypted output returns original input", () => {
    expect(aesUtil.decrypt(aesUtil.encrypt("some secret"))).toBe("some secret");
  });

  describe("getIv", () => {
    test("random IV generated", () =>
      expect(AesUtil.getIv()).not.toBe(AesUtil.getIv()));
  });

  describe("constructor", () => {
    test("AESUTIL_JS_AES_ENCRYPTION_KEY used if key not provided", () => {
      const aesUtil = new AesUtil();
      if (!process.env.AESUTIL_JS_AES_ENCRYPTION_KEY) throw Error();

      const envKey = Buffer.from(
        process.env.AESUTIL_JS_AES_ENCRYPTION_KEY,
        "base64"
      );

      expect(aesUtil.key).toStrictEqual(envKey);
    });

    test("uses provided key", () => {
      const providedKey = Buffer.from("b".repeat(32));

      const aesUtil = new AesUtil(providedKey);
      expect(aesUtil.key).toBe(providedKey);
    });

    test("decodes an encoded provided key", () => {
      const providedKey = Buffer.from("b".repeat(32));
      const providedEncodedKey = providedKey.toString("base64");

      const aesUtil = new AesUtil(providedEncodedKey);
      expect(aesUtil.key).toStrictEqual(providedKey);
    });

    test("throws if provided key string is not Base64-encoded", () => {
      const providedKey = "!".repeat(32);

      expect(() => new AesUtil(providedKey)).toThrowError(
        Error("Key must be a Base64-encoded string")
      );
    });

    test("throws if provided key string is invalid length", () => {
      const providedKey = Buffer.from("b".repeat(42));
      expect(() => new AesUtil(providedKey)).toThrowError(
        Error("Key must be 32 bytes when Base64-decoded")
      );
    });

    test("accepts IAesUtility params instead", () => {
      const providedKey = Buffer.from("b".repeat(32));

      const aesUtil = new AesUtil({
        binaryMode: true,
        providedKey,
        plaintextEncoding: "ascii",
      });
      expect(aesUtil.key).toBe(providedKey);
      expect(aesUtil.binaryMode).toBe(true);
      expect(aesUtil.plaintextEncoding).toBe("ascii");
    });
  });

  describe("encrypt", () => {
    test("encrypts correctly using key", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const actual = aesUtil.encrypt("some secret");
      expect(actual).toBe(
        "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
      );
    });

    test("encrypts with different plaintext encoding", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const aesUtil = new AesUtil({ plaintextEncoding: "hex" });
      const actual = aesUtil.encrypt("414141");
      expect(actual).toBe("YWFhYWFhYWFhYWFh.1b42zgCE1hBUVAQ2y1c4fg==.f7y/");
    });

    test("output is formatted correctly", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const actual = aesUtil.encrypt("hi");
      const [ivString, authTagString, cipherTextString] = actual.split(".");
      expect(Buffer.from(ivString, "base64").toString()).toBe(
        ivBytes.toString()
      );
      expect(Buffer.from(authTagString, "base64")).toHaveLength(16);
      expect(Buffer.from(cipherTextString, "base64")).toHaveLength(2);
    });

    test("two ciphertexts differ with same inputs", () => {
      expect(aesUtil.encrypt("some secret").split(".")[2]).not.toBe(
        aesUtil.encrypt("some secret").split(".")[2]
      );
    });

    test("encrypts with associated data", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const actual = aesUtil.encrypt("some secret", "with assoc data");
      expect(actual).toMatch(
        "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY="
      );
    });

    test("encrypts in binary mode", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const aesUtil = new AesUtil({ binaryMode: true });
      const actual = aesUtil.encrypt("abc");
      expect(actual).toMatch(
        Buffer.concat([
          Buffer.from("aaaaaaaaaaaa"),
          Buffer.from("413b0cee54c41340d3835ab09a834066", "hex"),
          Buffer.from("5f9f9d", "hex"),
        ]).toString("binary")
      );
    });
  });

  describe("aesUtil.decrypt", () => {
    test("decrypts correctly", () => {
      const actual = aesUtil.decrypt(
        "YWFhYWFhYWFhYWFh.8ZNQ2vxyxHKb5cGsryyFcQ==.TZKT/9YESrE8aQY="
      );
      expect(actual).toBe("some secret");
    });

    test("decrypts with different plaintext encoding", () => {
      const aesUtil = new AesUtil({ plaintextEncoding: "hex" });
      const actual = aesUtil.decrypt(
        "YWFhYWFhYWFhYWFh.1b42zgCE1hBUVAQ2y1c4fg==.f7y/"
      );
      expect(actual).toBe("414141");
    });

    test("throws if wrong key", () => {
      const otherEncKey = Buffer.from("b".repeat(32));
      const otherAesUtil = new AesUtil(otherEncKey);

      expect(() =>
        otherAesUtil.decrypt(aesUtil.encrypt("some secret"))
      ).toThrowError(Error("Unsupported state or unable to authenticate data"));
    });

    test("decrypts with associated data", () => {
      const actual = aesUtil.decrypt(
        "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY=",
        "with assoc data"
      );
      expect(actual).toBe("some secret");
    });

    test("throws if wrong associated data", () => {
      expect(() =>
        aesUtil.decrypt(
          "YWFhYWFhYWFhYWFh.52PQH34HGt7cOGDmMxiTDA==.TZKT/9YESrE8aQY=",
          "differing data"
        )
      ).toThrowError(Error("Unsupported state or unable to authenticate data"));
    });

    test("decrypts in binary mode", () => {
      const ivBytes = Buffer.from("a".repeat(12));
      const spy = jest.spyOn(AesUtil, "getIv").mockReturnValue(ivBytes);

      const aesUtil = new AesUtil({ binaryMode: true });
      const actual = aesUtil.decrypt(
        Buffer.concat([
          Buffer.from("aaaaaaaaaaaa"),
          Buffer.from("413b0cee54c41340d3835ab09a834066", "hex"),
          Buffer.from("5f9f9d", "hex"),
        ]).toString("binary")
      );
      expect(actual).toMatch("abc");
    });
  });
});
