import { describe, expect, test } from "@jest/globals";
import aesutil, { encryptValue, decryptValue, AesUtil } from "./index";

describe("Exported API", () => {
  test("default export object", () => {
    expect(aesutil.decryptValue(aesutil.encryptValue("hi"))).toBe("hi");
    const aesUtil = new aesutil.AesUtil();
    expect(aesUtil.decrypt(aesUtil.encrypt("hi"))).toBe("hi");
  });

  test("named enc/dec exports", () => {
    expect(decryptValue(encryptValue("hi"))).toBe("hi");
    const aesUtil = new AesUtil();
    expect(aesUtil.decrypt(aesUtil.encrypt("hi"))).toBe("hi");
  });
});
