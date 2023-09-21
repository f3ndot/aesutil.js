import { describe, expect, test } from "@jest/globals";
import aesutil, { encryptValue, decryptValue } from "./index";

describe("Exported API", () => {
  test("default export object", () => {
    expect(aesutil.decryptValue(aesutil.encryptValue("hi"))).toBe("hi");
  });

  test("named enc/dec exports", () => {
    expect(decryptValue(encryptValue("hi"))).toBe("hi");
  });
});
