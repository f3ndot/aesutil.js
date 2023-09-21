# aesutil.js

An ✨*opinionated*✨ NodeJS convenience library for AES-256-GCM Encryption/Decryption with optional Additional Data (AAD/AEAD) in a portable way.

Meant for ciphertext storage outside the running environment, such as in a database hosted elsewhere or publicly exposed.

## Install

```bash
yarn add @f3ndot/aesutil.js
```

## Configuration

Set the `AESUTIL_JS_AES_ENCRYPTION_KEY` environment variable to a cryptographically random 32 byte (256-bit) key, encoded in Base64. For example, using OpenSSL:

```bash
export AESUTIL_JS_AES_ENCRYPTION_KEY=$(openssl rand -base64 32)
```

Save that in your env whichever way you like, for example a `.env` file if your project is setup for it:

```
AESUTIL_JS_AES_ENCRYPTION_KEY="uQDJyFHpG7qKPZgGhC/74eIWx/ItMof+T00Tho2Cam8="
```

## Usage

Very simple.

Encryption:

```ts
import { encryptValue } from "@f3ndot/aesutil";

const encryptedDataForDb = encryptValue("some sensitive plaintext");
// => 'Am4ubpry3kg3BDDK.qWgj/gOHyV9pv5U/RZ6Rzw==.WOF0+fh4hnRi7IqyUKqU15u/5nyPspvX'

storeToDb(encryptedDataForDb);
```

Decryption:

```ts
import { decryptValue } from "@f3ndot/aesutil";

const encryptedDataFromDb =
  "Am4ubpry3kg3BDDK.qWgj/gOHyV9pv5U/RZ6Rzw==.WOF0+fh4hnRi7IqyUKqU15u/5nyPspvX";
const plaintext = decryptValue(encryptedDataFromDb); // => 'some sensitive plaintext'
```

### Associated Data / AAD / AEAD

Since AES-256-GCM is used, you can optionally supply associated data to tie to the ciphertext. This is particularly useful in a database context where a given ciphertext may belong to only one row. Associated Data would prevent ciphertext reuse.

Encryption:

```ts
import { encryptValue } from "@f3ndot/aesutil";

const encryptedDataForDb = encryptValue("some medical history", "user-id-1");
// => '4G4slwTqQpz3MYUf.vfgpx8urncMXtFCD+xJAKw==.fgyJEpyTr26PBknvHe3VYSeX8xM='

updateUserMedicalFile("user-id-1", encryptedDataForDb);
```

Decryption:

```ts
import { decryptValue } from "@f3ndot/aesutil";

const encryptedDataForUser1FromDb =
  "4G4slwTqQpz3MYUf.vfgpx8urncMXtFCD+xJAKw==.fgyJEpyTr26PBknvHe3VYSeX8xM=";

const user1History = decryptValue(encryptedDataForUser1FromDb, "user-id-1"); // => 'some medical history'

const user2History = decryptValue(encryptedDataForUser1FromDb, "user-id-2"); // => Throws an error
```

## Opinionated Decision Rationale

### Why is resulting output a string with some Base64 and dots?

Since the ciphertext, its IV, and auth tag are all encoded as Base64 strings smushed together, the resulting string is very portable and versatile. It can reasonably be copied around and transported anywhere. This can be useful in situations where binary data/non-ASCII characters would get mangled. Hex encoding could've been chosen and accomplishes the same job, but it takes up more characters.

And while SQL databases have the `BINARY` type, the additional overhead for storing the string as `TEXT` is small and consistency makes developer error less likely. Ditto for storing IV and auth tag alongside. While those could be stored in separate `BINARY` columns, it's just more work.

### Why AES-256-GCM?

- **AES:** A widely accepted standard algorithm that has stood the test of time and is fast
- **256-bit**: Since AES is fast enough, using its largest supported key just makes plain sense
- **Galois/Counter Mode (GCM)**: It's fast, concretely secure (as of 2023), and it adds authenticity/integrity to prevent ciphertext tampering

### Why a 12 byte (96-bit) IV length?

Because [NIST 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) says so.

### Why not a password-based encryption/decryption API?

Side-steps the whole debate on what best Password-Based Key Derivation function to use and keeps things fast (a property we want on symmetrically-encrypted data). Forces the implementer/developer to obtain a cryptographically random 256-bit key and use it directly versus deriving one from a less entropic password.

### Why do you want fast?

🚫 **This isn't for storing passwords!** _Never [encrypt your passwords!](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#hashing-vs-encryption)_ 🚫

Things going slowly is a desireable property for _hashing_ (commonly misnomered as _encrypting_) passwords, where the plaintext no longer needs to be known, and verifying/authenticating should be slowed to stymie brute-force attackers.

Conversely, adding an encryption layer for security at rest or transport in untrusted environments should not bog down your application/system.

### Why bother using Associated Data when storing in DB rows?

Guarantees encrypted data for a particular row cannot be reused in other rows. Consider a table of users with API keys that for business reasons cannot be hashed and thus are symmetrically encrypted. Should a vulnerability occur that would allow an attacker to duplicate the encrypted API key ciphertext to other user rows, an attacker could:

1. Sign up as a User and generate an API key known to them
2. Perform the exploit to copy their API key ciphertext to the other users'
3. Gain unauthorized access to other user's information all without knowing their original API plaintext

### Why not streams?

Because I don't have a use case for large inputs/outputs yet. PR's welcome 😌
