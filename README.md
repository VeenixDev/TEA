# TEA

TEA stands for "Tiny Encryption Algorithm", and was created from David J. Wheeler and Roger M. Needham in 1994.

You can use this algorithm to encrypt and decrypt any text.

---

## Example

Encode:
```ts
import TEA from './TEA';

const password = 'mySecurePassword';
let plainMessage = 'my message i want to encrypt';

console.log(TEA.encrypt(plainMessage, password));
```

This should output something like `-QûP\u0004¦\bÂ\u001aKÍ!10!àö\u001ciDô¶Ãý÷Olüg»;Ç*üu\u000e`.

Decode:
```ts
import TEA from './TEA'

const password = 'mySecurePassword';
let encryptedMessage = '-QûP\u0004¦\bÂ\u001aKÍ!10!àö\u001ciDô¶Ãý÷Olüg»;Ç*üu\u000e';

console.log(TEA.decrypt(encryptedMessage, password));
```

This should output something like `my message i want to encrypt`.
