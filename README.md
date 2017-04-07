# api documentation for  [ursa (v0.9.4)](https://github.com/quartzjer/ursa)  [![npm package](https://img.shields.io/npm/v/npmdoc-ursa.svg?style=flat-square)](https://www.npmjs.org/package/npmdoc-ursa) [![travis-ci.org build-status](https://api.travis-ci.org/npmdoc/node-npmdoc-ursa.svg)](https://travis-ci.org/npmdoc/node-npmdoc-ursa)
#### RSA public/private key OpenSSL bindings for node and io.js

[![NPM](https://nodei.co/npm/ursa.png?downloads=true)](https://www.npmjs.com/package/ursa)

[![apidoc](https://npmdoc.github.io/node-npmdoc-ursa/build/screenCapture.buildNpmdoc.browser._2Fhome_2Ftravis_2Fbuild_2Fnpmdoc_2Fnode-npmdoc-ursa_2Ftmp_2Fbuild_2Fapidoc.html.png)](https://npmdoc.github.io/node-npmdoc-ursa/build/apidoc.html)

![npmPackageListing](https://npmdoc.github.io/node-npmdoc-ursa/build/screenCapture.npmPackageListing.svg)

![npmPackageDependencyTree](https://npmdoc.github.io/node-npmdoc-ursa/build/screenCapture.npmPackageDependencyTree.svg)



# package.json

```json

{
    "author": {
        "name": "Dan Bornstein",
        "email": "danfuzz@milk.com",
        "url": "http://www.milk.com/"
    },
    "bugs": {
        "url": "https://github.com/quartzjer/ursa/issues"
    },
    "dependencies": {
        "bindings": "^1.2.1",
        "nan": "^2.3.3"
    },
    "description": "RSA public/private key OpenSSL bindings for node and io.js",
    "devDependencies": {},
    "directories": {},
    "dist": {
        "shasum": "0a2abfb7dc4267f733b0f8f2fc7f2c895d40a413",
        "tarball": "https://registry.npmjs.org/ursa/-/ursa-0.9.4.tgz"
    },
    "engines": {
        "node": ">=0.10.0"
    },
    "gitHead": "216ad542b6722c560d24555b4ea0a76051654e6c",
    "gypfile": true,
    "homepage": "https://github.com/quartzjer/ursa",
    "keywords": [
        "crypto",
        "key",
        "openssl",
        "private",
        "public",
        "rsa",
        "sign",
        "signature",
        "verify",
        "verification",
        "hash",
        "digest"
    ],
    "license": "Apache-2.0",
    "main": "lib/ursa.js",
    "maintainers": [
        {
            "name": "danfuzz",
            "email": "danfuzz@milk.com"
        },
        {
            "name": "dpup",
            "email": "dan@pupi.us"
        },
        {
            "name": "nicks",
            "email": "nicholas.j.santos@gmail.com"
        },
        {
            "name": "azulus",
            "email": "jeremy@obvious.com"
        },
        {
            "name": "quartzjer",
            "email": "jeremie@jabber.org"
        }
    ],
    "name": "ursa",
    "optionalDependencies": {},
    "readme": "ERROR: No README data found!",
    "repository": {
        "type": "git",
        "url": "git+https://github.com/quartzjer/ursa.git"
    },
    "scripts": {
        "install": "node-gyp rebuild",
        "test": "node test/test.js"
    },
    "version": "0.9.4"
}
```



# <a name="apidoc.tableOfContents"></a>[table of contents](#apidoc.tableOfContents)

#### [module ursa](#apidoc.module.ursa)
1.  [function <span class="apidocSignatureSpan">ursa.</span>assertKey (obj)](#apidoc.element.ursa.assertKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>assertPrivateKey (obj)](#apidoc.element.ursa.assertPrivateKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>assertPublicKey (obj)](#apidoc.element.ursa.assertPublicKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>coerceKey (orig)](#apidoc.element.ursa.coerceKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>coercePrivateKey (orig)](#apidoc.element.ursa.coercePrivateKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>coercePublicKey (orig)](#apidoc.element.ursa.coercePublicKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createKey (pem, encoding)](#apidoc.element.ursa.createKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createPrivateKey (pem, password, encoding)](#apidoc.element.ursa.createPrivateKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createPrivateKeyFromComponents (modulus, exponent, p, q, dp, dq, inverseQ, d)](#apidoc.element.ursa.createPrivateKeyFromComponents)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createPublicKey (pem, encoding)](#apidoc.element.ursa.createPublicKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createPublicKeyFromComponents (modulus, exponent)](#apidoc.element.ursa.createPublicKeyFromComponents)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createSigner (algorithm)](#apidoc.element.ursa.createSigner)
1.  [function <span class="apidocSignatureSpan">ursa.</span>createVerifier (algorithm)](#apidoc.element.ursa.createVerifier)
1.  [function <span class="apidocSignatureSpan">ursa.</span>equalKeys (key1, key2)](#apidoc.element.ursa.equalKeys)
1.  [function <span class="apidocSignatureSpan">ursa.</span>generatePrivateKey (modulusBits, exponent)](#apidoc.element.ursa.generatePrivateKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>isKey (obj)](#apidoc.element.ursa.isKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>isPrivateKey (obj)](#apidoc.element.ursa.isPrivateKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>isPublicKey (obj)](#apidoc.element.ursa.isPublicKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>matchingPublicKeys (key1, key2)](#apidoc.element.ursa.matchingPublicKeys)
1.  [function <span class="apidocSignatureSpan">ursa.</span>openSshPublicKey (key, encoding)](#apidoc.element.ursa.openSshPublicKey)
1.  [function <span class="apidocSignatureSpan">ursa.</span>sshFingerprint (sshKey, sshEncoding, outEncoding)](#apidoc.element.ursa.sshFingerprint)
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_NO_PADDING
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_PKCS1_OAEP_PADDING
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_PKCS1_PADDING
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_PKCS1_SALT_LEN_HLEN
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_PKCS1_SALT_LEN_MAX
1.  number <span class="apidocSignatureSpan">ursa.</span>RSA_PKCS1_SALT_LEN_RECOVER



# <a name="apidoc.module.ursa"></a>[module ursa](#apidoc.module.ursa)

#### <a name="apidoc.element.ursa.assertKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>assertKey (obj)](#apidoc.element.ursa.assertKey)
- description and source-code
```javascript
function assertKey(obj) {
    assert(isKey(obj));
}
```
- example usage
```shell
...

Create and return a private key from the given components.

### ursa.createPublicKeyFromComponents(modulus, exponent)

Create and return a public key from the given components.

### ursa.assertKey(obj)

Convenient shorthand for 'assert(ursa.isKey(obj))'.

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.
...
```

#### <a name="apidoc.element.ursa.assertPrivateKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>assertPrivateKey (obj)](#apidoc.element.ursa.assertPrivateKey)
- description and source-code
```javascript
function assertPrivateKey(obj) {
    assert(isPrivateKey(obj));
}
```
- example usage
```shell
...

Create and return a public key from the given components.

### ursa.assertKey(obj)

Convenient shorthand for 'assert(ursa.isKey(obj))'.

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)

Convenient shorthand for 'assert(ursa.isPublicKey(obj))'.
...
```

#### <a name="apidoc.element.ursa.assertPublicKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>assertPublicKey (obj)](#apidoc.element.ursa.assertPublicKey)
- description and source-code
```javascript
function assertPublicKey(obj) {
    assert(isPublicKey(obj));
}
```
- example usage
```shell
...

Convenient shorthand for 'assert(ursa.isKey(obj))'.

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)

Convenient shorthand for 'assert(ursa.isPublicKey(obj))'.

### ursa.coerceKey(orig)

Coerce the given key value into a key object (either public or
private), returning it. If given a private key object, this just
...
```

#### <a name="apidoc.element.ursa.coerceKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>coerceKey (orig)](#apidoc.element.ursa.coerceKey)
- description and source-code
```javascript
function coerceKey(orig) {
    if (isKey(orig)) {
        return orig;
    } else if (isStringOrBuffer(orig)) {
        return createKey(orig);
    }

    throw new Error("Not a key: " + orig);
}
```
- example usage
```shell
...

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)

Convenient shorthand for 'assert(ursa.isPublicKey(obj))'.

### ursa.coerceKey(orig)

Coerce the given key value into a key object (either public or
private), returning it. If given a private key object, this just
returns it as-is. If given a string or Buffer, it tries to parse it as
PEM. Anything else will result in an error.

### ursa.coercePrivateKey(orig)
...
```

#### <a name="apidoc.element.ursa.coercePrivateKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>coercePrivateKey (orig)](#apidoc.element.ursa.coercePrivateKey)
- description and source-code
```javascript
function coercePrivateKey(orig) {
    if (isPrivateKey(orig)) {
        return orig;
    } else if (isStringOrBuffer(orig)) {
        return createPrivateKey(orig);
    }

    throw new Error("Not a private key: " + orig);
}
```
- example usage
```shell
...
### ursa.coerceKey(orig)

Coerce the given key value into a key object (either public or
private), returning it. If given a private key object, this just
returns it as-is. If given a string or Buffer, it tries to parse it as
PEM. Anything else will result in an error.

### ursa.coercePrivateKey(orig)

Coerce the given key value into a private key object, returning it. If
given a private key object, this just returns it as-is. If given a
string or Buffer, it tries to parse it as PEM. Anything else will
result in an error.

### ursa.coercePublicKey(orig)
...
```

#### <a name="apidoc.element.ursa.coercePublicKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>coercePublicKey (orig)](#apidoc.element.ursa.coercePublicKey)
- description and source-code
```javascript
function coercePublicKey(orig) {
    if (isPublicKey(orig)) {
        return orig;
    } else if (isStringOrBuffer(orig)) {
        return createPublicKey(orig);
    }

    throw new Error("Not a public key: " + orig);
}
```
- example usage
```shell
...
### ursa.coercePrivateKey(orig)

Coerce the given key value into a private key object, returning it. If
given a private key object, this just returns it as-is. If given a
string or Buffer, it tries to parse it as PEM. Anything else will
result in an error.

### ursa.coercePublicKey(orig)

Coerce the given key value into a public key object, returning it. If
given a private key object, this just returns it as-is. If given a
string or Buffer, it tries to parse it as PEM. Anything else will
result in an error.

### ursa.createPublicKey(pem, encoding)
...
```

#### <a name="apidoc.element.ursa.createKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>createKey (pem, encoding)](#apidoc.element.ursa.createKey)
- description and source-code
```javascript
function createKey(pem, encoding) {
    pem = decodeString(pem, encoding);

    if (isPublicKeyPem(pem)) {
        return createPublicKey(pem);
    } else if (isPrivateKeyPem(pem)) {
        return createPrivateKey(pem);
    } else {
        throw new Error("Not a key.");
    }
}
```
- example usage
```shell
n/a
```

#### <a name="apidoc.element.ursa.createPrivateKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>createPrivateKey (pem, password, encoding)](#apidoc.element.ursa.createPrivateKey)
- description and source-code
```javascript
function createPrivateKey(pem, password, encoding) {
    var rsa = new RsaWrap();
    pem = decodeString(pem, encoding);
    password = decodeString(password, encoding);

    try {
        // Note: The native code is sensitive to the actual number of
        // arguments. It's *not* okay to pass undefined as a password.
        if (password) {
            rsa.setPrivateKeyPem(pem, password);
        } else {
            rsa.setPrivateKeyPem(pem);
        }
    } catch (ex) {
        if (!isPrivateKeyPem(pem)) {
            throw new Error("Not a private key.");
        }
        throw ex;
    }

    return PrivateKey(rsa);
}
```
- example usage
```shell
...
var fs = require('fs')
  , ursa = require('ursa')
  , crt
  , key
  , msg
  ;

key = ursa.createPrivateKey(fs.readFileSync('./certs/server/my-server.key.pem'));
crt = ursa.createPublicKey(fs.readFileSync('./certs/client/my-server.pub'));

console.log('Encrypt with Public');
msg = crt.encrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted', msg, '\n');

console.log('Decrypt with Private');
...
```

#### <a name="apidoc.element.ursa.createPrivateKeyFromComponents"></a>[function <span class="apidocSignatureSpan">ursa.</span>createPrivateKeyFromComponents (modulus, exponent, p, q, dp, dq, inverseQ, d)](#apidoc.element.ursa.createPrivateKeyFromComponents)
- description and source-code
```javascript
function createPrivateKeyFromComponents(modulus, exponent, p, q, dp, dq, inverseQ, d) {
    var rsa = new RsaWrap();
    rsa.createPrivateKeyFromComponents(modulus, exponent, p, q, dp, dq, inverseQ, d);

    return PrivateKey(rsa);
}
```
- example usage
```shell
...
PEM-format file.  If defined, the given password is used to decrypt
the PEM file.

The encoding, if specified, applies to both other arguments.

See "Public Key Methods" below for more details.

### ursa.createPrivateKeyFromComponents(modulus, exponent, p, q, dp, dq, inverseQ, d)

Create and return a private key from the given components.

### ursa.createPublicKeyFromComponents(modulus, exponent)

Create and return a public key from the given components.
...
```

#### <a name="apidoc.element.ursa.createPublicKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>createPublicKey (pem, encoding)](#apidoc.element.ursa.createPublicKey)
- description and source-code
```javascript
function createPublicKey(pem, encoding) {
    var rsa = new RsaWrap();
    pem = decodeString(pem, encoding);

    try {
        rsa.setPublicKeyPem(pem);
    } catch (ex) {
        if (!isPublicKeyPem(pem)) {
            throw new Error("Not a public key.");
        }
        throw ex;
    }

    return PublicKey(rsa);
}
```
- example usage
```shell
...
  , ursa = require('ursa')
  , crt
  , key
  , msg
  ;

key = ursa.createPrivateKey(fs.readFileSync('./certs/server/my-server.key.pem'));
crt = ursa.createPublicKey(fs.readFileSync('./certs/client/my-server.pub'));

console.log('Encrypt with Public');
msg = crt.encrypt("Everything is going to be 200 OK", 'utf8', 'base64');
console.log('encrypted', msg, '\n');

console.log('Decrypt with Private');
msg = key.decrypt(msg, 'base64', 'utf8');
...
```

#### <a name="apidoc.element.ursa.createPublicKeyFromComponents"></a>[function <span class="apidocSignatureSpan">ursa.</span>createPublicKeyFromComponents (modulus, exponent)](#apidoc.element.ursa.createPublicKeyFromComponents)
- description and source-code
```javascript
function createPublicKeyFromComponents(modulus, exponent) {
    var rsa = new RsaWrap();
    rsa.createPublicKeyFromComponents(modulus, exponent);
    return PublicKey(rsa);
}
```
- example usage
```shell
...

See "Public Key Methods" below for more details.

### ursa.createPrivateKeyFromComponents(modulus, exponent, p, q, dp, dq, inverseQ, d)

Create and return a private key from the given components.

### ursa.createPublicKeyFromComponents(modulus, exponent)

Create and return a public key from the given components.

### ursa.assertKey(obj)

Convenient shorthand for 'assert(ursa.isKey(obj))'.
...
```

#### <a name="apidoc.element.ursa.createSigner"></a>[function <span class="apidocSignatureSpan">ursa.</span>createSigner (algorithm)](#apidoc.element.ursa.createSigner)
- description and source-code
```javascript
function createSigner(algorithm) {
    var hash = crypto.createHash(algorithm);
    var self = {};

    function update(buf, bufEncoding) {
        buf = decodeString(buf, bufEncoding);
        hash.update(buf);
        return self;
    }

    function sign(privateKey, outEncoding) {
        var hashBuf = new Buffer(hash.digest(BINARY), BINARY);
        return privateKey.sign(algorithm, hashBuf, undefined, outEncoding);
    }

    self.sign = sign;
    self.update = update;
    return self;
}
```
- example usage
```shell
...
result in an error.

### ursa.createPublicKey(pem, encoding)

Create and return a public key read in from the given PEM-format file.
See "Public Key Methods" below for more details.

### ursa.createSigner(algorithm)

Create and return a signer which can sign a hash generated with the named
algorithm (such as '"sha256"' or '"md5"'). See "Signer Methods" below
for more details.

This function is similar to 'crypto.createSign()', except this function
takes a hash algorithm name (e.g., '"sha256"') and not a crypto+hash name
...
```

#### <a name="apidoc.element.ursa.createVerifier"></a>[function <span class="apidocSignatureSpan">ursa.</span>createVerifier (algorithm)](#apidoc.element.ursa.createVerifier)
- description and source-code
```javascript
function createVerifier(algorithm) {
    var hash = crypto.createHash(algorithm);
    var self = {};

    function update(buf, bufEncoding) {
        buf = decodeString(buf, bufEncoding);
        hash.update(buf);
        return self;
    }

    function verify(publicKey, sig, sigEncoding) {
        var hashBuf = new Buffer(hash.digest(BINARY), BINARY);
        sig = decodeString(sig, sigEncoding);
        return publicKey.verify(algorithm, hashBuf, sig);
    }

    self.update = update;
    self.verify = verify;
    return self;
}
```
- example usage
```shell
...
algorithm (such as '"sha256"' or '"md5"'). See "Signer Methods" below
for more details.

This function is similar to 'crypto.createSign()', except this function
takes a hash algorithm name (e.g., '"sha256"') and not a crypto+hash name
combination (e.g., '"RSA-SHA256"').

### ursa.createVerifier(algorithm)

Create and return a verifier which can verify a hash generated with the
named algorithm (such as '"sha256"' or '"md5"'). See "Verifier Methods" below
for more details.

This function is similar to 'crypto.createVerify()', except this function
takes a hash algorithm name (e.g., '"sha256"') and not a crypto+hash name
...
```

#### <a name="apidoc.element.ursa.equalKeys"></a>[function <span class="apidocSignatureSpan">ursa.</span>equalKeys (key1, key2)](#apidoc.element.ursa.equalKeys)
- description and source-code
```javascript
function equalKeys(key1, key2) {
    // See above for rationale. In this case, there's no ssh form for
    // private keys, so we just use PEM for that.

    if (isPrivateKey(key1) && isPrivateKey(key2)) {
        var pem1 = key1.toPrivatePem(UTF8);
        var pem2 = key2.toPrivatePem(UTF8);
        return pem1 === pem2;
    }

    if (isPublicKey(key1) && isPublicKey(key2)) {
        return matchingPublicKeys(key1, key2);
    }

    return false;
}
```
- example usage
```shell
...
named algorithm (such as '"sha256"' or '"md5"'). See "Verifier Methods" below
for more details.

This function is similar to 'crypto.createVerify()', except this function
takes a hash algorithm name (e.g., '"sha256"') and not a crypto+hash name
combination (e.g., '"RSA-SHA256"').

### ursa.equalKeys(key1, key2)

This returns 'true' if and only if both arguments are key objects of
the same type (public or private) and their contents match.

### ursa.generatePrivateKey(modulusBits, exponent)

Create and return a freshly-generated private key (aka a keypair).
...
```

#### <a name="apidoc.element.ursa.generatePrivateKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>generatePrivateKey (modulusBits, exponent)](#apidoc.element.ursa.generatePrivateKey)
- description and source-code
```javascript
function generatePrivateKey(modulusBits, exponent) {
    if (modulusBits === undefined) {
        modulusBits = 2048;
    }

    if (exponent === undefined) {
        exponent = 65537;
    }

    var rsa = new RsaWrap();
    rsa.generatePrivateKey(modulusBits, exponent);

    return PrivateKey(rsa);
}
```
- example usage
```shell
...
combination (e.g., '"RSA-SHA256"').

### ursa.equalKeys(key1, key2)

This returns 'true' if and only if both arguments are key objects of
the same type (public or private) and their contents match.

### ursa.generatePrivateKey(modulusBits, exponent)

Create and return a freshly-generated private key (aka a keypair).
The first argument indicates the number of bits in the modulus (1024
or more is generally considered secure). The second argument indicates
the exponent value, which must be odd (65537 is the typical value; 3
and 17 are also common).  Both arguments are optional and default to
2048 and 65537 (respectively).
...
```

#### <a name="apidoc.element.ursa.isKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>isKey (obj)](#apidoc.element.ursa.isKey)
- description and source-code
```javascript
function isKey(obj) {
    var obj2;

    try {
        var unseal = obj.unseal;
        if (typeof unseal !== "function") {
            return false;
        }
        obj2 = unseal(theUnsealer);
    } catch (ex) {
        // Ignore; can't assume that other objects obey any particular
        // unsealing protocol.
        // TODO: Log?
        return false;
    }

    return obj2 !== undefined;
}
```
- example usage
```shell
...

### ursa.createPublicKeyFromComponents(modulus, exponent)

Create and return a public key from the given components.

### ursa.assertKey(obj)

Convenient shorthand for 'assert(ursa.isKey(obj))'.

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)
...
```

#### <a name="apidoc.element.ursa.isPrivateKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>isPrivateKey (obj)](#apidoc.element.ursa.isPrivateKey)
- description and source-code
```javascript
function isPrivateKey(obj) {
    return isKey(obj) && (obj.decrypt !== undefined);
}
```
- example usage
```shell
...

### ursa.assertKey(obj)

Convenient shorthand for 'assert(ursa.isKey(obj))'.

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)

Convenient shorthand for 'assert(ursa.isPublicKey(obj))'.

### ursa.coerceKey(orig)
...
```

#### <a name="apidoc.element.ursa.isPublicKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>isPublicKey (obj)](#apidoc.element.ursa.isPublicKey)
- description and source-code
```javascript
function isPublicKey(obj) {
    return isKey(obj) && !isPrivateKey(obj);
}
```
- example usage
```shell
...

### ursa.assertPrivateKey(obj)

Convenient shorthand for 'assert(ursa.isPrivateKey(obj))'.

### ursa.assertPublicKey(obj)

Convenient shorthand for 'assert(ursa.isPublicKey(obj))'.

### ursa.coerceKey(orig)

Coerce the given key value into a key object (either public or
private), returning it. If given a private key object, this just
returns it as-is. If given a string or Buffer, it tries to parse it as
PEM. Anything else will result in an error.
...
```

#### <a name="apidoc.element.ursa.matchingPublicKeys"></a>[function <span class="apidocSignatureSpan">ursa.</span>matchingPublicKeys (key1, key2)](#apidoc.element.ursa.matchingPublicKeys)
- description and source-code
```javascript
function matchingPublicKeys(key1, key2) {
    if (!(isKey(key1) && isKey(key2))) {
        return false;
    }

    // This isn't the most efficient implementation, but it will suffice:
    // We convert both to ssh form, which has very little leeway for
    // variation, and compare bytes.

    var ssh1 = key1.toPublicSsh(UTF8);
    var ssh2 = key2.toPublicSsh(UTF8);

    return ssh1 === ssh2;
}
```
- example usage
```shell
...
Return 'true' if the given object is a public key object that
was created by this module. Return 'false' if not.

Note that, even though all the public key operations work on private
keys, this function only returns true if the given object is a
public key, per se.

### ursa.matchingPublicKeys(key1, key2)

This returns 'true' if and only if both arguments are key objects of
some sort (either can be public or private, and they don't have to
be the same) and their public aspects match each other.

### ursa.openSshPublicKey(key, encoding)
...
```

#### <a name="apidoc.element.ursa.openSshPublicKey"></a>[function <span class="apidocSignatureSpan">ursa.</span>openSshPublicKey (key, encoding)](#apidoc.element.ursa.openSshPublicKey)
- description and source-code
```javascript
function openSshPublicKey(key, encoding) {
    if (!Buffer.isBuffer(key)) {
        key = key.substr(0, 3) === 'ssh' ? key.split(' ')[1] : key;
        key = new Buffer(key, encoding || 'base64');
    }

    function parsePublicKey(key) {
        var parts = [],
            partsLength = 3;

        while(key.length) {
            var dLen = key.readInt32BE(0);
            var data = key.slice(4, dLen+4);
            key = key.slice(4+dLen);
            parts.push(data);
            if (!(--partsLength)) break;
        }

        return {
            modulus :   parts[2],
            exponent:   parts[1],
            type    :   parts[0]
        };
    }

    var pubKey = parsePublicKey(key);
    var rsa = new RsaWrap();

    if (pubKey.type != 'ssh-rsa') {
        throw new TypeError('Only "ssh-rsa" format supported');
    }

    rsa.openPublicSshKey(pubKey.modulus, pubKey.exponent);

    return PublicKey(rsa);
}
```
- example usage
```shell
...

### ursa.matchingPublicKeys(key1, key2)

This returns 'true' if and only if both arguments are key objects of
some sort (either can be public or private, and they don't have to
be the same) and their public aspects match each other.

### ursa.openSshPublicKey(key, encoding)

This returns 'publicKey' from ssh-rsa public key-string. First argument
must be a string like 'ssh-rsa AAAAB3Nz.... user@localhost' or Buffer of pubKey bits.

### ursa.sshFingerprint(sshKey, sshEncoding, outEncoding)

Return the SSH-style public key fingerprint of the given SSH-format
...
```

#### <a name="apidoc.element.ursa.sshFingerprint"></a>[function <span class="apidocSignatureSpan">ursa.</span>sshFingerprint (sshKey, sshEncoding, outEncoding)](#apidoc.element.ursa.sshFingerprint)
- description and source-code
```javascript
function sshFingerprint(sshKey, sshEncoding, outEncoding) {
    var hash = crypto.createHash(MD5);

    hash.update(decodeString(sshKey, sshEncoding));
    var result = new Buffer(hash.digest(BINARY), BINARY);
    return encodeBuffer(result, outEncoding);
}
```
- example usage
```shell
...
be the same) and their public aspects match each other.

### ursa.openSshPublicKey(key, encoding)

This returns 'publicKey' from ssh-rsa public key-string. First argument
must be a string like 'ssh-rsa AAAAB3Nz.... user@localhost' or Buffer of pubKey bits.

### ursa.sshFingerprint(sshKey, sshEncoding, outEncoding)

Return the SSH-style public key fingerprint of the given SSH-format
public key (which was, perhaps, the result of a call to
'toPublicSsh()' on a key object).

This is no more and no less than an MD5 hash of the given SSH-format
public key. This function doesn't actually check to see if the given
...
```



# misc
- this document was created with [utility2](https://github.com/kaizhu256/node-utility2)
