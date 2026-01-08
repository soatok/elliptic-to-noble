'use strict';

// Let's import noble-curves:
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const { p256, p384, p521 } = require('@noble/curves/nist.js');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { hexToBytes, bytesToHex } = require('@noble/curves/utils.js');

// Begin elliptic-compatible API
class EC {
    constructor(name) {
        if (name === 'secp256k1') {
            this.noble = secp256k1;
        } else if (name === 'p256') {
            this.noble = p256;
        } else if (name === 'p384') {
            this.noble = p384;
        } else if (name === 'p521') {
            this.noble = p521;
        } else {
            throw new Error(`Unsupported curve: ${name}`);
        }
    }

    keyFromPrivate(priv, enc = 'hex') {
        const bytes = enc === 'hex' ? hexToBytes(priv) : priv;
        return new KeyPair(this, { priv: bytes });
    }

    keyFromPublic(pub, enc = 'hex') {
        const bytes = enc === 'hex' ? hexToBytes(pub) : pub;
        return new KeyPair(this, { pub: bytes });
    }

    genKeyPair(opts) {
        if (opts?.hash || opts?.entropy) {
            throw new Error('HMAC DRBG not supported');
        }

        const { secretKey, publicKey } = this.noble.keygen();
        return new KeyPair(this, {
            priv: secretKey,
            pub: publicKey,
        });
    }
}

class KeyPair {
    #priv;
    #pub;

    constructor(ec, opts) {
        this.ec = ec;
        this.#priv = opts.priv ?? null;
        this.#pub = opts.pub ?? null;
    }

    get priv() {
        throw new Error("direct access to `.priv` not supported; use `.getPrivate('hex')`")
    }

    get pub() {
        throw new Error("direct access to `.pub` not supported; use `.getPublic([compressed, ]'hex')`")
    }

    #getPublic() {
        return this.#pub ??= this.ec.noble.getPublicKey(this.#priv, false);
    }

    getPublic(compressed, enc) {
        if (typeof compressed === 'string') {
            enc = compressed;
            compressed = undefined;
        }

        if (enc !== 'hex') {
            throw new Error('only hex encoding supported');
        }

        const point = this.ec.noble.Point.fromBytes(this.#getPublic());
        return point.toHex(compressed ?? false);
    }

    getPrivate(enc) {
        if (enc !== 'hex') {
            throw new Error('only hex encoding supported');
        }

        return bytesToHex(this.#priv);
    }

    sign(message, options) {
        if (typeof message === 'string') {
            message = hexToBytes(message);
        }

        const sig = this.ec.noble.sign(message, this.#priv, { lowS: true, prehash: false, format: 'der' });
        return new Signature(sig);
    }

    verify(message, signature) {
        if (typeof message === 'string') {
            message = hexToBytes(message);
        }

        const pub = this.#getPublic();
        const sigBytes = signature.toDER ? signature.toDER() : signature;
        return this.ec.noble.verify(sigBytes, message, pub, { prehash: false, format: 'der' });
    }
}

class Signature {
    #der;

    constructor(der) {
        this.#der = der;
    }

    get r() {
        throw new Error('not implemented');
    }

    get s() {
        throw new Error('not implemented');
    }

    toDER(enc) {
        if (enc === 'hex') return bytesToHex(this.#der);
        return new Uint8Array(this.#der);
    }
}

class EdDsa {
    constructor(curve) {
        if (curve !== 'ed25519') {
            throw new Error('only ed25519 supported for EdDSA');
        }
    }

    keyFromSecret(secret) {
        if (typeof secret === 'string') {
            secret = hexToBytes(secret);
        }

        if (secret.length !== 32) {
            throw new Error('only 32-byte secrets supported');
        }

        return new EdKeyPair({secret});
    }

    keyFromPublic(pub) {
        if (typeof pub === 'string') {
            pub = hexToBytes(pub);
        }

        return new EdKeyPair({pub});
    }
}

class EdKeyPair {
    #secret;
    #privBytes = undefined;
    #pubBytes;

    constructor(opts) {
        this.#secret = opts.secret;
        this.#pubBytes = opts.pubBytes;
    }

    secret() {
        return this.#secret;
    }

    getSecret(enc) {
        return enc === 'hex' ? bytesToHex(this.#secret) : this.#secret;
    }

    #getExtendedPublicKey() {
        const { scalar, pointBytes } = ed25519.utils.getExtendedPublicKey(this.#secret);
        this.#privBytes ??= scalar;
        this.#pubBytes ??= pointBytes;
    }

    privBytes() {
        if (this.#privBytes === undefined) {
            this.#getExtendedPublicKey();
        }

        return this.#privBytes;
    }

    pubBytes() {
        if (this.#pubBytes === undefined) {
            this.#getExtendedPublicKey();
        }

        return this.#pubBytes;
    }

    getPublic(enc) {
        const pubBytes = this.pubBytes();
        return enc === 'hex' ? bytesToHex(pubBytes) : pubBytes;
    }

    sign(message) {
        if (typeof message === 'string') {
            message = hexToBytes(message);
        }

        return new EdSignature(ed25519.sign(message, this.#secret));
    }

    verify(message, sig) {
        if (typeof message === 'string') {
            message = hexToBytes(message);
        }

        if (typeof sig === 'string') {
            sig = hexToBytes(sig);
        }

        if (sig instanceof EdSignature) {
            sig = sig.toBytes();
        } else if (!Array.isArray(sig)) {
            throw new TypeError('unsupported type for signature');
        }

        return ed25519.verify(sig, message, this.pubBytes());
    }
}

class EdSignature {
    #bytes;

    constructor(bytes) {
        this.#bytes = bytes;
    }

    toBytes() {
        return new Uint8Array(this.#bytes);
    }

    toHex() {
        return bytesToHex(this.#bytes).toUpperCase();
    }
}

module.exports = {
    version: '9999.0.0-soatok',
    ec: EC,
    eddsa: EdDsa,
};
