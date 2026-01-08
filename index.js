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
            this.noble = {...secp256k1};
        } else if (name === 'p256') {
            this.noble = {...p256};
        } else if (name === 'p384') {
            this.noble = {...p384};
        } else if (name === 'p521') {
            this.noble = {...p521};
        } else if (name === 'ed25519') {
            this.noble = ed25519;
        } else {
            throw new Error(`Unsupported curve: ${name}`);
        }
        this.curveName = name;
        if (this.noble.Point) {
            // noble ECC curves have a Point property
        } else if (this.noble.ProjectivePoint) {
            this.noble.Point = this.noble.ProjectivePoint;
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

    genKeyPair() {
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

    sign(msgHash, options) {
        const hash = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;
        const sig = this.ec.noble.sign(hash, this.#priv, { lowS: true, prehash: true });
        return {
            r: sig.r,
            s: sig.s,
            toDER: (enc) => {
                if (enc === 'hex') return bytesToHex(sig);
                return sig;
            }
        };
    }

    verify(msgHash, signature) {
        const hash = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;
        const pub = this.#getPublic();
        const sigBytes = signature.toDER ? signature.toDER() : signature;
        return this.ec.noble.verify(sigBytes, hash, pub, { prehash: true });
    }
}

module.exports = {
    version: '9999.0.0-soatok',
    ec: EC,
};
