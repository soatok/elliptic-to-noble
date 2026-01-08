'use strict';

// Let's import noble-curves:
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const { p256, p384, p521 } = require('@noble/curves/nist.js');

// x25519 will be undefined if @noble/curves is overridden to a version before 1.3.
const { ed25519, x25519 } = require('@noble/curves/ed25519.js');

const utils =require('@noble/curves/utils.js');

const hexToBytes = (hex) => {
    if (typeof hex !== 'string') throw new Error('hex string expected');
    if (hex.length % 2) throw new Error('hex string must have even length');
    const len = hex.length / 2;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
};

const bytesToHex = (bytes) => {
    return Array.from(bytes || [])
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
};

// Begin elliptic-compatible API
class EC {
    constructor(name) {
        if (name === 'secp256k1') {
            this.noble = {...secp256k1};
            this.privateKeyLength = 32;
        } else if (name === 'p256') {
            this.noble = {...p256};
            this.privateKeyLength = 32;
        } else if (name === 'p384') {
            this.noble = {...p384};
            this.privateKeyLength = 48;
        } else if (name === 'p521') {
            this.noble = {...p521};
            this.privateKeyLength = 66;
        } else if (name === 'ed25519') {
            this.noble = ed25519;
        } else if (name === 'curve25519') {
            if (!x25519) throw new Error('curve25519 requires @noble/curves ≥1.3');
            this.noble = { x25519 };
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
        let priv;
        while (!priv) {
            priv = utils.randomBytes(this.privateKeyLength || 32);
            try {
                this.keyFromPrivate(priv, 'bytes').getPublic();
            } catch (e) {
                priv = null;
            }
        }
        return this.keyFromPrivate(priv, 'bytes');
    }
}

class KeyPair {
    constructor(ec, opts) {
        this.ec = ec;
        if (opts.priv != null) {
            this.priv = opts.priv;
        }
        if (opts.pub != null) {
            this.pub = opts.pub;
        }
    }

    getPublic(compressed = true, enc = 'hex') {
        if (!this.pub) {
            this.pub = this.ec.noble.getPublicKey(this.priv, false);
        }
        let pubBytes = this.pub;
        const point = this.ec.noble.Point.fromBytes(pubBytes);

        if (enc === 'hex') {
            return point.toHex(compressed);
        }
        return point.toBytes(compressed);
    }

    getPrivate(enc = 'hex') {
        if (!this.priv) throw new Error('no private key');
        if (enc === 'hex') {
            return bytesToHex(this.priv);
        }
        return this.priv;
    }

    sign(msgHash, options) {
        const hash = typeof msgHash === 'string' ? hexToBytes(msgHash) : msgHash;
        const sig = this.ec.noble.sign(hash, this.priv, { lowS: true, prehash: true });
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
        const pub = this.getPublic(false, 'bytes');
        const sigBytes = signature.toDER ? signature.toDER() : signature;
        return this.ec.noble.verify(sigBytes, hash, pub, { prehash: true });
    }
}

module.exports = {
    version: '9999.0.0-soatok',
    ec: EC,
};
