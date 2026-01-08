import { describe, it, expect } from 'vitest';
import { ec as EC, eddsa as EdDsa } from '../index.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';

const ecdsaCurves = ['secp256k1', 'p256', 'p384', 'p521'];

describe.each(ecdsaCurves)('ECDSA with %s', (curve) => {
    it('should generate a key pair', () => {
        const ec = new EC(curve);
        const keyPair = ec.genKeyPair();
        expect(keyPair.getPrivate('hex')).toBeDefined();
        expect(keyPair.getPublic('hex')).toBeDefined();
    });

    it('should generate a key pair from a private key', () => {
        const ec = new EC(curve);
        const privateKey = ec.genKeyPair().getPrivate('hex');
        const keyPair = ec.keyFromPrivate(privateKey, 'hex');
        expect(keyPair.getPrivate('hex')).toBe(privateKey.toString('hex'));
    });

    it('should sign and verify a message', () => {
        const ec = new EC(curve);
        const keyPair = ec.genKeyPair();
        const msg = new TextEncoder().encode('Hello, world!');
        const msgHash = sha256(msg);
        const signature = keyPair.sign(msgHash);
        expect(keyPair.verify(msgHash, signature.toDER())).toBe(true);
    });

    it('should fail to verify a message with a wrong key', () => {
        const ec = new EC(curve);
        const keyPair = ec.genKeyPair();
        const wrongKeyPair = ec.genKeyPair();
        const msg = new TextEncoder().encode('Hello, world!');
        const msgHash = sha256(msg);
        const signature = keyPair.sign(msgHash);
        expect(wrongKeyPair.verify(msgHash, signature.toDER())).toBe(false);
    });
});

describe('EdDSA with ed25519', () => {
    const secretHex = '0123456789abcdef'.repeat(4);

    it('should generate a key pair from a secret', () => {
        const ed = new EdDsa('ed25519');
        const keyPair = ed.keyFromSecret(secretHex);
        expect(keyPair.getSecret('hex')).toBe(secretHex);
        expect(keyPair.getPublic('hex')).toBe('207a067892821e25d770f1fba0c47c11ff4b813e54162ece9eb839e076231ab6');
    });

    it('should sign and verify a message', () => {
        const ed = new EdDsa('ed25519');
        const keyPair = ed.keyFromSecret(secretHex);
        const msg = new TextEncoder().encode('Hello, world!');
        const signature = keyPair.sign(msg);
        expect(signature.toHex()).toBe('9BEF59F94C3ED82773D8DD953FB757CD804401CC807A0F99347FAE2CF529E3F5D0379F96111D41B8397F2017276A004DDFB883B778E7ADA522B22D534CEE4D0B');
        expect(keyPair.verify(msg, signature)).toBe(true);
    });

    it('should fail to verify a message with a wrong key', () => {
        const ed = new EdDsa('ed25519');
        const keyPair = ed.keyFromSecret(secretHex);
        const wrongKeyPair = ed.keyFromSecret('a0'.repeat(32));
        const msg = new TextEncoder().encode('Hello, world!');
        const signature = keyPair.sign(msg);
        expect(wrongKeyPair.verify(msg, signature)).toBe(false);
    });
});
