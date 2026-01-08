import { describe, it, expect } from 'vitest';
import { ec as EC } from '../index.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha512 } from '@noble/hashes/sha2.js';

const ecdsaCurves = ['secp256k1', 'p256', 'p384', 'p521'];

describe.each(ecdsaCurves)('ECDSA with %s', (curve) => {
    it('should generate a key pair', () => {
        const ec = new EC(curve);
        const keyPair = ec.genKeyPair();
        expect(keyPair.getPrivate()).toBeDefined();
        expect(keyPair.getPublic()).toBeDefined();
    });

    it('should generate a key pair from a private key', () => {
        const ec = new EC(curve);
        const privateKey = ec.genKeyPair().getPrivate();
        const keyPair = ec.keyFromPrivate(privateKey);
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
    it('should generate a key pair', () => {
        const ec = new EC('ed25519');
        const keyPair = ec.genKeyPair();
        expect(keyPair.getPrivate()).toBeDefined();
        expect(keyPair.getPublic()).toBeDefined();
    });

    it('should generate a key pair from a private key', () => {
        const ec = new EC('ed25519');
        const privateKey = ec.genKeyPair().getPrivate();
        const keyPair = ec.keyFromPrivate(privateKey);
        expect(keyPair.getPrivate('hex')).toBe(privateKey.toString('hex'));
    });

    it('should sign and verify a message', () => {
        const ec = new EC('ed25519');
        const keyPair = ec.genKeyPair();
        const msg = new TextEncoder().encode('Hello, world!');
        const signature = keyPair.sign(msg);
        expect(keyPair.verify(msg, signature)).toBe(true);
    });

    it('should fail to verify a message with a wrong key', () => {
        const ec = new EC('ed25519');
        const keyPair = ec.genKeyPair();
        const wrongKeyPair = ec.genKeyPair();
        const msg = new TextEncoder().encode('Hello, world!');
        const signature = keyPair.sign(msg);
        expect(wrongKeyPair.verify(msg, signature)).toBe(false);
    });
});
