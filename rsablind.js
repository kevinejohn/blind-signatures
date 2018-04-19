const BigInteger = require('jsbn').BigInteger;
const sha3 = require('js-sha3').sha3_256;
const NodeRSA = require('node-rsa');

/**
 * Simple wrapper for window.crypto.getRandomValues
 * @param {Number} size Number of bytes
 * @returns {Uint8Array} Contains random bytes
 * @author Benji Altman
 */
function secureRandom(size) {
	var tmp = new Uint8Array(size);
	window.crypto.getRandomValues(tmp);
	return tmp;
}

function keyGeneration(params) {
	const key = new NodeRSA(params || { b: 2048 });
	return key;
}

function keyProperties(key) {
	return {
		E: new BigInteger(key.keyPair.e.toString()),
		N: key.keyPair.n,
		D: key.keyPair.d,
	};
}

function messageToHash(message) {
	const messageHash = sha3(message);
	return messageHash;
}

function messageToHashInt(message) {
	const messageHash = messageToHash(message);
	const messageBig = new BigInteger(messageHash, 16);
	return messageBig;
}

function blind({ message, key, N, E }) {
	const messageHash = messageToHashInt(message);
	N = key ? key.keyPair.n : new BigInteger(N.toString());
	E = key
		? new BigInteger(key.keyPair.e.toString())
		: new BigInteger(E.toString());

	const bigOne = new BigInteger('1');
	let gcd;
	let r;
	do {
		let tmp = new Uint8Array(10);
		crypto.getr
		r = new BigInteger(secureRandom(10));
		gcd = r.gcd(N);
	} while (
		!gcd.equals(bigOne) ||
		r.compareTo(N) >= 0 ||
		r.compareTo(bigOne) <= 0
	);
	const blinded = messageHash.multiply(r.modPow(E, N)).mod(N);
	return {
		blinded,
		r,
	};
}

function sign({ blinded, key }) {
	const { N, D } = keyProperties(key);
	blinded = new BigInteger(blinded.toString());
	const signed = blinded.modPow(D, N);
	return signed;
}

function unblind({ signed, key, r, N }) {
	r = new BigInteger(r.toString());
	N = key ? key.keyPair.n : new BigInteger(N.toString());
	signed = new BigInteger(signed.toString());
	const unblinded = signed.multiply(r.modInverse(N)).mod(N);
	return unblinded;
}

function verify({ unblinded, key, message, E, N }) {
	unblinded = new BigInteger(unblinded.toString());
	const messageHash = messageToHashInt(message);
	N = key ? key.keyPair.n : new BigInteger(N.toString());
	E = key
		? new BigInteger(key.keyPair.e.toString())
		: new BigInteger(E.toString());

	const originalMsg = unblinded.modPow(E, N);
	const result = messageHash.equals(originalMsg);
	return result;
}

function verify2({ unblinded, key, message }) {
	unblinded = new BigInteger(unblinded.toString());
	const messageHash = messageToHashInt(message);
	const { D, N } = keyProperties(key);
	const msgSig = messageHash.modPow(D, N);
	const result = unblinded.equals(msgSig);
	return result;
}

module.exports = {
	keyGeneration,
	messageToHash,
	blind,
	sign,
	unblind,
	verify,
	verify2,
};
