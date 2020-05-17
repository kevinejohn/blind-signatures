const secureRandom = require('secure-random');
const BigInteger = require('jsbn').BigInteger;
const sha256 = require('js-sha256');
const NodeRSA = require('node-rsa');

function keyGeneration(params) {
  const key = new NodeRSA(params || { b: 2048 });
  return key;
}

function keyProperties(key) {
  const bigE = new BigInteger(key.keyPair.e.toString());
  const bigN = key.keyPair.n;
  const bigD = key.keyPair.d;
  const bigP = key.keyPair.p;
  const bigQ = key.keyPair.q;

  return {
    bigE,
    bigN,
    bigD,
    bigP,
    bigQ,
  };
}

function messageToHash(message) {
  const messageHash = sha256(message);
  return messageHash;
}

function messageToHashInt(message) {
  const messageHash = messageToHash(message);
  const messageBig = new BigInteger(messageHash, 16);
  return messageBig;
}

function blind({ message, key, N, E }) {
  const messageHash = messageToHashInt(message);
  const bigN = key ? key.keyPair.n : new BigInteger(N.toString());
  const bigE = key
    ? new BigInteger(key.keyPair.e.toString())
    : new BigInteger(E.toString());

  const bigOne = new BigInteger('1');
  let gcd;
  let r;
  do {
    r = new BigInteger(secureRandom(64));
    gcd = r.gcd(bigN);
    // console.log('Try');
  } while (
    !gcd.equals(bigOne) ||
    r.compareTo(bigN) >= 0 ||
    r.compareTo(bigOne) <= 0
  );

  // now that we got an r that satisfies the restrictions described we can proceed with calculation of mu
  const mu = r.modPow(bigE, bigN).multiply(messageHash).mod(bigN); // Alice computes mu = H(msg) * r^e mod N
  return {
    blinded: mu,
    r,
  };
}

function sign({ blinded, key }) {
  const { bigN, bigP, bigQ, bigD } = keyProperties(key);
  const mu = new BigInteger(blinded.toString());

  // We split the mu^d modN in two , one mode p , one mode q
  const PinverseModQ = bigP.modInverse(bigQ); // calculate p inverse modulo q
  const QinverseModP = bigQ.modInverse(bigP); // calculate q inverse modulo p
  // We split the message mu in to messages m1, m2 one mod p, one mod q
  const m1 = mu.modPow(bigD, bigN).mod(bigP); // calculate m1=(mu^d modN)modP
  const m2 = mu.modPow(bigD, bigN).mod(bigQ); // calculate m2=(mu^d modN)modQ
  // We combine the calculated m1 and m2 in order to calculate muprime
  // We calculate muprime: (m1*Q*QinverseModP + m2*P*PinverseModQ) mod N where N =P*Q
  const muprime = m1
    .multiply(bigQ)
    .multiply(QinverseModP)
    .add(m2.multiply(bigP).multiply(PinverseModQ))
    .mod(bigN);

  return muprime;
}

function unblind({ signed, key, r, N }) {
  const bigN = key ? key.keyPair.n : new BigInteger(N.toString());
  const muprime = new BigInteger(signed.toString());
  const s = r.modInverse(bigN).multiply(muprime).mod(bigN); // Alice computes sig = mu'*r^-1 mod N, inverse of r mod N multiplied with muprime mod N, to remove the blinding factor
  return s;
}

function verify({ unblinded, key, message, E, N }) {
  const signature = new BigInteger(unblinded.toString());
  const messageHash = messageToHashInt(message);
  const bigN = key ? key.keyPair.n : new BigInteger(N.toString());
  const bigE = key
    ? new BigInteger(key.keyPair.e.toString())
    : new BigInteger(E.toString());
  const signedMessageBigInt = signature.modPow(bigE, bigN); // calculate sig^e modN, if we get back the initial message that means that the signature is valid, this works because (m^d)^e modN = m
  const result = messageHash.equals(signedMessageBigInt);
  return result;
}

function verify2({ unblinded, key, message }) {
  const signature = new BigInteger(unblinded.toString());
  const messageHash = messageToHashInt(message);
  const { bigD, bigN } = keyProperties(key);
  const msgSig = messageHash.modPow(bigD, bigN); // calculate H(msg)^d modN, if we get back the signature that means the message was signed
  const result = signature.equals(msgSig);
  return result;
}

function verifyBlinding({ blinded, r, unblinded, key, E, N }) {
  const messageHash = messageToHashInt(unblinded);
  r = new BigInteger(r.toString());
  N = key ? key.keyPair.n : new BigInteger(N.toString());
  E = key
    ? new BigInteger(key.keyPair.e.toString())
    : new BigInteger(E.toString());

  const blindedHere = messageHash.multiply(r.modPow(E, N)).mod(N);
  const result = blindedHere.equals(blinded);
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
  verifyBlinding,
};
