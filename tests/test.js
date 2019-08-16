const test = require('tape');
const BlindSignature = require('../rsablind');
const BlindSignature2 = require('../rsablind2'); // Other implimentation

test('Full RSA Blind Signature test 1', (t) => {
    t.plan(6);

    const Bob = {
      key: BlindSignature.keyGeneration({ b: 512 }),
      blinded: null,
      unblinded: null,
      message: null,
    };

    const Alice = {
      message: 'Hello Chaum!',
      N: null,
      E: null,
      r: null,
      signed: null,
      unblinded: null,
    };

    // Alice wants Bob to sign a message without revealing it's contents.
    // Bob can later verify he did sign the message

    // Alice gets N and E variables from Bob's key
    Alice.N = Bob.key.keyPair.n.toString();
    Alice.E = Bob.key.keyPair.e.toString();

    // N, E
    const { blinded, r } = BlindSignature.blind({
      message: Alice.message,
      N: Alice.N,
      E: Alice.E,
    }); // Alice blinds message
    Alice.r = r;

    // Alice sends blinded to Bob
    Bob.blinded = blinded;

    // N, D (P, Q)
    const signed = BlindSignature.sign({
      blinded: Bob.blinded,
      key: Bob.key,
    }); // Bob signs blinded message

    // Bob sends signed to Alice
    Alice.signed = signed;

    // N
    const unblinded = BlindSignature.unblind({
      signed: Alice.signed,
      N: Alice.N,
      r: Alice.r,
    }); // Alice unblinds
    Alice.unblinded = unblinded;

    // Alice verifies
    // N, E
    const result = BlindSignature.verify({
      unblinded: Alice.unblinded,
      N: Alice.N,
      E: Alice.E,
      message: Alice.message,
    });
    t.ok(result);

    // Make sure invalid message fails
    const resultFailed = BlindSignature.verify({
      unblinded: Alice.unblinded,
      N: Alice.N,
      E: Alice.E,
      message: 'Invalid message',
    });
    t.notOk(resultFailed);

    // Alice sends Bob unblinded signature and original message
    Bob.unblinded = Alice.unblinded;
    Bob.message = Alice.message;

    // Bob verifies
    // N, D
    const result2 = BlindSignature.verify2({
      unblinded: Bob.unblinded,
      key: Bob.key,
      message: Bob.message,
    });
    t.ok(result2);

    // Make sure invalid message fails
    const resultFailed2 = BlindSignature.verify2({
      unblinded: Alice.unblinded,
      key: Bob.key,
      message: 'Invalid message',
    });
    t.notOk(resultFailed2);

    // Bob signs a lot of messages from Alice
    // and wants to verify the content of a blinded message
    // that he once signed

    // Bob verifies the content of this specific blinded message
    // makes sure it was not swaped for another message
    // that Bob signed before.
    const result3 = BlindSignature.verifyBlinding({
      blinded: Bob.blinded,
      unblinded: Bob.message,
      r: Alice.r,
      key: Bob.key,
    });
    t.ok(result3);

    // Make sure invalid message fails
    const resultFailed3 = BlindSignature.verifyBlinding({
      blinded: Bob.blinded,
      unblinded: "Bob have signed this before",
      r: Alice.r,
      key: Bob.key,
    });
    t.notOk(resultFailed3);
});

test('Full RSA Blind Signature test 2', (t) => {
    t.plan(6);

    const Bob = {
      key: BlindSignature2.keyGeneration({ b: 512 }),
      blinded: null,
      unblinded: null,
      message: null,
    };

    const Alice = {
      message: 'Hello Chaum!',
      N: null,
      E: null,
      r: null,
      signed: null,
      unblinded: null,
    };

    // Alice wants Bob to sign a message without revealing it's contents.
    // Bob can later verify he did sign the message

    // Alice gets N and E variables from Bob's key
    Alice.N = Bob.key.keyPair.n.toString();
    Alice.E = Bob.key.keyPair.e.toString();

    // N, E
    const { blinded, r } = BlindSignature2.blind({
      message: Alice.message,
      N: Alice.N,
      E: Alice.E,
    }); // Alice blinds message
    Alice.r = r;

    // Alice sends blinded to Bob
    Bob.blinded = blinded;

    // N, D (P, Q)
    const signed = BlindSignature2.sign({
      blinded: Bob.blinded,
      key: Bob.key,
    }); // Bob signs blinded message

    // Bob sends signed to Alice
    Alice.signed = signed;

    // N
    const unblinded = BlindSignature2.unblind({
      signed: Alice.signed,
      N: Alice.N,
      r: Alice.r,
    }); // Alice unblinds
    Alice.unblinded = unblinded;

    // Alice verifies
    // N, E
    const result = BlindSignature2.verify({
      unblinded: Alice.unblinded,
      N: Alice.N,
      E: Alice.E,
      message: Alice.message,
    });
    t.ok(result);

    // Make sure invalid message fails
    const resultFailed = BlindSignature2.verify({
      unblinded: Alice.unblinded,
      N: Alice.N,
      E: Alice.E,
      message: 'Invalid message',
    });
    t.notOk(resultFailed);

    // Alice sends Bob unblinded signature and original message
    Bob.unblinded = Alice.unblinded;
    Bob.message = Alice.message;

    // Bob verifies
    // N, D
    const result2 = BlindSignature2.verify2({
      unblinded: Bob.unblinded,
      key: Bob.key,
      message: Bob.message,
    });
    t.ok(result2);

    // Make sure invalid message fails
    const resultFailed2 = BlindSignature2.verify2({
      unblinded: Alice.unblinded,
      key: Bob.key,
      message: 'Invalid message',
    });
    t.notOk(resultFailed2);

    // Bob signs a lot of messages from Alice
    // and wants to verify the content of a blinded message
    // that he once signed

    // Bob verifies the content of this specific blinded message
    // makes sure it was not swaped for another message
    // that Bob signed before.
    const result3 = BlindSignature.verifyBlinding({
      blinded: Bob.blinded,
      unblinded: Bob.message,
      r: Alice.r,
      key: Bob.key,
    });
    t.ok(result3);

    // Make sure invalid message fails
    const resultFailed3 = BlindSignature.verifyBlinding({
      blinded: Bob.blinded,
      unblinded: "Bob have signed this before",
      r: Alice.r,
      key: Bob.key,
    });
    t.notOk(resultFailed3);
});
