import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:mlkem_native/mlkem512.dart';
import 'package:mlkem_native/mlkem768.dart';
import 'package:mlkem_native/mlkem1024.dart';
import 'package:mlkem_native/src/models.dart';
import 'package:mlkem_native/src/shared.dart';

void main() {
  group('KeyPair', () {
    test('constructs with secretKey and publicKey', () {
      final sk = Uint8List.fromList([1, 2, 3]);
      final pk = Uint8List.fromList([4, 5, 6]);
      final kp = KeyPair(secretKey: sk, publicKey: pk);

      expect(kp.secretKey, equals(sk));
      expect(kp.publicKey, equals(pk));
    });
  });

  group('EncapsulationResult', () {
    test('constructs with ciphertext and sharedSecret', () {
      final ct = Uint8List.fromList([1, 2, 3]);
      final ss = Uint8List.fromList([4, 5]);
      final result = EncapsulationResult(ciphertext: ct, sharedSecret: ss);

      expect(result.ciphertext, equals(ct));
      expect(result.sharedSecret, equals(ss));
    });
  });

  group('getRandomCoins', () {
    test('returns 32 bytes', () {
      final coins = getRandomCoins();
      expect(coins.length, equals(32));
    });

    test('returns different values on successive calls', () {
      final coins1 = getRandomCoins();
      final coins2 = getRandomCoins();
      // Extremely unlikely to collide for 32 random bytes
      expect(_bytesEqual(coins1, coins2), isFalse);
    });
  });

  group('Exceptions', () {
    test('MLKEMKeyPairGenerationException stores cError', () {
      final e = MLKEMKeyPairGenerationException(42);
      expect(e.cError, equals(42));
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMEncapsulationFailedException stores cError', () {
      final e = MLKEMEncapsulationFailedException(-1);
      expect(e.cError, equals(-1));
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMDecapsulationFailedException stores cError', () {
      final e = MLKEMDecapsulationFailedException(-2);
      expect(e.cError, equals(-2));
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMCoinsWrongSize is MLKEMException and Exception', () {
      final e = MLKEMCoinsWrongSize();
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMPublicKeyWrongLengthException is MLKEMException and Exception',
        () {
      final e = MLKEMPublicKeyWrongLengthException();
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMSecretKeyWrongLengthException is MLKEMException and Exception',
        () {
      final e = MLKEMSecretKeyWrongLengthException();
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });

    test('MLKEMCiphertextWrongLengthException is MLKEMException and Exception',
        () {
      final e = MLKEMCiphertextWrongLengthException();
      expect(e, isA<MLKEMException>());
      expect(e, isA<Exception>());
    });
  });

  // Integration tests for each security level
  _testSecurityLevel(
    'MLKEM512',
    () => MLKEM512(),
    800,
    1632,
    768,
    32,
  );

  _testSecurityLevel(
    'MLKEM768',
    () => MLKEM768(),
    1184,
    2400,
    1088,
    32,
  );

  _testSecurityLevel(
    'MLKEM1024',
    () => MLKEM1024(),
    1568,
    3168,
    1568,
    32,
  );
}

void _testSecurityLevel(
  String name,
  MLKEMImpl<InternalParameters> Function() factory,
  int pkBytes,
  int skBytes,
  int ctBytes,
  int ssBytes,
) {
  group(name, () {
    late MLKEMImpl<InternalParameters> kem;

    setUp(() {
      kem = factory();
    });

    group('generateKeyPair', () {
      test('produces correct-size keys', () {
        final kp = kem.generateKeyPair();
        expect(kp.publicKey.length, equals(pkBytes));
        expect(kp.secretKey.length, equals(skBytes));
      });

      test('deterministic mode produces correct-size keys', () {
        final coins = Uint8List(32);
        final kp = kem.generateKeyPair(coins: coins);
        expect(kp.publicKey.length, equals(pkBytes));
        expect(kp.secretKey.length, equals(skBytes));
      });

      test('deterministic mode is reproducible', () {
        final coins = getRandomCoins();
        final kp1 = kem.generateKeyPair(coins: coins);
        final kp2 = kem.generateKeyPair(coins: coins);
        expect(_bytesEqual(kp1.publicKey, kp2.publicKey), isTrue);
        expect(_bytesEqual(kp1.secretKey, kp2.secretKey), isTrue);
      });

      test('throws MLKEMCoinsWrongSize for wrong coins length', () {
        expect(
          () => kem.generateKeyPair(coins: Uint8List(16)),
          throwsA(isA<MLKEMCoinsWrongSize>()),
        );
        expect(
          () => kem.generateKeyPair(coins: Uint8List(64)),
          throwsA(isA<MLKEMCoinsWrongSize>()),
        );
      });
    });

    group('encapsulate', () {
      late Uint8List publicKey;

      setUp(() {
        publicKey = kem.generateKeyPair().publicKey;
      });

      test('produces correct-size ciphertext and shared secret', () {
        final result = kem.encapsulate(publicKey);
        expect(result.ciphertext.length, equals(ctBytes));
        expect(result.sharedSecret.length, equals(ssBytes));
      });

      test('deterministic mode is reproducible', () {
        final coins = getRandomCoins();
        final r1 = kem.encapsulate(publicKey, coins: coins);
        final r2 = kem.encapsulate(publicKey, coins: coins);
        expect(_bytesEqual(r1.ciphertext, r2.ciphertext), isTrue);
        expect(_bytesEqual(r1.sharedSecret, r2.sharedSecret), isTrue);
      });

      test('throws MLKEMPublicKeyWrongLengthException for wrong pk length', () {
        expect(
          () => kem.encapsulate(Uint8List(pkBytes - 1)),
          throwsA(isA<MLKEMPublicKeyWrongLengthException>()),
        );
        expect(
          () => kem.encapsulate(Uint8List(pkBytes + 1)),
          throwsA(isA<MLKEMPublicKeyWrongLengthException>()),
        );
      });

      test('throws MLKEMCoinsWrongSize for wrong coins length', () {
        expect(
          () => kem.encapsulate(publicKey, coins: Uint8List(16)),
          throwsA(isA<MLKEMCoinsWrongSize>()),
        );
      });
    });

    group('decapsulate', () {
      late Uint8List secretKey;
      late Uint8List ciphertext;

      setUp(() {
        final kp = kem.generateKeyPair();
        secretKey = kp.secretKey;
        ciphertext = kem.encapsulate(kp.publicKey).ciphertext;
      });

      test('returns correct-size shared secret', () {
        final ss = kem.decapsulate(ciphertext, secretKey);
        expect(ss.length, equals(ssBytes));
      });

      test('throws MLKEMCiphertextWrongLengthException for wrong ct length', () {
        expect(
          () => kem.decapsulate(Uint8List(ctBytes - 1), secretKey),
          throwsA(isA<MLKEMCiphertextWrongLengthException>()),
        );
      });

      test('throws MLKEMSecretKeyWrongLengthException for wrong sk length', () {
        expect(
          () => kem.decapsulate(ciphertext, Uint8List(skBytes - 1)),
          throwsA(isA<MLKEMSecretKeyWrongLengthException>()),
        );
      });
    });

    group('round-trip', () {
      test('shared secrets match (random mode)', () {
        final kp = kem.generateKeyPair();
        final enc = kem.encapsulate(kp.publicKey);
        final ss = kem.decapsulate(enc.ciphertext, kp.secretKey);
        expect(_bytesEqual(enc.sharedSecret, ss), isTrue);
      });

      test('shared secrets match (deterministic mode)', () {
        final keyCoins = getRandomCoins();
        final encCoins = getRandomCoins();
        final kp = kem.generateKeyPair(coins: keyCoins);
        final enc = kem.encapsulate(kp.publicKey, coins: encCoins);
        final ss = kem.decapsulate(enc.ciphertext, kp.secretKey);
        expect(_bytesEqual(enc.sharedSecret, ss), isTrue);
      });

      test('decapsulation with wrong secret key produces different result', () {
        final kp1 = kem.generateKeyPair();
        final kp2 = kem.generateKeyPair();
        final enc = kem.encapsulate(kp1.publicKey);
        final ss = kem.decapsulate(enc.ciphertext, kp2.secretKey);
        // With overwhelming probability, the shared secret will differ
        expect(_bytesEqual(enc.sharedSecret, ss), isFalse);
      });
    });
  });
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
