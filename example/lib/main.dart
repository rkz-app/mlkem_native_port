import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:mlkem_native/mlkem1024.dart';
import 'package:mlkem_native/mlkem512.dart';
import 'package:mlkem_native/mlkem768.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final mlKem768 = MLKEM768();
  final mlKem1024 = MLKEM1024();
  final mlkem512 = MLKEM512();

  late String randomCoinsKeyPair;
  late String randomCoinsEncapsulation;

  // MLKEM512 variables
  late String encapsulatedSS512;
  late String decapsulatedSS512;
  late bool resultsAreEqual512;

  // MLKEM768 variables
  late String encapsulatedSS768;
  late String decapsulatedSS768;
  late bool resultsAreEqual768;

  // MLKEM1024 variables
  late String encapsulatedSS1024;
  late String decapsulatedSS1024;
  late bool resultsAreEqual1024;

  bool useCoins = true;

  @override
  void initState() {
    super.initState();

    Uint8List? randomCoins;

    Uint8List? encapsulateCoins;

    if (useCoins) {
      randomCoins = getRandomCoins();
      encapsulateCoins = getRandomCoins();

      randomCoinsKeyPair = base64Encode(randomCoins);
      randomCoinsEncapsulation = base64Encode(encapsulateCoins);
    }

    // MLKEM512
    late KeyPair kp512 = mlkem512.generateKeyPair(coins: randomCoins);
    final result512 = mlkem512.encapsulate(
      kp512.publicKey,
      coins: encapsulateCoins,
    );
    final decapsulatedResult512 = mlkem512.decapsulate(
      result512.ciphertext,
      kp512.secretKey,
    );

    encapsulatedSS512 = base64Encode(result512.sharedSecret);
    decapsulatedSS512 = base64Encode(decapsulatedResult512);
    resultsAreEqual512 = encapsulatedSS512 == decapsulatedSS512;

    // MLKEM768
    late KeyPair kp768 = mlKem768.generateKeyPair(coins: randomCoins);
    final result768 = mlKem768.encapsulate(
      kp768.publicKey,
      coins: encapsulateCoins,
    );
    final decapsulatedResult768 = mlKem768.decapsulate(
      result768.ciphertext,
      kp768.secretKey,
    );

    encapsulatedSS768 = base64Encode(result768.sharedSecret);
    decapsulatedSS768 = base64Encode(decapsulatedResult768);
    resultsAreEqual768 = encapsulatedSS768 == decapsulatedSS768;

    // MLKEM1024
    late KeyPair kp1024 = mlKem1024.generateKeyPair(coins: randomCoins);
    final result1024 = mlKem1024.encapsulate(
      kp1024.publicKey,
      coins: encapsulateCoins,
    );
    final decapsulatedResult1024 = mlKem1024.decapsulate(
      result1024.ciphertext,
      kp1024.secretKey,
    );

    encapsulatedSS1024 = base64Encode(result1024.sharedSecret);
    decapsulatedSS1024 = base64Encode(decapsulatedResult1024);
    resultsAreEqual1024 = encapsulatedSS1024 == decapsulatedSS1024;
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('MLKEM Native')),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                spacing: 10,
                children: [
                  if (useCoins)
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text("KeyPair Coins: $randomCoinsKeyPair"),
                        TextButton(
                          onPressed: () {
                            Clipboard.setData(
                              ClipboardData(text: randomCoinsKeyPair),
                            );
                          },
                          child: Text("Copy"),
                        ),
                      ],
                    ),
                  if (useCoins)
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Text("Encapsulation Coins: $randomCoinsEncapsulation"),
                        TextButton(
                          onPressed: () {
                            Clipboard.setData(
                              ClipboardData(text: randomCoinsEncapsulation),
                            );
                          },
                          child: Text("Copy"),
                        ),
                      ],
                    ),
                  SizedBox(height: 50),
                  Text("MLKEM 512", textAlign: TextAlign.center),
                  Text(encapsulatedSS512),
                  Text(
                    resultsAreEqual512 ? "EQUAL" : "NOT EQUAL",
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  Text(decapsulatedSS512),
                  SizedBox(height: 50),
                  Text("MLKEM 768", textAlign: TextAlign.center),
                  Text(encapsulatedSS768),
                  Text(
                    resultsAreEqual768 ? "EQUAL" : "NOT EQUAL",
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  Text(decapsulatedSS768),
                  SizedBox(height: 50),
                  Text("MLKEM 1024", textAlign: TextAlign.center),
                  Text(encapsulatedSS1024),
                  Text(
                    resultsAreEqual1024 ? "EQUAL" : "NOT EQUAL",
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  Text(decapsulatedSS1024),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
