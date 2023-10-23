import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String _platformVersion = 'Unknown';
  NfcStatus _nfcStatus = NfcStatus.unknown;
  bool _started = false;

  @override
  void initState() {
    super.initState();
    initPlatformState();
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> initPlatformState() async {
    String? platformVersion;
    NfcStatus nfcStatus = NfcStatus.unknown;
    // Platform messages may fail, so we use a try/catch PlatformException.
    try {
      platformVersion = await NfcEmulator.platformVersion;
      nfcStatus = await NfcEmulator.nfcStatus;
    } on PlatformException {
      platformVersion = 'Failed to get platform version.';
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _platformVersion = platformVersion ?? 'Unknown';
      _nfcStatus = nfcStatus;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('NFC Emulator Example'),
        ),
        body: Container(
          alignment: Alignment.center,
          child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Text('Version: $_platformVersion'),
                SizedBox(height: 20.0),
                Text('Status: $_nfcStatus'),
                SizedBox(height: 40.0),
                ElevatedButton(
                    child: Text(_started ? "Stop Emulator" : "Start Emulator"),
                    onPressed: startStopEmulator),
              ]),
        ),
      ),
    );
  }

  void startStopEmulator() async {
    if (_started) {
      await NfcEmulator.stopNfcEmulator();
    } else {
      await NfcEmulator.startNfcEmulator(
          "666B65630001", "cd22c716", "79e64d05ed6475d3acf405d6a9cd506b");
    }
    setState(() {
      _started = !_started;
    });
  }
}

enum NfcStatus { unknown, enabled, notSupported, notEnabled }

class NfcEmulator {
  static const MethodChannel _channel = const MethodChannel('nfc_emulator');

  /*
   * Get platform version
   */
  static Future<String?> get platformVersion async {
    final String? version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  /*
   * Get NFC status
   */
  static Future<NfcStatus> get nfcStatus async {
    final int? status = await _channel.invokeMethod('getNfcStatus');
    return _parseNfcStatus(status);
  }

  /*
   * Start NFC Emulator
   * cardAid: Card AID, for example: 666B65630001
   * cardUid: Card UID, for example: cd22c716
   * aesKey: AES key to encrypt, optional, 16 bytes (hex length 32)
   */
  static Future<void> startNfcEmulator(String cardAid, String cardUid,
      [String? aesKey]) async {
    await _channel.invokeMethod('startNfcEmulator', {
      "cardAid": cardAid,
      "cardUid": cardUid,
      "aesKey": aesKey,
    });
  }

  /*
   * Stop NFC Emulator
   */
  static Future<void> stopNfcEmulator() async {
    await _channel.invokeMethod('stopNfcEmulator');
  }

  static NfcStatus _parseNfcStatus(int? value) {
    switch (value) {
      case -1:
        return NfcStatus.unknown;
      case 0:
        return NfcStatus.enabled;
      case 1:
        return NfcStatus.notSupported;
      case 2:
        return NfcStatus.notEnabled;
      default:
        return NfcStatus.unknown;
    }
  }
}
