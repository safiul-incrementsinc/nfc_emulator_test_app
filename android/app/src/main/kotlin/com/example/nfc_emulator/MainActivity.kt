package com.example.nfc_emulator

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.nfc.NfcAdapter
import android.nfc.cardemulation.HostApduService
import android.os.Build
import android.os.Bundle
import android.os.Vibrator
import android.util.Log
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : FlutterActivity() {
    private val channelName = "nfc_emulator"

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, channelName)
        channel.setMethodCallHandler { call, result ->
            if (call.method == "getPlatformVersion") {
                result.success("Android " + Build.VERSION.RELEASE)
            } else if (call.method == "getNfcStatus") {
                val nfcStatus = getNfcStatus()
                result.success(nfcStatus)
            } else if (call.method == "startNfcEmulator") {
                val cardAid = call.argument<String>("cardAid")
                val cardUid = call.argument<String>("cardUid")
                val aesKey = call.argument<String>("aesKey")
                startNfcEmulator(cardAid!!, cardUid!!, aesKey!!)
                result.success(null)
            } else if (call.method == "stopNfcEmulator") {
                stopNfcEmulator()
                result.success(null)
            } else {
                result.notImplemented()
            }
        }
    }

    private fun getNfcStatus(): Int {
        val nfcAdapter = NfcAdapter.getDefaultAdapter(activity)
            ?: // This device does not support NFC
            return 1
        return if (!nfcAdapter.isEnabled) {
            // NFC not enabled
            2
        } else 0
    }

    private fun startNfcEmulator(cardAid: String, cardUid: String, aesKey: String) {
        val sharePerf: SharedPreferences =
            activity.getSharedPreferences("NfcEmulator", Context.MODE_PRIVATE)
        val editor = sharePerf.edit()
        editor.putString("cardAid", cardAid)
        editor.putString("cardUid", cardUid)
        editor.putString("aesKey", aesKey)
        editor.apply()
        val intent = Intent(activity, NfcEmulatorService::class.java)
        activity.startService(intent)
    }

    private fun stopNfcEmulator() {
        val intent = Intent(activity, NfcEmulatorService::class.java)
        activity.stopService(intent)
        val sharePerf: SharedPreferences =
            activity.getSharedPreferences("NfcEmulator", Context.MODE_PRIVATE)
        val editor = sharePerf.edit()
        editor.remove("cardAid")
        editor.remove("cardUid")
        editor.remove("aesKey")
        editor.apply()
    }

}


class NfcEmulatorService : HostApduService() {
    private var vibrator: Vibrator? = null
    private var cardAid: String? = null
    private var cardUid: String? = null
    private var aesKey: String? = null
    override fun onCreate() {
        super.onCreate()
        vibrator = this.getSystemService(VIBRATOR_SERVICE) as Vibrator
        val sharePerf = getSharedPreferences("NfcEmulator", MODE_PRIVATE)
        cardAid = sharePerf.getString("cardAid", null)
        cardUid = sharePerf.getString("cardUid", null)
        aesKey = sharePerf.getString("aesKey", null)
        if (cardAid != null && cardAid != "") {
            SELECT_APDU = buildSelectApdu(
                cardAid!!
            )
        }
    }

    override fun processCommandApdu(bytes: ByteArray, bundle: Bundle): ByteArray {
        if (cardAid == null || cardAid == "" || cardUid == null || cardUid == "") {
            return UNKNOWN_CMD_SW // don't start emulator
        }

        // If the APDU matches the SELECT AID command for this service,
        // send the loyalty card account number, followed by a SELECT_OK status trailer (0x9000).
        if (Arrays.equals(SELECT_APDU, bytes)) {
            Log.i(TAG, "< SELECT_APDU: " + byteArrayToHexString(bytes))
            val account = ""
            // Log.i(TAG,"send data1:"+account);
            val accountBytes = hexStringToByteArray(account)
            val response = concatArrays(accountBytes, SELECT_OK_SW)
            Log.i(TAG, "> SELECT_APDU: " + byteArrayToHexString(bytes))
            return response
        } else {
            var decrypted = bytes
            if (aesKey != null) {
                try {
                    decrypted = decrypt(aesKey!!, bytes)
                } catch (e: Exception) {
                    Log.e(TAG, "Exception in decryption", e)
                }
            }
            if (Arrays.equals(GET_DATA_APDU, decrypted)) {
                Log.i(TAG, "< GET_DATA_APDU: " + byteArrayToHexString(decrypted))
                try {
                    val bytesToSend = buildGetDataReply() ?: return UNKNOWN_CMD_SW
                    if (aesKey != null) {
                        try {
                            val encryptedBytes = encrypt(aesKey!!, bytesToSend)
                            Log.i(TAG, "> GET_DATA_APDU: " + byteArrayToHexString(encryptedBytes))
                            vibrator!!.vibrate(400)
                            return encryptedBytes
                        } catch (e: Exception) {
                            Log.e(TAG, "Exception in encryption", e)
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Exception in GET_DATA_APDU", e)
                }
            }
        }
        return UNKNOWN_CMD_SW
    }


    override fun onDeactivated(i: Int) {}
    private fun buildGetDataReply(): ByteArray? {
        if (cardUid!!.isEmpty() || 32 != aesKey!!.length) {
            return null
        }
        val sCardMsg = String.format("%02X", cardUid!!.length / 2) + cardUid
        val accountBytes = hexStringToByteArray(sCardMsg)
        val result = ByteArray(accountBytes.size + SELECT_OK_SW.size)
        System.arraycopy(accountBytes, 0, result, 0, accountBytes.size)
        System.arraycopy(SELECT_OK_SW, 0, result, accountBytes.size, SELECT_OK_SW.size)
        return result
    }

    companion object {
        private const val TAG = "NfcEmulator"
        private const val AES = "AES"
        private const val CIPHERMODE = "AES/CBC/PKCS5Padding"

        // Format: [Class | Instruction | Parameter 1 | Parameter 2]
        private const val SELECT_APDU_HEADER = "00A40400"

        // Format: [Class | Instruction | Parameter 1 | Parameter 2]
        private const val GET_DATA_APDU_HEADER = "00CA0000"

        // "OK" status word sent in response to SELECT AID command (0x9000)
        private val SELECT_OK_SW = hexStringToByteArray("9000")

        // "UNKNOWN" status word sent in response to invalid APDU command (0x0000)
        private val UNKNOWN_CMD_SW = hexStringToByteArray("0000")
        private lateinit var SELECT_APDU: ByteArray
        private val GET_DATA_APDU = buildGetDataApdu()

        /**
         * Build APDU for SELECT AID command. This command indicates which service a reader is
         * interested in communicating with. See ISO 7816-4.
         *
         * @param aid Application ID (AID) to select
         * @return APDU for SELECT AID command
         */
        fun buildSelectApdu(aid: String): ByteArray {
            // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
            return hexStringToByteArray(
                SELECT_APDU_HEADER + String.format(
                    "%02X",
                    aid.length / 2
                ) + aid
            )
        }

        /**
         * Build APDU for GET_DATA command. See ISO 7816-4.
         *
         * @return APDU for SELECT AID command
         */
        fun buildGetDataApdu(): ByteArray {
            // Format: [CLASS | INSTRUCTION | PARAMETER 1 | PARAMETER 2 | LENGTH | DATA]
            return hexStringToByteArray(GET_DATA_APDU_HEADER + "0FFF")
        }

        @Throws(Exception::class)
        fun encrypt(key: String, clear: ByteArray?): ByteArray {
            val raw = hexStringToByteArray(key)
            val keySpec = SecretKeySpec(raw, AES)
            val cipher = Cipher.getInstance(CIPHERMODE)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(ByteArray(cipher.blockSize)))
            return cipher.doFinal(clear)
        }

        @Throws(Exception::class)
        fun decrypt(key: String, clear: ByteArray?): ByteArray {
            val raw = hexStringToByteArray(key)
            val keySpec = SecretKeySpec(raw, AES)
            val cipher = Cipher.getInstance(CIPHERMODE)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(ByteArray(cipher.blockSize)))
            return cipher.doFinal(clear)
        }

        /**
         * Utility method to convert a byte array to a hexadecimal string.
         *
         * @param bytes Bytes to convert
         * @return String, containing hexadecimal representation.
         */
        fun byteArrayToHexString(bytes: ByteArray): String {
            val hexArray = charArrayOf(
                '0',
                '1',
                '2',
                '3',
                '4',
                '5',
                '6',
                '7',
                '8',
                '9',
                'A',
                'B',
                'C',
                'D',
                'E',
                'F'
            )
            val hexChars = CharArray(bytes.size * 2) // Each byte has two hex characters (nibbles)
            var v: Int
            for (j in bytes.indices) {
                v = bytes[j].toInt() and 0xFF // Cast bytes[j] to int, treating as unsigned value
                hexChars[j * 2] = hexArray[v ushr 4] // Select hex character from upper nibble
                hexChars[j * 2 + 1] = hexArray[v and 0x0F] // Select hex character from lower nibble
            }
            return hexChars.toString()
        }

        /**
         * Utility method to convert a hexadecimal string to a byte string.
         *
         *
         * Behavior with input strings containing non-hexadecimal characters is undefined.
         *
         * @param s String containing hexadecimal characters to convert
         * @return Byte array generated from input
         * @throws java.lang.IllegalArgumentException if input length is incorrect
         */
        @Throws(IllegalArgumentException::class)
        fun hexStringToByteArray(s: String): ByteArray {
            val len = s.length
            require(len % 2 != 1) { "Hex string must have even number of characters" }
            val data = ByteArray(len / 2) // Allocate 1 byte per 2 hex characters
            var i = 0
            while (i < len) {

                // Convert each character into a integer (base-16), then bit-shift into place
                data[i / 2] = ((s[i].digitToIntOrNull(16) ?: -1 shl 4)
                + s[i + 1].digitToIntOrNull(16)!! ?: -1).toByte()
                i += 2
            }
            return data
        }

        /**
         * Utility method to concatenate two byte arrays.
         * @param first First array
         * @param rest Any remaining arrays
         * @return Concatenated copy of input arrays
         */
        fun concatArrays(first: ByteArray, vararg rest: ByteArray): ByteArray {
            var totalLength = first.size
            for (array in rest) {
                totalLength += array.size
            }
            val result = Arrays.copyOf(first, totalLength)
            var offset = first.size
            for (array in rest) {
                System.arraycopy(array, 0, result, offset, array.size)
                offset += array.size
            }
            return result
        }
    }
}
