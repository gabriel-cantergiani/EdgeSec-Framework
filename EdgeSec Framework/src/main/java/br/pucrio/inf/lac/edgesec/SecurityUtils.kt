/*
Module: SecurityUtils.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec


/*
Class: SecurityUtils
Description: Utility functions
 */
class SecurityUtils {

    private val TAG = "SecurityUtils"

    init {
    }

    companion object {

        fun ByteArray.decodeByteArrayToHexString(): String {

            var str: String = "";
            for (b in this) {
                str += String.format("%02X", b)
            }

            return str
        }

        fun Int.encodeToByteArray(): ByteArray {
            var buffer: ByteArray = ByteArray(4);
            buffer[0] = (this ushr 0).toByte()
            buffer[1] = (this ushr 8).toByte()
            buffer[2] = (this ushr 16).toByte()
            buffer[3] = (this ushr 24).toByte()

            return buffer;
        }

        fun ByteArray.decodeToInt(): Int {
            return (this[3].toInt() shl 24) or
                    (this[2].toInt() and 0xff shl 16) or
                    (this[1].toInt() and 0xff shl 8) or
                    (this[0].toInt() and 0xff)
        }
    }
}