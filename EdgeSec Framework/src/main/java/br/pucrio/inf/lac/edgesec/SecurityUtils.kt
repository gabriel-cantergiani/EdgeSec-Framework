package br.pucrio.inf.lac.edgesec


class SecurityUtils {
    // Implementa algumas funções auxiliares ao processo de autenticação como:
    // Concatenação de valores em bytes
    // Criação de timestamp, incremento de timestamp
    // Conversão de bytes para hex string e vice-versa

    private val TAG = "SecurityUtils"

    init {
    }

    companion object {
//        fun String.encodeToByteArray(): ByteArray {
//
//            check(length % 2 == 0) { "Must have an even length" }
//
//            return chunked(2)
//                .map { it.toInt(16).toByte() }
//                .toByteArray()
//        }

        fun ByteArray.decodeByteArrayToHexString(): String {

            var str: String = "";
            for (b in this) {
                str += String.format("%02X", b)
            }

            return str
        }

        fun Int.encodeToByteArray(): ByteArray {
            var buffer: ByteArray = ByteArray(4);
            buffer[0] = (this shr 0).toByte()
            buffer[1] = (this shr 8).toByte()
            buffer[2] = (this shr 16).toByte()
            buffer[3] = (this shr 24).toByte()

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