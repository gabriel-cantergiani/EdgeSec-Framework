/*
Module: Constants.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

/*
Object: Constants
Description: Constant values used in the package
 */
object Constants {
    const val EDGESEC_VERSION_BYTES_SIZE = 3
    const val GATEWAY_ID_BYTES_SIZE = 10
    const val DEVICE_ID_BYTES_SIZE = 10

    // Handshake
    const val HANDSHAKE_HELLO_BYTES_SIZE = EDGESEC_VERSION_BYTES_SIZE + GATEWAY_ID_BYTES_SIZE
    const val PROTOCOL_LIST_LENGTH_BYTES_SIZE = 4
    const val PROTOCOL_ID_BYTES_SIZE = 4


    val AUTH_PROTOCOL_ID = mapOf<String, Int>(
        "HMAC_MD5" to 1,
        "HMAC_SHA256" to 2
    )

    val CRYPTO_PROTOCOLS_ID = mapOf<String, Int>(
        "RC4" to 1,
        "FISH" to 2
    )

    val PROTOCOLS_SUITE_ID = mapOf<String, Byte>(
        "AES128_HMAC_MD5" to 0x01,
        "RC4_HMAC_SHA1" to 0x02,
        "RC4_HMAC_MD5" to 0x03,
//                0x0001 RC4_HMAC_SHA1
//                0x0002 RC4_HMAC_SHA256
//                0x0003 RC4_HMAC_SHA384
//                0x0004 RC4_HMAC_SHA512
//                0x0005 AES128_HMAC_MD5
//                0x0006 AES128_HMAC_SHA1
//                0x0007 AES128_HMAC_SHA256
//                0x0008 AES128_HMAC_SHA384
//                0x0009 AES128_HMAC_SHA512
//                0x000A AES256_HMAC_MD5

    )

    // Authentication
    const val OTP_BYTES_SIZE = 13
    const val SESSION_KEY_BYTES_SIZE = 11

}
