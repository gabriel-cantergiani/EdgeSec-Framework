/*
Module: Constants.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.contextnetcore

/*
Object: Constants
Description: Constant values used in ContextNet Core functionalities
 */
object Constants {

    val PROTOCOLS_SUITE_ID = mapOf<String, Byte>(
        "AES128_HMAC_MD5" to 0x01,
        "RC4_HMAC_SHA1" to 0x02,
        "RC4_HMAC_MD5" to 0x03,

    )

    // Authentication
    const val OTP_CHALLENGE_BYTES_SIZE = 13
    const val SESSION_KEY_BYTES_SIZE = 11

}
