/*
Module: AuthenticationPackage.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

import javax.crypto.spec.SecretKeySpec

/*
Class: AuthenticationPackage
Description: Data class to store variables related to authentication process
 */
class AuthenticationPackage(
    val protocolSuite: String,
    val signedAuthPackage: ByteArray,
    val OTP: ByteArray,
    val SessionKey: ByteArray,
    val messageTimestamp: ByteArray
) {
    private val TAG = "AuthenticationPackage"

    init {
    }
}