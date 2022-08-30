/*
Module: AuthorizationResponse.kt
Description: Data class representing the response model sent back from Authorization Server
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.contextnetcore

data class AuthorizationResponse(
    val OTP: ByteArray,
    val sessionKey: ByteArray,
    val authenticatioPackage: ByteArray,
    val protocolSuite: String,
)
