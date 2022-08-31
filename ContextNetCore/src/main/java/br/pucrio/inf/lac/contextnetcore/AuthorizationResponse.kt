/*
Module: AuthorizationResponse.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.contextnetcore

/*
Class: AuthorizationResponse
Description: Data class representing the response model sent back from Authorization Server
 */
data class AuthorizationResponse(
    val OTP: ByteArray,
    val sessionKey: ByteArray,
    val authenticatioPackage: ByteArray,
    val protocolSuite: String,
)
