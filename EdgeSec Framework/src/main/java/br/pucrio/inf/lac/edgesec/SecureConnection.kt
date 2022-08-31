/*
Module: SecureConnection.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

/*
Class: SecureConnection
Description: Data module to store variables needed after connection is established
 */
data class SecureConnection(
    val objectID: String,
    val sessionKey: ByteArray,
    val otp: ByteArray
)