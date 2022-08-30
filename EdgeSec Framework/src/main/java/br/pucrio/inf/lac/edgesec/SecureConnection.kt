/*
Module: SecureConnection.kt
Description: Data module to store variables needed after connection is established
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

class SecureConnection(
    val objectID: String,
    val sessionKey: ByteArray,
    val otp: ByteArray
) {

    // Classe que representa uma conexão segura existente entre o gateway e um dispositivo.

    // Guarda valores como chave de sessão, id do dispositivo, entre outras necessárias para ler e escrever mensagens de forma segura.
    private val TAG = "SecureConnection"

    init {
    }
}