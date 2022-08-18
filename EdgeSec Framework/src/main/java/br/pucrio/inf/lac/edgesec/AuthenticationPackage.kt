package br.pucrio.inf.lac.edgesec

import javax.crypto.spec.SecretKeySpec

class AuthenticationPackage(
    val protocolSuite: String,
    val signedAuthPackage: ByteArray,
    val OTP: ByteArray,
    val SessionKey: ByteArray
) {

    // Classe que representa o objeto de um pacote de autenticação

    // Guarda variáveis referentes à um pacote de autenticação, assim como setters e getters para estes valores.

    private val TAG = "AuthenticationPackage"

    init {
    }
}