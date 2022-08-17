package br.pucrio.inf.lac.edgesec

import javax.crypto.spec.SecretKeySpec

class AuthenticationPackage(
    val protocolSuite: String,
    val gatewayID: String,
    val objectID: String,
    val OTP: ByteArray,
    val SessionKey: ByteArray
) {

    // Classe que representa o objeto de um pacote de autenticação

    // Guarda variáveis referentes à um pacote de autenticação, assim como setters e getters para estes valores.

    private val TAG = "AuthenticationPackage"


    // MOCK (variaveis que sao usadas no processamento feito pelo SDDL)
    private val Kauth_sddl: SecretKeySpec = TODO();
    private val Kauth_object: ByteArray = ByteArray(0);
    private val Kcipher_object: ByteArray = ByteArray(0);

    init {
    }
}