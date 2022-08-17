package br.pucrio.inf.lac.edgesec

import javax.crypto.spec.SecretKeySpec

class Authorization {

    // Classe que obtem autorização para dois objetos se autenticarem. Encapsula operações referentes a obtenção da autorização, seja fazer requisições para um servidor, ou acessar um banco de dados

    private val TAG = "Authorization"

    // MOCK (variaveis que sao usadas no processamento feito pelo SDDL)
    private val Kauth_sddl: SecretKeySpec? = null;
    private val Kauth_object: ByteArray = ByteArray(0);
    private val Kcipher_object: ByteArray = ByteArray(0);

    init {
    }

    fun verifyAuthorization(gatewayID: String, objectID: String): AuthenticationPackage {

        // Call ContexNet class to authorize connection (mocked network request)

        // Receive response as byte array

        // Break down byte array into OTP, Session Key, and Protocol suites values

        return AuthenticationPackage("RC4_HMAC_MD5", gatewayID, objectID, "OTP".encodeToByteArray(), "Key".encodeToByteArray());
    }
}