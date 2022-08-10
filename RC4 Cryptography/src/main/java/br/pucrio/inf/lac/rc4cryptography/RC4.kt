package br.pucrio.inf.lac.rc4cryptography

import br.pucrio.inf.lac.edgesec.ICryptographicPlugin

class RC4(): ICryptographicPlugin {

    private val TAG = "RC4"

    init {
    }

    override fun getProtocolID(): String {
        return "RC4-Protocol";
    }

    override fun generateSecureRandomToken(size: Int): ByteArray {

        return ByteArray(20);
    }

    override fun generateSecretKeySpec(seed: String): ByteArray {
        return ByteArray(20);
    }

    override fun encrypt(plainText: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(20);
    }

    override fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(20);
    }
}