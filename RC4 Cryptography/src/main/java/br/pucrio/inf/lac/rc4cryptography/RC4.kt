package br.pucrio.inf.lac.rc4cryptography

import br.pucrio.inf.lac.edgesec.ICryptographicPlugin
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

class RC4(): ICryptographicPlugin {

    private val TAG = "RC4"

    init {
    }

    override fun getProtocolID(): String {
        return "RC4";
    }

    override fun generateSecureRandomToken(size: Int): ByteArray {

        val token = StringBuilder()
        val number = SecureRandom.getInstance("SHA1PRNG")
        for (i in 0..size) {
            token.append(number.nextInt(9))
        }

        return token.toString().toByteArray();
    }

    override fun generateSecretKey(seed: ByteArray): ByteArray {
        return SecretKeySpec(seed, getProtocolID()).toString().encodeToByteArray()
    }

    override fun encrypt(plainText: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(20);
    }

    override fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(20);
    }
}