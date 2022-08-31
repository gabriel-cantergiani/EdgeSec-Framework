/*
Module: RC4.kt
Description: Main module that implements RC4 protocol as an ICryptographicPlugin
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.rc4cryptography

import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import java.security.Key
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class RC4(): ICryptographicPlugin {

    private val TAG = "RC4"
    private val CryptoAlgorithmID = "RC4"

    init {
    }

    /*
        Returns ID of protocol implemented by plugin

        Returns:
            - String representing protocol
     */
    override fun getProtocolID(): String {
        return "RC4";
    }

    /*
        Generate a random token using protocol implemented by plugin

        Parameters:
            - size: Integer defining size of token to be generated in bytes

        Returns:
            - ByteArray representing secure random token generated
     */
    override fun generateSecureRandomToken(size: Int): ByteArray {

        val token = StringBuilder()
        val number = SecureRandom.getInstance("SHA1PRNG")
        for (i in 0..size) {
            token.append(number.nextInt(9))
        }

        return token.toString().toByteArray();
    }

    /*
        Generate a secret key

        Parameters:
            - seed: ByteArray to be used as seed to generate key

        Returns:
            - Key object generated
     */
    override fun generateSecretKey(seed: ByteArray): Key {
        return SecretKeySpec(seed, getProtocolID())
    }

    /*
        Encrypt data using a provided key

        Parameters:
            - plainText: ByteArray representing data to be encrypted
            - key: ByteArray representing key value to be used in encryption

        Returns:
            - ByteArray representing encrypted data
     */
    override fun encrypt(plainText: ByteArray, key: ByteArray): ByteArray {
        val rc4Key = SecretKeySpec(key, CryptoAlgorithmID)
        val rc4 = Cipher.getInstance(CryptoAlgorithmID)

        rc4.init(Cipher.ENCRYPT_MODE, rc4Key)

        return rc4.update(plainText);
    }

    /*
        Decrypt data using a provided key

        Parameters:
            - cipher: ByteArray representing encrypted data
            - key: ByteArray representing key value to be used in decryption

        Returns:
            - ByteArray representing decrypted data
     */
    override fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(20);
    }
}