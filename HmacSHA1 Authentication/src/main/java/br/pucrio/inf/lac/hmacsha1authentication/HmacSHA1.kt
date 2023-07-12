/*
Module: HmacSHA1.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.hmacsha1authentication

import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import java.security.Key
import java.security.MessageDigest
import javax.crypto.Mac

/*
Class: HmacSHA1
Description: Main module that implements HmacSHA1 protocol as an IAuthenticationPlugin
 */
class HmacSHA1(): IAuthenticationPlugin {

    private val TAG = "HmacMSHA1"
    private val SigningAlgorithmID = "hmacSHA1"
    private val DigestAlgorithmID = "SHA1"
    private val DigestAlgorithmBytesSize = 20

    init {
    }

    /*
        Returns ID of protocol implemented by plugin

        Returns:
            - String representing protocol
     */
    override fun getProtocolID(): String {
        return "HMAC_SHA1"
    }

    /*
        Sign data using provided key with the protocol implemented by plugin

        Parameters:
            - data: ByteArray representing data to be signed
            - key: Key object used for signature

        Returns:
            - ByteArray representing generated signature
     */
    override fun sign(data: ByteArray, key: Key): ByteArray {
        val macInstance = Mac.getInstance(SigningAlgorithmID)
        macInstance.init(key)
        return macInstance.doFinal(data)
    }

    /*
        Verify a signature

        Parameters:
            - data: ByteArray representing data of the signature to be verified
            - key: Key object used for signature
            - signature: ByteArray representing signature to be verified

        Returns:
            - True if signature is valid and false otherwise
     */
    override fun verifySignature(data: ByteArray, key: Key, signature: ByteArray): Boolean {
        val generatedSignature = sign(data, key)
        return signature.contentEquals(generatedSignature)
    }

    /*
        Generate a hash value using hashing function implemented by plugin

        Parameters:
            - payload: ByteArray representing payload to be hashed

        Returns:
            - ByteArray representing hash generated
     */
    override fun generateHash(payload: ByteArray): ByteArray {
        val digestInstance = MessageDigest.getInstance(DigestAlgorithmID)
        digestInstance.update(payload)
        return digestInstance.digest()
    }

    /*
        Return size in bytes of the hash generated by hashing function of protocol implemented by plugin

        Returns:
            - Integer representing size of hashes generated by plugin
     */
    override fun getHashSize(): Int {
        return DigestAlgorithmBytesSize;
    }
}