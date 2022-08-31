/*
Module: ICryptographicPlugin.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesecinterfaces

import java.security.Key

/*
Interface: ICryptographicPlugin
Description: Interface for plugin that provides a cryptography implementation, compatible with EdgeSec framework
 */
interface ICryptographicPlugin {

    /*
        Returns ID of protocol implemented by plugin

        Returns:
            - String representing protocol
     */
    fun getProtocolID(): String;

    /*
        Generate a random token using protocol implemented by plugin

        Parameters:
            - size: Integer defining size of token to be generated in bytes

        Returns:
            - ByteArray representing secure random token generated
     */
    fun generateSecureRandomToken(size: Int): ByteArray;

    /*
        Generate a secret key

        Parameters:
            - seed: ByteArray to be used as seed to generate key

        Returns:
            - Key object generated
     */
    fun generateSecretKey(seed: ByteArray): Key;


    /*
        Encrypt data using a provided key

        Parameters:
            - plainText: ByteArray representing data to be encrypted
            - key: ByteArray representing key value to be used in encryption

        Returns:
            - ByteArray representing encrypted data
     */
    fun encrypt(plainText: ByteArray, key: ByteArray): ByteArray;

    /*
        Decrypt data using a provided key

        Parameters:
            - cipher: ByteArray representing encrypted data
            - key: ByteArray representing key value to be used in decryption

        Returns:
            - ByteArray representing decrypted data
     */
    fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray;
}
