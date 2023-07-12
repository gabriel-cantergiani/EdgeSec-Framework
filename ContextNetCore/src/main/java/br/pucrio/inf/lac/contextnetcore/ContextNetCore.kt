/*
Module: ContextNetCore.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.contextnetcore

import br.pucrio.inf.lac.contextnetcore.ContextNetCore.decodeByteArrayToHexString
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5
import br.pucrio.inf.lac.hmacsha1authentication.HmacSHA1
import br.pucrio.inf.lac.rc4cryptography.RC4
import com.google.gson.Gson

/*
Object: ContextNetCore
Description: Module that simulates actions executed in processing servers on ContextNetCore
 */
object ContextNetCore : IAuthorizationProvider {

    private val coreAuthKey = "Kauth_core".encodeToByteArray();

    private val registeredObjects = arrayOf<String>("0879C623C9C8", "24:6F:28:B5:D8:3A", "ID_DEVICE0");
    private val objectsAuthKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kauth_Obj1".encodeToByteArray(),
        "24:6F:28:B5:D8:3A" to "Kauth_Obj2".encodeToByteArray(),
        "ID_DEVICE0" to "Kauth_obj".encodeToByteArray(),
    )
    private val objectsCipherKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kcipher_Obj1".encodeToByteArray(),
        "24:6F:28:B5:D8:3A" to "Kcipher_Obj2".encodeToByteArray(),
        "ID_DEVICE0" to "Kcipher_obj".encodeToByteArray(),
    )

    private val objectsSupportedProtocolSuites = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("RC4_HMAC_MD5", "RC4_HMAC_SHA1", "AES128_HMAC_MD5"),
        "24:6F:28:B5:D8:3A" to arrayOf<String>("RC4_HMAC_MD5", "RC4_HMAC_SHA1"),
        "ID_DEVICE0" to arrayOf<String>("RC4_HMAC_MD5", "RC4_HMAC_SHA1"),
    )
    private val objectsAuthorizedGateways = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("736DF76FC9KU", "LK9JD765JKO9"),
        "24:6F:28:B5:D8:3A" to arrayOf<String>("808DE88FC8TE", "02:00:00:00:00:00"),
        "ID_DEVICE0" to arrayOf<String>("808DE88FC8TE", "02:00:00:00:00:00", "GATEWAY_ID"),
    )

    private var cryptoPlugins = mapOf<String, ICryptographicPlugin>(
        "AES128" to RC4(), // TODO: REPLACE WITH AES128 IMPLEMENTATION
        "RC4" to RC4(),
    )

    private var authPlugins = mapOf<String, IAuthenticationPlugin>(
        "HMAC_SHA1" to HmacSHA1(),
        "HMAC_MD5" to HmacMD5(),
    )

    /*
       Receives a pair of gateway/object and verifies if they are allowed to securely communicate with each other

       Parameters:
           - gateway_id: string identifying MacAddress of gateway
           - object_id: string identifying MacAddress of smart object

       Returns:
           - A pair of values:
                - A boolean that has value true if devices are authorized, and false otherwise
                - A String representing the serialized JSON of the Authorization Response
    */
    override fun authorize(gatewayID: String, objectID: String): Pair<Boolean, String> {

        // Validate if object is registered
        if (!registeredObjects.contains(objectID))
            return Pair(false,"Object is not registered in ContextNetCore")

        if (!objectsAuthorizedGateways[objectID]!!.contains(gatewayID))
            return Pair(false, "Gateway is not authorized to communicate with this object")

        // Select protocol suite
        val selectedProtocolSuite = selectProtocolSuite(objectID)
            ?: return Pair(false, "Object does not support any of the required protocol suites")

        val cryptoPlugin =
            getCryptoPlugin(selectedProtocolSuite) ?: return Pair(false, "Failed to get crypto plugin")
        val authPlugin =
            getAuthPlugin(selectedProtocolSuite) ?: return Pair(false, "Failed to get auth plugin")

        // Generate authentication values
        val otpChallenge = cryptoPlugin.generateSecureRandomToken(Constants.OTP_CHALLENGE_BYTES_SIZE)
        print("otpChallenge (${otpChallenge.size}): " + otpChallenge.decodeByteArrayToHexString())
        val sessionKey = generateSessionKey(Constants.SESSION_KEY_BYTES_SIZE, cryptoPlugin)
        print("sessionKey (${sessionKey.size}): " + sessionKey.decodeByteArrayToHexString())
        val otp = generateOTP(objectID, gatewayID, otpChallenge, authPlugin)

        // Create authentication package
        val authenticationPackage =
            generateAuthPackage(objectsCipherKeys[objectID]!!, otpChallenge, sessionKey, cryptoPlugin, authPlugin)

        // Build response (with protocol suites)
        val response = AuthorizationResponse(otp, sessionKey, authenticationPackage, selectedProtocolSuite)

        val gson = Gson()
        // Send response as byte array (mocking network response)
        return Pair(true, gson.toJson(response))
    }

    /*
       Auxiliary function the checks the supported protocol suites of a device and select a preferred one

       Parameters:
           - object_id: string identifying MacAddress of smart object

       Returns:
           - A string representing the selected protocol suite
    */
    private fun selectProtocolSuite(objectID: String): String? {
        val listOfSupportedProtocolSuites = objectsSupportedProtocolSuites[objectID]

        // Iterate through protocol suites by order of preference
        for (protocolSuite in Constants.PROTOCOLS_SUITE_ID.keys) {
            // Check if object support current protocol
            if (listOfSupportedProtocolSuites!!.contains(protocolSuite)) {
                // Select first supported protocol that is found
                return protocolSuite
            }
        }

        return null;
    }

    /*
       Auxiliary function that parses the protocol suite string and retrieves the implementation of the cryptographic protocol

       Parameters:
           - protocolSuite: string representing the protocol suite

       Returns:
           - An object that implements the ICryptographicPlugin interface with the selected protocol
    */
    private fun getCryptoPlugin(protocolSuite: String): ICryptographicPlugin? {
        val cryptoProtocol = protocolSuite.split("_")[0]
        return cryptoPlugins[cryptoProtocol]
    }

    /*
       Auxiliary function that parses the protocol suite string and retrieves the implementation of the authentication protocol

       Parameters:
           - protocolSuite: string representing the protocol suite

       Returns:
           - An object that implements the IAuthenticationPlugin interface with the selected protocol
    */
    private fun getAuthPlugin(protocolSuite: String): IAuthenticationPlugin? {
        val authProtocol = protocolSuite.split("_")[1] + "_" + protocolSuite.split("_")[2]

        return authPlugins[authProtocol]
    }

    /*
       Auxiliary function that builds the authentication package object

       Parameters:
            - cipherKey: ByteArray representing the encrypting key
            - otp: ByteArray representing the generated OTP value
            - sessionKey: ByteArray representing the generated session key value
            - cryptoPlugin: object that implements ICryptographicPlugin interface
            - authPlugin: object that implements IAuthenticationPlugin interface

       Returns:
           - ByteArray that consists of the encrypted authentication package and its signature (HMAC)
    */
    private fun generateAuthPackage(
        cipherKey: ByteArray,
        otpChallenge: ByteArray,
        sessionKey: ByteArray,
        cryptoPlugin: ICryptographicPlugin,
        authPlugin: IAuthenticationPlugin
    ): ByteArray {

        val authPackage = otpChallenge + sessionKey
        print("GeneratedAuthPackage (${authPackage.size}): " + authPackage.decodeByteArrayToHexString())
        val encryptedAuthPackage = cryptoPlugin.encrypt(authPackage, cipherKey)
        print("EncryptedAuthPackage (${encryptedAuthPackage.size}): " + encryptedAuthPackage.decodeByteArrayToHexString())
        val signingKey = cryptoPlugin.generateSecretKey(coreAuthKey)
        val authPackageSignature = authPlugin.sign(encryptedAuthPackage, signingKey)
        print("Signature (${authPackageSignature.size}): " + authPackageSignature.decodeByteArrayToHexString())
        print("SignedAuthPackage (${(encryptedAuthPackage + authPackageSignature).size}): " + (encryptedAuthPackage + authPackageSignature).decodeByteArrayToHexString())
        return encryptedAuthPackage + authPackageSignature
    }

    /*
       Auxiliary function that generates a session key

       Parameters:
            - size: Integer that defines the size of the key
            - cryptoPlugin: object that implements ICryptographicPlugin interface

       Returns:
           - ByteArray that consists of the generated sessionKey
    */
    private fun generateSessionKey(size: Int, cryptoPlugin: ICryptographicPlugin): ByteArray {
        val seed = cryptoPlugin.generateSecureRandomToken(size)
        print("Session Key seed (${seed.size}): " + seed.decodeByteArrayToHexString())
        val sessionKey = cryptoPlugin.generateSecretKey(seed);
        print("Session Key (${sessionKey.encoded.size}): " + sessionKey.encoded.decodeByteArrayToHexString());
        return sessionKey.encoded;
    }

    /*
       Auxiliary function that generates a One Time Password

       Parameters:
            - object: string identifying MacAddress of smart object
            - gatewayID: string identifying MacAddress of gateway
            - otpChallenge: ByteArray representing the generated OTPChallenge value
            - authPlugin: object that implements IAuthenticationPlugin interface


       Returns:
           - ByteArray that consists of the generated One TIme Password
    */
    private fun generateOTP(
        objectID: String,
        gatewayID: String,
        otpChallenge: ByteArray,
        authPlugin: IAuthenticationPlugin
    ): ByteArray {
        val concatenation =
            objectID.encodeToByteArray() + gatewayID.encodeToByteArray() + otpChallenge + objectsAuthKeys[objectID]!!

        print("OTP concat data (${concatenation.size}): " + concatenation.decodeByteArrayToHexString())
        return authPlugin.generateHash(concatenation)
    }

    private fun print(s: String) {
        System.out.println("[EDGESEC-DEBUG-CONTEXTNETCORE] " + s)
    }

    private fun ByteArray.decodeByteArrayToHexString(): String {

        var str: String = "";
        for (b in this) {
            str += String.format("%02X", b)
        }

        return str
    }


}