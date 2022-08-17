package br.pucrio.inf.lac.contextnetcore

import br.pucrio.inf.lac.edgesec.Constants
import br.pucrio.inf.lac.edgesec.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesec.ICryptographicPlugin
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5
import br.pucrio.inf.lac.rc4cryptography.RC4

object ContextNetCore {
    // Mocks the functionalities of the ContextNetCore servers

    val coreAuthKey = "Kauth_core".encodeToByteArray();

    val registeredObjects = arrayOf<String>("0879C623C9C8", "607DE22FC767");
    val objectsAuthKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kauth_Obj1".encodeToByteArray(),
        "607DE22FC767" to "Kauth_Obj2".encodeToByteArray(),
    )
    val objectsCipherKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kcipher_Obj1".encodeToByteArray(),
        "607DE22FC767" to "Kcipher_Obj2".encodeToByteArray(),
    )

    val objectsSupportedProtocolSuites = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("RC4_HMAC_MD5", "AES128_HMAC_MD5"),
        "607DE22FC767" to arrayOf<String>("RC4_HMAC_MD5"),
    )
    val objectsAuthorizedGateways = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("736DF76FC9KU", "LK9JD765JKO9"),
        "607DE22FC767" to arrayOf<String>("808DE88FC8TE", "736DF76FC9KU"),
    )

    var cryptoPlugins = mapOf<String, ICryptographicPlugin>(
        "AES128" to RC4(), // TODO: REPLACE WITH AES128 IMPLEMENTATION
        "RC4" to RC4(),
    )

    var authPlugins = mapOf<String, IAuthenticationPlugin>(
        "HMAC_SHA1" to HmacMD5(), // TODO: REPLACE WITH AES128 IMPLEMENTATION
        "HMAC_MD5" to HmacMD5(),
    )

    fun authorize(gatewayID: String, objectID: String): ByteArray {
        // Validate if devices are authorized
        if (!objectsAuthorizedGateways.containsKey(objectID))
            throw Exception("Object is not registered in ContextNetCore")

        if (!objectsAuthorizedGateways[objectID]!!.contains(gatewayID))
            throw Exception("Gateway is not authorized to communicate with this object")

        // Select protocol suite
        val selectedProtocolSuite = selectProtocolSuite(objectID)
            ?: throw Exception("Object does not support any of the required protocol suites")

        val cryptoPlugin = getCryptoPlugin(selectedProtocolSuite) ?: throw Exception("Failed to get crypto plugin")
        val authPlugin = getAuthPlugin(selectedProtocolSuite) ?: throw Exception("Failed to get auth plugin")

        // Create authentication package
        val authenticationPackage = generateAuthPackage(objectID, gatewayID, cryptoPlugin, authPlugin)

        // Build response (with protocol suites)
        val response = authenticationPackage + Constants.PROTOCOLS_SUITE_ID[selectedProtocolSuite]!!

        // Send response as byte array (mocking network response)
        return response
    }

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

    private fun getCryptoPlugin(protocolSuite: String): ICryptographicPlugin? {
        val cryptoProtocol = protocolSuite.split("_")[0]
        return cryptoPlugins[cryptoProtocol]
    }

    private fun getAuthPlugin(protocolSuite: String): IAuthenticationPlugin? {
        val authProtocol = protocolSuite.split("_")[1] + protocolSuite.split("_")[2]
        return authPlugins[authProtocol]
    }

    private fun generateAuthPackage(
        objectID: String,
        gatewayID: String,
        cryptoPlugin: ICryptographicPlugin,
        authPlugin: IAuthenticationPlugin
    ): ByteArray {

        val otpChallenge = cryptoPlugin.generateSecureRandomToken(Constants.OTP_BYTES_SIZE)
        val sessionKey = generateSessionKey(Constants.SESSION_KEY_BYTES_SIZE, cryptoPlugin)
        val otp = generateOTP(objectID, gatewayID, otpChallenge, authPlugin)

        val authPackage = otp + sessionKey
        val encryptedAuthPackage = cryptoPlugin.encrypt(authPackage, objectsCipherKeys[objectID]!!)
        val authPackageSignature = authPlugin.sign(encryptedAuthPackage, coreAuthKey)

        return encryptedAuthPackage + authPackageSignature
    }

    private fun generateSessionKey(size: Int, cryptoPlugin: ICryptographicPlugin): ByteArray {
        val seed = cryptoPlugin.generateSecureRandomToken(size)
        val sessionKey = cryptoPlugin.generateSecretKey(seed);
        return sessionKey;
    }

    private fun generateOTP(objectID: String, gatewayID: String, otpChallenge: ByteArray, authPlugin: IAuthenticationPlugin): ByteArray {
        val concatenation = objectID.encodeToByteArray() + gatewayID.encodeToByteArray() + otpChallenge + objectsAuthKeys[objectID]!!
        val otp = authPlugin.generateHash(concatenation)
        return otp
    }


}