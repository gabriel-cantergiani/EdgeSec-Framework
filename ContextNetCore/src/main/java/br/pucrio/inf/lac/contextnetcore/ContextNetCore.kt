package br.pucrio.inf.lac.contextnetcore

import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5
import br.pucrio.inf.lac.rc4cryptography.RC4
import com.google.gson.Gson

object ContextNetCore {
    // Mocks the functionalities of the ContextNetCore servers

    private val coreAuthKey = "Kauth_core".encodeToByteArray();

    private val registeredObjects = arrayOf<String>("0879C623C9C8", "607DE22FC767");
    private val objectsAuthKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kauth_Obj1".encodeToByteArray(),
        "607DE22FC767" to "Kauth_Obj2".encodeToByteArray(),
    )
    private val objectsCipherKeys = mapOf<String, ByteArray>(
        "0879C623C9C8" to "Kcipher_Obj1".encodeToByteArray(),
        "607DE22FC767" to "Kcipher_Obj2".encodeToByteArray(),
    )

    private val objectsSupportedProtocolSuites = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("RC4_HMAC_MD5", "AES128_HMAC_MD5"),
        "607DE22FC767" to arrayOf<String>("RC4_HMAC_MD5"),
    )
    private val objectsAuthorizedGateways = mapOf<String, Array<String>>(
        "0879C623C9C8" to arrayOf<String>("736DF76FC9KU", "LK9JD765JKO9"),
        "607DE22FC767" to arrayOf<String>("808DE88FC8TE", "736DF76FC9KU"),
    )

    private var cryptoPlugins = mapOf<String, ICryptographicPlugin>(
        "AES128" to RC4(), // TODO: REPLACE WITH AES128 IMPLEMENTATION
        "RC4" to RC4(),
    )

    private var authPlugins = mapOf<String, IAuthenticationPlugin>(
        "HMAC_SHA1" to HmacMD5(), // TODO: REPLACE WITH AES128 IMPLEMENTATION
        "HMAC_MD5" to HmacMD5(),
    )

    fun authorize(gatewayID: String, objectID: String): Pair<Boolean, String> {

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
        val otpChallenge = cryptoPlugin.generateSecureRandomToken(Constants.OTP_BYTES_SIZE)
        val sessionKey = generateSessionKey(Constants.SESSION_KEY_BYTES_SIZE, cryptoPlugin)
        val otp = generateOTP(objectID, gatewayID, otpChallenge, authPlugin)

        // Create authentication package
        val authenticationPackage =
            generateAuthPackage(objectsCipherKeys[objectID]!!, otp, sessionKey, cryptoPlugin, authPlugin)

        // Build response (with protocol suites)
        val response = AuthorizationResponse(otp, sessionKey, authenticationPackage, selectedProtocolSuite)

        val gson = Gson()
        // Send response as byte array (mocking network response)
        return Pair(true, gson.toJson(response))
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
        val authProtocol = protocolSuite.split("_")[1] + "_" + protocolSuite.split("_")[2]

        return authPlugins[authProtocol]
    }

    private fun generateAuthPackage(
        cipherKey: ByteArray,
        otp: ByteArray,
        sessionKey: ByteArray,
        cryptoPlugin: ICryptographicPlugin,
        authPlugin: IAuthenticationPlugin
    ): ByteArray {

        val authPackage = otp + sessionKey
        val encryptedAuthPackage = cryptoPlugin.encrypt(authPackage, cipherKey)
        val signingKey = cryptoPlugin.generateSecretKey(coreAuthKey)
        val authPackageSignature = authPlugin.sign(encryptedAuthPackage, signingKey)

        return encryptedAuthPackage + authPackageSignature
    }

    private fun generateSessionKey(size: Int, cryptoPlugin: ICryptographicPlugin): ByteArray {
        val seed = cryptoPlugin.generateSecureRandomToken(size)
        val sessionKey = cryptoPlugin.generateSecretKey(seed);
        return sessionKey.encoded;
    }

    private fun generateOTP(
        objectID: String,
        gatewayID: String,
        otpChallenge: ByteArray,
        authPlugin: IAuthenticationPlugin
    ): ByteArray {
        val concatenation =
            objectID.encodeToByteArray() + gatewayID.encodeToByteArray() + otpChallenge + objectsAuthKeys[objectID]!!
        // TODO: MOCKED GENERATE OTP FOR TESTING
        return "MOCKEDOTP".encodeToByteArray()
//        return authPlugin.generateHash(concatenation)
        // MOCKED
    }


}