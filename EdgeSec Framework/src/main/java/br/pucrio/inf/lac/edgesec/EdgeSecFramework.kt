/*
Module: EdgeSecFramework.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.contextnetcore.ContextNetCore
import br.pucrio.inf.lac.contextnetcore.IAuthorizationProvider
import br.pucrio.inf.lac.edgesec.Utils.Companion.decodeByteArrayToHexString
import br.pucrio.inf.lac.edgesec.Utils.Companion.encodeToByteArray
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import io.reactivex.Observable
import io.reactivex.Single
import java.util.*

/*
Class: EdgeSecFramework
Description: Main class for EdgeSecFramework framework.
Implements IEdgeSec interface and provides all functionalities to establish a secure connectio and exchange of data
 */
class EdgeSecFramework() : IEdgeSec {

    private val TAG = "EdgeSecFramework"
    private val EdgeSecVersion = "1.0"
    private var gatewayID: String = "ID_GATEWAY"
    private var transportPlugin: ITransportPlugin? = null
    private var cryptoPlugins: ArrayList<ICryptographicPlugin>? = null
    private var authPlugins: ArrayList<IAuthenticationPlugin>? = null
    private var selectedCryptoPlugin: ICryptographicPlugin? = null
    private var selectedAuthPlugin: IAuthenticationPlugin? = null

    private var authorization: Authorization? = null
    private var secureConnections: MutableMap<String, SecureConnection>? = null

    // Variables used for Profiling
    private var timingSecureConnectStart: Long = 0
    private var timingConnectFinish: Long = 0
    private var timingHandshakeHelloStart: Long = 0
    private var timingHandshakeHelloFinish: Long = 0
    private var timingHandshakeResponseStart: Long = 0
    private var timingHandshakeResponseFinish: Long = 0
    private var timingAuthorizationStart: Long = 0
    private var timingAuthorizationFinish: Long = 0
    private var timingCreateHelloMessageStart: Long = 0
    private var timingCreateHelloMessageFinish: Long = 0
    private var timingSendHelloMessageStart: Long = 0
    private var timingSendHelloMessageFinish: Long = 0
    private var timingReadHelloMessageResponseStart: Long = 0
    private var timingReadHelloMessageResponseFinish: Long = 0
    private var timingVerifyHelloMessageStart: Long = 0
    private var timingVerifyHelloMessageFinish: Long = 0
    private var timingSecureConnectFinish: Long = 0
    private var timingSecureReadStart: Long = 0
    private var timingSecureReadReceived: Long = 0
    private var timingSecureReadVerifyStart: Long = 0
    private var timingSecureReadFinish: Long = 0

    init {
    }

    fun print(s: String) {
        System.out.println("[EDGESEC-DEBUG-$TAG] " + s)
    }

    /*
       Set up EdgeSecFramework framework initializing main variables

       Parameters:
           - gatewayID: string identifying MacAddress of gateway
           - transportPlugin: Object that implements ITransportPlugin interface
           - cryptoPlugin: Array of objects that implements ICryptographicPlugin interface
           - authPlugin: Array of objects that implements IAuthenticationPlugin interface

    */
    override fun initialize(
        gatewayID: String,
        transportPlugin: ITransportPlugin,
        cryptoPlugins: ArrayList<ICryptographicPlugin>,
        authPlugins: ArrayList<IAuthenticationPlugin>
    ) {

        // Store parameters in class variables
        if (gatewayID.length != Constants.GATEWAY_ID_BYTES_SIZE) {
            throw Exception("Invalid gateway ID: should be of size :" + Constants.GATEWAY_ID_BYTES_SIZE + ". actual size is: " + gatewayID.length)
        }
        this.gatewayID = gatewayID
        this.transportPlugin = transportPlugin

        if (cryptoPlugins.size < 1)
            throw Exception("Invalid crypto plugin list. Should have at least one plugin")

        this.cryptoPlugins = cryptoPlugins

        if (authPlugins.size < 1)
            throw Exception("Invalid auth plugin list. Should have at least one plugin")

        this.authPlugins = authPlugins

        // Initialize classes and wrappers
        this.authorization = Authorization(ContextNetCore)

        // Initialize internal variables
        this.secureConnections = mutableMapOf<String, SecureConnection>()
    }

    /*
        Search for devices nearby that are compatible with EdgeSecFramework using transport protocol

        Returns:
             - Observable that emits strings representing the MacAddress of devices that are found
     */
    override fun searchDevices(): Observable<String> {

        // Check if transport plugin is set
        this.transportPlugin ?: throw Exception("Transport Plugin not initialized")

        // Call transport plugin to scan for compatible devices
        return this.transportPlugin!!.scanDevices()
    }

    /*
    Tries to connect with device, perform handshake and start authentication process. If succeeded, device will be connected securely.

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits true if connection was succeeded and false otherwise
     */
    @Suppress("CheckResult")
    override fun secureConnect(deviceID: String): Single<Boolean> {

        // Verify if plugins are correctly set
        this.transportPlugin ?: throw Exception("Transport plugin not initialized")
        this.authPlugins ?: throw Exception("Authentication plugins not initialized")
        this.cryptoPlugins ?: throw Exception("Cryptographic plugins not initialized")

        timingSecureConnectStart = System.currentTimeMillis()
        return Single.create { emitter ->
            // Try to connect and perform EdgeSecFramework handshake to negotiate authentication and cryptographic protocols
            this.connectAndHandshake(deviceID).subscribe({
                val objectID = it

                timingAuthorizationStart = System.currentTimeMillis()
                // Invoke Authorization class to verify if connection is allowed
                val authorizationResponse =
                    this.authorization?.verifyAuthorization(this.gatewayID, objectID)

                timingAuthorizationFinish = System.currentTimeMillis()
                if (authorizationResponse == null)
                    emitter.onError(Exception("Failed to get authorization from Core"))
                else {
                    val authenticationPackage = buildAuthenticationPackage(
                        authorizationResponse.protocolSuite,
                        authorizationResponse.authenticatioPackage,
                        authorizationResponse.OTP,
                        authorizationResponse.sessionKey
                    )

                    print("OTP (${authenticationPackage.OTP.size}): " + authenticationPackage.OTP.decodeByteArrayToHexString())
                    print("SessionKey (${authenticationPackage.SessionKey.size}): " + authenticationPackage.SessionKey.decodeByteArrayToHexString())
                    print("Timestamp (${authenticationPackage.messageTimestamp.size}): " + authenticationPackage.messageTimestamp.decodeByteArrayToHexString())
                    print("Signed Auth Package (${authenticationPackage.signedAuthPackage.size}): " + authenticationPackage.signedAuthPackage.decodeByteArrayToHexString())
                    print("Protocol suite: " + authenticationPackage.protocolSuite)

                    // Set plugins
                    setPlugins(authenticationPackage.protocolSuite)

                    if (selectedAuthPlugin == null || selectedCryptoPlugin == null)
                        emitter.onError(Exception("Plugins not supported by smart object"))
                    else {
                        timingCreateHelloMessageStart = System.currentTimeMillis()
                        // Get helloMessage
                        val signedHelloMessage = createHelloMessage(authenticationPackage)
                        print("SignedHelloMessage (${signedHelloMessage.size}): " + signedHelloMessage.decodeByteArrayToHexString())
                        timingCreateHelloMessageFinish = System.currentTimeMillis()

                        // Send Hello Message
                        exchangeHelloMessage(deviceID, signedHelloMessage).subscribe({
                            val helloMessageResponse = it
                            print("HelloMessageResponse: " + helloMessageResponse!!.decodeByteArrayToHexString())

                            timingVerifyHelloMessageStart = System.currentTimeMillis()
                            // Invoke AuthenticatioPlugin to verify HelloMessageResponse
                            val success =
                                verifyHelloMessageResponse(
                                    objectID,
                                    authenticationPackage,
                                    helloMessageResponse
                                )
                            timingVerifyHelloMessageFinish = System.currentTimeMillis()
                            if (!success) {
                                emitter.onError(Exception("Invalid HelloMessageResponse from device"))
                            } else {
                                print("HelloMessageResponse validated successfully")

                                timingSecureConnectFinish = System.currentTimeMillis()
                                // Create SecureConnection class and add it to cache
                                val newSecureConnection =
                                    SecureConnection(
                                        objectID,
                                        authenticationPackage.SessionKey,
                                        authenticationPackage.OTP
                                    )
                                setSecureConnection(deviceID, newSecureConnection)
                                calculate_auth_time_performance()
                                emitter.onSuccess(true)
                            }
                        }, { emitter.onError(it) })
                    }
                }
            }, { emitter.onError(it) })
        }
    }

    /*
    Reads data securely from connected and authenticated device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits a ByteArray with the data read
     */
    @Suppress("CheckResult")
    override fun secureRead(deviceID: String): Single<ByteArray> {

        print("Starting secure read")
        // Verify if device is connected and authenticated
        val secureConnection = secureConnections?.get(deviceID) ?: return Single.create{emitter -> emitter.onError(Exception("Device not connected and authenticated"))}

        print("Retrieved connection")
        // Invoke TransportPlugin to read data from device
        return Single.create { emitter ->
            timingSecureReadStart = System.currentTimeMillis()
            transportPlugin!!.readData(deviceID).subscribe({
                print("Data read")
                timingSecureReadReceived = System.currentTimeMillis()
                if (it == null) {
                    print("Data is null")
                    emitter.onError(Exception("Failed to read data from device"))
                } else {
                    print("Data is not null. Starting to verify it")
                    val message = it
                    print("Message: " + message.decodeByteArrayToHexString())
                    val signatureSize = selectedAuthPlugin!!.getHashSize()
                    print("Signature Size: " + signatureSize)
                    val divisionIndex = message.size - signatureSize
                    val encryptedData = message.slice(IntRange(0, divisionIndex - 1)).toByteArray()
                    print("Encrypted Data: " + encryptedData.decodeByteArrayToHexString())
                    val signature =
                        message.slice(IntRange(divisionIndex, message.size - 1)).toByteArray()
                    print("Signature: " + signature.decodeByteArrayToHexString())
                    val signingKey = selectedCryptoPlugin!!.generateSecretKey(secureConnection.otp)
                    print("signing Key: " + signingKey.encoded.decodeByteArrayToHexString())


                    timingSecureReadVerifyStart = System.currentTimeMillis()
                    print("Verifying signature...")
                    // Invoke AuthenticationPlugin to verify message signature
                    if (!selectedAuthPlugin!!.verifySignature(
                            encryptedData,
                            signingKey,
                            signature
                        )
                    ) {
                        print("Error verifying it")
                        emitter.onError(Exception("Failed to validate message signature"))
                    }

                    print("Verified successfully. Decrypting data...")
                    print("Session key: " + secureConnection.sessionKey.decodeByteArrayToHexString())
                    // Invoke CryptographyPlugin to decrypt message
                    val decryptedData =
                        selectedCryptoPlugin!!.decrypt(encryptedData, secureConnection.sessionKey)

                    timingSecureReadFinish = System.currentTimeMillis()
                    print("Decrypted data: " + decryptedData.decodeToString())
                    calculate_read_time_performance()
                    // Emit message value
                    emitter.onSuccess(decryptedData)
                }
            }, {
                print("Error reading data...")
                emitter.onError(it) })
        }
    }

    /*
    Writes data securely to connected and authenticated device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits true if write was succeeded and false otherwise
     */
    override fun secureWrite(deviceID: String, data: ByteArray): Single<Boolean> {

        // Verify if device is connected and authenticated
        val secureConnection = secureConnections?.get(deviceID) ?: return Single.just(false)

        // Invoke CryptographyPlugin to encrypt message
        val encryptedData = selectedCryptoPlugin!!.encrypt(data, secureConnection.sessionKey)

        // Invoke AuthenticationPlugin to sign message
        val signingKey = selectedCryptoPlugin!!.generateSecretKey(secureConnection.otp)
        val signature = selectedAuthPlugin!!.sign(encryptedData, signingKey)

        val message = encryptedData + signature
        // Invoke TransportPlugin to send message
        return transportPlugin!!.writeData(deviceID, message)
    }

    /*
    Disconnects from a connected device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect
     */
    override fun disconnect(deviceID: String) {
        // Disconnect using Transport Plugin
        transportPlugin?.disconnect(deviceID)

        // Remove from connections cache
        secureConnections?.remove(deviceID);
    }


    /*
    Auxiliary function that connects and exchange handshake messages with device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits a string identifying the authentication ID of the Smart Object
     */
    @Suppress("CheckResult")
    private fun connectAndHandshake(deviceID: String): Single<String> {

        return Single.create { emitter ->
            // Connect
            this.transportPlugin!!.connect(deviceID).subscribe(
                { connectResult ->
                    timingConnectFinish = System.currentTimeMillis()
                    if (connectResult == false) {
                        emitter.onError(Exception("Failed to connect to device - security service not found"))
                    } else {
                        print("Starting handshake")

                        // Build HandshakeHello message with EdgeSecVersion + gateway ID
                        val version = this.EdgeSecVersion.encodeToByteArray()
                        val gatewayID = this.gatewayID.encodeToByteArray()
                        val handshakeHelloMessage: ByteArray = version + gatewayID

                        print("Sending handshake: " + handshakeHelloMessage.decodeByteArrayToHexString())

                        timingHandshakeHelloStart = System.currentTimeMillis()
                        //Send HandshakeHello message
                        this.transportPlugin!!.sendHandshakeHello(deviceID, handshakeHelloMessage)
                            .subscribe(
                                { handShakeHelloResult ->
                                    timingHandshakeHelloFinish = System.currentTimeMillis()
                                    if (!handShakeHelloResult)
                                        emitter.onError(Exception("Failed to send handshakeHello"))
                                    else {
                                        print("Handshake sent")

                                        // Invoke TransportPlugin to read message from device with following content:
                                        // - ID do objeto

                                        timingHandshakeResponseStart = System.currentTimeMillis()
                                        // Read HandshakeHello response
                                        this.transportPlugin!!.readHandshakeResponse(deviceID)
                                            .subscribe(
                                                { handshakeResponse ->
                                                    timingHandshakeResponseFinish = System.currentTimeMillis()
                                                    var lastIndexRead = 0

                                                    // Get Device Authentication ID
                                                    val objectID: String =
                                                        handshakeResponse!!.slice(
                                                            IntRange(
                                                                lastIndexRead,
                                                                lastIndexRead + Constants.DEVICE_ID_BYTES_SIZE - 1
                                                            )
                                                        ).toByteArray().decodeToString()
                                                    lastIndexRead += Constants.DEVICE_ID_BYTES_SIZE

                                                    print("objectID: " + objectID)
                                                    emitter.onSuccess(objectID)
                                                },
                                                { emitter.onError(Exception("Failed to read handshakeHelloResponse: " + it.message)) }
                                            )
                                    }
                                },
                                { emitter.onError(Exception("Failed to send handshakeHello: " + it.message)) }
                            )
                    }

                }, { emitter.onError(Exception("Failed to connect to device: " + it.message)) }
            )
        }
    }

    /*
    Auxiliary function that builds hello message

    Parameters:
        - authenticationPackage: AuthenticationPackage object

    Returns:
        - ByteArray with helloMessage as content
     */
    private fun createHelloMessage(authenticationPackage: AuthenticationPackage): ByteArray {

        val helloMessage =
            authenticationPackage.signedAuthPackage + authenticationPackage.messageTimestamp
        print("helloMessage (${helloMessage.size}): " + helloMessage.decodeByteArrayToHexString())
        val key = selectedCryptoPlugin!!.generateSecretKey(authenticationPackage.OTP)

        return helloMessage + selectedAuthPlugin!!.sign(this.gatewayID.encodeToByteArray() + helloMessage, key)
    }

    /*
    Auxiliary function that exchange hello message with device

    Parameters:
        - deviceID: String identifying MacAddress of device
        - helloMessage: ByteArray with hello message as content

    Returns:
        - Observable that emits a ByteArray with the helloMessageResponse as content
     */
    @Suppress("CheckResult")
    private fun exchangeHelloMessage(
        deviceID: String,
        helloMessage: ByteArray
    ): Single<ByteArray?> {
        // Invoke TransportPlugin to send hellomessage
        return Single.create { emitter ->
            timingSendHelloMessageStart = System.currentTimeMillis()
            transportPlugin!!.sendHelloMessage(deviceID, helloMessage).subscribe({
                timingSendHelloMessageFinish = System.currentTimeMillis()
                if (!it)
                    emitter.onError(Exception("Failed to send helloMessage"))
                else {
                    timingReadHelloMessageResponseStart = System.currentTimeMillis()
                    // Invoke TransportPlugin to read HelloMessage response
                    transportPlugin!!.readHelloMessageResponse(deviceID).subscribe({
                        timingReadHelloMessageResponseFinish = System.currentTimeMillis()
                        if (it != null) {
                            emitter.onSuccess(it)
                        } else {
                            emitter.onError(Exception("Failed to read helloMessageResponse"))
                        }
                    }, { emitter.onError(Exception("Failed to read helloMessageResponse: " + it.message))})
                }
            }, { emitter.onError(Exception("Failed to send helloMessage: " + it.message)) })
        }
    }

    /*
    Auxiliary function verify signature of hello message response

    Parameters:
        - objectID: String identifying authentication ID of smart object
        - authenticationPackage: AuthenticationPackage object
        - responseToBeVerified: ByteArray with the helloMessageResponse

    Returns:
        - true in case response is valid, false otherwise
     */
    private fun verifyHelloMessageResponse(
        objectID: String,
        authenticationPackage: AuthenticationPackage,
        responseToBeVerified: ByteArray
    ): Boolean {
        var responseContent = ByteArray(0)

        responseContent += gatewayID.encodeToByteArray()
        responseContent += objectID.encodeToByteArray()
        responseContent += authenticationPackage.messageTimestamp

        val key = selectedCryptoPlugin!!.generateSecretKey(authenticationPackage.OTP)

        return selectedAuthPlugin!!.verifySignature(responseContent, key, responseToBeVerified)
    }

    /*
    Auxiliary function builds authentication package object

    Parameters:
        - protocolSuite: String identifying protocol suite
        - signedAuthPackage: ByteArray representing signed authentication package
        - OTP: ByteArray representing One Time Password
        - sessionKey: ByteArray representing session key

    Returns:
        - Authentication Package Object
     */
    private fun buildAuthenticationPackage(
        protocolSuite: String,
        signedAuthPackage: ByteArray,
        OTP: ByteArray,
        sessionKey: ByteArray
    ): AuthenticationPackage {
        // Generate timestamp
        val timestamp = (System.currentTimeMillis() / 1000).toInt().encodeToByteArray()

        return AuthenticationPackage(protocolSuite, signedAuthPackage, OTP, sessionKey, timestamp)

    }

    /*
    Auxiliary function that parse protocol suite string and set the selected plugins

    Parameters:
        - protocolSuite: String identifying protocol suite

     */
    private fun setPlugins(protocolSuite: String) {
        val cryptoProtocol = protocolSuite.split("_")[0]
        val authProtocol = protocolSuite.split("_")[1] + "_" + protocolSuite.split("_")[2]

        selectedAuthPlugin = null
        selectedCryptoPlugin = null

        for (selectedPlugin in authPlugins!!) {
            if (authProtocol == selectedPlugin.getProtocolID()) {
                selectedAuthPlugin = selectedPlugin
            }
        }

        for (selectedPlugin in cryptoPlugins!!) {
            if (cryptoProtocol == selectedPlugin.getProtocolID()) {
                selectedCryptoPlugin = selectedPlugin
            }
        }
    }

    internal fun calculate_auth_time_performance() {
        print("[TIME] Basic Connected: " + (timingConnectFinish - timingSecureConnectStart) )
        print("[TIME] Send handshake hello: " + (timingHandshakeHelloFinish - timingHandshakeHelloStart) )
        print("[TIME] Read handshake response: " + (timingHandshakeResponseFinish - timingHandshakeResponseStart) )
        print("[TIME] Create Hello Message: " + (timingCreateHelloMessageFinish - timingCreateHelloMessageStart) )
        print("[TIME] Send Hello Message: " + (timingSendHelloMessageFinish - timingSendHelloMessageStart) )
        print("[TIME] Receive Hello Message Response: " + (timingReadHelloMessageResponseFinish - timingReadHelloMessageResponseStart) )
        print("[TIME] Verify Hello Message: " + (timingVerifyHelloMessageFinish - timingVerifyHelloMessageStart) )
        print("[TIME] Total time to authenticate: " + (timingSecureConnectFinish - timingConnectFinish) )
        print("[TIME] Total time to connect and authenticate: " + (timingSecureConnectFinish - timingSecureConnectStart) )
    }

    internal fun calculate_read_time_performance() {
        print("[TIME] Secure Read Received: " + (timingSecureReadReceived - timingSecureReadStart) )
        print("[TIME] Verify Secure Read: " + (timingSecureReadFinish - timingSecureReadVerifyStart) )
        print("[TIME] Total time to secure read: " + (timingSecureReadFinish - timingSecureReadStart) )
    }

    internal fun setAuthorizationProvider(provider: IAuthorizationProvider) {
        this.authorization?.authorizationProvider = provider
    }

    internal fun setSecureConnection(deviceID: String, conn: SecureConnection) {
        this.secureConnections?.put(deviceID, conn)
    }
}