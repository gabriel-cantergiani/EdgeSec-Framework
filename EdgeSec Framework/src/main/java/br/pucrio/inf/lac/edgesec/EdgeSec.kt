/*
Module: EdgeSec.kt
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
Class: EdgeSec
Description: Main class for EdgeSec framework.
Implements IEdgeSec interface and provides all functionalities to establish a secure connectio and exchange of data
 */
class EdgeSec() : IEdgeSec {

    private val TAG = "EdgeSec"
    private val EdgeSecVersion = "1.0"
    private var gatewayID: String = ""
    private var transportPlugin: ITransportPlugin? = null
    private var cryptoPlugins: ArrayList<ICryptographicPlugin>? = null
    private var authPlugins: ArrayList<IAuthenticationPlugin>? = null
    private var selectedCryptoPlugin: ICryptographicPlugin? = null
    private var selectedAuthPlugin: IAuthenticationPlugin? = null

    private var authorization: Authorization? = null
    private var secureConnections: MutableMap<String, SecureConnection>? = null

    init {
    }

    fun print(s: String) {
        System.out.println("[EDGESEC-DEBUG-$TAG] " + s)
    }

    /*
       Set up EdgeSec framework initializing main variables

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
        Search for devices nearby that are compatible with EdgeSec using transport protocol

        Returns:
             - Observable that emits strings representing the MacAddress of devices that are found
     */
    override fun searchDevices(): Observable<String> {

        // Check if transport plugin is set
        this.transportPlugin ?: throw Exception("Transport Plugin not initialized")

        // Call transport plugin to scan for compatible devices
        return this.transportPlugin!!.scanForCompatibleDevices()
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


        return Single.create { emitter ->
            // Try to connect and perform EdgeSec handshake to negotiate authentication and cryptographic protocols
            this.connectAndHandshake(deviceID).subscribe({
                val objectID = it

                // Invoke Authorization class to verify if connection is allowed
                val authorizationResponse =
                    this.authorization?.verifyAuthorization(this.gatewayID, objectID)

                if (authorizationResponse == null)
                    emitter.onError(Exception("Failed to get authorization from Core"))
                else {
                    val authenticationPackage = buildAuthenticationPackage(
                        authorizationResponse.protocolSuite,
                        authorizationResponse.authenticatioPackage,
                        authorizationResponse.OTP,
                        authorizationResponse.sessionKey
                    )

                    print("OTP: " + authenticationPackage.OTP.decodeByteArrayToHexString())
                    print("SessionKey: " + authenticationPackage.SessionKey.decodeByteArrayToHexString())
                    print("Timestamp: " + authenticationPackage.messageTimestamp.decodeByteArrayToHexString())
                    print("Signed Auth Package: " + authenticationPackage.signedAuthPackage.decodeByteArrayToHexString())
                    print("Protocol suite: " + authenticationPackage.protocolSuite)

                    // Set plugins
                    setPlugins(authenticationPackage.protocolSuite)

                    if (selectedAuthPlugin == null || selectedCryptoPlugin == null)
                        emitter.onError(Exception("Plugins not supported by smart object"))
                    else {
                        // Get helloMessage
                        val signedHelloMessage = createHelloMessage(authenticationPackage)
                        print("HelloMessage: " + signedHelloMessage.decodeByteArrayToHexString())

                        // Send Hello Message
                        exchangeHelloMessage(deviceID, signedHelloMessage).subscribe({
                            val helloMessageResponse = it
                            print("HelloMessageResponse: " + helloMessageResponse!!.decodeByteArrayToHexString())

                            // Invoke AuthenticatioPlugin to verify HelloMessageResponse
                            val success =
                                verifyHelloMessageResponse(
                                    objectID,
                                    authenticationPackage,
                                    helloMessageResponse!!
                                )
                            if (!success) {
                                emitter.onError(Exception("Invalid HelloMessageResponse from device"))
                            } else {
                                print("HelloMessageResponse validated successfully")

                                // Create SecureConnection class and add it to cache
                                val newSecureConnection =
                                    SecureConnection(
                                        objectID,
                                        authenticationPackage.SessionKey,
                                        authenticationPackage.OTP
                                    )
                                setSecureConnection(deviceID, newSecureConnection)

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

        // Verify if device is connected and authenticated
        val secureConnection = secureConnections?.get(deviceID) ?: return Single.create{emitter -> emitter.onError(Exception("Device not connected and authenticated"))}

        // Invoke TransportPlugin to read data from device
        return Single.create { emitter ->
            transportPlugin!!.readData(deviceID).subscribe({
                if (it == null) {
                    emitter.onError(Exception("Failed to read data from device"))
                } else {
                    val message = it!!
                    val signatureSize = selectedAuthPlugin!!.getHashSize()
                    val divisionIndex = message.size - signatureSize
                    val encryptedData = message.slice(IntRange(0, divisionIndex)).toByteArray()
                    val signature =
                        message.slice(IntRange(divisionIndex, message.size)).toByteArray()
                    val signingKey = selectedCryptoPlugin!!.generateSecretKey(secureConnection.otp)


                    // Invoke AuthenticationPlugin to verify message signature
                    if (!selectedAuthPlugin!!.verifySignature(
                            encryptedData,
                            signingKey,
                            signature
                        )
                    ) {
                        emitter.onError(Exception("Failed to validate message signature"))
                    }

                    // Invoke CryptographyPlugin to decrypt message
                    val decryptedData =
                        selectedCryptoPlugin!!.decrypt(encryptedData, secureConnection.sessionKey)

                    // Emit message value
                    emitter.onSuccess(decryptedData)
                }
            }, { emitter.onError(it) })
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
                {
                    if (it === false) {
                        emitter.onError(Exception("Failed to connect to device"))
                    } else {
                        print("Starting handshake")

                        // TODO: Review verifyCompatibility
                        // Use transport plugin to verify if device is compatible with EdgeSec
                        //        if (!this.transportPlugin!!.verifyDeviceCompatibility(deviceID))
                        //            throw Exception("Device is not compatible with EdgeSec");

                        // Build HandshakeHello message with EdgeSecVersion + gateway ID
                        val version = this.EdgeSecVersion.encodeToByteArray()
                        val gatewayID = this.gatewayID.encodeToByteArray()
                        val handshakeHelloMessage: ByteArray = version + gatewayID

                        print("Sending handshake: " + handshakeHelloMessage.decodeByteArrayToHexString())

                        //Send HandshakeHello message
                        this.transportPlugin!!.sendHandshakeHello(deviceID, handshakeHelloMessage)
                            .subscribe(
                                {
                                    if (!it)
                                        emitter.onError(Exception("Failed to send handshakeHello"))
                                    else {
                                        print("Handshake sent")

                                        // Invoke TransportPlugin to read message from device with following content:
                                        // - ID do objeto

                                        // Read HandshakeHello response
                                        this.transportPlugin!!.readHandshakeResponse(deviceID)
                                            .subscribe(
                                                { it ->
                                                    val handshakeResponse = it
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

        val key = selectedCryptoPlugin!!.generateSecretKey(authenticationPackage.OTP)

        return selectedAuthPlugin!!.sign(helloMessage, key)
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
            transportPlugin!!.sendHelloMessage(deviceID, helloMessage).subscribe({
                if (!it)
                    emitter.onError(Exception("Failed to send helloMessage"))
                else {
                    // Invoke TransportPlugin to read HelloMessage response
                    transportPlugin!!.readHelloMessageResponse(deviceID).subscribe({
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

    internal fun setAuthorizationProvider(provider: IAuthorizationProvider) {
        this.authorization?.authorizationProvider = provider
    }

    internal fun setSecureConnection(deviceID: String, conn: SecureConnection) {
        this.secureConnections?.put(deviceID, conn)
    }
}