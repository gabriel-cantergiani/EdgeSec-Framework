package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.contextnetcore.AuthorizationResponse
import br.pucrio.inf.lac.contextnetcore.IAuthorizationProvider
import org.junit.jupiter.api.Assertions.*
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import com.google.gson.Gson
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.observers.TestObserver
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.mockito.kotlin.any
import org.mockito.kotlin.whenever
import javax.crypto.spec.SecretKeySpec

internal class EdgeSecFrameworkTest {

    private val edgeSecFramework: EdgeSecFramework = EdgeSecFramework()
    var transportPluginMock: ITransportPlugin? = null
    var authPluginMock: IAuthenticationPlugin? = null
    var cryptoPluginMock: ICryptographicPlugin? = null
    var gatewayID = "ID_GATEWAY"
    var authPlugins = arrayListOf<IAuthenticationPlugin>()
    var cryptoPlugins = arrayListOf<ICryptographicPlugin>()

    @BeforeEach
    fun setUp() {
        transportPluginMock = mock<ITransportPlugin> {
            on { scanDevices() } doReturn Observable.just("mockedDeviceID")
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
        }

        gatewayID = "ID_GATEWAY"
        authPlugins = arrayListOf(authPluginMock!!)
        cryptoPlugins = arrayListOf(cryptoPluginMock!!)

    }

    @AfterEach
    fun tearDown() {
    }

    @Test
    fun initializeInvalidParameters() {
        gatewayID = "shortID"
        var exception = assertThrows(Exception::class.java) {
            edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        }

        assertEquals(
            "Invalid gateway ID: should be of size :" + Constants.GATEWAY_ID_BYTES_SIZE + ". actual size is: " + gatewayID.length,
            exception.message
        )

        gatewayID = "ID_GATEWAY"
        exception = assertThrows(Exception::class.java) {
            edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(), authPlugins)
        }

        assertEquals(
            "Invalid crypto plugin list. Should have at least one plugin",
            exception.message
        )

        exception = assertThrows(Exception::class.java) {
            edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, arrayListOf())
        }

        assertEquals(
            "Invalid auth plugin list. Should have at least one plugin",
            exception.message
        )
    }

    @Test
    fun initializeAllParametersValid() {
        assertDoesNotThrow {
            edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        }
    }

    @Test
    fun searchDevices() {

        val subscriber = TestObserver<String>()

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.searchDevices().subscribe(subscriber)

        subscriber.assertComplete()
        subscriber.assertNoErrors()
        subscriber.assertValueCount(1)
        val results = subscriber.values()
        assertEquals(results[0], "mockedDeviceID")
    }

    @Test
    fun secureConnectWithoutInitialize() {
        var exception = assertThrows(Exception::class.java) {
            edgeSecFramework.secureConnect("mockedID")
        }
        assertEquals("Transport plugin not initialized", exception.message)
    }

    @Test
    fun secureConnectConnectionError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(false)
        }

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to connect to device - security service not found")
    }

    @Test
    fun secureConnectSendHandshakeHelloError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(false)
        }

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to send handshakeHello")
    }

    @Test
    fun secureConnectReadHandshakeResponseError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.create{emitter -> emitter.onError(Exception("Device is not connected and authenticated"))}
        }

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to read handshakeHelloResponse: Device is not connected and authenticated")
    }

    @Test
    fun secureConnectAuthorizationResponseError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
        }

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(false, "testJSON"))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to get authorization from Core")
    }

    @Test
    fun secureConnectInvalidPluginError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
        }

        val authorizationResponse = AuthorizationResponse(ByteArray(0), ByteArray(0), ByteArray(0), "RANDOM_PROTOCOL_SUITE")
        val gson = Gson()


        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Plugins not supported by smart object")
    }

    @Test
    fun secureConnectSendHelloMessageError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
            on { sendHelloMessage(any(), any()) } doReturn  Single.just(false)
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
            on { sign(any(), any()) } doReturn "signature".encodeToByteArray()
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
            on { generateSecretKey(any()) } doReturn SecretKeySpec("key".encodeToByteArray(), "RC4")
        }

        val authorizationResponse = AuthorizationResponse("OTP".encodeToByteArray(), "SESSIONKEY".encodeToByteArray(), "AUTHPACK".encodeToByteArray(), "RC4_HMAC_MD5")
        val gson = Gson()

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(cryptoPluginMock!!), arrayListOf(authPluginMock!!))
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to send helloMessage")
    }

    @Test
    fun secureConnectReadHelloMessageResponseError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
            on { sendHelloMessage(any(), any()) } doReturn  Single.just(true)
            on { readHelloMessageResponse(any()) } doReturn  Single.create{emitter -> emitter.onError(Exception("Error"))}
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
            on { sign(any(), any()) } doReturn "signature".encodeToByteArray()
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
            on { generateSecretKey(any()) } doReturn SecretKeySpec("key".encodeToByteArray(), "RC4")
        }

        val authorizationResponse = AuthorizationResponse("OTP".encodeToByteArray(), "SESSIONKEY".encodeToByteArray(), "AUTHPACK".encodeToByteArray(), "RC4_HMAC_MD5")
        val gson = Gson()

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(cryptoPluginMock!!), arrayListOf(authPluginMock!!))
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to read helloMessageResponse: Error")
    }

    @Test
    fun secureConnectInvalidResponseError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()
        val hmResponse = "helloMessageResponse".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
            on { sendHelloMessage(any(), any()) } doReturn  Single.just(true)
            on { readHelloMessageResponse(any()) } doReturn  Single.just(hmResponse)
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
            on { sign(any(), any()) } doReturn "signature".encodeToByteArray()
            on { verifySignature(any(), any(), any()) } doReturn false
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
            on { generateSecretKey(any()) } doReturn SecretKeySpec("key".encodeToByteArray(), "RC4")
        }

        val authorizationResponse = AuthorizationResponse("OTP".encodeToByteArray(), "SESSIONKEY".encodeToByteArray(), "AUTHPACK".encodeToByteArray(), "RC4_HMAC_MD5")
        val gson = Gson()

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(cryptoPluginMock!!), arrayListOf(authPluginMock!!))
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Invalid HelloMessageResponse from device")
    }

    @Test
    fun secureConnectSuccess() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"
        val response = "01:01:01:01:01:01".encodeToByteArray()
        val hmResponse = "helloMessageResponse".encodeToByteArray()

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
            on { sendHelloMessage(any(), any()) } doReturn  Single.just(true)
            on { readHelloMessageResponse(any()) } doReturn  Single.just(hmResponse)
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
            on { sign(any(), any()) } doReturn "signature".encodeToByteArray()
            on { verifySignature(any(), any(), any()) } doReturn true
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
            on { generateSecretKey(any()) } doReturn SecretKeySpec("key".encodeToByteArray(), "RC4")
        }

        val authorizationResponse = AuthorizationResponse("OTP".encodeToByteArray(), "SESSIONKEY".encodeToByteArray(), "AUTHPACK".encodeToByteArray(), "RC4_HMAC_MD5")
        val gson = Gson()

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(cryptoPluginMock!!), arrayListOf(authPluginMock!!))
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertComplete()
        subscriber.assertNoErrors()
    }

    @Test
    fun secureReadNotAuthenticated() {
        val subscriber = TestObserver<ByteArray>()
        val deviceID = "mockedIDWrong"

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSecFramework.secureRead(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Device not connected and authenticated")
    }

    @Test
    fun secureReadFailToRead() {
        val subscriberConnect = TestObserver<Boolean>()
        val subscriber = TestObserver<ByteArray>()
        val response = "01:01:01:01:01:01".encodeToByteArray()
        val hmResponse = "helloMessageResponse".encodeToByteArray()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
            on { sendHelloMessage(any(), any()) } doReturn  Single.just(true)
            on { readHelloMessageResponse(any()) } doReturn  Single.just(hmResponse)
            on { readData(any()) } doReturn  Single.create{emitter -> emitter.onError(Exception("Error"))}
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HMAC_MD5"
            on { sign(any(), any()) } doReturn "signature".encodeToByteArray()
            on { verifySignature(any(), any(), any()) } doReturn true
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
            on { generateSecretKey(any()) } doReturn SecretKeySpec("key".encodeToByteArray(), "RC4")
        }

        val authorizationResponse = AuthorizationResponse("OTP".encodeToByteArray(), "SESSIONKEY".encodeToByteArray(), "AUTHPACK".encodeToByteArray(), "RC4_HMAC_MD5")
        val gson = Gson()

        val contextNetCoreMock = mock<IAuthorizationProvider>()
        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, gson.toJson(authorizationResponse)))

        edgeSecFramework.initialize(gatewayID, transportPluginMock!!, arrayListOf(cryptoPluginMock!!), arrayListOf(authPluginMock!!))
        edgeSecFramework.setAuthorizationProvider(contextNetCoreMock)
        edgeSecFramework.secureConnect(deviceID).subscribe(subscriberConnect)

        edgeSecFramework.secureRead(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Error")
    }

}