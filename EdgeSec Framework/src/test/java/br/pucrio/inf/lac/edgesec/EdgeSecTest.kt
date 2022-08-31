package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.contextnetcore.IAuthorizationProvider
import org.junit.jupiter.api.Assertions.*
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
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

internal class EdgeSecTest {

    private val edgeSec: EdgeSec = EdgeSec()
    var transportPluginMock: ITransportPlugin? = null
    var authPluginMock: IAuthenticationPlugin? = null
    var cryptoPluginMock: ICryptographicPlugin? = null
    var gatewayID = "00:00:00:00:00:00"
    var authPlugins = arrayListOf<IAuthenticationPlugin>()
    var cryptoPlugins = arrayListOf<ICryptographicPlugin>()

    @BeforeEach
    fun setUp() {
        transportPluginMock = mock<ITransportPlugin> {
            on { scanForCompatibleDevices() } doReturn Observable.just("mockedDeviceID")
        }

        authPluginMock = mock<IAuthenticationPlugin> {
            on { getProtocolID() } doReturn "HmacMD5"
        }

        cryptoPluginMock = mock<ICryptographicPlugin> {
            on { getProtocolID() } doReturn "RC4"
        }

        gatewayID = "00:00:00:00:00:00"
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
            edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        }

        assertEquals(
            "Invalid gateway ID: should be of size :" + Constants.GATEWAY_ID_BYTES_SIZE + ". actual size is: " + gatewayID.length,
            exception.message
        )

        gatewayID = "00:00:00:00:00:00"
        exception = assertThrows(Exception::class.java) {
            edgeSec.initialize(gatewayID, transportPluginMock!!, arrayListOf(), authPlugins)
        }

        assertEquals(
            "Invalid crypto plugin list. Should have at least one plugin",
            exception.message
        )

        exception = assertThrows(Exception::class.java) {
            edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, arrayListOf())
        }

        assertEquals(
            "Invalid auth plugin list. Should have at least one plugin",
            exception.message
        )
    }

    @Test
    fun initializeAllParametersValid() {
        assertDoesNotThrow {
            edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        }
    }

    @Test
    fun searchDevices() {

        val subscriber = TestObserver<String>()

        edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSec.searchDevices().subscribe(subscriber)

        subscriber.assertComplete()
        subscriber.assertNoErrors()
        subscriber.assertValueCount(1)
        val results = subscriber.values()
        assertEquals(results[0], "mockedDeviceID")
    }

    @Test
    fun secureConnectWithoutInitialize() {
        var exception = assertThrows(Exception::class.java) {
            edgeSec.secureConnect("mockedID")
        }
        assertEquals("Transport plugin not initialized", exception.message)
    }

    @Test
    fun secureConnectConnectError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(false)
        }

        edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSec.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to connect to device")
    }

    @Test
    fun secureConnectSendHelloMessageError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(false)
        }

        edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSec.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to send handshakeHello")
    }

    @Test
    fun secureConnectReadHelloMessageResponseError() {

        val subscriber = TestObserver<Boolean>()
        val deviceID = "mockedID"

        transportPluginMock = mock<ITransportPlugin> {
            on { connect(deviceID) } doReturn Single.just(true)
            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
            on { readHandshakeResponse(any()) } doReturn  Single.create{emitter -> emitter.onError(Exception("Device is not connected and authenticated"))}
        }

        edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
        edgeSec.secureConnect(deviceID).subscribe(subscriber)

        subscriber.assertError(Exception::class.java)
        subscriber.assertErrorMessage("Failed to read handshakeHelloResponse: Device is not connected and authenticated")
    }

//    @Test
//    fun secureConnectAuthorizationResponseError() {
//
//        val subscriber = TestObserver<Boolean>()
//        val deviceID = "mockedID"
//        val response = "01:01:01:01:01:01".encodeToByteArray()
//
//        transportPluginMock = mock<ITransportPlugin> {
//            on { connect(deviceID) } doReturn Single.just(true)
//            on { sendHandshakeHello(any(), any()) } doReturn Single.just(true)
//            on { readHandshakeResponse(any()) } doReturn  Single.just(response)
//        }
//
//        val contextNetCoreMock = mock<IAuthorizationProvider>()
//        whenever(contextNetCoreMock.authorize(any(), any())).thenReturn(Pair(true, "testJSON"))
//
//        edgeSec.initialize(gatewayID, transportPluginMock!!, cryptoPlugins, authPlugins)
//        edgeSec.secureConnect(deviceID).subscribe(subscriber)
//
//        subscriber.assertError(Exception::class.java)
//        subscriber.assertErrorMessage("Failed to read handshakeHelloResponse: Device is not connected and authenticated")
//    }

    @Test
    fun secureRead() {
    }

    @Test
    fun secureWrite() {
    }
}