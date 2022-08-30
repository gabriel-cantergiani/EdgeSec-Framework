/*
Module: BLE.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.ble

import android.util.Log
import android.util.LruCache
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import com.polidea.rxandroidble2.RxBleClient
import com.polidea.rxandroidble2.RxBleConnection
import com.polidea.rxandroidble2.scan.ScanResult
import com.polidea.rxandroidble2.scan.ScanSettings
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.disposables.CompositeDisposable
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/*
Class: BLE.kt
Description: Main class for BLE plugin - implements ITransportPlugin interface
 */
class BLE(
    private val bleClient: RxBleClient
) : ITransportPlugin {

    private val TAG = "BLE"
    private val cacheSize = 20

    private val connectionsCache = LruCache<String, RxBleConnection>(cacheSize)
    private val disposables = CompositeDisposable()

    private val characteristics: Map<String, UUID> = mapOf(
        "SECURITY_SERVICE_UUID" to UUID.fromString("dc33e26c-a82e-4fea-82ab-daa5dfac3dd3"),
        "HANDSHAKE_HELLO_UUID" to UUID.fromString("2c093c70-8b7c-4398-bda1-8340dfd50bae"),
        "HANDSHAKE_RESPONSE_UUID" to UUID.fromString("65d89516-59fd-453b-91a7-861982bbd8eb"),
        "HANDSHAKE_FINISH_UUID" to UUID.fromString("67d13516-22fd-346b-93a7-861982bbd8ea"),
        "SEND_HELLO_MESSAGE_UUID" to UUID.fromString("35875610-380a-4cfb-aa9e-6efcea4803ea"),
        "READ_HELLO_MESSAGE_UUID" to UUID.fromString("8b81383b-1136-4df2-85a4-dd29a7a4e81b"),
        "READ_DATA_UUID" to UUID.fromString("f86db954-a0d0-4d99-b27f-bb8d42585e97"),
        "WRITE_DATA_UUID" to UUID.fromString("2cb4b710-9ec7-47bf-bfc7-ad9341a0773e"),
    )

    init {
    }

    /*
        Scan for nearby compatible devices using the BLE transport protocol

        Returns:
            - Observable that emits the MacAddress of devices that are found
     */
    override fun scanForCompatibleDevices(): Observable<String> {
        // TODO: Review verifyCompatibility before returning it
        return configureScan()
            .retryWhen { it.observeIfStateIsReady() }
            .map { it.bleDevice.macAddress }
    }

    /*
       Tries to connect with a device using BLE protocol

       Parameters:
           - device_id: string identifying MacAddress of device

       Returns:
           - Observable that emits true if connection was successful, false otherwise
    */
    override fun connect(deviceID: String): Single<Boolean> {
        return Single.create<Boolean> {
         emitter -> bleClient.getBleDevice(deviceID)
            .establishConnection(false)
            .doOnNext { connection -> connectionsCache.put(deviceID, connection) }
            .doOnError { connectionsCache.remove(deviceID) }
            .subscribe(
                {
                    emitter.onSuccess(true); },
                { error ->
                    if (!emitter.isDisposed) {
                        emitter.onError(error)
                    }
                }
            )
            .let {
                disposables.add(it)
            }
        }
    }

    /*
        Verifies if device is compatible with EdgeSec architecture

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits true if it is successful, and false otherwise
     */
    override fun verifyDeviceCompatibility(deviceID: String): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
        // MOCKED
    }

    /*
        Sends the handshakeHelloMessage to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true if it is successful, false otherwise
     */
    override fun sendHandshakeHello(deviceID: String, data: ByteArray): Single<Boolean> {
        return writeDataToCharacteristic(deviceID, data, "HANDSHAKE_HELLO_UUID")
    }

    /*
        Reads the handshakeResponse from device

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the data that was read in case of success, and null in case of error.
     */
    override fun readHandshakeResponse(deviceID: String): Single<ByteArray?> {
        return readDataFromCharacteristic(deviceID, "HANDSHAKE_RESPONSE_UUID")
    }

    /*
        Send handshakeFinish message to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true in case of successful write, and false otherwise.
     */
    override fun sendHandshakeFinished(deviceID: String, data: ByteArray): Single<Boolean> {
        return writeDataToCharacteristic(deviceID, data, "HANDSHAKE_FINISH_UUID")
    }

    /*
        Sends hello message to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true in case of successful write, and false otherwise.
     */
    override fun sendHelloMessage(deviceID: String, data: ByteArray): Single<Boolean> {
        // TODO: Break data in 3 parts of 20 bytes
        return writeDataToCharacteristic(deviceID, data, "SEND_HELLO_MESSAGE_UUID")
    }

    /*
        Reads the HelloMessageResponse

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the message if read is successful, and null otherwise.
     */
    override fun readHelloMessageResponse(deviceID: String): Single<ByteArray?> {
        return readDataFromCharacteristic(deviceID, "READ_HELLO_MESSAGE_UUID")
    }

    /*
        Reads data from device

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the message if read is successful, and null otherwise.
     */
    override fun readData(deviceID: String): Single<ByteArray?> {
        return readDataFromCharacteristic(deviceID, "READ_DATA_UUID")
    }

    /*
        Writes data to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true if write is successful, and false otherwise.
     */
    override fun writeData(deviceID: String, data: ByteArray): Single<Boolean> {
        return writeDataToCharacteristic(deviceID, data, "WRITE_DATA_UUID")
    }

    /*
        Generic auxiliary function that writes data to a certain BLE characteristic

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be written in characteristic
            - characteristicName: Name of characteristic in map

        Returns:
            - Observable that emits true if write is successful, and false otherwise.
     */
    private fun writeDataToCharacteristic(deviceID: String, data: ByteArray, characteristicName: String): Single<Boolean> {
        val connection = connectionsCache[deviceID] ?: return Single.just(false)

        return Single.create<Boolean> { emitter ->
            connection.writeCharacteristic(characteristics[characteristicName]!!, data).subscribe(
                {
                    Log.d(TAG, "$characteristicName Characteristic wrote successfully: " + it.decodeToString())
                    emitter.onSuccess(true)
                },
                {
                    Log.d(TAG, "Error writing $characteristicName Characteristic")
                    emitter.onError(it)
                }
            )
        }
    }

    /*
        Generic auxiliary function that reads data from a certain BLE characteristic

        Parameters:
            - device_id: string identifying MacAddress of device
            - characteristicName: Name of characteristic in map

        Returns:
            - Observable that emits a ByteArray containing the message if read is successful, and null otherwise.
     */
    private fun readDataFromCharacteristic(deviceID: String, characteristicName: String): Single<ByteArray?> {
        val connection = connectionsCache[deviceID] ?: return Single.just(null)

        return Single.create<ByteArray> { emitter ->
            connection.readCharacteristic(characteristics[characteristicName]!!).subscribe(
                {
                    Log.d(TAG, "$characteristicName Characteristic read successfully: " + it.decodeToString())
                    emitter.onSuccess(it)
                },
                {
                    Log.d(TAG, "Error reading $characteristicName Characteristic")
                    emitter.onError(it)
                }
            )
        }
    }

    /*
         Auxiliary function that configures the scan of devices using bleClient

        Returns:
            - Observable that emits a ScanResult.
     */
    private fun configureScan(): Observable<ScanResult> = bleClient.scanBleDevices(
        ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_FIRST_MATCH)
            .build()
    )

    /*
         Auxiliary function that is used to check if an Observable has state ready

        Returns:
            - Observable that emits a ScanResult.
     */
    private fun Observable<Throwable>.observeIfStateIsReady(): Observable<ScanResult> = flatMap {
        bleClient.observeStateChanges()
            .switchMap { configureScanIfReady(it) }
            .doOnError { System.out.println(it.localizedMessage)}
            .onErrorResumeNext(Observable.empty())
    }

    /*
         Auxiliary function that configures the scan of devices depending on a client state

         Parameters:
            - state of BLE client

        Returns:
            - Observable that emits a ScanResult.
     */
    private fun configureScanIfReady(state: RxBleClient.State): Observable<ScanResult> = when (state) {
        RxBleClient.State.READY -> configureScan()
        RxBleClient.State.BLUETOOTH_NOT_AVAILABLE -> throw Exception("Bluetooth not available")
        RxBleClient.State.LOCATION_PERMISSION_NOT_GRANTED -> throw Exception("Location not granted")
        RxBleClient.State.BLUETOOTH_NOT_ENABLED -> throw Exception("Bluetooth not enabled")
        RxBleClient.State.LOCATION_SERVICES_NOT_ENABLED -> throw Exception("Location not enabled")
        else -> throw IllegalStateException(state.name)
    }

}