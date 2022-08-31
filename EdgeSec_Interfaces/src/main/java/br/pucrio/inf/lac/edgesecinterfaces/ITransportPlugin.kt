/*
Module: ITransportPlugin.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesecinterfaces

import io.reactivex.Observable
import io.reactivex.Single
import java.util.*

/*
Interface: ITransportPlugin
Description: Interface for plugin that provides a transportation protocol implementation, compatible with EdgeSec framework
 */
interface ITransportPlugin {

    /*
        Scan for nearby compatible devices using the BLE transport protocol

        Returns:
            - Observable that emits the MacAddress of devices that are found
     */
    fun scanForCompatibleDevices(): Observable<String>;

    /*
       Tries to connect with a device using BLE protocol

       Parameters:
           - device_id: string identifying MacAddress of device

       Returns:
           - Observable that emits true if connection was successful, false otherwise
    */
    fun connect(deviceID: String): Single<Boolean>;

    /*
        Verifies if device is compatible with EdgeSec architecture

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits true if it is successful, and false otherwise
     */
    fun verifyDeviceCompatibility(deviceID: String): Single<Boolean>;

    /*
       Sends the handshakeHelloMessage to device

       Parameters:
           - device_id: string identifying MacAddress of device
           - data: ByteArray with data to be sent

       Returns:
           - Observable that emits true if it is successful, false otherwise
    */
    fun sendHandshakeHello(deviceID: String, data: ByteArray): Single<Boolean>;

    /*
        Reads the handshakeResponse from device

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the data that was read in case of success, and null in case of error.
     */
    fun readHandshakeResponse(deviceID: String): Single<ByteArray?>;

    /*
        Send handshakeFinish message to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true in case of successful write, and false otherwise.
     */
    fun sendHandshakeFinished(deviceID: String, data: ByteArray): Single<Boolean>;

    /*
        Sends hello message to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true in case of successful write, and false otherwise.
     */
    fun sendHelloMessage(deviceID: String, data: ByteArray): Single<Boolean>;

    /*
        Reads the HelloMessageResponse

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the message if read is successful, and null otherwise.
     */
    fun readHelloMessageResponse(deviceID: String): Single<ByteArray?>;

    /*
        Reads data from device

        Parameters:
            - device_id: string identifying MacAddress of device

        Returns:
            - Observable that emits a ByteArray containing the message if read is successful, and null otherwise.
     */
    fun readData(deviceID: String): Single<ByteArray?>;

    /*
        Writes data to device

        Parameters:
            - device_id: string identifying MacAddress of device
            - data: ByteArray with data to be sent

        Returns:
            - Observable that emits true if write is successful, and false otherwise.
     */
    fun writeData(deviceID: String, data: ByteArray): Single<Boolean>;

}
