/*
Module: IEdgeSec.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import io.reactivex.Observable
import io.reactivex.Single

/*
Interface: IEdgeSec
Description: Public interface for using EdgeSec framework
 */
interface IEdgeSec {

    /*
       Set up EdgeSec framework initializing main variables and plugins

       Parameters:
           - gatewayID: string identifying MacAddress of gateway
           - transportPlugin: Object that implements ITransportPlugin interface
           - cryptoPlugin: Array of objects that implements ICryptographicPlugin interface
           - authPlugin: Array of objects that implements IAuthenticationPlugin interface

    */
    fun initialize(gatewayID: String, transportPlugin: ITransportPlugin, cryptoPlugins: ArrayList<ICryptographicPlugin>, authPlugins: ArrayList<IAuthenticationPlugin>);


    /*
        Search for devices nearby that are compatible with EdgeSec using transport protocol

        Returns:
             - Observable that emits strings representing the MacAddress of devices that are found
     */
    fun searchDevices(): Observable<String>;


    /*
    Tries to connect with device, perform handshake and start authentication process. If succeeded, device will be connected securely.

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits true if connection was succeeded and false otherwise
     */
    fun secureConnect(deviceID: String): Single<Boolean>;

    /*
    Reads data securely from connected and authenticated device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits a ByteArray with the data read
     */
    fun secureRead(deviceID: String): Single<ByteArray>;

    /*
    Writes data securely to connected and authenticated device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect

    Returns:
        - Observable that emits true if write was succeeded and false otherwise
     */
    fun secureWrite(deviceID: String, data: ByteArray): Single<Boolean>;

    /*
    Disconnects from a connected device

    Parameters:
        - deviceID: String identifying MacAddress of device to connect
     */
    fun disconnect(deviceID: String);
}