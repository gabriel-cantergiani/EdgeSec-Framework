/*
Module: IAuthorizationProvider.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.contextnetcore

/*
Interface: IAuthorizationProvider
Description: Interface that defines a provider that authorizes the communication of devices in EdgeSec Framework
 */
interface IAuthorizationProvider {

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
    fun authorize(gatewayID: String, objectID: String): Pair<Boolean, String>;
}