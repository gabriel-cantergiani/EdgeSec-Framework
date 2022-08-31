/*
Module: Authorization.kt
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.contextnetcore.AuthorizationResponse
import br.pucrio.inf.lac.contextnetcore.ContextNetCore
import com.google.gson.Gson

/*
Class: Authorization
Description: Wrapper for encapsulating communication with authorization server
 */
class Authorization {

    private val TAG = "Authorization"

    init {
    }

    /*
       Receive the ID of a gateway and an Smart Object and create an authorization request for ContextNetCore

       Parameters:
           - gateway_id: string identifying MacAddress of gateway
           - object_id: string identifying MacAddress of smart object

       Returns:
           - An AuthorizationResponse object with the content of the response from ContextNetCore
    */
    fun verifyAuthorization(gatewayID: String, objectID: String): AuthorizationResponse? {

        // Call ContexNet class to authorize connection (mocked network request)
        val (success, authorizationResponse) = ContextNetCore.authorize(gatewayID, objectID)

        if (!success) {
            System.out.println("Authorization error: " + authorizationResponse)
            return null
        }

        // Parse response
        val gson = Gson()

        return gson.fromJson(authorizationResponse, AuthorizationResponse::class.java);
    }
}