package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.contextnetcore.AuthorizationResponse
import br.pucrio.inf.lac.contextnetcore.ContextNetCore
import com.google.gson.Gson

class Authorization {

    // Classe que obtem autorização para dois objetos se autenticarem. Encapsula operações referentes a obtenção da autorização, seja fazer requisições para um servidor, ou acessar um banco de dados

    private val TAG = "Authorization"

    init {
    }

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