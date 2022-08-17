package br.pucrio.inf.lac.hmacmd5authentication

import br.pucrio.inf.lac.edgesec.IAuthenticationPlugin

class HmacMD5(): IAuthenticationPlugin {

    private val TAG = "HmacMD5"

    init {
    }

    override fun getProtocolID(): String {
        return "HMAC_MD5"
    }

    override fun sign(data: ByteArray, key: ByteArray): ByteArray {
        return ByteArray(1)
    }


    override fun verifySignature(data: ByteArray, key: ByteArray, signature: ByteArray): Boolean {
        return false
    }

    override fun generateHash(payload: ByteArray): ByteArray {
        return ByteArray(1)
    }
}