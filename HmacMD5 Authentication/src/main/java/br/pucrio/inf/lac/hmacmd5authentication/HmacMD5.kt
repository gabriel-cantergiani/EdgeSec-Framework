package br.pucrio.inf.lac.hmacmd5authentication

import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import java.security.Key
import java.security.MessageDigest
import javax.crypto.Mac

class HmacMD5(): IAuthenticationPlugin {

    private val TAG = "HmacMD5"
    private val SigningAlgorithmID = "hmacMD5"
    private val DigestAlgorithmID = "MD5"
    private val DigestAlgorithmBytesSize = 16

    init {
    }

    override fun getProtocolID(): String {
        return "HMAC_MD5"
    }

    override fun sign(data: ByteArray, key: Key): ByteArray {
        val macInstance = Mac.getInstance(SigningAlgorithmID)
        macInstance.init(key)
        return macInstance.doFinal(data)
    }

    override fun verifySignature(data: ByteArray, key: Key, signature: ByteArray): Boolean {
        val generatedSignature = sign(data, key)
        return signature.contentEquals(generatedSignature)
    }

    override fun generateHash(payload: ByteArray): ByteArray {
        val digestInstance = MessageDigest.getInstance(DigestAlgorithmID)
        digestInstance.update(payload)
        return digestInstance.digest()
    }

    override fun getHashSize(): Int {
        return DigestAlgorithmBytesSize;
    }
}