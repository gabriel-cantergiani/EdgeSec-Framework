package br.pucrio.inf.lac.contextnetcore

data class AuthorizationResponse(
    val OTP: ByteArray,
    val sessionKey: ByteArray,
    val authenticatioPackage: ByteArray,
    val protocolSuite: String,
)
