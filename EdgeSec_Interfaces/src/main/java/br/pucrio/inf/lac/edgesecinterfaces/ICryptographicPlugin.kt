package br.pucrio.inf.lac.edgesecinterfaces

import java.security.Key

interface ICryptographicPlugin {

    /*
        Retorna o identificador do protocolo immplementado pelo plugin. Este identificador é utilizado durante o processo de handshake para avaliar a compatibilidade entre gateway e dispositivo.
     */
    fun getProtocolID(): String;

    /*
        Gera um token aleatório seguro, utilizando ou não uma semente (usado no OTPChallenge)

        Parametros:
            - size: tamanho (em quantidade de bytes) do token aleatório a ser gerado

        Retorno:
            - array de bytes com o valor aleatório
     */
    fun generateSecureRandomToken(size: Int): ByteArray;

    /*
        Gera uma chave criptográfica a ser usada nos processos de autenticação e de criptografia dos dados trocados (usado na Ksession)

        Parametros:
            - seed: string que será a semente da geração do valor aleatório

        Retorno:
            - array de bytes da chave criptográfica
     */
    fun generateSecretKey(seed: ByteArray): Key;


    /*
        Criptografa dados

        Parametros:
            - plainText: array de bytes contendo o valor a ser criptografado em texto plano
            - key: chave a ser utilizada para criptografar

        Retorno:
            - array de bytes com o resultado criptografado
     */
    fun encrypt(plainText: ByteArray, key: ByteArray): ByteArray;

    /*
        Decripta dados

        Parametros:
            - cipher: array de bytes contendo o valor criptografado a ser decriptado
            - key: chave a ser utilizada para decriptar

        Retorno:
            - array de bytes com o resultado em texto plano
     */
    fun decrypt(cipher: ByteArray, key: ByteArray): ByteArray;
}
