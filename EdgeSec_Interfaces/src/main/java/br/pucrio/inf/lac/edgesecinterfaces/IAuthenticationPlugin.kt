/*
Module: IAuthenticationPlugin.kt
Description: Interface for plugin that provides an authentication implementation, compatible with EdgeSec framework
Author: Gabriel Cantergiani
 */
package br.pucrio.inf.lac.edgesecinterfaces

import java.security.Key

interface IAuthenticationPlugin {

    /*
        Retorna o identificador do protocolo immplementado pelo plugin. Este identificador é utilizado durante o processo de handshake para avaliar a compatibilidade entre gateway e dispositivo.
     */
    fun getProtocolID(): String;

    /*
        Assina um conjunto de dados utilizando um protocolo de autenticação

        Parametros:
            - data: array de bytes que será assinado
            - key: chave criptografica utilizada para assinar os dados

        Retorno:
            - array de bytes contendo conjunto de dados e sua assinatura
     */
    fun sign(data: ByteArray, key: Key): ByteArray;

    /*
        Verifica a assinatura de um conjunto de dados utilizando protocolo de autenticação

        Parametros:
            - data: array de bytes que será assinado
            - key: chave criptografica utilizada para assinar os dados
            - signature: assinatura que será verificada

        Retorno:
            - true se a assinatura for válida, false caso contrário
     */
    fun verifySignature(data: ByteArray, key: Key, signature: ByteArray): Boolean;

    /*
        Gera hash de um valor utilizando o algoritmo de hashing do plugin

        Parametros:
            - payload: array de bytes contendo o valor a passar pela função de hash

        Retorno:
            - array de bytes com o resultado da função de hash
     */
    fun generateHash(payload: ByteArray): ByteArray;

    /*
        Retorna o tamanho em bytes do valor gerado pelo algoritmo de hashing do plugin

        Retorno:
            - inteiro que representa o tamanho em bytes do valor gerado pelo hash
     */
    fun getHashSize(): Int;
}