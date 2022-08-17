package br.pucrio.inf.lac.bletransport

import br.pucrio.inf.lac.edgesec.Constants
import br.pucrio.inf.lac.edgesec.ITransportPlugin
import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.decodeToInt
import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.encodeToByteArray

class BLE() : ITransportPlugin {

    private val TAG = "BLE"

    init {
    }

    /*
        Escaneia por dispositivos compatíveis com o protocolo de transporte nas redondezas.

        ??? Possíveis parametros de distancia limite ou tempo limite ???

        Retorno:
            - lista de IDs de dispositivos encontrados
     */
    override fun scanForDevices(): Array<String> {
        // TODO: MOCKED
        return arrayOf<String>("08-79-C6-23-C9-C8", "60-7D-E2-2F-C7-67")
        // MOCKED
    }

    /*
       Se conecta com o dispositivo através do protocolo de transporte

       Parametros:
           - device_id: string identificadora do dispositivo

       Retorno:
           - true em caso de conectado com sucesso, false caso contrário
    */
    override fun connect(deviceID: String): Boolean {

        // TODO: MOCKED
        return deviceID == "60-7D-E2-2F-C7-67"
        // MOCKED
    }

    /*
        Verifica se o dispositivo é compatível com a arquitetura EdgeSec.

        Parametros:
            - device_id: string identificadora do dispositivo

        Retorno:
            - true em caso de compatível, false em caso de não compatível
     */
    override fun verifyDeviceCompatibility(deviceID: String): Boolean {
        // TODO: MOCKED
        return deviceID == "60-7D-E2-2F-C7-67"
        // MOCKED
    }

    /*
        Envia mensagem de hello do processo de handshake

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    override fun sendHandshakeHello(deviceID: String, data: ByteArray): Boolean {
        // TODO: MOCKED
        return deviceID == "60-7D-E2-2F-C7-67"
        // MOCKED
    }

    /*
        Faz a leitura da resposta do processo do handshake Hello. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readHandshakeResponse(deviceID: String): ByteArray? {
        // TODO: MOCKED
        if (deviceID == "60-7D-E2-2F-C7-67") {
            val deviceAuthIDBytes = "607DE22FC767".encodeToByteArray()
//            val authProtocolsMock = arrayOf<Int>(1, 2)
//            val sizeOfAuthListInBytes: Int =
//                (authProtocolsMock.size * Constants.PROTOCOL_ID_BYTES_SIZE)
//            var authListInBytes = ByteArray(sizeOfAuthListInBytes)
//
//            for (protocolID in authProtocolsMock) {
//                authListInBytes += protocolID.encodeToByteArray()
//            }
//
//            val cryptoProtocolsMock = arrayOf<Int>(1, 2)
//            val sizeOfCryptoListInBytes: Int =
//                (cryptoProtocolsMock.size * Constants.PROTOCOL_ID_BYTES_SIZE)
//            var cryptoListInBytes = ByteArray(sizeOfCryptoListInBytes)
//
//            for (protocolID in cryptoProtocolsMock) {
//                cryptoListInBytes += protocolID.encodeToByteArray()
//            }

            var response = ByteArray(0)

            response += deviceAuthIDBytes
//            response += sizeOfAuthListInBytes.encodeToByteArray()
//            response += authListInBytes
//            response += sizeOfCryptoListInBytes.encodeToByteArray()
//            response += cryptoListInBytes

            return response

        }

        return null
        // MOCKED
    }

    /*
        Envia mensagem de de término do handshake

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    override fun sendHandshakeFinished(deviceID: String, data: ByteArray): Boolean {
        return false
    }

    /*
        Envia hello message do processo de autenticação

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    override fun sendHelloMessage(deviceID: String, data: ByteArray): Boolean {
        return false
    }

    /*
        Faz a leitura da resposta dda hello message. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readHelloMessageResponse(deviceID: String): ByteArray? {
        if (deviceID == "")
            return null
        return ByteArray(1)
    }

    /*
        Faz a leitura de um dado do dispositivo. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readData(deviceID: String): ByteArray? {
        if (deviceID == "")
            return null
        return ByteArray(1)
    }

    /*
        Faz a escrita de um dado no dispositivo.

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        ** (plugin deve decidir se dá para enviar em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    override fun writeData(deviceID: String, data: ByteArray): Boolean {
        return false
    }

}