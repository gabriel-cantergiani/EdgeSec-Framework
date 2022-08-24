package br.pucrio.inf.lac.ble

import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import com.polidea.rxandroidble2.RxBleClient
import com.polidea.rxandroidble2.scan.ScanSettings
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.disposables.Disposable
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


class BLE(
    private val bleClient: RxBleClient
) : ITransportPlugin {

    private val TAG = "BLE"

    init {
    }

    /*
        Escaneia por dispositivos compatíveis com o protocolo de transporte nas redondezas.

        ??? Possíveis parametros de distancia limite ou tempo limite ???

        Retorno:
            - lista de IDs de dispositivos encontrados
     */
    override fun scanForCompatibleDevices(): Observable<Array<String>> {
        return Observable.create<Array<String>> {
            emitter -> val scanSubscription: Disposable = bleClient.scanBleDevices(
            ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_FIRST_MATCH)
                .build()
        ).subscribe({
            System.out.println("[debug] Scan result: " + it)
            // TODO: MOCKED
            emitter.onNext(arrayOf<String>("60-7D-E2-2F-C7-67"))
            // MOCKED
        },
            {
            emitter.onError(it)
            })
        }

    }

    /*
       Se conecta com o dispositivo através do protocolo de transporte

       Parametros:
           - device_id: string identificadora do dispositivo

       Retorno:
           - true em caso de conectado com sucesso, false caso contrário
    */
    override fun connect(deviceID: String): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
        // MOCKED
    }

    /*
        Verifica se o dispositivo é compatível com a arquitetura EdgeSec.

        Parametros:
            - device_id: string identificadora do dispositivo

        Retorno:
            - true em caso de compatível, false em caso de não compatível
     */
    override fun verifyDeviceCompatibility(deviceID: String): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
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
    override fun sendHandshakeHello(deviceID: String, data: ByteArray): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
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
    override fun readHandshakeResponse(deviceID: String): Single<ByteArray?> {
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

            // TODO: MOCKED
            return Single.create<ByteArray?>{emitter -> emitter.onSuccess(response) }
            // MOCKED

        }

        return Single.create<ByteArray?>{emitter -> emitter.onSuccess(ByteArray(0)) }
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
    override fun sendHandshakeFinished(deviceID: String, data: ByteArray): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
        // MOCKED
    }

    /*
        Envia hello message do processo de autenticação

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    override fun sendHelloMessage(deviceID: String, data: ByteArray): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(deviceID == "60-7D-E2-2F-C7-67") }
        // MOCKED
    }

    // TODO: MOCKED
    fun Int.encodeToByteArray(): ByteArray {
        var buffer: ByteArray = ByteArray(4);
        buffer[0] = (this ushr 0).toByte()
        buffer[1] = (this ushr 8).toByte()
        buffer[2] = (this ushr 16).toByte()
        buffer[3] = (this ushr 24).toByte()

        return buffer;
    }
    // MOCKED

    /*
        Faz a leitura da resposta da hello message. Dependendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readHelloMessageResponse(deviceID: String): Single<ByteArray?> {
        // TODO: MOCKED
        if (deviceID == "60-7D-E2-2F-C7-67") {
            var helloMessageResponse = ByteArray(0)

            helloMessageResponse += "808DE88FC8TE".encodeToByteArray() // gatewayID
            helloMessageResponse += "607DE22FC767".encodeToByteArray() // objectID
            helloMessageResponse += (91823 / 1000).toInt().encodeToByteArray() // objectID

            val key = SecretKeySpec("MOCKEDOTP".encodeToByteArray(), "RC4")
            val macInstance = Mac.getInstance("hmacMD5")
            macInstance.init(key)
            val result = macInstance.doFinal(helloMessageResponse)
            return Single.create<ByteArray?>{emitter -> emitter.onSuccess(result) }
        }

        return Single.create<ByteArray?>{emitter -> emitter.onSuccess(ByteArray(0)) }
        // MOCKED
    }

    /*
        Faz a leitura de um dado do dispositivo. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readData(deviceID: String): Single<ByteArray?> {
        return Single.create<ByteArray?>{emitter ->
            if (deviceID == "")
                emitter.onSuccess(ByteArray(0))
            emitter.onSuccess(ByteArray(1))

        }
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
    override fun writeData(deviceID: String, data: ByteArray): Single<Boolean> {
        // TODO: MOCKED
        return Single.create<Boolean>{emitter -> emitter.onSuccess(false) }
        // MOCKED
    }

}