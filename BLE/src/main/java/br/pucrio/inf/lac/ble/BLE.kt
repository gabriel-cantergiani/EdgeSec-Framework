package br.pucrio.inf.lac.ble

import android.util.Log
import android.util.LruCache
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import com.polidea.rxandroidble2.RxBleClient
import com.polidea.rxandroidble2.RxBleConnection
import com.polidea.rxandroidble2.scan.ScanResult
import com.polidea.rxandroidble2.scan.ScanSettings
import io.reactivex.Observable
import io.reactivex.Single
import io.reactivex.disposables.CompositeDisposable
import java.util.*
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec


class BLE(
    private val bleClient: RxBleClient
) : ITransportPlugin {

    private val TAG = "BLE"
    private val cacheSize = 20

    private val connectionsCache = LruCache<String, RxBleConnection>(cacheSize)
    private val disposables = CompositeDisposable()

    private val characteristics: Map<String, UUID> = mapOf(
        "SECURITY_SERVICE_UUID" to UUID.fromString("dc33e26c-a82e-4fea-82ab-daa5dfac3dd3"),
        "HANDSHAKE_HELLO_UUID" to UUID.fromString("2c093c70-8b7c-4398-bda1-8340dfd50bae"),
        "HANDSHAKE_RESPONSE_UUID" to UUID.fromString("65d89516-59fd-453b-91a7-861982bbd8eb"),
        "HANDSHAKE_FINISH_UUID" to UUID.fromString("67d13516-22fd-346b-93a7-861982bbd8ea"),
        "SEND_HELLO_MESSAGE_UUID" to UUID.fromString("35875610-380a-4cfb-aa9e-6efcea4803ea"),
        "READ_HELLO_MESSAGE_UUID" to UUID.fromString("8b81383b-1136-4df2-85a4-dd29a7a4e81b"),
        "READ_DATA_UUID" to UUID.fromString("f86db954-a0d0-4d99-b27f-bb8d42585e97"),
        "WRITE_DATA_UUID" to UUID.fromString("2cb4b710-9ec7-47bf-bfc7-ad9341a0773e"),
    )

    init {
    }

    /*
        Escaneia por dispositivos compatíveis com o protocolo de transporte nas redondezas.

        ??? Possíveis parametros de distancia limite ou tempo limite ???

        Retorno:
            - lista de IDs de dispositivos encontrados
     */
    override fun scanForCompatibleDevices(): Observable<String> {
        // TODO: Review verifyCompatibility before returning it
        return configureScan()
            .retryWhen { it.observeIfStateIsReady() }
            .map { it.bleDevice.macAddress }
    }

    /*
       Se conecta com o dispositivo através do protocolo de transporte

       Parametros:
           - device_id: string identificadora do dispositivo

       Retorno:
           - true em caso de conectado com sucesso, false caso contrário
    */
    override fun connect(deviceID: String): Single<Boolean> {
        return Single.create<Boolean> {
         emitter -> bleClient.getBleDevice(deviceID)
            .establishConnection(false)
            .doOnNext { connection -> connectionsCache.put(deviceID, connection) }
            .doOnError { connectionsCache.remove(deviceID) }
            .subscribe(
                {
                    emitter.onSuccess(true); },
                { error ->
                    if (!emitter.isDisposed) {
                        emitter.onError(error)
                    }
                }
            )
            .let {
                disposables.add(it)
            }
        }
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
        return writeDataToCharacteristic(deviceID, data, "HANDSHAKE_HELLO_UUID")
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
        return readDataFromCharacteristic(deviceID, "HANDSHAKE_RESPONSE_UUID")
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
        return writeDataToCharacteristic(deviceID, data, "HANDSHAKE_FINISH_UUID")
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
        // TODO: Break data in 3 parts of 20 bytes
        return writeDataToCharacteristic(deviceID, data, "SEND_HELLO_MESSAGE_UUID")
    }

    /*
        Faz a leitura da resposta da hello message. Dependendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    override fun readHelloMessageResponse(deviceID: String): Single<ByteArray?> {
        return readDataFromCharacteristic(deviceID, "READ_HELLO_MESSAGE_UUID")
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
        return readDataFromCharacteristic(deviceID, "READ_DATA_UUID")
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
        return writeDataToCharacteristic(deviceID, data, "WRITE_DATA_UUID")
    }

    private fun writeDataToCharacteristic(deviceID: String, data: ByteArray, characteristicName: String): Single<Boolean> {
        val connection = connectionsCache[deviceID] ?: return Single.just(false)

        return Single.create<Boolean> { emitter ->
            connection.writeCharacteristic(characteristics[characteristicName]!!, data).subscribe(
                {
                    Log.d(TAG, "$characteristicName Characteristic wrote successfully: " + it.decodeToString())
                    emitter.onSuccess(true)
                },
                {
                    Log.d(TAG, "Error writing $characteristicName Characteristic")
                    emitter.onError(it)
                }
            )
        }
    }

    private fun readDataFromCharacteristic(deviceID: String, characteristicName: String): Single<ByteArray?> {
        val connection = connectionsCache[deviceID] ?: return Single.just(null)

        return Single.create<ByteArray> { emitter ->
            connection.readCharacteristic(characteristics[characteristicName]!!).subscribe(
                {
                    Log.d(TAG, "$characteristicName Characteristic read successfully: " + it.decodeToString())
                    emitter.onSuccess(it)
                },
                {
                    Log.d(TAG, "Error reading $characteristicName Characteristic")
                    emitter.onError(it)
                }
            )
        }
    }

    private fun configureScan(): Observable<ScanResult> = bleClient.scanBleDevices(
        ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_FIRST_MATCH)
            .build()
    )

    private fun Observable<Throwable>.observeIfStateIsReady(): Observable<ScanResult> = flatMap {
        bleClient.observeStateChanges()
            .switchMap { configureScanIfReady(it) }
            .doOnError { System.out.println(it.localizedMessage)}
            .onErrorResumeNext(Observable.empty())
    }

    private fun configureScanIfReady(state: RxBleClient.State): Observable<ScanResult> = when (state) {
        RxBleClient.State.READY -> configureScan()
        RxBleClient.State.BLUETOOTH_NOT_AVAILABLE -> throw Exception("Bluetooth not available")
        RxBleClient.State.LOCATION_PERMISSION_NOT_GRANTED -> throw Exception("Location not granted")
        RxBleClient.State.BLUETOOTH_NOT_ENABLED -> throw Exception("Bluetooth not enabled")
        RxBleClient.State.LOCATION_SERVICES_NOT_ENABLED -> throw Exception("Location not enabled")
        else -> throw IllegalStateException(state.name)
    }

}