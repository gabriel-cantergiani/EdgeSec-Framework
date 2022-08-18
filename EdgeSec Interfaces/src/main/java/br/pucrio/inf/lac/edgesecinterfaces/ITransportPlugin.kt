package br.pucrio.inf.lac.edgesecinterfaces

interface ITransportPlugin {

    /*
        Escaneia por dispositivos compatíveis com o protocolo de transporte nas redondezas.

        ??? Possíveis parametros de distancia limite ou tempo limite ???

        Retorno:
            - lista de IDs de dispositivos encontrados
     */
    fun scanForDevices(): Array<String>;

    /*
       Se conecta com o dispositivo através do protocolo de transporte

       Parametros:
           - device_id: string identificadora do dispositivo

       Retorno:
           - true em caso de conectado com sucesso, false caso contrário
    */
    fun connect(deviceID: String): Boolean;

    /*
        Verifica se o dispositivo é compatível com a arquitetura EdgeSec.

        Parametros:
            - device_id: string identificadora do dispositivo

        Retorno:
            - true em caso de compatível, false em caso de não compatível
     */
    fun verifyDeviceCompatibility(deviceID: String): Boolean;

    /*
        Envia mensagem de hello do processo de handshake

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    fun sendHandshakeHello(deviceID: String, data: ByteArray): Boolean;

    /*
        Faz a leitura da resposta do processo do handshake Hello. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    fun readHandshakeResponse(deviceID: String): ByteArray?;

    /*
        Envia mensagem de de término do handshake

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    fun sendHandshakeFinished(deviceID: String, data: ByteArray): Boolean;

    /*
        Envia hello message do processo de autenticação

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    fun sendHelloMessage(deviceID: String, data: ByteArray): Boolean;

    /*
        Faz a leitura da resposta dda hello message. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    fun readHelloMessageResponse(deviceID: String): ByteArray?;

    /*
        Faz a leitura de um dado do dispositivo. Depedendo do protocolo, esta leitura pode ser ativa (ação iniciada pelo gateway) ou passiva (gateway espera por mensagem/ação do dispositivo).

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)

        ** (plugin deve decidir se dá para ler em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - Array de bytes contendo o dado lido, caso a leitura tenha sido bem sucedida. Em caso de falha, ou sem dado para ler, retorna nulo.
     */
    fun readData(deviceID: String): ByteArray?;

    /*
        Faz a escrita de um dado no dispositivo.

        Parametros:
            - device_id: string identificadora do dispositivo (obtida pelo protocolo de transporte)
            - data: array de bytes com os dados a serem escritos

        ** (plugin deve decidir se dá para enviar em uma só mensagem ou é necessário quebrar mensagem em várias partes)

        Retorno:
            - true caso a escrita tenha sido bem sucedida. Em caso de falha retorna false.
     */
    fun writeData(deviceID: String, data: ByteArray): Boolean;

}
