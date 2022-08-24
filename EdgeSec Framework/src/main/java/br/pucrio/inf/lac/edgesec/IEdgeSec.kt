package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import io.reactivex.Observable
import io.reactivex.Single

interface IEdgeSec {

    /*
    Inicializa framework configurando o identificador do gateway e os plugins que serão utilizados na comunicação.

    Parametros:
        - gateway_id: string identificadora do gateway
        - transportPlugin: objeto que implementa interface do plugin de transporte
        - criptoPlugins: lista de objetos que implementam interface do plugin de criptografia
        - authPlugins: lista de objetos que implementam interface do plugin de autenticação
     */
    fun initialize(gatewayID: String, transportPlugin: ITransportPlugin, cryptoPlugins: ArrayList<ICryptographicPlugin>, authPlugins: ArrayList<IAuthenticationPlugin>);


    /*
    Utiliza o protocolo de transporte configurado pelo plugin para buscar dispositivos nas redondezas.

    Retorno:
        - lista de IDs dos dispositivos compatíveis encontrados.
     */
    fun searchDevices(): Observable<ArrayList<String>>;


    /*
    Se conecta com dispositivo, realiza o handshake e inicia processo de autenticação. Se bem sucedido, o dispositivo estará conectado e autenticado e poderá trocar dados de forma segura.

    Parametros:
        - device_id: Identificador do dispositivo com quem o gateway deseja se autenticar

    Retorno:
        - true: em case de sucesso
        - false: em caso de falha
     */
    fun secureConnect(deviceID: String): Single<Boolean>;

    /*
    Faz a leitura de dados de um dispositivo conectado e autenticado.

    Parametros:
        - device_id: Identificador do dispositivo do qual o gateway deseja ler dados

    Retorno:
        - array de bytes representando os dados lidos. Array vazio em caso de falhar para ler os dados, ou caso dispositivo não exista ou não esteja autenticado.
     */
    fun secureRead(deviceID: String): Single<ByteArray>;

    /*
    Faz a escrita de dados em um dispositivo conectado e autenticado.

    Parametros:
        - device_id: Identificador do dispositivo do qual o gateway deseja ler dados
        - data: array de bytes representando os dados que se deseja escrever para o dispositivo

    Retorno:
        - true: em case de sucesso
        - false: em caso de falha
     */
    fun secureWrite(deviceID: String, data: ByteArray): Single<Boolean>;
}