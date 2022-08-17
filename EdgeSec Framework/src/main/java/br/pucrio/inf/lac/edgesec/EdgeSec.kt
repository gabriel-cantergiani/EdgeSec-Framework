package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.decodeByteArrayToHexString
import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.decodeToInt
import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.encodeToByteArray
import java.sql.DriverManager.println
import java.util.*

class EdgeSec() : IEdgeSec {

    private val TAG = "EdgeSec"
    private val EdgeSecVersion = "1.0"
    private var gatewayID: String = "";
    private var transportPlugin: ITransportPlugin? = null;
    private var cryptoPlugins: ArrayList<ICryptographicPlugin>? = null;
    private var authPlugins: ArrayList<IAuthenticationPlugin>? = null;

    private var authenticationPackage: AuthenticationPackage? = null;
    private var authorization: Authorization? = null;
    private var secureConnections: ArrayList<SecureConnection>? = null;
    private var compatibleDevices: ArrayList<String>? = null;

    init {
    }


    fun frameworkHello(): String {
        return "EdgeSec - Hello World!"
    }

    fun print(s: String) {
        System.out.println("[DEBUG] " + s);
    }

    override fun initialize(
        gatewayID: String,
        transportPlugin: ITransportPlugin,
        cryptoPlugins: ArrayList<ICryptographicPlugin>,
        authPlugins: ArrayList<IAuthenticationPlugin>
    ) {

        // Store parameters in class variables
        if (gatewayID.length != Constants.GATEWAY_ID_BYTES_SIZE) {
            throw Exception("Invalid gateway ID: should be of size :" + Constants.GATEWAY_ID_BYTES_SIZE)
        }
        this.gatewayID = gatewayID;
        this.transportPlugin = transportPlugin;
        if (cryptoPlugins.size > 0)
            this.cryptoPlugins = cryptoPlugins;
        if (authPlugins.size > 0)
            this.authPlugins = authPlugins;

        // Initialize classes and wrappers
        this.authorization = Authorization();

        // Initialize internal variables
        this.secureConnections = ArrayList<SecureConnection>();
    }

    override fun searchDevices(): ArrayList<String> {

        // Check if transport plugin is set
        this.transportPlugin ?: throw Exception("Transport Plugin not initialized");

        // Call transport plugin to scan for devices
        val foundDevices = this.transportPlugin!!.scanForDevices();
        var compatibleDevices: ArrayList<String> = ArrayList<String>();
        print("Devices scanned")

        // Use transport plugin to check which devices are compatible with EdgeSec
        for (device in foundDevices) {
            if (this.transportPlugin!!.verifyDeviceCompatibility(device)) {
                compatibleDevices.add(device);
            }
        }
        print("Compatible devices selected")

        // Update compatible devices array
        this.compatibleDevices = ArrayList<String>(compatibleDevices);

        // return ID of compatible devices
        return compatibleDevices;
    }

    override fun secureConnect(deviceID: String): Boolean {

        // Verify if plugins are correctly set
        this.transportPlugin ?: throw Exception("Transport plugin not initialized")
//        this.authPlugins?: throw Exception("Authentication plugins not initialized")
        this.cryptoPlugins ?: throw Exception("Cryptographic plugins not initialized")

        // Try to connect and perform EdgeSec handshake to negotiate authentication and cryptographic protocols
        val objectID = this.connectAndHandshake(deviceID);

        // TODO: Configura as classes AuthenticationPlugin e CryptographyPlugin com os protocolos decididos no handshake

        // SKIPPING: Chama função exchangeAuthenticationIDs para usar o TransportPlugin e realizar as primeiras etapas do processo de autenticação (troca de IDs)

        // Chama classe de Authorization para verificar se dispositivo pode se comunicar com o gateway

        // Chama função createHelloMessage para obter a Hello Message pronta

        // Chama função exchangeHelloMessage para enviar e receber resposta da Hello Message

        // Chama classe AuthenticationPlugin para verificar assinatura da resposta da Hello Message

        // Cria classe SecureConnection para dispositivo e adiciona na lista de autenticados e conectados, e retorna

        return false;
    }

    override fun secureRead(deviceID: String): ByteArray {

        // Verifica se dispositivo está na lista de conectados e autenticados

        // Chama classe TransportPlugin para ler dado do dispositivo

        // Chama classe CryptographyPlugin para decriptar mensagem

        // Chama classe AuthenticationPlugin para verificar assinatura da mensagem

        // Responde com valor da mensagem

        return ByteArray(20);
    }

    override fun secureWrite(deviceID: String, data: ByteArray): Boolean {

        // Verifica se dispositivo está na lista de conectados e autenticados

        // Chama classe CryptographyPlugin para encriptar mensagem

        // Chama classe AuthenticationPlugin para assinar a mensagem

        // Chama classe TransportPlugin para enviar dado ao dispositivo

        return false;
    }

    private fun connectAndHandshake(deviceID: String): String {

        print("Starting handshake")

        // Use transport plugin to verify if device is compatible with EdgeSec
        if (!this.transportPlugin!!.verifyDeviceCompatibility(deviceID))
            throw Exception("Device is not compatible with EdgeSec");


        // Build HandshakeHello message with EdgeSecVersion + gateway ID
        val version = this.EdgeSecVersion.encodeToByteArray()
        val gatewayID = this.gatewayID.encodeToByteArray();
        val handshakeHelloMessage: ByteArray = version + gatewayID;

        print("Sending handshake: " + handshakeHelloMessage.decodeToString());

        //Send HandshakeHello message
        this.transportPlugin!!.sendHandshakeHello(deviceID, handshakeHelloMessage);

        print("Handshake sent");
        // Chama classe de TransportPlugin para ler mensagem do dispositivo com:
        // - ID do objeto

        // Read HandshakeHello response
        val handshakeResponse: ByteArray = this.transportPlugin!!.readHandshakeResponse(deviceID)
            ?: throw Exception("Error reading handshake response");

        var lastIndexRead = 0;

        // Get Device Authentication ID
        val objectID: String = handshakeResponse.slice(
            IntRange(
                lastIndexRead,
                lastIndexRead + Constants.DEVICE_ID_BYTES_SIZE - 1
            )
        ).toByteArray().decodeToString()
        lastIndexRead += Constants.DEVICE_ID_BYTES_SIZE;

        print("deviceID: " + objectID)

        return objectID;
    }

    private fun exchangeAuthenticationIDs() {
        // Chama classe TransportPlugin e se conecta com dispositivo

        // chama classe de TransportPlugin para ler ID do dispositivo

        // chama classe de TransportPlugin para enviar ID ao dispositivo
    }

    private fun createHelloMessage() {
        // Chama função createAuthPackage para gerar pacote de autenticação

        // Chama classe AuthenticationPlugin para assinar pacote de autenticação

        // Gera timestamp

        // Chama função para gerar Hello Message utilizando pacote de autenticação e timestamp

        // Chama classe AuthenticationPlugin para assinar Hello Message

        // Chama função para gerar mensagem autenticada (Hello Message + Assinatura)
    }

    private fun createAuthPackage() {

        // Chama classe CryptographyPlugin para gerar OTPChallenge

        // Chama classe CryptographyPlugin para gerar chave de sessão

        // Chama classe CryptographyPlugin para gerar OTP

        // Cria classe AuthenticationPackage e chama função para montar o pacote de autenticação com os dados gerados
    }

    private fun exchangeHelloMessage() {
        // Chama classe de TransportPlugin para enviar a mensagem autenticada

        // Chama classe de TransportPlugin para ler resposta da Hello Message
    }


    /*
    PROCESSO DE NEGOCIACAO DE PROTOCOLOS (na funcao de handshake)
    // Chama classe de TransportPlugin para ler mensagem do dispositivo com:
        // - ID do dispositivo
        // - Tamanho em bytes da lista de protocolos auth
        // - Lista de protocolos de autenticacao disponiveis (codigos)
        // - Tamanho em bytes da lista de protocolos crypto
        // - Lista de protocolos de criptografia disponiveis (codigos)

    // Get Auth protocol list size
        val sizeOfAuthList: Int = handshakeResponse.slice(IntRange(lastIndexRead, lastIndexRead + Constants.PROTOCOL_LIST_LENGTH_BYTES_SIZE)).toByteArray().decodeToInt();
        lastIndexRead += Constants.PROTOCOL_LIST_LENGTH_BYTES_SIZE;

        print("size of auth list: " + sizeOfAuthList)
        var authProtocolsList = ArrayList<Int>();
        for(i in 0 until sizeOfAuthList / Constants.PROTOCOL_ID_BYTES_SIZE) {
            var startIndex = lastIndexRead + (i*Constants.PROTOCOL_ID_BYTES_SIZE)
            print("startIndex: " + startIndex)
            print("sliced int: " + handshakeResponse.slice(IntRange(startIndex, startIndex + Constants.PROTOCOL_ID_BYTES_SIZE)).toByteArray())
            authProtocolsList.add(handshakeResponse.slice(IntRange(startIndex, startIndex + Constants.PROTOCOL_ID_BYTES_SIZE)).toByteArray().decodeToInt());
            print("protocol list: " + authProtocolsList)
        }
        lastIndexRead += Constants.PROTOCOL_ID_BYTES_SIZE * sizeOfAuthList;


        // Get Crypto Protocol list
        val sizeOfCryptoList: Int = handshakeResponse.slice(IntRange(lastIndexRead, lastIndexRead + Constants.PROTOCOL_LIST_LENGTH_BYTES_SIZE)).toByteArray().decodeToInt();
        lastIndexRead += Constants.PROTOCOL_LIST_LENGTH_BYTES_SIZE;

        var cryptoProtocolsList = ArrayList<Int>();
        for(i in 0 until sizeOfCryptoList / Constants.PROTOCOL_ID_BYTES_SIZE) {
            var startIndex = lastIndexRead + (i*Constants.PROTOCOL_ID_BYTES_SIZE)
            cryptoProtocolsList.add(handshakeResponse.slice(IntRange(startIndex, Constants.PROTOCOL_ID_BYTES_SIZE)).toByteArray().decodeToInt());
        }

        print("Device Auth ID: " + deviceAuthenticationID)
        print("Size of auth list: " + sizeOfAuthList)
        print("Auth List: " + authProtocolsList)
        print("Size of crypto list: " + sizeOfCryptoList)
        print("Crypto List: " + cryptoProtocolsList)

        // Percorre as listas selecionando os protocolos a serem utilizados, sempre buscando por protocolos preferenciais. Se nao achar nenhum protocolo compativel, desconecta

        // Chama classe de TransportPlugin para enviar mensagem para o dispositivo com:
        // - Protocolo de autenticacao selecionado
        // - Protocolo de criptografia selecionado
     */
}