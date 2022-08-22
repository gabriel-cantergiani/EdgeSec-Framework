package br.pucrio.inf.lac.edgesec

import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.decodeByteArrayToHexString
import br.pucrio.inf.lac.edgesec.SecurityUtils.Companion.encodeToByteArray
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import java.util.*

class EdgeSec() : IEdgeSec {

    private val TAG = "EdgeSec"
    private val EdgeSecVersion = "1.0"
    private var gatewayID: String = "";
    private var transportPlugin: ITransportPlugin? = null;
    private var cryptoPlugins: ArrayList<ICryptographicPlugin>? = null;
    private var authPlugins: ArrayList<IAuthenticationPlugin>? = null;
    private var selectedCryptoPlugin: ICryptographicPlugin? = null
    private var selectedAuthPlugin: IAuthenticationPlugin? = null

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
        this.authPlugins ?: throw Exception("Authentication plugins not initialized")
        this.cryptoPlugins ?: throw Exception("Cryptographic plugins not initialized")

        // Try to connect and perform EdgeSec handshake to negotiate authentication and cryptographic protocols
        val objectID = this.connectAndHandshake(deviceID);

        // TODO: Configura as classes AuthenticationPlugin e CryptographyPlugin com os protocolos decididos no handshake

        // SKIPPING: Chama função exchangeAuthenticationIDs para usar o TransportPlugin e realizar as primeiras etapas do processo de autenticação (troca de IDs)

        // Chama classe de Authorization para verificar se dispositivo pode se comunicar com o gateway
        val authorizationResponse =
            this.authorization?.verifyAuthorization(this.gatewayID, objectID)
                ?: throw Exception("Failed to get authorization from Core")

        val authenticationPackage = buildAuthenticationPackage(
            authorizationResponse.protocolSuite,
            authorizationResponse.authenticatioPackage,
            authorizationResponse.OTP,
            authorizationResponse.sessionKey
        )

        print("OTP: " + authenticationPackage.OTP.decodeByteArrayToHexString())
        print("SessionKey: " + authenticationPackage.SessionKey.decodeByteArrayToHexString())
        print("Timestamp: " + authenticationPackage.messageTimestamp.decodeByteArrayToHexString())
        print("Signed Auth Package: " + authenticationPackage.signedAuthPackage.decodeByteArrayToHexString())
        print("Protocol suite: " + authenticationPackage.protocolSuite)

        // Set plugins
        setPlugins(authenticationPackage.protocolSuite)

        if (selectedAuthPlugin == null || selectedCryptoPlugin == null)
            throw Exception("Plugins not compatible")

        // Chama função createHelloMessage para obter a Hello Message pronta
        val signedHelloMessage = createHelloMessage(authenticationPackage)
        print("HelloMessage: " + signedHelloMessage.decodeByteArrayToHexString())

        // Chama função exchangeHelloMessage para enviar e receber resposta da Hello Message
        val helloMessageResponse = exchangeHelloMessage(deviceID, signedHelloMessage)
            ?: throw Exception("Failed to get helloMessageResponse")
        print("HelloMessageResponse: " + helloMessageResponse.decodeByteArrayToHexString())

        // Chama classe AuthenticationPlugin para verificar assinatura da resposta da Hello Message
        val success =
            verifyHelloMessageResponse(objectID, authenticationPackage, helloMessageResponse)
        if (!success) {
            throw Exception("Invalid HelloMessageResponse")
        }
        print("HelloMessageResponse validated successfully")

        // Cria classe SecureConnection para dispositivo e adiciona na lista de autenticados e conectados, e retorna
        val newSecureConnection = SecureConnection(objectID, authenticationPackage.SessionKey)
        secureConnections?.add(newSecureConnection) ?: throw Exception("Error creating secureConnection")

        return true;
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

        print("Sending handshake: " + handshakeHelloMessage.decodeByteArrayToHexString());

        //Send HandshakeHello message
        val success = this.transportPlugin!!.sendHandshakeHello(deviceID, handshakeHelloMessage);
        if (!success)
            throw Exception("Failed to send handshakeHello")

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

        print("objectID: " + objectID)

        return objectID;
    }

    private fun createHelloMessage(authenticationPackage: AuthenticationPackage): ByteArray {

        // Chama função para gerar Hello Message utilizando pacote de autenticação e timestamp
        val helloMessage =
            authenticationPackage.signedAuthPackage + authenticationPackage.messageTimestamp

        // Chama classe AuthenticationPlugin para assinar Hello Message
        val key = selectedCryptoPlugin!!.generateSecretKey(authenticationPackage.OTP)

        return selectedAuthPlugin!!.sign(helloMessage, key)
    }

    private fun exchangeHelloMessage(deviceID: String, helloMessage: ByteArray): ByteArray? {
        // Chama classe de TransportPlugin para enviar a mensagem autenticada
        val success = transportPlugin!!.sendHelloMessage(deviceID, helloMessage)
        if (!success)
            throw Exception("Failed to send helloMessage")

        // Chama classe de TransportPlugin para ler resposta da Hello Message
        return transportPlugin!!.readHelloMessageResponse(deviceID)

    }

    private fun verifyHelloMessageResponse(
        objectID: String,
        authenticationPackage: AuthenticationPackage,
        responseToBeVerified: ByteArray
    ): Boolean {
        var responseContent = ByteArray(0)

        responseContent += gatewayID.encodeToByteArray()
        responseContent += objectID.encodeToByteArray()
        responseContent += authenticationPackage.messageTimestamp

        val key = selectedCryptoPlugin!!.generateSecretKey(authenticationPackage.OTP)

        return selectedAuthPlugin!!.verifySignature(responseContent, key, responseToBeVerified)
    }

    private fun buildAuthenticationPackage(
        protocolSuite: String,
        signedAuthPackage: ByteArray,
        OTP: ByteArray,
        sessionKey: ByteArray
    ): AuthenticationPackage {
        // Generate timestamp
//        val timestamp = (System.currentTimeMillis() / 1000).toInt().encodeToByteArray()
        // TODO": MOCKED TIMESTAMP GENERATION FOR TESTING
        val timestamp = (91823 / 1000).toInt().encodeToByteArray()
        // MOCKED

        return AuthenticationPackage(protocolSuite, signedAuthPackage, OTP, sessionKey, timestamp)

    }

    private fun setPlugins(protocolSuite: String) {
        val cryptoProtocol = protocolSuite.split("_")[0]
        val authProtocol = protocolSuite.split("_")[1] + "_" + protocolSuite.split("_")[2]

        selectedAuthPlugin = null
        selectedCryptoPlugin = null

        for (selectedPlugin in authPlugins!!) {
            if (authProtocol == selectedPlugin.getProtocolID()) {
                selectedAuthPlugin = selectedPlugin
            }
        }

        for (selectedPlugin in cryptoPlugins!!) {
            if (cryptoProtocol == selectedPlugin.getProtocolID()) {
                selectedCryptoPlugin = selectedPlugin
            }
        }
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