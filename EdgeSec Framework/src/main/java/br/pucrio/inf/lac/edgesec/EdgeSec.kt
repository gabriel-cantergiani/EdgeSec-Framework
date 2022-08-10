package br.pucrio.inf.lac.edgesec

class EdgeSec() : IEdgeSec {

    private val TAG = "EdgeSec"
    private var gatewayID: String = "";
    private var transportPlugin: ITransportPlugin? = null;
    private var cryptoPlugins: ArrayList<ICryptographicPlugin>? = null;
    private var authPlugins: ArrayList<IAuthenticationPlugin>? = null;

    private var authenticationPackage: AuthenticationPackage? = null;
    private var authorization: Authorization? = null;
    private var secureConnections: ArrayList<SecureConnection>? = null;

    init {
    }


    fun frameworkHello(): String {
        return "EdgeSec - Hello World!"
    }

    override fun initialize(gatewayID: String, transportPlugin: ITransportPlugin, cryptoPlugins: ArrayList<ICryptographicPlugin>, authPlugins: ArrayList<IAuthenticationPlugin>) {

        // Guarda valores em variáveis da classe
        this.gatewayID = gatewayID;
        this.transportPlugin = transportPlugin;
        this.cryptoPlugins = cryptoPlugins;
        this.authPlugins = authPlugins;

        // Inicializa as outras classes do framework, como os wrappers de plugins
        this.authorization = Authorization();

        // Inicializa listas e variáveis
        this.secureConnections = ArrayList<SecureConnection>();
    }

    override fun searchDevices(): ArrayList<String> {

        if (this.transportPlugin == null) {
            return ArrayList<String>();
        }

        // chama classe TransportPlugin para iniciar scan
        val foundDevices = this.transportPlugin!!.scanForDevices();
        var compatibleDevices: ArrayList<String> = ArrayList<String>();

        // usa lista de dispositivos encontrados e chama classe TransportPlugin para verificar a compatibilidade deles com o EdgeSec (?? isso poderia ser feito diretamente no plugin, já abstraido para o framework ??)
        for (device in foundDevices) {
            if (this.transportPlugin!!.verifyDeviceCompatibility(device)) {
                compatibleDevices.add(device);
            }
        }

        // retorna ids dos dispositivos encontrados
        return compatibleDevices;
    }

    override fun secureConnect(deviceID: String): Boolean {

        // Chama função connectAndHandshake para se conectar e realizar o Handshake dos protocolos de criptografia e autenticação

        // Configura as classes AuthenticationPlugin e CryptographyPlugin com os protocolos decididos no handshake

        // Chama função exchangeAuthenticationIDs para usar o TransportPlugin e realizar as primeiras etapas do processo de autenticação (troca de IDs)

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

    private fun connectAndHandshake() {
        // Faz conexão inicial utilizando a classe TransportPlugin

        // Chama classe de TransportPlugin para verificar se dispositivo é compatível com EdgeSec

        // Chama classe de TransportPlugin para enviar mensagem para o dispositivo com:
        // - versao do EdgeSec
        // - ID do gateway

        // Chama classe de TransportPlugin para ler mensagem do dispositivo com:
        // - ID do dispositivo
        // - Lista de protocolos de autenticacao disponiveis
        // - Lista de protocolos de criptografia disponiveis

        // Percorre as listas selecionando os protocolos a serem utilizados, sempre buscando por protocolos preferenciais. Se nao achar nenhum protocolo compativel, desconecta

        // Chama classe de TransportPlugin para enviar mensagem para o dispositivo com:
        // - Protocolo de autenticacao selecionado
        // - Protocolo de criptografia selecionado

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
}