package br.pucrio.inf.lac.testlib;

import br.pucrio.inf.lac.bletransport.BLE;
import br.pucrio.inf.lac.edgesec.EdgeSec;
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin;
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin;
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin;
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5;
import br.pucrio.inf.lac.rc4cryptography.RC4;
import java.util.ArrayList;

import static java.sql.DriverManager.println;

public class TestClass {

    public static void main(String[] args) {
        EdgeSec edgeSec = new EdgeSec();
        ITransportPlugin blePlugin = new BLE();
        ICryptographicPlugin rc4Plugin = new RC4();
        IAuthenticationPlugin hmacMD5Plugin = new HmacMD5();

        String gatewayID = "808DE88FC8TE";
        ArrayList<ICryptographicPlugin> cryptoList = new ArrayList<ICryptographicPlugin>();
        ArrayList<IAuthenticationPlugin> authList = new ArrayList<IAuthenticationPlugin>();
        cryptoList.add(rc4Plugin);
        authList.add(hmacMD5Plugin);

        System.out.println("[DEBUG] Initializing edge sec");
        edgeSec.initialize(gatewayID, blePlugin, cryptoList, authList);

        System.out.println("[DEBUG] Edgesec initialized");

        ArrayList<String> devicesFound = edgeSec.searchDevices();
        System.out.println("[DEBUG] Devices found: " + devicesFound);

        edgeSec.secureConnect(devicesFound.get(0));
    }
}
