package br.pucrio.inf.lac.testlib;

import br.pucrio.inf.lac.bletransport.BLE;
import br.pucrio.inf.lac.edgesec.EdgeSec;
import br.pucrio.inf.lac.edgesec.IAuthenticationPlugin;
import br.pucrio.inf.lac.edgesec.ICryptographicPlugin;
import br.pucrio.inf.lac.edgesec.ITransportPlugin;
import br.pucrio.inf.lac.rc4cryptography.RC4;
import java.util.ArrayList;

import static java.sql.DriverManager.println;

public class TestClass {

    public static void main(String[] args) {
        EdgeSec edgeSec = new EdgeSec();
        ITransportPlugin blePlugin = new BLE();
        ICryptographicPlugin rc4Plugin = new RC4();

        String gatewayID = "808DE88FC8TE";
        ArrayList<ICryptographicPlugin> cryptoList = new ArrayList<ICryptographicPlugin>();
        cryptoList.add(rc4Plugin);

        System.out.println("[DEBUG] Initializing edge sec");
        edgeSec.initialize(gatewayID, blePlugin, cryptoList, new ArrayList<IAuthenticationPlugin>());

        System.out.println("[DEBUG] Edgesec initialized");

        ArrayList<String> devicesFound = edgeSec.searchDevices();
        System.out.println("[DEBUG] Devices found: " + devicesFound);

        edgeSec.secureConnect(devicesFound.get(0));
    }
}
