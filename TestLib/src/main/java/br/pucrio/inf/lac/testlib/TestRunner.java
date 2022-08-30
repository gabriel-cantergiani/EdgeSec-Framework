package br.pucrio.inf.lac.testlib;

import android.content.Context;

import com.polidea.rxandroidble2.RxBleClient;

import java.util.ArrayList;

import br.pucrio.inf.lac.ble.BLE;
import br.pucrio.inf.lac.edgesec.EdgeSec;
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin;
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin;
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin;
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5;
import br.pucrio.inf.lac.rc4cryptography.RC4;

public class TestRunner {

    public void init(Context context) {
        EdgeSec edgeSec = new EdgeSec();
        ITransportPlugin blePlugin = new BLE(RxBleClient.create(context));
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

        edgeSec.searchDevices().subscribe(resp -> {
            String devicesFound = resp;
            System.out.println("[DEBUG] Devices found: " + devicesFound);

            edgeSec.secureConnect(devicesFound).subscribe(resp2 -> {
                System.out.println("[DEBUG] Secure connect result: " + resp2);
            }, error2 -> {System.out.println("[DEBUG] ERROR: " + error2); });
        }, error -> {
            System.out.println("[DEBUG] ERROR: " + error);
        });
    }
}
