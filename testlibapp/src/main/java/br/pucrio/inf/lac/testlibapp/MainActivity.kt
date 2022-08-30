package br.pucrio.inf.lac.testlibapp

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import br.pucrio.inf.lac.ble.BLE
import br.pucrio.inf.lac.edgesec.EdgeSec
import br.pucrio.inf.lac.edgesecinterfaces.IAuthenticationPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ICryptographicPlugin
import br.pucrio.inf.lac.edgesecinterfaces.ITransportPlugin
import br.pucrio.inf.lac.hmacmd5authentication.HmacMD5
import br.pucrio.inf.lac.rc4cryptography.RC4
import br.pucrio.inf.lac.testlibapp.databinding.ActivityMainBinding
import com.google.android.material.snackbar.Snackbar
import com.polidea.rxandroidble2.RxBleClient

class MainActivity : AppCompatActivity() {

    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setSupportActionBar(binding.toolbar)

        val navController = findNavController(R.id.nav_host_fragment_content_main)
        appBarConfiguration = AppBarConfiguration(navController.graph)
        setupActionBarWithNavController(navController, appBarConfiguration)

        binding.fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }

        fun PackageManager.missingSystemFeature(name: String): Boolean = !hasSystemFeature(name)

        // Check to see if the BLE feature is available.
        packageManager.takeIf { it.missingSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE) }?.also {
            Toast.makeText(this, "BLE NOT SUPPORTED", Toast.LENGTH_SHORT).show()
            finish()
        }

        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            // TODO: Consider calling
            //    ActivityCompat#requestPermissions
            // here to request the missing permissions, and then overriding
            //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
            //                                          int[] grantResults)
            // to handle the case where the user grants the permission. See the documentation
            // for ActivityCompat#requestPermissions for more details.
            Toast.makeText(this, "BLE NOT SUPPORTED 2", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "BLE SUPPORTED", Toast.LENGTH_SHORT).show()
        }

        val edgeSec = EdgeSec()
        val blePlugin: ITransportPlugin = BLE(RxBleClient.create(this.applicationContext))
        val rc4Plugin: ICryptographicPlugin = RC4()
        val hmacMD5Plugin: IAuthenticationPlugin = HmacMD5()

        val gatewayID = BluetoothAdapter.getDefaultAdapter().address
        val cryptoList = ArrayList<ICryptographicPlugin>()
        val authList = ArrayList<IAuthenticationPlugin>()
        cryptoList.add(rc4Plugin)
        authList.add(hmacMD5Plugin)

        println("[EDGESEC-DEBUG] Initializing edge sec")
        edgeSec.initialize(gatewayID, blePlugin, cryptoList, authList)

        println("[EDGESEC-DEBUG] Edgesec initialized")

        edgeSec.searchDevices().subscribe({ resp: String ->
            println("[EDGESEC-DEBUG] Devices found: $resp")
            if (resp == "24:6F:28:B5:D8:3A") {
                edgeSec.secureConnect(resp).subscribe(
                    { resp2: Boolean -> println("[DEBUG] Secure connect result: $resp2") }
                ) { error2: Throwable ->
                    println(
                        "[EDGESEC-DEBUG] ERROR: $error2"
                    )
                }
            }
        }) { error: Throwable -> println("[EDGESEC-DEBUG] ERROR: $error") }


    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onSupportNavigateUp(): Boolean {
        val navController = findNavController(R.id.nav_host_fragment_content_main)
        return navController.navigateUp(appBarConfiguration)
                || super.onSupportNavigateUp()
    }
}