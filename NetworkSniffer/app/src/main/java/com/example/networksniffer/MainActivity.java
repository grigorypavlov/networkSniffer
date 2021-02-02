package com.example.networksniffer;

import android.app.Activity;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.RadioButton;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import com.example.networksniffer.observerpattern.ISubscriber;
import com.example.networksniffer.sniffers.Sniffer;
import com.example.networksniffer.vpnservice.LocalVPNService;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;
import com.google.android.material.tabs.TabLayout;
import androidx.viewpager.widget.ViewPager;
import androidx.appcompat.app.AppCompatActivity;
import com.example.networksniffer.ui.main.SectionsPagerAdapter;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

/**
 * Network-Sniffer
 *
 * @author Colin van Loo, Grigory Pavlov
 * @version 0.3
 *
 */

public class MainActivity extends AppCompatActivity implements ISubscriber {
    private TableLayout table;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TabLayout tabs = findViewById(R.id.tabs);
        ViewPager viewPager = findViewById(R.id.view_pager);
        tabs.addTab(tabs.newTab().setText("NetworkSniffer"));
        tabs.setTabGravity(TabLayout.GRAVITY_FILL);

        SectionsPagerAdapter sectionsPagerAdapter = new SectionsPagerAdapter(this, getSupportFragmentManager());
        viewPager.setAdapter(sectionsPagerAdapter);

        viewPager.addOnPageChangeListener(new TabLayout.TabLayoutOnPageChangeListener(tabs));
        tabs.addOnTabSelectedListener(new TabLayout.OnTabSelectedListener() {
            @Override
            public void onTabSelected(TabLayout.Tab tab) {
                viewPager.setCurrentItem(tab.getPosition());
            }
            @Override
            public void onTabUnselected(TabLayout.Tab tab) {
            }
            @Override
            public void onTabReselected(TabLayout.Tab tab) {
            }
        });

        Sniffer sniffer = Sniffer.getInstance();
        sniffer.Subscribe(this);

        /* Get permission to start the VPN Service
         *
         * Only one app can have this permission, the permissions are
         * revoked as soon as the user gives another VPN app the same permissions.
         */
        Intent vpnIntent = VpnService.prepare(this);
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, 0x0F);
        }
        else {
            onActivityResult(0x0F, Activity.RESULT_OK, null);
        }
    }

    /** Starts the VPN Service */
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 0x0F && resultCode == RESULT_OK) {
            startService(new Intent(this, LocalVPNService.class));
        }
    }

    private Enumeration<NetworkInterface> GetNetworkInterfaces() {
        try {
            return NetworkInterface.getNetworkInterfaces();
        } catch (SocketException ignored) { }

        return null;
    }

    /*public void onRadioButtonClicked(View view) {
        // Is the button now checked?
        boolean checked = ((RadioButton) view).isChecked();

        // Check which radio button was clicked
        switch(view.getId()) {
            case R.id.BluetoothRadio:
                if (checked)
                    System.out.println("1");
                break;
            case R.id.EthernetRadio:
                if (checked)
                    System.out.println("2");
                break;
            case R.id.WlanRadio:
                if (checked)
                    System.out.println("3");
        }
    }*/

    /** Send me the new packet
     * @param packet New packet
     */
    public void Update(Object packet) {
        // Ensures that the following code is executed on the ui-thread
        // FIXME: This is not working and the application crashes ;(
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Packet p = (Packet)packet;
                System.out.println(packet.toString());

                if (table == null) {
                    // Get a reference to the table
                    table = (TableLayout) findViewById(R.id.tableView);

                    // Create columns
                    TableRow trow1 = new TableRow(MainActivity.this);

                    TextView tview1 = new TextView(MainActivity.this);
                    tview1.setText("Sender");
                    tview1.setTextColor(Color.BLUE);
                    trow1.addView(tview1);

                    TextView tview2 = new TextView(MainActivity.this);
                    tview2.setText("Receiver");
                    tview2.setTextColor(Color.BLUE);
                    trow1.addView(tview2);

                    table.addView(trow1);
                }

                TableRow tableRow = new TableRow(MainActivity.this);

                // First column
                TextView textView1 = new TextView(MainActivity.this);
                textView1.setText(((Packet) packet).ip4Header.sourceAddress.toString());
                textView1.setTextColor(Color.WHITE);
                tableRow.addView(textView1);

                // Second column
                TextView textView2 = new TextView(MainActivity.this);
                textView2.setText(((Packet) packet).ip4Header.destinationAddress.toString());
                textView2.setTextColor(Color.WHITE);
                tableRow.addView(textView2);

                table.addView(tableRow);
            }
        });
    }
}