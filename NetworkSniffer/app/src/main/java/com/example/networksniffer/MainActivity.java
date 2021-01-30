package com.example.networksniffer;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.RadioButton;
import android.widget.Spinner;

import com.example.networksniffer.vpnservice.LocalVPNService;
import com.google.android.material.tabs.TabLayout;
import androidx.viewpager.widget.ViewPager;
import androidx.appcompat.app.AppCompatActivity;
import com.example.networksniffer.ui.main.SectionsPagerAdapter;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.sql.SQLOutput;
import java.util.Enumeration;

/**
 * Network-Sniffer
 *
 * @author Colin van Loo, Grigory Pavlov
 *
 * */

public class MainActivity extends AppCompatActivity {

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

    public void onRadioButtonClicked(View view) {
        // Is the button now checked?
        boolean checked = ((RadioButton) view).isChecked();

        // Check which radio button was clicked
        switch(view.getId()) {
            case R.id.radio1:
                if (checked)
                    System.out.println("1");
                break;
            case R.id.radio2:
                if (checked)
                    System.out.println("2");
                break;
        }
    }
}