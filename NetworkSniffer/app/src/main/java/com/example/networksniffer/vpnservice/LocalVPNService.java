package com.example.networksniffer.vpnservice;

import android.os.ParcelFileDescriptor;

/** Class to connect to a vpn service */
public class LocalVPNService extends android.net.VpnService {

    private static boolean isRunning = false;
    private ParcelFileDescriptor vpnInterface = null;

    /** Initialize the service */
    public LocalVPNService() {
        SetupVPN();
    }

    /** @return True when the service is running */
    public static boolean IsRunning() {
        return isRunning;
    }

    /** Setup the VPN */
    public void SetupVPN() {
        if (vpnInterface == null) {
            Builder builder = new Builder();

            vpnInterface = builder
                    .addAddress("2001:db8::1", 64)
                    .addRoute("::", 0) // Accept all traffic
                    .establish();
        }
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        isRunning = false;
        CleanUp();
    }

    private void CleanUp() {
        // TODO: Clean up resources
    }

    /** VPN-Thread */
    private static class VPNRunnable implements Runnable {

        /** Is executed when Thread.start() is called */
        @Override
        public void run() {
            // TODO: Implement the vpn
        }
    }
}
