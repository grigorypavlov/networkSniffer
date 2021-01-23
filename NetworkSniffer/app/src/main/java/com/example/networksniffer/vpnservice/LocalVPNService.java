package com.example.networksniffer.vpnservice;

import android.content.Intent;
import android.os.ParcelFileDescriptor;

import java.io.FileDescriptor;
import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;

/** Class to connect to a vpn service */
public class LocalVPNService extends android.net.VpnService {

    private static boolean isRunning = false;
    private ParcelFileDescriptor vpnInterface = null;

    /** Initialize the service */
    @Override
    public void onCreate() {
        super.onCreate();
        isRunning = true;
        SetupVPN();

        try {
            // TODO: Start the service
            throw new IOException(); // Make the compiler happy :)
        } catch (IOException ioEx) {
            // TODO: Notify user that the service could not be started
            CleanUp();
        }
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
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    /** @return Returns true when the service is running */
    public static boolean IsRunning() {
        return isRunning;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        isRunning = false;
        CleanUp();
    }

    /** Cleans up all resources */
    private void CleanUp() {
        // TODO: Clean up resources
    }

    /** VPN-Thread */
    private static class VPNRunnable implements Runnable {

        private FileDescriptor vpnFileDescriptor;

        private ConcurrentLinkedQueue<Packet>

        /** Is executed when Thread.start() is called */
        @Override
        public void run() {
            // TODO: Implement the vpn
        }
    }
}
