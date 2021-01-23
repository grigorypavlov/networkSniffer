package com.example.networksniffer.vpnservice;

import android.content.Intent;
import android.os.ParcelFileDescriptor;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
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

        private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
        private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
        private ConcurrentLinkedQueue<Packet> networkToDeviceQueue;

        /** Constructor
         * @param vpnFileDescriptor FileDescriptor
         * @param deviceToNetworkUDPQueue UDP-Queue
         * @param deviceToNetworkTCPQueue TCP-Queue
         * @param networkToDeviceQueue Network-Queue
         * */
        public VPNRunnable(FileDescriptor vpnFileDescriptor,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                           ConcurrentLinkedQueue<Packet> networkToDeviceQueue) {
            this.vpnFileDescriptor = vpnFileDescriptor;
            this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
            this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
            this.networkToDeviceQueue = networkToDeviceQueue;
        }

        /** Is executed when Thread.start() is called */
        public void run() {
            FileChannel vpnInput = new FileInputStream(vpnFileDescriptor).getChannel();
            FileChannel vpnOutput = new FileOutputStream(vpnFileDescriptor).getChannel();

            try {
                ByteBuffer bufferToNetwork = null;
                boolean dataSent = true;
                boolean dataReceived;

                while (!Thread.interrupted()) {
                    if (dataSent)
                        bufferToNetwork = ByteBufferPool.acquire();
                    else
                        bufferToNetwork.clear();

                    int readBytes = vpnInput.read(bufferToNetwork);
                    if (readBytes > 0) {
                        dataSent = true;
                        bufferToNetwork.flip();
                        Packet packet = new Packet(bufferToNetwork);

                        if (packet.isUDP()) {
                            deviceToNetworkUDPQueue.offer(packet);
                        } else if (packet.isTCP()) {
                            deviceToNetworkTCPQueue.offer(packet);
                        } else {
                            // Unknown packet type, discard packet
                            dataSent = false;
                        }
                    } else {
                        dataSent = false;
                    }

                    ByteBuffer bufferFromNetwork = networkToDeviceQueue.poll();
                    if (bufferFromNetwork != null) {
                        bufferFromNetwork.flip();
                        while (bufferFromNetwork.hasRemaining()) {
                            vpnOutput.write(bufferFromNetwork);
                        }
                        dataReceived = true;
                        ByteBufferPool.release(bufferFromNetwork);
                    } else {
                        dataReceived = false;
                    }

                    if (!dataSent && !dataReceived) {
                        Thread.sleep(10);
                    }
                }
            } catch (InterruptedException iex) {
                System.out.println("Stopping");
            } catch (IOException ioex) {
                System.out.println(ioex.getStackTrace());
            } finally {
                CloseResources(vpnInput, vpnOutput);
            }
        }
    }
}
