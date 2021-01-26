package com.example.networksniffer.vpnservice;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.ParcelFileDescriptor;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.example.networksniffer.R;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;
import com.example.networksniffer.vpnservice.networkprotocol.tcp.TCPInput;
import com.example.networksniffer.vpnservice.networkprotocol.tcp.TCPOutput;
import com.example.networksniffer.vpnservice.networkprotocol.udp.UDPInput;
import com.example.networksniffer.vpnservice.networkprotocol.udp.UDPOutput;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.Selector;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Class to connect to a vpn service */
public class LocalVPNService extends android.net.VpnService {
    private static final String VPN_ADDRESS = "10.0.0.2"; // Supports only IPv4
    private static final String VPN_ROUTE = "0.0.0.0"; // Intercept everything

    private static boolean isRunning = false;
    private ParcelFileDescriptor vpnInterface = null;
    private PendingIntent pendingIntent;

    private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
    private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
    private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;
    private ExecutorService executorService;

    private Selector udpSelector;
    private Selector tcpSelector;

    /** Initialize the service */
    @Override
    public void onCreate() {
        super.onCreate();
        isRunning = true;
        SetupVPN();

        try {
            udpSelector = Selector.open();
            tcpSelector = Selector.open();
            deviceToNetworkUDPQueue = new ConcurrentLinkedQueue<>();
            deviceToNetworkTCPQueue = new ConcurrentLinkedQueue<>();
            networkToDeviceQueue = new ConcurrentLinkedQueue<>();

            // Create threads
            executorService = Executors.newFixedThreadPool(5);

            executorService.submit(new UDPInput(networkToDeviceQueue, udpSelector));
            executorService.submit(new UDPOutput(deviceToNetworkUDPQueue, udpSelector, this));
            executorService.submit(new TCPInput(networkToDeviceQueue, tcpSelector));
            executorService.submit(new TCPOutput(deviceToNetworkTCPQueue, networkToDeviceQueue, tcpSelector, this));
            executorService.submit(new VPNRunnable(vpnInterface.getFileDescriptor(), deviceToNetworkUDPQueue, deviceToNetworkTCPQueue, networkToDeviceQueue));
            //LocalBroadcastManager.getInstance(this).sendBroadcast(new Intent("Test").putExtra("running", true));
        } catch (IOException ioEx) {
            /* TODO: Notify user that the service could not be started
            * The user has to disconnect the service manually
            */

            CleanUp();
        }
    }

    /** Setup the VPN */
    public void SetupVPN() {
        if (vpnInterface == null) {
            Builder builder = new Builder();
            builder.addAddress(VPN_ADDRESS, 32);
            builder.addRoute(VPN_ROUTE, 0);
            vpnInterface = builder.setSession(getString(R.string.app_name)).setConfigureIntent(pendingIntent).establish();
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

    /** Stop the VPN-Service */
    @Override
    public void onDestroy() {
        super.onDestroy();
        isRunning = false;
        executorService.shutdownNow(); // Stop all threads
        CleanUp();
    }

    /** Cleans up all resources */
    private void CleanUp() {
        deviceToNetworkUDPQueue = null;
        deviceToNetworkTCPQueue = null;
        networkToDeviceQueue = null;
        ByteBufferPool.Clear();
        CloseResources(udpSelector, tcpSelector, vpnInterface);
    }

    /** Close resources
     * @param resources Resources to close
     * */
    private static void CloseResources(Closeable... resources) {
        for (Closeable resource : resources) {
            try  {
                resource.close();
            } catch (IOException ioex) {
                // Ignore
            }
        }
    }

    /** VPN-Thread */
    private static class VPNRunnable implements Runnable {

        private FileDescriptor vpnFileDescriptor;

        private ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue;
        private ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue;
        private ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue;

        /** Constructor
         * @param vpnFileDescriptor FileDescriptor
         * @param deviceToNetworkUDPQueue UDP-Queue
         * @param deviceToNetworkTCPQueue TCP-Queue
         * @param networkToDeviceQueue Network-Queue
         * */
        public VPNRunnable(FileDescriptor vpnFileDescriptor,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkUDPQueue,
                           ConcurrentLinkedQueue<Packet> deviceToNetworkTCPQueue,
                           ConcurrentLinkedQueue<ByteBuffer> networkToDeviceQueue)
        {
            this.vpnFileDescriptor = vpnFileDescriptor;
            this.deviceToNetworkUDPQueue = deviceToNetworkUDPQueue;
            this.deviceToNetworkTCPQueue = deviceToNetworkTCPQueue;
            this.networkToDeviceQueue = networkToDeviceQueue;
        }

        /** Is executed when Thread.start() is called */
        @Override
        public void run() {
            FileChannel vpnInput = new FileInputStream(vpnFileDescriptor).getChannel();
            FileChannel vpnOutput = new FileOutputStream(vpnFileDescriptor).getChannel();

            try {
                ByteBuffer bufferToNetwork = null;
                boolean dataSent = true;
                boolean dataReceived = false;

                while (!Thread.interrupted()) {
                    if (dataSent)
                        bufferToNetwork = ByteBufferPool.Acquire();
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
                        ByteBufferPool.Release(bufferFromNetwork);
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
