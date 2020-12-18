package com.example.networksniffer.sniffers;

import android.widget.TableLayout;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;

import java.net.SocketException;
import java.util.ArrayList;

public abstract class PacketSniffer {
    private PcapIf nInterface = null;
    private StringBuilder errbuf = new StringBuilder();

    // Starts the listening-thread
    public void StartListeningAsync(TableLayout tl) throws Exception {
        if (nInterface == null) {
            throw new Exception("No network-interface specified!");
        }

        // TODO: Start listening
    };

    // Stops the listening thread
    public void StopListening() {
        // TODO: Stop listening
    };

    // Returns all available network interfaces
    public ArrayList<PcapIf> GetInterfaces() throws SocketException {
        // Get all available network interfaces
        ArrayList<PcapIf> networkDevices = new ArrayList<>();

        int r = Pcap.findAllDevs(networkDevices, errbuf);
        System.out.println(r);
        if (r != Pcap.OK) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return null;
        }

        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : networkDevices) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        return networkDevices;
    }

    // Select the interface to listen on
    public void SetListeningInterface(PcapIf nInterface) {
        this.nInterface = nInterface;
    }

    public void Listen() {
        // Open the device to capture packets
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 10 * 1000;

        Pcap pcap = Pcap.openLive(nInterface.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        System.out.println("Device opened.");

        // PacketHandler will receive the packets
        PcapPacketHandler packetHandler = new PcapPacketHandler() {
            Arp arp = new Arp();

            /*@Override
            public void nextPacket(PcapPacket pcapPacket, Object o) {
                // For testing, this will capture arp-packets only
                if (pcapPacket.hasHeader(arp)) {
                    System.out.println("Hardware type: " + arp.hardwareType());
                    System.out.println("Protocol type: " + arp.protocolType());
                    System.out.println("Packet: " + arp.getPacket());
                    System.out.println();
                }
            }*/

            @Override
            public void nextPacket(PcapPacket pcapPacket, Object o) {
                System.out.println(pcapPacket.toDebugString());
                System.out.println();
            }
        };

        // Start capturing (this will capture only 1 packets)
        pcap.loop(1, packetHandler, "test");

        // Close the device
        pcap.close();
    }
}
