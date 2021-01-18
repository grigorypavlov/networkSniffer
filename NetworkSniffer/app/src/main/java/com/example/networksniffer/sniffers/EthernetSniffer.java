package com.example.networksniffer.sniffers;


import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/** Sniffer for ethernet-packages */
public class EthernetSniffer extends PacketSniffer {

    public void Listen() {
        // Open the device to capture packets
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 10 * 1000;

        Pcap pcap = Pcap.openLive(getnInterface().getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        System.out.println("Device opened.");

        // PacketHandler will receive the packets
        PcapPacketHandler packetHandler = new PcapPacketHandler() {
            @Override
            public void nextPacket(PcapPacket pcapPacket, Object o) {
                System.out.println(pcapPacket.toDebugString());
                System.out.println();
            }
        };

        // Start capturing (this will capture only 1 packet)
        pcap.loop(1, packetHandler, "test");

        // Close the device
        pcap.close();
    }
}
