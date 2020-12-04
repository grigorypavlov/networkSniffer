package com.example.networksniffer.sniffers;

import org.jnetpcap.*;

import java.util.ArrayList;
import java.util.List;

public class WLanSniffer implements PacketSniffer{

    @Override
    public void StartListeningAsync() {
        
    }

    @Override
    public void StopListening() {

    }

    public void Test() {
        ArrayList<PcapIf> alldevs = new ArrayList();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(alldevs, errbuf);
        System.out.println(r);
        if (r != Pcap.OK) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }

        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription()
                    : "No description aviable";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }
    }
}
