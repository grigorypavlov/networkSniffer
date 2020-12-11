package com.example.networksniffer.sniffers;

import android.widget.Spinner;
import android.widget.TableLayout;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;

public interface PacketSniffer {
    NetworkInterface nInterface = null;

    void StartListeningAsync(TableLayout tl);
    void StopListening();

    default Enumeration<NetworkInterface> GetInterfaces(Spinner sp) throws SocketException {
        ArrayList<PcapIf> networkDevices = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(networkDevices, errbuf);
        System.out.println(r);
        if (r != Pcap.OK) {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return null;
        }

        System.out.println("Network devices found:");
        int i = 0;
        for (PcapIf device : networkDevices) {
            String description = (device.getDescription() != null) ? device.getDescription() : "No description aviable";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        System.out.println("Choose one of the above devices.");

        return null;
    }
}
