package com.example.networksniffer.sniffers;

import android.widget.TableLayout;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import java.net.SocketException;
import java.util.ArrayList;

public abstract class PacketSniffer {
    PcapIf nInterface = null;

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
            String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        return networkDevices;
    }

    // Select the interface to listen on
    public void SetListeningInterface(PcapIf nInterface) {
        this.nInterface = nInterface;
    }
}
