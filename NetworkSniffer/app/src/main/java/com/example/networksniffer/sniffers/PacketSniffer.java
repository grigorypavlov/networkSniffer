package com.example.networksniffer.sniffers;

import android.widget.TableLayout;

import com.example.networksniffer.observerpattern.IPublisher;
import com.example.networksniffer.observerpattern.ISubscriber;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import java.net.SocketException;
import java.util.ArrayList;

public abstract class PacketSniffer implements IPublisher {
    private PcapIf nInterface = null;
    public StringBuilder errbuf = new StringBuilder();
    protected boolean run = false;

    /** Notifies all subs with the new packet */
    public void Notify() {
        for (ISubscriber s : subscribers) {
            s.Update(null); // TODO: Pass packet
        }
    }

    /** @return Returns the selected interface */
    public PcapIf getnInterface() {
        return nInterface;
    }

    /** Starts the listening-thread
     * @param tl will be filled with the information from the packets */
    public void StartListeningAsync(TableLayout tl) throws Exception {
        if (nInterface == null) {
            throw new Exception("No network-interface specified!");
        }

        run = true;
        Listen();
    };

    // Stops the listening thread
    public void StopListening() {
        run = false;
    };

    /** @return all available network interfaces */
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

    /** Select the interface to listen on */
    public void SetListeningInterface(PcapIf nInterface) {
        this.nInterface = nInterface;
    }

    public abstract void Listen();
}
