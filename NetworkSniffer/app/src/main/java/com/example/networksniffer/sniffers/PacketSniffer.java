package com.example.networksniffer.sniffers;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;

public interface PacketSniffer {
    NetworkInterface nInterface = null;

    void StartListeningAsync();
    void StopListening();

    default Enumeration<NetworkInterface> GetInterfaces() throws SocketException {
        return NetworkInterface.getNetworkInterfaces();
    }
}
