package com.example.networksniffer.sniffers;

import java.net.NetworkInterface;

public interface PacketSniffer {
    NetworkInterface nInterface = null;

    void StartListeningAsync();
    void StopListening();
}
