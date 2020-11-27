package com.example.networksniffer.sniffers;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;

public class WLanSniffer implements PacketSniffer{

    @Override
    public void StartListeningAsync() {

    }

    @Override
    public void StopListening() {

    }

    private void Test() {
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName("lo");
        } catch (SocketException e) {
            e.printStackTrace();
        }
        
    }
}
