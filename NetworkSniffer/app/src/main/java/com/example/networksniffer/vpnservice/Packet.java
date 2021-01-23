package com.example.networksniffer.vpnservice;

import androidx.annotation.NonNull;

import com.example.networksniffer.vpnservice.headers.IP4Header;
import com.example.networksniffer.vpnservice.headers.TCPHeader;
import com.example.networksniffer.vpnservice.headers.TransportProtocol;
import com.example.networksniffer.vpnservice.headers.UDPHeader;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Packet {
    public IP4Header ip4Header;
    public TCPHeader tcpHeader;
    public UDPHeader udpHeader;
    public ByteBuffer backingBuffer;

    private boolean isTCP = false;
    private boolean isUDP = false;

    /** Constructor
     * @param buffer The package
     * */
    public Packet(ByteBuffer buffer) throws UnknownHostException {
        this.ip4Header = new IP4Header(buffer);

        if (this.ip4Header.protocol == TransportProtocol.TCP) {
            this.tcpHeader = new TCPHeader(buffer);
            this.isTCP = true;
        } else if (ip4Header.protocol == TransportProtocol.UDP) {
            this.udpHeader = new UDPHeader(buffer);
            this.isUDP = true;
        }

        this.backingBuffer = buffer;
    }

    /** Turns Packet into a human-readable form */
    @NonNull
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Packet{");
        sb.append("ip4Header=").append(ip4Header);
        if (isTCP) sb.append(", tcpHeader=").append(tcpHeader);
        else if (isUDP) sb.append(", udpHeader=").append(udpHeader);
        sb.append(", payloadSize=").append(backingBuffer.limit() - backingBuffer.position());
        sb.append('}');

        return sb.toString();
    }

    public boolean isTCP() {
        return isTCP;
    }

    public boolean isUDP() {
        return isUDP;
    }

    /** Swaps the Source and the Destination */
    public void SwapSourceAndDestination() {
        InetAddress newSourceAddress = ip4Header.destinationAddress;
        ip4Header.destinationAddress = ip4Header.sourceAddress;
        ip4Header.sourceAddress = newSourceAddress;

        if (isUDP) {
            int newSourcePort = udpHeader.destinationPort;
            udpHeader.destinationPort = udpHeader.sourcePort;
            udpHeader.sourcePort = newSourcePort;
        } else if (isTCP) {
            int newSourcePort = tcpHeader.destinationPort;
            tcpHeader.destinationPort = tcpHeader.sourcePort;
            tcpHeader.sourcePort = newSourcePort;
        }
    }
}
