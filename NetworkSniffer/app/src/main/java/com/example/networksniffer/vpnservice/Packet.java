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
    public static final int IP4_HEADER_SIZE = 20;
    public static final int TCP_HEADER_SIZE = 20;
    public static final int UDP_HEADER_SIZE = 8;

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

    /** Updates the TCP-Buffer
     * @param buffer Buffer to update
     * @param ackNum New ack-number
     * @param flags New flags
     * @param payloadSize New payload-size
     * @param sequenceNum New sequence-number
     * */
    public void UpdateTCPBuffer(ByteBuffer buffer, byte flags, long sequenceNum, long ackNum, int payloadSize) {
        buffer.position(0); // Go to the start of the buffer
        FillHeader(buffer);
        backingBuffer = buffer;

        tcpHeader.flags = flags;
        backingBuffer.put(IP4_HEADER_SIZE + 13, flags);

        tcpHeader.sequenceNumber = sequenceNum;
        backingBuffer.putInt(IP4_HEADER_SIZE + 4, (int)sequenceNum);

        tcpHeader.acknowledgementNumber = ackNum;
        backingBuffer.putInt(IP4_HEADER_SIZE + 8, (int)ackNum);

        // Reset header size, we don't care about the options
        byte dataOffset = (byte)(TCP_HEADER_SIZE << 2);
        tcpHeader.dataOffsetAndReserved = dataOffset;
        backingBuffer.put(IP4_HEADER_SIZE + 12, dataOffset);

        UpdateTCPChecksum(payloadSize);

        int ip4TotalLength = IP4_HEADER_SIZE + TCP_HEADER_SIZE + payloadSize;
        backingBuffer.putShort(2, (short)ip4TotalLength);
        ip4Header.totalLength = ip4TotalLength;

        UpdateIP4Checksum();
    }

    /** Updates the TCP-Buffer
     * @param buffer Buffer to update
     * @param payloadSize New payload-size
     * */
    public void UpdateUDPBuffer(ByteBuffer buffer, int payloadSize) {
        buffer.position(0); // Go to the start of the buffer
        FillHeader(buffer);
        backingBuffer = buffer;

        int udpTotalLength = UDP_HEADER_SIZE + payloadSize;
        backingBuffer.putShort(IP4_HEADER_SIZE + 4, (short)udpTotalLength);
        udpHeader.length = udpTotalLength;

        // Disable UDP checksum validation
        backingBuffer.putShort(IP4_HEADER_SIZE + 6, (short)0);
        udpHeader.checksum = 0;

        int ip4TotalLength = IP4_HEADER_SIZE + udpTotalLength;
        backingBuffer.putShort(2, (short)ip4TotalLength);
        ip4Header.totalLength = ip4TotalLength;

        UpdateIP4Checksum();
    }

    /** Updates the IPv4 checksum */
    private void UpdateIP4Checksum() {
        ByteBuffer buffer = backingBuffer.duplicate();
        buffer.position(0);

        // Clear previous checksum
        buffer.putShort(10, (short)0);

        int ipLength = ip4Header.headerLength;
        int sum = 0;

        while (ipLength > 0) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            ipLength -= 2;
        }

        while (sum >> 16 > 0)
            sum = (sum & 0xFFFF) + (sum >> 16);

        sum = ~sum;
        ip4Header.headerChecksum = sum;
        backingBuffer.putShort(10, (short)sum);
    }

    private void UpdateTCPChecksum(int payloadSize) {
        int sum = 0;
        int tcpLength = TCP_HEADER_SIZE + payloadSize;

        // Calculate pseudo-header checksum
        ByteBuffer buffer = ByteBuffer.wrap(ip4Header.sourceAddress.getAddress());
        sum = BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        buffer = ByteBuffer.wrap(ip4Header.destinationAddress.getAddress());
        sum += BitUtils.getUnsignedShort(buffer.getShort()) + BitUtils.getUnsignedShort(buffer.getShort());

        sum += TransportProtocol.TCP.GetNumber() + tcpLength;

        buffer = backingBuffer.duplicate();

        // Clear previous checksum
        buffer.putShort(IP4_HEADER_SIZE + 16, (short)0);

        // Calculate TCP segment checksum
        buffer.position(IP4_HEADER_SIZE);
        while (tcpLength > 1) {
            sum += BitUtils.getUnsignedShort(buffer.getShort());
            tcpLength -= 2;
        }

        if (tcpLength > 0)
            sum += BitUtils.getUnsignedShort(buffer.get()) << 8;

        while (sum >> 16 > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = ~sum;
        tcpHeader.checksum = sum;
        backingBuffer.putShort(IP4_HEADER_SIZE + 16, (short)sum);
    }

    /** Creates headers
     * @param buffer Contains header data
     * */
    public void FillHeader(ByteBuffer buffer) {
        ip4Header.FillHeader(buffer);
        if (isUDP)
            udpHeader.FillHeader(buffer);
        else if (isTCP)
            tcpHeader.FillHeader(buffer);
    }
}
