package com.example.networksniffer.vpnservice.headers;

import androidx.annotation.NonNull;

import com.example.networksniffer.vpnservice.BitUtils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class IP4Header {
    public byte version;
    public byte IHL;
    public int headerLength;
    public short typeOfService;
    public int totalLength;
    public int identificationAndFlagsAndFragmentOffset;
    public short TTL;
    private short protocolNumber;
    public TransportProtocol protocol;
    public int headerChecksum;
    public InetAddress sourceAddress;
    public InetAddress destinationAddress;
    public int optionsAndPadding;

    /** Constructor */
    public IP4Header(ByteBuffer buffer) throws UnknownHostException {
        byte versionAndIHL = buffer.get();
        this.version = (byte)(versionAndIHL >> 4);
        this.IHL = (byte)(versionAndIHL & 0x0F);
        this.typeOfService = BitUtils.getUnsignedByte(buffer.get());
        this.totalLength = BitUtils.getUnsignedShort(buffer.getShort());
        this.identificationAndFlagsAndFragmentOffset = buffer.getInt();
        this.TTL = BitUtils.getUnsignedByte(buffer.get());
        this.protocolNumber = BitUtils.getUnsignedByte(buffer.get());
        this.protocol = TransportProtocol.NumberToEnum(protocolNumber);
        this.headerChecksum = BitUtils.getUnsignedShort(buffer.getShort());

        byte[] addressBytes = new byte[4];
        buffer.get(addressBytes, 0, 4);
        this.sourceAddress = InetAddress.getByAddress(addressBytes);
    }

    /** Fill the header with information
     * @param buffer Data is written in this buffer */
    public void fillHeader(ByteBuffer buffer) {
        buffer.put((byte)(this.version << 4 | this.IHL));
        buffer.put((byte)this.totalLength);
        buffer.putShort((short)this.totalLength);
        buffer.putInt(this.identificationAndFlagsAndFragmentOffset);
        buffer.put((byte)this.TTL);
        buffer.put((byte)this.protocol.GetNumber());
        buffer.putShort((short)this.headerChecksum);
        buffer.put(this.sourceAddress.getAddress());
        buffer.put(this.destinationAddress.getAddress());
    }

    /** Turn IP4Header into more human-readable output */
    @NonNull
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IP4Header{");
        sb.append("version=").append(version);
        sb.append(", IHL=").append(IHL);
        sb.append(", typeOfService=").append(typeOfService);
        sb.append(", totalLength=").append(totalLength);
        sb.append(", identificationAndFlagsAndFragmentOffset=").append(identificationAndFlagsAndFragmentOffset);
        sb.append(", TTL=").append(TTL);
        sb.append(", protocol=").append(protocolNumber).append(":").append(protocol);
        sb.append(", headerChecksum=").append(headerChecksum);
        sb.append(", sourceAddress=").append(sourceAddress.getHostAddress());
        sb.append(", destinationAddress=").append(destinationAddress.getHostAddress());
        sb.append('}');
        return sb.toString();
    }
}
