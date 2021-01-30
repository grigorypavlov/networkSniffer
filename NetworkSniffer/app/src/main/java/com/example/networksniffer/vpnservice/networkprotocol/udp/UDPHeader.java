package com.example.networksniffer.vpnservice.networkprotocol.udp;

import androidx.annotation.NonNull;

import com.example.networksniffer.vpnservice.BitUtils;

import java.nio.ByteBuffer;

/*                   0      7 8     15 16    23 24    31
 *               +--------+--------+--------+--------+
 *               |     Source      |   Destination   |
 *               |      Port       |      Port       |
 *               +--------+--------+--------+--------+
 *               |                 |                 |
 *               |     Length      |    Checksum     |
 *               +--------+--------+--------+--------+
 *               |
 *               |          data octets ...
 *               +---------------- ...
 */

public class UDPHeader {
    public int sourcePort;
    public int destinationPort;

    public int length;
    public int checksum;

    public UDPHeader(ByteBuffer buffer) {
        this.sourcePort = BitUtils.getUnsignedShort(buffer.getShort());
        this.destinationPort = BitUtils.getUnsignedShort(buffer.getShort());

        this.length = BitUtils.getUnsignedShort(buffer.getShort());
        this.checksum = BitUtils.getUnsignedShort(buffer.getShort());
    }

    public void FillHeader(ByteBuffer buffer) {
        buffer.putShort((short)this.sourcePort);
        buffer.putShort((short)this.destinationPort);

        buffer.putShort((short)this.length);
        buffer.putShort((short)this.checksum);
    }

    @NonNull
    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("UDPHeader{");
        sb.append("sourcePort=").append(sourcePort);
        sb.append(", destinationPort=").append(destinationPort);
        sb.append(", length=").append(length);
        sb.append(", checksum=").append(checksum);
        sb.append('}');
        return sb.toString();
    }
}
