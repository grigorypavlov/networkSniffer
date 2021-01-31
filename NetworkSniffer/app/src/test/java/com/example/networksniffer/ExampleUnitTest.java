package com.example.networksniffer;

import com.example.networksniffer.sniffers.Sniffer;
import com.example.networksniffer.vpnservice.BitUtils;
import com.example.networksniffer.vpnservice.networkprotocol.TransportProtocol;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {

    @Test
    public void testBinary() {
        short ret1 = BitUtils.getUnsignedByte((byte)4);
        String binaryString = Integer.toBinaryString(ret1);
        assertEquals("100", binaryString);

        int ret2 = BitUtils.getUnsignedShort((short)4);
        binaryString = Integer.toBinaryString(ret2);
        assertEquals("100", binaryString);

        long ret3 = BitUtils.getUnsignedInt((short)4);
        binaryString = Long.toBinaryString(ret3);
        assertEquals("100", binaryString);
    }

    @Test
    public void testSingleton() {
        Sniffer sniffer1 = Sniffer.getInstance();
        Sniffer sniffer2 = Sniffer.getInstance();

        assertEquals(sniffer1, sniffer2);
    }

    @Test
    public void testVPN() {
        // TODO: Test the vpn
    }
}