package com.example.networksniffer;

import com.example.networksniffer.sniffers.EthernetSniffer;
import com.example.networksniffer.sniffers.PacketSniffer;
import com.example.networksniffer.vpnservice.BitUtils;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    /*@Test
    public void test() {
        PacketSniffer sniffer = new EthernetSniffer();
        assertTrue(sniffer.getnInterface() != null);
    }*/

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
}