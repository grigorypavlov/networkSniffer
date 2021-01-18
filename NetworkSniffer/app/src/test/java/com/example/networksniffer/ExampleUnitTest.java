package com.example.networksniffer;

import com.example.networksniffer.sniffers.EthernetSniffer;
import com.example.networksniffer.sniffers.PacketSniffer;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void test() {
        PacketSniffer sniffer = new EthernetSniffer();
        assertTrue(sniffer.getnInterface() != null);
    }
}