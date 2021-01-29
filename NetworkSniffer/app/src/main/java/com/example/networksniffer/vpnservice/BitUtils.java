package com.example.networksniffer.vpnservice;

/** Binary trickery */
public class BitUtils {
    /** @return Returns an unsigned byte
     * A byte is always signed in Java, but its
     * possible to get its unsigned value by binary-adding
     * it with 0xFF
     * */
    public static short getUnsignedByte(byte value) {
        return (short)(value & 0xFF);
    }

    /** @return Returns an unsigned short */
    public static int getUnsignedShort(short value) {
        return value & 0xFFFF;
    }

    /** @return Returns an unsigned int */
    public static long getUnsignedInt(int value) {
        return value & 0xFFFFFFFFL;
    }
}
