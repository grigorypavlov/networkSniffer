package com.example.networksniffer.vpnservice;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ByteBufferPool {
    private static final int BUFFER_SIZE = 16384;
    private static ConcurrentLinkedQueue<ByteBuffer> pool = new ConcurrentLinkedQueue<>();

    public static ByteBuffer Acquire() {
        ByteBuffer buffer = pool.poll();
        if (buffer == null)
            buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);
        return buffer;
    }

    public static void Release(ByteBuffer buffer) {
        buffer.clear();
        pool.offer(buffer);
    }

    public static void Clear() {
        pool.clear();
    }
}
