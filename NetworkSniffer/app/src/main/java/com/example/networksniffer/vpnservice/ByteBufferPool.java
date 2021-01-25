package com.example.networksniffer.vpnservice;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedQueue;

public class ByteBufferPool {
    private static final int BUFFER_SIZE = 16384; // Size of buffer
    private static ConcurrentLinkedQueue<ByteBuffer> pool = new ConcurrentLinkedQueue<>();

    /** Get a buffer from the pool */
    public static ByteBuffer Acquire() {
        ByteBuffer buffer = pool.poll();
        // If the buffer wasn't already allocated, allocate the buffer now
        if (buffer == null)
            buffer = ByteBuffer.allocateDirect(BUFFER_SIZE);

        return buffer;
    }

    /** Release the buffer */
    public static void Release(ByteBuffer buffer) {
        buffer.clear();
        pool.offer(buffer); // Makes the buffer available again
    }

    /** Deletes all buffers */
    public static void Clear() {
        pool.clear();
    }
}
