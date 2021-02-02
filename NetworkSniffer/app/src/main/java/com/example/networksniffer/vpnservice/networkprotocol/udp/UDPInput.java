package com.example.networksniffer.vpnservice.networkprotocol.udp;

import android.os.strictmode.CredentialProtectedWhileLockedViolation;

import com.example.networksniffer.vpnservice.ByteBufferPool;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

public class UDPInput implements Runnable {
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.UDP_HEADER_SIZE;

    private Selector selector;
    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;

    public UDPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector) {
        this.outputQueue = outputQueue;
        this.selector = selector;
    }

    @Override
    public void run() {
        try {
            while (!Thread.interrupted()) {
                int readyChannels = selector.select();

                if (readyChannels == 0) {
                    Thread.sleep(10);
                    continue;
                }

                Set<SelectionKey> keys = selector.selectedKeys();
                Iterator<SelectionKey> keyIterator = keys.iterator();

                while (keyIterator.hasNext() && !Thread.interrupted()) {
                    SelectionKey key = keyIterator.next();
                    if (key.isValid() && key.isReadable()) {
                        keyIterator.remove();;

                        ByteBuffer receiveBuffer = ByteBufferPool.Acquire();
                        receiveBuffer.position(HEADER_SIZE);

                        DatagramChannel inputChannel = (DatagramChannel) key.channel();
                        int readBytes = inputChannel.read(receiveBuffer);

                        Packet referencePacket = (Packet) key.attachment();
                        referencePacket.UpdateUDPBuffer(receiveBuffer, readBytes);
                        receiveBuffer.position(HEADER_SIZE + readBytes);

                        outputQueue.offer(receiveBuffer);
                    }
                }
            }
        } catch (InterruptedException iex) {
            // Stop
        } catch (IOException ioex) {
            // TODO: Handle exception
            ioex.printStackTrace();
        }
    }
}
