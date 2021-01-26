package com.example.networksniffer.vpnservice.networkprotocol.udp;

import com.example.networksniffer.vpnservice.ByteBufferPool;
import com.example.networksniffer.vpnservice.LocalVPNService;
import com.example.networksniffer.vpnservice.networkprotocol.LRUCache;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

public class UDPOutput implements Runnable {
    private LocalVPNService vpnService;
    private ConcurrentLinkedQueue<Packet> inputQueue;
    private Selector selector;

    private static final int MAX_CACHE_SIZE = 50;
    private LRUCache<String, DatagramChannel> channelCache =
            new LRUCache<>(MAX_CACHE_SIZE, new LRUCache.CleanupCallback<String, DatagramChannel>() {
                @Override
                public void Cleanup(Map.Entry<String, DatagramChannel> eldest) {
                    CloseChannel(eldest.getValue());
                }
            });

    public UDPOutput(ConcurrentLinkedQueue<Packet> inputQueue, Selector selector, LocalVPNService vpnService) {
        this.inputQueue = inputQueue;
        this.selector = selector;
        this.vpnService = vpnService;
    }

    @Override
    public void run() {
        try {
            Thread currentThread = Thread.currentThread();
            while (true) {
                Packet currentPacket;
                do {
                    currentPacket = inputQueue.poll();
                    if (currentPacket != null) {
                        break;
                    }
                    Thread.sleep(10);
                } while (!currentThread.isInterrupted());

                if (currentThread.isInterrupted())
                    break;

                InetAddress destinationAddress = currentPacket.ip4Header.destinationAddress;
                int destinationPort = currentPacket.udpHeader.destinationPort;
                int sourcePort = currentPacket.udpHeader.sourcePort;

                String ipAndPort = destinationAddress.getHostAddress() + ":" + destinationPort + ":" + sourcePort;
                DatagramChannel outputChannel = channelCache.get(ipAndPort);
                if (outputChannel == null) {
                    outputChannel = DatagramChannel.open();
                    vpnService.protect(outputChannel.socket());

                    try {
                        outputChannel.connect(new InetSocketAddress(destinationAddress, destinationPort));
                    } catch (IOException ioex) {
                        CloseChannel(outputChannel);
                        ByteBufferPool.Release(currentPacket.backingBuffer);
                        continue;
                    }

                    outputChannel.configureBlocking(false);
                    currentPacket.SwapSourceAndDestination();

                    selector.wakeup();
                    outputChannel.register(selector, SelectionKey.OP_READ, currentPacket);

                    channelCache.put(ipAndPort, outputChannel);
                }

                try {
                    ByteBuffer payloadBuffer = currentPacket.backingBuffer;
                    while (payloadBuffer.hasRemaining())
                        outputChannel.write(payloadBuffer);
                } catch (IOException ioex) {
                    channelCache.remove(ipAndPort);
                    CloseChannel(outputChannel);
                }

                ByteBufferPool.Release(currentPacket.backingBuffer);
            }
        } catch (InterruptedException iex) {
            // Stop
        } catch (IOException ioex) {
            // TODO: Handle exception
        } finally {
            CloseAll();
        }
    }

    private void CloseAll() {
        Iterator<Map.Entry<String, DatagramChannel>> iterator = channelCache.entrySet().iterator();
        while (iterator.hasNext()) {
            CloseChannel(iterator.next().getValue());
            iterator.remove();
        }
    }

    private void CloseChannel(DatagramChannel channel) {
        try {
            channel.close();
        } catch (IOException ioex) {
            // Ignore
        }
    }
}
