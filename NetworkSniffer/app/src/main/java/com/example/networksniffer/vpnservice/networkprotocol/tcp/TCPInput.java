package com.example.networksniffer.vpnservice.networkprotocol.tcp;

import com.example.networksniffer.vpnservice.ByteBufferPool;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

public class TCPInput implements Runnable {
    private static final int HEADER_SIZE = Packet.IP4_HEADER_SIZE + Packet.TCP_HEADER_SIZE;

    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    public TCPInput(ConcurrentLinkedQueue<ByteBuffer> outputQueue, Selector selector) {
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
                    if (key.isValid()) {
                        if (key.isConnectable()) {
                            ProcessConnect(key, keyIterator);
                        } else if (key.isReadable()) {
                            ProcessInput(key, keyIterator);
                        }
                    }
                }
            }
        } catch (InterruptedException iex) {
            // TODO: Handel exception
        } catch (IOException ioex) {
            // TODO: Handel exception
            ioex.printStackTrace();
        }
    }

    private void ProcessConnect(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        TCB tcb = (TCB) key.attachment();
        Packet referencePacket = tcb.referencePacket;

        try {
            if (tcb.channel.finishConnect()) {
                keyIterator.remove();
                tcb.status = TCB.TCBStatus.SYN_RECEIVED;

                ByteBuffer responseBuffer = ByteBufferPool.Acquire();
                referencePacket.UpdateTCPBuffer(responseBuffer, (byte) (TCPHeader.SYN | TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                outputQueue.offer(responseBuffer);

                tcb.mySequenceNum++;
                key.interestOps(SelectionKey.OP_READ);
            }
        } catch (IOException ioex) {
            ByteBuffer responeBuffer = ByteBufferPool.Acquire();
            referencePacket.UpdateTCPBuffer(responeBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
            outputQueue.offer(responeBuffer);
            TCB.CloseTCB(tcb);
        }
    }

    private void ProcessInput(SelectionKey key, Iterator<SelectionKey> keyIterator) {
        keyIterator.remove();
        ByteBuffer receiveBuffer = ByteBufferPool.Acquire();
        receiveBuffer.position(HEADER_SIZE);

        TCB tcb = (TCB) key.attachment();
        synchronized (tcb) {
            Packet referencePacket = tcb.referencePacket;
            SocketChannel inputChannel = (SocketChannel) key.channel();
            int readBytes;

            try {
                readBytes = inputChannel.read(receiveBuffer);
            } catch (IOException ioex) {
                referencePacket.UpdateTCPBuffer(receiveBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                outputQueue.offer(receiveBuffer);
                TCB.CloseTCB(tcb);
                return;
            }

            if (readBytes == -1) {
                // End of stream
                key.interestOps(0);
                tcb.waitingForNetworkData = false;

                if (tcb.status != TCB.TCBStatus.CLOSE_WAIT) {
                    ByteBufferPool.Release(receiveBuffer);
                    return;
                }

                tcb.status = TCB.TCBStatus.LAST_ACK;
                referencePacket.UpdateTCPBuffer(receiveBuffer, (byte) TCPHeader.FIN, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                tcb.mySequenceNum++;
            } else {
                referencePacket.UpdateTCPBuffer(receiveBuffer, (byte) (TCPHeader.PSH | TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, readBytes);
                tcb.mySequenceNum += readBytes;
                receiveBuffer.position(HEADER_SIZE + readBytes);
            }
        }

        System.out.println("TCP-Input:" + receiveBuffer.toString());
        outputQueue.offer(receiveBuffer);
    }
}
