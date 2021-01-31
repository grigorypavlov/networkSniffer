package com.example.networksniffer.vpnservice.networkprotocol.tcp;

import com.example.networksniffer.vpnservice.ByteBufferPool;
import com.example.networksniffer.vpnservice.LocalVPNService;
import com.example.networksniffer.vpnservice.networkprotocol.Packet;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

public class TCPOutput implements Runnable {
    private LocalVPNService vpnService;
    private ConcurrentLinkedQueue<Packet> inputQueue;
    private ConcurrentLinkedQueue<ByteBuffer> outputQueue;
    private Selector selector;

    private Random random = new Random();

    public TCPOutput(ConcurrentLinkedQueue<Packet> inputQueue, ConcurrentLinkedQueue<ByteBuffer> outputQueue,
                     Selector selector, LocalVPNService vpnService) {
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
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

                //System.out.println("TCP-Out: " + currentPacket.toString());

                ByteBuffer payloadBuffer = currentPacket.backingBuffer;
                currentPacket.backingBuffer = null;
                ByteBuffer responseBuffer = ByteBufferPool.Acquire();

                InetAddress destinationAddress = currentPacket.ip4Header.destinationAddress;

                TCPHeader tcpHeader = currentPacket.tcpHeader;
                int destinationPort = tcpHeader.destinationPort;
                int sourcePort = tcpHeader.sourcePort;

                String ipAndPort = destinationAddress.getHostAddress() + ":" + destinationPort + ":" + sourcePort;
                TCB tcb = TCB.GetTCB(ipAndPort);
                if (tcb == null)
                    InitializeConnection(ipAndPort, destinationAddress, destinationPort, currentPacket, tcpHeader, responseBuffer);
                else if (tcpHeader.isSYN())
                    ProcessDuplicateSYN(tcb, tcpHeader, responseBuffer);
                else if (tcpHeader.isRST())
                    CloseCleanly(tcb, responseBuffer);
                else if (tcpHeader.isFIN())
                    ProcessFIN(tcb, tcpHeader, responseBuffer);
                else if (tcpHeader.isACK())
                    ProcessACK(tcb, tcpHeader, payloadBuffer, responseBuffer);

                if (responseBuffer.position() == 0)
                    ByteBufferPool.Release(responseBuffer);
                ByteBufferPool.Release(payloadBuffer);
            }
        } catch (InterruptedException iex) {
            // Stop
        } catch (IOException ioex) {
            // TODO: Handle exception
            ioex.printStackTrace();
        } finally {
            TCB.CloseAll();
        }
    }

    private void InitializeConnection(String ipAndPort, InetAddress destinationAddress, int destinationPort,
                                      Packet currentPacket, TCPHeader tcpHeader, ByteBuffer responseBuffer) throws IOException {
        currentPacket.SwapSourceAndDestination();
        if (tcpHeader.isSYN()) {
            SocketChannel outputChannel = SocketChannel.open();
            outputChannel.configureBlocking(false);
            vpnService.protect(outputChannel.socket());

            TCB tcb = new TCB(ipAndPort, random.nextInt(Short.MAX_VALUE + 1), tcpHeader.sequenceNumber, tcpHeader.sequenceNumber + 1,
                    tcpHeader.acknowledgementNumber, outputChannel, currentPacket);
            TCB.SetTCB(ipAndPort, tcb);

            try {
                outputChannel.connect(new InetSocketAddress(destinationAddress, destinationPort));
                if (outputChannel.finishConnect()) {
                    tcb.status = TCB.TCBStatus.SYN_RECEIVED;

                    currentPacket.UpdateTCPBuffer(responseBuffer, (byte) (TCPHeader.SYN | TCPHeader.ACK),
                            tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                    tcb.mySequenceNum++;
                } else {
                    tcb.status = TCB.TCBStatus.SYN_SENT;
                    selector.wakeup();
                    tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_CONNECT, tcb);
                    return;
                }
            } catch (IOException ioex) {
                currentPacket.UpdateTCPBuffer(responseBuffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum, 0);
                TCB.CloseTCB(tcb);
            }
        } else {
            currentPacket.UpdateTCPBuffer(responseBuffer, (byte) TCPHeader.RST, 0, tcpHeader.sequenceNumber + 1, 0);
        }

        outputQueue.offer(responseBuffer);
    }

    private void ProcessDuplicateSYN(TCB tcb, TCPHeader tcpHeader, ByteBuffer responseBuffer) {
        synchronized (tcb) {
            if (tcb.status == TCB.TCBStatus.SYN_SENT) {
                tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1;
                return;
            }
        }

        SentRST(tcb, 1, responseBuffer);
    }

    private void ProcessFIN(TCB tcb, TCPHeader tcpHeader, ByteBuffer responseBuffer) {
        synchronized (tcb) {
            Packet referencePacket = tcb.referencePacket;
            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + 1;
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber;

            if (tcb.waitingForNetworkData) {
                tcb.status = TCB.TCBStatus.CLOSE_WAIT;
                referencePacket.UpdateTCPBuffer(responseBuffer, (byte) TCPHeader.ACK, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
            } else {
                tcb.status = TCB.TCBStatus.LAST_ACK;
                referencePacket.UpdateTCPBuffer(responseBuffer, (byte) (TCPHeader.FIN | TCPHeader.ACK),
                        tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
                tcb.mySequenceNum++;
            }
        }

        outputQueue.offer(responseBuffer);
    }

    private void ProcessACK(TCB tcb, TCPHeader tcpHeader, ByteBuffer payloadBuffer, ByteBuffer responseBuffer) throws IOException {
        int payloadSize = payloadBuffer.limit() - payloadBuffer.position();

        synchronized (tcb) {
            SocketChannel outputChannel = tcb.channel;
            if (tcb.status == TCB.TCBStatus.SYN_RECEIVED) {
                tcb.status = TCB.TCBStatus.ESTABLISHED;

                selector.wakeup();
                tcb.selectionKey = outputChannel.register(selector, SelectionKey.OP_READ, tcb);
                tcb.waitingForNetworkData = true;
            } else if (tcb.status == TCB.TCBStatus.LAST_ACK) {
                CloseCleanly(tcb, responseBuffer);
                return;
            }

            if (payloadSize == 0) return; // Empty ACK, ignore

            if (!tcb.waitingForNetworkData) {
                selector.wakeup();
                tcb.selectionKey.interestOps(SelectionKey.OP_READ);
                tcb.waitingForNetworkData = true;
            }

            // Forward to remote server
            try {
                while (payloadBuffer.hasRemaining()) {
                    outputChannel.write(payloadBuffer);
                }
            } catch (IOException ioex) {
                SentRST(tcb, payloadSize, responseBuffer);
                return;
            }

            tcb.myAcknowledgementNum = tcpHeader.sequenceNumber + payloadSize;
            tcb.theirAcknowledgementNum = tcpHeader.acknowledgementNumber;
            Packet referencePacket = tcb.referencePacket;
            referencePacket.UpdateTCPBuffer(responseBuffer, (byte) TCPHeader.ACK, tcb.mySequenceNum, tcb.myAcknowledgementNum, 0);
        }

        outputQueue.offer(responseBuffer);
    }

    private void SentRST(TCB tcb, int prevPayloadSize, ByteBuffer buffer) {
        tcb.referencePacket.UpdateTCPBuffer(buffer, (byte) TCPHeader.RST, 0, tcb.myAcknowledgementNum + prevPayloadSize, 0);
        outputQueue.offer(buffer);
        TCB.CloseTCB(tcb);
    }

    private void CloseCleanly(TCB tcb, ByteBuffer buffer) {
        ByteBufferPool.Release(buffer);
        TCB.CloseTCB(tcb);
    }
}
