package com.example.networksniffer.vpnservice.networkprotocol;

import com.example.networksniffer.vpnservice.Packet;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.Map;

/** Transmission Control Block
 *
 * */
public class TCB {
    public String ipAndPort;

    public long mySequenceNum, theirSequenceNum;
    public long myAcknowledgementNum, theirAcknowledgementNum;
    public TCBStatus status;

    public enum TCBStatus {
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK
    }

    public Packet referencePacket;

    public SocketChannel channel;
    public boolean waitingForNetworkData;
    public SelectionKey selectionKey;

    private static final int MAX_CACHE_SIZE = 50;
    private static LRUCache<String, TCB> tcbCache =
            new LRUCache<>(MAX_CACHE_SIZE, new LRUCache.CleanupCallback<String, TCB>() {
                @Override
                public void Cleanup(Map.Entry<String, TCB> eldest) {
                    eldest.getValue().CloseChannel();
                }
            });

    public static TCB GetTCB(String ipAndPort) {
        synchronized (tcbCache) {
            return tcbCache.get(ipAndPort);
        }
    }

    public static void PutTCB(String ipAndPort, TCB tcb) {
        synchronized (tcbCache) {
            tcbCache.put(ipAndPort, tcb);
        }
    }

    public TCB(String ipAndPort, long mySequenceNum, long theirSequenceNum, long myAcknowledgementNum, long theirAcknowledgementNum,
               SocketChannel channel, Packet referencePacket) {
        this.ipAndPort = ipAndPort;
        this.mySequenceNum = mySequenceNum;
        this.theirSequenceNum = theirSequenceNum;
        this.myAcknowledgementNum = myAcknowledgementNum;
        this.channel = channel;
        this.referencePacket = referencePacket;
    }

    public static void CloseTCB(TCB tcb) {
        tcb.CloseChannel();
        synchronized (tcbCache) {
            tcbCache.remove(tcb.ipAndPort);
        }
    }

    public static void CloseAll() {
        synchronized (tcbCache) {
            Iterator<Map.Entry<String, TCB>> iterator = tcbCache.entrySet().iterator();
            while (iterator.hasNext()) {
                iterator.next().getValue().CloseChannel();
                iterator.remove();
            }
        }
    }

    public void CloseChannel() {
        try {
            channel.close();
        } catch (IOException ioex) {
            // Ignore
        }
    }
}
