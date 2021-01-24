package com.example.networksniffer.vpnservice.networkprotocol;

import java.util.LinkedHashMap;

public class LRUCache<K, V> extends LinkedHashMap<K, V> {
    private int maxSize;
    private CleanupCallback callback;

    public LRUCache(int maxSize, CleanupCallback callback) {
        super(maxSize + 1, 1, true);

        this.maxSize = maxSize;
        this.callback = callback;
    }

    @Override
    protected boolean removeEldestEntry(Entry<K, V> eldest) {
        if (size() > maxSize) {
            callback.Cleanup(eldest);
            return true;
        }

        return false;
    }

    public static interface CleanupCallback<K, V> {
        public void Cleanup(Entry<K, V> eldest);
    }
}
