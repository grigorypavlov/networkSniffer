package com.example.networksniffer.vpnservice.networkprotocol;

import java.util.LinkedHashMap;

/** A cache that organizes items in order of use */
public class LRUCache<K, V> extends LinkedHashMap<K, V> {
    private int maxSize;
    private CleanupCallback callback;

    /** Constructor
     * @param maxSize The maximal size of the cache
     * @param callback The callback
     */
    public LRUCache(int maxSize, CleanupCallback callback) {
        super(maxSize + 1, 1, true);

        this.maxSize = maxSize;
        this.callback = callback;
    }

    /** Removes the oldest entry */
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
