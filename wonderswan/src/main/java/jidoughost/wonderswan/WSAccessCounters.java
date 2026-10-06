// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;

/** Primitive access counters; the public map remains live and mutable. */
final class WSAccessCounters extends AbstractMap<String, Integer> {
    static final int IN = 0, LOAD_IO = 1, LOAD_RAM = 2, OUT = 3, STORE_IO = 4, STORE_RAM = 5;
    private static final String[] KEYS = {
        "in:direct", "load:io", "load:ram", "out:direct", "store:io", "store:ram"
    };
    private final int[] counts = new int[KEYS.length];
    private final boolean[] seen = new boolean[KEYS.length], nullValue = new boolean[KEYS.length];
    private final TreeMap<String, Integer> extra = new TreeMap<>();
    private int modifications;

    void increment(int index) {
        if (!seen[index]) modifications++;
        counts[index] = !seen[index] || nullValue[index] ? 1 : counts[index] + 1;
        seen[index] = true; nullValue[index] = false;
    }

    private int index(Object key) {
        Objects.requireNonNull(key);
        for (int i = 0; i < KEYS.length; i++) if (KEYS[i].equals(key)) return i;
        return -1;
    }
    @Override public Integer get(Object key) {
        int i = index(key);
        return i < 0 ? extra.get(key) : !seen[i] || nullValue[i] ? null : counts[i];
    }
    @Override public boolean containsKey(Object key) {
        int i = index(key); return i < 0 ? extra.containsKey(key) : seen[i];
    }
    @Override public Integer put(String key, Integer value) {
        Integer old = get(key);
        if (!containsKey(key)) modifications++;
        int i = index(key);
        if (i < 0) extra.put(key, value);
        else { counts[i] = value == null ? 0 : value; nullValue[i] = value == null; seen[i] = true; }
        return old;
    }
    @Override public Integer remove(Object key) {
        if (!containsKey(key)) return null;
        Integer old = get(key); modifications++;
        int i = index(key);
        if (i < 0) extra.remove(key); else { seen[i] = false; nullValue[i] = false; }
        return old;
    }
    @Override public int size() {
        int size = extra.size(); for (boolean value : seen) if (value) size++; return size;
    }
    @Override public void clear() {
        if (size() == 0) return;
        Arrays.fill(counts, 0); Arrays.fill(seen, false); Arrays.fill(nullValue, false);
        extra.clear(); modifications++;
    }
    @Override public Set<Entry<String, Integer>> entrySet() {
        return new AbstractSet<>() {
            @Override public int size() { return WSAccessCounters.this.size(); }
            @Override public void clear() { WSAccessCounters.this.clear(); }
            @Override public Iterator<Entry<String, Integer>> iterator() {
                TreeSet<String> keys = new TreeSet<>(extra.keySet());
                for (int i = 0; i < KEYS.length; i++) if (seen[i]) keys.add(KEYS[i]);
                Iterator<String> it = keys.iterator();
                return new Iterator<>() {
                    int expected = modifications;
                    String last;
                    private void check() {
                        if (expected != modifications) throw new ConcurrentModificationException();
                    }
                    @Override public boolean hasNext() { check(); return it.hasNext(); }
                    @Override public Entry<String, Integer> next() {
                        check(); String key = it.next(); last = key;
                        return new Entry<>() {
                            @Override public String getKey() { return key; }
                            @Override public Integer getValue() { return get(key); }
                            @Override public Integer setValue(Integer value) { return put(key, value); }
                            @Override public boolean equals(Object other) {
                                return other instanceof Entry<?, ?> e && Objects.equals(key, e.getKey()) &&
                                    Objects.equals(getValue(), e.getValue());
                            }
                            @Override public int hashCode() { return key.hashCode() ^ Objects.hashCode(getValue()); }
                            @Override public String toString() { return key + "=" + getValue(); }
                        };
                    }
                    @Override public void remove() {
                        check(); if (last == null) throw new IllegalStateException();
                        WSAccessCounters.this.remove(last); expected = modifications; last = null;
                    }
                };
            }
        };
    }
}
