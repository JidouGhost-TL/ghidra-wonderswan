// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;

/** Address-indexed evidence with a live Map view and sorted iteration for analysis scripts. */
final class WSAddressMap<V> extends AbstractMap<Long, V> {
    private final Object[] values;
    private final BitSet present = new BitSet();
    private final TreeMap<Long, V> overflow = new TreeMap<>();
    private int size, modifications;

    WSAddressMap(int capacity) { values = new Object[capacity]; }

    private boolean dense(long key) { return key >= 0 && key < values.length; }

    @SuppressWarnings("unchecked")
    V get(long key) { return dense(key) ? (V) values[(int) key] : overflow.get(key); }

    boolean containsKey(long key) {
        return dense(key) ? present.get((int) key) : overflow.containsKey(key);
    }

    V putAt(long key, V value) {
        V old = get(key);
        if (!containsKey(key)) { size++; modifications++; }
        if (dense(key)) { values[(int) key] = value; present.set((int) key); }
        else overflow.put(key, value);
        return old;
    }

    @Override public V get(Object key) { return key instanceof Long k ? get(k.longValue()) : null; }
    @Override public boolean containsKey(Object key) {
        return key instanceof Long k && containsKey(k.longValue());
    }
    @Override public V put(Long key, V value) { return putAt(key.longValue(), value); }
    @Override public int size() { return size; }

    @Override public V remove(Object key) {
        if (!(key instanceof Long k) || !containsKey(k.longValue())) return null;
        V old = get(k.longValue());
        if (dense(k)) { values[k.intValue()] = null; present.clear(k.intValue()); }
        else overflow.remove(k);
        size--; modifications++;
        return old;
    }

    @Override public void clear() {
        if (size == 0) return;
        Arrays.fill(values, null); present.clear(); overflow.clear();
        size = 0; modifications++;
    }

    @Override public Set<Entry<Long, V>> entrySet() {
        return new AbstractSet<>() {
            @Override public int size() { return WSAddressMap.this.size; }
            @Override public void clear() { WSAddressMap.this.clear(); }
            @Override public Iterator<Entry<Long, V>> iterator() {
                // Iteration is a cold path; retain primitive indexing during instruction execution.
                TreeSet<Long> keys = new TreeSet<>(overflow.keySet());
                for (int k = present.nextSetBit(0); k >= 0; k = present.nextSetBit(k + 1)) keys.add((long) k);
                Iterator<Long> it = keys.iterator();
                return new Iterator<>() {
                    int expected = modifications;
                    Long last;
                    private void check() {
                        if (expected != modifications) throw new ConcurrentModificationException();
                    }
                    @Override public boolean hasNext() { check(); return it.hasNext(); }
                    @Override public Entry<Long, V> next() {
                        check();
                        long key = it.next(); last = key;
                        return new Entry<>() {
                            @Override public Long getKey() { return key; }
                            @Override public V getValue() { return get(key); }
                            @Override public V setValue(V value) { return putAt(key, value); }
                            @Override public boolean equals(Object other) {
                                return other instanceof Entry<?, ?> e && Objects.equals(getKey(), e.getKey()) &&
                                    Objects.equals(getValue(), e.getValue());
                            }
                            @Override public int hashCode() { return Objects.hashCode(getKey()) ^ Objects.hashCode(getValue()); }
                            @Override public String toString() { return key + "=" + getValue(); }
                        };
                    }
                    @Override public void remove() {
                        check();
                        if (last == null) throw new IllegalStateException();
                        WSAddressMap.this.remove(last); expected = modifications; last = null;
                    }
                };
            }
        };
    }
}
