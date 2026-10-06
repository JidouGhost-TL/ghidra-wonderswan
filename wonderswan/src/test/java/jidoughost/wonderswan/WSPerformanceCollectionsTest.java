// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

public class WSPerformanceCollectionsTest {
    @Test public void evidenceMapHasLiveMutableViewsAndSortedOverflow() {
        WSAddressMap<String> map = new WSAddressMap<>(16);
        map.put(5L, "five"); map.put(-1L, "negative"); map.put(32L, "overflow"); map.put(2L, null);
        assertEquals(List.of(-1L, 2L, 5L, 32L), new ArrayList<>(map.keySet()));
        assertTrue(map.containsKey(2L)); assertNull(map.get(2L));
        map.putIfAbsent(2L, "two"); assertEquals("two", map.get(2L));
        var iterator = map.entrySet().iterator();
        var entry = iterator.next();
        map.put(-1L, "changed"); assertEquals("changed", entry.getValue());
        assertEquals(Map.entry(-1L, "changed"), entry);
        assertEquals(Map.entry(-1L, "changed").hashCode(), entry.hashCode());
        entry.setValue("updated"); assertEquals("updated", map.get(-1L));
        iterator.remove(); assertFalse(map.containsKey(-1L));
        map.values().remove("overflow"); assertEquals(2, map.size());
        assertEquals(new TreeMap<>(map), map);
        map.keySet().clear(); assertTrue(map.isEmpty());
    }

    @Test public void evidenceIteratorsDetectStructuralChanges() {
        WSAddressMap<Integer> map = new WSAddressMap<>(16);
        map.put(1L, 1); var iterator = map.entrySet().iterator();
        map.put(2L, 2);
        assertThrows(ConcurrentModificationException.class, iterator::next);
    }

    @Test public void countersPreserveAbsentNullOverflowAndLiveEntries() {
        WSAccessCounters counters = new WSAccessCounters();
        assertTrue(counters.isEmpty());
        counters.increment(WSAccessCounters.LOAD_RAM);
        var entry = counters.entrySet().iterator().next();
        counters.increment(WSAccessCounters.LOAD_RAM);
        assertEquals(Integer.valueOf(2), entry.getValue());
        entry.setValue(Integer.MAX_VALUE);
        counters.increment(WSAccessCounters.LOAD_RAM);
        assertEquals(Integer.valueOf(Integer.MIN_VALUE), counters.get("load:ram"));
        counters.put("load:ram", null); assertTrue(counters.containsKey("load:ram"));
        counters.increment(WSAccessCounters.LOAD_RAM);
        assertEquals(Integer.valueOf(1), counters.get("load:ram"));
        counters.put("load:other", 7);
        assertEquals("{load:other=7, load:ram=1}", counters.toString());
        assertEquals(new TreeMap<>(counters), counters);
        var iterator = counters.entrySet().iterator(); iterator.next(); iterator.remove();
        assertEquals(1, counters.size());
        counters.clear(); counters.increment(WSAccessCounters.IN);
        assertEquals(Map.of("in:direct", 1), counters);
    }
}
