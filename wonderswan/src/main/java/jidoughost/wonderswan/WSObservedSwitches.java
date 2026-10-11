// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.StringPropertyMap;

/** J2: retain the union of observed computed edges independently of analysis references. */
public final class WSObservedSwitches {
    public static final String PROPERTY = "WS_OBSERVED_JUMPS";
    private WSObservedSwitches() { }
    public static void remember(Program p, Address site, Collection<Address> targets) throws Exception {
        StringPropertyMap map = p.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
        if (map == null) map = p.getUsrPropertyManager().createStringPropertyMap(PROPERTY);
        Set<String> union = new TreeSet<>();
        String old = map.getString(site);
        if (old != null && !old.isEmpty()) union.addAll(Arrays.asList(old.split("\\n")));
        for (Address t : targets) union.add(t.toString());
        String value = String.join("\n", union);
        if (!value.equals(old)) map.add(site, value);
    }
    static List<String> evidence(Program p) {
        List<String> out = new ArrayList<>();
        StringPropertyMap map = p.getUsrPropertyManager().getStringPropertyMap(PROPERTY);
        if (map == null) return out;
        var it = map.getPropertyIterator();
        while (it.hasNext()) {
            Address site = it.next(); String targets = map.getString(site);
            if (targets == null || targets.isEmpty()) continue;
            out.add("{\"rule\":\"E3\",\"site\":\"" + site + "\",\"targets\":[\""
                + targets.replace("\n", "\",\"") + "\"],\"src\":\"stored_observation\"}");
        }
        return out;
    }
}
