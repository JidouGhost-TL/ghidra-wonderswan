// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Registry of {@link WSCodec} decompressors available to the asset viewer.
 *
 * <p>Codecs registered here appear in the "decompress here" action and the
 * headless export script. This extension ships no game-specific codecs; private
 * tooling registers its own via {@link #register(WSCodec)} or by providing a
 * {@link ServiceLoader} entry.
 */
public final class WSCodecRegistry {
    private static final Map<String, WSCodec> CODECS = new LinkedHashMap<>();

    static {
        for (WSCodec c : ServiceLoader.load(WSCodec.class)) {
            CODECS.putIfAbsent(c.id(), c);
        }
    }

    private WSCodecRegistry() { }

    /** Register (or replace) a codec by its {@link WSCodec#id()}. */
    public static synchronized void register(WSCodec codec) {
        CODECS.put(codec.id(), codec);
    }

    /** Unregister a codec; used by tests. */
    public static synchronized void unregister(String id) {
        CODECS.remove(id);
    }

    /** Codec by id, or null when unknown. */
    public static synchronized WSCodec get(String id) {
        return CODECS.get(id);
    }

    /** All registered codecs in registration order. */
    public static synchronized Collection<WSCodec> all() {
        return Collections.unmodifiableCollection(new java.util.ArrayList<>(CODECS.values()));
    }
}
