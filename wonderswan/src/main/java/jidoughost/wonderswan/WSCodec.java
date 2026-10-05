// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

/**
 * Pluggable decompression codec for asset data viewed in the asset viewer.
 *
 * <p>Only general, documented codecs belong in this extension. Game-specific
 * formats stay in private tooling and plug in at run time via
 * {@link WSCodecRegistry#register(WSCodec)} or {@link java.util.ServiceLoader}.
 */
public interface WSCodec {
    /** Short stable identifier, e.g. {@code "raw"}. */
    String id();

    /** One-line human description of the format. */
    String description();

    /**
     * Decompress one stream starting at {@code src[offset]}.
     *
     * @param src bytes containing the stream
     * @param offset start of the stream in {@code src}
     * @param available bytes available from {@code offset} (may exceed the stream)
     * @return decoded bytes plus the number of source bytes consumed
     * @throws IllegalArgumentException when the stream is malformed or truncated
     */
    Result decode(byte[] src, int offset, int available);

    /** Decoded output plus consumed input length. */
    record Result(byte[] data, int consumed) { }
}
