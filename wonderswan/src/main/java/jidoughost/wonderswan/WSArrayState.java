// SPDX-License-Identifier: MIT OR Apache-2.0
package jidoughost.wonderswan;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import generic.ULongSpan;
import ghidra.generic.util.datastruct.SemisparseByteArray;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;

/** Zero-filled concrete state. Port effects still occur at the machine's instruction boundaries. */
final class WSArrayState extends BytesPcodeExecutorState {
    WSArrayState(Language language, PcodeStateCallbacks callbacks) {
        this(new Piece(language, callbacks));
    }

    private WSArrayState(Piece piece) {
        super(piece);
    }

    @Override
    public WSArrayState fork(PcodeStateCallbacks callbacks) {
        return new WSArrayState(((Piece) piece).fork(callbacks));
    }

    boolean matches(Address address, byte[] expected) {
        return ((Piece) piece).getForSpace(address.getAddressSpace(), false)
            .matches(address.getOffset(), expected);
    }

    boolean matches(Address address, byte[] expected, int sourceOffset, int length) {
        return ((Piece) piece).getForSpace(address.getAddressSpace(), false)
            .matches(address.getOffset(), expected, sourceOffset, length);
    }

    long scalar(Address address, int size) {
        return ((Piece) piece).getForSpace(address.getAddressSpace(), false).scalar(address.getOffset(), size);
    }

    void notifyWrite(Address address, byte[] value) {
        ((Piece) piece).notifyWrite(address, value);
    }

    private static final class Piece extends BytesPcodeExecutorStatePiece {
        Piece(Language language, PcodeStateCallbacks callbacks) {
            super(language, callbacks);
        }

        @Override
        protected Space newSpace(AddressSpace space) {
            int capacity = space.isRegisterSpace() ? 0x4100 :
                space.equals(language.getDefaultSpace()) ? 0x110000 : 0x10000;
            return new Space(language, space, this, new byte[capacity], new SemisparseByteArray());
        }

        @Override
        protected Space getForSpace(AddressSpace space, boolean toWrite) {
            return (Space) spaceMap.computeIfAbsent(space, this::newSpace);
        }

        void notifyWrite(Address address, byte[] value) {
            cb.dataWritten(this, address, value.length, value);
        }

        @Override
        public void checkRange(AddressSpace space, long offset, int size) {
            long end = offset + size - 1;
            if (space.isConstantSpace() || (size > 0 && offset >= 0 && end >= offset &&
                    Long.compareUnsigned(offset, space.getMinAddress().getOffset()) >= 0 &&
                    Long.compareUnsigned(end, space.getMaxAddress().getOffset()) <= 0)) return;
            super.checkRange(space, offset, size);
        }

        @Override
        public Piece fork(PcodeStateCallbacks callbacks) {
            Piece result = new Piece(language, callbacks);
            forkMap(result.spaceMap, spaceMap, space -> space.fork(result));
            return result;
        }

        @Override
        public Map.Entry<Long, byte[]> getNextEntryInternal(AddressSpace space, long offset) {
            return getForSpace(space, false).nextEntry(offset);
        }
    }

    private static final class Space extends BytesPcodeExecutorStateSpace {
        // Unusual injected unique offsets use sparse overflow instead of allocating huge arrays.
        private static final int MAX_DENSE = 16 * 1024 * 1024;
        private byte[] data;

        Space(Language language, AddressSpace space, Piece piece, byte[] data,
                SemisparseByteArray overflow) {
            super(language, space, piece, overflow);
            this.data = data;
        }

        @Override
        public Space fork(AbstractBytesPcodeExecutorStatePiece<?> piece) {
            return new Space(language, space, (Piece) piece, data.clone(), bytes.fork());
        }

        private boolean denseRange(long offset, int length) {
            return offset >= 0 && offset <= MAX_DENSE && length <= MAX_DENSE - offset;
        }

        @Override
        public void write(long offset, byte[] value, int sourceOffset, int length,
                PcodeStateCallbacks callbacks) {
            if (denseRange(offset, length)) {
                int end = (int) offset + length;
                if (end > data.length) {
                    data = Arrays.copyOf(data, Math.min(MAX_DENSE, Math.max(end, data.length * 2)));
                }
                System.arraycopy(value, sourceOffset, data, (int) offset, length);
            } else {
                // Split a rare access crossing the dense limit so both views stay coherent.
                int prefix = offset >= 0 && offset < MAX_DENSE ? (int) (MAX_DENSE - offset) : 0;
                if (prefix > 0) {
                    data = Arrays.copyOf(data, MAX_DENSE);
                    System.arraycopy(value, sourceOffset, data, (int) offset, prefix);
                }
                bytes.putData(offset + prefix, value, sourceOffset + prefix, length - prefix);
            }
            callbacks.dataWritten(piece, space.getAddress(offset), length, value);
        }

        @Override
        public byte[] read(long offset, int size, Reason reason, PcodeStateCallbacks callbacks) {
            byte[] result = new byte[size];
            int prefix = offset >= 0 && offset < data.length ?
                Math.min(size, data.length - (int) offset) : 0;
            if (prefix > 0) System.arraycopy(data, (int) offset, result, 0, prefix);
            if (!denseRange(offset, size)) {
                int densePrefix = offset >= 0 && offset < MAX_DENSE ?
                    Math.min(size, (int) (MAX_DENSE - offset)) : 0;
                bytes.getData(offset + densePrefix, result, densePrefix, size - densePrefix);
            }
            return result;
        }

        boolean matches(long offset, byte[] expected) {
            return matches(offset, expected, 0, expected.length);
        }

        boolean matches(long offset, byte[] expected, int sourceOffset, int length) {
            if (offset >= 0 && offset <= data.length && length <= data.length - offset) {
                return Arrays.equals(data, (int) offset, (int) offset + length,
                    expected, sourceOffset, sourceOffset + length);
            }
            return Arrays.equals(expected, sourceOffset, sourceOffset + length,
                read(offset, length, Reason.INSPECT, PcodeStateCallbacks.NONE), 0, length);
        }

        long scalar(long offset, int size) {
            byte[] source = data;
            int start;
            if (offset >= 0 && offset <= data.length && size <= data.length - offset) start = (int) offset;
            else { source = read(offset, size, Reason.INSPECT, PcodeStateCallbacks.NONE); start = 0; }
            long result = 0;
            for (int i = size - 1; i >= 0; i--) result = (result << 8) | (source[start + i] & 0xFF);
            return result;
        }

        @Override
        public Map<Register, byte[]> getRegisterValues(List<Register> registers) {
            Map<Register, byte[]> result = new HashMap<>();
            for (Register register : registers) {
                result.put(register, read(register.getAddress().getOffset(), register.getNumBytes(),
                    Reason.INSPECT, PcodeStateCallbacks.NONE));
            }
            return result;
        }

        Map.Entry<Long, byte[]> nextEntry(long offset) {
            if (offset >= 0 && offset < data.length) {
                return Map.entry(offset, Arrays.copyOfRange(data, (int) offset, data.length));
            }
            var initialized = bytes.getInitialized(offset, -1);
            var spans = initialized.intersecting(ULongSpan.span(offset, -1)).iterator();
            if (!spans.hasNext()) return null;
            var span = spans.next();
            long start = Long.compareUnsigned(offset, span.min()) > 0 ? offset : span.min();
            int length = (int) Math.min(Integer.MAX_VALUE, span.max() - start + 1);
            return Map.entry(start, read(start, length, Reason.INSPECT, PcodeStateCallbacks.NONE));
        }

        @Override
        public void clear() {
            Arrays.fill(data, (byte) 0);
            bytes.clear();
        }
    }
}
