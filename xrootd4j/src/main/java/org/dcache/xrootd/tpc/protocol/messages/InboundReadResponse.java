/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.tpc.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_read;

import io.netty.buffer.ByteBuf;
import io.netty.util.ReferenceCounted;
import java.nio.ByteBuffer;
import org.dcache.xrootd.util.ByteBuffersProvider;

/**
 * Response from third-party source server.</p>
 *
 * The implementation of the {@link ByteBuffersProvider} interface
 *    assimilates this response with an incoming client write request.</p>
 *
 * The third-party client in effect acts as a pipe between the
 *    remote read of the file and the local write. Merging that functionality
 *    into a single object allows us to bypass an extra buffer copy.</p>
 */
public class InboundReadResponse extends AbstractXrootdInboundResponse
      implements ByteBuffersProvider {

    private final ByteBuf data;
    private final int dlen;
    private long writeOffset;

    public InboundReadResponse(ByteBuf buffer) {
        super(buffer);
        dlen = buffer.getInt(4);
        data = buffer.alloc().ioBuffer(dlen);
        buffer.getBytes(8, data);
    }

    public int getDlen() {
        return dlen;
    }

    @Override
    public int getRequestId() {
        return kXR_read;
    }

    @Override
    public long getWriteOffset() {
        return writeOffset;
    }

    public void setWriteOffset(long writeOffset) {
        this.writeOffset = writeOffset;
    }

    @Override
    public ByteBuffer[] toByteBuffers() {
        return (data.nioBufferCount() == -1 ? data.copy() : data).nioBuffers();
    }

    @Override
    public int refCnt() {
        return data.refCnt();
    }

    @Override
    public ReferenceCounted retain() {
        data.retain();
        return this;
    }

    @Override
    public ReferenceCounted retain(int i) {
        data.retain(i);
        return this;
    }

    @Override
    public ReferenceCounted touch() {
        data.touch();
        return this;
    }

    @Override
    public ReferenceCounted touch(Object o) {
        data.touch(o);
        return this;
    }

    @Override
    public boolean release() {
        return data.release();
    }

    @Override
    public boolean release(int i) {
        return data.release(i);
    }
}
