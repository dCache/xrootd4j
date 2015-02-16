/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.protocol.messages;

import java.io.IOException;
import java.nio.channels.GatheringByteChannel;
import java.nio.ByteBuffer;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_write;
import io.netty.buffer.ByteBuf;
import io.netty.util.ReferenceCounted;

public class WriteRequest extends AbstractXrootdRequest implements ReferenceCounted
{
    private final int fhandle;
    private final long offset;
    private final int dlen;
    private final ByteBuf data;

    public WriteRequest(ByteBuf buffer)
    {
        super(buffer, kXR_write);

        fhandle = buffer.getInt(4);
        offset = buffer.getLong(8);
        dlen = buffer.getInt(20);
        data = buffer.alloc().ioBuffer(dlen); // Most likely this will be written to disk
        buffer.getBytes(24, data);
    }

    public int getFileHandle()
    {
        return fhandle;
    }

    public long getWriteOffset()
    {
        return offset;
    }

    public int getDataLength()
    {
        return dlen;
    }

    public void getData(GatheringByteChannel out)
        throws IOException
    {
        int index = 0;
        int len = dlen;
        while (len > 0) {
            int written = data.getBytes(index, out, len);
            index += written;
            len -= written;
        }
    }

    /**
     * Converts this requests's payload into an array of NIO
     * buffers. The returned buffers might or might not share the
     * content with this request.
     */
    public ByteBuffer[] toByteBuffers()
    {
        return (data.nioBufferCount() == -1 ? data.copy() : data).nioBuffers();
    }

    @Override
    public String toString()
    {
        return String.format("write[handle=%d,offset=%d,length=%d]",
                             fhandle, offset, dlen);
    }

    @Override
    public int refCnt()
    {
        return data.refCnt();
    }

    @Override
    public boolean release()
    {
        return data.release();
    }

    @Override
    public boolean release(int decrement)
    {
        return data.release(decrement);
    }

    @Override
    public WriteRequest retain(int increment)
    {
        data.retain(increment);
        return this;
    }

    @Override
    public WriteRequest retain()
    {
        data.retain();
        return this;
    }
}
