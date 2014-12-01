/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.protocol.messages;

import java.io.IOException;
import java.nio.channels.GatheringByteChannel;
import java.nio.ByteBuffer;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_write;
import io.netty.buffer.ByteBuf;
import io.netty.util.ReferenceCounted;

public class WriteRequest extends XrootdRequest implements ReferenceCounted
{
    private final int _fhandle;
    private final long _offset;
    private final int _dlen;
    private final ByteBuf _buffer;

    public WriteRequest(ByteBuf buffer)
    {
        super(buffer, kXR_write);

        _fhandle = buffer.getInt(4);
        _offset = buffer.getLong(8);
        _dlen = buffer.getInt(20);
        _buffer = buffer.alloc().ioBuffer(_dlen); // Most likely this will be written to disk
        buffer.getBytes(24, _buffer);
    }

    public int getFileHandle()
    {
        return _fhandle;
    }

    public long getWriteOffset()
    {
        return _offset;
    }

    public int getDataLength()
    {
        return _dlen;
    }

    public void getData(GatheringByteChannel out)
        throws IOException
    {
        int index = 0;
        int len = _dlen;
        while (len > 0) {
            int written = _buffer.getBytes(index, out, len);
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
        return (_buffer.nioBufferCount() == -1 ? _buffer.copy() : _buffer).nioBuffers();
    }

    @Override
    public String toString()
    {
        return String.format("write[handle=%d,offset=%d,length=%d]",
                             _fhandle, _offset, _dlen);
    }

    @Override
    public int refCnt()
    {
        return _buffer.refCnt();
    }

    @Override
    public boolean release()
    {
        return _buffer.release();
    }

    @Override
    public boolean release(int decrement)
    {
        return _buffer.release(decrement);
    }

    @Override
    public WriteRequest retain(int increment)
    {
        _buffer.retain(increment);
        return this;
    }

    @Override
    public WriteRequest retain()
    {
        _buffer.retain();
        return this;
    }
}
