/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
import org.jboss.netty.buffer.ChannelBuffer;

public class WriteRequest extends XrootdRequest
{
    private final int _fhandle;
    private final long _offset;
    private final int _dlen;
    private final ChannelBuffer _buffer;

    public WriteRequest(ChannelBuffer buffer)
    {
        super(buffer, kXR_write);

        _fhandle = buffer.getInt(4);
        _offset = buffer.getLong(8);
        _dlen = buffer.getInt(20);
        _buffer = buffer;
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
        int index = 24;
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
     *
     * @see ChannelBuffers.toByteBuffers
     */
    public ByteBuffer[] toByteBuffers()
    {
        return _buffer.toByteBuffers(24, _dlen);
    }

    @Override
    public String toString()
    {
        return String.format("write[handle=%d,offset=%d,length=%d]",
                             _fhandle, _offset, _dlen);
    }
}
