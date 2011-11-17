/**
 * Copyright (C) 2011 dCache.org <support@dcache.org>
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

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class WriteRequest extends AbstractRequestMessage
{
    private final int fhandle;
    private final long offset;
    private final int dlen;
    private final ChannelBuffer buffer;

    public WriteRequest(ChannelBuffer buffer)
    {
        super(buffer);

        if (getRequestID() != XrootdProtocol.kXR_write)
            throw new IllegalArgumentException("doesn't seem to be a kXR_write message");

        fhandle = buffer.getInt(4);
        offset = buffer.getLong(8);
        dlen = buffer.getInt(20);

        this.buffer = buffer;
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
        int index = 24;
        int len = dlen;
        while (len > 0) {
            int written = buffer.getBytes(index, out, len);
            index += written;
            len -= written;
        }
    }

    @Override
    public String toString()
    {
        return String.format("write[handle=%d,offset=%d,length=%d]", fhandle, offset, dlen);
    }
}
