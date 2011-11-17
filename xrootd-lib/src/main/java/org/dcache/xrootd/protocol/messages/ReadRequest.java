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

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.jboss.netty.buffer.ChannelBuffer;

public class ReadRequest extends GenericReadRequestMessage
{
    private final int fhandle;
    private final long offset;
    private final int rlen;

    public ReadRequest(ChannelBuffer buffer)
    {
        super(buffer);

        if (getRequestID() != XrootdProtocol.kXR_read)
            throw new IllegalArgumentException("doesn't seem to be a kXR_read message");

        fhandle = buffer.getInt(4);
        offset = buffer.getLong(8);
        rlen = buffer.getInt(16);
    }

    public int getFileHandle()
    {
        return fhandle;
    }

    public long getReadOffset()
    {
        return offset;
    }

    public int bytesToRead()
    {
        return rlen;
    }

    public int NumberOfPreReads()
    {
        return getSizeOfList();
    }

    public EmbeddedReadRequest[] getPreReadRequestList()
    {
        return getReadRequestList();
    }

    @Override
    public String toString()
    {
        return String.format("read[handle=%d,offset=%d,length=%d]",
                             fhandle, offset, rlen);
    }
}
