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

import java.nio.charset.Charset;

import org.jboss.netty.buffer.ChannelBuffer;

public abstract class AbstractRequestMessage
{
    protected final int streamId;
    protected final int requestId;

    protected final static Charset XROOTD_CHARSET = Charset.forName("ASCII");

    public AbstractRequestMessage()
    {
        streamId = 0;
        requestId = 0;
    }

    public AbstractRequestMessage(ChannelBuffer buffer)
    {
        streamId = buffer.getUnsignedShort(0);
        requestId = buffer.getUnsignedShort(2);
    }

    public int getStreamID()
    {
        return streamId;
    }

    public int getRequestID()
    {
        return requestId;
    }
}
