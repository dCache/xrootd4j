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

import org.jboss.netty.buffer.ChannelBuffer;

public class SetRequest extends QueryRequest
{
    private final String data;

    public SetRequest(ChannelBuffer buffer)
    {
        super(buffer);
        int dlen = buffer.getInt(20);
        data = buffer.toString(24, dlen, XROOTD_CHARSET);
    }

    public String getData()
    {
        return data;
    }

    @Override
    public String toString()
    {
        return String.format("set[%s]", data);
    }
}
