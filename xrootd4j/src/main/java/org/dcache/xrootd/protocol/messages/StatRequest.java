/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_stat;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_vfs;

public class StatRequest extends PathRequest
{
    private final short options;
    private final int fhandle;

    public StatRequest(ByteBuf buffer)
    {
        super(buffer, kXR_stat);
        options = buffer.getUnsignedByte(4);
        fhandle = buffer.getInt(16);
    }

    public boolean isVfsSet()
    {
        return (options & kXR_vfs) == kXR_vfs;
    }

    public int getFhandle() { return fhandle; }

    private short getOptions()
    {
        return options;
    }

    @Override
    public String toString()
    {
        return String.format("stat[%#x,%s,%s]",
                             getOptions(), getPath(), getOpaque());
    }
}
