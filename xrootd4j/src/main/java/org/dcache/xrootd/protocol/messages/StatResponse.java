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

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.util.FileStatus;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class StatResponse extends AbstractXrootdResponse
{
    private final FileStatus fs;
    private final String info;

    public StatResponse(XrootdRequest request, FileStatus fs)
    {
        this(request, fs, fs.toString());
    }

    private StatResponse(XrootdRequest request, FileStatus fs, String info)
    {
        super(request, XrootdProtocol.kXR_ok);
        this.fs = fs;
        this.info = info;
    }

    public long getSize()
    {
        return fs.getSize();
    }

    public int getFlags()
    {
        return fs.getFlags();
    }

    public long getId()
    {
        return fs.getId();
    }

    public long getModificationTime()
    {
        return fs.getModificationTime();
    }

    @Override
    protected int getLength()
    {
        return super.getLength() + info.length() + 1;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);
        buffer.writeBytes(info.getBytes(US_ASCII));
        buffer.writeByte('\0');
    }

    @Override
    public String toString()
    {
        return String.format("stat-response[%s]", fs);
    }
}
