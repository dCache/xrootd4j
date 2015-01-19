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

public class OpenResponse extends AbstractXrootdResponse<OpenRequest>
{
    private final int fileHandle;
    private final Integer cpsize;
    private final String cptype;
    private final FileStatus fs;

    public OpenResponse(OpenRequest request, int fileHandle,
                        Integer cpsize, String cptype, FileStatus fs)
    {
        super(request, XrootdProtocol.kXR_ok);
        this.fileHandle = fileHandle;
        this.cpsize = cpsize;
        this.cptype = cptype;
        this.fs = fs;
    }

    public int getFileHandle()
    {
        return fileHandle;
    }

    public FileStatus getFileStatus()
    {
        return fs;
    }

    @Override
    protected int getLength()
    {
        return super.getLength() + 4 +
               ((cpsize != null && cptype != null || fs != null) ? 8 : 0) +
               ((fs != null) ? fs.toString().length() + 1 : 0);
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);

        buffer.writeInt(fileHandle);

        if (cpsize != null && cptype != null) {
            buffer.writeInt(cpsize);
            int len = Math.min(cptype.length(), 4);
            buffer.writeBytes(cptype.getBytes(US_ASCII), 0, len);
            buffer.writeZero(4 - len);
        } else if (fs != null) {
            buffer.writeZero(8);
        }

        if (fs != null) {
            buffer.writeBytes(fs.toString().getBytes(US_ASCII));
            buffer.writeByte('\0');
        }
    }

    @Override
    public String toString()
    {
        return String.format("open-response[%d,%d,%s,%s]",
                             fileHandle, cpsize, cptype, fs);
    }
}
