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
    /**
     * How the client is specifying about which file the server should provided
     * metadata.
     */
    public enum Target
    {
        /**
         * The file is described by its path.
         */
        PATH,

        /**
         * The file is described by a file handle.
         */
        FHANDLE;
    }

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

    public int getFhandle()
    {
        return fhandle;
    }

    private short getOptions()
    {
        return options;
    }

    /**
     * Provide the target type of the kXR_stat request.  The protocol allows
     * the client to request information about a file by specifying that file's
     * path, or by specifying an opened file handle.
     * <p>
     * If this method returns {@literal Target.FHANDLE} then {@link #getFhandle}
     * describes the file handle the client is targeting.  If the returned
     * value is {@literal Target.PATH} then {@link #getPath} describes the file
     * path the client is targeting.
     * @return the kind of object the client is requesting
     */
    public Target getTarget()
    {
        /**
         * Although not documented (see https://github.com/xrootd/xrootd/issues/839 ),
         * the SLAC xrootd server seems to make the decision based on whether
         * plen is zero.
         */
        return getPath().isEmpty() ? Target.FHANDLE : Target.PATH;
    }

    @Override
    public String toString()
    {
        return String.format("stat[%#x,%s,%s]",
                             getOptions(), getPath(), getOpaque());
    }
}
