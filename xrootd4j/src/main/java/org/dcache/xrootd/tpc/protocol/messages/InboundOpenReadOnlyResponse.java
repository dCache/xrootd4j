/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

import java.nio.charset.StandardCharsets;

import org.dcache.xrootd.util.FileStatus;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;

/**
 * <p>Response from third-party source server.</p>
 */
public class InboundOpenReadOnlyResponse extends AbstractXrootdInboundResponse
{
    private final        int    resplen;
    private final        int    fhandle;
    private final int    cpsize;  // should be 0, since we request kXR_restat
    private final int    cptype;  // should have first byte = \0, no compression
    private final FileStatus fileStatus;

    public InboundOpenReadOnlyResponse(ByteBuf buffer)
    {
        super(buffer);
        resplen = buffer.getInt(4);
        fhandle = buffer.getInt(8);
        cpsize = buffer.getInt(12);
        cptype = buffer.getInt(16);
        int len = resplen - 12;
        if (resplen > 0) {
            fileStatus = new FileStatus(buffer.toString(20,
                                                        len,
                                                        StandardCharsets.US_ASCII));
        } else {
            fileStatus = null;
        }
    }

    public int getCpsize() {
        return cpsize;
    }

    public int getCptype() {
        return cptype;
    }

    public int getFhandle() {
        return fhandle;
    }

    public FileStatus getFileStatus() {
        return fileStatus;
    }

    @Override
    public int getRequestId() {
        return kXR_open;
    }
}
