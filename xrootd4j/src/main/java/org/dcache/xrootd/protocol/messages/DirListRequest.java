/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_dirlist;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_dstat;

import io.netty.buffer.ByteBuf;

public class DirListRequest extends PathRequest {

    private final short options;

    public DirListRequest(ByteBuf buffer) {
        super(buffer, kXR_dirlist);
        options = buffer.getUnsignedByte(19);
    }

    public boolean isDirectoryStat() {
        return (options & kXR_dstat) == kXR_dstat;
    }

    private short getOptions() {
        return options;
    }

    @Override
    public String toString() {
        return String.format("dirlist[%#x,%s,%s]",
              getOptions(), getPath(), getOpaque());
    }
}
