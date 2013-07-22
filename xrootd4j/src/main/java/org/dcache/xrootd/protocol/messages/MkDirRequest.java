/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkdir;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkpath;

/**
 * FIXME the mode field is currently unsupported, because the owner of the file
 * can not be determined. Supporting the mode is dependant on implementation of
 * authenticated (GSI) xrootd
 */
public class MkDirRequest extends PathRequest
{
    private final short _options;
    private final int _mode;

    public MkDirRequest(ByteBuf buffer) {
        super(buffer, kXR_mkdir);

        _options = buffer.getByte(4);
        _mode = buffer.getUnsignedShort(18);
    }

    public short getOptions() {
        return _options;
    }

    public boolean shouldMkPath() {
        return (getOptions() & kXR_mkpath) == kXR_mkpath;
    }

    public int getMode() {
        return _mode;
    }
}
