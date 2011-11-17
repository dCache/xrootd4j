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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import org.jboss.netty.buffer.ChannelBuffer;

/**
 * FIXME the mode field is currently unsupported, because the owner of the file
 * can not be determined. Supporting the mode is dependant on implementation of
 * authenticated (GSI) xrootd
 */
public class MkDirRequest extends AbstractRequestMessage
{
    private final short options;
    private final int mode;
    private final String path;
    private final String opaque;

    public MkDirRequest(ChannelBuffer buffer) {
        super(buffer);

        if (getRequestID() != kXR_mkdir) {
            throw new IllegalArgumentException("doesn't seem to be a kXR_mkdir message");
        }

        options = buffer.getByte(4);
        mode = buffer.getUnsignedShort(18);

        int dlen = buffer.getInt(20);
        int end = 24 + dlen;
        int pos = buffer.indexOf(24, end, (byte)0x3f);
        if (pos > -1) {
            path = buffer.toString(24,
                                   pos - 24,
                                   XROOTD_CHARSET);
            opaque = buffer.toString(pos + 1,
                                     end - (pos + 1),
                                     XROOTD_CHARSET);
        } else {
            path = buffer.toString(24,
                                   end - 24,
                                   XROOTD_CHARSET);
            opaque = null;
        }

    }

    public String getOpaque() {
        return opaque;
    }

    public String getPath() {
        return path;
    }

    public short getOptions() {
        return options;
    }

    public boolean shouldMkPath() {
        return (getOptions() & kXR_mkpath) == kXR_mkpath;
    }

    public int getMode() {
        return mode;
    }
}
