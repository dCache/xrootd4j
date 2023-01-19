/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>According to the third-party protocol, the destination server must
 *    actively read the file from the source.</p>
 *
 *  <p>The <code>path</code> field represents the logical file name plus
 *      opaque data establishing the rendezvous point.</p>
 */
public class OutboundOpenReadOnlyRequest extends AbstractXrootdOutboundRequest
{
    private static final int RESERVED_LEN = 12;
    private static final byte[] RESERVED = {0,0,0,0,0,0,0,0,0,0,0,0};

    private final String path;

    public OutboundOpenReadOnlyRequest(int streamId, String path)
    {
        super(streamId, kXR_open);
        this.path = path;
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        buffer.writeShort(kXR_ur | kXR_gr);
        buffer.writeShort(kXR_open_read | kXR_retstat);
        buffer.writeBytes(RESERVED);
        int len = path.length();
        buffer.writeInt(len);
        buffer.writeBytes(path.getBytes(US_ASCII));
    }

    @Override
    protected int getParamsLen() {
        return 8 + RESERVED_LEN + path.length();
    }
}
