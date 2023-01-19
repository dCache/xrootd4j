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

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;

import java.nio.charset.StandardCharsets;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Qcksum;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;

/**
 * <p>According to protocol, has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_query</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_Qcksum</td></tr>
 *      <tr><td>kXR_char</td><td>reserved[14]</td></tr>
 *      <tr><td>kXR_int32</td><td>plen</td></tr>
 *      <tr><td>kXR_char</td><td>path[plen]</td></tr>
 *  </table>
 */
public class OutboundChecksumRequest extends AbstractXrootdOutboundRequest
{
    private static final byte[] RESERVED = {0,0,0,0,0,0,0,0,0,0,0,0,0,0};

    private String path;

    public OutboundChecksumRequest(int streamId, String path)
    {
        super(streamId, kXR_query);
        this.path = Preconditions.checkNotNull(path);
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        buffer.writeShort(kXR_Qcksum);
        buffer.writeBytes(RESERVED);
        buffer.writeInt(path.length());
        buffer.writeBytes(path.getBytes(StandardCharsets.US_ASCII));
    }

    @Override
    protected int getParamsLen()
    {
        return 20 + path.length();
    }
}
