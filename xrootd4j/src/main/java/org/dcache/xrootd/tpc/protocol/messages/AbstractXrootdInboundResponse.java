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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

/**
 * Supports incoming third-party source server reponses.</p>
 *
 * According to protocol, all responses must
 *      have the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>stat</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *      <tr><td>kXR_char</td><td>data[dlen]</td></tr>
 *  </table>
 */
public abstract class AbstractXrootdInboundResponse
      implements XrootdInboundResponse {

    protected final int streamId;
    protected final int stat;

    protected AbstractXrootdInboundResponse(int streamId, int stat) {
        this.streamId = streamId;
        this.stat = stat;
    }

    protected AbstractXrootdInboundResponse(ByteBuf buffer) {
        this(buffer.getUnsignedShort(0), buffer.getUnsignedShort(2));
    }

    @Override
    public int getStatus() {
        return stat;
    }

    @Override
    public int getStreamId() {
        return streamId;
    }
}
