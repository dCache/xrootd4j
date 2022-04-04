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

import org.dcache.xrootd.core.XrootdSessionIdentifier;

import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;

/**
 * <p>Request to end session on the source server.</p>
 */
public class OutboundEndSessionRequest extends AbstractXrootdOutboundRequest
{
    private final XrootdSessionIdentifier sessionId;

    public OutboundEndSessionRequest(int streamId, XrootdSessionIdentifier sessionId)
    {
        super(streamId, kXR_endsess);
        this.sessionId = sessionId;
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        buffer.writeBytes(sessionId.getBytes());
        buffer.writeInt(0);
    }

    @Override
    protected int getParamsLen() {
        return SESSION_ID_SIZE + 4;
    }
}
