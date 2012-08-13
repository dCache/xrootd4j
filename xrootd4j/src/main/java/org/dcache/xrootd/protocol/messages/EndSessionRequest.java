/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.SESSION_ID_SIZE;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_endsess;

import org.dcache.xrootd.core.XrootdSessionIdentifier;
import org.jboss.netty.buffer.ChannelBuffer;

public class EndSessionRequest extends XrootdRequest
{
    private final byte[] _session = new byte[SESSION_ID_SIZE];

    public EndSessionRequest(ChannelBuffer buffer)
    {
        super(buffer, kXR_endsess);
        buffer.getBytes(4, _session);
    }

    public XrootdSessionIdentifier getSessionId()
    {
        return new XrootdSessionIdentifier(_session);
    }
}
