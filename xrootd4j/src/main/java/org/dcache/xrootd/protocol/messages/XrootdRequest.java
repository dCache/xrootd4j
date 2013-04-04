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

import java.nio.charset.Charset;
import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdSession;
import org.jboss.netty.buffer.ChannelBuffer;

import static com.google.common.base.Preconditions.checkState;

public abstract class XrootdRequest
{
    protected final static Charset XROOTD_CHARSET = Charset.forName("ASCII");

    protected final int _streamId;
    protected final int _requestId;
    protected XrootdSession _session;

    public XrootdRequest()
    {
        _streamId = 0;
        _requestId = 0;
    }

    public XrootdRequest(ChannelBuffer buffer, int requestId)
    {
        this(buffer);
        checkState(_requestId == requestId);
    }

    public XrootdRequest(ChannelBuffer buffer)
    {
        _streamId = buffer.getUnsignedShort(0);
        _requestId = buffer.getUnsignedShort(2);
    }

    public int getStreamId()
    {
        return _streamId;
    }

    public int getRequestId()
    {
        return _requestId;
    }

    public void setSession(XrootdSession session)
    {
        _session = session;
    }

    public XrootdSession getSession()
    {
        return _session;
    }

    @Deprecated
    public Subject getSubject()
    {
        return (_session == null) ? null : _session.getSubject();
    }
}
