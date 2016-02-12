/**
 * Copyright (C) 2011-2016 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdSession;

import static com.google.common.base.Preconditions.checkState;

public class AbstractXrootdRequest implements XrootdRequest
{
    protected final int streamId;
    protected final int requestId;
    protected XrootdSession session;

    public AbstractXrootdRequest(ByteBuf buffer, int requestId)
    {
        this(buffer);
        checkState(this.requestId == requestId);
    }

    public AbstractXrootdRequest(ByteBuf buffer)
    {
        streamId = buffer.getUnsignedShort(0);
        requestId = buffer.getUnsignedShort(2);
    }

    @Override
    public int getStreamId()
    {
        return streamId;
    }

    @Override
    public int getRequestId()
    {
        return requestId;
    }

    @Override
    public void setSession(XrootdSession session)
    {
        this.session = session;
    }

    @Override
    public XrootdSession getSession()
    {
        return session;
    }

    @Override
    public Subject getSubject()
    {
        return (session == null) ? null : session.getSubject();
    }
}
