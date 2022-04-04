/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import javax.security.auth.Subject;
import org.dcache.xrootd.core.XrootdSession;

/**
 * An xrootd request message.
 *
 * Request objects may be reference counted.
 */
public interface XrootdRequest {

    /**
     * Returns the stream id. The stream id is used by the client to
     * match responses to requests.
     */
    int getStreamId();

    /**
     * Returns the request id. The request id identifies the type of
     * the request.
     */
    int getRequestId();

    /**
     * Associates the request with an xrootd session.
     */
    void setSession(XrootdSession session);

    /**
     * Returns the xrootd session associated with the request. A session
     * is established during authentication. May be null.
     */
    XrootdSession getSession();

    /**
     * Returns the subject as identified by the associated session. May be null.
     */
    Subject getSubject();
}
