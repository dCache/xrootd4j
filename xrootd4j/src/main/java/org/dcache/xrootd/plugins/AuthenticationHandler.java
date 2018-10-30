/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins;

import javax.security.auth.Subject;

import org.dcache.xrootd.core.XrootdDecoder;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;

public interface AuthenticationHandler
{
    /**
     * Authenticate method, parsing the requests and creating adequate
     * responses. The internal state of the handler might be changed
     * by this method.
     *
     * @param request Request received from client
     * @return Response to be sent to the client
     */
    XrootdResponse<AuthenticationRequest> authenticate(AuthenticationRequest request)
        throws XrootdException;

    /**
     * @return the protocol that is implemented by the authentication
     * handler
     */
    String getProtocol();

    /**
     * Get the subject containing the credentials/principals found
     * during authentication. The method MUST return null if no user
     * has been authenticated yet. The method MAY return null even if
     * the authentication step has completed - this indicates an
     * anonymous user.
     */
    Subject getSubject();

    /**
     * Indicates if the authentication process completed successfully.
     */
    boolean isCompleted();

    /**
     * Allows handler to provide signed hash verification handling to
     * the decoder/
     */
    void setDecoder(XrootdDecoder decoder);
}
