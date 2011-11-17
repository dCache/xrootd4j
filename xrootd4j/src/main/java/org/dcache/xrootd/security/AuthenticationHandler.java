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
package org.dcache.xrootd.security;

import javax.security.auth.Subject;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;

public interface AuthenticationHandler {

    /**
     * Authenticate method, parsing the requests and creating adequate
     * responses. The internal state of the handler might be changed by this
     * method.
     *
     * @param request Request received from client
     * @return Response to be sent to the client
     */
    public AbstractResponseMessage authenticate(AuthenticationRequest request);

    /**
     * @return the protocol that is implemented by the authentication handler
     */
    public String getProtocol();

    /**
     * Get the subject containing the credentials/principals found during
     * authentication. It is recommended to check whether authentication is
     * completed before calling this method, or otherwise the subject may
     * contain no or partial information.
     * @return Subject populated during authentication
     */
    public Subject getSubject();

    /**
     * @return true if the authentication process is completed, false otherwise
     */
    public boolean isAuthenticationCompleted();

    /**
     * @return true if the provided authentication is strong
     */
    public boolean isStrongAuthentication();
}
