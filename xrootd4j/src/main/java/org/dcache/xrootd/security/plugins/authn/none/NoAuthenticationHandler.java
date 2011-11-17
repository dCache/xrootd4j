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
package org.dcache.xrootd.security.plugins.authn.none;

import javax.security.auth.Subject;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OKResponse;
import org.dcache.xrootd.security.AuthenticationHandler;

/**
 * Dummy authentication handler that accepts all authentication requests in
 * authenticate
 *
 * @author tzangerl
 *
 */
public class NoAuthenticationHandler implements AuthenticationHandler {

    @Override
    public AbstractResponseMessage authenticate(AuthenticationRequest request) {
        return new OKResponse(request.getStreamID());
    }

    @Override
    public String getProtocol() {
        return "";
    }

    /**
     * start with empty subject for noauthentication handler
     */
    @Override
    public Subject getSubject() {
        return new Subject();
    }

    @Override
    public boolean isAuthenticationCompleted() {
        return true;
    }

    @Override
    public boolean isStrongAuthentication() {
        return false;
    }

}
