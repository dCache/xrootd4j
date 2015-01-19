/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.none;

import javax.security.auth.Subject;

import org.dcache.xrootd.protocol.messages.XrootdResponse;
import org.dcache.xrootd.protocol.messages.AuthenticationRequest;
import org.dcache.xrootd.protocol.messages.OkResponse;
import org.dcache.xrootd.plugins.AuthenticationHandler;

/**
 * Dummy authentication handler that accepts all authentication
 * requests in authenticate.
 *
 * @author tzangerl
 */
public class NoAuthenticationHandler implements AuthenticationHandler
{
    @Override
    public XrootdResponse authenticate(AuthenticationRequest request) {
        return new OkResponse(request);
    }

    @Override
    public String getProtocol() {
        return "";
    }

    @Override
    public Subject getSubject() {
        return null;
    }

    @Override
    public boolean isCompleted() {
        return true;
    }
}
