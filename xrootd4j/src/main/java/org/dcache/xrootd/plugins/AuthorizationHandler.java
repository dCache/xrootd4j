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
package org.dcache.xrootd.plugins;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Map;
import javax.security.auth.Subject;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;

/**
 * The interface to authorization and path mapping plugins.
 */
public interface AuthorizationHandler {

    /**
     * Authorization and path mapping hook.
     *
     * Called upon any xrootd door operation.
     *
     * Implementations may perform authorization checks for the
     * requested operation.
     *
     * @param subject the user
     * @param localAddress local socket address of client connection
     * @param remoteAddress remote socket address of client connection
     * @param path the file which is checked
     * @param opaque the opaque data from the request
     * @param request xrootd request id of the operation
     * @param mode the requested mode
     * @throws SecurityException when the requested access is denied
     * @throws GeneralSecurityException when the process of
     *         authorizing fails
     * @throws XrootdException when some specific error should be propagated
     *         back to the xrootd client.
     */
    String authorize(Subject subject,
          InetSocketAddress localAddress,
          InetSocketAddress remoteAddress,
          String path, Map<String, String> opaque,
          int request, FilePerm mode)
          throws XrootdException, SecurityException, GeneralSecurityException;
}
