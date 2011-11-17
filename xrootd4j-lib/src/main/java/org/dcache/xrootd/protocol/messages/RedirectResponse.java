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
package org.dcache.xrootd.protocol.messages;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RedirectResponse extends AbstractResponseMessage
{
    private final static Logger _logger =
        LoggerFactory.getLogger(RedirectResponse.class);

    public RedirectResponse(int sId, String host, int port)
    {
        this(sId, host, port, "", "");
    }

    public RedirectResponse(int sId, String host, int port, String opaque, String token)
    {
        super(sId, XrootdProtocol.kXR_redirect,
              4 + host.length() + opaque.length() + token.length() + 2);

        putSignedInt(port);
        _logger.info("Sending the following host information to the client: {}", host);
        putCharSequence(host);

        if (!opaque.equals("")) {
            putCharSequence("?");
            putCharSequence(opaque);
        }

        if (!token.equals("")) {
            if (opaque.equals("")) {
                putCharSequence("?");
            }

            putCharSequence("?");
            putCharSequence(token);
        }
    }
}