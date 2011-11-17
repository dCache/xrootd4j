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

public class ErrorResponse extends AbstractResponseMessage
{
    private final static Logger _log = LoggerFactory.getLogger(ErrorResponse.class);

    public ErrorResponse(int sId, int errnum, String errmsg)
    {
        super(sId, XrootdProtocol.kXR_error, errmsg.length() + 4);

        putSignedInt(errnum);

        putCharSequence(errmsg);

        _log.info("Xrootd-Error-Response: ErrorNr="+errnum+" ErrorMsg="+errmsg);
    }
}
