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
package org.dcache.xrootd.protocol.messages;
import org.dcache.xrootd.protocol.XrootdProtocol;

import com.google.common.base.Charsets;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ErrorResponse extends AbstractXrootdResponse
{
    private static final Logger _log = LoggerFactory.getLogger(ErrorResponse.class);

    private final int errnum;
    private final String errmsg;

    public ErrorResponse(XrootdRequest request, int errnum, String errmsg)
    {
        super(request, XrootdProtocol.kXR_error);
        this.errnum = errnum;
        this.errmsg = errmsg;
        _log.info("Xrootd-Error-Response: ErrorNr={} ErrorMsg={}", errnum, errmsg);
    }

    public int getErrorNumber()
    {
        return errnum;
    }

    public String getErrorMessage()
    {
        return errmsg;
    }

    @Override
    protected int getLength()
    {
        return super.getLength() + 4 + errmsg.length() + 1;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);

        buffer.writeInt(errnum);
        buffer.writeBytes(errmsg.getBytes(Charsets.US_ASCII));
        buffer.writeByte('\0');
    }

    @Override
    public String toString()
    {
        return String.format("error[%d,%s]", errnum, errmsg);
    }
}
