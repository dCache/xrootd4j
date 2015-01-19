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

import com.google.common.base.CaseFormat;
import io.netty.buffer.ByteBuf;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class StringResponse extends AbstractXrootdResponse
{
    protected final String response;

    public StringResponse(XrootdRequest request, int stat, String response)
    {
        super(request, stat);
        this.response = response;
    }

    public String getResponse()
    {
        return response;
    }

    @Override
    protected int getLength()
    {
        return super.getLength() + response.length();
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);
        buffer.writeBytes(response.getBytes(US_ASCII));
    }

    @Override
    public String toString()
    {
        String type = CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_HYPHEN, getClass().getSimpleName());
        return String.format("%s[%s]", type, response);
    }
}
