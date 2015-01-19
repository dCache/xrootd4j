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

import io.netty.buffer.ByteBuf;

import java.util.Iterator;

import org.dcache.xrootd.protocol.XrootdProtocol;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class DirListResponse extends AbstractXrootdResponse<DirListRequest>
{
    private final Iterable<String> names;

    public DirListResponse(DirListRequest request, int statusCode, Iterable<String> names)
    {
        super(request, statusCode);
        this.names = names;
    }

    public DirListResponse(DirListRequest request, Iterable<String> names)
    {
        this(request, XrootdProtocol.kXR_ok, names);
    }

    public Iterable<String> getNames()
    {
        return names;
    }

    @Override
    protected int getLength()
    {
        int length = super.getLength();
        for (String name: names) {
            length += name.length() + 1;
        }
        return length;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);

        Iterator<String> i = names.iterator();
        if (i.hasNext()) {
            buffer.writeBytes(i.next().getBytes(US_ASCII));
            while (i.hasNext()) {
                buffer.writeByte('\n');
                buffer.writeBytes(i.next().getBytes(US_ASCII));
            }
            /* Last entry in the list is terminated by a 0 rather than by
             * a \n, if not more entries follow because the message is an
             * intermediate message */
            if (stat == XrootdProtocol.kXR_oksofar) {
                buffer.writeByte('\n');
            } else {
                buffer.writeByte(0);
            }
        }
    }
}
