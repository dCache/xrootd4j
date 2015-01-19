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

import org.dcache.xrootd.protocol.XrootdProtocol;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * Base class for requests that contain a path.
 *
 * The path and opaque data is found at offset 24 in the message, with
 * the length at offset 20. The path and opaque data are delimited by
 * a question mark.
 */
public class PathRequest extends AbstractXrootdRequest
{
    private String path;
    private String opaque;

    public PathRequest(ByteBuf buffer, int requestId)
    {
        super(buffer, requestId);
        setPathAndOpaque(buffer, 24, buffer.getInt(20));
    }

    private void setPathAndOpaque(ByteBuf buffer, int begin, int length)
    {
        int end = begin + length;
        int pos = buffer.indexOf(begin, end, XrootdProtocol.OPAQUE_DELIMITER);
        if (pos > -1) {
            setPath(buffer.toString(begin, pos - begin, US_ASCII));
            setOpaque(buffer.toString(pos + 1, end - (pos + 1), US_ASCII));
        } else {
            setPath(buffer.toString(begin, end - begin, US_ASCII));
            setOpaque("");
        }
    }

    public String getOpaque()
    {
        return opaque;
    }

    public void setOpaque(String opaque)
    {
        this.opaque = opaque;
    }

    public String getPath()
    {
        return path;
    }

    public void setPath(String path)
    {
        this.path = path;
    }
}
