/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import java.io.UnsupportedEncodingException;

import static io.netty.buffer.Unpooled.buffer;
import static org.dcache.xrootd.protocol.XrootdProtocol.SERVER_RESPONSE_LEN;

public abstract class AbstractResponseMessage
{
    protected final XrootdRequest _request;
    protected ByteBuf _buffer;

    public AbstractResponseMessage(XrootdRequest request, int stat, int length)
    {
        _request = request;
        _buffer = buffer(SERVER_RESPONSE_LEN + length);

        putUnsignedShort(request.getStreamId());
        putUnsignedShort(stat);


        // The following field is the length of the payload. We set it
        // to zero as the exact length is not known yet. The
        // XrootdDecoder will fill in the correct value before putting
        // the response on the wire.
        putSignedInt(0);
    }

    public final void setStatus(int s)
    {
        _buffer.setByte(2, (byte) (s >> 8));
        _buffer.setByte(3, (byte) s);
    }

    protected final void put(byte[] field)
    {
        _buffer.writeBytes(field);
    }

    protected final void putUnsignedChar(int c)
    {
        _buffer.writeByte((byte) c);
    }

    protected final void putUnsignedShort(int s)
    {
        _buffer.writeByte((byte) (s >> 8));
        _buffer.writeByte((byte) s);
    }

    protected final void putSignedInt(int i)
    {
        _buffer.writeInt(i);
    }

    protected final void putSignedLong(long l)
    {
        _buffer.writeLong(l);
    }

    /**
     * Put all characters of a String as unsigned kXR_chars
     * @param s the String representing the char sequence to put
     */
    protected final void putCharSequence(String s)
    {
        try {
            put(s.getBytes("ASCII"));
        } catch (UnsupportedEncodingException e) {
            /* We cannot possibly recover from this option, so
             * escalate it.
             */
            throw new RuntimeException("Failed to construct xrootd message", e);
        }
    }

    /**
     * Gives access to the internal ChannelBuffer of the response. The
     * response object is no longer valid if the read index of the
     * buffer is changed.
     */
    public ByteBuf getBuffer()
    {
        return _buffer;
    }

    public XrootdRequest getRequest()
    {
        return _request;
    }
}
