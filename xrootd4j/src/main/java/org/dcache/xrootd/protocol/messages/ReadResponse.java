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

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

import java.nio.channels.ScatteringByteChannel;
import java.io.IOException;

import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage.EmbeddedReadRequest;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

public class ReadResponse extends AbstractResponseMessage
{
    public static final int READ_LIST_HEADER_SIZE = 16;

    // TODO: Use a composite buffer

    public ReadResponse(XrootdRequest request, int length)
    {
        super(request, kXR_ok, length);
    }

    /**
     * Set the status field to indicate whether the response is
     * complete or not.
     */
    public void setIncomplete(boolean incomplete)
    {
        setStatus(incomplete ? kXR_oksofar : kXR_ok);
    }

    /**
     * Reads bytes from a channel into the response buffer.
     */
    public int writeBytes(ScatteringByteChannel in, int length)
        throws IOException
    {
        return _buffer.writeBytes(in, length);
    }

    /**
     * Reads bytes from a channel into the response buffer.
     */
    public int writeBytes(EmbeddedReadRequest req)
    {
        putSignedInt(req.getFileHandle());
        putSignedInt(req.BytesToRead());
        putSignedLong(req.getOffset());
        return 16;
    }

    private ByteBuf createReadListHeader(EmbeddedReadRequest request, int actualLength)
    {
        ByteBuf buffer = Unpooled.buffer(16);
        buffer.writeInt(request.getFileHandle());
        buffer.writeInt(actualLength);
        buffer.writeLong(request.getOffset());
        return buffer;
    }

    public void write(EmbeddedReadRequest[] requests,
                      ByteBuf[] buffers,
                      int offset, int length)
    {
        ByteBuf[] reply = new ByteBuf[2 * length + 1];
        reply[0] = _buffer;
        for (int i = 0; i < length; i++) {
            reply[2 * i + 1] = createReadListHeader(requests[offset + i], buffers[offset + i].readableBytes());
            reply[2 * i + 2] = buffers[offset + i];
        }
        _buffer = Unpooled.wrappedBuffer(reply);
    }

    public void append(ByteBuf buffer)
    {
        _buffer = Unpooled.wrappedBuffer(_buffer, buffer);
    }

    /**
     * Returns the size of the payload. Only accurate as the long as
     * we have not begun to send the buffer.
     */
    public int getDataLength()
    {
        return _buffer.readableBytes() - SERVER_RESPONSE_LEN;
    }

    @Override
    public String toString()
    {
        return String.format("read-response[length=%d]", getDataLength());
    }
}
