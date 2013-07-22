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
package org.dcache.xrootd.stream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.MessageBuf;
import io.netty.handler.stream.ChunkedMessageInput;

import java.io.IOException;

import org.dcache.xrootd.protocol.messages.AbstractResponseMessage;
import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadResponse;

public abstract class AbstractChunkedReadResponse implements ChunkedMessageInput<AbstractResponseMessage>
{
    protected final ReadRequest request;
    protected final int maxFrameSize;
    protected long position;
    protected int length;

    public AbstractChunkedReadResponse(ReadRequest request, int maxFrameSize)
    {
        this.request = request;
        this.maxFrameSize = maxFrameSize;
        this.position = request.getReadOffset();
        this.length = request.bytesToRead();
    }

    @Override
    public boolean readChunk(MessageBuf<AbstractResponseMessage> buffer) throws Exception
    {
        if (length == 0) {
            return false;
        }

        int chunkLength = Math.min(length, maxFrameSize);

        ByteBuf chunk = read(position, chunkLength);
        chunkLength = chunk.readableBytes();
        position += chunkLength;
        length -= chunkLength;

        ReadResponse response = new ReadResponse(request, 0);
        response.append(chunk);
        response.setIncomplete(length != 0);

        buffer.add(response);
        return true;
    }

    protected abstract ByteBuf read(long srcIndex, int length)
        throws IOException;

    @Override
    public boolean isEndOfInput() throws Exception
    {
        return (length == 0);
    }

    @Override
    public void close() throws Exception
    {
    }
}
