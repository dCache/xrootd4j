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
package org.dcache.xrootd.stream;

import org.jboss.netty.buffer.ChannelBuffer;

import java.io.IOException;

import org.dcache.xrootd.protocol.messages.ReadRequest;
import org.dcache.xrootd.protocol.messages.ReadResponse;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

public abstract class AbstractChunkedReadResponse implements ChunkedResponse
{
    protected final ReadRequest request;
    protected final int maxFrameSize;
    protected long position;
    protected int length;
    protected boolean isEndOfInput;

    public AbstractChunkedReadResponse(ReadRequest request, int maxFrameSize)
    {
        this.request = request;
        this.maxFrameSize = maxFrameSize;
        this.position = request.getReadOffset();
        this.length = request.bytesToRead();
    }

    @Override
    public XrootdRequest getRequest()
    {
        return request;
    }

    @Override
    public ReadResponse nextChunk() throws Exception
    {
        if (isEndOfInput) {
            return null;
        }
        ReadResponse response = new ReadResponse(request, 0);
        response.append(readNext());
        response.setIncomplete(!isEndOfInput);
        return response;
    }

    private ChannelBuffer readNext() throws IOException
    {
        int chunkLength = Math.min(length, maxFrameSize);
        ChannelBuffer buffer = read(position, chunkLength);
        int readableBytes = buffer.readableBytes();
        position += readableBytes;
        length = (readableBytes < chunkLength) ? 0 : length - readableBytes;
        if (length == 0) {
            isEndOfInput = true;
        }
        return buffer;
    }

    protected abstract ChannelBuffer read(long srcIndex, int length)
        throws IOException;

    @Override
    public boolean isEndOfInput() throws Exception
    {
        return isEndOfInput;
    }

    @Override
    public void close() throws Exception
    {
    }
}
