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

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage;
import org.dcache.xrootd.protocol.messages.ReadResponse;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.XrootdRequest;

public abstract class AbstractChunkedReadvResponse implements ChunkedResponse
{
    protected final ReadVRequest request;
    protected final int maxFrameSize;
    protected final GenericReadRequestMessage.EmbeddedReadRequest[] requests;
    protected int index;

    public AbstractChunkedReadvResponse(ReadVRequest request, int maxFrameSize)
    {
        this.maxFrameSize = maxFrameSize;
        this.request = request;
        this.requests = request.getReadRequestList();
    }

    @Override
    public XrootdRequest getRequest()
    {
        return request;
    }

    @Override
    public ReadResponse nextChunk() throws Exception
    {
        if (isEndOfInput()) {
            return null;
        }

        int count = getChunksInNextFrame(maxFrameSize);
        ChannelBuffer[] chunks = new ChannelBuffer[requests.length];
        for (int i = index; i < index + count; i++) {
            chunks[i] = read(requests[i]);
        }

        ReadResponse response = new ReadResponse(request, 0);
        response.write(requests, chunks, index, count);
        response.setIncomplete(index + count < requests.length);
        index += count;

        return response;
    }

    @Override
    public boolean isEndOfInput() throws Exception
    {
        return (index == requests.length);
    }

    @Override
    public void close() throws Exception
    {
    }

    private int getLengthOfRequest(GenericReadRequestMessage.EmbeddedReadRequest request)
        throws IOException, XrootdException
    {
        return (int) Math.min(request.BytesToRead(),
            getSize(request.getFileHandle()) - request.getOffset());
    }

    private int getChunksInNextFrame(int maxFrameSize) throws IOException, XrootdException
    {
        long length = 0;
        int count = 0;
        for (int i = index; i < requests.length && length < maxFrameSize; i++) {
            length += ReadResponse.READ_LIST_HEADER_SIZE;
            length += getLengthOfRequest(requests[i]);
            count++;
        }
        if (length > maxFrameSize) {
            count--;
        }
        if (count == 0) {
            throw new IllegalStateException("Maximum chunk size exceeded");
        }
        return count;
    }

    private ChannelBuffer read(GenericReadRequestMessage.EmbeddedReadRequest request)
        throws IOException, XrootdException
    {
        return read(request.getFileHandle(), request.getOffset(), request.BytesToRead());
    }

    protected abstract long getSize(int fd) throws IOException, XrootdException;

    protected abstract ChannelBuffer read(int fd, long position, int length)
        throws IOException, XrootdException;
}
