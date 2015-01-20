/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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
import io.netty.buffer.ByteBufAllocator;

import java.io.IOException;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage;
import org.dcache.xrootd.protocol.messages.ReadVRequest;
import org.dcache.xrootd.protocol.messages.ReadVResponse;
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
    public ReadVResponse nextChunk(ByteBufAllocator alloc) throws Exception
    {
        if (isEndOfInput()) {
            return null;
        }

        int count = getChunksInNextFrame(maxFrameSize);
        ByteBuf[] chunks = new ByteBuf[requests.length];
        for (int i = index; i < index + count; i++) {
            chunks[i] = read(alloc, requests[i]);
        }

        ReadVResponse response =
                new ReadVResponse(request, requests, chunks, index, count, index + count < requests.length);
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
            length += ReadVResponse.READ_LIST_HEADER_SIZE;
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

    private ByteBuf read(ByteBufAllocator alloc, GenericReadRequestMessage.EmbeddedReadRequest request)
        throws IOException, XrootdException
    {
        return read(alloc, request.getFileHandle(), request.getOffset(), request.BytesToRead());
    }

    protected abstract long getSize(int fd) throws IOException, XrootdException;

    protected abstract ByteBuf read(ByteBufAllocator alloc, int fd, long position, int length)
        throws IOException, XrootdException;
}
