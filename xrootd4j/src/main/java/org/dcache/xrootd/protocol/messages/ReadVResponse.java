/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.CompositeByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import io.netty.util.AbstractReferenceCounted;
import io.netty.util.ReferenceCounted;

import java.util.ArrayList;
import java.util.List;

import org.dcache.xrootd.protocol.messages.GenericReadRequestMessage.EmbeddedReadRequest;

import static com.google.common.base.Preconditions.*;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_oksofar;

public class ReadVResponse extends AbstractReferenceCounted implements XrootdResponse<ReadVRequest>
{
    public static final int READ_LIST_HEADER_SIZE = 16;

    private final ReadVRequest request;
    private final int stat;
    private final EmbeddedReadRequest[] requests;
    private final ByteBuf[] data;
    private final int index;
    private final int length;

    public ReadVResponse(ReadVRequest request,
                         EmbeddedReadRequest[] requests,
                         ByteBuf[] data,
                         int index,
                         int length,
                         boolean isIncomplete)
    {
        checkArgument(length > 0);
        this.request = checkNotNull(request);
        this.stat = isIncomplete ? kXR_oksofar : kXR_ok;
        this.requests = checkNotNull(requests);
        this.data = checkNotNull(data);
        this.index = index;
        this.length = length;
    }

    @Override
    public ReadVRequest getRequest()
    {
        return request;
    }

    @Override
    public int getStatus()
    {
        return stat;
    }

    /**
     * Returns the data segments of the response. Only the segments contained in
     * this response are returned.
     *
     * The buffers returned are unmodifiable views of the actual data segments.
     * Reference counts are shared and the caller should not release any reference
     * to the returned buffers.
     */
    public List<ByteBuf> getSegments()
    {
        List<ByteBuf> chunks = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            chunks.add(data[index + i].asReadOnly());
        }
        return chunks;
    }

    public List<Integer> getSegmentLengths()
    {
        List<Integer> chunks = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            chunks.add(data[index + i].readableBytes());
        }
        return chunks;
    }

    /**
     * Returns the starting index into the request read segments that this response
     * addresses.
     */
    public int getIndex()
    {
        return index;
    }

    /**
     * Returns the number of segments contained in this response.
     */
    public int getLength()
    {
        return length;
    }


    @Override
    public int getDataLength()
    {
        int payload = 0;
        for (int i = 0; i < length; i++) {
            payload += READ_LIST_HEADER_SIZE;
            payload += data[index + i].readableBytes();
        }
        return payload;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        checkState(refCnt() > 0);

        CompositeByteBuf buffer = ctx.alloc().compositeBuffer(2 * length + 1);

        ByteBuf header = ctx.alloc().buffer(8);
        header.writeShort(request.getStreamId());
        header.writeShort(stat);
        header.writeInt(getDataLength());
        buffer.addComponent(header);

        for (int i = 0; i < length; i++) {
            header = ctx.alloc().buffer(READ_LIST_HEADER_SIZE);
            header.writeInt(requests[index + i].getFileHandle());
            header.writeInt(data[index + i].readableBytes());
            header.writeLong(requests[index + i].getOffset());
            buffer.addComponent(header);
            buffer.addComponent(data[index + i].retain());
        }

        buffer.writerIndex(buffer.capacity());
        ctx.write(buffer, promise);

        release();
    }

    @Override
    public String toString()
    {
        int payload = 0;
        for (int i = 0; i < length; i++) {
            payload += data[index + i].readableBytes();
        }
        return String.format("readv-response[elements=%d,bytes=%d]", length, payload);
    }

    @Override
    public ReferenceCounted touch(Object hint)
    {
        for (int i = 0; i < length; i++) {
            data[i + index].touch(hint);
        }
        return this;
    }

    @Override
    protected void deallocate()
    {
        for (int i = 0; i < length; i++) {
            data[i + index].release();
        }
    }
}
