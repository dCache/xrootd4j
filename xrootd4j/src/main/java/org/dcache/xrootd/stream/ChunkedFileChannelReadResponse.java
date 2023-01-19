/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.stream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.dcache.xrootd.protocol.messages.ReadRequest;

public class ChunkedFileChannelReadResponse extends AbstractChunkedReadResponse {

    private final FileChannel channel;

    public ChunkedFileChannelReadResponse(ReadRequest request, int maxFrameSize,
          FileChannel channel) {
        super(request, maxFrameSize);
        this.channel = channel;
    }

    @Override
    protected ByteBuf read(ByteBufAllocator alloc, long position, int length)
          throws IOException {
        ByteBuf chunk = alloc.ioBuffer(length);
        try {
            chunk.writerIndex(length);
            ByteBuffer buffer = chunk.nioBuffer();
            while (length > 0) {
                /* use position independent thread safe call */
                int bytes = channel.read(buffer, position);
                if (bytes < 0) {
                    break;
                }
                position += bytes;
                length -= bytes;
            }
            chunk.writerIndex(chunk.writerIndex() - length);
            return chunk;
        } catch (RuntimeException | IOException e) {
            ReferenceCountUtil.release(chunk);
            throw e;
        }
    }
}
