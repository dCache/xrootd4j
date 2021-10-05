/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_FileNotOpen;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;
import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.ReadVRequest;

public class ChunkedFileChannelReadvResponse extends AbstractChunkedReadvResponse {

    private final List<FileChannel> channels;

    public ChunkedFileChannelReadvResponse(ReadVRequest request, int maxFrameSize,
          List<FileChannel> channels) {
        super(request, maxFrameSize);
        this.channels = channels;
    }

    private void checkValidFileDescriptor(int fd) throws XrootdException {
        if (fd < 0 || fd >= channels.size() || channels.get(fd) == null) {
            throw new XrootdException(kXR_FileNotOpen, "Invalid file descriptor");
        }
    }

    @Override
    protected long getSize(int fd) throws IOException, XrootdException {
        checkValidFileDescriptor(fd);
        return channels.get(fd).size();
    }

    @Override
    protected ByteBuf read(ByteBufAllocator alloc, int fd, long position, int length)
          throws IOException, XrootdException {
        checkValidFileDescriptor(fd);

        FileChannel channel = channels.get(fd);

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
