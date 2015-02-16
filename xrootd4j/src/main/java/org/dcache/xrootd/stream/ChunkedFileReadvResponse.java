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
 * License along with xrootd4j.  If not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.stream;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.ReadVRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_FileNotOpen;

public class ChunkedFileReadvResponse extends AbstractChunkedReadvResponse
{
    private final List<RandomAccessFile> files;

    public ChunkedFileReadvResponse(ReadVRequest request, int maxFrameSize, List<RandomAccessFile> files)
    {
        super(request, maxFrameSize);
        this.files = files;
    }

    @Override
    protected long getSize(int fd) throws IOException, XrootdException
    {
        if (fd < 0 || fd >= files.size() || files.get(fd) == null) {
            throw new XrootdException(kXR_FileNotOpen, "Invalid file descriptor");
        }
        return files.get(fd).length();
    }

    @Override
    protected ByteBuf read(ByteBufAllocator alloc, int fd, long position, int length)
        throws IOException, XrootdException
    {
        if (fd < 0 || fd >= files.size() || files.get(fd) == null) {
            throw new XrootdException(kXR_FileNotOpen, "Invalid file descriptor");
        }

        FileChannel channel = files.get(fd).getChannel();

        ByteBuf chunk = alloc.ioBuffer(length);
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
    }
}
