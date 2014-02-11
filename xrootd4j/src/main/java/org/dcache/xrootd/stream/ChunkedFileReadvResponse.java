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
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.List;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.protocol.messages.ReadVRequest;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_FileNotOpen;
import static org.jboss.netty.buffer.ChannelBuffers.wrappedBuffer;

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
    protected ChannelBuffer read(int fd, long position, int length)
        throws IOException, XrootdException
    {
        if (fd < 0 || fd >= files.size() || files.get(fd) == null) {
            throw new XrootdException(kXR_FileNotOpen, "Invalid file descriptor");
        }

        FileChannel channel = files.get(fd).getChannel();
        byte[] chunkArray = new byte[length];
        ByteBuffer chunk = ByteBuffer.wrap(chunkArray);

        while (length > 0) {
            /* use position independent thread safe call */
            int bytes = channel.read(chunk, position);
            if (bytes < 0) {
                break;
            }
            position += bytes;
            length -= bytes;
        }

        return wrappedBuffer(chunkArray, 0, chunkArray.length - length);
    }
}
