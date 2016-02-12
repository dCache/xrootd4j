/**
 * Copyright (C) 2011-2016 dCache.org <support@dcache.org>
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.netty.buffer.ByteBuf;

public abstract class GenericReadRequestMessage extends AbstractXrootdRequest
{
    public static class EmbeddedReadRequest
    {
        private final int fh;
        private final int len;
        private final long offs;

        EmbeddedReadRequest(int fh, int len, long offs)
        {
            this.fh = fh;
            this.len = len;
            this.offs = offs;
        }

        public int getFileHandle()
        {
            return fh;
        }

        public int BytesToRead()
        {
            return len;
        }

        public long getOffset()
        {
            return offs;
        }

        @Override
        public String toString()
        {
            return String.format("(%d,%d,%d)", fh, len, offs);
        }
    }

    private static final Logger LOGGER =
        LoggerFactory.getLogger(GenericReadRequestMessage.class);

    private final int pathid;
    private final EmbeddedReadRequest[] readList;

    public GenericReadRequestMessage(ByteBuf buffer, int requestId)
    {
        super(buffer, requestId);

        int alen = buffer.getInt(20);

        if (alen <= 8) {
            pathid = -1;
            readList = new EmbeddedReadRequest[0];
        } else {
            int prefix = 0;
            if (alen % 16 == 0) {
                pathid = -1;
            } else if (alen % 16 != 8) {
                pathid = -1;
                LOGGER.warn("invalid readv request: data doesn't start with 8 byte prefix (pathid)");
            } else {
                pathid = buffer.getUnsignedByte(24);
                prefix = 8;
            }

            int numberOfListEntries = (alen - prefix) / 16;

            readList = new EmbeddedReadRequest[numberOfListEntries];

            for (int i = 0; i < numberOfListEntries; i++) {
                int j = 24 + prefix + i * 16;
                readList[i] = new EmbeddedReadRequest(buffer.getInt(j),
                                                      buffer.getInt(j + 4),
                                                      buffer.getLong(j + 8));
            }
        }
    }

    public int getPathID()
    {
        return pathid;
    }

    protected int getSizeOfList()
    {
        return readList.length;
    }

    protected EmbeddedReadRequest[] getReadRequestList()
    {
        return readList;
    }
}
