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
package org.dcache.xrootd.protocol.messages;

import static java.nio.charset.StandardCharsets.US_ASCII;

import io.netty.buffer.ByteBuf;
import java.util.Iterator;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.util.FileStatus;

public class DirListStatResponse extends DirListResponse {

    private final Iterable<FileStatus> status;

    public DirListStatResponse(DirListRequest request, int statusCode, Iterable<String> names,
          Iterable<FileStatus> status) {
        super(request, statusCode, names);
        this.status = status;
    }

    public DirListStatResponse(DirListRequest request, Iterable<String> names,
          Iterable<FileStatus> status) {
        super(request, names);
        this.status = status;
    }

    public Iterable<FileStatus> getFileStatus() {
        return status;
    }

    @Override
    public int getDataLength() {
        if (!names.iterator().hasNext()) {
            return 0;
        }
        int length = 0;
        Iterator<String> names = this.names.iterator();
        Iterator<FileStatus> status = this.status.iterator();
        while (names.hasNext() && status.hasNext()) {
            length += names.next().length() + 1 + status.next().toString().length() + 1;
        }
        return length;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        Iterator<String> names = this.names.iterator();
        Iterator<FileStatus> status = this.status.iterator();
        if (names.hasNext() && status.hasNext()) {
            buffer.writeBytes(names.next().getBytes(US_ASCII));
            buffer.writeByte('\n');
            buffer.writeBytes(status.next().toString().getBytes(US_ASCII));
            while (names.hasNext() && status.hasNext()) {
                buffer.writeByte('\n');
                buffer.writeBytes(names.next().getBytes(US_ASCII));
                buffer.writeByte('\n');
                buffer.writeBytes(status.next().toString().getBytes(US_ASCII));
            }

            /* If no more entries follow, the last entry in the list is terminated
             * by a 0 rather than by a \n.
             */
            if (stat == XrootdProtocol.kXR_oksofar) {
                buffer.writeByte('\n');
            } else {
                buffer.writeByte(0);
            }
        }
    }
}
