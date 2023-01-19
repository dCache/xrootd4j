/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.util.FileStatus;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.collect.Iterables.concat;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.util.Collections.singleton;

public class DirListResponse extends AbstractXrootdResponse<DirListRequest>
{
    protected final Iterable<String> names;

    public DirListResponse(DirListRequest request, int statusCode, Iterable<String> names)
    {
        super(request, statusCode);
        this.names = names;
    }

    public DirListResponse(DirListRequest request, Iterable<String> names)
    {
        this(request, XrootdProtocol.kXR_ok, names);
    }

    public Iterable<String> getNames()
    {
        return names;
    }

    @Override
    public int getDataLength()
    {
        int length = 0;
        for (String name: names) {
            length += name.length() + 1;
        }
        return length;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        Iterator<String> i = names.iterator();
        if (i.hasNext()) {
            buffer.writeBytes(i.next().getBytes(US_ASCII));
            while (i.hasNext()) {
                buffer.writeByte('\n');
                buffer.writeBytes(i.next().getBytes(US_ASCII));
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

    public static Builder builder(DirListRequest request)
    {
        return request.isDirectoryStat() ? new StatBuilder(request) : new SimpleBuilder(request);
    }

    public interface Builder
    {
        void add(String name);
        void add(String name, FileStatus status);
        DirListResponse buildPartial();
        DirListResponse buildFinal();
        int count();
    }

    private static class SimpleBuilder implements Builder
    {
        private final DirListRequest request;
        private List<String> names = new ArrayList<>();

        public SimpleBuilder(DirListRequest request)
        {
            this.request = request;
        }

        @Override
        public void add(String name)
        {
            names.add(name);
        }

        @Override
        public void add(String name, FileStatus status)
        {
            names.add(name);
        }

        @Override
        public DirListResponse buildPartial()
        {
            checkState(!names.isEmpty());
            DirListResponse response = new DirListResponse(request, XrootdProtocol.kXR_oksofar, names);
            names = new ArrayList<>();
            return response;
        }

        @Override
        public DirListResponse buildFinal()
        {
            DirListResponse response = new DirListResponse(request, XrootdProtocol.kXR_ok, names);
            names = null;
            return response;
        }

        @Override
        public int count()
        {
            return names.size();
        }
    }

    private static class StatBuilder implements Builder
    {
        private final DirListRequest request;
        private List<String> names = new ArrayList<>();
        private List<FileStatus> fileStatus = new ArrayList<>();
        private boolean isFirst = true;

        public StatBuilder(DirListRequest request)
        {
            this.request = request;
        }

        @Override
        public void add(String name)
        {
            names.add(name);
            fileStatus.add(new FileStatus(0, 0, 0, 0));
        }

        @Override
        public void add(String name, FileStatus status)
        {
            names.add(name);
            fileStatus.add(status);
        }

        @Override
        public DirListResponse buildPartial()
        {
            checkState(!names.isEmpty());
            return createResponse(XrootdProtocol.kXR_oksofar, new ArrayList<String>(), new ArrayList<FileStatus>());
        }

        @Override
        public DirListResponse buildFinal()
        {
            if (names.isEmpty()) {
                return new DirListStatResponse(request, XrootdProtocol.kXR_ok, names, fileStatus);
            }
            return createResponse(XrootdProtocol.kXR_ok, null, null);
        }

        private DirListResponse createResponse(int statusCode, List<String> newNames, List<FileStatus> newFileStatuses)
        {
            Iterable<String> names = this.names;
            Iterable<FileStatus> fileStatus = this.fileStatus;
            this.names = newNames;
            this.fileStatus = newFileStatuses;
            if (isFirst) {
                names = concat(singleton("."), names);
                fileStatus = concat(singleton(new FileStatus(0, 0, 0, 0)), fileStatus);
                isFirst = false;
            }
            return new DirListStatResponse(request, statusCode, names, fileStatus);
        }

        @Override
        public int count()
        {
            return names.size();
        }
    }
}
