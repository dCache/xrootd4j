/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import static org.dcache.xrootd.protocol.XrootdProtocol.*;

public class OpenRequest extends PathRequest
{
    private final int _mode;
    private final int _options;

    public OpenRequest(ByteBuf buffer)
    {
        super(buffer, kXR_open);

        _mode = buffer.getUnsignedShort(4);
        _options = buffer.getUnsignedShort(6);
    }

    public int getUMask()
    {
        return _mode;
    }

    public int getOptions()
    {
        return _options;
    }

    public boolean isAsync() {
        return (getOptions() & kXR_async) == kXR_async;
    }

    public boolean isCompress() {
        return (getOptions() & kXR_compress) == kXR_compress;
    }

    public boolean isDelete() {
        return (getOptions() & kXR_delete) == kXR_delete;
    }

    public boolean isForce() {
        return (getOptions() & kXR_force) == kXR_force;
    }

    public boolean isNew() {
        return (getOptions() & kXR_new) == kXR_new;
    }

    public boolean isReadOnly() {
        return (getOptions() & kXR_open_read) == kXR_open_read;
    }

    public boolean isReadWrite() {
        return (getOptions() & kXR_open_updt) == kXR_open_updt;
    }

    public boolean isRefresh() {
        return (getOptions() & kXR_refresh) == kXR_refresh;
    }

    public boolean isRetStat() {
        return (getOptions() & kXR_retstat) == kXR_retstat;
    }

    public boolean isMkPath() {
        return (getOptions() & kXR_mkpath) == kXR_mkpath;
    }

    @Override
    public String toString()
    {
        return String.format("open[%d,%d,%s,%s]",
                             getUMask(), getOptions(), getPath(), getOpaque());
    }
}
