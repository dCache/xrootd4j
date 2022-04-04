/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_async;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_compress;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_delete;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_force;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_mkpath;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_new;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open_apnd;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open_read;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_open_updt;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_refresh;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_retstat;

import io.netty.buffer.ByteBuf;

public class OpenRequest extends PathRequest {

    private final int mode;
    private final int options;

    public OpenRequest(ByteBuf buffer) {
        super(buffer, kXR_open);

        mode = buffer.getUnsignedShort(4);
        options = buffer.getUnsignedShort(6);
    }

    public int getUMask() {
        return mode;
    }

    public int getOptions() {
        return options;
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

    public boolean isAppend() {
        return (getOptions() & kXR_open_apnd) == kXR_open_apnd;
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

    public FilePerm getRequiredPermission() {
        return isNew() || isDelete() || isReadWrite() || isAppend() ? FilePerm.WRITE
              : FilePerm.READ;
    }

    @Override
    public String toString() {
        return String.format("open[%d,%d,%s,%s]",
              getUMask(), getOptions(), getPath(), getOpaque());
    }
}
