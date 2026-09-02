/**
 * Copyright (C) 2011-2026 dCache.org <support@dcache.org>
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
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_cancel;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_coloc;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_evict;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fresh;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_noerrs;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_notify;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_prepare;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_stage;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_wmode;

import io.netty.buffer.ByteBuf;
import java.util.Arrays;

public class PrepareRequest extends AbstractXrootdRequest {

    private final int options;
    private final int priority;
    private String[] paths;
    private String[] opaques;

    public PrepareRequest(ByteBuf buffer) {
        super(buffer, kXR_prepare);

        options = buffer.getByte(4);
        priority = buffer.getByte(5);

        int plen = buffer.getInt(20);
        int end = 24 + plen;

        paths = buffer.toString(24, end - 24, US_ASCII).split("\n");
        opaques = new String[paths.length];

        for (int i = 0; i < paths.length; i++) {
            String path = paths[i];
            int pos = path.indexOf('?');
            if (pos > -1) {
                paths[i] = path.substring(0, pos);
                opaques[i] = path.substring(pos + 1);
            }
        }
    }

    public int getOptions() {
        return options;
    }

    public int getPriority() {
        return priority;
    }

    public String[] getPaths() {
        return paths;
    }

    public String[] getPathList() {
        return paths;
    }

    public String[] getOpaques() {
        return opaques;
    }

    public boolean isCancel() {
        return (getOptions() & kXR_cancel) == kXR_cancel;
    }

    public boolean isNotify() {
        return (getOptions() & kXR_notify) == kXR_notify;
    }

    public boolean isNoErrors() {
        return (getOptions() & kXR_noerrs) == kXR_noerrs;
    }

    public boolean isStage() {
        return (getOptions() & kXR_stage) == kXR_stage;
    }

    public boolean isWriteMode() {
        return (getOptions() & kXR_wmode) == kXR_wmode;
    }

    public boolean isColocate() {
        return (getOptions() & kXR_coloc) == kXR_coloc;
    }

    public boolean isFresh() {
        return (getOptions() & kXR_fresh) == kXR_fresh;
    }

    public boolean isEvict() {
        return (getOptions() & kXR_evict) == kXR_evict;
    }

    @Override
    public String toString() {
        return String.format("prepare[%d,%d,%s]", options, priority,
              Arrays.toString(paths));
    }
}
