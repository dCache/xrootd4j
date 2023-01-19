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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_wait;

import io.netty.buffer.ByteBuf;

public class WaitRetryResponse<T extends XrootdRequest> extends AbstractXrootdResponse<T> {

    private final int seconds;

    public WaitRetryResponse(T request, int seconds) {
        super(request, kXR_wait);
        this.seconds = seconds;
    }

    @Override
    public int getDataLength() {
        return 4;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        buffer.writeInt(seconds);
    }
}
