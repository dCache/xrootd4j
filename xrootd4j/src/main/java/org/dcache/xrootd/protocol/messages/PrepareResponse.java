/**
 * Copyright (C) 2011-2024 dCache.org <support@dcache.org>
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

import io.netty.buffer.ByteBuf;

public class PrepareResponse extends AbstractXrootdResponse<PrepareRequest> {

    byte[] locator;

    public PrepareResponse(PrepareRequest request, int stat, byte[] locator) {
        super(request, stat);
        this.locator = locator;
    }

    @Override
    public int getDataLength() {
        return locator.length;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        buffer.writeBytes(locator);
    }
}
