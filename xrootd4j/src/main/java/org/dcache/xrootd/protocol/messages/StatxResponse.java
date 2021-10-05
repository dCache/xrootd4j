/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
import org.dcache.xrootd.protocol.XrootdProtocol;

public class StatxResponse extends AbstractXrootdResponse<StatxRequest> {

    private final int[] fileStates;

    public StatxResponse(StatxRequest request, int[] fileStates) {
        super(request, XrootdProtocol.kXR_ok);
        this.fileStates = fileStates;
    }

    @Override
    public int getDataLength() {
        return fileStates.length;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        for (int state : fileStates) {
            buffer.writeByte(state);
        }
    }
}
