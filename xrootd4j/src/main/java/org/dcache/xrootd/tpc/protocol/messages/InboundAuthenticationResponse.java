/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;

/**
 * Response from third-party source server.
 */
public class InboundAuthenticationResponse extends AbstractXrootdInboundResponse
{
    private final int dataLength;
    private final ByteBuf data;

    public InboundAuthenticationResponse(ByteBuf buffer) throws
                    XrootdException {
        super(buffer);
        buffer.readerIndex(4);
        dataLength = buffer.readInt();

        if (dataLength == 0) {
            data = null;
            return;
        }

        data = buffer.alloc().ioBuffer(dataLength);
        data.writeBytes(buffer);
    }

    public int getDataLength() {
        return dataLength;
    }

    @Override
    public int getRequestId() {
        return kXR_auth;
    }

    public ByteBuf getDataBuffer()
    {
        return data;
    }

    public void releaseBuffer()
    {
        if (data != null) {
            data.release();
        }
    }
}
