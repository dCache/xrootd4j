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
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;

import java.util.function.Consumer;

import static org.dcache.xrootd.core.XrootdEncoder.writeZeroPad;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.messages.LoginResponse.AUTHN_PROTOCOL_TYPE_LEN;

/**
 * Request to third-party source server.
 * <p/>
 * This has the same structure as the request to the server.
 *  <p/>
 *  kXR_char streamid[2] <br/>
 *  kXR_unt16<br/>
 *  kXR_char reserved[12] <br/>
 *  kXR_char credtype[4] <br/>
 *  kXR_int32 credlen <br/>
 *  kXR_char cred[credlen]
 *  </p>
 *  Different security protocols will use the cred data differently.
 *  that functionality should not be here, but in the specific protocol's
 *  processing.
 */
public class OutboundAuthenticationRequest
                extends AbstractXrootdOutboundRequest
{
    private final String            credType;
    private final int               length;
    private final Consumer<ByteBuf> serializer;

    /**
     * @param streamId of this request
     * @param credType usually the protocol name
     * @param length of the data container to be serialized
     * @param serializer function responsible for writing to the buffer
     */
    public OutboundAuthenticationRequest(int streamId,
                                         String credType,
                                         int length,
                                         Consumer<ByteBuf> serializer)
    {
        super(streamId, kXR_auth);
        this.credType = credType;
        this.length = length;
        this.serializer = serializer;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        super.writeTo(ctx, promise);
    }

    @Override
    protected void getParams(ByteBuf buffer)
    {
        // pad ... skip the 12 reserved bytes
        buffer.writeZero(12);
        writeZeroPad(credType, buffer, AUTHN_PROTOCOL_TYPE_LEN);
        buffer.writeInt(length);
        serializer.accept(buffer);
    }

    @Override
    protected int getParamsLen()
    {
        // 12 bytes reserved + 4 bytes type + 4 bytes len + data
        return 20 + length;
    }
}
