/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdBucketUtils;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getClientStep;

/**
 * <p>Request to third-party source server.</p>
 */
public class OutboundAuthenticationRequest
                extends AbstractXrootdOutboundRequest {
    private static final Logger LOGGER =
                    LoggerFactory.getLogger(OutboundAuthenticationRequest.class);

    private final String             protocol;
    private final int                step;
    private final List<XrootdBucket> buckets;
    private final int length;

    /**
     * @param streamId of this request
     * @param length
     * @param protocol the currently used authentication protocol
     * @param step the processing step
     * @param buckets list of buckets containing server-side authentication
     *                information (challenge, host certificate, etc.)
     */
    public OutboundAuthenticationRequest(int streamId,
                                         int length,
                                         String protocol,
                                         int step,
                                         List<XrootdBucket> buckets) {
        super(streamId, kXR_auth);
        this.protocol = protocol;
        this.step = step;
        this.length = length;
        this.buckets = buckets;
    }

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe());
        }
        super.writeTo(ctx, promise);
    }

    public String describe()
    {
        return XrootdBucketUtils.describe("//           Outbound Authentication Response",
            b->XrootdBucketUtils.dumpBuckets(b, buckets, getClientStep(step)),
            streamId, requestId, null);
    }

    @Override
    protected void getParams(ByteBuf buffer) {
        // pad ... skip the 16 bytes
        buffer.writeZero(16);
        buffer.writeInt(12 + length);
        XrootdBucketUtils.writeBytes(buffer, protocol, step, buckets);
    }

    @Override
    protected int getParamsLen() {
        // 16 bytes reserved + len + data
        return getDataLen() + 20;
    }

    private int getDataLen() {
        // 12 = protocol + step + terminal
        return 12 + length;
    }
}
