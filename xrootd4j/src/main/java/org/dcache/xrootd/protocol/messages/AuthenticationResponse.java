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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPromise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdBucketUtils;

import static com.google.common.base.Preconditions.checkArgument;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getServerStep;

public class AuthenticationResponse extends AbstractXrootdResponse<AuthenticationRequest>
{
    private static final Logger LOGGER =
                    LoggerFactory.getLogger(AuthenticationResponse.class);

    @Override
    public void writeTo(ChannelHandlerContext ctx, ChannelPromise promise)
    {
        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe());
        }
        super.writeTo(ctx, promise);
    }

    private final String protocol;
    private final int step;
    private final List<XrootdBucket> buckets;
    private final int length;

    /**
     * @param request the request this is a response to
     * @param status the status (usually kXR_authmore)
     * @param length
     * @param protocol the currently used authentication protocol
     * @param step the processing step
     * @param buckets list of buckets containing server-side authentication
     *                information (challenge, host certificate, etc.)
     */
    public AuthenticationResponse(AuthenticationRequest request,
                                  int status,
                                  int length,
                                  String protocol,
                                  int step,
                                  List<XrootdBucket> buckets)
    {
        super(request, status);

        checkArgument(protocol.length() <= 4);

        this.protocol = protocol;
        this.step = step;
        this.buckets = buckets;
        this.length = length;
    }

    public String describe()
    {
        StringBuilder builder = new StringBuilder("\n");
        builder.append("/////////////////////////////////////////////////////////\n");
        builder.append("//               Authentication Response\n");
        builder.append("//\n");
        builder.append("//  stream:  ").append(request.getStreamId()).append("\n");
        builder.append("//  request: ").append(request.getRequestId()).append("\n");
        builder.append("//\n");

        int i = 0;

        for (XrootdBucket bucket : buckets) {
            i = bucket.dump(builder, getServerStep(step), ++i);
        }

        builder.append("/////////////////////////////////////////////////////////\n");

        return builder.toString();
    }

    public String getProtocol()
    {
        return protocol;
    }

    public int getStep()
    {
        return step;
    }

    @Override
    public int getDataLength()
    {
        // PROTOCOL + STEP + BODY + TERMINAL
        return 4 + 4 + length + 4;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        XrootdBucketUtils.writeBytes(buffer, protocol, step, buckets);
    }
}
