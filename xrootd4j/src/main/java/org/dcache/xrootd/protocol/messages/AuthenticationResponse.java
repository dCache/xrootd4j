/**
 * Copyright (C) 2011-2015 dCache.org <support@dcache.org>
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

import java.util.List;

import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static com.google.common.base.Preconditions.checkArgument;
import static java.nio.charset.StandardCharsets.US_ASCII;

public class AuthenticationResponse extends AbstractXrootdResponse<AuthenticationRequest>
{
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

    public String getProtocol()
    {
        return protocol;
    }

    public int getStep()
    {
        return step;
    }

    @Override
    protected int getLength()
    {
        // HEADER + PROTOCOL + STEP + BODY + TERMINAL
        return super.getLength() + 4 + 4 + length + 4;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        super.getBytes(buffer);

        byte[] bytes = protocol.getBytes(US_ASCII);
        buffer.writeBytes(bytes);
        /* protocol must be 0-padded to 4 bytes */
        buffer.writeZero(4 - bytes.length);

        buffer.writeInt(step);
        for (XrootdBucket bucket : buckets) {
            bucket.serialize(buffer);
        }

        buffer.writeInt(BucketType.kXRS_none.getCode());
    }
}
