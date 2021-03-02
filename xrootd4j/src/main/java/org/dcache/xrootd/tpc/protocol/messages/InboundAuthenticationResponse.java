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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.RawBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdBucketUtils;
import org.dcache.xrootd.security.XrootdSecurityProtocol;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static io.netty.buffer.Unpooled.wrappedBuffer;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_IOError;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_main;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGS_pxyreq;

/**
 * <p>Response from third-party source server.</p>
 */
public class InboundAuthenticationResponse
                extends AbstractXrootdInboundResponse
{
    private static final Logger LOGGER =
                    LoggerFactory.getLogger(InboundAuthenticationResponse.class);

    /**
     * Map of the buckets (kind of a serialized datatype with an
     * int32 block of metadata) received from the client.
     */
    private final Map<BucketType, XrootdBucket> bucketMap =
                    new EnumMap<>(BucketType.class);

    private int dataLength;
    private int serverStep;
    private String protocol;

    public InboundAuthenticationResponse(ByteBuf buffer) throws
                    XrootdException {
        super(buffer);
        buffer.readerIndex(4);
        dataLength = buffer.readInt();

        if (dataLength == 0) {
            /*
             *  OK response;
             */
            return;
        }

        protocol = XrootdBucketUtils.deserializeProtocol(buffer);
        serverStep = buffer.readInt();

        try {
            bucketMap.putAll(XrootdBucketUtils.deserializeBuckets(buffer));

            /*
             *  if pxyreq, do not deserialize and unpack the main bucket.
             */
            if (serverStep != kXGS_pxyreq) {
                RawBucket mainBucket = (RawBucket) bucketMap.remove(kXRS_main);
                ByteBuf mainBuffer = wrappedBuffer(mainBucket.getContent());
                /*
                 *   protocol and server step are repeated inside this bucket;
                 *   skip.
                 */
                mainBuffer.readerIndex(8);
                bucketMap.putAll(XrootdBucketUtils.deserializeBuckets(mainBuffer));
            }
        } catch (IOException e) {
            throw new XrootdException(kXR_IOError, e.toString());
        }

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe());
        }
    }

    public String describe()
    {
        StringBuilder builder = new StringBuilder("\n");
        builder.append("/////////////////////////////////////////////////////////\n");
        builder.append("//           Inbound Authentication Response\n");
        builder.append("//\n");
        builder.append("//  stream:  ").append(streamId).append("\n");
        builder.append("//  stat:    ").append(stat).append("\n");
        builder.append("//\n");

        int i = 0;

        Collection<XrootdBucket> buckets = bucketMap.values();

        for (XrootdBucket bucket : buckets) {
            i = bucket.dump(builder,
                            XrootdSecurityProtocol.getServerStep(serverStep), ++i);
        }

        builder.append("/////////////////////////////////////////////////////////\n");

        return builder.toString();
    }

    public Map<BucketType, XrootdBucket> getBuckets() {
        return bucketMap;
    }

    public int getDataLength() {
        return dataLength;
    }

    public String getProtocol() {
        return protocol;
    }

    @Override
    public int getRequestId() {
        return kXR_auth;
    }

    public int getServerStep() {
        return serverStep;
    }
}
