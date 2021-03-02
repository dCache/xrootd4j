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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.EnumMap;
import java.util.Map;

import org.dcache.xrootd.security.UnsignedIntBucket;
import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdBucketUtils;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_version;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.getClientStep;

public class AuthenticationRequest extends AbstractXrootdRequest
{
    private static final Logger LOGGER =
        LoggerFactory.getLogger(AuthenticationRequest.class);

    /** the protocol as it is send by the client, zero-padded char[4] */
    private final String protocol;
    /** the step as it is send by the client, int32 */
    private final int step;
    /** store the buckets (kind of a serialized datatype with an
     * int32 block of metadata) received from the client
     */
    /**
     *  pull the protocol version of the client out of the bucket map
     *  for convenient access.
     */
    private Integer version;

    private final Map<BucketType, XrootdBucket> bucketMap =
        new EnumMap<>(BucketType.class);

    /**
     * Deserialize protocol, processing step and all the bucks sent by the
     * client
     * @param buffer The buffer containing the above
     */
    public AuthenticationRequest(ByteBuf buffer)
    {
        super(buffer, kXR_auth);

        /* skip reserved bytes and credlen */
        buffer.readerIndex(24);

        protocol = XrootdBucketUtils.deserializeProtocol(buffer);

        if (protocol.equals("unix")) {
            step = kXR_ok;
            return;
        }

        step = XrootdBucketUtils.deserializeStep(buffer);

        try {
            bucketMap.putAll(XrootdBucketUtils.deserializeBuckets(buffer));
        } catch (IOException ioex) {
            throw new IllegalArgumentException("Illegal credential format: {}",
                                               ioex);
        }

        UnsignedIntBucket versionBucket
                        = (UnsignedIntBucket)bucketMap.get(kXRS_version);

        if (versionBucket != null) {
            version = versionBucket.getContent();
        }

        if (LOGGER.isTraceEnabled()) {
            LOGGER.trace(describe());
        }
    }

    public String describe()
    {
        return XrootdBucketUtils.describe("//                Authentication Request",
            b -> XrootdBucketUtils.dumpBuckets(b,
                                                  bucketMap.values(),
                                                  getClientStep(step)),
            streamId, requestId,null);
    }

    public Map<BucketType, XrootdBucket> getBuckets() {
        return bucketMap;
    }

    public int getStep() {
        return step;
    }

    public String getProtocol() {
        return protocol;
    }

    public Integer getVersion() {
        return version;
    }
}
