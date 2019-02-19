/**
 * Copyright (C) 2011-2019 dCache.org <support@dcache.org>
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
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType.kXRS_version;

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

        protocol = deserializeProtocol(buffer);

        if (protocol.equals("unix")) {
            step = kXR_ok;
            return;
        }

        step = deserializeStep(buffer);

        try {
            bucketMap.putAll(deserializeBuckets(buffer));
        } catch (IOException ioex) {
            throw new IllegalArgumentException("Illegal credential format: {}",
                                               ioex);
        }

        UnsignedIntBucket versionBucket
                        = (UnsignedIntBucket)bucketMap.get(kXRS_version);

        if (versionBucket != null) {
            version = versionBucket.getContent();
        }
    }

    /**
     * Deserialize the buckets sent by the client and put them into a EnumMap
     * sorted by their header-information. As there are list-type buffers,
     * this method can be called recursively. In current xrootd, this is
     * limited to a maximum of 1 recursion (main buffer containing list of
     * further buffers).
     *
     * @param buffer The buffer containing the received buckets
     * @return Map from bucket-type to deserialized buckets
     * @throws IOException Failure of deserialization
     */
    public static Map<BucketType, XrootdBucket> deserializeBuckets(ByteBuf buffer)
        throws IOException {

        int bucketCode = buffer.readInt();
        BucketType bucketType = BucketType.get(bucketCode);

        LOGGER.debug("Deserializing a bucket with code {}", bucketCode);

        Map<BucketType, XrootdBucket> buckets =
            new EnumMap<>(BucketType.class);

        while (bucketType != BucketType.kXRS_none) {
            int bucketLength = buffer.readInt();

            XrootdBucket bucket = XrootdBucket.deserialize(bucketType,
                                                           buffer.slice(buffer.readerIndex(), bucketLength));
            buckets.put(bucketType, bucket);

            /* proceed to the next bucket */
            buffer.readerIndex(buffer.readerIndex() + bucketLength);

            bucketCode = buffer.readInt();
            bucketType = BucketType.get(bucketCode);
        }

        return buckets;
    }

    public static String deserializeProtocol(ByteBuf buffer) {
       String protocol = buffer.toString(buffer.readerIndex(), 4, US_ASCII).trim();

       /* toString does not advance the index */
       buffer.readerIndex(buffer.readerIndex() + 4);
       return protocol;
    }

    public static int deserializeStep(ByteBuf buffer) {
        return buffer.readInt();
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
