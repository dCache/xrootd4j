/**
 * Copyright (C) 2011-2014 dCache.org <support@dcache.org>
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
 * License along with xrootd4j.  If not, see
 * <http://www.gnu.org/licenses/>.
 */
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.EnumMap;
import java.util.Map;

import org.dcache.xrootd.security.XrootdBucket;
import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;

public class AuthenticationRequest extends XrootdRequest
{
    private static final Logger _logger =
        LoggerFactory.getLogger(AuthenticationRequest.class);

    /** the protocol as it is send by the client, zero-padded char[4] */
    private final String _protocol;
    /** the step as it is send by the client, int32 */
    private final int _step;
    /** store the buckets (kind of a serialized datatype with an
     * int32 block of metadata) received from the client
     */
    private final Map<BucketType, XrootdBucket> _bucketMap =
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

        _protocol = deserializeProtocol(buffer);
        _step = deserializeStep(buffer);

        try {
            _bucketMap.putAll(deserializeBuckets(buffer));
        } catch (IOException ioex) {
            throw new IllegalArgumentException("Illegal credential format: {}",
                                               ioex);
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

        _logger.debug("Deserializing a bucket with code {}", bucketCode);

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
       String protocol = buffer.toString(buffer.readerIndex(),
                                         4,
                                         Charset.forName("ASCII")).trim();

       /* toString does not advance the index */
       buffer.readerIndex(buffer.readerIndex() + 4);
       return protocol;
    }

    public static int deserializeStep(ByteBuf buffer) {
        return buffer.readInt();
    }

    public Map<BucketType, XrootdBucket> getBuckets() {
        return _bucketMap;
    }

    public int getStep() {
        return _step;
    }

    public String getProtocol() {
        return _protocol;
    }
}
