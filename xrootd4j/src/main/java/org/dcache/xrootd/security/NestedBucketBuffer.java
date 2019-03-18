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
package org.dcache.xrootd.security;

import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

import org.dcache.xrootd.protocol.messages.AuthenticationRequest;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_certreq;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXGC_reserved;

/**
 * Format of a NestedBucketBuffer:
 *
 *  - int32 BucketType (usually kXRS_main)
 *  - int32 len
 *  - char[4] protocol (\0 padded)
 *  - int32 step (e.g. kXGS_cert)
 *
 *      -- int32 BucketType (first nested bucket)
 *      -- int32 len
 *      -- byte[len] bucket-content
 *      -- int32 kXRS_none
 *
 *      -- int32 BucketType (second nested bucket)
 *      ...
 *
 *  - kXRS_none
 *
 * @see XrootdBucket
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class NestedBucketBuffer extends XrootdBucket {
    private static final Logger _logger =
        LoggerFactory.getLogger(NestedBucketBuffer.class);
    private final Map<BucketType, XrootdBucket> _nestedBuckets;
    private final String _protocol;
    private final int _step;

    public NestedBucketBuffer(BucketType type,
                              String protocol,
                              int step,
                              Map<BucketType, XrootdBucket> nestedBuckets) {
        super(type);
        _protocol = protocol;
        _step = step;
        _nestedBuckets = nestedBuckets;
    }

    @Override
    public int dump(StringBuilder builder, String step, int number)
    {
        super.dump(builder, step, number);
        builder.append("//........................NESTED.........................\n");

        int i = number;

        Collection<XrootdBucket> buckets = _nestedBuckets.values();
        for (XrootdBucket bucket: buckets) {
            i = bucket.dump(builder, step, ++i);
        }
        builder.append("//\n");
        builder.append("//......................END NESTED.......................\n");

        return i;
    }

    /**
     * Deserialize the NestedBucketBuffer. Retrieve all the buckets and
     * recursively deserialize them. Also, retrieve the protocol information
     * and the step.
     *
     * @param type The type of the bucket (usually kXRS_main)
     * @param buffer The buffer containing the nested bucket buffer
     * @return Deserialized buffer
     * @throws IOException Deserialization fails
     */
    public static NestedBucketBuffer deserialize(BucketType type, ByteBuf buffer)
        throws IOException {

        /* kXRS_main can be a nested or an encrypted (raw) bucket. Try whether it
         * looks like a nested buffer and use raw deserialization if not */
        int readIndex = buffer.readerIndex();

        String protocol = AuthenticationRequest.deserializeProtocol(buffer);

        int step = AuthenticationRequest.deserializeStep(buffer);

        _logger.debug("NestedBucketBuffer protocol: {}, step {}", protocol, step);

        if (step < kXGC_certreq || step > kXGC_reserved) {
            /* reset buffer */
            buffer.readerIndex(readIndex);
            throw new IOException("Buffer contents are not a nested buffer!");
        }

        return new NestedBucketBuffer(type,
                protocol,
                step,
                AuthenticationRequest.deserializeBuckets(buffer));
    }

    /**
     *
     * @return the list of XrootdBuckets nested in this buffer
     */
    public Map<BucketType, XrootdBucket> getNestedBuckets() {
        return _nestedBuckets;
    }

    public int getStep() {
        return _step;
    }

    public String getProtocol() {
        return _protocol;
    }

    @Override
    /**
     * Serialize all the buckets in that buffer to an outputstream.
     *
     * @param out The ByteBuf to which this buffer will be serialized
     */
    public void serialize(ByteBuf out) {

        super.serialize(out);

        //
        // The nesting is a bit tricky. First, we skip 4 bytes (here we store later the
        // size of the nested serialized bucket buffer, which we don't know yet). Then, we
        // serialize the nested bucket buffer and store it in the bytebuffer. Then we jump
        // back to the previously marked position and store the size of the nested bucket buffer.
        //
        int start = out.writerIndex();
        out.writeInt(0); // placeholder value

        /* the protocol is be 0-padded to 4 bytes */
        byte[] protocol = _protocol.getBytes(US_ASCII);
        out.writeBytes(protocol);
        out.writeZero(4 - protocol.length);

        out.writeInt(_step);

        for (XrootdBucket bucket : _nestedBuckets.values()) {
            bucket.serialize(out);
        }

        out.writeInt(BucketType.kXRS_none.getCode());

        out.setInt(start, out.writerIndex() - start - 4);
    }

    @Override
    public int getSize() {
        int size = super.getSize() + 4 + 4 + 4;

        for (XrootdBucket bucket : _nestedBuckets.values()) {
            size += bucket.getSize();
        }

        return size + 4;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString()).append("begin nested BucketBuffer\n");

        for (XrootdBucket bucket : _nestedBuckets.values()) {
            sb.append(bucket.toString());
        }

        sb.append("end nested BucketBuffer\n");

        return sb.toString();
    }
}
