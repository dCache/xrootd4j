/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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

import java.io.IOException;

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

/**
 * An XrootdBucket is a serialized datatype (string, uint, binary, list) with
 * an int32 header describing its contents. The headers are well defined and
 * for each header it is known which datatype to expect.
 *
 *
 * @author radicke
 * @author tzangerl
 *
 */
public abstract class XrootdBucket
{

    protected final BucketType _type;

    public XrootdBucket(BucketType type) {
        _type = type;
    }

    public BucketType getType() {
        return _type;
    }

    public void serialize(ByteBuf out) {
        out.writeInt(_type.getCode());
    }

    /**
     * Deserialize an XrootdBucket. Depending on the BucketType, return an
     * XrootdBucket of a specific subtype.
     *
     * The only type where the returned type is not a-priori known is
     * kXRS_main, which can be encrypted. If it is encrypted, a binary (raw)
     * bucket is returned, if it is not encyrpted, a list of contained
     * buckets (nestedBuffer) is returned.
     *
     * @param type The type of the bucket that should be deserialized
     * @param buffer The buffer containing the buckets
     * @return The deserialized bucket
     */
    public static XrootdBucket deserialize(BucketType type, ByteBuf buffer)
        throws IOException {

        XrootdBucket bucket;

        switch (type) {

            case kXRS_main:

                try {

                    bucket = NestedBucketBuffer.deserialize(type, buffer);

                } catch (IOException e) {
                    // ok the nested buffer seems to be encrypted
                    // just store the binary data for now, it will be decrypted later on
                    bucket = RawBucket.deserialize(type, buffer);
                }

                break;

            case kXRS_cryptomod:    // fall through
            case kXRS_issuer_hash:  // fall through
            case kXRS_rtag:         // fall through
            case kXRS_puk:          // fall through
            case kXRS_cipher_alg:   // fall through
            case kXRS_x509:         // fall through
            case kXRS_md_alg:

                bucket = StringBucket.deserialize(type, buffer);
                break;

            case kXRS_version:      // fall through
            case kXRS_clnt_opts:

                bucket = UnsignedIntBucket.deserialize(type, buffer);
                break;

            default:

                bucket = RawBucket.deserialize(type, buffer);
                break;
        }

        return bucket;
    }

    /**
     * @return Length of the serialized bucket (in bytes)
     */
    public int getSize() {
        return 4;
    }

    @Override
    public String toString() {
        return "bucket type: "+ _type +"\n";
    }
}

