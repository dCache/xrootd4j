/**
 * Copyright (C) 2011,2012 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.security;


import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.jboss.netty.buffer.ChannelBuffer;

/**
 * A bucket containing a header plus a number of bytes. This can be binary
 * data, but a raw-bucket can also represent encryptet buckets of another
 * type.
 *
 * @see XrootdBucket
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class RawBucket extends XrootdBucket
{
    private byte[] _data;

    public RawBucket(BucketType type, byte[] data) {
        super(type);
        _data = data;
    }

    public byte[] getContent() {
        return _data;
    }

    public static RawBucket deserialize(BucketType type, ChannelBuffer buffer) {

        byte [] tmp = new byte[buffer.readableBytes()];
        buffer.getBytes(0, tmp);
        RawBucket bucket = new RawBucket(type, tmp);

        return bucket;
    }

    @Override
    public void serialize(ChannelBuffer out) {
        super.serialize(out);
        out.writeInt(_data.length);
        out.writeBytes(_data);
    }

    @Override
    public int getSize() {
        return super.getSize() + 4 + _data.length;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(super.toString()+" hex dump:");

        for (int i = 0; i < _data.length;i++) {
            sb.append(" ").append(Integer.toHexString(_data[i]));
        }

        return sb.toString();
    }
}

