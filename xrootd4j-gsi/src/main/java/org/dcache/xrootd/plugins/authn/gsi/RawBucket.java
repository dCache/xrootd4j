/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.plugins.authn.gsi;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

/**
 * A bucket containing a header plus a number of bytes. This can be binary
 * data, but a raw-bucket can also represent encryptet buckets of another
 * type.
 *
 * @see GSIBucket
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class RawBucket extends GSIBucket
{
    private final byte[] _data;

    public RawBucket(BucketType type, byte[] data) {
        super(type);
        _data = data;
    }

    /**
     *  This usually will be called only if trace is enabled.
     *
     *  We here imitate the XrootD XrdSutBuffer DUMP printout.
     */
    public int dump(StringBuilder builder, String step, int number)
    {
        super.dump(builder, step, number);
        builder.append("//\n");
        builder.append("//                  RAW BYTE CONTENTS                  //\n");
        builder.append("//\n");
        GSIBucketUtils.dumpBytes(builder, _data);
        return number;
    }

    public byte[] getContent() {
        return _data;
    }

    public static RawBucket deserialize(BucketType type, ByteBuf buffer) {

        byte [] tmp = new byte[buffer.readableBytes()];
        buffer.getBytes(0, tmp);
        return new RawBucket(type, tmp);
    }

    @Override
    public void serialize(ByteBuf out) {
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

        for (byte b : _data) {
            sb.append(" ").append(Integer.toHexString(b));
        }

        return sb.toString();
    }
}

