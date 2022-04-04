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
package org.dcache.xrootd.security;

import io.netty.buffer.ByteBuf;

import java.nio.ByteBuffer;

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static org.dcache.xrootd.security.RawBucket.dumpBytes;

/**
 * A bucket containing a header plus an unsigned integer.
 *
 * @see XrootdBucket
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class UnsignedIntBucket extends XrootdBucket
{
   private final int _data;

    public UnsignedIntBucket(BucketType type, int data) {
        super(type);
        _data = data;
    }

    @Override
    public int dump(StringBuilder builder, String step, int number)
    {
        super.dump(builder, step, number);
        builder.append("//\n");
        builder.append("//                UNSIGNED INT CONTENTS\n");
        builder.append("//\n");
        builder.append("//  decimal: ").append(_data).append("\n");
        builder.append("//\n");
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(_data);
        byte[] result = b.array();
        dumpBytes(builder, result);
        return number;
    }

    public int getContent() {
        return _data;
    }

    public static UnsignedIntBucket deserialize(BucketType type, ByteBuf buffer) {

        return new UnsignedIntBucket(type, buffer.getInt(0));
    }

    @Override
    public void serialize(ByteBuf out) {
        super.serialize(out);
        out.writeInt(4);
        out.writeInt(_data);
    }

    @Override
    public int getSize() {
        return super.getSize() + 8;
    }

    @Override
    public String toString() {
        return super.toString() + " decimal int: "+ _data;
    }
}
