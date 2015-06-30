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
package org.dcache.xrootd.security;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

import static java.nio.charset.StandardCharsets.US_ASCII;

/**
 * A bucket containing a header plus a String.
 *
 * @see XrootdBucket
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class StringBucket extends XrootdBucket {
  private final String _data;

    public StringBucket(BucketType type, String data) {
        super(type);
        _data = data;
    }

    public String getContent() {
        return _data;
    }

    public static StringBucket deserialize(BucketType type, ByteBuf buffer) {

        String s = buffer.toString(US_ASCII);
        return new StringBucket(type, s);
    }

    @Override
    public void serialize(ByteBuf out) {
        super.serialize(out);
        byte[] bytes = _data.getBytes(US_ASCII);
        out.writeInt(bytes.length);
        out.writeBytes(bytes);
    }

    @Override
    public int getSize() {
        return super.getSize() + 4 + _data.length();
    }

    @Override
    public String toString() {
        return super.toString() + _data;
    }

}
