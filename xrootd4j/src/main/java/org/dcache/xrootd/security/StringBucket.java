/**
 * Copyright (C) 2011-2013 dCache.org <support@dcache.org>
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

import java.nio.charset.Charset;

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;
import org.jboss.netty.buffer.ChannelBuffer;

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
  private String _data;

    public StringBucket(BucketType type, String data) {
        super(type);
        _data = data;
    }

    public String getContent() {
        return _data;
    }

    public static StringBucket deserialize(BucketType type, ChannelBuffer buffer) {

        String s = buffer.toString(Charset.forName("ASCII"));
        StringBucket bucket = new StringBucket(type, s);
        return bucket;
    }

    @Override
    public void serialize(ChannelBuffer out) {
        super.serialize(out);
        out.writeInt(_data.length());
        out.writeBytes(_data.getBytes());
    }

    @Override
    public int getSize() {
        return super.getSize() + 4 + _data.getBytes().length;
    }

    @Override
    public String toString() {
        return super.toString() + _data;
    }

}
