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

import org.dcache.xrootd.security.XrootdSecurityProtocol.BucketType;

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
    private static final String BYTE_DUMP[] =
    {
        "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x    %s\n",
        "//  0x%02x                                                     %s\n",
        "//  0x%02x 0x%02x                                              %s\n",
        "//  0x%02x 0x%02x 0x%02x                                       %s\n",
        "//  0x%02x 0x%02x 0x%02x 0x%02x                                %s\n",
        "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x                         %s\n",
        "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x                  %s\n",
        "//  0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x           %s\n"
    };

    public static void dumpBytes(StringBuilder builder, byte[] data)
    {
        int i = 0;
        int D = data.length / 8;

        for (int d = 0; d < D; ++d) {
            builder.append(String.format(BYTE_DUMP[0],
                                         data[i], data[i+1], data[i+2],
                                         data[i+3], data[i+4], data[i+5],
                                         data[i+6], data[i+7],
                                         getAscii(data, i, 8)));
            i+=8;
        }

        switch (data.length % 8) {
            case 7:
                builder.append(String.format(BYTE_DUMP[7],
                                             data[i], data[i+1], data[i+2],
                                             data[i+3], data[i+4], data[i+5],
                                             data[i+6],
                                             getAscii(data, i, 7)));
                break;
            case 6:
                builder.append(String.format(BYTE_DUMP[6],
                                             data[i], data[i+1], data[i+2],
                                             data[i+3], data[i+4], data[i+5],
                                             getAscii(data, i, 6)));
                break;
            case 5:
                builder.append(String.format(BYTE_DUMP[5],
                                             data[i], data[i+1], data[i+2],
                                             data[i+3], data[i+4],
                                             getAscii(data, i, 5)));
                break;
            case 4:
                builder.append(String.format(BYTE_DUMP[4],
                                             data[i], data[i+1], data[i+2],
                                             data[i+3],
                                             getAscii(data, i, 4)));
                break;
            case 3:
                builder.append(String.format(BYTE_DUMP[3],
                                             data[i], data[i+1], data[i+2],
                                             getAscii(data, i, 3)));
                break;
            case 2:
                builder.append(String.format(BYTE_DUMP[2],
                                             data[i], data[i+1],
                                             getAscii(data, i, 2)));
                break;
            case 1:
                builder.append(String.format(BYTE_DUMP[1],
                                             data[i],
                                             getAscii(data, i, 1)));
                break;
        }
    }

    private static String getAscii(byte[] bytes, int from, int len)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; ++i) {
            byte b = bytes[from+i];
            if (32 < b && b < 127) {
                sb.append((char)b);
            } else {
                sb.append('.');
            }
        }
        return sb.toString();
    }

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
        dumpBytes(builder, _data);
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

