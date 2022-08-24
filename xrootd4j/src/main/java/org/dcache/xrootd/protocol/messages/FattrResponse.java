/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
 *
 * This file is part of xrootd4j.
 *
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ok;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.util.ReferenceCounted;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class FattrResponse extends AbstractXrootdResponse<FattrRequest>
      implements ReferenceCounted {

    public static class NamedValue {

        private final String name;
        private final short code;
        private final byte[] value;

        public NamedValue(String name, short code, byte[] value) {
            this.name = name;
            this.code = code;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public byte[] getValue() {
            return value;
        }

        public short getCode() {
            return code;
        }
    }


    public static class Builder {

        private final FattrRequest req;
        private final List<NamedValue> attr = new ArrayList<>();

        private Builder(FattrRequest req) {
            this.req = req;
        }

        public Builder addName(String name) {
            return addName(name, kXR_ok);
        }

        public Builder addName(String name, int code) {
            return addNamedValue(name, code, new byte[0]);
        }

        public Builder addNamedValue(String name, int code, String value) {
            return addNamedValue(name, code,
                  value == null ? new byte[0] : value.getBytes(StandardCharsets.US_ASCII));
        }

        public Builder addNamedValue(String name, int code, byte[] value) {
            attr.add(new NamedValue(name, (short) code, value));
            return this;
        }

        public FattrResponse build() {
            return new FattrResponse(req, attr);
        }
    }

    public static Builder builder(FattrRequest request) {
        return new Builder(request);
    }


    private final ByteBuf bb = Unpooled.buffer();


    public FattrResponse(FattrRequest request, List<NamedValue> attr) {
        super(request, kXR_ok);

        if (request.isList()) {
            for (NamedValue nv : attr) {
                bb.writeCharSequence(nv.getName(), StandardCharsets.US_ASCII);
                bb.writeByte(0);
                if (request.aData()) {
                    bb.writeInt(nv.getValue().length);
                    bb.writeBytes(nv.getValue());
                }
            }
        } else {
            int nerrs = (int) attr.stream().filter(nv -> nv.getCode() != 0).count();
            bb.writeByte(nerrs);
            bb.writeByte(request.getNattr());

            for (NamedValue nv : attr) {
                bb.writeShort(nv.getCode());
                bb.writeCharSequence(nv.getName(), StandardCharsets.US_ASCII);
                bb.writeByte(0);
            }
            if (request.isGet()) {
                for (NamedValue nv : attr) {
                    bb.writeInt(nv.getValue().length);
                    bb.writeBytes(nv.getValue());
                }
            }
        }
    }


    @Override
    public int getDataLength() {
        return bb.writerIndex();
    }


    @Override
    protected void getBytes(ByteBuf buffer) {
        buffer.writeBytes(bb);
    }


    @Override
    public int refCnt() {
        return bb.refCnt();
    }


    @Override
    public FattrResponse retain() {
        bb.retain();
        return this;
    }


    @Override
    public FattrResponse retain(int increment) {
        bb.retain(increment);
        return this;
    }


    @Override
    public FattrResponse touch() {
        bb.touch();
        return this;
    }


    @Override
    public FattrResponse touch(Object hint) {
        bb.touch(hint);
        return this;
    }


    @Override
    public boolean release() {
        return bb.release();
    }


    @Override
    public boolean release(int decrement) {
        return bb.release(decrement);
    }
}
