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
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j. If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.protocol.messages;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattrDel;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattrGet;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattrList;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattrSet;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattr_aData;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_fattr_isNew;

import com.google.common.base.Preconditions;
import io.netty.buffer.ByteBuf;
import java.util.Arrays;

/**
 * Not every QueryRequest is a path request, so it does not extend that class.
 */
public class FattrRequest extends AbstractXrootdRequest {

    private final int fhandle;
    private final int subcode;
    private final int nattr;
    private final int options;
    private final String[] nvec;

    /*
     * Can be altered by authorization plugins.
     */
    private String path;


    public FattrRequest(ByteBuf buffer) {
        super(buffer, kXR_fattr);
        fhandle = buffer.getInt(4);
        subcode = buffer.getUnsignedByte(8);
        int alen = buffer.getInt(20);

        ByteBuf bb = buffer.slice(24, alen);

        int pos = 0;
        int len = bb.bytesBefore(pos, alen, (byte) 0);
        path = bb.toString(pos, len, US_ASCII);
        pos += len + 1;

        if (isList()) {
            nattr = 0;
            nvec = new String[0];
        } else {
            nattr = buffer.getUnsignedByte(9);
            nvec = new String[nattr];
            for (int i = 0; i < nattr; ++i) {
                pos += 2;
                len = bb.bytesBefore(pos, alen - pos, (byte) 0);
                nvec[i] = bb.toString(pos, len, US_ASCII);
                pos += len;
            }
        }
        Preconditions.checkState(nattr == nvec.length);
        options = buffer.getUnsignedByte(10);
    }

    public int getCode() {
        return subcode;
    }

    public int getFhandle() {
        return fhandle;
    }

    public boolean isNew() {
        return (options & kXR_fattr_isNew) == kXR_fattr_isNew;
    }

    public boolean aData() {
        return (options & kXR_fattr_aData) == kXR_fattr_aData;
    }

    public boolean isList() {
        return subcode == kXR_fattrList;
    }

    public boolean isGet() {
        return subcode == kXR_fattrGet;
    }

    public boolean isSet() {
        return subcode == kXR_fattrSet;
    }

    public boolean isDel() {
        return subcode == kXR_fattrDel;
    }

    public String getPath() {
        return path;
    }

    public String[] getNames() {
        return nvec;
    }

    public int getNattr() {
        return nattr;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public String toString() {
        return String.format("fattr[%d,%d,%d,%d,%s]", subcode, fhandle, nattr, options,
              Arrays.asList(nvec).toString());
    }
}
