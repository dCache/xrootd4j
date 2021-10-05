/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.OPAQUE_DELIMITER;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Qcksum;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_Qxattr;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;

import com.google.common.base.CharMatcher;
import io.netty.buffer.ByteBuf;

/**
 *  Not every QueryRequest is a path request, so it
 *  does not extend that class.
 */
public class QueryRequest extends AbstractXrootdRequest {

    public static final CharMatcher NULL_CHARACTER = CharMatcher.is('\0');
    private final int reqcode;
    private final int fhandle;
    private final String args;
    private final String opaque;

    /*
     *  Can be altered by authorization plugins.
     */
    private String path;

    public QueryRequest(ByteBuf buffer) {
        super(buffer, kXR_query);
        reqcode = buffer.getUnsignedShort(4);
        fhandle = buffer.getInt(8);
        int alen = buffer.getInt(20);

        /* The protocol spec doesn't state anything about trailing zeros in args,
         * however the xrdfs client sends zero terminated paths.
         */
        args = NULL_CHARACTER.trimTrailingFrom(buffer.toString(24, alen, US_ASCII));

        switch (reqcode) {
            case kXR_Qcksum:
            case kXR_Qxattr:
                int pos = args.indexOf(OPAQUE_DELIMITER);
                if (pos > -1) {
                    path = args.substring(0, pos);
                    opaque = args.substring(pos + 1);
                } else {
                    path = args;
                    opaque = "";
                }
                break;
            default:
                path = null;
                opaque = null;
        }
    }

    public int getReqcode() {
        return reqcode;
    }

    public int getFhandle() {
        return fhandle;
    }

    public String getArgs() {
        return args;
    }

    public String getOpaque() {
        return opaque;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    @Override
    public String toString() {
        return String.format("query[%d,%d,%s]", reqcode, fhandle, args);
    }
}
