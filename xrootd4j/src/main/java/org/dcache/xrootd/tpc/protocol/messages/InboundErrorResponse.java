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
package org.dcache.xrootd.tpc.protocol.messages;

import static java.nio.charset.StandardCharsets.US_ASCII;

import io.netty.buffer.ByteBuf;

/**
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>stat</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *      <tr><td>kXR_int32</td><td>errnum</td></tr>
 *      <tr><td>kXR_char</td><td>errmsg[dlen-4]</td></tr>
 *  </table>
 */
public class InboundErrorResponse extends AbstractXrootdInboundResponse {

    private int error;
    private String errorMessage;

    public InboundErrorResponse(ByteBuf buffer) {
        super(buffer);
        int len = buffer.getInt(4);
        error = buffer.getInt(8);
        errorMessage = buffer.toString(12, len - 4, US_ASCII);
    }

    public int getError() {
        return error;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    @Override
    public int getRequestId() {
        return 0;
    }
}
