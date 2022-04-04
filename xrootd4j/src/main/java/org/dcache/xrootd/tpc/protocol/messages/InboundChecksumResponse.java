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
package org.dcache.xrootd.tpc.protocol.messages;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_query;

import io.netty.buffer.ByteBuf;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.dcache.xrootd.util.ParseException;

/**
 * Response from third-party source server.</p>
 *
 * According to protocol, has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>0</td></tr>
 *      <tr><td>kXR_int32</td><td>ilen</td></tr>
 *      <tr><td>kXR_char</td><td>info[ilen]</td></tr>
 *  </table>
 */
public class InboundChecksumResponse extends AbstractXrootdInboundResponse {

    private Map<String, String> checksums = new HashMap<>();

    public InboundChecksumResponse(ByteBuf buffer)
          throws ParseException {
        super(buffer);
        int len = buffer.getInt(4);
        if (len > 0) {
            parse(buffer.toString(8, len, StandardCharsets.US_ASCII));
        }
    }

    public Map<String, String> getChecksums() {
        return checksums;
    }

    @Override
    public int getRequestId() {
        return kXR_query;
    }

    private void parse(String info) throws ParseException {
        String[] parts = info.split("\\s+");
        if (parts.length % 2 != 0) {
            throw new ParseException("malformed checksum info: '" + info + "'");
        }
        for (int i = 0; i < parts.length; i += 2) {
            checksums.put(parts[i], parts[i + 1]);
        }
    }
}
