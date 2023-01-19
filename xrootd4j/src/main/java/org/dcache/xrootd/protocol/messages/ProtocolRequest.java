/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;

import io.netty.buffer.ByteBuf;

/**
 * The kXR_protocol request has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_protocol</td></tr>
 *      <tr><td>kXR_int32</td><td>clientpv</td></tr>
 *      <tr><td>kXR_char</td><td>options</td></tr>
 *      <tr><td>kXR_char</td><td>expect</td></tr>
 *      <tr><td>kXR_char</td><td>reserved[10]</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *  </table>
 */
public class ProtocolRequest extends AbstractXrootdRequest {

    private final int version;
    private final int option;
    private final int expect;

    public ProtocolRequest(ByteBuf buffer) {
        super(buffer, kXR_protocol);
        version = buffer.getInt(4);
        option = buffer.getUnsignedByte(8);
        expect = buffer.getUnsignedByte(9);
    }

    public int getVersion() {
        return version;
    }

    public int getOption() {
        return option;
    }

    public int getExpect() {
        return expect;
    }
}
