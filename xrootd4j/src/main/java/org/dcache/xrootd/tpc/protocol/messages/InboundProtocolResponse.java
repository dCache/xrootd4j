/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.tpc.protocol.messages;

import io.netty.buffer.ByteBuf;

import java.util.HashMap;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.SigningPolicy;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_protocol;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secNone;

/**
 * <p>According to protocol, has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>0</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *      <tr><td>kXR_int32</td><td>pval</td></tr>
 *      <tr><td>kXR_int32</td><td>flags</td></tr>
 *      <tr><td>kXR_char</td><td>'S'</td></tr>
 *      <tr><td>kXR_char</td><td>rsvd</td></tr>
 *      <tr><td>kXR_char</td><td>secver</td></tr>
 *      <tr><td>kXR_char</td><td>secopt</td></tr>
 *      <tr><td>kXR_char</td><td>seclvl</td></tr>
 *      <tr><td>kXR_char</td><td>secvsz</td></tr>
 *      <tr><td>{kXR_char,kXR_char}</td><td>[reqidx,reqlvl]</td></tr>
 *  </table>
 *
 *  <p>dlen is either 8, if no security requirements are returned,
 *     or 14 + secvsz*2.</p>
 */
public class InboundProtocolResponse extends AbstractXrootdInboundResponse
{
    private SigningPolicy signingPolicy;
    private int pval;
    private int flags;

    public InboundProtocolResponse(ByteBuf buffer) throws XrootdException
    {
        super(buffer);

        int len = buffer.getInt(4);
        pval = buffer.getInt(8);
        flags = buffer.getInt(12);
        setSigningPolicy(len, buffer);
    }

    @Override
    public int getRequestId()
    {
        return kXR_protocol;
    }

    public SigningPolicy getSigningPolicy()
    {
        return signingPolicy;
    }

    public int getFlags()
    {
        return flags;
    }

    public int getPval()
    {
        return pval;
    }

    private void setSigningPolicy(int len, ByteBuf buffer)
    {
        byte secopt = (byte)0;
        int seclvl = kXR_secNone;
        Map<Integer, Integer> overrides = new HashMap<>();

        if (len >= 14) {
            secopt = buffer.getByte(19);
            seclvl = buffer.getByte(20);
            int secvsz = buffer.getByte(21);
            int index = 22;
            for (int i = 0; i < secvsz; ++i) {
                overrides.put((int) buffer.getByte(index++),
                              (int) buffer.getByte(index++));
            }
        }

        signingPolicy = new SigningPolicy(seclvl, secopt, overrides);
    }
}
