/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import org.dcache.xrootd.protocol.XrootdProtocol;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secNone;
import static org.dcache.xrootd.security.XrootdSecurityProtocol.kXR_secOFrce;

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
 *
 *  <p>For the moment, the dCache server does not set any overrides,
 *     but merely communicates the security level (this determines
 *     which requests it expects to be preceded by a signed hash
 *     verification request).</p>
 *
 *  <p>Signing can be enforced if the protocol does not
 *     provide encryption by setting a dCache property.  In this
 *     case, secopt should be set to kXR_secOFrce</p>
 */
public class ProtocolResponse extends AbstractXrootdResponse<ProtocolRequest>
{
    private static final byte RESERVED = 0;
    private static final byte SECVER = 0;

    private final int flags;
    private final int seclvl;
    private final int secopt;

    public ProtocolResponse(ProtocolRequest request,
                            int flags,
                            int seclvl,
                            byte secopt)
    {
        super(request, XrootdProtocol.kXR_ok);
        this.flags = flags;
        this.seclvl = seclvl;
        this.secopt = secopt;
    }

    public int getFlags()
    {
        return flags;
    }

    public int getSeclvl()
    {
        return seclvl;
    }

    public boolean isForceSigningIfNoEncryption()
    {
        return secopt == kXR_secOFrce;
    }

    @Override
    public int getDataLength()
    {
        return seclvl == kXR_secNone ? 8 : 14;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        buffer.writeInt(XrootdProtocol.PROTOCOL_VERSION);
        buffer.writeInt(flags);
        if (getDataLength() == 14) {
            buffer.writeByte('S');
            buffer.writeByte(RESERVED);
            buffer.writeByte(SECVER);
            buffer.writeByte(secopt);
            buffer.writeByte(seclvl);
            // no overrides
            buffer.writeByte(0);
        }
    }

    @Override
    public String toString()
    {
        return String.format("protocol-response[%d][%d][%d]",
                             flags, seclvl, secopt);
    }
}
