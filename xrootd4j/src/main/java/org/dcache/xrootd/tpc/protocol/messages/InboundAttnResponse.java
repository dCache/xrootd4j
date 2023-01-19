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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * <p>Server's prerogative to tell the client to do something.</p>
 *
 * <p>According to protocol, response has this structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>pad[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_attn</td></tr>
 *      <tr><td>kXR_int32</td><td>plen</td></tr>
 *      <tr><td>kXR_int32</td><td>actnum</td></tr>
 *      <tr><td>kXR_char</td><td>parms[plen-4]</td></tr>
 *  </table>
 */
public class InboundAttnResponse extends AbstractXrootdInboundResponse {
    private final int nextRequest;
    private final int actnum;

    /*
     * kXR_asyncab, kXR_asyncms
     */
    private String message;

    /*
     * kXR_asyncdi, kXR_asyncwt
     */
    private int wsec;
    private int msec;

    /*
     * kXR_asyncrd
     */
    private int port;
    private String redirectData;

    /*
     * kXR_asynresp
     */
    private int rStreamId;
    private int rStat;
    private byte[] rData;

    public InboundAttnResponse(ByteBuf buffer, int requestId)
    {
        super(buffer);
        nextRequest = requestId;
        int plen = buffer.getInt(4);
        actnum = buffer.getInt(8);

        if (plen > 4) {
            parseParameters(buffer, plen-4);
        }
    }

    public int getActnum()
    {
        return actnum;
    }

    public byte[] getrData()
    {
        return rData;
    }

    public String getMessage()
    {
        return message;
    }

    public int getMsec()
    {
        return msec;
    }

    public int getPort()
    {
        return port;
    }

    public String getRedirectData()
    {
        return redirectData;
    }

    @Override
    public int getRequestId()
    {
        return nextRequest;
    }

    public int getrStreamId()
    {
        return rStreamId;
    }

    public int getrStat()
    {
        return rStat;
    }


    public int getWsec()
    {
        return wsec;
    }

    private void parseParameters(ByteBuf buffer, int len)
    {
        switch(actnum) {
            case kXR_asyncab:
            case kXR_asyncms:
                message = buffer.toString(12, len, US_ASCII);
                break;
            case kXR_asyncdi:
                wsec = buffer.getInt(12);
                msec = buffer.getInt(16);
                break;
            case kXR_asyncrd:
                port = buffer.getInt(12);
                redirectData = buffer.toString(16, len-4, US_ASCII);
                break;
            case kXR_asynresp:
                rStreamId = buffer.getUnsignedShort(16);
                rStat = buffer.getUnsignedShort(18);
                int dlen = buffer.getInt(20);
                if (dlen > 0) {
                    rData = new byte[dlen];
                    buffer.getBytes(24, rData);
                }
                break;
            case kXR_asyncwt:
                wsec = buffer.getInt(12);
                break;
            default:
                break;
        }
    }
}
