/**
 * Copyright (C) 2011-2022 dCache.org <support@dcache.org>
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import org.dcache.xrootd.util.ParseException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncdi;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_asyncrd;

/**
 * <p>Response from third-party source server.</p>
 *
 * <p>According to protocol, has the following packet structure:</p>
 *
 *  <table>
 *      <tr><td>kXR_char</td><td>streamid[2]</td></tr>
 *      <tr><td>kXR_unt16</td><td>kXR_redirect</td></tr>
 *      <tr><td>kXR_int32</td><td>dlen</td></tr>
 *      <tr><td>kXR_int32</td><td>port</td></tr>
 *      <tr><td>kXR_char</td><td>host[?[opaque][?token]][dlen-4] | url</td></tr>
 *  </table>
 *
 *  <p>Can also be constructed from a kXR_attn kXR_asyncrd or kXR_asyncdi
 *     response.</p>
 */
public class InboundRedirectResponse extends AbstractXrootdInboundResponse
{
    static final Logger LOGGER = LoggerFactory.getLogger(InboundRedirectResponse.class);
    private final int requestId;

    private int port;
    private String host;
    private String opaque;

    private String token;
    private URL    url;

    private int wsec;
    private int msec;

    public InboundRedirectResponse(InboundAttnResponse attnResponse)
                    throws ParseException
    {
        super(attnResponse.streamId, attnResponse.stat);
        this.requestId = attnResponse.getRequestId();
        switch(attnResponse.getActnum()) {
            case kXR_asyncdi:
                wsec = attnResponse.getWsec();
                msec = attnResponse.getMsec();
                break;
            case kXR_asyncrd:
                port = attnResponse.getPort();
                parseRedirectString(attnResponse.getRedirectData());
                // there is no opaque in this case
                token = opaque;
                opaque = null;
                wsec = 0;
                msec = 0;
                break;
        }
    }

    public InboundRedirectResponse(ByteBuf buffer, int requestId) throws
                    ParseException
    {
        super(buffer);
        this.requestId = requestId;
        int len = buffer.getInt(4);
        port = buffer.getInt(8);
        parseRedirectString(buffer.toString(12, len-4, StandardCharsets.US_ASCII));
        wsec = 0;
        msec = 0;
    }

    @Override
    public int getRequestId()
    {
        return requestId;
    }

    public String getHost()
    {
        return this.host;
    }

    public int getMsec()
    {
        return msec;
    }

    public String getOpaque()
    {
        return opaque;
    }

    public int getPort()
    {
        return this.port;
    }

    public String getToken()
    {
        return token;
    }

    public URL getUrl()
    {
        return url;
    }

    public int getWsec()
    {
        return wsec;
    }

    public boolean isReconnect()
    {
        return host == null && url == null;
    }

    @Override
    public String toString()
    {
        return String.format("[kXR_redirect (host %s)(port %d)"
                                             + "(opaque %s)(token %s)(url %s)]",
                             host, port, opaque, token, url);
    }

    private void parseRedirectString(String redirect)
                    throws ParseException
    {
        if (port == -1) {
            try {
                url = new URL(redirect);
            } catch (MalformedURLException e) {
                throw new ParseException("redirect : " + e.getMessage());
            }
        } else {
            int index = redirect.indexOf("?");
            if (index == -1) {
                host = redirect;
            } else {
                host = redirect.substring(0, index);
                redirect = redirect.substring(index);

                while (redirect.startsWith("?")) {
                    redirect = redirect.substring(1);
                }

                if (redirect.contains("=")) {
                    String[] parts = redirect.split("[?]");
                    opaque = parts[0];
                    if (parts.length > 1) {
                        token = parts[1];
                    }
                } else {
                    opaque = "";
                    token = redirect;
                }
            }
        }
    }
}
