/**
 * Copyright (C) 2011-2016 dCache.org <support@dcache.org>
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

import com.google.common.base.Joiner;
import com.google.common.net.InetAddresses;
import io.netty.buffer.ByteBuf;

import java.net.InetSocketAddress;

import org.dcache.xrootd.protocol.XrootdProtocol;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class LocateResponse extends AbstractXrootdResponse<LocateRequest>
{
    private final String encoded;

    public LocateResponse(LocateRequest request, InfoElement... info)
    {
        this(request, encode(info));
    }

    private LocateResponse(LocateRequest request, String encoded)
    {
        super(request, XrootdProtocol.kXR_ok);
        this.encoded = encoded;
    }

    public static String encode(InfoElement[] info)
    {
        return Joiner.on(" ").join(info);
    }

    @Override
    public int getDataLength()
    {
        return encoded.length() + 1;
    }

    @Override
    protected void getBytes(ByteBuf buffer)
    {
        buffer.writeBytes(encoded.getBytes(US_ASCII));
        buffer.writeByte('\0');
    }

    public enum Node
    {
        MANAGER("M"), MANAGER_PENDING("m"), SERVER("S"), SERVER_PENDING("s");

        final String value;

        Node(String value)
        {
            this.value = value;
        }
    }

    public enum Access
    {
        READ("r"), WRITE("w");

        final String value;

        Access(String value)
        {
            this.value = value;
        }
    }

    public static class InfoElement
    {
        private final InetSocketAddress address;
        private final Node node;
        private final Access access;

        public InfoElement(InetSocketAddress address, Node node, Access access)
        {

            this.address = address;
            this.node = node;
            this.access = access;
        }

        @Override
        public String toString()
        {
            return node.value + access.value + InetAddresses.toUriString(address.getAddress()) + ":" + address.getPort();
        }
    }

    @Override
    public String toString()
    {
        return "locate-reponse[" + encoded + "]";
    }
}
