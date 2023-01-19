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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_prefname;

import com.google.common.net.InetAddresses;
import io.netty.buffer.ByteBuf;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Iterator;
import org.dcache.xrootd.protocol.XrootdProtocol;

public class LocateResponse extends AbstractXrootdResponse<LocateRequest> {

    private final String encoded;

    public LocateResponse(LocateRequest request, InfoElement... info) {
        this(request, encode(request, info));
    }

    private LocateResponse(LocateRequest request, String encoded) {
        super(request, XrootdProtocol.kXR_ok);
        this.encoded = encoded;
    }

    @Override
    public int getDataLength() {
        return encoded.length() + 1;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        buffer.writeBytes(encoded.getBytes(US_ASCII));
        buffer.writeByte('\0');
    }

    public enum Node {
        MANAGER("M"), MANAGER_PENDING("m"), SERVER("S"), SERVER_PENDING("s");

        final String value;

        Node(String value) {
            this.value = value;
        }
    }

    public enum Access {
        READ("r"), WRITE("w");

        final String value;

        Access(String value) {
            this.value = value;
        }
    }

    public static class InfoElement {

        private final InetSocketAddress address;
        private final Node node;
        private final Access access;

        public InfoElement(InetSocketAddress address, Node node, Access access) {

            this.address = address;
            this.node = node;
            this.access = access;
        }

        @Override
        public String toString() {
            return node.value + access.value + InetAddresses.toUriString(address.getAddress()) + ":"
                  + address.getPort();
        }

        void append(StringBuilder builder, boolean preferName) {
            builder.append(node.value).append(access.value).append(
                        preferName ? address.getHostName()
                              : InetAddresses.toUriString(address.getAddress()))
                  .append(":").append(address.getPort());
        }
    }

    @Override
    public String toString() {
        return "locate-reponse[" + encoded + "]";
    }

    private static String encode(LocateRequest request, InfoElement[] info) {
        boolean prefName = (request.getOptions() & kXR_prefname) == kXR_prefname;
        StringBuilder builder = new StringBuilder();
        Iterator<InfoElement> it = Arrays.stream(info).iterator();
        if (it.hasNext()) {
            it.next().append(builder, prefName);
        }

        while (it.hasNext()) {
            builder.append(" ");
            it.next().append(builder, prefName);
        }

        return builder.toString();
    }
}
