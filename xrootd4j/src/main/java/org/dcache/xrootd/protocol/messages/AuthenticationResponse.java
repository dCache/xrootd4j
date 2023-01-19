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

import io.netty.buffer.ByteBuf;
import java.util.function.Consumer;

public class AuthenticationResponse extends AbstractXrootdResponse<AuthenticationRequest> {

    private final int length;
    private final Consumer<ByteBuf> serializer;

    /**
     * @param request the request this is a response to
     * @param status the status (usually kXR_authmore)
     * @param length of the data container to be serialized
     * @param serializer function responsible for writing to the buffer
     */
    public AuthenticationResponse(AuthenticationRequest request,
          int status,
          int length,
          Consumer<ByteBuf> serializer) {
        super(request, status);
        this.length = length;
        this.serializer = serializer;
    }

    @Override
    public int getDataLength() {
        return length;
    }

    @Override
    protected void getBytes(ByteBuf buffer) {
        serializer.accept(buffer);
    }
}
