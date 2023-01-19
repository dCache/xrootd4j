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
package org.dcache.xrootd.protocol.messages;

import io.netty.buffer.ByteBuf;

import static org.dcache.xrootd.core.XrootdDecoder.readAscii;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_auth;
import static org.dcache.xrootd.protocol.messages.LoginResponse.AUTHN_PROTOCOL_TYPE_LEN;

/**
 *  The structure of the authentication request according to the protocol:
 *  <p/>
 *  kXR_char streamid[2] <br/>
 *  kXR_unt16 kXR_auth <br/>
 *  kXR_char reserved[12] <br/>
 *  kXR_char credtype[4] <br/>
 *  kXR_int32 credlen <br/>
 *  kXR_char cred[credlen]
 *  </p>
 *  Different security protocols will use the cred data differently.
 *  That functionality should not be here, but in the specific protocol's
 *  processing.
 */
public class AuthenticationRequest extends AbstractXrootdRequest
{
    private final String credType;
    private final int    credLen;
    private final ByteBuf credential;

    public AuthenticationRequest(ByteBuf buffer)
    {
        super(buffer, kXR_auth);

        /*
         * skip reserved bytes
         */
        buffer.readerIndex(16);

        credType = readAscii(buffer, AUTHN_PROTOCOL_TYPE_LEN);

        credLen = buffer.readInt();

        if (credLen == 0) {
            credential = null;
            return;
        }

        credential = buffer.alloc().ioBuffer(credLen);
        credential.writeBytes(buffer);
    }

    public String getCredType()
    {
        return credType;
    }

    public int getCredLen()
    {
        return credLen;
    }

    public ByteBuf getCredentialBuffer()
    {
        return credential;
    }

    public void releaseBuffer()
    {
       if (credential != null) {
           credential.release();
       }
    }
}
