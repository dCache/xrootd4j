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
package org.dcache.xrootd.plugins.authn.ztn;

import com.google.common.base.Strings;
import io.netty.buffer.ByteBuf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.security.TokenValidator;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.dcache.xrootd.core.XrootdDecoder.readAscii;
import static org.dcache.xrootd.core.XrootdEncoder.writeZeroPad;
import static org.dcache.xrootd.plugins.authn.ztn.ZTNCredential.PROTOCOL;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgInvalid;
import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgMissing;
import static org.dcache.xrootd.protocol.messages.LoginResponse.AUTHN_PROTOCOL_TYPE_LEN;

/**
 *  Simple to- and from- ByteBuf methods.
 */
public class ZTNCredentialUtils
{
    private static final Logger LOGGER
                    = LoggerFactory.getLogger(ZTNCredentialUtils.class);

    public static ZTNCredential deserialize(ByteBuf buffer)
                    throws XrootdException {
        ZTNCredential credential = new ZTNCredential();
        String protocol = readAscii(buffer, AUTHN_PROTOCOL_TYPE_LEN);

        if (!PROTOCOL.equals(protocol)) {
            String error = "protocol " + protocol + "  does not match "
                            + PROTOCOL + "; this is a bug.";
            throw new IllegalArgumentException(error);
        }

        credential.setVersion(buffer.readByte());
        credential.setOpr(buffer.readByte());

        /*
         *  Reserved.  Currently put here for the purpose of word-boundary
         *  alignment in the C++ server.
         */
        buffer.readBytes(2);

        int len = buffer.readShort();
        if (len <= 1) {
            throw new XrootdException(kXR_ArgInvalid, "illegal token length");
        }

        String token = Strings.emptyToNull(readAscii(buffer,len));
        if (token == null) {
            throw new XrootdException(kXR_ArgMissing, "no token");
        }

        token = TokenValidator.stripOffPrefix(token);

        /*
         *  Store the credential token stripped of possible prefix.
         */
        credential.setTokenLength(token.length());
        credential.setToken(token);

        LOGGER.debug("deserialize, got credential {}.", credential);
        return credential;
    }

    public static void writeBytes(ByteBuf buffer, ZTNCredential credential)
    {
        writeZeroPad(PROTOCOL, buffer, AUTHN_PROTOCOL_TYPE_LEN);
        buffer.writeByte(credential.getVersion());
        buffer.writeByte(credential.getOpr());
        buffer.writeZero(2); // see above
        buffer.writeShort(credential.getNullTerminatedTokenLength());
        buffer.writeBytes(credential.getToken().getBytes(US_ASCII));
        buffer.writeByte('\0');
    }
}
