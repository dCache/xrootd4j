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

import static org.dcache.xrootd.security.XrootdSecurityProtocol.ZTN;

/**
 *  According to the xroot ztn protocol, the credential sent on the
 *  request method by the client has this structure:
 *  <p/>
 *  char id[4]; ztn\0<br/>  (we can skip storing this)
 *  char ver; <br/>
 *  char opr; ‘T’<br/>
 *  char reserved[2];   (currently for struct word alignment in C++)
 *  uint16_t tlen; Length of token in network byte order<br/>
 *  char token; Actual token ending with null byte<br/>
 */
public class ZTNCredential {

    public static final String PROTOCOL = ZTN;

    private int    version;
    private byte   opr;
    private int    length;
    private String token;

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public byte getOpr() {
        return opr;
    }

    public void setOpr(byte opr) {
        this.opr = opr;
    }

    public int getNullTerminatedTokenLength() {
        return length + 1;
    }

    public void setTokenLength(int length) {
        this.length = length;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public int getLength()
    {
        /*
         * PROTOCOL (4) + VERSION (1) + OPR (1) + RESERVED (2) + LEN (2)
         *          + token length + null byte
         */
        return 10 + getNullTerminatedTokenLength();
    }

    public String toString()
    {
        return String.format("(ZTN credential [id %s] [version %s][opc %s]"
                                             + "[token len %s][token %s]"
                                             + "[cred len %s])",
                             PROTOCOL + "\\0",
                             version,
                             opr,
                             getNullTerminatedTokenLength(),
                             token,
                             getLength());
    }
}
