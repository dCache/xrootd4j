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
package org.dcache.xrootd.plugins.authn.gsi;

import java.io.Serializable;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SerializableX509Credential implements Serializable
{
    private static final long serialVersionUID = -3090177688719198722L;
    private final X509Certificate[] certChain;
    private final PrivateKey        privateKey;

    public SerializableX509Credential(X509Certificate[] certChain,
                                      PrivateKey privateKey)
    {
        this.certChain = certChain;
        this.privateKey = privateKey;
    }

    public X509Certificate[] getCertChain()
    {
        return certChain;
    }

    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }
}
