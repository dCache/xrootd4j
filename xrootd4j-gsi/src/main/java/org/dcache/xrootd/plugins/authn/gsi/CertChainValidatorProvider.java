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

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.ValidatorParams;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 *  The intention here is to limit this class to one shared instance per
 *  domain.  Hence, the door will constuct it in connection with the
 *  authentication factory, the pool in connection with the client
 *  authentication factory.
 */
public class CertChainValidatorProvider
{
    private final String                 caCertificatePath;
    private final X509CertChainValidator certChainValidator;
    private final long                   trustAnchorRefreshInterval;

    public CertChainValidatorProvider(Properties properties)
                    throws FileNotFoundException
    {
        caCertificatePath = properties.getProperty("xrootd.gsi.ca.path");
        if (!new File(caCertificatePath).isDirectory()) {
            throw new FileNotFoundException(caCertificatePath +
                                            " is missing: GSI requires the X509 "
                                                            + "certificate "
                                                            + "authority CRLs");
        }

        trustAnchorRefreshInterval =
                        TimeUnit.valueOf(properties.getProperty("xrootd.gsi.ca.refresh.unit"))
                                .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.ca.refresh")));
        NamespaceCheckingMode namespaceMode =
                        NamespaceCheckingMode.valueOf(properties.getProperty("xrootd.gsi.ca.namespace-mode"));
        CrlCheckingMode crlCheckingMode =
                        CrlCheckingMode.valueOf(properties.getProperty("xrootd.gsi.ca.crl-mode"));
        OCSPCheckingMode ocspCheckingMode =
                        OCSPCheckingMode.valueOf(properties.getProperty("xrootd.gsi.ca.ocsp-mode"));
        ValidatorParams validatorParams = new ValidatorParams(
                        new RevocationParameters(crlCheckingMode, new OCSPParametes(ocspCheckingMode)), ProxySupport.ALLOW);
        certChainValidator = new OpensslCertChainValidator(caCertificatePath, false, namespaceMode,
                                                           trustAnchorRefreshInterval, validatorParams, false);
    }

    public X509CertChainValidator getCertChainValidator()
    {
        return certChainValidator;
    }
}
