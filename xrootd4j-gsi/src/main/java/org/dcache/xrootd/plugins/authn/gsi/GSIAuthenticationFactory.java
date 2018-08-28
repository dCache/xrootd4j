/**
 * Copyright (C) 2011-2018 dCache.org <support@dcache.org>
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

import eu.emi.security.authn.x509.impl.PEMCredential;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.plugins.AuthenticationFactory;
import org.dcache.xrootd.plugins.AuthenticationHandler;
import org.dcache.xrootd.plugins.InvalidHandlerConfigurationException;

/**
 * Authentication factory that returns GSI security handlers. Initiates the
 * server-side certificate objects (host certificate, host key, trusted
 * certificates and CRLs) needed for the handler to perform its tasks.
 *
 * Thus the certificates and trust anchors can be cached for a configurable
 * time period. The configuration option controlling this caching is the
 * same as the one used in the SRM door.
 *
 * @author tzangerl
 *
 */
public class GSIAuthenticationFactory extends BaseGSIAuthenticationFactory
                implements AuthenticationFactory
{
    private final String hostCertificatePath;
    private final String hostKeyPath;
    private final long hostCertRefreshInterval;
    private final boolean verifyHostCertificate;

    private PEMCredential hostCredential;
    private long hostCertRefreshTimestamp = 0;

    public GSIAuthenticationFactory(Properties properties)
    {
        super(properties);
        hostKeyPath = properties.getProperty("xrootd.gsi.hostcert.key");
        hostCertificatePath = properties.getProperty("xrootd.gsi.hostcert.cert");
        hostCertRefreshInterval =
                        TimeUnit.valueOf(properties.getProperty("xrootd.gsi.hostcert.refresh.unit"))
                                .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.hostcert.refresh")));
        verifyHostCertificate =
                        Boolean.parseBoolean(properties.getProperty("xrootd.gsi.hostcert.verify"));
    }

    @Override
    public AuthenticationHandler createHandler()
        throws InvalidHandlerConfigurationException
    {
        try {
            loadServerCredentials();
        } catch (GeneralSecurityException gssex) {
            String msg = "Could not load certificates/key due to security error";
            throw new InvalidHandlerConfigurationException(msg, gssex);
        } catch (IOException ioex) {
            String msg = "Could not read certificates/key from file-system";
            throw new InvalidHandlerConfigurationException(msg, ioex);
        }

        return new GSIAuthenticationHandler(hostCredential, validator, caCertificatePath);
    }

    private synchronized void loadServerCredentials()
                    throws CertificateException, KeyStoreException, IOException
    {
        if (shouldReloadServerCredentials()) {
            LOGGER.info("Loading server certificates. Current refresh interval: {} ms",
                        hostCertRefreshInterval);
            PEMCredential credential = new PEMCredential(hostKeyPath, hostCertificatePath, null);
            if (verifyHostCertificate) {
                LOGGER.info("Verifying host certificate");
                validator.validate(credential.getCertificateChain());
            }
            hostCredential = credential;
            hostCertRefreshTimestamp = System.currentTimeMillis();
        }
    }

    private boolean shouldReloadServerCredentials()
    {
        long timeSinceLastServerRefresh = (System.currentTimeMillis() - hostCertRefreshTimestamp);
        LOGGER.info("Time since last server cert refresh {}", timeSinceLastServerRefresh);
        return hostCredential == null || timeSinceLastServerRefresh >= hostCertRefreshInterval;
    }
}
