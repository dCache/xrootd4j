/**
 * Copyright (C) 2011-2020 dCache.org <support@dcache.org>
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

import com.google.common.base.Strings;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 *  Loads and stores credentials based on certificate .pems on the local
 *  disk.  Shared between all instances of the GSICredentialManager
 *  to optimize/cache the refreshed credentials and caCerts.
 */
public class CredentialLoader
{
    private static final Logger LOGGER
                    = LoggerFactory.getLogger(CredentialLoader.class);

    /*
     *  Local credentials and CA certs.
     */
    private final X509CertChainValidator certChainValidator;
    private final String                 hostCertificatePath;
    private final String                 hostKeyPath;
    private final long                   hostCertRefreshInterval;
    private final boolean                verifyHostCertificate;
    private final String                 clientCertificatePath;
    private final String                 clientKeyPath;
    private final long                   proxyRefreshInterval;
    private final boolean                verifyClientCertificate;
    private final boolean                delegationOnly;
    private final String                 proxyPath;

    private long   hostCertRefreshTimestamp = 0;
    private long   proxyRefreshTimestamp    = 0;

    private PEMCredential  hostCredential;
    private PEMCredential  clientCredential;
    private X509Credential proxy;

    public CredentialLoader(Properties properties,
                            X509CertChainValidator certChainValidator)
    {
        this.certChainValidator = certChainValidator;

        /**
         *  Local host
         */
        hostKeyPath = properties.getProperty("xrootd.gsi.hostcert.key");
        hostCertificatePath = properties.getProperty("xrootd.gsi.hostcert.cert");
        hostCertRefreshInterval =
                        TimeUnit.valueOf(properties.getProperty("xrootd.gsi.hostcert.refresh.unit"))
                                .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.hostcert.refresh")));
        verifyHostCertificate =
                        Boolean.parseBoolean(properties.getProperty("xrootd.gsi.hostcert.verify"));

        /**
         *  If dCache third-party copy properties are locally defined
         */
        clientKeyPath = properties.getProperty("xrootd.gsi.tpc.cred.key");
        clientCertificatePath = properties.getProperty("xrootd.gsi.tpc.cred.cert");
        proxyRefreshInterval =
                        TimeUnit.valueOf(properties.getProperty("xrootd.gsi.tpc.cred.refresh.unit"))
                                .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.tpc.cred.refresh")));
        verifyClientCertificate =
                        Boolean.parseBoolean(properties.getProperty("xrootd.gsi.tpc.cred.verify"));
        proxyPath = properties.getProperty("xrootd.gsi.tpc.proxy.path");
        delegationOnly = Boolean.parseBoolean(properties.getProperty("xrootd.gsi.tpc.delegation-only"));
    }

    public PEMCredential getHostCredential()
    {
        loadServerCredentials();
        return hostCredential;
    }

    public X509Credential getProxy() {
        loadClientCredentials();
        return proxy;
    }

    public boolean isDelegationOnly()
    {
        return delegationOnly;
    }

    /**
     * Client-side, will attempt to read in a prefetched proxy from a given
     * path, or to construct one from the local cert and key, if refresh
     * has expired.
     */
    private synchronized void loadClientCredentials()
    {
        try {
            if (shouldRefreshClientProxyCredential()) {
                LOGGER.info("Refreshing proxy credential. Current refresh interval: {} ms",
                            proxyRefreshInterval);

                if (!Strings.isNullOrEmpty(proxyPath)) {
                    clientCredential = new PEMCredential(proxyPath, (char[]) null);
                    proxy = clientCredential;
                } else {
                    clientCredential = new PEMCredential(clientKeyPath,
                                                         clientCertificatePath,
                                                         null);
                    if (verifyClientCertificate) {
                        LOGGER.info("Verifying client certificate");
                        certChainValidator.validate(clientCredential.getCertificateChain());
                    }

                    /*
                     *  SLAC server requires an actual proxy, that is,
                     *  cert chain length > 1.
                     */
                    try {
                        ProxyCertificateOptions options
                                        = new ProxyCertificateOptions(
                                        clientCredential.getCertificateChain());
                        ProxyCertificate proxyCert = ProxyGenerator.generate(
                                        options,
                                        clientCredential.getKey());
                        proxy = proxyCert.getCredential();
                    } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
                        throw new CertificateException(
                                        "could not generate host proxy credential.",
                                        e);
                    }
                }

                proxyRefreshTimestamp = System.currentTimeMillis();
            }
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Could not load client certificates/key due to security error; {}: {}.",
                         getCredentialValues(), gssex.toString());
        } catch (IOException ioex) {
            LOGGER.error("Could not read client certificates/key from file-system; {}: {}.",
                         getCredentialValues(), ioex.toString());

        }
    }

    /**
     * Server-side, will attempt to generate host credential from
     * local cert and key, if refresh has expired.
     */
    private synchronized void loadServerCredentials()
    {
        try {
            if (shouldReloadServerCredentials()) {
                LOGGER.info("Loading server certificates. Current refresh interval: {} ms",
                            hostCertRefreshInterval);
                PEMCredential credential = new PEMCredential(hostKeyPath,
                                                             hostCertificatePath,
                                                             null);
                if (verifyHostCertificate) {
                    LOGGER.info("Verifying host certificate");
                    certChainValidator.validate(
                                    credential.getCertificateChain());
                }
                hostCredential = credential;
                hostCertRefreshTimestamp = System.currentTimeMillis();
            }
        } catch (GeneralSecurityException gssex) {
            LOGGER.error("Could not load server certificates/key due to security error; {}: {}.",
                         getCredentialValues(), gssex.toString());
        } catch (IOException ioex) {
            LOGGER.error("Could not read server certificates/key from file-system; {}: {}.",
                         getCredentialValues(), ioex.toString());

        }
    }

    private String getCredentialValues()
    {
        return "client cert path: " + clientCertificatePath
                        + ", client key path: " + clientKeyPath
                        + ", proxy path: " + proxyPath;
    }

    private boolean shouldReloadServerCredentials()
    {
        long timeSinceLastServerRefresh = (System.currentTimeMillis() - hostCertRefreshTimestamp);
        LOGGER.info("Time since last server cert refresh {}", timeSinceLastServerRefresh);
        return hostCredential == null || timeSinceLastServerRefresh >= hostCertRefreshInterval;
    }

    private boolean shouldRefreshClientProxyCredential()
    {
        long timeSinceLastClientRefresh = (System.currentTimeMillis() - proxyRefreshTimestamp);
        LOGGER.info("Time since last client cert refresh {}", timeSinceLastClientRefresh);
        return proxy == null || timeSinceLastClientRefresh >= proxyRefreshInterval;
    }
}
