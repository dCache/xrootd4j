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

import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyCertificate;
import eu.emi.security.authn.x509.proxy.ProxyCertificateOptions;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import io.netty.channel.ChannelHandler;

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.dcache.xrootd.plugins.ChannelHandlerFactory;

import static org.dcache.xrootd.plugins.authn.gsi.BaseGSIAuthenticationHandler.PROTOCOL;

/**
 * <p>Authentication factory that returns GSI security handlers to add to the
 *    third-party client channel pipeline.</p>
 *
 * <p>In addition to loading host cert, key and crl validators, generates
 *     a proxy credential from the host cert and key, as required by
 *     the standard (SLAC) implementation of the server.</p>
 */
public class GSIClientAuthenticationFactory extends BaseGSIAuthenticationFactory
                implements ChannelHandlerFactory {
    private final String  clientCertificatePath;
    private final String  clientKeyPath;
    private final long    proxyRefreshInterval;
    private final boolean verifyClientCertificate;

    private PEMCredential clientCredential;
    private long          proxyRefreshTimestamp = 0;

    private String         clientCredIssuerHashes;
    private String         proxyPath;
    private X509Credential proxy;

    public GSIClientAuthenticationFactory(Properties properties)
    {
        super(properties);
        clientKeyPath = properties.getProperty("xrootd.gsi.tpc.cred.key");
        clientCertificatePath = properties.getProperty("xrootd.gsi.tpc.cred.cert");
        proxyRefreshInterval =
                        TimeUnit.valueOf(properties.getProperty("xrootd.gsi.tpc.cred.refresh.unit"))
                                .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.tpc.cred.refresh")));
        verifyClientCertificate =
                        Boolean.parseBoolean(properties.getProperty("xrootd.gsi.tpc.cred.verify"));
        proxyPath = properties.getProperty("xrootd.gsi.tpc.proxy.path");
    }

    @Override
    public ChannelHandler createHandler()
    {
        /*
         *  This is an SPI interface method with no throws signature.
         *  Non-runtime exceptions on the credential load thus need to be logged.
         *
         *  If the credentials fail to load, the issue will soon be discovered
         *  when GSI TPC fails.
         */
        loadClientCredentials();

        GSIClientAuthenticationHandler handler =
                        new GSIClientAuthenticationHandler(proxy,
                                                           validator,
                                                           caCertificatePath,
                                                           clientCredIssuerHashes);
        return handler;
    }

    @Override
    public String getDescription()
    {
        return "GSI authentication client plugin for third-party transfers";
    }

    @Override
    public String getName()
    {
        return PROTOCOL;
    }

    private synchronized void loadClientCredentials()
    {
        try {
            if (shouldRefreshClientProxyCredential()) {
                LOGGER.info("Refreshing proxy credential. Current refresh interval: {} ms",
                            proxyRefreshInterval);

                if (!Strings.isNullOrEmpty(proxyPath)) {
                    proxy = new PEMCredential(proxyPath, (char[]) null);
                } else {
                    clientCredential = new PEMCredential(clientKeyPath,
                                                         clientCertificatePath,
                                                         null);
                    if (verifyClientCertificate) {
                        LOGGER.info("Verifying client certificate");
                        validator.validate(clientCredential.getCertificateChain());
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
            LOGGER.error("Could not load certificates/key due to security error; {}: {}.",
                         getCredentialValues(), gssex.toString());
        } catch (IOException ioex) {
            LOGGER.error("Could not read certificates/key from file-system; {}: {}.",
                         getCredentialValues(), ioex.toString());

        }

        clientCredIssuerHashes = getClientCredIssuerHashes();
    }

    private String getClientCredIssuerHashes()
    {
        Set<String> issuers = new HashSet<>();

        for (X509Certificate certificate: proxy.getCertificateChain()) {
            X500Principal certIssuer = certificate.getIssuerX500Principal();
            issuers.add(OpensslTruststoreHelper.getOpenSSLCAHash(certIssuer,
                                                                true));
        }

        return Joiner.on("|").join(issuers);
    }

    private String getCredentialValues()
    {
        return "client cert path: " + clientCertificatePath
                        + ", client key path: " + clientKeyPath
                        + ", client issuer hashes: " + clientCredIssuerHashes
                        + ", proxy path: " + proxyPath;
    }

    private boolean shouldRefreshClientProxyCredential()
    {
        long timeSinceLastClientRefresh = (System.currentTimeMillis() - proxyRefreshTimestamp);
        LOGGER.info("Time since last client cert refresh {}", timeSinceLastClientRefresh);
        return proxy == null || timeSinceLastClientRefresh >= proxyRefreshInterval;
    }
}
