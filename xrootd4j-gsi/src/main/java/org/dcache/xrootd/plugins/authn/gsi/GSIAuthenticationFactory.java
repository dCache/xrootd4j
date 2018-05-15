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

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.OCSPCheckingMode;
import eu.emi.security.authn.x509.OCSPParametes;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.RevocationParameters;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.impl.ValidatorParams;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class GSIAuthenticationFactory implements AuthenticationFactory
{
    private static final Logger _logger =
        LoggerFactory.getLogger(GSIAuthenticationFactory.class);

    private final String _hostCertificatePath;
    private final String _hostKeyPath;
    private final String _caCertificatePath;
    private final X509CertChainValidator _validator;

    private final long _hostCertRefreshInterval;
    private final long _trustAnchorRefreshInterval;
    private long _hostCertRefreshTimestamp = 0;

    private final boolean _verifyHostCertificate;

    private PEMCredential _hostCredential;

    public GSIAuthenticationFactory(Properties properties)
    {
        _hostKeyPath =
            properties.getProperty("xrootd.gsi.hostcert.key");
        _hostCertificatePath =
            properties.getProperty("xrootd.gsi.hostcert.cert");
        _hostCertRefreshInterval =
                TimeUnit.valueOf(properties.getProperty("xrootd.gsi.hostcert.refresh.unit"))
                        .toMillis(Integer.parseInt(properties.getProperty("xrootd.gsi.hostcert.refresh")));
        _verifyHostCertificate =
            Boolean.parseBoolean(properties.getProperty("xrootd.gsi.hostcert.verify"));

        _caCertificatePath = properties.getProperty("xrootd.gsi.ca.path");
        _trustAnchorRefreshInterval =
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
        _validator =
                new OpensslCertChainValidator(_caCertificatePath, false, namespaceMode,
                                              _trustAnchorRefreshInterval, validatorParams, false);
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

        return new GSIAuthenticationHandler(_hostCredential, _validator);
    }

    private synchronized void loadServerCredentials() throws CertificateException, KeyStoreException, IOException
    {
        long timeSinceLastServerRefresh = (System.currentTimeMillis() - _hostCertRefreshTimestamp);
        if (_hostCredential == null || timeSinceLastServerRefresh >= _hostCertRefreshInterval) {
            _logger.info("Time since last server cert refresh {}", timeSinceLastServerRefresh);
            _logger.info("Loading server certificates. Current refresh interval: {} ms",
                      _hostCertRefreshInterval);
            PEMCredential credential = new PEMCredential(_hostKeyPath, _hostCertificatePath, null);
             if (_verifyHostCertificate) {
                 _logger.info("Verifying host certificate");
                 _validator.validate(credential.getCertificateChain());
             }
             _hostCredential = credential;
             _hostCertRefreshTimestamp = System.currentTimeMillis();
        }
    }
}
