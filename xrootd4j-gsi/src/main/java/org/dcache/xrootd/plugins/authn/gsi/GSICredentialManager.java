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

import com.google.common.base.Joiner;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.helpers.ssl.HostnameToCertificateChecker;
import eu.emi.security.authn.x509.helpers.trust.OpensslTruststoreHelper;
import eu.emi.security.authn.x509.impl.PEMCredential;
import eu.emi.security.authn.x509.proxy.ProxyGenerator;
import eu.emi.security.authn.x509.proxy.ProxyRequestOptions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.ProxyDelegationClient;
import org.dcache.xrootd.util.ProxyRequest;

import static org.dcache.xrootd.security.XrootdSecurityProtocol.kGSErrError;

/**
 *  <p>The component which provides credential management and related
 *     support to the request handlers.  Wraps loading and refreshing
 *     done by the credential loader, and validation of the cert
 *     chain.</p>
 *
 *  <p>Also supports calls to delegation client in support of direct
 *      proxy delegation.</p>
 */
public class GSICredentialManager
{
    private static final Logger                       LOGGER
                    = LoggerFactory.getLogger(GSICredentialManager.class);

    private static final HostnameToCertificateChecker CERT_CHECKER =
                    new HostnameToCertificateChecker();

    private static final CertificateFactory CERTIFICATE_FACTORY;

    static {
        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509",
                                                                 "BC");
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to create X.509 certificate factory: "
                                                       + e.getMessage(), e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Failed to load bouncy castle provider: "
                                                       + e.getMessage(), e);
        }
    }

    public static void checkIdentity(X509Certificate certificate, String name)
                    throws GeneralSecurityException, UnknownHostException
    {
        LOGGER.debug("Checking identity of certificate against source {}.", name);

        if (certificate.getSubjectDN().getName().contains(name) ||
                        CERT_CHECKER.checkMatching(name, certificate)) {
            return;
        }

        String error = "The name of the source server does not match any subject "
                        + "name of the received credential.";
        throw new GeneralSecurityException(error);
    }

    private static String generateIssuerHashes(X509Credential credential)
    {
        Set<String> issuers = new HashSet<>();

        for (X509Certificate cert: credential.getCertificateChain()) {
            X500Principal certIssuer = cert.getIssuerX500Principal();
            issuers.add(OpensslTruststoreHelper.getOpenSSLCAHash(certIssuer,
                                                                 true));
        }

        return Joiner.on("|").join(issuers);
    }

    public X509Certificate createCertificate(byte[] bytes) throws CertificateException
    {
        return (X509Certificate)CERTIFICATE_FACTORY.generateCertificate(new ByteArrayInputStream(bytes));
    }

    private final CredentialLoader credentialLoader;
    private final String           caCertificatePath;
    private final X509CertChainValidator certChainValidator;

    private String issuerHashes;

    /*
     *  For delegated proxy request
     */
    private X509ProxyDelegationClient               proxyDelegationClient;
    private ProxyRequest<X509Certificate[], String> proxyRequest;

    public GSICredentialManager(Properties properties,
                                CredentialLoader credentialLoader,
                                X509CertChainValidator certChainValidator)
    {
        this.caCertificatePath = properties.getProperty("xrootd.gsi.ca.path");
        this.credentialLoader = credentialLoader;
        this.certChainValidator = certChainValidator;
    }

    public synchronized void cancelOutstandingProxyRequest()
    {
        if (proxyRequest != null && proxyRequest.getId() != null) {
            try {
                proxyDelegationClient.cancelProxyRequest(proxyRequest);
            } catch (XrootdException e) {
                LOGGER.warn("Problem cancelling proxy delegation request {} {}: {}.",
                            proxyRequest.getKey()[0].getSubjectDN(),
                            proxyRequest.getId(),
                            e.toString());
            }
            proxyRequest = null;
        }
    }

    public void checkCaIdentities(String[] caIdentities) throws XrootdException
    {
        List<String> valid = new ArrayList<>();

        for (String ca : caIdentities) {
            if (isValidCaPath(ca)) {
                valid.add(ca);
            }
        }

        if (valid.isEmpty()) {
            throw new XrootdException(kGSErrError, "no ca identity is recognized.");
        }

        LOGGER.debug("The following ca hashes are recognized: {}.", valid);
    }

    /**
     * Attempts to store the new proxy.
     *
     * @param certChain signed by client.
     */
    public synchronized SerializableX509Credential
            finalizeDelegatedProxy(X509Certificate[] certChain)
                    throws XrootdException {
        if (proxyRequest == null) {
            throw new XrootdException(kGSErrError, "cannot finalize proxy: "
                            + "proxy request was not sent.");
        }

        X509Certificate[] oldChain = proxyRequest.getKey();
        String serializedCert = CertUtil.chainToPEM(CertUtil.prepend(certChain[0],
                                                                     oldChain));

        LOGGER.debug("finalizing proxy credential for {}, id {}.",
                     oldChain[0].getSubjectDN(),
                     proxyRequest.getId());

        SerializableX509Credential x509Credential
            = proxyDelegationClient().finalizeProxyCredential(proxyRequest.getId(),
                                                              serializedCert);

        /*
         *  This call is understood to be the last in a sequence
         *  for any given GSI exchange.
         */
        proxyRequest = null;

        return x509Credential;
    }

    public X509CertChainValidator getCertChainValidator()
    {
        return certChainValidator;
    }

    public PEMCredential getHostCredential()
    {
        return credentialLoader.getHostCredential();
    }

    public String getIssuerHashes()
    {
        if (issuerHashes == null) {
            X509Credential proxy = getProxy();
            if (proxy != null) {
                issuerHashes = generateIssuerHashes(proxy);
            }
        }
        return issuerHashes;
    }

    public X509Credential getProxy()
    {
        return credentialLoader.getProxy();
    }

    public PublicKey getSenderPublicKey()
    {
        if (proxyRequest != null) {
            return proxyRequest.getKey()[0].getPublicKey();
        }

        return null;
    }

    public boolean isDelegationOnly()
    {
        return credentialLoader.isDelegationOnly();
    }

    /**
     * Server-side method.
     *
     * Create a proxy request (CSR) from the client's certificate chain.
     *
     * Also stores the cert chain and proxy request
     * for future processing/finalization.
     *
     * @param certChain from authenticating client.
     * @return String representing the CSR (for inclusion in message to
     *         client).
     */
    public synchronized String prepareSerializedProxyRequest(X509Certificate[] certChain)
                    throws XrootdException {
        LOGGER.debug("Credential manager requesting proxy request "
                                     + "(CSR) from client for {}.",
                     certChain[0].getSubjectDN());
        proxyRequest = proxyDelegationClient().getProxyRequest(certChain);
        LOGGER.debug("Credential manager got proxy request (CSR) "
                                     + "from client for {}.",
                     certChain[0].getSubjectDN());
        if (proxyRequest == null) {
            throw new XrootdException(kGSErrError, "fetch of proxy request "
                            + "(CSR) failed");
        }

        return proxyRequest.getRequest();
    }

    /**
     * Client-side method.
     *
     * Takes the CSR request from the server, and adds the new signed certificate
     * based on it to the top/front of the certificate chain.
     *
     * NOTA BENE:  This method is here only for completeness.  Hopefully,
     * the SLAC server will be smart enough to know not to request
     * a delegated proxy from the TPC client.  When talking to a dCache
     * door, this should always be the case, as the destination server will
     * have already authenticated the user client and checked for/requested
     * a proxy then, which hopefully would be found in cache on the TPC client
     * call.
     *
     * @param serverCSR
     * @return full cert chain with chain[0] equal to the new signed cert.
     */
    public synchronized X509Certificate[] getSignedProxyRequest(byte[] serverCSR)
                    throws IOException, NoSuchAlgorithmException,
                    SignatureException, InvalidKeyException,
                    CertificateParsingException, NoSuchProviderException
    {
        ProxyRequestOptions options = new ProxyRequestOptions(
                        credentialLoader.getProxy().getCertificateChain(),
                        new PKCS10CertificationRequest(serverCSR));
        LOGGER.debug("Client, signing proxy request (CSR) with client private key {}.",
                     credentialLoader.getProxy().getKey());
        return ProxyGenerator.generate(options, credentialLoader.getProxy().getKey());
    }

    public void setProxyDelegationClient(ProxyDelegationClient proxyDelegationClient)
    {
        this.proxyDelegationClient = (X509ProxyDelegationClient)proxyDelegationClient;
    }

    public void setIssuerHashesFromCredential(X509Credential credential)
    {
        issuerHashes = generateIssuerHashes(credential);
    }

    private X509ProxyDelegationClient proxyDelegationClient() throws XrootdException
    {
        if (proxyDelegationClient == null) {
            throw new XrootdException(kGSErrError, "no client to credential "
                            + "store has been provided.");
        }

        return proxyDelegationClient;
    }

    private boolean isValidCaPath(String path)
    {
        path = path.trim();

        if (path.indexOf(".") < 1) {
            path += ".0";
        }

        return new File(caCertificatePath, path).exists();
    }
}
