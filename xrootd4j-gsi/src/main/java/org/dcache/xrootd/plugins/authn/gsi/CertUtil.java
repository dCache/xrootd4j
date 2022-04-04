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

import com.google.common.base.Throwables;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.security.auth.x500.X500Principal;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * CertUtil - convenience methods for certificate processing
 *
 * @author radicke
 * @author tzangerl
 *
 */
public class CertUtil
{
    private static final Map<X500Principal,String> _hashCache =
        new ConcurrentHashMap<>();

    /**
     * Rebuild the cert chain by adding the new cert in first position.
     * @param certificate to prepend
     * @param chain current
     * @return new chain
     */
    public static List<X509Certificate> prepend(X509Certificate certificate,
                                                X509Certificate[] chain)
    {
        List<X509Certificate> newChain = new ArrayList<>();
        newChain.add(certificate);

        for (X509Certificate cert : chain) {
            newChain.add(cert);
        }

        return newChain;
    }

    /**
     * Decodes PEM by removing the given header and footer, and decodes
     * the inner content with base64.
     * @param pem the full PEM-encoded data including header + footer
     * @param header the header to be striped off
     * @param footer the footer to be striped off
     * @return the content in DER format
     */
    public static byte[] fromPEM(String pem, String header, String footer)
    {
        if (!pem.startsWith(header)) {
            throw new IllegalArgumentException("The provided PEM string doesn't start with '" + header
                                               + "'");
        }

        // strip header
        StringBuilder sb = new StringBuilder(pem);
        sb.delete(0, header.length());

        removeChar(sb, '\n');

        // remove footer
        if (!sb.subSequence(sb.length() - footer.length(), sb.length()).equals(
                                                                               footer)) {
            throw new IllegalArgumentException("The provided PEM string doesn't end with '" + footer + "'");
        }
        sb.delete(sb.indexOf(footer), sb.length());

        // finally decode base64
        return Base64.decodeBase64(sb.toString());
    }

    /**
     * Encodes to PEM format with default X.509 certificate
     * header/footer
     * @param certificate the certificate to be encoded
     * @return the PEM-encoded String
     */
    public static String certToPEM(X509Certificate certificate)
    {
        try {
            StringWriter output = new StringWriter();
            PEMWriter writer = new PEMWriter(output);
            writer.writeObject(certificate);
            writer.flush();
            return output.toString();
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    public static String chainToPEM(Iterable<X509Certificate> certificates)
    {
        try {
            StringWriter output = new StringWriter();
            PEMWriter writer = new PEMWriter(output);
            for (X509Certificate certificate : certificates) {
                writer.writeObject(certificate);
            }
            writer.flush();
            return output.toString();
        } catch (IOException e) {
            throw Throwables.propagate(e);
        }
    }

    private PKCS10CertificationRequest fromPEM(String data) throws IOException
    {
        PEMParser reader = new PEMParser(new StringReader(data));
        return (PKCS10CertificationRequest)reader.readObject();
    }

    /**
     * Encodes to PEM. The content is base64-encoded and the header and
     * footer is added.
     * @param der the content to be encoded
     * @param header the header line
     * @param footer the footer line
     * @return the PEM-encoded String
     */
    public static String toPEM(byte[] der, String header, String footer)
    {
        StringBuilder result = new StringBuilder(header);

        // make sure the header line ends with a new line char
        if (header.charAt(header.length() - 1) != '\n') {
            result.append('\n');
        }

        String base64 =
            StringUtils.newStringUtf8(Base64.encodeBase64(der));

        //
        // PEM requires that each line of the BASE64-encoded data is
        // not longer than 64 characters. Therefore we insert a new
        // line character each 64 characters.
        //
        int pos = 0;
        while (pos + 64 < base64.length()) {

            result.append(base64.substring(pos, pos + 64));
            result.append('\n');

            pos += 64;
        }
        result.append(base64.substring(pos));
        result.append('\n');

        result.append(footer);

        // make sure the header line ends with a new line char
        if (footer.charAt(footer.length() - 1) != '\n') {
            result.append('\n');
        }

        return result.toString();
    }


    /**
     * Convenience method to compute a openssl-compatible md5 hash
     * @param principal the principal (either issuer or subject)
     * @return the 8-digit hexadecimal hash string
     */
    public static String computeMD5Hash(X500Principal principal)
    {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(e);
        }

        return computeHash(md, principal);
    }


    /**
     * Computes the hash from the principal, using the passed-in digest
     * (usually MD5).  After applying the digest on the DER-encoded
     * principal, the first 4 bytes of the computed hash are taken and
     * interpreted as a hexadecimal integer in Little Endian. This
     * corresponds to the openssl hash mechanism.
     *
     * Keep a cache of principals, as this method will often be called
     * with the same principal (to avoid costly rehashing).
     *
     * @param md the digest instance
     * @param principal the principal (subject or issuer)
     * @return the 8-digit hexadecimal hash
     */
    public static String computeHash(MessageDigest md, X500Principal principal)
    {
        String principalHash;

        if (_hashCache.containsKey(principal)) {
            principalHash = _hashCache.get(principal);
        } else {
            md.reset();
            md.update(principal.getEncoded());
            byte[] md5hash = md.digest();


            // take the first 4 bytes in little Endian
            int shortHash =   (0xff & md5hash[3]) << 24
                | (0xff & md5hash[2]) << 16
                | (0xff & md5hash[1]) << 8
                | (0xff & md5hash[0]);

            /*
             *  Convert to hex. An 8-digit hex string is required.
             */
            principalHash = String.format("%08x", shortHash);

            _hashCache.put(principal, principalHash);
        }

        return principalHash;
    }

    /**
     * remove all occurences of a character from a string
     *
     * @param sb the stringbuilder
     * @param c the char to be removed
     * @return the resulting stringbuilder
     */
    private static StringBuilder removeChar(StringBuilder sb, char c)
    {
        int index;
        while ((index = sb.indexOf("\n")) > -1) {
            sb.deleteCharAt(index);
        }
        return sb;
    }

}
