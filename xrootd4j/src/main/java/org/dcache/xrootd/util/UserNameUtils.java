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
package org.dcache.xrootd.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.dcache.xrootd.core.XrootdException;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgInvalid;

/**
 *  It is possible to confuse the OpaqueStringParser by introducing
 *  Posix Non-Compliant UserNames.  This utility guards against
 *  parser failure.
 */
public class UserNameUtils
{
    private static final String XROOTD_UNKNOWN_NAME = "????";
    private static final String XROOTD_MAGIC_NAME = "_anon_";
    private static final Pattern POSIX_COMPLIANT_UNAME
                    = Pattern.compile("^[a-z_][a-z0-9_-]*[$]?$",
                                      Pattern.CASE_INSENSITIVE);
    private static final Pattern UNAME_SLOT = Pattern.compile("[=]([^@=]+)[@]");

    /**
     * Checks for POSIX compliance.  Rejects <code>null</code> names but
     * accepts zero-length names.  If the name equals "????" it returns
     * "_anon_"; if the name is otherwise invalid, it throws an exception;
     * else it returns the name unchanged.
     *
     * @param username to validate.
     * @return "_anon_" if "????", or the valid name.
     * @throws XrootdException if the name is invalid.
     */
    public static String checkUsernameValid(String username)
                    throws XrootdException
    {
        if (XROOTD_UNKNOWN_NAME.equals(username)) {
            return XROOTD_MAGIC_NAME;
        }

        if (username == null
                        || (!username.isEmpty()
                        && !POSIX_COMPLIANT_UNAME.matcher(username).matches())) {
            throw new XrootdException(kXR_ArgInvalid, "Bad user name.");
        }

        return username;
    }

    /**
     * Finds all segments/groups of the string which could potentially be
     * usernames (bounded by '=' and '@'), and checks each for validity.
     * If the Xrootd Unknown marker is found ('????') it is replaced by
     * ('_anon_').  If an invalid name is found in the string, the check
     * fails.  Otherwise, the valid names are left as they are.
     *
     * @param string original string to validate.
     * @return string with "magic" substitutions, if any.
     * @throws XrootdException if any name found in the string is invalid.
     */
    public static String checkAllUsernamesValid(String string)
                    throws XrootdException
    {
        StringBuilder builder = new StringBuilder();
        int from = 0;
        int to;

        Matcher matcher = UNAME_SLOT.matcher(string);

        while (matcher.find())
        {
            String group = matcher.group(1);
            to = string.indexOf(group, from);
            builder.append(string.substring(from, to));
            String[] unamepid = group.split("[.]");
            if (unamepid.length > 2) {
                throw new XrootdException(kXR_ArgInvalid, "Bad user name.");
            }
            /*
             *  POSIX-validate only the part of the name up to a period.
             */
            from = to + unamepid[0].length();
            String valid = checkUsernameValid(unamepid[0]);
            builder.append(valid);
            if (unamepid.length == 2) {
                builder.append(".").append(unamepid[1]);
                from = from + unamepid[1].length() + 1;
            }
        }

        if (from < string.length()) {
            builder.append(string.substring(from));
        }

        return builder.toString();
    }
}
