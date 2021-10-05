/**
 * Copyright (C) 2011-2021 dCache.org <support@dcache.org>
 * 
 * This file is part of xrootd4j.
 * 
 * xrootd4j is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 * 
 * xrootd4j is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along with xrootd4j.  If
 * not, see http://www.gnu.org/licenses/.
 */
package org.dcache.xrootd.security;

import static org.dcache.xrootd.protocol.XrootdProtocol.kXR_ArgMissing;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.dcache.xrootd.core.XrootdException;

/**
 * Utility class for holding security requirement information.
 */
public class SecurityInfo {

    private final String protocol;
    private final Map<String, String> data;
    private final String description;

    public SecurityInfo(String description) throws XrootdException {
        this.description = description;
        int comma = description.indexOf(',');
        if (comma == -1) {
            protocol = description.trim();
            data = Collections.emptyMap();
        } else {
            protocol = description.substring(0, comma);
            data = new HashMap<>();
            String keyValueData = description.substring(comma + 1);
            String[] kvPairs = keyValueData.split(",");
            for (String pair : kvPairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    data.put(keyValue[0], keyValue[1]);
                } else {
                    data.put(keyValue[0], keyValue[0]);
                }
            }
        }

        if (protocol.isEmpty()) {
            throw new XrootdException(kXR_ArgMissing, "Missing protocol name");
        }
    }

    public String getProtocol() {
        return protocol;
    }

    @Override
    public String toString() {
        return description;
    }

    public Optional<String> getValue(String key) {
        return Optional.ofNullable(data.get(key));
    }

    /**
     * Return the value corresponding to a key.
     * @param key the item to extract
     * @return the corresponding value
     * @throws XrootdException if key is not defined
     */
    public String getRequiredValue(String key) throws XrootdException {
        String value = data.get(key);
        if (value == null) {
            throw new XrootdException(kXR_ArgMissing, "missing '" + key + "' in sec");
        }
        return value;
    }
}
