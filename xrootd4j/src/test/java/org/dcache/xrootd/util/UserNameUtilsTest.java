/**
 * Copyright (C) 2011-2023 dCache.org <support@dcache.org>
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
package org.dcache.xrootd.util;

import static org.dcache.xrootd.util.OpaqueStringParser.OPAQUE_STRING_PREFIX;
import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.Test;

/**
 *  Tests checks for Posix compliance of user names, and for
 *  replacement of non-compliant names in strings.
 */
public class UserNameUtilsTest {

    private static final String TPC_SRC = "tpc.src";
    private static final String TPC_DLG = "tpc.dlg";
    private static final String CLIENT = "org.dcache.xrootd.client";
    private static final String OSS_ASIZE = "oss.asize";
    private static final String TPC_KEY = "tpc.key";
    private static final String TPC_LFN = "tpc.lfn";
    private static final String TPC_SPR = "tpc.spr";
    private static final String TPC_TPR = "tpc.tpr";
    private static final String TPC_STAGE = "tpc.stage";
    private static final String TPC_STR = "tpc.str";
    private static final String MOVER_UUID = "org.dcache.uuid";

    private static final String XROOTD_UNKNOWN_TPC_SRC = "????@foobar.org";
    private static final String XROOTD_UNKNOWN_TPC_DLG = "????@foobar.org";
    private static final String XROOTD_UNKNOWN_CLIENT = "????.29931@foobar.org";

    private static final String NON_COMPLIANT_CLIENT = "i&v4.29931@foobar.org";
    private static final String NON_COMPLIANT_SRC = "alrossi7&@foobar.org";
    private static final String COMPLIANT_PID_2 = "foo.bar.29931@foobar.org";
    private static final String EXTENDED_PID = "foo.29042:10@foobar.org";

    private static final String COMPLIANT_TPC_SRC = "arossi2020@foobar.org";
    private static final String COMPLIANT_TPC_DLG = "arossi2020@foobar.org";
    private static final String COMPLIANT_CLIENT = "arossi2020.29931@foobar.org";

    private static final String REPLACED_TPC_SRC = "_anon_@foobar.org";
    private static final String REPLACED_TPC_DLG = "_anon_@foobar.org";
    private static final String REPLACED_CLIENT = "_anon_.29931@foobar.org";

    private static final String KEY_VAL = UUID.randomUUID().toString();
    private static final String ASIZE_VAL = "2048";
    private static final String LFN_VAL = "/pnfs/fs/usr/test/arossi/volatile/testdata";
    private static final String SPR_VAL = "root";
    private static final String TPR_VAL = "root";
    private static final String STAGE_VAL = "copy";
    private static final String STR_VAL = "1";
    private static final String UUID_VAL = UUID.randomUUID().toString();

    private String opaqueString;
    private Map<String, String> parsed;

    @Test
    public void shouldAcceptEmptyUserName() throws Exception {
        assertEquals("Should have accepted empty name", "",
              UserNameUtils.checkUsernameValid(""));
    }

    @Test
    public void shouldNotAcceptNullUserName() throws Exception {
        assertEquals("Should have replaced user name",
              UserNameUtils.XROOTD_MAGIC_NAME,
              UserNameUtils.checkUsernameValid(null));
    }

    @Test
    public void shouldAcceptCompliantUserName() throws Exception {
        assertEquals("Should have accepted user name.",
              "a_l_rossi1955-06-01",
              UserNameUtils.checkUsernameValid("a_l_rossi1955-06-01"));
    }

    @Test
    public void shouldAcceptUserNameThatBeginsWithUpperCaseLetter() throws Exception {
        assertEquals("Should have accepted user name.",
              "A_l_rossi1955-06-01",
              UserNameUtils.checkUsernameValid("A_l_rossi1955-06-01"));
    }

    @Test
    public void shouldReplaceNonCompliantUserNameWithPeriod() throws Exception {
        assertEquals("Should have replaced user name.",
              UserNameUtils.XROOTD_MAGIC_NAME,
              UserNameUtils.checkUsernameValid("a_l_rossi1955-06-01.c"));
    }

    @Test
    public void shouldNotFailIfClientContainsExtendedPid() throws Exception {
        givenOpaqueStringWithClientName(EXTENDED_PID);
        whenStringIsParsed();
    }

    @Test
    public void shouldReplaceUserNameThatBeginsWithNumber() throws Exception {
        assertEquals("Should have replaced user name.",
              UserNameUtils.XROOTD_MAGIC_NAME,
              UserNameUtils.checkUsernameValid("7a_l_rossi1955-06-01"));
    }

    @Test
    public void shouldReplaceUserNameThatContainsUpperCaseLetter() throws Exception {
        assertEquals("Should have replaced user name.",
              UserNameUtils.XROOTD_MAGIC_NAME,
              UserNameUtils.checkUsernameValid("a_l_Rossi?1955-06-01"));
    }

    @Test
    public void shouldReplaceUserNameThatContainsSpecialCharacters() throws Exception {
        UserNameUtils.checkUsernameValid("7a_l_rossi?1955-06-01");
    }

    @Test
    public void shouldChangeUnknownToMagicNameForAllUsernames() throws Exception {
        givenOpaqueStringWithXrootdUnknownNames();
        whenStringIsParsed();
        assertThatXrootdUnknownNamesAreReplaced();
    }

    @Test
    public void shouldNotReplaceCompliantUsernames() throws Exception {
        givenOpaqueStringWithClientName(COMPLIANT_CLIENT);
        whenStringIsParsed();
        assertThatCompliantNamesAreUnchanged();
    }

    @Test
    public void shouldNotFailIfClientContainsNonCompliantUsername() throws Exception {
        givenOpaqueStringWithClientName(NON_COMPLIANT_CLIENT);
        whenStringIsParsed();
    }

    @Test
    public void shouldNotFailIfSrcContainsNonCompliantUsername() throws Exception {
        givenOpaqueStringWithSrcName(NON_COMPLIANT_SRC);
        whenStringIsParsed();
    }

    public void shouldNotFailIfClientContainsDoublePeriod() throws Exception {
        givenOpaqueStringWithClientName(COMPLIANT_PID_2);
        whenStringIsParsed();
    }

    private void whenStringIsParsed() throws Exception {
        parsed = OpaqueStringParser.getOpaqueMap(opaqueString);
    }

    private void assertThatCompliantNamesAreUnchanged() throws Exception {
        assertEquals("Wrong " + TPC_SRC + " value",
              COMPLIANT_TPC_SRC, parsed.get(TPC_SRC));
        assertEquals("Wrong " + TPC_DLG + " value",
              COMPLIANT_TPC_DLG, parsed.get(TPC_DLG));
        assertEquals("Wrong " + CLIENT + " value",
              COMPLIANT_CLIENT, parsed.get(CLIENT));
    }

    private void assertThatXrootdUnknownNamesAreReplaced() throws Exception {
        assertEquals("Wrong " + TPC_SRC + " value",
              REPLACED_TPC_SRC, parsed.get(TPC_SRC));
        assertEquals("Wrong " + TPC_DLG + " value",
              REPLACED_TPC_DLG, parsed.get(TPC_DLG));
        assertEquals("Wrong " + CLIENT + " value",
              REPLACED_CLIENT, parsed.get(CLIENT));
    }

    private void givenOpaqueStringWithXrootdUnknownNames() {
        Map<String, String> opaqueMap = new HashMap<>();
        opaqueMap.put(TPC_SRC, XROOTD_UNKNOWN_TPC_SRC);
        opaqueMap.put(TPC_DLG, XROOTD_UNKNOWN_TPC_DLG);
        opaqueMap.put(CLIENT, XROOTD_UNKNOWN_CLIENT);
        addOtherValues(opaqueMap);
        opaqueString = OPAQUE_STRING_PREFIX + OpaqueStringParser.buildOpaqueString(opaqueMap);
    }

    private void givenOpaqueStringWithClientName(String name) {
        Map<String, String> opaqueMap = new HashMap<>();
        opaqueMap.put(TPC_SRC, COMPLIANT_TPC_SRC);
        opaqueMap.put(TPC_DLG, COMPLIANT_TPC_DLG);
        add(CLIENT, name, opaqueMap);
        addOtherValues(opaqueMap);
        opaqueString = OPAQUE_STRING_PREFIX + OpaqueStringParser.buildOpaqueString(opaqueMap);
    }

    private void givenOpaqueStringWithSrcName(String name) {
        Map<String, String> opaqueMap = new HashMap<>();
        add(TPC_SRC, name, opaqueMap);
        opaqueMap.put(TPC_DLG, COMPLIANT_TPC_DLG);
        opaqueMap.put(CLIENT, COMPLIANT_CLIENT);
        addOtherValues(opaqueMap);
        opaqueString = OPAQUE_STRING_PREFIX + OpaqueStringParser.buildOpaqueString(opaqueMap);
    }

    private void add(String name, String value, Map<String, String> opaqueMap) {
        opaqueMap.put(name, value);
    }

    private void addOtherValues(Map<String, String> opaqueMap) {
        opaqueMap.put(OSS_ASIZE, ASIZE_VAL);
        opaqueMap.put(TPC_KEY, KEY_VAL);
        opaqueMap.put(TPC_LFN, LFN_VAL);
        opaqueMap.put(TPC_SPR, SPR_VAL);
        opaqueMap.put(TPC_TPR, TPR_VAL);
        opaqueMap.put(TPC_STAGE, STAGE_VAL);
        opaqueMap.put(TPC_STR, STR_VAL);
        opaqueMap.put(MOVER_UUID, UUID_VAL);
    }
}
