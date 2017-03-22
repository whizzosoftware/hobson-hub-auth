/*
 *******************************************************************************
 * Copyright (c) 2017 Whizzo Software, LLC.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************
*/
package com.whizzosoftware.hobson.security;

import com.whizzosoftware.hobson.api.HobsonAuthenticationException;
import com.whizzosoftware.hobson.api.hub.*;
import com.whizzosoftware.hobson.api.security.HobsonUser;
import org.junit.Test;

import java.io.File;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.*;

public class LocalAccessManagerTest {
    @Test
    public void testGetUsers() throws Exception {
        File f = File.createTempFile("users", "db");
        f.deleteOnExit();
        LocalAccessManager s = new LocalAccessManager(f);
        Collection<HobsonUser> users = s.getUsers();
        assertEquals(1, users.size());
        HobsonUser u = users.iterator().next();
        assertEquals("admin", u.getId());
        assertEquals("Administrator", u.getGivenName());
        assertEquals("User", u.getFamilyName());
        assertEquals(1, u.getRoles().size());
        assertEquals("administrator", u.getRoles().iterator().next());
    }

    @Test
    public void testAddUser() throws Exception {
        File f = File.createTempFile("users", "db");
        f.deleteOnExit();

        LocalAccessManager s = new LocalAccessManager(f);

        // add a new user
        s.addUser("test", "test", "Test", "User", Collections.singletonList("userRead"));

        // make sure we can authenticate
        HobsonUser a = s.authenticate("test", "test");
        assertEquals("test", a.getId());

        // make sure we can pull info
        HobsonUser u = s.getUser("test");
        assertNotNull(u);
        assertEquals("test", u.getId());
        assertEquals("Test", u.getGivenName());
        assertEquals("User", u.getFamilyName());
        assertEquals(1, u.getRoles().size());
        assertEquals("userRead", u.getRoles().iterator().next());
    }

    @Test
    public void testChangePassword() throws Exception {
        File f = File.createTempFile("users", "db");
        f.deleteOnExit();

        LocalAccessManager s = new LocalAccessManager(f);

        HobsonUser a = s.authenticate("admin", "password");
        assertEquals("admin", a.getId());

        s.changeUserPassword("admin", new PasswordChange("password", "password2"));

        a = s.authenticate("admin", "password2");
        assertEquals("admin", a.getId());

        try {
            s.authenticate("admin", "password");
            fail("Should have thrown exception");
        } catch (HobsonAuthenticationException ignored) {}
    }

    @Test
    public void testAuthenticate() throws Exception {
        File f = File.createTempFile("users", "db");
        f.deleteOnExit();
        LocalAccessManager mgr = new LocalAccessManager(f);
        HobsonUser user = mgr.authenticate("admin", "password");
        assertNotNull(user);

        assertEquals("admin", user.getId());
        assertEquals("Administrator", user.getGivenName());
        assertEquals("User", user.getFamilyName());
        assertNull(user.getEmail());
    }
}
