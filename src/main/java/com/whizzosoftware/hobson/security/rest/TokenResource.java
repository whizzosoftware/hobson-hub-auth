/*
 *******************************************************************************
 * Copyright (c) 2017 Whizzo Software, LLC.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *******************************************************************************
*/
package com.whizzosoftware.hobson.security.rest;

import com.whizzosoftware.hobson.api.HobsonAuthenticationException;
import com.whizzosoftware.hobson.api.security.AccessManager;
import com.whizzosoftware.hobson.api.security.HobsonUser;
import org.json.JSONObject;
import org.restlet.data.Form;
import org.restlet.ext.guice.SelfInjectingServerResource;
import org.restlet.ext.json.JsonRepresentation;
import org.restlet.representation.EmptyRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.ResourceException;

import javax.inject.Inject;

/**
 * The OIDC token endpoint.
 *
 * @author Dan Noguerol
 */
public class TokenResource extends SelfInjectingServerResource {
    public static final String PATH = "/token";

    @Inject
    AccessManager accessManager;

    @Override
    protected Representation post(Representation entity) throws ResourceException {
        final Form form = new Form(entity);

        String grantType = form.getFirstValue("grant_type");

        if ("password".equals(grantType) || "token".equals(grantType)) {
            String username = form.getFirstValue("username");
            String password = form.getFirstValue("password");
            if (username != null && password != null) {
                HobsonUser user = accessManager.authenticate(username, password);
                if ("password".equals(grantType)) {
                    String token = accessManager.createToken(user);
                    JSONObject json = new JSONObject();
                    json.put("id_token", token);
                    json.put("access_token", token);
                    return new JsonRepresentation(json);
                } else {
                    return new EmptyRepresentation();
                }
            } else {
                throw new HobsonAuthenticationException("Missing username and/or password");
            }
        } else {
            throw new HobsonAuthenticationException("Invalid grant_type");
        }
    }
}
