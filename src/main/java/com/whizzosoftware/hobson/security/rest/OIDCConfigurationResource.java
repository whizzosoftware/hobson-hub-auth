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

import com.whizzosoftware.hobson.api.hub.HubContext;
import org.json.JSONArray;
import org.json.JSONObject;
import org.restlet.ext.guice.SelfInjectingServerResource;
import org.restlet.ext.json.JsonRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.ResourceException;

/**
 * The OIDC discovery endpoint.
 *
 * @author Dan Noguerol
 */
public class OIDCConfigurationResource extends SelfInjectingServerResource {
    public static final String PATH = "/.well-known/openid-configuration";

    @Override
    protected Representation get() throws ResourceException {
        JSONObject json = new JSONObject();
        json.put("issuer", "Hobon");
        json.put("authorization_endpoint", AuthorizationResource.PATH);
        json.put("userinfo_endpoint", "/v1/api/userInfo");
        json.put("token_endpoint", TokenResource.PATH);
        json.put("jwks_uri", JWKSResource.PATH);
        JSONArray ja = new JSONArray();
        ja.put("id_token");
        json.put("response_types_supported", ja);
        ja = new JSONArray();
        ja.put("public");
        json.put("subject_types_supported", ja);
        ja = new JSONArray();
        ja.put("openid");
        json.put("scopes_supported", ja);
        ja = new JSONArray();
        ja.put("RS256");
        json.put("id_token_signing_alg_values_supported", ja);
        ja = new JSONArray();
        ja.put("password");
        ja.put("implicit");
        json.put("grant_types_supported", ja);

        getResponse().getHeaders().add("X-Default-User", HubContext.DEFAULT_USER);

        return new JsonRepresentation(json);
    }

}
