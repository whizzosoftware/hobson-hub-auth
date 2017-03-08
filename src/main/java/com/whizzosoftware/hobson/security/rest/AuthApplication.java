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

import com.whizzosoftware.hobson.api.HobsonRuntimeException;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.lang.JoseException;
import org.restlet.Restlet;
import org.restlet.ext.guice.ResourceInjectingApplication;
import org.restlet.routing.Redirector;
import org.restlet.routing.Router;

/**
 * The REST application that provides OIDC resources.
 *
 * @author Dan Noguerol
 */
public class AuthApplication extends ResourceInjectingApplication {
    public AuthApplication() {
        try {
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            rsaJsonWebKey.setKeyId("k1");
        } catch (JoseException e) {
            throw new HobsonRuntimeException("Error creating RSA web key", e);
        }
    }

    @Override
    public Restlet createInboundRoot() {
        Router router = newRouter();

        router.attach("/", new Redirector(getContext(), "/console/index.html", Redirector.MODE_CLIENT_TEMPORARY));

        // OIDC related resources
        router.attach(AuthorizationResource.PATH, AuthorizationResource.class);
        router.attach(JWKSResource.PATH, JWKSResource.class);
        router.attach(OIDCConfigurationResource.PATH, OIDCConfigurationResource.class);
        router.attach(TokenResource.PATH, TokenResource.class);

        return router;
    }
}
