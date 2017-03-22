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
import com.whizzosoftware.hobson.api.HobsonAuthorizationException;
import com.whizzosoftware.hobson.api.HobsonRuntimeException;
import com.whizzosoftware.hobson.api.config.ConfigurationManager;
import com.whizzosoftware.hobson.api.executor.ExecutorManager;
import com.whizzosoftware.hobson.api.hub.OIDCConfig;
import com.whizzosoftware.hobson.api.hub.PasswordChange;
import com.whizzosoftware.hobson.api.security.AccessManager;
import com.whizzosoftware.hobson.api.security.HobsonUser;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.File;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static com.whizzosoftware.hobson.api.hub.HubContext.DEFAULT_USER;

/**
 * A local implementation of AccessManager that stores user information in a MapDB database.
 *
 * @author Dan Noguerol
 */
public class LocalAccessManager implements AccessManager {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    public static final String PROP_FIRST_NAME = "given_name";
    public static final String PROP_LAST_NAME = "family_name";
    private static final int DEFAULT_EXPIRATION_MINUTES = 60;

    @Inject
    private volatile ExecutorManager executorManager;

    private DB db;
    private OIDCConfig oidcConfig;
    private JwtConsumer jwtConsumer;

    public LocalAccessManager() {}

    public LocalAccessManager(File f) {
        setFile(f);
    }

    public void start() {
        File f = new File(System.getProperty(ConfigurationManager.HOBSON_HOME, "."), "data");
        if (!f.exists()) {
            if (!f.mkdir()) {
                logger.error("Error creating data directory");
                return;
            }
        }

        setFile(new File(f, "com.whizzosoftware.hobson.hub.hobson-hub-localauth$users"));

        try {
            RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
            rsaJsonWebKey.setKeyId("k1");
            oidcConfig = new OIDCConfig("Hobson", "/login", "/token", "/userInfo", ".well-known/jwks.json", rsaJsonWebKey);

            jwtConsumer = new JwtConsumerBuilder()
                    .setRequireExpirationTime()
                    .setAllowedClockSkewInSeconds(30)
                    .setRequireSubject()
                    .setExpectedIssuer(oidcConfig.getIssuer())
                    .setVerificationKey(((RsaJsonWebKey)oidcConfig.getSigningKey()).getKey())
                    .setExpectedAudience(System.getenv("OIDC_AUDIENCE") != null ? System.getenv("OIDC_AUDIENCE") : System.getProperty("OIDC_AUDIENCE", "hobson-webconsole"))
                    .build();
        } catch (JoseException e) {
            throw new HobsonRuntimeException("Error generating RSA JWK", e);
        }

        // create action store housekeeping task (run it starting at random interval between 22 and 24 hours)
        if (executorManager != null) {
            executorManager.schedule(new Runnable() {
                @Override
                public void run() {
                    System.out.println("Running user store housekeeping");
                    try {
                        synchronized (db) {
                            db.commit();
                            db.compact();
                        }
                    } catch (Throwable t) {
                        logger.error("Error compacting user database", t);
                    }
                    System.out.println("User store housekeeping complete");
                }
            }, 1440 - ThreadLocalRandom.current().nextInt(0, 121), 1440, TimeUnit.MINUTES);
        } else {
            logger.error("No executor manager available to perform user store housekeeping");
        }
    }

    @Override
    public void addUser(String username, String password, String givenName, String familyName, Collection<String> roles) {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            synchronized (db) {
                Map<String, Object> m = db.createTreeMap(username).makeOrGet();
                m.put("user", username);
                m.put("password", DigestUtils.sha256Hex(password));
                m.put("givenName", givenName);
                m.put("familyName", familyName);
                m.put("roles", new ArrayList<>(roles));

                db.commit();
            }
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    @Override
    public HobsonUser authenticate(String username, String password) throws HobsonAuthenticationException {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            Map<String,Object> map = db.getTreeMap(username);
            if (map != null) {
                String p = (String)map.get("password");
                if (p != null && p.equals(DigestUtils.sha256Hex(password))) {
                    return createUser(username, map);
                }
            }

            throw new HobsonAuthenticationException("Invalid username and/or password.");
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    @Override
    public HobsonUser authenticate(String token) throws HobsonAuthenticationException {
        try {
            // extract the claims from the token
            JwtClaims claims = jwtConsumer.processToClaims(token);

            // make sure the token hasn't expired
            if (claims.getExpirationTime().isAfter(NumericDate.now())) {
                List<String> roles = null;
                Map realmAccess = claims.getClaimValue("realm_access", Map.class);
                if (realmAccess != null && realmAccess.containsKey("roles")) {
                    roles = (List<String>)realmAccess.get("roles");
                }
                return new HobsonUser.Builder(claims.getSubject())
                        .givenName(claims.getStringClaimValue(PROP_FIRST_NAME))
                        .familyName(claims.getStringClaimValue(PROP_LAST_NAME))
                        .roles(roles != null ? roles : new ArrayList<String>())
                        .hubs(Collections.singletonList(claims.getClaimValue("hubs", String.class)))
                        .build();
            } else {
                throw new HobsonAuthenticationException("Token has expired");
            }
        } catch (Exception e) {
            throw new HobsonAuthenticationException("Error validating bearer token: " + e.getMessage());
        }
    }

    @Override
    public void authorize(HobsonUser user, String action, String resource) {
        // NO-OP
    }

    @Override
    public void changeUserPassword(String username, PasswordChange change) {
        synchronized (db) {
            Map<String, Object> map = db.getTreeMap(username);
            if (map != null) {
                String currentPassword = (String) map.get("password");
                if (DigestUtils.sha256Hex(change.getCurrentPassword()).equals(currentPassword)) {
                    map.put("password", DigestUtils.sha256Hex(change.getNewPassword()));
                    db.commit();
                } else {
                    throw new HobsonAuthorizationException("Unable to change user password");
                }
            } else {
                throw new HobsonAuthorizationException("Unable to change user password");
            }
        }
    }

    @Override
    public String createToken(HobsonUser user) {
        try {
            JwtClaims claims = new JwtClaims();
            claims.setIssuer(oidcConfig.getIssuer());
            claims.setAudience(System.getenv("OIDC_AUDIENCE") != null ? System.getenv("OIDC_AUDIENCE") : System.getProperty("OIDC_AUDIENCE", "hobson-webconsole"));
            claims.setSubject(user.getId());
            claims.setStringClaim(PROP_FIRST_NAME, user.getGivenName());
            claims.setStringClaim(PROP_LAST_NAME, user.getFamilyName());
            claims.setExpirationTimeMinutesInTheFuture(DEFAULT_EXPIRATION_MINUTES);
            claims.setClaim("realm_access", Collections.singletonMap("roles", user.getRoles()));
            Collection<String> hubs = getHubsForUser(user.getId());
            if (hubs != null) {
                claims.setStringClaim("hubs", StringUtils.join(hubs, ","));
            }

            JsonWebSignature jws = new JsonWebSignature();
            jws.setPayload(claims.toJson());
            jws.setKey(((RsaJsonWebKey)oidcConfig.getSigningKey()).getPrivateKey());
            jws.setKeyIdHeaderValue(((RsaJsonWebKey)oidcConfig.getSigningKey()).getKeyType());
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            return jws.getCompactSerialization();
        } catch (JoseException e) {
            logger.error("Error generating token", e);
            throw new HobsonAuthenticationException("Error generating token");
        }
    }

    @Override
    public String getDefaultUser() {
        return DEFAULT_USER;
    }

    @Override
    public Collection<String> getHubsForUser(String username) {
        return Collections.singletonList("local");
    }

    @Override
    public OIDCConfig getOIDCConfig() {
        return oidcConfig;
    }

    @Override
    public Set<String> getRoles() {
        return null;
    }

    @Override
    public HobsonUser getUser(String username) {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            Map<String,Object> map = db.getTreeMap(username);
            return createUser(username, map);
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    @Override
    public Collection<HobsonUser> getUsers() {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            List<HobsonUser> users = new ArrayList<>();
            Map<String,Object> map = db.getAll();
            for (String username : map.keySet()) {
                users.add(createUser(username, (Map<String,Object>)map.get(username)));
            }
            return users;

        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    @Override
    public boolean hasDefaultUser() {
        return true;
    }

    @Override
    public boolean isFederated() {
        return false;
    }

    public void setFile(File file) {
        ClassLoader old = Thread.currentThread().getContextClassLoader();
        try {
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());

            db = DBMaker.newFileDB(file)
                    .closeOnJvmShutdown()
                    .make();

            synchronized (db) {
                Map<String, Object> m = db.createTreeMap("admin").makeOrGet();
                if (!m.containsKey("password")) {
                    m.put("user", DEFAULT_USER);
                    m.put("password", DigestUtils.sha256Hex("password"));
                    m.put("givenName", "Administrator");
                    m.put("familyName", "User");
                    m.put("roles", Collections.singletonList("administrator"));
                    db.commit();
                }
            }
        } finally {
            Thread.currentThread().setContextClassLoader(old);
        }
    }

    private HobsonUser createUser(String username, Map<String,Object> map) {
        return new HobsonUser.Builder(username).givenName((String)map.get("givenName")).familyName((String)map.get("familyName")).roles((List<String>)map.get("roles")).build();
    }
}
