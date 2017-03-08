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

import com.whizzosoftware.hobson.api.executor.ExecutorManager;
import com.whizzosoftware.hobson.api.hub.HubWebApplication;
import com.whizzosoftware.hobson.api.security.AccessManager;
import com.whizzosoftware.hobson.security.rest.AuthApplication;
import org.apache.felix.dm.DependencyActivatorBase;
import org.apache.felix.dm.DependencyManager;
import org.osgi.framework.BundleContext;

/**
 * The auth bundle activator.
 *
 * @author Dan Noguerol
 */
public class Activator extends DependencyActivatorBase {
    private org.apache.felix.dm.Component accessManager;

    @Override
    public void init(BundleContext context, DependencyManager manager) throws Exception {
        // publish access manager
        accessManager = manager.createComponent();
        accessManager.setInterface(AccessManager.class.getName(), null);
        accessManager.setImplementation(LocalAccessManager.class);
        accessManager.add(createServiceDependency().setService(ExecutorManager.class).setRequired(true));
        manager.add(accessManager);

        // register OIDC application
        context.registerService(HubWebApplication.class.getName(), new HubWebApplication("", AuthApplication.class), null);
    }

    @Override
    public void destroy(BundleContext context, DependencyManager manager) throws Exception {
        manager.remove(accessManager);
    }
}
