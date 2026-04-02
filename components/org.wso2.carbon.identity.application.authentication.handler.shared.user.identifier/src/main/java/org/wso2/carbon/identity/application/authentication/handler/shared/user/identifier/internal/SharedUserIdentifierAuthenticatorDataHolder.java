/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal;

import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for Shared User Identifier Handler.
 */
public class SharedUserIdentifierAuthenticatorDataHolder {

    private static final SharedUserIdentifierAuthenticatorDataHolder instance =
            new SharedUserIdentifierAuthenticatorDataHolder();

    private RealmService realmService;
    private OrganizationUserSharingService organizationUserSharingService;
    private OrganizationManager organizationManager;

    private SharedUserIdentifierAuthenticatorDataHolder() {

    }

    /**
     * Get the singleton instance of SharedUserIdentifierAuthenticatorDataHolder.
     *
     * @return SharedUserIdentifierAuthenticatorDataHolder instance.
     */
    public static SharedUserIdentifierAuthenticatorDataHolder getInstance() {

        return instance;
    }

    /**
     * Get the Realm Service.
     *
     * @return RealmService instance.
     */
    public RealmService getRealmService() {

        return realmService;
    }

    /**
     * Set the Realm Service.
     *
     * @param realmService RealmService instance.
     */
    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Get the Organization User Sharing Service.
     *
     * @return OrganizationUserSharingService instance.
     */
    public OrganizationUserSharingService getOrganizationUserSharingService() {

        return organizationUserSharingService;
    }

    /**
     * Set the Organization User Sharing Service.
     *
     * @param organizationUserSharingService OrganizationUserSharingService instance.
     */
    public void setOrganizationUserSharingService(OrganizationUserSharingService organizationUserSharingService) {

        this.organizationUserSharingService = organizationUserSharingService;
    }

    /**
     * Get the Organization Manager.
     *
     * @return OrganizationManager instance.
     */
    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    /**
     * Set the Organization Manager.
     *
     * @param organizationManager OrganizationManager instance.
     */
    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }
}
