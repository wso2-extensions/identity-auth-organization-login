/*
 * Copyright (c) 2022-2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.organization.login.constant;

/**
 * Class for constants.
 */
public class AuthenticatorConstants {

    private AuthenticatorConstants() {

    }

    public static final String AUTHENTICATOR_NAME = "OrganizationAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "OrganizationLogin";

    public static final String AUTHORIZATION_ENDPOINT_ORGANIZATION_PATH = "oauth2/authorize";
    public static final String USERINFO_ENDPOINT_ORGANIZATION_PATH = "oauth2/userinfo";
    public static final String USERINFO_URL = "UserInfoUrl";

    public static final String TOKEN_ENDPOINT_ORGANIZATION_PATH = "oauth2/token";
    public static final String ORGANIZATION_PLACEHOLDER = "{organization}";

    public static final String ORGANIZATION_ATTRIBUTE = "Organization";
    public static final String USER_ORGANIZATION_CLAIM = "user_organization";
    public static final String ORG_PARAMETER = "org";
    public static final String IDP_PARAMETER = "idp";
    public static final String AUTHENTICATOR_PARAMETER = "authenticator";
    public static final String ORG_ID_PARAMETER = "orgId";
    public static final String ORG_COUNT_PARAMETER = "orgCount";
    public static final String ORG_DESCRIPTION_PARAMETER = "orgDesc";
    public static final String ORG_DISCOVERY_PARAMETER = "orgDiscovery";
    public static final String ORG_DISCOVERY_ENABLED_PARAMETER = "orgDiscoveryEnabled";
    public static final String ORG_DISCOVERY_TYPE_PARAMETER = "orgDiscoveryType";
    public static final String PROMPT_PARAMETER = "prompt";
    public static final String ORGANIZATION_DISCOVERY_TYPE = "discoveryType";
    public static final String ORGANIZATION_NAME = "orgName";
    public static final String ENABLE_CONFIG = ".enable";
    public static final String LOGIN_HINT_PARAMETER = "login_hint";
    public static final String SP_ID_PARAMETER = "spId";

    public static final String ORGANIZATION_LOGIN_FAILURE = "organizationLoginFailure";
    public static final String ERROR_MESSAGE = "&authFailure=true&authFailureMsg=";

    public static final String REQUEST_ORG_PAGE_URL = "authenticationendpoint/org_name.do";
    public static final String REQUEST_ORG_SELECT_PAGE_URL = "authenticationendpoint/select_org.do";
    public static final String REQUEST_ORG_DISCOVERY_PAGE_URL = "authenticationendpoint/org_discovery.do";
    public static final String REQUEST_ORG_PAGE_URL_CONFIG = "RequestOrganizationPage";
    public static final String INBOUND_AUTH_TYPE_OAUTH = "oauth2";
    public static final String APP_ROLES_SCOPE = "app_roles";

    public static final String EQUAL_SIGN = "=";
    public static final String AMPERSAND_SIGN = "&";
    public static final String ID_TOKEN_ORG_ID_PARAM = "org_id";
    public static final String OIDC_CLAIM_DIALECT_URL = "http://wso2.org/oidc/claim";

    public static final String SAML_RESP = "SAMLResponse";
}
