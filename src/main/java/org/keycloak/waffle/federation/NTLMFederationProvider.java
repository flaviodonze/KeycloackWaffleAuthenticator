package org.keycloak.waffle.federation;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialAuthentication;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.*;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportedUserValidation;
import org.keycloak.waffle.NTLMCredentialInput;
import waffle.windows.auth.IWindowsAccount;
import waffle.windows.auth.IWindowsIdentity;

import java.util.HashMap;
import java.util.Map;

public class NTLMFederationProvider implements UserStorageProvider,
        CredentialAuthentication,
        ImportedUserValidation {
    private KeycloakSession session;
    private UserStorageProviderModel userStorageProviderModel;
    private NTLMFederationProviderFactory factory;
    private static final Logger logger = Logger.getLogger(NTLMFederationProvider.class);

    public NTLMFederationProvider(KeycloakSession session
            , UserStorageProviderModel userStorageProviderModel
            , NTLMFederationProviderFactory ntlmFederationProviderFactory) {
        this.session = session;
        this.userStorageProviderModel = userStorageProviderModel;
        factory = ntlmFederationProviderFactory;
    }

    @Override
    public void close() {
    }

    @Override
    public boolean supportsCredentialAuthenticationFor(String type) {
        return NTLMCredentialInput.NTLM_CREDENTIAL_TYPE.equals(type);
    }

    @Override
    public CredentialValidationOutput authenticate(RealmModel realm, CredentialInput input) {
        if (!(input instanceof NTLMCredentialInput)) return null;
        NTLMCredentialInput credential = (NTLMCredentialInput) input;
        if (credential.getType().equals(NTLMCredentialInput.NTLM_CREDENTIAL_TYPE)) {
            IWindowsIdentity windowsIdentity = credential.getWindowsIdentity();

            Map<String, String> state = new HashMap<String, String>();
            if (!windowsIdentity.isGuest()) {
                String username = extractUserWithoutDomain(windowsIdentity.getFqn());
                UserModel user = findOrCreateAuthenticatedUser(realm
                        , username
                        , windowsIdentity.getGroups()
                        , windowsIdentity.getSidString());
                if (user == null) {
                    return CredentialValidationOutput.failed();
                } else {
                    return new CredentialValidationOutput(user, CredentialValidationOutput.Status.AUTHENTICATED, state);
                }
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    private UserModel findOrCreateAuthenticatedUser(RealmModel realm, String username, IWindowsAccount[] groups, String sidString) {
        UserModel user = session.userLocalStorage().getUserByUsername(username, realm);
        if (user != null) {
            user = session.users().getUserById(user.getId(), realm);  // make sure we get a cached instance
            logger.debug("NTLM authenticated user " + username + " found in Keycloak storage");

            if (!userStorageProviderModel.getId().equals(user.getFederationLink())) {
                logger.warn("User with username " + username + " already exists, but is not linked to provider [" + userStorageProviderModel.getName() + "]");
                return null;
            } else {
                onImportUserFromLDAP(groups, user, realm, false);
                UserModel proxied = validate(realm, user);
                if (proxied != null) {
                    return proxied;
                } else {
                    logger.warn("User with username " + username + " already exists and is linked to provider [" + userStorageProviderModel.getName() +
                            "] but NTLM principal is not correct. NTLM principal on user is: " + user.getId());
                    logger.warn("Will re-create user");
                    new UserManager(session).removeUser(realm, user, session.userLocalStorage());
                }
            }
        }

        logger.debug("Kerberos authenticated user " + username + " not in Keycloak storage. Creating him");
        return importUserToKeycloak(realm, sidString, username, groups);
    }

    private UserModel importUserToKeycloak(RealmModel realm
            , String sidString
            , String username
            , IWindowsAccount[] groups) {
        // Just guessing email from kerberos realm

        logger.debugf("Creating NTLM user: %s, to local Keycloak storage", username);
        UserModel user = session.userLocalStorage().addUser(realm, username);
        user.setEnabled(true);
        user.setFederationLink(userStorageProviderModel.getId());
        user.setSingleAttribute("SID", sidString);
        onImportUserFromLDAP(groups, user, realm, true);

        user.addRequiredAction(UserModel.RequiredAction.UPDATE_PROFILE);

        return validate(realm, user);
    }

    private String extractUserWithoutDomain(String username) {
        if (username.contains("\\")) {
            username = username.substring(username.indexOf("\\") + 1, username.length());
        }
        return username;
    }

    public boolean isValid(RealmModel realm, UserModel local) {
        return true;
    }

    @Override
    public UserModel validate(RealmModel realm, UserModel user) {
        if (!isValid(realm, user)) {
            return null;
        }

        return new ReadOnlyUserModelDelegate(user, this);
    }

    public void onImportUserFromLDAP(IWindowsAccount[] groups, UserModel user, RealmModel realm, boolean isCreate) {
        for (IWindowsAccount account : groups) {
            String roleName = account.getName();

            RoleModel role = realm.getRole(roleName);

            if (role == null) {
                role = realm.addRole(roleName);
            }

            logger.debugf("Granting role [%s] to user [%s] during import from NTLM", roleName, user.getUsername());
            user.grantRole(role);
        }
    }

}
