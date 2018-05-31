package org.keycloak.waffle.federation;

import org.keycloak.models.UserModel;
import org.keycloak.models.utils.UserModelDelegate;

public class ReadOnlyUserModelDelegate extends UserModelDelegate {

    protected NTLMFederationProvider provider;

    public ReadOnlyUserModelDelegate(UserModel user, NTLMFederationProvider ntlmFederationProvider) {
        super(user);
        this.provider = ntlmFederationProvider;
    }
}
