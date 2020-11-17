package org.keycloak.waffle.federation;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;

public class NTLMFederationProviderFactory implements UserStorageProviderFactory<NTLMFederationProvider> {
    public static final String PROVIDER_NAME = "waffle-ntlm";

    @Override
    public NTLMFederationProvider create(KeycloakSession session, ComponentModel model) {
        return new NTLMFederationProvider(session, new UserStorageProviderModel(model), this);
    }

    @Override
    public String getId() {
        return PROVIDER_NAME;
    }
}
