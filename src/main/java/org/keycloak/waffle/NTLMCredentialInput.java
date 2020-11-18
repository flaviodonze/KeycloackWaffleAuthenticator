package org.keycloak.waffle;

import org.keycloak.credential.CredentialInput;

import waffle.windows.auth.IWindowsIdentity;

public class NTLMCredentialInput implements CredentialInput {

	private final IWindowsIdentity windowsIdentity;
	public static final String NTLM_CREDENTIAL_TYPE = "NTLM";

	public NTLMCredentialInput(IWindowsIdentity windowsIdentity) {
		this.windowsIdentity = windowsIdentity;
	}

	@Override
	public String getType() {
		return NTLM_CREDENTIAL_TYPE;
	}

	public IWindowsIdentity getWindowsIdentity() {
		return windowsIdentity;
	}

	@Override
	public String getCredentialId() {
		return windowsIdentity != null ? windowsIdentity.getSidString() : null;
	}

	@Override
	public String getChallengeResponse() {
		return null;
	}
}
