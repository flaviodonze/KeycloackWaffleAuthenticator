# keycloak-waffle-authenticator

Keycloack authenticator module using waffle.<br/>
Uses SPI as per Keycloak documentation. The waffle usage is little altered, because of http request usage.

Author: bogdan <bogdan.tudor@nn.ro> and flavio.donze <flavio.donze@scodi.ch>

Tested with keycloak-11.0.3

## Keycloak behind [nginx](http://nginx.org/) - reverse proxy

It is important to use a upstream configuration with keepalive as proxy_pass, also the here declared proxy parameters are required otherwise will run into an excpetion:
> com.sun.jna.platform.win32.Win32Exception: The token supplied to the function is invalid

	upstream keycloak_backend {
		server 127.0.0.1:9091;
		keepalive 16;
	}

	server {
		...
		location /auth/ {
			# required for SSO through NTLM
			proxy_set_header Connection "";
			proxy_http_version 1.1;

			proxy_pass http://keycloak_backend/auth/;
		} 
	}
