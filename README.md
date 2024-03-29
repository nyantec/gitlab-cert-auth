## X.509 Client Certificate Authentication for GitLab FOSS

Configure our reverse proxy to forward requests to `/cert-auth/` to `http://127.0.0.1:8123/`, and add the X-SSL-Client-Dn header. With nginx your configuration might look like this:

```
...
		ssl_client_certificate CA.pem;
		ssl_verify_client on;
		ssl_verify_depth 1;

		location /cert-auth/ {
			proxy_pass http://127.0.0.1:8123/;
			proxy_set_header X-SSL-Client-Dn $ssl_client_s_dn;
		}
...
```

Then, adjust the omniauth options in your `gitlab.yml`:
```
...
    "omniauth": {
      "allow_single_sign_on": [
        "jwt"
      ],
      "auto_sign_in_with_provider": "jwt",
      "block_auto_created_users": false,
      "enabled": true,
      "providers": [
        {
          "args": {
            "algorithm": "HS256",
            "auth_url": "/cert-auth/",
            "info_maps": {
              "email": "email",
              "name": "name"
            },
            "required_claims": [
              "name",
              "email"
            ],
            "secret": "xxx",
            "uid_claim": "email",
            "valid_within": 3600
          },
          "name": "jwt"
        }
      ]
    },
...
```

# License

```
Copyright © 2021 nyantec GmbH <oss@nyantec.com>

Authors:
  Milan Pässler <mil@nyantec.com>

Provided that these terms and disclaimer and all copyright notices
are retained or reproduced in an accompanying document, permission
is granted to deal in this work without restriction, including un‐
limited rights to use, publicly perform, distribute, sell, modify,
merge, give away, or sublicence.

This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to
the utmost extent permitted by applicable law, neither express nor
implied; without malicious intent or gross negligence. In no event
may a licensor, author or contributor be held liable for indirect,
direct, other damage, loss, or other issues arising in any way out
of dealing in the work, even if advised of the possibility of such
damage or existence of a defect, except proven that it results out
of said person’s immediate fault when using the work as intended.
```
