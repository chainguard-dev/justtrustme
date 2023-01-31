# justtrustme

justtrust me is a demo/testing OIDC token issuer. It will accept any claims as query parameters and mint valid OIDC tokens with them.

Needless to say, __do not trust anything about this__.

Interesting endpoints:

- [/](https://justtrustme.dev/)
- [/token](https://justtrustme.dev/token)
- [/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true](https://justtrustme.dev/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true)
- [/keys](https://justtrustme.dev/keys)
- [/.well-known/openid-configuration](https://justtrustme.dev/.well-known/openid-configuration)

`?debug=true` is a special query arg that will render a decoded token.
