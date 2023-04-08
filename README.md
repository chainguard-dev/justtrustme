# justtrustme

justtrust me is a demo/testing OIDC token issuer. It will accept any claims as
query parameters (or POST body using JSON encoding) and mint valid OIDC tokens
with them.

Needless to say, __do not trust anything about this__.

Interesting endpoints:

- [/](https://justtrustme.dev/)
- [/token](https://justtrustme.dev/token)
- [/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true](https://justtrustme.dev/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true)
- [/keys](https://justtrustme.dev/keys)
- [/.well-known/openid-configuration](https://justtrustme.dev/.well-known/openid-configuration)

`?debug=true` is a special query arg that will render a decoded token.

You can also POST a JSON struct that contains the keys. This allows for embedded
queries for example. As an example:
`curl -X POST 'https://justtrustme.dev/token?debug=true&foo=bar' -d '{"key1":"value1","embedded":{"key2":"value2","key3":"value3"}}'`

Would create the following claims:
```
	"payload": {
		"embedded": {
			"key2": "value2",
			"key3": "value3"
		},
		"exp": 1680999300,
		"foo": "bar",
		"iat": 1680997500,
		"iss": "https://justtrustme.dev",
		"key1": "value1"
	}
```
