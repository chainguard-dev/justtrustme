# justtrustme

justtrust me is a demo/testing OIDC token issuer. It will accept any claims as query parameters and mint valid OIDC tokens with them.

Needless to say, __do not trust anything about this__.

Interesting endpoints:

- [/](https://justtrustme.dev/)
- [/token](https://justtrustme.dev/token)
- [/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true](https://justtrustme.dev/token?aud=sts.amazonaws.com&likes_dogs=true&debug=true)
- [/token?foo=bar&MAP:embedded=key1=value1,key2=value2&debug=true"](https://justtrustme.dev/token?foo=bar&MAP:embedded=key1=value1,key2=value2&debug=true)
- [/keys](https://justtrustme.dev/keys)
- [/.well-known/openid-configuration](https://justtrustme.dev/.well-known/openid-configuration)

`?debug=true` is a special query arg that will render a decoded token.

Keys prefixed with `MAP:` is a special query arg that will allow for embedded
simple string=>string structures as embedded claims. For example, if you wanted
to provide foo=>bar as claim, but also a struct called embedded with
key1=>value1 and key2=>value2 that would then look like this:

```
	"payload": {
		"embedded": {
			"key1": "value1",
			"key2": "value2"
		},
		"exp": 1680895833,
		"foo": "bar"
    }
```

You would use this: `/token?foo=bar&MAP:embedded=key1=value1,key2=value2`
