Erlang JWT Library
=

JWT is a simple authorization token [format](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) based on JSON. [Peter Hizalev](http://twitter.com/petrohi) started this library at Kato.im and put it under open-source.
The library was enhanced with tests, stylechecking and the RS256 algorithm.

## Smoke test example

Compilation
```shell
   make
   make tests
```

In Erlang shell:

    %% Create JWT token
    application:start(crypto).
    Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>.
    Claims = {[
        {user_id, <<"bob123">>},
        {user_name, <<"Bob">>}
    ]}.
    ExpirationSeconds = 86400,
    Token = ejwt:jwt(<<"HS256">>, Claims, ExpirationSeconds, Key).

    %% Parse JWT token
    ejwt:parse_jwt(Token, Key).


You should get back the original claims Jterm, plus expiration claim:

    {[
        {<<"exp">>,1392607527},
        {<<"user_id">>,<<"bob123">>},
        {<<"user_name">>,<<"Bob">>}
    ]}

