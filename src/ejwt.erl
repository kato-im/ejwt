%%
%% JWT Library for Erlang.
%% Written by Peter Hizalev at Kato (http://kato.im)
%%

-module(ejwt).

-export([parse_jwt/2]).
-export([parse_jwt_iss_sub/2]).
-export([jwt/4]).
-export([jwt_hs256_iss_sub/4]).

jiffy_decode_safe(Bin) ->
    R = try jiffy:decode(Bin) of Jterm0 -> Jterm0 catch Err -> Err end,
    case R of
        {error, _} ->
            invalid;
        {List} = Jterm ->
            %% force absence of duplicate keys http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#Claims
            Keys = [K || {K, _} <- List],
            case length(lists:usort(Keys)) =:= length(Keys) of
                true ->
                    Jterm;
                false ->
                    invalid
            end;
        _ ->
            invalid
    end.

parse_jwt(Token, Key) ->
    case binary:split(Token, [<<".">>], [global]) of
        [Header, ClaimSet, Signature] ->
            case jiffy_decode_safe(base64url:decode(Header)) of
                invalid ->
                    invalid;
                HeaderJterm ->
                    case {ej:get({<<"typ">>}, HeaderJterm), ej:get({<<"alg">>}, HeaderJterm)} of
                        {<<"JWT">>, Alg} ->
                            Payload = <<Header/binary, ".", ClaimSet/binary>>,
                            case jwt_sign(Alg, Payload, Key) of
                                Signature ->
                                    case jiffy_decode_safe(base64url:decode(ClaimSet)) of
                                        invalid ->
                                            invalid;
                                        ClaimSetJterm ->
                                            case (ej:get({<<"exp">>}, ClaimSetJterm) - lechat_utils:epoch()) of
                                                DeltaSecs when DeltaSecs > 0 ->
                                                    ClaimSetJterm;
                                                _ ->
                                                    expired
                                            end
                                    end;
                                _ ->
                                    invalid
                            end;
                        _ ->
                            invalid
                    end
            end;
        _ ->
            invalid
    end.

parse_jwt_iss_sub(Token, Key) ->
    case parse_jwt(Token, Key) of
        invalid ->
            invalid;
        expired ->
            expired;
        ClaimSetJterm ->
            {ej:get({<<"iss">>}, ClaimSetJterm), ej:get({<<"sub">>}, ClaimSetJterm)}
    end.

jwt(Alg, ClaimSetJterm, ExpirationSeconds, Key) ->
    ClaimSet = base64url:encode(jiffy:encode(jwt_add_exp(ClaimSetJterm, ExpirationSeconds))),
    Header = base64url:encode(jiffy:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    case jwt_sign(Alg, Payload, Key) of
        alg_not_supported ->
            alg_not_supported;
        Signature ->
            <<Payload/binary, ".", Signature/binary>>
    end.

jwt_add_exp(ClaimSetJterm, ExpirationSeconds) ->
    {ClaimsSet} = ClaimSetJterm,
    {[{<<"exp">>, lechat_utils:epoch() + ExpirationSeconds} | ClaimsSet]}.

jwt_hs256_iss_sub(Iss, Sub, ExpirationSeconds, Key) ->
    jwt(<<"HS256">>, {[
        {<<"iss">>, Iss},
        {<<"sub">>, Sub}
    ]}, ExpirationSeconds, Key).

jwt_sign(<<"HS256">>, Payload, Key) ->
    base64url:encode(crypto:hmac(sha256, Key, Payload));

jwt_sign(_, _, _) ->
    alg_not_supported.

jwt_header(Alg) ->
    {[
        {<<"alg">>, Alg},
        {<<"typ">>, <<"JWT">>}
    ]}.
