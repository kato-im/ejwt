%%
%% JWT Library for Erlang.
%% Written by Peter Hizalev at Kato (http://kato.im)
%%

-module(ejwt).

-export([pre_parse_jwt/1]).
-export([parse_jwt/2]).
-export([parse_jwt_iss_sub/2]).
-export([jwt/3, jwt/4, jwt/5]).
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

pre_parse_jwt(Token) ->
    case decode_jwt(split_jwt_token(Token)) of
        {_HeaderJterm, ClaimSetJterm, _Signature} ->
            ClaimSetJterm;
        invalid ->
            invalid
    end.

parse_jwt(Token, Key) ->
    SplitToken = split_jwt_token(Token),
    case decode_jwt(SplitToken) of
        {HeaderJterm, ClaimSetJterm, Signature} ->
            [Header, ClaimSet | _] = SplitToken,
            Type = ej:get({<<"typ">>}, HeaderJterm),
            Alg  = ej:get({<<"alg">>}, HeaderJterm),
            case parse_jwt_check_sig(Type, Alg, Header, ClaimSet, Signature, Key) of
                false -> invalid;
                true ->
                    case parse_jwt_has_expired(ClaimSetJterm) of
                        true  -> expired;
                        false -> ClaimSetJterm
                    end
            end;
        invalid -> invalid
    end.

parse_jwt_has_expired(ClaimSetJterm) ->
    Expiry = ej:get({<<"exp">>}, ClaimSetJterm, none),
    case Expiry of
        none ->
            false;
        _ ->
            case (ej:get({<<"exp">>}, ClaimSetJterm) - epoch()) of
                DeltaSecs when DeltaSecs > 0 ->
                    false;
                _ ->
                    true
            end
    end.

parse_jwt_check_sig(<<"JWT">>, Alg, Header, ClaimSet, Signature, Key) ->
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    jwt_sign(Alg, Payload, Key) =:= Signature.

split_jwt_token(Token) ->
    binary:split(Token, [<<".">>], [global]).

decode_jwt([Header, ClaimSet, Signature]) ->
    [HeaderJterm, ClaimSetJterm] =
        Decoded = [jiffy_decode_safe(base64url:decode(X)) || X <- [Header, ClaimSet]],
    case lists:any(fun(E) -> E =:= invalid end, Decoded) of
        true  -> invalid;
        false -> {HeaderJterm, ClaimSetJterm, Signature}
    end;
decode_jwt(_) ->
    invalid.

parse_jwt_iss_sub(Token, Key) ->
    case parse_jwt(Token, Key) of
        invalid ->
            invalid;
        expired ->
            expired;
        ClaimSetJterm ->
            {ej:get({<<"iss">>}, ClaimSetJterm), ej:get({<<"sub">>}, ClaimSetJterm)}
    end.

jwt(Alg, ClaimSetJterm, Key) ->
    jwt(Alg, ClaimSetJterm, undefined, Key).

jwt(Alg, ClaimSetJterm, ExpirationSeconds, Key) ->
    jwt(Alg, ClaimSetJterm, ExpirationSeconds, [], Key).

jwt(Alg, ClaimSetJterm, ExpirationSeconds, Extra_Headers, Key) ->
    Effective_Claims = apply_expiration(ExpirationSeconds, ClaimSetJterm),
    ClaimSet = base64url:encode(jiffy:encode(Effective_Claims)),
    Header = base64url:encode(jiffy:encode(jwt_header(Alg, Extra_Headers))),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    case jwt_sign(Alg, Payload, Key) of
        alg_not_supported ->
            alg_not_supported;
        Signature ->
            <<Payload/binary, ".", Signature/binary>>
    end.

apply_expiration(undefined,         ClaimSetJterm) -> ClaimSetJterm;
apply_expiration(ExpirationSeconds, ClaimSetJterm) -> jwt_add_exp(ClaimSetJterm, ExpirationSeconds).

jwt_add_exp(ClaimSetJterm, ExpirationSeconds) ->
    {ClaimsSet} = ClaimSetJterm,
    Expiration = case ExpirationSeconds of
        {hourly, ExpirationSeconds0} ->
            Ts = epoch(),
            (Ts - (Ts rem 3600)) + ExpirationSeconds0;
        {daily, ExpirationSeconds0} ->
            Ts = epoch(),
            (Ts - (Ts rem (24*3600))) + ExpirationSeconds0;
        _ ->
            epoch() + ExpirationSeconds
    end,        
    {[{<<"exp">>, Expiration} | ClaimsSet]}.

jwt_hs256_iss_sub(Iss, Sub, ExpirationSeconds, Key) ->
    jwt(<<"HS256">>, {[
        {<<"iss">>, Iss},
        {<<"sub">>, Sub}
    ]}, ExpirationSeconds, Key).

jwt_sign(<<"HS256">>, Payload, Key) ->
    base64url:encode(crypto:hmac(sha256, Key, Payload));

jwt_sign(_, _, _) ->
    alg_not_supported.

jwt_header(Alg, Extra_Headers) ->
    {[
        {<<"alg">>, Alg},
        {<<"typ">>, <<"JWT">>} | Extra_Headers
    ]}.

epoch() ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_universal_time(os:timestamp())) - 719528 * 24 * 3600.
