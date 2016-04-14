%%
%% JWT Library for Erlang.
%% Written by Peter Hizalev at Kato (http://kato.im)
%%

-module(ejwt).

-include_lib("public_key/include/public_key.hrl").

-export([pre_parse_jwt/1]).
-export([get_jwt_header/1]).
-export([parse_jwt/2]).
-export([parse_jwt/3]).
-export([jwt/3, jwt/4]).

jsx_decode_safe(Bin) ->
    R = try jsx:decode(Bin, [{labels, attempt_atom}])
        of List0 -> List0
        catch Err -> Err
        end,
    case R of
        {error, _} ->
            invalid;
        List when is_list(List) ->
            %% force absence of duplicate keys
            %% http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
            Keys = [K || {K, _} <- List],
            case length(lists:usort(Keys)) =:= length(Keys) of
                true ->
                    maps:from_list(List);
                false ->
                    invalid
            end;
        _ ->
            invalid
    end.

pre_parse_jwt(Token) ->
    case decode_jwt(split_jwt_token(Token)) of
        #{} = JwtMap ->
            JwtMap;
        invalid ->
            invalid
    end.

get_jwt_header(Token) ->
    case decode_jwt(split_jwt_token(Token)) of
        #{header := HeaderMap } ->
            HeaderMap;
        invalid ->
            invalid
    end.

parse_jwt(Token, Key) ->
    parse_jwt(Token, Key, undefined).

parse_jwt(Token, Key, FallbackType) ->
    SplitToken = split_jwt_token(Token),
    case decode_jwt(SplitToken) of
        #{header := HeaderMap,
          claims := ClaimSetMap,
          signature := Signature} ->
            [Header, ClaimSet | _] = SplitToken,
            Type = case maps:get(typ, HeaderMap, undefined) of
                       undefined -> FallbackType;
                       T -> T
                   end,
            Alg  = maps:get(alg, HeaderMap, undefined),
            SignatureOk = parse_jwt_check_sig(Type, Alg, Header,
                                              ClaimSet, Signature, Key),
            Expired = parse_jwt_has_expired(ClaimSetMap),
            case {SignatureOk, Expired} of
                {true, false} -> ClaimSetMap;
                {false, _} -> invalid;
                {true, true} -> expired
            end;
        invalid -> invalid
    end.

parse_jwt_has_expired(ClaimSetMap) ->
    Expiry  = maps:get(exp, ClaimSetMap, none),
    case Expiry of
        none ->
            false;
        _ ->
            case (Expiry - epoch()) of
                DeltaSecs when DeltaSecs > 0 ->
                    false;
                _ ->
                    true
            end
    end.

parse_jwt_check_sig(<<"JWT">>, Alg, Header, ClaimSet, Signature, Key) ->
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    jwt_check_signature(Signature, Alg, Payload, Key).

split_jwt_token(Token) ->
    binary:split(Token, [<<".">>], [global]).

decode_jwt([Header, ClaimSet, Signature]) ->
    [HeaderMap, ClaimSetMap] =
    Decoded = [jsx_decode_safe(base64url:decode(X)) || X <- [Header, ClaimSet]],
    case lists:any(fun(E) -> E =:= invalid end, Decoded) of
        true  -> invalid;
        false -> #{
          header => HeaderMap,
          claims => ClaimSetMap,
          signature => Signature}
    end;
decode_jwt(_) ->
    invalid.

jwt(Alg, ClaimSetMap, ExpirationSeconds, Key) ->
    ClaimSetExpMap = jwt_add_exp(ClaimSetMap, ExpirationSeconds),
    jwt(Alg, ClaimSetExpMap, Key).

jwt(Alg, ClaimSetMap, Key) ->
    ClaimSet = base64url:encode(jsx:encode(ClaimSetMap)),
    Header = base64url:encode(jsx:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    jwt_return_signed(Alg, Payload, Key).

jwt_return_signed(Alg, Payload, Key) ->
    case jwt_sign(Alg, Payload, Key) of
        alg_not_supported ->
            alg_not_supported;
        Signature ->
            <<Payload/binary, ".", Signature/binary>>
    end.


jwt_add_exp(ClaimSetMap, ExpirationSeconds) ->
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
    maps:put(exp, Expiration, ClaimSetMap).


jwt_check_signature(EncSignature, <<"RS256">>, Payload, #'RSAPublicKey'{} =
                    PublicKey) ->
    Signature = base64url:decode(EncSignature),
    public_key:verify(Payload, sha256, Signature, PublicKey);
jwt_check_signature(EncSignature, <<"RS256">>, Payload, PublicKey)
  when is_list(PublicKey) ->
    Signature = base64url:decode(EncSignature),
    crypto:verify(rsa, sha256, Payload, Signature, PublicKey);
jwt_check_signature(Signature, <<"HS256">>, Payload, SharedKey) ->
    Signature =:= jwt_sign(hs256, Payload, SharedKey).

jwt_sign(rs256, Payload, Key) when is_list(Key)->
    base64url:encode(crypto:sign(rsa, sha256, Payload, Key));
jwt_sign(rs256, Payload, #'RSAPrivateKey'{} = Key) ->
    base64url:encode(public_key:sign(Payload, sha256, Key));
jwt_sign(hs256, Payload, Key) ->
    base64url:encode(crypto:hmac(sha256, Key, Payload));
jwt_sign(_, _, _) ->
    alg_not_supported.

jwt_header(rs256) ->
    #{ alg => <<"RS256">>, typ => <<"JWT">>};
jwt_header(hs256) ->
    #{ alg => <<"HS256">>, typ => <<"JWT">>}.

epoch() ->
    UniversalNow = calendar:now_to_universal_time(os:timestamp()),
    calendar:datetime_to_gregorian_seconds(UniversalNow) - 719528 * 24 * 3600.
