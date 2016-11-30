PROJECT = ejwt

DEPS = jiffy base64url ej

dep_jiffy       = git git://github.com/davisp/jiffy.git      d16a4fd968e000b65e4678cccfad68d7a0a8bd1c
dep_base64url   = git git://github.com/inaka/base64url.git   bab9f431693a8888528d5c2db933c6f222c6fd44
dep_ej          = git git://github.com/seth/ej.git           0332523799fdbab4b7c8e87074dcf57bb15005a6


include erlang.mk



