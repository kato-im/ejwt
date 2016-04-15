PROJECT = ejwt 

DEPS = jsx base64url
BUILD_DEPS = elvis_mk
DEP_PLUGINS = elvis_mk

dep_jsx = git https://github.com/talentdeficit/jsx.git v2.8.0 
dep_base64url = git https://github.com/dvv/base64url.git v1.0 

dep_elvis_mk = git https://github.com/inaka/elvis.mk.git 215616a

COVER = 1

include erlang.mk
