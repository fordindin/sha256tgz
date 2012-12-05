PROG= sha256tgz
CC=/usr/bin/clang

LDADD= -larchive -lz -lmd -lm
CFLAGS+= -Wall

.if defined(DEBUG)
CFLAGS+= -ggdb
.endif
.if defined(PROFILE)
CFLAGS+= -pg
.endif

.include <bsd.prog.mk>
