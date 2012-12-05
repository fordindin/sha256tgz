PROG= sha256tgz

LDADD= -larchive -lz -lmd -lm
CFLAGS+= -ggdb -Wall

.include <bsd.prog.mk>
