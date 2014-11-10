all: mquery mhttp

mhttp: mhttp.c
	$(CC) -fdiagnostics-color=always -Wno-pointer-sign -Os -g -o mhttp mhttp.c mdnsd.c 1035.c sdtxt.c xht.c

pos: pos.c
	$(CC) -fdiagnostics-color=always -Wno-pointer-sign -Wno-parentheses -Os -g -o pos pos.c mdnsd.c 1035.c

mquery: mquery.c
	$(CC) -Os -g -o mquery mquery.c mdnsd.c 1035.c

clean:
	rm -f mquery mhttp pos
