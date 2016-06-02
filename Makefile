all: nconstraints

nconstraints: nconstraints.c
	gcc -O2 $^ -o $@ -lgnutls -ltasn1
