#!/bin/sh



echo "delete old files..."
rm -rf ./dell
rm -rf ./*.o
echo "gcc -c .c files..."

#if compile (-c) in gcc but with link parameters will cause this warning:linker input unused because linking not done

gcc -c  -w  ./utils.c

gcc -c  -w  ./kvm.c

gcc -c  -w  ./mem.c

gcc -c -w ./cli.c

gcc -c  -w  ./main.c

gcc -c  -w  ./kmp.c

echo "gcc .o files..."

gcc -w -static  ./cli.o ./kvm.o ./mem.o  ./utils.o ./kmp.o ./main.o -o ./dell_clear -lkvm -O0 -g


