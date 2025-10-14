#!/bin/sh

#cd /root/ljg/DellLog
#pwd | more

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

echo "gcc .o files..."

gcc -w -static  ./cli.o ./main.o ./mem.o ./kvm.o ./utils.o  -o ./dell -lkvm -O0 -g


