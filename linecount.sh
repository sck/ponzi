#! /bin/sh

perl -ne 'print if /^\s*["\-\\(#{;a-zA-Z}]/' ponzi.c > a.c
gcc -o a a.c && wc  a.c
