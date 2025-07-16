#!/bin/sh

echo 'R"FFIContent('
cat $1 $2
echo ')FFIContent"'
