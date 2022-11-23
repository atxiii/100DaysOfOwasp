#!/bin/bash
NUMBER=$(($RANDOM % 23))

for ((run=1; run <= NUMBER + 1; run++))
do
  fortune -a > ~/workspace/100DaysOfOwasp/files/file.txt
  git add .
  git commit -m "`fortune -sn 32`"
done

