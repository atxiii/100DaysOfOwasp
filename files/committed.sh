#!/bin/bash
NUMBER=$(($RANDOM % 23))
P=/home/mrcat/workspace/100DaysOfOwasp/
for ((run=1; run <= NUMBER + 1; run++))
do
	fortune -a > $P/files/file.txt
  git -C $P add .
  git -C $P commit -m "`fortune -sn 32`"
done

