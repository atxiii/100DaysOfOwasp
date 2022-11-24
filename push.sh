#!/bin/bash
git config --global --add safe.directory /home/mrcat/workspace/100DaysOfOwasp
bash /home/mrcat/workspace/100DaysOfOwasp/committed.sh
git -C /home/mrcat/workspace/100DaysOfOwasp/ push origin main
