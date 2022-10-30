#!/bin/bash
if [ -t 0 ]; then
				echo stdin coming from keyboard
else
				echo stdin coming from a pipe or a file
fi
