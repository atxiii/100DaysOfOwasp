BEGIN {FS = "\t"} {printf "%5s(%s)\n" , $1, $NF}
