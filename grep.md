syntax

```bash
grep [option] pattern file
```

options:

```
-c : This prints only a count of the lines that match a pattern
-h : Display the matched lines, but do not display the filenames.
-i : Ignores, case for matching
-l : Displays list of a filenames only.
-n : Display the matched lines and their line numbers.
-v : This prints out all the lines that do not matches the pattern
-e exp : Specifies expression with this option. Can use multiple times.
-f file : Takes patterns from file, one per line.
-E : Treats pattern as an extended regular expression (ERE)
-w : Match whole word
-o : Print only the matched parts of a matching line,
 with each such part on a separate output line.

-A n: Prints searched line and nlines after the result.
-B n : Prints searched line and n line before the result.
-C n : Prints searched line and n lines after before the result.
```

Examples:

- print only a count of selected lines per FILE → `-c`
- Ignore case→ `-i`
- take PATTERNS from FILE → `-f filename`

```bash
grep -ic -f pattern *.js

# output=>
# class-extends.js:4
# constructor.js:16
# factory.js:20
# main.js:26
# time.js:0
# timer.js:0
```

- Display only match `-o`
- Show line `-n`
- Extend Regular Expression `-E`

```bash
grep -on -E '(ht|f|sf)tp(s?\:\/\/).*\.txt' test.txt
```

test.txt is:

```bash
#> cat test.txt
https://google.com/a.js
http://mrcatdev.com/docs/info.txt
ftp://mrcatdev.com/link/file.txt
ftp://mrcatdev.ir/files/doc2.html
```

output:

```bash
#> grep -on -E '(ht|f|sf)tp(s?\:\/\/).*\.txt' test.txt
2:http://mrcatdev.com/docs/info.txt
3:ftp://mrcatdev.com/link/file.txt
```

- Count how many lines there are in the file /etc/passwd.
    - `[[:alnum:]]` both digit and alphabatic
    - count of the lines that matche the pattern

```bash
# wc
wc -l /etc/passwd
# Grep
grep -c '[[:alnum:]]' /etc/passwd
```
