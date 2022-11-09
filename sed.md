# SED
Sed stands for Stream Editor. The sed is a text processing.This is a “non-interactive” stream-oriented editor. This command dosen’t change the content of original file and it works with buffers. sed has two buffers which are called `pattern buffer` and `hold buffer` ,both are initially empty. sed reads from a file or stdin, and outputs to its stdout .

- syntax

```bash
sed [options]…  [script] [file]
```

## Printing from the pattern buffer - `p`

- `p` is a command for printing the data from the pattern buffer(space). (sites-list file [here](./files/sites-list))

```bash
> sed 's/com/net/p' files/sites-list
mrcatdev.net
mrcatdev.net
google.net
google.net
memoryleaks.ir

> sed 's/com/net/'p files/sites-list
mrcatdev.net
mrcatdev.net
google.net
google.net
memoryleaks.ir
```

- `-n` option:

To suppress automatic printing of pattern space use -n command with sed. sed -n option will not print anything, unless an explicit request to print is found

```bash
> sed 's/com/net/'p -n files/sites-list
mrcatdev.net
google.net
```

- print specific a line of file

```bash
# print line 2
> sed '2'p -n files/sites-list
google.com

# print line 1
> sed '1'p -n files/sites-list
mrcatdev.com

#print line 3
> sed '3'p -n files/sites-list
memoryleaks.ir

#print line 4 ( not exist )
> sed '4'p -n files/sites-list
```

- print from a specific line with step `~` ([customer.txt](./files/customer.txt))

```bash
# Start from line 2 step 1
> sed '2~1'p -n files/customer.txt
10248   Wilman Kala     Federal Shipping
10249   Tradição Hipermercados  Speedy Express
10250   Hanari Carnes   United Package
10251   Victuailles en stock    Speedy Express
10252   Suprêmes délices        United Package
10253   Hanari Carnes   United Package
10254   Chop-suey Chinese       United Package
10255   Richter Supermarkt      Federal Shipping
10256   Wellington Importadora  United Package
10257   HILARIÓN-Abastos        Federal Shipping
10258   Ernst Handel    Speedy Express
10259   Centro comercial Moctezuma      Federal Shipping
10260   Old World Delicatessen  Speedy Express
10261   Que Delícia     United Package
10262   Rattlesnake Canyon Grocery      Federal Shipping
10263   Ernst Handel    Federal Shipping
10264   Folk och fä HB  Federal Shipping
10265   Blondel père et fils    Speedy Express
10266   Wartian Herkku  Federal Shipping
10267   Frankenversand  Speedy Express
10268   GROSELLA-Restaurante    Federal Shipping
10269   White Clover Markets    Speedy Express
10270   Wartian Herkku  Speedy Express
10271   Split Rail Beer & Ale   United Package

# Start from line 2 step 5
> sed '2~5'p -n files/customer.txt
10248   Wilman Kala     Federal Shipping
10253   Hanari Carnes   United Package
10258   Ernst Handel    Speedy Express
10263   Ernst Handel    Federal Shipping
10268   GROSELLA-Restaurante    Federal Shipping
```

- Print from start a line to another line number. `,`

```bash
# start from line 1 to line 3
> sed '1,3'p -n files/customer.txt
OrderID CustomerName    ShipperName
10248   Wilman Kala     Federal Shipping
10249   Tradição Hipermercados  Speedy Express
```

- Print last line `$` ([products.txt](./files/products.txt))

```bash
#print last line of products.txt
> sed '$'p -n files/products.txt
39      Chartreuse verte        18      1       750 cc per bottle       18
```

- Print from a line to end of file `$p`

```bash
# Note: this file has a header in line 1
> sed '36,$'p -n files/products.txt
35      Steeleye Stout  16      1       24 - 12 oz bottles      18
36      Inlagd Sill     17      8       24 - 250 g jars 19
37      Gravad lax      17      8       12 - 500 g pkgs.        26
38      Côte de Blaye   18      1       12 - 75 cl bottles      263.5
39      Chartreuse verte        18      1       750 cc per bottle       18
> sed '36,$p' -n files/products.txt
35      Steeleye Stout  16      1       24 - 12 oz bottles      18
36      Inlagd Sill     17      8       24 - 250 g jars 19
37      Gravad lax      17      8       12 - 500 g pkgs.        26
38      Côte de Blaye   18      1       12 - 75 cl bottles      263.5
39      Chartreuse verte        18      1       750 cc per bottle       18

sed '1,$p' -n files/products.txt
ProductID       ProductName     SupplierID      CategoryID      Unit    Price
1       Chais   1       1       10 boxes x 20 bags      18
2       Chang   1       1       24 - 12 oz bottles      19
3       Aniseed Syrup   1       2       12 - 550 ml bottles     10
4       Chef Anton's Cajun Seasoning    2       2       48 - 6 oz jars  22
5       Chef Anton's Gumbo Mix  2       2       36 boxes        21.35
6       Grandma's Boysenberry Spread    3       2       12 - 8 oz jars  25
7       Uncle Bob's Organic Dried Pears 3       7       12 - 1 lb pkgs. 30
8       Northwoods Cranberry Sauce      3       2       12 - 12 oz jars 40
9       Mishi Kobe Niku 4       6       18 - 500 g pkgs.        97
10      Ikura   4       8       12 - 200 ml jars        31
11      Queso Cabrales  5       4       1 kg pkg.       21
12      Queso Manchego La Pastora       5       4       10 - 500 g pkgs.        38
13      Konbu   6       8       2 kg box        6
14      Tofu    6       7       40 - 100 g pkgs.        23.25
15      Genen Shouyu    6       2       24 - 250 ml bottles     15.5
16      Pavlova 7       3       32 - 500 g boxes        17.45
17      Alice Mutton    7       6       20 - 1 kg tins  39
18      Carnarvon Tigers        7       8       16 kg pkg.      62.5
19      Teatime Chocolate Biscuits      8       3       10 boxes x 12 pieces    9.2
20      Sir Rodney's Marmalade  8       3       30 gift boxes   81
21      Sir Rodney's Scones     8       3       24 pkgs. x 4 pieces     10
22      Gustaf's Knäckebröd     9       5       24 - 500 g pkgs.        21
23      Tunnbröd        9       5       12 - 250 g pkgs.        9
24      Guaraná Fantástica      10      1       12 - 355 ml cans        4.5
25      NuNuCa Nuß-Nougat-Creme 11      3       20 - 450 g glasses      14
26      Gumbär Gummibärchen     11      3       100 - 250 g bags        31.23
27      Schoggi Schokolade      11      3       100 - 100 g pieces      43.9
28      Rössle Sauerkraut       12      7       25 - 825 g cans 45.6
29      Thüringer Rostbratwurst 12      6       50 bags x 30 sausgs.    123.79
30      Nord-Ost Matjeshering   13      8       10 - 200 g glasses      25.89
31      Gorgonzola Telino       14      4       12 - 100 g pkgs 12.5
32      Mascarpone Fabioli      14      4       24 - 200 g pkgs.        32
33      Geitost 15      4       500 g   2.5
34      Sasquatch Ale   16      1       24 - 12 oz bottles      14
35      Steeleye Stout  16      1       24 - 12 oz bottles      18
36      Inlagd Sill     17      8       24 - 250 g jars 19
37      Gravad lax      17      8       12 - 500 g pkgs.        26
38      Côte de Blaye   18      1       12 - 75 cl bottles      263.5
39      Chartreuse verte        18      1       750 cc per bottle       18
```

- Prints from the line matches the given pattern to end of file. `/pattern/,$p`

```bash
# print from lax pattern to end of file
> sed '/lax/,$p' -n files/products.txt
37      Gravad lax      17      8       12 - 500 g pkgs.        26
38      Côte de Blaye   18      1       12 - 75 cl bottles      263.5
39      Chartreuse verte        18      1       750 cc per bottle       18

# print journalctl from date Nov 09 to end of file
journalctl | sed '/Nov 09/, $p' -n | less
```

- Prints N next line `/pattern/Np`

```bash
Print pattern and next line
> sed '/lax/,+1p' -n files/products.txt
37      Gravad lax      17      8       12 - 500 g pkgs.        26
38      Côte de Blaye   18      1       12 - 75 cl bottles      263.5
```

## Append the contents of Holding space to Pattern space

The `G` function appends the contents of the holding area to the contents of the pattern space. The former and new contents are separated by a newline. The maximum number of addresses is two.

- Double Space with `G`

```bash
> sed 'G' files/passwords.txt
root

user

admin

123456789

administrator

test
```

- Add space except a specific line

```bash
# add space except line 2
> sed '2!G' files/passwords.txt
root

user
admin

123456789

administrator

test
```

- Add space then print last line

```bash
> sed 'G;$p' -n files/passwords.txt
test
# there is a space
```

## Copy from Holding area to Pattern area

The `h` (hold) function copies the contents of the pattern space into a holding area (also called as **sed hold space**), destroying any previous contents of the holding area.

```bash
> cat files/passwords2.txt
Admin
petter23
0129345
abcde24
oakasw

> sed -n '/^[0-9]/h;${x;p}' files/passwords2.txt
0129345

# ^[0-9]/h => if the line started with number copy it to hold space
# x => swap pattern with hold space

#Line------Command------Pattern Space-------Hold Space
# 1       ^[0-9]/h      Admin                 -
# 2       ^[0-9]/h      petter23              -
# 3       ^[0-9]/h      0129345             0129345
# 4       ^[0-9]/h      abcde24             0129345
# 5       ^[0-9]/h      oakasw              0129345
# >          x          0129345             oakasw
#            p          0129345             oakasw
```

- Print file content in reverse order

```bash
> sed -n '1!G;h;$p' files/passwords2.txt
oakasw
abcde24
0129345
petter23
Admin

#Line------Command------Pattern Space-------Hold Space
# 1         1!G          Admin              
#            h           Admin               Admin
#            p           Admin               Admin

# 2         1!G          petter23            Admin 
#                        Admin

#            h           petter23            petter23 
#                        Admin               Admin

#            p           petter23            petter23 
#                        Admin               Admin

# 3         1!G          0129345             petter23        
#                        petter23            Admin       
#                        Admin

#            h           0129345             0129345 
#                        petter23            petter23
#                        Admin               Admin

#            p           0129345             0129345 
#                        petter23            petter23
#                        Admin               Admin
```

## Search and Replace

1. `/s` indicates the search and replace task. 

```bash
echo "Hello Bash" | sed "s/Bash/zsh/"
# output => Hello zsh
```

1. Read file and serach and replace

```bash
> sed 's/mrcatdev/https:\/\/mrcatdev/' files/sites-list
https://mrcatdev.com
google.com
memoryleaks.ir
```

1. `g` option is used in `sed` command to replace all occurrences of matching pattern

```bash
> sed 's/com/org/g' files/sites-list
mrcatdev.org
google.org
memoryleaks.ir
```

1. Replace after the second occurrence of a match on each line by using `g2`

```bash
> sed 's/com/coooom/' files/sites-list | sed 's/o/O/g2'
mrcatdev.coOOOm
goOgle.cOOOOm
memoryleaks.ir
```

1. Replace the last occurrence of a match on each line by using `\1`

```bash
> sed 's/com/coooom/' files/sites-list | sed 's/\(.*\)o/\1O/'
mrcatdev.coooOm
google.coooOm
memOryleaks.ir
```

1. Replace the first match in a file by using `1`

```bash
 > sed '1 s/com/net/' files/sites-list
mrcatdev.net
google.com
memoryleaks.ir
```

1. Replace the last match in a file by using `$`

```bash
>  sed '$ s/m/M/' files/sites-list
mrcatdev.com
google.com
Memoryleaks.ir

>  sed '$ s/m/M/g' files/sites-list
mrcatdev.com
google.com
MeMoryleaks.ir
```

1. Substitute text 

```bash
# -e script, --expression=script | add the script to the commands to be executed
> sed -e '/Chais/ s/18/22/; /Chang/ s/19/25/;' files/products.txt | sed '1,3'p -n
ProductID       ProductName     SupplierID      CategoryID      Unit    Price
1      Chais   1       1       10   boxes x 20 bags              22
2      Chang   1       1       24 - 12 oz bottles              25
```

1. Substitute text with not operator `!`

```bash
# find and replace 'e' with xxxxxx except line which has 'p' 
> sed -e '/p/! s/e/xxxxx/i;' files/passwords2.txt
Admin
petter23
0129345
abcdxxxxx24
oakasw
```

1. Add string before and after the matching pattern using `\1` `\2` and …

```bash
> cat sites-list
mrcatdev.com
google.com
memoryleaks.ir

> sed 's/\(.*com\)/https:\/\/\1/g'  files/sites-list
https://mrcatdev.com
https://google.com
memoryleaks.ir
```

## Delete

**`d`** option is used in `sed` command to delete any line from the file.

```bash
> sed '/ir/d'  files/sites-list
mrcatdev.com
google.com
```

- Delete empty lines

```bash
> cat awk-tax.awk
#1 function tax(price){
#2                         tx=20;
#3                         return ((price * tx)/100)+price
#4 }
#5 
#6 BEGIN {
#7                         print "ENTER PRICE:"
#8                         getline p < "-"
#9                         print "Tax = " tax(p)
#10 }
> sed '/^$/d' awk-tax.awk
#1 function tax(price){
#2                         tx=20;
#3                         return ((price * tx)/100)+price
#4 }
#5 BEGIN {
#6                         print "ENTER PRICE:"
#7                         getline p < "-"
#8                         print "Tax = " tax(p)
#9 }

```
