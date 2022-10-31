# awk
Awk is a utility that enables a programmer to write tiny but effective programs in the form of statements that define text patterns that are to be searched for in each line of a document and the action that is to be taken when a match is found within a line.

Syntax:

```bash
awk options 'selection _criteria {action }' input-file > output-file
#options 
# f => for read source from file
# F => for the input field separator
```

### **Print each line with {print}**

```bash
awk {print} ./files/products.txt
```

### **Print the lines which match the given pattern.**

```bash
awk '/express/i {print}' ./files/customer.txt
```

### **Splitting a Line Into Fields**

For each record i.e line, the awk command splits the record delimited by whitespace character by default and stores it in the $n variables.

```bash
awk '{print $1}' ./files/customer.txt | head
```

```bash

OrderID
10248
10249
10250
10251
10252
10253
10254
10255
10256
```

### **awk with tab-delimited data**

`FS` command contains the field separator character
`NR` command keeps a current count of the number of input records.

```bash
awk '{print NR, $2}' FS='\t' ./files/customer.txt | head
```

```bash
1 CustomerName
2 Wilman Kala
3 Tradição Hipermercados
4 Hanari Carnes
5 Victuailles en stock
6 Suprêmes délices
7 Hanari Carnes
8 Chop-suey Chinese
9 Richter Supermarkt
10 Wellington Importadora
```

### Using OFS variable with tab

```bash
ls -l |  awk -v OFS='->' 'BEGIN {printf "%s=>%s\n" , "Name", "Size"} {print $7,$2}'
```

- output

```bash
Name=>Size
grep.md->1.8k
helper->196
README.md->141
stdio.md->6.2k
```

### **awk with {printf}**

```bash
awk '{printf "%s- %s sending products via %s \n", NR,$2,$3 }' FS='\t' ./files/customer.txt| head
```

```bash
1- CustomerName sending products via ShipperName 
2- Wilman Kala sending products via Federal Shipping 
3- Tradição Hipermercados sending products via Speedy Express 
4- Hanari Carnes sending products via United Package 
5- Victuailles en stock sending products via Speedy Express 
6- Suprêmes délices sending products via United Package 
7- Hanari Carnes sending products via United Package 
8- Chop-suey Chinese sending products via United Package 
9- Richter Supermarkt sending products via Federal Shipping 
10- Wellington Importadora sending products via United Package
```

the first line shows our header texts, we can set our output start from line 2 with `NR>1`

```bash
awk 'NR>1 {printf "%s- %s sending products via %s \n", NR,$2,$3 }' FS='\t' ./files/customer.txt| head
```

### **Show last feild by `NF`**

`NF` is number of fileds and a built-in variable of awk.

```bash
awk 'NR>1 {printf "%s price is $%s \n" , $2 , $NF}' FS='\t' ./files/products.txt | head
```

### **awk with CSV data**

 **`-F`** option is used with awk command to set the delimiter for splitting each line of the file.

```bash
awk -F ',' 'NR>1 {print $1, "price is: " $3 }' ./files/data.csv
```

### **Reading CSV file using an awk script**

my-awk-script.awk

```bash
BEGIN {FS = "\t"} {printf "%5s(%s)\n" , $1, $NF}
```

```bash
awk -f ./files/my-awk-script.awk ./files/products.txt | head
```

- output:

```bash
ProductID(Price)
    1(18)
    2(19)
    3(10)
    4(22)
    5(21.35)
    6(25)
    7(30)
    8(40)
    9(97)
```

### awk with custom function

awk-tax.awk

```bash
function tax(price){
	tx=20;
	return ((price * tx)/100)+price
}

BEGIN {
	print "ENTER PRICE:"
	getline p < "-"
	print "Tax = " tax(p)
}
```

```bash
awk -f ./files/awk-tax.awk
# ENTER PRICE:
# 20
# Tax = 24
```

### awk with if

```bash
awk '{ if ($NF < 5) print "item-"NR,$2,"has affordable price!->"$NF"$" }' products.txt
```

```bash
item-25 Guaraná has affordable price!->4.5$
item-34 Geitost has affordable price!->2.5$
```

### awk loop

```bash
awk 'BEGIN { n = 1; while (n <= 10) { if(n > 5) break; print n; n++ } }'
```
### subdomain maker with awk for a specific site.

`$1>0` filter empty fields. 

```bash
awk '$1>0 {printf "%s.mrcatdev.com\n", $1}' ./files/sub-wordlist
```
