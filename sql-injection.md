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

## MYSQL UNION OPERATOR

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
