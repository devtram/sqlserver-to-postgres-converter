# Convert SQL Server Query Files to Postgres Query Files
Convert SQL script files to Postgres sql queries files


A safe T-SQL → PostgreSQL translator. Converts SQL Server queries to PostgreSQL, but **refuses to guess**: anything it can't translate with certainty becomes a `-- TODO` block with the original preserved, instead of silently emitting wrong SQL.

> **Draft generator, not a migration authority.** Review the output, run it on a test DB, diff results before production.

  
---


## Install
```bash
pip install "sqlglot==25.*"
chmod +x sqlserver-to-postgres.py
```

Requires Python 3.8+.
---

## Quick start

#### Single file
```
python ./sqlserver-to-postgres.py ./sql/auth.sql -o migrated/ --preserve-case --paranoid
```
#### Full folder (recursive)
```
python ./sqlserver-to-postgres.py ./sql -o migrated/ --preserve-case --paranoid
```
#### Inline query
```
python ./sqlserver-to-postgres.py -q "SELECT TOP 5 [Name] FROM dbo.Users WITH (NOLOCK)" --preserve-case
```
#### stdin
```
cat q.sql | ./sqlserver-to-postgres.py - --preserve-case
```

Pass a **file** → single-file mode. Pass a **folder** → recursive scan. Output goes to `<name>.pg.sql` next to the input, or to `-o out/`.

---

## Behavior

Every statement ends in one of two states:

|State|Output|
|---|---|
|`ok`|Runnable PostgreSQL|
|`manual`|`-- TODO: MANUAL MIGRATION REQUIRED` block with original preserved|

No middle ground. Grep for what needs fixing:

bash

grep -rn "TODO: MANUAL" migrated/

---

## What translates automatically

`TOP n`→`LIMIT n`, `ISNULL`→`COALESCE`, `GETDATE()`→`CURRENT_TIMESTAMP`, `LEN`→`LENGTH`, `IIF`→`CASE`, `[x]`→`"x"`, `dbo`→`public`, `CROSS APPLY`→`LATERAL`. Hints (`NOLOCK`, `OPTION(...)`) are removed.

## What becomes a TODO

- Variables (`@x`, `@@ROWCOUNT`), `DECLARE`, `EXEC`, `TRY/CATCH`, `CURSOR`, temp tables
    
- `PIVOT`, `MERGE`, `OUTPUT`, `FOR XML/JSON`, `NEXT VALUE FOR`, `IDENTITY`
    
- `DATEDIFF`, `DATEADD`, `DATEPART`, `CONVERT` with style codes, `ROUND`, `CHARINDEX`, `STUFF`, `ISNUMERIC`, `FORMAT`, `NEWID`
    
- String `+` concat, `LIKE`, `COLLATE`, T-SQL-only types (`NVARCHAR`, `MONEY`, `DATETIME2`, …)
    
- `BACKUP`, `RESTORE`, `DBCC`, `sp_*`, `xp_*`
    
- With `--paranoid`: **any** function not on the safe whitelist
    

---

## Options

|Flag|Effect|
|---|---|
|`-o DIR`|Output folder (mirrors input structure)|
|`--preserve-case`|Keep identifier case, quote them. **Implies `--quote-all`.**|
|`--paranoid`|Block any function outside the whitelist. **Recommended.**|
|`--strict`|Exit 1 if any statement needs manual work (use in CI)|
|`--report FILE`|Write JSON report of manual statements|
|`--schema-map OLD=NEW`|Rename schemas (default `dbo=public`)|
|`--param-style {keep,psycopg,named}`|`@id` → `@id` / `%(id)s` / `:id`|
|`--allow-risky`|Translate risky constructs anyway. **Refused in CI.**|
|`--compact`|Single-line output|
|`--no-uppercase-keywords`|Keep `select`/`from` lowercase|

---

## Examples

**Mixed-case identifiers:**



```
python ./sqlserver-to-postgres.py -q "SELECT * FROM [AssetManager].[Table]" --preserve-case
```

```sql

SELECT * FROM "AssetManager"."Table";

```

**Auto-translation:**
```sql

-- input
SELECT [Id], ISNULL([Name], 'unknown') AS [Name], GETDATE() AS [CheckedAt] FROM [dbo].[User];
-- output
SELECT "Id", COALESCE("Name", 'unknown') AS "Name", CURRENT_TIMESTAMP AS "CheckedAt"
FROM public."User";

```

**Blocked — `NEXT VALUE FOR`:**
```
-- TODO: MANUAL MIGRATION REQUIRED
--   NEXT VALUE FOR (use nextval('...'))
--
-- SELECT NEXT VALUE FOR "DailyUserSequence";
```

**Blocked — `DATEDIFF`:**
```sql
-- TODO: MANUAL MIGRATION REQUIRED
--   DATEDIFF (boundary-crossing semantics)
--
-- SELECT DATEDIFF(day, [CreatedAt], GETDATE()) FROM [dbo].[User];
```

---

## Recommended workflow



#### 1. Translate
```bash
python  ./sqlserver-to-postgres.py ./sql -o migrated/ --preserve-case --paranoid --report report.json
```
#### 2. See what needs manual work
```bash
jq '.files[] | select(.manual > 0)' report.json
grep -rn "TODO: MANUAL" migrated/
```
#### 3. Fix TODOs by hand
You need to work manual for some cases
#### 4. Test on a scratch DB
```bash
createdb migration_test
psql -d migration_test -f migrated/some.pg.sql
```
#### 5. Diff results against SQL Server originals
Do comparison
#### 6. Promote only after step 5 passes
**Never run translated output directly on production.**

---

## CI
```yaml

- run: pip install "sqlglot==25.*"
- run: |
    python ./sqlserver-to-postgres.py ./sql -o migrated/ \
      --preserve-case --paranoid --strict --report report.json

`--strict` exits 1 if anything needs manual work. `--allow-risky` is auto-refused in CI (override with `TSQL2PG_ALLOW_RISKY=1`).
```

---

## Limitations
Does **not** verify semantic equivalence, translate procedures/triggers, handle types/constraints/indexes, or know your schema types. `ROUND`, implicit casts, `LIKE` collation, and `ORDER BY` null ordering can still behave differently.

To get closer to "risk-free": add a type-aware linter, a schema migration tool, and **differential testing** (run T-SQL and Postgres side-by-side, diff the rows). No translator replaces differential testing.

---

## FAQ
1. **Run output on production directly?** No. Test first.

2. **Does it convert `CREATE TABLE`?** No — it translates syntax but not type mapping. Write DDL by hand.

3. **Will it overwrite inputs?** No. Output goes to `*.pg.sql` files.

4. **Can I re-run safely?** Yes — `*.pg.sql` files are skipped on input.

5. **Why does it block things I know are safe?** Conservative default. Edit `BLOCKING_BASE` in the script or use `--allow-risky` locally.

6. **Full scan or single file?** Both — pass a folder to recurse, a file to translate one.
