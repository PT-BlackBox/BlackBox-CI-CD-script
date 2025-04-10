# blackbox-scan

This tool is a command-line client for the [BlackBox](https://bbs.ptsecurity.com/) API, that can help to integrate Dynamic Application Security Testing (DAST) into a CI/CD pipeline.

## Requirements

[Python](https://www.python.org/) version 3.8.19 or above is required to run the tool. The use of [virtualenv](https://docs.python.org/3/library/venv.html) or [poetry](https://python-poetry.org/docs/) is recommended.

To install required Python packages, run:

```shell
pip install -r requirements.txt
```

Or:

```shell
poetry install
```

## Usage

### Synopsis

```
  main.py [OPTIONS]
```

### Options

```
Usage: main.py [OPTIONS]

Options:                                                                      
  --blackbox-url TEXT                                                         
  --blackbox-api-token TEXT       [required]                                  
  --target-url TEXT               Set url of scan target. Do not use with     
                                  --target-file, --target-uuid.               
  --target-file FILENAME          Set filename with target urls. Do not use   
                                  with --target-url, --target-uuid.           
  --target-uuid TEXT              Set uuid of scan target. Do not use with    
                                  --target-url, --target-file.                
  --group-uuid TEXT               Set group UUID for site                     
  --ignore-ssl                    Skip verification of BlackBox API host      
                                  certificate.                                
  --auto-create                   Automatically create a site if a site with  
                                  the target URL in the specified group was   
                                  not found.                                  
  --previous [wait|stop|fail]     What to do if the target is currently being 
                                  scanned.                                    
  --no-wait                       Do not wait until the started scan is       
                                  finished.                                   
  --shared-link                   Create shared link for scan.                
  --scan-profile TEXT             Set scan profile UUID for new scan          
  --auth-profile TEXT             Set authentication profile UUID for site.   
                                  Cannot be used with --auth-data option. For
                                  scanning without authentication specify
                                  `RESET` in the option                       
  --api-schema TEXT               Set API-schema UUID for site. For scanning  
                                  without API-schema specify `RESET` in the   
                                  option                                      
  --fail-under-score FLOAT RANGE  Fail with exit code 3 if report scoring is  
                                  less than given score (set "1" or do not set
                                  to never fail).  [1<=x<=10]                 
  --report-dir DIRECTORY          Set directory path for storing the generated
                                  report file. If the option is used, the     
                                  report will be saved in the specified       
                                  directory. Cannot be used with --no-wait
                                  option. To generate a report the scan must
                                  be finished or stopped.
  --report-template [html|nist|oud4|owasp|owasp_mobile|pcidss|sarif|sans]
                                  Template shortname of the report to be
                                  generated. Specifies file format for report
                                  in --report-dir.
  --report-locale [ru|en]         Localization of the report file to be
                                  generated. Specifies file localization for
                                  report in --report-dir.
  --results-only                  Only get results of specified site. Last
                                  scan results by default. Use --scan-uuid
                                  option to get results of specific scan.
  --scan-uuid, --scan-id TEXT     Set the scan UUID to get the results. Can be
                                  used without --results-only option.
  --auth-data FILENAME            Set path to file with authentication data.
                                  If this option is used, a new authentication
                                  profile with the data provided will be
                                  created and used for new scan. Cannot be
                                  used with --auth-profile option. It is
                                  highly recommended to use environment
                                  variables to store passwords, tokens and api
                                  keys: AUTH_PASSWORD, AUTH_TOKEN,
                                  AUTH_API_KEY_VALUE
  --help                          Show this message and exit.
```

### Authorization data file

The file with authentication data contains `KEY=VALUE` pairs in its lines. Keys are:

- `TYPE` - Authentication type, one of `httpBasic` `htmlAutoForm`, `htmlFormBased`, `rawCookie`, `apiKey`, `bearer`.
- `USERNAME` - Username which must be entered in the appropriate form field (its value)
- `PASSWORD` - Password which must be entered in the appropriate form field (its value)
- `FORM_URL` - Authorization page URL
- `SUCCESS_STRING` - String for verifying authentication success
- `FORM_X_PATH` - Xpath of a form in an HTML document
- `USERNAME_FIELD` - Username field ID
- `PASSWORD_FIELD` - Password field ID
- `REGEXP_OF_SUCCESS` - Regexp for verifying authentication success
- `SUBMIT_VALUE` - Submit button ID
- `COOKIES` - Cookie strings separated by the `;` character
- `SUCCESS_URL` - Address of successful sign-in page
- `PLACE` - Defines the api key transfer place: `COOKIE`, `HEADER` or `QUERY`
- `NAME` - Query parameter name for `QUERY` or header name for `COOKIE`, `HEADER`
- `VALUE` - Value of the api key
- `TOKEN` - Value of the Bearer token

#### httpBasic

```
TYPE=httpBasic
USERNAME=username
PASSWORD=password
```

#### htmlAutoForm

```
TYPE=htmlAutoForm
USERNAME=username
PASSWORD=password
FORM_URL=http://staging.example.com/login/
SUCCESS_STRING=My profile
```

#### htmlFormBased

`SUBMIT_VALUE` is optional

```
TYPE=htmlFormBased
FORM_URL=http://staging.example.com/login/
FORM_X_PATH=.//form
USERNAME_FIELD=login
USERNAME=username
PASSWORD_FIELD=pass
PASSWORD=password
REGEXP_OF_SUCCESS=Welcome to my site!
SUBMIT_VALUE=Log in
```

#### rawCookie

```
TYPE=rawCookie
COOKIES=PHPSESSID=bnc3li5jhmebd50suf9a99u0u3;SOMECOOKIE=1a2b3c4;
SUCCESS_URL=http://staging.example.com/after_login/
REGEXP_OF_SUCCESS=Logout
```

#### apiKey

`SUCCESS_STRING` is optional

```
TYPE=apiKey
PLACE=HEADER
NAME=X-Some-Header
VALUE=some-token-value
SUCCESS_URL=http://api.example.test:8000/auth/check
SUCCESS_STRING=Access granted
```

#### bearer

`SUCCESS_STRING` is optional

```
TYPE=bearer
TOKEN=some-token-value
SUCCESS_URL=http://api.example.test:8000/auth/check
SUCCESS_STRING=Access granted
```


### Environment

The following environment variables may be used instead of corresponding options:

- `BLACKBOX_URL`/`--blackbox-url`
- `BLACKBOX_API_TOKEN`/`--blackbox-api-token`
- `TARGET_URL`/`--target-url`
- `TARGET_UUID`/`--target-uuid`
- `TARGET_FILE`/`--target-file`
- `IGNORE_SSL`/`--ignore-ssl`
- `SCAN_PROFILE`/`--scan-profile`
- `GROUP_UUID`/`--group-uuid`
- `AUTH_PROFILE`/`--auth-profile`
- `API_SCHEMA`/`--api-schema`

It is recommended that you use these environment variables instead of the corresponding keys in the file with authentication data:

- `AUTH_PASSWORD`/ key `PASSWORD`
- `AUTH_TOKEN`/ key `TOKEN`
- `AUTH_API_KEY_VALUE`/ key `VALUE`

## Example

```shell
export BLACKBOX_URL=https://bbs.ptsecurity.com/
export BLACKBOX_API_TOKEN=D4OPXw7mXCWjHER0lE48PCr4UkcfD86AwOwnio9I1w3HsOSS3Hxo9xi82hoWOB5deVYMk3kedgh0f9yq
export TARGET_URL=http://staging.example.com/
export GROUP_UUID=ee2e5f90-c9ee-454e-a4db-123463d29851

python main.py --auto-create --previous=stop --report_dir=/path/to/report/dir
```

## Results

When a scan finishes without an error, the tool returns exit code `0` and prints JSON-formatted report to `stdout`. A report may be passed for processing to a tool such as [jq](https://stedolan.github.io/jq/).

Example output for `--target-url` option (reformatted for readability):

```json
{
    "target_url": "http://staging.example.com/",
    "target_uuid": "ccb7de77-ff51-464d-bf25-7ebcfe0403d6",
    "url": "https://bbs.ptsecurity.com/sites/ccb7de77-ff51-464d-bf25-7ebcfe0403d6/scans/d1b06ccb-3d56-46e6-9826-b53df8e0ff9f",
    "scan_status": "FINISHED",
    "score": 1,
    "sharedLink": "https://bbs.ptsecurity.com/shared/dee4Lyx",
    "report_path": "/path/to/report/dir/20230825_182339_staging_example_com.ru.html",
    "vulns": {
        "issue_groups": [
            {
                "severity": "low",
                "category": "sensitive_data",
                "group_title": "server_software_version_disclosure",
                "vulns": [
                    {
                        "url": "http://staging.example.com/"
                    },
                    {
                        "url": "http://staging.example.com/upload.php"
                    }
                ]
            },
            {
                "severity": "high",
                "category": "insecure_design",
                "group_title": "fileupload",
                "vulns": [
                    {
                        "url": "http://staging.example.com/upload.php"
                    }
                ]
            },
            {
                "severity": "medium",
                "category": "cryptography",
                "group_title": "no_https_scheme",
                "vulns": [
                    {
                        "url": "https://staging.example.com/"
                    }
                ]
            }
        ],
        "error_page_groups": [
            {
                "group_title": "404",
                "category": "tech_info",
                "vulns": [
                    {
                        "url": "http://staging.example.com/cgi-bin/"
                    }
                ]
            },
            {
                "group_title": "501",
                "category": "tech_info",
                "vulns": [
                    {
                        "url": "http://staging.example.com/"
                    }
                ]
            }
        ],
        "cve_groups": [
            {
                "category": "cve",
                "group_title": "Apache 2.4.43",
                "vulns": [
                    {
                        "cve_id": "CVE-2021-26691",
                        "vector": "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"
                    },
                    {
                        "cve_id": "CVE-2020-9490",
                        "vector": "(CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)"
                    }
                ]
            }
        ]
    },
    "errors": null
}
```

Example output for `--target-file` option (with `--no-wait` option provided and without shared link generation):

```json
[
    {
        "target_url": "http://first.example.com/",
        "target_uuid": "ccb7de77-ff51-464d-bf25-7ebcfe0403d6",
        "url": "https://bbs.ptsecurity.com/sites/ccb7de77-ff51-464d-bf25-7ebcfe0403d6/scans/d1b06ccb-3d56-46e6-9826-b53df8e0ff9f",
        "scan_status": "IN_PROGRESS",
        "score": null,
        "sharedLink": null,
        "report_path": null,
        "vulns": null,
        "errors": null
    },
    {
        "target_url": "http://second.example.com/",
        "target_uuid": "cce4cf46-1edf-443c-ae57-5b2abc8703bd",
        "url": "https://bbs.ptsecurity.com/sites/d04df6be-6aa2-47a5-bb06-cabada4e41d3/scans/50d5cc1f-1dbc-4768-bb23-5dc303f00e87",
        "scan_status": "IN_PROGRESS",
        "score": null,
        "sharedLink": null,
        "report_path": null,
        "vulns": null,
        "errors": null
    },
    {
        "target_url": "http://third.example.com/",
        "target_uuid": "cbb3971e-3a22-40b9-8d43-aceca9bc4b19",
        "url": "https://bbs.ptsecurity.com/sites/39598b70-c704-4882-918d-c59f09e8bd7e/scans/d8dd5e74-8313-4e24-86bf-31a4fdd03c51",
        "scan_status": "IN_PROGRESS",
        "score": null,
        "sharedLink": null,
        "report_path": null,
        "vulns": null,
        "errors": null
    }
]
```

In case an error occurs, the tool returns non-zero exit code and prints error log messages to `stderr`:

```
2021-12-03 13:24:52,517 ERROR [root] BlackBox error: the scan did not succeed, see UI for the error reason: http://bbs.ptsecurity.com/sites/ccb7de77-ff51-464d-bf25-7ebcfe0403d6/scans/d1b06ccb-3d56-46e6-9826-b53df8e0ff9f
```

## Bugs and Issues

To report a problem related to the tool, please create a new issue.

## Terms

For BlackBox terms of use, see [BlackBox License](https://bbs.ptsecurity.com/license).

## License

For the tool licensing terms, see [LICENSE](LICENSE) file.
