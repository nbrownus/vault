---
layout: "docs"
page_title: "Audit Backend: File"
sidebar_current: "docs-audit-file"
description: |-
  The "file" audit backend writes audit logs to a file.
---

# Audit Backend: File

Name: `file`

The "file" audit backend writes audit logs to a file.

This is a very simple audit backend: it appends logs to a file. It does
not currently assist with any log rotation.

## Options

When enabling this backend, the following options are accepted:

  * `path` (required) - The path to where the file will be written. If
      this path exists, the audit backend will append to it.
  * `log_raw` (optional) - Should security sensitive information be logged raw. Defaults to "false".
  * `log_http` (optional) - Logs each http request/response in a json parsable line instead of
      the higher level `request` and `response` logs. Defaults to "false"

## Format

The format of the log file depends on the `log_http` setting.

If `log_raw` is false, as is default, all sensitive information is first hashed
before logging. If explicitly enabled, all values are logged raw without hashing.

### Default Format

Each line in the audit log is a JSON object. The "type" field specifies
what type of object it is. Currently, only two types exist: "request" and
"response".

The line contains all of the information for any given request and response.

### HTTP Format

Each line in the audit log is a JSON object. the "type" field will be `http` and the object will
contain a "duration", "http", and "message" object.

The "request" object will contain an the URI, headers, remote address, and body of the request.
 
The "response" object will contain the headers, body, status code, and "reason" which is a status
code description.

The "message" field is a more human readable form mostly meant for consuming events in something
like Kibana.
