"""
C/C++ Taint Flow Scanner - Pattern-based taint analysis for CI pipelines.

Usage:
    python c_taint_scanner.py src/main.c
    python c_taint_scanner.py src/ --severity high --format json
    python c_taint_scanner.py . --format text --severity low
"""

import argparse
import json
import os
import re
import sys

TAINT_SOURCES = [
    (r'\bgetenv\s*\(', 'getenv', 'high'),
    (r'\bfgets\s*\(([^,)]+)', 'fgets', 'high'),
    (r'\bscanf\s*\([^,]+,\s*([^,)]+)', 'scanf', 'high'),
    (r'\bfscanf\s*\([^,]+,[^,]+,\s*([^,)]+)', 'fscanf', 'high'),
    (r'\breadline\s*\(', 'readline', 'medium'),
    (r'\brecv\s*\([^,]+,\s*([^,]+)', 'recv', 'high'),
    (r'\bread\s*\([^,]+,\s*([^,]+)', 'read', 'medium'),
    (r'\bargv\s*\[', 'argv', 'high'),
    (r'\bgetchar\s*\(', 'getchar', 'low'),
    (r'\bgets\s*\(([^)]+)', 'gets', 'high'),
]

TAINT_SINKS = [
    (r'\bstrcpy\s*\(([^,)]+)', 'strcpy', 'high'),
    (r'\bstrcat\s*\(([^,)]+)', 'strcat', 'high'),
    (r'\bsprintf\s*\(([^,]+),\s*([^,)]+)', 'sprintf', 'high'),
    (r'\bsystem\s*\(([^)]+)', 'system', 'high'),
    (r'\bexec[lv][pe]?\s*\(([^)]+)', 'exec', 'high'),
    (r'\bpopen\s*\(([^,)]+)', 'popen', 'high'),
    (r'\bprintf\s*\(([^,)]+)', 'printf', 'medium'),
    (r'\bfprintf\s*\([^,]+,\s*([^,)]+)', 'fprintf', 'medium'),
    (r'\bstrcmp\s*\(([^,)]+)', 'strcmp', 'low'),
    (r'\bstrlen\s*\(([^)]+)', 'strlen', 'low'),
    (r'\bmemcpy\s*\(([^,]+)', 'memcpy', 'medium'),
]

SEVERITY_RANK = {'low': 0, 'medium': 1, 'high': 2}

REPRO_TEMPLATE = """\
/* Reproduction stub (illustrative only - DO NOT compile/run without review) */
/* File: {file}, Line: {line} */
#include <stdio.h>
#include <string.h>
int main(int argc, char *argv[]) {{
    char buf[256];
    /* taint source: {source} */ {source_code}
    /* taint sink: {sink} */    {sink_code}
    return 0;
}}"""

SOURCE_STUBS = {
    'argv': 'char *input = argv[1];',
    'fgets': 'fgets(buf, sizeof(buf), stdin);',
    'gets': 'gets(buf);',
    'scanf': 'scanf("%s", buf);',
    'getenv': 'char *input = getenv("USER_INPUT");',
    'recv': 'recv(sockfd, buf, sizeof(buf), 0);',
    'read': 'read(fd, buf, sizeof(buf));',
    'readline': 'char *input = readline("Enter: ");',
    'fscanf': 'fscanf(fp, "%s", buf);',
    'getchar': 'buf[0] = getchar();',
}

SINK_STUBS = {
    'strcpy': 'strcpy(dest, buf);',
    'strcat': 'strcat(dest, buf);',
    'sprintf': 'sprintf(out, buf);',
    'system': 'system(buf);',
    'exec': 'execl(buf, buf, NULL);',
    'popen': 'popen(buf, "r");',
    'printf': 'printf(buf);',
    'fprintf': 'fprintf(stderr, buf);',
    'strcmp': 'strcmp(buf, "secret");',
    'strlen': 'strlen(buf);',
    'memcpy': 'memcpy(dest, buf, strlen(buf));',
}

def extract_var(match_str):
    var = re.sub(r'["\'\s]', '', match_str.strip())
    var = re.split(r'[+\-*/\[\]&]', var)[0]
    return var if re.match(r'^[a-zA-Z_]\w*$', var) else ''

def scan_file(path, min_severity):
    findings = []
    try:
        with open(path, 'r', errors='replace') as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[warn] cannot read {path}: {e}", file=sys.stderr)
        return findings

    sources_by_line = []
    sinks_by_line = []

    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('*'):
            continue
        for pattern, name, sev in TAINT_SOURCES:
            m = re.search(pattern, line)
            if m:
                var = extract_var(m.group(1)) if m.lastindex and m.lastindex >= 1 else ''
                sources_by_line.append({'line': lineno, 'source': name, 'var': var, 'severity': sev, 'raw': line.rstrip()})

        for pattern, name, sev in TAINT_SINKS:
            m = re.search(pattern, line)
            if m:
                var = extract_var(m.group(1)) if m.lastindex and m.lastindex >= 1 else ''
                sinks_by_line.append({'line': lineno, 'sink': name, 'var': var, 'severity': sev, 'raw': line.rstrip()})

    seen = set()
    for src in sources_by_line:
        for snk in sinks_by_line:
            if snk['line'] < src['line']:
                continue
            if snk['line'] - src['line'] > 50:
                continue
            var_match = src['var'] and snk['var'] and src['var'] == snk['var']
            proximity = snk['line'] - src['line'] <= 15
            if not (var_match or proximity):
                continue
            sev = src['severity'] if SEVERITY_RANK[src['severity']] >= SEVERITY_RANK[snk['severity']] else snk['severity']
            if SEVERITY_RANK[sev] < SEVERITY_RANK[min_severity]:
                continue
            key = (path, src['line'], snk['line'], src['source'], snk['sink'])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                'file': path, 'source_line': src['line'], 'sink_line': snk['line'],
                'source': src['source'], 'sink': snk['sink'],
                'var': src['var'] or snk['var'] or 'buf',
                'severity': sev,
                'source_raw': src['raw'], 'sink_raw': snk['raw'],
            })
    return findings

def emit_report(findings, fmt):
    if fmt == 'json':
        out = []
        for f in findings:
            out.append({k: v for k, v in f.items() if not k.endswith('_raw')})
        print(json.dumps(out, indent=2))
        return

    if not findings:
        print("No taint flows found.")
        return

    for f in findings:
        stub = REPRO_TEMPLATE.format(
            file=f['file'], line=f['source_line'],
            source=f['source'], sink=f['sink'],
            source_code=SOURCE_STUBS.get(f['source'], f'/* {f["source"]} */'),
            sink_code=SINK_STUBS.get(f['sink'], f'/* {f["sink"]} */'),
        )
        print(f"{'='*60}")
        print(f"SEVERITY : {f['severity'].upper()}")
        print(f"FILE     : {f['file']}:{f['source_line']}")
        print(f"SOURCE   : {f['source']} (line {f['source_line']})")
        print(f"SINK     : {f['sink']} (line {f['sink_line']})")
        print(f"VARIABLE : {f['var']}")
        print(f"CONTEXT  : {f['source_raw'].strip()}")
        print(f"         : ... => {f['sink_raw'].strip()}")
        print(stub)
        print()

def collect_files(source_path):
    exts = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp'}
    if os.path.isfile(source_path):
        return [source_path]
    results = []
    for root, _, files in os.walk(source_path):
        for name in files:
            if os.path.splitext(name)[1].lower() in exts:
                results.append(os.path.join(root, name))
    return sorted(results)

def main():
    parser = argparse.ArgumentParser(description='C/C++ Taint Flow Scanner')
    parser.add_argument('source_path', help='File or directory to scan')
    parser.add_argument('--severity', choices=['low', 'medium', 'high'], default='medium')
    parser.add_argument('--format', choices=['text', 'json'], default='text', dest='fmt')
    args = parser.parse_args()

    files = collect_files(args.source_path)
    if not files:
        print(f"No C/C++ files found at: {args.source_path}", file=sys.stderr)
        sys.exit(1)

    all_findings = []
    for f in files:
        all_findings.extend(scan_file(f, args.severity))

    all_findings.sort(key=lambda x: (SEVERITY_RANK[x['severity']], x['file'], x['source_line']), reverse=True)
    emit_report(all_findings, args.fmt)

    if args.fmt == 'text':
        print(f"Scanned {len(files)} file(s), found {len(all_findings)} taint flow(s).")

if __name__ == '__main__':
    main()