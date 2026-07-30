"""
NuGet Typosquat Supply Chain Monitor

Scores each package name in a NuGet dependency list against a bundled corpus of
popular libraries using normalized edit-distance similarity, flagging candidates
whose names closely resemble a known package but differ by one or two characters.

Usage:
    python nuget_typosquat_monitor.py packages.txt
    python nuget_typosquat_monitor.py packages.txt --corpus extra.json --threshold 0.85
    python nuget_typosquat_monitor.py packages.txt --threshold 0.90
"""
import argparse, difflib, json, sys
from pathlib import Path

BUNDLED_CORPUS = [
    "Newtonsoft.Json", "Microsoft.Extensions.DependencyInjection", "Microsoft.Extensions.Logging",
    "Microsoft.Extensions.Configuration", "Microsoft.EntityFrameworkCore", "Serilog",
    "AutoMapper", "Dapper", "Polly", "FluentValidation", "NLog", "log4net",
    "Moq", "xunit", "NUnit", "MSTest.TestFramework", "Bogus", "FluentAssertions",
    "Microsoft.AspNetCore", "Microsoft.AspNetCore.Mvc", "Microsoft.AspNetCore.Authentication",
    "Microsoft.AspNetCore.Authorization", "StackExchange.Redis", "RabbitMQ.Client",
    "MassTransit", "MediatR", "AutoFac", "Ninject", "StructureMap",
    "RestSharp", "HttpClientFactory", "Refit", "Flurl", "Flurl.Http",
    "Microsoft.Data.SqlClient", "Npgsql", "MySqlConnector", "MongoDB.Driver",
    "Azure.Storage.Blobs", "Azure.Identity", "Azure.KeyVault.Secrets",
    "AWSSDK.Core", "AWSSDK.S3", "AWSSDK.DynamoDBv2", "AWSSDK.SQS",
    "Google.Cloud.Storage.V1", "Google.Apis.Auth", "Google.Cloud.PubSub.V1",
    "System.Text.Json", "System.CommandLine", "System.Reactive",
    "Microsoft.CodeAnalysis", "Microsoft.CodeAnalysis.CSharp",
    "Swashbuckle.AspNetCore", "NSwag.AspNetCore", "OpenTelemetry",
    "Hangfire", "Quartz", "NCrontab", "Microsoft.Extensions.Hosting",
    "SignalR", "Microsoft.AspNetCore.SignalR", "Grpc.Net.Client", "protobuf-net",
    "HtmlAgilityPack", "AngleSharp", "CsvHelper", "ExcelDataReader", "EPPlus",
    "iTextSharp", "PdfPig", "ImageSharp", "SkiaSharp", "Emgu.CV",
    "NHibernate", "PetaPoco", "ServiceStack", "ServiceStack.OrmLite",
    "Elasticsearch.Net", "NEST", "Lucene.Net", "Solr.Net",
    "MimeKit", "MailKit", "SendGrid", "Twilio",
    "Microsoft.IdentityModel.Tokens", "System.IdentityModel.Tokens.Jwt",
    "BCrypt.Net-Next", "Konscious.Security.Cryptography", "libsodium",
    "Polly.Extensions.Http", "Microsoft.Extensions.Http.Polly",
    "Mapster", "TinyMapper", "ValueInjecter",
    "BenchmarkDotNet", "JetBrains.Annotations", "Fody", "PostSharp",
    "NSubstitute", "FakeItEasy", "WireMock.Net", "Microsoft.AspNetCore.TestHost",
    "coverlet.collector", "ReportGenerator", "dotnet-sonarscanner",
    "Serilog.Sinks.Console", "Serilog.Sinks.File", "Serilog.Sinks.Seq",
    "Microsoft.Extensions.Logging.Abstractions", "Castle.Core",
    "Scrutor", "Microsoft.Extensions.Options", "Microsoft.Extensions.Caching.Memory",
]


def load_corpus(extra_path=None):
    corpus = {n.lower() for n in BUNDLED_CORPUS}
    if extra_path:
        try:
            data = json.loads(Path(extra_path).read_text())
            if not isinstance(data, list):
                print(f"[ERROR] --corpus file must contain a JSON array, got {type(data).__name__}", file=sys.stderr)
                sys.exit(2)
            corpus.update(str(n).lower() for n in data)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"[ERROR] Failed to load corpus file '{extra_path}': {exc}", file=sys.stderr)
            sys.exit(2)
    return corpus


def score_similarity(candidate, corpus):
    key = candidate.lower()
    if key in corpus:
        return None, 0.0
    best_name, best_score = "", 0.0
    for entry in corpus:
        score = difflib.SequenceMatcher(None, key, entry).ratio()
        if score > best_score:
            best_score = score
            best_name = entry
    return best_name, best_score


def scan_and_report(packages_file, corpus, threshold):
    try:
        lines = Path(packages_file).read_text().splitlines()
    except OSError as exc:
        print(f"[ERROR] Cannot read packages file '{packages_file}': {exc}", file=sys.stderr)
        sys.exit(2)

    packages = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    if not packages:
        print("[WARN] No package names found in input file.", file=sys.stderr)
        sys.exit(0)

    flagged = 0
    peak_high = False

    print(f"{'CANDIDATE':<45} {'CLOSEST MATCH':<45} {'SCORE':>6}  SEVERITY")
    print("-" * 110)

    for pkg in packages:
        match, score = score_similarity(pkg, corpus)
        if match is None:
            continue
        if score < threshold:
            continue
        severity = "HIGH" if score >= 0.90 else "MEDIUM"
        if severity == "HIGH":
            peak_high = True
        flagged += 1
        print(f"{pkg:<45} {match:<45} {score:>6.3f}  {severity}")

    print("-" * 110)
    peak_label = "HIGH" if peak_high else ("MEDIUM" if flagged else "NONE")
    print(f"\nSummary: {len(packages)} packages scanned, {flagged} flagged, peak severity: {peak_label}")

    if peak_high:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Detect NuGet typosquat packages via edit-distance similarity scoring."
    )
    parser.add_argument("packages_file", help="Plain-text file with one NuGet package name per line")
    parser.add_argument("--corpus", metavar="PATH", help="JSON file with array of additional trusted package names")
    parser.add_argument("--threshold", type=float, default=0.80,
                        help="Minimum similarity score to flag (default: 0.80); >= 0.90 = HIGH, else MEDIUM")
    args = parser.parse_args()

    if not (0.0 <= args.threshold <= 1.0):
        print("[ERROR] --threshold must be between 0.0 and 1.0", file=sys.stderr)
        sys.exit(2)

    corpus = load_corpus(args.corpus)
    scan_and_report(args.packages_file, corpus, args.threshold)


if __name__ == "__main__":
    main()