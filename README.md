# virustotal-md5-batch-search

A three-stage Python tool for batch-searching MD5 hashes against VirusTotal, extracting detailed file metadata, and hunting for the actual files across public sources. Designed for the **VirusTotal free API tier** with built-in rate limiting.

## Stages

**Stage 1 — Hash Scan**
Query a list of MD5 hashes against VirusTotal. Identifies which hashes exist in the database, flags malicious vs. clean, and exports results to JSON.

**Stage 2 — Metadata Extraction**
Takes Stage 1 output and fetches deep metadata for confirmed hashes — basic properties, submission history, alternate names, and execution parents (the archives and installers the file has been observed inside).

**Stage 3 — File Hunter**
Takes Stage 2 output and attempts to locate and download the actual files. Searches Internet Archive collections, Hugging Face datasets, GitHub (code search + direct Contents API on known repos), and Hybrid Analysis. Walks nested archives up to 6 layers deep (ZIP, RAR, 7z) and verifies every candidate by hash before keeping it. Also scans all extracted files against the full Stage 1 hash list as a bonus pass.

## Requirements

```bash
pip install requests rarfile py7zr python-magic
# Linux: sudo apt install unrar
# Mac:   brew install unrar
```

- Python 3.8+
- VirusTotal API key — [free tier](https://www.virustotal.com/gui/my-apikey)
- GitHub personal access token — required for Stage 3
- Hybrid Analysis API key — optional for Stage 3

## Configuration

Place a `config.txt` file in the same directory as the script. It is loaded automatically on startup. Any credentials found there skip their prompts.

```
[virustotal api]
your_vt_api_key

[github token]
your_github_token

[hybrid analysis api]
your_hybrid_key

[blocklist]
libretro/libretro-database
mamedev/mame

[known_binaries]
Abdess/retrobios
archtaurus/RetroPieBIOS

[md5s]
042a0adecf2d616ccfb915a5cd71fde5
06dd41b614a6d6d079ec1ee73e2bf87d
```

**Sections:**
- `[virustotal api]` / `[github token]` / `[hybrid analysis api]` — credentials
- `[blocklist]` — `owner/repo` pairs that GitHub code search should never download from (e.g. hash database repos that reference filenames in text rather than containing the actual files)
- `[known_binaries]` — repos walked via the GitHub Contents API to find actual binary files by name
- `[md5s]` — hash list for Stage 1 (one per line)

All sections are optional. A plain file of MD5s with no section headers also works.

## Usage

```bash
python virustotal_md5_batch_search.py
```

Select a stage at the menu. Stages chain automatically — after Stage 1 completes you can continue straight to Stage 2, then Stage 3, without re-entering credentials or file paths.

Running Stage 3 standalone prompts for the Stage 2 JSON path and optionally a Stage 1 hash list for the extended scan.

## Output

All output files are written to the script directory.

| File | Stage |
|---|---|
| `virustotal_results_{timestamp}.json` | Stage 1 |
| `virustotal_detailed_analysis_{timestamp}.json` | Stage 2 |
| `stage3_report_{timestamp}.json` | Stage 3 |
| `found/{md5}.{ext}` | Stage 3 verified files |

Stage 3 uses a hard **3 GB download cap** per file. Files exceeding the cap are skipped and logged in the report. Temporary extraction files are deleted after each target regardless of outcome — only verified files are kept.

## Rate Limiting

The free VirusTotal API allows 4 requests/minute. The script enforces a 15-second delay between requests and automatically retries on HTTP 429 after 60 seconds. Stage 2 makes 2 API calls per hash. GitHub code search is rate-limited to 5,000 requests/hour with a token.

## License

MIT
