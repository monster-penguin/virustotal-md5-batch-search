# virustotal-md5-batch-search

A two-stage Python tool for batch-searching MD5 hashes against VirusTotal and extracting detailed metadata for files found in the database. Designed for the **VirusTotal free API tier** with built-in rate limiting (4 requests/minute).

## Features

**Stage 1 — Initial Scan**
- Batch-search MD5 hashes against VirusTotal
- Identify which hashes are in the database vs. not found
- Flag malicious vs. clean files
- Export results to timestamped JSON

**Stage 2 — Detailed Analysis**
- Reads Stage 1 output and fetches deeper info for found hashes only
- Extracts: basic properties, history, names, execution parents
- Uses SHA-256 from Stage 1 to query the `execution_parents` endpoint
- Export detailed metadata to timestamped JSON

## Requirements

- Python 3.7+
- `requests` library
- VirusTotal API key (free tier works — get one at https://www.virustotal.com/gui/my-apikey)

```bash
pip install requests
```

## Usage

```bash
python virustotal_batch_search.py
```

You'll be prompted for:
1. Your VirusTotal API key
2. Stage selection (1 or 2)
3. Input source:
   - **Stage 1**: file path with MD5s (one per line) OR comma-separated MD5s
   - **Stage 2**: path to a Stage 1 JSON output file

### Example workflow

```bash
# Stage 1: scan a list of MD5s
$ python virustotal_batch_search.py
# Select 1, provide hashes.txt
# Output: virustotal_results_YYYYMMDD_HHMMSS.json

# Stage 2: get details on the hashes that were found
$ python virustotal_batch_search.py
# Select 2, provide the Stage 1 JSON path
# Output: virustotal_detailed_analysis_YYYYMMDD_HHMMSS.json
```

## Output Structure

### Stage 1 JSON
```json
{
  "timestamp": "...",
  "total_hashes_searched": 40,
  "in_virustotal_database": {
    "count": 10,
    "malicious": 0,
    "clean": 10
  },
  "not_in_virustotal_database": 30,
  "errors": 0,
  "results": {
    "<md5>": {
      "found": true,
      "malicious": false,
      "error": null
    }
  }
}
```

### Stage 2 JSON
```json
{
  "details": {
    "<md5>": {
      "basic_properties": {
        "md5", "sha256", "sha1", "file_type", "magic", "size_bytes"
      },
      "history": {
        "first_seen_itw", "first_submission", "last_submission", "last_analysis"
      },
      "names": ["...", "..."],
      "execution_parents": [
        {
          "type", "name", "sha256", "size",
          "first_submission", "last_analysis", "detections"
        }
      ]
    }
  }
}
```

## Rate Limiting

The free VirusTotal API allows **4 requests/minute**. The script enforces a 15-second delay between hashes. Stage 2 makes 2 API calls per hash (file info + execution parents), so total runtime ≈ `(number of hashes × 15) + (number of hashes × 1)` seconds.

If rate limited (HTTP 429), the script automatically waits 60 seconds and retries.

## Notes

- For each found hash, the script extracts the **SHA-256** from the file info response and uses it to query the `execution_parents` endpoint.
- Stage 2 only processes hashes marked `"found": true` in Stage 1 output, saving API calls.
- All timestamps are converted to readable UTC format.
- Not all files have execution parents — `null` is a valid result.

## License

MIT
