#!/usr/bin/env python3
"""
VirusTotal Batch MD5 Search Script
Searches a batch of MD5 hashes on VirusTotal and exports results to JSON.
Implements rate limiting for free API tier (4 requests per minute).
"""

import requests
import json
import time
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

class VirusTotalDetailedAnalyzer:
    """Fetches detailed analysis for hashes found in VirusTotal."""
    REQUEST_DELAY = 15  # seconds between requests (free API limit)
    API_URL = "https://www.virustotal.com/api/v3/files"
    
    def __init__(self, api_key: str):
        """Initialize with API key."""
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key
        })
        self.detailed_results = {}
        self.errors = {}
    
    def extract_file_details(self, md5_hash: str, response_data: dict) -> Dict[str, Any]:
        """Extract relevant file details from VirusTotal API response."""
        try:
            attributes = response_data.get("data", {}).get("attributes", {})
            
            # Basic properties (as shown in VirusTotal UI)
            basic_properties = {
                "md5": attributes.get("md5"),
                "sha256": attributes.get("sha256"),
                "sha1": attributes.get("sha1"),
                "file_type": attributes.get("type_description"),
                "magic": attributes.get("magic"),
                "size_bytes": attributes.get("size"),
            }
            
            # History (submission and analysis dates)
            from datetime import datetime as dt
            history = {
                "first_seen_itw": self._format_timestamp(attributes.get("first_seen_itw_date")),
                "first_submission": self._format_timestamp(attributes.get("first_submission_date")),
                "last_submission": self._format_timestamp(attributes.get("last_submission_date")),
                "last_analysis": self._format_timestamp(attributes.get("last_analysis_date")),
            }
            
            # Names (alternate filenames)
            names = attributes.get("names", [])
            
            return {
                "md5": md5_hash,
                "basic_properties": basic_properties,
                "history": history,
                "names": names if names else None,
                "execution_parents": None  # Will be populated by separate API call
            }
        
        except Exception as e:
            return {
                "md5": md5_hash,
                "error": f"Failed to parse details: {str(e)}"
            }
    
    def get_execution_parents(self, sha256_hash: str) -> List[Dict[str, Any]]:
        """Fetch execution parents for a hash from VirusTotal API.
        
        Note: This endpoint requires the SHA-256 hash, not MD5 or SHA-1.
        Endpoint: /files/{sha256}/execution_parents (with underscore)
        """
        try:
            response = self.session.get(
                f"{self.API_URL}/{sha256_hash}/execution_parents",
                timeout=10,
                params={"limit": 40}
            )
            
            if response.status_code == 200:
                data = response.json()
                parents = []
                
                # Parse execution parents from response
                for parent in data.get("data", []):
                    try:
                        parent_attrs = parent.get("attributes", {})
                        
                        # Extract meaningful name (fallback chain)
                        name = parent_attrs.get("meaningful_name")
                        if not name:
                            name = parent_attrs.get("name")
                        if not name:
                            name = parent.get("id", "Unknown")
                        
                        parent_entry = {
                            "type": parent_attrs.get("type_description"),
                            "name": name,
                            "sha256": parent.get("id"),
                            "size": parent_attrs.get("size"),
                            "first_submission": self._format_timestamp(parent_attrs.get("first_submission_date")),
                            "last_analysis": self._format_timestamp(parent_attrs.get("last_analysis_date")),
                            "detections": parent_attrs.get("last_analysis_stats", {}).get("malicious", 0)
                        }
                        parents.append(parent_entry)
                    except Exception:
                        continue
                
                return parents if parents else None
            
            elif response.status_code == 404:
                return None
            
            elif response.status_code == 429:
                print("WARNING: Rate limited on execution parents. Waiting 60 seconds...")
                time.sleep(60)
                return self.get_execution_parents(sha256_hash)
            
            else:
                return None
        
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None
    
    def _format_timestamp(self, timestamp: int) -> str:
        """Convert Unix timestamp to readable format."""
        if not timestamp:
            return None
        try:
            from datetime import datetime, timezone
            return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            return None
    
    def get_file_details(self, md5_hash: str) -> Dict[str, Any]:
        """Fetch detailed information for a single hash."""
        try:
            # First call: Get basic file info
            response = self.session.get(
                f"{self.API_URL}/{md5_hash}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = self.extract_file_details(md5_hash, data)
                
                # Get SHA-256 for execution parents query (required by API)
                sha256 = result["basic_properties"].get("sha256")
                
                # Second call: Get execution parents using SHA-256
                time.sleep(1)  # Small delay to avoid rate limiting
                if sha256:
                    execution_parents = self.get_execution_parents(sha256)
                    result["execution_parents"] = execution_parents
                else:
                    result["execution_parents"] = None
                
                return result
            
            elif response.status_code == 404:
                self.errors[md5_hash] = "Hash not found"
                return {"md5": md5_hash, "error": "Hash not found"}
            
            elif response.status_code == 401:
                print("ERROR: Invalid API key.")
                sys.exit(1)
            
            elif response.status_code == 429:
                print("WARNING: Rate limited. Waiting 60 seconds...")
                time.sleep(60)
                return self.get_file_details(md5_hash)
            
            else:
                error_msg = f"HTTP {response.status_code}"
                self.errors[md5_hash] = error_msg
                return {"md5": md5_hash, "error": error_msg}
        
        except requests.exceptions.Timeout:
            error_msg = "Request timeout"
            self.errors[md5_hash] = error_msg
            return {"md5": md5_hash, "error": error_msg}
        
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            self.errors[md5_hash] = error_msg
            return {"md5": md5_hash, "error": error_msg}
    
    def analyze_batch(self, md5_hashes: List[str], verbose: bool = True) -> Dict[str, Any]:
        """Fetch detailed analysis for a batch of hashes."""
        total = len(md5_hashes)
        
        # Adjusted for 2 API calls per hash (file info + execution parents)
        adjusted_delay = self.REQUEST_DELAY * 2
        
        print(f"\n{'='*60}")
        print(f"VirusTotal Detailed Analysis (Stage 2)")
        print(f"{'='*60}")
        print(f"Total hashes to analyze: {total}")
        print(f"API calls per hash: 2 (file info + execution parents)")
        print(f"Rate limit: 1 request every {self.REQUEST_DELAY} seconds")
        print(f"Estimated time: {(total * adjusted_delay) / 60:.1f} minutes")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        for i, md5_hash in enumerate(md5_hashes, 1):
            md5_hash = md5_hash.strip().lower()
            
            if verbose:
                print(f"[{i}/{total}] Fetching details for {md5_hash}...", end=" ", flush=True)
            
            result = self.get_file_details(md5_hash)
            self.detailed_results[md5_hash] = result
            
            if verbose:
                status = "OK" if "error" not in result else "ERROR"
                print(status)
            
            # Rate limiting: wait before next request (except on last iteration)
            if i < total:
                time.sleep(self.REQUEST_DELAY)
        
        elapsed_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"Analysis completed in {elapsed_time:.1f} seconds")
        print(f"Successful: {len([v for v in self.detailed_results.values() if 'error' not in v])}")
        if self.errors:
            print(f"Errors: {len(self.errors)}")
        print(f"{'='*60}\n")
        
        return self.detailed_results
    
    def export_json(self, output_file: str = None) -> str:
        """Export detailed results to JSON file."""
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"virustotal_detailed_analysis_{timestamp}.json"
        
        successful = len([v for v in self.detailed_results.values() if "error" not in v])
        
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "total_hashes_analyzed": len(self.detailed_results),
            "successful_analyses": successful,
            "errors": len(self.errors),
            "details": self.detailed_results,
            "error_details": self.errors if self.errors else None
        }
        
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Detailed results exported to: {output_file}\n")
        return output_file


class VirusTotalBatchSearcher:
    # Free API allows 4 requests per minute = 1 request every 15 seconds
    REQUEST_DELAY = 15  # seconds between requests
    API_URL = "https://www.virustotal.com/api/v3/files"
    
    def __init__(self, api_key: str):
        """Initialize with API key."""
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key
        })
        self.results = {}
        self.errors = {}
        self.request_count = 0
    
    def search_hash(self, md5_hash: str) -> Dict[str, Any]:
        """
        Search a single MD5 hash on VirusTotal.
        Returns dict with:
          - 'found': bool (whether hash exists in VirusTotal database)
          - 'malicious': bool (whether detected as malicious)
          - 'error': str (error message if applicable)
        """
        try:
            response = self.session.get(
                f"{self.API_URL}/{md5_hash}",
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Check if any security vendor flagged it as malicious
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                return {
                    "found": True,
                    "malicious": malicious_count > 0,
                    "error": None
                }
            
            elif response.status_code == 404:
                # Hash not found in VirusTotal database
                return {
                    "found": False,
                    "malicious": False,
                    "error": None
                }
            
            elif response.status_code == 401:
                print("ERROR: Invalid API key. Please check your credentials.")
                sys.exit(1)
            
            elif response.status_code == 429:
                print("WARNING: Rate limited by VirusTotal. Waiting 60 seconds...")
                time.sleep(60)
                # Retry the request
                return self.search_hash(md5_hash)
            
            else:
                error_msg = f"HTTP {response.status_code}"
                self.errors[md5_hash] = error_msg
                print(f"ERROR for {md5_hash}: {error_msg}")
                return {
                    "found": None,
                    "malicious": None,
                    "error": error_msg
                }
        
        except requests.exceptions.Timeout:
            error_msg = "Request timeout"
            self.errors[md5_hash] = error_msg
            print(f"ERROR for {md5_hash}: {error_msg}")
            return {
                "found": None,
                "malicious": None,
                "error": error_msg
            }
        
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            self.errors[md5_hash] = error_msg
            print(f"ERROR for {md5_hash}: {error_msg}")
            return {
                "found": None,
                "malicious": None,
                "error": error_msg
            }
    
    def search_batch(self, md5_hashes: List[str], verbose: bool = True) -> Dict[str, Any]:
        """
        Search a batch of MD5 hashes with rate limiting.
        """
        total = len(md5_hashes)
        
        print(f"\n{'='*60}")
        print(f"VirusTotal Batch Search")
        print(f"{'='*60}")
        print(f"Total hashes to search: {total}")
        print(f"Rate limit: 1 request every {self.REQUEST_DELAY} seconds")
        print(f"Estimated time: {(total * self.REQUEST_DELAY) / 60:.1f} minutes")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        
        for i, md5_hash in enumerate(md5_hashes, 1):
            md5_hash = md5_hash.strip().lower()
            
            if verbose:
                print(f"[{i}/{total}] Searching {md5_hash}...", end=" ", flush=True)
            
            result = self.search_hash(md5_hash)
            self.results[md5_hash] = result
            
            if verbose:
                if result["error"]:
                    status = "ERROR"
                elif result["found"] is True:
                    status = "FOUND - MALICIOUS" if result["malicious"] else "FOUND - CLEAN"
                elif result["found"] is False:
                    status = "NOT IN DATABASE"
                else:
                    status = "UNKNOWN"
                print(status)
            
            # Rate limiting: wait before next request (except on last iteration)
            if i < total:
                time.sleep(self.REQUEST_DELAY)
        
        elapsed_time = time.time() - start_time
        
        # Count statistics
        found_count = len([v for v in self.results.values() if v["found"] is True])
        not_found_count = len([v for v in self.results.values() if v["found"] is False])
        malicious_count = len([v for v in self.results.values() if v["found"] is True and v["malicious"] is True])
        clean_count = len([v for v in self.results.values() if v["found"] is True and v["malicious"] is False])
        
        print(f"\n{'='*60}")
        print(f"Search completed in {elapsed_time:.1f} seconds")
        print(f"Results:")
        print(f"  - In VirusTotal database: {found_count}")
        print(f"    - Malicious: {malicious_count}")
        print(f"    - Clean: {clean_count}")
        print(f"  - NOT in VirusTotal database: {not_found_count}")
        if self.errors:
            print(f"  - Errors: {len(self.errors)}")
        print(f"{'='*60}\n")
        
        return self.results
    
    def export_json(self, output_file: str = None) -> str:
        """
        Export results to JSON file.
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"virustotal_results_{timestamp}.json"
        
        # Calculate statistics
        found_count = len([v for v in self.results.values() if v["found"] is True])
        not_found_count = len([v for v in self.results.values() if v["found"] is False])
        malicious_count = len([v for v in self.results.values() if v["found"] is True and v["malicious"] is True])
        clean_count = len([v for v in self.results.values() if v["found"] is True and v["malicious"] is False])
        
        export_data = {
            "timestamp": datetime.now().isoformat(),
            "total_hashes_searched": len(self.results),
            "in_virustotal_database": {
                "count": found_count,
                "malicious": malicious_count,
                "clean": clean_count
            },
            "not_in_virustotal_database": not_found_count,
            "errors": len(self.errors),
            "results": self.results,
            "error_details": self.errors if self.errors else None
        }
        
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Results exported to: {output_file}\n")
        return output_file


def load_md5_list(input_source: str) -> List[str]:
    """
    Load MD5 hashes from file or use provided list.
    """
    if Path(input_source).exists():
        with open(input_source, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        # If input is not a file, assume it's a comma-separated list
        return [h.strip() for h in input_source.split(",") if h.strip()]


def load_found_hashes_from_json(json_file: str) -> List[str]:
    """
    Load hashes marked as 'found': true from stage 1 JSON output.
    """
    try:
        with open(json_file, "r") as f:
            data = json.load(f)
        
        found_hashes = []
        for md5, result in data.get("results", {}).items():
            if isinstance(result, dict) and result.get("found") is True:
                found_hashes.append(md5)
        
        return found_hashes
    
    except Exception as e:
        print(f"ERROR: Failed to load hashes from JSON: {e}")
        sys.exit(1)


def stage1_search(api_key: str):
    """Run Stage 1: Initial MD5 search."""
    # Get input source
    print("\nEnter MD5 hashes to search:")
    print("  - Path to a file (one MD5 per line), OR")
    print("  - Comma-separated MD5 values")
    input_source = input("\nInput: ").strip()
    
    if not input_source:
        print("ERROR: No input provided.")
        sys.exit(1)
    
    # Load hashes
    try:
        md5_list = load_md5_list(input_source)
    except Exception as e:
        print(f"ERROR: Failed to load hashes: {e}")
        sys.exit(1)
    
    if not md5_list:
        print("ERROR: No valid MD5 hashes found.")
        sys.exit(1)
    
    # Validate MD5 format (basic check)
    valid_hashes = []
    for h in md5_list:
        if len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h):
            valid_hashes.append(h)
        else:
            print(f"WARNING: Skipping invalid MD5 format: {h}")
    
    if not valid_hashes:
        print("ERROR: No valid MD5 hashes to search.")
        sys.exit(1)
    
    print(f"\nLoaded {len(valid_hashes)} valid MD5 hash(es)")
    
    # Initialize searcher and run batch search
    searcher = VirusTotalBatchSearcher(api_key)
    searcher.search_batch(valid_hashes)
    
    # Export results
    output_file = searcher.export_json()
    
    # Print summary
    print("Summary:")
    found_count = len([v for v in searcher.results.values() if v.get("found") is True])
    not_found_count = len([v for v in searcher.results.values() if v.get("found") is False])
    print(f"  Found in database: {found_count}")
    print(f"  Not in database: {not_found_count}")
    if searcher.errors:
        print(f"  Errors: {len(searcher.errors)}")
    
    return output_file


def stage2_analyze(api_key: str):
    """Run Stage 2: Detailed analysis of found hashes."""
    # Get stage 1 JSON file
    print("\nEnter path to Stage 1 JSON output file:")
    json_file = input("Path: ").strip()
    
    if not json_file or not Path(json_file).exists():
        print("ERROR: JSON file not found.")
        sys.exit(1)
    
    # Load found hashes
    found_hashes = load_found_hashes_from_json(json_file)
    
    if not found_hashes:
        print("ERROR: No hashes marked as 'found' in the JSON file.")
        sys.exit(1)
    
    print(f"\nLoaded {len(found_hashes)} found hash(es) from JSON")
    
    # Initialize analyzer and run detailed analysis
    analyzer = VirusTotalDetailedAnalyzer(api_key)
    analyzer.analyze_batch(found_hashes)
    
    # Export results
    output_file = analyzer.export_json()
    
    # Print summary
    print("Summary:")
    successful = len([v for v in analyzer.detailed_results.values() if "error" not in v])
    print(f"  Successful analyses: {successful}")
    if analyzer.errors:
        print(f"  Errors: {len(analyzer.errors)}")


def load_md5_list(input_source: str) -> List[str]:
    """
    Load MD5 hashes from file or use provided list.
    """
    if Path(input_source).exists():
        with open(input_source, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        # If input is not a file, assume it's a comma-separated list
        return [h.strip() for h in input_source.split(",") if h.strip()]


def main():
    """Main execution."""
    print("\n" + "="*60)
    print("VirusTotal Batch Search & Analysis Tool")
    print("="*60 + "\n")
    
    # Get API Key
    api_key = input("Enter your VirusTotal API key: ").strip()
    if not api_key:
        print("ERROR: API key is required.")
        sys.exit(1)
    
    # Choose stage
    print("\nChoose operation:")
    print("  1 - Stage 1: Search for MD5 hashes (initial scan)")
    print("  2 - Stage 2: Detailed analysis of found hashes (requires Stage 1 output)")
    
    choice = input("\nSelect (1 or 2): ").strip()
    
    if choice == "1":
        stage1_search(api_key)
    elif choice == "2":
        stage2_analyze(api_key)
    else:
        print("ERROR: Invalid choice.")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user.")
        sys.exit(0)
