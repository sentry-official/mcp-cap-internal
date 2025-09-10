"""Configuration management for mcpcap."""

import os
import requests
from typing import List, Optional
from urllib.parse import urljoin, urlparse


class Config:
    """Configuration management for mcpcap server."""

    def __init__(
        self, 
        pcap_path: Optional[str] = None,
        pcap_url: Optional[str] = None,
        modules: Optional[List[str]] = None,
        protocols: Optional[List[str]] = None,
        max_packets: Optional[int] = None
    ):
        """Initialize configuration.

        Args:
            pcap_path: Path to directory containing PCAP files
            pcap_url: HTTP server URL containing PCAP files
            modules: List of modules to load
            protocols: List of protocols to analyze
            max_packets: Maximum number of packets to analyze per file
        """
        self.pcap_path = pcap_path
        self.pcap_url = pcap_url
        self.modules = modules or ['dns']
        self.protocols = protocols or ['dns']
        self.max_packets = max_packets
        self.is_remote = pcap_url is not None
        
        self._validate_configuration()

    def _validate_configuration(self) -> None:
        """Validate the configuration parameters."""
        if not self.pcap_path and not self.pcap_url:
            raise ValueError("Either --pcap-path or --pcap-url must be specified")
        
        if self.pcap_path and self.pcap_url:
            raise ValueError("Cannot specify both --pcap-path and --pcap-url")
        
        if self.pcap_path:
            self._validate_pcap_path()
        
        if self.pcap_url:
            self._validate_pcap_url()
        
        if self.max_packets is not None and self.max_packets <= 0:
            raise ValueError("max_packets must be a positive integer")

    def _validate_pcap_path(self) -> None:
        """Validate that the PCAP path exists and is a directory."""
        if not os.path.exists(self.pcap_path):
            raise ValueError(f"PCAP directory '{self.pcap_path}' does not exist")

        if not os.path.isdir(self.pcap_path):
            raise ValueError(f"'{self.pcap_path}' is not a directory")

    def _validate_pcap_url(self) -> None:
        """Validate that the PCAP URL is accessible."""
        try:
            parsed = urlparse(self.pcap_url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(f"Invalid URL format: {self.pcap_url}")
            
            # Test connectivity with a HEAD request
            response = requests.head(self.pcap_url, timeout=10)
            if response.status_code >= 400:
                raise ValueError(f"Cannot access PCAP URL: {self.pcap_url} (HTTP {response.status_code})")
                
        except requests.RequestException as e:
            raise ValueError(f"Cannot connect to PCAP URL '{self.pcap_url}': {str(e)}")

    def get_pcap_file_path(self, pcap_file: str) -> str:
        """Get full path or URL to a PCAP file.

        Args:
            pcap_file: Filename or relative path to PCAP file

        Returns:
            Full path or URL to the PCAP file
        """
        if self.is_remote:
            if pcap_file.startswith('http'):
                return pcap_file
            return urljoin(self.pcap_url.rstrip('/') + '/', pcap_file)
        else:
            if os.path.isabs(pcap_file):
                return pcap_file
            return os.path.join(self.pcap_path, pcap_file)

    def list_pcap_files(self) -> list[str]:
        """List all PCAP files in the configured directory or remote URL.

        Returns:
            List of PCAP filenames
        """
        if self.is_remote:
            return self._list_remote_pcap_files()
        else:
            try:
                return [
                    f
                    for f in os.listdir(self.pcap_path)
                    if f.endswith((".pcap", ".pcapng"))
                ]
            except Exception:
                return []

    def _list_remote_pcap_files(self) -> list[str]:
        """List PCAP files from a remote HTTP server.
        
        Returns:
            List of PCAP filenames found on the remote server
        """
        try:
            response = requests.get(self.pcap_url, timeout=30)
            response.raise_for_status()
            
            # Parse HTML to find .pcap and .pcapng files
            # This is a simple implementation that looks for href attributes
            import re
            pcap_files = []
            
            # Look for links to .pcap and .pcapng files
            pattern = r'href=["\']([^"\']*\.pcapng?)["\']'
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            
            for match in matches:
                # Extract just the filename, not the full path
                filename = os.path.basename(match)
                if filename and filename not in pcap_files:
                    pcap_files.append(filename)
            
            return sorted(pcap_files)
            
        except requests.RequestException:
            return []

    def download_pcap_file(self, pcap_file: str, local_path: str) -> str:
        """Download a remote PCAP file to local storage.
        
        Args:
            pcap_file: Name of the PCAP file to download
            local_path: Local path to save the file
            
        Returns:
            Local path to the downloaded file
        """
        if not self.is_remote:
            raise ValueError("Cannot download file: not using remote source")
            
        url = self.get_pcap_file_path(pcap_file)
        
        try:
            response = requests.get(url, timeout=60, stream=True)
            response.raise_for_status()
            
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            with open(local_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            return local_path
            
        except requests.RequestException as e:
            raise ValueError(f"Failed to download PCAP file '{pcap_file}': {str(e)}")
