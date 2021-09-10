# VT-Hash-Finder

This is a simple python script to lookup one type of hash in Virustotal and outputs all 3 types of hashes.
This is useful when you need convert a specific type of malware hash to MD5, SHA1 and SHA256 in scenarios where some security products (ex: AV, EDR, SIEM, FW etc.) only supports specific type of hash when feeding Malware IOCs for blacklisting.

# Usage

```python
python3 vt-hash-finder.py <virustotal api-key> <hash_list.txt>
```
