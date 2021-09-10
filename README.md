# VT-Hash-Finder

> This is a simple python script to lookup one type of hash in Virustotal and outputs all 3 types of hashes.

<br>

> This is useful when you need convert a specific type of malware hash to MD5, SHA1 and SHA256 in scenarios where some security products (ex: AV, EDR, SIEM, FW etc.) only supports specific type of hash when feeding Malware IOCs for blacklisting.

<br>

## Usage

```python
python3 vt-hash-finder.py <api-key> hashes.txt
```

<br>

## Output

> This will output a csv file (hashes.csv) consists of all the hashes.

|input_hash | names | md5 |sha1 | sh256 |
|:----------|:------|:----|:----|:------|
|xxx        | xxx   | xxx | xxx | xxx   |
