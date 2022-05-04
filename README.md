# VT-Hash-Converter

> This is a simple python script to lookup one type of hash in Virustotal and outputs all 3 hashes supported by VirusTotal (MD5, SHA1, SHA256).

<br>

> This is useful when you need to find the other hash types of a particular malware hash. In scenarios where some security products (ex: AV, EDR, SIEM, FW etc.) only supports specific type of hash when feeding Malware IOCs for blacklisting/monitoring, you can feed the available hash list as a file to this script and get all 3 hashes as an output.

<br>

## Usage

```python
python3 vt-hash-converter.py <api-key> hashes.txt
```

<br>

## Output

> This will output a csv file (hashes.csv) consists of all the hashes.

|input_hash | names | md5 | sha1 | sha256 |
|:----------|:------|:----|:-----|:-------|
|xxx        | xxx   | xxx | xxx  | xxx    |
