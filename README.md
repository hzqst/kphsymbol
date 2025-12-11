## Toolkits for KPH Dynamic Data

[kphdyn.xml](https://github.com/winsiderss/systeminformer/blob/master/kphlib/kphdyn.xml).

Requirements:
```
pip install pefile requests
```

## Download PE & Symbol listed in kphdyn.xml from msdl

Downloads PE files and their corresponding PDB symbol files from Microsoft Symbol Server
based on entries from `kphdyn.xml`

Usage, [] for optional:

```
python download_symbols.py -xml="path/to/kphdyn.xml" -symboldir="C:/Symbols" [-arch=amd64] [-version=10.0.10240.16393] [-symbol_server="https//msdl.microsoft.com/download/symbols"]
```

Files downloaded:

```
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntoskrnl.exe
C:\Symbols\amd64\ntoskrnl.exe.10.0.10240.16393\ntkrnlmp.pdb
...others
```

## Adding new symbol to kphdyn.xml

```
python update_symbols.py -xml="path/to/kphdyn.xml" -symbol="EPROCESS->Protection" -symname="EpProtection"
```

Adds `EpProtection` to `kphdyn.xml`

## Add new ntoskrnl entry to kphdyn.xml with known MD5/SHA256

```
python add_ntoskrnl_from_virustotal.py -xml="path/to/kphdyn.xml" -md5=9F4D868D410F6D68D0A73C9139D754B0 -apikey="{YourAPIKey}"
```

An entry `9F4D868D410F6D68D0A73C9139D754B0  10.0.26100.5067 (amd64)` will be added to `kphdyn.xml`

Get a valid api key from https://www.virustotal.com/