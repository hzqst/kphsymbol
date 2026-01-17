You are a reverse engineering expert. I have two disassembly outputs of the same function from two different Windows kernel versions.

**Reference version (with full symbols):**
```
{reference.procedure}
```

**Target version (with missing symbols):**
```
{reverse.procedure}
```

Based on the code structure and calling patterns, please identify the mapping between the unnamed symbols (like sub_XXXXXXXX, loc_XXXXXXXX) in the target version and the named symbols in the reference version.

Output format (YAML only, no explanations):
```yaml
sub_XXXXXXXX: SymbolName
loc_XXXXXXXX: LabelName
```

If there are no unmapped symbols to map, output an empty YAML:
```yaml
```
