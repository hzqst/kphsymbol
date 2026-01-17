# 常用命令（Windows 优先）

## 安装依赖
- `python -m pip install -r requirements.txt`

## 获取 kphdyn.xml
- `powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/winsiderss/systeminformer/refs/heads/kph-staging/kphlib/kphdyn.xml' -OutFile kphdyn.xml"`

## 下载符号与 PE
- `python download_symbols.py -xml="path\to\kphdyn.xml" -symboldir="C:\Symbols" [-arch=amd64] [-version=10.0.x.x] [-symbol_server="https://msdl.microsoft.com/download/symbols"] [-fast]`

## 更新/同步 kphdyn.xml 偏移
- `python update_symbols.py -xml "kphdyn.xml" -symboldir "C:\Symbols" [-yaml kphdyn.yaml] [-syncfile] [-fast] [-fixnull]`

## 逆向缺 PDB 的符号
- `python reverse_symbols.py -symboldir "C:\Symbols" -reverse=PsSetCreateProcessNotifyRoutine -provider=openai -api_key="..." [-model "..."] [-api_base "..."] [-ida "C:\Program Files\IDA Professional 9.0\ida64.exe"]`

## 启动上传服务
- `python upload_server.py -symboldir="C:\Symbols" [-port=8000]`

## 环境变量（Windows）
- `set KPHTOOLS_XML=path\to\kphdyn.xml`
- `set KPHTOOLS_SYMBOLDIR=C:\Symbols`
- `set KPHTOOLS_SYMBOL_SERVER=https://msdl.microsoft.com/download/symbols`
- `set KPHTOOLS_SERVER_PORT=8000`
- `set OPENAI_API_KEY=...` / `set ANTHROPIC_API_KEY=...`
- `set IDA64_PATH=C:\Program Files\IDA Professional 9.0\ida64.exe`