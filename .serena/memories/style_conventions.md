# 代码风格与约定

- 未发现显式的格式化/静态检查配置（未见 `pyproject.toml`/`ruff`/`black`/`flake8` 等）。
- 脚本风格为标准 Python CLI（`argparse` + 顶部模块级 docstring）。
- 建议遵循 PEP 8，变量/函数命名使用 `snake_case`，保留已有脚本的参数命名和环境变量约定。
- 若新增依赖或参数，请同步更新 `README.md` 与 `requirements.txt`。
