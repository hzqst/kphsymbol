# 任务完成时的建议

- 若修改了脚本参数或行为，优先用最小样例运行相关脚本（如 `download_symbols.py`/`update_symbols.py`/`reverse_symbols.py`）验证。
- 若修改了 `kphdyn.xml`/`kphdyn.yaml`，检查输出结构与字段 ID/偏移是否符合预期。
- 若新增依赖或环境变量，请更新 `requirements.txt` 与 `README.md` 中的使用说明。
- 项目未提供统一测试/格式化命令；提交前确保主要脚本可运行并输出正常。
