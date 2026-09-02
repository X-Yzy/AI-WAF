# 原始攻击流量

本目录保存 22 类未混淆攻击载荷、来源文件和许可证，清单共 2,260 条。每个攻击类型
目录的 `source_records.json` 是统一后的训练来源；`original_files/` 只用于溯源。

主要来源包括 PayloadsAllTheThings 和 fuzzdb。使用或再分发时必须保留根目录下的
`LICENSE-PayloadsAllTheThings.txt` 与 `LICENSE-fuzzdb.txt`。训练代码对原始载荷计算
稳定指纹，再把它与混淆变种绑定为同一数据家族。

不要删除 `original_files/` 中第三方项目自带的 README 或许可证，它们属于来源材料。
