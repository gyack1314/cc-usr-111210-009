# 仓储TAR稀疏导出的逻辑窗口采集

这是商品与服务履约资料的独立Python工具。`data/`保存合成报文、导出文件或解码服务响应，`source_data.io`读取清单并核对原文件身份，`source_data.tarwindow`建立TAR只读索引并按逻辑字节窗口取资料（ustar、PAX全局/局部扩展头、GNU PAX sparse 1.0；其他GNU sparse版本、旧式扩展与链接成员只列不支持），`source_data.domain`提供原始资料概况与窗口采集，`source_data.replay`按记录返回响应，`source_data.cli`显示JSON摘要。字段与来源格式见[资料约定](docs/data-contract.md)。不接入真实商家、支付账户或在线平台。

Python 3.11及以上，无第三方Python依赖。在项目根目录使用：

```sh
python -m unittest discover -s tests -v
python -m compileall -q source_data tests
python -m source_data.cli inspect data/normal.json
python -m source_data.cli collect data/normal.json
```

`inspect`仅读取清单、原始字节身份和基本配置，不覆盖资料。`collect`按清单`windows`取逻辑窗口：索引只读头部、PAX数据与稀疏extent表，窗口只读命中物理范围，孔洞以不超过`max_chunk_bytes`的零块迭代返回，不把整包落地展开；输出各窗口截短标记、内容摘要与逐块来源（hole或归档物理偏移）。`invalid-config.json`是配置反例，其他清单有不同的源边界，边界报文可以保持合法清单但源内容不完整。资料中的姓名、编号、订单和站点均为虚构。

Dockerfile固定Linux基础镜像。`docker build -t commerce-source .`构建，`docker run --rm commerce-source`读取正常清单；`docker run --rm commerce-source python -m unittest discover -s tests -v`运行已有检查。运行资料均在本地，不需要账号、安装脚本或生产系统。
