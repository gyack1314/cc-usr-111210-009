# TAR逻辑范围

实体序号从1开始，PAX x/g不计实体。普通文件typeflag为0或NUL，x为下个实体局部扩展、g为全局；PAX size按物理成员payload字节数覆盖header size。GNU sparse1额外GNU.sparse.realsize为逻辑大小，GNU.sparse.name作为实际名字，局部path优先于sparse.name再优先ustar prefix/name。空PAX值删除同键继承，其他不认识的键原样保留；局部头可以连续叠加，遇实体后清空。

GNU sparse1 payload开头十进制行：extent数量，然后每个offset/length两行；表后补齐到512边界，再是extent实体字节相接，所有填充不计逻辑内容。允许长度0的末extent且不得逆序，正extent不重叠；逻辑孔洞以迭代零块返回，不创建同长bytes对象。窗口[start,start+length)按EOF截短，读取记录包含各输出块来自hole或实际归档范围。超出EOF返回空并标截短。

尾部两个512零块之后只允许零填充。base256仅正数，不接受负size。路径按POSIX语义，拒绝根路径、上级逃逸与NUL，反斜杠保留字面且不拼成本地路径。软硬链接、设备和目录只清点，窗口不读取。合成归档含普通重名成员及32字节稀疏逻辑文件。

## 索引与窗口记录

尾部状态`tail_status`：`ok`两个零块后仅零填充，`garbage`尾部含非零字节，`truncated`零块不足或成员/扩展数据被截断；后两者只标记状态，已索引成员仍可查询。成员身份为`归档sha256:实体序号`，重名成员分别留存；按名称查询有多项时必须显式给实体序号，不默认取最后一个。索引成员记录原头字段、PAX键值及其来源（global/local）、逻辑extent与物理偏移。

窗口输出逐块记录：`source`为`hole`（孔洞，不读物理字节）或`data`（归档实际范围，附`physical`物理偏移），`logical`为块在逻辑流的起点，`length`为块长，块长不超过清单`max_chunk_bytes`。窗口结果附`truncated`截短标记与整体sha256；`entity`超界、成员不支持窗口或配置越界都按错误处理。`max_index_members`限制实体数量。
