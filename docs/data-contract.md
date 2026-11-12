# TAR逻辑范围

实体序号从1开始，PAX x/g不计实体。普通文件typeflag为0或NUL，x为下个实体局部扩展、g为全局；PAX size按物理成员payload字节数覆盖header size。GNU sparse1额外GNU.sparse.realsize为逻辑大小，GNU.sparse.name作为实际名字，局部path优先于sparse.name再优先ustar prefix/name。空PAX值删除同键继承，其他不认识的键原样保留；局部头可以连续叠加，遇实体后清空。

GNU sparse1 payload开头十进制行：extent数量，然后每个offset/length两行；表后补齐到512边界，再是extent实体字节相接，所有填充不计逻辑内容。允许长度0的末extent且不得逆序，正extent不重叠；逻辑孔洞以迭代零块返回，不创建同长bytes对象。窗口[start,start+length)按EOF截短，读取记录包含各输出块来自hole或实际归档范围。超出EOF返回空并标截短。

尾部两个512零块之后只允许零填充。base256仅正数，不接受负size。路径按POSIX语义，拒绝根路径、上级逃逸与NUL，反斜杠保留字面且不拼成本地路径。软硬链接、设备和目录只清点，窗口不读取。合成归档含普通重名成员及32字节稀疏逻辑文件。
