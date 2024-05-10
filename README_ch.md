# 简介
替代了 IDA 自带的不好用的记事本窗口，添加了很多实用的功能。 IDA 的记事本是全局共用的， 而我的想法是给每个函数都有自己的记事本空间， 安全研究员在伪代码窗口中看哪个函数， 记事本就显示对应函数的内容。 这些内容都会同步到磁盘上， 也方便在 IDA 之外使用搜索工具查询关键字。 此外记事本还提供了选中地址自动跳转的小功能。

# 功能
1. 快捷键快速创建当前函数的记事本
2. 如果伪代码窗口或者反汇编窗口有任何高亮选中的内容，快捷键为该内容创建记事本
2. 用户在记事本中所做的更改， 会自动保存写入到磁盘
3. 开启 sync 选项， 伪代码窗口中函数切换， 记事本窗口也会切换到对应的函数
4. 开启 autojump 选项， 选中记事本中的地址， 会自动跳转
5. 提供 AutoCreate 选项，通过此选项配置 在创建笔记之前是否需要用户确认

演示创建新的笔记和开启 sync 选项

![这是图片](/assets/create_md.gif "Create notepad example")

演示为高亮的内容创建笔记或打开对应的笔记

![这是图片](/assets/highlight_md.gif "Create highlight notepad example")

演示 autojump 功能

![这是图片](/assets/autojump.gif "Autojump example")

# 安装
把 ida_notepad_plus.py 拷贝到 IDA 的插件目录下
或者使用PluginLoader 插件， 将 ida_notepad_plus.py的路径添加到 plugins.list 

# TODO
3. 提交到 github
4. autojump 功能支持更多跳转方式， 例如 module+offset, 函数名

# credits
Thanks to @Alexander Hanel's DocsViewerIDA! 受此项目启发