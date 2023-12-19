"""
Author: Alexander Hanel, dddong 
Version: 1.1
Purpose: Document viewer for IDA. 
Updates:
    * Version 1.0   - Release
    * Version 1.1   - Fixed issues with opening and closing widget 
"""

import os, re, sys, traceback  
import ida_kernwin
import ida_idaapi
import ida_name
import idc 
import idaapi 

from idaapi import PluginForm
from PyQt5 import QtWidgets
from PyQt5.QtGui import QFont 
from PyQt5.QtWidgets import QApplication, QTextEdit, QMenu, QFontDialog
import sark 


# Path to the Markdown docs. Folder should start with 
IDB_DIR = os.path.dirname(idc.get_idb_path())
API_MD = os.path.join(IDB_DIR, "Notes-" + idaapi.get_root_filename())
if not os.path.exists(API_MD):
    os.mkdir(API_MD)

# global variables used to track initialization/creation of the forms.  
started = False
frm = None 



def clean_filename(filename):
    # 由于MAC与Linux只限制少量字符, 而Windows限制的字符较多，
    # 以下为三个系统的非法字符并集
    invalid_chars = '<>:"/\\|?*'
    
    # 为了安全起见, 这里还包括了ASCII控制字符（0-31）
    control_chars = ''.join(map(chr, range(0, 32)))
    
    # 将所有非法字符以及控制字符替换为下划线
    return re.sub('[{}{}]'.format(re.escape(invalid_chars), re.escape(control_chars)), '_', filename)

def get_selected_name():
    try:
        v = ida_kernwin.get_current_viewer()
        ret = ida_kernwin.get_highlight(v)
        name = None
        if ret is None:
            # 判断是不是在伪代码窗口，如果是，返回当前显示的函数名
            if idaapi.get_widget_type(v) == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(v)
                fn = sark.Function(ea=vu.cfunc.entry_ea)
                name = fn.demangled 
            else:    
                print("No identifier was highlighted")
                return None
        else: 
            name, flag = ret 
        t = ida_name.FUNC_IMPORT_PREFIX
        if name.startswith(t):
            name = name[len(t):]
        name = name.lstrip('_')
        if '(' in name:
            name = name[:name.index('(')]
        return name
    except Exception as e:
        # traceback.print_exc()
        return None 


class CustomTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super(CustomTextEdit, self).__init__(parent)
        
    def contextMenuEvent(self, event):
        # 创建标准右键菜单
        menu = self.createStandardContextMenu()

        # 添加一个分隔符
        menu.addSeparator()
        
        # 添加一个自定义菜单项
        fontAction = menu.addAction("Font")
        
        # 连接信号槽
        fontAction.triggered.connect(self.changeFont)
        
        # 执行菜单
        menu.exec_(event.globalPos())

    def changeFont(self):
        # 打开字体对话框
        font, ok = QFontDialog.getFont(self.font(), self)
        if ok:
            # 设置文本框的字体
            self.setFont(font)

    def insertFromMimeData(self, source):
        # 只有在MIME数据中有文本时，才执行插入操作
        if source.hasText():
            # 获取MIME数据中的纯文本
            text = source.text()
            # 插入纯文本
            self.insertPlainText(text)
        else:
            # 对于其他类型的数据，调用基类的默认行为
            super(CustomTextEdit, self).insertFromMimeData(source)

class DocViewer(PluginForm):
    def OnCreate(self, form):
        """
        defines widget layout 
        """
        self.api_name = None 
        self.md_path = None 

        self.parent = self.FormToPyQtWidget(form)
        self.main_layout = QtWidgets.QVBoxLayout()
        self.markdown_viewer_label = QtWidgets.QLabel()
        self.markdown_viewer_label.setText("API MSDN Docs")
        font = QFont("Microsoft YaHei")
        font.setBold(True)
        self.markdown_viewer_label.setFont(font)
        
        self.markdown_viewer = CustomTextEdit()
        self.markdown_viewer.setFontFamily("Courier")
        self.main_layout.addWidget(self.markdown_viewer_label)
        self.main_layout.addWidget(self.markdown_viewer)
        self.parent.setLayout(self.main_layout)
        self.load_markdown()

    def load_markdown(self):
        """
        gets api and load corresponding (if present) api markdown 
        """
        self.save()

        self.api_name = get_selected_name()
        if not self.api_name:
            api_markdown ="#### Invalid Address Selected"
            self.markdown_viewer.setMarkdown(api_markdown)
            return
        self.markdown_viewer_label.setText(f"`{self.api_name}` 文档")

        self.md_path = os.path.join(API_MD, clean_filename(self.api_name + ".md"))
        if os.path.isfile(self.md_path):
            with open(self.md_path, "r", encoding="utf-8") as infile:
                api_markdown = infile.read()
        else:
            btn_sel = idaapi.ask_yn(idaapi.ASKBTN_NO, f"{self.api_name}.md 没有找到，是否创建新的文件?")
            if btn_sel == idaapi.ASKBTN_CANCEL or btn_sel == idaapi.ASKBTN_NO:
                api_markdown = "!!!File not found!!!" 
            else:
                with open(self.md_path, "w", encoding="utf-8") as file:
                    pass 
                api_markdown = "" 
            
        self.markdown_viewer.setText(api_markdown)

    def save(self):
        # Save the content of the QTextEdit back to the Markdown file
        # print(f"Sava back markdown content to {self.md_path}")
        if self.api_name and os.path.isfile(self.md_path):
            with open(self.md_path, "w", encoding="utf-8") as outfile:
                outfile.write(self.markdown_viewer.toPlainText())

            
    def OnClose(self, form):
        """
        Called when the widget is closed
        """
        global frm
        global started

        self.save()

        del frm 
        started = False

class DocViewerPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MOD
    comment = "Docs Viewer, substitude for IDA's notepad window"
    help = ""
    wanted_name = "Docs Viewer"
    wanted_hotkey = "Meta-Shift-]"

    def init(self):
        self.options = (ida_kernwin.PluginForm.WOPN_MENU |
            ida_kernwin.PluginForm.WOPN_ONTOP |
            ida_kernwin.PluginForm.WOPN_RESTORE |
            ida_kernwin.PluginForm.WOPN_PERSIST |
            ida_kernwin.PluginForm.WCLS_CLOSE_LATER)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        global started
        global frm  
        if not started:
            #API_MD
            if not os.path.isdir(API_MD):
                print("ERROR: API_MD directory could not be found. Make sure to execute python run_me_first.py ")
            frm = DocViewer()
            frm.Show("Docs Viewer", options=self.options)
            started = True
        else:
            frm.load_markdown()
        
    def term(self):
        pass

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():
    return DocViewerPlugin()
