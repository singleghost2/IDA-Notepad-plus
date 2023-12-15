"""
Author: Alexander Hanel, dddong 
Version: 1.1
Purpose: Document viewer for IDA. 
Updates:
    * Version 1.0   - Release
    * Version 1.1   - Fixed issues with opening and closing widget 
"""

import os
import ida_kernwin
import ida_idaapi
import ida_name
import idc 
import idaapi 

from idaapi import PluginForm
from PyQt5 import QtWidgets
from PyQt5.QtGui import QFont 

# Path to the Markdown docs. Folder should start with 
IDB_DIR = os.path.dirname(idc.get_idb_path())
API_MD = os.path.join(IDB_DIR, "Notes-" + idaapi.get_root_filename())
if not os.path.exists(API_MD):
    os.mkdir(API_MD)

# global variables used to track initialization/creation of the forms.  
started = False
frm = None 

def get_selected_name():
    try:
        v = ida_kernwin.get_current_viewer()
        ret = ida_kernwin.get_highlight(v)
        if ret is None:
            print("No identifier was highlighted")
            return None 
        name, flag = ret 
        t = ida_name.FUNC_IMPORT_PREFIX
        if name.startswith(t):
            return name[len(t):]
        return name
    except:
        return None 

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
        
        self.markdown_viewer = QtWidgets.QTextEdit()
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

        self.md_path = os.path.join(API_MD, self.api_name + ".md" )
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
