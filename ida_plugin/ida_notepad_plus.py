import os, re, sys, traceback  
import ida_kernwin
import ida_idaapi
import ida_name
import idc 
import idaapi 
import ida_hexrays

from idaapi import PluginForm
from PyQt5 import QtWidgets
from PyQt5.QtGui import QFont 
from PyQt5.QtWidgets import QApplication, QTextEdit, QMenu, QFontDialog


# Path to the Markdown docs. Folder should start with 
IDB_DIR = ""
API_MD = ""
IDB_DIR = os.path.dirname(idc.get_idb_path())
API_MD = os.path.join(IDB_DIR,idaapi.get_root_filename())
API_MD = API_MD + "_notes"
if not os.path.exists(API_MD):
    os.mkdir(API_MD)

# global variables used to track initialization/creation of the forms.  
started = False
frm = None 



def clean_filename(filename):
    # Since MAC and Linux only limit a small number of characters, while Windows limits more characters,
    # The following is the union of illegal characters from the three systems
    invalid_chars = '<>:"/\\|?*'
    
    # For security reasons, ASCII control characters (0-31) are also included here
    control_chars = ''.join(map(chr, range(0, 32)))
    
    # 将所有非法字符以及控制字符替换为下划线
    # Replace all illegal characters as well as control characters with underscores
    return re.sub('[{}{}]'.format(re.escape(invalid_chars), re.escape(control_chars)), '_', filename)

def normalize_name(name):
    t = ida_name.FUNC_IMPORT_PREFIX
    if name.startswith(t):
        name = name[len(t):]
    name = name.lstrip('_')
    if '(' in name:
        name = name[:name.index('(')]
    return name 

def demangle(name, disable_mask=0):
    demangled_name = idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL)
    if demangled_name:
        return demangled_name
    return name

def get_selected_name():
    try:
        v = ida_kernwin.get_current_viewer()
        ret = ida_kernwin.get_highlight(v)
        name = None
        if ret is None:
            # Determine whether it is in the pseudocode window. If so, return the currently displayed function name.
            if idaapi.get_widget_type(v) == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(v)
                name = idaapi.get_ea_name(vu.cfunc.entry_ea)
                name = demangle(name)
            else:    
                print("No identifier was highlighted")
                return None
        else: 
            name, flag = ret 
        
        return normalize_name(name)
    except Exception as e:
        # traceback.print_exc()
        return None 


class CustomTextEdit(QTextEdit):
    def __init__(self, pluginForm, parent=None):
        super(CustomTextEdit, self).__init__(parent)
        self.pluginForm = pluginForm
        # Create a standard right-click context menu
        self.menu = self.createStandardContextMenu()

        # add a separator
        self.menu.addSeparator()
        
        # Add custom menu items
        self.fontAction = self.menu.addAction("Font")
        self.SyncAction = self.menu.addAction("Sync")
        self.autoJumpAction = self.menu.addAction("AutoJump")

        self.menu.addSeparator()
        self.autoCreateOption = self.menu.addAction("AutoCreate")
        
        # Connect signal slots
        self.fontAction.triggered.connect(self.changeFont)
        self.SyncAction.triggered.connect(self.changeSync)
        self.autoJumpAction.triggered.connect(self.changeAutoJumpSetting)
        self.autoCreateOption.triggered.connect(self.changeAutoCreateOption)

        self.autoJump = False 
        
    def contextMenuEvent(self, event):
        self.menu.exec_(event.globalPos())

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)

        if self.autoJump:
            selected_text = self.textCursor().selectedText().strip()
            if selected_text:
                # print(f"Selected text: {selected_text}")
                match_obj = re.match(r'^(0x)?([0-9a-f`]+)$', selected_text, flags=re.IGNORECASE)
                if match_obj is not None:
                    addr_str = match_obj.group(2)
                    addr_str = addr_str.replace('`', '')
                    # print(f"jumpto addr {hex(int(addr_str, 16))}")
                    idaapi.jumpto(int(addr_str, 16))
                else:
                    try:
                        ea = idc.get_name_ea_simple(selected_text)
                        idaapi.jumpto(ea)
                    except:
                        pass 
        

    def changeFont(self):
        # Open font dialog
        font, ok = QFontDialog.getFont(self.font(), self)
        if ok:
            self.setFont(font)
        
    def changeSync(self):
        self.pluginForm.sync = not self.pluginForm.sync 
        if self.pluginForm.sync:
            self.SyncAction.setText("Sync ✔")
        else:
            self.SyncAction.setText("Sync")

    def changeAutoJumpSetting(self):
        if self.pluginForm.sync:
            self.changeSync()

        self.autoJump = not self.autoJump
        if self.autoJump:
            self.autoJumpAction.setText("AutoJump ✔")
        else:
            self.autoJumpAction.setText("AutoJump")

    def changeAutoCreateOption(self):
        self.pluginForm.autoCreate = not self.pluginForm.autoCreate 
        if self.pluginForm.autoCreate:
            self.autoCreateOption.setText("AutoCreate ✔")
        else:
            self.autoCreateOption.setText("AutoCreate")

    def insertFromMimeData(self, source):
        # 只有在MIME数据中有文本时，才执行插入操作
        # Only perform insert operations if there is text in the MIME data
        if source.hasText():
            # Get plain text from MIME data
            text = source.text()
            # Insert plain text
            self.insertPlainText(text)
        else:
            # For other types of data, the default behavior of the base class is invoked
            super(CustomTextEdit, self).insertFromMimeData(source)



class DocViewer(PluginForm):
    class HexRaysEventHandler(ida_hexrays.Hexrays_Hooks):
        def __init__(self, docViewer):
            super().__init__()
            self.docViewer = docViewer 

        def switch_pseudocode(self, vdui):
            name = demangle(idaapi.get_ea_name(vdui.cfunc.entry_ea))
            name = normalize_name(name)
            self.docViewer.load_markdown(api_name_force = name)
            return 1 
        

    def OnCreate(self, form):
        self.autoCreate = False 
        """
        defines widget layout 
        """
        self.api_name = None 
        self.md_path = None 

        self.parent = self.FormToPyQtWidget(form)
        self.main_layout = QtWidgets.QVBoxLayout()
        self.markdown_viewer_label = QtWidgets.QLabel()
        self.markdown_viewer_label.setText("IDA Notepad+")
        font = QFont("Microsoft YaHei")
        font.setBold(True)
        self.markdown_viewer_label.setFont(font)
        
        self.markdown_viewer = CustomTextEdit(self)
        self.markdown_viewer.setFontFamily("Courier")
        self.main_layout.addWidget(self.markdown_viewer_label)
        self.main_layout.addWidget(self.markdown_viewer)
        self.parent.setLayout(self.main_layout)
        self.load_markdown()

        self.pseudocodeSwitchEventHandler = self.HexRaysEventHandler(self)
        self._sync = False 

    @property 
    def sync(self):
        return self._sync 
    
    @sync.setter 
    def sync(self, new_value):
        if new_value:
            self.pseudocodeSwitchEventHandler.hook()
            v = ida_kernwin.get_current_viewer()
            # 判断是不是在伪代码窗口，如果是, 显示当前伪代码窗口中的函数
            # Determine whether it is in the pseudocode window. If so, display the function in the current pseudocode window.
            if idaapi.get_widget_type(v) == idaapi.BWN_PSEUDOCODE:
                vu = idaapi.get_widget_vdui(v)
                name = demangle(idaapi.get_ea_name(vu.cfunc.entry_ea))
                name = normalize_name(name) 
                self.load_markdown(api_name_force = name)
        else:
            self.pseudocodeSwitchEventHandler.unhook()
        self._sync = new_value 

    def load_markdown(self, api_name_force = None):
        """
        gets api and load corresponding (if present) api markdown 
        """
        self.save()

        self.api_name = api_name_force if api_name_force else get_selected_name()
        if not self.api_name:
            api_markdown ="#### Invalid Address Selected"
            self.markdown_viewer.setMarkdown(api_markdown)
            return
        self.markdown_viewer_label.setText(f"`{self.api_name}` doc")

        self.md_path = os.path.join(API_MD, clean_filename(self.api_name + ".md"))
        if os.path.isfile(self.md_path):
            with open(self.md_path, "r", encoding="utf-8") as infile:
                api_markdown = infile.read()
        else:
            if not self.autoCreate:
                btn_sel = idaapi.ask_yn(idaapi.ASKBTN_NO, f"{self.api_name}.md is not found, create new file or not?")
                if btn_sel == idaapi.ASKBTN_CANCEL or btn_sel == idaapi.ASKBTN_NO:
                    api_markdown = "!!!File not found!!!" 
                else:
                    with open(self.md_path, "w", encoding="utf-8") as file:
                        pass 
                    api_markdown = "" 
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
        self.pseudocodeSwitchEventHandler.unhook()
        # print("PseudocodeEventHandler unhook")

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
