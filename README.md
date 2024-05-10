[中文](/README_ch.md)
# Introduction
This plugin replaces the built-in notepad window in IDA, which is not user-friendly, and adds many practical features. The notepad in IDA is shared globally, but my idea is to provide a separate notepad space for each function. 

Security researchers can view the content of the corresponding function in the notepad while looking at a specific function in the pseudocode window. All these contents are synchronized to the disk, making it convenient to search for keywords using search tools outside of IDA. Additionally, the notepad provides extra small but useful features.

# Features
1. Quickly create a notepad for the current function using a keyboard shortcut.
2. Quickly create a notepad for any highlighted content in pseudocode window or disassembly window.
3. Changes made in the notepad are automatically saved to the disk.
4. When the "Sync" option is enabled, switching functions in the pseudocode window will also switch the notepad window to the corresponding function
5. When the "AutoJump" option is enabled, selecting an address in the notepad will automatically jump to that address
6. Provide an "AutoCreate" option, which configures whether user confirmation is required before creating a note.

Demonstration of creating a new note and enabling the "Sync" option

![This is an image](/assets/create_md.gif "Create notepad example")

Demonstration of creating a note for highlighted content or opening the corresponding note

![This is an image](/assets/highlight_md.gif "Create highlight notepad example")

Demonstration of the "AutoJump" feature

![This is an image](/assets/autojump.gif "Autojump example")

# Installation
Copy ida_notepad_plus.py to the plugin directory of IDA
Or use the PluginLoader plugin and add the path of ida_notepad_plus.py to plugins.list

# TODO
1. Support more jump methods for the "AutoJump" feature, such as module+offset, function name

# Credits
Thanks to @Alexander Hanel's DocsViewerIDA! Inspired by this project.