# Ghidra Pattern Extractor Plugin
# Extract hex patterns from selected functions for Frida hooking
# @category Security.Mobile
# @menupath Tools.GhidraPatternExtractor

import json
import os
from ghidra.program.model.listing import CodeUnit
from javax.swing import (JOptionPane, JTextField, JPanel, JLabel, JCheckBox, 
                         JTextArea, JScrollPane, JButton, JFrame, JTabbedPane, 
                         BorderFactory)
from java.awt import (GridLayout, BorderLayout, FlowLayout, Toolkit, Font, Dimension)
from java.awt.datatransfer import StringSelection

class PatternExtractor:
    def __init__(self):
        self.default_bytes = 20
        self.include_wildcards = True
        
    def run(self):
        try:
            if not self.showOptionsDialog():
                return
                
            selected_functions = self.getSelectedFunctions()
            if not selected_functions:
                JOptionPane.showMessageDialog(None, "No functions selected. Please select one or more functions.")
                return
                
            patterns = []
            for func in selected_functions:
                pattern_data = self.extractPattern(func)
                if pattern_data:
                    patterns.append(pattern_data)
                    
            if patterns:
                self.showResultsDialog(patterns)
            else:
                print("No patterns extracted.")
                
        except Exception as e:
            print("Error: {}".format(str(e)))

    def getSelectedFunctions(self):
        functions = []
        selection = currentSelection
        if selection and not selection.isEmpty():
            function_manager = currentProgram.getFunctionManager()
            addresses = selection.getAddresses(True)
            for addr in addresses:
                func = function_manager.getFunctionContaining(addr)
                if func and func not in functions:
                    functions.append(func)
        
        if not functions:
            current_addr = currentAddress 
            if current_addr:
                func = currentProgram.getFunctionManager().getFunctionContaining(current_addr)
                if func:
                    functions.append(func)
        return functions

    def extractPattern(self, function):
        try:
            entry_point = function.getEntryPoint()
            func_name = function.getName()
            bytes_data = []
            addr = entry_point
            
            for i in range(self.default_bytes):
                try:
                    byte_val = getByte(addr)
                    bytes_data.append(byte_val & 0xFF)
                    addr = addr.add(1)
                except:
                    break
            
            if not bytes_data: return None
            
            hex_pattern = " ".join(["{:02x}".format(b) for b in bytes_data])
            
            pattern_data = {
                "name": func_name,
                "address": str(entry_point),
                "pattern": hex_pattern,
                "size": len(bytes_data)
            }
            
            if self.include_wildcards:
                pattern_data["smart_pattern"] = self.applySmartWildcards(hex_pattern, entry_point)
            
            return pattern_data
        except Exception as e:
            print("Error in extractPattern: {}".format(str(e)))
            return None

    def applySmartWildcards(self, pattern, start_addr):
        bytes_array = pattern.split(" ")
        smart_pattern = []
        addr = start_addr
        for i, byte_hex in enumerate(bytes_array):
            try:
                inst = getInstructionAt(addr)
                if inst:
                    is_addr = False
                    for j in range(inst.getNumOperands()):
                        for op in inst.getOpObjects(j):
                            if "Address" in str(type(op)):
                                is_addr = True
                    
                    if is_addr and i > 0:
                        smart_pattern.append("??")
                    else:
                        smart_pattern.append(byte_hex)
                    addr = addr.add(1)
                else:
                    smart_pattern.append(byte_hex)
                    addr = addr.add(1)
            except:
                smart_pattern.append(byte_hex)
        return " ".join(smart_pattern)

    def showOptionsDialog(self):
        panel = JPanel(GridLayout(0, 2, 10, 10))
        bytes_field = JTextField(str(self.default_bytes))
        wildcard_cb = JCheckBox("Apply Smart Wildcards", self.include_wildcards)
        
        panel.add(JLabel("Bytes to extract:"))
        panel.add(bytes_field)
        panel.add(JLabel("Options:"))
        panel.add(wildcard_cb)
        
        result = JOptionPane.showConfirmDialog(None, panel, "Pattern Extractor Options", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            try:
                self.default_bytes = int(bytes_field.getText())
                self.include_wildcards = wildcard_cb.isSelected()
                return True
            except ValueError:
                return False
        return False

    def showResultsDialog(self, patterns):
        frame = JFrame("Extracted Frida Patterns")
        frame.setSize(Dimension(500, 300))
        frame.setLayout(BorderLayout())
        
        tabs = JTabbedPane()

        for p in patterns:
            # Create a panel for each function found
            func_panel = JPanel(BorderLayout(10, 10))
            func_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            
            display_pattern = p.get('smart_pattern', p['pattern'])
            
            # Text area for the hex
            text_area = JTextArea(display_pattern)
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            text_area.setFont(Font("Monospaced", Font.PLAIN, 12))
            text_area.setEditable(False)
            
            scroll_pane = JScrollPane(text_area)
            func_panel.add(scroll_pane, BorderLayout.CENTER)
            
            # Copy Button logic
            btn_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
            copy_btn = JButton("Copy to Clipboard")
            
            def copy_action(e, pattern=display_pattern):
                selection = StringSelection(pattern)
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, None)
                # Small visual feedback in Ghidra console
                print("Copied pattern for {} to clipboard.".format(p['name']))

            copy_btn.addActionListener(copy_action)
            btn_panel.add(copy_btn)
            func_panel.add(btn_panel, BorderLayout.SOUTH)
            
            tabs.addTab(p['name'], func_panel)

        frame.add(tabs, BorderLayout.CENTER)
        frame.setLocationRelativeTo(None)
        frame.setVisible(True)

if __name__ == "__main__":
    extractor = PatternExtractor()
    extractor.run()
