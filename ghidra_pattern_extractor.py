# Ghidra Pattern Extractor Plugin
# Extract hex patterns from selected functions for Frida hooking
# @menupath Tools.GhidraPatternExtractor
# @toolbar

import json
import os
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SymbolType
from java.io import File
from javax.swing import JOptionPane, JTextField, JPanel, JLabel, JCheckBox, JTextArea, JScrollPane, JButton, JFrame, JTabbedPane, BorderFactory, JFileChooser
from java.awt import GridLayout, BorderLayout, FlowLayout, Toolkit, Font, Dimension
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener
from javax.swing.filechooser import FileNameExtensionFilter
import java.util.Date

# Note: We removed (GhidraScript) inheritance.
class PatternExtractor:
    def __init__(self):
        # These variables (currentProgram, currentAddress, etc.) are injected by Ghidra
        self.default_bytes = 20
        self.output_format = "frida"
        self.include_wildcards = True
        self.export_path = os.path.join(os.path.expanduser("~"), "frida_patterns.json")
        
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
        # 'currentSelection' is a global injected variable
        selection = currentSelection
        if selection and not selection.isEmpty():
            function_manager = currentProgram.getFunctionManager()
            addresses = selection.getAddresses(True)
            for addr in addresses:
                func = function_manager.getFunctionContaining(addr)
                if func and func not in functions:
                    functions.append(func)
        
        if not functions:
            current_addr = currentAddress # Global injected variable
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
                    # getByte is a global Ghidra API function
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
                "raw_pattern": hex_pattern.replace(" ", ""),
                "size": len(bytes_data),
                "description": "Pattern for {}".format(func_name)
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
                # getInstructionAt is global Ghidra API
                inst = getInstructionAt(addr)
                if inst:
                    # Logic to wildcard if the byte is part of an operand that is an address
                    # This is a simplified version of your logic
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

    # ... [Keep your GUI methods here, but replace 'self.popup' with JOptionPane] ...
    def showOptionsDialog(self):
        panel = JPanel(GridLayout(0, 2))
        bytes_field = JTextField(str(self.default_bytes))
        panel.add(JLabel("Bytes to extract:"))
        panel.add(bytes_field)
        
        result = JOptionPane.showConfirmDialog(None, panel, "Pattern Extractor Options", JOptionPane.OK_CANCEL_OPTION)
        if result == JOptionPane.OK_OPTION:
            self.default_bytes = int(bytes_field.getText())
            return True
        return False

    def showResultsDialog(self, patterns):
        # Simplified result display for brevity, use your existing TabbedPane logic here
        print("Extracted {} patterns".format(len(patterns)))
        for p in patterns:
            print("Func: {} | Pattern: {}".format(p['name'], p.get('smart_pattern', p['pattern'])))

# --- Execution ---
if __name__ == "__main__":
    extractor = PatternExtractor()
    extractor.run()
