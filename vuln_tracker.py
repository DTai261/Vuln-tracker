#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Burp Suite Vuln tracker Extension
Automatically highlights HTTP requests that match specified paths/URLs
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorTabFactory, IMessageEditorTab
from java.awt import Component, GridBagLayout, GridBagConstraints, Insets, Color, BorderLayout, Dimension, FlowLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JLabel, JSplitPane
from javax.swing import JMenuItem, JOptionPane, SwingUtilities, JTabbedPane, JComboBox, JPopupMenu
from javax.swing import JTable, JTextField, ListSelectionModel, Box, BoxLayout, JFileChooser, JCheckBox, JProgressBar, BorderFactory
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from javax.swing.filechooser import FileNameExtensionFilter
import java.io
import java.lang
import re
import threading
import json
import traceback
import os
import shutil
import time
from datetime import datetime

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IMessageEditorTabFactory):
    
    def _get_path_without_params(self, url):
        """Extract the path from URL without query parameters for consistent grouping"""
        try:
            if hasattr(url, 'getPath'):
                path = url.getPath()
            else:
                path = str(url)
            
            # Remove query parameters (everything after ?)
            if '?' in path:
                path = path.split('?')[0]
            
            return path
        except Exception as e:
            print("Error extracting path: {}".format(str(e)))
            return str(url)
    
    def _create_request_hash(self, url, method):
        """Create a consistent hash for requests, ignoring query parameters"""
        try:
            path = self._get_path_without_params(url)
            host = ""
            
            # Try to get host for more specific grouping
            if hasattr(url, 'getHost'):
                host = url.getHost()
            elif hasattr(url, 'host'):
                host = url.host
            
            # Create hash from method + host + path (without query params)
            hash_string = "{}:{}{}".format(method, host, path)
            return hash(hash_string)
        except Exception as e:
            print("Error creating request hash: {}".format(str(e)))
            return hash(str(url) + method)
    
    def _highlight_tab_success(self):
        """Provide visual feedback for successful operations by highlighting the tab"""
        try:
            # Get the current tab index (Vuln tracker tab)
            current_tab_index = self._callbacks.getCustomTabIndex()
            
            if current_tab_index >= 0:
                # Create a brief highlight effect using a timer
                def highlight_effect():
                    try:
                        # Import Timer for delayed execution
                        from javax.swing import Timer
                        from java.awt.event import ActionListener
                        from java.awt import Color
                        
                        original_color = None
                        highlight_count = [0]  # Use list to make it mutable in closure
                        
                        class HighlightAction(ActionListener):
                            def actionPerformed(self, event):
                                try:
                                    highlight_count[0] += 1
                                    
                                    # Get the tab component
                                    if hasattr(self, '_main_panel') and self._main_panel.getParent():
                                        tab_pane = self._main_panel.getParent()
                                        
                                        if highlight_count[0] % 2 == 1:
                                            # Highlight phase - change background
                                            if hasattr(tab_pane, 'setBackgroundAt'):
                                                if original_color is None:
                                                    original_color = tab_pane.getBackgroundAt(current_tab_index) if hasattr(tab_pane, 'getBackgroundAt') else Color.WHITE
                                                tab_pane.setBackgroundAt(current_tab_index, Color.GREEN.brighter())
                                        else:
                                            # Normal phase - restore original
                                            if hasattr(tab_pane, 'setBackgroundAt') and original_color:
                                                tab_pane.setBackgroundAt(current_tab_index, original_color)
                                        
                                        # Stop after 3 blinks (6 phases)
                                        if highlight_count[0] >= 6:
                                            event.getSource().stop()
                                            # Ensure we end in normal state
                                            if hasattr(tab_pane, 'setBackgroundAt') and original_color:
                                                tab_pane.setBackgroundAt(current_tab_index, original_color)
                                                
                                except Exception as e:
                                    print("Error in highlight animation: {}".format(str(e)))
                                    # Stop the timer on error
                                    try:
                                        event.getSource().stop()
                                    except:
                                        pass
                        
                        # Create and start the timer (200ms intervals for smooth animation)
                        timer = Timer(200, HighlightAction())
                        timer.start()
                        
                    except Exception as e:
                        print("Error setting up highlight effect: {}".format(str(e)))
                        # Fallback: simple status message
                        self._show_status_feedback()
                
                SwingUtilities.invokeLater(highlight_effect)
            else:
                # Fallback if we can't get tab index
                self._show_status_feedback()
                
        except Exception as e:
            print("Error in tab highlighting: {}".format(str(e)))
            # Fallback to simple status feedback
            self._show_status_feedback()
    
    def _show_status_feedback(self, message=None):
        """Show status feedback with optional message"""
        try:
            if hasattr(self, '_status_label'):
                if message:
                    # Show the specific message
                    original_text = self._status_label.getText()
                    self._status_label.setText(message)
                    print("Status: {}".format(message))
                    
                    # Create timer to restore original text after 3 seconds
                    from javax.swing import Timer
                    from java.awt.event import ActionListener
                    
                    class RestoreAction(ActionListener):
                        def actionPerformed(self, event):
                            try:
                                self._status_label.setText(original_text)
                                event.getSource().stop()
                            except:
                                pass
                    
                    timer = Timer(3000, RestoreAction())
                    timer.start()
                else:
                    # Fallback visual feedback using status label
                    original_text = self._status_label.getText()
                    
                    # Temporarily change status text to show success
                    self._status_label.setText("Action completed successfully!")
                    
                    # Create timer to restore original text after 2 seconds
                    from javax.swing import Timer
                    from java.awt.event import ActionListener
                    
                    class RestoreAction(ActionListener):
                        def actionPerformed(self, event):
                            try:
                                self._status_label.setText(original_text)
                                event.getSource().stop()
                            except:
                                pass
                    
                    timer = Timer(2000, RestoreAction())
                    timer.start()
            else:
                print("Status feedback: {}".format(message if message else "Action completed"))
                
        except Exception as e:
            print("Error showing status feedback: {}".format(str(e)))
            if message:
                print("Intended message: {}".format(message))
    
    def _update_row_numbers(self):
        """Update the row numbers in the first column after table changes"""
        try:
            if hasattr(self, '_watch_table_model'):
                # Set flag to prevent recursion from table model listener AND prevent saving corruption
                self._is_updating_gui = True
                print("Updating row numbers - GUI update mode enabled, saving disabled")
                for row in range(self._watch_table_model.getRowCount()):
                    self._watch_table_model.setValueAt(str(row + 1), row, 0)  # Column 0 is the # column
                # Clear flag
                self._is_updating_gui = False
        except Exception as e:
            print("Error updating row numbers: {}".format(str(e)))
            # Ensure flag is cleared even on error
            if hasattr(self, '_is_updating_gui'):
                self._is_updating_gui = False
                print("GUI update flag cleared after error")
    
    def _init_database(self):
        """Initialize JSON file for persistent storage with project mapping"""
        try:
            # Initialize project management
            self._init_project_mapping()
            
            # Use current project's data file
            self._data_file_path = self._get_current_project_data_file()
            
            # Create initial data structure if file doesn't exist
            if not os.path.exists(self._data_file_path):
                initial_data = {
                    "vulnerabilities": {},
                    "watch_list_audit": [],
                    "settings": {
                        "project_name": self._current_project_name
                    },
                    "vuln_counter": 0
                }
                try:
                    # Ensure directory exists (Jython-compatible way)
                    data_dir = os.path.dirname(self._data_file_path)
                    if not os.path.exists(data_dir):
                        try:
                            os.makedirs(data_dir)
                        except OSError:
                            pass  # Directory might already exist
                    self._save_data_to_file(initial_data)
                except Exception as save_error:
                    print("Error creating initial data file: {}".format(str(save_error)))
                    # Try fallback location
                    self._data_file_path = os.path.join(os.getcwd(), "path_highlighter_data.json")
                    print("Using fallback location: {}".format(self._data_file_path))
                    self._save_data_to_file(initial_data)
            
            print("Data storage initialized successfully for project: {}".format(self._current_project_name))
            
        except Exception as e:
            print("Error initializing data storage: {}".format(str(e)))
            traceback.print_exc()
            # Fallback to current directory
            self._data_file_path = os.path.join(os.getcwd(), "path_highlighter_data.json")
            print("Using fallback data file path: {}".format(self._data_file_path))
    
    def _init_project_mapping(self):
        """Initialize project mapping system"""
        try:
            # Get project mapping file location
            user_home = os.path.expanduser("~")
            burp_dir = os.path.join(user_home, ".BurpSuite")
            
            # Create directory if it doesn't exist (Jython-compatible way)
            if not os.path.exists(burp_dir):
                try:
                    os.makedirs(burp_dir)
                except OSError:
                    pass  # Directory might already exist
            
            self._project_mapping_file = os.path.join(burp_dir, "path_highlighter_projects.json")
            
            # Load existing project mappings
            self._project_mappings = self._load_project_mappings()
            
            # Auto-detect current Burp project name
            self._current_project_name = self._detect_current_burp_project()
            
            
        except Exception as e:
            print("Error initializing project mapping: {}".format(str(e)))
            self._project_mappings = {}
            self._current_project_name = "default"
            # Set fallback project mapping file
            self._project_mapping_file = os.path.join(os.getcwd(), "path_highlighter_projects.json")
    
    def _detect_current_burp_project(self):
        """Detect or prompt for current Burp project name and data file location"""
        try:
            print("Determining current Burp project...")
            
            # Method 1: Check if there are existing projects - use the most recent one
            if self._project_mappings:
                # Find the most recently used project
                most_recent_project = None
                most_recent_time = None
                
                for project_name, project_info in self._project_mappings.items():
                    last_used = project_info.get("last_used", "")
                    if last_used:
                        try:
                            # Parse the timestamp
                            from datetime import datetime
                            time_obj = datetime.strptime(last_used, "%Y-%m-%d %H:%M:%S")
                            if most_recent_time is None or time_obj > most_recent_time:
                                most_recent_time = time_obj
                                most_recent_project = project_name
                        except:
                            continue
                
                if most_recent_project:
                    
                    # Ask user if they want to use the most recent project or create a new one
                    choice = self._ask_project_choice(most_recent_project)
                    
                    if choice == "use_recent":
                        print("User chose to use recent project: '{}'".format(most_recent_project))
                        return most_recent_project
                    elif choice == "select_existing":
                        # Let user select from existing projects
                        selected_project = self._select_existing_project()
                        if selected_project:
                            print("User selected existing project: '{}'".format(selected_project))
                            return selected_project
                    # If choice is "create_new" or selection failed, continue to create new project
            
            # Method 2: No existing projects or user wants to create new - prompt for project setup
            project_info = self._prompt_for_new_project_setup()
            
            if project_info:
                project_name = project_info["name"]
                data_file_path = project_info["data_file"]
                
                # Create new project entry
                self._create_new_project_entry_with_path(project_name, data_file_path)
                
                return project_name
            
            # Fallback - create a default project with prompted location
            print("Creating fallback project...")
            return self._create_fallback_project()
            
        except Exception as e:
            print("Error detecting Burp project: {}".format(str(e)))
            return self._create_emergency_fallback()
    
    def _ask_project_choice(self, most_recent_project):
        """Ask user what they want to do with existing projects"""
        try:
            from javax.swing import JOptionPane, JPanel, JLabel, JRadioButton, ButtonGroup
            from java.awt import GridLayout
            
            # Create radio button panel
            panel = JPanel(GridLayout(6, 1))
            panel.add(JLabel("Existing projects found!"))
            panel.add(JLabel("Most recent project: '{}'".format(most_recent_project)))
            panel.add(JLabel("What would you like to do?"))
            
            # Radio buttons
            use_recent_radio = JRadioButton("Use most recent project ('{}')".format(most_recent_project), True)
            select_existing_radio = JRadioButton("Select from existing projects")
            create_new_radio = JRadioButton("Create a new project")
            
            # Group the radio buttons
            button_group = ButtonGroup()
            button_group.add(use_recent_radio)
            button_group.add(select_existing_radio)
            button_group.add(create_new_radio)
            
            panel.add(use_recent_radio)
            panel.add(select_existing_radio)
            panel.add(create_new_radio)
            
            result = JOptionPane.showConfirmDialog(
                None,
                panel,
                "Project Selection",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.OK_OPTION:
                if use_recent_radio.isSelected():
                    return "use_recent"
                elif select_existing_radio.isSelected():
                    return "select_existing"
                elif create_new_radio.isSelected():
                    return "create_new"
            
            # Default to using recent if cancelled or no selection
            return "use_recent"
            
        except Exception as e:
            print("Error in project choice dialog: {}".format(str(e)))
            return "use_recent"
    
    def _select_existing_project(self):
        """Let user select from existing projects"""
        try:
            from javax.swing import JOptionPane
            
            # Get list of existing projects
            project_names = list(self._project_mappings.keys())
            if not project_names:
                return None
            
            # Show selection dialog
            selected = JOptionPane.showInputDialog(
                None,
                "Select an existing project:",
                "Select Project",
                JOptionPane.QUESTION_MESSAGE,
                None,
                project_names,
                project_names[0]
            )
            
            return str(selected) if selected else None
            
        except Exception as e:
            return None
    
    def _prompt_for_new_project_setup(self):
        """Prompt user for new project name and data file location"""
        try:
            from javax.swing import JOptionPane, JTextField, JPanel, JLabel, JButton, JFileChooser
            from javax.swing.filechooser import FileNameExtensionFilter
            from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout
            import java.io
            
            # Create setup dialog
            dialog_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            
            # Project name section
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.anchor = GridBagConstraints.WEST
            gbc.insets = Insets(5, 5, 5, 5)
            dialog_panel.add(JLabel("Project Name:"), gbc)
            
            project_name_field = JTextField("testA", 20)
            gbc.gridx = 1
            dialog_panel.add(project_name_field, gbc)
            
            # Data file location section
            gbc.gridx = 0
            gbc.gridy = 1
            dialog_panel.add(JLabel("Data File Location:"), gbc)
            
            # Container for file path and browse button
            file_panel = JPanel(BorderLayout())
            file_path_field = JTextField(30)
            file_path_field.setEditable(False)
            
            # Set default location suggestion
            default_location = os.path.join(os.path.expanduser("~"), "Documents", "testA_data.json")
            file_path_field.setText(default_location)
            
            browse_button = JButton("Browse...")
            
            def browse_action(e):
                file_chooser = JFileChooser()
                file_chooser.setDialogTitle("Choose Data File Location")
                file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
                
                # Add JSON filter
                json_filter = FileNameExtensionFilter("JSON Data Files (*.json)", ["json"])
                file_chooser.setFileFilter(json_filter)
                
                # Set suggested filename based on project name
                current_project_name = project_name_field.getText().strip()
                if current_project_name:
                    suggested_name = "{}_data.json".format(current_project_name.replace(" ", "_"))
                    suggested_path = os.path.join(os.path.expanduser("~"), "Documents", suggested_name)
                    file_chooser.setSelectedFile(java.io.File(suggested_path))
                
                if file_chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                    selected_file = file_chooser.getSelectedFile().getAbsolutePath()
                    
                    # Ensure .json extension
                    if not selected_file.lower().endswith('.json'):
                        selected_file += '.json'
                    
                    file_path_field.setText(selected_file)
            
            browse_button.addActionListener(browse_action)
            
            file_panel.add(file_path_field, BorderLayout.CENTER)
            file_panel.add(browse_button, BorderLayout.EAST)
            
            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            dialog_panel.add(file_panel, gbc)
            
            # Instructions
            gbc.gridx = 0
            gbc.gridy = 2
            gbc.gridwidth = 2
            gbc.insets = Insets(15, 5, 5, 5)
            instructions = JLabel("Choose a project name and location to save your data. This will be remembered for future sessions.")
            dialog_panel.add(instructions, gbc)
            
            # Show dialog
            result = JOptionPane.showConfirmDialog(
                None,
                dialog_panel,
                "New Project Setup",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.OK_OPTION:
                project_name = project_name_field.getText().strip()
                data_file_path = file_path_field.getText().strip()
                
                if project_name and data_file_path:
                    return {
                        "name": project_name,
                        "data_file": data_file_path
                    }
                else:
                    JOptionPane.showMessageDialog(
                        None,
                        "Please provide both project name and data file location.",
                        "Missing Information",
                        JOptionPane.WARNING_MESSAGE
                    )
                    return None
            
            return None
            
        except Exception as e:
            print("Error in new project setup: {}".format(str(e)))
            return None
    
    def _create_new_project_entry_with_path(self, project_name, data_file_path):
        """Create a new project entry with specified path"""
        try:
            safe_project_name = project_name.replace(" ", "_").replace("-", "_")
            
            self._project_mappings[safe_project_name] = {
                "data_file": data_file_path,
                "description": "Project: {}".format(project_name),
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_used": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self._save_project_mappings()
            
            return safe_project_name
            
        except Exception as e:
            print("Error creating new project entry: {}".format(str(e)))
            return None
    
    def _create_fallback_project(self):
        """Create a fallback project with user-selected location"""
        try:
            from javax.swing import JFileChooser, JOptionPane
            from javax.swing.filechooser import FileNameExtensionFilter
            import java.io
            
            # Ask for data file location
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Choose Location for Data File")
            file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
            
            # Add JSON filter
            json_filter = FileNameExtensionFilter("JSON Data Files (*.json)", ["json"])
            file_chooser.setFileFilter(json_filter)
            
            # Set default location
            default_location = os.path.join(os.path.expanduser("~"), "Documents", "burp_project_data.json")
            file_chooser.setSelectedFile(java.io.File(default_location))
            
            if file_chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Ensure .json extension
                if not selected_file.lower().endswith('.json'):
                    selected_file += '.json'
                
                # Create project with timestamp name
                timestamp = datetime.now().strftime("%Y%m%d_%H%M")
                project_name = "project_{}".format(timestamp)
                
                self._create_new_project_entry_with_path(project_name, selected_file)
                
                return project_name
            
            return self._create_emergency_fallback()
            
        except Exception as e:
            print("Error creating fallback project: {}".format(str(e)))
            return self._create_emergency_fallback()
    
    def _create_emergency_fallback(self):
        """Emergency fallback - create project in current directory"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            project_name = "emergency_{}".format(timestamp)
            data_file = os.path.join(os.getcwd(), "path_highlighter_data.json")
            
            self._create_new_project_entry_with_path(project_name, data_file)
            
            return project_name
            
        except Exception as e:
            print("Emergency fallback failed: {}".format(str(e)))
            return "default"
    
    def _rename_current_project(self, new_name):
        """Rename the current project and update all associated files"""
        try:
            old_name = self._current_project_name
            safe_new_name = new_name.replace(' ', '_').replace('-', '_')
            
            if old_name == safe_new_name:
                print("Project name unchanged")
                return True
            
            if safe_new_name in self._project_mappings:
                print("Project name '{}' already exists".format(safe_new_name))
                return False
            
            # Update project identifier file
            self._save_project_identifier(safe_new_name)
            
            # Create new project entry with new name
            old_data_file = self._data_file_path
            new_data_file = self._create_new_project_entry(safe_new_name)
            
            # Copy data from old file to new file if it exists
            if os.path.exists(old_data_file):
                try:
                    data = self._load_data_from_file()
                    # Update settings in data
                    if "settings" not in data:
                        data["settings"] = {}
                    data["settings"]["project_name"] = safe_new_name
                    
                    # Update the data file path and save
                    old_path = self._data_file_path
                    self._data_file_path = new_data_file
                    self._save_data_to_file(data)
                    self._data_file_path = old_path  # Restore for cleanup
                    
                    print("Data copied from '{}' to '{}'".format(old_data_file, new_data_file))
                except Exception as copy_error:
                    print("Error copying data to new project file: {}".format(str(copy_error)))
            
            # Remove old project entry
            if old_name in self._project_mappings and old_name != "default":
                del self._project_mappings[old_name]
                self._save_project_mappings()
                print("Removed old project entry: '{}'".format(old_name))
            
            # Update current project references
            self._current_project_name = safe_new_name
            self._data_file_path = new_data_file
            
            # Reload GUI with new project name
            self._update_gui_with_loaded_data()
            
            print("Successfully renamed project from '{}' to '{}'".format(old_name, safe_new_name))
            return True
            
        except Exception as e:
            print("Error renaming project: {}".format(str(e)))
            return False
    
    def _load_project_mappings(self):
        """Load project mappings from config file"""
        try:
            if not os.path.exists(self._project_mapping_file):
                # Start with empty mappings - projects will be created on demand
                return {}
            
            with open(self._project_mapping_file, 'r') as f:
                mappings = json.load(f)
                
            print("Loaded {} existing project(s)".format(len(mappings)))
            return mappings
            
        except Exception as e:
            print("Error loading project mappings: {}".format(str(e)))
            # Return empty mappings - projects will be created on demand
            return {}
    
    def _save_project_mappings(self, mappings=None):
        """Save project mappings to config file"""
        try:
            if mappings is None:
                mappings = self._project_mappings
                
            with open(self._project_mapping_file, 'w') as f:
                json.dump(mappings, f, indent=2)
                
        except Exception as e:
            print("Error saving project mappings: {}".format(str(e)))
    
    def _get_current_project_data_file(self):
        """Get the data file path for the current project"""
        try:
            if self._current_project_name in self._project_mappings:
                data_file = self._project_mappings[self._current_project_name]["data_file"]
                # Update last used timestamp
                self._project_mappings[self._current_project_name]["last_used"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self._save_project_mappings()
                return data_file
            else:
                # Create new project entry
                return self._create_new_project_entry(self._current_project_name)
                
        except Exception as e:
            print("Error getting current project data file: {}".format(str(e)))
            # Fallback
            return os.path.join(os.path.expanduser("~"), ".BurpSuite", "path_highlighter_data_default.json")
    
    def _create_new_project_entry(self, project_name, custom_path=None):
        """Create a new project entry in the mapping"""
        try:
            if custom_path:
                data_file_path = custom_path
            else:
                # If no custom path provided, ask user for location
                from javax.swing import JFileChooser, JOptionPane
                from javax.swing.filechooser import FileNameExtensionFilter
                import java.io
                
                file_chooser = JFileChooser()
                file_chooser.setDialogTitle("Choose Location for Data File")
                file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
                
                # Add JSON filter
                json_filter = FileNameExtensionFilter("JSON Data Files (*.json)", ["json"])
                file_chooser.setFileFilter(json_filter)
                
                # Set suggested filename
                safe_project_name = project_name.replace(" ", "_").replace("-", "_")
                suggested_name = "{}_data.json".format(safe_project_name)
                suggested_path = os.path.join(os.path.expanduser("~"), "Documents", suggested_name)
                file_chooser.setSelectedFile(java.io.File(suggested_path))
                
                if file_chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                    data_file_path = file_chooser.getSelectedFile().getAbsolutePath()
                    
                    # Ensure .json extension
                    if not data_file_path.lower().endswith('.json'):
                        data_file_path += '.json'
                else:
                    # User cancelled, use default location
                    user_home = os.path.expanduser("~")
                    data_file_path = os.path.join(user_home, "Documents", "{}_data.json".format(safe_project_name))
            
            safe_project_name = project_name.replace(" ", "_").replace("-", "_")
            
            self._project_mappings[safe_project_name] = {
                "data_file": data_file_path,
                "description": "Project: {}".format(project_name),
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_used": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self._save_project_mappings()
            
            return data_file_path
            
        except Exception as e:
            print("Error creating new project entry: {}".format(str(e)))
            # Fallback
            return os.path.join(os.path.expanduser("~"), "Documents", "path_highlighter_data_default.json")
    
    def _switch_project(self, project_name):
        """Switch to a different project"""
        try:
            if project_name not in self._project_mappings:
                print("Project '{}' not found in mappings".format(project_name))
                return False
            
            # Save current data if needed
            if hasattr(self, '_data_file_path') and self._data_file_path:
                print("Switching from project '{}' to '{}'".format(self._current_project_name, project_name))
                # Save current project data before switching
                try:
                    self._save_watch_list_to_database()
                    print("Saved current project data before switch")
                except Exception as save_error:
                    print("Warning: Could not save current project data: {}".format(str(save_error)))
            
            # Switch to new project
            old_project = self._current_project_name
            self._current_project_name = project_name
            self._data_file_path = self._get_current_project_data_file()
            
            # Set flag to prevent saving during project switch
            self._is_updating_gui = True
            print("Project switch started - saving disabled")
            
            # Clear current data before loading new project data
            with self._vuln_lock:
                self._vulnerabilities = {}
                self._vuln_counter = 0
            
            # Clear all project-specific data including watch list and configuration
            self._data = {
                "vulnerabilities": {},
                "watch_list_audit": [],
                "settings": {},
                "vuln_counter": 0
            }
            
            # Reset auto-audit settings to defaults
            self._auto_audit_repeater_enabled = True
            self._auto_audit_scanner_enabled = True
            self._sitemap_config = None
            
            print("Cleared all data for project switch. Loading new project data...")
            
            # Reload data from new project
            self._load_data_from_database()
            
            # Update GUI with a small delay to ensure data is fully loaded
            def update_gui_delayed():
                try:
                    self._update_gui_with_loaded_data()
                    print("GUI update completed after project switch")
                except Exception as gui_error:
                    print("Error updating GUI after project switch: {}".format(str(gui_error)))
                    # Ensure flag is cleared even if GUI update fails
                    self._is_updating_gui = False
                    print("Saving re-enabled after GUI update error")
            
            # Use SwingUtilities to ensure GUI updates happen on the Event Dispatch Thread
            SwingUtilities.invokeLater(update_gui_delayed)
            
            # Verify the switch was successful
            path_count = len(self._data.get('watch_list_audit', [])) if hasattr(self, '_data') else 0
            vuln_count = len(self._vulnerabilities)
            print("Project switch verification:")
            print("  - Current project: {}".format(self._current_project_name))
            print("  - Data file: {}".format(self._data_file_path))
            print("  - Paths loaded: {}".format(path_count))
            print("  - Vulnerabilities loaded: {}".format(vuln_count))
            print("  - Auto-audit Repeater: {}".format(self._auto_audit_repeater_enabled))
            print("  - Auto-audit Scanner: {}".format(self._auto_audit_scanner_enabled))
            
            # Debug: Print sample data if available
            if hasattr(self, '_data') and self._data.get('watch_list_audit'):
                sample_item = self._data['watch_list_audit'][0] if self._data['watch_list_audit'] else None
                if sample_item:
                    print("  - Sample audit item: {}".format(sample_item))
            
            print("Successfully switched to project: {}".format(project_name))
            return True
            
        except Exception as e:
            print("Error switching project: {}".format(str(e)))
            return False
    
    def _load_data_from_database(self):
        """Load existing vulnerabilities and watch paths from JSON file"""
        try:
            print("Loading data from: {}".format(self._data_file_path))
            
            # Load data using the robust method
            data = self._load_data_from_file()
            
            if not data:
                print("No data loaded, using defaults")
                # Initialize empty data structure
                self._data = {
                    "vulnerabilities": {},
                    "watch_list_audit": [],
                    "settings": {},
                    "vuln_counter": 0
                }
                return
            
            # Store the loaded data for GUI access
            self._data = data
            
            # Load vulnerabilities
            vulnerabilities_data = data.get("vulnerabilities", {})
            loaded_vuln_count = 0
            
            with self._vuln_lock:
                for vuln_id_str, vuln in vulnerabilities_data.items():
                    try:
                        vuln_id = int(vuln_id_str)
                        self._vulnerabilities[vuln_id] = {
                            'cwe': vuln.get('cwe', 'Unknown'),
                            'description': vuln.get('description', 'No description'),
                            'url': vuln.get('url', ''),
                            'method': vuln.get('method', 'GET'),
                            'timestamp': vuln.get('timestamp', ''),
                            'request_hash': vuln.get('request_hash', 0),
                            'message': None  # Message objects can't be persisted
                        }
                        # Update counter to avoid ID conflicts
                        if vuln_id > self._vuln_counter:
                            self._vuln_counter = vuln_id
                        loaded_vuln_count += 1
                    except Exception as vuln_error:
                        print("Error loading vulnerability {}: {}".format(vuln_id_str, str(vuln_error)))
            
            # Load paths - use watch_list_audit as the only source
            loaded_paths_count = 0
            
            # Load from watch_list_audit (primary and only source)
            watch_list_audit = data.get("watch_list_audit", [])
            if watch_list_audit and isinstance(watch_list_audit, list):
                loaded_paths_count = len(watch_list_audit)
                print("Loaded {} paths from watch_list_audit".format(loaded_paths_count))
            else:
                # Fallback 1: Try path_list and migrate to watch_list_audit
                path_list_data = data.get("path_list", [])
                if path_list_data and isinstance(path_list_data, list):
                    # Migrate path_list to watch_list_audit format
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                    data['watch_list_audit'] = []
                    for path in path_list_data:
                        if path:  # Only add non-empty paths
                            data['watch_list_audit'].append({
                                'path': str(path),
                                'manual_audited': False,
                                'scanned': False,
                                'last_audit': 'Never',
                                'highlight': False,
                                'note': ''
                            })
                    
                    loaded_paths_count = len(data['watch_list_audit'])
                    print("Migrated {} paths from path_list to watch_list_audit".format(loaded_paths_count))
                    
                    # Remove old path_list after migration
                    del data['path_list']
                    
                    # Save the migrated data
                    try:
                        self._save_data_to_file(data)
                        print("Saved migrated audit data to file")
                    except Exception as save_error:
                        print("Error saving migrated audit data: {}".format(str(save_error)))
                        
                else:
                    # Fallback 2: Try legacy watch_paths format (for very old data files)
                    watch_paths_data = data.get("watch_paths", [])
                    if watch_paths_data and isinstance(watch_paths_data, list):
                        # Migrate watch_paths to watch_list_audit format
                        current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                        data['watch_list_audit'] = []
                        for path in watch_paths_data:
                            if path:  # Only add non-empty paths
                                data['watch_list_audit'].append({
                                    'path': str(path),
                                    'manual_audited': False,
                                    'scanned': False,
                                    'last_audit': 'Never',
                                    'highlight': False,
                                    'note': ''
                                })
                        
                        loaded_paths_count = len(data['watch_list_audit'])
                        print("Migrated {} paths from watch_paths to watch_list_audit".format(loaded_paths_count))
                        
                        # Remove old watch_paths after migration
                        if "watch_paths" in data:
                            del data["watch_paths"]
                        
                        # Save the migrated data
                        try:
                            self._save_data_to_file(data)
                            print("Saved migrated legacy data to file")
                        except Exception as save_error:
                            print("Error saving migrated legacy data: {}".format(str(save_error)))
                
                # Update watch_list_audit variable after migration
                watch_list_audit = data.get("watch_list_audit", [])
                
                # Ensure backward compatibility: add note field to existing entries if missing
                for item in watch_list_audit:
                    if isinstance(item, dict) and 'note' not in item:
                        item['note'] = ''
            
            # Store the final audit data in self._data
            self._data['watch_list_audit'] = watch_list_audit
            
            # Load vuln counter and migrate to new system if needed
            if "max_vuln_id" in data:
                # New system: use max_vuln_id for ID generation
                self._vuln_counter = data.get("max_vuln_id", 0)
            else:
                # Old system: migrate existing data
                self._vuln_counter = max(self._vuln_counter, data.get("vuln_counter", 0))
                # Set max_vuln_id to current counter value for future use
                data["max_vuln_id"] = self._vuln_counter
                # Update vuln_counter to actual count
                data["vuln_counter"] = len(data.get("vulnerabilities", {}))
                # Save the migrated data
                self._save_data_to_file(data)
            
            # Load auto-audit settings
            settings = data.get("settings", {})
            if "auto_audit_enabled" in settings:
                # Legacy setting - apply to both if new settings don't exist
                legacy_setting = settings["auto_audit_enabled"]
                self._auto_audit_repeater_enabled = settings.get("auto_audit_repeater_enabled", legacy_setting)
                self._auto_audit_scanner_enabled = settings.get("auto_audit_scanner_enabled", legacy_setting)
                print("Loaded auto-audit settings - Repeater: {}, Scanner: {}".format(
                    self._auto_audit_repeater_enabled, self._auto_audit_scanner_enabled))
            else:
                # Load individual settings
                self._auto_audit_repeater_enabled = settings.get("auto_audit_repeater_enabled", True)
                self._auto_audit_scanner_enabled = settings.get("auto_audit_scanner_enabled", True)
                print("Loaded auto-audit settings - Repeater: {}, Scanner: {}".format(
                    self._auto_audit_repeater_enabled, self._auto_audit_scanner_enabled))
            
            # Load table view settings
            self._show_full_urls_in_table = settings.get("show_full_urls_in_table", True)
            print("Loaded table view setting - Show full URLs: {}".format(self._show_full_urls_in_table))
            
            # Load sitemap configuration if available
            sitemap_config = settings.get("sitemap_config", None)
            if sitemap_config and sitemap_config.get("auto_update", False):
                self._sitemap_config = sitemap_config
                print("Loaded sitemap auto-update config for target: {}".format(sitemap_config.get('target', 'unknown')))
                # Start monitoring after GUI is created
            
            print("Successfully loaded {} vulnerabilities and {} paths from data file".format(
                loaded_vuln_count, loaded_paths_count))
            
                        
        except Exception as e:
            print("Error loading data from file: {}".format(str(e)))
            traceback.print_exc()
            # Initialize with empty data on error
            with self._vuln_lock:
                self._vulnerabilities = {}
                self._vuln_counter = 0
            # Initialize empty data structure
            self._data = {
                "vulnerabilities": {},
                "watch_list_audit": [],
                "settings": {},
                "vuln_counter": 0
            }
    
    def _save_data_to_file(self, data):
        """Save data to JSON file with timeout protection and enhanced error handling"""
        import time
        
        try:
            # Use a temporary file for atomic writes
            temp_path = self._data_file_path + ".tmp"
            
            # Write to temporary file first
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2)
                f.flush()  # Ensure data is written to disk
                os.fsync(f.fileno())  # Force write to disk
            
            # Verify the temporary file was written correctly
            try:
                with open(temp_path, 'r') as f:
                    test_data = json.load(f)
                if not isinstance(test_data, dict):
                    raise Exception("Temporary file verification failed - invalid JSON structure")
            except Exception as verify_error:
                print("Error verifying temporary file: {}".format(str(verify_error)))
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                return False
            
            # Atomic move (Windows-safe implementation with retries)
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    if os.path.exists(self._data_file_path):
                        os.remove(self._data_file_path)
                    os.rename(temp_path, self._data_file_path)
                    break  # Success
                    
                except Exception as move_error:
                    print("Error moving temp file (attempt {}): {}".format(attempt + 1, str(move_error)))
                    if attempt == max_retries - 1:
                        # Final attempt - try copy instead
                        try:
                            import shutil
                            if os.path.exists(self._data_file_path):
                                os.remove(self._data_file_path)
                            shutil.copy2(temp_path, self._data_file_path)
                            os.remove(temp_path)
                        except Exception as copy_error:
                            print("Error copying temp file: {}".format(str(copy_error)))
                            return False
                    else:
                        time.sleep(0.1)  # Brief delay before retry
            
            # Verify the final file was saved correctly
            try:
                with open(self._data_file_path, 'r') as f:
                    final_data = json.load(f)
                if not isinstance(final_data, dict):
                    raise Exception("Final file verification failed - invalid JSON structure")
            except Exception as final_verify_error:
                print("Error verifying final saved file: {}".format(str(final_verify_error)))
                return False
            
            return True  # Success
                
        except Exception as e:
            print("Error saving data to file: {}".format(str(e)))
            # Clean up temp file if it exists
            temp_path = self._data_file_path + ".tmp"
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except:
                    pass
            return False  # Failure
    
    def _load_data_from_file(self):
        """Load current data from JSON file with error recovery"""
        try:
            if not os.path.exists(self._data_file_path):
                print("Data file does not exist, returning default data")
                return {
                    "vulnerabilities": {},
                    "watch_list_audit": [],
                    "settings": {},
                    "vuln_counter": 0
                }
            
            # Check if file is readable
            if not os.access(self._data_file_path, os.R_OK):
                print("Data file is not readable, returning default data")
                return {
                    "vulnerabilities": {},
                    "watch_list_audit": [],
                    "settings": {},
                    "vuln_counter": 0
                }
                
            with open(self._data_file_path, 'r') as f:
                data = json.load(f)
                
            # Validate data structure
            if not isinstance(data, dict):
                print("Invalid data format, returning default data")
                return {
                    "vulnerabilities": {},
                    "watch_list_audit": [],
                    "settings": {},
                    "vuln_counter": 0
                }
                
            # Ensure required keys exist
            default_data = {
                "vulnerabilities": {},
                "watch_list_audit": [],
                "settings": {},
                "vuln_counter": 0
            }
            
            for key, default_value in default_data.items():
                if key not in data:
                    data[key] = default_value
            
            # Migration: if we have path_list but no watch_list_audit, create audit data
            if data.get('path_list') and not data.get('watch_list_audit'):
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                data['watch_list_audit'] = []
                for path in data['path_list']:
                    data['watch_list_audit'].append({
                        'path': path,
                        'manual_audited': False,
                        'scanned': False,
                        'last_audit': 'Never',
                        'highlight': False
                    })
                print("Migrated {} paths to watch_list_audit format".format(len(data['path_list'])))
                
                # Remove old path_list after migration
                del data['path_list']
                
                # Save the migrated data immediately
                try:
                    self._save_data_to_file(data)
                    print("Saved migrated data to file")
                except Exception as save_error:
                    print("Error saving migrated data: {}".format(str(save_error)))
            
            # Validate and repair watch_list_audit data structure
            if data.get('watch_list_audit'):
                watch_list_audit = data['watch_list_audit']
                repaired_items = []
                needs_repair = False
                
                for i, item in enumerate(watch_list_audit):
                    if isinstance(item, str):
                        # Old format: just path strings, convert to full structure
                        repaired_items.append({
                            'path': item,
                            'manual_audited': False,
                            'scanned': False,
                            'last_audit': 'Never',
                            'note': '',
                            'highlight': False
                        })
                        needs_repair = True
                        print("Repaired string item '{}' to full audit structure".format(item))
                    elif isinstance(item, dict):
                        # Check for data corruption first
                        if self._is_item_corrupted(item):
                            print("CORRUPTION DETECTED in item {}: {}".format(i, item))
                            repaired_item = self._repair_corrupted_item(item)
                            if repaired_item:
                                repaired_items.append(repaired_item)
                                needs_repair = True
                                print("REPAIRED item {}: {}".format(i, repaired_item))
                            else:
                                print("COULD NOT REPAIR item {}, skipping".format(i))
                                needs_repair = True
                        else:
                            # Validate required fields and add missing ones
                            required_fields = {
                                'path': '',
                                'manual_audited': False,
                                'scanned': False,
                                'last_audit': 'Never',
                                'note': '',
                                'highlight': False
                            }
                            
                            repaired_item = {}
                            for field, default_value in required_fields.items():
                                if field in item:
                                    # Ensure data types are correct
                                    if field == 'manual_audited' or field == 'scanned' or field == 'highlight':
                                        repaired_item[field] = bool(item[field]) if isinstance(item[field], bool) else False
                                    else:
                                        repaired_item[field] = str(item[field]) if item[field] is not None else default_value
                                else:
                                    repaired_item[field] = default_value
                                    needs_repair = True
                                    print("Added missing field '{}' to item '{}'".format(field, item.get('path', 'unknown')))
                            
                            # Preserve additional fields
                            for field, value in item.items():
                                if field not in repaired_item:
                                    repaired_item[field] = value
                            
                            repaired_items.append(repaired_item)
                    else:
                        print("Skipping invalid item type in watch_list_audit: {}".format(type(item)))
                        needs_repair = True
                
                if needs_repair:
                    data['watch_list_audit'] = repaired_items
                    print("Repaired {} items in watch_list_audit, saving changes...".format(len(repaired_items)))
                    try:
                        self._save_data_to_file(data)
                        print("Saved repaired audit data to file")
                    except Exception as save_error:
                        print("Error saving repaired audit data: {}".format(str(save_error)))
                else:
                    print("watch_list_audit data structure is valid, no repairs needed")
                    
            return data
            
        except Exception as e:
            print("Error loading data from file: {}".format(str(e)))
            return {
                "vulnerabilities": {},
                "watch_list_audit": [],
                "settings": {},
                "vuln_counter": 0
            }
    
    def _is_item_corrupted(self, item):
        """Check if a watch list audit item is corrupted"""
        try:
            # Check for type mismatches that indicate corruption
            if not isinstance(item, dict):
                return True
            
            path = item.get('path')
            manual_audited = item.get('manual_audited')
            scanned = item.get('scanned')
            last_audit = item.get('last_audit')
            note = item.get('note')
            highlight = item.get('highlight')
            
            # Check for corruption patterns:
            # 1. manual_audited should be bool, not string/URL
            if manual_audited is not None and not isinstance(manual_audited, bool) and str(manual_audited).startswith('http'):
                return True
            
            # 2. highlight should be bool, not string
            if highlight is not None and not isinstance(highlight, bool) and isinstance(highlight, str) and len(str(highlight)) > 10:
                return True
            
            # 3. note should be string, not timestamp in wrong field
            if note is not None and isinstance(note, str) and note.count('-') == 2 and note.count(':') == 1:
                # Looks like a timestamp got put in note field
                return True
            
            # 4. scanned should be bool, not string
            if scanned is not None and not isinstance(scanned, bool) and isinstance(scanned, str):
                return True
            
            # 5. last_audit should be string, not bool
            if last_audit is not None and isinstance(last_audit, bool):
                return True
            
            return False
            
        except Exception as e:
            print("Error checking item corruption: {}".format(str(e)))
            return True
    
    def _repair_corrupted_item(self, item):
        """Attempt to repair a corrupted watch list audit item"""
        try:
            if not isinstance(item, dict):
                return None
            
            # Try to extract the correct path (should be the only HTTP URL)
            path = ""
            for key, value in item.items():
                if isinstance(value, str) and value.startswith('http'):
                    path = value
                    break
            
            if not path:
                # Try to get path from the 'path' field even if corrupted
                path = str(item.get('path', ''))
                if not path.startswith('http'):
                    print("Cannot find valid path in corrupted item")
                    return None
            
            # Create repaired item with correct defaults
            repaired_item = {
                'path': path,
                'manual_audited': False,
                'scanned': False,
                'last_audit': 'Never',
                'note': '',
                'highlight': False
            }
            
            # Try to salvage any valid data
            original_manual_audited = item.get('manual_audited')
            if isinstance(original_manual_audited, bool):
                repaired_item['manual_audited'] = original_manual_audited
            
            original_scanned = item.get('scanned')
            if isinstance(original_scanned, bool):
                repaired_item['scanned'] = original_scanned
            
            original_last_audit = item.get('last_audit')
            if isinstance(original_last_audit, str) and not isinstance(original_last_audit, bool):
                repaired_item['last_audit'] = original_last_audit
            
            original_note = item.get('note')
            if isinstance(original_note, str) and len(original_note) < 200:  # Reasonable note length
                repaired_item['note'] = original_note
            
            original_highlight = item.get('highlight')
            if isinstance(original_highlight, bool):
                repaired_item['highlight'] = original_highlight
            
            return repaired_item
            
        except Exception as e:
            print("Error repairing corrupted item: {}".format(str(e)))
            return None
    
    def _save_vulnerability_to_database(self, vuln_id, vulnerability):
        """Save a single vulnerability to JSON file"""
        try:
            data = self._load_data_from_file()
            
            # Update vulnerabilities
            data["vulnerabilities"][str(vuln_id)] = {
                'cwe': vulnerability['cwe'],
                'description': vulnerability['description'],
                'url': vulnerability['url'],
                'method': vulnerability['method'],
                'timestamp': vulnerability['timestamp'],
                'request_hash': vulnerability['request_hash']
            }
            
            # Update the max ID for generating unique IDs
            if "max_vuln_id" not in data:
                data["max_vuln_id"] = data.get("vuln_counter", 0)
            data["max_vuln_id"] = max(data.get("max_vuln_id", 0), vuln_id)
            
            # Update counter to reflect actual count
            data["vuln_counter"] = len(data["vulnerabilities"])
            
            save_success = self._save_data_to_file(data)
            if not save_success:
                print("Failed to save vulnerability data to file")
                return False
            
            return True  # Success
            
        except Exception as e:
            print("Error saving vulnerability to file: {}".format(str(e)))
            return False  # Failure
    
    def _remove_vulnerability_from_database(self, vuln_id):
        """Remove a vulnerability from JSON file and update counters"""
        try:
            data = self._load_data_from_file()
            
            # Remove vulnerability
            if str(vuln_id) in data["vulnerabilities"]:
                del data["vulnerabilities"][str(vuln_id)]
                
                # Update the vuln_counter to reflect actual count (for user display)
                # Keep the ID generator separate by using max_vuln_id
                actual_count = len(data["vulnerabilities"])
                
                # Preserve the max ID for generating new unique IDs
                if "max_vuln_id" not in data:
                    data["max_vuln_id"] = data.get("vuln_counter", 0)
                
                # Update vuln_counter to show actual count
                data["vuln_counter"] = actual_count
            
            save_success = self._save_data_to_file(data)
            if not save_success:
                print("Failed to save vulnerability removal to file")
                return False
            
            return True
            
        except Exception as e:
            print("Error removing vulnerability from file: {}".format(str(e)))
            return False
    
    def _save_watch_list_to_database(self):
        """Save current watch list audit data to JSON file"""
        try:
            # Get current audit data and save it
            if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                data = self._load_data_from_file()
                
                # Update from current audit data
                data["watch_list_audit"] = self._data['watch_list_audit']
                
                # Save data
                self._save_data_to_file(data)
            else:
                print("No watch_list_audit data available to save")
            
        except Exception as e:
            print("Error saving watch list to file: {}".format(str(e)))
    
    def _clear_all_data_from_database(self):
        """Clear all vulnerabilities from JSON file"""
        try:
            data = self._load_data_from_file()
            
            # Clear vulnerabilities but keep other data
            data["vulnerabilities"] = {}
            
            self._save_data_to_file(data)
            
        except Exception as e:
            print("Error clearing data from file: {}".format(str(e)))
    
    def _change_database_location(self, event):
        """Allow user to choose a different data file location"""
        try:
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Choose Data File Location")
            file_chooser.setSelectedFile(java.io.File(self._data_file_path))
            
            # Add JSON filter
            json_filter = FileNameExtensionFilter("JSON Data Files (*.json)", ["json"])
            file_chooser.setFileFilter(json_filter)
            
            result = file_chooser.showSaveDialog(self._main_panel)
            
            if result == JFileChooser.APPROVE_OPTION:
                new_file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Ensure .json extension
                if not new_file_path.lower().endswith('.json'):
                    new_file_path += '.json'
                
                # Export current data to new location
                self._migrate_data_file(new_file_path)
                
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Data file location changed to:\n{}".format(new_file_path),
                    "Data File Location Changed",
                    JOptionPane.INFORMATION_MESSAGE
                )
                
        except Exception as e:
            print("Error changing data file location: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error changing data file location: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _migrate_data_file(self, new_file_path):
        """Migrate data to new JSON file location"""
        try:
            # Prepare data for migration
            data = {
                "vulnerabilities": {},
                "watch_list_audit": [],
                "settings": {},
                "vuln_counter": self._vuln_counter
            }
            
            # Copy vulnerabilities
            with self._vuln_lock:
                for vuln_id, vuln in self._vulnerabilities.items():
                    data["vulnerabilities"][str(vuln_id)] = {
                        'cwe': vuln['cwe'],
                        'description': vuln['description'],
                        'url': vuln['url'],
                        'method': vuln['method'],
                        'timestamp': vuln['timestamp'],
                        'request_hash': vuln['request_hash']
                    }
            
            # Copy paths from audit data
            if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                data["watch_list_audit"] = self._data['watch_list_audit']
            else:
                # Initialize empty watch list if no data exists
                data["watch_list_audit"] = []
            
            # Update file path and save
            self._data_file_path = new_file_path
            self._save_data_to_file(data)
            
            print("Data migrated to new file: {}".format(new_file_path))
            
        except Exception as e:
            print("Error migrating data file: {}".format(str(e)))
            raise
    
    def _manage_projects(self, event):
        """Show project management dialog"""
        try:
            # Create project management dialog
            dialog_panel = JPanel(BorderLayout())
            
            # Top panel with current project info
            info_panel = JPanel()
            info_panel.add(JLabel("Current Project: {}".format(self._current_project_name)))
            dialog_panel.add(info_panel, BorderLayout.NORTH)
            
            # Center panel with project list
            center_panel = JPanel(BorderLayout())
            center_panel.add(JLabel("Available Projects:"), BorderLayout.NORTH)
            
            # Project list
            project_list_data = []
            for name, info in self._project_mappings.items():
                status = " (current)" if name == self._current_project_name else ""
                project_list_data.append([
                    name + status,
                    info.get("description", ""),
                    info.get("last_used", ""),
                    info.get("data_file", "")
                ])
            
            column_names = ["Project", "Description", "Last Used", "Data File"]
            project_table_model = DefaultTableModel(column_names, 0)
            for row in project_list_data:
                project_table_model.addRow(row)
            
            project_table = JTable(project_table_model)
            project_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            project_scroll = JScrollPane(project_table)
            project_scroll.setPreferredSize(Dimension(600, 200))
            center_panel.add(project_scroll, BorderLayout.CENTER)
            
            dialog_panel.add(center_panel, BorderLayout.CENTER)
            
            # Bottom panel with buttons
            button_panel = JPanel()
            
            # Switch project button
            switch_btn = JButton("Switch to Selected Project")
            def switch_action(e):
                selected_row = project_table.getSelectedRow()
                if selected_row >= 0:
                    project_name = str(project_table_model.getValueAt(selected_row, 0))
                    # Remove "(current)" suffix if present
                    if " (current)" in project_name:
                        project_name = project_name.replace(" (current)", "")
                    
                    if project_name != self._current_project_name:
                        if self._switch_project(project_name):
                            JOptionPane.showMessageDialog(
                                self._main_panel,
                                "Switched to project: {}".format(project_name),
                                "Project Switched",
                                JOptionPane.INFORMATION_MESSAGE
                            )
                        else:
                            JOptionPane.showMessageDialog(
                                self._main_panel,
                                "Failed to switch to project: {}".format(project_name),
                                "Switch Failed",
                                JOptionPane.ERROR_MESSAGE
                            )
                    else:
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Already using project: {}".format(project_name),
                            "Already Current",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                else:
                    JOptionPane.showMessageDialog(
                        self._main_panel,
                        "Please select a project first",
                        "No Selection",
                        JOptionPane.WARNING_MESSAGE
                    )
            
            switch_btn.addActionListener(switch_action)
            button_panel.add(switch_btn)
            
            # New project button
            new_btn = JButton("Create New Project")
            def new_action(e):
                self._create_new_project_dialog()
            
            new_btn.addActionListener(new_action)
            button_panel.add(new_btn)
            
            # Rename current project button
            rename_btn = JButton("Rename Current Project")
            def rename_action(e):
                current_name = self._current_project_name
                new_name = JOptionPane.showInputDialog(
                    self._main_panel,
                    "Enter new name for project '{}':\n\n(This will create a new data file and preserve your data)".format(current_name),
                    "Rename Project",
                    JOptionPane.QUESTION_MESSAGE
                )
                
                if new_name and new_name.strip():
                    new_name = new_name.strip()
                    if self._rename_current_project(new_name):
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Project renamed from '{}' to '{}'".format(current_name, new_name),
                            "Project Renamed",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    else:
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Failed to rename project. Name may already exist.",
                            "Rename Failed",
                            JOptionPane.ERROR_MESSAGE
                        )
            
            rename_btn.addActionListener(rename_action)
            button_panel.add(rename_btn)
            
            # Delete project button
            delete_btn = JButton("Delete Selected Project")
            def delete_action(e):
                selected_row = project_table.getSelectedRow()
                if selected_row >= 0:
                    project_name = str(project_table_model.getValueAt(selected_row, 0))
                    if " (current)" in project_name:
                        project_name = project_name.replace(" (current)", "")
                    
                    if project_name == "default":
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Cannot delete the default project",
                            "Cannot Delete",
                            JOptionPane.WARNING_MESSAGE
                        )
                        return
                    
                    if project_name == self._current_project_name:
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Cannot delete the currently active project.\nSwitch to another project first.",
                            "Cannot Delete",
                            JOptionPane.WARNING_MESSAGE
                        )
                        return
                    
                    confirm = JOptionPane.showConfirmDialog(
                        self._main_panel,
                        "Delete project '{}'?\nThis will remove the project mapping but not the data file.".format(project_name),
                        "Confirm Delete",
                        JOptionPane.YES_NO_OPTION
                    )
                    
                    if confirm == JOptionPane.YES_OPTION:
                        del self._project_mappings[project_name]
                        self._save_project_mappings()
                        JOptionPane.showMessageDialog(
                            self._main_panel,
                            "Project '{}' deleted".format(project_name),
                            "Project Deleted",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                else:
                    JOptionPane.showMessageDialog(
                        self._main_panel,
                        "Please select a project first",
                        "No Selection",
                        JOptionPane.WARNING_MESSAGE
                    )
            
            delete_btn.addActionListener(delete_action)
            button_panel.add(delete_btn)
            
            dialog_panel.add(button_panel, BorderLayout.SOUTH)
            
            # Show dialog
            JOptionPane.showMessageDialog(
                self._main_panel,
                dialog_panel,
                "Project Management",
                JOptionPane.PLAIN_MESSAGE
            )
            
        except Exception as e:
            print("Error in project management: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error managing projects: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _create_new_project_dialog(self):
        """Show dialog to create a new project"""
        try:
            # Use the same setup dialog as initial project creation
            project_info = self._prompt_for_new_project_setup()
            
            if not project_info:
                return
            
            project_name = project_info["name"]
            data_file_path = project_info["data_file"]
            
            # Check if project already exists
            safe_project_name = project_name.replace(" ", "_").replace("-", "_")
            if safe_project_name in self._project_mappings:
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Project '{}' already exists".format(project_name),
                    "Project Exists",
                    JOptionPane.WARNING_MESSAGE
                )
                return
            
            # Create the project
            self._create_new_project_entry_with_path(safe_project_name, data_file_path)
            
            # Ask if user wants to switch to new project
            switch_choice = JOptionPane.showConfirmDialog(
                self._main_panel,
                "Project '{}' created successfully.\n\nWould you like to switch to this project now?".format(project_name),
                "Project Created",
                JOptionPane.YES_NO_OPTION
            )
            
            if switch_choice == JOptionPane.YES_OPTION:
                self._switch_project(safe_project_name)
            
        except Exception as e:
            print("Error creating new project: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error creating project: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # Set our extension name
        callbacks.setExtensionName("Vuln tracker")
        
        print("Starting Vuln tracker extension initialization...")
        
        # Initialize vulnerability tracking
        self._vulnerabilities = {}  # Format: {unique_id: {cwe: 'CWE-89', description: 'SQL Injection', url: '', method: '', timestamp: '', request_hash: ''}}
        self._vuln_lock = threading.Lock()
        self._vuln_counter = 0  # Counter for unique vulnerability IDs
        
        # Performance optimization for Scanner auto-audit
        self._scanner_request_cache = {}  # Cache for scanner requests to prevent duplicate processing
        self._last_cache_clear = time.time()  # Track when cache was last cleared
        self._scanner_processing_queue = []  # Queue for batched scanner processing
        self._last_batch_process = time.time()  # Track last batch processing time
        self._scan_status_cache = {}  # Cache for scan status lookups
        self._scan_cache_time = {}  # Cache timestamps
        self._watchlist_match_cache = {}  # Cache for expensive watchlist matching
        self._watchlist_cache_time = {}  # Timestamps for match cache
        
        # Flag to prevent saving during project switches and GUI updates
        # CRITICAL: This prevents data corruption when the GUI is being updated
        # It ensures that table model changes don't trigger saves that could overwrite
        # the internal data structure with incorrect column mappings
        self._is_updating_gui = False
        
        # CWE definitions
        self._cwe_types = {
            "CWE-89": "SQL Injection",
            "CWE-78": "OS Command Injection",
            "CWE-94": "Code Injection",
            "CWE-611": "XML External Entity (XXE) Injection",
            "CWE-502": "Unsafe Deserialization",
            "CWE-79": "Reflected Cross-Site Scripting (XSS)",
            "CWE-79_2": "Stored Cross-Site Scripting (XSS)",
            "CWE-306": "Missing Authentication",
            "CWE-862": "Missing Authorization",
            "CWE-639": "Insecure Direct Object Reference (IDOR)",
            "CWE-307": "Brute Force",
            "CWE-204": "User Enumeration",
            "CWE-352": "Cross-Site Request Forgery (CSRF)",
            "CWE-601": "Open Redirect",
            "CWE-434": "Unrestricted File Upload",
            "CWE-22": "Path Traversal",
            "CWE-841": "Business Logic Errors",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-1104": "Use of Unmaintained Third Party Components",
            "CWE-200": "Information Disclosure",
            "CWE-209": "Error Message Containing Sensitive Information"
        }

        
        # Auto-audit settings - default to enabled
        self._auto_audit_repeater_enabled = True
        self._auto_audit_scanner_enabled = True
        
        # Table view settings - default to show full URLs
        self._show_full_urls_in_table = True
        
        # Sitemap monitoring settings
        self._sitemap_config = None
        self._sitemap_last_check = None
        self._sitemap_monitor_thread = None
        
        # Initialize JSON file for persistent storage
        self._init_database()
        
        # Load existing data from JSON file
        self._load_data_from_database()
        
        # Create the GUI
        self._create_gui()
        
        # Update GUI with loaded data
        self._update_gui_with_loaded_data()
        
        # Register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)
        
        # Register ourselves as a context menu factory
        callbacks.registerContextMenuFactory(self)
        
        # Register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(self)
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # Defer sitemap monitoring startup to prevent initial GUI freeze
        if self._sitemap_config and self._sitemap_config.get("auto_update", False):
            self._defer_sitemap_monitoring_startup()
        
        print("Vuln tracker extension loaded successfully!")
    
    def _defer_sitemap_monitoring_startup(self):
        """Defer sitemap monitoring startup to prevent initial GUI freeze"""
        try:
            def startup_task():
                try:
                    # Wait a bit more to ensure GUI is fully initialized
                    import time
                    time.sleep(2)
                    
                    # Start monitoring
                    self._start_sitemap_monitoring()
                    
                except Exception as e:
                    print("Error in deferred sitemap startup: {}".format(str(e)))
            
            # Start monitoring after a delay to let GUI settle
            monitoring_thread = threading.Thread(target=startup_task)
            monitoring_thread.daemon = True
            monitoring_thread.start()
            
        except Exception as e:
            print("Error scheduling deferred sitemap startup: {}".format(str(e)))
            # Fallback to immediate startup
            self._start_sitemap_monitoring()
    
    def _create_gui(self):
        """Create the extension's GUI with tabbed interface"""
        # Main panel with tabbed pane
        self._main_panel = JPanel(BorderLayout())
        self._tabbed_pane = JTabbedPane()
        
        # Create tabs
        self._create_watch_list_tab()
        self._create_vulnerabilities_tab()
        
        self._main_panel.add(self._tabbed_pane, BorderLayout.CENTER)
    
    def _create_watch_list_tab(self):
        """Create the watch list management tab"""
        watch_panel = JPanel(BorderLayout())
        
        # Top panel for title and controls
        top_panel = JPanel(BorderLayout())
        
        # Title and instructions panel
        title_panel = JPanel()
        title_panel.setLayout(BoxLayout(title_panel, BoxLayout.Y_AXIS))
        
        title_label = JLabel("Vuln tracker - Manage Watch List")
        title_label.setFont(title_label.getFont().deriveFont(16.0))
        title_panel.add(title_label)
        
        instructions = JLabel("Manage paths/URLs to monitor. Import from file or add manually.")
        title_panel.add(Box.createVerticalStrut(5))
        title_panel.add(instructions)
        
        top_panel.add(title_panel, BorderLayout.WEST)
        
        # Button panel for top
        top_button_panel = JPanel()
        
        # Import from file button
        self._import_button = JButton("Import from File", actionPerformed=self._import_watch_list)
        top_button_panel.add(self._import_button)
        
        # Import from sitemap button
        self._import_sitemap_button = JButton("Import from Sitemap", actionPerformed=self._import_from_sitemap)
        top_button_panel.add(self._import_sitemap_button)
        
        # Export button
        self._export_watch_button = JButton("Export to File", actionPerformed=self._export_watch_list)
        top_button_panel.add(self._export_watch_button)
        
        # Configuration button
        self._config_button = JButton("Configuration", actionPerformed=self._show_configuration_dialog)
        top_button_panel.add(self._config_button)
        
        top_panel.add(top_button_panel, BorderLayout.EAST)
        
        watch_panel.add(top_panel, BorderLayout.NORTH)
        
        # Center panel with tabbed interface for different views
        center_tabbed_pane = JTabbedPane()
        
        # Table view tab
        self._create_table_view_tab(center_tabbed_pane)
        
        # Text editor tab  
        self._create_text_editor_tab(center_tabbed_pane)
        
        watch_panel.add(center_tabbed_pane, BorderLayout.CENTER)
        
        # Bottom panel for status
        bottom_panel = JPanel()
        bottom_panel.setLayout(BoxLayout(bottom_panel, BoxLayout.Y_AXIS))
        
        # Status label
        self._status_label = JLabel("Ready - 0 paths in watch list")
        bottom_panel.add(self._status_label)
        
        # Progress panel for audit completion
        progress_panel = JPanel()
        progress_panel.setLayout(BoxLayout(progress_panel, BoxLayout.X_AXIS))
        
        # Progress label
        self._progress_label = JLabel("Audit Progress:")
        progress_panel.add(self._progress_label)
        progress_panel.add(Box.createHorizontalStrut(10))
        
        # Progress bar
        self._progress_bar = JProgressBar(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setString("0%")
        self._progress_bar.setPreferredSize(Dimension(200, 20))
        progress_panel.add(self._progress_bar)
        
        # Progress details label
        progress_panel.add(Box.createHorizontalStrut(10))
        self._progress_details = JLabel("(0/0 audited)")
        self._progress_details.setFont(self._progress_details.getFont().deriveFont(10.0))
        progress_panel.add(self._progress_details)
        
        bottom_panel.add(progress_panel)
        
        # Project info label
        self._project_info_label = JLabel("Project: Not set")
        self._project_info_label.setFont(self._project_info_label.getFont().deriveFont(10.0))
        bottom_panel.add(self._project_info_label)
        
        watch_panel.add(bottom_panel, BorderLayout.SOUTH)
        
        self._tabbed_pane.addTab("Watch List", watch_panel)
    
    def _create_table_view_tab(self, parent_pane):
        """Create the table view tab for watch list management"""
        table_panel = JPanel(BorderLayout())
        
        # Instructions
        instruction_label = JLabel("Monitor paths for manual testing (Repeater) and automated scanning. Right-click or use buttons to manage notes and other operations:")
        table_panel.add(instruction_label, BorderLayout.NORTH)
        
        # Create table for watch list with audit status
        column_names = ["#", "Path/URL", "Manual Audited", "Scanned", "Last Audit", "Note", "Highlight"]
        
        # Create custom table model
        class AuditTableModel(DefaultTableModel):
            def __init__(self, column_names, rows):
                DefaultTableModel.__init__(self, column_names, rows)
            
            def isCellEditable(self, row, column):
                if column == 5:  # "Note" column is user-editable (moved from 4 to 5)
                    return True
                if column == 6:  # "Highlight" column is user-editable (moved from 5 to 6)
                    return True
                return False  # Other columns are auto-managed by tool detection
            
            def getColumnClass(self, column):
                if column in [2, 3, 6]:  # "Manual Audited", "Scanned", "Highlight" columns (shifted by 1)
                    return java.lang.Boolean
                return java.lang.String
        
        self._watch_table_model = AuditTableModel(column_names, 0)
        # Store original data for filtering
        self._original_watch_data = []
        
        self._watch_table = JTable(self._watch_table_model)
        self._watch_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        
        # Add custom row highlighting for cursor hover
        self._watch_table.addMouseMotionListener(self._create_table_hover_listener())
        
        # Add right-click context menu
        self._watch_table.addMouseListener(self._create_table_context_menu_listener())
        
        # Custom renderer for row highlighting
        self._setup_table_row_highlighting()
        
        # Set column widths
        column_model = self._watch_table.getColumnModel()
        column_model.getColumn(0).setPreferredWidth(40)   # # (Number)
        column_model.getColumn(1).setPreferredWidth(280)  # Path/URL
        column_model.getColumn(2).setPreferredWidth(100)  # Manual Audited
        column_model.getColumn(3).setPreferredWidth(80)   # Scanned
        column_model.getColumn(4).setPreferredWidth(130)  # Last Audit
        column_model.getColumn(5).setPreferredWidth(200)  # Note
        column_model.getColumn(6).setPreferredWidth(80)   # Highlight
        
        # Add table change listener to save audit status
        self._watch_table_model.addTableModelListener(lambda e: self._on_audit_status_changed(e))
        
        # Create search panel
        search_panel = JPanel(BorderLayout())
        search_label = JLabel("Search (Path/URL or Note): ")
        search_panel.add(search_label, BorderLayout.WEST)
        
        from javax.swing import JTextField
        from javax.swing.event import DocumentListener
        
        self._watch_search_field = JTextField(20)
        search_panel.add(self._watch_search_field, BorderLayout.CENTER)
        
        # Add search functionality
        class SearchDocumentListener(DocumentListener):
            def __init__(self, extension_parent):
                self.extension_parent = extension_parent
            
            def insertUpdate(self, e):
                self.extension_parent._filter_watch_table()
            
            def removeUpdate(self, e):
                self.extension_parent._filter_watch_table()
            
            def changedUpdate(self, e):
                self.extension_parent._filter_watch_table()
        
        self._watch_search_field.getDocument().addDocumentListener(SearchDocumentListener(self))
        
        # Clear search button
        clear_search_btn = JButton("Clear", actionPerformed=self._clear_watch_search)
        search_panel.add(clear_search_btn, BorderLayout.EAST)
        
        # Create center panel with search and table
        center_panel = JPanel(BorderLayout())
        center_panel.add(search_panel, BorderLayout.NORTH)
        
        # Scroll pane for table
        table_scroll = JScrollPane(self._watch_table)
        center_panel.add(table_scroll, BorderLayout.CENTER)
        
        table_panel.add(center_panel, BorderLayout.CENTER)
        
        # Button panel for table operations
        table_button_panel = JPanel()
        
        # Add single path button
        add_path_btn = JButton("Add Path", actionPerformed=self._add_single_path)
        table_button_panel.add(add_path_btn)
        
        # Remove selected path button
        remove_path_btn = JButton("Remove Selected", actionPerformed=self._remove_selected_path)
        table_button_panel.add(remove_path_btn)
        
        # Edit note button
        edit_note_btn = JButton("Edit Note", actionPerformed=self._edit_note_for_selected)
        table_button_panel.add(edit_note_btn)
        
        # Clear all button
        clear_all_btn = JButton("Clear All", actionPerformed=self._clear_all_from_table)
        table_button_panel.add(clear_all_btn)
        
        table_panel.add(table_button_panel, BorderLayout.SOUTH)
        
        parent_pane.addTab("Table View", table_panel)
    
    def _create_table_hover_listener(self):
        """Create mouse motion listener for table row highlighting on hover"""
        class TableHoverListener(MouseAdapter):
            def __init__(self, extension_parent):
                MouseAdapter.__init__(self)
                self.extension_parent = extension_parent
                self.last_hover_row = -1
            
            def mouseMoved(self, event):
                table = event.getSource()
                point = event.getPoint()
                hover_row = table.rowAtPoint(point)
                
                if hover_row != self.last_hover_row:
                    if self.last_hover_row >= 0:
                        table.repaint(table.getCellRect(self.last_hover_row, 0, True))
                    if hover_row >= 0:
                        table.repaint(table.getCellRect(hover_row, 0, True))
                    self.last_hover_row = hover_row
        
        return TableHoverListener(self)
    
    def _create_table_context_menu_listener(self):
        """Create mouse listener for right-click context menu"""
        class TableContextMenuListener(MouseAdapter):
            def __init__(self, extension_parent):
                MouseAdapter.__init__(self)
                self.extension_parent = extension_parent
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self._show_context_menu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self._show_context_menu(event)
            
            def _show_context_menu(self, event):
                table = event.getSource()
                point = event.getPoint()
                row = table.rowAtPoint(point)
                
                if row >= 0:
                    # If the clicked row is not selected, select only that row
                    if row not in table.getSelectedRows():
                        table.setRowSelectionInterval(row, row)
                    
                    # Create context menu
                    from javax.swing import JPopupMenu, JMenuItem
                    popup = JPopupMenu()
                    
                    selected_rows = table.getSelectedRows()
                    
                    # Edit Note option (only for single selection)
                    if len(selected_rows) == 1:
                        note_item = JMenuItem("Edit Note...")
                        note_item.addActionListener(lambda e: self.extension_parent._edit_note_for_row(selected_rows[0]))
                        popup.add(note_item)
                    
                    # Copy URL option
                    if len(selected_rows) == 1:
                        copy_text = "Copy URL"
                    else:
                        copy_text = "Copy {} URLs".format(len(selected_rows))
                    
                    copy_item = JMenuItem(copy_text)
                    copy_item.addActionListener(lambda e: self.extension_parent._copy_selected_watch_urls())
                    popup.add(copy_item)
                    popup.addSeparator()
                    
                    # Delete option
                    if len(selected_rows) == 1:
                        delete_item = JMenuItem("Delete Selected Request")
                    else:
                        delete_item = JMenuItem("Delete {} Selected Requests".format(len(selected_rows)))
                    
                    delete_item.addActionListener(lambda e: self.extension_parent._delete_selected_requests())
                    popup.add(delete_item)
                    
                    # Mark as vulnerable option
                    if len(selected_rows) == 1:
                        vuln_item = JMenuItem("Mark as Vulnerable...")
                    else:
                        vuln_item = JMenuItem("Mark {} Requests as Vulnerable...".format(len(selected_rows)))
                    
                    vuln_item.addActionListener(lambda e: self.extension_parent._mark_selected_as_vulnerable(selected_rows))
                    popup.add(vuln_item)
                    
                    # Set highlight option
                    if len(selected_rows) == 1:
                        highlight_item = JMenuItem("Enable Highlighting")
                        unhighlight_item = JMenuItem("Disable Highlighting")
                    else:
                        highlight_item = JMenuItem("Enable Highlighting for {} Requests".format(len(selected_rows)))
                        unhighlight_item = JMenuItem("Disable Highlighting for {} Requests".format(len(selected_rows)))
                    
                    highlight_item.addActionListener(lambda e: self.extension_parent._set_highlight_for_selected(selected_rows, True))
                    unhighlight_item.addActionListener(lambda e: self.extension_parent._set_highlight_for_selected(selected_rows, False))
                    popup.add(highlight_item)
                    popup.add(unhighlight_item)
                    popup.addSeparator()
                    
                    # Add "Send to Repeater" option (only for single selection)
                    if len(selected_rows) == 1:
                        send_item = JMenuItem("Send to Repeater")
                        send_item.addActionListener(lambda e: self.extension_parent._send_to_repeater(selected_rows[0]))
                        popup.add(send_item)
                    
                    popup.show(table, event.getX(), event.getY())
        
        return TableContextMenuListener(self)
    
    def _setup_table_row_highlighting(self):
        """Setup custom table renderer for row highlighting"""
        from java.awt import Color
        from javax.swing.table import DefaultTableCellRenderer
        from javax.swing import JCheckBox
        
        class HoverRowRenderer(DefaultTableCellRenderer):
            def __init__(self, extension_parent):
                DefaultTableCellRenderer.__init__(self)
                self.extension_parent = extension_parent
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                
                # Default colors
                if isSelected:
                    component.setBackground(table.getSelectionBackground())
                    component.setForeground(table.getSelectionForeground())
                else:
                    # Check if this is the hover row
                    mouse_listener = None
                    for listener in table.getMouseMotionListeners():
                        if hasattr(listener, 'last_hover_row'):
                            mouse_listener = listener
                            break
                    
                    if mouse_listener and row == mouse_listener.last_hover_row:
                        # Light blue highlight for hover
                        component.setBackground(Color(230, 240, 255))
                        component.setForeground(Color.BLACK)
                    else:
                        component.setBackground(table.getBackground())
                        component.setForeground(table.getForeground())
                
                return component
        
        from javax.swing.table import TableCellRenderer
        
        class HoverCheckBoxRenderer(JCheckBox, TableCellRenderer):
            def __init__(self, extension_parent):
                JCheckBox.__init__(self)
                self.extension_parent = extension_parent
                self.setHorizontalAlignment(JCheckBox.CENTER)
                self.setOpaque(True)  # Important for background color to show
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                # Set checkbox state
                if value is not None and isinstance(value, (bool, java.lang.Boolean)):
                    self.setSelected(bool(value))
                else:
                    self.setSelected(False)
                
                # Handle colors and selection
                if isSelected:
                    self.setBackground(table.getSelectionBackground())
                    self.setForeground(table.getSelectionForeground())
                else:
                    # Check if this is the hover row
                    mouse_listener = None
                    for listener in table.getMouseMotionListeners():
                        if hasattr(listener, 'last_hover_row'):
                            mouse_listener = listener
                            break
                    
                    if mouse_listener and row == mouse_listener.last_hover_row:
                        # Light blue highlight for hover
                        self.setBackground(Color(230, 240, 255))
                        self.setForeground(Color.BLACK)
                    else:
                        self.setBackground(table.getBackground())
                        self.setForeground(table.getForeground())
                
                return self
        
        # Apply the appropriate renderer to each column
        text_renderer = HoverRowRenderer(self)
        checkbox_renderer = HoverCheckBoxRenderer(self)
        
        # Apply renderers based on column type
        for i in range(self._watch_table.getColumnCount()):
            column = self._watch_table.getColumnModel().getColumn(i)
            if i in [2, 3, 6]:  # "Manual Audited", "Scanned", "Highlight" columns (shifted by 1)
                column.setCellRenderer(checkbox_renderer)
            else:  # Text columns (#, Path/URL, Last Audit, Note)
                column.setCellRenderer(text_renderer)
    
    def _copy_selected_watch_urls(self):
        """Copy URLs of selected watch list entries to clipboard"""
        try:
            selected_rows = self._watch_table.getSelectedRows()
            if not selected_rows:
                self._show_status_feedback("No requests selected")
                return
            
            # Collect URLs from selected rows
            urls = []
            for row in selected_rows:
                url = self._watch_table_model.getValueAt(row, 1)  # Path/URL is column 1
                if url and url.strip():
                    urls.append(str(url).strip())
            
            if not urls:
                self._show_status_feedback("No valid URLs found in selected rows")
                return
            
            # Remove duplicates while preserving order
            unique_urls = []
            seen = set()
            for url in urls:
                if url not in seen:
                    unique_urls.append(url)
                    seen.add(url)
            
            # Join URLs with newlines
            url_text = '\n'.join(unique_urls)
            
            # Copy to clipboard
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            
            selection = StringSelection(url_text)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            
            # Show feedback
            if len(unique_urls) == 1:
                self._show_status_feedback("Copied 1 URL to clipboard")
            else:
                self._show_status_feedback("Copied {} unique URLs to clipboard".format(len(unique_urls)))
            
            print("Copied watch list URLs to clipboard:\n{}".format(url_text))
            
        except Exception as e:
            print("Error copying watch list URLs: {}".format(str(e)))
            self._show_status_feedback("Error copying URLs: {}".format(str(e)))
    
    def _delete_selected_requests(self):
        """Delete selected requests from the watch table"""
        try:
            selected_rows = self._watch_table.getSelectedRows()
            if not selected_rows:
                return
            
            # Confirm deletion
            from javax.swing import JOptionPane
            message = "Delete {} selected request(s)?".format(len(selected_rows))
            result = JOptionPane.showConfirmDialog(
                None,
                message,
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.YES_OPTION:
                # First, collect all the path URLs to be deleted
                paths_to_delete = []
                for row in selected_rows:
                    path_url = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                    paths_to_delete.append(path_url)
                
                # Remove rows in reverse order to maintain indices
                for row in sorted(selected_rows, reverse=True):
                    self._watch_table_model.removeRow(row)
                
                # Update row numbers after deletion
                self._update_row_numbers()
                
                # Remove from internal watch list audit data
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    # Create a new list without the deleted paths
                    current_watch_list = self._data['watch_list_audit']
                    updated_watch_list = [item for item in current_watch_list if item.get('path') not in paths_to_delete]
                    self._data['watch_list_audit'] = updated_watch_list
                
                # Save the updated watch list
                self._save_watch_list_data()
                
                # Update status label
                remaining_count = len(self._data.get('watch_list_audit', [])) if hasattr(self, '_data') else 0
                if hasattr(self, '_status_label'):
                    self._status_label.setText("Ready - {} path(s) in watch list".format(remaining_count))
                
                self._show_status_feedback("Deleted {} request(s)".format(len(selected_rows)))
                
        except Exception as e:
            print("Error deleting selected requests: {}".format(str(e)))
            self._show_status_feedback("Error deleting requests: {}".format(str(e)))
    
    def _mark_selected_as_vulnerable(self, selected_rows):
        """Mark selected requests as vulnerable with chosen CWE type"""
        try:
            if not selected_rows:
                return
            
            # Get full URLs from internal storage (not table display)
            selected_paths = []
            for row in selected_rows:
                # Get the full URL from internal storage based on row index
                if (hasattr(self, '_data') and 'watch_list_audit' in self._data and 
                    row < len(self._data['watch_list_audit'])):
                    full_url = self._data['watch_list_audit'][row].get('path', '')
                    if full_url:
                        selected_paths.append(full_url)
                        print("Selected for vulnerability marking: {}".format(full_url))
                else:
                    # Fallback: get from table display (might be just a path)
                    path_url = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                    selected_paths.append(path_url)
                    print("Fallback: Using table display value: {}".format(path_url))
            
            # Show CWE selection dialog
            from javax.swing import JDialog, JPanel, JLabel, JComboBox, JButton, JOptionPane
            from java.awt import GridBagLayout, GridBagConstraints, Insets, BorderLayout
            
            # Create dialog
            dialog = JDialog(None, "Mark as Vulnerable", True)
            dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE)
            dialog.setSize(500, 300)
            dialog.setLocationRelativeTo(None)
            
            main_panel = JPanel(BorderLayout())
            
            # Content panel
            content_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.insets = Insets(10, 10, 10, 10)
            gbc.anchor = GridBagConstraints.WEST
            
            # Title
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.gridwidth = 2
            if len(selected_rows) == 1:
                title_text = "Mark request as vulnerable:"
            else:
                title_text = "Mark {} requests as vulnerable:".format(len(selected_rows))
            title_label = JLabel(title_text)
            title_label.setFont(title_label.getFont().deriveFont(14.0))
            content_panel.add(title_label, gbc)
            
            # Show selected paths (limited to first few for display)
            gbc.gridy = 1
            gbc.gridwidth = 2
            if len(selected_paths) <= 5:
                paths_text = "\n".join(selected_paths)
            else:
                paths_text = "\n".join(selected_paths[:3]) + "\n... and {} more".format(len(selected_paths) - 3)
            
            paths_label = JLabel("<html><pre>{}</pre></html>".format(paths_text))
            paths_label.setFont(paths_label.getFont().deriveFont(10.0))
            content_panel.add(paths_label, gbc)
            
            # CWE selection
            gbc.gridy = 2
            gbc.gridwidth = 1
            gbc.weightx = 0.0
            content_panel.add(JLabel("CWE Type:"), gbc)
            
            gbc.gridx = 1
            gbc.weightx = 1.0
            gbc.fill = GridBagConstraints.HORIZONTAL
            cwe_items = ["{} - {}".format(k, v) for k, v in self._cwe_types.items()]
            cwe_combo = JComboBox(cwe_items)
            content_panel.add(cwe_combo, gbc)
            
            main_panel.add(content_panel, BorderLayout.CENTER)
            
            # Button panel
            button_panel = JPanel()
            
            # Track the result
            result = {"cwe_selected": None}
            
            # Mark button
            def mark_action(e):
                selected_item = str(cwe_combo.getSelectedItem())
                if selected_item:
                    result["cwe_selected"] = selected_item
                    dialog.dispose()
            
            mark_button = JButton("Mark as Vulnerable")
            mark_button.addActionListener(mark_action)
            button_panel.add(mark_button)
            
            # Cancel button
            cancel_button = JButton("Cancel")
            cancel_button.addActionListener(lambda e: dialog.dispose())
            button_panel.add(cancel_button)
            
            main_panel.add(button_panel, BorderLayout.SOUTH)
            
            dialog.add(main_panel)
            dialog.setVisible(True)
            
            # Process the result if user selected a CWE
            if result["cwe_selected"]:
                self._process_bulk_vulnerability_marking(selected_paths, result["cwe_selected"])
            
        except Exception as e:
            print("Error marking selected as vulnerable: {}".format(str(e)))
            self._show_status_feedback("Error marking vulnerabilities: {}".format(str(e)))
    
    def _get_actual_target_host(self):
        """Get the actual target hostname from current Burp project"""
        try:
            # Try to get a target from sitemap first
            targets = self._get_available_targets()
            if targets:
                # Return the first available target (most common case)
                return targets[0]
            
            # Fallback: try to get from proxy history
            if hasattr(self._callbacks, 'getProxyHistory'):
                history = self._callbacks.getProxyHistory()
                if history:
                    for item in history[:10]:  # Check first 10 items
                        try:
                            url = item.getUrl()
                            if url:
                                return "{}://{}:{}".format(
                                    url.getProtocol(),
                                    url.getHost(),
                                    url.getPort() if url.getPort() != -1 else (443 if url.getProtocol() == "https" else 80)
                                )
                        except:
                            continue
            
            # Last resort: return None so caller can handle appropriately
            return None
            
        except Exception as e:
            print("Error getting actual target host: {}".format(str(e)))
            return None

    def _process_bulk_vulnerability_marking(self, selected_paths, cwe_selection):
        """Process marking multiple paths as vulnerable"""
        try:
            # Parse CWE code and description
            cwe_code = cwe_selection.split(" - ")[0]
            description = cwe_selection.split(" - ")[1]
            
            marked_count = 0
            duplicate_count = 0
            
            for path_or_url in selected_paths:
                try:
                    # Default method
                    method = "GET"
                    
                    # Determine if we have a full URL or just a path
                    if path_or_url.startswith("http"):
                        # We have a full URL (from sitemap import)
                        full_url = path_or_url
                        # Extract just the path portion for the hash
                        try:
                            from java.net import URL
                            url_obj = URL(full_url)
                            path_for_hash = url_obj.getPath()
                            if url_obj.getQuery():
                                path_for_hash += "?" + url_obj.getQuery()
                        except:
                            # Fallback: extract path manually
                            if "://" in full_url:
                                # Remove protocol and host
                                parts = full_url.split("://", 1)
                                if len(parts) > 1:
                                    remaining = parts[1]
                                    if "/" in remaining:
                                        path_for_hash = "/" + remaining.split("/", 1)[1]
                                    else:
                                        path_for_hash = "/"
                                else:
                                    path_for_hash = "/"
                            else:
                                path_for_hash = full_url
                    else:
                        # We have just a path (legacy data or manual entry)
                        path_for_hash = path_or_url
                        # Try to get the actual target host from Burp
                        actual_target = self._get_actual_target_host()
                        if actual_target:
                            # Use the actual target host
                            if not path_or_url.startswith("/"):
                                path_or_url = "/" + path_or_url
                            full_url = "{}{}".format(actual_target, path_or_url)
                            print("Using actual target for vulnerability marking: {}".format(full_url))
                        else:
                            # Fallback: use a placeholder but warn user
                            full_url = "https://[TARGET_HOST]{}".format(path_or_url if path_or_url.startswith("/") else "/" + path_or_url)
                            print("Warning: Could not determine actual target host, using placeholder: {}".format(full_url))
                    
                    # Create hash for grouping using the path portion
                    request_hash = hash("{}:{}".format(method, path_for_hash))
                    
                    # Check for duplicate CWE on same URL
                    is_duplicate = False
                    with self._vuln_lock:
                        for vuln_id, vuln in self._vulnerabilities.items():
                            if (vuln['url'] == full_url and 
                                vuln['cwe'] == cwe_code):
                                is_duplicate = True
                                duplicate_count += 1
                                break
                        
                        if not is_duplicate:
                            # Create unique vulnerability ID using internal counter
                            self._vuln_counter += 1
                            vuln_id = self._vuln_counter
                            
                            # Store vulnerability
                            self._vulnerabilities[vuln_id] = {
                                'cwe': cwe_code,
                                'description': description,
                                'url': full_url,
                                'method': method,
                                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                'request_hash': request_hash,
                                'message': None  # No actual request message available
                            }
                            
                            # Save to database
                            self._save_vulnerability_to_database(vuln_id, self._vulnerabilities[vuln_id])
                            marked_count += 1
                
                except Exception as path_error:
                    print("Error processing path '{}': {}".format(path, str(path_error)))
            
            # Update vulnerability table
            self._refresh_vulnerability_table()
            
            # Switch to vulnerabilities tab to show results
            self._tabbed_pane.setSelectedIndex(1)
            
            # Show success message
            message_parts = []
            if marked_count > 0:
                message_parts.append("Marked {} path(s) as vulnerable to {}".format(marked_count, cwe_code))
            if duplicate_count > 0:
                message_parts.append("{} path(s) already marked with this CWE".format(duplicate_count))
            
            final_message = "\n".join(message_parts)
            
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(
                None,
                final_message,
                "Bulk Vulnerability Marking Complete",
                JOptionPane.INFORMATION_MESSAGE
            )
            
            self._show_status_feedback("Marked {} vulnerabilities".format(marked_count))
            print("Bulk vulnerability marking: {} new, {} duplicates for {}".format(
                marked_count, duplicate_count, cwe_code))
            
        except Exception as e:
            print("Error processing bulk vulnerability marking: {}".format(str(e)))
            self._show_status_feedback("Error processing vulnerabilities: {}".format(str(e)))
    
    def _set_highlight_for_selected(self, selected_rows, enable_highlight=True):
        """Enable or disable highlighting for selected requests in the watch table"""
        try:
            if not selected_rows:
                return
            
            # Confirm action
            from javax.swing import JOptionPane
            action_word = "enable" if enable_highlight else "disable"
            action_word_title = "Enable" if enable_highlight else "Disable"
            
            if len(selected_rows) == 1:
                message = "{} highlighting for the selected request?".format(action_word_title)
            else:
                message = "{} highlighting for {} selected requests?".format(action_word_title, len(selected_rows))
            
            result = JOptionPane.showConfirmDialog(
                None,
                message,
                "Confirm {} Highlighting".format(action_word_title),
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.YES_OPTION:
                # Set highlight value for all selected rows
                for row in selected_rows:
                    # Column 6 is the Highlight column
                    self._watch_table_model.setValueAt(enable_highlight, row, 6)
                
                # Update the internal data structure
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    for row in selected_rows:
                        path_url = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                        # Find the corresponding item in the watch list audit data
                        for item in self._data['watch_list_audit']:
                            if isinstance(item, dict) and item.get('path') == path_url:
                                item['highlight'] = enable_highlight
                                break
                
                # Save the updated data
                self._save_watch_list_data()
                
                # Show success message
                action_past = "enabled" if enable_highlight else "disabled"
                if len(selected_rows) == 1:
                    success_message = "Highlighting {} for the selected request".format(action_past)
                else:
                    success_message = "Highlighting {} for {} requests".format(action_past, len(selected_rows))
                
                self._show_status_feedback(success_message)
                print("{} highlighting for {} request(s)".format(action_past.title(), len(selected_rows)))
                
        except Exception as e:
            print("Error setting highlight for selected requests: {}".format(str(e)))
            self._show_status_feedback("Error updating highlighting: {}".format(str(e)))
    
    def _send_to_repeater(self, row_index):
        """Send the selected request to Burp Repeater"""
        try:
            path_url = self._watch_table_model.getValueAt(row_index, 1)  # Column 1 is now path/URL
            
            # For now, just show feedback. In a real implementation, you would:
            # 1. Find the corresponding HTTP request from the sitemap
            # 2. Use self._callbacks.sendToRepeater() to send it to Repeater
            
            self._show_status_feedback("Send to Repeater feature - Path: {}".format(path_url))
            print("Send to Repeater requested for: {}".format(path_url))
            
        except Exception as e:
            print("Error sending to repeater: {}".format(str(e)))
            self._show_status_feedback("Error sending to repeater: {}".format(str(e)))

    def _create_text_editor_tab(self, parent_pane):
        """Create the text editor tab for bulk editing"""
        text_panel = JPanel(BorderLayout())
        
        # Instructions
        instruction_label = JLabel("Add paths/URLs to monitor (one per line). Supports wildcards (*)")
        text_panel.add(instruction_label, BorderLayout.NORTH)
        
        # Text area for path list (keep the original functionality)
        self._path_textarea = JTextArea(15, 50)
        self._path_textarea.setFont(self._path_textarea.getFont().deriveFont(12.0))
        scroll_pane = JScrollPane(self._path_textarea)
        text_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # Button panel for text operations
        text_button_panel = JPanel()
        
        # Update button
        self._add_button = JButton("Update Watch List", actionPerformed=self._update_paths)
        text_button_panel.add(self._add_button)
        
        # Clear button
        self._clear_button = JButton("Clear All", actionPerformed=self._clear_paths)
        text_button_panel.add(self._clear_button)
        
        # Load sample button
        self._sample_button = JButton("Load Sample Paths", actionPerformed=self._load_sample)
        text_button_panel.add(self._sample_button)
        
        # Fetch from Sitemap button
        self._fetch_sitemap_button = JButton("Fetch from Sitemap", actionPerformed=self._fetch_from_sitemap_immediate)
        self._fetch_sitemap_button.setToolTipText("Immediately import new endpoints from sitemap using current configuration")
        text_button_panel.add(self._fetch_sitemap_button)
        
        text_panel.add(text_button_panel, BorderLayout.SOUTH)
        
        parent_pane.addTab("Text Editor", text_panel)
    
    def _create_vulnerabilities_tab(self):
        """Create the vulnerabilities tracking tab"""
        vuln_panel = JPanel(BorderLayout())
        
        # Top panel for CWE filter
        top_panel = JPanel()
        top_panel.add(JLabel("Filter by CWE Type:"))
        
        # CWE filter dropdown
        cwe_items = ["All Vulnerabilities"] + ["{} - {}".format(k, v) for k, v in self._cwe_types.items()]
        self._cwe_filter = JComboBox(cwe_items)
        self._cwe_filter.addActionListener(lambda e: self._filter_vulnerabilities())
        top_panel.add(self._cwe_filter)
        
        # Clear vulnerabilities button
        clear_vuln_btn = JButton("Clear All Vulnerabilities", actionPerformed=self._clear_vulnerabilities)
        top_panel.add(clear_vuln_btn)
        
        # Data file location button
        db_btn = JButton("Change Data File Location", actionPerformed=self._change_database_location)
        top_panel.add(db_btn)
        
        # Project directory button
        project_btn = JButton("Manage Projects", actionPerformed=self._manage_projects)
        top_panel.add(project_btn)
        
        # Export options
        top_panel.add(JLabel("Export as:"))
        
        # Export format dropdown
        export_formats = ["Text (URLs only)", "CSV (Save to file)", "JSON (Copy from dialog)"]
        self._export_format = JComboBox(export_formats)
        self._export_format.setSelectedIndex(0)  # Default to Text
        top_panel.add(self._export_format)
        
        # Export button
        export_btn = JButton("Export", actionPerformed=self._export_vulnerabilities)
        top_panel.add(export_btn)
        
        vuln_panel.add(top_panel, BorderLayout.NORTH)
        
        # Vulnerabilities table
        column_names = ["CWE", "Description", "Method", "URL", "Note", "Timestamp", "Remove"]
        
        # Create custom table model for remove button
        class VulnTableModel(DefaultTableModel):
            def __init__(self, column_names, rows):
                DefaultTableModel.__init__(self, column_names, rows)
            
            def isCellEditable(self, row, column):
                return False  # All cells are read-only
            
            def getColumnClass(self, column):
                if column == 6:  # "Remove" column (moved from 5 to 6)
                    return java.lang.String  # Will be rendered as button
                return java.lang.String
        
        self._vuln_table_model = VulnTableModel(column_names, 0)
        # Store original vulnerability data for filtering
        self._original_vuln_data = []
        
        self._vuln_table = JTable(self._vuln_table_model)
        self._vuln_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        # self._vuln_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        self._vuln_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        
        # Add hover highlighting for vulnerability table
        self._vuln_table.addMouseMotionListener(self._create_vuln_table_hover_listener())
        
        # Add right-click context menu for bulk operations
        self._vuln_table.addMouseListener(self._create_vuln_table_context_menu_listener())
        
        # Custom renderer and editor for remove button column
        self._setup_vuln_table_renderers()
        
        # Set column widths
        column_model = self._vuln_table.getColumnModel()
        column_model.getColumn(0).setPreferredWidth(60)   # CWE
        column_model.getColumn(1).setPreferredWidth(150)  # Description
        column_model.getColumn(2).setPreferredWidth(60)   # Method
        column_model.getColumn(3).setPreferredWidth(280)  # URL
        column_model.getColumn(4).setPreferredWidth(120)  # Note
        column_model.getColumn(5).setPreferredWidth(120)  # Timestamp
        column_model.getColumn(6).setPreferredWidth(70)   # Remove button
        
        # Create search panel for vulnerabilities
        vuln_search_panel = JPanel(BorderLayout())
        vuln_search_label = JLabel("Search (URL or Note): ")
        vuln_search_panel.add(vuln_search_label, BorderLayout.WEST)
        
        from javax.swing import JTextField
        from javax.swing.event import DocumentListener
        
        self._vuln_search_field = JTextField(20)
        vuln_search_panel.add(self._vuln_search_field, BorderLayout.CENTER)
        
        # Add search functionality for vulnerabilities
        class VulnSearchDocumentListener(DocumentListener):
            def __init__(self, extension_parent):
                self.extension_parent = extension_parent
            
            def insertUpdate(self, e):
                self.extension_parent._filter_vuln_table()
            
            def removeUpdate(self, e):
                self.extension_parent._filter_vuln_table()
            
            def changedUpdate(self, e):
                self.extension_parent._filter_vuln_table()
        
        self._vuln_search_field.getDocument().addDocumentListener(VulnSearchDocumentListener(self))
        
        # Clear search button for vulnerabilities
        clear_vuln_search_btn = JButton("Clear", actionPerformed=self._clear_vuln_search)
        vuln_search_panel.add(clear_vuln_search_btn, BorderLayout.EAST)
        
        # Create center panel with search and table
        vuln_center_panel = JPanel(BorderLayout())
        vuln_center_panel.add(vuln_search_panel, BorderLayout.NORTH)
        
        vuln_scroll = JScrollPane(self._vuln_table)
        vuln_center_panel.add(vuln_scroll, BorderLayout.CENTER)
        
        vuln_panel.add(vuln_center_panel, BorderLayout.CENTER)
        
        # Bottom panel for stats
        stats_panel = JPanel()
        self._vuln_stats_label = JLabel("Total Vulnerabilities: 0")
        stats_panel.add(self._vuln_stats_label)
        vuln_panel.add(stats_panel, BorderLayout.SOUTH)
        
        self._tabbed_pane.addTab("Vulnerabilities", vuln_panel)
    
    def _create_vuln_table_hover_listener(self):
        """Create mouse motion listener for vulnerability table row highlighting on hover"""
        class VulnTableHoverListener(MouseAdapter):
            def __init__(self, extension_parent):
                MouseAdapter.__init__(self)
                self.extension_parent = extension_parent
                self.last_hover_row = -1
            
            def mouseMoved(self, event):
                table = event.getSource()
                point = event.getPoint()
                hover_row = table.rowAtPoint(point)
                
                if hover_row != self.last_hover_row:
                    if self.last_hover_row >= 0:
                        table.repaint()
                    if hover_row >= 0:
                        table.repaint()
                    self.last_hover_row = hover_row
        
        return VulnTableHoverListener(self)
    
    def _create_vuln_table_context_menu_listener(self):
        """Create mouse listener for vulnerability table right-click context menu"""
        class VulnTableContextMenuListener(MouseAdapter):
            def __init__(self, extension_parent):
                MouseAdapter.__init__(self)
                self.extension_parent = extension_parent
            
            def mousePressed(self, event):
                if event.isPopupTrigger():
                    self._show_context_menu(event)
            
            def mouseReleased(self, event):
                if event.isPopupTrigger():
                    self._show_context_menu(event)
            
            def mouseClicked(self, event):
                # Handle remove button clicks
                if event.getClickCount() == 1:
                    table = event.getSource()
                    row = table.rowAtPoint(event.getPoint())
                    col = table.columnAtPoint(event.getPoint())
                    
                    # Check if "Remove" column was clicked
                    if col == 6 and row >= 0:  # Remove column (moved from 5 to 6)
                        self.extension_parent._remove_vulnerability_at_row(row)
            
            def _show_context_menu(self, event):
                table = event.getSource()
                point = event.getPoint()
                row = table.rowAtPoint(point)
                
                if row >= 0:
                    # If the clicked row is not selected, select only that row
                    if row not in table.getSelectedRows():
                        table.setRowSelectionInterval(row, row)
                    
                    # Create context menu
                    from javax.swing import JPopupMenu, JMenuItem
                    popup = JPopupMenu()
                    
                    selected_rows = table.getSelectedRows()
                    
                    # Copy URL option
                    if len(selected_rows) == 1:
                        copy_text = "Copy URL"
                    else:
                        copy_text = "Copy {} URLs".format(len(selected_rows))
                    
                    copy_item = JMenuItem(copy_text)
                    copy_item.addActionListener(lambda e: self.extension_parent._copy_selected_urls())
                    popup.add(copy_item)
                    
                    # Separator
                    popup.addSeparator()
                    
                    # Delete option
                    if len(selected_rows) == 1:
                        delete_text = "Delete Vulnerability"
                    else:
                        delete_text = "Delete {} Vulnerabilities".format(len(selected_rows))
                    
                    delete_item = JMenuItem(delete_text)
                    delete_item.addActionListener(lambda e: self.extension_parent._delete_selected_vulnerabilities())
                    popup.add(delete_item)
                    
                    popup.show(table, event.getX(), event.getY())
        
        return VulnTableContextMenuListener(self)
    
    def _setup_vuln_table_renderers(self):
        """Setup custom table renderer for vulnerability table row highlighting and remove button"""
        from java.awt import Color
        from javax.swing.table import DefaultTableCellRenderer, TableCellRenderer
        from javax.swing import JButton
        
        class VulnHoverRowRenderer(DefaultTableCellRenderer):
            def __init__(self, extension_parent):
                DefaultTableCellRenderer.__init__(self)
                self.extension_parent = extension_parent
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                component = DefaultTableCellRenderer.getTableCellRendererComponent(
                    self, table, value, isSelected, hasFocus, row, column)
                
                # Default colors
                if isSelected:
                    component.setBackground(table.getSelectionBackground())
                    component.setForeground(table.getSelectionForeground())
                else:
                    # Check if this is the hover row
                    mouse_listener = None
                    for listener in table.getMouseMotionListeners():
                        if hasattr(listener, 'last_hover_row'):
                            mouse_listener = listener
                            break
                    
                    if mouse_listener and row == mouse_listener.last_hover_row:
                        # Light blue highlight for hover
                        component.setBackground(Color(230, 240, 255))
                        component.setForeground(Color.BLACK)
                    else:
                        component.setBackground(table.getBackground())
                        component.setForeground(table.getForeground())
                
                return component
        
        class RemoveButtonRenderer(JButton, TableCellRenderer):
            def __init__(self, extension_parent):
                JButton.__init__(self, "Remove")
                self.extension_parent = extension_parent
                self.setOpaque(True)
            
            def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
                # Handle colors and selection
                if isSelected:
                    self.setBackground(table.getSelectionBackground())
                    self.setForeground(table.getSelectionForeground())
                else:
                    # Check if this is the hover row
                    mouse_listener = None
                    for listener in table.getMouseMotionListeners():
                        if hasattr(listener, 'last_hover_row'):
                            mouse_listener = listener
                            break
                    
                    if mouse_listener and row == mouse_listener.last_hover_row:
                        # Light blue highlight for hover
                        self.setBackground(Color(230, 240, 255))
                        self.setForeground(Color.BLACK)
                    else:
                        self.setBackground(table.getBackground())
                        self.setForeground(table.getForeground())
                
                return self
        
        # Apply renderers to appropriate columns
        text_renderer = VulnHoverRowRenderer(self)
        button_renderer = RemoveButtonRenderer(self)
        
        for i in range(self._vuln_table.getColumnCount()):
            column = self._vuln_table.getColumnModel().getColumn(i)
            if i == 6:  # Remove button column (moved from 5 to 6)
                column.setCellRenderer(button_renderer)
            else:  # Text columns
                column.setCellRenderer(text_renderer)
    
    def _delete_selected_vulnerabilities(self):
        """Delete selected vulnerabilities from the table"""
        try:
            selected_rows = self._vuln_table.getSelectedRows()
            if not selected_rows:
                return
            
            # Confirm deletion
            from javax.swing import JOptionPane
            message = "Delete {} selected vulnerability(ies)?".format(len(selected_rows))
            result = JOptionPane.showConfirmDialog(
                None,
                message,
                "Confirm Deletion",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.YES_OPTION:
                # First, collect all the vulnerability IDs to be deleted
                vuln_ids_to_delete = []
                for row in selected_rows:
                    # We need to find the vulnerability ID based on the row data
                    cwe = self._vuln_table_model.getValueAt(row, 0)
                    description = self._vuln_table_model.getValueAt(row, 1)
                    method = self._vuln_table_model.getValueAt(row, 2)
                    url = self._vuln_table_model.getValueAt(row, 3)
                    timestamp = self._vuln_table_model.getValueAt(row, 5)  # Fixed: timestamp is column 5, not 4
                    
                    # Find matching vulnerability ID
                    vuln_found = False
                    with self._vuln_lock:
                        for vuln_id, vuln_data in self._vulnerabilities.items():
                            if (vuln_data.get('cwe') == cwe and 
                                vuln_data.get('description') == description and
                                vuln_data.get('method') == method and
                                vuln_data.get('url') == url and
                                vuln_data.get('timestamp') == timestamp):
                                vuln_ids_to_delete.append(vuln_id)
                                vuln_found = True
                                print("DEBUG: Found vulnerability ID {} for deletion".format(vuln_id))
                                break
                    
                    if not vuln_found:
                        print("WARNING: Could not find vulnerability for row {} with data: CWE={}, URL={}, timestamp={}".format(
                            row, cwe, url, timestamp))
                
                print("DEBUG: Found {} vulnerabilities to delete out of {} selected rows".format(
                    len(vuln_ids_to_delete), len(selected_rows)))
                
                # Remove rows in reverse order to maintain indices
                for row in sorted(selected_rows, reverse=True):
                    self._vuln_table_model.removeRow(row)
                
                # Remove from internal vulnerability list and database
                deleted_count = 0
                failed_deletes = 0
                with self._vuln_lock:
                    for vuln_id in vuln_ids_to_delete:
                        if vuln_id in self._vulnerabilities:
                            del self._vulnerabilities[vuln_id]
                            print("DEBUG: Removed vulnerability {} from memory".format(vuln_id))
                        
                        # Remove from database file
                        if self._remove_vulnerability_from_database(vuln_id):
                            deleted_count += 1
                            print("DEBUG: Removed vulnerability {} from database".format(vuln_id))
                        else:
                            failed_deletes += 1
                            print("ERROR: Failed to delete vulnerability {} from database".format(vuln_id))
                
                print("DEBUG: Successfully deleted {} vulnerabilities from database".format(deleted_count))
                if failed_deletes > 0:
                    print("WARNING: Failed to delete {} vulnerabilities from database".format(failed_deletes))
                
                # Update vulnerability stats
                self._update_vulnerability_stats()
                
                if deleted_count > 0:
                    status_msg = "Deleted {} vulnerability(ies) - changes saved to file".format(deleted_count)
                    if failed_deletes > 0:
                        status_msg += " (Warning: {} failed to save)".format(failed_deletes)
                    self._show_status_feedback(status_msg)
                else:
                    if failed_deletes > 0:
                        self._show_status_feedback("Error: {} vulnerability deletion(s) failed to save to file".format(failed_deletes))
                    else:
                        self._show_status_feedback("Warning: No vulnerabilities were deleted from database")
                
        except Exception as e:
            print("Error deleting selected vulnerabilities: {}".format(str(e)))
            self._show_status_feedback("Error deleting vulnerabilities: {}".format(str(e)))
    
    def _copy_selected_urls(self):
        """Copy URLs of selected vulnerabilities to clipboard"""
        try:
            selected_rows = self._vuln_table.getSelectedRows()
            if not selected_rows:
                self._show_status_feedback("No vulnerabilities selected")
                return
            
            # Collect URLs from selected rows
            urls = []
            for row in selected_rows:
                url = self._vuln_table_model.getValueAt(row, 3)  # URL is column 3
                if url and url.strip():
                    urls.append(str(url).strip())
            
            if not urls:
                self._show_status_feedback("No valid URLs found in selected rows")
                return
            
            # Remove duplicates while preserving order
            unique_urls = []
            seen = set()
            for url in urls:
                if url not in seen:
                    unique_urls.append(url)
                    seen.add(url)
            
            # Join URLs with newlines
            url_text = '\n'.join(unique_urls)
            
            # Copy to clipboard
            from java.awt.datatransfer import StringSelection
            from java.awt import Toolkit
            
            selection = StringSelection(url_text)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(selection, None)
            
            # Show feedback
            if len(unique_urls) == 1:
                self._show_status_feedback("Copied 1 URL to clipboard")
            else:
                self._show_status_feedback("Copied {} unique URLs to clipboard".format(len(unique_urls)))
            
            print("Copied URLs to clipboard:\n{}".format(url_text))
            
        except Exception as e:
            print("Error copying URLs: {}".format(str(e)))
            self._show_status_feedback("Error copying URLs: {}".format(str(e)))
    
    def _remove_vulnerability_at_row(self, row):
        """Remove vulnerability at specific row with confirmation"""
        try:
            # Get vulnerability details for confirmation
            cwe = self._vuln_table_model.getValueAt(row, 0)
            description = self._vuln_table_model.getValueAt(row, 1)
            url = self._vuln_table_model.getValueAt(row, 3)
            
            # Confirm removal
            from javax.swing import JOptionPane
            message = "Remove vulnerability?\n\nCWE: {}\nDescription: {}\nURL: {}".format(cwe, description, url)
            result = JOptionPane.showConfirmDialog(
                None,
                message,
                "Confirm Removal",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.YES_OPTION:
                # Find and remove the vulnerability
                method = self._vuln_table_model.getValueAt(row, 2)
                timestamp = self._vuln_table_model.getValueAt(row, 5)  # Fixed: timestamp is column 5, not 4
                
                # Find matching vulnerability ID
                vuln_id_to_remove = None
                with self._vuln_lock:
                    for vuln_id, vuln_data in self._vulnerabilities.items():
                        if (vuln_data.get('cwe') == cwe and 
                            vuln_data.get('description') == description and
                            vuln_data.get('method') == method and
                            vuln_data.get('url') == url and
                            vuln_data.get('timestamp') == timestamp):
                            vuln_id_to_remove = vuln_id
                            break
                
                if vuln_id_to_remove is not None:
                    # Remove from table
                    self._vuln_table_model.removeRow(row)
                    
                    # Remove from internal list and database
                    with self._vuln_lock:
                        if vuln_id_to_remove in self._vulnerabilities:
                            del self._vulnerabilities[vuln_id_to_remove]
                    
                    if self._remove_vulnerability_from_database(vuln_id_to_remove):
                        self._show_status_feedback("Vulnerability deleted and saved to file")
                    else:
                        self._show_status_feedback("Error: Vulnerability deleted from UI but failed to save to file")
                    
                    # Update stats
                    self._update_vulnerability_stats()
                    
                    self._show_status_feedback("Vulnerability removed successfully")
                else:
                    self._show_status_feedback("Error: Could not find vulnerability to remove")
            
        except Exception as e:
            print("Error removing vulnerability: {}".format(str(e)))
            self._show_status_feedback("Error removing vulnerability: {}".format(str(e)))
    
    def _update_vulnerability_stats(self):
        """Update vulnerability statistics display"""
        try:
            total_count = len(self._vulnerabilities)
            displayed_count = self._vuln_table_model.getRowCount()
            unique_requests = len(set(v['request_hash'] for v in self._vulnerabilities.values())) if self._vulnerabilities else 0
            
            # Update the stats label
            if hasattr(self, '_vuln_stats_label'):
                if displayed_count != total_count:
                    # Filtered view
                    self._vuln_stats_label.setText("Showing {} of {} vulnerabilities | {} unique requests".format(
                        displayed_count, total_count, unique_requests))
                else:
                    # All vulnerabilities
                    self._vuln_stats_label.setText("Total: {} vulnerabilities across {} unique requests".format(
                        total_count, unique_requests))
                        
        except Exception as e:
            print("Error updating vulnerability stats: {}".format(str(e)))
    
    def _update_gui_with_loaded_data(self):
        """Update GUI components with data loaded from JSON file"""
        try:
            # Set flag to prevent saving during GUI update
            self._is_updating_gui = True
            
            # Update watch paths text area from watch_list_audit
            if hasattr(self, '_data') and self._data.get('watch_list_audit'):
                paths = [item.get('path', '') for item in self._data['watch_list_audit'] if item.get('path')]
                self._path_textarea.setText('\n'.join(paths))
                self._status_label.setText("Ready - {} path(s) in watch list".format(len(paths)))
            else:
                self._path_textarea.setText('')
                self._status_label.setText("Ready - 0 paths in watch list")
            
            # Update watch list table with audit status if available
            if hasattr(self, '_watch_table_model') and hasattr(self, '_data'):
                
                # Set flag to prevent table model listener from firing during population
                self._is_updating_gui = True
                
                # Clear existing table data thoroughly with enhanced clearing
                self._watch_table_model.setRowCount(0)
                self._watch_table_model.fireTableDataChanged()
                
                # Force table to recognize the change immediately
                if hasattr(self, '_watch_table'):
                    try:
                        SwingUtilities.invokeLater(lambda: self._watch_table.revalidate())
                    except:
                        pass
                
                print("Cleared existing table data, now loading new data...")
                
                # Load audit data if available
                if 'watch_list_audit' in self._data and self._data['watch_list_audit']:
                    # Load from detailed audit data
                    row_number = 1
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict):
                            path = item.get('path', '')
                            # Use display format for the table
                            display_path = self._get_display_url(path)
                            manual_audited = item.get('manual_audited', False)
                            scanned = item.get('scanned', False)
                            date_added = item.get('date_added', datetime.now().strftime("%Y-%m-%d %H:%M"))
                            last_audit = item.get('last_audit', date_added if manual_audited or scanned else "Never")
                            note = item.get('note', '')  # Get user note
                            highlight = item.get('highlight', False)  # Default to false for highlighting
                            row_data = [str(row_number), display_path, manual_audited, scanned, last_audit, note, highlight]
                            self._watch_table_model.addRow(row_data)
                            row_number += 1
                elif hasattr(self, '_data') and self._data.get('watch_list_audit'):
                    # Fallback: create table entries from watch list audit data
                    row_number = 1
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict):
                            path = item.get('path', '')
                            # Use display format for the table
                            display_path = self._get_display_url(path)
                            manual_audited = item.get('manual_audited', False)
                            scanned = item.get('scanned', False)
                            last_audit = item.get('last_audit', "Never")
                            note = item.get('note', '')  # Get user note
                            highlight = item.get('highlight', False)
                            row_data = [str(row_number), display_path, manual_audited, scanned, last_audit, note, highlight]
                            self._watch_table_model.addRow(row_data)
                            row_number += 1
                else:
                    pass
                
                # Update status with audit counts
                total_paths = self._watch_table_model.getRowCount()
                if total_paths > 0:
                    audited_count = 0
                    for row in range(total_paths):
                        if self._watch_table_model.getValueAt(row, 2):  # Manual audited column is now 2
                            audited_count += 1
                    
                    self._status_label.setText("Ready - {} paths ({} audited, {} pending)".format(
                        total_paths, audited_count, total_paths - audited_count))
                else:
                    pass
                
                # Enhanced table refresh - fire multiple events to ensure GUI updates
                try:
                    self._watch_table_model.fireTableDataChanged()
                    self._watch_table_model.fireTableStructureChanged()
                    print("Fired table data changed events")
                    
                    # Force immediate table component refresh
                    if hasattr(self, '_watch_table'):
                        SwingUtilities.invokeLater(lambda: self._watch_table.revalidate())
                        SwingUtilities.invokeLater(lambda: self._watch_table.repaint())
                except Exception as table_error:
                    print("Error firing table events: {}".format(str(table_error)))
            else:
                if not hasattr(self, '_watch_table_model'):
                    print("Watch table model not found")
                if not hasattr(self, '_data'):
                    print("Data attribute not found")
            
            # Update project info
            if hasattr(self, '_current_project_name'):
                project_info = "Project: {} ({} projects available)".format(
                    self._current_project_name, 
                    len(self._project_mappings)
                )
                self._project_info_label.setText(project_info)
            
            # Update vulnerabilities table
            self._refresh_vulnerability_table()
            
            # Clear the flag before updating audit status to allow the audit display to work properly
            self._is_updating_gui = False
            
            # Update progress bar display
            self._update_audit_status_display()
            
            # Re-set flag temporarily for final UI updates
            self._is_updating_gui = True
            
            # Force repaint of table components to ensure they show the new data
            if hasattr(self, '_watch_table'):
                try:
                    SwingUtilities.invokeLater(lambda: self._watch_table.repaint())
                except:
                    pass
            
            if hasattr(self, '_vuln_table'):
                try:
                    SwingUtilities.invokeLater(lambda: self._vuln_table.repaint())
                except:
                    pass
            
            # Get path count from watch_list_audit
            # path_count = len(self._data.get('watch_list_audit', [])) if hasattr(self, '_data') else 0
            # print("GUI updated with loaded data: {} paths, {} vulnerabilities".format(
            #     path_count, len(self._vulnerabilities)))
            # print("Project switch complete: Configuration and paths loaded for project '{}'".format(
            #     getattr(self, '_current_project_name', 'Unknown')))
            
            # Clear the flag to re-enable saving
            self._is_updating_gui = False
            print("GUI update completed - saving re-enabled")
            
            # Store original watch table data for search filtering
            self._store_original_watch_data()
                
        except Exception as e:
            print("Error updating GUI with loaded data: {}".format(str(e)))
            # Ensure flag is cleared even on error
            self._is_updating_gui = False
            traceback.print_exc()
    
    def _validate_and_convert_paths(self, path_list):
        """Validate path list and convert paths to full URLs if needed"""
        try:
            if not path_list:
                return []
            
            # Check if any paths are missing hostname/schema
            paths_without_url = []
            full_urls = []
            
            for path in path_list:
                path = path.strip()
                if not path:
                    continue
                    
                # Check if it's already a full URL
                if path.startswith('http://') or path.startswith('https://'):
                    full_urls.append(path)
                else:
                    # It's just a path
                    paths_without_url.append(path)
            
            # If we have paths without URLs, prompt user for base URL
            if paths_without_url:
                from javax.swing import JOptionPane, JTextField, JPanel, JLabel
                from java.awt import GridBagLayout, GridBagConstraints, Insets
                
                # Show dialog to get base URL
                dialog_panel = JPanel(GridBagLayout())
                gbc = GridBagConstraints()
                gbc.insets = Insets(5, 5, 5, 5)
                gbc.anchor = GridBagConstraints.WEST
                
                # Title
                gbc.gridx = 0
                gbc.gridy = 0
                gbc.gridwidth = 2
                title_label = JLabel("No hostname and schema found for {} path(s)".format(len(paths_without_url)))
                title_label.setFont(title_label.getFont().deriveFont(14.0))
                dialog_panel.add(title_label, gbc)
                
                # Show example paths
                gbc.gridy = 1
                if len(paths_without_url) <= 3:
                    example_text = "Paths: " + ", ".join(paths_without_url)
                else:
                    example_text = "Paths: " + ", ".join(paths_without_url[:3]) + "... and {} more".format(len(paths_without_url) - 3)
                example_label = JLabel(example_text)
                example_label.setFont(example_label.getFont().deriveFont(10.0))
                dialog_panel.add(example_label, gbc)
                
                # Base URL input
                gbc.gridy = 2
                gbc.gridwidth = 1
                gbc.weightx = 0.0
                dialog_panel.add(JLabel("Please specify base URL:"), gbc)
                
                gbc.gridx = 1
                gbc.weightx = 1.0
                gbc.fill = GridBagConstraints.HORIZONTAL
                base_url_field = JTextField("https://example.com", 20)
                dialog_panel.add(base_url_field, gbc)
                
                # Show dialog
                result = JOptionPane.showConfirmDialog(
                    None,
                    dialog_panel,
                    "Specify Base URL",
                    JOptionPane.OK_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE
                )
                
                if result == JOptionPane.OK_OPTION:
                    base_url = base_url_field.getText().strip()
                    
                    if not base_url:
                        self._show_status_feedback("Base URL is required for path conversion")
                        return []
                    
                    # Validate base URL format
                    if not (base_url.startswith('http://') or base_url.startswith('https://')):
                        self._show_status_feedback("Base URL must start with http:// or https://")
                        return []
                    
                    # Remove trailing slash from base URL if present
                    if base_url.endswith('/'):
                        base_url = base_url[:-1]
                    
                    # Convert paths to full URLs
                    for path in paths_without_url:
                        if path.startswith('/'):
                            full_url = base_url + path
                        else:
                            full_url = base_url + '/' + path
                        full_urls.append(full_url)
                    
                    print("Converted {} paths using base URL: {}".format(len(paths_without_url), base_url))
                    for i, path in enumerate(paths_without_url):
                        print("  {} -> {}{}{}".format(path, base_url, '/' if not path.startswith('/') else '', path if path.startswith('/') else path))
                    
                else:
                    # User cancelled
                    self._show_status_feedback("Base URL input cancelled")
                    return []
            
            return full_urls
            
        except Exception as e:
            print("Error validating and converting paths: {}".format(str(e)))
            self._show_status_feedback("Error processing paths: {}".format(str(e)))
            return []
    
    def _url_to_path(self, url_or_path):
        """Convert a full URL to just the path portion for display"""
        try:
            if not url_or_path:
                return url_or_path
            
            # If it's already just a path, return as-is
            if not url_or_path.startswith('http'):
                return url_or_path
            
            # Extract path from full URL
            if "://" in url_or_path:
                # Remove protocol and host
                parts = url_or_path.split("://", 1)
                if len(parts) > 1:
                    remaining = parts[1]
                    if "/" in remaining:
                        path = "/" + remaining.split("/", 1)[1]
                    else:
                        path = "/"
                    return path
            
            return url_or_path
            
        except Exception as e:
            print("Error converting URL to path: {}".format(str(e)))
            return url_or_path
    
    def _get_display_url(self, stored_url):
        """Get the URL to display in the table based on user preference"""
        try:
            if self._show_full_urls_in_table:
                return stored_url  # Show full URL
            else:
                return self._url_to_path(stored_url)  # Show only path
        except Exception as e:
            print("Error getting display URL: {}".format(str(e)))
            return stored_url
    
    def _refresh_table_display(self):
        """Refresh the table display based on current URL display setting"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return
            
            # Update each row in the table to reflect current display preference
            for row in range(self._watch_table_model.getRowCount()):
                # Get the stored URL (this should always be the full URL in our data)
                stored_url = None
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    if row < len(self._data['watch_list_audit']):
                        stored_url = self._data['watch_list_audit'][row].get('path', '')
                
                if stored_url:
                    # Update the table display
                    display_url = self._get_display_url(stored_url)
                    self._watch_table_model.setValueAt(display_url, row, 1)  # Column 1 is now path/URL
            
            # Also update the text area
            self._sync_table_to_text()
            
        except Exception as e:
            print("Error refreshing table display: {}".format(str(e)))
    
    def _update_paths(self, event):
        """Update the path list from the text area - optimized to prevent UI freezing"""
        try:
            # Set updating flag to prevent events during processing
            self._is_updating_gui = True
            
            try:
                text = self._path_textarea.getText()
                raw_path_list = [line.strip() for line in text.split('\n') if line.strip()]
                
                if not raw_path_list:
                    # Clear the watch list if no paths provided
                    if not hasattr(self, '_data'):
                        self._data = {}
                    self._data['watch_list_audit'] = []
                    
                    if hasattr(self, '_watch_table_model'):
                        # Clear table efficiently
                        self._watch_table_model.setRowCount(0)
                        self._save_watch_list_data()
                    
                    self._status_label.setText("Ready - 0 paths in watch list")
                    self._update_audit_status_display()
                    return
                
                # Show progress feedback
                self._status_label.setText("Processing {} paths...".format(len(raw_path_list)))
                
                # Validate and convert paths to full URLs if needed
                validated_path_list = self._validate_and_convert_paths(raw_path_list)
                
                if not validated_path_list:
                    # User cancelled or validation failed
                    self._status_label.setText("Update cancelled")
                    return
                
                # Update watch_list_audit with validated paths
                if not hasattr(self, '_data'):
                    self._data = {}
                
                # Create new watch list audit data with CORRECT default values
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                self._data['watch_list_audit'] = []
                for path in validated_path_list:
                    self._data['watch_list_audit'].append({
                        'path': path,
                        'manual_audited': False,  # NEW PATHS: NOT manually audited
                        'scanned': False,         # NEW PATHS: NOT scanned
                        'last_audit': 'Never',
                        'highlight': False,
                        'note': '',
                        'added': current_time,
                        'source': 'text_update'
                    })
                
                # Update the text area with the validated full URLs
                self._path_textarea.setText('\n'.join(validated_path_list))
                
                # Sync to table if it exists (this will use the optimized sync function)
                if hasattr(self, '_watch_table_model'):
                    self._sync_text_to_table()
                    # Save watch list data with audit status
                    self._save_watch_list_data()
                else:
                    # Fallback: save using the new method
                    def save_in_background():
                        try:
                            self._save_watch_list_to_database()
                        except Exception as e:
                            print("Error saving watch list in background: {}".format(str(e)))
                    
                    # Run save operation in background thread
                    save_thread = threading.Thread(target=save_in_background)
                    save_thread.daemon = True
                    save_thread.start()
                
                # Update status and progress
                count = len(validated_path_list)
                self._status_label.setText("Ready - {} path(s) in watch list".format(count))
                self._update_audit_status_display()
                
                # Show brief success feedback
                SwingUtilities.invokeLater(lambda: self._show_status_feedback("Watch list updated with {} paths".format(count)))
                
            finally:
                # Always clear the updating flag
                self._is_updating_gui = False
            
        except Exception as e:
            print("Error updating paths: {}".format(str(e)))
            self._is_updating_gui = False
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error updating watch list: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _clear_paths(self, event):
        """Clear all paths from the list"""
        try:
            self._path_textarea.setText("")
            
            # Clear watch_list_audit data
            if not hasattr(self, '_data'):
                self._data = {}
            self._data['watch_list_audit'] = []
            
            self._status_label.setText("Ready - 0 paths in watch list")
            
            # Save to JSON file in background
            def save_in_background():
                try:
                    self._save_watch_list_to_database()
                except Exception as e:
                    print("Error saving cleared watch list: {}".format(str(e)))
            
            save_thread = threading.Thread(target=save_in_background)
            save_thread.daemon = True
            save_thread.start()
            
            print("Watch list cleared")
            
        except Exception as e:
            print("Error clearing paths: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error clearing watch list: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _load_sample(self, event):
        """Load sample paths for demonstration"""
        try:
            sample_paths = [
                "/admin/*",
                "/api/v1/*",
                "/login",
                "/logout", 
                "/dashboard",
                "/user/profile",
                "/config/*",
                "/debug/*",
                "/test/*",
                "*/upload",
                "*/download",
                "/rpc/construction/apartment/*"
            ]
            
            self._path_textarea.setText('\n'.join(sample_paths))
            self._update_paths(None)
            
        except Exception as e:
            print("Error loading sample paths: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error loading sample paths: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _fetch_from_sitemap_immediate(self, event):
        """Immediately fetch and import data from sitemap based on current configuration"""
        try:
            # Check if sitemap config exists
            if not hasattr(self, '_sitemap_config') or not self._sitemap_config:
                self._show_status_feedback("No sitemap configuration found. Please configure sitemap settings first.")
                return
            
            self._show_status_feedback("Fetching data from sitemap...")
            
            # Extract sitemap data using current configuration
            sitemap_data = self._extract_sitemap_data(self._sitemap_config)
            if not sitemap_data:
                self._show_status_feedback("No sitemap data found for target: {}".format(
                    self._sitemap_config.get("target", "Unknown")))
                return
            
            # Filter endpoints using current configuration
            filtered_endpoints = self._filter_sitemap_endpoints(sitemap_data, self._sitemap_config)
            if not filtered_endpoints:
                self._show_status_feedback("No endpoints found after filtering")
                return
            
            # Add new endpoints to watchlist
            imported_count = self._add_endpoints_to_watchlist(filtered_endpoints)
            
            if imported_count > 0:
                self._show_status_feedback("Successfully imported {} new endpoints from sitemap".format(imported_count))
                
                # Refresh the text area to show newly added paths
                if hasattr(self, '_path_textarea'):
                    self._sync_table_to_text()
            else:
                self._show_status_feedback("No new endpoints found - all sitemap URLs already in watch list")
            
        except Exception as e:
            error_msg = "Error fetching from sitemap: {}".format(str(e))
            print("ERROR: {}".format(error_msg))
            import traceback
            traceback.print_exc()
            self._show_status_feedback("{}".format(error_msg))
    
    def _import_watch_list(self, event):
        """Import watch list from a file"""
        try:
            # Open file dialog
            file_chooser = JFileChooser()
            file_chooser.setFileFilter(FileNameExtensionFilter("Text files (*.txt)", ["txt"]))
            file_chooser.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", ["json"]))
            file_chooser.setFileFilter(FileNameExtensionFilter("All supported files", ["txt", "json"]))
            
            result = file_chooser.showOpenDialog(None)
            if result != JFileChooser.APPROVE_OPTION:
                return
            
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            # Read file content
            with open(file_path, 'r') as f:
                content = f.read().strip()
            
            # Parse content based on file type
            raw_paths = []
            if file_path.lower().endswith('.json'):
                try:
                    import json
                    data = json.loads(content)
                    if isinstance(data, list):
                        raw_paths = [str(item) for item in data]
                    elif isinstance(data, dict) and 'paths' in data:
                        raw_paths = [str(item) for item in data['paths']]
                    else:
                        # Try to extract strings from dict values
                        for value in data.values():
                            if isinstance(value, list):
                                raw_paths.extend([str(item) for item in value])
                            elif isinstance(value, str):
                                raw_paths.append(value)
                except:
                    # Fallback to treating as text
                    raw_paths = [line.strip() for line in content.split('\n') if line.strip()]
            else:
                # Text file - one path per line
                raw_paths = [line.strip() for line in content.split('\n') if line.strip()]
            
            if not raw_paths:
                self._show_status_feedback("No valid paths found in file")
                return
            
            # Validate and convert paths to full URLs if needed
            validated_paths = self._validate_and_convert_paths(raw_paths)
            
            if not validated_paths:
                # User cancelled or validation failed
                return
            
            # Add paths to table with audit status
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            imported_count = 0
            
            # Ensure internal data structure exists
            if not hasattr(self, '_data') or 'watch_list_audit' not in self._data:
                self._data = {'watch_list_audit': []}
            
            # Get existing paths to avoid duplicates (check both table and internal data)
            existing_display_paths = set()
            for row in range(self._watch_table_model.getRowCount()):
                existing_display_paths.add(self._watch_table_model.getValueAt(row, 1))  # Column 1 is now path/URL
            
            # Also check internal data for existing full URLs
            existing_full_urls = set()
            for item in self._data['watch_list_audit']:
                if isinstance(item, dict):
                    full_url = item.get('path', '')
                    if full_url:
                        existing_full_urls.add(full_url)
                        # Add display version to existing paths too
                        display_url = self._get_display_url(full_url)
                        existing_display_paths.add(display_url)
            
            for path in validated_paths:
                display_path = self._get_display_url(path)
                if path and display_path not in existing_display_paths and path not in existing_full_urls:
                    # Add to table: [Path, Manual Audited (False), Scanned (False), Last Audit, Note, Highlight (False)]
                    row_data = [display_path, False, False, "Never", "", False]
                    self._watch_table_model.addRow(row_data)
                    
                    # CRITICAL FIX: Also add to internal data structure with full URL
                    audit_item = {
                        'path': path,  # Store full URL in internal data
                        'manual_audited': False,
                        'scanned': False,
                        'last_audit': 'Never',
                        'note': '',
                        'highlight': False,
                        'added': current_time,
                        'source': 'file_import'
                    }
                    self._data['watch_list_audit'].append(audit_item)
                    
                    imported_count += 1
                    print("Added path to both table and internal data: {}".format(path))
            
            # Update text area to sync
            self._sync_table_to_text()
            
            # Save the data
            self._save_watch_list_data()
            
            # Update status
            total_paths = self._watch_table_model.getRowCount()
            self._status_label.setText("Ready - {} paths in watch list ({} imported)".format(total_paths, imported_count))
            
            # Update progress display
            self._update_audit_status_display()
            
            # Show feedback
            self._show_status_feedback("Imported {} new paths from file".format(imported_count))
            
        except Exception as e:
            self._show_status_feedback("Error importing file: {}".format(str(e)))
            print("Import error: {}".format(str(e)))
    
    def _import_from_sitemap(self, event):
        """Import endpoints from Burp's Target sitemap with configuration dialog"""
        try:
            # Debug: Check basic requirements
            if not hasattr(self, '_callbacks'):
                print("ERROR: _callbacks not found!")
                return
            
            if not hasattr(self._callbacks, 'getSiteMap'):
                print("ERROR: getSiteMap method not available!")
                return
            
            # Quick test of sitemap access
            try:
                test_sitemap = self._callbacks.getSiteMap(None)
                if test_sitemap:
                    pass  # Sitemap is accessible
            except Exception as e:
                print("ERROR: Cannot access sitemap - {}".format(str(e)))
                return
            
            # Show configuration dialog
            print("DEBUG: Showing configuration dialog...")
            config = self._show_sitemap_import_config()
            if not config:
                print("DEBUG: User cancelled configuration dialog")
                return  # User cancelled
            
            print("DEBUG: Configuration received - Target: {}".format(config.get("target", "None")))
            
            # Get sitemap data from Burp
            sitemap_data = self._extract_sitemap_data(config)
            if not sitemap_data:
                self._show_status_feedback("No endpoints found in sitemap for target")
                return
            
            
            # Process and filter the endpoints
            filtered_endpoints = self._filter_sitemap_endpoints(sitemap_data, config)
            if not filtered_endpoints:
                print("DEBUG: No endpoints passed filtering")
                self._show_status_feedback("No endpoints match the filter criteria")
                return
            
            print("DEBUG: {} endpoints passed filtering".format(len(filtered_endpoints)))
            
            # Add to watch list
            print("DEBUG: Adding endpoints to watchlist...")
            imported_count = self._add_endpoints_to_watchlist(filtered_endpoints)
            print("DEBUG: Added {} new endpoints to watchlist".format(imported_count))
            
            # Save configuration if auto-update is enabled
            if config.get("auto_update", False):
                print("DEBUG: Saving sitemap configuration for auto-update")
                self._sitemap_config = config
                self._save_sitemap_config()
                self._start_sitemap_monitoring()
            
            # Save and update UI
            self._save_watch_list_data()
            self._update_audit_status_display()
            
            # Show feedback
            auto_update_msg = " (auto-update enabled)" if config.get("auto_update", False) else ""
            success_msg = "Imported {} endpoints from sitemap{}".format(imported_count, auto_update_msg)
            self._show_status_feedback(success_msg)
            
        except Exception as e:
            error_msg = "Error importing from sitemap: {}".format(str(e))
            print("ERROR: {}".format(error_msg))
            print("Exception details:", e)
            import traceback
            traceback.print_exc()
            self._show_status_feedback(error_msg)
    
    def _show_sitemap_import_config(self):
        """Show configuration dialog for sitemap import"""
        try:
            from javax.swing import JDialog, JFrame, JTextField, JTextArea, JCheckBox, JLabel, JPanel, JComboBox, JScrollPane, JOptionPane
            from java.awt import GridBagLayout, GridBagConstraints, Insets
            
            print("Starting sitemap import configuration dialog...")
            
            # Create dialog
            dialog_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.insets = Insets(5, 5, 5, 5)
            gbc.anchor = GridBagConstraints.WEST
            
            # Target selection
            gbc.gridx = 0
            gbc.gridy = 0
            dialog_panel.add(JLabel("Target URL:"), gbc)
            
            # Get available targets from sitemap
            available_targets = self._get_available_targets()
            target_combo = JComboBox(available_targets if available_targets else ["No targets found"])
            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            dialog_panel.add(target_combo, gbc)
            
            # Out-scope extensions
            gbc.gridx = 0
            gbc.gridy = 1
            gbc.fill = GridBagConstraints.NONE
            dialog_panel.add(JLabel("Exclude Extensions:"), gbc)
            
            extensions_field = JTextField("js,gif,jpg,css,svg,png,woff,pdf", 30)
            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            dialog_panel.add(extensions_field, gbc)
            
            # Exclude patterns
            gbc.gridx = 0
            gbc.gridy = 2
            gbc.fill = GridBagConstraints.NONE
            dialog_panel.add(JLabel("Exclude Path Patterns:"), gbc)
            
            exclude_area = JTextArea(3, 30)
            exclude_area.setText("*/admin/login/*\n*/logout\n*/static/*")
            exclude_scroll = JScrollPane(exclude_area)
            gbc.gridx = 1
            gbc.fill = GridBagConstraints.BOTH
            dialog_panel.add(exclude_scroll, gbc)
            
            # Exclude status codes
            gbc.gridx = 0
            gbc.gridy = 3
            gbc.fill = GridBagConstraints.NONE
            dialog_panel.add(JLabel("Exclude Status Codes:"), gbc)
            
            status_field = JTextField("101,404,500", 15)
            gbc.gridx = 1
            gbc.fill = GridBagConstraints.HORIZONTAL
            dialog_panel.add(status_field, gbc)
            
            # Auto-update checkbox
            gbc.gridx = 0
            gbc.gridy = 4
            gbc.gridwidth = 2
            auto_update_checkbox = JCheckBox("Auto-update when sitemap changes", False)
            dialog_panel.add(auto_update_checkbox, gbc)
            
            # Instructions
            # gbc.gridy = 5
            # instructions = JLabel("Wildcards: */pattern/* matches any path containing 'pattern'. /pattern/* matches paths starting with '/pattern/'")
            # dialog_panel.add(instructions, gbc)
            
            # Show dialog
            result = JOptionPane.showConfirmDialog(
                None,
                dialog_panel,
                "Import from Sitemap - Configuration",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE
            )
            
            if result == JOptionPane.OK_OPTION:
                selected_target = str(target_combo.getSelectedItem()) if target_combo.getSelectedItem() else None
                if not selected_target or selected_target == "No targets found":
                    return None
                
                return {
                    "target": selected_target,
                    "exclude_extensions": [ext.strip().lower() for ext in extensions_field.getText().split(",") if ext.strip()],
                    "exclude_patterns": [pattern.strip() for pattern in exclude_area.getText().split("\n") if pattern.strip()],
                    "exclude_status_codes": [int(code.strip()) for code in status_field.getText().split(",") if code.strip().isdigit()],
                    "auto_update": auto_update_checkbox.isSelected()
                }
            
            return None
            
        except Exception as e:
            print("Error showing sitemap config dialog: {}".format(str(e)))
            return None
    
    def _get_available_targets(self):
        """Get list of available targets from Burp's sitemap"""
        try:
            print("Getting available targets from sitemap...")
            targets = set()
            
            # Get all HTTP messages from the proxy history/sitemap
            if hasattr(self._callbacks, 'getSiteMap'):
                # Try to get sitemap for all URLs (pass None to get all)
                print("Attempting to get sitemap data...")
                site_map = self._callbacks.getSiteMap(None)
                
                if site_map:
                    for message_info in site_map:
                        if message_info:
                            try:
                                request_info = self._helpers.analyzeRequest(message_info)
                                url = request_info.getUrl()
                                if url:
                                    protocol = url.getProtocol()
                                    host = url.getHost()
                                    port = url.getPort()
                                    
                                    # Create full URL with schema
                                    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80) or port == -1:
                                        # Use default ports - don't show port number
                                        full_url = "{}://{}".format(protocol, host)
                                    else:
                                        # Non-default ports - include port number
                                        full_url = "{}://{}:{}".format(protocol, host, port)
                                    
                                    targets.add(full_url)
                            except Exception as e:
                                print("Error processing sitemap entry: {}".format(str(e)))
                                continue
            
            # If no targets found, try proxy history
            if not targets and hasattr(self._callbacks, 'getProxyHistory'):
                print("No sitemap targets found, trying proxy history...")
                proxy_history = self._callbacks.getProxyHistory()
                print("Got {} proxy history entries".format(len(proxy_history) if proxy_history else 0))
                
                if proxy_history:
                    for message_info in proxy_history:
                        if message_info:
                            try:
                                request_info = self._helpers.analyzeRequest(message_info)
                                url = request_info.getUrl()
                                if url:
                                    protocol = url.getProtocol()
                                    host = url.getHost()
                                    port = url.getPort()
                                    
                                    # Create full URL with schema
                                    if (protocol == "https" and port == 443) or (protocol == "http" and port == 80) or port == -1:
                                        # Use default ports - don't show port number
                                        full_url = "{}://{}".format(protocol, host)
                                    else:
                                        # Non-default ports - include port number
                                        full_url = "{}://{}:{}".format(protocol, host, port)
                                    
                                    targets.add(full_url)
                                    print("Added proxy target: {}".format(full_url))
                            except Exception as e:
                                print("Error processing proxy entry: {}".format(str(e)))
                                continue
            
            target_list = sorted(list(targets)) if targets else []
            return target_list
            
        except Exception as e:
            print("Error getting available targets: {}".format(str(e)))
            return []
    
    def _extract_sitemap_data(self, config):
        """Extract sitemap data for the specified target"""
        try:
            target_url = config["target"]
            sitemap_data = []
            
            # Parse the full URL (schema://host:port)
            if target_url.startswith("http://") or target_url.startswith("https://"):
                # Extract components from full URL
                if target_url.startswith("https://"):
                    protocol = "https"
                    host_part = target_url[8:]  # Remove "https://"
                    default_port = 443
                else:
                    protocol = "http"
                    host_part = target_url[7:]   # Remove "http://"
                    default_port = 80
                
                # Parse host and port
                if ":" in host_part:
                    host, port_str = host_part.split(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        print("Invalid port in target URL: {}".format(target_url))
                        return []
                else:
                    host = host_part
                    port = default_port
            else:
                # Fallback for old format (hostname only) - preserve backward compatibility
                if ":" in target_url:
                    host, port_str = target_url.split(":", 1)
                    try:
                        port = int(port_str)
                        # Guess protocol based on port
                        protocol = "https" if port == 443 else "http"
                    except ValueError:
                        print("Invalid port in target: {}".format(target_url))
                        return []
                else:
                    host = target_url
                    port = -1
                    protocol = "https"  # Default to HTTPS
                        
            # Get sitemap entries for the target
            if hasattr(self._callbacks, 'getSiteMap'):
                # Build URL pattern for the exact target
                if port in [80, 443] or port == -1:
                    # Use protocol-specific default port handling
                    if protocol == "https" and (port == 443 or port == -1):
                        base_url = "https://{}".format(host)
                    elif protocol == "http" and (port == 80 or port == -1):
                        base_url = "http://{}".format(host)
                    else:
                        # Mixed protocol/port - try both
                        base_url = "{}://{}".format(protocol, host)
                else:
                    # Custom port
                    base_url = "{}://{}:{}".format(protocol, host, port)
                                
                try:
                    site_map = self._callbacks.getSiteMap(base_url)
                    
                    if site_map:
                        # Found entries - process them silently
                        for message_info in site_map:
                            if message_info:
                                try:
                                    request_info = self._helpers.analyzeRequest(message_info)
                                    url = request_info.getUrl()
                                    
                                    if url and url.getHost() == host:
                                        # Check protocol and port matching
                                        url_protocol = url.getProtocol()
                                        url_port = url.getPort()
                                        
                                        protocol_matches = (url_protocol == protocol)
                                        port_matches = False
                                        
                                        if port == -1:
                                            # Accept default ports for the protocol
                                            if protocol == "https":
                                                port_matches = url_port in [443, -1]
                                            else:  # http
                                                port_matches = url_port in [80, -1]
                                        else:
                                            # Exact port match
                                            port_matches = (url_port == port)
                                        
                                        if protocol_matches and port_matches:
                                            response = message_info.getResponse()
                                            status_code = 200  # Default
                                            
                                            if response:
                                                try:
                                                    response_info = self._helpers.analyzeResponse(response)
                                                    status_code = response_info.getStatusCode()
                                                except:
                                                    pass
                                            
                                            entry = {
                                                "url": url,
                                                "method": request_info.getMethod(),
                                                "path": url.getPath() if url.getPath() else "/",
                                                "status_code": status_code,
                                                "response": response,  # Include response for MIME type checking
                                                "message_info": message_info
                                            }
                                            
                                            sitemap_data.append(entry)
                                            
                                except Exception as e:
                                    print("Error processing sitemap entry: {}".format(str(e)))
                                    continue
                    else:
                        pass
                        
                except Exception as e:
                    print("Error getting sitemap for {}: {}".format(base_url, str(e)))
            
            return sitemap_data
            
        except Exception as e:
            print("Error extracting sitemap data: {}".format(str(e)))
            return []
    
    def _normalize_sitemap_url(self, url):
        """Normalize URL from sitemap by removing default ports to match request URLs"""
        try:
            protocol = url.getProtocol()
            host = url.getHost()
            port = url.getPort()
            path = url.getPath() if url.getPath() else "/"
            
            # Build normalized URL without default ports
            if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                # Remove default port
                normalized_url = "{}://{}{}".format(protocol, host, path)
            else:
                # Keep non-default port
                normalized_url = "{}://{}:{}{}".format(protocol, host, port, path)
            
            return normalized_url
            
        except Exception as e:
            print("Error normalizing sitemap URL: {}".format(str(e)))
            # Fallback to string conversion
            return str(url)
    
    def _filter_sitemap_endpoints(self, sitemap_data, config):
        """Filter sitemap endpoints based on configuration"""
        try:
            filtered_endpoints = set()  # Use set to ensure uniqueness
            exclude_extensions = config.get("exclude_extensions", [])
            exclude_patterns = config.get("exclude_patterns", [])
            exclude_status_codes = config.get("exclude_status_codes", [])
            exclude_mime_types = config.get("exclude_mime_types", [])
            
            for entry in sitemap_data:
                url = entry["url"]
                path = entry["path"]
                status_code = entry.get("status_code", 200)
                response = entry.get("response", None)
                
                # Remove query parameters for uniqueness
                clean_path = path.split("?")[0] if "?" in path else path
                
                # Create full URL from the URL object and normalize it
                full_url = self._normalize_sitemap_url(url)
                # Remove query parameters from full URL for uniqueness 
                if "?" in full_url:
                    full_url = full_url.split("?")[0]
                                
                # Check status code exclusion
                if status_code in exclude_status_codes:
                    continue
                
                # Check file extension exclusion (check against path only)
                if self._has_excluded_extension(clean_path, exclude_extensions):
                    continue
                
                # Check pattern exclusion (check against path only)
                if self._matches_exclude_pattern(clean_path, exclude_patterns):
                    continue
                
                # Check MIME type exclusion
                if self._has_excluded_mime_type(response, exclude_mime_types):
                    continue
                
                # Add to filtered set (ensures uniqueness) - store full URL now
                filtered_endpoints.add(full_url)
            
            return list(filtered_endpoints)
            
        except Exception as e:
            print("Error filtering sitemap endpoints: {}".format(str(e)))
            return []
    
    def _has_excluded_extension(self, path, exclude_extensions):
        """Check if path has an excluded file extension"""
        try:
            if not exclude_extensions:
                return False
            
            # Get file extension
            if "." in path:
                extension = path.split(".")[-1].lower()
                return extension in exclude_extensions
            
            return False
            
        except Exception as e:
            print("Error checking excluded extension: {}".format(str(e)))
            return False
    
    def _matches_exclude_pattern(self, path, exclude_patterns):
        """Check if path matches any exclude pattern"""
        try:
            if not exclude_patterns:
                return False
            
            for pattern in exclude_patterns:
                if self._matches_wildcard_pattern(path, pattern):
                    return True
            
            return False
            
        except Exception as e:
            print("Error checking exclude patterns: {}".format(str(e)))
            return False
    
    def _matches_wildcard_pattern(self, path, pattern):
        """Check if path matches a wildcard pattern"""
        try:
            # Convert wildcard pattern to regex
            if pattern.startswith("*/") and pattern.endswith("/*"):
                # */pattern/* - matches any path containing 'pattern'
                inner_pattern = pattern[2:-2]  # Remove */ and /*
                return inner_pattern in path
            elif pattern.startswith("/") and pattern.endswith("/*"):
                # /pattern/* - matches paths starting with '/pattern/'
                prefix = pattern[:-2]  # Remove /*
                return path.startswith(prefix)
            elif pattern.endswith("/*"):
                # pattern/* - matches paths starting with 'pattern'
                prefix = pattern[:-2]  # Remove /*
                return path.startswith(prefix)
            elif pattern.startswith("*/"):
                # */pattern - matches paths ending with 'pattern'
                suffix = pattern[2:]  # Remove */
                return path.endswith(suffix)
            else:
                # Exact match or contains
                return pattern in path
                
        except Exception as e:
            print("Error matching wildcard pattern: {}".format(str(e)))
            return False
    
    def _has_excluded_mime_type(self, response, exclude_mime_types):
        """Check if response has excluded MIME type"""
        try:
            if not response or not exclude_mime_types:
                return False
            
            # Analyze the response to get MIME type using Burp's helpers
            try:
                response_info = self._helpers.analyzeResponse(response)
                inferred_mime_type = response_info.getInferredMimeType()
                
                if inferred_mime_type:
                    # Convert Burp MimeType enum to string for comparison
                    mime_type_str = str(inferred_mime_type).lower()
                    
                    # Check against excluded MIME types
                    for excluded_mime in exclude_mime_types:
                        excluded_mime_lower = excluded_mime.strip().lower()
                        
                        # Handle common MIME type mappings
                        if self._mime_type_matches(mime_type_str, excluded_mime_lower):
                            print("DEBUG: Excluding {} due to MIME type {} matching filter {}".format(
                                "response", mime_type_str, excluded_mime_lower))
                            return True
                
            except Exception as mime_error:
                print("Error getting MIME type from response: {}".format(str(mime_error)))
                
                # Fallback: try to determine from Content-Type header
                try:
                    headers = response_info.getHeaders() if response_info else []
                    content_type = None
                    
                    for header in headers:
                        header_str = str(header).lower()
                        if header_str.startswith("content-type:"):
                            content_type = header_str.split(":", 1)[1].strip() if ":" in header_str else ""
                            break
                    
                    if content_type:
                        mime_type = self._infer_mime_type_from_content_type(content_type)
                        if mime_type:
                            for excluded_mime in exclude_mime_types:
                                excluded_mime_lower = excluded_mime.strip().lower()
                                if self._mime_type_matches(mime_type, excluded_mime_lower):
                                    return True
                                    
                except Exception as header_error:
                    print("Error checking Content-Type header: {}".format(str(header_error)))
            
            return False
            
        except Exception as e:
            print("Error checking MIME type exclusion: {}".format(str(e)))
            return False
    
    def _infer_mime_type_from_content_type(self, content_type):
        """Infer MIME type from Content-Type header"""
        try:
            if not content_type:
                return None
            
            # Map common content types to MIME type categories
            if "text/html" in content_type:
                return "html"
            elif "application/json" in content_type:
                return "json"
            elif "application/xml" in content_type or "text/xml" in content_type:
                return "xml"
            elif "image/" in content_type:
                return "image"
            elif "video/" in content_type:
                return "video"
            elif "audio/" in content_type:
                return "sound"
            elif "font/" in content_type or "application/font" in content_type:
                return "font"
            elif "text/css" in content_type:
                return "css"
            elif "javascript" in content_type or "application/javascript" in content_type:
                return "script"
            else:
                return "other"
                
        except Exception as e:
            print("Error inferring MIME type: {}".format(str(e)))
            return None
    
    def _mime_type_matches(self, mime_type_str, excluded_mime):
        """Check if MIME type matches excluded pattern"""
        try:
            # Direct match
            if excluded_mime in mime_type_str:
                return True
            
            # Handle Burp MimeType enum values and aliases
            mime_mappings = {
                "image": ["image", "img", "gif", "jpeg", "jpg", "png", "svg", "bmp", "webp"],
                "video": ["video", "vid", "mp4", "avi", "mov", "wmv", "flv"],
                "sound": ["sound", "audio", "mp3", "wav", "ogg", "m4a", "flac"],
                "font": ["font", "woff", "woff2", "ttf", "otf", "eot"],
                "css": ["css", "stylesheet"],
                "script": ["script", "javascript", "js", "ecmascript"],
                "html": ["html", "htm"],
                "json": ["json", "application_json"],
                "xml": ["xml", "application_xml", "text_xml"]
            }
            
            # Check if the MIME type string contains any variations
            for mime_category, aliases in mime_mappings.items():
                if excluded_mime == mime_category:
                    for alias in aliases:
                        if alias in mime_type_str:
                            return True
            
            # Special handling for common Burp MIME type enum values
            burp_mime_mappings = {
                "xml": ["xml", "application_xml", "text_xml"],
                "json": ["json", "application_json"],
                "html": ["html", "text_html"],
                "css": ["css", "text_css"],
                "script": ["script", "javascript", "application_javascript", "text_javascript"],
                "image": ["image", "gif", "jpeg", "png"]
            }
            
            for excluded_type, burp_variations in burp_mime_mappings.items():
                if excluded_mime == excluded_type:
                    for variation in burp_variations:
                        if variation in mime_type_str:
                            return True
            
            return False
            
        except Exception as e:
            print("Error matching MIME type: {}".format(str(e)))
            return False

    def _add_endpoints_to_watchlist(self, endpoints):
        """Add filtered endpoints to the watch list with chunked processing to prevent GUI freezing"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return 0
            
            # Ensure internal data structure exists
            if not hasattr(self, '_data') or 'watch_list_audit' not in self._data:
                self._data = {'watch_list_audit': []}
            
            # Get existing paths to avoid duplicates (check both table and internal data)
            existing_paths = set()
            for row in range(self._watch_table_model.getRowCount()):
                existing_paths.add(self._watch_table_model.getValueAt(row, 1))  # Column 1 is now path/URL
            
            # Also check internal data for existing full URLs
            existing_full_urls = set()
            for item in self._data['watch_list_audit']:
                if isinstance(item, dict):
                    full_url = item.get('path', '')
                    if full_url:
                        existing_full_urls.add(full_url)
                        # Add display version to existing paths too
                        display_url = self._get_display_url(full_url)
                        existing_paths.add(display_url)
            
            # Filter out duplicates first
            new_endpoints = []
            for endpoint in endpoints:
                display_endpoint = self._get_display_url(endpoint)
                if endpoint and display_endpoint not in existing_paths and endpoint not in existing_full_urls:
                    new_endpoints.append(endpoint)
            
            if not new_endpoints:
                return 0
            
            print("Processing {} new endpoints from sitemap (chunked processing)".format(len(new_endpoints)))
            
            # Process in chunks to prevent GUI freezing
            chunk_size = 50  # Process 50 endpoints at a time
            total_imported = 0
            
            for i in range(0, len(new_endpoints), chunk_size):
                chunk = new_endpoints[i:i + chunk_size]
                chunk_imported = self._add_endpoint_chunk(chunk, i, len(new_endpoints))
                total_imported += chunk_imported
                
                # Small delay between chunks to keep GUI responsive
                if i + chunk_size < len(new_endpoints):  # Not the last chunk
                    # Use SwingUtilities to yield to GUI thread
                    SwingUtilities.invokeLater(lambda: None)
                    import time
                    time.sleep(0.1)  # 100ms pause between chunks
            
            # Final updates after all chunks processed
            print("Completed chunked processing: {} endpoints imported".format(total_imported))
            
            # Defer heavy operations to prevent freezing
            self._deferred_sitemap_completion(total_imported)
            
            return total_imported
            
        except Exception as e:
            print("Error adding endpoints to watchlist: {}".format(str(e)))
            import traceback
            traceback.print_exc()
            return 0
    
    def _add_endpoint_chunk(self, chunk_endpoints, start_index, total_count):
        """Add a chunk of endpoints to the table and internal data"""
        try:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            imported_count = 0
            
            # Set updating flag to prevent table model events during bulk updates
            self._is_updating_gui = True
            
            for endpoint in chunk_endpoints:
                display_endpoint = self._get_display_url(endpoint)
                
                # Add to table: [#, Path, Manual Audited, Scanned, Last Audit, Note, Highlight]
                row_number = self._watch_table_model.getRowCount() + 1
                row_data = [row_number, display_endpoint, False, False, "Never", "", False]
                self._watch_table_model.addRow(row_data)
                
                # Add to internal data structure with full URL
                audit_item = {
                    'path': endpoint,  # Store full URL in internal data
                    'manual_audited': False,
                    'scanned': False,
                    'last_audit': 'Never',
                    'note': '',
                    'highlight': False,
                    'added': current_time,
                    'source': 'sitemap'
                }
                self._data['watch_list_audit'].append(audit_item)
                imported_count += 1
            
            # Update row numbers after adding chunk
            self._update_row_numbers()
            
            # Clear updating flag
            self._is_updating_gui = False
            
            # Progress feedback
            progress = start_index + len(chunk_endpoints)
            print("Processed chunk: {}/{} endpoints ({:.1f}%)".format(
                progress, total_count, (progress / total_count) * 100))
            
            return imported_count
            
        except Exception as e:
            print("Error adding endpoint chunk: {}".format(str(e)))
            self._is_updating_gui = False  # Ensure flag is cleared
            return 0
    
    def _deferred_sitemap_completion(self, imported_count):
        """Deferred completion tasks after sitemap import to prevent GUI freezing"""
        try:
            # Use SwingUtilities to defer heavy GUI operations
            def completion_task():
                try:
                    print("Performing deferred sitemap completion tasks...")
                    
                    # Update text area (throttled)
                    self._sync_table_to_text()
                    
                    # Save data (throttled)
                    self._save_watch_list_data()
                    
                    # Update status (throttled)
                    self._update_audit_status_display()
                    
                    # Show feedback
                    if imported_count > 0:
                        self._show_status_feedback("Imported {} endpoints from sitemap".format(imported_count))
                    
                    print("Deferred sitemap completion finished: {} endpoints".format(imported_count))
                    
                except Exception as e:
                    print("Error in deferred sitemap completion: {}".format(str(e)))
            
            # Run completion task on GUI thread after a small delay
            SwingUtilities.invokeLater(completion_task)
            
        except Exception as e:
            print("Error scheduling deferred sitemap completion: {}".format(str(e)))
    
    def _save_sitemap_config(self):
        """Save sitemap configuration to data file"""
        try:
            if self._sitemap_config:
                # Save to file
                data = self._load_data_from_file()
                if 'settings' not in data:
                    data['settings'] = {}
                data['settings']['sitemap_config'] = self._sitemap_config
                self._save_data_to_file(data)
                
                # Refresh cached data to stay in sync
                self._data = data
                
                print("Sitemap configuration saved")
                print("  Saved patterns: {}".format(self._sitemap_config.get('exclude_patterns', [])))
                
        except Exception as e:
            print("Error saving sitemap config: {}".format(str(e)))
            import traceback
            traceback.print_exc()
    
    def _load_sitemap_config(self):
        """Load sitemap configuration from data file"""
        try:
            # Always read fresh data from file to avoid stale cached data
            data = self._load_data_from_file()
            config = data.get('settings', {}).get('sitemap_config', None)
            
            if config:
                self._sitemap_config = config
                return config
            else:
                pass  # No sitemap configuration found
                    
        except Exception as e:
            print("Error loading sitemap config: {}".format(str(e)))
            import traceback
            traceback.print_exc()
        
        return None
    
    def _start_sitemap_monitoring(self):
        """Start monitoring sitemap for changes"""
        try:
            if not self._sitemap_config:
                return
            
            # Stop existing monitoring thread if any
            self._stop_sitemap_monitoring()
            
            # Start new monitoring thread
            def monitor_sitemap():
                import time
                last_sitemap_size = 0
                check_counter = 0
                
                # Get monitoring frequency from config (default to less aggressive 10 seconds)
                monitor_frequency = self._sitemap_config.get("monitor_frequency", 10)
                full_check_interval = max(6, int(60 / monitor_frequency))  # Full check at least every 60 seconds
                                
                while self._sitemap_config and self._sitemap_config.get("auto_update", False):
                    try:
                        time.sleep(monitor_frequency)  # Use configured frequency
                        check_counter += 1
                        
                        if self._sitemap_config:
                            # Quick size check every iteration to detect changes
                            current_sitemap_size = self._get_sitemap_size()
                            
                            # Skip auto-update if table is already very large to prevent freeze
                            if hasattr(self, '_watch_table_model'):
                                current_table_size = self._watch_table_model.getRowCount()
                                if current_table_size > 1000:  # Skip if table already has 1000+ entries
                                    time.sleep(monitor_frequency * 3)  # Wait longer before next check
                                    continue
                            
                            # If sitemap size changed or periodic full check
                            if (current_sitemap_size > last_sitemap_size or 
                                check_counter % full_check_interval == 0):
                                                                
                                # Additional safeguard: if size difference is huge, warn and throttle
                                size_diff = current_sitemap_size - last_sitemap_size
                                if size_diff > 500:
                                    print("WARNING: Large sitemap change detected ({} new entries). Processing will be throttled.".format(size_diff))
                                    time.sleep(5)  # Extra delay for large changes
                                
                                self._check_sitemap_updates()
                                last_sitemap_size = current_sitemap_size
                            
                    except Exception as e:
                        break
            
            self._sitemap_monitor_thread = threading.Thread(target=monitor_sitemap)
            self._sitemap_monitor_thread.daemon = True
            self._sitemap_monitor_thread.start()
            
            
        except Exception as e:
            print("Error starting sitemap monitoring: {}".format(str(e)))
    
    def _stop_sitemap_monitoring(self):
        """Stop sitemap monitoring"""
        try:
            if self._sitemap_monitor_thread and self._sitemap_monitor_thread.is_alive():
                # Signal thread to stop by clearing config
                old_config = self._sitemap_config
                self._sitemap_config = None
                
                # Wait a bit for thread to notice
                import time
                time.sleep(1)
                
                
        except Exception as e:
            print("Error stopping sitemap monitoring: {}".format(str(e)))
    
    def _get_sitemap_size(self):
        """Get approximate size of sitemap for quick change detection"""
        try:
            if not self._sitemap_config:
                return 0
            
            target_url = self._sitemap_config["target"]
            
            # Parse the full URL (schema://host:port) - same logic as _extract_sitemap_data
            if target_url.startswith("http://") or target_url.startswith("https://"):
                # Extract components from full URL
                if target_url.startswith("https://"):
                    protocol = "https"
                    host_part = target_url[8:]  # Remove "https://"
                    default_port = 443
                else:
                    protocol = "http"
                    host_part = target_url[7:]   # Remove "http://"
                    default_port = 80
                
                # Parse host and port
                if ":" in host_part:
                    host, port_str = host_part.split(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        print("Invalid port in target URL: {}".format(target_url))
                        return 0
                else:
                    host = host_part
                    port = default_port
            else:
                # Fallback for old format (hostname only) - preserve backward compatibility
                if ":" in target_url:
                    host, port_str = target_url.split(":", 1)
                    try:
                        port = int(port_str)
                        protocol = "https" if port == 443 else "http"
                    except ValueError:
                        print("Invalid port in target: {}".format(target_url))
                        return 0
                else:
                    host = target_url
                    port = 443
                    protocol = "https"
            
            sitemap_size = 0
            
            # Quick count of sitemap entries for the exact target
            if hasattr(self._callbacks, 'getSiteMap'):
                # Build URL pattern for the exact target
                if port in [80, 443]:
                    # Use protocol-specific default port handling
                    if protocol == "https" and port == 443:
                        base_url = "https://{}".format(host)
                    elif protocol == "http" and port == 80:
                        base_url = "http://{}".format(host)
                    else:
                        base_url = "{}://{}".format(protocol, host)
                else:
                    # Custom port
                    base_url = "{}://{}:{}".format(protocol, host, port)
                
                try:
                    sitemap_entries = self._callbacks.getSiteMap(base_url)
                    if sitemap_entries:
                        sitemap_size = len(sitemap_entries)
                except Exception as e:
                    print("Error getting sitemap for {}: {}".format(base_url, str(e)))
            
            return sitemap_size
            
        except Exception as e:
            print("Error getting sitemap size: {}".format(str(e)))
            return 0
    
    def _check_sitemap_updates(self):
        """Check for new endpoints in sitemap and add them to watch list (optimized for large datasets)"""
        try:
            import time
            
            if not self._sitemap_config:
                return
            
            start_time = time.time()
            
            # Get current sitemap data
            sitemap_data = self._extract_sitemap_data(self._sitemap_config)
            if not sitemap_data:
                return
            
            
            # Filter endpoints
            filter_start = time.time()
            filtered_endpoints = self._filter_sitemap_endpoints(sitemap_data, self._sitemap_config)
            if not filtered_endpoints:
                return
            
            
            # Check for new endpoints efficiently
            new_endpoints = []
            if hasattr(self, '_watch_table_model'):
                # Build existing paths set for O(1) lookups (check both display and full URLs)
                existing_display_paths = set()
                existing_full_urls = set()
                
                for row in range(self._watch_table_model.getRowCount()):
                    existing_display_paths.add(self._watch_table_model.getValueAt(row, 1))  # Column 1 is now path/URL
                
                # Also check internal data for existing full URLs
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict):
                            full_url = item.get('path', '')
                            if full_url:
                                existing_full_urls.add(full_url)
                                # Add display version too
                                display_url = self._get_display_url(full_url)
                                existing_display_paths.add(display_url)
                
                # Find new endpoints
                for endpoint in filtered_endpoints:
                    display_endpoint = self._get_display_url(endpoint)
                    if endpoint not in existing_full_urls and display_endpoint not in existing_display_paths:
                        new_endpoints.append(endpoint)
            
            # Add new endpoints if any found
            if new_endpoints:
                
                # Use the same chunked processing as sitemap import to prevent GUI freezing
                imported_count = self._add_endpoints_to_watchlist_chunked(new_endpoints, is_auto_update=True)
                
                
            else:
                pass  # No new endpoints found
                
        except Exception as e:
            print("Error checking sitemap updates: {}".format(str(e)))
            import traceback
            traceback.print_exc()
    
    def _add_endpoints_to_watchlist_chunked(self, endpoints, is_auto_update=False):
        """Add endpoints using chunked processing specifically for auto-updates"""
        try:
            if not hasattr(self, '_watch_table_model') or not endpoints:
                return 0
            
            # Ensure internal data structure exists
            if not hasattr(self, '_data') or 'watch_list_audit' not in self._data:
                self._data = {'watch_list_audit': []}
            
            # Use smaller chunks for auto-updates to minimize GUI impact
            chunk_size = 20  # Smaller chunks for background auto-updates
            total_imported = 0
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            
            for i in range(0, len(endpoints), chunk_size):
                chunk = endpoints[i:i + chunk_size]
                
                # Set updating flag to prevent table model events during bulk updates
                self._is_updating_gui = True
                
                try:
                    for endpoint in chunk:
                        display_endpoint = self._get_display_url(endpoint)
                        
                        # Add to table: [#, Path, Manual Audited, Scanned, Last Audit, Note, Highlight]
                        row_number = self._watch_table_model.getRowCount() + 1
                        row_data = [row_number, display_endpoint, False, False, "Never", "", False]
                        self._watch_table_model.addRow(row_data)
                        
                        # Add to internal data structure with full URL
                        audit_item = {
                            'path': endpoint,  # Store full URL in internal data
                            'manual_audited': False,
                            'scanned': False,
                            'last_audit': 'Never',
                            'note': '',
                            'highlight': False,
                            'added': current_time,
                            'source': 'sitemap_auto'
                        }
                        self._data['watch_list_audit'].append(audit_item)
                        total_imported += 1
                    
                    # Update row numbers for this chunk
                    self._update_row_numbers()
                    
                finally:
                    # Always clear updating flag
                    self._is_updating_gui = False
                
                # Longer pause between chunks for auto-updates to stay out of the way
                if i + chunk_size < len(endpoints):  # Not the last chunk
                    import time
                    time.sleep(0.2)  # 200ms pause for auto-updates
                    
                    # Yield to GUI thread
                    SwingUtilities.invokeLater(lambda: None)
            
            # Deferred completion for auto-updates (less frequent saves)
            if total_imported > 0:
                self._deferred_auto_update_completion(total_imported)
            
            return total_imported
            
        except Exception as e:
            print("Error in chunked auto-update processing: {}".format(str(e)))
            self._is_updating_gui = False  # Ensure flag is cleared
            return 0
    
    def _deferred_auto_update_completion(self, imported_count):
        """Deferred completion for auto-updates with throttled saves"""
        try:
            def completion_task():
                try:
                    current_time = time.time()
                    
                    # Throttle saves for auto-updates (only save every 60 seconds)
                    if not hasattr(self, '_last_auto_save') or current_time - self._last_auto_save > 60:
                        self._save_watch_list_data()
                        self._last_auto_save = current_time
                    
                    # Throttle status updates (only update every 30 seconds)
                    if not hasattr(self, '_last_auto_status') or current_time - self._last_auto_status > 30:
                        self._update_audit_status_display()
                        self._last_auto_status = current_time
                    
                    # Always sync text area but throttle it too
                    if not hasattr(self, '_last_auto_sync') or current_time - self._last_auto_sync > 45:
                        self._sync_table_to_text()
                        self._last_auto_sync = current_time
                    
                    # Minimal feedback for auto-updates
                    # if imported_count > 0:
                    #     print("Auto-update completed: {} new endpoints added".format(imported_count))
                    
                except Exception as e:
                    print("Error in auto-update completion: {}".format(str(e)))
            
            # Delay completion task to avoid interfering with user activities
            SwingUtilities.invokeLater(completion_task)
            
        except Exception as e:
            print("Error scheduling auto-update completion: {}".format(str(e)))
    
    def _export_watch_list(self, event):
        """Export watch list to a file"""
        try:
            if hasattr(self, '_watch_table_model') and self._watch_table_model.getRowCount() == 0:
                self._show_status_feedback("No paths to export")
                return
            
            # Open save dialog
            file_chooser = JFileChooser()
            file_chooser.setFileFilter(FileNameExtensionFilter("Text files (*.txt)", ["txt"]))
            file_chooser.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", ["json"]))
            
            result = file_chooser.showSaveDialog(None)
            if result != JFileChooser.APPROVE_OPTION:
                return
            
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            # Prepare data - export from internal storage to preserve full URLs
            export_data = []
            if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                # Export from internal storage (always contains full URLs)
                for item in self._data['watch_list_audit']:
                    if isinstance(item, dict):
                        path = item.get('path', '')  # This is always a full URL
                        audited = item.get('manual_audited', False) or item.get('scanned', False)
                        last_audit = item.get('last_audit', 'Never')
                        
                        if file_path.lower().endswith('.json'):
                            export_data.append({
                                'path': path,
                                'audited': audited,
                                'last_audit': last_audit,
                                'note': item.get('note', ''),
                                'highlight': item.get('highlight', False)
                            })
                        else:
                            # Text format - just full URLs
                            export_data.append(path)
            elif hasattr(self, '_watch_table_model') and self._watch_table_model.getRowCount() > 0:
                # Fallback: export from table if no internal data (shouldn't normally happen)
                print("Warning: Exporting from table display instead of internal storage")
                for row in range(self._watch_table_model.getRowCount()):
                    path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                    audited = self._watch_table_model.getValueAt(row, 2)  # Column 2 is now manual audited
                    scanned = self._watch_table_model.getValueAt(row, 3)  # Column 3 is now scanned
                    last_audit = self._watch_table_model.getValueAt(row, 4)  # Column 4 is now last audit
                    note = self._watch_table_model.getValueAt(row, 5)  # Column 5 is now note
                    
                    if file_path.lower().endswith('.json'):
                        export_data.append({
                            'path': path,
                            'audited': audited,
                            'date_added': date_added
                        })
                    else:
                        # Text format - just paths
                        export_data.append(path)
            else:
                # Fallback - export empty list if no watch list data
                export_data = []
            
            # Write file
            with open(file_path, 'w') as f:
                if file_path.lower().endswith('.json'):
                    import json
                    json.dump(export_data, f, indent=2)
                else:
                    f.write('\n'.join(export_data))
            
            self._show_status_feedback("Watch list exported to {}".format(selected_file.getName()))
            
        except Exception as e:
            self._show_status_feedback("Error exporting file: {}".format(str(e)))
            print("Export error: {}".format(str(e)))
    
    def _show_configuration_dialog(self, event):
        """Show configuration dialog with all settings from data file"""
        try:
            from javax.swing import JDialog, JPanel, JLabel, JCheckBox, JButton, JTextArea, JScrollPane, JTabbedPane, JTextField, JComboBox, BorderFactory
            from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Dimension
            
            # Load current data to get all settings
            data = self._load_data_from_file()
            settings = data.get("settings", {})
            
            # Create dialog
            dialog = JDialog(None, "Vuln tracker Configuration", True)
            dialog.setSize(900, 750)  # Made wider and taller
            dialog.setLocationRelativeTo(None)
            
            main_panel = JPanel(BorderLayout())
            
            # Create status label that will be used in all tabs
            dialog_status_label = JLabel(" ")  # Empty initially
            dialog_status_label.setFont(dialog_status_label.getFont().deriveFont(12.0))
            
            # Create tabbed pane for different config sections
            config_tabs = JTabbedPane()
            
            # === AUTO-AUDIT SETTINGS TAB ===
            auto_audit_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.insets = Insets(8, 8, 8, 8)  # Increased spacing
            gbc.anchor = GridBagConstraints.WEST
            gbc.weightx = 1.0  # Allow horizontal expansion
            gbc.weighty = 0.0  # No vertical expansion initially
            
            # Title
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.gridwidth = 2
            title_label = JLabel("Auto-Audit Settings")
            title_label.setFont(title_label.getFont().deriveFont(16.0))
            auto_audit_panel.add(title_label, gbc)
            
            # Description
            gbc.gridy = 1
            desc_label = JLabel("Configure automatic marking of paths as audited")
            auto_audit_panel.add(desc_label, gbc)
            
            # Repeater checkbox
            gbc.gridy = 2
            gbc.gridwidth = 1
            auto_audit_repeater_checkbox = JCheckBox("Auto-mark as audited when accessed from Repeater", self._auto_audit_repeater_enabled)
            auto_audit_panel.add(auto_audit_repeater_checkbox, gbc)
            
            # Scanner checkbox
            gbc.gridy = 3
            auto_audit_scanner_checkbox = JCheckBox("Auto-mark as audited when accessed from Scanner", self._auto_audit_scanner_enabled)
            auto_audit_panel.add(auto_audit_scanner_checkbox, gbc)
            
            # Table view section separator
            gbc.gridx = 0
            gbc.gridy = 4
            gbc.gridwidth = 2
            title_label = JLabel("Table View Settings")
            title_label.setFont(title_label.getFont().deriveFont(16.0))
            auto_audit_panel.add(title_label, gbc)
            
            # Table view description
            gbc.gridy = 5
            table_view_desc = JLabel("Configure how URLs are displayed in the watch list table")
            auto_audit_panel.add(table_view_desc, gbc)
            
            # Show full URLs checkbox
            gbc.gridy = 6
            gbc.gridwidth = 1
            show_full_urls_checkbox = JCheckBox("Show full URLs in table (uncheck to show paths only)", self._show_full_urls_in_table)
            auto_audit_panel.add(show_full_urls_checkbox, gbc)
            
            config_tabs.addTab("Watch List", auto_audit_panel)
            
            # === SITEMAP SETTINGS TAB ===
            sitemap_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.insets = Insets(8, 8, 8, 8)  # Increased spacing
            gbc.anchor = GridBagConstraints.WEST
            gbc.weightx = 1.0  # Allow horizontal expansion
            gbc.weighty = 0.0  # No vertical expansion for most components
            
            # Title
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.gridwidth = 2
            sitemap_title = JLabel("Sitemap Import Configuration")
            sitemap_title.setFont(sitemap_title.getFont().deriveFont(16.0))
            sitemap_panel.add(sitemap_title, gbc)
            
            # Get current sitemap config or create default
            sitemap_config = settings.get("sitemap_config", {})
            
            # Define sitemap action buttons here so they can be referenced later
            update_sitemap_btn = JButton("Update Sitemap Config")
            clear_sitemap_btn = JButton("Clear Configuration")
            fetch_sitemap_btn = JButton("Fetch Data from Sitemap")
            fetch_sitemap_btn.setToolTipText("Immediately fetch and import new endpoints from sitemap")
            
            # Target selection
            gbc.gridx = 0
            gbc.gridy = 1
            gbc.gridwidth = 1
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Target URL:"), gbc)
            
            # Get available targets from sitemap
            available_targets = self._get_available_targets()
            current_target = sitemap_config.get("target", "")
            if current_target and current_target not in available_targets:
                available_targets.append(current_target)
            
            target_combo = JComboBox(available_targets if available_targets else ["No targets found"])
            if current_target:
                target_combo.setSelectedItem(current_target)
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.fill = GridBagConstraints.HORIZONTAL
            sitemap_panel.add(target_combo, gbc)
            
            # Exclude extensions
            gbc.gridx = 0
            gbc.gridy = 2
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Exclude Extensions:"), gbc)
            
            current_extensions = ",".join(sitemap_config.get("exclude_extensions", ["js", "gif", "jpg", "css", "svg", "png", "woff", "pdf"]))
            extensions_field = JTextField(current_extensions, 35)  # Made wider
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.fill = GridBagConstraints.HORIZONTAL
            sitemap_panel.add(extensions_field, gbc)
            
            # Exclude patterns
            gbc.gridx = 0
            gbc.gridy = 3
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Exclude Path Patterns:"), gbc)
            
            current_patterns = "\n".join(sitemap_config.get("exclude_patterns", ["*/admin/login/*", "*/logout", "*/static/*"]))
            exclude_area = JTextArea(8, 35)  # Made much taller (8 rows instead of 5)
            exclude_area.setText(current_patterns)
            exclude_area.setLineWrap(False)  # Disable line wrapping for better readability
            exclude_area.setWrapStyleWord(False)
            exclude_scroll = JScrollPane(exclude_area)
            exclude_scroll.setPreferredSize(Dimension(450, 180))  # Larger preferred size
            exclude_scroll.setMinimumSize(Dimension(400, 120))    # Set minimum size
            exclude_scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
            exclude_scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.weighty = 1.0  # Allow vertical expansion for text area
            gbc.fill = GridBagConstraints.BOTH
            sitemap_panel.add(exclude_scroll, gbc)
            
            # Exclude status codes
            gbc.gridx = 0
            gbc.gridy = 4
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Exclude Status Codes:"), gbc)
            
            current_status_codes = ",".join(map(str, sitemap_config.get("exclude_status_codes", [101, 404, 500])))
            status_field = JTextField(current_status_codes, 25)  # Made wider
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.fill = GridBagConstraints.HORIZONTAL
            sitemap_panel.add(status_field, gbc)
            
            # Exclude MIME types
            gbc.gridx = 0
            gbc.gridy = 5
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Exclude MIME Types:"), gbc)
            
            # Create MIME type checkboxes panel with control buttons
            mime_container = JPanel(BorderLayout())
            
            # Top panel with Select All/None and preset buttons
            mime_controls = JPanel()
            select_all_btn = JButton("Select All")
            select_none_btn = JButton("Select None")
            assets_btn = JButton("Static Assets")  # images, css, js, fonts
            api_btn = JButton("API Responses")     # json, xml
            
            mime_controls.add(select_all_btn)
            mime_controls.add(Box.createHorizontalStrut(3))
            mime_controls.add(select_none_btn)
            mime_controls.add(Box.createHorizontalStrut(8))
            mime_controls.add(JLabel("Presets:"))
            mime_controls.add(Box.createHorizontalStrut(3))
            mime_controls.add(assets_btn)
            mime_controls.add(Box.createHorizontalStrut(3))
            mime_controls.add(api_btn)
            
            mime_container.add(mime_controls, BorderLayout.NORTH)
            
            # Checkboxes panel
            mime_panel = JPanel()
            mime_panel.setLayout(BoxLayout(mime_panel, BoxLayout.X_AXIS))
            
            # Available MIME types with descriptions
            mime_options = [
                ("image", "Images (jpg, png, gif, etc.)"),
                ("video", "Videos (mp4, avi, etc.)"),
                ("sound", "Audio (mp3, wav, etc.)"),
                ("font", "Fonts (woff, ttf, etc.)"),
                ("css", "Stylesheets"),
                ("script", "JavaScript"),
                ("html", "HTML pages"),
                ("json", "JSON responses"),
                ("xml", "XML documents")
            ]
            
            # Get currently selected MIME types
            current_mime_types = sitemap_config.get("exclude_mime_types", ["image", "video", "sound", "font", "css", "script"])
            
            # Create checkboxes and store references
            mime_checkboxes = {}
            for mime_type, description in mime_options:
                checkbox = JCheckBox(mime_type, mime_type in current_mime_types)
                checkbox.setToolTipText(description)  # Show description on hover
                mime_checkboxes[mime_type] = checkbox
                mime_panel.add(checkbox)
                mime_panel.add(Box.createHorizontalStrut(5))  # Small spacing
            
            mime_container.add(mime_panel, BorderLayout.CENTER)
            
            # Add action listeners for control buttons
            def select_all_mime(e):
                for checkbox in mime_checkboxes.values():
                    checkbox.setSelected(True)
            
            def select_none_mime(e):
                for checkbox in mime_checkboxes.values():
                    checkbox.setSelected(False)
            
            def select_static_assets(e):
                # Select typical static assets: images, css, scripts, fonts, videos, sounds
                for checkbox in mime_checkboxes.values():
                    checkbox.setSelected(False)  # Clear all first
                static_types = ["image", "video", "sound", "font", "css", "script"]
                for mime_type in static_types:
                    if mime_type in mime_checkboxes:
                        mime_checkboxes[mime_type].setSelected(True)
            
            def select_api_responses(e):
                # Select API response types: json, xml
                for checkbox in mime_checkboxes.values():
                    checkbox.setSelected(False)  # Clear all first
                api_types = ["json", "xml"]
                for mime_type in api_types:
                    if mime_type in mime_checkboxes:
                        mime_checkboxes[mime_type].setSelected(True)
            
            select_all_btn.addActionListener(select_all_mime)
            select_none_btn.addActionListener(select_none_mime)
            assets_btn.addActionListener(select_static_assets)
            api_btn.addActionListener(select_api_responses)
            
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.fill = GridBagConstraints.HORIZONTAL
            sitemap_panel.add(mime_container, gbc)
            
            # Auto-update checkbox
            gbc.gridx = 0
            gbc.gridy = 6
            gbc.gridwidth = 2
            auto_update_checkbox = JCheckBox("Auto-update when sitemap changes", sitemap_config.get("auto_update", False))
            sitemap_panel.add(auto_update_checkbox, gbc)
            
            # Monitoring frequency setting
            gbc.gridx = 0
            gbc.gridy = 7
            gbc.gridwidth = 1
            gbc.weightx = 0.0  # Label doesn't expand
            gbc.fill = GridBagConstraints.NONE
            sitemap_panel.add(JLabel("Monitoring Frequency:"), gbc)
            
            frequency_options = ["Fast (5 seconds)", "Normal (10 seconds)", "Slow (30 seconds)"]
            current_frequency = sitemap_config.get("monitor_frequency", 5)  # Default to 5 seconds
            if current_frequency <= 5:
                selected_freq = 0
            elif current_frequency <= 10:
                selected_freq = 1
            else:
                selected_freq = 2
                
            frequency_combo = JComboBox(frequency_options)
            frequency_combo.setSelectedIndex(selected_freq)
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            gbc.fill = GridBagConstraints.HORIZONTAL
            sitemap_panel.add(frequency_combo, gbc)
            
            # Instructions
            # gbc.gridy = 8
            # gbc.gridwidth = 2
            # instructions = JLabel("Wildcards: */pattern/* matches any path containing 'pattern'. /pattern/* matches paths starting with '/pattern/'. Fast monitoring uses more CPU but detects changes quicker")
            # sitemap_panel.add(instructions, gbc)
            
            config_tabs.addTab("Sitemap", sitemap_panel)
            
            # === PROJECT SETTINGS TAB ===
            project_panel = JPanel(GridBagLayout())
            gbc = GridBagConstraints()
            gbc.insets = Insets(8, 8, 8, 8)  # Increased spacing
            gbc.anchor = GridBagConstraints.WEST
            gbc.weightx = 1.0  # Allow horizontal expansion
            gbc.weighty = 0.0  # No vertical expansion initially
            
            # Title
            gbc.gridx = 0
            gbc.gridy = 0
            gbc.gridwidth = 2
            project_title = JLabel("Project Information")
            project_title.setFont(project_title.getFont().deriveFont(16.0))
            project_panel.add(project_title, gbc)
            
            # Project details
            gbc.gridy = 1
            gbc.gridwidth = 1
            gbc.weightx = 0.0  # Label doesn't expand
            project_panel.add(JLabel("Current Project:"), gbc)
            
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            project_name_field = JTextField(self._current_project_name, 25)  # Made wider
            project_name_field.setEditable(False)
            project_panel.add(project_name_field, gbc)
            
            gbc.gridx = 0
            gbc.gridy = 2
            gbc.weightx = 0.0  # Label doesn't expand
            project_panel.add(JLabel("Data File:"), gbc)
            
            gbc.gridx = 1
            gbc.weightx = 1.0  # Allow expansion
            data_file_field = JTextField(self._data_file_path, 40)  # Made wider
            data_file_field.setEditable(False)
            project_panel.add(data_file_field, gbc)
            
            # Statistics
            gbc.gridx = 0
            gbc.gridy = 3
            gbc.gridwidth = 2
            stats_text = "\nStatistics:\n"
            stats_text += "Watch List Paths: {}\n".format(len(data.get("watch_list_audit", [])))
            stats_text += "Vulnerabilities: {}\n".format(len(data.get("vulnerabilities", {})))
            stats_text += "Vulnerability Counter: {}\n".format(data.get("vuln_counter", 0))
            
            stats_label = JLabel(stats_text.replace("\n", " | "))
            stats_label.setFont(stats_label.getFont().deriveFont(10.0))
            project_panel.add(stats_label, gbc)
            
            config_tabs.addTab("Project", project_panel)
            
            # Add action listeners for sitemap buttons now that all form elements are created
            def update_sitemap_config(e):
                try:
                    dialog_status_label.setText(" ")  # Clear previous status
                    
                    selected_target = str(target_combo.getSelectedItem()) if target_combo.getSelectedItem() else ""
                    if not selected_target or selected_target == "No targets found":
                        dialog_status_label.setText("Please select a valid target")
                        return
                    
                    # Parse and validate extensions
                    extensions_text = extensions_field.getText().strip()
                    exclude_extensions = []
                    if extensions_text:
                        exclude_extensions = [ext.strip().lower() for ext in extensions_text.split(",") if ext.strip()]
                    
                    # Parse and validate patterns - preserve exact user input
                    patterns_text = exclude_area.getText().strip()
                    exclude_patterns = []
                    if patterns_text:
                        # Split by lines and preserve non-empty patterns exactly as entered
                        exclude_patterns = [pattern.strip() for pattern in patterns_text.split("\n") if pattern.strip()]
                    
                    # Parse and validate status codes
                    status_text = status_field.getText().strip()
                    exclude_status_codes = []
                    if status_text:
                        for code in status_text.split(","):
                            code = code.strip()
                            if code.isdigit():
                                exclude_status_codes.append(int(code))
                    
                    # Parse and validate MIME types from checkboxes
                    exclude_mime_types = []
                    for mime_type, checkbox in mime_checkboxes.items():
                        if checkbox.isSelected():
                            exclude_mime_types.append(mime_type)
                    
                    # Get monitoring frequency
                    freq_index = frequency_combo.getSelectedIndex()
                    if freq_index == 0:
                        monitor_frequency = 5  # Fast
                    elif freq_index == 1:
                        monitor_frequency = 10  # Normal
                    else:
                        monitor_frequency = 30  # Slow
                    
                    new_config = {
                        "target": selected_target,
                        "exclude_extensions": exclude_extensions,
                        "exclude_patterns": exclude_patterns,
                        "exclude_status_codes": exclude_status_codes,
                        "exclude_mime_types": exclude_mime_types,
                        "auto_update": auto_update_checkbox.isSelected(),
                        "monitor_frequency": monitor_frequency
                    }
                    
                    # Update sitemap config in memory
                    self._sitemap_config = new_config
                    
                    # Load current data and update settings
                    data = self._load_data_from_file()
                    if "settings" not in data:
                        data["settings"] = {}
                    
                    # Save the configuration exactly as entered
                    data["settings"]["sitemap_config"] = new_config
                    self._save_data_to_file(data)
                    
                    # Update cached data to stay in sync
                    self._data = data
                                        
                    # Handle auto-update monitoring
                    if new_config.get("auto_update", False):
                        self._start_sitemap_monitoring()
                        dialog_status_label.setText("Sitemap configuration updated successfully (auto-update enabled)")
                    else:
                        self._stop_sitemap_monitoring()
                        dialog_status_label.setText("Sitemap configuration updated successfully")
                    
                    # Verify the save worked by reloading
                    verify_data = self._load_data_from_file()
                    saved_config = verify_data.get("settings", {}).get("sitemap_config", {})
                    print("DEBUG: Verified saved patterns: {}".format(saved_config.get("exclude_patterns", [])))
                    
                except Exception as ex:
                    error_msg = "Error updating sitemap config: {}".format(str(ex))
                    print("ERROR: {}".format(error_msg))
                    import traceback
                    traceback.print_exc()
                    dialog_status_label.setText("{}".format(error_msg))
            
            def clear_sitemap_config(e):
                try:
                    dialog_status_label.setText(" ")  # Clear previous status
                    
                    # Clear sitemap config
                    self._sitemap_config = None
                    self._stop_sitemap_monitoring()
                    
                    # Update data file
                    data = self._load_data_from_file()
                    if "settings" in data and "sitemap_config" in data["settings"]:
                        del data["settings"]["sitemap_config"]
                    self._save_data_to_file(data)
                    
                    # Update cached data to stay in sync
                    self._data = data
                    
                    # Reset form fields
                    target_combo.setSelectedIndex(0)
                    extensions_field.setText("js,gif,jpg,css,svg,png,woff,pdf")
                    exclude_area.setText("*/admin/login/*\n*/logout\n*/static/*")
                    status_field.setText("101,404,500")
                    auto_update_checkbox.setSelected(False)
                    frequency_combo.setSelectedIndex(0)  # Reset to Fast
                    
                    dialog_status_label.setText("Sitemap configuration cleared")
                    
                except Exception as ex:
                    error_msg = "Error clearing sitemap config: {}".format(str(ex))
                    print("ERROR: {}".format(error_msg))
                    dialog_status_label.setText("{}".format(error_msg))
            
            def fetch_from_sitemap(e):
                try:
                    dialog_status_label.setText(" ")  # Clear previous status
                    
                    # Check if sitemap config exists
                    if not self._sitemap_config:
                        dialog_status_label.setText("No sitemap configuration found. Please update configuration first.")
                        return
                    
                    dialog_status_label.setText("Fetching data from sitemap...")
                    
                    # Extract sitemap data using current configuration
                    sitemap_data = self._extract_sitemap_data(self._sitemap_config)
                    if not sitemap_data:
                        dialog_status_label.setText("No sitemap data found for target")
                        return
                    
                    # Filter endpoints using current configuration
                    filtered_endpoints = self._filter_sitemap_endpoints(sitemap_data, self._sitemap_config)
                    if not filtered_endpoints:
                        dialog_status_label.setText("No endpoints found after filtering")
                        return
                    
                    # Add new endpoints to watchlist
                    imported_count = self._add_endpoints_to_watchlist(filtered_endpoints)
                    
                    if imported_count > 0:
                        dialog_status_label.setText("Successfully imported {} new endpoints from sitemap".format(imported_count))
                    else:
                        dialog_status_label.setText("No new endpoints found - all sitemap URLs already in watch list")
                    
                except Exception as ex:
                    error_msg = "Error fetching from sitemap: {}".format(str(ex))
                    print("ERROR: {}".format(error_msg))
                    import traceback
                    traceback.print_exc()
                    dialog_status_label.setText("{}".format(error_msg))
            
            # Attach action listeners to sitemap buttons
            update_sitemap_btn.addActionListener(update_sitemap_config)
            clear_sitemap_btn.addActionListener(clear_sitemap_config)
            fetch_sitemap_btn.addActionListener(fetch_from_sitemap)
            
            main_panel.add(config_tabs, BorderLayout.CENTER)
            
            # Bottom panel with status label and buttons
            bottom_panel = JPanel(BorderLayout())
            bottom_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))  # Add padding
            
            # Add status label at the bottom for in-dialog feedback
            status_panel = JPanel()
            dialog_status_label = JLabel(" ")  # Empty initially
            dialog_status_label.setFont(dialog_status_label.getFont().deriveFont(12.0))
            status_panel.add(dialog_status_label)
            bottom_panel.add(status_panel, BorderLayout.NORTH)
            
            # Button panel
            button_panel = JPanel()
            
            # Apply Watch List Settings button
            apply_btn = JButton("Apply Watch List Settings")
            def apply_settings(e):
                try:
                    dialog_status_label.setText(" ")  # Clear previous status
                    
                    # Update auto-audit settings
                    self._auto_audit_repeater_enabled = auto_audit_repeater_checkbox.isSelected()
                    self._auto_audit_scanner_enabled = auto_audit_scanner_checkbox.isSelected()
                    
                    # Update table view setting
                    old_show_full_urls = self._show_full_urls_in_table
                    self._show_full_urls_in_table = show_full_urls_checkbox.isSelected()
                    
                    # Save settings to data file
                    data = self._load_data_from_file()
                    if "settings" not in data:
                        data["settings"] = {}
                    
                    data["settings"]["auto_audit_repeater_enabled"] = self._auto_audit_repeater_enabled
                    data["settings"]["auto_audit_scanner_enabled"] = self._auto_audit_scanner_enabled
                    data["settings"]["show_full_urls_in_table"] = self._show_full_urls_in_table
                    
                    self._save_data_to_file(data)
                    
                    # Update cached data to stay in sync
                    self._data = data
                    
                    # Refresh table display if the setting changed
                    if old_show_full_urls != self._show_full_urls_in_table:
                        self._refresh_table_display()
                    
                    dialog_status_label.setText("Watch list settings applied successfully")
                    
                except Exception as ex:
                    error_msg = "Error applying settings: {}".format(str(ex))
                    print("ERROR: {}".format(error_msg))
                    dialog_status_label.setText("{}".format(error_msg))
            
            apply_btn.addActionListener(apply_settings)
            
            # Import New Sitemap Config button (will be moved to sitemap tab)
            import_btn = JButton("Import New Sitemap Config")
            def import_new_sitemap(e):
                try:
                    dialog.dispose()
                    # Call the sitemap import dialog
                    self._import_from_sitemap(None)
                    
                except Exception as ex:
                    print("Error launching sitemap import: {}".format(str(ex)))
            
            import_btn.addActionListener(import_new_sitemap)
            
            # Close button (will be used in all tabs)
            close_btn = JButton("Close")
            close_btn.addActionListener(lambda e: dialog.dispose())
            
            # Create tab-specific button panels
            from javax.swing import JPanel
            from java.awt import CardLayout
            
            # Button container with CardLayout to switch between different button sets
            button_container = JPanel(CardLayout())
            
            # Watch List tab buttons
            watchlist_button_panel = JPanel()
            watchlist_button_panel.add(apply_btn)
            watchlist_button_panel.add(JButton("Close", actionPerformed=lambda e: dialog.dispose()))
            button_container.add(watchlist_button_panel, "watchlist")
            
            # Sitemap tab buttons  
            sitemap_button_panel = JPanel()
            sitemap_button_panel.add(update_sitemap_btn)
            sitemap_button_panel.add(clear_sitemap_btn)
            sitemap_button_panel.add(fetch_sitemap_btn)
            sitemap_button_panel.add(import_btn)
            sitemap_button_panel.add(JButton("Close", actionPerformed=lambda e: dialog.dispose()))
            button_container.add(sitemap_button_panel, "sitemap")
            
            # Project tab buttons
            project_button_panel = JPanel()
            project_button_panel.add(JButton("Close", actionPerformed=lambda e: dialog.dispose()))
            button_container.add(project_button_panel, "project")
            
            # Add tab change listener to switch button panels
            from javax.swing.event import ChangeListener
            class TabChangeListener(ChangeListener):
                def stateChanged(self, e):
                    selected_index = config_tabs.getSelectedIndex()
                    card_layout = button_container.getLayout()
                    if selected_index == 0:  # Watch List tab
                        card_layout.show(button_container, "watchlist")
                    elif selected_index == 1:  # Sitemap tab
                        card_layout.show(button_container, "sitemap")
                    elif selected_index == 2:  # Project tab
                        card_layout.show(button_container, "project")
            
            config_tabs.addChangeListener(TabChangeListener())
            
            # Set initial button panel (Watch List tab)
            card_layout = button_container.getLayout()
            card_layout.show(button_container, "watchlist")
            
            # Add button container to bottom panel
            bottom_panel.add(button_container, BorderLayout.SOUTH)
            
            # Add bottom panel to main panel
            main_panel.add(bottom_panel, BorderLayout.SOUTH)
            
            dialog.add(main_panel)
            dialog.setVisible(True)
            
        except Exception as e:
            print("Error showing configuration dialog: {}".format(str(e)))
            self._show_status_feedback("Error opening configuration: {}".format(str(e)))
    
    def _on_audit_status_changed(self, event):
        """Handle changes to audit status in the table"""
        try:
            # Don't save if we're currently updating the GUI (prevents overwriting during project switches)
            if hasattr(self, '_is_updating_gui') and self._is_updating_gui:
                return
            
            # Save the updated data
            self._save_watch_list_data()
            
            # Update status using the centralized method
            self._update_audit_status_display()
            
        except Exception as e:
            print("Error saving audit status: {}".format(str(e)))
    
    def _add_single_path(self, event):
        """Add a single path via dialog"""
        try:
            # Get path from user
            path = JOptionPane.showInputDialog(
                None,
                "Enter path/URL to add to watch list:",
                "Add Path",
                JOptionPane.PLAIN_MESSAGE
            )
            
            if not path or not path.strip():
                return
            
            path = path.strip()
            
            # Validate and convert path if needed
            validated_paths = self._validate_and_convert_paths([path])
            
            if not validated_paths:
                # User cancelled or validation failed
                return
            
            final_path = validated_paths[0]
            
            # Check for duplicates in table and internal data
            if hasattr(self, '_watch_table_model'):
                display_path = self._get_display_url(final_path)
                
                # Check table for display path duplicates
                for row in range(self._watch_table_model.getRowCount()):
                    if self._watch_table_model.getValueAt(row, 1) == display_path:  # Column 1 is now path/URL
                        self._show_status_feedback("Path already exists in watch list")
                        return
                
                # Also check internal data for full URL duplicates
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict) and item.get('path', '') == final_path:
                            self._show_status_feedback("Path already exists in watch list")
                            return
                
                # Ensure internal data structure exists
                if not hasattr(self, '_data') or 'watch_list_audit' not in self._data:
                    self._data = {'watch_list_audit': []}
                
                # Add to table with row number as first column
                row_number = self._watch_table_model.getRowCount() + 1
                row_data = [str(row_number), display_path, False, False, "Never", "", False]  # [#, Path/URL, Manual Audited, Scanned, Last Audit, Note, Highlight]
                self._watch_table_model.addRow(row_data)
                
                # CRITICAL FIX: Also add to internal data structure with full URL
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                audit_item = {
                    'path': final_path,  # Store full URL in internal data
                    'manual_audited': False,
                    'scanned': False,
                    'last_audit': 'Never',
                    'note': '',
                    'highlight': False,
                    'added': current_time,
                    'source': 'manual_add'
                }
                self._data['watch_list_audit'].append(audit_item)
                print("Added single path to both table and internal data: {}".format(final_path))
                
                # Sync to text area
                self._sync_table_to_text()
                
                # Save data
                self._save_watch_list_data()
                
                # Update original data for search filtering
                self._store_original_watch_data()
                
                # Update status
                total_paths = self._watch_table_model.getRowCount()
                self._status_label.setText("Ready - {} paths in watch list".format(total_paths))
                
                # Update progress display
                self._update_audit_status_display()
                
                self._show_status_feedback("Path added successfully")
            
        except Exception as e:
            self._show_status_feedback("Error adding path: {}".format(str(e)))
            print("Add path error: {}".format(str(e)))
    
    def _remove_selected_path(self, event):
        """Remove the selected path from the table"""
        try:
            if not hasattr(self, '_watch_table'):
                return
                
            selected_row = self._watch_table.getSelectedRow()
            if selected_row == -1:
                self._show_status_feedback("Please select a path to remove")
                return
            
            # Get path for confirmation
            path = self._watch_table_model.getValueAt(selected_row, 1)  # Column 1 is now path/URL
            
            # Confirm removal
            result = JOptionPane.showConfirmDialog(
                None,
                "Remove path: {}?".format(path),
                "Confirm Removal",
                JOptionPane.YES_NO_OPTION
            )
            
            if result == JOptionPane.YES_OPTION:
                self._watch_table_model.removeRow(selected_row)
                
                # Update row numbers after deletion
                self._update_row_numbers()
                
                # Sync to text area
                self._sync_table_to_text()
                
                # Save data
                self._save_watch_list_data()
                
                # Update original data for search filtering
                self._store_original_watch_data()
                
                # Update status
                total_paths = self._watch_table_model.getRowCount()
                self._status_label.setText("Ready - {} paths in watch list".format(total_paths))
                
                # Update progress display
                self._update_audit_status_display()
                
                self._show_status_feedback("Path removed successfully")
            
        except Exception as e:
            self._show_status_feedback("Error removing path: {}".format(str(e)))
            print("Remove path error: {}".format(str(e)))
    
    def _edit_note_for_row(self, row_index):
        """Edit the note for a specific row in the watch list table"""
        try:
            if not hasattr(self, '_watch_table_model') or row_index < 0 or row_index >= self._watch_table_model.getRowCount():
                return
                
            # Get current note
            current_note = ""
            if self._watch_table_model.getColumnCount() > 5:  # Note column is now 5
                current_note = self._watch_table_model.getValueAt(row_index, 5) or ""  # Column 5 is now note
            
            # Get the path for context
            path = self._watch_table_model.getValueAt(row_index, 0)
            
            # Show input dialog for note
            from javax.swing import JOptionPane, JScrollPane, JTextArea
            from java.awt import Dimension
            
            # Create a text area for multi-line notes
            text_area = JTextArea(current_note, 5, 40)
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            scroll_pane = JScrollPane(text_area)
            scroll_pane.setPreferredSize(Dimension(400, 120))
            
            result = JOptionPane.showConfirmDialog(
                None,
                scroll_pane,
                "Edit Note for: {}".format(path),
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
            )
            
            if result == JOptionPane.OK_OPTION:
                new_note = text_area.getText().strip()
                
                # Update the table model
                self._watch_table_model.setValueAt(new_note, row_index, 5)  # Column 5 is now note
                
                # Save the updated data
                self._save_watch_list_data()
                
                # Update original data for search filtering
                self._store_original_watch_data()
                
                self._show_status_feedback("Note updated for {}".format(path))
                
        except Exception as e:
            self._show_status_feedback("Error editing note: {}".format(str(e)))
            print("Edit note error: {}".format(str(e)))
    
    def _edit_note_for_selected(self, event):
        """Edit note for the currently selected row (button handler)"""
        try:
            if not hasattr(self, '_watch_table'):
                self._show_status_feedback("Table not available")
                return
                
            selected_row = self._watch_table.getSelectedRow()
            if selected_row == -1:
                self._show_status_feedback("Please select a path to edit its note")
                return
            
            self._edit_note_for_row(selected_row)
            
        except Exception as e:
            self._show_status_feedback("Error editing note: {}".format(str(e)))
            print("Edit note button error: {}".format(str(e)))
    
    def _mark_all_audited(self, event):
        """Mark all paths as audited"""
        try:
            if not hasattr(self, '_watch_table_model') or self._watch_table_model.getRowCount() == 0:
                self._show_status_feedback("No paths to mark")
                return
            
            # Confirm action
            result = JOptionPane.showConfirmDialog(
                None,
                "Mark all {} paths as audited?".format(self._watch_table_model.getRowCount()),
                "Confirm Mark All",
                JOptionPane.YES_NO_OPTION
            )
            
            if result == JOptionPane.YES_OPTION:
                # Mark all as audited
                for row in range(self._watch_table_model.getRowCount()):
                    self._watch_table_model.setValueAt(True, row, 2)  # Manual audited column is now 2
                
                # Save data
                self._save_watch_list_data()
                
                # Update status
                total_paths = self._watch_table_model.getRowCount()
                self._status_label.setText("Ready - {} paths ({} audited, 0 pending)".format(total_paths, total_paths))
                
                self._show_status_feedback("All paths marked as audited")
            
        except Exception as e:
            self._show_status_feedback("Error marking paths: {}".format(str(e)))
            print("Mark all error: {}".format(str(e)))
    
    def _clear_all_from_table(self, event):
        """Clear all paths from table view"""
        try:
            if not hasattr(self, '_watch_table_model') or self._watch_table_model.getRowCount() == 0:
                self._show_status_feedback("Watch list is already empty")
                return
            
            # Confirm clearing
            result = JOptionPane.showConfirmDialog(
                None,
                "Clear all {} paths from watch list?".format(self._watch_table_model.getRowCount()),
                "Confirm Clear All",
                JOptionPane.YES_NO_OPTION
            )
            
            if result == JOptionPane.YES_OPTION:
                # Clear table
                self._watch_table_model.setRowCount(0)
                
                # Clear text area
                if hasattr(self, '_path_textarea'):
                    self._path_textarea.setText("")
                
                # Clear internal data directly (don't use _save_watch_list_data which reads from table)
                if hasattr(self, '_data'):
                    self._data['watch_list_audit'] = []
                    self._save_data_to_file(self._data)
                
                # Update status
                self._status_label.setText("Ready - 0 paths in watch list")
                
                # Update progress display
                self._update_audit_status_display()
                
                self._show_status_feedback("Watch list cleared")
            
        except Exception as e:
            self._show_status_feedback("Error clearing paths: {}".format(str(e)))
            print("Clear error: {}".format(str(e)))
    
    def _filter_watch_table(self):
        """Filter watch list table based on search text"""
        try:
            if not hasattr(self, '_watch_search_field') or not hasattr(self, '_watch_table_model'):
                return
            
            search_text = self._watch_search_field.getText().lower().strip()
            
            # If search is empty, restore original data
            if not search_text:
                self._restore_original_watch_data()
                return
            
            # Store original data if not already stored
            if not hasattr(self, '_original_watch_data') or not self._original_watch_data:
                self._store_original_watch_data()
            
            # Clear current table
            self._watch_table_model.setRowCount(0)
            
            # Filter and add matching rows
            row_number = 1
            for row_data in self._original_watch_data:
                # Check if search text matches Path/URL (index 1) or Note (index 5)
                path_url = str(row_data[1]).lower() if row_data[1] else ""
                note = str(row_data[5]).lower() if row_data[5] else ""
                
                if search_text in path_url or search_text in note:
                    # Update row number and add to table
                    filtered_row = row_data[:]  # Copy the row
                    filtered_row[0] = str(row_number)  # Update row number
                    self._watch_table_model.addRow(filtered_row)
                    row_number += 1
            
            # Update status
            total_rows = len(self._original_watch_data)
            filtered_rows = self._watch_table_model.getRowCount()
            self._status_label.setText("Showing {} of {} paths (filtered)".format(filtered_rows, total_rows))
            
        except Exception as e:
            print("Error filtering watch table: {}".format(str(e)))
    
    def _store_original_watch_data(self):
        """Store current table data for filtering"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return
            
            self._original_watch_data = []
            for row in range(self._watch_table_model.getRowCount()):
                row_data = []
                for col in range(self._watch_table_model.getColumnCount()):
                    row_data.append(self._watch_table_model.getValueAt(row, col))
                self._original_watch_data.append(row_data)
                
        except Exception as e:
            print("Error storing original watch data: {}".format(str(e)))
    
    def _restore_original_watch_data(self):
        """Restore original table data (remove filter)"""
        try:
            if not hasattr(self, '_original_watch_data') or not hasattr(self, '_watch_table_model'):
                return
            
            # Clear current table
            self._watch_table_model.setRowCount(0)
            
            # Restore original data
            for row_data in self._original_watch_data:
                self._watch_table_model.addRow(row_data)
            
            # Update status
            total_rows = len(self._original_watch_data)
            self._status_label.setText("Ready - {} paths in watch list".format(total_rows))
            
        except Exception as e:
            print("Error restoring original watch data: {}".format(str(e)))
    
    def _clear_watch_search(self, event):
        """Clear search field and restore full table"""
        try:
            if hasattr(self, '_watch_search_field'):
                self._watch_search_field.setText("")
            # The document listener will automatically trigger _filter_watch_table()
            
        except Exception as e:
            print("Error clearing watch search: {}".format(str(e)))
    
    def _filter_vuln_table(self):
        """Filter vulnerability table based on search text"""
        try:
            if not hasattr(self, '_vuln_search_field') or not hasattr(self, '_vuln_table_model'):
                return
            
            search_text = self._vuln_search_field.getText().lower().strip()
            
            # If search is empty, restore original data
            if not search_text:
                self._restore_original_vuln_data()
                return
            
            # Store original data if not already stored
            if not hasattr(self, '_original_vuln_data') or not self._original_vuln_data:
                self._store_original_vuln_data()
            
            # Clear current table
            self._vuln_table_model.setRowCount(0)
            
            # Filter and add matching rows
            for row_data in self._original_vuln_data:
                # Check if search text matches URL (index 3) or Note (index 4)
                url = str(row_data[3]).lower() if row_data[3] else ""
                note = str(row_data[4]).lower() if row_data[4] else ""
                
                if search_text in url or search_text in note:
                    # Add to table
                    self._vuln_table_model.addRow(row_data)
            
            # Update stats
            total_rows = len(self._original_vuln_data)
            filtered_rows = self._vuln_table_model.getRowCount()
            self._vuln_stats_label.setText("Showing {} of {} vulnerabilities (filtered)".format(filtered_rows, total_rows))
            
        except Exception as e:
            print("Error filtering vulnerability table: {}".format(str(e)))
    
    def _store_original_vuln_data(self):
        """Store current vulnerability table data for filtering"""
        try:
            if not hasattr(self, '_vuln_table_model'):
                return
            
            self._original_vuln_data = []
            for row in range(self._vuln_table_model.getRowCount()):
                row_data = []
                for col in range(self._vuln_table_model.getColumnCount()):
                    row_data.append(self._vuln_table_model.getValueAt(row, col))
                self._original_vuln_data.append(row_data)
                
        except Exception as e:
            print("Error storing original vulnerability data: {}".format(str(e)))
    
    def _restore_original_vuln_data(self):
        """Restore original vulnerability table data (remove filter)"""
        try:
            if not hasattr(self, '_original_vuln_data') or not hasattr(self, '_vuln_table_model'):
                return
            
            # Clear current table
            self._vuln_table_model.setRowCount(0)
            
            # Restore original data
            for row_data in self._original_vuln_data:
                self._vuln_table_model.addRow(row_data)
            
            # Update stats
            total_rows = len(self._original_vuln_data)
            self._vuln_stats_label.setText("Total Vulnerabilities: {}".format(total_rows))
            
        except Exception as e:
            print("Error restoring original vulnerability data: {}".format(str(e)))
    
    def _clear_vuln_search(self, event):
        """Clear vulnerability search field and restore full table"""
        try:
            if hasattr(self, '_vuln_search_field'):
                self._vuln_search_field.setText("")
            # The document listener will automatically trigger _filter_vuln_table()
            
        except Exception as e:
            print("Error clearing vulnerability search: {}".format(str(e)))
    
    def _sync_table_to_text(self):
        """Sync table data to text area"""
        try:
            if hasattr(self, '_watch_table_model') and hasattr(self, '_path_textarea'):
                # Get the full URLs from the internal data structure
                full_urls = []
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict):
                            full_urls.append(item.get('path', ''))
                
                self._path_textarea.setText('\n'.join(full_urls))
            
        except Exception as e:
            print("Error syncing table to text: {}".format(str(e)))
    
    def _sync_text_to_table(self):
        """Sync text area data to table - optimized to prevent UI freezing"""
        try:
            if not hasattr(self, '_watch_table_model') or not hasattr(self, '_path_textarea'):
                return
                
            # Get paths from text area
            text_content = self._path_textarea.getText().strip()
            if not text_content:
                return
            
            new_paths = [line.strip() for line in text_content.split('\n') if line.strip()]
            
            # Set updating flag to prevent events during bulk operations
            self._is_updating_gui = True
            
            try:
                # Get existing data from internal structure
                existing_data = {}
                if hasattr(self, '_data') and 'watch_list_audit' in self._data:
                    for item in self._data['watch_list_audit']:
                        if isinstance(item, dict):
                            path = item.get('path', '')
                            manual_audited = item.get('manual_audited', False)
                            scanned = item.get('scanned', False)
                            last_audit = item.get('last_audit', 'Never')
                            note = item.get('note', '')
                            highlight = item.get('highlight', False)
                            existing_data[path] = (manual_audited, scanned, last_audit, note, highlight)
                
                # Clear table efficiently
                self._watch_table_model.setRowCount(0)
                
                # Clear internal data
                if hasattr(self, '_data'):
                    self._data['watch_list_audit'] = []
                
                # Re-add paths in batches to prevent UI freezing
                batch_size = 50
                for i in range(0, len(new_paths), batch_size):
                    batch = new_paths[i:i + batch_size]
                    
                    for j, path in enumerate(batch):
                        # Use display format for the table
                        display_path = self._get_display_url(path)
                        
                        if path in existing_data:
                            # Preserve existing data
                            manual_audited, scanned, last_audit, note, highlight = existing_data[path]
                        else:
                            # New path - DEFAULT VALUES: not audited, not scanned
                            manual_audited, scanned, last_audit, note, highlight = False, False, "Never", "", False
                        
                        # Table columns: [#, Path, Manual Audited, Scanned, Last Audit, Note, Highlight]
                        row_number = i + j + 1
                        row_data = [row_number, display_path, manual_audited, scanned, last_audit, note, highlight]
                        self._watch_table_model.addRow(row_data)
                        
                        # Add to internal data structure (full URL)
                        if hasattr(self, '_data'):
                            self._data['watch_list_audit'].append({
                                'path': path,  # Store full URL in internal data
                                'manual_audited': manual_audited,
                                'scanned': scanned,
                                'last_audit': last_audit,
                                'note': note,
                                'highlight': highlight
                            })
                    
                    # Yield to GUI thread between batches
                    if i + batch_size < len(new_paths):
                        SwingUtilities.invokeLater(lambda: None)
                        
            finally:
                # Always clear the updating flag
                self._is_updating_gui = False
            
        except Exception as e:
            print("Error syncing text to table: {}".format(str(e)))
            self._is_updating_gui = False
    
    def _save_watch_list_data(self):
        """Save watch list data including audit status"""
        try:
            # Don't save if we're currently updating the GUI (prevents overwriting during project switches)
            if hasattr(self, '_is_updating_gui') and self._is_updating_gui:
                print("Skipping watch list save during GUI update to prevent data corruption")
                return
                
            if not hasattr(self, '_current_project_name') or not self._current_project_name:
                print("No current project to save watch list data")
                return
            
            # Update audit status in existing internal data (preserving full URLs)
            if hasattr(self, '_watch_table_model') and hasattr(self, '_data') and 'watch_list_audit' in self._data:
                # Make sure we have the same number of rows in table and internal data
                table_rows = self._watch_table_model.getRowCount()
                internal_items = len(self._data['watch_list_audit'])
                
                if table_rows == internal_items:
                    # Update audit status for each item, preserving the full URL
                    for row in range(table_rows):
                        # CRITICAL FIX: Ensure we're getting the correct data types from table
                        manual_audited_raw = self._watch_table_model.getValueAt(row, 2)  # Manual audited column is now 2
                        scanned_raw = self._watch_table_model.getValueAt(row, 3)  # Scanned column is now 3
                        last_audit_raw = self._watch_table_model.getValueAt(row, 4)  # Last audit column is now 4
                        note_raw = self._watch_table_model.getValueAt(row, 5) if self._watch_table_model.getColumnCount() > 5 else ""  # Note column is now 5
                        highlight_raw = self._watch_table_model.getValueAt(row, 6) if self._watch_table_model.getColumnCount() > 6 else False  # Highlight column is now 6
                        
                        # Convert to proper data types to prevent corruption
                        manual_audited = bool(manual_audited_raw) if manual_audited_raw is not None else False
                        scanned = bool(scanned_raw) if scanned_raw is not None else False
                        last_audit = str(last_audit_raw) if last_audit_raw is not None else "Never"
                        note = str(note_raw) if note_raw is not None else ""
                        highlight = bool(highlight_raw) if highlight_raw is not None else False
                        
                        # Update only the audit status, keep the original full URL
                        if row < len(self._data['watch_list_audit']):
                            item = self._data['watch_list_audit'][row]
                            # CRITICAL: Only update the specific fields, never overwrite 'path'
                            item['manual_audited'] = manual_audited
                            item['scanned'] = scanned
                            item['last_audit'] = last_audit
                            item['note'] = note
                            item['highlight'] = highlight
                            # Ensure 'path' field is never corrupted by always preserving it as-is
                            if 'path' not in item or not item['path']:
                                print("WARNING: Missing path in item {}, skipping save to prevent corruption".format(row))
                                return
                        else:
                            print("WARNING: Row {} exceeds internal data length, skipping save".format(row))
                            return
                else:
                    print("Warning: Table rows ({}) and internal data ({}) count mismatch - skipping save to prevent data corruption".format(table_rows, internal_items))
                    return
                
                # Save to file using the correct method
                self._save_data_to_file(self._data)
                print("Updated audit status for {} watch list items (URLs preserved, data integrity maintained)".format(table_rows))
            
        except Exception as e:
            print("Error saving watch list data: {}".format(str(e)))
    
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Vuln tracker"
    
    def getUiComponent(self):
        """Return the component to be used as the contents of our tab"""
        return self._main_panel
    
    def createNewInstance(self, controller, editable):
        """Create a new instance of our custom message editor tab"""
        return CWEMessageEditorTab(self, controller, editable)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Process HTTP messages and highlight matching requests"""
        # Only process requests (not responses)
        if not messageIsRequest:
            return
        
        # Only process requests from tools we care about for performance
        # Proxy: for highlighting, Repeater/Scanner: for auto-audit
        relevant_tools = [
            self._callbacks.TOOL_PROXY,     # For highlighting new requests
            self._callbacks.TOOL_REPEATER,  # For auto-audit
            self._callbacks.TOOL_SCANNER    # For auto-audit
        ]
        
        if toolFlag not in relevant_tools:
            return  # Skip processing for other tools
        
        # Get the request details
        try:
            request = messageInfo.getRequest()
            if request is None:
                return
                
            request_info = self._helpers.analyzeRequest(messageInfo)
            url = request_info.getUrl()
            
            if url is None:
                return
                
            path = url.getPath()
            full_url = str(url)
            
            # Quick check: only proceed if we have watchlist data
            if not hasattr(self, '_data') or 'watch_list_audit' not in self._data or not self._data['watch_list_audit']:
                return
            
            # For proxy requests, do a fast preliminary check to avoid expensive matching
            if toolFlag == self._callbacks.TOOL_PROXY:
                # Quick hostname check - if the hostname doesn't match any watchlist item, skip
                from urlparse import urlparse
                try:
                    parsed_url = urlparse(full_url)
                    request_hostname = parsed_url.hostname
                    
                    # Quick check: see if any watchlist item contains this hostname
                    hostname_match_found = False
                    for item in self._data['watch_list_audit']:
                        watch_path = item.get('path', '') if isinstance(item, dict) else str(item)
                        if request_hostname and request_hostname in watch_path:
                            hostname_match_found = True
                            break
                    
                    if not hostname_match_found:
                        return  # Skip expensive matching for unrelated hosts
                        
                except:
                    pass  # If URL parsing fails, continue with normal processing
            
            # Check if this request matches any of our paths (with caching for Scanner)
            matches_watchlist = False
            if toolFlag == self._callbacks.TOOL_SCANNER:
                matches_watchlist = self._matches_watchlist_cached(path, full_url)
            else:
                matches_watchlist = self._matches_watchlist(path, full_url)
            
            if matches_watchlist:
                # Check if highlighting is enabled for matching paths (only for proxy requests)
                if toolFlag == self._callbacks.TOOL_PROXY:
                    if self._should_highlight_path(path, full_url):
                        messageInfo.setHighlight("red")
                        
                        # Get the note for this path and include it in the comment
                        note = self._get_note_for_path(path, full_url)
                        if note:
                            messageInfo.setComment("Vuln Tracker: {} | Note: {}".format(path, note))
                        else:
                            messageInfo.setComment("Vuln Tracker: {}".format(path))
                
                # Auto-mark as audited if request comes from Repeater
                if toolFlag == self._callbacks.TOOL_REPEATER and self._auto_audit_repeater_enabled:
                    # Only auto-mark if not already manually audited
                    if not self._is_already_manually_audited(path, full_url):
                        self._auto_mark_as_audited(path, full_url, "Repeater")
                
                # Auto-mark as audited if request comes from Scanner
                if toolFlag == self._callbacks.TOOL_SCANNER and self._auto_audit_scanner_enabled:
                    # Use throttled scanner processing to prevent performance issues
                    self._throttled_scanner_processing(path, full_url)
                
        except Exception as e:
            # Only log actual errors, not normal operation
            print("Error processing HTTP message: {}".format(str(e)))
    
    def _throttled_scanner_processing(self, path, full_url):
        """Throttled processing for Scanner requests to prevent performance issues"""
        try:
            current_time = time.time()
            
            # Create a cache key for this request (normalize to avoid duplicates)
            cache_key = "{}::{}".format(path, full_url.split('?')[0])  # Remove query params for cache key
            
            # Clear cache every 30 seconds to prevent memory buildup
            if current_time - self._last_cache_clear > 30:
                self._scanner_request_cache.clear()
                self._last_cache_clear = current_time
            
            # Check if we've already processed this request recently (within 5 seconds)
            if cache_key in self._scanner_request_cache:
                if current_time - self._scanner_request_cache[cache_key] < 5:
                    return  # Skip duplicate processing
            
            # Update cache with current time
            self._scanner_request_cache[cache_key] = current_time
            
            # Add to processing queue instead of immediate processing
            request_data = {
                'path': path,
                'full_url': full_url,
                'timestamp': current_time
            }
            
            self._scanner_processing_queue.append(request_data)
            
            # Process queue in batches every 3 seconds to reduce GUI updates
            if current_time - self._last_batch_process > 3:
                self._process_scanner_queue_batch()
                self._last_batch_process = current_time
                
        except Exception as e:
            print("Error in throttled scanner processing: {}".format(str(e)))
    
    def _process_scanner_queue_batch(self):
        """Process queued scanner requests in batches"""
        try:
            if not self._scanner_processing_queue:
                return
            
            # Take up to 10 items from queue to process at once
            batch_size = min(10, len(self._scanner_processing_queue))
            batch_to_process = self._scanner_processing_queue[:batch_size]
            self._scanner_processing_queue = self._scanner_processing_queue[batch_size:]
            
            marked_any = False
            
            # Process batch
            for request_data in batch_to_process:
                path = request_data['path']
                full_url = request_data['full_url']
                
                # Quick check if already scanned (with optimized lookup)
                if not self._is_already_scanned_optimized(path, full_url):
                    # Mark as scanned using optimized method
                    if self._auto_mark_as_audited_optimized(path, full_url, "Scanner"):
                        marked_any = True
            
            # Only update GUI and save if something changed
            if marked_any:
                # Defer GUI updates to prevent freezing
                SwingUtilities.invokeLater(lambda: self._deferred_update_after_scanner_batch())
                
        except Exception as e:
            print("Error processing scanner queue batch: {}".format(str(e)))
    
    def _deferred_update_after_scanner_batch(self):
        """Deferred GUI update after scanner batch processing"""
        try:
            # Save data (but limit frequency)
            current_time = time.time()
            if not hasattr(self, '_last_scanner_save') or current_time - self._last_scanner_save > 10:
                self._save_watch_list_data()
                self._last_scanner_save = current_time
            
            # Update status (throttled)
            if not hasattr(self, '_last_status_update') or current_time - self._last_status_update > 5:
                self._update_audit_status_display()
                self._last_status_update = current_time
                
        except Exception as e:
            print("Error in deferred scanner update: {}".format(str(e)))
    
    def _is_already_scanned_optimized(self, path, full_url):
        """Optimized check if path is already scanned (with caching)"""
        try:
            # Use cache to avoid repeated table lookups
            cache_key = "scanned_{}".format(path)
            current_time = time.time()
            
            # Initialize scan status cache if needed
            if not hasattr(self, '_scan_status_cache'):
                self._scan_status_cache = {}
            if not hasattr(self, '_scan_cache_time'):
                self._scan_cache_time = {}
            
            # Check cache first (cache valid for 30 seconds)
            if cache_key in self._scan_status_cache:
                if current_time - self._scan_cache_time.get(cache_key, 0) < 30:
                    return self._scan_status_cache[cache_key]
            
            # Cache miss - check table
            result = self._is_already_scanned(path, full_url)
            
            # Update cache
            self._scan_status_cache[cache_key] = result
            self._scan_cache_time[cache_key] = current_time
            
            return result
            
        except Exception as e:
            print("Error in optimized scan check: {}".format(str(e)))
            return False
    
    def _auto_mark_as_audited_optimized(self, path, full_url, source_tool="Scanner"):
        """Optimized version of auto-mark for scanner (batch-friendly)"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return False
            
            marked_any = False
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
            
            # Only scan table once, cache the matched rows
            for row in range(self._watch_table_model.getRowCount()):
                table_path = self._watch_table_model.getValueAt(row, 1)
                
                if self._is_match(table_path, path, full_url):
                    # Check if not already scanned
                    current_scanned = self._watch_table_model.getValueAt(row, 3)
                    if not current_scanned:
                        # Mark as scanned
                        self._watch_table_model.setValueAt(True, row, 3)
                        self._watch_table_model.setValueAt(current_time, row, 4)
                        marked_any = True
                        
                        # Update cache to reflect the change
                        cache_key = "scanned_{}".format(path)
                        if hasattr(self, '_scan_status_cache'):
                            self._scan_status_cache[cache_key] = True
                            self._scan_cache_time[cache_key] = time.time()
                        
                        break  # Only mark first match to avoid duplicates
            
            return marked_any
            
        except Exception as e:
            print("Error in optimized auto-mark: {}".format(str(e)))
            return False
    
    def _auto_mark_as_audited(self, path, full_url, source_tool="Repeater"):
        """Automatically mark matching paths as audited when accessed from specified tool"""
        try:
            print("DEBUG: _auto_mark_as_audited called - Path: {}, Full URL: {}, Tool: {}".format(path, full_url, source_tool))
            
            if not hasattr(self, '_watch_table_model'):
                print("DEBUG: No watch table model available")
                return
            
            # Find matching paths in the table and mark them as audited
            marked_count = 0
            table_row_count = self._watch_table_model.getRowCount()
            print("DEBUG: Checking {} rows in watch table".format(table_row_count))
            
            for row in range(table_row_count):
                table_path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                print("DEBUG: Comparing table path '{}' with request path '{}' and full URL '{}'".format(table_path, path, full_url))
                
                # Check if this table entry matches the current request
                is_match = self._is_match(table_path, path, full_url)
                print("DEBUG: Match result: {}".format(is_match))
                
                if is_match:
                    # Determine which column to update based on source tool
                    marked_this_path = False
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M")
                    
                    if source_tool == "Repeater":
                        # Check if not already manually audited
                        current_manual_audited = self._watch_table_model.getValueAt(row, 2)  # Manual audited column is now 2
                        if not current_manual_audited:
                            # Mark as manually audited (column 1)
                            self._watch_table_model.setValueAt(True, row, 2)  # Manual audited column is now 2
                            # Update last audit time (column 4)
                            self._watch_table_model.setValueAt(current_time, row, 4)  # Last audit column is now 4
                            marked_this_path = True
                            print("Auto-marked path as manually audited ({}): {}".format(source_tool, table_path))
                    
                    elif source_tool == "Scanner":
                        # Check if not already scanned
                        current_scanned = self._watch_table_model.getValueAt(row, 3)  # Scanned column is now 3
                        if not current_scanned:
                            # Mark as scanned (column 3)
                            self._watch_table_model.setValueAt(True, row, 3)  # Scanned column is now 3
                            # Update last audit time (column 4)
                            self._watch_table_model.setValueAt(current_time, row, 4)  # Last audit column is now 4
                            marked_this_path = True
                            print("Auto-marked path as scanned ({}): {}".format(source_tool, table_path))
                    
                    if marked_this_path:
                        marked_count += 1
            
            if marked_count > 0:
                # Save the updated audit data
                self._save_watch_list_data()
                
                # Update status display
                self._update_audit_status_display()
                
                # Show brief visual feedback
                self._show_auto_audit_feedback(marked_count, source_tool)
            
        except Exception as e:
            print("Error auto-marking as audited: {}".format(str(e)))
    
    def _update_audit_status_display(self):
        """Update the status label with current audit counts"""
        try:
            if hasattr(self, '_watch_table_model') and hasattr(self, '_status_label'):
                total_paths = self._watch_table_model.getRowCount()
                manual_audited_count = 0
                scanned_count = 0
                
                for row in range(total_paths):
                    if self._watch_table_model.getValueAt(row, 2):  # Manual Audited column is now 2
                        manual_audited_count += 1
                    if self._watch_table_model.getValueAt(row, 3):  # Scanned column is now 3
                        scanned_count += 1
                
                # Calculate how many paths have any kind of audit
                audited_paths = set()
                for row in range(total_paths):
                    if self._watch_table_model.getValueAt(row, 2) or self._watch_table_model.getValueAt(row, 3):  # Manual audited or scanned
                        audited_paths.add(row)
                
                audited_count = len(audited_paths)
                pending_count = total_paths - audited_count
                
                # Update status label
                self._status_label.setText("Ready - {} paths ({} manual, {} scanned, {} pending)".format(
                    total_paths, manual_audited_count, scanned_count, pending_count))
                
                # Update progress bar - SHOULD TRACK MANUAL AUDITS ONLY
                if hasattr(self, '_progress_bar') and hasattr(self, '_progress_details'):
                    if total_paths > 0:
                        # Progress bar tracks manual audits only (not scanned)
                        progress_percentage = int((manual_audited_count * 100) / total_paths)
                        self._progress_bar.setValue(progress_percentage)
                        self._progress_bar.setString("{}%".format(progress_percentage))
                        self._progress_details.setText("({}/{} manually audited)".format(manual_audited_count, total_paths))
                    else:
                        self._progress_bar.setValue(0)
                        self._progress_bar.setString("0%")
                        self._progress_details.setText("(0/0 manually audited)")
                
        except Exception as e:
            print("Error updating audit status display: {}".format(str(e)))
    
    def _show_auto_audit_feedback(self, count, source_tool="Repeater"):
        """Show brief feedback when paths are auto-marked as audited"""
        try:
            if hasattr(self, '_status_label'):
                original_text = self._status_label.getText()
                
                # Show temporary feedback
                feedback_text = "Auto-marked {} path{} as audited ({})".format(
                    count, "s" if count > 1 else "", source_tool)
                self._status_label.setText(feedback_text)
                
                # Restore original text after 3 seconds
                from javax.swing import Timer
                from java.awt.event import ActionListener
                
                class RestoreAction(ActionListener):
                    def actionPerformed(self, event):
                        if hasattr(self.extension_parent, '_status_label'):
                            self.extension_parent._update_audit_status_display()
                        event.getSource().stop()
                    
                    def __init__(self, extension_parent):
                        self.extension_parent = extension_parent
                
                timer = Timer(3000, RestoreAction(self))
                timer.start()
                
        except Exception as e:
            print("Error showing auto-audit feedback: {}".format(str(e)))
    
    def _should_highlight_path(self, path, full_url):
        """Check if this path should be highlighted based on highlight column setting"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return False
            
            # Check each row in the table to see if highlighting is enabled for matching paths
            for row in range(self._watch_table_model.getRowCount()):
                table_path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                highlight_enabled = self._watch_table_model.getValueAt(row, 6)  # Highlight column is now at position 6
                
                # Check if this table entry matches the current request and highlighting is enabled
                if highlight_enabled and self._is_match(table_path, path, full_url):
                    print("Highlighting enabled for path: {} (pattern: {})".format(path, table_path))
                    return True
            
            return False
            
        except Exception as e:
            print("Error checking highlight status: {}".format(str(e)))
            return False
    
    def _get_note_for_path(self, path, full_url):
        """Get the note for a matching path in the watch list"""
        try:
            if hasattr(self, '_watch_table_model'):
                for row in range(self._watch_table_model.getRowCount()):
                    table_path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                    if self._is_match(table_path, path, full_url):
                        note = self._watch_table_model.getValueAt(row, 5)  # Note column is now 5
                        return note if note else ""
            return ""
        except Exception as e:
            print("Error getting note for path: {}".format(str(e)))
            return ""
    
    def _matches_watchlist_cached(self, path, full_url):
        """Cached version of watchlist matching for Scanner performance"""
        try:
            # Create cache key (normalize URL to reduce cache misses)
            cache_key = "match_{}::{}".format(path, full_url.split('?')[0])  # Remove query params
            current_time = time.time()
            
            # Check cache first (cache valid for 60 seconds)
            if cache_key in self._watchlist_match_cache:
                if current_time - self._watchlist_cache_time.get(cache_key, 0) < 60:
                    return self._watchlist_match_cache[cache_key]
            
            # Cache miss - do actual matching
            result = self._matches_watchlist(path, full_url)
            
            # Update cache
            self._watchlist_match_cache[cache_key] = result
            self._watchlist_cache_time[cache_key] = current_time
            
            # Clean old cache entries every 100 lookups to prevent memory buildup
            if len(self._watchlist_match_cache) > 100:
                cutoff_time = current_time - 120  # Remove entries older than 2 minutes
                keys_to_remove = [k for k, t in self._watchlist_cache_time.items() if t < cutoff_time]
                for key in keys_to_remove:
                    self._watchlist_match_cache.pop(key, None)
                    self._watchlist_cache_time.pop(key, None)
            
            return result
            
        except Exception as e:
            print("Error in cached watchlist matching: {}".format(str(e)))
            return self._matches_watchlist(path, full_url)  # Fallback to non-cached
    
    def _matches_watchlist(self, path, full_url):
        """Check if the path/URL matches any item in our watch list"""
        # Check if _data exists
        if not hasattr(self, '_data'):
            return False
        
        if hasattr(self, '_data') and 'watch_list_audit' in self._data:
            watchlist_size = len(self._data['watch_list_audit'])
            
            if watchlist_size == 0:
                return False
            
            # For performance: if we have a large watchlist, do quick hostname filtering
            if watchlist_size > 10:
                # Extract hostname from full_url for quick filtering
                try:
                    from urlparse import urlparse
                    parsed_url = urlparse(full_url)
                    request_hostname = parsed_url.hostname
                    
                    # Quick hostname pre-filter
                    potential_matches = []
                    for item in self._data['watch_list_audit']:
                        watch_path = item.get('path', '') if isinstance(item, dict) else str(item)
                        if request_hostname and request_hostname in watch_path:
                            potential_matches.append(item)
                    
                    # If no hostname matches, skip expensive pattern matching
                    if not potential_matches:
                        return False
                    
                    # Only check the potential matches
                    items_to_check = potential_matches
                except:
                    # If hostname extraction fails, check all items
                    items_to_check = self._data['watch_list_audit']
            else:
                # Small watchlist - check everything
                items_to_check = self._data['watch_list_audit']
                
            for item in items_to_check:
                watch_path = item.get('path', '') if isinstance(item, dict) else str(item)
                
                if self._is_match(watch_path, path, full_url):
                    return True
                    
        else:
            return False
            
        return False
    
    def _is_already_scanned(self, path, full_url):
        """Check if the path/URL is already marked as scanned in the watch list"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return False
            
            for row in range(self._watch_table_model.getRowCount()):
                table_path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                
                # Check if this table entry matches the current request
                if self._is_match(table_path, path, full_url):
                    # Check if already scanned (column 3)
                    scanned = self._watch_table_model.getValueAt(row, 3)  # Scanned column is now 3
                    if scanned:
                        return True
            return False
        except Exception as e:
            print("Error checking if already scanned: {}".format(str(e)))
            return False
    
    def _is_already_manually_audited(self, path, full_url):
        """Check if the path/URL is already marked as manually audited in the watch list"""
        try:
            if not hasattr(self, '_watch_table_model'):
                return False
            
            total_rows = self._watch_table_model.getRowCount()
            
            for row in range(total_rows):
                table_path = self._watch_table_model.getValueAt(row, 1)  # Column 1 is now path/URL
                manually_audited = self._watch_table_model.getValueAt(row, 2)  # Manual audited column is now 2
                
                # Check if this table entry matches the current request
                if self._is_match(table_path, path, full_url):
                    if manually_audited:
                        return True
                    else:
                        return False
            
            return False
        except Exception as e:
            print("Error checking if already manually audited: {}".format(str(e)))
            return False
    
    def _is_match(self, pattern, path, full_url):
        """Check if a pattern matches the given path or URL"""
        try:
            # Normalize URLs by removing default ports for comparison
            def normalize_url(url):
                """Remove default ports from URLs for better matching"""
                import re
                # Remove :443 from HTTPS URLs and :80 from HTTP URLs
                normalized = re.sub(r':443(/|$)', r'\1', url)  # Remove :443 for HTTPS
                normalized = re.sub(r':80(/|$)', r'\1', normalized)  # Remove :80 for HTTP
                return normalized
            
            normalized_pattern = normalize_url(pattern)
            normalized_full_url = normalize_url(full_url)
            
            # Method 1: Exact URL match (highest priority)
            if normalized_pattern.lower() == normalized_full_url.lower():
                return True
            
            # Method 2: Wildcard/regex pattern matching
            if '*' in normalized_pattern:
                regex_pattern = normalized_pattern.replace('*', '.*')
                regex_pattern = '^' + regex_pattern + '$'
                
                url_match = re.match(regex_pattern, normalized_full_url, re.IGNORECASE)
                if url_match:
                    return True
            
            # Method 3: Path-only matching (extract path from both pattern and URL)
            try:
                from urlparse import urlparse
                
                # Extract path from pattern (if it's a full URL)
                if normalized_pattern.startswith(('http://', 'https://')):
                    pattern_parsed = urlparse(normalized_pattern)
                    pattern_path = pattern_parsed.path if pattern_parsed.path else '/'
                else:
                    pattern_path = normalized_pattern
                
                # Extract path from full URL
                url_parsed = urlparse(normalized_full_url)
                url_path = url_parsed.path if url_parsed.path else '/'
                
                # Special handling for root path - only match exact root
                if pattern_path == '/' and url_path == '/':
                    return True
                elif pattern_path == '/' and url_path != '/':
                    # Continue to other matching methods, don't return False yet
                    pass
                
                # Exact path match (for non-root paths)
                elif pattern_path.lower() == url_path.lower():
                    return True
                
                # Path pattern matching (if pattern has wildcards)
                if '*' in pattern_path:
                    path_regex = pattern_path.replace('*', '.*')
                    path_regex = '^' + path_regex + '$'
                    if re.match(path_regex, url_path, re.IGNORECASE):
                        return True
                
                # Directory-based matching (only for specific directory patterns, not root)
                # Pattern must end with / and be more specific than just root "/"
                if (pattern_path.endswith('/') and 
                    len(pattern_path) > 1 and  # Not just root "/"
                    pattern_path != '/' and    # Explicitly exclude root
                    url_path.lower().startswith(pattern_path.lower())):
                    return True
                    
            except ImportError:
                # Fallback if urlparse is not available
                pass
            
            return False
                                
        except Exception as e:
            print("Error matching pattern '{}': {}".format(pattern, str(e)))
        
        return False
    
    def createMenuItems(self, invocation):
        """Create context menu items"""
        menu_items = []
        
        # Only show menu for requests in the repeater, target site map or proxy history
        context = invocation.getInvocationContext()
        if context in [invocation.CONTEXT_TARGET_SITE_MAP_TABLE, 
                      invocation.CONTEXT_PROXY_HISTORY,
                      invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
                      invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            
            # Get selected messages
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                # Add path to watch list
                menu_item1 = JMenuItem("Add path to watch list", 
                                    actionPerformed=lambda event: self._add_path_from_context(messages[0]))
                menu_items.append(menu_item1)
                
                # Mark as vulnerable - create submenu for CWE types
                cwe_menu = JMenuItem("Mark as Vulnerable")
                menu_items.append(cwe_menu)
                
                # Add individual CWE options
                for cwe_code, description in self._cwe_types.items():
                    cwe_item = JMenuItem("{} - {}".format(cwe_code, description),
                                       actionPerformed=lambda event, code=cwe_code, desc=description: 
                                       self._mark_vulnerable(messages[0], code, desc))
                    menu_items.append(cwe_item)
        
        return menu_items
    
    def _add_path_from_context(self, message):
        """Add a path to the watch list from context menu"""
        try:
            request_info = self._helpers.analyzeRequest(message)
            url = request_info.getUrl()
            full_url = str(url)  # Get the full URL instead of just the path
            
            # Use SwingUtilities to ensure UI updates happen on Event Dispatch Thread
            def update_ui():
                try:
                    # Add to text area (use full URL now)
                    current_text = self._path_textarea.getText()
                    if current_text:
                        new_text = current_text + '\n' + full_url
                    else:
                        new_text = full_url
                    
                    self._path_textarea.setText(new_text)
                    self._update_paths(None)
                    
                    # Visual feedback instead of dialog
                    self._highlight_tab_success()
                    
                except Exception as e:
                    print("Error in UI update: {}".format(str(e)))
            
            SwingUtilities.invokeLater(update_ui)
            
        except Exception as e:
            print("Error adding path from context: {}".format(str(e)))
    
    def _mark_vulnerable(self, message, cwe_code, description):
        """Mark a request as vulnerable with specified CWE"""
        try:
            request_info = self._helpers.analyzeRequest(message)
            url = request_info.getUrl()
            method = request_info.getMethod()
            
            # Create hash for this request (for grouping purposes - ignoring query params)
            request_hash = self._create_request_hash(url, method)
            
            # Check if this exact CWE already exists for this request
            with self._vuln_lock:
                # Check for duplicate CWE on same request
                for vuln_id, vuln in self._vulnerabilities.items():
                    if (vuln['request_hash'] == request_hash and 
                        vuln['cwe'] == cwe_code):
                        # Show message that this CWE already exists
                        SwingUtilities.invokeLater(lambda: JOptionPane.showMessageDialog(
                            self._main_panel,
                            "This request is already marked as vulnerable to {}\n{} {}".format(
                                cwe_code, method, url),
                            "Duplicate Vulnerability",
                            JOptionPane.WARNING_MESSAGE
                        ))
                        return
                
                # Create unique vulnerability ID using internal counter
                self._vuln_counter += 1
                vuln_id = self._vuln_counter
                
                # Store vulnerability with unique ID
                self._vulnerabilities[vuln_id] = {
                    'cwe': cwe_code,
                    'description': description,
                    'url': str(url),
                    'method': method,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'request_hash': request_hash,
                    'message': message  # Store reference for later use
                }
                
                # Save to JSON file
                self._save_vulnerability_to_database(vuln_id, self._vulnerabilities[vuln_id])
            
            # Update vulnerability table
            self._refresh_vulnerability_table()
            
            # Switch to vulnerabilities tab
            self._tabbed_pane.setSelectedIndex(1)
            
            # Count total vulnerabilities for this request
            vuln_count = sum(1 for v in self._vulnerabilities.values() if v['request_hash'] == request_hash)
            
            # Visual feedback instead of dialog
            self._highlight_tab_success()
            
            print("Marked vulnerability: {} {} - {} {} (Total for this request: {})".format(
                method, url, cwe_code, description, vuln_count))
            
        except Exception as e:
            print("Error marking vulnerability: {}".format(str(e)))
    
    def _get_note_for_url(self, url_str):
        """Get the note for a given URL from the watch list"""
        try:
            if not hasattr(self, '_data') or 'watch_list_audit' not in self._data:
                return ""
            
            # Try to find exact URL match first
            for item in self._data['watch_list_audit']:
                if isinstance(item, dict) and item.get('path') == url_str:
                    return item.get('note', '')
            
            # If no exact match, try path matching (for backward compatibility)
            try:
                # Simple path extraction without urlparse
                if '://' in url_str:
                    # Find the path part after the domain
                    parts = url_str.split('/', 3)
                    if len(parts) > 3:
                        path = '/' + parts[3]
                    else:
                        path = '/'
                else:
                    path = url_str  # Already a path
                    
                for item in self._data['watch_list_audit']:
                    if isinstance(item, dict) and item.get('path') == path:
                        return item.get('note', '')
            except:
                pass
            
            return ""  # No note found
        except Exception as e:
            print("Error getting note for URL {}: {}".format(url_str, str(e)))
            return ""
    
    def _refresh_vulnerability_table(self):
        """Refresh the vulnerability table with current data"""
        try:
            # Clear existing rows
            self._vuln_table_model.setRowCount(0)
            
            # Get current filter
            selected_filter = str(self._cwe_filter.getSelectedItem())
            filter_cwe = None
            if selected_filter != "All Vulnerabilities":
                filter_cwe = selected_filter.split(" - ")[0]
            
            # Add vulnerabilities to table - sorted by timestamp (oldest first)
            with self._vuln_lock:
                # Sort vulnerabilities by timestamp
                sorted_vulns = sorted(self._vulnerabilities.items(), 
                                    key=lambda x: x[1].get('timestamp', ''), 
                                    reverse=False)  # False = oldest first, True = newest first
                
                for vuln_id, vuln in sorted_vulns:
                    # Apply filter
                    if filter_cwe and vuln['cwe'] != filter_cwe:
                        continue
                    
                    # Get note from watch list for this URL
                    note = self._get_note_for_url(vuln['url'])
                    
                    row_data = [
                        vuln['cwe'],
                        vuln['description'],
                        vuln['method'],
                        vuln['url'],
                        note,
                        vuln['timestamp'],
                        "Remove"
                    ]
                    self._vuln_table_model.addRow(row_data)
            
            # Update stats - show unique requests and total vulnerabilities
            total_count = len(self._vulnerabilities)
            displayed_count = self._vuln_table_model.getRowCount()
            unique_requests = len(set(v['request_hash'] for v in self._vulnerabilities.values()))
            
            if filter_cwe:
                self._vuln_stats_label.setText("Showing {} of {} vulnerabilities (filtered by {}) | {} unique requests".format(
                    displayed_count, total_count, filter_cwe, unique_requests))
            else:
                self._vuln_stats_label.setText("Total: {} vulnerabilities across {} unique requests".format(
                    total_count, unique_requests))
            
            # Store original vulnerability data for search filtering
            self._store_original_vuln_data()
                
        except Exception as e:
            print("Error refreshing vulnerability table: {}".format(str(e)))
    
    def _filter_vulnerabilities(self):
        """Filter vulnerabilities based on selected CWE type"""
        # Clear search field when using CWE filter
        if hasattr(self, '_vuln_search_field'):
            self._vuln_search_field.setText("")
        
        self._refresh_vulnerability_table()
    
    def _remove_vulnerability_at_row(self, row):
        """Remove vulnerability at specified table row"""
        try:
            if row < 0 or row >= self._vuln_table_model.getRowCount():
                return
            
            # Get vulnerability details from table
            cwe = str(self._vuln_table_model.getValueAt(row, 0))
            url = str(self._vuln_table_model.getValueAt(row, 3))
            method = str(self._vuln_table_model.getValueAt(row, 2))
            timestamp = str(self._vuln_table_model.getValueAt(row, 5))  # Moved from 4 to 5
            
            # Find and remove the corresponding vulnerability
            with self._vuln_lock:
                vuln_to_remove = None
                for vuln_id, vuln in self._vulnerabilities.items():
                    if (vuln['cwe'] == cwe and 
                        vuln['url'] == url and 
                        vuln['method'] == method and
                        vuln['timestamp'] == timestamp):
                        vuln_to_remove = vuln_id
                        break
                
                if vuln_to_remove is not None:
                    del self._vulnerabilities[vuln_to_remove]
                    # Remove from database
                    self._remove_vulnerability_from_database(vuln_to_remove)
                    print("Removed vulnerability: {} {} - {}".format(method, url, cwe))
            
            # Refresh table
            self._refresh_vulnerability_table()
            
        except Exception as e:
            print("Error removing vulnerability: {}".format(str(e)))
    
    def _clear_vulnerabilities(self, event):
        """Clear all tracked vulnerabilities"""
        result = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Are you sure you want to clear all vulnerability data?",
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if result == JOptionPane.YES_OPTION:
            with self._vuln_lock:
                self._vulnerabilities.clear()
            # Clear from database
            self._clear_all_data_from_database()
            self._refresh_vulnerability_table()
            print("All vulnerability data cleared")
    
    def _export_vulnerabilities(self, event):
        """Export vulnerabilities in selected format - respects current filter"""
        try:
            # Get current filter selection
            selected_filter = str(self._cwe_filter.getSelectedItem())
            filter_cwe = None
            if selected_filter != "All Vulnerabilities":
                filter_cwe = selected_filter.split(" - ")[0]
            
            # Get export format
            export_format = str(self._export_format.getSelectedItem())
            
            with self._vuln_lock:
                # Prepare data for export - apply filter
                filtered_vulns = []
                for vuln_id, vuln in self._vulnerabilities.items():
                    # Apply the same filter as the table
                    if filter_cwe and vuln['cwe'] != filter_cwe:
                        continue
                    filtered_vulns.append((vuln_id, vuln))

                # Sort by timestamp (oldest first)
                filtered_vulns.sort(key=lambda x: x[1].get('timestamp', ''), reverse=False)

                if len(filtered_vulns) == 0:
                    JOptionPane.showMessageDialog(
                        self._main_panel,
                        "No vulnerabilities to export with current filter",
                        "Nothing to Export",
                        JOptionPane.INFORMATION_MESSAGE
                    )
                    return

                # Export based on format
                if export_format.startswith("Text"):
                    self._export_as_text(filtered_vulns, filter_cwe)
                elif export_format.startswith("CSV"):
                    self._export_as_csv(filtered_vulns, filter_cwe)
                elif export_format.startswith("JSON"):
                    self._export_as_json(filtered_vulns, filter_cwe)
                
        except Exception as e:
            print("Error exporting vulnerabilities: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._main_panel,
                "Error exporting data: {}".format(str(e)),
                "Export Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _export_as_text(self, filtered_vulns, filter_cwe):
        """Export URLs as text list (one per line)"""
        try:
            # Extract unique URLs
            urls = set()
            for vuln_id, vuln in filtered_vulns:
                urls.add(vuln['url'])
            
            # Create text content
            text_content = '\n'.join(sorted(urls))
            
            # Show in dialog for copying
            text_area = JTextArea(text_content)
            text_area.setEditable(False)
            text_area.setCaretPosition(0)
            scroll_pane = JScrollPane(text_area)
            scroll_pane.setPreferredSize(Dimension(500, 300))
            
            # Update dialog title
            dialog_title = "Export URLs as Text (Copy from text area)"
            if filter_cwe:
                dialog_title = "Export {} URLs as Text (Copy from text area)".format(filter_cwe)
            
            JOptionPane.showMessageDialog(
                self._main_panel,
                scroll_pane,
                dialog_title,
                JOptionPane.INFORMATION_MESSAGE
            )
            
            if filter_cwe:
                print("Exported {} unique URLs for {} vulnerabilities as text".format(len(urls), filter_cwe))
            else:
                print("Exported {} unique URLs as text (all vulnerabilities)".format(len(urls)))
                
        except Exception as e:
            print("Error exporting as text: {}".format(str(e)))
            raise
    
    def _export_as_csv(self, filtered_vulns, filter_cwe):
        """Export vulnerabilities as CSV file"""
        try:
            # Create file chooser
            file_chooser = JFileChooser()
            file_chooser.setDialogTitle("Save CSV Export")
            
            # Set default filename
            default_name = "vulnerabilities_export.csv"
            if filter_cwe:
                default_name = "{}_vulnerabilities_export.csv".format(filter_cwe.replace("-", "_"))
            file_chooser.setSelectedFile(java.io.File(default_name))
            
            # Add CSV filter
            csv_filter = FileNameExtensionFilter("CSV Files (*.csv)", ["csv"])
            file_chooser.setFileFilter(csv_filter)
            
            # Show save dialog
            result = file_chooser.showSaveDialog(self._main_panel)
            
            if result == JFileChooser.APPROVE_OPTION:
                file_path = file_chooser.getSelectedFile().getAbsolutePath()
                
                # Ensure .csv extension
                if not file_path.lower().endswith('.csv'):
                    file_path += '.csv'
                
                # Create CSV content
                csv_content = "CWE,Description,Method,URL,Timestamp,Request_Hash\n"
                for vuln_id, vuln in filtered_vulns:
                    # Escape commas and quotes in values
                    def csv_escape(value):
                        value = str(value).replace('"', '""')
                        if ',' in value or '"' in value or '\n' in value:
                            return '"{}"'.format(value)
                        return value
                    
                    csv_content += "{},{},{},{},{},{}\n".format(
                        csv_escape(vuln['cwe']),
                        csv_escape(vuln['description']),
                        csv_escape(vuln['method']),
                        csv_escape(vuln['url']),
                        csv_escape(vuln['timestamp']),
                        csv_escape(str(vuln['request_hash']))
                    )
                
                # Write to file
                with open(file_path, 'w') as f:
                    f.write(csv_content)
                
                # Show success message
                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Successfully exported {} vulnerabilities to:\n{}".format(len(filtered_vulns), file_path),
                    "Export Successful",
                    JOptionPane.INFORMATION_MESSAGE
                )
                
                if filter_cwe:
                    print("Exported {} {} vulnerabilities to CSV: {}".format(len(filtered_vulns), filter_cwe, file_path))
                else:
                    print("Exported {} vulnerabilities to CSV: {}".format(len(filtered_vulns), file_path))
            else:
                print("CSV export cancelled by user")
                
        except Exception as e:
            print("Error exporting as CSV: {}".format(str(e)))
            raise
    
    def _export_as_json(self, filtered_vulns, filter_cwe):
        """Export vulnerabilities as JSON (original functionality)"""
        try:
            # Prepare data for export (exclude message objects)
            export_data = {}
            
            for vuln_id, vuln in filtered_vulns:
                export_data[str(vuln_id)] = {
                    'cwe': vuln['cwe'],
                    'description': vuln['description'],
                    'url': vuln['url'],
                    'method': vuln['method'],
                    'timestamp': vuln['timestamp'],
                    'request_hash': str(vuln['request_hash'])
                }
            
            # Convert to JSON
            json_data = json.dumps(export_data, indent=2)
            
            # Show in dialog for copying
            text_area = JTextArea(json_data)
            text_area.setEditable(False)
            text_area.setCaretPosition(0)
            scroll_pane = JScrollPane(text_area)
            scroll_pane.setPreferredSize(Dimension(600, 400))
            
            # Update dialog title to show filter info
            dialog_title = "Export Vulnerabilities as JSON (Copy from text area)"
            if filter_cwe:
                dialog_title = "Export {} Vulnerabilities as JSON (Copy from text area)".format(filter_cwe)
            
            JOptionPane.showMessageDialog(
                self._main_panel,
                scroll_pane,
                dialog_title,
                JOptionPane.INFORMATION_MESSAGE
            )
            
            if filter_cwe:
                print("Exported {} {} vulnerabilities to JSON".format(len(filtered_vulns), filter_cwe))
            else:
                print("Exported {} vulnerabilities to JSON (all vulnerabilities)".format(len(filtered_vulns)))
                
        except Exception as e:
            print("Error exporting as JSON: {}".format(str(e)))
            raise

class CWEMessageEditorTab(IMessageEditorTab):
    """Custom message editor tab for CWE tracking"""
    
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._editable = editable
        self._current_message = None
        self._current_request_info = None
        
        # Create the UI
        self._create_tab_ui()
    
    def _create_tab_ui(self):
        """Create the UI for the CWE tracking tab"""
        self._component = JPanel(BorderLayout())
        
        # Top panel for CWE selection
        top_panel = JPanel()
        top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
        
        # Request info panel
        info_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._request_info_label = JLabel("No request selected")
        self._request_info_label.setFont(self._request_info_label.getFont().deriveFont(12.0))
        info_panel.add(self._request_info_label)
        top_panel.add(info_panel)
        
        # CWE selection panel
        cwe_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        cwe_panel.add(JLabel("Mark as vulnerable to:"))
        
        # CWE dropdown
        cwe_items = ["Select CWE..."] + ["{} - {}".format(k, v) for k, v in self._extender._cwe_types.items()]
        self._cwe_combo = JComboBox(cwe_items)
        cwe_panel.add(self._cwe_combo)
        
        # Mark vulnerability button
        self._mark_button = JButton("Mark Vulnerability", actionPerformed=self._mark_vulnerability)
        cwe_panel.add(self._mark_button)
        
        # Add to watch list button
        self._watch_button = JButton("Add to Watch List", actionPerformed=self._add_to_watch_list)
        cwe_panel.add(self._watch_button)
        
        top_panel.add(cwe_panel)
        
        # Note panel
        note_panel = JPanel(BorderLayout())
        note_panel.add(JLabel("Note for this request:"), BorderLayout.NORTH)
        
        # Note text area
        self._note_textarea = JTextArea(3, 50)
        self._note_textarea.setLineWrap(True)
        self._note_textarea.setWrapStyleWord(True)
        self._note_textarea.setBorder(BorderFactory.createEtchedBorder())
        note_scroll = JScrollPane(self._note_textarea)
        note_panel.add(note_scroll, BorderLayout.CENTER)
        
        # Note button panel
        note_button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._save_note_button = JButton("Save Note", actionPerformed=self._save_note)
        self._clear_note_button = JButton("Clear Note", actionPerformed=self._clear_note)
        note_button_panel.add(self._save_note_button)
        note_button_panel.add(self._clear_note_button)
        note_panel.add(note_button_panel, BorderLayout.SOUTH)
        
        top_panel.add(note_panel)
        
        self._component.add(top_panel, BorderLayout.NORTH)
        
        # Center panel for existing vulnerabilities
        center_panel = JPanel(BorderLayout())
        center_panel.add(JLabel("Existing vulnerabilities for this request:"), BorderLayout.NORTH)
        
        # Vulnerabilities table for current request
        column_names = ["CWE", "Description", "Timestamp", "Actions"]
        self._request_vuln_model = DefaultTableModel(column_names, 0)
        self._request_vuln_table = JTable(self._request_vuln_model)
        self._request_vuln_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        
        # Add click handler for remove button
        class RequestTableClickHandler(MouseAdapter):
            def __init__(self, extension_parent):
                MouseAdapter.__init__(self)
                self.extension_parent = extension_parent
                
            def mouseClicked(self, event):
                if event.getClickCount() == 1:
                    table = event.getSource()
                    row = table.rowAtPoint(event.getPoint())
                    col = table.columnAtPoint(event.getPoint())
                    
                    # Check if "Actions" column was clicked
                    if col == 3 and row >= 0:  # Actions column
                        self.extension_parent._remove_request_vulnerability_at_row(row)
        
        self._request_vuln_table.addMouseListener(RequestTableClickHandler(self))
        
        request_scroll = JScrollPane(self._request_vuln_table)
        center_panel.add(request_scroll, BorderLayout.CENTER)
        
        self._component.add(center_panel, BorderLayout.CENTER)
        
        # Bottom panel for statistics
        stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._stats_label = JLabel("No vulnerabilities for this request")
        stats_panel.add(self._stats_label)
        self._component.add(stats_panel, BorderLayout.SOUTH)
    
    def getTabCaption(self):
        """Return the caption for this tab"""
        return "Vuln Tracker"
    
    def getUiComponent(self):
        """Return the UI component for this tab"""
        return self._component
    
    def isEnabled(self, content, isRequest):
        """Return True if this tab should be enabled for the given content"""
        enabled = isRequest  # Only show for requests, not responses
        return enabled
    
    def setMessage(self, content, isRequest):
        """Called when the message changes"""
        if content is None or not isRequest:
            self._current_message = None
            self._current_request_info = None
            self._update_ui_for_request()
            return

        self._current_message = content
        try:
            # Try Burp's helpers first for better accuracy
            self._current_request_info = None
            
            try:
                if hasattr(self._extender, '_helpers'):
                    # Convert array.array to bytes if needed
                    if hasattr(content, 'tostring'):
                        # For array.array objects, convert to bytes
                        request_bytes = content.tostring()
                        request_info = self._extender._helpers.analyzeRequest(request_bytes)
                    elif hasattr(content, 'getRequest'):
                        # For IHttpRequestResponse objects
                        service = content.getHttpService()
                        request_bytes = content.getRequest()
                        request_info = self._extender._helpers.analyzeRequest(service, request_bytes)
                    else:
                        # Direct analysis for other types
                        request_info = self._extender._helpers.analyzeRequest(content)
                    
                    try:
                        if request_info and hasattr(request_info, 'getUrl'):
                            # WORKAROUND: Skip getUrl() call as it seems to cause tab refresh
                            # Instead, extract URL info manually from the original request bytes
                            self._current_request_info = request_info
                            
                            # Store the original request bytes for manual URL extraction
                            try:
                                self._original_request_bytes = request_bytes
                            except:
                                self._original_request_bytes = None
                            
                            # Try to get method to verify the object works
                            try:
                                method = request_info.getMethod()
                            except Exception as method_ex:
                                pass  # Continue even if method extraction fails
                        else:
                            self._current_request_info = None
                    except Exception as parse_ex:
                        # Even if parsing fails, try to use the request_info
                        if request_info:
                            self._current_request_info = request_info
            except Exception as e:
                pass  # Fall back to manual parsing
            
            # Fall back to manual parsing if helpers failed
            if self._current_request_info is None:
                self._current_request_info = self._parse_request_manually(content)
            
            self._update_ui_for_request()
                
        except Exception as e:
            print("Error analyzing request in CWE tab: {}".format(str(e)))
            self._current_request_info = None
            self._update_ui_for_request()
    
    def _parse_request_manually(self, content):
        """Manually parse request if helpers fail"""
        try:
            # Handle different types of content objects
            request_str = ""
            
            # If content is IHttpRequestResponse, get the request bytes
            if hasattr(content, 'getRequest'):
                request_bytes = content.getRequest()
                if request_bytes:
                    if hasattr(request_bytes, 'tostring'):
                        request_str = request_bytes.tostring()
                    else:
                        request_str = ''.join(chr(b & 0xFF) for b in request_bytes)
                else:
                    return None
            else:
                # Handle raw content - particularly array.array objects
                if hasattr(content, 'tostring'):
                    # For array.array objects
                    request_str = content.tostring()
                elif isinstance(content, (bytes, bytearray)):
                    request_str = str(content)
                elif hasattr(content, '__iter__'):
                    # Handle byte arrays
                    try:
                        request_str = ''.join(chr(b & 0xFF) for b in content)
                    except:
                        request_str = str(content)
                else:
                    request_str = str(content)
            
            if not request_str:
                return None
            
            lines = request_str.split('\n')
            if len(lines) > 0:
                first_line = lines[0].strip()
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    
                    # Extract host from headers
                    host = "unknown.host"
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            host = line.split(':', 1)[1].strip()
                            break
                    
                    # Detect protocol from the original request context
                    # Check if the request was made over HTTPS by examining various indicators
                    protocol = "http"  # Default to HTTP
                    
                    # Method 1: Check if helpers can parse it and get the URL
                    try:
                        if hasattr(self._extender, '_helpers'):
                            temp_request_info = self._extender._helpers.analyzeRequest(self._current_message)
                            if temp_request_info and hasattr(temp_request_info, 'getUrl'):
                                temp_url = temp_request_info.getUrl()
                                if temp_url and hasattr(temp_url, 'getProtocol'):
                                    detected_protocol = temp_url.getProtocol()
                                    if detected_protocol in ["http", "https"]:
                                        protocol = detected_protocol
                    except:
                        pass  # Fall back to HTTP if helper analysis fails
                    
                    # Method 2: Check for HTTPS indicators in headers if helper method failed
                    if protocol == "http":  # Only check if we haven't detected HTTPS yet
                        for line in lines[1:]:
                            line_lower = line.lower()
                            # Look for HTTPS-specific headers or indicators
                            if ('x-forwarded-proto: https' in line_lower or 
                                'x-forwarded-ssl: on' in line_lower or
                                'x-scheme: https' in line_lower):
                                protocol = "https"
                                break
                    
                    # Create a robust request info object
                    class ManualRequestInfo:
                        def __init__(self, method, path, host, protocol):
                            self.method = method
                            self.path = path
                            self.host = host
                            self.protocol = protocol
                            
                        def getMethod(self):
                            return self.method
                            
                        def getUrl(self):
                            # Create a URL object that works with our needs
                            class ManualURL:
                                def __init__(self, path, host, protocol):
                                    self.path = path
                                    self.host = host
                                    self.protocol = protocol
                                    
                                def getPath(self):
                                    return self.path
                                    
                                def getHost(self):
                                    return self.host
                                    
                                def getProtocol(self):
                                    return self.protocol
                                    
                                def toString(self):
                                    return "{}://{}{}".format(self.protocol, self.host, self.path)
                                    
                                def __str__(self):
                                    return "{}://{}{}".format(self.protocol, self.host, self.path)
                                    
                            return ManualURL(self.path, self.host, self.protocol)
                    
                    return ManualRequestInfo(method, path, host, protocol)
            
            return None
        except Exception as e:
            print("Manual parsing failed: {}".format(str(e)))
            return None

    def getMessage(self):
        """Return the current message"""
        return self._current_message
    
    def _extract_url_manually(self):
        """Extract URL information manually from stored request bytes"""
        try:
            if not hasattr(self, '_original_request_bytes') or not self._original_request_bytes:
                print("DEBUG: No original request bytes available")
                return None
                
            # Convert bytes to string
            request_str = self._original_request_bytes
            if hasattr(request_str, 'decode'):
                request_str = request_str.decode('utf-8', errors='ignore')
            elif not isinstance(request_str, str):
                request_str = str(request_str)
                
            print("DEBUG: Manual URL extraction from request: {}".format(request_str[:200]))
            
            lines = request_str.split('\n')
            if not lines:
                return None
                
            # Parse first line: METHOD path HTTP/1.1
            first_line = lines[0].strip()
            parts = first_line.split(' ')
            if len(parts) < 2:
                return None
                
            path = parts[1]
            
            # Extract host from headers
            host = "unknown.host"
            protocol = "http"  # Default
            
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host = line.split(':', 1)[1].strip()
                    break
            
            print("DEBUG: Extracted host: {}".format(host))
            
            # Enhanced HTTPS detection
            # Method 1: Look for HTTPS indicators in headers
            request_lower = request_str.lower()
            https_indicators = [
                'https://',  # Direct HTTPS URLs in content
                'x-forwarded-proto: https',
                'x-forwarded-ssl: on',
                'x-scheme: https',
                'x-forwarded-protocol: https',
                'x-url-scheme: https',
                'front-end-https: on'
            ]
            
            for indicator in https_indicators:
                if indicator in request_lower:
                    protocol = "https"
                    print("DEBUG: Detected HTTPS from indicator: {}".format(indicator))
                    break
            
            # Method 2: Check standard HTTPS ports (if host includes port)
            if ':443' in host:
                protocol = "https"
                print("DEBUG: Detected HTTPS from port 443")
                # Remove port from host for display
                host = host.replace(':443', '')
            
            # Method 3: Common HTTPS patterns in cookies or content
            if protocol == "http":  # Only check if not already detected as HTTPS
                https_patterns = [
                    'secure;',  # Secure cookie flag
                    'samesite=none',  # Often used with HTTPS
                    'redirect_uri=https://',  # OAuth/SSO redirects
                    'referer: https://',
                    'origin: https://'
                ]
                
                for pattern in https_patterns:
                    if pattern in request_lower:
                        protocol = "https"
                        print("DEBUG: Detected HTTPS from pattern: {}".format(pattern))
                        break
            
            # Method 4: Check if we can get protocol from the original Burp request_info
            # This is a last resort that might work without causing tab refresh
            if protocol == "http" and hasattr(self, '_current_request_info'):
                try:
                    # Try to get headers to see if we can find more clues
                    if hasattr(self._current_request_info, 'getHeaders'):
                        headers = self._current_request_info.getHeaders()
                        for header in headers:
                            header_str = str(header).lower()
                            if 'https' in header_str:
                                protocol = "https"
                                print("DEBUG: Detected HTTPS from request headers")
                                break
                except:
                    pass  # Ignore if headers method doesn't work
            
            print("DEBUG: Final detected protocol: {}".format(protocol))
            
            return {
                'protocol': protocol,
                'host': host,
                'path': path
            }
            
        except Exception as e:
            print("DEBUG: Manual URL extraction failed: {}".format(str(e)))
            return None
    
    def isModified(self):
        """Return whether the message has been modified"""
        return False  # This tab doesn't modify the message
    
    def getSelectedData(self):
        """Return the selected data"""
        return None  # This tab doesn't support selection
    
    def _update_ui_for_request(self):
        """Update the UI based on the current request"""
        print("DEBUG: _update_ui_for_request called - request_info: {}".format(
            "None" if self._current_request_info is None else "Available"))
        
        if self._current_request_info is None:
            print("DEBUG: No request info available - showing 'No request selected'")
            self._request_info_label.setText("No request selected")
            self._clear_vulnerabilities_table()
            self._stats_label.setText("No vulnerabilities for this request")
            self._note_textarea.setText("")  # Clear note when no request selected
            return
        
        try:
            print("DEBUG: Trying to get URL and method from request_info...")
            
            # Safely get method first (this seems to work)
            method = "UNKNOWN"
            try:
                method = self._current_request_info.getMethod()
                print("DEBUG: Successfully got method: {}".format(method))
            except Exception as method_ex:
                print("DEBUG: Failed to get method: {}".format(str(method_ex)))
            
            # Try to extract URL manually from stored request bytes
            url_info = self._extract_url_manually()
            if url_info:
                print("DEBUG: Successfully extracted URL manually: {}".format(url_info))
                # Create a mock URL object with the extracted info
                class MockURL:
                    def __init__(self, url_info):
                        self.url_info = url_info
                    
                    def getProtocol(self):
                        return self.url_info.get('protocol', 'http')
                    
                    def getHost(self):
                        return self.url_info.get('host', 'unknown.host')
                    
                    def getPath(self):
                        return self.url_info.get('path', '/')
                    
                    def getPort(self):
                        # Return default ports or -1 if not specified
                        protocol = self.url_info.get('protocol', 'http')
                        if protocol == 'https':
                            return 443
                        else:
                            return 80
                    
                    def toString(self):
                        return "{}://{}{}".format(
                            self.url_info.get('protocol', 'http'),
                            self.url_info.get('host', 'unknown.host'),
                            self.url_info.get('path', '/')
                        )
                    
                    def __str__(self):
                        return self.toString()
                
                url = MockURL(url_info)
                print("DEBUG: Created mock URL object: {}".format(str(url)))
                
                # Create a wrapper request_info that intercepts getUrl() calls
                class RequestInfoWrapper:
                    def __init__(self, original_request_info, mock_url):
                        self.original_request_info = original_request_info
                        self.mock_url = mock_url
                    
                    def getUrl(self):
                        return self.mock_url
                    
                    def getMethod(self):
                        return self.original_request_info.getMethod()
                    
                    def __getattr__(self, name):
                        # Forward any other method calls to the original object
                        return getattr(self.original_request_info, name)
                
                # Replace the current_request_info with our wrapper
                self._current_request_info = RequestInfoWrapper(self._current_request_info, url)
                print("DEBUG: Created request info wrapper with mock URL")
            else:
                print("DEBUG: Could not extract URL manually")
                url = None
            
            print("DEBUG: Updating UI for request - URL: {}, Method: {}".format(str(url), method))
            
            # Handle case where URL might be None
            if url is not None:
                # Get clean path for display
                try:
                    clean_path = self._extender._get_path_without_params(url)
                    full_url_str = str(url)
                except Exception as path_ex:
                    print("DEBUG: Error getting path: {}".format(str(path_ex)))
                    clean_path = "/"
                    full_url_str = "Error getting URL"
                
                # Get protocol for correct URL construction
                protocol = "https"  # Default
                if hasattr(url, 'getProtocol'):
                    protocol = url.getProtocol()
                elif hasattr(url, 'protocol'):
                    protocol = url.protocol
                
                # Get host
                host = "unknown.host"
                if hasattr(url, 'getHost'):
                    host = url.getHost()
                elif hasattr(url, 'host'):
                    host = url.host
                
                print("DEBUG: Extracted - Protocol: {}, Host: {}, Clean path: {}".format(protocol, host, clean_path))
                
                # Show clean path but indicate if there are parameters
                if '?' in full_url_str:
                    display_text = "{} {} (with parameters)".format(method, "{}://{}{}".format(protocol, host, clean_path))
                else:
                    display_text = "{} {}".format(method, full_url_str)
            else:
                # No URL available - show just the method
                display_text = "{} (URL unavailable)".format(method)
                full_url_str = "URL unavailable"
                clean_path = "/"
                protocol = "http"
                host = "unknown.host"
                print("DEBUG: No URL available, using defaults")
                
            print("DEBUG: Display text: {}".format(display_text))
            self._request_info_label.setText(display_text)
            
            # Update vulnerabilities table for this request
            self._update_vulnerabilities_table(url, method)
            
            # Load note for this request
            self._load_note_for_current_request()
            
        except Exception as e:
            print("Error updating UI for request: {}".format(str(e)))
            self._request_info_label.setText("Error analyzing request")
            self._clear_vulnerabilities_table()
            self._note_textarea.setText("")
    
    def _update_vulnerabilities_table(self, url, method):
        """Update the vulnerabilities table for the current request"""
        # Clear existing rows
        self._request_vuln_model.setRowCount(0)
        
        # Get request hash (ignoring query parameters for consistent grouping)
        request_hash = self._extender._create_request_hash(url, method)
        
        # Find vulnerabilities for this request
        matching_vulns = []
        with self._extender._vuln_lock:
            for vuln_id, vuln in self._extender._vulnerabilities.items():
                if vuln['request_hash'] == request_hash:
                    matching_vulns.append((vuln_id, vuln))
        
        # Sort by timestamp (oldest first)
        matching_vulns.sort(key=lambda x: x[1].get('timestamp', ''), reverse=False)
        
        # Add to table
        for vuln_id, vuln in matching_vulns:
            row_data = [
                vuln['cwe'],
                vuln['description'],
                vuln['timestamp'],
                "Remove"
            ]
            self._request_vuln_model.addRow(row_data)
        
        # Update stats
        count = len(matching_vulns)
        if count == 0:
            self._stats_label.setText("No vulnerabilities for this request")
        elif count == 1:
            self._stats_label.setText("1 vulnerability found for this request")
        else:
            self._stats_label.setText("{} vulnerabilities found for this request".format(count))
    
    def _clear_vulnerabilities_table(self):
        """Clear the vulnerabilities table"""
        self._request_vuln_model.setRowCount(0)
    
    def _mark_vulnerability(self, event):
        """Mark the current request with the selected CWE"""
        print("Mark vulnerability called - current_request_info: {}".format(self._current_request_info))
        
        if self._current_request_info is None:
            print("No request info available")
            JOptionPane.showMessageDialog(
                self._component,
                "No request selected",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            return
        
        selected_item = str(self._cwe_combo.getSelectedItem())
        print("Selected CWE item: {}".format(selected_item))
        
        if selected_item == "Select CWE...":
            JOptionPane.showMessageDialog(
                self._component,
                "Please select a CWE type",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            return
        
        try:
            # Parse CWE code and description
            cwe_code = selected_item.split(" - ")[0]
            description = selected_item.split(" - ")[1]
            
            print("DEBUG: About to call getUrl() in _mark_vulnerability...")
            url = self._current_request_info.getUrl()
            print("DEBUG: Successfully got URL: {}".format(str(url)))
            
            print("DEBUG: About to call getMethod() in _mark_vulnerability...")
            method = self._current_request_info.getMethod()
            print("DEBUG: Successfully got method: {}".format(method))
            # Create hash ignoring query parameters for consistent grouping
            request_hash = self._extender._create_request_hash(url, method)
            
            # Check for duplicate CWE
            with self._extender._vuln_lock:
                for vuln_id, vuln in self._extender._vulnerabilities.items():
                    if (vuln['request_hash'] == request_hash and 
                        vuln['cwe'] == cwe_code):
                        JOptionPane.showMessageDialog(
                            self._component,
                            "This request is already marked as vulnerable to {}".format(cwe_code),
                            "Duplicate Vulnerability",
                            JOptionPane.WARNING_MESSAGE
                        )
                        return
                
                # Create unique vulnerability ID using internal counter
                self._extender._vuln_counter += 1
                vuln_id = self._extender._vuln_counter
                
                # Store vulnerability
                self._extender._vulnerabilities[vuln_id] = {
                    'cwe': cwe_code,
                    'description': description,
                    'url': str(url),
                    'method': method,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'request_hash': request_hash,
                    'message': None  # We don't have access to the full message object here
                }
                
                # Save to database
                save_success = self._extender._save_vulnerability_to_database(vuln_id, self._extender._vulnerabilities[vuln_id])
                
                if not save_success:
                    # Remove from memory if save failed
                    del self._extender._vulnerabilities[vuln_id]
                    self._extender._vuln_counter -= 1
                    raise Exception("Failed to save vulnerability to file")
            
            # Update the main vulnerabilities tab
            self._extender._refresh_vulnerability_table()
            
            # Update this tab's table
            self._update_vulnerabilities_table(url, method)
            
            # Reset combo box
            self._cwe_combo.setSelectedIndex(0)
            
            # Show success message
            JOptionPane.showMessageDialog(
                self._component,
                "Marked {} {} as vulnerable to {}\n{}".format(method, url, cwe_code, description),
                "Vulnerability Marked",
                JOptionPane.INFORMATION_MESSAGE
            )
            
            print("Marked vulnerability from CWE tab: {} {} - {} {}".format(method, url, cwe_code, description))
            
        except Exception as e:
            print("Error marking vulnerability from CWE tab: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._component,
                "Error marking vulnerability: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _add_to_watch_list(self, event):
        """Add the current request path to the watch list"""
        print("Add to watch list called - current_request_info: {}".format(self._current_request_info))
        
        if self._current_request_info is None:
            print("No request info available for watch list")
            JOptionPane.showMessageDialog(
                self._component,
                "No request selected",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            return
        
        try:
            url = self._current_request_info.getUrl()
            path = url.getPath()
            
            # Add to watch list
            current_text = self._extender._path_textarea.getText()
            if current_text:
                new_text = current_text + '\n' + path
            else:
                new_text = path
            
            self._extender._path_textarea.setText(new_text)
            self._extender._update_paths(None)
            
            JOptionPane.showMessageDialog(
                self._component,
                "Added '{}' to watch list".format(path),
                "Path Added",
                JOptionPane.INFORMATION_MESSAGE
            )
            
        except Exception as e:
            print("Error adding path to watch list from CWE tab: {}".format(str(e)))
    
    def _remove_request_vulnerability_at_row(self, row):
        """Remove vulnerability at specified row for current request"""
        try:
            if row < 0 or row >= self._request_vuln_model.getRowCount():
                return
            
            # Get vulnerability details
            cwe = str(self._request_vuln_model.getValueAt(row, 0))
            timestamp = str(self._request_vuln_model.getValueAt(row, 2))
            
            url = self._current_request_info.getUrl()
            method = self._current_request_info.getMethod()
            
            # Find and remove the vulnerability
            with self._extender._vuln_lock:
                vuln_to_remove = None
                for vuln_id, vuln in self._extender._vulnerabilities.items():
                    if (vuln['cwe'] == cwe and 
                        vuln['url'] == str(url) and 
                        vuln['method'] == method and
                        vuln['timestamp'] == timestamp):
                        vuln_to_remove = vuln_id
                        break
                
                if vuln_to_remove is not None:
                    del self._extender._vulnerabilities[vuln_to_remove]
                    # Remove from database
                    self._extender._remove_vulnerability_from_database(vuln_to_remove)
                    print("Removed vulnerability from CWE tab: {} {} - {}".format(method, url, cwe))
            
            # Update both tables
            self._extender._refresh_vulnerability_table()
            self._update_vulnerabilities_table(url, method)
            
        except Exception as e:
            print("Error removing vulnerability from CWE tab: {}".format(str(e)))
    
    def _update_table_note_for_path(self, path, note):
        """Update the note column in the watch table for a specific path"""
        try:
            if not hasattr(self._extender, '_watch_table_model'):
                return False
            
            # Convert full URL to display format for table lookup
            display_path = self._extender._get_display_url(path)
            
            table_model = self._extender._watch_table_model
            for row in range(table_model.getRowCount()):
                table_path = table_model.getValueAt(row, 1)  # Path column is now 1
                if table_path == display_path:
                    table_model.setValueAt(note, row, 5)  # Note column is now 5
                    print("Updated table note for path {}: '{}'".format(display_path, note))
                    return True
            
            return False  # Path not found in table
            
        except Exception as e:
            print("Error updating table note: {}".format(str(e)))
            return False
    
    def _add_path_to_table(self, path, note):
        """Add a new path with note to the watch table"""
        try:
            if not hasattr(self._extender, '_watch_table_model'):
                return False
            
            # Convert full URL to display format for table
            display_path = self._extender._get_display_url(path)
            
            table_model = self._extender._watch_table_model
            # Add new row: [path, manual_audited, scanned, last_audit, note, highlight]
            row_data = [display_path, False, False, "Never", note, False]
            table_model.addRow(row_data)
            print("Added new path to table: {} with note: '{}'".format(display_path, note))
            return True
            
        except Exception as e:
            print("Error adding path to table: {}".format(str(e)))
            return False
    
    def _save_note(self, event):
        """Save the note for the current request to the watch list (only if request is already in watch list)"""
        print("DEBUG: _save_note called")
        
        if self._current_request_info is None:
            print("DEBUG: No current request info for save note")
            JOptionPane.showMessageDialog(
                self._component,
                "No request selected",
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
            return
        
        try:
            print("DEBUG: About to call getUrl() in _save_note...")
            url = self._current_request_info.getUrl()
            print("DEBUG: Successfully got URL: {}".format(str(url)))
            
            print("DEBUG: About to call toString()...")
            full_url = url.toString()
            print("DEBUG: Successfully got full_url: {}".format(full_url))
            
            print("DEBUG: About to call getPath()...")
            path = url.getPath()
            print("DEBUG: Successfully got path: {}".format(path))
            
            note_text = self._note_textarea.getText().strip()
            print("DEBUG: Note text: '{}'".format(note_text))
            
            # Check if the path exists in the watch list first
            if hasattr(self._extender, '_data') and 'watch_list_audit' in self._extender._data:
                found_in_watch_list = False
                for item in self._extender._data['watch_list_audit']:
                    if isinstance(item, dict) and (item.get('path') == full_url or item.get('path') == path):
                        # Found in watch list, update the note
                        item['note'] = note_text
                        item['path'] = full_url  # Update to full URL format
                        found_in_watch_list = True
                        break
                
                if not found_in_watch_list:
                    # Request not in watch list, show error
                    JOptionPane.showMessageDialog(
                        self._component,
                        "This request is not in the watch list.\nPlease add it to the watch list first before saving notes.",
                        "Request Not in Watch List",
                        JOptionPane.WARNING_MESSAGE
                    )
                    return
                
                # Save the updated data to database
                self._extender._save_watch_list_to_database()
                
                # Update the table note
                self._update_table_note_for_path(full_url, note_text)
                
                # Update vulnerability table to reflect note changes
                self._extender._refresh_vulnerability_table()
                
                JOptionPane.showMessageDialog(
                    self._component,
                    "Note saved for path: {}".format(path),
                    "Note Saved",
                    JOptionPane.INFORMATION_MESSAGE
                )
            else:
                JOptionPane.showMessageDialog(
                    self._component,
                    "No watch list data available",
                    "Error",
                    JOptionPane.ERROR_MESSAGE
                )
            
        except Exception as e:
            print("Error saving note from CWE tab: {}".format(str(e)))
            JOptionPane.showMessageDialog(
                self._component,
                "Error saving note: {}".format(str(e)),
                "Error",
                JOptionPane.ERROR_MESSAGE
            )
    
    def _clear_note(self, event):
        """Clear the note text area and save the changes"""
        if self._current_request_info is None:
            self._note_textarea.setText("")
            return
        
        try:
            url = self._current_request_info.getUrl()
            full_url = url.toString()
            path = url.getPath()
            
            # Clear the text area
            self._note_textarea.setText("")
            
            # Find the path in the watch list and clear its note
            # Check both full URL and path for backward compatibility
            if hasattr(self._extender, '_data') and 'watch_list_audit' in self._extender._data:
                for item in self._extender._data['watch_list_audit']:
                    if isinstance(item, dict) and (item.get('path') == full_url or item.get('path') == path):
                        item['note'] = ''
                        item['path'] = full_url  # Update to full URL format
                        print("Cleared note for path: {}".format(full_url))
                        break
                
                # Save the updated data to database
                self._extender._save_watch_list_to_database()
                
                # Update the specific row in the watch list table
                self._update_table_note_for_path(full_url, '')
                
                # Update vulnerability table to reflect note changes
                self._extender._refresh_vulnerability_table()
            
        except Exception as e:
            print("Error clearing note from CWE tab: {}".format(str(e)))
    
    def _load_note_for_current_request(self):
        """Load existing note for the current request path"""
        if self._current_request_info is None:
            return
        
        try:
            url = self._current_request_info.getUrl()
            full_url = url.toString()
            path = url.getPath()
            
            # Search for existing note in watch list
            if hasattr(self._extender, '_data') and 'watch_list_audit' in self._extender._data:
                for item in self._extender._data['watch_list_audit']:
                    if isinstance(item, dict) and (item.get('path') == full_url or item.get('path') == path):
                        note = item.get('note', '')
                        self._note_textarea.setText(note)
                        print("Loaded note for path {}: '{}'".format(item.get('path'), note))
                        return
            
            # No note found, clear the text area
            self._note_textarea.setText("")
            
        except Exception as e:
            print("Error loading note for current request: {}".format(str(e)))

# Register the extension
if __name__ in ('__main__', 'main'):
    BurpExtender()
