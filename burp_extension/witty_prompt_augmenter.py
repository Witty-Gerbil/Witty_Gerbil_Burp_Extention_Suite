#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Updated on Mon Dec  9 12:43:21 2024

@author:
    samuelcameron
    

Credit: Witty Gerbil

"""


import json
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Dimension
from javax.swing import JPanel, JLabel, JTextField, JComboBox, JButton, JTextArea, JScrollPane
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStream
from burp import IBurpExtender, ITab, IIntruderPayloadProcessor
from java.awt import Insets, GridBagConstraints
from burp import IBurpExtender, ITab, IIntruderPayloadProcessor, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
from javax.swing import JPanel, JLabel, JTextField, JComboBox, JButton, JTextArea, JScrollPane
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets
import json
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStream
from burp import IContextMenuFactory, IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt.event import ActionListener
from javax.swing import SwingUtilities
from java.lang import String




class BurpExtender(IBurpExtender, ITab, IIntruderPayloadProcessor, IContextMenuFactory):
    API_URL = "http://localhost:8000/api/v1/burp_suite_prompt_augmentor/"
    
    def registerExtenderCallbacks(self, callbacks):
        # Set the extension name
        callbacks.setExtensionName("Witty Prompt Augmenter")
        
        # Store callbacks and helpers
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        
        # Create and register the custom tab
        self.panel = self.createCustomTab()
        callbacks.addSuiteTab(self)
        
        # Register this class as a payload processor
        callbacks.registerIntruderPayloadProcessor(self)
        
        callbacks.registerContextMenuFactory(self)
        
        # Print credit information to the Burp Suite console
        print("\n" + "="*50)
        print("Brought to you by: Witty Gerbil 🐹")
        print("="*50 + "\n")
        
        
        
    def handleContextMenuAction(self, invocation):
        """
        Handles the action of the context menu item, with fallback for Intruder context.
        """
        try:
            print("Context menu action triggered.")
    
            # Get the invocation context
            context = invocation.getInvocationContext()
            print("Invocation context (type): {}".format(context))
    
            # Get the selected messages
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages or len(selected_messages) == 0:
                print("No selected messages found.")
                return
    
            print("Selected message count: {}".format(len(selected_messages)))
    
            # Process the first selected message
            selected_message = selected_messages[0]
            print("Selected message (object): {}".format(selected_message))
    
            # Decode the request bytes
            request_bytes = selected_message.getRequest()
            if request_bytes is None:
                print("No request bytes found in the selected message.")
                return
    
            # Decode request to string
            try:
                request_str = String(request_bytes, "UTF-8")
                print("Decoded request string successfully using java.lang.String.")
            except Exception as e:
                print("Error decoding request bytes to UTF-8: {}".format(e))
                return
    
            # Attempt to get selection bounds
            selection_bounds = invocation.getSelectionBounds()
            if selection_bounds:
                # Use selection bounds if available
                print("Selection bounds: start={}, end={}".format(selection_bounds[0], selection_bounds[1]))
                highlighted_text = request_str.substring(selection_bounds[0], selection_bounds[1])
                print("Highlighted text (via bounds): {}".format(highlighted_text))
            elif context == 8:  # Intruder-specific fallback
                print("No selection bounds. Attempting Intruder-specific fallback.")
                # Logic to extract payload positions in Intruder
                payload_positions = self.extractIntruderPayloadPositions(selected_message)
                if not payload_positions:
                    print("No payload positions found in Intruder.")
                    return
                highlighted_text = payload_positions
                print("Highlighted text (Intruder fallback): {}".format(highlighted_text))
            else:
                print("Selection bounds not found. Ensure text is highlighted in a supported editor.")
                return
    
            # Update the base_prompt_field on the Swing Event Dispatch Thread
            SwingUtilities.invokeLater(lambda: self.base_prompt_field.setText(highlighted_text))
            print("Base prompt field updated in the custom tab.")
    
        except Exception as e:
            print("Error in handleContextMenuAction: {}".format(e))
    
    
    def extractIntruderPayloadPositions(self, selected_message):
        """
        Custom logic to extract payload positions in Intruder using analyzeRequest.
        """
        try:
            # Analyze the request to split headers and body
            request_info = self.helpers.analyzeRequest(selected_message)
            body_offset = request_info.getBodyOffset()
            request_bytes = selected_message.getRequest()
            if not request_bytes:
                print("No request bytes found.")
                return None
    
            # Decode the request into a string
            request_str = self.helpers.bytesToString(request_bytes)
    
            # Split the request into headers and body
            headers = request_str[:body_offset]
            body = request_str[body_offset:]
    
            # Log headers and body for debugging
            print("Request Headers:\n{}".format(headers))
            print("Request Body:\n{}".format(body))
    
            # In Intruder, the user likely highlights part of the body
            # Return the entire body if no exact markers are found
            return body.strip() if body else None
    
        except Exception as e:
            print("Error extracting Intruder payload positions: {}".format(e))
            return None

    
    def createMenuItems(self, invocation):
        """
        Creates context menu items.
        """
        menu_item = JMenuItem("Send to Prompt Augmentor as base prompt", actionPerformed=lambda event: self.handleContextMenuAction(invocation))
        return [menu_item]
    
    
    def sendApiRequest(self, payload):
        """
        Sends the API request and returns the JSON response.
        """
        try:
            url = URL(self.API_URL)
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")
            
            # Write the payload
            output_stream = connection.getOutputStream()
            payload_str = json.dumps(payload).encode("utf-8")
            output_stream.write(payload_str)
            output_stream.flush()
            output_stream.close()
            
            # Read the response
            response_code = connection.getResponseCode()
            if response_code == 200:
                reader = BufferedReader(InputStreamReader(connection.getInputStream()))
                response = ""
                line = reader.readLine()
                while line is not None:
                    response += line
                    line = reader.readLine()
                reader.close()
                return json.loads(response)
            else:
                raise Exception("API call failed with status code: " + str(response_code))
        except Exception as e:
            raise Exception("Error sending API request: " + str(e))

    
    
    def getTabCaption(self):
        """
        Returns the name of the custom tab.
        """
        return "Witty Prompt Augmenter"
    
    def getUiComponent(self):
        """
        Returns the UI component of the custom tab.
        """
        return self.panel
    
    def createCustomTab(self):
        """
        Creates the custom tab UI with proper formatting.
        """
        panel = JPanel(BorderLayout())
        input_panel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(5, 5, 5, 5)  # Fix: Use Insets instead of a tuple
    
        # Function to add a labeled input field
        def add_field(label_text, component, row):
            constraints.gridx = 0
            constraints.gridy = row
            constraints.weightx = 0.2
            input_panel.add(JLabel(label_text), constraints)
            constraints.gridx = 1
            constraints.weightx = 0.8
            input_panel.add(component, constraints)
    
        # Add input fields
        self.model_dropdown = JComboBox(["OpenAI", "OtherModel"])
        add_field("Model:", self.model_dropdown, 0)
    
        self.base_prompt_field = JTextField(20)
        add_field("Base Prompt:", self.base_prompt_field, 1)
    
        self.objective_field = JTextField(20)
        add_field("Objective:", self.objective_field, 2)
    
        self.llm_info_field = JTextField(20)
        add_field("LLM Information:", self.llm_info_field, 3)
    
        self.special_notes_field = JTextField(20)  # New Special Notes field
        add_field("Special Notes:", self.special_notes_field, 4)
    
        self.num_augments_field = JTextField(5)
        add_field("Number of Augments:", self.num_augments_field, 5)
    
        self.augment_type_dropdown = JComboBox(["Prompt Injection"])
        add_field("Augment Type:", self.augment_type_dropdown, 6)
    
        panel.add(input_panel, BorderLayout.NORTH)
    
        # Add a text area for the augmented prompt
        self.output_area = JTextArea(10, 40)
        self.output_area.setEditable(False)
        scroll_pane = JScrollPane(self.output_area)
        panel.add(scroll_pane, BorderLayout.CENTER)
    
        # Add "Submit" button
        submit_button = JButton("Submit", actionPerformed=self.handleSubmit)
        panel.add(submit_button, BorderLayout.SOUTH)
        
        # Add Submit and Send to Intruder buttons
        button_panel = JPanel()
        submit_button = JButton("Submit", actionPerformed=self.handleSubmit)
        send_to_intruder_button = JButton("Send to Intruder", actionPerformed=self.sendToIntruder)
        button_panel.add(submit_button)
        button_panel.add(send_to_intruder_button)
        panel.add(button_panel, BorderLayout.SOUTH)
    
        return panel

    
    def sendToIntruder(self, event):
        """
        Sends the augmented prompts to the Intruder queue.
        """
        try:
            prompts = self.output_area.getText().strip().split("\n")[1:]  # Exclude the header
            if not prompts:
                print("No prompts to send to Intruder.")
                return
    
            # Create and register the payload generator factory with the prompts
            generator_factory = AugmentedPromptGeneratorFactory(prompts)
            self.callbacks.registerIntruderPayloadGeneratorFactory(generator_factory)
    
            print("Prompts registered to Intruder Payload Generator.")
        except Exception as e:
            print("Error sending prompts to Intruder: " + str(e))




    def handleSubmit(self, event):
        """
        Handles the submission of the input fields to the API.
        """
        try:
            # Get values from input fields
            model = self.model_dropdown.getSelectedItem()
            base_prompt = self.base_prompt_field.getText()
            objective = self.objective_field.getText()
            llm_info = self.llm_info_field.getText()
            special_notes = self.special_notes_field.getText()  # New Special Notes field
            num_augments = int(self.num_augments_field.getText()) if self.num_augments_field.getText().isdigit() else 1
            augment_type = self.augment_type_dropdown.getSelectedItem()
    
            # Prepare API payload
            api_payload = {
                "column_name": "Prompt",
                "number_of_augments": num_augments,
                "prompt_list": [{"prompt": base_prompt}],
                "augmentor_model_type": model,
                "model_type": model,
                "augmentor_model_id": "gpt-4o" if model == "OpenAI" else "",
                "augmentor_api_key_env": "OPENAI_API_KEY" if model == "OpenAI" else "",
                "augment_types": [augment_type],
                "download_csv": False,
                "suppress_terminal_output": False,
                "objective": objective,
                "llm_information": llm_info,
                "special_notes": special_notes  # Include Special Notes
            }
    
            # Make API request
            response_json = self.sendApiRequest(api_payload)
    
            # Process augmented prompts
            augmented_prompts = response_json.get("augmented_prompt_list", [])
            if isinstance(augmented_prompts, list):
                formatted_prompts = "\n".join(augmented_prompts)
            else:
                formatted_prompts = "No augmented prompts returned."
    
            self.output_area.setText("Augmented Prompt(s):\n" + formatted_prompts)
        except Exception as e:
            self.output_area.setText("Error: " + str(e))


        
    def getProcessorName(self):
        """
        Returns the name of the payload processor.
        """
        return "PromptAugmentation"
    
    def processPayload(self, currentPayload, originalPayload, baseValue):
        """
        Processes the given payload by sending it to the prompt augmentation API.
        """
        try:
            # Convert payload to string
            currentPayloadStr = self.helpers.bytesToString(currentPayload)
    
            # Use settings from the custom tab for other fields
            model = self.model_dropdown.getSelectedItem()
            objective = self.objective_field.getText()
            llm_info = self.llm_info_field.getText()
            special_notes = self.special_notes_field.getText()  # New Special Notes field
            num_augments = int(self.num_augments_field.getText()) if self.num_augments_field.getText().isdigit() else 1
            augment_type = self.augment_type_dropdown.getSelectedItem()
    
            # Prepare API payload
            api_payload = {
                "column_name": "Prompt",
                "number_of_augments": 1,
                "prompt_list": [{"prompt": currentPayloadStr}],
                "augmentor_model_type": model,
                "model_type": model,
                "augmentor_model_id": "gpt-4o" if model == "OpenAI" else "",
                "augmentor_api_key_env": "OPENAI_API_KEY" if model == "OpenAI" else "",
                "augment_types": [augment_type],
                "download_csv": False,
                "suppress_terminal_output": False,
                "objective": objective,
                "llm_information": llm_info,
                "special_notes": special_notes  # Include Special Notes
            }
    
            # Make API request
            response_json = self.sendApiRequest(api_payload)
    
            # Process augmented prompts
            augmented_prompts = response_json.get("augmented_prompt_list", [])
            if isinstance(augmented_prompts, list):
                processed_prompts = "\n".join(augmented_prompts)
                return self.helpers.stringToBytes(processed_prompts)
    
        except Exception as e:
            print("ERROR: Exception in processPayload: " + str(e))
    
        return currentPayload
    
    
class AugmentedPromptGenerator(IIntruderPayloadGenerator):
    def __init__(self, prompts):
        self.prompts = prompts
        self.index = 0

    def hasMorePayloads(self):
        return self.index < len(self.prompts)

    def getNextPayload(self, baseValue):
        if self.index < len(self.prompts):
            payload = self.prompts[self.index]
            self.index += 1
            return payload.encode()
        return None

    def reset(self):
        self.index = 0


class AugmentedPromptGeneratorFactory(IIntruderPayloadGeneratorFactory):
    def __init__(self, prompts):
        self.prompts = prompts

    def getGeneratorName(self):
        return "Augmented Prompt Generator"

    def createNewInstance(self, attack):
        return AugmentedPromptGenerator(self.prompts)
