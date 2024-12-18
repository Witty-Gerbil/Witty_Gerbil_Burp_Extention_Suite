#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Updated on Mon Dec 15 12:43:21 2024

@author:
    samuelcameron
    
Credit: Witty Gerbil
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory, IContextMenuInvocation, IMessageEditorController
from burp import IHttpRequestResponse
from java.io import PrintWriter
from javax.swing import (JPanel, JSplitPane, JTable, JScrollPane, JLabel, JButton, 
                         JOptionPane, BoxLayout, Box, SwingConstants, JTabbedPane, JTextArea)
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout
from java.awt.event import MouseAdapter, MouseEvent
from java.util import ArrayList
import json
import threading
import javax

# Import Java classes for HTTP connections
from java.net import URL
from java.io import OutputStreamWriter, BufferedReader, InputStreamReader

class TransactionTableModel(AbstractTableModel):
    def __init__(self, helpers):
        self._helpers = helpers
        self._transactions = []
        self._column_names = ["#", "Method", "URL", "Status", "Length"]

    def getColumnCount(self):
        return len(self._column_names)

    def getRowCount(self):
        return len(self._transactions)

    def getColumnName(self, columnIndex):
        return self._column_names[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        if rowIndex < 0 or rowIndex >= len(self._transactions):
            return ""
        t = self._transactions[rowIndex]
        if columnIndex == 0:
            return rowIndex + 1
        elif columnIndex == 1:
            request_info = self._helpers.analyzeRequest(t)
            return request_info.getMethod()
        elif columnIndex == 2:
            request_info = self._helpers.analyzeRequest(t)
            return str(request_info.getUrl())
        elif columnIndex == 3:
            response = t.getResponse()
            if response:
                response_info = self._helpers.analyzeResponse(response)
                return response_info.getStatusCode()
            else:
                return ""
        elif columnIndex == 4:
            response = t.getResponse()
            if response:
                return len(response)
            else:
                return 0
        return ""

    def addTransaction(self, httpRequestResponse):
        self._transactions.append(httpRequestResponse)
        self.fireTableRowsInserted(len(self._transactions)-1, len(self._transactions)-1)

    def getTransaction(self, rowIndex):
        if rowIndex < 0 or rowIndex >= len(self._transactions):
            return None
        return self._transactions[rowIndex]

    def getAllTransactions(self):
        return self._transactions[:]


class RequestResponseController(IMessageEditorController):
    def __init__(self, helpers):
        self._currentMessage = None
        self._helpers = helpers

    def getHttpService(self):
        if self._currentMessage is None:
            return None
        return self._currentMessage.getHttpService()

    def getRequest(self):
        if self._currentMessage is None:
            return None
        return self._currentMessage.getRequest()

    def getResponse(self):
        if self._currentMessage is None:
            return None
        return self._currentMessage.getResponse()

    def setMessage(self, message):
        self._currentMessage = message


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("Witty Transactions")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        self.initUI()

        print("\n" + "="*50)
        print("Brought to you by: Witty Gerbil 🐹")
        print("="*50 + "\n")

    def initUI(self):
        self.panel = JPanel(BorderLayout())
        
        header = JLabel("Witty Transactions - OpenAI Analysis", JLabel.CENTER)
        self.panel.add(header, BorderLayout.NORTH)

        main_vertical_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        self.transaction_model = TransactionTableModel(self._helpers)
        self.transaction_table = JTable(self.transaction_model)
        scroll_table = JScrollPane(self.transaction_table)
        
        self.main_split.setTopComponent(scroll_table)

        self.rr_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self.main_split.setBottomComponent(self.rr_split)

        self.controller = RequestResponseController(self._helpers)
        self.requestViewer = self._callbacks.createMessageEditor(self.controller, False)
        self.responseViewer = self._callbacks.createMessageEditor(self.controller, False)

        self.rr_split.setLeftComponent(self.requestViewer.getComponent())
        self.rr_split.setRightComponent(self.responseViewer.getComponent())

        self.resultsTabbedPane = JTabbedPane()

        # Renaming tabs to reflect the user's request:
        # - First tab: Security Analysis Results (triggered by a new button "Run Security Analysis")
        # - Second tab: Detailed Insights and Next Steps (former summary)
        # - Third tab: Chatbot Activity Results
        self.securityAnalysisArea = JTextArea()
        self.securityAnalysisArea.setEditable(False)
        self.detailedInsightsArea = JTextArea()
        self.detailedInsightsArea.setEditable(False)
        self.chatbotArea = JTextArea()
        self.chatbotArea.setEditable(False)

        self.resultsTabbedPane.addTab("Security Analysis Results", JScrollPane(self.securityAnalysisArea))
        self.resultsTabbedPane.addTab("Detailed Insights and Next Steps", JScrollPane(self.detailedInsightsArea))
        self.resultsTabbedPane.addTab("Chatbot Activity Results", JScrollPane(self.chatbotArea))

        main_vertical_split.setTopComponent(self.main_split)
        main_vertical_split.setBottomComponent(self.resultsTabbedPane)

        self.panel.add(main_vertical_split, BorderLayout.CENTER)

        button_panel = JPanel()
        button_panel.setLayout(BoxLayout(button_panel, BoxLayout.X_AXIS))
        
        # New button for security analysis:
        security_analysis_button = JButton("Run Security Analysis", actionPerformed=self.run_security_analysis)
        # The summary button now is for the detailed insights and next steps:
        summary_button = JButton("Get Detailed Insights and Next Steps", actionPerformed=self.get_summary)
        chatbot_button = JButton("Find Chatbot Activity", actionPerformed=self.find_chatbot_activity)
        clear_button = JButton("Clear Results", actionPerformed=self.clear_results)

        button_panel.add(Box.createHorizontalGlue())
        button_panel.add(security_analysis_button)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(summary_button)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(chatbot_button)
        button_panel.add(Box.createHorizontalStrut(10))
        button_panel.add(clear_button)
        button_panel.add(Box.createHorizontalGlue())

        self.panel.add(button_panel, BorderLayout.SOUTH)

        self.transaction_table.getSelectionModel().addListSelectionListener(lambda e: self.update_request_response_view())

        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Witty Transactions"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        if (context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY or
            context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST or
            context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE):
    
            menu = ArrayList()
            menu_item = javax.swing.JMenuItem("Send to Witty Transactions", 
                                              actionPerformed=lambda x: self.handle_send_to_openai(invocation))
            menu.add(menu_item)
            return menu
    
        return None

    def handle_send_to_openai(self, invocation):
        # Now we only load the transactions, do not analyze immediately.
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            return
        for msg in selected_messages:
            self.transaction_model.addTransaction(msg)
        JOptionPane.showMessageDialog(self.panel, "Requests sent to Witty Transactions tab. Now click 'Run Security Analysis' when ready.")

    def run_security_analysis(self, event):
        # Extract all transactions and analyze them now
        transactions = self.extract_transactions_data()
        if not transactions:
            JOptionPane.showMessageDialog(self.panel, "No transactions to analyze.")
            return
        thread = threading.Thread(target=self.analyze_messages, args=(transactions,))
        thread.start()

    def analyze_messages(self, transactions):
        # Instead of using selected messages from invocation, we now directly use 'transactions'
        try:
            _, raw_content = self.send_request_to_backend(transactions, "analyze_http_requests_batch")
            formatted = self.format_analysis_results(raw_content)
            self.securityAnalysisArea.append("\n--- New Security Analysis ---\n")
            self.securityAnalysisArea.append(formatted + "\n")

            JOptionPane.showMessageDialog(self.panel, "Security Analysis Complete.\nCheck 'Security Analysis Results' tab.")
            self.stdout.println("Security Analysis Results:\n" + raw_content)

        except Exception as e:
            self.stdout.println("Error during analysis: " + str(e))
            JOptionPane.showMessageDialog(self.panel, "Error during analysis: " + str(e))

    def update_request_response_view(self):
        row = self.transaction_table.getSelectedRow()
        if row < 0:
            self.controller.setMessage(None)
            self.requestViewer.setMessage(None, True)
            self.responseViewer.setMessage(None, False)
            return
        http_message = self.transaction_model.getTransaction(row)
        self.controller.setMessage(http_message)
        self.requestViewer.setMessage(http_message.getRequest(), True)
        self.responseViewer.setMessage(http_message.getResponse(), False)

    def clear_results(self, event):
        self.transaction_model._transactions = []
        self.transaction_model.fireTableDataChanged()
        self.requestViewer.setMessage(None, True)
        self.responseViewer.setMessage(None, False)
        self.controller.setMessage(None)

        self.securityAnalysisArea.setText("")
        self.detailedInsightsArea.setText("")
        self.chatbotArea.setText("")

        self.stdout.println("Transactions and results cleared.")

    def get_summary(self, event):
        transactions = self.extract_transactions_data()
        if not transactions:
            JOptionPane.showMessageDialog(self.panel, "No transactions to summarize.")
            return
        thread = threading.Thread(target=self.run_summary, args=(transactions,))
        thread.start()

    def run_summary(self, transactions):
        try:
            summary = self.send_request_to_backend(transactions, "summary_http_requests_batch")
            self.detailedInsightsArea.append("\n--- New Detailed Insights and Next Steps ---\n")
            self.detailedInsightsArea.append(summary + "\n")

            JOptionPane.showMessageDialog(self.panel, "Detailed insights obtained.\nCheck 'Detailed Insights and Next Steps' tab.")
        except Exception as e:
            self.stderr.println("Error getting detailed insights: " + str(e))
            JOptionPane.showMessageDialog(self.panel, "Error getting detailed insights: " + str(e))

    def find_chatbot_activity(self, event):
        transactions = self.extract_transactions_data()
        if not transactions:
            JOptionPane.showMessageDialog(self.panel, "No transactions to analyze.")
            return
        thread = threading.Thread(target=self.run_chatbot_activity, args=(transactions,))
        thread.start()

    def run_chatbot_activity(self, transactions):
        try:
            result = self.send_request_to_backend(transactions, "find_chatbot_activity")
            
            if isinstance(result, dict):
                result_str = json.dumps(result, indent=2)
            else:
                try:
                    parsed = json.loads(result)
                    result_str = json.dumps(parsed, indent=2)
                except:
                    result_str = str(result)

            formatted = self.format_chatbot_activity_results(result_str)
            self.chatbotArea.append("\n--- New Chatbot Activity Analysis ---\n")
            self.chatbotArea.append(formatted + "\n")
    
            JOptionPane.showMessageDialog(self.panel, "Chatbot activity analysis complete.\nCheck the 'Chatbot Activity Results' tab.")
        except Exception as e:
            self.stderr.println("Error finding chatbot activity: " + str(e))
            JOptionPane.showMessageDialog(self.panel, "Error finding chatbot activity: " + str(e))

    def extract_transactions_data(self):
        transactions = []
        all_msgs = self.transaction_model.getAllTransactions()
        for msg in all_msgs:
            request = msg.getRequest()
            response = msg.getResponse()
            request_str = self._helpers.bytesToString(request).decode('utf-8', 'replace')
            if response:
                response_str = self._helpers.bytesToString(response).decode('utf-8', 'replace')
            else:
                response_str = "No response available"
            sanitized_request = self.sanitize_request(request_str)
            sanitized_response = self.sanitize_request(response_str)
            transactions.append({
                "request": sanitized_request,
                "response": sanitized_response
            })
        return transactions

    def send_request_to_backend(self, transactions, endpoint_name):
        try:
            BACKEND_API_URL = "http://localhost:8000/api/v1/{}/".format(endpoint_name)
            headers = {
                "Content-Type": "application/json"
            }

            payload = {
                "model_id": "gpt-4o",
                "transactions": transactions
            }

            self.stdout.println("Payload sent to {}:\n{}".format(endpoint_name, json.dumps(payload, indent=2)))

            json_data = json.dumps(payload)

            url = URL(BACKEND_API_URL)
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", headers["Content-Type"])

            output_stream = OutputStreamWriter(connection.getOutputStream(), 'UTF-8')
            output_stream.write(json_data)
            output_stream.flush()
            output_stream.close()

            response_code = connection.getResponseCode()
            self.stdout.println("{} Response Code: {}".format(endpoint_name, response_code))

            if 200 <= response_code < 300:
                input_stream = BufferedReader(InputStreamReader(connection.getInputStream(), 'UTF-8'))
                response = ""
                line = input_stream.readLine()
                while line:
                    response += line
                    line = input_stream.readLine()
                input_stream.close()

                response_json = json.loads(response)
                if endpoint_name == "analyze_http_requests_batch":
                    raw_content = json.dumps(response_json, indent=2)
                    return "", raw_content
                elif endpoint_name == "summary_http_requests_batch":
                    summary = response_json.get("summary", "No summary available.")
                    return summary
                elif endpoint_name == "find_chatbot_activity":
                    result = response_json.get("analysis", "No analysis available.")
                    return result
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), 'UTF-8'))
                error_response = ""
                line = error_stream.readLine()
                while line:
                    error_response += line
                    line = error_stream.readLine()
                error_stream.close()
                raise Exception("API Error " + str(response_code) + ": " + error_response)

        except Exception as e:
            raise Exception("Error while sending request to backend API: " + str(e))

    def sanitize_request(self, request_str):
        try:
            sanitized = request_str.encode('utf-8', 'replace').decode('utf-8')
            return sanitized
        except Exception as e:
            self.stdout.println("Error sanitizing request: {}".format(str(e)))
            return request_str

    def format_analysis_results(self, raw_json_str):
        """
        Format the analysis results returned by the backend.

        The returned JSON can have:
        {
          "TRANSACTION ANALYSIS": {
             ... single transaction analysis ...
          }
        }
        OR
        {
          "TRANSACTION ANALYSIS": [
            { ... analysis for tx #1 ...},
            { ... analysis for tx #2 ...},
            ...
          ]
        }

        We'll handle both cases. If it's a list, we'll print each one in a loop.
        """
        try:
            data = json.loads(raw_json_str)
            analyses = data.get("TRANSACTION ANALYSIS", [])

            if isinstance(analyses, dict):
                analyses = [analyses]

            if not isinstance(analyses, list):
                return "No valid analysis data found."

            if len(analyses) == 0:
                return "No transactions analyzed."

            formatted = ""
            for analysis in analyses:
                req_num = analysis.get("Request Number", "N/A")
                threat_level = analysis.get("Threat Level", "N/A")
                threats = analysis.get("Detected Threats", [])
                if not threats:
                    threats = ["None detected"]
                explanation = analysis.get("Explanation", "No explanation.")

                formatted += (
                    "----------------------------------------\n"
                    "Transaction Analysis for Request #{}:\n"
                    "Threat Level: {}\n"
                    "Detected Threats: {}\n"
                    "Explanation:\n{}\n"
                    "----------------------------------------\n\n"
                ).format(req_num, threat_level, ", ".join(threats), explanation)

            return formatted.strip()

        except Exception as e:
            return "Error formatting analysis results: {}\n{}".format(str(e), raw_json_str)


    def format_chatbot_activity_results(self, raw_json_str):
        try:
            data = json.loads(raw_json_str)
            activities = data.get("transactions_with_chatbot_activity", [])
            if not activities:
                return "No chatbot activity found."
            formatted = "Chatbot Activity Detected:\n"
            for act in activities:
                tnum = act.get("transaction_number", "N/A")
                explanation = act.get("explanation", "No explanation")
                formatted += "\n- Transaction #{}:\n  {}\n".format(tnum, explanation)
            return formatted
        except Exception as e:
            return "Error formatting chatbot activity results: {}\n{}".format(str(e), raw_json_str)
