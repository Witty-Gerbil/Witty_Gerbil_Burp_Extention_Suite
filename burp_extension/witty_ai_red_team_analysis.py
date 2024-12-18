#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Revised Extension Code
- Fixed benchmarking ASCII issues by writing UTF-8 encoded bytes to CSV
- Replaced HTTP/2 with HTTP/1.1 in request line for resend request
- Added extra debug prints
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from java.awt import BorderLayout, FlowLayout, Dimension, Color, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from javax.swing import (
    JPanel, JTable, JTextArea, JScrollPane, BorderFactory,
    ListSelectionModel, JSplitPane, JLabel,
    JTabbedPane, JButton, JMenuItem, JFileChooser, JOptionPane
)
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.util import ArrayList
from java.lang import Thread, Runnable
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import csv
import os
import time
import base64

class PieChartPanel(JPanel):
    def __init__(self, title, data, colors):
        super(PieChartPanel, self).__init__()
        self.title = title
        self.data = data
        self.colors = colors

    def paintComponent(self, g):
        super(PieChartPanel, self).paintComponent(g)
        if not self.data:
            return
        g.setColor(Color.BLACK)
        g.drawString(self.title, 10, 20)
        total = sum(self.data.values())
        if total == 0:
            return
        width = self.getWidth()
        height = self.getHeight()
        diameter = min(width, height) - 100
        start_angle = 0
        for label, value in self.data.items():
            angle = (float(value) / float(total)) * 360.0
            g.setColor(self.colors.get(label, Color.GRAY))
            g.fillArc(50, 50, diameter, diameter, int(start_angle), int(angle))
            start_angle += angle
        x = 50
        y = 50 + diameter + 20
        for label in self.data:
            g.setColor(self.colors.get(label, Color.GRAY))
            g.fillRect(x, y, 10, 10)
            g.setColor(Color.BLACK)
            g.drawString(label, x + 15, y + 10)
            y += 15

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory, ListSelectionListener, ActionListener):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.callbacks.setExtensionName("Witty Analysis")
        self.callbacks.registerContextMenuFactory(self)
        self.callbacks.registerHttpListener(self)

        self.panel = JPanel(BorderLayout())
        topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        topPanel.add(JLabel("Witty Analysis Extension"))
        self.panel.add(topPanel, BorderLayout.NORTH)

        self.resultsTableModel = DefaultTableModel(["Index", "Request", "Response", "Status"], 0)
        self.resultsTable = JTable(self.resultsTableModel)
        self.resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.resultsTable.getSelectionModel().addListSelectionListener(self)

        resultsScrollPane = JScrollPane(self.resultsTable)
        resultsScrollPane.setBorder(BorderFactory.createTitledBorder("Intruder Results"))

        exportPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        exportButton = JButton("Export Results")
        exportButton.setActionCommand("export_results")
        exportButton.addActionListener(self)
        exportPanel.add(exportButton)

        self.scoreAllButton = JButton("Score All")
        self.scoreAllButton.setActionCommand("score_all")
        self.scoreAllButton.addActionListener(self)
        exportPanel.add(self.scoreAllButton)

        self.benchmarkButton = JButton("Benchmark")
        self.benchmarkButton.setActionCommand("benchmark")
        self.benchmarkButton.addActionListener(self)
        exportPanel.add(self.benchmarkButton)

        resultsPaneContainer = JPanel(BorderLayout())
        resultsPaneContainer.add(resultsScrollPane, BorderLayout.CENTER)
        resultsPaneContainer.add(exportPanel, BorderLayout.NORTH)

        requestPanel = JPanel(BorderLayout())
        self.requestTextArea = JTextArea(10, 40)
        self.requestTextArea.setEditable(True)
        requestScrollPane = JScrollPane(self.requestTextArea)
        requestScrollPane.setBorder(BorderFactory.createTitledBorder("Request Details"))

        resendButton = JButton("Resend")
        resendButton.setActionCommand("resend_request")
        resendButton.addActionListener(self)
        buttonPanel = JPanel(BorderLayout())
        buttonPanel.add(resendButton, BorderLayout.EAST)

        requestPanel.add(requestScrollPane, BorderLayout.CENTER)
        requestPanel.add(buttonPanel, BorderLayout.NORTH)

        self.responseTextArea = JTextArea(10, 40)
        self.responseTextArea.setEditable(False)
        responseScrollPane = JScrollPane(self.responseTextArea)
        responseScrollPane.setBorder(BorderFactory.createTitledBorder("Response Details"))

        detailsSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, requestPanel, responseScrollPane)
        detailsSplitPane.setResizeWeight(0.5)

        leftSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, resultsPaneContainer, detailsSplitPane)
        leftSplitPane.setResizeWeight(0.3)
        leftSplitPane.setDividerLocation(300)

        rightPanel = JPanel(BorderLayout())
        self.tabbedPane = JTabbedPane()

        mainAnalysisPanel = JPanel(BorderLayout())
        self.llmAnalysisButton = JButton("Analyze Request/Response Pair")
        self.llmAnalysisButton.setActionCommand("analyze_client_request")
        self.llmAnalysisButton.addActionListener(self)
        mainAnalysisPanel.add(self.llmAnalysisButton, BorderLayout.NORTH)

        self.llmAnalysisOutput = JTextArea(10, 20)
        self.llmAnalysisOutput.setEditable(False)
        self.llmAnalysisOutput.setLineWrap(True)
        self.llmAnalysisOutput.setWrapStyleWord(True)
        analysisScrollPane = JScrollPane(self.llmAnalysisOutput)
        analysisScrollPane.setBorder(BorderFactory.createTitledBorder("Analysis Output"))
        mainAnalysisPanel.add(analysisScrollPane, BorderLayout.CENTER)

        self.tabbedPane.addTab("Main Analysis", mainAnalysisPanel)

        option_text_mapping = {
            "analyze_get_params": "Suggest GET Parameters",
            "analyze_post_params": "Suggest POST Parameters",
            "find_endpoints": "Suggest Endpoints",
            "check_headers": "Suggest Headers",
            "review_server_response": "Analyze Server Response"
        }

        for option_key, option_text in option_text_mapping.items():
            self.addOptionTab(option_key, option_text)

        benchmarkingPanel = self.createBenchmarkingTab()
        self.tabbedPane.addTab("Benchmarking", benchmarkingPanel)

        rightPanel.add(self.tabbedPane, BorderLayout.CENTER)
        mainSplitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplitPane, rightPanel)
        mainSplitPane.setResizeWeight(0.7)
        mainSplitPane.setDividerLocation(800)
        self.panel.add(mainSplitPane, BorderLayout.CENTER)

        self.messageInfos = {}
        self.callbacks.addSuiteTab(self)

        print("\n" + "="*50)
        print("Witty Analysis Extension Loaded 🐹")
        print("="*50 + "\n")

    def addOptionTab(self, option_key, option_text):
        tabPanel = JPanel(BorderLayout())
        optionButton = JButton(option_text)
        optionButton.setActionCommand("option_" + option_key)
        optionButton.addActionListener(self)
        tabPanel.add(optionButton, BorderLayout.NORTH)

        outputTextArea = JTextArea(10, 40)
        outputTextArea.setEditable(False)
        outputTextArea.setLineWrap(True)
        outputTextArea.setWrapStyleWord(True)
        outputScrollPane = JScrollPane(outputTextArea)
        outputScrollPane.setBorder(BorderFactory.createTitledBorder(option_text + " Output"))
        tabPanel.add(outputScrollPane, BorderLayout.CENTER)

        setattr(self, option_key + "_output", outputTextArea)
        self.tabbedPane.addTab(option_text, tabPanel)

    def createBenchmarkingTab(self):
        benchmarkingPanel = JPanel(BorderLayout())
        topBenchmarkPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        runBenchmarkButton = JButton("Run Benchmark")
        runBenchmarkButton.setActionCommand("run_benchmark")
        runBenchmarkButton.addActionListener(self)
        topBenchmarkPanel.add(runBenchmarkButton)

        selectFileLabel = JLabel("Benchmark results will be saved automatically.")
        topBenchmarkPanel.add(selectFileLabel)

        self.selectedFilePathLabel = JLabel("No file selected.")
        topBenchmarkPanel.add(self.selectedFilePathLabel)
        benchmarkingPanel.add(topBenchmarkPanel, BorderLayout.NORTH)

        metricsPanel = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.insets = Insets(10, 10, 10, 10)
        constraints.anchor = GridBagConstraints.WEST

        def addMetricRow(y, labelText, lblVar):
            constraints.gridx = 0
            constraints.gridy = y
            metricsPanel.add(JLabel(labelText), constraints)
            constraints.gridx = 1
            metricsPanel.add(lblVar, constraints)

        self.benchmark_total_requests_label = JLabel("0")
        addMetricRow(0, "Total Requests:", self.benchmark_total_requests_label)
        self.benchmark_pass_count_label = JLabel("0")
        addMetricRow(1, "Pass Count:", self.benchmark_pass_count_label)
        self.benchmark_fail_count_label = JLabel("0")
        addMetricRow(2, "Fail Count:", self.benchmark_fail_count_label)
        self.benchmark_pass_percentage_label = JLabel("0.0")
        addMetricRow(3, "Pass Percentage (%):", self.benchmark_pass_percentage_label)
        self.benchmark_fail_percentage_label = JLabel("0.0")
        addMetricRow(4, "Fail Percentage (%):", self.benchmark_fail_percentage_label)

        constraints.gridx = 0
        constraints.gridy = 5
        constraints.gridwidth = 2
        metricsPanel.add(JLabel("Pass/Fail Distribution:"), constraints)

        scorePieData = {"Pass": 0, "Fail": 0}
        scorePieColors = {"Pass": Color.GREEN, "Fail": Color.RED}
        self.benchmark_score_pie_chart = PieChartPanel("Pass vs Fail", scorePieData, scorePieColors)
        self.benchmark_score_pie_chart.setPreferredSize(Dimension(400, 300))
        constraints.gridy = 6
        metricsPanel.add(self.benchmark_score_pie_chart, constraints)

        constraints.gridx = 0
        constraints.gridy = 7
        constraints.gridwidth = 2
        metricsPanel.add(JLabel("Word Frequencies of Failed Responses:"), constraints)

        self.benchmark_word_freq_table_model = DefaultTableModel(["Word", "Frequency"], 0)
        self.benchmark_word_freq_table = JTable(self.benchmark_word_freq_table_model)
        self.benchmark_word_freq_table.setAutoCreateRowSorter(True)
        benchmark_word_freq_scroll_pane = JScrollPane(self.benchmark_word_freq_table)
        benchmark_word_freq_scroll_pane.setPreferredSize(Dimension(300, 150))
        constraints.gridy = 8
        metricsPanel.add(benchmark_word_freq_scroll_pane, constraints)

        constraints.gridx = 0
        constraints.gridy = 9
        constraints.gridwidth = 2
        metricsPanel.add(JLabel("Additional Metrics:"), constraints)

        constraints.gridy = 10
        metricsPanel.add(JLabel("Status Code Distribution:"), constraints)

        self.benchmark_status_code_table_model = DefaultTableModel(["Status Code", "Count"], 0)
        self.benchmark_status_code_table = JTable(self.benchmark_status_code_table_model)
        self.benchmark_status_code_table.setAutoCreateRowSorter(True)
        benchmark_status_code_scroll_pane = JScrollPane(self.benchmark_status_code_table)
        benchmark_status_code_scroll_pane.setPreferredSize(Dimension(300, 150))
        constraints.gridy = 11
        metricsPanel.add(benchmark_status_code_scroll_pane, constraints)

        constraints.gridx = 0
        constraints.gridy = 12
        constraints.gridwidth = 1
        metricsPanel.add(JLabel("Average Response Length:"), constraints)
        self.benchmark_avg_response_length_label = JLabel("0.0")
        constraints.gridx = 1
        metricsPanel.add(self.benchmark_avg_response_length_label, constraints)

        constraints.gridx = 0
        constraints.gridy = 13
        metricsPanel.add(JLabel("Average Request Length:"), constraints)
        self.benchmark_avg_request_length_label = JLabel("0.0")
        constraints.gridx = 1
        metricsPanel.add(self.benchmark_avg_request_length_label, constraints)

        constraints.gridx = 0
        constraints.gridy = 14
        metricsPanel.add(JLabel("Unique Endpoints:"), constraints)
        self.benchmark_unique_endpoints_label = JLabel("0")
        constraints.gridx = 1
        metricsPanel.add(self.benchmark_unique_endpoints_label, constraints)

        benchmarkingPanel.add(metricsPanel, BorderLayout.CENTER)
        return benchmarkingPanel

    def getTabCaption(self):
        return "Witty Analysis"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu = ArrayList()
        selectedMessages = invocation.getSelectedMessages()
        if selectedMessages:
            menuItem = JMenuItem("Send to Witty Analysis", actionPerformed=lambda x: self.sendToViewer(selectedMessages))
            menu.add(menuItem)
        return menu

    def sendToViewer(self, selectedMessages):
        for messageInfo in selectedMessages:
            try:
                request = messageInfo.getRequest()
                response = messageInfo.getResponse()

                if request:
                    analyzedRequest = self.helpers.analyzeRequest(request)
                    method = analyzedRequest.getMethod()
                    headers = analyzedRequest.getHeaders()
                    payload = self.helpers.bytesToString(request[analyzedRequest.getBodyOffset():])
                    requestSummary = "{} {}".format(method, (headers[0] if headers else "No URL")) + " (Payload: {})".format(payload)
                else:
                    requestSummary = "No Request Data"

                if response:
                    analyzedResponse = self.helpers.analyzeResponse(response)
                    status = str(analyzedResponse.getStatusCode())
                    body = self.helpers.bytesToString(response[analyzedResponse.getBodyOffset():])
                    responseSummary = body[:100]
                else:
                    status = "N/A"
                    responseSummary = "No Response Data"

                rowIndex = self.resultsTableModel.getRowCount()
                self.resultsTableModel.addRow([rowIndex, requestSummary, responseSummary, status])

                self.messageInfos[rowIndex] = {
                    "request": self.helpers.bytesToString(request) if request else "",
                    "response": self.helpers.bytesToString(response) if response else ""
                }

            except Exception as e:
                print("Error processing message:", str(e))

    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            selectedRow = self.resultsTable.getSelectedRow()
            if selectedRow >= 0:
                messageInfo = self.messageInfos.get(selectedRow)
                if messageInfo:
                    request = messageInfo.get("request", "No Request")
                    response = messageInfo.get("response", "No Response")
                    self.requestTextArea.setText(request)
                    self.requestTextArea.setCaretPosition(0)
                    self.responseTextArea.setText(response)
                    self.responseTextArea.setCaretPosition(0)

    def runOptionAnalysis(self, option_key):
        selectedRow = self.resultsTable.getSelectedRow()
        if selectedRow < 0:
            self.updateOptionOutput(option_key, "Error: No request/response pair selected.")
            return
        messageInfo = self.messageInfos.get(selectedRow)
        if not messageInfo:
            self.updateOptionOutput(option_key, "Error: Could not retrieve request/response for analysis.")
            return
        request = messageInfo.get("request", "")
        response = messageInfo.get("response", "")
        redacted_request = self.redact_sensitive_headers(request)
        payload = {
            "option_key": option_key,
            "request_text": redacted_request,
            "response_text": response
        }
        try:
            url = URL("http://127.0.0.1:8000/api/v1/option_analyze")
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")

            outputStream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            outputStream.write(json.dumps(payload))
            outputStream.flush()
            outputStream.close()

            response_code = connection.getResponseCode()
            if 200 <= response_code < 300:
                inputStream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                responseStr = u""
                line = inputStream.readLine()
                while line:
                    responseStr += line + u"\n"
                    line = inputStream.readLine()
                inputStream.close()
                responseJson = json.loads(responseStr)
                result = responseJson.get("analysis", "No analysis provided.")
                self.updateOptionOutput(option_key, result)
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), "UTF-8"))
                error_response = u""
                line = error_stream.readLine()
                while line:
                    error_response += line + u"\n"
                    line = error_stream.readLine()
                error_stream.close()
                self.updateOptionOutput(option_key, "Error from server: " + error_response)
        except Exception as e:
            self.updateOptionOutput(option_key, "Error: " + str(e))

    def updateOptionOutput(self, option_key, text):
        output_text_area = getattr(self, option_key + "_output", None)
        if output_text_area:
            output_text_area.setText(text)
            output_text_area.setCaretPosition(0)

    def redact_sensitive_headers(self, request_string):
        sensitive_headers = ["cookie", "authorization"]
        lines = request_string.splitlines()
        new_lines = []
        for line in lines:
            lower_line = line.lower()
            if any(lower_line.startswith(h + ":") for h in sensitive_headers):
                header_name = line.split(":",1)[0]
                new_lines.append(header_name + ": [REDACTED]")
            else:
                new_lines.append(line)
        return "\r\n".join(new_lines)

    def runLLMAnalysis(self):
        selectedRow = self.resultsTable.getSelectedRow()
        if selectedRow < 0:
            self.llmAnalysisOutput.setText("Error: No request/response pair selected.")
            return

        messageInfo = self.messageInfos.get(selectedRow)
        if not messageInfo:
            self.llmAnalysisOutput.setText("Error: Could not retrieve request/response for analysis.")
            return

        request = messageInfo.get("request", "")
        response = messageInfo.get("response", "")

        payload = {
            "string_one": request,
            "string_two": response
        }

        try:
            url = URL("http://127.0.0.1:8000/api/v1/analyzehttptransaction/")
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")

            outputStream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            outputStream.write(json.dumps(payload))
            outputStream.flush()
            outputStream.close()

            response_code = connection.getResponseCode()
            if 200 <= response_code < 300:
                inputStream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                responseStr = u""
                line = inputStream.readLine()
                while line:
                    responseStr += line + u"\n"
                    line = inputStream.readLine()
                inputStream.close()
                responseJson = json.loads(responseStr)
                analysis = responseJson.get("analysis", "No analysis provided.")
                self.llmAnalysisOutput.setText(analysis)
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), "UTF-8"))
                error_response = u""
                line = error_stream.readLine()
                while line:
                    error_response += line + u"\n"
                    line = error_stream.readLine()
                error_stream.close()
                self.llmAnalysisOutput.setText("Error: " + error_response)

        except Exception as e:
            self.llmAnalysisOutput.setText("Error calling backend:\n" + str(e))

    def runScoreAllAnalysis(self):
        if "Score" not in [self.resultsTableModel.getColumnName(i) for i in range(self.resultsTableModel.getColumnCount())]:
            self.resultsTableModel.addColumn("Score")

        scoreColumnIndex = self.resultsTableModel.getColumnCount() - 1
        data = []
        for rowIndex in range(self.resultsTableModel.getRowCount()):
            messageInfo = self.messageInfos.get(rowIndex)
            if messageInfo:
                data.append({
                    "request": messageInfo.get("request", ""),
                    "response": messageInfo.get("response", "")
                })
            else:
                data.append({"request": "", "response": ""})

        payload = {
            "data": data
        }

        try:
            url = URL("http://127.0.0.1:8000/api/v1/analyzehttptransaction_scorer/bulk_score")
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")

            outputStream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            outputStream.write(json.dumps(payload))
            outputStream.flush()
            outputStream.close()

            response_code = connection.getResponseCode()
            if 200 <= response_code < 300:
                inputStream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                responseStr = u""
                line = inputStream.readLine()
                while line:
                    responseStr += line + u"\n"
                    line = inputStream.readLine()
                inputStream.close()

                responseJson = json.loads(responseStr)
                scores = responseJson.get("scores", [])
                for i, score in enumerate(scores):
                    self.resultsTableModel.setValueAt(score, i, scoreColumnIndex)

                JOptionPane.showMessageDialog(self.panel, "Scoring completed successfully.")
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), "UTF-8"))
                error_response = u""
                line = error_stream.readLine()
                while line:
                    error_response += line + u"\n"
                    line = error_stream.readLine()
                error_stream.close()
                JOptionPane.showMessageDialog(self.panel, "Error from scoring API: " + error_response, "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.panel, "Error during Score All:\n" + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def runBenchmark(self):
        try:
            benchmark_dir = os.path.join(os.getcwd(), 'benchmark_data')
            if not os.path.exists(benchmark_dir):
                os.makedirs(benchmark_dir)

            timestamp = time.strftime("%Y%m%d-%H%M%S")
            csv_filename = "benchmark_data_{}.csv".format(timestamp)
            csv_filepath = os.path.join(benchmark_dir, csv_filename)

            # Write CSV in binary mode and UTF-8 encode each field
            with open(csv_filepath, 'wb') as csvfile:
                writer = csv.writer(csvfile)
                # Encode headers
                headers = []
                for i in range(self.resultsTableModel.getColumnCount()):
                    h = self.resultsTableModel.getColumnName(i)
                    if not isinstance(h, unicode):
                        h = unicode(h, 'utf-8', 'replace')
                    headers.append(h.encode('utf-8', 'replace'))
                writer.writerow(headers)

                for row in range(self.resultsTableModel.getRowCount()):
                    rowData = []
                    for col in range(self.resultsTableModel.getColumnCount()):
                        val = self.resultsTableModel.getValueAt(row, col)
                        if val is None:
                            val = u""
                        if not isinstance(val, unicode):
                            # Convert to unicode
                            # If it's str, assume utf-8 or fallback
                            try:
                                val = unicode(str(val), 'utf-8', 'replace')
                            except:
                                val = unicode(val)
                        # Now val is unicode, encode to utf-8 bytes
                        val = val.encode('utf-8', 'replace')
                        rowData.append(val)
                    writer.writerow(rowData)

            print("Benchmarking CSV file saved to:", csv_filepath)
            payload = {
                "file_path": csv_filepath
            }

            url = URL("http://127.0.0.1:8000/api/v1/burp_suite_extention_benchmarker/analyze")
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")

            outputStream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            outputStream.write(json.dumps(payload))
            outputStream.flush()
            outputStream.close()

            response_code = connection.getResponseCode()
            print("Benchmark response code:", response_code)
            if 200 <= response_code < 300:
                inputStream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                responseStr = u""
                line = inputStream.readLine()
                while line:
                    responseStr += line + u"\n"
                    line = inputStream.readLine()
                inputStream.close()

                responseJson = json.loads(responseStr)
                self.updateBenchmarkingMetrics(responseJson)
                self.selectedFilePathLabel.setText(csv_filename)
                JOptionPane.showMessageDialog(self.panel, "Benchmarking completed successfully.", "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), "UTF-8"))
                error_response = u""
                line = error_stream.readLine()
                while line:
                    error_response += line + u"\n"
                    line = error_stream.readLine()
                error_stream.close()
                raise Exception("Benchmarking API Error " + str(response_code) + ": " + error_response)
        except Exception as e:
            print("Error during Benchmarking:", str(e))
            JOptionPane.showMessageDialog(self.panel, "Error during Benchmarking:\n" + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def updateBenchmarkingMetrics(self, data):
        try:
            self.benchmark_total_requests_label.setText(str(data.get("total_requests", 0)))
            self.benchmark_pass_count_label.setText(str(data.get("pass_count", 0)))
            self.benchmark_fail_count_label.setText(str(data.get("fail_count", 0)))
            self.benchmark_pass_percentage_label.setText("{0:.2f}".format(data.get("pass_percentage", 0.0)))
            self.benchmark_fail_percentage_label.setText("{0:.2f}".format(data.get("fail_percentage", 0.0)))

            scorePieData = {
                "Pass": data.get("pass_count", 0),
                "Fail": data.get("fail_count", 0)
            }
            self.benchmark_score_pie_chart.data = scorePieData
            self.benchmark_score_pie_chart.repaint()

            self.benchmark_word_freq_table_model.setRowCount(0)
            failed_word_freq = data.get("failed_word_frequencies", {})
            sorted_words = sorted(failed_word_freq.items(), key=lambda x: x[1], reverse=True)[:20]
            for word, freq in sorted_words:
                if not isinstance(word, unicode):
                    word = unicode(word, 'utf-8', 'replace')
                # freq is int, convert to str
                self.benchmark_word_freq_table_model.addRow([word, str(freq)])

            additional_metrics = data.get("additional_metrics", {})
            status_code_distribution = additional_metrics.get("status_code_distribution", {})
            self.benchmark_status_code_table_model.setRowCount(0)
            for sc, cnt in status_code_distribution.items():
                if not isinstance(sc, unicode):
                    sc = unicode(sc, 'utf-8', 'replace')
                self.benchmark_status_code_table_model.addRow([sc, str(cnt)])

            self.benchmark_avg_response_length_label.setText(str(additional_metrics.get("average_response_length", 0.0)))
            self.benchmark_avg_request_length_label.setText(str(additional_metrics.get("average_request_length", 0.0)))
            self.benchmark_unique_endpoints_label.setText(str(additional_metrics.get("unique_endpoints", 0)))

        except Exception as e:
            print("Error updating benchmarking metrics:", str(e))

    def resendRequest(self):
        try:
            editedRequest = self.requestTextArea.getText()
            print("Debug: Original Edited Request:\n", editedRequest)
    
            if not editedRequest.strip():
                print("Error: Request is empty.")
                return
    
            # Split lines on any newline, then normalize to CRLF later
            lines = editedRequest.replace('\r\n','\n').split('\n')
            if not lines:
                print("Error: No lines in request")
                return
    
            # Fix request line if it has HTTP/2 -> HTTP/1.1
            request_line_parts = lines[0].split(' ')
            if len(request_line_parts) < 3:
                print("Error: Invalid request line format.")
                return
    
            if request_line_parts[-1].upper().strip() == "HTTP/2":
                request_line_parts[-1] = "HTTP/1.1"
                lines[0] = " ".join(request_line_parts)
                print("Debug: Changed HTTP/2 to HTTP/1.1 in request line")
    
            # Extract host and prepare lines
            host = None
            normalized_lines = []
            for line in lines:
                stripped_line = line.rstrip('\r\n')
                if stripped_line.lower().startswith("host:"):
                    host = stripped_line.split(":", 1)[1].strip()
                normalized_lines.append(stripped_line)
    
            if not host:
                print("Error: Host header not found.")
                return
    
            # Now we must recalculate Content-Length if present
            # First, separate headers and body
            # Find the blank line that separates headers from the body
            # If none found, it might be a request without a body (then Content-Length might not matter)
            blank_line_index = None
            for i, l in enumerate(normalized_lines):
                if l.strip() == "":
                    blank_line_index = i
                    break
    
            # finalRequest construction
            # We'll join with CRLF and add CRLFCRLF after headers if needed
            if blank_line_index is not None:
                # Headers are everything before blank_line_index
                # Body is after that index
                headers = normalized_lines[:blank_line_index]
                body_lines = normalized_lines[blank_line_index+1:]
            else:
                # No blank line found means no body
                headers = normalized_lines
                body_lines = []
    
            # Body combined
            body = "\r\n".join(body_lines)
            # Recalculate Content-Length if present
            # Content-Length should be length of body in bytes (assuming ASCII/UTF-8)
            body_bytes = body.encode('utf-8')  # Convert to bytes to get correct length
            new_length = len(body_bytes)
            updated_headers = []
            length_found = False
            for h in headers:
                if h.lower().startswith("content-length:"):
                    print("Debug: Old Content-Length header:", h)
                    updated_headers.append("Content-Length: {}".format(new_length))
                    length_found = True
                else:
                    updated_headers.append(h)
    
            # If no length was found but we do have a body, consider adding it if original request had it.
            # Usually we don't add Content-Length if not present, but most servers require it for POST.
            # If original had no content-length and there is a body, let's assume not needed.
            # If original had it, we replaced it above.
    
            final_headers_str = "\r\n".join(updated_headers)
            if body_lines:
                finalRequest = final_headers_str + "\r\n\r\n" + body
            else:
                finalRequest = final_headers_str + "\r\n\r\n"
    
            print("Debug: Final Request Sent:\n", finalRequest)
            print("Debug: Host extracted:", host)
            print("Debug: Calculated Content-Length:", new_length)
    
            class SendRequestRunnable(Runnable):
                def __init__(self, extender, finalRequest, host):
                    self.extender = extender
                    self.finalRequest = finalRequest
                    self.host = host
    
                def run(self):
                    try:
                        requestBytes = self.extender.helpers.stringToBytes(self.finalRequest)
                        print("Debug: Making HTTP request to:", self.host)
                        responseBytes = self.extender.callbacks.makeHttpRequest(self.host, 443, True, requestBytes)
                        print("Debug: Request sent successfully.")
    
                        if responseBytes:
                            analyzedResponse = self.extender.helpers.analyzeResponse(responseBytes)
                            status = str(analyzedResponse.getStatusCode())
                            response_body = self.extender.helpers.bytesToString(responseBytes[analyzedResponse.getBodyOffset():])[:100]
                        else:
                            status = "N/A"
                            response_body = "No Response Data"
    
                        analyzedRequest = self.extender.helpers.analyzeRequest(requestBytes)
                        method = analyzedRequest.getMethod()
                        headers = analyzedRequest.getHeaders()
                        payload = self.extender.helpers.bytesToString(requestBytes[analyzedRequest.getBodyOffset():])
                        requestSummary = "{} {}".format(method, (headers[0] if headers else "No URL")) + " (Payload: {})".format(payload)
    
                        def updateUI():
                            rowIndex = self.extender.resultsTableModel.getRowCount()
                            self.extender.resultsTableModel.addRow([rowIndex, requestSummary, response_body, status])
                            self.extender.messageInfos[rowIndex] = {
                                "request": self.extender.helpers.bytesToString(requestBytes),
                                "response": self.extender.helpers.bytesToString(responseBytes) if responseBytes else ""
                            }
                        from javax.swing import SwingUtilities
                        SwingUtilities.invokeLater(updateUI)
    
                    except Exception as e:
                        print("Error sending request in thread:", str(e))
    
            thread = Thread(SendRequestRunnable(self, finalRequest, host))
            thread.start()
    
        except Exception as e:
            print("Error in resendRequest:", str(e))


    def exportResultsHandler(self):
        formats = ["csv", "excel", "parquet"]
        format_choice = JOptionPane.showInputDialog(self.panel, "Choose export format:", "Export Format", JOptionPane.PLAIN_MESSAGE, None, formats, formats[0])
        if format_choice is None:
            return

        headers = [self.resultsTableModel.getColumnName(i) for i in range(self.resultsTableModel.getColumnCount())]
        rows = []
        for r in range(self.resultsTableModel.getRowCount()):
            rowData = []
            for c in range(self.resultsTableModel.getColumnCount()):
                val = self.resultsTableModel.getValueAt(r, c)
                if val is None:
                    val = u""
                if not isinstance(val, unicode):
                    # Convert to unicode safely
                    try:
                        val = unicode(str(val), 'utf-8', 'replace')
                    except:
                        val = unicode(val)
                rowData.append(val)
            rows.append(rowData)

        payload = {
            "headers": headers,
            "rows": rows,
            "format": format_choice
        }

        try:
            url = URL("http://127.0.0.1:8000/api/v1/export")
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Accept", "application/json")

            outputStream = OutputStreamWriter(connection.getOutputStream(), "UTF-8")
            outputStream.write(json.dumps(payload))
            outputStream.flush()
            outputStream.close()

            response_code = connection.getResponseCode()
            if 200 <= response_code < 300:
                inputStream = BufferedReader(InputStreamReader(connection.getInputStream(), "UTF-8"))
                responseStr = u""
                line = inputStream.readLine()
                while line:
                    responseStr += line + u"\n"
                    line = inputStream.readLine()
                inputStream.close()

                responseJson = json.loads(responseStr)
                file_content_b64 = responseJson.get("file_content_base64", "")
                if not file_content_b64:
                    JOptionPane.showMessageDialog(self.panel, "No file content returned by backend.", "Error", JOptionPane.ERROR_MESSAGE)
                    return

                fileBytes = base64.b64decode(file_content_b64)
                fileChooser = JFileChooser()
                fileChooser.setDialogTitle("Save Results")
                if fileChooser.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
                    filePath = fileChooser.getSelectedFile().getAbsolutePath()
                    if format_choice == "csv" and not filePath.endswith(".csv"):
                        filePath += ".csv"
                    elif format_choice == "excel" and not filePath.endswith(".xlsx"):
                        filePath += ".xlsx"
                    elif format_choice == "parquet" and not filePath.endswith(".parquet"):
                        filePath += ".parquet"

                    with open(filePath, "wb") as f:
                        f.write(fileBytes)

                    JOptionPane.showMessageDialog(self.panel, "Exported successfully to " + filePath)
            else:
                error_stream = BufferedReader(InputStreamReader(connection.getErrorStream(), "UTF-8"))
                error_response = u""
                line = error_stream.readLine()
                while line:
                    error_response += line + u"\n"
                    line = error_stream.readLine()
                error_stream.close()
                JOptionPane.showMessageDialog(self.panel, "Error from export API: " + error_response, "Error", JOptionPane.ERROR_MESSAGE)

        except Exception as e:
            JOptionPane.showMessageDialog(self.panel, "Error during export:\n" + str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        pass

    def actionPerformed(self, event):
        cmd = event.getActionCommand()
        if cmd.startswith("option_"):
            option_key = cmd.replace("option_", "")
            self.runOptionAnalysis(option_key)
        elif cmd == "analyze_client_request":
            self.runLLMAnalysis()
        elif cmd == "score_all":
            self.runScoreAllAnalysis()
        elif cmd == "benchmark":
            self.runBenchmark()
        elif cmd == "run_benchmark":
            self.runBenchmark()
        elif cmd == "export_results":
            self.exportResultsHandler()
        elif cmd == "resend_request":
            self.resendRequest()
