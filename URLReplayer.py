# -*- coding: utf-8 -*-

from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditor

from javax.swing import JScrollPane, JList, JButton, JPanel, JTextArea, JSplitPane, DefaultListModel
from javax.swing import JTable, JTabbedPane, JLabel, JTextField
from javax.swing import ListSelectionModel, JToggleButton
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener
from java.awt import BorderLayout, FlowLayout
from java.net import URL
from javax.swing import JPopupMenu, JMenuItem

from java.util.concurrent import ConcurrentHashMap
from java.lang import String
import re
from java.lang import Runnable, Thread
from javax.swing import SwingUtilities

import json


class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Replayer")

        self.url_map = ConcurrentHashMap()
        self.http_results = []
        self.is_listening = True

        self.IGNORED_EXTENSIONS = [
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
            ".woff", ".woff2", ".ttf", ".eot", ".map", ".htc",
            ".mp4", ".mp3", ".webm", ".ogg", ".vue", ".ts", ".jsx"
        ]
        
        self.DEFAULT_HOST_EXCLUSIONS = [
            "google.com",
            "mozilla.org",
            "microsoft.com",
            "apple.com",
            "127.0.0.1"
        ]
        
        self.PATH_REGEX = re.compile(r'["\']([a-zA-Z0-9_./-]{3,})["\']')

        self._main_panel = JPanel(BorderLayout())
        
        self.main_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._main_panel.add(self.main_split_pane, BorderLayout.CENTER)
        
        self.list_model = DefaultListModel()
        self.url_list = JList(self.list_model)
        self.url_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        left_panel = JScrollPane(self.url_list) 
        
        self.results_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        self.results_model = DefaultTableModel(None, ["ID", "Method", "URL", "Status", "Length/Error"])
        self.results_table = JTable(self.results_model)
        results_table_scroll = JScrollPane(self.results_table)
        
        popup_menu = JPopupMenu()
        menu_item = JMenuItem("Send to Repeater", actionPerformed=self.onSendToRepeater)
        popup_menu.add(menu_item)
        self.results_table.setComponentPopupMenu(popup_menu)

        tabs = JTabbedPane()
        self.request_viewer = self._callbacks.createMessageEditor(None, False)
        self.response_viewer = self._callbacks.createMessageEditor(None, False)
        tabs.addTab("Request", self.request_viewer.getComponent())
        tabs.addTab("Response", self.response_viewer.getComponent())
        
        self.results_split_pane.setTopComponent(results_table_scroll)
        self.results_split_pane.setBottomComponent(tabs)
        self.results_split_pane.setResizeWeight(0.4)
        
        self.main_split_pane.setLeftComponent(left_panel)
        self.main_split_pane.setRightComponent(self.results_split_pane)
        self.main_split_pane.setResizeWeight(0.4)

        config_panel = JPanel(BorderLayout())

        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.toggle_listen_button = JToggleButton(
            "Listening (On)", 
            selected=True, 
            actionPerformed=self.onToggleListen
        )
        self.send_button = JButton(
            "Send Request", 
            actionPerformed=self.onSendRequestClick
        )
        self.clear_button = JButton(
            "Clear List",
            actionPerformed=self.onClearClick
        )
        button_panel.add(self.toggle_listen_button)
        button_panel.add(self.send_button)
        button_panel.add(self.clear_button)
        config_panel.add(button_panel, BorderLayout.NORTH)
        
        exclusion_panel = JPanel(BorderLayout())
        exclusion_label = JLabel(" Exclude Hosts (comma-separated): ")
        self.exclude_hosts_field = JTextField(20)
        self.exclude_hosts_field.setText(",".join(self.DEFAULT_HOST_EXCLUSIONS))
        
        exclusion_panel.add(exclusion_label, BorderLayout.WEST)
        exclusion_panel.add(self.exclude_hosts_field, BorderLayout.CENTER)
        config_panel.add(exclusion_panel, BorderLayout.SOUTH)

        self._main_panel.add(config_panel, BorderLayout.SOUTH)
        
        self.results_table.getSelectionModel().addListSelectionListener(self.onResultSelected)

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        
        print("URL Replayer Plugin LOADED (V1.1 - Final Version)")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        if not self.is_listening:
            return
            
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            
            try:
                host = messageInfo.getHttpService().getHost()
                exclusion_text = self.exclude_hosts_field.getText()
                
                if exclusion_text:
                    excluded_domains = exclusion_text.split(",")
                    for domain in excluded_domains:
                        clean_domain = domain.strip()
                        if clean_domain and host.endswith(clean_domain):
                            return
                            
            except Exception as e:
                print("Error in host exclusion check: " + str(e))
                return 
            
            response_bytes = messageInfo.getResponse()
            if not response_bytes:
                return
            response_info = self._helpers.analyzeResponse(response_bytes)
            body_bytes = response_bytes[response_info.getBodyOffset():]
            try:
                body_string = self._helpers.bytesToString(body_bytes)
            except Exception as e:
                return 
            source_url = messageInfo.getUrl()
            source_request_bytes = messageInfo.getRequest()
            
            json_parsed = False
            try:
                data = json.loads(body_string)
                if isinstance(data, dict) and "paths" in data and ("swagger" in data or "openapi" in data):
                    self.parseSwaggerDoc(data, source_url, source_request_bytes)
                    json_parsed = True
            except Exception as e:
                pass
            
            if not json_parsed:
                self.parseWithRegex(body_string, source_url, source_request_bytes)


    def parseSwaggerDoc(self, data, source_url, source_request_bytes):
        try:
            paths = data.get('paths', {})
            for path, methods in paths.items():
                if not isinstance(methods, dict):
                    continue
                
                for method, details in methods.items():
                    method_upper = method.upper()
                    if method_upper not in ["GET", "POST", "PUT", "DELETE"]:
                        continue
                        
                    try:
                        new_url = URL(source_url, path)
                        new_url_string = str(new_url).split("?")[0].split("#")[0]
                        
                        if not self.url_map.containsKey(new_url_string):
                            data_to_store = {"request": source_request_bytes, "method": method_upper}
                            self.url_map.put(new_url_string, data_to_store)
                            SwingUtilities.invokeLater(
                                lambda new_url_to_add=new_url_string: self.list_model.addElement(new_url_to_add)
                            )
                    except Exception as e:
                        pass
        except Exception as e:
            print("Error parsing Swagger JSON: " + str(e))


    def parseWithRegex(self, body_string, source_url, source_request_bytes):
        try:
            potential_paths = self.PATH_REGEX.finditer(body_string)
        except Exception as e:
            return
            
        for match in potential_paths:
            try:
                path = match.group(1).strip()
                
                if not path or "/" not in path:
                    continue
                
                path_lower = path.lower()
                is_static = False
                for ext in self.IGNORED_EXTENSIONS:
                    if path_lower.endswith(ext):
                        is_static = True
                        break
                if is_static:
                    continue
                
                
                method = "GET"  # 默认方法
                start_pos = match.start()
                end_pos = match.end()
                
                context_before = body_string[max(0, start_pos - 100) : start_pos].lower()
                
                pos_post = max(context_before.rfind(".post("), context_before.rfind("\"post\":"))
                pos_get = max(context_before.rfind(".get("), context_before.rfind("\"get\":"))
                pos_put = max(context_before.rfind(".put("), context_before.rfind("\"put\":"))
                pos_delete = max(context_before.rfind(".delete("), context_before.rfind("\"delete\":"))

                positions = {
                    "POST": pos_post,
                    "GET": pos_get,
                    "PUT": pos_put,
                    "DELETE": pos_delete
                }
                
                found_methods = {m: p for m, p in positions.items() if p != -1}
                
                if found_methods:
                    method = max(found_methods, key=found_methods.get)
                else:
                    context_after = body_string[end_pos : min(len(body_string), end_pos + 50)].lower()
                    
                    if "method: \"post\"" in context_after or "type: \"post\"" in context_after:
                        method = "POST"
                    elif "method: \"put\"" in context_after or "type: \"put\"" in context_after:
                        method = "PUT"
                    elif "method: \"delete\"" in context_after or "type: \"delete\"" in context_after:
                        method = "DELETE"
                    elif "method: \"get\"" in context_after or "type: \"get\"" in context_after:
                        method = "GET"

                new_url = URL(source_url, path)
                new_url_string = str(new_url).split("?")[0].split("#")[0]
                
                if not self.url_map.containsKey(new_url_string):
                    data = {"request": source_request_bytes, "method": method}
                    self.url_map.put(new_url_string, data)
                    SwingUtilities.invokeLater(
                        lambda new_url_to_add=new_url_string: self.list_model.addElement(new_url_to_add)
                    )
            except Exception as e:
                pass # 忽略单个路径的解析错误

    def getTabCaption(self):
        return "URL Replayer"

    def getUiComponent(self):
        return self._main_panel
    
    def onToggleListen(self, event):
        if self.toggle_listen_button.isSelected():
            self.is_listening = True
            self.toggle_listen_button.setText("Listening (On)")
            print("URL Replayer: Listening STARTED")
        else:
            self.is_listening = False
            self.toggle_listen_button.setText("Stopped (Off)")
            print("URL Replayer: Listening STOPPED")
        
    def onResultSelected(self, event):
        if event.getValueIsAdjusting():
            return
        selected_row = self.results_table.getSelectedRow()
        if selected_row != -1:
            try:
                result_id = int(self.results_model.getValueAt(selected_row, 0))
                if result_id < len(self.http_results):
                    http_message = self.http_results[result_id]
                    if http_message:
                        self.request_viewer.setMessage(http_message.getRequest(), True)
                        self.response_viewer.setMessage(http_message.getResponse(), False)
                    else:
                        self.request_viewer.setMessage(None, True)
                        self.response_viewer.setMessage(None, False)
            except Exception as e:
                print("Error in onResultSelected: " + str(e))

    def onSendToRepeater(self, event):
        selected_row = self.results_table.getSelectedRow()
        if selected_row == -1:
            return
            
        try:
            result_id = int(self.results_model.getValueAt(selected_row, 0))
            if result_id < len(self.http_results):
                http_message = self.http_results[result_id]
                if http_message:
                    self._callbacks.sendToRepeater(
                        http_message.getHttpService().getHost(),
                        http_message.getHttpService().getPort(),
                        (http_message.getHttpService().getProtocol() == "https"),
                        http_message.getRequest(),
                        "Replayer " + str(result_id)
                    )
        except Exception as e:
            print("Error in onSendToRepeater: " + str(e))

    def onSendRequestClick(self, event):
        try:
            self.results_model.setRowCount(0)
            self.http_results = []
            
            selected_urls_obj = self.url_list.getSelectedValues()
            
            if not selected_urls_obj:
                self.results_model.addRow([0, "N/A", "Error: Please select one or more URLs.", "", ""])
                return
            
            for url_obj in selected_urls_obj:
                url_str = str(url_obj)
                source_data = self.url_map.get(url_str)
                if source_data:
                    method = source_data.get("method")
                    task = RequestTask(self, url_str, method)
                    Thread(task).start()
                else:
                    print("Error: No source data found for URL: " + url_str)
        
        except Exception as e:
            print("CRITICAL ERROR in onSendRequestClick: %s" % str(e))
            try:
                self.results_model.addRow([0, "N/A", "CRITICAL ERROR", "See Extender Output", str(e)])
            except:
                pass

    def onClearClick(self, event):
        try:
            self.url_map.clear()
            self.list_model.clear()
            self.results_model.setRowCount(0)
            self.http_results = []
            
            try:
                self.request_viewer.setMessage(None, True)
                self.response_viewer.setMessage(None, False)
            except Exception as e:
                pass
                
        except Exception as e:
            print("CRITICAL ERROR in onClearClick: %s" % str(e))


class RequestTask(Runnable):
    
    def __init__(self, extender, url, method):
        self.extender = extender
        self.url = url
        self.method = method

    def run(self):
        try:
            parsed_url = URL(self.url)
            host = parsed_url.getHost()
            port = parsed_url.getPort()
            protocol = parsed_url.getProtocol()
            if port == -1:
                port = 80 if protocol == "http" else 443
            use_https = (protocol == "https")
            path = parsed_url.getPath() or "/"
            
            source_data = self.extender.url_map.get(self.url)
            if not source_data:
                raise Exception("Source request not found in map for " + self.url)
                
            source_request_bytes = source_data.get("request")
            source_info = self.extender._helpers.analyzeRequest(source_request_bytes)
            source_headers = source_info.getHeaders()
            
            new_request_lines = []
            
            request_line = "%s %s HTTP/1.1" % (self.method, path)
            new_request_lines.append(request_line)
            
            for header in source_headers:
                if header.lower().startswith("get ") or \
                   header.lower().startswith("post ") or \
                   header.lower().startswith("put ") or \
                   header.lower().startswith("delete ") or \
                   header.lower().startswith("host:"):
                    continue
                new_request_lines.append(header)
                
            new_request_lines.append("Host: %s" % host)
            
            if self.method == "POST" or self.method == "PUT":
                if not any("content-length:" in h.lower() for h in new_request_lines):
                    new_request_lines.append("Content-Length: 0")
            
            if not any("connection:" in h.lower() for h in new_request_lines):
                 new_request_lines.append("Connection: close")

            request_string = "\r\n".join(new_request_lines) + "\r\n\r\n"
            request_bytes = self.extender._helpers.stringToBytes(request_string)
            
            http_service = self.extender._helpers.buildHttpService(host, port, use_https)
            response_message = self.extender._callbacks.makeHttpRequest(
                http_service, 
                request_bytes
            )

            status_code = -1
            length = -1
            if response_message and response_message.getResponse():
                response_info = self.extender._helpers.analyzeResponse(response_message.getResponse())
                status_code = response_info.getStatusCode()
                length = len(response_message.getResponse()) - response_info.getBodyOffset()
            else:
                status_code = 0
                length = 0
                
            result_data = {
                "url": self.url,
                "method": self.method,
                "status": status_code,
                "length": length,
                "message": response_message 
            }
            
            SwingUtilities.invokeLater(UpdateTableTask(self.extender, result_data))

        except Exception as e:
            error_data = {
                "url": self.url,
                "method": self.method,
                "status": -1,
                "length": -1,
                "message": None,
                "error": str(e)
            }
            SwingUtilities.invokeLater(UpdateTableTask(self.extender, error_data))


class UpdateTableTask(Runnable):
    def __init__(self, extender, data):
        self.extender = extender
        self.data = data
        
    def run(self):
        try:
            new_id = len(self.extender.http_results)
            
            self.extender.http_results.append(self.data.get("message"))
            
            if "error" in self.data:
                self.extender.results_model.addRow([
                    new_id,
                    self.data.get("method"),
                    self.data["url"],
                    "ERROR",
                    self.data["error"]
                ])
            else:
                self.extender.results_model.addRow([
                    new_id,
                    self.data.get("method"),
                    self.data["url"],
                    self.data["status"],
                    self.data["length"]
                ])
        except Exception as e:
            print("CRITICAL ERROR in UpdateTableTask.run: %s" % str(e))