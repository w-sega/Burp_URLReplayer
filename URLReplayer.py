# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener
from burp import ITab
from burp import IMessageEditor

from javax.swing import JScrollPane, JList, JButton, JPanel, JTextArea, JSplitPane, DefaultListModel
from javax.swing import JTable, JTabbedPane, JLabel, JTextField
from javax.swing import ListSelectionModel, JToggleButton
from javax.swing.table import DefaultTableModel
from javax.swing.event import ListSelectionListener, DocumentListener
from java.awt import BorderLayout, FlowLayout
from java.net import URL
from javax.swing import JPopupMenu, JMenuItem
from java.awt.event import MouseAdapter
from java.awt.event import MouseEvent

from java.util.concurrent import ConcurrentHashMap
from java.lang import String
import re
from java.lang import Runnable, Thread
from javax.swing import SwingUtilities

import json

class FilterDocumentListener(DocumentListener):
    def __init__(self, callback):
        self.callback = callback
    def insertUpdate(self, e):
        self.callback()
    def removeUpdate(self, e):
        self.callback()
    def changedUpdate(self, e):
        self.callback()

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("URL Replayer")

        self.url_map = ConcurrentHashMap()
        self.http_results = []
        self.is_listening = True
        self.sort_order_ascending = True
        self.sorted_column_name = "ID" 

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
        self.list_popup = JPopupMenu()
        self.list_popup.add(JMenuItem("Send Default Request", actionPerformed=self.onListSendDefault))
        self.list_popup.addSeparator()
        self.list_popup.add(JMenuItem("GET Request", actionPerformed=self.onListGet))
        self.list_popup.add(JMenuItem("POST Request", actionPerformed=self.onListPost))
        self.list_popup.addSeparator()
        self.list_popup.add(JMenuItem("Send to Repeater", actionPerformed=self.onListToRepeater))
        self.list_popup.addSeparator()
        self.list_popup.add(JMenuItem("Delete", actionPerformed=self.onListDelete))
        
        self.url_list.addMouseListener(ListMouseListener(self.url_list, self.list_popup))

        list_scroll_pane = JScrollPane(self.url_list) 
        searchable_list_panel = JPanel(BorderLayout())
        self.search_field = JTextField()
        self.search_field.getDocument().addDocumentListener(FilterDocumentListener(self.filterUrlList))
        search_panel = JPanel(BorderLayout())
        search_panel.add(JLabel(" Search: "), BorderLayout.WEST)
        search_panel.add(self.search_field, BorderLayout.CENTER)
        searchable_list_panel.add(search_panel, BorderLayout.NORTH)
        searchable_list_panel.add(list_scroll_pane, BorderLayout.CENTER)
        
        self.results_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.results_model = DefaultTableModel(None, ["ID", "Method", "URL", "Status", "Length/Error"])
        self.results_table = JTable(self.results_model)
        results_table_scroll = JScrollPane(self.results_table)
        header = self.results_table.getTableHeader()
        header.addMouseListener(TableSorter(self, self.results_table))
        
        table_popup = JPopupMenu()
        table_popup.add(JMenuItem("Send to Repeater", actionPerformed=self.onSendToRepeater))
        self.results_table.setComponentPopupMenu(table_popup)

        tabs = JTabbedPane()
        self.request_viewer = self._callbacks.createMessageEditor(None, False)
        self.response_viewer = self._callbacks.createMessageEditor(None, False)
        tabs.addTab("Request", self.request_viewer.getComponent())
        tabs.addTab("Response", self.response_viewer.getComponent())
        
        self.results_split_pane.setTopComponent(results_table_scroll)
        self.results_split_pane.setBottomComponent(tabs)
        self.results_split_pane.setResizeWeight(0.4)
        
        self.main_split_pane.setLeftComponent(searchable_list_panel)
        self.main_split_pane.setRightComponent(self.results_split_pane)
        self.main_split_pane.setResizeWeight(0.4)

        config_panel = JPanel(BorderLayout())
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.toggle_listen_button = JToggleButton("Listening (On)", selected=True, actionPerformed=self.onToggleListen)
        self.send_button = JButton("Send Request", actionPerformed=self.onSendRequestClick)
        self.clear_button = JButton("Clear List", actionPerformed=self.onClearClick)
        button_panel.add(self.toggle_listen_button)
        button_panel.add(self.send_button)
        button_panel.add(self.clear_button)
        
        exclusion_panel = JPanel(BorderLayout())
        self.exclude_hosts_field = JTextField(20)
        self.exclude_hosts_field.setText(",".join(self.DEFAULT_HOST_EXCLUSIONS))
        exclusion_panel.add(JLabel(" Exclude Hosts (comma-separated): "), BorderLayout.WEST)
        exclusion_panel.add(self.exclude_hosts_field, BorderLayout.CENTER)
        
        headers_panel = JPanel(BorderLayout())
        headers_panel.add(JLabel(" Custom Headers (one per line, e.g., 'Cookie: value')"), BorderLayout.NORTH)
        self.custom_headers_area = JTextArea(5, 20)
        headers_panel.add(JScrollPane(self.custom_headers_area), BorderLayout.CENTER)
        
        config_panel.add(button_panel, BorderLayout.NORTH)
        config_panel.add(headers_panel, BorderLayout.CENTER)
        config_panel.add(exclusion_panel, BorderLayout.SOUTH)

        self._main_panel.add(config_panel, BorderLayout.SOUTH)
        self.results_table.getSelectionModel().addListSelectionListener(self.onResultSelected)

        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        self.updateTableHeaderText() 
        print("URL Replayer Plugin LOADED (V1.6 - Right-click Default Request)")

    def buildRequestBytes(self, url_str, method, custom_headers_text):
        try:
            parsed_url = URL(url_str)
            path = parsed_url.getPath() or "/"
            if parsed_url.getQuery():
                path += "?" + parsed_url.getQuery()
            host = parsed_url.getHost()
            
            source_data = self.url_map.get(url_str)
            if not source_data:
                return None
                
            source_request_bytes = source_data.get("request")
            source_info = self._helpers.analyzeRequest(source_request_bytes)
            source_headers = source_info.getHeaders()
            
            parsed_custom_headers = []
            custom_header_names = set()
            if custom_headers_text:
                for line in custom_headers_text.splitlines():
                    line = line.strip()
                    if line and ":" in line:
                        header_name = line.split(":", 1)[0].strip()
                        custom_header_names.add(header_name.lower())
                        parsed_custom_headers.append(line)

            new_request_lines = []
            request_line = "%s %s HTTP/1.1" % (method, path)
            new_request_lines.append(request_line)
            
            for header in source_headers:
                h_lower = header.lower()
                if h_lower.startswith("get ") or h_lower.startswith("post ") or \
                   h_lower.startswith("put ") or h_lower.startswith("delete ") or \
                   h_lower.startswith("host:"):
                    continue
                
                try:
                    header_name = header.split(":", 1)[0].strip().lower()
                    if header_name in custom_header_names:
                        continue 
                except:
                    pass 
                new_request_lines.append(header)
                
            new_request_lines.append("Host: %s" % host)
            for custom_header in parsed_custom_headers:
                new_request_lines.append(custom_header)
            
            if method in ["POST", "PUT"]:
                if not any("content-length:" in h.lower() for h in new_request_lines):
                    new_request_lines.append("Content-Length: 0")
            
            if not any("connection:" in h.lower() for h in new_request_lines):
                 new_request_lines.append("Connection: close")

            request_string = "\r\n".join(new_request_lines) + "\r\n\r\n"
            return self._helpers.stringToBytes(request_string)
        except Exception as e:
            print("Error building request: " + str(e))
            return None

    def onListSendDefault(self, event):
        self.onSendRequestClick(event)

    def onListToRepeater(self, event):
        selected_urls = self.url_list.getSelectedValues()
        custom_headers_text = self.custom_headers_area.getText()
        for url_obj in selected_urls:
            url_str = str(url_obj)
            source_data = self.url_map.get(url_str)
            if source_data:
                try:
                    req_bytes = self.buildRequestBytes(url_str, source_data.get("method"), custom_headers_text)
                    if not req_bytes: continue
                    
                    parsed_url = URL(url_str)
                    host = parsed_url.getHost()
                    port = parsed_url.getPort()
                    if port == -1:
                        port = 80 if parsed_url.getProtocol() == "http" else 443
                    
                    self._callbacks.sendToRepeater(
                        host, port, (parsed_url.getProtocol() == "https"),
                        req_bytes, "Replayer-Discovery"
                    )
                except Exception as e:
                    print("Error sending to repeater: " + str(e))

    def onListGet(self, event):
        self.executeCustomMethodOnSelected("GET")

    def onListPost(self, event):
        self.executeCustomMethodOnSelected("POST")

    def executeCustomMethodOnSelected(self, method):
        selected_urls = self.url_list.getSelectedValues()
        if not selected_urls: return
        custom_headers_text = self.custom_headers_area.getText()
        for url_obj in selected_urls:
            url_str = str(url_obj)
            task = RequestTask(self, url_str, method, custom_headers_text)
            Thread(task).start()

    def onListDelete(self, event):
        selected_urls = self.url_list.getSelectedValues()
        if not selected_urls: return
        for url_obj in list(selected_urls):
            url_str = str(url_obj)
            if self.url_map.containsKey(url_str):
                self.url_map.remove(url_str)
            self.list_model.removeElement(url_obj)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.is_listening: return
        if not messageIsRequest and toolFlag == self._callbacks.TOOL_PROXY:
            try:
                host = messageInfo.getHttpService().getHost()
                exclusion_text = self.exclude_hosts_field.getText()
                if exclusion_text:
                    for domain in exclusion_text.split(","):
                        if domain.strip() and host.endswith(domain.strip()): return
            except: return 
            
            response_bytes = messageInfo.getResponse()
            if not response_bytes: return
            response_info = self._helpers.analyzeResponse(response_bytes)
            body_string = self._helpers.bytesToString(response_bytes[response_info.getBodyOffset():])
            source_url = messageInfo.getUrl()
            source_request_bytes = messageInfo.getRequest()
            
            json_parsed = False
            try:
                data = json.loads(body_string)
                if isinstance(data, dict) and "paths" in data and ("swagger" in data or "openapi" in data):
                    self.parseSwaggerDoc(data, source_url, source_request_bytes)
                    json_parsed = True
            except: pass
            
            if not json_parsed:
                self.parseWithRegex(body_string, source_url, source_request_bytes)

    def parseSwaggerDoc(self, data, source_url, source_request_bytes):
        try:
            paths = data.get('paths', {})
            for path, methods in paths.items():
                if not isinstance(methods, dict): continue
                for method, details in methods.items():
                    m_upper = method.upper()
                    if m_upper not in ["GET", "POST", "PUT", "DELETE"]: continue
                    try:
                        new_url = URL(source_url, path)
                        new_url_string = str(new_url).split("?")[0].split("#")[0]
                        if not self.url_map.containsKey(new_url_string):
                            self.url_map.put(new_url_string, {"request": source_request_bytes, "method": m_upper})
                            SwingUtilities.invokeLater(lambda u=new_url_string: self.addUrlToListModel(u))
                    except: pass
        except Exception as e:
            print("Swagger Parse Error: " + str(e))

    def parseWithRegex(self, body_string, source_url, source_request_bytes):
        for match in self.PATH_REGEX.finditer(body_string):
            try:
                path = match.group(1).strip()
                if not path or "/" not in path: continue
                if any(path.lower().endswith(ext) for ext in self.IGNORED_EXTENSIONS): continue
                
                method = "GET"
                start, end = match.start(), match.end()
                ctx_before = body_string[max(0, start - 100) : start].lower()
                if any(x in ctx_before for x in [".post(", "\"post\":", "method:\"post\""]): method = "POST"
                elif any(x in ctx_before for x in [".put(", "\"put\":", "method:\"put\""]): method = "PUT"
                elif any(x in ctx_before for x in [".delete(", "\"delete\":", "method:\"delete\""]): method = "DELETE"

                new_url = URL(source_url, path)
                new_url_string = str(new_url).split("?")[0].split("#")[0]
                if not self.url_map.containsKey(new_url_string):
                    self.url_map.put(new_url_string, {"request": source_request_bytes, "method": method})
                    SwingUtilities.invokeLater(lambda u=new_url_string: self.addUrlToListModel(u))
            except: pass

    def addUrlToListModel(self, url_to_add):
        if self.search_field.getText().lower() in url_to_add.lower():
            self.list_model.addElement(url_to_add)

    def filterUrlList(self):
        txt = self.search_field.getText().lower()
        selected = set(self.url_list.getSelectedValues())
        self.list_model.clear()
        all_urls = sorted(list(self.url_map.keySet()))
        indices = []
        curr = 0
        for u in all_urls:
            if txt in str(u).lower():
                self.list_model.addElement(u)
                if u in selected: indices.append(curr)
                curr += 1
        self.url_list.setSelectedIndices(indices)

    def updateTableHeaderText(self):
        hdrs = ["ID", "Method", "URL", "Status", "Length/Error"]
        arrow = u'\u25b2' if self.sort_order_ascending else u'\u25bc'
        if self.sorted_column_name in hdrs:
            idx = hdrs.index(self.sorted_column_name)
            hdrs[idx] = u"{} {}".format(self.sorted_column_name, arrow)
        self.results_model.setColumnIdentifiers(hdrs)

    def sortResults(self, column_index):
        if column_index != 4:
            self.sorted_column_name = "ID"; self.sort_order_ascending = True
            self.updateTableHeaderText(); return
        self.sort_order_ascending = not self.sort_order_ascending if self.sorted_column_name == "Length/Error" else False
        self.sorted_column_name = "Length/Error"
        try:
            rows = []
            for i in range(self.results_model.getRowCount()):
                try: val = int(self.results_model.getValueAt(i, 4))
                except: val = -1
                rows.append((val, [self.results_model.getValueAt(i, c) for c in range(5)]))
            rows.sort(key=lambda x: x[0], reverse=not self.sort_order_ascending)
            self.results_model.setRowCount(0)
            for _, r in rows: self.results_model.addRow(r)
            self.updateTableHeaderText()
        except: pass

    def getTabCaption(self): return "URL Replayer"
    def getUiComponent(self): return self._main_panel
    def onToggleListen(self, e): 
        self.is_listening = self.toggle_listen_button.isSelected()
        self.toggle_listen_button.setText("Listening (On)" if self.is_listening else "Stopped (Off)")

    def onResultSelected(self, e):
        if e.getValueIsAdjusting(): return
        row = self.results_table.getSelectedRow()
        if row != -1:
            try:
                idx = int(self.results_model.getValueAt(row, 0))
                msg = self.http_results[idx]
                if msg:
                    self.request_viewer.setMessage(msg.getRequest(), True)
                    self.response_viewer.setMessage(msg.getResponse(), False)
            except: pass

    def onSendToRepeater(self, e):
        row = self.results_table.getSelectedRow()
        if row != -1:
            try:
                idx = int(self.results_model.getValueAt(row, 0))
                msg = self.http_results[idx]
                svc = msg.getHttpService()
                self._callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol()=="https", msg.getRequest(), "Replayer " + str(idx))
            except: pass

    def onSendRequestClick(self, e):
        self.results_model.setRowCount(0); self.http_results = []
        urls = self.url_list.getSelectedValues()
        if not urls: 
            self.results_model.addRow([0, "N/A", "Error: Select URLs", "", ""])
            return
        custom_hdrs = self.custom_headers_area.getText()
        for u in urls:
            url_str = str(u)
            data = self.url_map.get(url_str)
            if data:
                Thread(RequestTask(self, url_str, data.get("method"), custom_hdrs)).start()

    def onClearClick(self, e):
        self.search_field.setText(""); self.url_map.clear(); self.list_model.clear()
        self.results_model.setRowCount(0); self.http_results = []; self.custom_headers_area.setText("")
        self.sorted_column_name = "ID"; self.sort_order_ascending = True; self.updateTableHeaderText()
        self.request_viewer.setMessage(None, True); self.response_viewer.setMessage(None, False)

class ListMouseListener(MouseAdapter):
    def __init__(self, list_comp, popup): 
        self.list_comp = list_comp
        self.popup = popup
    def mousePressed(self, e): 
        if e.isPopupTrigger(): self.showMenu(e)
    def mouseReleased(self, e): 
        if e.isPopupTrigger(): self.showMenu(e)
    def showMenu(self, e):
        idx = self.list_comp.locationToIndex(e.getPoint())
        if idx != -1 and not self.list_comp.isSelectedIndex(idx):
            self.list_comp.setSelectedIndex(idx)
        if self.list_comp.getSelectedIndex() != -1:
            self.popup.show(e.getComponent(), e.getX(), e.getY())

class TableSorter(MouseAdapter):
    def __init__(self, ext, tbl): 
        self.ext = ext
        self.tbl = tbl
    def mouseClicked(self, e):
        if e.getSource() == self.tbl.getTableHeader() and e.getButton() == MouseEvent.BUTTON1:
            idx = self.tbl.convertColumnIndexToModel(self.tbl.getTableHeader().columnAtPoint(e.getPoint()))
            SwingUtilities.invokeLater(lambda i=idx: self.ext.sortResults(i))

class RequestTask(Runnable):
    def __init__(self, ext, url, method, hdrs): 
        self.ext = ext
        self.url = url
        self.method = method
        self.hdrs = hdrs
    def run(self):
        try:
            req_bytes = self.ext.buildRequestBytes(self.url, self.method, self.hdrs)
            if not req_bytes: return
            
            u = URL(self.url)
            port = u.getPort()
            if port == -1: port = 80 if u.getProtocol() == "http" else 443
            svc = self.ext._helpers.buildHttpService(u.getHost(), port, u.getProtocol()=="https")
            resp = self.ext._callbacks.makeHttpRequest(svc, req_bytes)
            
            st, ln = (0, 0)
            if resp and resp.getResponse():
                info = self.ext._helpers.analyzeResponse(resp.getResponse())
                st = info.getStatusCode()
                ln = len(resp.getResponse()) - info.getBodyOffset()
            
            SwingUtilities.invokeLater(UpdateTableTask(self.ext, {
                "url": self.url, "method": self.method, "status": st, "length": ln, "message": resp
            }))
        except Exception as e:
            SwingUtilities.invokeLater(UpdateTableTask(self.ext, {
                "url": self.url, "method": self.method, "status": -1, "length": -1, "error": str(e)
            }))

class UpdateTableTask(Runnable):
    def __init__(self, ext, data): 
        self.ext = ext
        self.data = data
    def run(self):
        try:
            idx = len(self.ext.http_results)
            self.ext.http_results.append(self.data.get("message"))
            status = self.data.get("status")
            length_or_err = self.data.get("length") if status != -1 else self.data.get("error")
            row = [idx, self.data["method"], self.data["url"], status if status != -1 else "ERROR", length_or_err]
            self.ext.results_model.addRow(row)
        except Exception as e:
            print("Update Table Error: " + str(e))