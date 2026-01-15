# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory, ITab, IHttpListener
from javax.swing import (JMenuItem, JPanel, JButton, JLabel, JSplitPane, JTextArea, JList, 
                         DefaultListModel, JScrollPane, BorderFactory, JPopupMenu, ListSelectionModel, 
                         JTabbedPane, JTable, JTextField, JToggleButton, SwingUtilities, SwingConstants)
from javax.swing.table import DefaultTableModel
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, FlowLayout, Font, Color
from java.awt.event import MouseAdapter, MouseEvent
from java.util import ArrayList
from java.util.concurrent import ConcurrentHashMap
from java.net import URL
from java.lang import Runnable, Thread
import re, json, traceback

class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Burp_Parsing")
        print("Author: github.com/w-sega") 
        self._main_panel = JPanel(BorderLayout())
        self._tabs = JTabbedPane()
        self.replayer_panel = ReplayerPanel(callbacks, self)
        self.parsing_panel = ParsingPanel(callbacks, self, self.replayer_panel)
        self._tabs.addTab("Analysis (Parsing)", self.parsing_panel.get_ui())
        self._tabs.addTab("Batch Verification (Replayer)", self.replayer_panel.get_ui())
        self._main_panel.add(self._tabs, BorderLayout.CENTER)
        
        # UI Footer for Author
        footer = JPanel(FlowLayout(FlowLayout.RIGHT))
        author_label = JLabel("Author: github.com/w-sega")
        author_label.setForeground(Color.GRAY)
        footer.add(author_label)
        self._main_panel.add(footer, BorderLayout.SOUTH)

        callbacks.registerContextMenuFactory(self)
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

    def getTabCaption(self): return "Burp_Parsing"
    def getUiComponent(self): return self._main_panel
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.replayer_panel.processHttpMessage(toolFlag, messageIsRequest, messageInfo)
    def createMenuItems(self, inv):
        return ArrayList([JMenuItem("Extract to API Hunter (Parsing)", actionPerformed=lambda x: self.parsing_panel.run(inv))])

class ParsingPanel:
    def __init__(self, callbacks, extender, replayer_instance):
        self._callbacks, self._helpers, self._extender, self._replayer = callbacks, callbacks.getHelpers(), extender, replayer_instance
        self._storage, self._src_model, self._ep_model, self._mode = {}, DefaultListModel(), DefaultListModel(), "POST"
        self.init_ui()

    def get_ui(self): return self._p
    def init_ui(self):
        self._p = JPanel(BorderLayout())
        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JButton("Clear All", actionPerformed=lambda e: self.clear()))
        top.add(JButton("Send to Repeater", actionPerformed=lambda e: self.to_repeater()))
        top.add(JLabel(" | Hint: Right-click on 'Endpoints' list to send to Batch Replayer"))
        self._src_l, self._ep_l, self._res = JList(self._src_model), JList(self._ep_model), JTextArea()
        self._ep_l.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._src_l.addListSelectionListener(self.on_src)
        self._ep_l.addListSelectionListener(self.on_ep)
        self._ep_l.addMouseListener(self.ML(self))
        s1, s2, s3 = JScrollPane(self._src_l), JScrollPane(self._ep_l), JScrollPane(self._res)
        s1.setBorder(BorderFactory.createTitledBorder("Sources (JS/HTML)"))
        s2.setBorder(BorderFactory.createTitledBorder("Endpoints"))
        s3.setBorder(BorderFactory.createTitledBorder("Request Preview"))
        sp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, s2, s3)
        sp.setDividerLocation(300)
        main_sp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, s1, sp)
        main_sp.setDividerLocation(250)
        self._p.add(top, BorderLayout.NORTH); self._p.add(main_sp, BorderLayout.CENTER)

    def clear(self):
        self._storage = {}; self._src_model.clear(); self._ep_model.clear(); self._res.setText("")

    def on_src(self, e):
        if not e.getValueIsAdjusting():
            self._ep_model.clear()
            src = self._src_l.getSelectedValue()
            if src in self._storage:
                for x in sorted(self._storage[src]["eps"]): self._ep_model.addElement(x)

    def on_ep(self, e):
        if not e or not e.getValueIsAdjusting():
            src, ep = self._src_l.getSelectedValue(), self._ep_l.getSelectedValue()
            if src and ep: self._res.setText(self.build(src, ep))

    def build(self, src, ep):
        d = self._storage[src]
        path = "/REPLACE_ME_API" if ep == "[No API Detected]" else ep
        obj = {p: (10 if "size" in p.lower() else (1 if any(k in p.lower() for k in ["page","id"]) else "test")) for p in d["ps"]}
        h_b = ["Host: %s" % d["svc"].getHost(), "Connection: close"]
        skip = ["content-length", "content-type", "connection", "host"]
        for l in d["hs"][1:]:
            if not any(l.lower().startswith(s) for s in skip): h_b.append(l)
        if self._mode == "GET":
            q = "&".join(["%s=%s" % (k, v) for k, v in obj.items()])
            req_path = "%s?%s" % (path, q) if q else path
            return "GET %s HTTP/1.1\r\n%s\r\n\r\n" % (req_path, "\r\n".join(h_b))
        body = json.dumps(obj, indent=4, ensure_ascii=False)
        h = ["POST %s HTTP/1.1" % path] + h_b + ["Content-Type: application/json", "Content-Length: %d" % len(body)]
        return "\r\n".join(h) + "\r\n\r\n" + body

    def to_repeater(self, batch=False):
        src = self._src_l.getSelectedValue()
        if not src: return
        eps = self._ep_l.getSelectedValues() if batch else [self._ep_l.getSelectedValue()]
        s = self._storage[src]["svc"]
        for ep in eps:
            if ep:
                req = self.build(src, ep)
                self._callbacks.sendToRepeater(s.getHost(), s.getPort(), s.getProtocol()=="https", self._helpers.stringToBytes(req), "Parsed")

    def send_to_replayer(self):
        src = self._src_l.getSelectedValue()
        if not src: return
        eps = self._ep_l.getSelectedValues()
        if not eps: return
        d = self._storage[src]
        svc = d["svc"]
        prot, host, port = svc.getProtocol(), svc.getHost(), svc.getPort()
        base = "%s://%s" % (prot, host) if (prot == "http" and port == 80) or (prot == "https" and port == 443) else "%s://%s:%s" % (prot, host, port)
        for ep in eps:
            req_str = self.build(src, ep)
            req_bytes = self._helpers.stringToBytes(req_str)
            first_line = req_str.split('\n')[0].strip()
            parts = first_line.split(' ')
            method = parts[0] if len(parts) > 0 else "GET"
            path_part = parts[1] if len(parts) > 1 else ep
            if not path_part.startswith("/"): path_part = "/" + path_part
            full_url = base + path_part
            self._replayer.import_synthetic_request(full_url, method, req_bytes)
        self._extender._tabs.setSelectedIndex(1)

    def run(self, inv):
        try:
            for m in inv.getSelectedMessages():
                svc = m.getHttpService(); ri = self._helpers.analyzeRequest(svc, m.getRequest())
                u, resp = str(ri.getUrl()), m.getResponse()
                if not resp: continue
                b = self._helpers.bytesToString(resp[self._helpers.analyzeResponse(resp).getBodyOffset():])
                eps = [f for f in re.findall(r'["\'](/[a-zA-Z0-9\._\-/]{3,100})["\']', b) if not f.lower().split('?')[0].endswith(('.js','.css','.png','.jpg','.svg','.ico','.woff','.ttf'))]
                ps = set(re.findall(r'["\']([a-zA-Z0-9$]{2,50})["\']\s*:', b) + re.findall(r'([a-zA-Z0-9$]{2,50})\s*:', b))
                ps = {x for x in ps if x.lower() not in ['var','let','const','true','false','null','return','function','headers','script','doctype','html','body','head']}
                if not eps and ps: eps = ["[No API Detected]"]
                if ps:
                    if u not in self._storage:
                        self._storage[u] = {"hs": list(ri.getHeaders()), "eps": set(), "ps": set(), "svc": svc}
                        self._src_model.addElement(u)
                    self._storage[u]["eps"].update(eps); self._storage[u]["ps"].update(ps)
        except: print(traceback.format_exc())

    class ML(MouseAdapter):
        def __init__(self, ext): self.e = ext
        def mousePressed(self, e): 
            if e.isPopupTrigger(): self.m(e)
        def mouseReleased(self, e): 
            if e.isPopupTrigger(): self.m(e)
        def m(self, e):
            i = self.e._ep_l.locationToIndex(e.getPoint())
            if i != -1:
                if not self.e._ep_l.isSelectedIndex(i): self.e._ep_l.setSelectedIndex(i)
                m = JPopupMenu()
                m.add(JMenuItem("Send Selected to Repeater", actionPerformed=lambda x: self.e.to_repeater(True)))
                m.add(JMenuItem("Send Selected to Batch Replayer", actionPerformed=lambda x: self.e.send_to_replayer()))
                m.addSeparator()
                m.add(JMenuItem("Convert to GET", actionPerformed=lambda x: self.s("GET")))
                m.add(JMenuItem("Convert to POST (JSON)", actionPerformed=lambda x: self.s("POST")))
                m.show(e.getComponent(), e.getX(), e.getY())
        def s(self, m): self.e._mode = m; self.e.on_ep(None)

class ReplayerPanel:
    def __init__(self, callbacks, extender):
        self._callbacks, self._helpers, self._extender = callbacks, callbacks.getHelpers(), extender
        self.url_map, self.http_results = ConcurrentHashMap(), []
        self.is_listening = False # Default OFF
        self.sort_order_ascending, self.sorted_column_name = True, "ID"
        self.IGNORED_EXTENSIONS = [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".htc", ".mp4", ".mp3", ".webm", ".ogg", ".vue", ".ts", ".jsx"]
        self.DEFAULT_HOST_EXCLUSIONS = ["google.com", "mozilla.org", "microsoft.com", "apple.com", "127.0.0.1"]
        self.PATH_REGEX = re.compile(r'["\']([a-zA-Z0-9_./-]{3,})["\']')
        self.init_ui()

    def get_ui(self): return self._main_panel
    def init_ui(self):
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
        self.list_popup.add(JMenuItem("Delete", actionPerformed=self.onListDelete))
        self.url_list.addMouseListener(self.ListMouseListener(self.url_list, self.list_popup))
        list_scroll_pane = JScrollPane(self.url_list) 
        searchable_list_panel = JPanel(BorderLayout())
        self.search_field = JTextField()
        self.search_field.getDocument().addDocumentListener(self.FilterDocumentListener(self.filterUrlList))
        search_panel = JPanel(BorderLayout())
        search_panel.add(JLabel(" Search: "), BorderLayout.WEST); search_panel.add(self.search_field, BorderLayout.CENTER)
        searchable_list_panel.add(search_panel, BorderLayout.NORTH); searchable_list_panel.add(list_scroll_pane, BorderLayout.CENTER)
        self.results_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self.results_model = DefaultTableModel(None, ["ID", "Method", "URL", "Status", "Length/Error"])
        self.results_table = JTable(self.results_model)
        self.results_table.getTableHeader().addMouseListener(self.TableSorter(self, self.results_table))
        table_popup = JPopupMenu()
        table_popup.add(JMenuItem("Send to Repeater", actionPerformed=self.onSendToRepeater))
        self.results_table.setComponentPopupMenu(table_popup)
        tabs = JTabbedPane()
        self.request_viewer = self._callbacks.createMessageEditor(None, False)
        self.response_viewer = self._callbacks.createMessageEditor(None, False)
        tabs.addTab("Request", self.request_viewer.getComponent()); tabs.addTab("Response", self.response_viewer.getComponent())
        self.results_split_pane.setTopComponent(JScrollPane(self.results_table)); self.results_split_pane.setBottomComponent(tabs); self.results_split_pane.setResizeWeight(0.4)
        self.main_split_pane.setLeftComponent(searchable_list_panel); self.main_split_pane.setRightComponent(self.results_split_pane); self.main_split_pane.setResizeWeight(0.4)
        config_panel = JPanel(BorderLayout())
        button_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        # Default OFF UI
        self.toggle_listen_button = JToggleButton("Stopped (Off)", selected=False, actionPerformed=self.onToggleListen)
        self.send_button = JButton("Send Request (Batch)", actionPerformed=self.onSendRequestClick)
        self.clear_button = JButton("Clear List", actionPerformed=self.onClearClick)
        button_panel.add(self.toggle_listen_button); button_panel.add(self.send_button); button_panel.add(self.clear_button)
        exclusion_panel = JPanel(BorderLayout())
        self.exclude_hosts_field = JTextField(20); self.exclude_hosts_field.setText(",".join(self.DEFAULT_HOST_EXCLUSIONS))
        exclusion_panel.add(JLabel(" Exclude Hosts: "), BorderLayout.WEST); exclusion_panel.add(self.exclude_hosts_field, BorderLayout.CENTER)
        headers_panel = JPanel(BorderLayout())
        headers_panel.add(JLabel(" Custom Headers (Optional - Overrides defaults)"), BorderLayout.NORTH)
        self.custom_headers_area = JTextArea(3, 20)
        headers_panel.add(JScrollPane(self.custom_headers_area), BorderLayout.CENTER)
        config_panel.add(button_panel, BorderLayout.NORTH); config_panel.add(headers_panel, BorderLayout.CENTER); config_panel.add(exclusion_panel, BorderLayout.SOUTH)
        self._main_panel.add(config_panel, BorderLayout.SOUTH)
        self.results_table.getSelectionModel().addListSelectionListener(self.onResultSelected)
        self.updateTableHeaderText() 

    def import_synthetic_request(self, url_str, method, req_bytes):
        self.url_map.put(url_str, {"request": req_bytes, "method": method})
        SwingUtilities.invokeLater(lambda: self.addUrlToListModel(url_str))

    def buildRequestBytes(self, url_str, method, custom_headers_text):
        try:
            parsed_url = URL(url_str)
            path = parsed_url.getPath() or "/"
            if parsed_url.getQuery(): path += "?" + parsed_url.getQuery()
            host = parsed_url.getHost()
            source_data = self.url_map.get(url_str)
            if not source_data: return None
            source_request_bytes = source_data.get("request")
            source_info = self._helpers.analyzeRequest(source_request_bytes)
            new_request_lines = []
            request_line = "%s %s HTTP/1.1" % (method, path)
            new_request_lines.append(request_line)
            parsed_custom_headers = []
            custom_header_names = set()
            if custom_headers_text:
                for line in custom_headers_text.splitlines():
                    if line.strip() and ":" in line:
                        parsed_custom_headers.append(line.strip())
                        custom_header_names.add(line.split(":", 1)[0].strip().lower())
            source_headers = source_info.getHeaders()
            body_offset = source_info.getBodyOffset()
            body_bytes = source_request_bytes[body_offset:] if len(source_request_bytes) > body_offset else ""
            for header in source_headers:
                h_lower = header.lower()
                if h_lower.startswith(("get ", "post ", "put ", "delete ", "host:")): continue
                header_name = header.split(":", 1)[0].strip().lower()
                if header_name in custom_header_names: continue 
                new_request_lines.append(header)
            new_request_lines.append("Host: %s" % host)
            for ch in parsed_custom_headers: new_request_lines.append(ch)
            if method in ["POST", "PUT"]:
                if not any("content-length:" in h.lower() for h in new_request_lines):
                    new_request_lines.append("Content-Length: %d" % len(body_bytes))
            if not any("connection:" in h.lower() for h in new_request_lines): new_request_lines.append("Connection: close")
            request_string = "\r\n".join(new_request_lines) + "\r\n\r\n"
            final_bytes = self._helpers.stringToBytes(request_string)
            if method in ["POST", "PUT"] and body_bytes:
                import java.io.ByteArrayOutputStream
                baos = java.io.ByteArrayOutputStream()
                baos.write(final_bytes); baos.write(body_bytes)
                return baos.toByteArray()
            return final_bytes
        except Exception as e:
            print("Error building request: " + str(e))
            return None

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
                if isinstance(data, dict) and "paths" in data:
                    self.parseSwaggerDoc(data, source_url, source_request_bytes); json_parsed = True
            except: pass
            if not json_parsed: self.parseWithRegex(body_string, source_url, source_request_bytes)

    def parseSwaggerDoc(self, data, source_url, source_request_bytes):
        try:
            paths = data.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE"]:
                        new_url = URL(source_url, path); new_url_string = str(new_url).split("?")[0].split("#")[0]
                        if not self.url_map.containsKey(new_url_string):
                            self.url_map.put(new_url_string, {"request": source_request_bytes, "method": method.upper()})
                            SwingUtilities.invokeLater(lambda: self.addUrlToListModel(new_url_string))
        except: pass

    def parseWithRegex(self, body_string, source_url, source_request_bytes):
        for match in self.PATH_REGEX.finditer(body_string):
            try:
                path = match.group(1).strip()
                if not path or "/" not in path: continue
                if any(path.lower().endswith(ext) for ext in self.IGNORED_EXTENSIONS): continue
                method = "GET"
                start = match.start(); ctx = body_string[max(0, start - 50) : start].lower()
                if "post" in ctx: method = "POST"
                elif "put" in ctx: method = "PUT"
                elif "delete" in ctx: method = "DELETE"
                new_url = URL(source_url, path); new_url_string = str(new_url).split("?")[0].split("#")[0]
                if not self.url_map.containsKey(new_url_string):
                    self.url_map.put(new_url_string, {"request": source_request_bytes, "method": method})
                    SwingUtilities.invokeLater(lambda: self.addUrlToListModel(new_url_string))
            except: pass

    def addUrlToListModel(self, url_to_add):
        if self.search_field.getText().lower() in url_to_add.lower():
            if not self.list_model.contains(url_to_add):
                self.list_model.addElement(url_to_add)

    def filterUrlList(self):
        txt = self.search_field.getText().lower()
        self.list_model.clear()
        all_urls = sorted(list(self.url_map.keySet()))
        for u in all_urls:
            if txt in str(u).lower(): self.list_model.addElement(u)

    def updateTableHeaderText(self):
        hdrs = ["ID", "Method", "URL", "Status", "Length/Error"]
        arrow = u'\u25b2' if self.sort_order_ascending else u'\u25bc'
        if self.sorted_column_name in hdrs: hdrs[hdrs.index(self.sorted_column_name)] = u"{} {}".format(self.sorted_column_name, arrow)
        self.results_model.setColumnIdentifiers(hdrs)

    def sortResults(self, column_index):
        if column_index != 4: self.sorted_column_name = "ID"; self.sort_order_ascending = True
        else:
            self.sort_order_ascending = not self.sort_order_ascending if self.sorted_column_name == "Length/Error" else False
            self.sorted_column_name = "Length/Error"
        rows = []
        for i in range(self.results_model.getRowCount()): rows.append([self.results_model.getValueAt(i, c) for c in range(5)])
        if self.sorted_column_name == "Length/Error":
            def sort_key(row):
                try: return int(row[4])
                except: return -1
            rows.sort(key=sort_key, reverse=not self.sort_order_ascending)
        self.results_model.setRowCount(0)
        for r in rows: self.results_model.addRow(r)
        self.updateTableHeaderText()

    def onToggleListen(self, e): 
        self.is_listening = self.toggle_listen_button.isSelected()
        self.toggle_listen_button.setText("Listening (On)" if self.is_listening else "Stopped (Off)")
    def onResultSelected(self, e):
        if e.getValueIsAdjusting(): return
        row = self.results_table.getSelectedRow()
        if row != -1:
            try:
                idx = int(self.results_model.getValueAt(row, 0)); msg = self.http_results[idx]
                if msg: self.request_viewer.setMessage(msg.getRequest(), True); self.response_viewer.setMessage(msg.getResponse(), False)
            except: pass
    def onSendToRepeater(self, e):
        row = self.results_table.getSelectedRow()
        if row != -1:
            idx = int(self.results_model.getValueAt(row, 0)); msg = self.http_results[idx]; svc = msg.getHttpService()
            self._callbacks.sendToRepeater(svc.getHost(), svc.getPort(), svc.getProtocol()=="https", msg.getRequest(), "API Batch " + str(idx))
    def onSendRequestClick(self, e):
        self.results_model.setRowCount(0); self.http_results = []
        urls = self.url_list.getSelectedValues()
        if not urls: return
        custom_hdrs = self.custom_headers_area.getText()
        for u in urls:
            url_str = str(u); data = self.url_map.get(url_str)
            if data: Thread(self.RequestTask(self, url_str, data.get("method"), custom_hdrs)).start()
    def onClearClick(self, e):
        self.url_map.clear(); self.list_model.clear(); self.results_model.setRowCount(0); self.http_results = []
    def onListSendDefault(self, e): self.onSendRequestClick(e)
    def onListGet(self, e): self.executeCustomMethod("GET")
    def onListPost(self, e): self.executeCustomMethod("POST")
    def onListDelete(self, e):
        for v in self.url_list.getSelectedValues(): self.url_map.remove(str(v)); self.list_model.removeElement(v)
    def executeCustomMethod(self, method):
        urls = self.url_list.getSelectedValues(); hdrs = self.custom_headers_area.getText()
        for u in urls: Thread(self.RequestTask(self, str(u), method, hdrs)).start()

    class FilterDocumentListener(DocumentListener):
        def __init__(self, cb): self.cb = cb
        def insertUpdate(self, e): self.cb()
        def removeUpdate(self, e): self.cb()
        def changedUpdate(self, e): self.cb()
    class ListMouseListener(MouseAdapter):
        def __init__(self, l, p): self.l, self.p = l, p
        def mousePressed(self, e): 
            if e.isPopupTrigger(): self.show(e)
        def mouseReleased(self, e): 
            if e.isPopupTrigger(): self.show(e)
        def show(self, e):
            i = self.l.locationToIndex(e.getPoint())
            if i != -1 and not self.l.isSelectedIndex(i): self.l.setSelectedIndex(i)
            if self.l.getSelectedIndex() != -1: self.p.show(e.getComponent(), e.getX(), e.getY())
    class TableSorter(MouseAdapter):
        def __init__(self, ext, tbl): self.ext, self.tbl = ext, tbl
        def mouseClicked(self, e):
            if e.getSource() == self.tbl.getTableHeader() and e.getButton() == MouseEvent.BUTTON1:
                idx = self.tbl.convertColumnIndexToModel(self.tbl.getTableHeader().columnAtPoint(e.getPoint()))
                SwingUtilities.invokeLater(lambda: self.ext.sortResults(idx))
    class RequestTask(Runnable):
        def __init__(self, ext, url, method, hdrs): self.ext, self.url, self.method, self.hdrs = ext, url, method, hdrs
        def run(self):
            try:
                import java.io.ByteArrayOutputStream
                req_bytes = self.ext.buildRequestBytes(self.url, self.method, self.hdrs)
                if not req_bytes: return
                u = URL(self.url); port = u.getPort()
                if port == -1: port = 80 if u.getProtocol() == "http" else 443
                svc = self.ext._helpers.buildHttpService(u.getHost(), port, u.getProtocol()=="https")
                resp = self.ext._callbacks.makeHttpRequest(svc, req_bytes)
                st, ln = 0, 0
                if resp and resp.getResponse():
                    info = self.ext._helpers.analyzeResponse(resp.getResponse()); st = info.getStatusCode(); ln = len(resp.getResponse()) - info.getBodyOffset()
                SwingUtilities.invokeLater(self.ext.UpdateTableTask(self.ext, {"url": self.url, "method": self.method, "status": st, "length": ln, "message": resp}))
            except Exception as e:
                SwingUtilities.invokeLater(self.ext.UpdateTableTask(self.ext, {"url": self.url, "method": self.method, "status": -1, "length": -1, "error": str(e)}))
    class UpdateTableTask(Runnable):
        def __init__(self, ext, data): self.ext, self.data = ext, data
        def run(self):
            try:
                idx = len(self.ext.http_results); self.ext.http_results.append(self.data.get("message")); status = self.data.get("status")
                val = self.data.get("length") if status != -1 else self.data.get("error")
                self.ext.results_model.addRow([idx, self.data["method"], self.data["url"], status if status != -1 else "ERR", val])
            except: pass