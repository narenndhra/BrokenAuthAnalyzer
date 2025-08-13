# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JLabel, JTextField,
                         JButton, JTextArea, JMenuItem, JPopupMenu, JSplitPane, JCheckBox,
                         BoxLayout, Box, BorderFactory, ListSelectionModel, SwingUtilities,
                         RowFilter, JProgressBar)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing.event import DocumentListener, TableModelListener, TableModelEvent
from java.awt import BorderLayout, Font, Color, Dimension, GridLayout
from java.awt.event import ActionListener, MouseAdapter, KeyAdapter, KeyEvent
from threading import Thread

try:
    basestring
except NameError:
    basestring = str
# Unicode guard for Jython/CPython compatibility (for quick-saves)
try:
    unicode
except NameError:
    unicode = str


# -------------------- Helper Renderers & Listeners --------------------

class ResultCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        try:
            result = table.getValueAt(row, 6)
        except Exception:
            result = value
        if result == "VULNERABLE":
            c.setBackground(Color(255, 102, 102))
        elif result == "SAFE":
            c.setBackground(Color(153, 255, 153))
        else:
            c.setBackground(Color.WHITE)
        if isSelected:
            c.setBackground(Color(184, 207, 229))
        return c

class VerdictColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        v = (value or "").upper()
        color = None
        if v in ("VULNERABLE", "AT_RISK"): color = Color(255,102,102)
        elif v == "AUTH_ENFORCED": color = Color(153,255,153)
        elif v in ("INPUT_ERROR","ROUTING_ERROR"): color = Color(255,220,130)
        elif v == "SERVER_ERROR": color = Color(204,153,255)
        elif v in ("NOT_VULNERABLE_EXPECTED_2XX","NOT_VULNERABLE_STATIC"): color = Color(220,220,220)
        if color and not isSelected: c.setBackground(color)
        return c

class ConfidenceBarRenderer(DefaultTableCellRenderer):
    def __init__(self):
        self.bar = JProgressBar(0,100); self.bar.setStringPainted(True)
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        try: v = int(value)
        except: v = 0
        self.bar.setValue(v); self.bar.setString(str(v)); return self.bar

class HeaderDiffRenderer(DefaultTableCellRenderer):
    def __init__(self, extender): self.ext = extender
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
        try:
            modelRow = table.convertRowIndexToModel(row)
            url = table.getModel().getValueAt(modelRow, 0)
            mode = table.getModel().getValueAt(modelRow, 1)
            key = (url, mode)
            tip = self.ext.header_diff_tooltips.get(key, "")
            c.setToolTipText(tip)
        except: pass
        return c

class DocListener(DocumentListener):
    def __init__(self, on_change): self.on_change = on_change
    def insertUpdate(self, e): self.on_change()
    def removeUpdate(self, e): self.on_change()
    def changedUpdate(self, e): self.on_change()

class InsightsTableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        # Only Notes column is editable
        return col == self.getColumnCount() - 1


# ----------------------------- Core Extension -----------------------------

SESSION_HEADERS = [
    "Authorization", "Cookie", "X-Auth-Token", "X-Session-Token",
    "X-Access-Token", "X-User-Token", "X-Csrf-Token", "X-XSRF-Token",
    "X-Requested-With", "X-Identity", "X-Session-Id"
]

VERDICTS = [
    "VULNERABLE",
    "AUTH_ENFORCED",
    "INPUT_ERROR",
    "ROUTING_ERROR",
    "SERVER_ERROR",
    "NOT_VULNERABLE_EXPECTED_2XX",
    "NOT_VULNERABLE_STATIC",
    "UNKNOWN",
    "AT_RISK"  # roll-up verdict
]

# Static assets: conservative (no .html)
STATIC_EXTS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".map"
)
STATIC_CT_PREFIX = (
    "text/css",
    "application/javascript", "application/x-javascript", "text/javascript",
    "image/",
    "font/"
)
# Explicit dynamic/server-side extensions (never static)
DYNAMIC_EXTS = (
    ".php", ".phtml",
    ".asp", ".aspx",
    ".jsp", ".jspx",
    ".do", ".action",
    ".cfm", ".cfml",
    ".cgi", ".pl", ".rb", ".py", ".go"
)

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BrokenAuth Analyzer")

        self.TOOL_PROXY    = callbacks.TOOL_PROXY
        self.TOOL_REPEATER = callbacks.TOOL_REPEATER

        # Dashboard model
        self.model = DefaultTableModel(["URL", "Status Code", "Method", "Size", "Mode", "Header", "Result"], 0)

        # State
        self.stored_data = []   # (url, req_bytes, resp_bytes, httpService)
        self.existing_rows = set()
        self.selected_headers = set(SESSION_HEADERS)
        self.result_map = {}
        self.auto_mode = False
        self._tested_pairs = set()
        self._status_counts = {}
        self._project_base_url = "-"

        # Per-row info map: row_index -> dict(...)
        self.row_info = {}
        self.header_diff_tooltips = {}      # (url, mode) -> tooltip
        self.notes_map = {}                 # (url, mode/ROLLUP) -> note

        # Default save dir/file
        self._default_dir = self._detect_default_dir()
        self._default_csv = "brokenauth_insights.csv"
        self._default_jsonl = "brokenauth_insights.jsonl"

        # UI
        self.setup_gui()
        self._callbacks.customizeUiComponent(self.main_panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)

    # ---------------- GUI ----------------
    def setup_gui(self):
        self.main_panel = JTabbedPane()

        # ===== Summary =====
        summary_panel = JPanel()
        summary_panel.setLayout(BoxLayout(summary_panel, BoxLayout.Y_AXIS))
        summary_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        self.metrics_model = DefaultTableModel(["Metric", "Value"], 0)
        self.metrics_table = JTable(self.metrics_model); self.metrics_table.setRowHeight(24)
        metrics_scroll = JScrollPane(self.metrics_table); metrics_scroll.setPreferredSize(Dimension(900, 120))
        summary_panel.add(metrics_scroll); summary_panel.add(Box.createVerticalStrut(6))

        self.status_model = DefaultTableModel(["Status Code", "Count"], 0)
        self.status_table = JTable(self.status_model); self.status_table.setRowHeight(22)
        status_scroll = JScrollPane(self.status_table)
        status_scroll.setPreferredSize(Dimension(450, 160))
        status_scroll.setBorder(BorderFactory.createTitledBorder("Status Code Summary"))
        summary_panel.add(status_scroll); summary_panel.add(Box.createVerticalStrut(6))

        # Insights controls (roll-up + quick-saves only)
        insights_bar = JPanel(); insights_bar.setLayout(BoxLayout(insights_bar, BoxLayout.X_AXIS))
        self.group_checkbox = JCheckBox("Group by URL+Method (roll-up)")
        self.group_checkbox.addActionListener(lambda e: self.update_summary())
        insights_bar.add(self.group_checkbox); insights_bar.add(Box.createHorizontalStrut(12))

        quick_csv_btn = JButton("Save CSV")
        quick_csv_btn.addActionListener(lambda e: self._quick_save_insights_csv())
        insights_bar.add(quick_csv_btn); insights_bar.add(Box.createHorizontalStrut(6))

        quick_json_btn = JButton("Save JSON")
        quick_json_btn.addActionListener(lambda e: self._quick_save_insights_json())
        insights_bar.add(quick_json_btn)

        insights_bar.add(Box.createHorizontalGlue())
        summary_panel.add(insights_bar); summary_panel.add(Box.createVerticalStrut(4))

        # Insights table (NO "Had Session Headers" column)
        self.insights_model = InsightsTableModel(
            ["URL","Mode","Verdict","Severity","Confidence","Baseline","Mutated",
             "Delta Size","Similarity","Header Diff","Signals","Notes"], 0
        )
        self.insights_table = JTable(self.insights_model)
        self.insights_table.setRowHeight(22)
        self.insights_table.setAutoCreateRowSorter(True)
        self.insights_table.getColumnModel().getColumn(2).setCellRenderer(VerdictColorRenderer())
        self.insights_table.getColumnModel().getColumn(4).setCellRenderer(ConfidenceBarRenderer())
        self.insights_table.getColumnModel().getColumn(9).setCellRenderer(HeaderDiffRenderer(self))  # Header Diff col index
        self.insights_table.getModel().addTableModelListener(self._notes_listener())

        insights_scroll = JScrollPane(self.insights_table)
        insights_scroll.setBorder(BorderFactory.createTitledBorder("Insights"))
        insights_scroll.setPreferredSize(Dimension(900, 310))
        summary_panel.add(insights_scroll)

        self.main_panel.addTab("Summary", summary_panel)

        # ===== Dashboard =====
        self.table = JTable(self.model)
        self.table.setFont(Font("Courier New", Font.PLAIN, 12))
        self.table.setRowHeight(26)
        self.table.setDefaultRenderer(self.table.getColumnClass(0), ResultCellRenderer())
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(lambda e: self.inline_viewer())
        self.dashboard_sorter = TableRowSorter(self.model); self.table.setRowSorter(self.dashboard_sorter)

        self.req_area = JTextArea(); self.req_area.setEditable(False); self.req_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        req_scroll = JScrollPane(self.req_area)
        req_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "Request"))

        self.resend_btn = JButton("Resend Selected"); self.resend_btn.addActionListener(lambda e: self._resend_selected())
        left_panel = JPanel(); left_panel.setLayout(BoxLayout(left_panel, BoxLayout.Y_AXIS))
        left_panel.add(req_scroll); left_panel.add(Box.createVerticalStrut(4)); left_panel.add(self.resend_btn)

        self.resp_area = JTextArea(); self.resp_area.setEditable(False); self.resp_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        resp_scroll = JScrollPane(self.resp_area)
        resp_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "Response"))

        viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_panel, resp_scroll); viewer_split.setResizeWeight(0.5)
        result_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), viewer_split)
        result_split.setResizeWeight(0.6); result_split.setPreferredSize(Dimension(1000, 500))

        toolbar = JPanel(); toolbar.setLayout(BoxLayout(toolbar, BoxLayout.X_AXIS))
        toolbar.add(JLabel("Filter: "))
        self.filter_field = JTextField("", 28); self.filter_field.setMaximumSize(Dimension(300,26))
        clear_btn = JButton("Clear"); clear_btn.addActionListener(lambda e: self._clear_filter())
        toolbar.add(self.filter_field); toolbar.add(Box.createHorizontalStrut(8)); toolbar.add(clear_btn)
        toolbar.add(Box.createHorizontalGlue())
        self.filter_field.getDocument().addDocumentListener(DocListener(lambda: self._apply_filter()))

        self.popup_menu = JPopupMenu()
        delete_item = JMenuItem("Delete Selected"); delete_item.addActionListener(DeleteSelectedAction(self))
        clear_item = JMenuItem("Clear All"); clear_item.addActionListener(ClearTableAction(self))
        self.popup_menu.add(delete_item); self.popup_menu.add(clear_item)
        self.table.addMouseListener(TablePopupListener(self)); self.table.addKeyListener(KeyNavigator(self))

        dashboard_panel = JPanel(BorderLayout())
        dashboard_panel.add(toolbar, BorderLayout.NORTH); dashboard_panel.add(result_split, BorderLayout.CENTER)
        self.main_panel.addTab("Dashboard", dashboard_panel)

        SwingUtilities.invokeLater(lambda: self._autosize_table_columns(self.table))
        SwingUtilities.invokeLater(lambda: self._autosize_table_columns(self.insights_table, max_width=600))

        # ===== Settings =====
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
        settings_panel.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))

        settings_panel.add(JLabel("Session headers to manipulate:"))
        self.check_grid = JPanel(GridLayout(0, 2, 8, 2))
        self.checkboxes = {}
        for header in SESSION_HEADERS:
            box = JCheckBox(header); box.setSelected(True)
            self.check_grid.add(box); self.checkboxes[header] = box
        settings_panel.add(self.check_grid); settings_panel.add(Box.createVerticalStrut(8))

        row_add = JPanel(); row_add.setLayout(BoxLayout(row_add, BoxLayout.X_AXIS))
        row_add.add(JLabel("Add custom header: "))
        self.custom_header_field = JTextField("", 20); self.custom_header_field.setMaximumSize(Dimension(280,25))
        add_btn = JButton("Add"); add_btn.addActionListener(lambda e: self._add_custom_header())
        row_add.add(self.custom_header_field); row_add.add(Box.createHorizontalStrut(6)); row_add.add(add_btn); row_add.add(Box.createHorizontalGlue())
        settings_panel.add(row_add)

        row_sel = JPanel(); row_sel.setLayout(BoxLayout(row_sel, BoxLayout.X_AXIS))
        sel_all = JButton("Select All"); sel_all.addActionListener(lambda e: self._select_all_headers(True))
        sel_none = JButton("Select None"); sel_none.addActionListener(lambda e: self._select_all_headers(False))
        row_sel.add(sel_all); row_sel.add(Box.createHorizontalStrut(6)); row_sel.add(sel_none); row_sel.add(Box.createHorizontalGlue())
        settings_panel.add(Box.createVerticalStrut(8)); settings_panel.add(row_sel)

        settings_panel.add(Box.createVerticalStrut(12))
        self.auto_toggle = JCheckBox("Enable Auto Scan for Proxy & Repeater")
        self.auto_toggle.addActionListener(lambda e: setattr(self, 'auto_mode', self.auto_toggle.isSelected()))
        settings_panel.add(self.auto_toggle)

        apply_button = JButton("Apply Header Settings"); apply_button.addActionListener(ApplySettings(self))
        settings_panel.add(Box.createVerticalStrut(10)); settings_panel.add(apply_button)

        self.main_panel.addTab("Settings", JScrollPane(settings_panel))

    # --------------- Dashboard helpers ---------------
    def _apply_filter(self):
        try:
            text = self.filter_field.getText().strip()
            if text: self.dashboard_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + text))
            else: self.dashboard_sorter.setRowFilter(None)
        except: self.dashboard_sorter.setRowFilter(None)

    def _clear_filter(self):
        try:
            self.filter_field.setText(""); self.dashboard_sorter.setRowFilter(None)
        except: pass

    def _autosize_table_columns(self, table, max_width=480, sample_rows=400):
        try:
            colModel = table.getColumnModel()
            for i in range(colModel.getColumnCount()):
                col = colModel.getColumn(i)
                width = 50
                header = table.getTableHeader().getDefaultRenderer() \
                    .getTableCellRendererComponent(table, col.getHeaderValue(), False, False, 0, i)
                width = max(width, header.getPreferredSize().width)
                rows = min(table.getRowCount(), sample_rows)
                for r in range(rows):
                    comp = table.prepareRenderer(table.getCellRenderer(r, i), r, i)
                    width = max(width, comp.getPreferredSize().width)
                col.setPreferredWidth(min(width + 24, max_width))
        except: pass

    def _resend_selected(self):
        try:
            view_row = self.table.getSelectedRow()
            if view_row < 0: return
            row = self.table.convertRowIndexToModel(view_row)
            url, req_bytes, _, httpService = self.stored_data[row]
            resp = self._callbacks.makeHttpRequest(httpService, req_bytes)
            resp_bytes = resp.getResponse()
            info = self._helpers.analyzeResponse(resp_bytes)
            self.resp_area.setText(self._helpers.bytesToString(resp_bytes))
            self.resp_area.setCaretPosition(0)
            self._callbacks.issueAlert("Resent: %s -> %d" % (url, info.getStatusCode()))
        except Exception as ex:
            self._callbacks.issueAlert("Resend failed: %s" % ex)

    # --------------- Quick-saves (Summary > Insights) ---------------
    def _detect_default_dir(self):
        try:
            import os
            d = os.path.dirname(__file__)
            if d and os.path.isdir(d): return d
        except: pass
        try:
            import os
            d = os.getcwd()
            if d and os.path.isdir(d): return d
        except: pass
        try:
            from java.lang import System
            d = System.getProperty("user.home")
            return d if d else "."
        except:
            return "."

    def _quick_save_insights_csv(self):
        try:
            import os, codecs
            path = os.path.join(self._default_dir, self._default_csv)
            append = True
            write_header = True
            if append and os.path.exists(path):
                try: write_header = (os.path.getsize(path) == 0)
                except: write_header = True
            out = codecs.open(path, "a", "utf-8")
            try:
                model = self.insights_model
                cols = model.getColumnCount()
                if write_header:
                    headers = [unicode(model.getColumnName(i)) for i in range(cols)]
                    out.write(u",".join([h.replace(u",", u" ") for h in headers]) + u"\n")
                rows = model.getRowCount()
                for r in range(rows):
                    vals = []
                    for c in range(cols):
                        v = model.getValueAt(r, c)
                        s = u"" if v is None else unicode(v)
                        s = s.replace(u"\n", u" ").replace(u"\r", u" ").replace(u",", u" ")
                        vals.append(s)
                    out.write(u",".join(vals) + u"\n")
            finally:
                out.close()
            self._callbacks.issueAlert("Saved Insights CSV: " + path)
        except Exception as ex:
            self._callbacks.issueAlert("Quick CSV save failed: %s" % ex)

    def _quick_save_insights_json(self):
        try:
            import os, json, codecs
            path = os.path.join(self._default_dir, self._default_jsonl)
            out = codecs.open(path, "a", "utf-8")
            try:
                model = self.insights_model
                cols = model.getColumnCount()
                headers = [unicode(model.getColumnName(i)) for i in range(cols)]
                rows = model.getRowCount()
                for r in range(rows):
                    obj = {}
                    for c in range(cols):
                        v = model.getValueAt(r, c)
                        s = u"" if v is None else unicode(v)
                        obj[headers[c]] = s
                    out.write(unicode(json.dumps(obj, ensure_ascii=False)) + u"\n")
            finally:
                out.close()
            self._callbacks.issueAlert("Saved Insights JSONL: " + path)
        except Exception as ex:
            self._callbacks.issueAlert("Quick JSON save failed: %s" % ex)

    # --------------- Core send & results -----------------
    def send_test(self, url, headers, body, messageInfo, mode, header_name,
                  present_in_baseline, baseline_status, baseline_bytes, orig_method):
        new_request = self._helpers.buildHttpMessage(headers, body)

        # Light checksum (Jython-friendly) to avoid false dupes on same length
        body_sum = 0
        try:
            for b in body:
                body_sum = (body_sum + (b & 0xFF)) & 0xFFFFFFFF
        except:
            body_sum = len(body)

        # include proto/host/port + method + url + mode + normalized header set + body checksum
        svc = messageInfo.getHttpService()
        try:
            proto = svc.getProtocol()
        except:
            proto = None
        host = svc.getHost()
        port = svc.getPort()
        row_id = (proto, host, port, orig_method, url, mode, header_name, body_sum)
        if row_id in self.existing_rows:
            return
        self.existing_rows.add(row_id)

        row_index_holder = []

        def add_pending_row():
            self.model.addRow([url, "Pending...", orig_method, "-", mode, header_name, "Pending..."])
            self.stored_data.append((url, new_request, b"", messageInfo.getHttpService()))
            row_index_holder.append(self.model.getRowCount() - 1)
        SwingUtilities.invokeLater(add_pending_row)

        def send():
            try:
                import time
                while not row_index_holder: time.sleep(0.01)
                pending_row_index = row_index_holder[0]

                response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_request)
                mut_bytes = response.getResponse()
                mut_info = self._helpers.analyzeResponse(mut_bytes)
                mut_status = mut_info.getStatusCode()
                mut_headers = mut_info.getHeaders()
                mut_body = self._helpers.bytesToString(mut_bytes[mut_info.getBodyOffset():])
                mut_ct = ""
                for h in mut_headers:
                    if h.lower().startswith("content-type:"):
                        mut_ct = h.split(":",1)[1].strip().lower(); break

                # Baseline parse
                base_status = baseline_status
                base_headers, base_body = [], ""
                if baseline_bytes:
                    binfo = self._helpers.analyzeResponse(baseline_bytes)
                    base_headers = binfo.getHeaders()
                    base_body = self._helpers.bytesToString(baseline_bytes[binfo.getBodyOffset():])

                result = "VULNERABLE" if (200 <= mut_status < 300) else "SAFE"

                delta_size = len(mut_bytes) - (len(baseline_bytes) if baseline_bytes else 0)
                similarity = self._similarity(base_body, mut_body)
                hsum, htip = self._header_diff_summary(base_headers, mut_headers)

                verdict, confidence = self._verdict(mut_status, orig_method, url, mut_ct, present_in_baseline)

                # store latest response for inline viewer
                self.stored_data[pending_row_index] = (url, self._helpers.buildHttpMessage(headers, body), mut_bytes, messageInfo.getHttpService())
                size = len(mut_bytes)

                def update_row():
                    self.model.setValueAt(str(mut_status), pending_row_index, 1)
                    self.model.setValueAt(str(size), pending_row_index, 3)
                    self.model.setValueAt(result, pending_row_index, 6)

                    info = {
                        "verdict": verdict,
                        "confidence": confidence,
                        "signals": "status=%d; ct=%s; baseline_session_headers=%s; baseline_status=%s" %
                                   (mut_status, (mut_ct.split(";")[0] if mut_ct else "-"),
                                    ("yes" if present_in_baseline else "no"),
                                    (str(base_status) if isinstance(base_status,int) else "-")),
                        "baseline": base_status if base_status is not None else "-",
                        "mutated": mut_status,
                        "delta": delta_size,
                        "similarity": similarity,
                        "hdiff_sum": hsum,
                        "hdiff_tip": htip
                    }
                    self.row_info[pending_row_index] = info
                    self.header_diff_tooltips[(url, mode)] = htip

                    self._status_counts[mut_status] = self._status_counts.get(mut_status, 0) + 1
                    self.update_summary()
                SwingUtilities.invokeLater(update_row)

            except Exception as ex:
                def show_error():
                    from javax.swing import JOptionPane
                    JOptionPane.showMessageDialog(None, "Error sending request:\n{}".format(str(ex)), "Error", JOptionPane.ERROR_MESSAGE)
                SwingUtilities.invokeLater(show_error)
        Thread(target=send).start()

    # --------- Scanner orchestration (ONLY 2 MODES) ----------
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.auto_mode or not messageIsRequest: return
        if toolFlag == self.TOOL_PROXY or toolFlag == self.TOOL_REPEATER:
            self.scan_with_modes(messageInfo)

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            menu = JMenuItem("Send to BrokenAuth Analyzer")
            menu.addActionListener(lambda e: self.manual_trigger(messages))
            return [menu]
        return []

    def manual_trigger(self, messages):
        for messageInfo in messages: self.scan_with_modes(messageInfo)

    def _remove_all_session_headers(self, headers, present_names):
        lower = set([n.lower() for n in present_names])
        return [h for h in headers if h.split(":",1)[0].strip().lower() not in lower]

    def _strip_all_session_headers(self, headers, present_names):
        lower = set([n.lower() for n in present_names])
        out = []
        for h in headers:
            name = h.split(":",1)[0].strip()
            if name.lower() in lower: out.append(name + ":")
            else: out.append(h)
        return out

    def scan_with_modes(self, messageInfo):
        req_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(req_info.getHeaders())
        body = messageInfo.getRequest()[req_info.getBodyOffset():]
        url_obj = req_info.getUrl()
        url = str(url_obj)
        method = req_info.getMethod()
        path = url_obj.getPath() or "/"

        try:
            base = url_obj.getProtocol() + "://" + url_obj.getHost()
            if path and path.startswith("/api"): base = base + "/api"
            self._project_base_url = base
        except Exception:
            self._project_base_url = "-"

        self._tested_pairs.add((method, path))

        # FIX: case-insensitive selection and normalization
        selected_lower = set([h.lower() for h in self.selected_headers])
        present = []
        for h in headers:
            name = h.split(":",1)[0].strip()
            if name.lower() in selected_lower:
                present.append(name)
        present_norm = sorted(list(set([n.lower() for n in present])))

        if not present_norm:  # no session headers to mutate for this METHOD+URL
            return

        # Baseline bytes/status
        baseline_bytes = None; baseline_status = -1
        try:
            base_resp = messageInfo.getResponse()
            if base_resp:
                baseline_bytes = base_resp
                info = self._helpers.analyzeResponse(base_resp)
                baseline_status = info.getStatusCode()
        except Exception: pass
        if baseline_bytes is None:
            try:
                base_response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), messageInfo.getRequest())
                baseline_bytes = base_response.getResponse()
                base_info = self._helpers.analyzeResponse(baseline_bytes)
                baseline_status = base_info.getStatusCode()
            except Exception:
                baseline_bytes = None; baseline_status = -1

        present_in_baseline = (len(present_norm) > 0)
        header_key = ",".join(present_norm)

        # Mutations driven ONLY by present session headers
        removed_all = self._remove_all_session_headers(headers, present_norm)
        self.send_test(url, removed_all, body, messageInfo,
                       "Removed All Session Headers", header_key,
                       present_in_baseline, baseline_status, baseline_bytes, method)

        stripped_all = self._strip_all_session_headers(headers, present_norm)
        self.send_test(url, stripped_all, body, messageInfo,
                       "Stripped All Session Headers", header_key,
                       present_in_baseline, baseline_status, baseline_bytes, method)

    # --------------- Analysis helpers ---------------
    def _is_static(self, method, url, ct):
        if method != "GET": return False
        try:
            u = (url or "").lower()
            for ext in DYNAMIC_EXTS:
                if u.endswith(ext): return False
            for ext in STATIC_EXTS:
                if u.endswith(ext): return True
            if ct:
                for pref in STATIC_CT_PREFIX:
                    if ct.startswith(pref): return True
        except: pass
        return False

    def _verdict(self, mutated_status, method, url, content_type, had_session_headers):
        if 200 <= mutated_status < 300 and self._is_static(method, url, content_type):
            return ("NOT_VULNERABLE_STATIC", 95)
        if 200 <= mutated_status < 300:
            return ("VULNERABLE", 95) if had_session_headers else ("NOT_VULNERABLE_EXPECTED_2XX", 95)
        if mutated_status in (401,403): return ("AUTH_ENFORCED", 90)
        if mutated_status in (400,409,422): return ("INPUT_ERROR", 80)
        if mutated_status in (404,405): return ("ROUTING_ERROR", 80)
        if mutated_status >= 500: return ("SERVER_ERROR", 80)
        return ("UNKNOWN", 55)

    def _similarity(self, base_body, mut_body):
        try:
            def toks(s):
                s = (s or "").lower()
                out = []; cur = []
                for ch in s:
                    if ch.isalnum(): cur.append(ch)
                    else:
                        if cur: out.append("".join(cur)); cur=[]
                if cur: out.append("".join(cur))
                return set(out)
            a = toks(base_body); b = toks(mut_body)
            if not a and not b: return 100
            if not a or not b: return 0
            inter = len(a & b); union = len(a | b)
            return int(round((100.0 * inter) / union))
        except:
            return 0

    def _header_diff_summary(self, base_headers, mut_headers):
        try:
            def to_map(hs):
                m = {}
                for h in hs:
                    parts = h.split(":",1)
                    if len(parts) != 2: continue
                    k = parts[0].strip().lower(); v = parts[1].strip()
                    m[k] = v
                return m
            bm = to_map(base_headers or []); mm = to_map(mut_headers or [])
            bset = set(bm.keys()); mset = set(mm.keys())
            added = sorted(list(mset - bset))
            removed = sorted(list(bset - mset))
            common = bset & mset
            changed = sorted([k for k in common if bm.get(k,"") != mm.get(k,"")])

            def cap(keys): return [k.title() for k in keys][:6]
            chips = []
            if added: chips.append("+" + ",".join(cap(added)))
            if removed: chips.append("-" + ",".join(cap(removed)))
            if changed: chips.append("~" + ",".join(cap(changed)))
            summary = " ".join(chips) if chips else "-"
            tip_lines = []
            if added:
                tip_lines.append("Added:");  [tip_lines.append("  %s: %s" % (k, mm.get(k,""))) for k in added]
            if removed:
                tip_lines.append("Removed:"); [tip_lines.append("  %s: %s" % (k, bm.get(k,""))) for k in removed]
            if changed:
                tip_lines.append("Changed:")
                for k in changed: tip_lines.append("  %s: '%s' -> '%s'" % (k, bm.get(k,""), mm.get(k,"")))
            tooltip = "\n".join(tip_lines) if tip_lines else ""
            return (summary, tooltip)
        except:
            return ("-", "")

    # --------------- Inline viewers & summary ---------------
    def inline_viewer(self):
        row = self.table.getSelectedRow()
        if row >= 0 and row < len(self.stored_data):
            model_row = self.table.convertRowIndexToModel(row)
            url, req_bytes, resp_bytes, _ = self.stored_data[model_row]
            self.req_area.setText(self._helpers.bytesToString(req_bytes))
            if resp_bytes: self.resp_area.setText(self._helpers.bytesToString(resp_bytes))
            self.req_area.setCaretPosition(0); self.resp_area.setCaretPosition(0)

    def _severity_for_verdict(self, verdict):
        v = (verdict or "").upper()
        if v in ("VULNERABLE","AT_RISK"): return "HIGH"
        if v in ("SERVER_ERROR","INPUT_ERROR","ROUTING_ERROR"): return "MEDIUM"
        return "LOW"

    def _notes_listener(self):
        extender = self
        class _L(TableModelListener):
            def tableChanged(self, e):
                try:
                    if e.getType() != TableModelEvent.UPDATE: return
                    row = e.getFirstRow(); col = e.getColumn()
                    if col != extender.insights_model.getColumnCount()-1: return
                    url = extender.insights_model.getValueAt(row, 0)
                    mode = extender.insights_model.getValueAt(row, 1)
                    note = extender.insights_model.getValueAt(row, col)
                    key = (url, mode); extender.notes_map[key] = note
                except: pass
        return _L()

    def update_summary(self):
        self.status_model.setRowCount(0)
        for code in sorted(self._status_counts.keys()):
            self.status_model.addRow([str(code), str(self._status_counts[code])])

        two_xx = 0
        for r in range(self.model.getRowCount()):
            sc = self.model.getValueAt(r, 1)
            try:
                if 200 <= int(sc) < 300: two_xx += 1
            except: pass

        metrics = [
            ("Project Base URL", self._project_base_url),
            ("Tested", str(len(self._tested_pairs))),
            ("2xx OK", str(two_xx)),
        ]
        self.metrics_model.setRowCount(0)
        for k,v in metrics: self.metrics_model.addRow([k,v])

        # Assemble detailed rows (capture METHOD too)
        detailed = []
        for r in range(self.model.getRowCount()):
            url = self.model.getValueAt(r, 0)
            method = self.model.getValueAt(r, 2)
            mode = self.model.getValueAt(r, 4)
            mut_status = self.model.getValueAt(r, 1)
            if r not in self.row_info: continue
            info = self.row_info[r]
            row = {
                "url": url, "method": method, "mode": mode,
                "verdict": info["verdict"], "confidence": info["confidence"],
                "baseline": str(info["baseline"]), "mutated": str(mut_status),
                "delta": str(info["delta"]), "similarity": str(info["similarity"]),
                "hdiff_sum": info["hdiff_sum"], "hdiff_tip": info["hdiff_tip"],
                "signals": info["signals"]
            }
            detailed.append(row)

        self.insights_model.setRowCount(0)
        self.header_diff_tooltips = dict(self.header_diff_tooltips)

        if self.group_checkbox.isSelected():
            # Group by (URL + METHOD)
            by_pair = {}
            for row in detailed:
                key = (row["url"], row["method"])
                by_pair.setdefault(key, []).append(row)
            for (url, method), rows in by_pair.items():
                verdicts = dict((r["mode"], r["verdict"]) for r in rows)
                any_vuln = any(rv == "VULNERABLE" for rv in verdicts.values())
                if any_vuln: combined = "AT_RISK"
                elif all(rv == "AUTH_ENFORCED" for rv in verdicts.values()): combined = "AUTH_ENFORCED"
                elif all(rv in ("NOT_VULNERABLE_EXPECTED_2XX","NOT_VULNERABLE_STATIC") for rv in verdicts.values()):
                    combined = "NOT_VULNERABLE_EXPECTED_2XX"
                else:
                    combined = "AUTH_ENFORCED" if "AUTH_ENFORCED" in verdicts.values() else "UNKNOWN"
                sev = self._severity_for_verdict(combined)
                conf = max(int(r["confidence"]) for r in rows if str(r["confidence"]).isdigit()) if rows else 80
                baseline = rows[0]["baseline"] if rows else "-"
                mutated = "rem:%s str:%s" % (verdicts.get("Removed All Session Headers","-"),
                                             verdicts.get("Stripped All Session Headers","-"))
                signals = "[%s] Removed=%s; Stripped=%s" % (method, verdicts.get("Removed All Session Headers","-"),
                                                            verdicts.get("Stripped All Session Headers","-"))
                hnames = []
                for r in rows:
                    s = r["hdiff_sum"]
                    if s and s != "-" and s not in hnames: hnames.append(s)
                hsum = " | ".join(hnames) if hnames else "-"
                mode = "ROLLUP (%s)" % method
                url_label = "%s %s" % (method, url)
                note = self.notes_map.get((url_label, mode), "")
                self.insights_model.addRow([url_label, mode, combined, sev, str(conf), baseline, mutated,
                                            "-", "-", hsum, signals, note])
                self.header_diff_tooltips[(url_label, mode)] = "\n".join([rr["hdiff_tip"] for rr in rows if rr["hdiff_tip"]])
        else:
            for row in detailed:
                sev = self._severity_for_verdict(row["verdict"])
                url = row["url"]; mode = row["mode"]
                note = self.notes_map.get((url, mode), "")
                self.insights_model.addRow([url, mode, row["verdict"], sev, str(row["confidence"]),
                                            row["baseline"], row["mutated"], row["delta"], row["similarity"],
                                            row["hdiff_sum"], row["signals"], note])

    def getTabCaption(self):
        return "BrokenAuth Analyzer"

    def getUiComponent(self):
        return self.main_panel

    # --------------- Settings helpers ---------------
    def _add_custom_header(self):
        name = self.custom_header_field.getText().strip()
        if not name or name in self.checkboxes: return
        box = JCheckBox(name); box.setSelected(True)
        self.checkboxes[name] = box
        self.check_grid.add(box); self.check_grid.revalidate(); self.check_grid.repaint()
        self.custom_header_field.setText("")

    def _select_all_headers(self, on):
        for box in self.checkboxes.values(): box.setSelected(on)


# --- Remaining Helper Classes ---
class ApplySettings(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        self.extender.selected_headers = set()
        for name, box in self.extender.checkboxes.items():
            if box.isSelected(): self.extender.selected_headers.add(name)
        custom = self.extender.custom_header_field.getText().strip()
        if custom: self.extender.selected_headers.add(custom)

class TablePopupListener(MouseAdapter):
    def __init__(self, extender): self.extender = extender
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            table = event.getComponent()
            row = table.rowAtPoint(event.getPoint())
            if row != -1: table.setRowSelectionInterval(row, row)
            self.extender.popup_menu.show(table, event.getX(), event.getY())

class DeleteSelectedAction(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        row = self.extender.table.getSelectedRow()
        if row >= 0:
            model_row = self.extender.table.convertRowIndexToModel(row)
            self.extender.model.removeRow(model_row)
            del self.extender.stored_data[model_row]
            try: del self.extender.row_info[model_row]
            except: pass
            self.extender.update_summary()

class ClearTableAction(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        self.extender.model.setRowCount(0)
        self.extender.stored_data = []
        self.extender.row_info = {}
        self.extender.header_diff_tooltips = {}
        self.extender.result_map.clear()
        self.extender.existing_rows.clear()
        self.extender._tested_pairs.clear()
        self.extender._status_counts.clear()
        self.extender._project_base_url = "-"
        self.extender.update_summary()

class KeyNavigator(KeyAdapter):
    def __init__(self, extender): self.extender = extender
    def keyReleased(self, event):
        if event.getKeyCode() in [KeyEvent.VK_UP, KeyEvent.VK_DOWN]:
            self.extender.inline_viewer()
