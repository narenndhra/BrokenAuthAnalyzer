# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IContextMenuFactory, IHttpListener
from javax.swing import (JPanel, JTabbedPane, JTable, JScrollPane, JLabel, JTextField,
                         JButton, JTextArea, JMenuItem, JPopupMenu, JSplitPane, JCheckBox,
                         BoxLayout, Box, BorderFactory, ListSelectionModel, SwingUtilities)
from javax.swing.border import TitledBorder
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, Font, Color, Dimension
from java.awt.event import ActionListener, MouseAdapter, MouseEvent, KeyAdapter, KeyEvent
from threading import Thread

SESSION_HEADERS = [
    "Authorization", "Cookie", "X-Auth-Token", "X-Session-Token",
    "X-Access-Token", "X-User-Token", "X-Csrf-Token", "X-XSRF-Token",
    "X-Requested-With", "X-Identity", "X-Session-Id"
]

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("ES BrokenAuth Analyzer")

        self.model = DefaultTableModel(["URL", "Status Code", "Method", "Size", "Mode", "Header", "Result"], 0)
        self.stored_data = []
        self.existing_rows = set()
        self.selected_headers = set(SESSION_HEADERS)
        self.result_map = {}
        self.auto_mode = False

        self.setup_gui()
        self._callbacks.customizeUiComponent(self.main_panel)
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerHttpListener(self)

    def setup_gui(self):
        self.main_panel = JTabbedPane()

        # Summary Tab
        summary_panel = JPanel()
        summary_panel.setLayout(BoxLayout(summary_panel, BoxLayout.Y_AXIS))
        summary_panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))
        self.summary_label = JLabel("SAFE: 0 | VULNERABLE: 0")
        self.summary_label.setFont(Font("Arial", Font.BOLD, 16))
        summary_panel.add(self.summary_label)
        summary_panel.add(Box.createVerticalStrut(10))
        summary_panel.add(JLabel("Vulnerable URLs:"))
        self.vuln_area = JTextArea(5, 80)
        self.vuln_area.setEditable(False)
        self.vuln_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        summary_panel.add(JScrollPane(self.vuln_area))
        summary_panel.add(Box.createVerticalStrut(10))
        summary_panel.add(JLabel("Safe URLs:"))
        self.safe_area = JTextArea(5, 80)
        self.safe_area.setEditable(False)
        self.safe_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        summary_panel.add(JScrollPane(self.safe_area))
        self.main_panel.addTab("Summary", summary_panel)

        # Results Tab
        self.table = JTable(self.model)
        self.table.setFont(Font("Courier New", Font.PLAIN, 12))
        self.table.setRowHeight(26)
        self.table.setDefaultRenderer(self.table.getColumnClass(0), ResultCellRenderer())
        self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(lambda e: self.inline_viewer())

        self.req_area = JTextArea()
        self.req_area.setEditable(False)
        self.req_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        req_scroll = JScrollPane(self.req_area)
        req_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "Request"))

        self.resp_area = JTextArea()
        self.resp_area.setEditable(False)
        self.resp_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        resp_scroll = JScrollPane(self.resp_area)
        resp_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.GRAY), "Response"))

        viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, req_scroll, resp_scroll)
        viewer_split.setResizeWeight(0.5)

        result_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), viewer_split)
        result_split.setResizeWeight(0.6)
        result_split.setPreferredSize(Dimension(1000, 500))

        results_panel = JPanel(BorderLayout())
        results_panel.add(result_split, BorderLayout.CENTER)

        self.popup_menu = JPopupMenu()
        delete_item = JMenuItem("Delete Selected")
        delete_item.addActionListener(DeleteSelectedAction(self))
        clear_item = JMenuItem("Clear All")
        clear_item.addActionListener(ClearTableAction(self))
        self.popup_menu.add(delete_item)
        self.popup_menu.add(clear_item)
        self.table.addMouseListener(TablePopupListener(self))
        self.table.addKeyListener(KeyNavigator(self))

        self.main_panel.addTab("Results", results_panel)

        # Settings Tab
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
        settings_panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15))

        self.checkboxes = {}
        for header in SESSION_HEADERS:
            box = JCheckBox(header)
            box.setSelected(True)
            box.setFont(Font("Arial", Font.PLAIN, 12))
            settings_panel.add(box)
            settings_panel.add(Box.createVerticalStrut(5))
            self.checkboxes[header] = box

        settings_panel.add(Box.createVerticalStrut(10))
        settings_panel.add(JLabel("Custom Header:"))
        self.custom_header_field = JTextField("", 20)
        self.custom_header_field.setMaximumSize(Dimension(300, 25))
        settings_panel.add(self.custom_header_field)

        self.auto_toggle = JCheckBox("Enable Auto Scan (Proxy/History)")
        self.auto_toggle.setFont(Font("Arial", Font.BOLD, 12))
        self.auto_toggle.addActionListener(lambda e: setattr(self, 'auto_mode', self.auto_toggle.isSelected()))
        settings_panel.add(Box.createVerticalStrut(15))
        settings_panel.add(self.auto_toggle)

        apply_button = JButton("Apply Settings")
        apply_button.addActionListener(ApplySettings(self))
        settings_panel.add(Box.createVerticalStrut(10))
        settings_panel.add(apply_button)

        self.main_panel.addTab("Settings", JScrollPane(settings_panel))

    # Continuing immediately below (posting next stretch without stopping)... ✅
    def send_test(self, url, headers, body, messageInfo, mode, header_name):
        new_request = self._helpers.buildHttpMessage(headers, body)
        row_id = (url, mode, header_name, len(body))
        if row_id in self.existing_rows:
            return
        self.existing_rows.add(row_id)

        method = self._helpers.analyzeRequest(new_request).getMethod()

        row_index_holder = []

        def add_pending_row():
            self.model.addRow([url, "Pending...", method, "-", mode, header_name, "Pending..."])
            self.stored_data.append((url, new_request, b""))
            row_index_holder.append(self.model.getRowCount() - 1)

        SwingUtilities.invokeLater(add_pending_row)

        def send():
            try:
                import time
                while not row_index_holder:
                    time.sleep(0.01)

                pending_row_index = row_index_holder[0]

                response = self._callbacks.makeHttpRequest(messageInfo.getHttpService(), new_request)
                resp_info = self._helpers.analyzeResponse(response.getResponse())
                status = resp_info.getStatusCode()
                result = "VULNERABLE" if status == 200 else "SAFE"

                self.stored_data[pending_row_index] = (url, new_request, response.getResponse())
                size = len(response.getResponse())

                def update_row():
                    self.model.setValueAt(str(status), pending_row_index, 1)
                    self.model.setValueAt(str(size), pending_row_index, 3)
                    self.model.setValueAt(result, pending_row_index, 6)

                    if url in self.result_map and result == "VULNERABLE":
                        self.result_map[url] = "VULNERABLE"
                    elif url not in self.result_map:
                        self.result_map[url] = result
                    self.update_summary()

                SwingUtilities.invokeLater(update_row)

            except Exception as ex:
                def show_error():
                    from javax.swing import JOptionPane
                    JOptionPane.showMessageDialog(
                        None,
                        "Error sending request:\n{}".format(str(ex)),
                        "Error",
                        JOptionPane.ERROR_MESSAGE
                    )
                SwingUtilities.invokeLater(show_error)

        Thread(target=send).start()

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if self.auto_mode and messageIsRequest:
            self.scan_with_modes(messageInfo)

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages:
            menu = JMenuItem("Send to ES BrokenAuth Analyzer")
            menu.addActionListener(lambda e: self.manual_trigger(messages))
            return [menu]
        return []

    def manual_trigger(self, messages):
        for messageInfo in messages:
            self.scan_with_modes(messageInfo)

    def scan_with_modes(self, messageInfo):
        req_info = self._helpers.analyzeRequest(messageInfo)
        headers = list(req_info.getHeaders())
        body = messageInfo.getRequest()[req_info.getBodyOffset():]
        url = str(req_info.getUrl())
        original_headers = headers[:]
        header_names = [h.split(":")[0].strip() for h in headers]

        for name in header_names:
            if name in self.selected_headers:
                stripped = [h if not h.lower().startswith(name.lower() + ":") else name + ":" for h in original_headers]
                self.send_test(url, stripped, body, messageInfo, "Stripped Value", name)
                removed = [h for h in original_headers if not h.lower().startswith(name.lower() + ":")]
                self.send_test(url, removed, body, messageInfo, "Removed Header", name)

    def inline_viewer(self):
        row = self.table.getSelectedRow()
        if row >= 0 and row < len(self.stored_data):
            url, req_bytes, resp_bytes = self.stored_data[row]
            self.req_area.setText(self._helpers.bytesToString(req_bytes))
            self.resp_area.setText(self._helpers.bytesToString(resp_bytes))
            self.req_area.setCaretPosition(0)
            self.resp_area.setCaretPosition(0)

    def update_summary(self):
        safe_urls = []
        vuln_urls = []
        for url, status in self.result_map.items():
            if status == "VULNERABLE":
                vuln_urls.append(url)
            else:
                safe_urls.append(url)
        self.summary_label.setText("SAFE: {} | VULNERABLE: {}".format(len(safe_urls), len(vuln_urls)))
        self.safe_area.setText("\n".join(safe_urls))
        self.vuln_area.setText("\n".join(vuln_urls))

    def getTabCaption(self):
        return "ES BrokenAuth Analyzer"

    def getUiComponent(self):
        return self.main_panel

# Helper classes are posted next immediately without stop!
# --- Helper Classes ---

class ResultCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        result = table.getValueAt(row, 6)
        if result == "VULNERABLE":
            component.setBackground(Color(255, 102, 102))
        elif result == "SAFE":
            component.setBackground(Color(153, 255, 153))
        else:
            component.setBackground(Color.WHITE)
        if isSelected:
            component.setBackground(Color(184, 207, 229))
        return component

class ApplySettings(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        self.extender.selected_headers = set()
        for name, box in self.extender.checkboxes.items():
            if box.isSelected():
                self.extender.selected_headers.add(name)
        custom = self.extender.custom_header_field.getText().strip()
        if custom:
            self.extender.selected_headers.add(custom)

class TablePopupListener(MouseAdapter):
    def __init__(self, extender): self.extender = extender
    def mouseReleased(self, event):
        if event.isPopupTrigger():
            table = event.getComponent()
            row = table.rowAtPoint(event.getPoint())
            if row != -1:
                table.setRowSelectionInterval(row, row)
            self.extender.popup_menu.show(table, event.getX(), event.getY())

class DeleteSelectedAction(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        row = self.extender.table.getSelectedRow()
        if row >= 0:
            self.extender.model.removeRow(row)
            del self.extender.stored_data[row]

class ClearTableAction(ActionListener):
    def __init__(self, extender): self.extender = extender
    def actionPerformed(self, e):
        self.extender.model.setRowCount(0)
        self.extender.stored_data = []
        self.extender.result_map.clear()
        self.extender.existing_rows.clear()
        self.extender.update_summary()

class KeyNavigator(KeyAdapter):
    def __init__(self, extender): self.extender = extender
    def keyReleased(self, event):
        if event.getKeyCode() in [KeyEvent.VK_UP, KeyEvent.VK_DOWN]:
            self.extender.inline_viewer()
