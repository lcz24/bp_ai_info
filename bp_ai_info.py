# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab, IMessageEditorTab, IMessageEditorTabFactory
from javax.swing import JMenuItem, JMenu, JPanel, JTextArea, JTextField, JButton, BoxLayout, JScrollPane, JLabel, JFrame, SwingUtilities, JTabbedPane
from java.util import ArrayList
from java.awt import Component
from burp.api.montoya.http.message import HttpRequestResponse
import requests
import json
import threading
API_KEY = "wk38vfS8UMtZOtez9Bu5k2AV"
SECRET_KEY = "tikcipqvWUFQzUNrwukgDvgjoPKolIc8"
class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        # 保存回调对象和助手对象以便之后使用1
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        # 设置扩展名
        self._callbacks.setExtensionName("Simple Burp Extension")
        # 注册 HTTP 监听器
        self._callbacks.registerHttpListener(self)
        # 注册上下文菜单工厂
        self._callbacks.registerContextMenuFactory(self)
        # 注册消息编辑器标签工厂
        self._callbacks.registerMessageEditorTabFactory(self)
        # 添加自定义标签页
        self._callbacks.addSuiteTab(self)
        # 初始化白名单列表
        self.whitelist = []

        self._callbacks.printOutput("Extension registered successfully.")
        self.response_cache = {} # 初始化缓存字典

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 0 and messageIsRequest:
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            url = requestInfo.getUrl()
            host = url.getHost()
            if host in self.whitelist:
                self.logWhitelistTraffic(host, url.toString())
                self.showWhitelistInRequest(messageInfo)

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        main_menu = JMenu("Custom Menu")
        menu_item1 = JMenuItem("Show Custom Window", actionPerformed=self.onClick)
        main_menu.add(menu_item1)
        menu_list.add(main_menu)
        return menu_list

    def onClick(self, event):
        SwingUtilities.invokeLater(self.showWindow)

    def showWindow(self):
        frame = JFrame("Custom Window")
        frame.setSize(300, 200)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        label = JLabel("Hello, this is a custom window!")
        frame.getContentPane().add(label)
        frame.setVisible(True)

    def getTabCaption(self):
        return "Custom Tab"

    def getUiComponent(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

        label = JLabel("Enter domain to whitelist:")
        panel.add(label)

        self.textField = JTextField(20)
        panel.add(self.textField)

        addButton = JButton("Add to Whitelist", actionPerformed=self.addToWhitelist)
        panel.add(addButton)

        self.whitelistArea = JTextArea(10, 30)
        self.whitelistArea.setEditable(False)
        self.whitelistArea.setLineWrap(True)        # 启用自动换行
        self.whitelistArea.setWrapStyleWord(True)    # 在单词边界换行
        panel.add(JScrollPane(self.whitelistArea))

        trafficLabel = JLabel("Whitelist Traffic:")
        panel.add(trafficLabel)

        self.trafficArea = JTextArea(10, 30)
        self.trafficArea.setEditable(False)
        self.trafficArea.setLineWrap(True)           # 启用自动换行
        self.trafficArea.setWrapStyleWord(True)      # 在单词边界换行
        panel.add(JScrollPane(self.trafficArea))

        return panel

    def addToWhitelist(self, event):
        domain = self.textField.getText().strip()
        if domain and domain not in self.whitelist:
            self.whitelist.append(domain)
            self.updateWhitelistArea()

    def updateWhitelistArea(self):
        self.whitelistArea.setText("\n".join(self.whitelist))

    def logWhitelistTraffic(self, host, url):
        self.trafficArea.append("Request to whitelisted domain: {}\nURL: {}\n\n".format(host, url))

    def showWhitelistInRequest(self, messageInfo):
        # 获取请求的原始数据
        request = messageInfo.getRequest()
        # 创建一个新的标签页
        tabbedPane = JTabbedPane()
        # 添加原始请求的标签页
        # tabbedPane.addTab("Request", self._requestViewer.getComponent())
        # self._requestViewer.setMessage(request, True)
        # 添加白名单内容的标签页
        whitelistTextArea = JTextArea(10, 30)
        whitelistTextArea.setEditable(False)
        whitelistTextArea.setText("\n".join(self.whitelist))
        tabbedPane.addTab("Whitelist", JScrollPane(whitelistTextArea))
        # 将标签页添加到 HTTP 请求的自定义组件中
        self._callbacks.customizeUiComponent(tabbedPane)
        messageInfo.setHighlight("yellow")
        messageInfo.setComment("Whitelisted domain")
        # messageInfo.setRequest(self._helpers.buildHttpMessage(requestInfo.getHeaders(), requestInfo.getBody()))
        # # 将标签页添加到 HTTP 请求框中
        # self._callbacks.addSuiteTab(self)

    def createNewInstance(self, controller, editable):
        return CustomEditorTab(self, controller, editable)

class CustomEditorTab(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._controller = controller
        self._tabbedPane = JTabbedPane()
        self._textArea = JTextArea()
        self._textArea.setEditable(editable)
        self._tabbedPane.addTab("MarkInfo", JScrollPane(self._textArea))
        self.lastMessage = None
        self._modified = False  # 使用私有变量

        self.lastMessage = None
        self._modified = False
       
        self._textArea.setLineWrap(True)        # 启用自动换行
        self._textArea.setWrapStyleWord(True)   # 在单词边界换行

    def getTabCaption(self):
        return "MarkInfo"

    def getUiComponent(self):
        return self._tabbedPane

    def isEnabled(self, content, isRequest):
        return True

    def isModified(self):
        return self._modified  # 返回私有变量


    def setMessage(self, content, isRequest):
            if content is None:
                self._textArea.setText("")
                self.lastMessage = None
                self._modified = False
            else:
                text = self._extender._helpers.bytesToString(content)
                if text != self.lastMessage:
                    self.lastMessage = text
                    self._textArea.setText(text)
                    self._modified = False
                    
                    requestInfo = self._extender._helpers.analyzeRequest(self._controller.getHttpService(), content)
                    if requestInfo.getUrl() is not None:
                        url = requestInfo.getUrl()
                        host = url.getHost()
                        if host in self._extender.whitelist:
                            # 检查缓存
                            if text in self._extender.response_cache:
                                cached_response = self._extender.response_cache[text]
                                self.displayResponse(cached_response)
                            else:
                                threading.Thread(target=self.makeRequest, args=(text,)).start()

    def makeRequest(self, text):
        try:
            def wrap_text(text, max_width):
                wrapped_lines = []
                for line in text.splitlines():
                    while len(line) > max_width:
                        wrapped_lines.append(line[:max_width])
                        line = line[max_width:]
                    wrapped_lines.append(line)
                return "\n".join(wrapped_lines)
            max_length = 20000
            parts = [text[i:i + max_length] for i in range(0, len(text), max_length)]
            token_url = "https://aip.baidubce.com/oauth/2.0/token"
            params = {"grant_type": "client_credentials", "client_id": API_KEY, "client_secret": SECRET_KEY}
            token_response = requests.post(token_url, params=params)
            access_token = token_response.json().get("access_token")

            full_response_text = ""
            for part in parts:

                url = "https://integrate.api.nvidia.com/v1/chat/completions"
                payload = json.dumps({
  "messages": [
    {
      "role": "user",
      "content":  u"""请分析数据包,解析每一个参数和内容、HTML、js、json、xml等请求头和体、响应头和体可能用到技术和可能存在漏洞。请用中文回答："""+part
    }
  ],
  "stream": False,
  "model": "meta/llama-3.2-3b-instruct",
  "max_tokens": 5024,
  "presence_penalty": 0,
  "frequency_penalty": 0,
  "top_p": 0.7,
  "temperature": 0.2
})



                headers = {'Accept':'application/json','Content-Type': 'application/json','Authorization':'Bearer '}
                response = requests.post(url, headers=headers, data=payload)
                try:
                    # 单独解析每个响应 JSON
                    http_request_example=json.loads(response.text)
                   # print(http_request_example)
                    esponse_result=http_request_example['choices'][0]['message']['content']
                    full_response_text += esponse_result
                except Exception as e:
                    print("Error parsing JSON for part: {}".format(e))

            wrapped_response = wrap_text(full_response_text, 50)
            # 缓存结果
            self._extender.response_cache[text] = wrapped_response
            # 显示结果
            self.displayResponse(wrapped_response)
        except Exception as e:
            print("Error: {}".format(e))

    def displayResponse(self, response_text):
        SwingUtilities.invokeLater(lambda: self._textArea.append(u"\n\n--- 白名单 ---\n" + response_text))


    def getMessage(self):
        return self._extender._helpers.stringToBytes(self._textArea.getText())

    def getSelectedData(self):
        return self._textArea.getSelectedText()



# 创建并注册扩展实例
if __name__ == "__main__":
    extender = BurpExtender()


