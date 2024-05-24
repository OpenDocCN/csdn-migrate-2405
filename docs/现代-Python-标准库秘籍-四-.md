# 现代 Python 标准库秘籍（四）

> 原文：[`zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8`](https://zh.annas-archive.org/md5/3fab99a8deba9438823e5414cd05b6e8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：网络

在本章中，我们将涵盖以下内容：

+   发送电子邮件-从您的应用程序发送电子邮件

+   获取电子邮件-检查并阅读新收到的邮件

+   FTP-从 FTP 上传、列出和下载文件

+   套接字-基于 TCP/IP 编写聊天系统

+   AsyncIO-基于协程的异步 HTTP 服务器，用于静态文件

+   远程过程调用-通过 XMLRPC 实现 RPC

# 介绍

现代应用程序经常需要通过网络与用户或其他软件进行交互。我们的社会越向连接的世界发展，用户就越希望软件能够与远程服务或网络进行交互。

基于网络的应用程序依赖于几十年来稳定且经过广泛测试的工具和范例，Python 标准库提供了对从传输到应用程序协议的最常见技术的支持。

除了提供对通信通道本身（如套接字）的支持外，标准库还提供了实现基于事件的应用程序模型，这些模型是网络使用案例的典型，因为在大多数情况下，应用程序将不得不对来自网络的输入做出反应并相应地处理它。

在本章中，我们将看到如何处理一些最常见的应用程序协议，如 SMTP、IMAP 和 FTP。但我们还将看到如何通过套接字直接处理网络，并如何实现我们自己的 RPC 通信协议。

# 发送电子邮件

电子邮件是当今最广泛使用的通信工具，如果您在互联网上，几乎可以肯定您有一个电子邮件地址，它们现在也高度集成在智能手机中，因此可以随时随地访问。

出于所有这些原因，电子邮件是向用户发送通知、完成报告和长时间运行进程结果的首选工具。

发送电子邮件需要一些机制，如果您想自己支持 SMTP 和 MIME 协议，这两种协议都相当复杂。

幸运的是，Python 标准库内置支持这两种情况，我们可以依赖`smtplib`模块与 SMTP 服务器交互以发送我们的电子邮件，并且可以依赖`email`包来实际创建电子邮件的内容并处理所需的所有特殊格式和编码。

# 如何做...

发送电子邮件是一个三步过程：

1.  联系 SMTP 服务器并对其进行身份验证

1.  准备电子邮件本身

1.  向 SMTP 服务器提供电子邮件

Python 标准库中涵盖了所有三个阶段，我们只需要将它们包装起来，以便在更简单的接口中方便使用：

```py
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
from smtplib import SMTP

class EmailSender:
    def __init__(self, host="localhost", port=25, login="", password=""):
        self._host = host
        self._port = int(port)
        self._login = login
        self._password = password

    def send(self, sender, recipient, subject, body):
        header_charset = 'UTF-8'
        body_charset = 'UTF-8'

        sender_name, sender_addr = parseaddr(sender)
        recipient_name, recipient_addr = parseaddr(recipient)

        sender_name = str(Header(sender_name, header_charset))
        recipient_name = str(Header(recipient_name, header_charset))

        msg = MIMEText(body.encode(body_charset), 'plain', body_charset)
        msg['From'] = formataddr((sender_name, sender_addr))
        msg['To'] = formataddr((recipient_name, recipient_addr))
        msg['Subject'] = Header(subject, header_charset)

        smtp = SMTP(self._host, self._port)
        try:
            smtp.starttls()
        except:
            pass
        smtp.login(self._login, self._password)
        smtp.sendmail(sender, recipient, msg.as_string())
        smtp.quit()
```

我们的`EmailSender`类可用于轻松通过我们的电子邮件提供商发送电子邮件。

```py
es = EmailSender('mail.myserver.it', 
                 login='amol@myserver.it', 
                 password='mymailpassword')
es.send(sender='Sender <no-reply@senders.net>', 
        recipient='amol@myserver.it',
        subject='Hello my friend!',
        body='''Here is a little email for you''')
```

# 它是如何工作的...

发送电子邮件需要连接到 SMTP 服务器，这需要数据，如服务器运行的主机、暴露的端口以及用于对其进行身份验证的用户名和密码。

每次我们想要发送电子邮件时，都需要所有这些细节，因为每封电子邮件都需要单独的连接。因此，这些都是我们负责发送电子邮件的类始终需要可用的所有细节，并且在创建实例时请求：

```py
class EmailSender:
    def __init__(self, host="localhost", port=25, login="", password=""):
        self._host = host
        self._port = int(port)
        self._login = login
        self._password = password
```

一旦知道连接到 SMTP 服务器所需的所有细节，我们类的唯一公开方法就是实际发送电子邮件的方法：

```py
def send(self, sender, recipient, subject, body):
```

这需要组成电子邮件所需的细节：发件人地址、接收电子邮件的地址、主题和电子邮件内容本身。

我们的方法必须解析提供的发件人和收件人。包含发件人和收件人名称的部分与包含地址的部分是分开的：

```py
sender_name, sender_addr = parseaddr(sender)
recipient_name, recipient_addr = parseaddr(recipient)
```

如果`sender`类似于`"Alessandro Molina <amol@myserver.it>"`，`sender_name`将是`"Alessandro Molina"`，`sender_addr`将是`"amol@myserver.it"`。

这是必需的，因为名称部分通常包含不受限于纯 ASCII 的名称，邮件可能会发送到中国、韩国或任何其他需要正确支持 Unicode 以处理收件人名称的地方。

因此，我们必须以一种邮件客户端在接收电子邮件时能够理解的方式正确编码这些字符，这是通过使用提供的字符集编码的`Header`类来完成的，在我们的情况下是`"UTF-8"`：

```py
sender_name = str(Header(sender_name, header_charset))
recipient_name = str(Header(recipient_name, header_charset))
```

一旦发件人和收件人的名称以电子邮件标题所期望的格式进行编码，我们就可以将它们与地址部分结合起来，以构建回一个完整的收件人和发件人，形式为`"Name <address>"`：

```py
msg['From'] = formataddr((sender_name, sender_addr))
msg['To'] = formataddr((recipient_name, recipient_addr))
```

相同的情况也适用于“主题”，作为邮件的一个标题字段，也需要进行编码：

```py
msg['Subject'] = Header(subject, header_charset)
```

相反，消息的正文不必作为标题进行编码，并且可以以任何编码的纯字节表示形式提供，只要指定了编码。

在我们的情况下，消息的正文也被编码为`UTF-8`：

```py
msg = MIMEText(body.encode(body_charset), 'plain', body_charset)
```

然后，一旦消息本身准备就绪，正文和标题都被正确编码，唯一剩下的部分就是实际与 SMTP 服务器取得联系并发送电子邮件。

这是通过创建一个已知地址和端口的`SMTP`对象来完成的：

```py
smtp = SMTP(self._host, self._port)
```

然后，如果 SMTP 服务器支持 TLS 加密，我们就启动它。如果不支持，我们就忽略错误并继续：

```py
try:
    smtp.starttls()
except:
    pass
```

一旦启用了加密（如果可用），我们最终可以对 SMTP 服务器进行身份验证，并将邮件本身发送给相关的收件人：

```py
smtp.login(self._login, self._password)
smtp.sendmail(sender, recipient, msg.as_string())
smtp.quit()
```

为了测试编码是否按预期工作，您可以尝试发送一封包含标准 ASCII 字符之外字符的电子邮件，以查看您的客户端是否正确理解了电子邮件：

```py
es.send(sender='Sender <no-reply@senders.net>', 
        recipient='amol@myserver.it',
        subject='Have some japanese here: ã“ã‚“ã«ã¡ã¯',
        body='''And some chinese here! ä½ å¥½''')
```

如果一切都按预期进行，您应该能够对 SMTP 提供程序进行身份验证，发送电子邮件，并在收件箱中看到具有适当内容的电子邮件。

# 获取电子邮件

经常情况下，应用程序需要对某种事件做出反应，它们接收来自用户或软件的消息，然后需要相应地采取行动。基于网络的应用程序的整体性质在于对接收到的消息做出反应，但这类应用程序的一个非常特定和常见的情况是需要对接收到的电子邮件做出反应。

典型情况是，当用户需要向您的应用程序发送某种文档（通常是身份证或签署的合同）时，您希望对该事件做出反应，例如在用户发送签署的合同后启用服务。

这要求我们能够访问收到的电子邮件并扫描它们以检测发件人和内容。

# 如何做...

这个食谱的步骤如下：

1.  使用`imaplib`和`email`模块，可以构建一个工作的 IMAP 客户端，从支持的 IMAP 服务器中获取最近的消息：

```py
import imaplib
import re
from email.parser import BytesParser

class IMAPReader:
    ENCODING = 'utf-8'
    LIST_PATTERN = re.compile(
        r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)'
    )

    def __init__(self, host, username, password, ssl=True):
        if ssl:
            self._imap = imaplib.IMAP4_SSL(host)
        else:
            self._imap = imaplib.IMAP4(host)
        self._imap.login(username, password)

    def folders(self):
        """Retrieve list of IMAP folders"""
        resp, lines = self._imap.list()
        if resp != 'OK':
            raise Exception(resp)

        entries = []
        for line in lines:
            flags, _, name = self.LIST_PATTERN.match(
                line.decode(self.ENCODING)
            ).groups()
            entries.append(dict(
                flags=flags,
                name=name.strip('"')
            ))
        return entries

    def messages(self, folder, limit=10, peek=True):
        """Return ``limit`` messages from ``folder``

        peek=False will also fetch message body
        """
        resp, count = self._imap.select('"%s"' % folder, readonly=True)
        if resp != 'OK':
            raise Exception(resp)

        last_message_id = int(count[0])
        msg_ids = range(last_message_id, last_message_id-limit, -1)

        mode = '(BODY.PEEK[HEADER])' if peek else '(RFC822)'

        messages = []
        for msg_id in msg_ids:
            resp, msg = self._imap.fetch(str(msg_id), mode)
            msg = msg[0][-1]

            messages.append(BytesParser().parsebytes(msg))
            if len(messages) >= limit:
                break
        return messages

    def get_message_body(self, message):
        """Given a message for which the body was fetched, returns it"""
        body = []
        if message.is_multipart():
            for payload in message.get_payload():
                body.append(payload.get_payload())
        else:
            body.append(message.get_payload())
        return body

    def close(self):
        """Close connection to IMAP server"""
        self._imap.close()
```

1.  然后可以使用`IMAPReader`访问兼容的邮件服务器以阅读最近的电子邮件：

```py
mails = IMAPReader('imap.gmail.com', 
                   YOUR_EMAIL, YOUR_PASSWORD,
                   ssl=True)

folders = mails.folders()
for msg in mails.messages('INBOX', limit=2, peek=True):
    print(msg['Date'], msg['Subject'])
```

1.  这返回了最近两封收到的电子邮件的标题和时间戳：

```py
Fri, 8 Jun 2018 00:07:16 +0200 Hello Python CookBook!
Thu, 7 Jun 2018 08:21:11 -0400 SSL and turbogears.org
```

如果我们需要实际的电子邮件内容和附件，我们可以通过使用`peek=False`来检索它们，然后在检索到的消息上调用`IMAPReader.get_message_body`。

# 它的工作原理是...

我们的类充当了`imaplib`和`email`模块的包装器，为从文件夹中获取邮件的需求提供了一个更易于使用的接口。

实际上，可以从`imaplib`创建两种不同的对象来连接到 IMAP 服务器，一种使用 SSL，一种不使用。根据服务器的要求，您可能需要打开或关闭它（例如，Gmail 需要 SSL），这在`__init__`中进行了抽象处理：

```py
def __init__(self, host, username, password, ssl=True):
    if ssl:
        self._imap = imaplib.IMAP4_SSL(host)
    else:
        self._imap = imaplib.IMAP4(host)
    self._imap.login(username, password)
```

`__init__`方法还负责登录到 IMAP 服务器，因此一旦创建了阅读器，它就可以立即使用。

然后我们的阅读器提供了列出文件夹的方法，因此，如果您想要从所有文件夹中读取消息，或者您想要允许用户选择文件夹，这是可能的：

```py
def folders(self):
    """Retrieve list of IMAP folders"""
```

我们的`folders`方法的第一件事是从服务器获取文件夹列表。`imaplib`方法已经在出现错误时报告异常，但作为安全措施，我们还检查响应是否为`OK`：

```py
resp, lines = self._imap.list()
if resp != 'OK':
    raise Exception(resp)
```

IMAP 是一种基于文本的协议，服务器应该始终响应`OK <response>`，如果它能够理解您的请求并提供响应。否则，可能会返回一堆替代响应代码，例如`NO`或`BAD`。如果返回了其中任何一个，我们认为我们的请求失败了。

一旦我们确保实际上有文件夹列表，我们需要解析它。列表由多行文本组成。每行包含有关一个文件夹的详细信息，这些详细信息：标志和文件夹名称。它们由一个分隔符分隔，这不是标准的。在某些服务器上，它是一个点，而在其他服务器上，它是一个斜杠，因此我们在解析时需要非常灵活。这就是为什么我们使用允许标志和名称由任何分隔符分隔的正则表达式来解析它：

```py
LIST_PATTERN = re.compile(
    r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)'
)
```

一旦我们知道如何解析响应中的这些行，我们就可以根据它们构建一个包含名称和这些文件夹的标志的字典列表：

```py
entries = []
for line in lines:
    flags, _, name = self.LIST_PATTERN.match(
        line.decode(self.ENCODING)
    ).groups()
    entries.append(dict(
        flags=flags,
        name=name.strip('"')
    ))
return entries
```

然后可以使用`imaplib.ParseFlags`类进一步解析这些标志。

一旦我们知道要获取消息的文件夹的名称，我们就可以通过`messages`方法检索消息：

```py
def messages(self, folder, limit=10, peek=True):
    """Return ``limit`` messages from ``folder``

    peek=False will also fetch message body
    """
```

由于 IMAP 是一种有状态的协议，我们需要做的第一件事是选择我们想要运行后续命令的文件夹：

```py
resp, count = self._imap.select('"%s"' % folder, readonly=True)
if resp != 'OK':
    raise Exception(resp)
```

我们提供一个`readonly`选项，这样我们就不会无意中销毁我们的电子邮件，并像往常一样验证响应代码。

然后`select`方法的响应内容实际上是上传到该文件夹的最后一条消息的 ID。

由于这些 ID 是递增的数字，我们可以使用它来生成要获取的最近消息的最后`limit`条消息的 ID：

```py
last_message_id = int(count[0])
msg_ids = range(last_message_id, last_message_id-limit, -1)
```

然后，根据调用者的选择，我们选择要下载的消息的内容。如果只有标题或整个内容：

```py
mode = '(BODY.PEEK[HEADER])' if peek else '(RFC822)'
```

模式将被提供给`fetch`方法，告诉它我们要下载什么数据：

```py
resp, msg = self._imap.fetch(str(msg_id), mode)
```

然后，消息本身被组合成一个包含两个元素的元组列表。第一个元素包含消息返回的大小和模式（由于我们自己提供了模式，所以我们并不真的在乎），元组的最后一个元素包含消息本身，所以我们只需抓取它：

```py
msg = msg[0][-1]
```

一旦我们有了可用的消息，我们将其提供给`BytesParser`，以便我们可以得到一个`Message`实例：

```py
BytesParser().parsebytes(msg)
```

我们循环遍历所有消息，解析它们，并添加到我们将返回的消息列表中。一旦达到所需数量的消息，我们就停止：

```py
messages = []
for msg_id in msg_ids:
    resp, msg = self._imap.fetch(str(msg_id), mode)
    msg = msg[0][-1]

    messages.append(BytesParser().parsebytes(msg))
    if len(messages) >= limit:
        break
return messages
```

从`messages`方法中，我们得到一个`Message`对象的列表，我们可以轻松访问除消息正文之外的所有数据。因为正文实际上可能由多个项目组成（想象一条带附件的消息 - 它包含文本、图像、PDF 文件或任何附件）。

因此，读取器提供了一个`get_message_body`方法，用于检索消息正文的所有部分（如果是多部分消息），并将它们返回：

```py
def get_message_body(self, message):
    """Given a message for which the body was fetched, returns it"""
    body = []
    if message.is_multipart():
        for payload in message.get_payload():
            body.append(payload.get_payload())
    else:
        body.append(message.get_payload())
    return body
```

通过结合`messages`和`get_message_body`方法，我们能够从邮箱中抓取消息及其内容，然后根据需要对其进行处理。

# 还有更多...

编写一个功能完备且完全运行的 IMAP 客户端是一个独立的项目，超出了本书的范围。

IMAP 是一个复杂的协议，包括对标志、搜索和许多其他功能的支持。大多数这些命令都由`imaplib`提供，还可以上传消息到服务器或创建工具来执行备份或将消息从一个邮件帐户复制到另一个邮件帐户。

此外，当解析复杂的电子邮件时，`email`模块将处理电子邮件相关的 RFCs 指定的各种数据表示，例如，我们的示例将日期返回为字符串，但`email.utils.parsedate`可以将其解析为 Python 对象。

# FTP

FTP 是保存和从远程服务器检索文件的最广泛使用的解决方案。它已经存在了几十年，是一个相当容易使用的协议，可以提供良好的性能，因为它在传输内容上提供了最小的开销，同时支持强大的功能，如传输恢复。

通常，软件需要接收由其他软件自动上传的文件；多年来，FTP 一直被频繁地用作这些场景中的强大解决方案。无论您的软件是需要上传内容的软件，还是需要接收内容的软件，Python 标准库都内置了对 FTP 的支持，因此我们可以依靠`ftplib`来使用 FTP 协议。

# 如何做到这一点...

`ftplib`是一个强大的基础，我们可以在其上提供一个更简单的 API 来与 FTP 服务器进行交互，用于存储和检索文件：

```py
import ftplib

class FTPCLient:
    def __init__(self, host, username='', password=''):
        self._client = ftplib.FTP_TLS(timeout=10)
        self._client.connect(host)

        # enable TLS
        try:
            self._client.auth()
        except ftplib.error_perm:
            # TLS authentication not supported
            # fallback to a plain FTP client
            self._client.close()
            self._client = ftplib.FTP(timeout=10)
            self._client.connect(host)

        self._client.login(username, password)

        if hasattr(self._client, 'prot_p'):
            self._client.prot_p()

    def cwd(self, directory):
        """Enter directory"""
        self._client.cwd(directory)

    def dir(self):
        """Returns list of files in current directory.

        Each entry is returned as a tuple of two elements,
        first element is the filename, the second are the
        properties of that file.
        """
        entries = []
        for idx, f in enumerate(self._client.mlsd()):
            if idx == 0:
                # First entry is current path
                continue
            if f[0] in ('..', '.'):
                continue
            entries.append(f)
        return entries

    def download(self, remotefile, localfile):
        """Download remotefile into localfile"""
        with open(localfile, 'wb') as f:
            self._client.retrbinary('RETR %s' % remotefile, f.write)

    def upload(self, localfile, remotefile):
        """Upload localfile to remotefile"""
        with open(localfile, 'rb') as f:
            self._client.storbinary('STOR %s' % remotefile, f)

    def close(self):
        self._client.close()
```

然后，我们可以通过上传和获取一个简单的文件来测试我们的类：

```py
with open('/tmp/hello.txt', 'w+') as f:
    f.write('Hello World!')

cli = FTPCLient('localhost', username=USERNAME, password=PASSWORD)
cli.upload('/tmp/hello.txt', 'hellofile.txt')    
cli.download('hellofile.txt', '/tmp/hello2.txt')

with open('/tmp/hello2.txt') as f:
    print(f.read())
```

如果一切按预期工作，输出应该是`Hello World!`

# 工作原理...

`FTPClient`类提供了一个初始化程序，负责设置与服务器的正确连接以及一堆方法来实际对连接的服务器进行操作。

`__init__`做了很多工作，尝试建立与远程服务器的正确连接：

```py
def __init__(self, host, username='', password=''):
    self._client = ftplib.FTP_TLS(timeout=10)
    self._client.connect(host)

    # enable TLS
    try:
        self._client.auth()
    except ftplib.error_perm:
        # TLS authentication not supported
        # fallback to a plain FTP client
        self._client.close()
        self._client = ftplib.FTP(timeout=10)
        self._client.connect(host)

    self._client.login(username, password)

    if hasattr(self._client, 'prot_p'):
        self._client.prot_p()
```

首先它尝试建立 TLS 连接，这可以保证加密，否则 FTP 是一种明文协议，会以明文方式发送所有数据。

如果我们的远程服务器支持 TLS，可以通过调用`.auth()`在控制连接上启用它，然后通过调用`prot_p()`在数据传输连接上启用它。

FTP 基于两种连接，控制连接用于发送和接收服务器的命令及其结果，数据连接用于发送上传和下载的数据。

如果可能的话，它们两者都应该加密。如果我们的服务器不支持它们，我们将退回到普通的 FTP 连接，并继续通过对其进行身份验证来进行操作。

如果您的服务器不需要任何身份验证，提供`anonymous`作为用户名，空密码通常足以登录。

一旦我们连接上了，我们就可以自由地在服务器上移动，可以使用`cwd`命令来实现：

```py
def cwd(self, directory):
    """Enter directory"""
    self._client.cwd(directory)
```

这个方法只是内部客户端方法的代理，因为内部方法已经很容易使用并且功能齐全。

但一旦我们进入一个目录，我们需要获取它的内容，这就是`dir()`方法发挥作用的地方：

```py
def dir(self):
    """Returns list of files in current directory.

    Each entry is returned as a tuple of two elements,
    first element is the filename, the second are the
    properties of that file.
    """
    entries = []
    for idx, f in enumerate(self._client.mlsd()):
        if idx == 0:
            # First entry is current path
            continue
        if f[0] in ('..', '.'):
            continue
        entries.append(f)
    return entries
```

`dir()`方法调用内部客户端的`mlsd`方法，负责返回当前目录中文件的列表。

这个列表被返回为一个包含两个元素的元组：

```py
('Desktop', {'perm': 'ceflmp', 
             'unique': 'BAAAAT79CAAAAAAA', 
             'modify': '20180522213143', 
             'type': 'dir'})
```

元组的第一个条目包含文件名，而第二个条目包含其属性。

我们自己的方法只做了两个额外的步骤，它跳过了第一个返回的条目——因为那总是当前目录（我们用`cwd()`选择的目录）——然后跳过了任何特殊的父目录或当前目录的条目。我们对它们并不感兴趣。

一旦我们能够在目录结构中移动，我们最终可以将文件`upload`和`download`到这些目录中：

```py
def download(self, remotefile, localfile):
    """Download remotefile into localfile"""
    with open(localfile, 'wb') as f:
        self._client.retrbinary('RETR %s' % remotefile, f.write)

def upload(self, localfile, remotefile):
    """Upload localfile to remotefile"""
    with open(localfile, 'rb') as f:
        self._client.storbinary('STOR %s' % remotefile, f)
```

这两种方法非常简单，当我们上传文件时，它们只是打开本地文件进行读取，当我们下载文件时，它们只是打开本地文件进行写入，并发送 FTP 命令来检索或存储文件。

当上传一个新的`remotefile`时，将创建一个具有与`localfile`相同内容的文件。当下载时，将打开`localfile`以在其中写入`remotefile`的内容。

# 还有更多...

并非所有的 FTP 服务器都支持相同的命令。多年来，该协议进行了许多扩展，因此一些命令可能缺失或具有不同的语义。

例如，`mlsd`函数可能会缺失，但您可能有`LIST`或`nlst`，它们可以执行类似的工作。

您可以参考 RFC 959 了解 FTP 协议应该如何工作，但经常通过明确与您要连接的 FTP 服务器进行实验是评估它将接受哪些命令和签名的最佳方法。

经常，FTP 服务器实现了一个`HELP`命令，您可以使用它来获取支持的功能列表。

# 套接字

套接字是您可以用来编写网络应用程序的最低级别概念之一。这意味着我们通常要自己管理整个连接，当直接依赖套接字时，您需要处理连接请求，接受它们，然后启动一个线程或循环来处理通过新创建的连接通道发送的后续命令或数据。

这几乎所有依赖网络的应用程序都必须实现的流程，通常您调用服务器时都有一个基础在上述循环中。

Python 标准库提供了一个很好的基础，避免每次必须处理基于网络的应用程序时手动重写该流程。我们可以使用`socketserver`模块，让它为我们处理连接循环，而我们只需专注于实现应用程序层协议和处理消息。

# 如何做...

对于这个配方，您需要执行以下步骤：

1.  通过混合`TCPServer`和`ThreadingMixIn`类，我们可以轻松构建一个通过 TCP 处理并发连接的多线程服务器：

```py
import socket
import threading
import socketserver

class EchoServer:
    def __init__(self, host='0.0.0.0', port=9800):
        self._host = host
        self._port = port
        self._server = ThreadedTCPServer((host, port), EchoRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever)
        self._thread.daemon = True

    def start(self):
        if self._thread.is_alive():
            # Already serving
            return

        print('Serving on %s:%s' % (self._host, self._port))
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()

class ThreadedTCPServer(socketserver.ThreadingMixIn, 
                        socketserver.TCPServer):
    allow_reuse_address = True

class EchoRequestHandler(socketserver.BaseRequestHandler):
    MAX_MESSAGE_SIZE = 2**16  # 65k
    MESSAGE_HEADER_LEN = len(str(MAX_MESSAGE_SIZE))

    @classmethod
    def recv_message(cls, socket):
        data_size = int(socket.recv(cls.MESSAGE_HEADER_LEN))
        data = socket.recv(data_size)
        return data

    @classmethod
    def prepare_message(cls, message):
        if len(message) > cls.MAX_MESSAGE_SIZE:
            raise ValueError('Message too big'

        message_size = str(len(message)).encode('ascii')
        message_size = message_size.zfill(cls.MESSAGE_HEADER_LEN)
        return message_size + message

    def handle(self):
        message = self.recv_message(self.request)
        self.request.sendall(self.prepare_message(b'ECHO: %s' % message))
```

1.  一旦我们有一个工作的服务器，为了测试它，我们需要一个客户端向其发送消息。为了方便起见，我们将保持客户端简单，只需连接，发送消息，然后等待一个简短的回复：

```py
def send_message_to_server(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        message = EchoRequestHandler.prepare_message(message)
        sock.sendall(message)
        response = EchoRequestHandler.recv_message(sock)
        print("ANSWER: {}".format(response))
    finally:
        sock.close()
```

1.  现在我们既有服务器又有客户端，我们可以测试我们的服务器是否按预期工作：

```py
server = EchoServer()
server.start()

send_message_to_server('localhost', server._port, b"Hello World 1")
send_message_to_server('localhost', server._port, b"Hello World 2")
send_message_to_server('localhost', server._port, b"Hello World 3")

server.stop()
```

1.  如果一切正常，您应该看到：

```py
Serving on 0.0.0.0:9800
ANSWER: b'ECHO: Hello World 1'
ANSWER: b'ECHO: Hello World 2'
ANSWER: b'ECHO: Hello World 3'
```

# 它是如何工作的...

服务器部分由三个不同的类组成。

`EchoServer`，它编排服务器并提供我们可以使用的高级 API。`EchoRequestHandler`，它管理传入的消息并提供服务。`ThreadedTCPServer`，它负责整个网络部分，打开套接字，监听它们，并生成线程来处理连接。

`EchoServer`允许启动和停止我们的服务器：

```py
class EchoServer:
    def __init__(self, host='0.0.0.0', port=9800):
        self._host = host
        self._port = port
        self._server = ThreadedTCPServer((host, port), EchoRequestHandler)
        self._thread = threading.Thread(target=self._server.serve_forever)
        self._thread.daemon = True

    def start(self):
        if self._thread.is_alive():
            # Already serving
            return

        print('Serving on %s:%s' % (self._host, self._port))
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
```

它创建一个新的线程，服务器将在其中运行并启动它（如果尚未运行）。该线程将只运行`ThreadedTCPServer.serve_forever`方法，该方法循环运行，依次为每个请求提供服务。

当我们完成服务器时，我们可以调用`stop()`方法，它将关闭服务器并等待其完成（一旦完成所有当前运行的请求，它将退出）。

`ThreadedTCPServer`基本上是标准库提供的标准服务器，如果不是因为我们也继承自`ThreadingMixIn`。`Mixin`是一组附加功能，您可以通过继承它来注入类中，在这种特定情况下，它为套接字服务器提供了线程功能。因此，我们可以同时处理多个请求，而不是一次只能处理一个请求。

我们还设置了服务器的`allow_reuse_address = True`属性，以便在发生崩溃或超时的情况下，套接字可以立即重用，而不必等待系统关闭它们。

最后，`EchoRequestHandler`提供了整个消息处理和解析。每当`ThreadedTCPServer`接收到新连接时，它将在处理程序上调用`handle`方法，由处理程序来执行正确的操作。

在我们的情况下，我们只是实现了一个简单的服务器，它会回复发送给它的内容，因此处理程序必须执行两件事：

+   解析传入的消息以了解其内容

+   发送一个具有相同内容的消息

在使用套接字时的一个主要复杂性是它们实际上并不是基于消息的。它们是一连串的数据（好吧，UDP 是基于消息的，但就我们而言，接口并没有太大变化）。这意味着不可能知道新消息何时开始以及消息何时结束。

`handle`方法只告诉我们有一个新连接，但在该连接上，可能会连续发送多条消息，除非我们知道消息何时结束，否则我们会将它们读取为一条大消息。

为了解决这个问题，我们使用了一个非常简单但有效的方法，即给所有消息加上它们自己的大小前缀。因此，当接收到新消息时，我们总是知道我们只需要读取消息的大小，然后一旦知道大小，我们将读取由大小指定的剩余字节。

要读取这些消息，我们依赖于一个实用方法`recv_message`，它将能够从任何提供的套接字中读取以这种方式制作的消息：

```py
@classmethod
def recv_message(cls, socket):
    data_size = int(socket.recv(cls.MESSAGE_HEADER_LEN))
    data = socket.recv(data_size)
    return data
```

该函数的第一件事是从套接字中精确读取`MESSAGE_HEADER_LEN`个字节。这些字节将包含消息的大小。所有大小必须相同。因此，诸如`10`之类的大小将必须表示为`00010`。然后前缀的零将被忽略。然后，该大小使用`int`进行转换，我们将得到正确的数字。大小必须全部相同，否则我们将不知道需要读取多少字节来获取大小。

我们决定将消息大小限制为 65,000，这导致`MESSAGE_HEADER_LEN`为五，因为需要五位数字来表示最多 65,536 的数字：

```py
MAX_MESSAGE_SIZE = 2**16  # 65k
MESSAGE_HEADER_LEN = len(str(MAX_MESSAGE_SIZE))
```

大小并不重要，我们只选择了一个相当大的值。允许的消息越大，就需要更多的字节来表示它们的大小。

然后`recv_message`方法由`handle()`使用来读取发送的消息：

```py
def handle(self):
    message = self.recv_message(self.request)
    self.request.sendall(self.prepare_message(b'ECHO: %s' % message))
```

一旦消息知道，`handle()`方法还会以相同的方式准备发送回一条新消息，并且为了准备响应，它依赖于`prepare_message`，这也是客户端用来发送消息的方法：

```py
@classmethod
def prepare_message(cls, message):
    if len(message) > cls.MAX_MESSAGE_SIZE:
        raise ValueError('Message too big'

    message_size = str(len(message)).encode('ascii')
    message_size = message_size.zfill(cls.MESSAGE_HEADER_LEN)
    return message_size + message
```

该函数的作用是，给定一条消息，它确保消息不会超过允许的最大大小，然后在消息前面加上它的大小。

该大小是通过将消息的长度作为文本获取，然后使用`ascii`编码将其编码为字节来计算的。由于大小只包含数字，因此`ascii`编码已经足够表示它们了：

```py
message_size = str(len(message)).encode('ascii')
```

由于生成的字符串可以有任何大小（从一到五个字节），我们总是用零填充它，直到达到预期的大小：

```py
message_size = message_size.zfill(cls.MESSAGE_HEADER_LEN)
```

然后将生成的字节添加到消息前面，并返回准备好的消息。

有了这两个函数，服务器就能够接收和发送任意大小的消息。

客户端函数的工作方式几乎相同，因为它必须发送一条消息，然后接收答案：

```py
def send_message_to_server(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        message = EchoRequestHandler.prepare_message(message)
        sock.sendall(message)
        response = EchoRequestHandler.recv_message(sock)
        print("ANSWER: {}".format(response))
    finally:
        sock.close()
```

它仍然使用`EchoRequestHandler.prepare_message`来准备发送到服务器的消息，以及`EchoRequestHandler.recv_message`来读取服务器的响应。

唯一的额外部分与连接到服务器有关。为此，我们实际上创建了一个类型为`AF_INET`、`SOCK_STREAM`的套接字，这实际上意味着我们要使用 TCP/IP。

然后我们连接到服务器运行的`ip`和`port`，一旦连接成功，我们就通过生成的套接字`sock`发送消息并在同一个套接字上读取答案。

完成后，我们必须记得关闭套接字，否则它们将一直泄漏，直到操作系统决定杀死它们，因为它们长时间不活动。

# AsyncIO

虽然异步解决方案已经存在多年，但这些天它们变得越来越普遍。主要原因是，拥有一个没有数千个并发用户的应用程序不再是一个不寻常的场景；对于一个小型/中型应用程序来说，这实际上是一个常态，而且我们可以通过全球范围内使用的主要服务扩展到数百万用户。

能够提供这样的服务量，使用基于线程或进程的方法并不适合。特别是当用户触发的许多连接大部分时间可能都在那里无所事事。想想 Facebook Messenger 或 WhatsApp 这样的服务。无论你使用哪一个，你可能偶尔发送一条消息，大部分时间你与服务器的连接都在那里无所事事。也许你是一个热络的聊天者，每秒收到一条消息，但这仍然意味着在你的计算机每秒钟可以做的数百万次操作中，大部分时间都在无所事事。这种应用程序中的大部分繁重工作是由网络部分完成的，因此有很多资源可以通过在单个进程中进行多个连接来共享。

异步技术正好允许这样做，编写一个网络应用程序，而不是需要多个单独的线程（这将浪费内存和内核资源），我们可以有一个由多个协程组成的单个进程和线程，直到实际有事情要做时才会执行。

只要协程需要做的事情非常快速（比如获取一条消息并将其转发给你的另一个联系人），大部分工作将在网络层进行，因此可以并行进行。

# 如何做...

这个配方的步骤如下：

1.  我们将复制我们的回显服务器，但不再使用线程，而是使用 AsyncIO 和协程来提供请求：

```py
import asyncio

class EchoServer:
    MAX_MESSAGE_SIZE = 2**16  # 65k
    MESSAGE_HEADER_LEN = len(str(MAX_MESSAGE_SIZE))

    def __init__(self, host='0.0.0.0', port=9800):
        self._host = host
        self._port = port
        self._server = None

    def serve(self, loop):
        coro = asyncio.start_server(self.handle, self._host, self._port,
                                    loop=loop)
        self._server = loop.run_until_complete(coro)
        print('Serving on %s:%s' % (self._host, self._port))
        loop.run_until_complete(self._server.wait_closed())
        print('Done')

    @property
    def started(self):
        return self._server is not None and self._server.sockets

    def stop(self):
        print('Stopping...')
        self._server.close()

    async def handle(self, reader, writer):
        data = await self.recv_message(reader)
        await self.send_message(writer, b'ECHO: %s' % data)
        # Signal we finished handling this request
        # or the server will hang.
        writer.close()

    @classmethod
    async def recv_message(cls, socket):
        data_size = int(await socket.read(cls.MESSAGE_HEADER_LEN))
        data = await socket.read(data_size)
        return data

    @classmethod
    async def send_message(cls, socket, message):
        if len(message) > cls.MAX_MESSAGE_SIZE:
            raise ValueError('Message too big')

        message_size = str(len(message)).encode('ascii')
        message_size = message_size.zfill(cls.MESSAGE_HEADER_LEN)
        data = message_size + message

        socket.write(data)
        await socket.drain()
```

1.  现在我们有了服务器实现，我们需要一个客户端来测试它。由于实际上客户端做的与我们之前的配方相同，我们只是要重用相同的客户端实现。因此，客户端不会是基于 AsyncIO 和协程的，而是一个使用`socket`的普通函数：

```py
import socket

def send_message_to_server(ip, port, message):
    def _recv_message(socket):
        data_size = int(socket.recv(EchoServer.MESSAGE_HEADER_LEN))
        data = socket.recv(data_size)
        return data

    def _prepare_message(message):
        if len(message) > EchoServer.MAX_MESSAGE_SIZE:
            raise ValueError('Message too big')

        message_size = str(len(message)).encode('ascii')
        message_size = message_size.zfill(EchoServer.MESSAGE_HEADER_LEN)
        return message_size + message

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    try:
        sock.sendall(_prepare_message(message))
        response = _recv_message(sock)
        print("ANSWER: {}".format(response))
    finally:
        sock.close()
```

1.  现在我们可以把这些部分放在一起。为了在同一个进程中运行客户端和服务器，我们将在一个单独的线程中运行`asyncio`循环。因此，我们可以同时启动客户端。这并不是为了服务多个客户端而必须的，只是为了方便，避免不得不启动两个不同的 Python 脚本来玩服务器和客户端。

1.  首先，我们为服务器创建一个将持续`3`秒的线程。3 秒后，我们将明确停止我们的服务器：

```py
server = EchoServer()
def serve_for_3_seconds():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.call_later(3, server.stop)
    server.serve(loop)
    loop.close()

import threading
server_thread = threading.Thread(target=serve_for_3_seconds)
server_thread.start()
```

1.  然后，一旦服务器启动，我们就创建三个客户端并发送三条消息：

```py
while not server.started:
    pass

send_message_to_server('localhost', server._port, b"Hello World 1")
send_message_to_server('localhost', server._port, b"Hello World 2")
send_message_to_server('localhost', server._port, b"Hello World 3")
```

1.  完成后，我们等待服务器退出，因为 3 秒后它应该停止并退出：

```py
server_thread.join()
```

1.  如果一切按预期进行，你应该看到服务器启动，为三个客户端提供服务，然后退出：

```py
Serving on 0.0.0.0:9800
ANSWER: b'ECHO: Hello World 1'
ANSWER: b'ECHO: Hello World 2'
ANSWER: b'ECHO: Hello World 3'
Stopping...
Done 
```

# 工作原理...

这个配方的客户端大部分是直接从套接字服务配方中取出来的。区别在于服务器端不再是多线程的，而是基于协程的。

给定一个`asyncio`事件循环（我们在`serve_for_3_seconds`线程中使用`asyncio.new_event_loop()`创建的），`EchoServer.serve`方法创建一个基于协程的新服务器，并告诉循环永远提供请求，直到服务器本身关闭为止：

```py
def serve(self, loop):
    coro = asyncio.start_server(self.handle, self._host, self._port,
                                loop=loop)
    self._server = loop.run_until_complete(coro)
    print('Serving on %s:%s' % (self._host, self._port))
    loop.run_until_complete(self._server.wait_closed())
    print('Done')
```

`loop.run_until_complete`将阻塞，直到指定的协程退出，而`self._server.wait_closed()`只有在服务器本身停止时才会退出。

为了确保服务器在短时间内停止，当我们创建循环时，我们发出了`loop.call_later(3, server.stop)`的调用。这意味着 3 秒后，服务器将停止，整个循环将退出。

同时，直到服务器真正停止，它将继续提供服务。每个请求都会生成一个运行`handle`函数的协程：

```py
async def handle(self, reader, writer):
    data = await self.recv_message(reader)
    await self.send_message(writer, b'ECHO: %s' % data)
    # Signal we finished handling this request
    # or the server will hang.
    writer.close()
```

处理程序将接收两个流作为参数。一个用于传入数据，另一个用于传出数据。

就像我们在使用线程套接字服务器的情况下所做的那样，我们从`reader`流中读取传入的消息。为此，我们将`recv_message`重新实现为一个协程，这样我们就可以同时读取数据和处理其他请求：

```py
@classmethod
async def recv_message(cls, socket):
    data_size = int(await socket.read(cls.MESSAGE_HEADER_LEN))
    data = await socket.read(data_size)
    return data
```

当消息的大小和消息本身都可用时，我们只需返回消息，以便`send_message`函数可以将其回显到客户端。

在这种情况下，与`socketserver`的唯一特殊更改是我们要写入流写入器，但然后我们必须将其排空：

```py
socket.write(data)
await socket.drain()
```

这是因为在我们写入套接字后，我们需要将控制权发送回`asyncio`循环，以便它有机会实际刷新这些数据。

三秒后，调用`server.stop`方法，这将停止服务器，唤醒`wait_closed()`函数，从而使`EchoServer.serve`方法退出，因为它已经完成。

# 远程过程调用

有数百种系统可以在 Python 中执行 RPC，但由于它具有强大的网络工具并且是一种动态语言，我们需要的一切都已经内置在标准库中。

# 如何做到...

您需要执行以下步骤来完成此操作：

1.  使用`xmlrpc.server`，我们可以轻松创建一个基于 XMLRPC 的服务器，该服务器公开多个服务：

```py
import xmlrpc.server

class XMLRPCServices:
    class ExposedServices:
        pass

    def __init__(self, **services):
        self.services = self.ExposedServices()
        for name, service in services.items():
            setattr(self.services, name, service)

    def serve(self, host='localhost', port=8000):
        print('Serving XML-RPC on {}:{}'.format(host, port))
        self.server = xmlrpc.server.SimpleXMLRPCServer((host, port))
        self.server.register_introspection_functions()
        self.server.register_instance(self.services, 
                                      allow_dotted_names=True)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
```

1.  特别是，我们将公开两项服务：一个用于获取当前时间，另一个用于将数字乘以`2`：

```py
class MathServices:
    def double(self, v):
        return v**2

class TimeServices:
    def currentTime(self):
        import datetime
        return datetime.datetime.utcnow()
```

1.  一旦我们有了我们的服务，我们可以使用`xmlrpc.client.ServerProxy`来消费它们，它提供了一个简单的调用接口来对 XMLRPC 服务器进行操作。

1.  通常情况下，为了在同一进程中启动客户端和服务器，我们可以使用一个线程来启动服务器，并让服务器在该线程中运行，而客户端驱动主线程：

```py
xmlrpcserver = XMLRPCServices(math=MathServices(),
                              time=TimeServices())

import threading
server_thread = threading.Thread(target=xmlrpcserver.serve)
server_thread.start()

from xmlrpc.client import ServerProxy
client = ServerProxy("http://localhost:8000")
print(
    client.time.currentTime()
)

xmlrpcserver.stop()
server_thread.join()
```

1.  如果一切正常，您应该在终端上看到当前时间的打印：

```py
Serving XML-RPC on localhost:8000
127.0.0.1 - - [10/Jun/2018 23:41:25] "POST /RPC2 HTTP/1.1" 200 -
20180610T21:41:25
```

# 它是如何工作的...

`XMLRPCServices`类接受我们要公开的所有服务作为初始化参数并将它们公开：

```py
xmlrpcserver = XMLRPCServices(math=MathServices(),
                              time=TimeServices())
```

这是因为我们公开了一个本地对象（`ExposedServices`），默认情况下为空，但我们将提供的所有服务作为属性附加到其实例上：

```py
def __init__(self, **services):
    self.services = self.ExposedServices()
    for name, service in services.items():
        setattr(self.services, name, service)
```

因此，我们最终暴露了一个`self.services`对象，它有两个属性：`math`和`time`，它们分别指向`MathServices`和`TimeServices`类。

实际上是由`XMLRPCServices.serve`方法来提供它们的：

```py
def serve(self, host='localhost', port=8000):
    print('Serving XML-RPC on {}:{}'.format(host, port))
    self.server = xmlrpc.server.SimpleXMLRPCServer((host, port))
    self.server.register_introspection_functions()
    self.server.register_instance(self.services, 
                                  allow_dotted_names=True)
    self.server.serve_forever()
```

这创建了一个`SimpleXMLRPCServer`实例，它是负责响应 XMLRPC 请求的 HTTP 服务器。

然后，我们将`self.services`对象附加到该实例，并允许它访问子属性，以便嵌套的`math`和`time`属性可以作为服务公开：

```py
self.server.register_instance(self.services, 
                              allow_dotted_names=True)
```

在实际启动服务器之前，我们还启用了内省功能。这些都是允许我们访问公开服务列表并请求其帮助和签名的所有功能：

```py
self.server.register_introspection_functions()
```

然后我们实际上启动了服务器：

```py
self.server.serve_forever()
```

这将阻止`serve`方法并循环提供请求，直到调用`stop`方法为止。

这就是为什么在示例中，我们在单独的线程中启动服务器的原因；也就是说，这样就不会阻塞我们可以用于客户端的主线程。

`stop`方法负责停止服务器，以便`serve`方法可以退出。该方法要求服务器在完成当前请求后立即终止，然后关闭关联的网络连接：

```py
def stop(self):
    self.server.shutdown()
    self.server.server_close()
```

因此，只需创建`XMLRPCServices`并提供它就足以使我们的 RPC 服务器正常运行：

```py
xmlrpcserver = XMLRPCServices(math=MathServices(),
                              time=TimeServices())
xmlrpcserver.serve()
```

在客户端，代码基础要简单得多；只需创建一个针对服务器公开的 URL 的`ServerProxy`即可：

```py
client = ServerProxy("http://localhost:8000")
```

然后，服务器公开的服务的所有方法都可以通过点表示法访问：

```py
client.time.currentTime()
```

# 还有更多...

`XMLRPCServices`具有很大的安全性影响，因此您不应该在开放网络上使用`SimpleXMLRPCServer`。

最明显的问题是，您允许任何人执行远程代码，因为 XMLRPC 服务器未经身份验证。因此，服务器应仅在您可以确保只有受信任的客户端能够访问服务的私人网络上运行。

但即使您在服务前提供适当的身份验证（通过在其前面使用任何 HTTP 代理来实现），您仍希望确保信任客户端将要发送的数据，因为`XMLRPCServices`存在一些安全限制。

所提供的数据是以明文交换的，因此任何能够嗅探您网络的人都能够看到它。

可以通过一些努力绕过这个问题，通过对`SimpleXMLRPCServer`进行子类化，并用 SSL 包装的`socket`实例替换它（客户端也需要这样做才能连接）。

但是，即使涉及到通信渠道的加固，您仍需要信任将要发送的数据，因为解析器是天真的，可以通过发送大量递归数据来使其失效。想象一下，您有一个实体，它扩展到数十个实体，每个实体又扩展到数十个实体，依此类推，达到 10-20 个级别。这将迅速需要大量的 RAM 来解码，但只需要几千字节来构建并通过网络发送。

此外，我们暴露子属性意味着我们暴露了比我们预期的要多得多。

您肯定希望暴露`time`服务的`currentTime`方法：

```py
client.time.currentTime()
```

请注意，您正在暴露`TimeServices`中声明的每个不以`_`开头的属性或方法。

在旧版本的 Python（如 2.7）中，这实际上意味着也暴露了内部代码，因为您可以通过诸如以下方式访问所有公共变量：

```py
client.time.currentTime.im_func.func_globals.keys()
```

然后，您可以通过以下方式检索它们的值：

```py
client.time.currentTime.im_func.func_globals.get('varname')
```

这是一个重大的安全问题。

幸运的是，函数的`im_func`属性已更名为`__func__`，因此不再可访问。但是，对于您自己声明的任何属性，仍然存在这个问题。


# 第十一章：Web 开发

在本章中，我们将介绍以下配方：

+   处理 JSON - 如何解析和编写 JSON 对象

+   解析 URL - 如何解析 URL 的路径、查询和其他部分

+   消费 HTTP - 如何从 HTTP 端点读取数据

+   提交表单到 HTTP - 如何将 HTML 表单提交到 HTTP 端点

+   构建 HTML - 如何生成带有适当转义的 HTML

+   提供 HTTP - 在 HTTP 上提供动态内容

+   提供静态文件 - 如何通过 HTTP 提供静态文件

+   Web 应用程序中的错误 - 如何报告 Web 应用程序中的错误

+   处理表单和文件 - 解析从 HTML 表单和上传的文件接收到的数据

+   REST API - 提供基本的 REST/JSON API

+   处理 cookies - 如何处理 cookies 以识别返回用户

# 介绍

HTTP 协议，更一般地说，Web 技术集，被认为是创建分布式系统的一种有效和健壮的方式，可以利用一种广泛和可靠的方式来实现进程间通信，具有可用的技术和缓存、错误传播、可重复请求的范例，以及在服务可能失败而不影响整体系统状态的情况下的最佳实践。

Python 有许多非常好的和可靠的 Web 框架，从全栈解决方案，如 Django 和 TurboGears，到更精细调整的框架，如 Pyramid 和 Flask。然而，对于许多情况来说，标准库可能已经提供了您需要实现基于 HTTP 的软件的工具，而无需依赖外部库和框架。

在本章中，我们将介绍标准库提供的一些常见配方和工具，这些工具在 HTTP 和基于 Web 的应用程序的上下文中非常方便。

# 处理 JSON

在使用基于 Web 的解决方案时，最常见的需求之一是解析和处理 JSON。Python 内置支持 XML 和 HTML，还支持 JSON 编码和解码。

JSON 编码器也可以被专门化以处理非标准类型，如日期。

# 如何做...

对于这个配方，需要执行以下步骤：

1.  `JSONEncoder`和`JSONDecoder`类可以被专门化以实现自定义的编码和解码行为：

```py
import json
import datetime
import decimal
import types

class CustomJSONEncoder(json.JSONEncoder):
    """JSON Encoder with support for additional types.

    Supports dates, times, decimals, generators and
    any custom class that implements __json__ method.
    """
    def default(self, obj):
        if hasattr(obj, '__json__') and callable(obj.__json__):
            return obj.__json__()
        elif isinstance(obj, (datetime.datetime, datetime.time)):
            return obj.replace(microsecond=0).isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        elif isinstance(obj, types.GeneratorType):
            return list(obj)
        else:
            return super().default(obj)
```

1.  然后，我们可以将我们的自定义编码器传递给`json.dumps`，以根据我们的规则对 JSON 输出进行编码：

```py
jsonstr = json.dumps({'s': 'Hello World',
                    'dt': datetime.datetime.utcnow(),
                    't': datetime.datetime.utcnow().time(),
                    'g': (i for i in range(5)),
                    'd': datetime.date.today(),
                    'dct': {
                        's': 'SubDict',
                        'dt': datetime.datetime.utcnow()
                    }}, 
                    cls=CustomJSONEncoder)

>>> print(jsonstr)
{"t": "10:53:53", 
 "s": "Hello World", 
 "d": "2018-06-29", 
 "dt": "2018-06-29T10:53:53", 
 "dct": {"dt": "2018-06-29T10:53:53", "s": "SubDict"}, 
 "g": [0, 1, 2, 3, 4]}
```

1.  只要提供了`__json__`方法，我们也可以对任何自定义类进行编码：

```py
class Person:
    def __init__(self, name, surname):
        self.name = name
        self.surname = surname

    def __json__(self):
        return {
            'name': self.name,
            'surname': self.surname
        }
```

1.  结果将是一个包含提供数据的 JSON 对象：

```py
>>> print(json.dumps({'person': Person('Simone', 'Marzola')}, 
                     cls=CustomJSONEncoder))
{"person": {"name": "Simone", "surname": "Marzola"}}
```

1.  加载回编码值将导致纯字符串被解码，因为它们不是 JSON 类型：

```py
>>> print(json.loads(jsonstr))
{'g': [0, 1, 2, 3, 4], 
 'd': '2018-06-29', 
 's': 'Hello World', 
 'dct': {'s': 'SubDict', 'dt': '2018-06-29T10:56:30'}, 
 't': '10:56:30', 
 'dt': '2018-06-29T10:56:30'}
```

1.  如果我们还想解析回日期，我们可以尝试专门化`JSONDecoder`来猜测字符串是否包含 ISO 8601 格式的日期，并尝试解析它：

```py
class CustomJSONDecoder(json.JSONDecoder):
    """Custom JSON Decoder that tries to decode additional types.

    Decoder tries to guess dates, times and datetimes in ISO format.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, **kwargs, object_hook=self.parse_object
        )

    def parse_object(self, values):
        for k, v in values.items():
            if not isinstance(v, str):
                continue

            if len(v) == 10 and v.count('-') == 2:
                # Probably contains a date
                try:
                    values[k] = datetime.datetime.strptime(v, '%Y-
                    %m-%d').date()
                except:
                    pass
            elif len(v) == 8 and v.count(':') == 2:
                # Probably contains a time
                try:
                    values[k] = datetime.datetime.strptime(v, 
                    '%H:%M:%S').time()
                except:
                    pass
            elif (len(v) == 19 and v.count('-') == 2 and 
                v.count('T') == 1 and v.count(':') == 2):
                # Probably contains a datetime
                try:
                    values[k] = datetime.datetime.strptime(v, '%Y-
                    %m-%dT%H:%M:%S')
                except:
                    pass
        return values
```

1.  回到以前的数据应该导致预期的类型：

```py
>>> jsondoc = json.loads(jsonstr, cls=CustomJSONDecoder)
>>> print(jsondoc)
{'g': [0, 1, 2, 3, 4], 
 'd': datetime.date(2018, 6, 29), 
 's': 'Hello World', 
 'dct': {'s': 'SubDict', 'dt': datetime.datetime(2018, 6, 29, 10, 56, 30)},
 't': datetime.time(10, 56, 30), 
 'dt': datetime.datetime(2018, 6, 29, 10, 56, 30)}
```

# 它是如何工作的...

要生成 Python 对象的 JSON 表示，使用`json.dumps`方法。该方法接受一个额外的参数`cls`，可以提供自定义编码器类：

```py
json.dumps({'key': 'value', cls=CustomJSONEncoder)
```

每当需要编码编码器不知道如何编码的对象时，提供的类的`default`方法将被调用。

我们的`CustomJSONEncoder`类提供了一个`default`方法，用于处理编码日期、时间、生成器、小数和任何提供`__json__`方法的自定义类：

```py
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, '__json__') and callable(obj.__json__):
            return obj.__json__()
        elif isinstance(obj, (datetime.datetime, datetime.time)):
            return obj.replace(microsecond=0).isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, decimal.Decimal):
            return float(obj)
        elif isinstance(obj, types.GeneratorType):
            return list(obj)
        else:
            return super().default(obj)
```

这是通过依次检查编码对象的属性来完成的。请记住，编码器知道如何编码的对象不会被提供给`default`方法；只有编码器不知道如何处理的对象才会传递给`default`方法。

因此，我们只需要检查我们想要支持的对象，而不是标准对象。

我们的第一个检查是验证提供的对象是否有`__json__`方法：

```py
if hasattr(obj, '__json__') and callable(obj.__json__):
    return obj.__json__()
```

对于具有`__json__`属性的任何对象，该属性是可调用的，我们将依赖调用它来检索对象的 JSON 表示。`__json__`方法所需做的就是返回任何 JSON 编码器知道如何编码的对象，通常是一个`dict`，其中对象的属性将被存储。

对于日期的情况，我们将使用简化的 ISO 8601 格式对其进行编码：

```py
elif isinstance(obj, (datetime.datetime, datetime.time)):
    return obj.replace(microsecond=0).isoformat()
elif isinstance(obj, datetime.date):
    return obj.isoformat()
```

这通常允许来自客户端的轻松解析，例如 JavaScript 解释器可能需要从提供的数据中构建`date`对象。

`Decimal`只是为了方便转换为浮点数。这在大多数情况下足够了，并且与任何 JSON 解码器完全兼容，无需任何额外的机制。当然，我们可以返回更复杂的对象，例如字典，以保留固定的精度：

```py
elif isinstance(obj, decimal.Decimal):
    return float(obj)
```

最后，生成器被消耗，并从中返回包含的值的列表。这通常是您所期望的，表示生成器逻辑本身将需要不合理的努力来保证跨语言的兼容性：

```py
elif isinstance(obj, types.GeneratorType):
    return list(obj)
```

对于我们不知道如何处理的任何对象，我们只需让父对象实现`default`方法并继续：

```py
else:
    return super().default(obj)
```

这将只是抱怨对象不可 JSON 序列化，并通知开发人员我们不知道如何处理它。

自定义解码器支持的工作方式略有不同。

虽然编码器将接收它知道的对象和它不知道的对象（因为 Python 对象比 JSON 对象更丰富），但很容易看出它只能请求对它不知道的对象进行额外的指导，并对它知道如何处理的对象以标准方式进行处理。

解码器只接收有效的 JSON 对象；否则，提供的字符串根本就不是有效的 JSON。

它如何知道提供的字符串必须解码为普通字符串，还是应该要求额外的指导？

它不能，因此它要求对任何单个解码的对象进行指导。

这就是为什么解码器基于一个`object_hook`可调用，它将接收每个单独解码的 JSON 对象，并可以检查它以执行其他转换，或者如果正常解码是正确的，它可以让它继续。

在我们的实现中，我们对解码器进行了子类化，并提供了一个基于本地类方法`parse_object`的默认`object_hook`参数：

```py
class CustomJSONDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, **kwargs, object_hook=self.parse_object
        )
```

然后，`parse_object`方法将接收到解码 JSON（顶级或嵌套的）中找到的任何 JSON 对象；因此，它将接收到一堆字典，可以以任何需要的方式检查它们，并编辑它们的内容以执行 JSON 解码器本身执行的其他转换：

```py
def parse_object(self, values):
    for k, v in values.items():
        if not isinstance(v, str):
            continue

        if len(v) == 10 and v.count('-') == 2:
            # Probably contains a date
            try:
                values[k] = datetime.datetime.strptime(v, '%Y-%m-
                %d').date()
            except:
                pass
        elif len(v) == 8 and v.count(':') == 2:
            # Probably contains a time
            try:
                values[k] = datetime.datetime.strptime(v, 
                '%H:%M:%S').time()
            except:
                pass
        elif (len(v) == 19 and v.count('-') == 2 and 
            v.count('T') == 1 and v.count(':') == 2):
            # Probably contains a datetime
            try:
                values[k] = datetime.datetime.strptime(v, '%Y-%m-
                %dT%H:%M:%S')
            except:
                pass
    return values
```

接收到的参数实际上是一个完整的 JSON 对象，因此它永远不会是单个字段；它总是一个对象（因此，一个完整的 Python 字典，具有多个键值）。

看看以下对象：

```py
{'g': [0, 1, 2, 3, 4], 
 'd': '2018-06-29', 
 's': 'Hello World', 
```

您不会收到一个`g`键，但您将收到整个 Python 字典。这意味着如果您的 JSON 文档没有嵌套的 JSON 对象，您的`object_hook`将被调用一次，并且不会再有其他调用。

因此，我们的`parse_object`方法提供的自定义`object_hook`会迭代解码后的 JSON 对象的所有属性：

```py
for k, v in values.items():
    if not isinstance(v, str):
        continue
```

由于 JSON 中的日期和时间通常以 ISO 8601 格式的字符串表示，因此它会忽略一切不是字符串的内容。

我们对数字、列表和字典的转换非常满意（如果您期望日期被放在列表中，可能需要转到列表），因此如果值不是字符串，我们就跳过它。

当值是字符串时，我们检查其属性，如果我们猜测它可能是日期，我们尝试将其解析为日期。

我们可以考虑日期的正确定义：由两个破折号分隔的三个值，后跟由两个冒号分隔的三个值，中间有一个"T"来分隔两个值：

```py
elif (len(v) == 19 and v.count('-') == 2 and 
      v.count('T') == 1 and v.count(':') == 2):
    # Probably contains a datetime
```

如果匹配该定义，我们实际上会尝试将其解码为 Python 的`datetime`对象，并在解码后的 JSON 对象中替换该值：

```py
# Probably contains a datetime
try:
    values[k] = datetime.datetime.strptime(v, '%Y-%m-%dT%H:%M:%S')
except:
    pass
```

# 还有更多...

您可能已经注意到，将 Python 编码为 JSON 是相当合理和健壮的，但返回的过程中充满了问题。

JSON 不是一种非常表达性的语言；它不提供任何用于自定义类型的机制，因此您有一种标准方法可以向解码器提供关于您期望将某些内容解码为的类型的提示。

虽然我们可以*猜测*像`2017-01-01T13:21:17`这样的东西是一个日期，但我们根本没有任何保证。也许最初它实际上是一些文本，碰巧包含可以解码为日期的内容，但从未打算成为 Python 中的`datetime`对象。

因此，通常只在受限环境中实现自定义解码是安全的。如果您知道并控制将接收数据的源，通常可以安全地提供自定义解码。您可能希望通过使用自定义属性来扩展 JSON，这些属性可能会指导解码器（例如具有告诉您它是日期还是字符串的`__type__`键），但在开放的网络世界中，通常不明智地尝试猜测人们发送给您的内容，因为网络非常多样化。

有一些扩展的标准 JSON 版本试图解决解码数据中的这种歧义，例如 JSON-LD 和 JSON Schema，它们允许您在 JSON 中表示更复杂的实体。

如果有必要，您应该依赖这些标准，以避免重新发明轮子的风险，并面对您的解决方案已经由现有标准解决的限制。

# 解析 URL

在处理基于 Web 的软件时，经常需要了解链接、协议和路径。

您可能会倾向于依赖正则表达式或字符串拆分来解析 URL，但是如果考虑到 URL 可能包含的所有奇特之处（例如凭据或特定协议等），它可能并不像您期望的那样容易。

Python 提供了`urllib`和`cgi`模块中的实用工具，当您想要考虑 URL 可能具有的所有可能不同的格式时，这些工具可以使生活更轻松。

依靠它们可以使生活更轻松，使您的软件更健壮。

# 如何做...

`urllib.parse`模块具有多种工具可用于解析 URL。最常用的解决方案是依赖于`urllib.parse.urlparse`，它可以处理最常见的 URL 类型：

```py
import urllib.parse

def parse_url(url):
    """Parses an URL of the most widespread format.

    This takes for granted there is a single set of parameters
    for the whole path.
    """
    parts = urllib.parse.urlparse(url)
    parsed = vars(parts)
    parsed['query'] = urllib.parse.parse_qs(parts.query)
    return parsed
```

可以在命令行上调用前面的代码片段，如下所示：

```py
>>> url = 'http://user:pwd@host.com:80/path/subpath?arg1=val1&arg2=val2#fragment'
>>> result = parse_url(url)
>>> print(result)
OrderedDict([('scheme', 'http'),
             ('netloc', 'user:pwd@host.com:80'),
             ('path', '/path/subpath'),
             ('params', ''),
             ('query', {'arg1': ['val1'], 'arg2': ['val2']}),
             ('fragment', 'fragment')])
```

返回的`OrderedDict`包含组成我们的 URL 的所有部分，并且对于查询参数，它们已经被解析。

# 还有更多...

如今，URI 还支持在每个路径段中提供参数。这在实践中很少使用，但如果您的代码预期接收此类 URI，则不应依赖于`urllib.parse.urlparse`，因为它尝试从 URL 中解析参数，而这对于这些 URI 来说并不受支持：

```py
>>> url = 'http://user:pwd@host.com:80/root;para1/subpath;para2?arg1=val1#fragment'
>>> result = urllib.parse.urlparse(url)
>>> print(result)
ParseResult(scheme='http', netloc='user:pwd@host.com:80', 
            path='/root;para1/subpath', 
            params='para2', 
            query='arg1=val1', 
            fragment='fragment')
```

您可能已经注意到，路径的最后一部分的参数在`params`中被正确解析，但是第一部分的参数保留在`path`中。

在这种情况下，您可能希望依赖于`urllib.parse.urlsplit`，它不会解析参数，而会将它们保留下来供您解析。因此，您可以自行拆分 URL 段和参数：

```py
>>> parsed = urllib.parse.urlsplit(url)
>>> print(parsed)
SplitResult(scheme='http', netloc='user:pwd@host.com:80', 
            path='/root;para1/subpath;para2', 
            query='arg1=val1', 
            fragment='fragment')
```

请注意，在这种情况下，所有参数都保留在“路径”中，然后您可以自行拆分它们。

# HTTP 消费

您可能正在与基于 HTTP REST API 的第三方服务进行交互，或者可能正在从第三方获取内容或仅下载软件需要的文件。这并不重要。如今，几乎不可能编写一个应用程序并忽略 HTTP；您迟早都会面对它。人们期望各种应用程序都支持 HTTP。如果您正在编写图像查看器，他们可能希望能够将指向图像的 URL 传递给它并看到图像出现。

虽然它们从来没有真正用户友好和明显，但 Python 标准库一直有与 HTTP 交互的方式，并且这些方式可以直接使用。

# 如何做到这一点...

此处的步骤如下：

1.  `urllib.request`模块提供了提交 HTTP 请求所需的机制。它的轻量级包装可以解决大多数 HTTP 使用需求：

```py
import urllib.request
import urllib.parse
import json

def http_request(url, query=None, method=None, headers={}, data=None):
    """Perform an HTTP request and return the associated response."""
    parts = vars(urllib.parse.urlparse(url))
    if query:
        parts['query'] = urllib.parse.urlencode(query)

    url = urllib.parse.ParseResult(**parts).geturl()
    r = urllib.request.Request(url=url, method=method, 
                            headers=headers,
                            data=data)
    with urllib.request.urlopen(r) as resp:
        msg, resp = resp.info(), resp.read()

    if msg.get_content_type() == 'application/json':
        resp = json.loads(resp.decode('utf-8'))

    return msg, resp
```

1.  我们可以使用我们的`http_request`函数执行请求以获取文件：

```py
>>> msg, resp = http_request('https://httpbin.org/bytes/16')
>>> print(msg.get_content_type(), resp)
application/octet-stream b'k\xe3\x05\x06=\x17\x1a9%#\xd0\xae\xd8\xdc\xf9>'
```

1.  我们还可以使用它与基于 JSON 的 API 进行交互：

```py
>>> msg, resp = http_request('https://httpbin.org/get', query={
...     'a': 'Hello',
...     'b': 'World'
... })
>>> print(msg.get_content_type(), resp)
application/json
{'url': 'https://httpbin.org/get?a=Hello&b=World', 
 'headers': {'Accept-Encoding': 'identity', 
             'User-Agent': 'Python-urllib/3.5', 
             'Connection': 'close', 
             'Host': 'httpbin.org'}, 
 'args': {'a': 'Hello', 'b': 'World'}, 
 'origin': '127.19.102.123'}
```

1.  它还可以用于提交或上传数据到端点：

```py
>>> msg, resp = http_request('https://httpbin.org/post', method='POST',
...                          data='This is my posted data!'.encode('ascii'),
...                          headers={'Content-Type': 'text/plain'})
>>> print(msg.get_content_type(), resp)
application/json 
{'data': 'This is my posted data!', 
 'json': None, 
 'form': {}, 
 'args': {}, 
 'files': {}, 
 'headers': {'User-Agent': 'Python-urllib/3.5', 
             'Connection': 'close', 
             'Content-Type': 'text/plain', 
             'Host': 'httpbin.org', 
             'Accept-Encoding': 'identity', 
             'Content-Length': '23'}, 
 'url': 'https://httpbin.org/post', 
 'origin': '127.19.102.123'}
```

# 它是如何工作的...

`http_request`方法负责创建`urllib.request.Request`实例，通过网络发送它并获取响应。

向指定的 URL 发送请求，其中附加了查询参数。

函数的第一件事是解析 URL，以便能够替换其中的部分。这样做是为了能够用提供的部分替换/追加查询参数：

```py
parts = vars(urllib.parse.urlparse(url))
if query:
    parts['query'] = urllib.parse.urlencode(query)
```

`urllib.parse.urlencode`将接受一个参数字典，例如`{'a': 5, 'b': 7}`，并将返回带有`urlencode`参数的字符串：`'b=7&a=5'`。

然后，将生成的查询字符串放入`url`的解析部分中，以替换当前存在的查询参数。

然后，从现在包括正确查询参数的所有部分构建`url`：

```py
url = urllib.parse.ParseResult(**parts).geturl()
```

一旦准备好带有编码查询的`url`，它就会构建一个请求，代理指定的方法、标头和请求的主体：

```py
r = urllib.request.Request(url=url, method=method, headers=headers,
                           data=data)
```

在进行普通的`GET`请求时，这些将是默认的，但能够指定它们允许我们执行更高级的请求，例如`POST`，或者在我们的请求中提供特殊的标头。

然后打开请求并读取响应：

```py
with urllib.request.urlopen(r) as resp:
    msg, resp = resp.info(), resp.read()
```

响应以`urllib.response.addinfourl`对象的形式返回，其中包括两个相关部分：响应的主体和一个`http.client.HTTPMessage`，我们可以从中获取所有响应信息，如标头、URL 等。

通过像读取文件一样读取响应来检索主体，而通过`info()`方法检索`HTTPMessage`。

通过检索的信息，我们可以检查响应是否为 JSON 响应，在这种情况下，我们将其解码回字典，以便我们可以浏览响应而不仅仅是接收纯字节：

```py
if msg.get_content_type() == 'application/json':
    resp = json.loads(resp.decode('utf-8'))
```

对于所有响应，我们返回消息和主体。如果不需要，调用者可以忽略消息：

```py
return msg, resp
```

# 还有更多...

对于简单的情况来说，进行 HTTP 请求可能非常简单，但对于更复杂的情况来说可能非常复杂。完美地处理 HTTP 协议可能是一项漫长而复杂的工作，特别是因为协议规范本身并不总是清楚地规定事物应该如何工作，很多都来自于对现有的网络服务器和客户端工作方式的经验。

因此，如果您的需求超出了仅仅获取简单端点的范围，您可能希望依赖于第三方库来执行 HTTP 请求，例如几乎适用于所有 Python 环境的 requests 库。

# 向 HTTP 提交表单

有时您必须与 HTML 表单交互或上传文件。这通常需要处理`multipart/form-data`编码。

表单可以混合文件和文本数据，并且表单中可以有多个不同的字段。因此，它需要一种方式来在同一个请求中表示多个字段，其中一些字段可以是二进制文件。

这就是为什么在多部分中编码数据可能会变得棘手，但是可以使用标准库工具来制定一个基本的食谱，以便在大多数情况下都能正常工作。

# 如何做到这一点...

以下是此食谱的步骤：

1.  `multipart`本身需要跟踪我们想要编码的所有字段和文件，然后执行编码本身。

1.  我们将依赖`io.BytesIO`来存储所有生成的字节：

```py
import io
import mimetypes
import uuid

class MultiPartForm:
    def __init__(self):
        self.fields = {}
        self.files = []

    def __setitem__(self, name, value):
        self.fields[name] = value

    def add_file(self, field, filename, data, mimetype=None):
        if mimetype is None:
            mimetype = (mimetypes.guess_type(filename)[0] or
                        'application/octet-stream')
        self.files.append((field, filename, mimetype, data))

    def _generate_bytes(self, boundary):
        buffer = io.BytesIO()
        for field, value in self.fields.items():
            buffer.write(b'--' + boundary + b'\r\n')
            buffer.write('Content-Disposition: form-data; '
                        'name="{}"\r\n'.format(field).encode('utf-8'))
            buffer.write(b'\r\n')
            buffer.write(value.encode('utf-8'))
            buffer.write(b'\r\n')
        for field, filename, f_content_type, body in self.files:
            buffer.write(b'--' + boundary + b'\r\n')
            buffer.write('Content-Disposition: file; '
                        'name="{}"; filename="{}"\r\n'.format(
                            field, filename
                        ).encode('utf-8'))
            buffer.write('Content-Type: {}\r\n'.format(
                f_content_type
            ).encode('utf-8'))
            buffer.write(b'\r\n')
            buffer.write(body)
            buffer.write(b'\r\n')
        buffer.write(b'--' + boundary + b'--\r\n')
        return buffer.getvalue()

    def encode(self):
        boundary = uuid.uuid4().hex.encode('ascii')
        while boundary in self._generate_bytes(boundary=b'NOBOUNDARY'):
            boundary = uuid.uuid4().hex.encode('ascii')

        content_type = 'multipart/form-data; boundary={}'.format(
            boundary.decode('ascii')
        )
        return content_type, self._generate_bytes(boundary)
```

1.  然后我们可以提供并编码我们的`form`数据：

```py
>>> form = MultiPartForm()
>>> form['name'] = 'value'
>>> form.add_file('file1', 'somefile.txt', b'Some Content', 'text/plain')
>>> content_type, form_body = form.encode()
>>> print(content_type, '\n\n', form_body.decode('ascii'))
multipart/form-data; boundary=6c5109dfa19a450695013d4eecac2b0b 

--6c5109dfa19a450695013d4eecac2b0b
Content-Disposition: form-data; name="name"

value
--6c5109dfa19a450695013d4eecac2b0b
Content-Disposition: file; name="file1"; filename="somefile.txt"
Content-Type: text/plain

Some Content
--6c5109dfa19a450695013d4eecac2b0b--
```

1.  使用我们先前食谱中的`http_request`方法，我们可以通过 HTTP 提交任何`form`：

```py
>>> _, resp = http_request('https://httpbin.org/post', method='POST',
                           data=form_body, 
                           headers={'Content-Type': content_type})
>>> print(resp)
{'headers': {
    'Accept-Encoding': 'identity', 
    'Content-Type': 'multipart/form-data; boundary=6c5109dfa19a450695013d4eecac2b0b', 
    'User-Agent': 'Python-urllib/3.5', 
    'Content-Length': '272', 
    'Connection': 'close', 
    'Host': 'httpbin.org'
 }, 
 'json': None,
 'url': 'https://httpbin.org/post', 
 'data': '', 
 'args': {}, 
 'form': {'name': 'value'}, 
 'origin': '127.69.102.121', 
 'files': {'file1': 'Some Content'}}
```

正如你所看到的，`httpbin`正确接收了我们的`file1`和我们的`name`字段，并对两者进行了处理。

# 工作原理...

`multipart`实际上是基于在单个主体内编码多个请求。每个部分都由一个**boundary**分隔，而在边界内则是该部分的数据。

每个部分都可以提供数据和元数据，例如所提供数据的内容类型。

这样接收者就可以知道所包含的数据是二进制、文本还是其他类型。例如，指定`form`的`surname`字段值的部分将如下所示：

```py
Content-Disposition: form-data; name="surname"

MySurname
```

提供上传文件数据的部分将如下所示：

```py
Content-Disposition: file; name="file1"; filename="somefile.txt"
Content-Type: text/plain

Some Content
```

我们的`MultiPartForm`允许我们通过字典语法存储纯`form`字段：

```py
def __setitem__(self, name, value):
    self.fields[name] = value
```

我们可以在命令行上调用它，如下所示：

```py
>>> form['name'] = 'value'
```

并通过`add_file`方法提供文件：

```py
def add_file(self, field, filename, data, mimetype=None):
    if mimetype is None:
        mimetype = (mimetypes.guess_type(filename)[0] or
                    'application/octet-stream')
    self.files.append((field, filename, mimetype, data))
```

我们可以在命令行上调用这个方法，如下所示：

```py
>>> form.add_file('file1', 'somefile.txt', b'Some Content', 'text/plain')
```

这些只是在稍后调用`_generate_bytes`时才会使用的字典和列表，用于记录想要的字段和文件。

所有的辛苦工作都是由`_generate_bytes`完成的，它会遍历所有这些字段和文件，并为每一个创建一个部分：

```py
for field, value in self.fields.items():
    buffer.write(b'--' + boundary + b'\r\n')
    buffer.write('Content-Disposition: form-data; '
                'name="{}"\r\n'.format(field).encode('utf-8'))
    buffer.write(b'\r\n')
    buffer.write(value.encode('utf-8'))
    buffer.write(b'\r\n')
```

由于边界必须分隔每个部分，非常重要的是要验证边界是否不包含在数据本身中，否则接收者可能会在遇到它时错误地认为部分已经结束。

这就是为什么我们的`MultiPartForm`类会生成一个`boundary`，检查它是否包含在多部分响应中，如果是，则生成一个新的，直到找到一个不包含在数据中的`boundary`：

```py
boundary = uuid.uuid4().hex.encode('ascii')
while boundary in self._generate_bytes(boundary=b'NOBOUNDARY'):
    boundary = uuid.uuid4().hex.encode('ascii')
```

一旦我们找到了一个有效的`boundary`，我们就可以使用它来生成多部分内容，并将其返回给调用者，同时提供必须使用的内容类型（因为内容类型为接收者提供了关于要检查的`boundary`的提示）：

```py
content_type = 'multipart/form-data; boundary={}'.format(
    boundary.decode('ascii')
)
return content_type, self._generate_bytes(boundary)
```

# 还有更多...

多部分编码并不是一个简单的主题；例如，在多部分主体中对名称的编码并不是一个简单的话题。

多年来，关于在多部分内容中对字段名称和文件名称进行正确编码的方式已经多次更改和讨论。

从历史上看，在这些字段中只依赖于纯 ASCII 名称是安全的，因此，如果您想确保您提交的数据的服务器能够正确接收您的数据，您可能希望坚持使用简单的文件名和字段，不涉及 Unicode 字符。

多年来，提出了多种其他编码这些字段和文件名的方法。UTF-8 是 HTML5 的官方支持的后备之一。建议的食谱依赖于 UTF-8 来编码文件名和字段，以便与使用纯 ASCII 名称的情况兼容，但仍然可以在服务器支持它们时依赖于 Unicode 字符。

# 构建 HTML

每当您构建网页、电子邮件或报告时，您可能会依赖用实际值替换 HTML 模板中的占位符，以便向用户显示所需的内容。

我们已经在第二章中看到了*文本管理*，如何实现一个最小的简单模板引擎，但它并不特定于 HTML。

在处理 HTML 时，特别重要的是要注意对用户提供的值进行转义，因为这可能导致页面损坏甚至 XSS 攻击。

显然，您不希望您的用户因为您在网站上注册时使用姓氏`"<script>alert('You are hacked!')</script>"`而对您生气。

出于这个原因，Python 标准库提供了可以用于正确准备内容以插入 HTML 的转义工具。

# 如何做...

结合`string.Formatter`和`cgi`模块，可以创建一个负责为我们进行转义的格式化程序：

```py
import string
import cgi

class HTMLFormatter(string.Formatter):
    def get_field(self, field_name, args, kwargs):
        val, key = super().get_field(field_name, args, kwargs)
        if hasattr(val, '__html__'):
            val = val.__html__()
        elif isinstance(val, str):
            val = cgi.escape(val)
        return val, key

class Markup:
    def __init__(self, v):
        self.v = v
    def __str__(self):
        return self.v
    def __html__(self):
        return str(self)
```

然后我们可以在需要时使用`HTMLFormatter`和`Markup`类，同时保留注入原始`html`的能力：

```py
>>> html = HTMLFormatter().format('Hello {name}, you are {title}', 
                                  name='<strong>Name</strong>',
                                  title=Markup('<em>a developer</em>'))
>>> print(html)
Hello &lt;strong&gt;Name&lt;/strong&gt;, you are <em>a developer</em>
```

我们还可以轻松地将此配方与有关文本模板引擎的配方相结合，以实现一个具有转义功能的极简 HTML 模板引擎。

# 它是如何工作的...

每当`HTMLFormatter`需要替换格式字符串中的值时，它将检查检索到的值是否具有`__html__`方法：

```py
if hasattr(val, '__html__'):
    val = val.__html__()
```

如果存在该方法，则预计返回值的 HTML 表示。并且预计是一个完全有效和转义的 HTML。

否则，预计值将是需要转义的字符串：

```py
elif isinstance(val, str):
    val = cgi.escape(val)
```

这样，我们提供给`HTMLFormatter`的任何值都会默认进行转义：

```py
>>> html = HTMLFormatter().format('Hello {name}', 
                                  name='<strong>Name</strong>')
>>> print(html)
Hello &lt;strong&gt;Name&lt;/strong&gt;
```

如果我们想要避免转义，我们可以依赖`Markup`对象，它可以包装一个字符串，使其原样传递而不进行任何转义：

```py
>>> html = HTMLFormatter().format('Hello {name}', 
                                  name=Markup('<strong>Name</strong>'))
>>> print(html)
Hello <strong>Name</strong>
```

这是因为我们的`Markup`对象实现了一个`__html__`方法，该方法返回原样的字符串。由于我们的`HTMLFormatter`忽略了任何具有`__html__`方法的值，因此我们的字符串将无需任何形式的转义而通过。

虽然`Markup`允许我们根据需要禁用转义，但是当我们知道实际上需要 HTML 时，我们可以将 HTML 方法应用于任何其他对象。需要在网页中表示的任何对象都可以提供一个`__html__`方法，并将根据它自动转换为 HTML。

例如，您可以向您的`User`类添加`__html__`，并且每当您想要将用户放在网页中时，您只需要提供`User`实例本身。

# 提供 HTTP

通过 HTTP 进行交互是分布式应用程序或完全分离的软件之间最常见的通信手段之一，也是所有现有 Web 应用程序和基于 Web 的工具的基础。

虽然 Python 有数十个出色的 Web 框架可以满足大多数不同的需求，但标准库本身具有您可能需要实现基本 Web 应用程序的所有基础。

# 如何做...

Python 有一个方便的协议名为 WSGI 来实现基于 HTTP 的应用程序。对于更高级的需求，可能需要一个 Web 框架；对于非常简单的需求，Python 本身内置的`wsgiref`实现可以满足我们的需求：

```py
import re
import inspect
from wsgiref.headers import Headers
from wsgiref.simple_server import make_server
from wsgiref.util import request_uri
from urllib.parse import parse_qs

class WSGIApplication:
    def __init__(self):
        self.routes = []

    def route(self, path):
        def _route_decorator(f):
            self.routes.append((re.compile(path), f))
            return f
        return _route_decorator

    def serve(self):
        httpd = make_server('', 8000, self)
        print("Serving on port 8000...")
        httpd.serve_forever()

    def _not_found(self, environ, resp):
        resp.status = '404 Not Found'
        return b"""<h1>Not Found</h1>"""

    def __call__(self, environ, start_response):
        request = Request(environ)

        routed_action = self._not_found
        for regex, action in self.routes:
            match = regex.fullmatch(request.path)
            if match:
                routed_action = action
                request.urlargs = match.groupdict()
                break

        resp = Response()

        if inspect.isclass(routed_action):
            routed_action = routed_action()
        body = routed_action(request, resp)

        resp.send(start_response)
        return [body]

class Response:
    def __init__(self):
        self.status = '200 OK'
        self.headers = Headers([
            ('Content-Type', 'text/html; charset=utf-8')
        ])

    def send(self, start_response):
        start_response(self.status, self.headers.items())

class Request:
    def __init__(self, environ):
        self.environ = environ
        self.urlargs = {}

    @property
    def path(self):
        return self.environ['PATH_INFO']

    @property
    def query(self):
        return parse_qs(self.environ['QUERY_STRING'])
```

然后我们可以创建一个`WSGIApplication`并向其注册任意数量的路由：

```py
app = WSGIApplication()

@app.route('/')
def index(request, resp):
    return b'Hello World, <a href="/link">Click here</a>'

@app.route('/link')
def link(request, resp):
    return (b'You clicked the link! '
            b'Try <a href="/args?a=1&b=2">Some arguments</a>')

@app.route('/args')
def args(request, resp):
    return (b'You provided %b<br/>'
            b'Try <a href="/name/HelloWorld">URL Arguments</a>' % 
            repr(request.query).encode('utf-8'))

@app.route('/name/(?P<first_name>\\w+)')
def name(request, resp):
    return (b'Your name: %b' % request.urlargs['first_name'].encode('utf-8'))
```

一旦准备就绪，我们只需要提供应用程序：

```py
app.serve()
```

如果一切正常，通过将浏览器指向`http://localhost:8000`，您应该会看到一个 Hello World 文本和一个链接，引导您到进一步提供查询参数，URL 参数并在各种 URL 上提供服务的页面。

# 它是如何工作的...

`WSGIApplication`创建一个负责提供 Web 应用程序本身（`self`）的 WSGI 服务器：

```py
def serve(self):
    httpd = make_server('', 8000, self)
    print("Serving on port 8000...")
    httpd.serve_forever()
```

在每个请求上，服务器都会调用`WSGIApplication.__call__`来检索该请求的响应。

`WSGIApplication.__call__`扫描所有注册的路由（每个路由可以使用`app.route(path)`注册，其中`path`是正则表达式）。当正则表达式与当前 URL 路径匹配时，将调用注册的函数以生成该路由的响应：

```py
def __call__(self, environ, start_response):
    request = Request(environ)

    routed_action = self._not_found
    for regex, action in self.routes:
        match = regex.fullmatch(request.path)
        if match:
            routed_action = action
            request.urlargs = match.groupdict()
            break
```

一旦找到与路径匹配的函数，就会调用该函数以获取响应主体，然后将生成的主体返回给服务器：

```py
resp = Response()
body = routed_action(request, resp)

resp.send(start_response)
return [body]
```

在返回主体之前，将调用`Response.send`通过`start_response`可调用发送响应 HTTP 标头和状态。

`Response`和`Request`对象用于保留当前请求的环境（以及从 URL 解析的任何附加参数）、响应的标头和状态。这样，处理请求的操作可以接收它们并检查请求或在发送之前添加/删除响应的标头。

# 还有更多...

虽然基本的基于 HTTP 的应用程序可以使用提供的`WSGIApplication`实现，但完整功能的应用程序还有很多缺失或不完整的地方。

在涉及更复杂的 Web 应用程序时，通常需要缓存、会话、身份验证、授权、管理数据库连接、事务和管理等部分，并且大多数 Python Web 框架都可以轻松为您提供这些部分。

实现完整的 Web 框架不在本书的范围之内，当 Python 环境中有许多出色的 Web 框架可用时，您可能应该尽量避免重复造轮子。

Python 拥有广泛的 Web 框架，涵盖了从用于快速开发的全栈框架（如 Django）到面向 API 的微框架（如 Flask）以及灵活的解决方案（如 Pyramid 和 TurboGears），其中所需的部分可以根据需要启用、禁用或替换，从全栈解决方案到微框架。

# 提供静态文件

有时在处理基于 JavaScript 的应用程序或静态网站时，有必要能够直接从磁盘上提供目录的内容。

Python 标准库提供了一个现成的 HTTP 服务器，用于处理请求，并将它们映射到目录中的文件，因此我们可以快速地编写自己的 HTTP 服务器来编写网站，而无需安装任何其他工具。

# 如何做...

`http.server`模块提供了实现负责提供目录内容的 HTTP 服务器所需的大部分内容：

```py
import os.path
import socketserver
from http.server import SimpleHTTPRequestHandler, HTTPServer

def serve_directory(path, port=8000):
    class ConfiguredHandler(HTTPDirectoryRequestHandler):
        SERVED_DIRECTORY = path
    httpd = ThreadingHTTPServer(("", port), ConfiguredHandler)
    print("serving on port", port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    pass

class HTTPDirectoryRequestHandler(SimpleHTTPRequestHandler):
    SERVED_DIRECTORY = '.'

    def translate_path(self, path):
        path = super().translate_path(path)
        relpath = os.path.relpath(path)
        return os.path.join(self.SERVED_DIRECTORY, relpath)
```

然后`serve_directory`可以针对任何路径启动，以在`http://localhost:8000`上提供该路径的内容：

```py
serve_directory('/tmp')
```

将浏览器指向`http://localhost:8000`应该列出`/tmp`目录的内容，并允许您浏览它并查看任何文件的内容。

# 工作原理...

`ThreadingHTTPServer`将`HTTPServer`与`ThreadingMixin`结合在一起，这允许您一次提供多个请求。

这在提供静态网站时尤其重要，因为浏览器经常保持连接时间比需要的更长，当一次只提供一个请求时，您可能无法获取您的 CSS 或 JavaScript 文件，直到浏览器关闭前一个连接。

对于每个请求，`HTTPServer`将其转发到指定的处理程序进行处理。`SimpleHTTPRequestHandler`能够提供请求，将其映射到磁盘上的本地文件，但在大多数 Python 版本中，它只能从当前目录提供服务。

为了能够从任何目录提供请求，我们提供了一个自定义的`translate_path`方法，它替换了相对于`SERVED_DIRECTORY`类变量的标准实现产生的路径。

然后`serve_directory`将所有内容放在一起，并将`HTTPServer`与定制的请求处理程序结合在一起，以创建一个能够处理提供路径的请求的服务器。

# 还有更多...

在较新的 Python 版本中，关于`http.server`模块已经发生了很多变化。最新版本 Python 3.7 已经提供了`ThreadingHTTPServer`类，并且现在可以配置特定目录由`SimpleHTTPRequestHandler`提供服务，因此无需自定义`translate_path`方法来提供特定目录的服务。

# Web 应用程序中的错误

通常，当 Python WSGI Web 应用程序崩溃时，您会在终端中获得一个回溯，浏览器中的路径为空。

这并不是很容易调试发生了什么，除非您明确检查终端，否则很容易错过页面没有显示出来的情况，因为它实际上崩溃了。

幸运的是，Python 标准库为 Web 应用程序提供了一些基本的调试工具，使得可以将崩溃报告到浏览器中，这样您就可以在不离开浏览器的情况下查看并修复它们。

# 如何做...

`cgitb`模块提供了将异常及其回溯格式化为 HTML 的工具，因此我们可以利用它来实现一个 WSGI 中间件，该中间件可以包装任何 Web 应用程序，以在浏览器中提供更好的错误报告：

```py
import cgitb
import sys

class ErrorMiddleware:
    """Wrap a WSGI application to display errors in the browser"""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        app_iter = None
        try:
            app_iter = self.app(environ, start_response)
            for item in app_iter:
                yield item
        except:
            try:
                start_response('500 INTERNAL SERVER ERROR', [
                    ('Content-Type', 'text/html; charset=utf-8'),
                    ('X-XSS-Protection', '0'),
                ])
            except Exception:
                # There has been output but an error occurred later on. 
                # In that situation we can do nothing fancy anymore, 
                # better log something into the error log and fallback.
                environ['wsgi.errors'].write(
                    'Debugging middleware caught exception in streamed '
                    'response after response headers were already sent.\n'
                )
            else:
                yield cgitb.html(sys.exc_info()).encode('utf-8')
        finally:
            if hasattr(app_iter, 'close'):
                app_iter.close()
```

`ErrorMiddleware`可以用于包装任何 WSGI 应用程序，以便在出现错误时将错误显示在 Web 浏览器中。

例如，我们可以从上一个示例中重新获取我们的`WSGIApplication`，添加一个将导致崩溃的路由，并提供包装后的应用程序以查看错误如何报告到 Web 浏览器中：

```py
from web_06 import WSGIApplication
from wsgiref.simple_server import make_server

app = WSGIApplication()

@app.route('/crash')
def crash(req, resp):
    raise RuntimeError('This is a crash!')

app = ErrorMiddleware(app)

httpd = make_server('', 8000, app)
print("Serving on port 8000...")
httpd.serve_forever()
```

一旦将浏览器指向`http://localhost:8000/crash`，您应该看到触发异常的精美格式的回溯。

# 工作原理...

`ErrorMiddleware`接收原始应用程序并替换请求处理。

所有 HTTP 请求都将被`ErrorMiddleware`接收，然后将其代理到应用程序，返回应用程序提供的结果响应。

如果在消耗应用程序响应时出现异常，它将停止标准流程，而不是进一步消耗应用程序的响应，它将格式化异常并将其作为响应发送回浏览器。

这是因为`ErrorMiddleware.__call__`实际上调用了包装的应用程序并迭代了任何提供的结果：

```py
def __call__(self, environ, start_response):
    app_iter = None
    try:
        app_iter = self.app(environ, start_response)
        for item in app_iter:
            yield item
    ...
```

这种方法适用于返回正常响应的应用程序和返回生成器作为响应的应用程序。

如果在调用应用程序或消耗响应时出现错误，则会捕获错误并尝试使用新的`start_response`来通知服务器错误到浏览器：

```py
except:
    try:
        start_response('500 INTERNAL SERVER ERROR', [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('X-XSS-Protection', '0'),
        ])
```

如果`start_response`失败，这意味着被包装的应用程序已经调用了`start_response`，因此不可能再更改响应状态码或标头。

在这种情况下，由于我们无法再提供精美格式的响应，我们只能退回到在终端上提供错误：

```py
except Exception:
    # There has been output but an error occurred later on. 
    # In that situation we can do nothing fancy anymore, 
    # better log something into the error log and fallback.
    environ['wsgi.errors'].write(
        'Debugging middleware caught exception in streamed '
        'response after response headers were already sent.\n'
    )
```

如果`start_response`成功，我们将停止返回应用程序响应的内容，而是返回错误和回溯，由`cgitb`精美格式化：

```py
else:
    yield cgitb.html(sys.exc_info()).encode('utf-8')
```

在这两种情况下，如果它提供了`close`方法，我们将关闭应用程序响应。这样，如果它是一个需要关闭的文件或任何源，我们就可以避免泄漏它：

```py
finally:
    if hasattr(app_iter, 'close'):
        app_iter.close()
```

# 还有更多...

Python 标准库之外还提供了更完整的 Web 应用程序错误报告解决方案。如果您有进一步的需求或希望通过电子邮件或通过 Sentry 等云错误报告解决方案通知错误，您可能需要提供一个错误报告 WSGI 库。

来自 Flask 的`Werkzeug`调试器，来自 Pylons 项目的`WebError`库，以及来自 TurboGears 项目的`Backlash`库可能是这个目的最常见的解决方案。

您可能还想检查您的 Web 框架是否提供了一些高级的错误报告配置，因为其中许多提供了这些功能，依赖于这些库或其他工具。

# 处理表单和文件

在提交表单和上传文件时，它们通常以`multipart/form-data`编码发送。

我们已经看到如何创建以`multipart/form-data`编码的数据，并将其提交到端点，但是如何处理以这种格式接收的数据呢？

# 如何做...

标准库中的`cgi.FieldStorage`类已经提供了解析多部分数据并以易于处理的方式发送回数据所需的所有机制。

我们将创建一个简单的 Web 应用程序（基于`WSGIApplication`），以展示如何使用`cgi.FieldStorage`来解析上传的文件并将其显示给用户：

```py
import cgi

from web_06 import WSGIApplication
import base64

app = WSGIApplication()

@app.route('/')
def index(req, resp):
    return (
        b'<form action="/upload" method="post" enctype="multipart/form-
           data">'
        b'  <input type="file" name="uploadedfile"/>'
        b'  <input type="submit" value="Upload">'
        b'</form>'
    )

@app.route('/upload')
def upload(req, resp):
    form = cgi.FieldStorage(fp=req.environ['wsgi.input'], 
                            environ=req.environ)
    if 'uploadedfile' not in form:
        return b'Nothing uploaded'

    uploadedfile = form['uploadedfile']
    if uploadedfile.type.startswith('image'):
        # User uploaded an image, show it
        return b'<img src="data:%b;base64,%b"/>' % (
            uploadedfile.type.encode('ascii'),
            base64.b64encode(uploadedfile.file.read())
        )
    elif uploadedfile.type.startswith('text'):
        return uploadedfile.file.read()
    else:
        return b'You uploaded %b' % uploadedfile.filename.encode('utf-8')

app.serve()
```

# 工作原理...

该应用程序公开了两个网页。一个位于网站的根目录（通过`index`函数），只显示一个带有上传字段的简单表单。

另一个`upload`函数，接收上传的文件，如果是图片或文本文件，则显示出来。在其他情况下，它将只显示上传文件的名称。

处理多部分格式上传的唯一要求是创建一个`cgi.FieldStorage`：

```py
form = cgi.FieldStorage(fp=req.environ['wsgi.input'], 
                        environ=req.environ)
```

`POST`请求的整个主体始终在`environ`请求中可用，使用`wsgi.input`键。

这提供了一个类似文件的对象，可以读取以消耗已发布的数据。确保在创建`FieldStorage`后将其保存，如果需要多次使用它，因为一旦从`wsgi.input`中消耗了数据，它就变得不可访问。

`cgi.FieldStorage`提供了类似字典的接口，因此我们可以通过检查`uploadedfile`条目是否存在来检查是否上传了文件：

```py
if 'uploadedfile' not in form:
    return b'Nothing uploaded'
```

这是因为在我们的表单中，我们提供了`uploadedfile`作为字段的名称：

```py
b'  <input type="file" name="uploadedfile"/>'
```

该特定字段将可以通过`form['uploadedfile']`访问。

因为它是一个文件，它将返回一个对象，通过该对象我们可以检查上传文件的 MIME 类型，以确定它是否是一张图片：

```py
if uploadedfile.type.startswith('image'):
```

如果它是一张图片，我们可以读取它的内容，将其编码为`base64`，这样它就可以被`img`标签显示出来：

```py
base64.b64encode(uploadedfile.file.read())
```

`filename`属性仅在上传文件是无法识别的格式时使用，这样我们至少可以打印出上传文件的名称：

```py
return b'You uploaded %b' % uploadedfile.filename.encode('utf-8')
```

# REST API

REST 与 JSON 已成为基于 Web 的应用程序之间的跨应用程序通信技术的事实标准。

这是一个非常有效的协议，而且它的定义可以被每个人理解，这使得它很快就变得流行起来。

与其他更复杂的通信协议相比，快速的 REST 实现可以相对快速地推出。

由于 Python 标准库提供了我们构建基于 WSGI 的应用程序所需的基础，因此很容易扩展我们现有的配方以支持基于 REST 的请求分发。

# 如何做...

我们将使用我们之前的配方中的`WSGIApplication`，但是不是为根注册一个函数，而是注册一个能够根据请求方法进行分发的特定类。

1.  我们想要实现的所有 REST 类都必须继承自单个`RestController`实现：

```py
class RestController:
    def __call__(self, req, resp):
        method = req.environ['REQUEST_METHOD']
        action = getattr(self, method, self._not_found)
        return action(req, resp)

    def _not_found(self, environ, resp):
        resp.status = '404 Not Found'
        return b'{}'  # Provide an empty JSON document
```

1.  然后我们可以子类化`RestController`来实现所有特定的`GET`、`POST`、`DELETE`和`PUT`方法，并在特定路由上注册资源：

```py
import json
from web_06 import WSGIApplication

app = WSGIApplication()

@app.route('/resources/?(?P<id>\\w*)')
class ResourcesRestController(RestController):
    RESOURCES = {}

    def GET(self, req, resp):
        resource_id = req.urlargs['id']
        if not resource_id:
            # Whole catalog requested
            return json.dumps(self.RESOURCES).encode('utf-8')

        if resource_id not in self.RESOURCES:
            return self._not_found(req, resp)

        return json.dumps(self.RESOURCES[resource_id]).encode('utf-8')

    def POST(self, req, resp):
        content_length = int(req.environ['CONTENT_LENGTH'])
        data = req.environ['wsgi.input'].read(content_length).decode('utf-8')

        resource = json.loads(data)
        resource['id'] = str(len(self.RESOURCES)+1)
        self.RESOURCES[resource['id']] = resource
        return json.dumps(resource).encode('utf-8')

    def DELETE(self, req, resp):
        resource_id = req.urlargs['id']
        if not resource_id:
            return self._not_found(req, resp)
        self.RESOURCES.pop(resource_id, None)

        req.status = '204 No Content'
        return b''
```

这已经提供了基本功能，允许我们从内存目录中添加、删除和列出资源。

1.  为了测试这一点，我们可以在后台线程中启动服务器，并使用我们之前的配方中的`http_request`函数：

```py
import threading
threading.Thread(target=app.serve, daemon=True).start()

from web_03 import http_request
```

1.  然后我们可以创建一个新的资源：

```py
>>> _, resp = http_request('http://localhost:8000/resources', method='POST', 
                           data=json.dumps({'name': 'Mario',
                                            'surname': 'Mario'}).encode('utf-8'))
>>> print('NEW RESOURCE: ', resp)
NEW RESOURCE:  b'{"surname": "Mario", "id": "1", "name": "Mario"}'
```

1.  这里我们列出它们全部：

```py
>>> _, resp = http_request('http://localhost:8000/resources')
>>> print('ALL RESOURCES: ', resp)
ALL RESOURCES:  b'{"1": {"surname": "Mario", "id": "1", "name": "Mario"}}'
```

1.  添加第二个：

```py
>>> http_request('http://localhost:8000/resources', method='POST', 
                 data=json.dumps({'name': 'Luigi',
                                  'surname': 'Mario'}).encode('utf-8'))
```

1.  接下来，我们看到现在列出了两个资源：

```py
>>> _, resp = http_request('http://localhost:8000/resources')
>>> print('ALL RESOURCES: ', resp)
ALL RESOURCES:  b'{"1": {"surname": "Mario", "id": "1", "name": "Mario"}, 
                   "2": {"surname": "Mario", "id": "2", "name": "Luigi"}}'
```

1.  然后我们可以从目录中请求特定的资源：

```py
>>> _, resp = http_request('http://localhost:8000/resources/1')
>>> print('RESOURCES #1: ', resp)
RESOURCES #1:  b'{"surname": "Mario", "id": "1", "name": "Mario"}'
```

1.  我们还可以删除特定的资源：

```py
>>> http_request('http://localhost:8000/resources/2', method='DELETE')
```

1.  然后查看它是否已被删除：

```py
>>> _, resp = http_request('http://localhost:8000/resources')
>>> print('ALL RESOURCES', resp)
ALL RESOURCES b'{"1": {"surname": "Mario", "id": "1", "name": "Mario"}}'
```

这应该允许我们为大多数简单情况提供 REST 接口，依赖于 Python 标准库中已经可用的内容。

# 工作原理...

大部分工作由`RestController.__call__`完成：

```py
class RestController:
    def __call__(self, req, resp):
        method = req.environ['REQUEST_METHOD']
        action = getattr(self, method, self._not_found)
        return action(req, resp)
```

每当调用`RestController`的子类时，它将查看 HTTP 请求方法，并查找一个命名类似于 HTTP 方法的实例方法。

如果有的话，将调用该方法，并返回方法本身提供的响应。如果没有，则调用`self._not_found`，它将只响应 404 错误。

这依赖于`WSGIApplication.__call__`对类而不是函数的支持。

当`WSGIApplication.__call__`通过`app.route`找到与路由关联的对象是一个类时，它将始终创建它的一个实例，然后它将调用该实例：

```py
if inspect.isclass(routed_action):
    routed_action = routed_action()
body = routed_action(request, resp)
```

如果`routed_action`是`RestController`的子类，那么将会发生的是`routed_action = routed_action()`将用其实例替换类，然后`routed_action(request, resp)`将调用`RestController.__call__`方法来实际处理请求。

然后，`RestController.__call__`方法可以根据 HTTP 方法将请求转发到正确的实例方法。

请注意，由于 REST 资源是通过在 URL 中提供资源标识符来识别的，因此分配给`RestController`的路由必须具有一个`id`参数和一个可选的`/`：

```py
@app.route('/resources/?(?P<id>\\w*)')
```

否则，您将无法区分对整个`GET`资源目录`/resources`的请求和对特定`GET`资源`/resources/3`的请求。

缺少`id`参数正是我们的`GET`方法决定何时返回整个目录的内容或不返回的方式：

```py
def GET(self, req, resp):
    resource_id = req.urlargs['id']
    if not resource_id:
        # Whole catalog requested
        return json.dumps(self.RESOURCES).encode('utf-8')
```

对于接收请求体中的数据的方法，例如`POST`，`PUT`和`PATCH`，您将不得不从`req.environ['wsgi.input']`读取请求体。

在这种情况下，重要的是提供要读取的字节数，因为连接可能永远不会关闭，否则读取可能会永远阻塞。

`Content-Length`头部可用于知道输入的长度：

```py
def POST(self, req, resp):
    content_length = int(req.environ['CONTENT_LENGTH'])
    data = req.environ['wsgi.input'].read(content_length).decode('utf-8')
```

# 处理 cookie

在 Web 应用程序中，cookie 经常用于在浏览器中存储数据。最常见的用例是用户识别。

我们将实现一个非常简单且不安全的基于 cookie 的身份识别系统，以展示如何使用它们。

# 如何做...

`http.cookies.SimpleCookie`类提供了解析和生成 cookie 所需的所有设施。

1.  我们可以依赖它来创建一个将设置 cookie 的 Web 应用程序端点：

```py
from web_06 import WSGIApplication

app = WSGIApplication()

import time
from http.cookies import SimpleCookie

@app.route('/identity')
def identity(req, resp):
    identity = int(time.time())

    cookie = SimpleCookie()
    cookie['identity'] = 'USER: {}'.format(identity)

    for set_cookie in cookie.values():
        resp.headers.add_header('Set-Cookie', set_cookie.OutputString())
    return b'Go back to <a href="/">index</a> to check your identity'
```

1.  我们可以使用它来创建一个解析 cookie 并告诉我们当前用户是谁的 cookie：

```py
@app.route('/')
def index(req, resp):
    if 'HTTP_COOKIE' in req.environ:
        cookies = SimpleCookie(req.environ['HTTP_COOKIE'])
        if 'identity' in cookies:
            return b'Welcome back, %b' % cookies['identity'].value.encode('utf-8')
    return b'Visit <a href="/identity">/identity</a> to get an identity'
```

1.  一旦启动应用程序，您可以将浏览器指向`http://localhost:8000`，然后您应该看到 Web 应用程序抱怨您缺少身份：

```py
app.serve()
```

点击建议的链接后，您应该得到一个，返回到索引页面，它应该通过 cookie 识别您。

# 它是如何工作的...

`SimpleCookie`类表示一个或多个值的 cookie。

每个值都可以像字典一样设置到 cookie 中：

```py
cookie = SimpleCookie()
cookie['identity'] = 'USER: {}'.format(identity)
```

如果 cookie`morsel`必须接受更多选项，那么可以使用字典语法进行设置：

```py
cookie['identity']['Path'] = '/'
```

每个 cookie 可以包含多个值，每个值都应该使用`Set-Cookie` HTTP 头进行设置。

迭代 cookie 将检索构成 cookie 的所有键/值对，然后在它们上调用`OutputString()`将返回编码为`Set-Cookie`头部所期望的 cookie 值，以及所有其他属性：

```py
for set_cookie in cookie.values():
    resp.headers.add_header('Set-Cookie', set_cookie.OutputString())
```

实际上，一旦设置了 cookie，调用`OutputString()`将会将您发送回浏览器的字符串：

```py
>>> cookie = SimpleCookie()
>>> cookie['somevalue'] = 42
>>> cookie['somevalue']['Path'] = '/'
>>> cookie['somevalue'].OutputString()
'somevalue=42; Path=/'
```

读取 cookie 与从`environ['HTTP_COOKIE']`值构建 cookie 一样简单，如果它可用的话：

```py
cookies = SimpleCookie(req.environ['HTTP_COOKIE'])
```

一旦 cookie 被解析，其中存储的值可以通过字典语法访问：

```py
cookies['identity']
```

# 还有更多...

在处理 cookie 时，您应该注意的一个特定条件是它们的生命周期。

Cookie 可以有一个`Expires`属性，它将说明它们应该在哪个日期死亡（浏览器将丢弃它们），实际上，这就是您删除 cookie 的方式。使用过去日期的`Expires`日期再次设置 cookie 将删除它。

但是 cookie 也可以有一个`Max-Age`属性，它规定它们应该保留多长时间，或者可以创建为会话 cookie，当浏览器窗口关闭时它们将消失。

因此，如果您遇到 cookie 随机消失或未正确加载回来的问题，请始终检查这些属性，因为 cookie 可能刚刚被浏览器删除。
