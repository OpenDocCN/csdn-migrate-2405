# Python 数字取证秘籍（三）

> 原文：[`zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03`](https://zh.annas-archive.org/md5/941c711b36df2129e5f7d215d3712f03)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：阅读电子邮件和获取名称的配方

本章涵盖了以下配方：

+   解析 EML 文件

+   查看 MSG 文件

+   订购外卖

+   盒子里有什么？

+   解析 PST 和 OST 邮箱

# 介绍

一旦计算机证据被添加到混乱中，他说她说的游戏通常就被抛到一边。电子邮件在大多数类型的调查中起着重要作用。电子邮件证据涉及到商业和个人设备，因为它被广泛用于发送文件、与同行交流以及从在线服务接收通知。通过检查电子邮件，我们可以了解托管人使用哪些社交媒体、云存储或其他网站。我们还可以寻找组织外的数据外流，或者调查钓鱼计划的来源。

本章将涵盖揭示此信息以进行调查的配方，包括：

+   使用内置库读取 EML 格式

+   利用`win32com`库从 Outlook MSG 文件中提取信息

+   使用 Takeouts 保存 Google Gmail 并解析保存内容

+   使用内置库从 MBOX 容器中读取

+   使用`libpff`读取 PST 文件

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 解析 EML 文件

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

EML 文件格式被广泛用于存储电子邮件消息，因为它是一个结构化的文本文件，兼容多个电子邮件客户端。这个文本文件以纯文本形式存储电子邮件头部、正文内容和附件数据，使用`base64`来编码二进制数据，使用**Quoted-Printable**（**QP**）编码来存储内容信息。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。我们将使用内置的`email`库来读取和提取 EML 文件中的关键信息。

要了解更多关于`email`库的信息，请访问[`docs.python.org/3/library/email.html`](https://docs.python.org/3/library/email.html)。

# 如何做...

要创建一个 EML 解析器，我们必须：

1.  接受一个 EML 文件的参数。

1.  从头部读取值。

1.  从 EML 的各个部分中解析信息。

1.  在控制台中显示此信息以便审查。

# 它是如何工作的...

我们首先导入用于处理参数、EML 处理和解码 base64 编码数据的库。`email`库提供了从 EML 文件中读取数据所需的类和方法。我们将使用`message_from_file()`函数来解析提供的 EML 文件中的数据。`Quopri`是本书中的一个新库，我们使用它来解码 HTML 正文和附件中的 QP 编码值。`base64`库，正如人们所期望的那样，允许我们解码任何 base64 编码的数据：

```py
from __future__ import print_function
from argparse import ArgumentParser, FileType
from email import message_from_file
import os
import quopri
import base64
```

此配方的命令行处理程序接受一个位置参数`EML_FILE`，表示我们将处理的 EML 文件的路径。我们使用`FileType`类来处理文件的打开：

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EML_FILE",
                        help="Path to EML File", type=FileType('r'))
    args = parser.parse_args()

    main(args.EML_FILE)
```

在`main()`函数中，我们使用`message_from_file()`函数将类似文件的对象读入`email`库。现在我们可以使用结果变量`emlfile`来访问头部、正文内容、附件和其他有效载荷信息。读取电子邮件头部只是通过迭代库的`_headers`属性提供的字典来处理。要处理正文内容，我们必须检查此消息是否包含多个有效载荷，并且如果是这样，将每个传递给指定的处理函数`process_payload()`：

```py
def main(input_file):
    emlfile = message_from_file(input_file)

    # Start with the headers
    for key, value in emlfile._headers:
        print("{}: {}".format(key, value))

    # Read payload
    print("\nBody\n")
    if emlfile.is_multipart():
        for part in emlfile.get_payload():
            process_payload(part)
    else:
        process_payload(emlfile[1])
```

`process_payload()`函数首先通过使用`get_content_type()`方法提取消息的 MIME 类型。我们将这个值打印到控制台上，并在新行上打印一些`"="`字符来区分这个值和消息的其余部分。

在一行中，我们使用`get_payload()`方法提取消息正文内容，并使用`quopri.decodestring()`函数解码 QP 编码的数据。然后，我们检查数据是否有字符集，如果我们确定了字符集，则在指定字符集的同时使用`decode()`方法对内容进行解码。如果编码是未知的，我们将尝试使用 UTF8 对对象进行解码，这是在将`decode()`方法留空时的默认值，以及 Windows-1252：

```py
def process_payload(payload):
    print(payload.get_content_type() + "\n" + "=" * len(
        payload.get_content_type()))
    body = quopri.decodestring(payload.get_payload())
    if payload.get_charset():
        body = body.decode(payload.get_charset())
    else:
        try:
            body = body.decode()
        except UnicodeDecodeError:
            body = body.decode('cp1252')
```

使用我们解码的数据，我们检查内容的 MIME 类型，以便正确处理电子邮件的存储。 HTML 信息的第一个条件，由`text/html` MIME 类型指定，被写入到与输入文件相同目录中的 HTML 文档中。在第二个条件中，我们处理`Application` MIME 类型下的二进制数据。这些数据以`base64`编码的值传输，我们在使用`base64.b64decode()`函数写入到当前目录中的文件之前对其进行解码。二进制数据具有`get_filename()`方法，我们可以使用它来准确命名附件。请注意，输出文件必须以`"w"`模式打开第一种类型，以`"wb"`模式打开第二种类型。如果 MIME 类型不是我们在这里涵盖的类型，我们将在控制台上打印正文：

```py
    if payload.get_content_type() == "text/html":
        outfile = os.path.basename(args.EML_FILE.name) + ".html"
        open(outfile, 'w').write(body)
    elif payload.get_content_type().startswith('application'):
        outfile = open(payload.get_filename(), 'wb')
        body = base64.b64decode(payload.get_payload())
        outfile.write(body)
        outfile.close()
        print("Exported: {}\n".format(outfile.name))
    else:
        print(body)
```

当我们执行此代码时，我们首先在控制台上看到头信息，然后是各种有效载荷。在这种情况下，我们首先有一个`text/plain` MIME 内容，其中包含一个示例消息，然后是一个`application/vnd.ms-excel`附件，我们将其导出，然后是另一个`text/plain`块显示初始消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00064.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00065.jpeg)

# 查看 MSG 文件

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：Windows

电子邮件消息可以以许多不同的格式出现。MSG 格式是存储消息内容和附件的另一种流行容器。在这个例子中，我们将学习如何使用 Outlook API 解析 MSG 文件。

# 入门

这个配方需要安装第三方库`pywin32`。这意味着该脚本只能在 Windows 系统上兼容。我们还需要安装`pywin32`，就像我们在第一章中所做的那样，*基本脚本和文件信息配方*。

要安装`pywin32`，我们需要访问其 SourceForge 页面[`sourceforge.net/projects/pywin32/`](https://sourceforge.net/projects/pywin32/)，并下载与您的 Python 安装相匹配的版本。要检查我们的 Python 版本，我们可以导入`sys`模块，并在解释器中调用`sys.version`。在选择正确的`pywin32`安装程序时，版本和架构都很重要。我们还希望确认我们在计算机上安装了有效的 Outlook，因为`pywin32`绑定依赖于 Outlook 提供的资源。在运行`pywin32`安装程序后，我们准备创建脚本。

# 如何做...

要创建 MSG 解析器，我们必须：

1.  接受一个 MSG 文件的参数。

1.  将有关 MSG 文件的一般元数据打印到控制台。

1.  将特定于收件人的元数据打印到控制台。

1.  将消息内容导出到输出文件。

1.  将嵌入在消息中的任何附件导出到适当的输出文件。

# 它是如何工作的...

我们首先导入用于参数处理的库`argparse`和`os`，然后是来自`pywin32`的`win32com`库。我们还导入`pywintypes`库以正确捕获和处理`pywin32`错误：

```py
from __future__ import print_function
from argparse import ArgumentParser
import os
import win32com.client
import pywintypes
```

这个配方的命令行处理程序接受两个位置参数，`MSG_FILE`和`OUTPUT_DIR`，分别表示要处理的 MSG 文件的路径和所需的输出文件夹。我们检查所需的输出文件夹是否存在，如果不存在，则创建它。之后，我们将这两个输入传递给`main()`函数：

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("MSG_FILE", help="Path to MSG file")
    parser.add_argument("OUTPUT_DIR", help="Path to output folder")
    args = parser.parse_args()
    out_dir = args.OUTPUT_DIR
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    main(args.MSG_FILE, args.OUTPUT_DIR)
```

在 `main()` 函数中，我们调用 `win32com` 库来设置 Outlook API，以便以允许访问 `MAPI` 命名空间的方式进行配置。使用这个 `mapi` 变量，我们可以使用 `OpenSharedItem()` 方法打开一个 `MSG` 文件，并创建一个我们将在本示例中使用的对象。这些函数包括：`display_msg_attribs()`、`display_msg_recipients()`、`extract_msg_body()` 和 `extract_attachments()`。现在让我们依次关注这些函数，看看它们是如何工作的：

```py
def main(msg_file, output_dir):
    mapi = win32com.client.Dispatch(
        "Outlook.Application").GetNamespace("MAPI")
    msg = mapi.OpenSharedItem(os.path.abspath(args.MSG_FILE))
    display_msg_attribs(msg)
    display_msg_recipients(msg)
    extract_msg_body(msg, output_dir)
    extract_attachments(msg, output_dir)
```

`display_msg_attribs()` 函数允许我们显示消息的各种属性（主题、收件人、密件抄送、大小等）。其中一些属性可能不存在于我们解析的消息中，但是我们尝试导出所有值。`attribs` 列表按顺序显示我们尝试从消息中访问的属性。当我们遍历每个属性时，我们在 `msg` 对象上使用内置的 `getattr()` 方法，并尝试提取相关值（如果存在），如果不存在，则为 `"N/A"`。然后我们将属性及其确定的值打印到控制台。需要注意的是，其中一些值可能存在，但仅设置为默认值，例如某些日期的年份为 `4501`：

```py
def display_msg_attribs(msg):
    # Display Message Attributes
    attribs = [
        'Application', 'AutoForwarded', 'BCC', 'CC', 'Class',
        'ConversationID', 'ConversationTopic', 'CreationTime',
        'ExpiryTime', 'Importance', 'InternetCodePage', 'IsMarkedAsTask',
        'LastModificationTime', 'Links', 'OriginalDeliveryReportRequested',
        'ReadReceiptRequested', 'ReceivedTime', 'ReminderSet',
        'ReminderTime', 'ReplyRecipientNames', 'Saved', 'Sender',
        'SenderEmailAddress', 'SenderEmailType', 'SenderName', 'Sent',
        'SentOn', 'SentOnBehalfOfName', 'Size', 'Subject',
        'TaskCompletedDate', 'TaskDueDate', 'To', 'UnRead'
    ]
    print("\nMessage Attributes")
    print("==================")
    for entry in attribs:
        print("{}: {}".format(entry, getattr(msg, entry, 'N/A')))
```

`display_msg_recipients()` 函数遍历消息并显示收件人详细信息。`msg` 对象提供了一个 `Recipients()` 方法，该方法接受一个整数参数以按索引访问收件人。使用 `while` 循环，我们尝试加载和显示可用收件人的值。对于找到的每个收件人，与之前的函数一样，我们使用 `getattr()` 方法与属性列表 `recipient_attrib` 提取和打印相关值，或者如果它们不存在，则赋予它们值 `"N/A"`。尽管大多数 Python 可迭代对象使用零作为第一个索引，但 `Recipients()` 方法从 `1` 开始。因此，变量 `i` 将从 `1` 开始递增，直到找不到更多的收件人为止。我们将继续尝试读取这些值，直到收到 `pywin32` 错误。

```py
def display_msg_recipients(msg):
    # Display Recipient Information
    recipient_attrib = [
        'Address', 'AutoResponse', 'Name', 'Resolved', 'Sendable'
    ]
    i = 1
    while True:
        try:
            recipient = msg.Recipients(i)
        except pywintypes.com_error:
            break

        print("\nRecipient {}".format(i))
        print("=" * 15)
        for entry in recipient_attrib:
            print("{}: {}".format(entry, getattr(recipient, entry, 'N/A')))
        i += 1
```

`extract_msg_body()` 函数旨在从消息中提取正文内容。`msg` 对象以几种不同的格式公开正文内容；在本示例中，我们将导出 HTML（使用 `HTMLBody()` 方法）和纯文本（使用 `Body()` 方法）版本的正文。由于这些对象是字节字符串，我们必须首先解码它们，这是通过使用 `cp1252` 代码页来完成的。有了解码后的内容，我们打开用户指定目录中的输出文件，并创建相应的 `*.body.html` 和 `*.body.txt` 文件：

```py
def extract_msg_body(msg, out_dir):
    # Extract HTML Data
    html_data = msg.HTMLBody.encode('cp1252')
    outfile = os.path.join(out_dir, os.path.basename(args.MSG_FILE))
    open(outfile + ".body.html", 'wb').write(html_data)
    print("Exported: {}".format(outfile + ".body.html"))

    # Extract plain text
    body_data = msg.Body.encode('cp1252')
    open(outfile + ".body.txt", 'wb').write(body_data)
    print("Exported: {}".format(outfile + ".body.txt"))
```

最后，`extract_attachments()` 函数将附件数据从 MSG 文件导出到所需的输出目录。使用 `msg` 对象，我们再次创建一个列表 `attachment_attribs`，表示有关附件的一系列属性。与收件人函数类似，我们使用 `while` 循环和 `Attachments()` 方法，该方法接受一个整数作为参数，以选择要迭代的附件。与之前的 `Recipients()` 方法一样，`Attachments()` 方法从 `1` 开始索引。因此，变量 `i` 将从 `1` 开始递增，直到找不到更多的附件为止：

```py
def extract_attachments(msg, out_dir):
    attachment_attribs = [
        'DisplayName', 'FileName', 'PathName', 'Position', 'Size'
    ]
    i = 1 # Attachments start at 1
    while True:
        try:
            attachment = msg.Attachments(i)
        except pywintypes.com_error:
            break
```

对于每个附件，我们将其属性打印到控制台。我们提取和打印的属性在此函数开始时的 `attachment_attrib` 列表中定义。打印可用附件详细信息后，我们使用 `SaveAsFile()` 方法写入其内容，并提供一个包含输出路径和所需输出附件名称的字符串（使用 `FileName` 属性获取）。之后，我们准备移动到下一个附件，因此我们递增变量 `i` 并尝试访问下一个附件。

```py
        print("\nAttachment {}".format(i))
        print("=" * 15)
        for entry in attachment_attribs:
            print('{}: {}'.format(entry, getattr(attachment, entry,
                                                 "N/A")))
        outfile = os.path.join(os.path.abspath(out_dir),
                               os.path.split(args.MSG_FILE)[-1])
        if not os.path.exists(outfile):
            os.makedirs(outfile)
        outfile = os.path.join(outfile, attachment.FileName)
        attachment.SaveAsFile(outfile)
        print("Exported: {}".format(outfile))
        i += 1
```

当我们执行此代码时，我们将看到以下输出，以及输出目录中的几个文件。这包括正文文本和 HTML，以及任何发现的附件。消息及其附件的属性将显示在控制台窗口中。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00066.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议如下：

+   考虑通过参考 MSDN 上 MSG 对象的属性来向解析器添加更多字段[`msdn.microsoft.com/en-us/library/microsoft.office.interop.outlook.mailitem_properties.aspx`](https://msdn.microsoft.com/en-us/library/microsoft.office.interop.outlook.mailitem_properties.aspx)

# 另请参阅

还存在其他用于访问 MSG 文件的库，包括`Redemption`库。该库提供了访问标头信息的处理程序，以及与此示例中显示的许多相同属性。

# 订购外卖

教程难度：简单

Python 版本：N/A

操作系统：任何

谷歌邮件，通常称为 Gmail，是更广泛使用的网络邮件服务之一。Gmail 帐户不仅可以作为电子邮件地址，还可以作为通往谷歌提供的众多其他服务的入口。除了通过网络或**Internet Message Access Protocol**（**IMAP**）和**Post Office Protocol**（**POP**）邮件协议提供邮件访问外，谷歌还开发了一种用于存档和获取 Gmail 帐户中存储的邮件和其他相关数据的系统。

# 入门

信不信由你，这个教程实际上不涉及任何 Python，而是需要浏览器和对 Google 帐户的访问。这个教程的目的是以 MBOX 格式获取 Google 帐户邮箱，我们将在下一个教程中解析它。

# 如何做...

要启动 Google Takeout，我们按照以下步骤进行：

1.  登录到相关的谷歌帐户。

1.  导航到帐户设置和创建存档功能。

1.  选择要存档的所需谷歌产品并开始该过程。

1.  下载存档数据。

# 它是如何工作的...

我们通过登录帐户并选择“我的帐户”选项来开始 Google Takeout 过程。如果“我的帐户”选项不存在，我们也可以导航到[`myaccount.google.com`](https://myaccount.google.com)：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00067.jpeg)

在“我的帐户”仪表板上，我们选择“个人信息和隐私”部分下的“控制您的内容”链接：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00068.jpeg)

在“控制您的内容”部分，我们将看到一个“创建存档”的选项。这是我们开始 Google Takeout 收集的地方：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00069.jpeg)

选择此选项时，我们将看到管理现有存档或生成新存档的选项。生成新存档时，我们将看到每个我们希望包括的 Google 产品的复选框。下拉箭头提供子菜单，可更改导出格式或内容。例如，我们可以选择将 Google Drive 文档导出为 Microsoft Word、PDF 或纯文本格式。在这种情况下，我们将保留选项为默认值，确保邮件选项设置为收集所有邮件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00070.jpeg)

选择所需的内容后，我们可以配置存档的格式。Google Takeout 允许我们选择存档文件类型和最大段大小，以便轻松下载和访问。我们还可以选择如何访问 Takeout。此选项可以设置为将下载链接发送到被存档的帐户（默认选项）或将存档上传到帐户的 Google Drive 或其他第三方云服务，这可能会修改比必要更多的信息以保留这些数据。我们选择接收电子邮件，然后选择“创建存档”以开始该过程！

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00071.jpeg)

现在我们必须等待。根据要保存的数据大小，这可能需要相当长的时间，因为 Google 必须为您收集、转换和压缩所有数据。

当您收到通知电子邮件时，请选择提供的链接下载存档。此存档仅在有限的时间内可用，因此在收到通知后尽快收集它是很重要的。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00072.jpeg)

下载数据后，提取存档的内容并查看内部文件夹结构和提供的数据。所选的每个产品都有一个包含相关内容或产品的文件夹结构的文件夹。在这种情况下，我们最感兴趣的是以 MBOX 格式提供的邮件。在下一个配方中，我们将展示如何使用 Python 解析这些 MBOX 数据。

# 还有更多...

如果您更喜欢更直接的方式来获取这些数据，您可以在登录账户后导航到[`takeout.google.com/settings/takeout`](https://takeout.google.com/settings/takeout)。在这里，您可以选择要导出的产品。

# 盒子里有什么?!

配方难度：中等

Python 版本：3.5

操作系统：任何

MBOX 文件通常与 UNIX 系统、Thunderbird 和 Google Takeouts 相关联。这些 MBOX 容器是具有特殊格式的文本文件，用于分割存储在其中的消息。由于有几种用于构造 MBOX 文件的格式，我们的脚本将专注于来自 Google Takeout 的格式，使用前一个配方的输出。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。我们使用内置的`mailbox`库来解析 Google Takeout 结构化的 MBOX 文件。

要了解更多关于`mailbox`库的信息，请访问[`docs.python.org/3/library/mailbox.html`](https://docs.python.org/3/library/mailbox.html)。

# 如何做...

要实现这个脚本，我们必须：

1.  设计参数以接受 MBOX 文件的文件路径并输出报告内容。

1.  开发一个处理编码数据的自定义 MBOX 阅读器。

1.  提取消息元数据，包括附件名称。

1.  将附件写入输出目录。

1.  创建一个 MBOX 元数据报告。

# 它是如何工作的...

我们首先导入用于处理参数的库，然后是用于创建脚本输出的`os`、`time`和`csv`库。接下来，我们导入`mailbox`库来解析 MBOX 消息格式和`base64`来解码附件中的二进制数据。最后，我们引入`tqdm`库来提供与消息解析状态相关的进度条：

```py
from __future__ import print_function
from argparse import ArgumentParser
import mailbox
import os
import time
import csv
from tqdm import tqdm
import base64
```

这个配方的命令行处理程序接受两个位置参数，`MBOX`和`OUTPUT_DIR`，分别表示要处理的 MBOX 文件的路径和期望的输出文件夹。这两个参数都传递给`main()`函数来启动脚本：

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("MBOX", help="Path to mbox file")
    parser.add_argument("OUTPUT_DIR",
                        help="Path to output directory to write report "
                        "and exported content")
    args = parser.parse_args()

    main(args.MBOX, args.OUTPUT_DIR)
```

`main()`函数从调用`mailbox`库的`mbox`类开始。使用这个类，我们可以通过提供文件路径和一个可选的工厂参数来解析 MBOX 文件，这在我们的情况下是一个自定义阅读器函数。使用这个库，我们现在有一个包含我们可以交互的消息对象的可迭代对象。我们使用内置的`len()`方法来打印 MBOX 文件中包含的消息数量。让我们首先看看`custom_reader()`函数是如何工作的：

```py
def main(mbox_file, output_dir):
    # Read in the MBOX File
    print("Reading mbox file...")
    mbox = mailbox.mbox(mbox_file, factory=custom_reader)
    print("{} messages to parse".format(len(mbox)))
```

这个配方需要一些函数来运行（看到我们做了什么吗...），但`custom_reader()`方法与其他方法有些不同。这个函数是`mailbox`库的一个阅读器方法。我们需要创建这个函数，因为默认的阅读器不能处理诸如`cp1252`之类的编码。我们可以将其他编码添加到这个阅读器中，尽管 ASCII 和`cp1252`是 MBOX 文件的两种最常见的编码。

在输入数据流上使用`read()`方法后，它尝试使用 ASCII 代码页对数据进行解码。如果不成功，它将依赖`cp1252`代码页来完成任务。使用`cp1252`代码页解码时遇到的任何错误都将被替换为替换字符`U+FFFD`，通过向`decode()`方法提供`errors`关键字并将其设置为`"replace"`来实现。我们使用`mailbox.mboxMessage()`函数以适当的格式返回解码后的内容：

```py
def custom_reader(data_stream):
    data = data_stream.read()
    try:
        content = data.decode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        content = data.decode("cp1252", errors="replace")
    return mailbox.mboxMessage(content)
```

回到`main()`函数，在开始处理消息之前，我们准备了一些变量。具体来说，我们设置了`parsed_data`结果列表，为附件创建了一个输出目录，并定义了 MBOX 元数据报告的`columns`。这些列也将用于使用`get()`方法从消息中提取信息。其中两列不会从消息对象中提取信息，而是在处理附件后包含我们分配的数据。为了保持一致性，我们将这些值保留在`columns`列表中，因为它们将默认为`"N/A"`值：

```py
    parsed_data = []
    attachments_dir = os.path.join(output_dir, "attachments")
    if not os.path.exists(attachments_dir):
        os.makedirs(attachments_dir)
    columns = ["Date", "From", "To", "Subject", "X-Gmail-Labels",
               "Return-Path", "Received", "Content-Type", "Message-ID",
               "X-GM-THRID", "num_attachments_exported", "export_path"]
```

当我们开始迭代消息时，我们实现了一个`tqdm`进度条来跟踪迭代过程。由于`mbox`对象具有长度属性，因此我们不需要为`tqdm`提供任何额外的参数。在循环内部，我们定义了`msg_data`字典来存储消息结果，然后尝试通过第二个`for`循环使用`get()`方法在`header_data`字典中查询`columns`键来分配消息属性：

```py
    for message in tqdm(mbox):
        # Preserve header information
        msg_data = dict()
        header_data = dict(message._headers)
        for hdr in columns:
            msg_data[hdr] = header_data.get(hdr, "N/A")
```

接下来，在一个`if`语句中，我们检查`message`是否具有有效载荷，如果有，我们使用`write_payload()`方法，向其提供`message`对象和输出附件目录作为输入。如果`message`没有有效载荷，那么两个与附件相关的列将保持默认的`"N/A"`值。否则，我们计算找到的附件数量，并将它们的路径列表连接成逗号分隔的列表：

```py
        if len(message.get_payload()):
            export_path = write_payload(message, attachments_dir)
            msg_data['num_attachments_exported'] = len(export_path)
            msg_data['export_path'] = ", ".join(export_path)
```

每处理完一条消息，其数据都会被附加到`parsed_data`列表中。在处理完所有消息后，将调用`create_report()`方法，并传递`parsed_data`列表和所需的输出 CSV 名称。让我们回溯一下，首先看一下`write_payload()`方法：

```py
        parsed_data.append(msg_data)

    # Create CSV report
    create_report(
        parsed_data, os.path.join(output_dir, "mbox_report.csv"), columns
    )
```

由于消息可能具有各种各样的有效载荷，我们需要编写一个专门的函数来处理各种`MIME`类型。`write_payload()`方法就是这样一个函数。该函数首先通过`get_payload()`方法提取有效载荷，并进行快速检查，看看有效载荷内容是否包含多个部分。如果是，我们会递归调用此函数来处理每个子部分，通过迭代有效载荷并将输出附加到`export_path`变量中：

```py
def write_payload(msg, out_dir):
    pyld = msg.get_payload()
    export_path = []
    if msg.is_multipart():
        for entry in pyld:
            export_path += write_payload(entry, out_dir)
```

如果有效载荷不是多部分的，我们使用`get_content_type()`方法确定其 MIME 类型，并创建逻辑来根据类别适当地处理数据源。应用程序、图像和视频等数据类型通常表示为`base64`编码数据，允许将二进制信息作为 ASCII 字符传输。因此，大多数格式（包括文本类别中的一些格式）都要求我们在提供写入之前对数据进行解码。在其他情况下，数据已存在为字符串，并且可以按原样写入文件。无论如何，方法通常是相同的，数据被解码（如果需要），并使用`export_content()`方法将其内容写入文件系统。最后，表示导出项目路径的字符串被附加到`export_path`列表中：

```py
    else:
        content_type = msg.get_content_type()
        if "application/" in content_type.lower():
            content = base64.b64decode(msg.get_payload())
            export_path.append(export_content(msg, out_dir, content))
        elif "image/" in content_type.lower():
            content = base64.b64decode(msg.get_payload())
            export_path.append(export_content(msg, out_dir, content))
        elif "video/" in content_type.lower():
            content = base64.b64decode(msg.get_payload())
            export_path.append(export_content(msg, out_dir, content))
        elif "audio/" in content_type.lower():
            content = base64.b64decode(msg.get_payload())
            export_path.append(export_content(msg, out_dir, content))
        elif "text/csv" in content_type.lower():
            content = base64.b64decode(msg.get_payload())
            export_path.append(export_content(msg, out_dir, content))
        elif "info/" in content_type.lower():
            export_path.append(export_content(msg, out_dir,
                                              msg.get_payload()))
        elif "text/calendar" in content_type.lower():
            export_path.append(export_content(msg, out_dir,
                                              msg.get_payload()))
        elif "text/rtf" in content_type.lower():
            export_path.append(export_content(msg, out_dir,
                                              msg.get_payload()))
```

`else` 语句在负载中添加了一个额外的 `if-elif` 语句，以确定导出是否包含文件名。如果有，我们将其视为其他文件，但如果没有，它很可能是存储为 HTML 或文本的消息正文。虽然我们可以通过修改这一部分来导出每个消息正文，但这将为本示例生成大量数据，因此我们选择不这样做。一旦我们完成了从消息中导出数据，我们将导出的数据的路径列表返回给 `main()` 函数：

```py
        else:
            if "name=" in msg.get('Content-Disposition', "N/A"):
                content = base64.b64decode(msg.get_payload())
                export_path.append(export_content(msg, out_dir, content))
            elif "name=" in msg.get('Content-Type', "N/A"):
                content = base64.b64decode(msg.get_payload())
                export_path.append(export_content(msg, out_dir, content))

    return export_path
```

`export_content()` 函数首先调用 `get_filename()` 函数，这个方法从 `msg` 对象中提取文件名。对文件名进行额外处理以提取扩展名（如果有的话），如果没有找到则使用通用的 `.FILE` 扩展名：

```py
def export_content(msg, out_dir, content_data):
    file_name = get_filename(msg)
    file_ext = "FILE"
    if "." in file_name:
        file_ext = file_name.rsplit(".", 1)[-1]
```

接下来，我们进行额外的格式化，通过整合时间（表示为 Unix 时间整数）和确定的文件扩展名来创建一个唯一的文件名。然后将此文件名连接到输出目录，形成用于写入输出的完整路径。这个唯一的文件名确保我们不会错误地覆盖输出目录中已经存在的附件：

```py
    file_name = "{}_{:.4f}.{}".format(
        file_name.rsplit(".", 1)[0], time.time(), file_ext)
    file_name = os.path.join(out_dir, file_name)
```

这个函数中代码的最后一部分处理文件内容的实际导出。这个 `if` 语句处理不同的文件模式（`"w"` 或 `"wb"`），根据源类型。写入数据后，我们返回用于导出的文件路径。这个路径将被添加到我们的元数据报告中：

```py
    if isinstance(content_data, str):
        open(file_name, 'w').write(content_data)
    else:
        open(file_name, 'wb').write(content_data)

    return file_name
```

下一个函数 `get_filename()` 从消息中提取文件名以准确表示这些文件的名称。文件名可以在 `"Content-Disposition"` 或 `"Content-Type"` 属性中找到，并且通常以 `"name="` 或 `"filename="` 字符串开头。对于这两个属性，逻辑基本相同。该函数首先用一个空格替换任何换行符，然后在分号和空格上拆分字符串。这个分隔符通常分隔这些属性中的值。使用列表推导，我们确定哪个元素包含 `name=` 子字符串，并将其用作文件名：

```py
def get_filename(msg):
    if 'name=' in msg.get("Content-Disposition", "N/A"):
        fname_data = msg["Content-Disposition"].replace("\r\n", " ")
        fname = [x for x in fname_data.split("; ") if 'name=' in x]
        file_name = fname[0].split("=", 1)[-1]

    elif 'name=' in msg.get("Content-Type", "N/A"):
        fname_data = msg["Content-Type"].replace("\r\n", " ")
        fname = [x for x in fname_data.split("; ") if 'name=' in x]
        file_name = fname[0].split("=", 1)[-1]
```

如果这两个内容属性为空，我们分配一个通用的 `NO_FILENAME` 并继续准备文件名。提取潜在的文件名后，我们删除任何不是字母数字、空格或句号的字符，以防止在系统中写入文件时出错。准备好我们的文件系统安全文件名后，我们将其返回供前面讨论的 `export_content()` 方法使用：

```py
    else:
        file_name = "NO_FILENAME"

    fchars = [x for x in file_name if x.isalnum() or x.isspace() or
              x == "."]
    return "".join(fchars)
```

最后，我们已经到达了准备讨论 CSV 元数据报告的阶段。`create_report()` 函数类似于本书中我们已经看到的各种变体，它使用 `DictWriter` 类从字典列表创建 CSV 报告。哒哒！

```py
def create_report(output_data, output_file, columns):
    with open(output_file, 'w', newline="") as outfile:
        csvfile = csv.DictWriter(outfile, columns)
        csvfile.writeheader()
        csvfile.writerows(output_data)
```

这个脚本创建了一个 CSV 报告和一个附件目录。第一个截图显示了 CSV 报告的前几列和行以及数据如何显示给用户：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00073.jpeg)

这第二个截图显示了这些相同行的最后几列，并反映了附件信息的报告方式。这些文件路径可以被跟踪以访问相应的附件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00074.jpeg)

# 解析 PST 和 OST 邮箱

食谱难度：困难

Python 版本：2.7

操作系统：Linux

**个人存储表**（**PST**）文件通常在许多系统上找到，并提供对归档电子邮件的访问。这些文件通常与 Outlook 应用程序相关联，包含消息和附件数据。这些文件通常在企业环境中找到，因为许多商业环境继续利用 Outlook 进行内部和外部电子邮件管理。

# 入门指南

该配方需要安装`libpff`及其 Python 绑定`pypff`才能正常运行。这个库在 GitHub 上提供了工具和 Python 绑定，用于处理和提取 PST 文件中的数据。我们将在 Ubuntu 16.04 上为 Python 2 设置这个库以便开发。这个库也可以为 Python 3 构建，不过在本节中我们将使用 Python 2 的绑定。

在安装所需的库之前，我们必须安装一些依赖项。使用 Ubuntu 的`apt`软件包管理器，我们将安装以下八个软件包。您可能希望将这个 Ubuntu 环境保存好，因为我们将在第八章以及以后的章节中广泛使用它：

```py
sudo apt-get install automake autoconf libtool pkg-config autopoint git python-dev
```

安装依赖项后，转到 GitHub 存储库并下载所需的库版本。这个配方是使用`pypff`库的`libpff-experimental-20161119`版本开发的。接下来，一旦提取了发布的内容，打开终端并导航到提取的目录，并执行以下命令以进行发布：

```py
./synclibs.sh
./autogen.sh
sudo python setup.py install 
```

要了解有关`pypff`库的更多信息，请访问[`github.com/libyal/libpff`](https://github.com/libyal/libpff)。

最后，我们可以通过打开 Python 解释器，导入`pypff`并运行`pypff.get_version()`方法来检查库的安装情况，以确保我们有正确的发布版本。

# 如何操作...

我们按照以下步骤提取 PST 消息内容：

1.  使用`pypff`为 PST 文件创建一个句柄。

1.  遍历 PST 中的所有文件夹和消息。

1.  存储每条消息的相关元数据。

1.  根据 PST 的内容创建元数据报告。

# 工作原理...

该脚本首先导入用于处理参数、编写电子表格、执行正则表达式搜索和处理 PST 文件的库：

```py
from __future__ import print_function
from argparse import ArgumentParser
import csv
import pypff
import re
```

此配方的命令行处理程序接受两个位置参数，`PFF_FILE`和`CSV_REPORT`，分别表示要处理的 PST 文件的路径和所需的输出 CSV 路径。在这个配方中，我们不使用`main()`函数，而是立即使用`pypff.file()`对象来实例化`pff_obj`变量。随后，我们使用`open()`方法并尝试访问用户提供的 PST。我们将此 PST 传递给`process_folders()`方法，并将返回的字典列表存储在`parsed_data`变量中。在对`pff_obj`变量使用`close()`方法后，我们使用`write_data()`函数写入 PST 元数据报告，通过传递所需的输出 CSV 路径和处理后的数据字典：

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("PFF_FILE", help="Path to PST or OST File")
    parser.add_argument("CSV_REPORT", help="Path to CSV report location")
    args = parser.parse_args()

    # Open file
    pff_obj = pypff.file()
    pff_obj.open(args.PFF_FILE)

    # Parse and close file
    parsed_data = process_folders(pff_obj.root_folder)
    pff_obj.close()

    # Write CSV report
    write_data(args.CSV_REPORT, parsed_data)
```

这个配方由几个处理 PST 文件不同元素的函数组成。`process_folders()`函数处理文件夹处理和迭代。在处理这些文件夹时，我们将它们的名称、子文件夹的数量以及该文件夹中的消息数量打印到控制台。这可以通过在`pff_folder`对象上调用`number_of_sub_folders`和`number_of_sub_messages`属性来实现：

```py
def process_folders(pff_folder):
    folder_name = pff_folder.name if pff_folder.name else "N/A"
    print("Folder: {} (sub-dir: {}/sub-msg: {})".format(folder_name,
          pff_folder.number_of_sub_folders,
          pff_folder.number_of_sub_messages))
```

在打印这些消息后，我们设置了`data_list`，它负责存储处理过的消息数据。当我们遍历文件夹中的消息时，我们调用`process_message()`方法来创建带有处理过的消息数据的字典对象。紧接着，我们将文件夹名称添加到字典中，然后将其附加到结果列表中。

第二个循环通过递归调用`process_folders()`函数并将子文件夹传递给它，然后将结果字典列表附加到`data_list`中。这使我们能够遍历 PST 并提取所有数据，然后返回`data_list`并编写 CSV 报告：

```py
    # Process messages within a folder
    data_list = []
    for msg in pff_folder.sub_messages:
        data_dict = process_message(msg)
        data_dict['folder'] = folder_name
        data_list.append(data_dict)

    # Process folders within a folder
    for folder in pff_folder.sub_folders:
        data_list += process_folders(folder)

    return data_list
```

`process_message()` 函数负责访问消息的各种属性，包括电子邮件头信息。正如在以前的示例中所看到的，我们使用对象属性的列表来构建结果的字典。然后我们遍历`attribs`字典，并使用`getattr()`方法将适当的键值对附加到`data_dict`字典中。最后，如果存在电子邮件头，我们通过使用`transport_headers`属性来确定，我们将从`process_headers()`函数中提取的附加值更新到`data_dict`字典中：

```py
def process_message(msg):
    # Extract attributes
    attribs = ['conversation_topic', 'number_of_attachments',
               'sender_name', 'subject']
    data_dict = {}
    for attrib in attribs:
        data_dict[attrib] = getattr(msg, attrib, "N/A")

    if msg.transport_headers is not None:
        data_dict.update(process_headers(msg.transport_headers))

    return data_dict
```

`process_headers()` 函数最终返回一个包含提取的电子邮件头数据的字典。这些数据以键值对的形式显示，由冒号和空格分隔。由于头部中的内容可能存储在新的一行上，我们使用正则表达式来检查是否在行首有一个键，后面跟着一个值。如果我们找不到与模式匹配的键（任意数量的字母或破折号字符后跟着一个冒号），我们将把新值附加到先前的键上，因为头部以顺序方式显示信息。在这个函数的结尾，我们有一些特定的代码行，使用`isinstance()`来处理字典值的赋值。这段代码检查键的类型，以确保值被分配给键的方式不会覆盖与给定键关联的任何数据：

```py
def process_headers(header):
    # Read and process header information
    key_pattern = re.compile("^([A-Za-z\-]+:)(.*)$")
    header_data = {}
    for line in header.split("\r\n"):
        if len(line) == 0:
            continue

        reg_result = key_pattern.match(line)
        if reg_result:
            key = reg_result.group(1).strip(":").strip()
            value = reg_result.group(2).strip()
        else:
            value = line

        if key.lower() in header_data:
            if isinstance(header_data[key.lower()], list):
                header_data[key.lower()].append(value)
            else:
                header_data[key.lower()] = [header_data[key.lower()],
                                            value]
        else:
            header_data[key.lower()] = value
    return header_data
```

最后，`write_data()` 方法负责创建元数据报告。由于我们可能从电子邮件头解析中有大量的列名，我们遍历数据并提取不在列表中已定义的不同列名。使用这种方法，我们确保来自 PST 的动态信息不会被排除。在`for`循环中，我们还将`data_list`中的值重新分配到`formatted_data_list`中，主要是将列表值转换为字符串，以更容易地将数据写入电子表格。`csv`库很好地确保了单元格内的逗号被转义并由我们的电子表格应用程序适当处理：

```py
def write_data(outfile, data_list):
    # Build out additional columns
    print("Writing Report: ", outfile)
    columns = ['folder', 'conversation_topic', 'number_of_attachments',
               'sender_name', 'subject']
    formatted_data_list = []
    for entry in data_list:
        tmp_entry = {}

        for k, v in entry.items():
            if k not in columns:
                columns.append(k)

            if isinstance(v, list):
                tmp_entry[k] = ", ".join(v)
            else:
                tmp_entry[k] = v
        formatted_data_list.append(tmp_entry)
```

使用`csv.DictWriter`类，我们打开文件，写入头部和每一行到输出文件：

```py
    # Write CSV report
    with open(outfile, 'wb') as openfile:
        csvfile = csv.DictWriter(openfile, columns)
        csvfile.writeheader()
        csvfile.writerows(formatted_data_list)
```

当这个脚本运行时，将生成一个 CSV 报告，其外观应该与以下截图中显示的类似。在水平滚动时，我们可以看到在顶部指定的列名；特别是在电子邮件头列中，大多数这些列只包含少量的值。当您在您的环境中对更多的电子邮件容器运行此代码时，请注意哪些列是最有用的，并且在您处理 PST 时最常见，以加快分析的速度：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00075.jpeg)

# 还有更多...

这个过程可以进一步改进。我们提供了一个或多个以下建议：

+   这个库还处理**离线存储表**（**OST**）文件，通常与 Outlook 的离线邮件内容存储相关。找到并测试这个脚本在 OST 文件上，并在必要时修改以支持这种常见的邮件格式。

# 另请参阅

在这种情况下，我们还可以利用`Redemtion`库来访问 Outlook 中的信息。


# 第七章：基于日志的工件配方

本章涵盖了以下配方：

+   关于时间

+   使用 RegEx 解析 IIS weblogs

+   去探险

+   解释每日日志

+   将`daily.out`解析添加到 Axiom

+   使用 YARA 扫描指标

# 介绍

这些天，遇到配备某种形式的事件或活动监控软件的现代系统并不罕见。这种软件可能被实施以协助安全、调试或合规要求。无论情况如何，这些宝贵的信息宝库通常被广泛利用于各种类型的网络调查。日志分析的一个常见问题是需要筛选出感兴趣的子集所需的大量数据。通过本章的配方，我们将探索具有很大证据价值的各种日志，并演示快速处理和审查它们的方法。具体来说，我们将涵盖：

+   将不同的时间戳格式（UNIX、FILETIME 等）转换为人类可读的格式

+   解析来自 IIS 平台的 Web 服务器访问日志

+   使用 Splunk 的 Python API 摄取、查询和导出日志

+   从 macOS 的`daily.out`日志中提取驱动器使用信息

+   从 Axiom 执行我们的`daily.out`日志解析器

+   使用 YARA 规则识别感兴趣的文件的奖励配方

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 关于时间

配方难度：简单

Python 版本：2.7 或 3.5

操作系统：任何

任何良好日志文件的一个重要元素是时间戳。这个值传达了日志中记录的活动或事件的日期和时间。这些日期值可以以许多格式出现，并且可以表示为数字或十六进制值。除了日志之外，不同的文件和工件以不同的方式存储日期，即使数据类型保持不变。一个常见的区分因素是纪元值，即格式从中计算时间的日期。一个常见的纪元是 1970 年 1 月 1 日，尽管其他格式从 1601 年 1 月 1 日开始计算。在不同格式之间不同的因素是用于计数的间隔。虽然常见的是看到以秒或毫秒计数的格式，但有些格式计算时间块，比如自纪元以来的 100 纳秒数。因此，这里开发的配方可以接受原始日期时间输入，并将格式化的时间戳作为其输出。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。

# 如何做...

为了在 Python 中解释常见的日期格式，我们执行以下操作：

1.  设置参数以获取原始日期值、日期来源和数据类型。

1.  开发一个为不同日期格式提供通用接口的类。

1.  支持处理 Unix 纪元值和 Microsoft 的`FILETIME`日期。

# 它是如何工作的...

我们首先导入用于处理参数和解析日期的库。具体来说，我们需要从`datetime`库中导入`datetime`类来读取原始日期值，以及`timedelta`类来指定时间戳偏移量。

```py
from __future__ import print_function
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
from datetime import datetime as dt
from datetime import timedelta
```

这个配方的命令行处理程序接受三个位置参数，`date_value`、`source`和`type`，分别代表要处理的日期值、日期值的来源（UNIX、FILETIME 等）和类型（整数或十六进制值）。我们使用`choices`关键字来限制用户可以提供的选项。请注意，源参数使用自定义的`get_supported_formats()`函数，而不是预定义的受支持日期格式列表。然后，我们获取这些参数并初始化`ParseDate`类的一个实例，并调用`run()`方法来处理转换过程，然后将其`timestamp`属性打印到控制台。

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        formatter_class=ArgumentDefaultsHelpFormatter,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("date_value", help="Raw date value to parse")
    parser.add_argument("source", help="Source format of date",
                        choices=ParseDate.get_supported_formats())
    parser.add_argument("type", help="Data type of input value",
                        choices=('number', 'hex'), default='int')
    args = parser.parse_args()

    date_parser = ParseDate(args.date_value, args.source, args.type)
    date_parser.run()
    print(date_parser.timestamp)
```

让我们看看`ParseDate`类是如何工作的。通过使用一个类，我们可以轻松地扩展和在其他脚本中实现这段代码。从命令行参数中，我们接受日期值、日期源和值类型的参数。这些值和输出变量`timestamp`在`__init__`方法中被定义：

```py
class ParseDate(object):
    def __init__(self, date_value, source, data_type):
        self.date_value = date_value
        self.source = source
        self.data_type = data_type
        self.timestamp = None
```

`run（）`方法是控制器，很像我们许多食谱中的`main（）`函数，并根据日期源选择要调用的正确方法。这使我们能够轻松扩展类并轻松添加新的支持。在这个版本中，我们只支持三种日期类型：Unix 纪元秒，Unix 纪元毫秒和 Microsoft 的 FILETIME。为了减少我们需要编写的方法数量，我们将设计 Unix 纪元方法来处理秒和毫秒格式的时间戳。

```py
    def run(self):
        if self.source == 'unix-epoch':
            self.parse_unix_epoch()
        elif self.source == 'unix-epoch-ms':
            self.parse_unix_epoch(True)
        elif self.source == 'windows-filetime':
            self.parse_windows_filetime()
```

为了帮助未来想要使用这个库的人，我们添加了一个查看支持的格式的方法。通过使用`@classmethod`装饰器，我们可以在不需要先初始化类的情况下公开这个函数。这就是我们可以在命令行处理程序中使用`get_supported_formats（）`方法的原因。只需记住在添加新功能时更新它！

```py
    @classmethod
    def get_supported_formats(cls):
        return ['unix-epoch', 'unix-epoch-ms', 'windows-filetime']
```

`parse_unix_epoch（）`方法处理处理 Unix 纪元时间。我们指定一个可选参数`milliseconds`，以在处理秒和毫秒值之间切换此方法。首先，我们必须确定数据类型是``"hex"``还是``"number"``。如果是``"hex"``，我们将其转换为整数，如果是``"number"``，我们将其转换为浮点数。如果我们不认识或不支持此方法的数据类型，比如`string`，我们向用户抛出错误并退出脚本。

在转换值后，我们评估是否应将其视为毫秒值，如果是，则在进一步处理之前将其除以`1,000`。随后，我们使用`datetime`类的`fromtimestamp（）`方法将数字转换为`datetime`对象。最后，我们将这个日期格式化为人类可读的格式，并将这个字符串存储在`timestamp`属性中。

```py
    def parse_unix_epoch(self, milliseconds=False):
        if self.data_type == 'hex':
            conv_value = int(self.date_value)
            if milliseconds:
                conv_value = conv_value / 1000.0
        elif self.data_type == 'number':
            conv_value = float(self.date_value)
            if milliseconds:
                conv_value = conv_value / 1000.0
        else:
            print("Unsupported data type '{}' provided".format(
                self.data_type))
            sys.exit('1')

        ts = dt.fromtimestamp(conv_value)
        self.timestamp = ts.strftime('%Y-%m-%d %H:%M:%S.%f')
```

`parse_windows_filetime（）`类方法处理`FILETIME`格式，通常存储为十六进制值。使用与之前相似的代码块，我们将``"hex"``或``"number"``值转换为 Python 对象，并对任何其他提供的格式引发错误。唯一的区别是在进一步处理之前，我们将日期值除以`10`而不是`1,000`。

在之前的方法中，`datetime`库处理了纪元偏移，这次我们需要单独处理这个偏移。使用`timedelta`类，我们指定毫秒值，并将其添加到代表 FILETIME 格式纪元的`datetime`对象中。现在得到的`datetime`对象已经准备好供我们格式化和输出给用户了：

```py
    def parse_windows_filetime(self):
        if self.data_type == 'hex':
            microseconds = int(self.date_value, 16) / 10.0
        elif self.data_type == 'number':
            microseconds = float(self.date_value) / 10
        else:
            print("Unsupported data type '{}' provided".format(
                self.data_type))
            sys.exit('1')

        ts = dt(1601, 1, 1) + timedelta(microseconds=microseconds)
        self.timestamp = ts.strftime('%Y-%m-%d %H:%M:%S.%f')
```

当我们运行这个脚本时，我们可以提供一个时间戳，并以易于阅读的格式查看转换后的值，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00076.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议如下：

+   为其他类型的时间戳（OLE，WebKit 等）添加支持

+   通过`pytz`添加时区支持

+   使用`dateutil`处理难以阅读的日期格式

# 使用 RegEx 解析 IIS Web 日志

食谱难度：中等

Python 版本：3.5

操作系统：任何

来自 Web 服务器的日志对于生成用户统计信息非常有用，为我们提供了有关使用的设备和访问者的地理位置的深刻信息。它们还为寻找试图利用 Web 服务器或未经授权使用的用户的审查人员提供了澄清。虽然这些日志存储了重要的细节，但以一种不便于高效分析的方式进行。如果您尝试手动分析，字段名称被指定在文件顶部，并且在阅读文本文件时需要记住字段的顺序。幸运的是，有更好的方法。使用以下脚本，我们展示了如何遍历每一行，将值映射到字段，并创建一个正确显示结果的电子表格 - 使得快速分析数据集变得更加容易。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。

# 如何做...

为了正确制作这个配方，我们需要采取以下步骤：

1.  接受输入日志文件和输出 CSV 文件的参数。

1.  为日志的每一列定义正则表达式模式。

1.  遍历日志中的每一行，并以一种我们可以解析单独元素并处理带引号的空格字符的方式准备每一行。

1.  验证并将每个值映射到其相应的列。

1.  将映射的列和值写入电子表格报告。

# 它是如何工作的...

我们首先导入用于处理参数和日志记录的库，然后是我们需要解析和验证日志信息的内置库。这些包括`re`正则表达式库和`shlex`词法分析器库。我们还包括`sys`和`csv`来处理日志消息和报告的输出。我们通过调用`getLogger()`方法初始化了该配方的日志对象。

```py
from __future__ import print_function
from argparse import ArgumentParser, FileType
import re
import shlex
import logging
import sys
import csv

logger = logging.getLogger(__file__)
```

在导入之后，我们为从日志中解析的字段定义模式。这些信息在日志之间可能会有所不同，尽管这里表达的模式应该涵盖日志中的大多数元素。

您可能需要添加、删除或重新排序以下定义的模式，以正确解析您正在使用的 IIS 日志。这些模式应该涵盖 IIS 日志中常见的元素。

我们将这些模式构建为名为`iis_log_format`的元组列表，其中第一个元组元素是列名，第二个是用于验证预期内容的正则表达式模式。通过使用正则表达式模式，我们可以定义数据必须遵循的一组规则以使其有效。这些列必须按它们在日志中出现的顺序来表达，否则代码将无法正确地将值映射到列。

```py
iis_log_format = [
    ("date", re.compile(r"\d{4}-\d{2}-\d{2}")),
    ("time", re.compile(r"\d\d:\d\d:\d\d")),
    ("s-ip", re.compile(
        r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")),
    ("cs-method", re.compile(
        r"(GET)|(POST)|(PUT)|(DELETE)|(OPTIONS)|(HEAD)|(CONNECT)")),
    ("cs-uri-stem", re.compile(r"([A-Za-z0-1/\.-]*)")),
    ("cs-uri-query", re.compile(r"([A-Za-z0-1/\.-]*)")),
    ("s-port", re.compile(r"\d*")),
    ("cs-username", re.compile(r"([A-Za-z0-1/\.-]*)")),
    ("c-ip", re.compile(
        r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}")),
    ("cs(User-Agent)", re.compile(r".*")),
    ("sc-status", re.compile(r"\d*")),
    ("sc-substatus", re.compile(r"\d*")),
    ("sc-win32-status", re.compile(r"\d*")),
    ("time-taken", re.compile(r"\d*"))
]
```

此配方的命令行处理程序接受两个位置参数，`iis_log`和`csv_report`，分别表示要处理的 IIS 日志和所需的 CSV 路径。此外，此配方还接受一个可选参数`l`，指定配方日志文件的输出路径。

接下来，我们初始化了该配方的日志实用程序，并为控制台和基于文件的日志记录进行了配置。这一点很重要，因为我们应该以正式的方式注意到当我们无法为用户解析一行时。通过这种方式，如果出现问题，他们不应该在错误的假设下工作，即所有行都已成功解析并显示在生成的 CSV 电子表格中。我们还希望记录运行时消息，包括脚本的版本和提供的参数。在这一点上，我们准备调用`main()`函数并启动脚本。有关设置日志对象的更详细解释，请参阅第一章中的日志配方，*基本脚本和文件信息配方*。

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('iis_log', help="Path to IIS Log",
                        type=FileType('r'))
    parser.add_argument('csv_report', help="Path to CSV report")
    parser.add_argument('-l', help="Path to processing log",
                        default=__name__ + '.log')
    args = parser.parse_args()

    logger.setLevel(logging.DEBUG)
    msg_fmt = logging.Formatter("%(asctime)-15s %(funcName)-10s "
                                "%(levelname)-8s %(message)s")

    strhndl = logging.StreamHandler(sys.stdout)
    strhndl.setFormatter(fmt=msg_fmt)
    fhndl = logging.FileHandler(args.log, mode='a')
    fhndl.setFormatter(fmt=msg_fmt)

    logger.addHandler(strhndl)
    logger.addHandler(fhndl)

    logger.info("Starting IIS Parsing ")
    logger.debug("Supplied arguments: {}".format(", ".join(sys.argv[1:])))
    logger.debug("System " + sys.platform)
    logger.debug("Version " + sys.version)
    main(args.iis_log, args.csv_report, logger)
    logger.info("IIS Parsing Complete")
```

`main（）`函数处理了脚本中大部分的逻辑。我们创建一个列表`parsed_logs`，用于在迭代日志文件中的行之前存储解析后的行。在`for`循环中，我们剥离行并创建一个存储字典`log_entry`，以存储记录。通过跳过以注释（或井号）字符开头的行或者行为空，我们加快了处理速度，并防止了列匹配中的错误。

虽然 IIS 日志存储为以空格分隔的值，但它们使用双引号来转义包含空格的字符串。例如，`useragent`字符串是一个单一值，但通常包含一个或多个空格。使用`shlex`模块，我们可以使用`shlex（）`方法解析带有双引号的空格的行，并通过正确地在空格值上分隔数据来自动处理引号转义的空格。这个库可能会减慢处理速度，因此我们只在包含双引号字符的行上使用它。

```py
def main(iis_log, report_file, logger):
    parsed_logs = []
    for raw_line in iis_log:
        line = raw_line.strip()
        log_entry = {}
        if line.startswith("#") or len(line) == 0:
            continue
        if '\"' in line:
            line_iter = shlex.shlex(line_iter)
        else:
            line_iter = line.split(" ")
```

将行正确分隔后，我们使用`enumerate`函数逐个遍历记录中的每个元素，并提取相应的列名和模式。使用模式，我们在值上调用`match（）`方法，如果匹配，则在`log_entry`字典中创建一个条目。如果值不匹配模式，我们记录一个错误，并在日志文件中提供整行。在遍历每个列后，我们将记录字典附加到初始解析日志记录列表，并对剩余行重复此过程。

```py
        for count, split_entry in enumerate(line_iter):
            col_name, col_pattern = iis_log_format[count]
            if col_pattern.match(split_entry):
                log_entry[col_name] = split_entry
            else:
                logger.error("Unknown column pattern discovered. "
                             "Line preserved in full below")
                logger.error("Unparsed Line: {}".format(line))

        parsed_logs.append(log_entry)
```

处理完所有行后，我们在准备`write_csv（）`方法之前向控制台打印状态消息。我们使用一个简单的列表推导表达式来提取`iis_log_format`列表中每个元组的第一个元素，这代表一个列名。有了提取的列，让我们来看看报告编写器。

```py
    logger.info("Parsed {} lines".format(len(parsed_logs)))

    cols = [x[0] for x in iis_log_format]
    logger.info("Creating report file: {}".format(report_file))
    write_csv(report_file, cols, parsed_logs)
    logger.info("Report created")
```

报告编写器使用我们之前探讨过的方法创建一个 CSV 文件。由于我们将行存储为字典列表，我们可以使用`csv.DictWriter`类的四行代码轻松创建报告。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'w', newline="") as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

当我们查看脚本生成的 CSV 报告时，我们会在样本输出中看到以下字段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00077.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00078.jpeg)

# 还有更多...

这个脚本可以进一步改进。以下是一个建议：

+   虽然我们可以像在脚本开头看到的那样定义正则表达式模式，但我们可以使用正则表达式管理库来简化我们的生活。一个例子是`grok`库，它用于为模式创建变量名。这使我们能够轻松地组织和扩展模式，因为我们可以按名称而不是字符串值来表示它们。这个库被其他平台使用，比如 ELK 堆栈，用于管理和实现正则表达式。

# 进行洞穴探险

菜谱难度：中等

Python 版本：2.7

操作系统：任何

由于保存的详细级别和时间范围，日志文件很快就会变得相当庞大。正如您可能已经注意到的那样，先前菜谱的 CSV 报告很容易变得过大，以至于我们的电子表格应用程序无法有效地打开或浏览。与其在电子表格中分析这些数据，一个替代方法是将数据加载到数据库中。

**Splunk**是一个将 NoSQL 数据库与摄取和查询引擎结合在一起的平台，使其成为一个强大的分析工具。它的数据库的操作方式类似于 Elasticsearch 或 MongoDB，允许存储文档或结构化记录。因此，我们不需要为了将记录存储在数据库中而提供具有一致键值映射的记录。这就是使 NoSQL 数据库对于日志分析如此有用的原因，因为日志格式可能根据事件类型而变化。

在这个步骤中，我们学习将上一个步骤的 CSV 报告索引到 Splunk 中，从而可以在平台内部与数据交互。我们还设计脚本来针对数据集运行查询，并将响应查询的结果子集导出到 CSV 文件。这些过程分别处理，因此我们可以根据需要独立查询和导出数据。

# 入门

这个步骤需要安装第三方库`splunk-sdk`。此脚本中使用的所有其他库都包含在 Python 的标准库中。此外，我们必须在主机操作系统上安装 Splunk，并且由于`splunk-sdk`库的限制，必须使用 Python 2 来运行脚本。

要安装 Splunk，我们需要转到[Splunk.com](https://www.splunk.com/)，填写表格，并选择 Splunk Enterprise 免费试用下载。这个企业试用版允许我们练习 API，并且可以每天上传 500MB。下载应用程序后，我们需要启动它来配置应用程序。虽然有很多配置可以更改，但现在使用默认配置启动，以保持简单并专注于 API。这样做后，服务器的默认地址将是`localhost:8000`。通过在浏览器中导航到这个地址，我们可以首次登录，设置账户和（*请执行此操作*）更改管理员密码。

新安装的 Splunk 的默认用户名和密码是*admin*和*changeme*。

在 Splunk 实例激活后，我们现在可以安装 API 库。这个库处理从 REST API 到 Python 对象的转换。在撰写本书时，Splunk API 只能在 Python 2 中使用。`splunk-sdk`库可以使用`pip`安装：

```py
pip install splunk-sdk==1.6.2
```

要了解更多关于`splunk-sdk`库的信息，请访问[`dev.splunk.com/python`](http://dev.splunk.com/python)。

# 如何做到...

现在环境已经正确配置，我们可以开始开发代码。这个脚本将新数据索引到 Splunk，对该数据运行查询，并将响应我们查询的数据子集导出到 CSV 文件。为了实现这一点，我们需要：

1.  开发一个强大的参数处理接口，允许用户指定这些选项。

1.  构建一个处理各种属性方法的操作类。

1.  创建处理索引新数据和创建数据存储索引的过程的方法。

1.  建立运行 Splunk 查询的方法，以便生成信息丰富的报告。

1.  提供一种将报告导出为 CSV 格式的机制。

# 它是如何工作的...

首先导入此脚本所需的库，包括新安装的`splunklib`。为了防止由于用户无知而引起不必要的错误，我们使用`sys`库来确定执行脚本的 Python 版本，并在不是 Python 2 时引发错误。

```py
from __future__ import print_function
from argparse import ArgumentParser, ArgumentError
from argparse import ArgumentDefaultsHelpFormatter
import splunklib.client as client
import splunklib.results as results
import os
import sys
import csv

if sys.version_info.major != 2:
    print("Invalid python version. Must use Python 2 due to splunk api "
          "library")
```

下一个逻辑块是开发步骤的命令行参数处理程序。由于这段代码有很多选项和操作需要在代码中执行，我们需要在这一部分花费一些额外的时间。而且因为这段代码是基于类的，所以我们必须在这一部分设置一些额外的逻辑。

这个步骤的命令行处理程序接受一个位置输入`action`，表示要运行的操作（索引、查询或导出）。此步骤还支持七个可选参数：`index`、`config`、`file`、`query`、`cols`、`host`和`port`。让我们开始看看所有这些选项都做什么。

`index`参数实际上是一个必需的参数，用于指定要从中摄取、查询或导出数据的 Splunk 索引的名称。这可以是现有的或新的`index`名称。`config`参数是指包含 Splunk 实例的用户名和密码的配置文件。如参数帮助中所述，此文件应受保护并存储在代码执行位置之外。在企业环境中，您可能需要进一步保护这些凭据。

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        formatter_class=ArgumentDefaultsHelpFormatter,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument('action', help="Action to run",
                        choices=['index', 'query', 'export'])
    parser.add_argument('--index-name', help="Name of splunk index",
                        required=True)
    parser.add_argument('--config',
                        help="Place where login details are stored."
                        " Should have the username on the first line and"
                        " the password on the second."
                        " Please Protect this file!",
                        default=os.path.expanduser("~/.splunk_py.ini"))
```

`file`参数将用于提供要`index`到平台的文件的路径，或用于指定要将导出的`query`数据写入的文件名。例如，我们将使用`file`参数指向我们希望从上一个配方中摄取的 CSV 电子表格。`query`参数也具有双重作用，它可以用于从 Splunk 运行查询，也可以用于指定要导出为 CSV 的查询 ID。这意味着`index`和`query`操作只需要其中一个参数，但`export`操作需要两个参数。

```py
    parser.add_argument('--file', help="Path to file")
    parser.add_argument('--query', help="Splunk query to run or sid of "
                        "existing query to export")
```

最后一组参数允许用户修改配方的默认属性。例如，`cols`参数可用于指定从源数据中导出的列及其顺序。由于我们将查询和导出 IIS 日志，因此我们已经知道可用的列，并且对我们感兴趣。您可能希望根据正在探索的数据类型指定替代默认列。我们的最后两个参数包括`host`和`port`参数，每个参数默认为本地服务器，但可以配置为允许您与替代实例进行交互。

```py
    parser.add_argument(
        '--cols',
        help="Speficy columns to export. comma seperated list",
        default='_time,date,time,sc_status,c_ip,s_ip,cs_User_Agent')
    parser.add_argument('--host', help="hostname of server",
                        default="localhost")
    parser.add_argument('--port', help="help", default="8089")
    args = parser.parse_args()
```

确定了我们的参数后，我们可以解析它们并在执行配方之前验证所有要求是否满足。首先，我们必须打开并读取包含身份验证凭据的`config`文件，其中`username`在第一行，`password`在第二行。使用这些信息，我们创建一个包含登录详细信息和服务器位置的字典`conn_dict`，并将该字典传递给`splunklib`的`client.connect()`方法。请注意，我们使用`del()`方法删除包含这些敏感信息的变量。虽然用户名和密码仍然可以通过`service`对象访问，但我们希望限制存储这些详细信息的区域数量。在创建`service`变量后，我们测试是否在 Splunk 中安装了任何应用程序，因为默认情况下至少有一个应用程序，并将其用作成功验证的测试。

```py
    with open(args.config, 'r') as open_conf:
        username, password = [x.strip() for x in open_conf.readlines()]
    conn_dict = {'host': args.host, 'port': int(args.port),
                 'username': username, 'password': password}
    del(username)
    del(password)
    service = client.connect(**conn_dict)
    del(conn_dict)

    if len(service.apps) == 0:
        print("Login likely unsuccessful, cannot find any applications")
        sys.exit()
```

我们继续处理提供的参数，将列转换为列表并创建`Spelunking`类实例。要初始化该类，我们必须向其提供`service`变量、要执行的操作、索引名称和列。使用这些信息，我们的类实例现在已经准备就绪。

```py
    cols = args.cols.split(",")
    spelunking = Spelunking(service, args.action, args.index_name, cols)
```

接下来，我们使用一系列`if-elif-else`语句来处理我们预期遇到的三种不同操作。如果用户提供了`index`操作，我们首先确认可选的`file`参数是否存在，如果不存在则引发错误。如果我们找到它，我们将该值分配给`Spelunking`类实例的相应属性。对于`query`和`export`操作，我们重复这种逻辑，确认它们也使用了正确的可选参数。请注意，我们使用`os.path.abspath()`函数为类分配文件的绝对路径。这允许`splunklib`在系统上找到正确的文件。也许这是本书中最长的参数处理部分，我们已经完成了必要的逻辑，现在可以调用类的`run()`方法来启动特定操作的处理。

```py
    if spelunking.action == 'index':
        if 'file' not in vars(args):
            ArgumentError('--file parameter required')
            sys.exit()
        else:
            spelunking.file = os.path.abspath(args.file)

    elif spelunking.action == 'export':
        if 'file' not in vars(args):
            ArgumentError('--file parameter required')
            sys.exit()
        if 'query' not in vars(args):
            ArgumentError('--query parameter required')
            sys.exit()
        spelunking.file = os.path.abspath(args.file)
        spelunking.sid = args.query

    elif spelunking.action == 'query':
        if 'query' not in vars(args):
            ArgumentError('--query parameter required')
            sys.exit()
        else:
            spelunking.query = "search index={} {}".format(args.index_name,
                                                           args.query)

    else:
        ArgumentError('Unknown action required')
        sys.exit()

    spelunking.run()
```

现在参数已经在我们身后，让我们深入研究负责处理用户请求操作的类。这个类有四个参数，包括`service`变量，用户指定的`action`，Splunk 索引名称和要使用的列。所有其他属性都设置为`None`，如前面的代码块所示，如果它们被提供，将在执行时适当地初始化。这样做是为了限制类所需的参数数量，并处理某些属性未使用的情况。所有这些属性都在我们的类开始时初始化，以确保我们已经分配了默认值。

```py
class Spelunking(object):
    def __init__(self, service, action, index_name, cols):
        self.service = service
        self.action = action
        self.index = index_name
        self.file = None
        self.query = None
        self.sid = None
        self.job = None
        self.cols = cols
```

`run()`方法负责使用`get_or_create_index()`方法从 Splunk 实例获取`index`对象。它还检查在命令行指定了哪个动作，并调用相应的类实例方法。

```py
    def run(self):
        index_obj = self.get_or_create_index()
        if self.action == 'index':
            self.index_data(index_obj)
        elif self.action == 'query':
            self.query_index()
        elif self.action == 'export':
            self.export_report()
        return
```

`get_or_create_index()`方法，顾名思义，首先测试指定的索引是否存在，并连接到它，或者如果没有找到该名称的索引，则创建一个新的索引。由于这些信息存储在`service`变量的`indexes`属性中，作为一个类似字典的对象，我们可以很容易地通过名称测试索引的存在。

```py
    def get_or_create_index(self):
        # Create a new index
        if self.index not in self.service.indexes:
            return service.indexes.create(self.index)
        else:
            return self.service.indexes[self.index]
```

要从文件中摄取数据，比如 CSV 文件，我们可以使用一行语句将信息发送到`index_data()`方法中的实例。这个方法使用`splunk_index`对象的`upload()`方法将文件发送到 Splunk 进行摄取。虽然 CSV 文件是一个简单的例子，说明我们可以如何导入数据，但我们也可以使用前面的方法从原始日志中读取数据到 Splunk 实例，而不需要中间的 CSV 步骤。为此，我们希望使用`index`对象的不同方法，允许我们逐个发送每个解析的事件。

```py
    def index_data(self, splunk_index):
        splunk_index.upload(self.file)
```

`query_index()`方法涉及更多，因为我们首先需要修改用户提供的查询。如下面的片段所示，我们需要将用户指定的列添加到初始查询中。这将使在导出阶段未使用的字段在查询中可用。在修改后，我们使用`service.jobs.create()`方法在 Splunk 系统中创建一个新的作业，并记录查询 SID。这个 SID 将在导出阶段用于导出特定查询作业的结果。我们打印这些信息，以及作业在 Splunk 实例中到期之前的时间。默认情况下，这个生存时间值是`300`秒，或五分钟。

```py
    def query_index(self):
        self.query = self.query + "| fields + " + ", ".join(self.cols)
        self.job = self.service.jobs.create(self.query, rf=self.cols)
        self.sid = self.job.sid
        print("Query job {} created. will expire in {} seconds".format(
            self.sid, self.job['ttl']))
```

正如之前提到的，`export_report()`方法使用前面方法中提到的 SID 来检查作业是否完成，并检索要导出的数据。为了做到这一点，我们遍历可用的作业，如果我们的作业不存在，则发出警告。如果找到作业，但`is_ready()`方法返回`False`，则作业仍在处理中，尚未准备好导出结果。

```py
    def export_report(self):
        job_obj = None
        for j in self.service.jobs:
            if j.sid == self.sid:
                job_obj = j

        if job_obj is None:
            print("Job SID {} not found. Did it expire?".format(self.sid))
            sys.exit()

        if not job_obj.is_ready():
            print("Job SID {} is still processing. "
                  "Please wait to re-run".format(self.sir))
```

如果作业通过了这两个测试，我们从 Splunk 中提取数据，并使用`write_csv()`方法将其写入 CSV 文件。在这之前，我们需要初始化一个列表来存储作业结果。接下来，我们检索结果，指定感兴趣的列，并将原始数据读入`job_results`变量。幸运的是，`splunklib`提供了一个`ResultsReader`，它将`job_results`变量转换为一个字典列表。我们遍历这个列表，并将每个字典附加到`export_data`列表中。最后，我们提供文件路径、列名和要导出到 CSV 写入器的数据集。

```py
        export_data = []
        job_results = job_obj.results(rf=self.cols)
        for result in results.ResultsReader(job_results):
            export_data.append(result)

        self.write_csv(self.file, self.cols, export_data)
```

这个类中的`write_csv()`方法是一个`@staticmethod`。这个装饰器允许我们在类中使用一个通用的方法，而不需要指定一个实例。这个方法无疑会让那些在本书的其他地方使用过的人感到熟悉，我们在那里打开输出文件，创建一个`DictWriter`对象，然后将列标题和数据写入文件。

```py
    @staticmethod
    def write_csv(outfile, fieldnames, data):
        with open(outfile, 'wb') as open_outfile:
            csvfile = csv.DictWriter(open_outfile, fieldnames,
                                     extrasaction="ignore")
            csvfile.writeheader()
            csvfile.writerows(data)
```

在我们的假设用例中，第一阶段将是索引前一个食谱中 CSV 电子表格中的数据。如下片段所示，我们提供了前一个食谱中的 CSV 文件，并将其添加到 Splunk 索引中。接下来，我们寻找所有用户代理为 iPhone 的条目。最后，最后一个阶段涉及从查询中获取输出并创建一个 CSV 报告。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00079.jpeg)

成功执行这三个命令后，我们可以打开并查看过滤后的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00080.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议，如下所示：

+   Python 的 Splunk API（以及一般）还有许多其他功能。此外，还可以使用更高级的查询技术来生成我们可以将其转换为技术和非技术最终用户的图形的数据。了解更多 Splunk API 提供的许多功能。

# 解释 daily.out 日志

食谱难度：中等

Python 版本：3.5

操作系统：任意

操作系统日志通常反映系统上软件、硬件和服务的事件。这些细节可以在我们调查事件时帮助我们，比如可移动设备的使用。一个可以证明在识别这种活动中有用的日志的例子是在 macOS 系统上找到的`daily.out`日志。这个日志记录了大量信息，包括连接到机器上的驱动器以及每天可用和已使用的存储量。虽然我们也可以从这个日志中了解关机时间、网络状态和其他信息，但我们将专注于随时间的驱动器使用情况。

# 入门

此脚本中使用的所有库都包含在 Python 的标准库中。

# 如何做...

这个脚本将利用以下步骤：

1.  设置参数以接受日志文件和写入报告的路径。

1.  构建一个处理日志各个部分解析的类。

1.  创建一个提取相关部分并传递给进一步处理的方法。

1.  从这些部分提取磁盘信息。

1.  创建一个 CSV 写入器来导出提取的细节。

# 它是如何工作的...

我们首先导入必要的库来处理参数、解释日期和写入电子表格。在 Python 中处理文本文件的一个很棒的地方是你很少需要第三方库。

```py
from __future__ import print_function
from argparse import ArgumentParser, FileType
from datetime import datetime
import csv
```

这个食谱的命令行处理程序接受两个位置参数，`daily_out`和`output_report`，分别代表 daily.out 日志文件的路径和 CSV 电子表格的期望输出路径。请注意，我们通过`argparse.FileType`类传递一个打开的文件对象进行处理。随后，我们用日志文件初始化`ProcessDailyOut`类，并调用`run()`方法，并将返回的结果存储在`parsed_events`变量中。然后我们调用`write_csv()`方法，使用`processor`类对象中定义的列将结果写入到所需输出目录中的电子表格中。

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("daily_out", help="Path to daily.out file",
                        type=FileType('r'))
    parser.add_argument("output_report", help="Path to csv report")
    args = parser.parse_args()

    processor = ProcessDailyOut(args.daily_out)
    parsed_events = processor.run()
    write_csv(args.output_report, processor.report_columns, parsed_events)
```

在`ProcessDailyOut`类中，我们设置了用户提供的属性，并定义了报告中使用的列。请注意，我们添加了两组不同的列：`disk_status_columns`和`report_columns`。`report_columns`只是`disk_status_columns`，再加上两个额外的字段来标识条目的日期和时区。

```py
class ProcessDailyOut(object):
    def __init__(self, daily_out):
        self.daily_out = daily_out
        self.disk_status_columns = [
            'Filesystem', 'Size', 'Used', 'Avail', 'Capacity', 'iused',
            'ifree', '%iused', 'Mounted on']
        self.report_columns = ['event_date', 'event_tz'] + \
            self.disk_status_columns
```

`run()`方法首先遍历提供的日志文件。在从每行的开头和结尾去除空白字符后，我们验证内容以识别部分中断。`"-- End of daily output --"`字符串中断了日志文件中的每个条目。每个条目包含几个由新行分隔的数据部分。因此，我们必须使用几个代码块来分割和处理每个部分。

在这个循环中，我们收集来自单个事件的所有行，并将其传递给`process_event()`方法，并将处理后的结果追加到最终返回的`parsed_events`列表中。

```py
    def run(self):
        event_lines = []
        parsed_events = []
        for raw_line in self.daily_out:
            line = raw_line.strip()
            if line == '-- End of daily output --':
                parsed_events += self.process_event(event_lines)
                event_lines = []
            else:
                event_lines.append(line)
        return parsed_events
```

在`process_event()`方法中，我们将定义变量，以便我们可以分割事件的各个部分以进行进一步处理。为了更好地理解代码的下一部分，请花一点时间查看以下事件的示例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00081.jpeg)

在此事件中，我们可以看到第一个元素是日期值和时区，后面是一系列子部分。每个子部分标题都是以冒号结尾的行；我们使用这一点来拆分文件中的各种数据元素，如下面的代码所示。我们使用部分标题作为键，其内容（如果存在）作为值，然后进一步处理每个子部分。

```py
    def process_event(self, event_lines):
        section_header = ""
        section_data = []
        event_data = {}
        for line in event_lines:
            if line.endswith(":"):
                if len(section_data) > 0:
                    event_data[section_header] = section_data
                    section_data = []
                    section_header = ""

                section_header = line.strip(":")
```

如果部分标题行不以冒号结尾，我们检查行中是否恰好有两个冒号。如果是这样，我们尝试将此行验证为日期值。为了处理此日期格式，我们需要从日期的其余部分单独提取时区，因为已知 Python 3 版本在解析带有`%Z`格式化程序的时区时存在已知错误。对于感兴趣的人，可以在[`bugs.python.org/issue22377`](https://bugs.python.org/issue22377)找到有关此错误的更多信息。

为了将时区与日期值分开，我们在空格值上分隔字符串，在这个示例中将时区值（元素`4`）放入自己的变量中，然后将剩余的时间值连接成一个新的字符串，我们可以使用`datetime`库解析。如果字符串没有至少`5`个元素，可能会引发`IndexError`，或者如果`datetime`格式字符串无效，可能会引发`ValueError`。如果没有引发这两种错误类型，我们将日期分配给`event_data`字典。如果我们收到这些错误中的任何一个，该行将附加到`section_data`列表中，并且下一个循环迭代将继续。这很重要，因为一行可能包含两个冒号，但不是日期值，所以我们不希望将其从脚本的考虑中移除。

```py
            elif line.count(":") == 2:
                try:
                    split_line = line.split()
                    timezone = split_line[4]
                    date_str = " ".join(split_line[:4] + [split_line[-1]])
                    try:
                        date_val = datetime.strptime(
                            date_str, "%a %b %d %H:%M:%S %Y")
                    except ValueError:
                        date_val = datetime.strptime(
                            date_str, "%a %b %d %H:%M:%S %Y")
                    event_data["event_date"] = [date_val, timezone]
                    section_data = []
                    section_header = ""
                except ValueError:
                    section_data.append(line)
                except IndexError:
                    section_data.append(line)
```

此条件的最后一部分将任何具有内容的行附加到`section_data`变量中，以根据需要进行进一步处理。这可以防止空白行进入，并允许我们捕获两个部分标题之间的所有信息。

```py
            else:
                if len(line):
                    section_data.append(line)
```

通过调用任何子部分处理器来关闭此函数。目前，我们只处理磁盘信息子部分，使用`process_disk()`方法，尽管可以开发代码来提取其他感兴趣的值。此方法接受事件信息和事件日期作为其输入。磁盘信息作为处理过的磁盘信息元素列表返回，我们将其返回给`run()`方法，并将值添加到处理过的事件列表中。

```py
        return self.process_disk(event_data.get("Disk status", []),
                                 event_data.get("event_date", []))
```

要处理磁盘子部分，我们遍历每一行，如果有的话，并提取相关的事件信息。`for`循环首先检查迭代号，并跳过行零，因为它包含数据的列标题。对于任何其他行，我们使用列表推导式，在单个空格上拆分行，去除空白，并过滤掉任何空字段。

```py
    def process_disk(self, disk_lines, event_dates):
        if len(disk_lines) == 0:
            return {}

        processed_data = []
        for line_count, line in enumerate(disk_lines):
            if line_count == 0:
                continue
            prepped_lines = [x for x in line.split(" ")
                             if len(x.strip()) != 0]
```

接下来，我们初始化一个名为`disk_info`的字典，其中包含了此快照的日期和时区详细信息。`for`循环使用`enumerate()`函数将值映射到它们的列名。如果列名包含`"/Volumes/"`（驱动器卷的标准挂载点），我们将连接剩余的拆分项。这样可以确保保留具有空格名称的卷。

```py
            disk_info = {
                "event_date": event_dates[0],
                "event_tz": event_dates[1]
            }
            for col_count, entry in enumerate(prepped_lines):
                curr_col = self.disk_status_columns[col_count]
                if "/Volumes/" in entry:
                    disk_info[curr_col] = " ".join(
                        prepped_lines[col_count:])
                    break
                disk_info[curr_col] = entry.strip()
```

最内层的`for`循环通过将磁盘信息附加到`processed_data`列表来结束。一旦磁盘部分中的所有行都被处理，我们就将`processed_data`列表返回给父函数。

```py
            processed_data.append(disk_info)
        return processed_data
```

最后，我们简要介绍了`write_csv()`方法，它使用`DictWriter`类来打开文件并将标题行和内容写入 CSV 文件。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'w', newline="") as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

当我们运行这个脚本时，我们可以在 CSV 报告中看到提取出的细节。这里展示了这个输出的一个例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00082.jpeg)

# 将 daily.out 解析添加到 Axiom

教程难度：简单

Python 版本：2.7

操作系统：任意

使用我们刚刚开发的代码来解析 macOS 的`daily.out`日志，我们将这个功能添加到 Axiom 中，由*Magnet Forensics*开发，用于自动提取这些事件。由于 Axiom 支持处理取证镜像和松散文件，我们可以提供完整的获取或只是`daily.out`日志的导出作为示例。通过这个工具提供的 API，我们可以访问和处理其引擎发现的文件，并直接在 Axiom 中返回审查结果。

# 入门

Magnet Forensics 团队开发了一个 API，用于 Python 和 XML，以支持在 Axiom 中创建自定义 artifact。截至本书编写时，Python API 仅适用于运行 Python 版本 2.7 的`IronPython`。虽然我们在这个平台之外开发了我们的代码，但我们可以按照本教程中的步骤轻松地将其集成到 Axiom 中。我们使用了 Axiom 版本 1.1.3.5726 来测试和开发这个教程。

我们首先需要在 Windows 实例中安装 Axiom，并确保我们的代码稳定且可移植。此外，我们的代码需要在沙盒中运行。Axiom 沙盒限制了对第三方库的使用以及对可能导致代码与应用程序外部系统交互的一些 Python 模块和函数的访问。因此，我们设计了我们的`daily.out`解析器，只使用在沙盒中安全的内置库，以演示使用这些自定义 artifact 的开发的便利性。

# 如何做...

要开发和实现自定义 artifact，我们需要：

1.  在 Windows 机器上安装 Axiom。

1.  导入我们开发的脚本。

1.  创建`Artifact`类并定义解析器元数据和列。

1.  开发`Hunter`类来处理 artifact 处理和结果报告。

# 工作原理...

对于这个脚本，我们导入了`axiom`库和 datetime 库。请注意，我们已经删除了之前的`argparse`和`csv`导入，因为它们在这里是不必要的。

```py
from __future__ import print_function
from axiom import *
from datetime import datetime
```

接下来，我们必须粘贴前一个教程中的`ProcessDailyOut`类，不包括`write_csv`或参数处理代码，以在这个脚本中使用。由于当前版本的 API 不允许导入，我们必须将所有需要的代码捆绑到一个单独的脚本中。为了节省页面并避免冗余，我们将在本节中省略代码块（尽管它在本章附带的代码文件中存在）。

下一个类是`DailyOutArtifact`，它是 Axiom API 提供的`Artifact`类的子类。在定义插件的名称之前，我们调用`AddHunter()`方法，提供我们的（尚未显示的）`hHunter`类。

```py
class DailyOutArtifact(Artifact):
    def __init__(self):
        self.AddHunter(DailyOutHunter())

    def GetName(self):
        return 'daily.out parser'
```

这个类的最后一个方法`CreateFragments()`指定了如何处理已处理的 daily.out 日志结果的单个条目。就 Axiom API 而言，片段是用来描述 artifact 的单个条目的术语。这段代码允许我们添加自定义列名，并为这些列分配适当的类别和数据类型。这些类别包括日期、位置和工具定义的其他特殊值。我们 artifact 的大部分列将属于`None`类别，因为它们不显示特定类型的信息。

一个重要的分类区别是`DateTimeLocal`与`DateTime`：`DateTime`将日期呈现为 UTC 值呈现给用户，因此我们需要注意选择正确的日期类别。因为我们从 daily.out 日志条目中提取了时区，所以在这个示例中我们使用`DateTimeLocal`类别。`FragmentType`属性是所有值的字符串，因为该类不会将值从字符串转换为其他数据类型。

```py
    def CreateFragments(self):
        self.AddFragment('Snapshot Date - LocalTime (yyyy-mm-dd)',
                         Category.DateTimeLocal, FragmentType.DateTime)
        self.AddFragment('Snapshot Timezone', Category.None,
                         FragmentType.String)
        self.AddFragment('Volume Name',
                         Category.None, FragmentType.String)
        self.AddFragment('Filesystem Mount',
                         Category.None, FragmentType.String)
        self.AddFragment('Volume Size',
                         Category.None, FragmentType.String)
        self.AddFragment('Volume Used',
                         Category.None, FragmentType.String)
        self.AddFragment('Percentage Used',
                         Category.None, FragmentType.String)
```

接下来的类是我们的`Hunter`。这个父类用于运行处理代码，并且正如你将看到的，指定了将由 Axiom 引擎提供给插件的平台和内容。在这种情况下，我们只想针对计算机平台和一个单一名称的文件运行。`RegisterFileName()`方法是指定插件将请求哪些文件的几种选项之一。我们还可以使用正则表达式或文件扩展名来选择我们想要处理的文件。

```py
class DailyOutHunter(Hunter):
    def __init__(self):
        self.Platform = Platform.Computer

    def Register(self, registrar):
        registrar.RegisterFileName('daily.out')
```

`Hunt()`方法是魔法发生的地方。首先，我们获取一个临时路径，在沙箱内可以读取文件，并将其分配给`temp_daily_out`变量。有了这个打开的文件，我们将文件对象交给`ProcessDailyOut`类，并使用`run()`方法解析文件，就像上一个示例中一样。

```py
    def Hunt(self, context):
        temp_daily_out = open(context.Searchable.FileCopy, 'r')

        processor = ProcessDailyOut(temp_daily_out)
        parsed_events = processor.run()
```

在收集了解析的事件信息之后，我们准备将数据“发布”到软件并显示给用户。在`for`循环中，我们首先初始化一个`Hit()`对象，使用`AddValue()`方法向新片段添加数据。一旦我们将事件值分配给了一个 hit，我们就使用`PublishHit()`方法将 hit 发布到平台，并继续循环直到所有解析的事件都被发布：

```py
        for entry in parsed_events:
            hit = Hit()
            hit.AddValue(
                "Snapshot Date - LocalTime (yyyy-mm-dd)",
                entry['event_date'].strftime("%Y-%m-%d %H:%M:%S"))
            hit.AddValue("Snapshot Timezone", entry['event_tz'])
            hit.AddValue("Volume Name", entry['Mounted on'])
            hit.AddValue("Filesystem Mount", entry["Filesystem"])
            hit.AddValue("Volume Size", entry['Size'])
            hit.AddValue("Volume Used", entry['Used'])
            hit.AddValue("Percentage Used", entry['Capacity'])
            self.PublishHit(hit)
```

最后一部分代码检查文件是否不是`None`，如果是，则关闭它。这是处理代码的结尾，如果在系统上发现另一个`daily.out`文件，可能会再次调用它！

```py
        if temp_daily_out is not None:
            temp_daily_out.close()
```

最后一行注册了我们的辛勤工作到 Axiom 的引擎，以确保它被框架包含和调用。

```py
RegisterArtifact(DailyOutArtifact())
```

要在 Axiom 中使用新开发的工件，我们需要采取一些步骤来导入并针对图像运行代码。首先，我们需要启动 Axiom Process。这是我们将加载、选择并针对提供的证据运行工件的地方。在工具菜单下，我们选择管理自定义工件选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00083.jpeg)

在管理自定义工件窗口中，我们将看到任何现有的自定义工件，并可以像这样导入新的工件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00084.jpeg)

我们将添加我们的自定义工件，更新的管理自定义工件窗口应该显示工件的名称：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00085.jpeg)

现在我们可以按下确定并继续进行 Axiom，添加证据并配置我们的处理选项。当我们到达计算机工件选择时，我们要确认选择运行自定义工件。可能不用说：我们应该只在机器运行 macOS 或者在其上有 macOS 分区时运行这个工件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00086.jpeg)

完成剩余的配置选项后，我们可以开始处理证据。处理完成后，我们运行 Axiom Examine 来查看处理结果。如下截图所示，我们可以导航到工件审查的自定义窗格，并看到插件解析的列！这些列可以使用 Axiom 中的标准选项进行排序和导出，而无需我们额外的代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00087.jpeg)

# 使用 YARA 扫描指示器

配方难度：中等

Python 版本：3.5

操作系统：任何

作为一个额外的部分，我们将利用强大的**Yet Another Recursive Algorithm**（**YARA**）正则表达式引擎来扫描感兴趣的文件和妥协指标。YARA 是一种用于恶意软件识别和事件响应的模式匹配实用程序。许多工具使用此引擎作为识别可能恶意文件的基础。通过这个示例，我们学习如何获取 YARA 规则，编译它们，并在一个或多个文件夹或文件中进行匹配。虽然我们不会涵盖形成 YARA 规则所需的步骤，但可以从他们的文档中了解更多关于这个过程的信息[`yara.readthedocs.io/en/latest/writingrules.html`](http://yara.readthedocs.io/en/latest/writingrules.html)。

# 入门

此示例需要安装第三方库`yara`。此脚本中使用的所有其他库都包含在 Python 的标准库中。可以使用`pip`安装此库：

```py
pip install yara-python==3.6.3
```

要了解更多关于`yara-python`库的信息，请访问[`yara.readthedocs.io/en/latest/`](https://yara.readthedocs.io/en/latest/)。

我们还可以使用项目如 YaraRules ([`yararules.com`](http://yararules.com))，并使用行业和 VirusShare ([`virusshare.com`](http://virusshare.com))的预构建规则来使用真实的恶意软件样本进行分析。

# 如何做...

此脚本有四个主要的开发步骤：

1.  设置和编译 YARA 规则。

1.  扫描单个文件。

1.  遍历目录以处理单个文件。

1.  将结果导出到 CSV。

# 它是如何工作的...

此脚本导入所需的库来处理参数解析、文件和文件夹迭代、编写 CSV 电子表格，以及`yara`库来编译和扫描 YARA 规则。

```py
from __future__ import print_function
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import os
import csv
import yara
```

这个示例的命令行处理程序接受两个位置参数，`yara_rules`和`path_to_scan`，分别表示 YARA 规则的路径和要扫描的文件或文件夹。此示例还接受一个可选参数`output`，如果提供，将扫描结果写入电子表格而不是控制台。最后，我们将这些值传递给`main()`方法。

```py
if __name__ == '__main__':
    parser = ArgumentParser(
        description=__description__,
        formatter_class=ArgumentDefaultsHelpFormatter,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument(
        'yara_rules',
        help="Path to Yara rule to scan with. May be file or folder path.")
    parser.add_argument(
        'path_to_scan',
        help="Path to file or folder to scan")
    parser.add_argument(
        '--output',
        help="Path to output a CSV report of scan results")
    args = parser.parse_args()

    main(args.yara_rules, args.path_to_scan, args.output)
```

在`main()`函数中，我们接受`yara`规则的路径、要扫描的文件或文件夹以及输出文件（如果有）。由于`yara`规则可以是文件或目录，我们使用`ios.isdir()`方法来确定我们是否在整个目录上使用`compile()`方法，或者如果输入是一个文件，则使用`filepath`关键字将其传递给该方法。`compile()`方法读取规则文件或文件并创建一个我们可以与我们扫描的对象进行匹配的对象。

```py
def main(yara_rules, path_to_scan, output):
    if os.path.isdir(yara_rules):
        yrules = yara.compile(yara_rules)
    else:
        yrules = yara.compile(filepath=yara_rules)
```

一旦规则被编译，我们执行类似的`if-else`语句来处理要扫描的路径。如果要扫描的输入是一个目录，我们将其传递给`process_directory()`函数，否则，我们使用`process_file()`方法。两者都使用编译后的 YARA 规则和要扫描的路径，并返回包含任何匹配项的字典列表。

```py
    if os.path.isdir(path_to_scan):
        match_info = process_directory(yrules, path_to_scan)
    else:
        match_info = process_file(yrules, path_to_scan)
```

正如你可能猜到的，如果指定了输出路径，我们最终将把这个字典列表转换为 CSV 报告，使用我们在`columns`列表中定义的列。然而，如果输出参数是`None`，我们将以不同的格式将这些数据写入控制台。

```py
    columns = ['rule_name', 'hit_value', 'hit_offset', 'file_name',
               'rule_string', 'rule_tag']

    if output is None:
        write_stdout(columns, match_info)
    else:
        write_csv(output, columns, match_info)
```

`process_directory()`函数本质上是遍历目录并将每个文件传递给`process_file()`函数。这减少了脚本中冗余代码的数量。返回的每个处理过的条目都被添加到`match_info`列表中，因为返回的对象是一个列表。一旦我们处理了每个文件，我们将完整的结果列表返回给父函数。

```py
def process_directory(yrules, folder_path):
    match_info = []
    for root, _, files in os.walk(folder_path):
        for entry in files:
            file_entry = os.path.join(root, entry)
            match_info += process_file(yrules, file_entry)
    return match_info
```

`process_file()` 方法使用了 `yrules` 对象的 `match()` 方法。返回的匹配对象是一个可迭代的对象，包含了一个或多个与规则匹配的结果。从匹配结果中，我们可以提取规则名称、任何标签、文件中的偏移量、规则的字符串值以及匹配结果的字符串值。这些信息加上文件路径将形成报告中的一条记录。总的来说，这些信息对于确定匹配结果是误报还是重要的非常有用。在微调 YARA 规则以确保只呈现相关结果进行审查时也非常有帮助。

```py
def process_file(yrules, file_path):
    match = yrules.match(file_path)
    match_info = []
    for rule_set in match:
        for hit in rule_set.strings:
            match_info.append({
                'file_name': file_path,
                'rule_name': rule_set.rule,
                'rule_tag': ",".join(rule_set.tags),
                'hit_offset': hit[0],
                'rule_string': hit[1],
                'hit_value': hit[2]
            })
    return match_info
```

`write_stdout()` 函数如果用户没有指定输出文件，则将匹配信息报告到控制台。我们遍历 `match_info` 列表中的每个条目，并以冒号分隔、换行分隔的格式打印出 `match_info` 字典中的每个列名及其值。在每个条目之后，我们打印 `30` 个等号来在视觉上将条目分隔开。

```py
def write_stdout(columns, match_info):
    for entry in match_info:
        for col in columns:
            print("{}: {}".format(col, entry[col]))
        print("=" * 30)
```

`write_csv()` 方法遵循标准约定，使用 `DictWriter` 类来写入标题和所有数据到表格中。请注意，这个函数已经调整为在 Python 3 中处理 CSV 写入，使用了 `'w'` 模式和 `newline` 参数。

```py
def write_csv(outfile, fieldnames, data):
    with open(outfile, 'w', newline="") as open_outfile:
        csvfile = csv.DictWriter(open_outfile, fieldnames)
        csvfile.writeheader()
        csvfile.writerows(data)
```

使用这段代码，我们可以在命令行提供适当的参数，并生成任何匹配的报告。以下截图显示了用于检测 Python 文件和键盘记录器的自定义规则：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00088.jpeg)

这些规则显示在输出的 CSV 报告中，如果没有指定报告，则显示在控制台中，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00089.jpeg)


# 第八章：处理数字取证容器配方

在本章中，我们将涵盖以下配方：

+   打开收购

+   收集收购和媒体信息

+   遍历文件

+   处理容器内的文件

+   搜索哈希

# 介绍

Sleuth Kit 及其 Python 绑定`pytsk3`可能是最知名的 Python 数字取证库。该库提供了丰富的支持，用于访问和操作文件系统。借助支持库（如`pyewf`），它们可以用于处理 EnCase 流行的`E01`格式等常见数字取证容器。如果没有这些库（以及许多其他库），我们在数字取证中所能完成的工作将受到更多限制。由于其作为一体化文件系统分析工具的宏伟目标，`pytsk3`可能是我们在本书中使用的最复杂的库。

出于这个原因，我们专门制定了一些配方，探索了这个库的基本原理。到目前为止，配方主要集中在松散文件支持上。这种惯例到此为止。我们将会经常使用这个库来与数字取证证据进行交互。了解如何与数字取证容器进行交互将使您的 Python 数字取证能力提升到一个新的水平。

在本章中，我们将学习如何安装`pytsk3`和`pyewf`，这两个库将允许我们利用 Sleuth Kit 和`E01`镜像支持。此外，我们还将学习如何执行基本任务，如访问和打印分区表，遍历文件系统，按扩展名导出文件，以及在数字取证容器中搜索已知的不良哈希。您将学习以下内容：

+   安装和设置`pytsk3`和`pyewf`

+   打开数字取证收购，如`raw`和`E01`文件

+   提取分区表数据和`E01`元数据

+   递归遍历活动文件并创建活动文件列表电子表格

+   按文件扩展名从数字取证容器中导出文件

+   在数字取证容器中搜索已知的不良哈希

访问[www.packtpub.com/books/content/support](http://www.packtpub.com/books/content/support)下载本章的代码包。

# 打开收购

配方难度：中等

Python 版本：2.7

操作系统：Linux

使用`pyewf`和`pytsk3`将带来一整套新的工具和操作，我们必须首先学习。在这个配方中，我们将从基础知识开始：打开数字取证容器。这个配方支持`raw`和`E01`镜像。请注意，与我们之前的脚本不同，由于在使用这些库的 Python 3.X 版本时发现了一些错误，这些配方将使用 Python 2.X。也就是说，主要逻辑在两个版本之间并没有区别，可以很容易地移植。在学习如何打开容器之前，我们需要设置我们的环境。我们将在下一节中探讨这个问题。

# 入门

除了一些脚本之外，我们在本书的大部分内容中都是与操作系统无关的。然而，在这里，我们将专门提供在 Ubuntu 16.04.2 上构建的说明。在 Ubuntu 的新安装中，执行以下命令以安装必要的依赖项：

```py
sudo apt-get update && sudo apt-get -y upgrade 
sudo apt-get install python-pip git autoconf automake autopoint libtool pkg-config  
```

除了前面提到的两个库（`pytsk3`和`pyewf`）之外，我们还将使用第三方模块`tabulate`来在控制台打印表格。由于这是最容易安装的模块，让我们首先完成这个任务，执行以下操作：

```py
pip install tabulate==0.7.7
```

要了解更多关于 tabulate 库的信息，请访问[`pypi.python.org/pypi/tabulate`](https://pypi.python.org/pypi/tabulate)。

信不信由你，我们也可以使用`pip`安装`pytsk3`：

```py
pip install pytsk3==20170802
```

要了解更多关于`pytsk3`库的信息，请访问[`github.com/py4n6/pytsk.`](https://github.com/py4n6/pytsk)

最后，对于`pyewf`，我们必须采取稍微绕弯的方法，从其 GitHub 存储库中安装，[`github.com/libyal/libewf/releases`](https://github.com/libyal/libewf/releases)。这些配方是使用`libewf-experimental-20170605`版本编写的，我们建议您在这里安装该版本。一旦包被下载并解压，打开提取目录中的命令提示符，并执行以下操作：

```py
./synclibs.sh 
./autogen.sh 
sudo python setup.py build 
sudo python setup.py install 
```

要了解更多关于`pyewf`库的信息，请访问：[`github.com/libyal/libewf.`](https://github.com/libyal/libewf)

毋庸置疑，对于这个脚本，您需要一个`raw`或`E01`证据文件来运行这些配方。对于第一个脚本，我们建议使用逻辑图像，比如来自[`dftt.sourceforge.net/test2/index.html`](http://dftt.sourceforge.net/test2/index.html)的`fat-img-kw.dd`。原因是这个第一个脚本将缺少一些处理物理磁盘图像及其分区所需的必要逻辑。我们将在*收集获取和媒体信息*配方中介绍这个功能。

# 操作步骤...

我们采用以下方法来打开法证证据容器：

1.  确定证据容器是`raw`图像还是`E01`容器。

1.  使用`pytsk3`访问图像。

1.  在控制台上打印根级文件夹和文件的表格。

# 它是如何工作的...

我们导入了一些库来帮助解析参数、处理证据容器和文件系统，并创建表格式的控制台数据。

```py
from __future__ import print_function
import argparse
import os
import pytsk3
import pyewf
import sys
from tabulate import tabulate
```

这个配方的命令行处理程序接受两个位置参数，`EVIDENCE_FILE`和`TYPE`，它们代表证据文件的路径和证据文件的类型（即`raw`或`ewf`）。请注意，对于分段的`E01`文件，您只需要提供第一个`E01`的路径（假设其他分段在同一个目录中）。在对证据文件进行一些输入验证后，我们将提供两个输入给`main()`函数，并开始执行脚本。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE",
                        help="Type of evidence: raw (dd) or EWF (E01)",
                        choices=("raw", "ewf"))
    parser.add_argument("-o", "--offset",
                        help="Partition byte offset", type=int)
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.offset)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

在`main()`函数中，我们首先检查我们正在处理的证据文件的类型。如果是`E01`容器，我们需要首先使用`pyewf`创建一个句柄，然后才能使用`pytsk3`访问其内容。对于`raw`图像，我们可以直接使用`pytsk3`访问其内容，而无需先执行这个中间步骤。

在这里使用`pyewf.glob()`方法来组合`E01`容器的所有段，如果有的话，并将段的名称存储在一个列表中。一旦我们有了文件名列表，我们就可以创建`E01`句柄对象。然后我们可以使用这个对象来打开`filenames`。

```py
def main(image, img_type, offset):
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Invalid EWF format:\n {}".format(e))
            sys.exit(2)
        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
```

接下来，我们必须将`ewf_handle`传递给`EWFImgInfo`类，该类将创建`pytsk3`对象。这里的 else 语句是为了`raw`图像，可以使用`pytsk3.Img_Info`函数来实现相同的任务。现在让我们看看`EWFImgInfo`类，了解 EWF 文件是如何稍有不同地处理的。

```py
        # Open PYTSK3 handle on EWF Image
        img_info = EWFImgInfo(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)
```

这个脚本组件的代码来自`pyewf`的 Python 开发页面的*将 pyewf 与 pytsk3 结合使用*部分。

了解更多关于`pyewf`函数的信息，请访问[`github.com/libyal/libewf/wiki/Development`](https://github.com/libyal/libewf/wiki/Development)。

这个`EWFImgInfo`类继承自`pytsk3.Img_Info`基类，属于`TSK_IMG_TYPE_EXTERNAL`类型。重要的是要注意，接下来定义的三个函数，`close()`、`read()`和`get_size()`，都是`pytsk3`要求的，以便与证据容器进行适当的交互。有了这个简单的类，我们现在可以使用`pytsk3`来处理任何提供的`E01`文件。

```py
class EWFImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        self._ewf_handle = ewf_handle
        super(EWFImgInfo, self).__init__(url="",
                                         type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        self._ewf_handle.close()

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._ewf_handle.get_media_size()
```

回到`main()`函数，我们已经成功地为`raw`或`E01`镜像创建了`pytsk3`处理程序。现在我们可以开始访问文件系统。如前所述，此脚本旨在处理逻辑图像而不是物理图像。我们将在下一个步骤中引入对物理图像的支持。访问文件系统非常简单；我们通过在`pytsk3`处理程序上调用`FS_Info()`函数来实现。

```py
    # Get Filesystem Handle
    try:
        fs = pytsk3.FS_Info(img_info, offset)
    except IOError:
        _, e, _ = sys.exc_info()
        print("[-] Unable to open FS:\n {}".format(e))
        exit()
```

有了对文件系统的访问权限，我们可以遍历根目录中的文件夹和文件。首先，我们使用文件系统上的`open_dir()`方法，并指定根目录`**/**`作为输入来访问根目录。接下来，我们创建一个嵌套的列表结构，用于保存表格内容，稍后我们将使用`tabulate`将其打印到控制台。这个列表的第一个元素是表格的标题。

之后，我们将开始遍历图像，就像处理任何 Python 可迭代对象一样。每个对象都有各种属性和函数，我们从这里开始使用它们。首先，我们使用`f.info.name.name`属性提取对象的名称。然后，我们使用`f.info.meta.type`属性检查我们处理的是目录还是文件。如果这等于内置的`TSK_FS_META_TYPE_DIR`对象，则将`f_type`变量设置为`DIR`；否则，设置为`FILE`。

最后，我们使用更多的属性来提取目录或文件的大小，并创建和修改时间戳。请注意，对象时间戳存储在`Unix`时间中，如果您想以人类可读的格式显示它们，必须进行转换。提取了这些属性后，我们将数据附加到`table`列表中，并继续处理下一个对象。一旦我们完成了对根文件夹中所有对象的处理，我们就使用`tabulate`将数据打印到控制台。通过向`tabulate()`方法提供列表并将`headers`关键字参数设置为`firstrow`，以指示应使用列表中的第一个元素作为表头，可以在一行中完成此操作。

```py
    root_dir = fs.open_dir(path="/")
    table = [["Name", "Type", "Size", "Create Date", "Modify Date"]]
    for f in root_dir:
        name = f.info.name.name
        if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            f_type = "DIR"
        else:
            f_type = "FILE"
        size = f.info.meta.size
        create = f.info.meta.crtime
        modify = f.info.meta.mtime
        table.append([name, f_type, size, create, modify])
    print(tabulate(table, headers="firstrow"))
```

当我们运行脚本时，我们可以了解到在证据容器的根目录中看到的文件和文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00090.jpeg)

# 收集获取和媒体信息

食谱难度：中等

Python 版本：2.7

操作系统：Linux

在这个食谱中，我们学习如何使用`tabulate`查看和打印分区表。此外，对于`E01`容器，我们将打印存储在证据文件中的`E01`获取和容器元数据。通常，我们将使用给定机器的物理磁盘镜像。在接下来的任何过程中，我们都需要遍历不同的分区（或用户选择的分区）来获取文件系统及其文件的处理。因此，这个食谱对于我们建立对 Sleuth Kit 及其众多功能的理解至关重要。

# 入门

有关`pytsk3`、`pyewf`和`tabulate`的构建环境和设置详细信息，请参阅*打开获取*食谱中的*入门*部分。此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何操作...

该食谱遵循以下基本步骤：

1.  确定证据容器是`raw`镜像还是`E01`容器。

1.  使用`pytsk3`访问镜像。

1.  如果适用，将`E01`元数据打印到控制台。

1.  将分区表数据打印到控制台。

# 它是如何工作的...

我们导入了许多库来帮助解析参数、处理证据容器和文件系统，并创建表格式的控制台数据。

```py
from __future__ import print_function
import argparse
import os
import pytsk3
import pyewf
import sys
from tabulate import tabulate
```

这个配方的命令行处理程序接受两个位置参数，`EVIDENCE_FILE`和`TYPE`，它们代表证据文件的路径和证据文件的类型。此外，如果用户在处理证据文件时遇到困难，他们可以使用可选的`p`开关手动提供分区。这个开关在大多数情况下不应该是必要的，但作为一种预防措施已经添加。在执行输入验证检查后，我们将这三个参数传递给`main（）`函数。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("-p", help="Partition Type",
                        choices=("DOS", "GPT", "MAC", "SUN"))
    args = parser.parse_args()

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.p)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

`main（）`函数在很大程度上与之前的配方相似，至少最初是这样。我们必须首先创建`pyewf`句柄，然后使用`EWFImgInfo`类来创建，如前面在`pytsk3`句柄中所示。如果您想了解更多关于`EWFImgInfo`类的信息，请参阅*打开获取*配方。但是，请注意，我们添加了一个额外的行调用`e01_metadata（）`函数来将`E01`元数据打印到控制台。现在让我们来探索一下这个函数。

```py
def main(image, img_type, part_type):
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError:
            print("[-] Invalid EWF format:\n {}".format(e))
            sys.exit(2)

        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)
        e01_metadata(ewf_handle)

        # Open PYTSK3 handle on EWF Image
        img_info = EWFImgInfo(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)
```

`e01_metadata（）`函数主要依赖于`get_header_values（）`和`get_hash_values（）`方法来获取`E01`特定的元数据。`get_header_values（）`方法返回各种类型的获取和媒体元数据的`键值`对字典。我们使用循环来遍历这个字典，并将`键值`对打印到控制台。

同样，我们使用`hashes`字典的循环将图像的存储获取哈希打印到控制台。最后，我们调用一个属性和一些函数来打印获取大小的元数据。

```py
def e01_metadata(e01_image):
    print("\nEWF Acquisition Metadata")
    print("-" * 20)
    headers = e01_image.get_header_values()
    hashes = e01_image.get_hash_values()
    for k in headers:
        print("{}: {}".format(k, headers[k]))
    for h in hashes:
        print("Acquisition {}: {}".format(h, hashes[h]))
    print("Bytes per Sector: {}".format(e01_image.bytes_per_sector))
    print("Number of Sectors: {}".format(
        e01_image.get_number_of_sectors()))
    print("Total Size: {}".format(e01_image.get_media_size()))
```

有了这些，我们现在可以回到`main（）`函数。回想一下，在本章的第一个配方中，我们没有为物理获取创建支持（这完全是有意的）。然而，现在，我们使用`Volume_Info（）`函数添加了对此的支持。虽然`pytsk3`一开始可能令人生畏，但要欣赏到目前为止我们介绍的主要函数中使用的命名约定的一致性：`Img_Info`、`FS_Info`和`Volume_Info`。这三个函数对于访问证据容器的内容至关重要。在这个配方中，我们不会使用`FS_Info（）`函数，因为这里的目的只是打印分区表。

我们尝试在`try-except`块中访问卷信息。首先，我们检查用户是否提供了`p`开关，如果是，则将该分区类型的属性分配给一个变量。然后，我们将它与`pytsk3`句柄一起提供给`Volume_Info`方法。否则，如果没有指定分区，我们调用`Volume_Info`方法，并只提供`pytsk3`句柄对象。如果我们尝试这样做时收到`IOError`，我们将捕获异常作为`e`并将其打印到控制台，然后退出。如果我们能够访问卷信息，我们将其传递给`part_metadata（）`函数，以将分区数据打印到控制台。

```py
    try:
        if part_type is not None:
            attr_id = getattr(pytsk3, "TSK_VS_TYPE_" + part_type)
            volume = pytsk3.Volume_Info(img_info, attr_id)
        else:
            volume = pytsk3.Volume_Info(img_info)
    except IOError:
        _, e, _ = sys.exc_info()
        print("[-] Unable to read partition table:\n {}".format(e))
        sys.exit(3)
    part_metadata(volume)
```

`part_metadata（）`函数在逻辑上相对较轻。我们创建一个嵌套的列表结构，如前面的配方中所见，第一个元素代表最终的表头。接下来，我们遍历卷对象，并将分区地址、类型、偏移量和长度附加到`table`列表中。一旦我们遍历了分区，我们使用`tabulate`使用`firstrow`作为表头将这些数据的表格打印到控制台。

```py
def part_metadata(vol):
    table = [["Index", "Type", "Offset Start (Sectors)",
              "Length (Sectors)"]]
    for part in vol:
        table.append([part.addr, part.desc.decode("utf-8"), part.start,
                      part.len])
    print("\n Partition Metadata")
    print("-" * 20)
    print(tabulate(table, headers="firstrow"))
```

运行此代码时，如果存在，我们可以在控制台中查看有关获取和分区信息的信息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00091.jpeg)

# 遍历文件

配方难度：中等

Python 版本：2.7

操作系统：Linux

在这个配方中，我们学习如何递归遍历文件系统并创建一个活动文件列表。作为法庭鉴定人，我们经常被问到的第一个问题之一是“设备上有什么数据？”。在这里，活动文件列表非常有用。在 Python 中，创建松散文件的文件列表是一个非常简单的任务。然而，这将会稍微复杂一些，因为我们处理的是法庭图像而不是松散文件。这个配方将成为未来脚本的基石，因为它将允许我们递归访问和处理图像中的每个文件。正如您可能已经注意到的，本章的配方是相互建立的，因为我们开发的每个函数都需要进一步探索图像。类似地，这个配方将成为未来配方中的一个重要部分，用于迭代目录并处理文件。

# 入门

有关`pytsk3`和`pyewf`的构建环境和设置详细信息，请参考*开始*部分中的*打开获取*配方。此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何做...

我们在这个配方中执行以下步骤：

1.  确定证据容器是`raw`图像还是`E01`容器。

1.  使用`pytsk3`访问法庭图像。

1.  递归遍历每个分区中的所有目录。

1.  将文件元数据存储在列表中。

1.  将`active`文件列表写入 CSV。

# 工作原理...

我们导入了许多库来帮助解析参数、解析日期、创建 CSV 电子表格，以及处理证据容器和文件系统。

```py
from __future__ import print_function
import argparse
import csv
from datetime import datetime
import os
import pytsk3
import pyewf
import sys
```

这个配方的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`、`TYPE`和`OUTPUT_CSV`，分别代表证据文件的路径、证据文件的类型和输出 CSV 文件。与上一个配方类似，可以提供可选的`p`开关来指定分区类型。我们使用`os.path.dirname()`方法来提取 CSV 文件的所需输出目录路径，并使用`os.makedirs()`函数，如果不存在，则创建必要的输出目录。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("OUTPUT_CSV", 
                        help="Output CSV with lookup results")
    parser.add_argument("-p", help="Partition Type",
                        choices=("DOS", "GPT", "MAC", "SUN"))
    args = parser.parse_args()

    directory = os.path.dirname(args.OUTPUT_CSV)
    if not os.path.exists(directory) and directory != "":
        os.makedirs(directory)
```

一旦我们通过检查输入证据文件是否存在并且是一个文件来验证了输入证据文件，四个参数将被传递给`main()`函数。如果在输入的初始验证中出现问题，脚本将在退出之前将错误打印到控制台。

```py
    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.OUTPUT_CSV, args.p)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

在`main()`函数中，我们用`None`实例化卷变量，以避免在脚本后面引用它时出错。在控制台打印状态消息后，我们检查证据类型是否为`E01`，以便正确处理它并创建有效的`pyewf`句柄，如在*打开获取*配方中更详细地演示的那样。有关更多详细信息，请参阅该配方。最终结果是为用户提供的证据文件创建`pytsk3`句柄`img_info`。

```py
def main(image, img_type, output, part_type):
    volume = None
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Invalid EWF format:\n {}".format(e))
            sys.exit(2)

        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        # Open PYTSK3 handle on EWF Image
        img_info = EWFImgInfo(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)
```

接下来，我们尝试使用`pytsk3.Volume_Info()`方法访问图像的卷，通过提供图像句柄作为参数。如果提供了分区类型参数，我们将其属性 ID 添加为第二个参数。如果在尝试访问卷时收到`IOError`，我们将捕获异常作为`e`并将其打印到控制台。然而，请注意，当我们收到错误时，我们不会退出脚本。我们将在下一个函数中解释原因。最终，我们将`volume`、`img_info`和`output`变量传递给`open_fs()`方法。

```py
    try:
        if part_type is not None:
            attr_id = getattr(pytsk3, "TSK_VS_TYPE_" + part_type)
            volume = pytsk3.Volume_Info(img_info, attr_id)
        else:
            volume = pytsk3.Volume_Info(img_info)
    except IOError:
        _, e, _ = sys.exc_info()
        print("[-] Unable to read partition table:\n {}".format(e))

    open_fs(volume, img_info, output)
```

`open_fs()`方法尝试以两种方式访问容器的文件系统。如果`volume`变量不是`None`，它会遍历每个分区，并且如果该分区符合某些条件，则尝试打开它。但是，如果`volume`变量是`None`，它将尝试直接在图像句柄`img`上调用`pytsk3.FS_Info()`方法。正如我们所看到的，后一种方法将适用于逻辑图像，并为我们提供文件系统访问权限，而前一种方法适用于物理图像。让我们看看这两种方法之间的区别。

无论使用哪种方法，我们都创建一个`recursed_data`列表来保存我们的活动文件元数据。在第一种情况下，我们有一个物理图像，我们遍历每个分区，并检查它是否大于`2,048`扇区，并且在其描述中不包含`Unallocated`、`Extended`或`Primary Table`这些词。对于符合这些条件的分区，我们尝试使用`FS_Info()`函数访问它们的文件系统，方法是提供`pytsk3 img`对象和分区的偏移量（以字节为单位）。

如果我们能够访问文件系统，我们将使用`open_dir()`方法获取根目录，并将其与分区地址 ID、文件系统对象、两个空列表和一个空字符串一起传递给`recurse_files()`方法。这些空列表和字符串将在对此函数进行递归调用时发挥作用，我们很快就会看到。一旦`recurse_files()`方法返回，我们将活动文件的元数据附加到`recursed_data`列表中。我们对每个分区重复这个过程。

```py
def open_fs(vol, img, output):
    print("[+] Recursing through files..")
    recursed_data = []
    # Open FS and Recurse
    if vol is not None:
        for part in vol:
            if part.len > 2048 and "Unallocated" not in part.desc and \
                    "Extended" not in part.desc and \
                    "Primary Table" not in part.desc:
                try:
                    fs = pytsk3.FS_Info(
                        img, offset=part.start * vol.info.block_size)
                except IOError:
                    _, e, _ = sys.exc_info()
                    print("[-] Unable to open FS:\n {}".format(e))
                root = fs.open_dir(path="/")
                data = recurse_files(part.addr, fs, root, [], [], [""])
                recursed_data.append(data)
```

对于第二种情况，我们有一个逻辑图像，卷是`None`。在这种情况下，我们尝试直接访问文件系统，如果成功，我们将其传递给`recurseFiles()`方法，并将返回的数据附加到我们的`recursed_data`列表中。一旦我们有了活动文件列表，我们将其和用户提供的输出文件路径发送到`csvWriter()`方法。让我们深入了解`recurseFiles()`方法，这是本教程的核心。

```py
    else:
        try:
            fs = pytsk3.FS_Info(img)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Unable to open FS:\n {}".format(e))
        root = fs.open_dir(path="/")
        data = recurse_files(1, fs, root, [], [], [""])
        recursed_data.append(data)
    write_csv(recursed_data, output)
```

`recurse_files()`函数基于*FLS*工具的一个示例（[`github.com/py4n6/pytsk/blob/master/examples/fls.py`](https://github.com/py4n6/pytsk/blob/master/examples/fls.py)）和 David Cowen 的工具 DFIR Wizard（[`github.com/dlcowen/dfirwizard/blob/master/dfirwizard-v9.py`](https://github.com/dlcowen/dfirwizard/blob/master/dfirwizard-v9.py)）。为了启动这个函数，我们将根目录`inode`附加到`dirs`列表中。稍后将使用此列表以避免无休止的循环。接下来，我们开始循环遍历根目录中的每个对象，并检查它是否具有我们期望的某些属性，以及它的名称既不是`"**.**"`也不是`"**..**"`。

```py
def recurse_files(part, fs, root_dir, dirs, data, parent):
    dirs.append(root_dir.info.fs_file.meta.addr)
    for fs_object in root_dir:
        # Skip ".", ".." or directory entries without a name.
        if not hasattr(fs_object, "info") or \
                not hasattr(fs_object.info, "name") or \
                not hasattr(fs_object.info.name, "name") or \
                fs_object.info.name.name in [".", ".."]:
            continue
```

如果对象通过了这个测试，我们将使用`info.name.name`属性提取其名称。接下来，我们使用作为函数输入之一提供的`parent`变量手动为此对象创建文件路径。对于我们来说，没有内置的方法或属性可以自动执行此操作。

然后，我们检查文件是否是目录，并将`f_type`变量设置为适当的类型。如果对象是文件，并且具有扩展名，我们将提取它并将其存储在`file_ext`变量中。如果在尝试提取此数据时遇到`AttributeError`，我们将继续到下一个对象。

```py
        try:
            file_name = fs_object.info.name.name
            file_path = "{}/{}".format(
                "/".join(parent), fs_object.info.name.name)
            try:
                if fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    f_type = "DIR"
                    file_ext = ""
                else:
                    f_type = "FILE"
                    if "." in file_name:
                        file_ext = file_name.rsplit(".")[-1].lower()
                    else:
                        file_ext = ""
            except AttributeError:
                continue
```

与本章第一个示例类似，我们为对象大小和时间戳创建变量。但是，请注意，我们将日期传递给`convert_time()`方法。此函数用于将`Unix`时间戳转换为人类可读的格式。提取了这些属性后，我们使用分区地址 ID 将它们附加到数据列表中，以确保我们跟踪对象来自哪个分区。

```py
            size = fs_object.info.meta.size
            create = convert_time(fs_object.info.meta.crtime)
            change = convert_time(fs_object.info.meta.ctime)
            modify = convert_time(fs_object.info.meta.mtime)
            data.append(["PARTITION {}".format(part), file_name, file_ext,
                         f_type, create, change, modify, size, file_path])
```

如果对象是一个目录，我们需要递归遍历它，以访问其所有子目录和文件。为此，我们将目录名称附加到`parent`列表中。然后，我们使用`as_directory()`方法创建一个目录对象。我们在这里使用`inode`，这对于所有目的来说都是一个唯一的数字，并检查`inode`是否已经在`dirs`列表中。如果是这样，那么我们将不处理这个目录，因为它已经被处理过了。

如果需要处理目录，我们在新的`sub_directory`上调用`recurse_files()`方法，并传递当前的`dirs`、`data`和`parent`变量。一旦我们处理了给定的目录，我们就从`parent`列表中弹出该目录。如果不这样做，将导致错误的文件路径细节，因为除非删除，否则所有以前的目录将继续在路径中被引用。

这个函数的大部分内容都在一个大的`try-except`块中。我们传递在这个过程中生成的任何`IOError`异常。一旦我们遍历了所有的子目录，我们将数据列表返回给`open_fs()`函数。

```py
            if f_type == "DIR":
                parent.append(fs_object.info.name.name)
                sub_directory = fs_object.as_directory()
                inode = fs_object.info.meta.addr

                # This ensures that we don't recurse into a directory
                # above the current level and thus avoid circular loops.
                if inode not in dirs:
                    recurse_files(part, fs, sub_directory, dirs, data,
                                  parent)
                parent.pop(-1)

        except IOError:
            pass
    dirs.pop(-1)
    return data
```

让我们简要地看一下`convert_time()`函数。我们以前见过这种类型的函数：如果`Unix`时间戳不是`0`，我们使用`datetime.utcfromtimestamp()`方法将时间戳转换为人类可读的格式。

```py
def convert_time(ts):
    if str(ts) == "0":
        return ""
    return datetime.utcfromtimestamp(ts)
```

有了手头的活动文件列表数据，我们现在准备使用`write_csv()`方法将其写入 CSV 文件。如果我们找到了数据（即列表不为空），我们打开输出 CSV 文件，写入标题，并循环遍历`data`变量中的每个列表。我们使用`csvwriterows()`方法将每个嵌套列表结构写入 CSV 文件。

```py
def write_csv(data, output):
    if data == []:
        print("[-] No output results to write")
        sys.exit(3)

    print("[+] Writing output to {}".format(output))
    with open(output, "wb") as csvfile:
        csv_writer = csv.writer(csvfile)
        headers = ["Partition", "File", "File Ext", "File Type",
                   "Create Date", "Modify Date", "Change Date", "Size",
                   "File Path"]
        csv_writer.writerow(headers)
        for result_list in data:
            csv_writer.writerows(result_list)
```

以下截图演示了这个示例从取证图像中提取的数据类型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00092.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议，如下所示：

+   使用`tqdm`或其他库创建进度条，以通知用户当前执行的进度

+   了解可以使用`pytsk3`从文件系统对象中提取的附加元数据值，并将它们添加到输出 CSV 文件中

# 处理容器内的文件

食谱难度：中等

Python 版本：2.7

操作系统：Linux

现在我们可以遍历文件系统，让我们看看如何创建文件对象，就像我们习惯做的那样。在这个示例中，我们创建一个简单的分流脚本，提取与指定文件扩展名匹配的文件，并将它们复制到输出目录，同时保留它们的原始文件路径。

# 入门

有关构建环境和`pytsk3`和`pyewf`的设置详细信息，请参考*入门*部分中的*打开收购*食谱。此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何做...

在这个示例中，我们将执行以下步骤：

1.  确定证据容器是`raw`镜像还是`E01`容器。

1.  使用`pytsk3`访问图像。

1.  递归遍历每个分区中的所有目录。

1.  检查文件扩展名是否与提供的扩展名匹配。

1.  将具有保留文件夹结构的响应文件写入输出目录。

# 它是如何工作的...

我们导入了许多库来帮助解析参数、创建 CSV 电子表格，并处理证据容器和文件系统。

```py
from __future__ import print_function
import argparse
import csv
import os
import pytsk3
import pyewf
import sys
```

这个示例的命令行处理程序接受四个位置参数：`EVIDENCE_FILE`、`TYPE`、`EXT`和`OUTPUT_DIR`。它们分别是证据文件本身、证据文件类型、要提取的逗号分隔的扩展名列表，以及所需的输出目录。我们还有可选的`p`开关，用于手动指定分区类型。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("EXT",
                        help="Comma-delimited file extensions to extract")
    parser.add_argument("OUTPUT_DIR", help="Output Directory")
    parser.add_argument("-p", help="Partition Type",
                        choices=("DOS", "GPT", "MAC", "SUN"))
    args = parser.parse_args()
```

在调用`main()`函数之前，我们创建任何必要的输出目录，并执行我们的标准输入验证步骤。一旦我们验证了输入，我们将提供的参数传递给`main()`函数。

```py
    if not os.path.exists(args.OUTPUT_DIR):
        os.makedirs(args.OUTPUT_DIR)

    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE):
        main(args.EVIDENCE_FILE, args.TYPE, args.EXT, args.OUTPUT_DIR,
             args.p)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

`main()`函数、`EWFImgInfo`类和`open_fs()`函数在之前的配方中已经涵盖过。请记住，本章采用更迭代的方法来构建我们的配方。有关每个函数和`EWFImgInfo`类的更详细描述，请参考之前的配方。让我们简要地再次展示这两个函数，以避免逻辑上的跳跃。

在`main()`函数中，我们检查证据文件是`raw`文件还是`E01`文件。然后，我们执行必要的步骤，最终在证据文件上创建一个`pytsk3`句柄。有了这个句柄，我们尝试访问卷，使用手动提供的分区类型（如果提供）。如果我们能够打开卷，我们将`pytsk3`句柄和卷传递给`open_fs()`方法。

```py
def main(image, img_type, ext, output, part_type):
    volume = None
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Invalid EWF format:\n {}".format(e))
            sys.exit(2)

        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        # Open PYTSK3 handle on EWF Image
        img_info = EWFImgInfo(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)

    try:
        if part_type is not None:
            attr_id = getattr(pytsk3, "TSK_VS_TYPE_" + part_type)
            volume = pytsk3.Volume_Info(img_info, attr_id)
        else:
            volume = pytsk3.Volume_Info(img_info)
    except IOError:
        _, e, _ = sys.exc_info()
        print("[-] Unable to read partition table:\n {}".format(e))

    open_fs(volume, img_info, ext, output)
```

在`open_fs()`函数中，我们使用逻辑来支持对文件系统进行逻辑和物理获取。对于逻辑获取，我们可以简单地尝试访问`pytsk3`句柄上文件系统的根。另一方面，对于物理获取，我们必须迭代每个分区，并尝试访问那些符合特定条件的文件系统。一旦我们访问到文件系统，我们调用`recurse_files()`方法来迭代文件系统中的所有文件。

```py
def open_fs(vol, img, ext, output):
    # Open FS and Recurse
    print("[+] Recursing through files and writing file extension matches "
          "to output directory")
    if vol is not None:
        for part in vol:
            if part.len > 2048 and "Unallocated" not in part.desc \
                    and "Extended" not in part.desc \
                    and "Primary Table" not in part.desc:
                try:
                    fs = pytsk3.FS_Info(
                        img, offset=part.start * vol.info.block_size)
                except IOError:
                    _, e, _ = sys.exc_info()
                    print("[-] Unable to open FS:\n {}".format(e))
                root = fs.open_dir(path="/")
                recurse_files(part.addr, fs, root, [], [""], ext, output)
    else:
        try:
            fs = pytsk3.FS_Info(img)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Unable to open FS:\n {}".format(e))
        root = fs.open_dir(path="/")
        recurse_files(1, fs, root, [], [""], ext, output)
```

不要浏览了！这个配方的新逻辑包含在`recurse_files()`方法中。这有点像眨眼就错过的配方。我们已经在之前的配方中做了大部分工作，现在我们基本上可以像处理任何其他 Python 文件一样处理这些文件。让我们看看这是如何工作的。

诚然，这个函数的第一部分仍然与以前相同，只有一个例外。在函数的第一行，我们使用列表推导来分割用户提供的每个逗号分隔的扩展名，并删除任何空格并将字符串规范化为小写。当我们迭代每个对象时，我们检查对象是目录还是文件。如果是文件，我们将文件的扩展名分离并规范化为小写，并将其存储在`file_ext`变量中。

```py
def recurse_files(part, fs, root_dir, dirs, parent, ext, output):
    extensions = [x.strip().lower() for x in ext.split(',')]
    dirs.append(root_dir.info.fs_file.meta.addr)
    for fs_object in root_dir:
        # Skip ".", ".." or directory entries without a name.
        if not hasattr(fs_object, "info") or \
                not hasattr(fs_object.info, "name") or \
                not hasattr(fs_object.info.name, "name") or \
                fs_object.info.name.name in [".", ".."]:
            continue
        try:
            file_name = fs_object.info.name.name
            file_path = "{}/{}".format("/".join(parent),
                                       fs_object.info.name.name)
            try:
                if fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    f_type = "DIR"
                    file_ext = ""
                else:
                    f_type = "FILE"
                    if "." in file_name:
                        file_ext = file_name.rsplit(".")[-1].lower()
                    else:
                        file_ext = ""
            except AttributeError:
                continue
```

接下来，我们检查提取的文件扩展名是否在用户提供的列表中。如果是，我们将文件对象本身及其名称、扩展名、路径和所需的输出目录传递给`file_writer()`方法进行输出。请注意，在这个操作中，我们有逻辑，即在前面的配方中讨论过的逻辑，来递归处理任何子目录，以识别更多符合扩展名条件的潜在文件。到目前为止，一切顺利；现在让我们来看看这最后一个函数。

```py
            if file_ext.strip() in extensions:
                print("{}".format(file_path))
                file_writer(fs_object, file_name, file_ext, file_path,
                            output)
            if f_type == "DIR":
                parent.append(fs_object.info.name.name)
                sub_directory = fs_object.as_directory()
                inode = fs_object.info.meta.addr
                if inode not in dirs:
                    recurse_files(part, fs, sub_directory, dirs,
                                  parent, ext, output)
                    parent.pop(-1)
        except IOError:
            pass
    dirs.pop(-1)
```

`file_writer()`方法依赖于文件对象的`read_random()`方法来访问文件内容。然而，在这之前，我们首先设置文件的输出路径，将用户提供的输出与扩展名和文件的路径结合起来。然后，如果这些目录不存在，我们就创建这些目录。接下来，我们以`"w"`模式打开输出文件，现在准备好将文件的内容写入输出文件。在这里使用的`read_random()`函数接受两个输入：文件中要开始读取的字节偏移量和要读取的字节数。在这种情况下，由于我们想要读取整个文件，我们使用整数`0`作为第一个参数，文件的大小作为第二个参数。

我们直接将其提供给`write()`方法，尽管请注意，如果我们要对这个文件进行任何处理，我们可以将其读入变量中，并从那里处理文件。另外，请注意，对于包含大文件的证据容器，将整个文件读入内存的这个过程可能并不理想。在这种情况下，您可能希望分块读取和写入这个文件，而不是一次性全部读取和写入。

```py
def file_writer(fs_object, name, ext, path, output):
    output_dir = os.path.join(output, ext,
                              os.path.dirname(path.lstrip("//")))
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(os.path.join(output_dir, name), "w") as outfile:
        outfile.write(fs_object.read_random(0, fs_object.info.meta.size))
```

当我们运行这个脚本时，我们会看到基于提供的扩展名的响应文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00093.jpeg)

此外，我们可以在以下截图中查看这些文件的定义结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00094.jpeg)

# 搜索哈希

配方难度：困难

Python 版本：2.7

操作系统：Linux

在这个配方中，我们创建了另一个分类脚本，这次专注于识别与提供的哈希值匹配的文件。该脚本接受一个文本文件，其中包含以换行符分隔的`MD5`、`SHA-1`或`SHA-256`哈希，并在证据容器中搜索这些哈希。通过这个配方，我们将能够快速处理证据文件，找到感兴趣的文件，并通过将文件路径打印到控制台来提醒用户。

# 入门

参考*打开获取*配方中的*入门*部分，了解有关`build`环境和`pytsk3`和`pyewf`的设置详细信息。此脚本中使用的所有其他库都包含在 Python 的标准库中。

# 如何做...

我们使用以下方法来实现我们的目标：

1.  确定证据容器是`raw`图像还是`E01`容器。

1.  使用`pytsk3`访问图像。

1.  递归遍历每个分区中的所有目录。

1.  使用适当的哈希算法发送每个文件进行哈希处理。

1.  检查哈希是否与提供的哈希之一匹配，如果是，则打印到控制台。

# 工作原理...

我们导入了许多库来帮助解析参数、创建 CSV 电子表格、对文件进行哈希处理、处理证据容器和文件系统，并创建进度条。

```py
from __future__ import print_function
import argparse
import csv
import hashlib
import os
import pytsk3
import pyewf
import sys
from tqdm import tqdm
```

该配方的命令行处理程序接受三个位置参数，`EVIDENCE_FILE`，`TYPE`和`HASH_LIST`，分别表示证据文件，证据文件类型和要搜索的换行分隔哈希列表。与往常一样，用户也可以在必要时使用`p`开关手动提供分区类型。

```py
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__description__,
        epilog="Developed by {} on {}".format(
            ", ".join(__authors__), __date__)
    )
    parser.add_argument("EVIDENCE_FILE", help="Evidence file path")
    parser.add_argument("TYPE", help="Type of Evidence",
                        choices=("raw", "ewf"))
    parser.add_argument("HASH_LIST",
                        help="Filepath to Newline-delimited list of "
                             "hashes (either MD5, SHA1, or SHA-256)")
    parser.add_argument("-p", help="Partition Type",
                        choices=("DOS", "GPT", "MAC", "SUN"))
    parser.add_argument("-t", type=int,
                        help="Total number of files, for the progress bar")
    args = parser.parse_args()
```

在解析输入后，我们对证据文件和哈希列表进行了典型的输入验证检查。如果通过了这些检查，我们调用`main()`函数并提供用户提供的输入。

```py
    if os.path.exists(args.EVIDENCE_FILE) and \
            os.path.isfile(args.EVIDENCE_FILE) and \
            os.path.exists(args.HASH_LIST) and \
            os.path.isfile(args.HASH_LIST):
        main(args.EVIDENCE_FILE, args.TYPE, args.HASH_LIST, args.p, args.t)
    else:
        print("[-] Supplied input file {} does not exist or is not a "
              "file".format(args.EVIDENCE_FILE))
        sys.exit(1)
```

与以前的配方一样，`main()`函数、`EWFImgInfo`类和`open_fs()`函数几乎与以前的配方相同。有关这些函数的更详细解释，请参考以前的配方。`main()`函数的一个新添加是第一行，我们在其中调用`read_hashes()`方法。该方法读取输入的哈希列表并返回哈希列表和哈希类型（即`MD5`、`SHA-1`或`SHA-256`）。

除此之外，`main()`函数的执行方式与我们习惯看到的方式相同。首先，它确定正在处理的证据文件的类型，以便在图像上创建一个`pytsk3`句柄。然后，它使用该句柄并尝试访问图像卷。完成此过程后，变量被发送到`open_fs()`函数进行进一步处理。

```py
def main(image, img_type, hashes, part_type, pbar_total=0):
    hash_list, hash_type = read_hashes(hashes)
    volume = None
    print("[+] Opening {}".format(image))
    if img_type == "ewf":
        try:
            filenames = pyewf.glob(image)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Invalid EWF format:\n {}".format(e))
            sys.exit(2)

        ewf_handle = pyewf.handle()
        ewf_handle.open(filenames)

        # Open PYTSK3 handle on EWF Image
        img_info = EWFImgInfo(ewf_handle)
    else:
        img_info = pytsk3.Img_Info(image)

    try:
        if part_type is not None:
            attr_id = getattr(pytsk3, "TSK_VS_TYPE_" + part_type)
            volume = pytsk3.Volume_Info(img_info, attr_id)
        else:
            volume = pytsk3.Volume_Info(img_info)
    except IOError:
        _, e, _ = sys.exc_info()
        print("[-] Unable to read partition table:\n {}".format(e))

    open_fs(volume, img_info, hash_list, hash_type, pbar_total)
```

让我们快速看一下新函数`read_hashes()`方法。首先，我们将`hash_list`和`hash_type`变量实例化为空列表和`None`对象。接下来，我们打开并遍历输入的哈希列表，并将每个哈希添加到我们的列表中。在这样做时，如果`hash_type`变量仍然是`None`，我们检查行的长度作为识别应该使用的哈希算法类型的手段。

在此过程结束时，如果`hash_type`变量仍然是`None`，则哈希列表必须由我们不支持的哈希组成，因此在将错误打印到控制台后退出脚本。

```py
def read_hashes(hashes):
    hash_list = []
    hash_type = None
    with open(hashes) as infile:
        for line in infile:
            if hash_type is None:
                if len(line.strip()) == 32:
                    hash_type = "md5"
                elif len(line.strip()) == 40:
                    hash_type == "sha1"
                elif len(line.strip()) == 64:
                    hash_type == "sha256"
            hash_list.append(line.strip().lower())
    if hash_type is None:
        print("[-] No valid hashes identified in {}".format(hashes))
        sys.exit(3)

    return hash_list, hash_type
```

`open_fs()`方法函数与以前的配方相同。它尝试使用两种不同的方法来访问物理和逻辑文件系统。一旦成功，它将这些文件系统传递给`recurse_files()`方法。与以前的配方一样，这个函数中发生了奇迹。我们还使用`tqdm`来提供进度条，向用户提供反馈，因为在图像中对所有文件进行哈希可能需要一段时间。

```py
def open_fs(vol, img, hashes, hash_type, pbar_total=0):
    # Open FS and Recurse
    print("[+] Recursing through and hashing files")
    pbar = tqdm(desc="Hashing", unit=" files",
                unit_scale=True, total=pbar_total)
    if vol is not None:
        for part in vol:
            if part.len > 2048 and "Unallocated" not in part.desc and \
                    "Extended" not in part.desc and \
                    "Primary Table" not in part.desc:
                try:
                    fs = pytsk3.FS_Info(
                        img, offset=part.start * vol.info.block_size)
                except IOError:
                    _, e, _ = sys.exc_info()
                    print("[-] Unable to open FS:\n {}".format(e))
                root = fs.open_dir(path="/")
                recurse_files(part.addr, fs, root, [], [""], hashes,
                              hash_type, pbar)
    else:
        try:
            fs = pytsk3.FS_Info(img)
        except IOError:
            _, e, _ = sys.exc_info()
            print("[-] Unable to open FS:\n {}".format(e))
        root = fs.open_dir(path="/")
        recurse_files(1, fs, root, [], [""], hashes, hash_type, pbar)
    pbar.close()
```

在`recurse_files()`方法中，我们遍历所有子目录并对每个文件进行哈希处理。我们跳过`。`和`..`目录条目，并检查`fs_object`是否具有正确的属性。如果是，我们构建文件路径以在输出中使用。

```py
def recurse_files(part, fs, root_dir, dirs, parent, hashes,
                  hash_type, pbar):
    dirs.append(root_dir.info.fs_file.meta.addr)
    for fs_object in root_dir:
        # Skip ".", ".." or directory entries without a name.
        if not hasattr(fs_object, "info") or \
                not hasattr(fs_object.info, "name") or \
                not hasattr(fs_object.info.name, "name") or \
                fs_object.info.name.name in [".", ".."]:
            continue
        try:
            file_path = "{}/{}".format("/".join(parent),
                                       fs_object.info.name.name)
```

在执行每次迭代时，我们确定哪些对象是文件，哪些是目录。对于发现的每个文件，我们将其发送到`hash_file()`方法，以及其路径，哈希列表和哈希算法。`recurse_files()`函数逻辑的其余部分专门设计用于处理目录，并对任何子目录进行递归调用，以确保整个树都被遍历并且不会错过文件。

```py
            if getattr(fs_object.info.meta, "type", None) == \
                    pytsk3.TSK_FS_META_TYPE_DIR:
                parent.append(fs_object.info.name.name)
                sub_directory = fs_object.as_directory()
                inode = fs_object.info.meta.addr

                # This ensures that we don't recurse into a directory
                # above the current level and thus avoid circular loops.
                if inode not in dirs:
                    recurse_files(part, fs, sub_directory, dirs,
                                  parent, hashes, hash_type, pbar)
                    parent.pop(-1)
            else:
                hash_file(fs_object, file_path, hashes, hash_type, pbar)

        except IOError:
            pass
    dirs.pop(-1)
```

`hash_file()`方法首先检查要创建的哈希算法实例的类型，根据`hash_type`变量。确定了这一点，并更新了文件大小到进度条，我们使用`read_random()`方法将文件的数据读入哈希对象。同样，我们通过从第一个字节开始读取并读取整个文件的大小来读取整个文件的内容。我们使用哈希对象上的`hexdigest()`函数生成文件的哈希，然后检查该哈希是否在我们提供的哈希列表中。如果是，我们通过打印文件路径来提醒用户，使用`pbar.write()`来防止进度条显示问题，并将名称打印到控制台。

```py
def hash_file(fs_object, path, hashes, hash_type, pbar):
    if hash_type == "md5":
        hash_obj = hashlib.md5()
    elif hash_type == "sha1":
        hash_obj = hashlib.sha1()
    elif hash_type == "sha256":
        hash_obj = hashlib.sha256()
    f_size = getattr(fs_object.info.meta, "size", 0)
    pbar.set_postfix(File_Size="{:.2f}MB".format(f_size / 1024.0 / 1024))
    hash_obj.update(fs_object.read_random(0, f_size))
    hash_digest = hash_obj.hexdigest()
    pbar.update()

    if hash_digest in hashes:
        pbar.write("[*] MATCH: {}\n{}".format(path, hash_digest))
```

通过运行脚本，我们可以看到一个漂亮的进度条，显示哈希状态和与提供的哈希列表匹配的文件列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-dg-frns-cb/img/00095.jpeg)

# 还有更多...

这个脚本可以进一步改进。我们提供了一个或多个建议，如下所示：

+   而不是打印匹配项，创建一个包含匹配文件的元数据的 CSV 文件以供审查。

+   添加一个可选开关，将匹配的文件转储到输出目录（保留文件夹路径）
