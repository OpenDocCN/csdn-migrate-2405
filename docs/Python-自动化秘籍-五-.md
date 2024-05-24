# Python 自动化秘籍（五）

> 原文：[`zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245`](https://zh.annas-archive.org/md5/de38d8b70825b858336fa5194110e245)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：为什么不自动化您的营销活动呢？

在本章中，我们将介绍与营销活动相关的以下配方：

+   检测机会

+   创建个性化优惠券代码

+   通过用户的首选渠道向客户发送通知

+   准备销售信息

+   生成销售报告

# 介绍

在本章中，我们将创建一个完整的营销活动，逐步进行每个自动步骤。我们将在一个项目中利用本书中的所有概念和配方，这将需要不同的步骤。

让我们举个例子。对于我们的项目，我们的公司希望设置一个营销活动来提高参与度和销售额。这是一个非常值得赞扬的努力。为此，我们可以将行动分为几个步骤：

1.  我们希望检测启动活动的最佳时机，因此我们将从不同来源收到关键词的通知，这将帮助我们做出明智的决定

1.  该活动将包括生成个人代码以发送给潜在客户

1.  这些代码的部分将直接通过用户的首选渠道发送给他们，即短信或电子邮件

1.  为了监控活动的结果，将编制销售信息并生成销售报告

本章将逐步介绍这些步骤，并提出基于本书介绍的模块和技术的综合解决方案。

尽管这些示例是根据现实生活中的需求创建的，但请注意，您的特定环境总会让您感到意外。不要害怕尝试、调整和改进您的系统，随着对系统的了解越来越多，迭代是创建出色系统的方法。

让我们开始吧！

# 检测机会

在这个配方中，我们提出了一个分为几个步骤的营销活动：

1.  检测启动活动的最佳时机

1.  生成个人代码以发送给潜在客户

1.  通过用户的首选渠道直接发送代码，即短信或电子邮件

1.  整理活动的结果，并生成带有结果分析的销售报告

这个配方展示了活动的第一步。

我们的第一阶段是检测启动活动的最佳时间。为此，我们将监视一系列新闻网站，搜索包含我们定义关键词之一的新闻。任何与这些关键词匹配的文章都将被添加到一份报告中，并通过电子邮件发送。

# 做好准备

在这个配方中，我们将使用本书中之前介绍的几个外部模块，`delorean`、`requests`和`BeautifulSoup`。如果尚未添加到我们的虚拟环境中，我们需要将它们添加进去：

```py
$ echo "delorean==1.0.0" >> requirements.txt
$ echo "requests==2.18.3" >> requirements.txt
$ echo "beautifulsoup4==4.6.0" >> requirements.txt
$ echo "feedparser==5.2.1" >> requirements.txt
$ echo "jinja2==2.10" >> requirements.txt
$ echo "mistune==0.8.3" >> requirements.txt
$ pip install -r requirements.txt
```

您需要列出一些 RSS 源，我们将从中获取数据。

在我们的示例中，我们使用以下源，这些源都是知名新闻网站上的技术源：

[`feeds.reuters.com/reuters/technologyNews`](http://feeds.reuters.com/reuters/technologyNews)

[`rss.nytimes.com/services/xml/rss/nyt/Technology.xml`](http://rss.nytimes.com/services/xml/rss/nyt/Technology.xml)

[`feeds.bbci.co.uk/news/science_and_environment/rss.xml`](http://feeds.bbci.co.uk/news/science_and_environment/rss.xml)

下载`search_keywords.py`脚本，该脚本将从 GitHub 执行操作，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/search_keywords.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/search_keywords.py)。

您还需要下载电子邮件模板，可以在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/email_styling.html`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/email_styling.html)和[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/email_template.md`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/email_template.md)找到。

在[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-opportunity.ini`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-opportunity.ini)中有一个配置模板。

你需要一个有效的用户名和密码来使用电子邮件服务。在第八章的*发送单独的电子邮件*示例中检查。

# 如何做...

1.  创建一个`config-opportunity.ini`文件，格式如下。记得填写你的详细信息：

```py
[SEARCH]
keywords = keyword, keyword
feeds = feed, feed

[EMAIL]
user = <YOUR EMAIL USERNAME>
password = <YOUR EMAIL PASSWORD>
from = <EMAIL ADDRESS FROM>
to = <EMAIL ADDRESS TO>
```

你可以使用 GitHub 上的模板[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-opportunity.ini`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-opportunity.ini)来搜索关键词`cpu`和一些测试源。记得用你自己的账户信息填写`EMAIL`字段。

1.  调用脚本生成电子邮件和报告：

```py
$ python search_keywords.py config-opportunity.ini
```

1.  检查`to`电子邮件，你应该收到一份包含找到的文章的报告。它应该类似于这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/83e66ce4-be5b-46e2-96f3-5a4c5390865c.png)

# 工作原理...

在步骤 1 中创建脚本的适当配置后，通过调用`search_keywords.py`在步骤 2 中完成网页抓取和发送电子邮件的结果。

让我们看一下`search_keywords.py`脚本。代码分为以下几部分：

+   `IMPORTS`部分使所有 Python 模块可供以后使用。它还定义了`EmailConfig namedtuple`来帮助处理电子邮件参数。

+   `READ TEMPLATES`检索电子邮件模板并将它们存储以供以后在`EMAIL_TEMPLATE`和`EMAIL_STYLING`常量中使用。

+   `__main__`块通过获取配置参数、解析配置文件，然后调用主函数来启动过程。

+   `main`函数组合了其他函数。首先，它检索文章，然后获取正文并发送电子邮件。

+   `get_articles`遍历所有的源，丢弃任何超过一周的文章，检索每一篇文章，并搜索关键词的匹配。返回所有匹配的文章，包括链接和摘要的信息。

+   `compose_email_body`使用电子邮件模板编写电子邮件正文。注意模板是 Markdown 格式，它被解析为 HTML，以便在纯文本和 HTML 中提供相同的信息。

+   `send_email`获取正文信息，以及用户名/密码等必要信息，最后发送电子邮件。

# 还有更多...

从不同来源检索信息的主要挑战之一是在所有情况下解析文本。一些源可能以不同的格式返回信息。

例如，在我们的示例中，你可以看到路透社的摘要包含 HTML 信息，这些信息在最终的电子邮件中被渲染。如果你遇到这种问题，你可能需要进一步处理返回的数据，直到它变得一致。这可能高度依赖于预期的报告质量。

在开发自动任务时，特别是处理多个输入源时，预计会花费大量时间以一致的方式清理输入。但另一方面，要找到平衡，并牢记最终的接收者。例如，如果邮件是要由你自己或一个理解的队友接收，你可以比对待重要客户的情况更宽容一些。

另一种可能性是增加匹配的复杂性。在这个示例中，检查是用简单的`in`完成的，但请记住，第一章中的所有技术，包括所有正则表达式功能，都可以供您使用。

此脚本可以通过定时作业自动化，如《第二章》中所述，《自动化任务变得容易》。尝试每周运行一次！

# 另请参阅

+   在《第一章》的“添加命令行参数”中，《让我们开始我们的自动化之旅》

+   在《第一章》的“介绍正则表达式”中，《让我们开始我们的自动化之旅》

+   在《第二章》的“准备任务”中，《自动化任务变得容易》

+   在《第二章》的“设置定时作业”中，《自动化任务变得容易》

+   在《第三章》的“解析 HTML”中，《第一个网络爬虫应用程序》

+   在《第三章》的“爬取网络”中，《第一个网络爬虫应用程序》

+   在《第三章》的“构建您的第一个网络爬虫应用程序”中，订阅提要的食谱

+   在《第八章》的“发送个人电子邮件”中，《处理通信渠道》

# 创建个性化优惠券代码

在本章中，我们将一个营销活动分为几个步骤：

1.  检测最佳时机启动活动

1.  生成要发送给潜在客户的个人代码

1.  通过用户首选的渠道，即短信或电子邮件，直接发送代码给用户

1.  收集活动的结果

1.  生成带有结果分析的销售报告

这个食谱展示了活动的第 2 步。

在发现机会后，我们决定为所有客户生成一项活动。为了直接促销并避免重复，我们将生成 100 万个独特的优惠券，分为三批：

+   一半的代码将被打印并在营销活动中分发

+   30 万代码将被保留，以备将来在活动达到一些目标时使用

+   其余的 20 万将通过短信和电子邮件直接发送给客户，我们稍后会看到

这些优惠券可以在在线系统中兑换。我们的任务是生成符合以下要求的正确代码：

+   代码需要是唯一的

+   代码需要可打印且易于阅读，因为一些客户将通过电话口述它们

+   在检查代码之前应该有一种快速丢弃代码的方法（避免垃圾邮件攻击）

+   代码应以 CSV 格式呈现以供打印

# 做好准备

从 GitHub 上下载`create_personalised_coupons.py`脚本，该脚本将在 CSV 文件中生成优惠券，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/create_personalised_coupons.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/create_personalised_coupons.py)。

# 如何做...

1.  调用`create_personalised_coupons.py`脚本。根据您的计算机速度，运行时间可能需要一两分钟。它将在屏幕上显示生成的代码：

```py
$ python create_personalised_coupons.py
Code: HWLF-P9J9E-U3
Code: EAUE-FRCWR-WM
Code: PMW7-P39MP-KT
...
```

1.  检查它是否创建了三个 CSV 文件，其中包含代码`codes_batch_1.csv`，`codes_batch_2.csv`和`codes_batch_3.csv`，每个文件都包含正确数量的代码：

```py
$ wc -l codes_batch_*.csv
  500000 codes_batch_1.csv
  300000 codes_batch_2.csv
  200000 codes_batch_3.csv
 1000000 total
```

1.  检查每个批次文件是否包含唯一代码。您的代码将是唯一的，并且与此处显示的代码不同：

```py
$ head codes_batch_2.csv
9J9F-M33YH-YR
7WLP-LTJUP-PV
WHFU-THW7R-T9
...
```

# 它是如何工作的...

步骤 1 调用生成所有代码的脚本，步骤 2 检查结果是否正确。步骤 3 显示代码存储的格式。让我们分析`create_personalised_coupons.py`脚本。

总之，它具有以下结构：

```py
# IMPORTS

# FUNCTIONS
def random_code(digits)
def checksum(code1, code2)
def check_code(code)
def generate_code()

# SET UP TASK

# GENERATE CODES

# CREATE AND SAVE BATCHES
```

不同的功能一起工作来创建代码。`random_code`生成一组随机字母和数字的组合，取自`CHARACTERS`。该字符串包含所有可供选择的有效字符。

字符的选择被定义为易于打印且不易混淆的符号。例如，很难区分字母 O 和数字 0，或数字 1 和字母 I，这取决于字体。这可能取决于具体情况，因此如有必要，请进行打印测试以定制字符。但是避免使用所有字母和数字，因为这可能会引起混淆。如有必要，增加代码的长度。

`checksum`函数基于两个代码生成一个额外的数字，这个过程称为**哈希**，在计算中是一个众所周知的过程，尤其是在密码学中。

哈希的基本功能是从一个输入产生一个较小且不可逆的输出，这意味着很难猜测，除非已知输入。哈希在计算中有很多常见的应用，通常在底层使用。例如，Python 字典广泛使用哈希。

在我们的示例中，我们将使用 SHA256，这是一个众所周知的快速哈希算法，包含在 Python 的`hashlib`模块中：

```py
def checksum(code1, code2):
    m = hashlib.sha256()
    m.update(code1.encode())
    m.update(code2.encode())
    checksum = int(m.hexdigest()[:2], base=16)
    digit = CHARACTERS[checksum % len(CHARACTERS)]
    return digit
```

两个代码作为输入添加，然后将哈希的两个十六进制数字应用于`CHARACTERS`，以获得其中一个可用字符。这些数字被转换为数字（因为它们是十六进制的），然后我们应用`模`运算符来确保获得其中一个可用字符。

这个校验和的目的是能够快速检查代码是否正确，并且丢弃可能的垃圾邮件。我们可以再次对代码执行操作，以查看校验和是否相同。请注意，这不是加密哈希，因为在操作的任何时候都不需要秘密。鉴于这个特定的用例，这种（低）安全级别对我们的目的来说可能是可以接受的。

密码学是一个更大的主题，确保安全性强可能会很困难。密码学中涉及哈希的主要策略可能是仅存储哈希以避免以可读格式存储密码。您可以在这里阅读有关此的快速介绍：[`crackstation.net/hashing-security.htm`](https://crackstation.net/hashing-security.htm)。

`generate_code`函数然后生成一个随机代码，由四位数字、五位数字和两位校验和组成，用破折号分隔。第一个数字使用前九个数字按顺序生成（四位然后五位），第二个数字将其反转（五位然后四位）。

`check_code`函数将反转过程，并在代码正确时返回`True`，否则返回`False`。

有了基本元素之后，脚本开始定义所需的批次——500,000、300,000 和 200,000。

所有的代码都是在同一个池中生成的，称为`codes`。这是为了避免在池之间产生重复。请注意，由于过程的随机性，我们无法排除生成重复代码的可能性，尽管这很小。我们允许最多重试三次，以避免生成重复代码。代码被添加到一个集合累加器中，以确保它们的唯一性，并加快检查代码是否已经存在的速度。

`sets`是 Python 在底层使用哈希的另一个地方，因此它将要添加的元素进行哈希处理，并将其与已经存在的元素的哈希进行比较。这使得在集合中进行检查非常快速。

为了确保过程是正确的，每个代码都经过验证并打印出来，以显示生成代码的进度，并允许检查一切是否按预期工作。

最后，代码被分成适当数量的批次，每个批次保存在单独的`.csv`文件中。 代码使用`.pop()`从`codes`中逐个删除，直到`batch`达到适当大小为止：

```py
batch = [(codes.pop(),) for _ in range(batch_size)]
```

请注意，前一行创建了一个包含单个元素的适当大小行的批次。每一行仍然是一个列表，因为对于 CSV 文件来说应该是这样。

然后，创建一个文件，并使用`csv.writer`将代码存储为行。

作为最后的测试，验证剩余的`codes`是否为空。

# 还有更多...

在这个食谱中，流程采用了直接的方法。这与第二章中*准备运行任务*食谱中介绍的原则相反，*简化任务变得更容易*。请注意，与那里介绍的任务相比，此脚本旨在运行一次以生成代码，然后结束。它还使用了定义的常量，例如`BATCHES`，用于配置。

鉴于这是一个独特的任务，设计为仅运行一次，花时间将其构建成可重用的组件可能不是我们时间的最佳利用方式。

过度设计肯定是可能的，而在实用设计和更具未来导向性的方法之间做出选择可能并不容易。要对维护成本保持现实，并努力找到自己的平衡。

同样，这个食谱中的校验和设计旨在提供一种最小的方式来检查代码是否完全虚构或看起来合法。鉴于代码将被检查系统，这似乎是一个明智的方法，但要注意您特定的用例。

我们的代码空间是`22 个字符** 9 个数字= 1,207,269,217,792 个可能的代码`，这意味着猜测其中一个百万个生成的代码的概率非常小。也不太可能产生相同的代码两次，但尽管如此，我们通过最多三次重试来保护我们的代码。

这些检查以及检查每个代码的验证以及最终没有剩余代码的检查在开发这种脚本时非常有用。这确保了我们朝着正确的方向前进，事情按计划进行。只是要注意，在某些情况下`asserts`可能不会被执行。

如 Python 文档所述，如果使用`-O`命令运行 Python 代码，则`assert`命令将被忽略。请参阅此处的文档[`docs.python.org/3/reference/simple_stmts.html#the-assert-statement`](https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement)。通常情况下不会这样做，但如果是这种情况可能会令人困惑。避免过度依赖`asserts`。

学习加密的基础并不像你可能认为的那么困难。有一些基本模式是众所周知且易于学习的。一个很好的介绍文章是这篇[`thebestvpn.com/cryptography/`](https://thebestvpn.com/cryptography/)。Python 也集成了大量的加密函数；请参阅文档[`docs.python.org/3/library/crypto.html`](https://docs.python.org/3/library/crypto.html)。最好的方法是找一本好书，知道虽然这是一个难以真正掌握的主题，但绝对是可以掌握的。

# 另请参阅

+   第一章中的*介绍正则表达式*食谱，*让我们开始自动化之旅*

+   第四章中的*读取 CSV 文件*食谱，*搜索和阅读本地文件*

# 向客户发送他们首选渠道的通知

在本章中，我们介绍了一个分为几个步骤的营销活动：

1.  检测最佳推出活动的时机

1.  生成要发送给潜在客户的个别代码

1.  直接将代码发送给用户，通过他们首选的渠道，短信或电子邮件

1.  收集活动的结果

1.  生成带有结果分析的销售报告

这个食谱展示了活动的第 3 步。

一旦我们的代码为直接营销创建好，我们需要将它们分发给我们的客户。

对于这个食谱，从包含所有客户及其首选联系方式信息的 CSV 文件中，我们将使用先前生成的代码填充文件，然后通过适当的方法发送通知，其中包括促销代码。

# 做好准备

在这个示例中，我们将使用已经介绍过的几个模块——`delorean`、`requests`和`twilio`。如果尚未添加到我们的虚拟环境中，我们需要将它们添加进去：

```py
$ echo "delorean==1.0.0" >> requirements.txt
$ echo "requests==2.18.3" >> requirements.txt
$ echo "twilio==6.16.3" >> requirements.txt
$ pip install -r requirements.txt
```

我们需要定义一个`config-channel.ini`文件，其中包含我们用于 Mailgun 和 Twilio 的服务的凭据。可以在 GitHub 上找到此文件的模板：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-channel.ini`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/config-channel.ini)。

有关如何获取凭据的信息，请参阅*通过电子邮件发送通知*和*生成短信*的示例第八章，*处理通信渠道*

文件的格式如下：

```py
[MAILGUN]
KEY = <YOUR KEY>
DOMAIN = <YOUR DOMAIN>
FROM = <YOUR FROM EMAIL>
[TWILIO]
ACCOUNT_SID = <YOUR SID>
AUTH_TOKEN = <YOUR TOKEN>
FROM = <FROM TWILIO PHONE NUMBER>
```

为了描述所有目标联系人，我们需要生成一个 CSV 文件`notifications.csv`，格式如下：

| Name | Contact Method | Target | Status | Code | Timestamp |
| --- | --- | --- | --- | --- | --- |
| John Smith | PHONE | +1-555-12345678 | `NOT-SENT` |  |  |
| Paul Smith | EMAIL | `paul.smith@test.com` | `NOT-SENT` |  |  |
| … |  |  |  |  |  |

请注意`Code`列为空，所有状态应为`NOT-SENT`或空。

如果您正在使用 Twilio 和 Mailgun 的测试帐户，请注意其限制。例如，Twilio 只允许您向经过身份验证的电话号码发送消息。您可以创建一个只包含两三个联系人的小型 CSV 文件来测试脚本。

应该准备好在 CSV 文件中使用的优惠券代码。您可以使用 GitHub 上的`create_personalised_coupons.py`脚本生成多个批次，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/create_personalised_coupons.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/create_personalised_coupons.py)。

从 GitHub 上下载要使用的脚本`send_notifications.py`，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/send_notifications.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/send_notifications.py)。

# 操作步骤...

1.  运行`send_notifications.py`以查看其选项和用法：

```py
$ python send_notifications.py --help
usage: send_notifications.py [-h] [-c CODES] [--config CONFIG_FILE] notif_file

positional arguments:
  notif_file notifications file

optional arguments:
  -h, --help show this help message and exit
  -c CODES, --codes CODES
                        Optional file with codes. If present, the file will be
                        populated with codes. No codes will be sent
  --config CONFIG_FILE config file (default config.ini)
```

1.  将代码添加到`notifications.csv`文件中：

```py
$ python send_notifications.py --config config-channel.ini notifications.csv -c codes_batch_3.csv 
$ head notifications.csv
Name,Contact Method,Target,Status,Code,Timestamp
John Smith,PHONE,+1-555-12345678,NOT-SENT,CFXK-U37JN-TM,
Paul Smith,EMAIL,paul.smith@test.com,NOT-SENT,HJGX-M97WE-9Y,
...
```

1.  最后，发送通知：

```py
$ python send_notifications.py --config config-channel.ini notifications.csv
$ head notifications.csv
Name,Contact Method,Target,Status,Code,Timestamp
John Smith,PHONE,+1-555-12345678,SENT,CFXK-U37JN-TM,2018-08-25T13:08:15.908986+00:00
Paul Smith,EMAIL,paul.smith@test.com,SENT,HJGX-M97WE-9Y,2018-08-25T13:08:16.980951+00:00
...
```

1.  检查电子邮件和电话，以验证消息是否已收到。

# 工作原理...

第 1 步展示了脚本的使用。总体思路是多次调用它，第一次用于填充代码，第二次用于发送消息。如果出现错误，可以再次执行脚本，只会重试之前未发送的消息。

`notifications.csv`文件获取将在第 2 步中注入的代码。这些代码最终将在第 3 步中发送。

让我们分析`send_notifications.py`的代码。这里只显示了最相关的部分：

```py
# IMPORTS

def send_phone_notification(...):
def send_email_notification(...):
def send_notification(...):

def save_file(...):
def main(...):

if __name__ == '__main__':
    # Parse arguments and prepare configuration
    ...
```

主要函数逐行遍历文件，并分析每种情况下要执行的操作。如果条目为`SENT`，则跳过。如果没有代码，则尝试填充。如果尝试发送，则会附加时间戳以记录发送或尝试发送的时间。

对于每个条目，整个文件都会被保存在名为`save_file`的文件中。注意文件光标定位在文件开头，然后写入文件，并刷新到磁盘。这样可以在每次条目操作时覆盖文件，而无需关闭和重新打开文件。

为什么要为每个条目写入整个文件？这是为了让您可以重试。如果其中一个条目产生意外错误或超时，甚至出现一般性故障，所有进度和先前的代码都将被标记为已发送，并且不会再次发送。这意味着可以根据需要重试操作。对于大量条目，这是确保在过程中出现问题不会导致我们重新发送消息给客户的好方法。

对于要发送的每个代码，`send_notification` 函数决定调用 `send_phone_notification` 或 `send_email_notification`。在两种情况下都附加当前时间。

如果无法发送消息，两个 `send` 函数都会返回错误。这允许您在生成的 `notifications.csv` 中标记它，并稍后重试。

`notifications.csv` 文件也可以手动更改。例如，假设电子邮件中有拼写错误，这就是错误的原因。可以更改并重试。

`send_email_notification` 根据 Mailgun 接口发送消息。有关更多信息，请参阅第八章中的*通过电子邮件发送通知*配方，*处理通信渠道*。请注意这里发送的电子邮件仅为文本。

`send_phone_notification` 根据 Twilio 接口发送消息。有关更多信息，请参阅第八章中的*生成短信*配方，*处理通信渠道*。

# 还有更多...

时间戳的格式故意以 ISO 格式编写，因为它是可解析的格式。这意味着我们可以轻松地以这种方式获取一个正确的对象，就像这样：

```py
>>> import datetime
>>> timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
>>> timestamp
'2018-08-25T14:13:53.772815+00:00'
>>> datetime.datetime.fromisoformat(timestamp)
datetime.datetime(2018, 9, 11, 21, 5, 41, 979567, tzinfo=datetime.timezone.utc)
```

这使您可以轻松地解析时间戳。

ISO 8601 时间格式在大多数编程语言中都得到很好的支持，并且非常精确地定义了时间，因为它包括时区。如果可以使用它，这是记录时间的绝佳选择。

`send_notification` 中用于路由通知的策略非常有趣：

```py
# Route each of the notifications
METHOD = {
    'PHONE': send_phone_notification,
    'EMAIL': send_email_notification,
}
try:
    method = METHOD[entry['Contact Method']]
    result = method(entry, config)
except KeyError:
    result = 'INVALID_METHOD'
```

`METHOD` 字典将每个可能的 `Contact Method` 分配给具有相同定义的函数，接受条目和配置。

然后，根据特定的方法，从字典中检索并调用函数。请注意 `method` 变量包含要调用的正确函数。

这类似于其他编程语言中可用的 `switch` 操作。也可以通过 `if...else` 块来实现。对于这种简单的代码，字典方法使代码非常易读。

`invalid_method` 函数被用作默认值。如果 `Contact Method` 不是可用的方法之一（`PHONE` 或 `EMAIL`），将引发 `KeyError`，捕获并将结果定义为 `INVALID METHOD`。

# 另请参阅

+   第八章中的*通过电子邮件发送通知*配方，*处理通信渠道*

+   第八章中的*生成短信*配方，*处理通信渠道*

# 准备销售信息

在本章中，我们介绍了一个分为几个步骤的营销活动：

1.  检测启动广告活动的最佳时机

1.  生成要发送给潜在客户的个人代码

1.  直接通过用户首选的渠道，短信或电子邮件，发送代码

1.  收集广告活动的结果

1.  生成带有结果分析的销售报告

这个配方展示了广告活动的第 4 步。

向用户发送信息后，我们需要收集商店的销售日志，以监控情况和广告活动的影响有多大。

销售日志作为与各个关联商店的单独文件报告，因此在这个配方中，我们将看到如何将所有信息汇总到一个电子表格中，以便将信息作为一个整体处理。

# 做好准备

对于这个配方，我们需要安装以下模块：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ echo "parse==1.8.2" >> requirements.txt
$ echo "delorean==1.0.0" >> requirements.txt
$ pip install -r requirements.txt
```

我们可以从 GitHub 上获取这个配方的测试结构和测试日志：[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter09/sales`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter09/sales)。请下载包含大量测试日志的完整`sales`目录。为了显示结构，我们将使用`tree`命令（[`mama.indstate.edu/users/ice/tree/`](http://mama.indstate.edu/users/ice/tree/)），它在 Linux 中默认安装，并且可以在 macOs 中使用`brew`安装（[`brew.sh/`](https://brew.sh/)）。您也可以使用图形工具来检查目录。

我们还需要`sale_log.py`模块和`parse_sales_log.py`脚本，可以在 GitHub 上找到：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/parse_sales_log.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/parse_sales_log.py)。

# 如何做...

1.  检查`sales`目录的结构。每个子目录代表一个商店提交了其销售日志的期间：

```py
$ tree sales
sales
├── 345
│   └── logs.txt
├── 438
│   ├── logs_1.txt
│   ├── logs_2.txt
│   ├── logs_3.txt
│   └── logs_4.txt
└── 656
 └── logs.txt
```

1.  检查日志文件：

```py
$ head sales/438/logs_1.txt
[2018-08-27 21:05:55+00:00] - SALE - PRODUCT: 12346 - PRICE: $02.99 - NAME: Single item - DISCOUNT: 0%
[2018-08-27 22:05:55+00:00] - SALE - PRODUCT: 12345 - PRICE: $07.99 - NAME: Family pack - DISCOUNT: 20%
...
```

1.  调用`parse_sales_log.py`脚本生成存储库：

```py
$ python parse_sales_log.py sales -o report.xlsx
```

1.  检查生成的 Excel 结果，`report.xlsx`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/f0a6152c-2b86-4262-9f0f-cf5283ba2602.png)

# 它是如何工作的...

步骤 1 和 2 展示了数据的结构。步骤 3 调用`parse_sales_log.py`来读取所有日志文件并解析它们，然后将它们存储在 Excel 电子表格中。电子表格的内容在步骤 4 中显示。

让我们看看`parse_sales_log.py`的结构：

```py
# IMPORTS
from sale_log import SaleLog

def get_logs_from_file(shop, log_filename):
    with open(log_filename) as logfile:
        logs = [SaleLog.parse(shop=shop, text_log=log)
                for log in logfile]
    return logs

def main(log_dir, output_filename):
    logs = []
    for dirpath, dirnames, filenames in os.walk(log_dir):
        for filename in filenames:
            # The shop is the last directory
            shop = os.path.basename(dirpath)
            fullpath = os.path.join(dirpath, filename)
            logs.extend(get_logs_from_file(shop, fullpath))

    # Create and save the Excel sheet
    xlsfile = openpyxl.Workbook()
    sheet = xlsfile['Sheet']
    sheet.append(SaleLog.row_header())
    for log in logs:
        sheet.append(log.row())
    xlsfile.save(output_filename)

if __name__ == '__main__':
  # PARSE COMMAND LINE ARGUMENTS AND CALL main()

```

命令行参数在第一章中有解释，*让我们开始自动化之旅*。请注意，导入包括`SaleLog`。

主要函数遍历整个目录并通过`os.walk`获取所有文件。您可以在第二章中获取有关`os.walk`的更多信息，*简化任务自动化*。然后将每个文件传递给`get_logs_from_file`来解析其日志并将它们添加到全局`logs`列表中。

注意，特定商店存储在最后一个子目录中，因此可以使用`os.path.basename`来提取它。

完成日志列表后，使用`openpyxl`模块创建一个新的 Excel 表。`SaleLog`模块有一个`.row_header`方法来添加第一行，然后所有日志都被转换为行格式使用`.row`。最后，文件被保存。

为了解析日志，我们创建一个名为`sale_log.py`的模块。这个模块抽象了解析和处理一行的过程。大部分都很简单，并且正确地结构化了每个不同的参数，但是解析方法需要一点注意：

```py
    @classmethod
    def parse(cls, shop, text_log):
        '''
        Parse from a text log with the format
        ...
        to a SaleLog object
        '''
        def price(string):
            return Decimal(string)

        def isodate(string):
            return delorean.parse(string)

        FORMAT = ('[{timestamp:isodate}] - SALE - PRODUCT: {product:d} '
                  '- PRICE: ${price:price} - NAME: {name:D} '
                  '- DISCOUNT: {discount:d}%')

        formats = {'price': price, 'isodate': isodate}
        result = parse.parse(FORMAT, text_log, formats)

        return cls(timestamp=result['timestamp'],
                   product_id=result['product'],
                   price=result['price'],
                   name=result['name'],
                   discount=result['discount'],
                   shop=shop)
```

`sale_log.py`是一个*classmethod*，意味着可以通过调用`SaleLog.parse`来使用它，并返回类的新元素。

Classmethods 被调用时，第一个参数存储类，而不是通常存储在`self`中的对象。约定是使用`cls`来表示它。在最后调用`cls(...)`等同于`SaleFormat(...)`，因此它调用`__init__`方法。

该方法使用`parse`模块从模板中检索值。请注意，`timestamp`和`price`这两个元素具有自定义解析。`delorean`模块帮助我们解析日期，价格最好描述为`Decimal`以保持适当的分辨率。自定义过滤器应用于`formats`参数。

# 还有更多...

`Decimal`类型在 Python 文档中有详细描述：[`docs.python.org/3/library/decimal.html`](https://docs.python.org/3/library/decimal.html)。

完整的`openpyxl`可以在这里找到：[`openpyxl.readthedocs.io/en/stable/`](https://openpyxl.readthedocs.io/en/stable/)。还要检查第六章，*电子表格的乐趣*，以获取有关如何使用该模块的更多示例。

完整的`parse`文档可以在这里找到：[`github.com/r1chardj0n3s/parse`](https://github.com/r1chardj0n3s/parse)。第一章中也更详细地描述了这个模块。

# 另请参阅

+   第一章中的*使用第三方工具—parse*配方，*让我们开始自动化之旅*

+   第四章中的*爬取和搜索目录*配方，*搜索和读取本地文件*

+   第四章中的*读取文本文件*配方，*搜索和读取本地文件*

+   第六章中的*更新 Excel 电子表格*配方，*电子表格的乐趣*

# 生成销售报告

在这一章中，我们提出了一个分为几个步骤的营销活动：

1.  检测最佳推出活动的时机

1.  生成个人代码以发送给潜在客户

1.  直接将代码通过用户首选的渠道，短信或电子邮件发送给用户

1.  收集活动的结果

1.  生成带有结果分析的销售报告

这个配方展示了活动的第 5 步。

作为最后一步，所有销售的信息都被汇总并显示在销售报告中。

在这个配方中，我们将看到如何利用从电子表格中读取、创建 PDF 和生成图表，以便自动生成全面的报告，以分析我们活动的表现。

# 准备工作

在这个配方中，我们将在虚拟环境中需要以下模块：

```py
$ echo "openpyxl==2.5.4" >> requirements.txt
$ echo "fpdf==1.7.2" >> requirements.txt
$ echo "delorean==1.0.0" >> requirements.txt
$ echo "PyPDF2==1.26.0" >> requirements.txt
$ echo "matplotlib==2.2.2" >> requirements.txt
$ pip install -r requirements.txt
```

我们需要在 GitHub 上的`sale_log.py`模块，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/sale_log.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/sale_log.py)。

输入电子表格是在前一个配方中生成的，准备销售信息。在那里查找更多信息。

您可以从 GitHub 上下载用于生成输入电子表格的脚本`parse_sales_log.py`，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/parse_sales_log.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/parse_sales_log.py)。

从 GitHub 上下载原始日志文件，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter09/sales`](https://github.com/PacktPublishing/Python-Automation-Cookbook/tree/master/Chapter09/sales)。请下载完整的`sales`目录。

从 GitHub 上下载`generate_sales_report.py`脚本，网址为[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/generate_sales_report.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter09/generate_sales_report.py)。

# 如何做...

1.  检查输入文件和使用`generate_sales_report.py`：

```py
$ ls report.xlsx
report.xlsx
$ python generate_sales_report.py --help
usage: generate_sales_report.py [-h] input_file output_file

positional arguments:
  input_file
  output_file

optional arguments:
  -h, --help show this help message and exit
```

1.  使用输入文件和输出文件调用`generate_sales_report.py`脚本：

```py
$ python generate_sales_report.py report.xlsx output.pdf
```

1.  检查`output.pdf`输出文件。它将包含三页，第一页是简要摘要，第二页和第三页是按天和按商店的销售图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/d1492287-b767-48b3-b522-fa5c294f4eb2.png)

第二页显示了每天的销售图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/28b396ae-1c0d-4831-b27d-843ca484f302.png)

第三页按商店划分销售额：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-auto-cb/img/b3cbce7b-0a65-40b0-adff-515c6d66bee8.png)

# 它是如何工作的

第 1 步显示如何使用脚本，第 2 步在输入文件上调用它。让我们来看一下`generate_sales_report.py`脚本的基本结构：

```py
# IMPORTS
def generate_summary(logs):

def aggregate_by_day(logs):
def aggregate_by_shop(logs):

def graph(...):

def create_summary_brief(...):

def main(input_file, output_file):
  # open and read input file
  # Generate each of the pages calling the other calls
  # Group all the pdfs into a single file
  # Write the resulting PDF

if __name__ == '__main__':
  # Compile the input and output files from the command line
  # call main
```

有两个关键元素——以不同方式（按商店和按天）聚合日志以及在每种情况下生成摘要。摘要是通过`generate_summary`生成的，它从日志列表中生成一个带有聚合信息的字典。日志的聚合是在`aggregate_by`函数中以不同的样式完成的。

`generate_summary`生成一个包含聚合信息的字典，包括开始和结束时间，所有日志的总收入，总单位，平均折扣，以及相同数据按产品进行的详细分解。

通过从末尾开始理解脚本会更好。主要函数将所有不同的操作组合在一起。读取每个日志并将其转换为本地的`SaleLog`对象。

然后，它将每个页面生成为一个中间的 PDF 文件：

+   `create_summary_brief`生成一个关于所有数据的总摘要。

+   日志被`aggregate_by_day`。创建一个摘要并生成一个图表。

+   日志被`aggregate_by_shop`。创建一个摘要并生成一个图表。

使用`PyPDF2`将所有中间 PDF 页面合并成一个文件。最后，删除中间页面。

`aggregate_by_day`和`aggregate_by_shop`都返回一个包含每个元素摘要的列表。在`aggregate_by_day`中，我们使用`.end_of_day`来检测一天何时结束，以区分一天和另一天。

`graph`函数执行以下操作：

1.  准备要显示的所有数据。这包括每个标签（日期或商店）的单位数量，以及每个标签的总收入。

1.  创建一个顶部图表，显示按产品分割的总收入，以堆叠条形图的形式。为了能够做到这一点，同时计算总收入时，还计算了基线（下一个堆叠位置的位置）。

1.  它将图表的底部部分分成与产品数量相同的图表，并显示每个标签（日期或商店）上销售的单位数量。

为了更好地显示，图表被定义为 A4 纸的大小。它还允许我们使用`skip_labels`在第二个图表的 X 轴上打印每个*X*标签中的一个，以避免重叠。这在显示日期时很有用，并且设置为每周只显示一个标签。

生成的图表被保存到文件中。

`create_summary_brief`使用`fpdf`模块保存一个包含总摘要信息的文本 PDF 页面。

`create_summary_brief`中的模板和信息被故意保持简单，以避免使这个配方复杂化，但可以通过更好的描述性文本和格式进行复杂化。有关如何使用`fpdf`的更多详细信息，请参阅第五章，“生成精彩报告”。

如前所示，`main`函数将所有 PDF 页面分组并合并成一个单一文档，然后删除中间页面。

# 还有更多...

此配方中包含的报告可以扩展。例如，可以在每个页面中计算平均折扣，并显示为一条线：

```py
# Generate a data series with the average discount
discount = [summary['average_discount'] for _, summary in full_summary]
....
# Print the legend
# Plot the discount in a second axis
plt.twinx()
plt.plot(pos, discount,'o-', color='green')
plt.ylabel('Average Discount')
```

但要小心，不要在一个图表中放入太多信息。这可能会降低可读性。在这种情况下，另一个图表可能是更好的显示方式。

在创建第二个轴之前小心打印图例，否则它将只显示第二个轴上的信息。

图表的大小和方向可以决定是否使用更多或更少的标签，以便清晰可读。这在使用`skip_labels`避免混乱时得到了证明。请注意生成的图形，并尝试通过更改大小或在某些情况下限制标签来适应该领域可能出现的问题。

例如，可能的限制是最多只能有三种产品，因为在我们的图表中打印第二行的四个图表可能会使文本难以辨认。请随意尝试并检查代码的限制。

完整的`matplotlib`文档可以在[`matplotlib.org/`](https://matplotlib.org/)找到。

`delorean`文档可以在这里找到：[`delorean.readthedocs.io/en/latest/`](https://delorean.readthedocs.io/en/latest/)

`openpyxl`的所有文档都可以在[`openpyxl.readthedocs.io/en/stable/`](https://openpyxl.readthedocs.io/en/stable/)找到。 

PyPDF2 的 PDF 操作模块的完整文档可以在[`pythonhosted.org/PyPDF2/`](https://pythonhosted.org/PyPDF2/)找到，`pyfdf`的文档可以在[`pyfpdf.readthedocs.io/en/latest/`](https://pyfpdf.readthedocs.io/en/latest/)找到。

本食谱利用了第五章中提供的不同概念和技术，用于 PDF 创建和操作，《第六章](404a9dc7-22f8-463c-9f95-b480dc17518d.xhtml)中的*与电子表格玩耍*，用于电子表格阅读，以及第七章中的*开发令人惊叹的图表*，用于图表创建。查看它们以了解更多信息。

# 另请参阅

+   在第五章中的*聚合 PDF*报告食谱

+   在第六章中的*读取 Excel*电子表格食谱

+   在第七章中的*绘制堆叠条形图*食谱

+   在《开发令人惊叹的图表》第七章中的*显示多行*食谱

+   在《开发令人惊叹的图表》第七章中的*添加图例和注释*食谱

+   在《开发令人惊叹的图表》第七章中的*组合图表*食谱

+   在《开发令人惊叹的图表》第七章中的*保存图表*食谱


# 第十章：调试技术

在本章中，我们将介绍以下配方：

+   学习 Python 解释器基础知识

+   通过日志调试

+   使用断点调试

+   提高你的调试技能

# 介绍

编写代码并不容易。实际上，它非常困难。即使是世界上最好的程序员也无法预见代码的任何可能的替代方案和流程。

这意味着执行我们的代码将总是产生惊喜和意外的行为。有些会非常明显，而其他的则会非常微妙，但是识别和消除代码中的这些缺陷的能力对于构建稳固的软件至关重要。

这些软件中的缺陷被称为**bug**，因此消除它们被称为**调试**。

仅通过阅读来检查代码并不好。总会有意外，复杂的代码很难跟踪。这就是为什么通过停止执行并查看当前状态的能力是重要的。

每个人，每个人都会在代码中引入 bug，通常稍后会对此感到惊讶。有些人将调试描述为*在一部犯罪电影中扮演侦探，而你也是凶手*。

任何调试过程大致遵循以下路径：

1.  你意识到有一个问题

1.  你了解正确的行为应该是什么

1.  你发现了当前代码产生 bug 的原因

1.  你改变代码以产生正确的结果

在这 95%的时间里，除了步骤 3 之外的所有事情都是微不足道的，这是调试过程的主要部分。

意识到 bug 的原因，本质上使用了科学方法：

1.  测量和观察代码的行为

1.  对为什么会这样产生假设

1.  验证或证明是否正确，也许通过实验

1.  使用得到的信息来迭代这个过程

调试是一种能力，因此随着时间的推移会得到改善。实践在培养对哪些路径看起来有希望识别错误的直觉方面起着重要作用，但也有一些一般的想法可能会帮助你：

+   **分而治之：**隔离代码的小部分，以便理解代码。尽可能简化问题。

这有一个称为**狼围栏算法**的格式，由爱德华·高斯描述：

"阿拉斯加有一只狼；你怎么找到它？首先在州的中间建造一道围栏，等待狼嚎叫，确定它在围栏的哪一边。然后只在那一边重复这个过程，直到你能看到狼为止。"

+   **从错误处向后移动：**如果在特定点有明显的错误，那么 bug 可能位于周围。从错误处逐渐向后移动，沿着轨迹直到找到错误的源头。

+   **只要你证明了你的假设，你可以假设任何东西：**代码非常复杂，无法一次性记住所有内容。您需要验证小的假设，这些假设结合起来将为检测和修复问题提供坚实的基础。进行小实验，这将允许您从头脑中删除实际工作的代码部分，并专注于未经测试的代码部分。

或用福尔摩斯的话说：

"一旦你排除了不可能的，无论多么不可能，剩下的，必定是真相。"

但记住要证明它。避免未经测试的假设。

所有这些听起来有点可怕，但实际上大多数 bug 都是相当明显的。也许是拼写错误，或者一段代码还没有准备好接受特定的值。尽量保持简单。简单的代码更容易分析和调试。

在本章中，我们将看到一些调试工具和技术，并将它们特别应用于 Python 脚本。这些脚本将有一些 bug，我们将作为配方的一部分来修复它们。

# 学习 Python 解释器基础知识

在这个配方中，我们将介绍一些 Python 内置的功能，以检查代码，调查发生了什么事情，并检测当事情不正常时。

我们还可以验证事情是否按预期进行。记住，能够排除代码的一部分作为错误源是非常重要的。

在调试时，我们通常需要分析来自外部模块或服务的未知元素和对象。鉴于 Python 的动态特性，代码在执行的任何时刻都是高度可发现的。

这个方法中的所有内容都是 Python 解释器的默认内容。

# 如何做到...

1.  导入`pprint`：

```py
>>> from pprint import pprint
```

1.  创建一个名为`dictionary`的新字典：

```py
>>> dictionary = {'example': 1}
```

1.  将`globals`显示到此环境中：

```py
>>> globals()
{...'pprint': <function pprint at 0x100995048>, 
...'dictionary': {'example': 1}}
```

1.  以可读格式使用`pprint`打印`globals`字典：

```py
>>> pprint(globals())
{'__annotations__': {},
 ...
 'dictionary': {'example': 1},
 'pprint': <function pprint at 0x100995048>}
```

1.  显示`dictionary`的所有属性：

```py
>>> dir(dictionary)
['__class__', '__contains__', '__delattr__', '__delitem__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__iter__', '__le__', '__len__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', 'clear', 'copy', 'fromkeys', 'get', 'items', 'keys', 'pop', 'popitem', 'setdefault', 'update', 'values']
```

1.  展示`dictionary`对象的帮助：

```py
>>> help(dictionary)

Help on dict object:

class dict(object)
 | dict() -> new empty dictionary
 | dict(mapping) -> new dictionary initialized from a mapping object's
 | (key, value) pairs
...
```

# 它是如何工作的...

在第 1 步导入`pprint`（漂亮打印）之后，我们创建一个新的字典作为第 2 步中的示例。

第 3 步显示了全局命名空间包含已定义的字典和模块等内容。`globals()`显示所有导入的模块和其他全局变量。

本地命名空间有一个等效的`locals()`。

`pprint`有助于以第 4 步中更可读的格式显示`globals`，增加更多空间并将元素分隔成行。

第 5 步显示了如何使用`dir()`获取 Python 对象的所有属性。请注意，这包括所有双下划线值，如`__len__`。

使用内置的`help()`函数将显示对象的相关信息。

# 还有更多...

`dir()`特别适用于检查未知对象、模块或类。如果需要过滤默认属性并澄清输出，可以通过以下方式过滤输出：

```py
>>> [att for att in dir(dictionary) if not att.startswith('__')]
['clear', 'copy', 'fromkeys', 'get', 'items', 'keys', 'pop', 'popitem', 'setdefault', 'update', 'values']
```

同样，如果要搜索特定方法（例如以`set`开头的方法），也可以以相同的方式进行过滤。

`help()`将显示函数或类的`docstring`。`docstring`是在定义之后定义的字符串，用于记录函数或类的信息：

```py
>>> def something():
...     '''
...     This is help for something
...     '''
...     pass
...
>>> help(something)
Help on function something in module __main__:

something()
    This is help for something
```

请注意，在下一个示例中，*这是某物的帮助*字符串是在函数定义之后定义的。

`docstring`通常用三引号括起来，以允许编写多行字符串。Python 将三引号内的所有内容视为一个大字符串，即使有换行符也是如此。您可以使用`'`或`"`字符，只要使用三个即可。您可以在[`www.python.org/dev/peps/pep-0257/`](https://www.python.org/dev/peps/pep-0257/)找到有关`docstrings`的更多信息。

内置函数的文档可以在[`docs.python.org/3/library/functions.html#built-in-functions`](https://docs.python.org/3/library/functions.html#built-in-functions)找到，`pprint`的完整文档可以在[`docs.python.org/3/library/pprint.html#`](https://docs.python.org/3/library/pprint.html#)找到。

# 另请参阅

+   *提高调试技能*的方法

+   *通过日志进行调试*的方法

# 通过日志进行调试

毕竟，调试就是检测程序内部发生了什么以及可能发生的意外或不正确的影响。一个简单但非常有效的方法是在代码的战略部分输出变量和其他信息，以跟踪程序的流程。

这种方法的最简单形式称为**打印调试**，或者在调试时在某些点插入打印语句以打印变量或点的值。

但是，稍微深入了解这种技术，并将其与第二章中介绍的日志技术相结合，*轻松实现自动化任务*使我们能够创建程序执行的半永久跟踪，这在检测运行中的程序中的问题时非常有用。

# 准备工作

从 GitHub 下载 `debug_logging.py` 文件：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_logging.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_logging.py)。

它包含了冒泡排序算法的实现（[`www.studytonight.com/data-structures/bubble-sort`](https://www.studytonight.com/data-structures/bubble-sort)），这是对元素列表进行排序的最简单方式。它在列表上进行多次迭代，每次迭代都会检查并交换两个相邻的值，使得较大的值在较小的值之后。这样就使得较大的值像气泡一样在列表中上升。

冒泡排序是一种简单但天真的排序实现方式，有更好的替代方案。除非你有极好的理由，否则依赖列表中的标准 `.sort` 方法。

运行时，它检查以下列表以验证其正确性：

```py
assert [1, 2, 3, 4, 7, 10] == bubble_sort([3, 7, 10, 2, 4, 1])
```

我们在这个实现中有一个 bug，所以我们可以将其作为修复的一部分来修复！

# 如何做...

1.  运行 `debug_logging.py` 脚本并检查是否失败：

```py
$ python debug_logging.py
INFO:Sorting the list: [3, 7, 10, 2, 4, 1]
INFO:Sorted list:      [2, 3, 4, 7, 10, 1]
Traceback (most recent call last):
  File "debug_logging.py", line 17, in <module>
    assert [1, 2, 3, 4, 7, 10] == bubble_sort([3, 7, 10, 2, 4, 1])
AssertionError
```

1.  启用调试日志，更改`debug_logging.py`脚本的第二行：

```py
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
```

将前一行改为以下一行：

```py
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
```

注意不同的 `level`。

1.  再次运行脚本，增加更多信息：

```py
$ python debug_logging.py
INFO:Sorting the list: [3, 7, 10, 2, 4, 1]
DEBUG:alist: [3, 7, 10, 2, 4, 1]
DEBUG:alist: [3, 7, 10, 2, 4, 1]
DEBUG:alist: [3, 7, 2, 10, 4, 1]
DEBUG:alist: [3, 7, 2, 4, 10, 1]
DEBUG:alist: [3, 7, 2, 4, 10, 1]
DEBUG:alist: [3, 2, 7, 4, 10, 1]
DEBUG:alist: [3, 2, 4, 7, 10, 1]
DEBUG:alist: [2, 3, 4, 7, 10, 1]
DEBUG:alist: [2, 3, 4, 7, 10, 1]
DEBUG:alist: [2, 3, 4, 7, 10, 1]
INFO:Sorted list : [2, 3, 4, 7, 10, 1]
Traceback (most recent call last):
  File "debug_logging.py", line 17, in <module>
    assert [1, 2, 3, 4, 7, 10] == bubble_sort([3, 7, 10, 2, 4, 1])
AssertionError
```

1.  分析输出后，我们意识到列表的最后一个元素没有排序。我们分析代码并发现第 7 行有一个 off-by-one 错误。你看到了吗？让我们通过更改以下一行来修复它：

```py
for passnum in reversed(range(len(alist) - 1)):
```

将前一行改为以下一行：

```py
for passnum in reversed(range(len(alist))):
```

（注意移除了 `-1` 操作。）

1.  再次运行它，你会发现它按预期工作。调试日志不会显示在这里：

```py
$ python debug_logging.py
INFO:Sorting the list: [3, 7, 10, 2, 4, 1]
...
INFO:Sorted list     : [1, 2, 3, 4, 7, 10]
```

# 它是如何工作的...

第 1 步介绍了脚本，并显示代码有错误，因为它没有正确地对列表进行排序。

脚本已经有一些日志来显示开始和结束结果，以及一些调试日志来显示每个中间步骤。在第 2 步中，我们激活了显示 `DEBUG` 日志的显示，因为在第 1 步中只显示了 `INFO`。

注意，默认情况下日志会显示在标准错误输出中。这在终端中是默认显示的。如果你需要将日志重定向到其他地方，比如文件中，可以查看如何配置不同的处理程序。查看 Python 中的日志配置以获取更多详细信息：[`docs.python.org/3/howto/logging.html`](https://docs.python.org/3/howto/logging.html)。

第 3 步再次运行脚本，这次显示额外信息，显示列表中的最后一个元素没有排序。

这个 bug 是一个 off-by-one 错误，这是一种非常常见的错误，因为它应该迭代整个列表的大小。这在第 4 步中得到修复。

检查代码以了解为什么会出现错误。整个列表应该被比较，但我们错误地减少了一个大小。

第 5 步显示修复后的脚本运行正确。

# 还有更多...

在这个示例中，我们已经有策略地放置了调试日志，但在实际的调试练习中可能不是这样。你可能需要添加更多或更改位置作为 bug 调查的一部分。

这种技术的最大优势是我们能够看到程序的流程，能够检查代码执行的一个时刻到另一个时刻，并理解流程。但缺点是我们可能会得到一大堆不提供关于问题的具体信息的文本。你需要在提供太多和太少信息之间找到平衡。

出于同样的原因，除非必要，尽量限制非常长的变量。

记得在修复 bug 后降低日志级别。很可能你发现一些不相关的日志需要被删除。

这种技术的快速而粗糙的版本是添加打印语句而不是调试日志。虽然有些人对此持反对意见，但实际上这是一种用于调试目的的有价值的技术。但记得在完成后清理它们。

所有的内省元素都可用，因此可以创建显示例如`dir(object)`对象的所有属性的日志：

```py
logging.debug(f'object {dir(object)}')
```

任何可以显示为字符串的内容都可以在日志中呈现，包括任何文本操作。

# 另请参阅

+   *学习 Python 解释器基础*食谱

+   *提高调试技能*食谱

# 使用断点进行调试

Python 有一个现成的调试器叫做`pdb`。鉴于 Python 代码是解释性的，这意味着可以通过设置断点来在任何时候停止代码的执行，这将跳转到一个命令行，可以在其中使用任何代码来分析情况并执行任意数量的指令。

让我们看看如何做。

# 准备工作

下载`debug_algorithm.py`脚本，可从 GitHub 获取：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_algorithm.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_algorithm.py)。

在下一节中，我们将详细分析代码的执行。代码检查数字是否符合某些属性：

```py
def valid(candidate):
    if candidate <= 1:
        return False

    lower = candidate - 1
    while lower > 1:
        if candidate / lower == candidate // lower:
            return False
        lower -= 1

    return True

assert not valid(1)
assert valid(3)
assert not valid(15)
assert not valid(18)
assert not valid(50)
assert valid(53)
```

可能你已经认识到代码在做什么，但请跟着我一起交互分析它。

# 如何做...

1.  运行代码以查看所有断言是否有效：

```py
$ python debug_algorithm.py
```

1.  在`while`循环之后添加`breakpoint()`，就在第 7 行之前，结果如下：

```py
    while lower > 1:
        breakpoint()
        if candidate / lower == candidate // lower:
```

1.  再次执行代码，看到它在断点处停止，进入交互式`Pdb`模式：

```py
$ python debug_algorithm.py
> .../debug_algorithm.py(8)valid()
-> if candidate / lower == candidate // lower:
(Pdb)
```

1.  检查候选值和两个操作的值。这一行是在检查`candidate`除以`lower`是否为整数（浮点数和整数除法是相同的）：

```py
(Pdb) candidate
3
(Pdb) candidate / lower
1.5
(Pdb) candidate // lower
1
```

1.  使用`n`继续到下一条指令。看到它结束了 while 循环并返回`True`：

```py
(Pdb) n
> ...debug_algorithm.py(10)valid()
-> lower -= 1
(Pdb) n
> ...debug_algorithm.py(6)valid()
-> while lower > 1:
(Pdb) n
> ...debug_algorithm.py(12)valid()
-> return True
(Pdb) n
--Return--
> ...debug_algorithm.py(12)valid()->True
-> return True
```

1.  继续执行，直到找到另一个断点，使用`c`。请注意，这是对`valid()`的下一个调用，输入为 15：

```py
(Pdb) c
> ...debug_algorithm.py(8)valid()
-> if candidate / lower == candidate // lower:
(Pdb) candidate
15
(Pdb) lower
14
```

1.  继续运行和检查数字，直到`valid`函数的操作有意义。你能找出代码在做什么吗？（如果你不能，不要担心，查看下一节。）完成后，使用`q`退出。这将停止执行：

```py
(Pdb) q
...
bdb.BdbQuit
```

# 工作原理...

代码正在检查一个数字是否是质数，这点你可能已经知道。它试图将数字除以比它小的所有整数。如果在任何时候可以被整除，它将返回`False`结果，因为它不是质数。

实际上，这是一个检查质数的非常低效的方法，因为处理大数字将需要很长时间。不过，对于我们的教学目的来说，它足够快。如果你有兴趣找质数，可以查看 SymPy 等数学包（[`docs.sympy.org/latest/modules/ntheory.html?highlight=prime#sympy.ntheory.primetest.isprime`](https://docs.sympy.org/latest/modules/ntheory.html?highlight=prime#sympy.ntheory.primetest.isprime)）。

在步骤 1 中检查了一般的执行，在步骤 2 中，在代码中引入了一个`breakpoint`。

当在步骤 3 中执行代码时，它会在`breakpoint`位置停止，进入交互模式。

在交互模式下，我们可以检查任何变量的值，以及执行任何类型的操作。如步骤 4 所示，有时，通过重现其部分，可以更好地分析一行代码。

可以检查代码并在命令行中执行常规操作。可以通过调用`n(ext)`来执行下一行代码，就像步骤 5 中多次执行一样，以查看代码的流程。

步骤 6 显示了如何使用`c(ontinue)`命令恢复执行，以便在下一个断点处停止。所有这些操作都可以迭代以查看流程和值，并了解代码在任何时候正在做什么。

可以使用`q(uit)`停止执行，如步骤 7 所示。

# 还有更多...

要查看所有可用的操作，可以在任何时候调用`h(elp)`。

您可以使用`l(ist)`命令在任何时候检查周围的代码。例如，在步骤 4 中：

```py
(Pdb) l
  3   return False
  4
  5   lower = candidate - 1
  6   while lower > 1:
  7     breakpoint()
  8 ->  if candidate / lower == candidate // lower:
  9       return False
 10     lower -= 1
 11
 12   return True
```

另外两个主要的调试器命令是`s(tep)`，它将执行下一步，包括进入新的调用，以及`r(eturn)`，它将从当前函数返回。

您可以使用`pdb`命令`b(reak)`设置（和禁用）更多断点。您需要为断点指定文件和行，但实际上更直接，更不容易出错的方法是改变代码并再次运行它。

您可以覆盖变量以及读取它们。或者创建新变量。或进行额外的调用。或者您能想象到的其他任何事情。Python 解释器的全部功能都在您的服务中！用它来检查某些东西是如何工作的，或者验证某些事情是否发生。

避免使用调试器保留的名称创建变量，例如将列表称为`l`。这将使事情变得混乱，并在尝试调试时干扰，有时以非明显的方式。

`breakpoint()`函数是 Python 3.7 中的新功能，但如果您使用该版本，强烈推荐使用它。在以前的版本中，您需要用以下内容替换它：

```py
import pdb; pdb.set_trace()
```

它们的工作方式完全相同。请注意同一行中的两个语句，这在 Python 中通常是不推荐的，但这是保持断点在单行中的一个很好的方法。

记得在调试完成后删除任何`breakpoints`！特别是在提交到 Git 等版本控制系统时。

您可以在官方 PEP 中阅读有关新的`breakpoint`调用的更多信息，该 PEP 描述了其用法：[`www.python.org/dev/peps/pep-0553/`](https://www.python.org/dev/peps/pep-0553/)。

完整的`pdb`文档可以在这里找到：[`docs.python.org/3.7/library/pdb.html#module-pdb`](https://docs.python.org/3.7/library/pdb.html#module-pdb)。它包括所有的调试命令。

# 另请参阅

+   *学习 Python 解释器基础*食谱

+   *改进您的调试技能*食谱

# 改进您的调试技能

在这个食谱中，我们将分析一个小脚本，它复制了对外部服务的调用，分析并修复了一些错误。我们将展示不同的技术来改进调试。

脚本将一些个人姓名 ping 到互联网服务器（`httpbin.org`，一个测试站点）以获取它们，模拟从外部服务器检索它们。然后将它们分成名和姓，并准备按姓氏排序。最后，它将对它们进行排序。

脚本包含了几个我们将检测和修复的错误。

# 准备工作

对于这个食谱，我们将使用`requests`和`parse`模块，并将它们包含在我们的虚拟环境中：

```py
$ echo "requests==2.18.3" >> requirements.txt
$ echo "parse==1.8.2" >> requirements.txt
$ pip install -r requirements.txt
```

`debug_skills.py`脚本可以从 GitHub 获取：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_skills.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_skills.py)。请注意，它包含我们将在本食谱中修复的错误。

# 如何做...

1.  运行脚本，将生成错误：

```py
$ python debug_skills.py
Traceback (most recent call last):
 File "debug_skills.py", line 26, in <module>
 raise Exception(f'Error accessing server: {result}')
Exception: Error accessing server: <Response [405]>
```

1.  分析状态码。我们得到了 405，这意味着我们发送的方法不被允许。我们检查代码并意识到，在第 24 行的调用中，我们使用了`GET`，而正确的方法是`POST`（如 URL 中所述）。用以下内容替换代码：

```py
# ERROR Step 2\. Using .get when it should be .post
# (old) result = requests.get('http://httpbin.org/post', json=data)
result = requests.post('http://httpbin.org/post', json=data)
```

我们将旧的错误代码用`(old)`进行了注释，以便更清楚地进行更改。

1.  再次运行代码，将产生不同的错误：

```py
$ python debug_skills.py
Traceback (most recent call last):
  File "debug_skills_solved.py", line 34, in <module>
    first_name, last_name = full_name.split()
ValueError: too many values to unpack (expected 2)
```

1.  在第 33 行插入一个断点，一个在错误之前。再次运行它并进入调试模式：

```py
$ python debug_skills_solved.py
..debug_skills.py(35)<module>()
-> first_name, last_name = full_name.split()
(Pdb) n
> ...debug_skills.py(36)<module>()
-> ready_name = f'{last_name}, {first_name}'
(Pdb) c
> ...debug_skills.py(34)<module>()
-> breakpoint()
```

运行`n`不会产生错误，这意味着它不是第一个值。在`c`上运行几次后，我们意识到这不是正确的方法，因为我们不知道哪个输入是产生错误的。

1.  相反，我们用`try...except`块包装该行，并在那一点产生一个`breakpoint`：

```py
    try:
        first_name, last_name = full_name.split()
    except:
        breakpoint()
```

1.  我们再次运行代码。这次代码在数据产生错误的时候停止：

```py
$ python debug_skills.py
> ...debug_skills.py(38)<module>()
-> ready_name = f'{last_name}, {first_name}'
(Pdb) full_name
'John Paul Smith'
```

1.  现在原因很明显，第 35 行只允许我们分割两个单词，但如果添加中间名就会引发错误。经过一些测试，我们确定了这行来修复它：

```py
    # ERROR Step 6 split only two words. Some names has middle names
    # (old) first_name, last_name = full_name.split()
    first_name, last_name = full_name.rsplit(maxsplit=1)
```

1.  我们再次运行脚本。确保移除`breakpoint`和`try..except`块。这次，它生成了一个名字列表！并且它们按姓氏字母顺序排序。然而，一些名字看起来不正确：

```py
$ python debug_skills_solved.py
['Berg, Keagan', 'Cordova, Mai', 'Craig, Michael', 'Garc\\u00eda, Roc\\u00edo', 'Mccabe, Fathima', "O'Carroll, S\\u00e9amus", 'Pate, Poppy-Mae', 'Rennie, Vivienne', 'Smith, John Paul', 'Smyth, John', 'Sullivan, Roman']
```

谁叫`O'Carroll, S\\u00e9amus`？

1.  为了分析这个特殊情况，但跳过其余部分，我们必须创建一个`if`条件，只在第 33 行为那个名字中断。注意`in`，以避免必须完全正确：

```py
    full_name = parse.search('"custname": "{name}"', raw_result)['name']
    if "O'Carroll" in full_name:
        breakpoint()
```

1.  再次运行脚本。`breakpoint`在正确的时刻停止了：

```py
$ python debug_skills.py
> debug_skills.py(38)<module>()
-> first_name, last_name = full_name.rsplit(maxsplit=1)
(Pdb) full_name
"S\\u00e9amus O'Carroll"
```

1.  向上移动代码，检查不同的变量：

```py
(Pdb) full_name
"S\\u00e9amus O'Carroll"
(Pdb) raw_result
'{"custname": "S\\u00e9amus O\'Carroll"}'
(Pdb) result.json()
{'args': {}, 'data': '{"custname": "S\\u00e9amus O\'Carroll"}', 'files': {}, 'form': {}, 'headers': {'Accept': '*/*', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'close', 'Content-Length': '37', 'Content-Type': 'application/json', 'Host': 'httpbin.org', 'User-Agent': 'python-requests/2.18.3'}, 'json': {'custname': "Séamus O'Carroll"}, 'origin': '89.100.17.159', 'url': 'http://httpbin.org/post'}
```

1.  在`result.json()`字典中，实际上有一个不同的字段，似乎正确地呈现了名字，这个字段叫做`'json'`。让我们仔细看一下；我们可以看到它是一个字典：

```py
(Pdb) result.json()['json']
{'custname': "Séamus O'Carroll"}
(Pdb) type(result.json()['json'])
<class 'dict'>
```

1.  改变代码，不要解析`'data'`中的原始值，直接使用结果中的`'json'`字段。这简化了代码，非常棒！

```py
    # ERROR Step 11\. Obtain the value from a raw value. Use
    # the decoded JSON instead
    # raw_result = result.json()['data']
    # Extract the name from the result
    # full_name = parse.search('"custname": "{name}"', raw_result)['name']
    raw_result = result.json()['json']
    full_name = raw_result['custname']
```

1.  再次运行代码。记得移除`breakpoint`：

```py
$ python debug_skills.py
['Berg, Keagan', 'Cordova, Mai', 'Craig, Michael', 'García, Rocío', 'Mccabe, Fathima', "O'Carroll, Séamus", 'Pate, Poppy-Mae', 'Rennie, Vivienne', 'Smith, John Paul', 'Smyth, John', 'Sullivan, Roman']
```

这一次，一切都正确了！您已成功调试了程序！

# 它是如何工作的...

食谱的结构分为三个不同的问题。让我们分块分析它：

+   **第一个错误-对外部服务的错误调用**：

在步骤 1 中显示第一个错误后，我们仔细阅读了产生的错误，说服务器返回了 405 状态码。这对应于不允许的方法，表明我们的调用方法不正确。

检查以下行：

```py
result = requests.get('http://httpbin.org/post', json=data)
```

它告诉我们，我们正在使用`GET`调用一个为`POST`定义的 URL，所以我们在步骤 2 中进行了更改。

请注意，在这个错误中并没有额外的调试步骤，而是仔细阅读错误消息和代码。记住要注意错误消息和日志。通常，这已经足够发现问题了。

我们在步骤 3 中运行代码，找到下一个问题。

+   **第二个错误-中间名处理错误**：

在步骤 3 中，我们得到了一个值过多的错误。我们在步骤 4 中创建一个`breakpoint`来分析这一点的数据，但发现并非所有数据都会产生这个错误。在步骤 4 中进行的分析表明，当错误没有产生时停止执行可能会非常令人困惑，必须继续直到产生错误。我们知道错误是在这一点产生的，但只对某种类型的数据产生错误。

由于我们知道错误是在某个时候产生的，我们在步骤 5 中用`try..except`块捕获它。当异常产生时，我们触发`breakpoint`。

这使得步骤 6 执行脚本时停止，当`full_name`是`'John Paul Smith'`时。这会产生一个错误，因为`split`期望返回两个元素，而不是三个。

这在步骤 7 中得到了修复，允许除了最后一个单词之外的所有内容都成为名字的一部分，将任何中间名归为第一个元素。这符合我们这个程序的目的，按姓氏排序。

实际上，名字处理起来相当复杂。如果您想对关于名字的错误假设感到惊讶，请查看这篇文章：[`www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/`](https://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/)。

以下行使用`rsplit`：

```py
first_name, last_name = full_name.rsplit(maxsplit=1)
```

它通过单词从右边开始分割文本，最多分割一次，确保只返回两个元素。

当代码更改时，第 8 步再次运行代码以发现下一个错误。

+   **第三个错误——使用外部服务返回的错误值**：

在第 8 步运行代码会显示列表，并且不会产生任何错误。 但是，检查结果，我们可以看到一些名称被错误处理了。

我们选择第 9 步中的一个示例，并创建一个条件断点。 只有在数据满足`if`条件时才激活`breakpoint`。

在这种情况下，`if`条件在任何时候停止`"O'Carroll"`字符串出现，而不必使用等号语句使其更严格。 对于这段代码要实用主义，因为在修复错误后，您将需要将其删除。

代码在第 10 步再次运行。 从那里，一旦验证数据符合预期，我们就开始*向后*寻找问题的根源。 第 11 步分析先前的值和到目前为止的代码，试图找出导致不正确值的原因。

然后我们发现我们在从服务器的`result`返回值中使用了错误的字段。 `json`字段的值更适合这个任务，而且它已经为我们解析了。 第 12 步检查该值并查看应该如何使用它。

在第 13 步，我们更改代码进行调整。 请注意，不再需要`parse`模块，而且使用`json`字段的代码实际上更清晰。

这个结果实际上比看起来更常见，特别是在处理外部接口时。 我们可能会以一种有效的方式使用它，但也许这并不是最好的。 花点时间阅读文档，并密切关注改进并学习如何更好地使用工具。

一旦这个问题解决了，代码在第 14 步再次运行。 最后，代码按姓氏按字母顺序排列。 请注意，包含奇怪字符的其他名称也已修复。

# 还有更多...

修复后的脚本可以从 GitHub 获取：[`github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_skills_fixed.py`](https://github.com/PacktPublishing/Python-Automation-Cookbook/blob/master/Chapter10/debug_skills_fixed.py)。 您可以下载并查看其中的差异。

还有其他创建条件断点的方法。 实际上，调试器支持创建断点，但仅当满足某些条件时才停止。 可以在 Python `pdb`文档中查看如何创建它：[`docs.python.org/3/library/pdb.html#pdbcommand-break`](https://docs.python.org/3/library/pdb.html#pdbcommand-break)。

在第一个错误中显示的捕获异常的断点类型演示了在代码中制作条件是多么简单。 只是要小心在之后删除它们！

还有其他可用的调试器具有更多功能。 例如：

+   `ipdb` ([`github.com/gotcha/ipdb`](https://github.com/gotcha/ipdb))：添加制表符补全和语法高亮显示

+   `pudb` ([`documen.tician.de/pudb/`](https://documen.tician.de/pudb/))：显示旧式的半图形文本界面，以自动显示环境变量的方式显示 90 年代早期工具的风格

+   `web-pdb` ([`pypi.org/project/web-pdb/`](https://pypi.org/project/web-pdb/))：打开一个 Web 服务器以访问带有调试器的图形界面

查看它们的文档以了解如何安装和运行它们。

还有更多可用的调试器，通过互联网搜索将为您提供更多选项，包括 Python IDE。 无论如何，要注意添加依赖项。 能够使用默认调试器总是很好的。

Python 3.7 中的新断点命令允许我们使用`PYTHONBREAKPOINT`环境变量轻松地在调试器之间切换。 例如：

```py
$ PYTHONBREAKPOINT=ipdb.set_trace python my_script.py
```

这将在代码中的任何断点上启动`ipdb`。您可以在`breakpoint()`文档中了解更多信息：[`www.python.org/dev/peps/pep-0553/#environment-variable`](https://www.python.org/dev/peps/pep-0553/#environment-variable)。

对此的一个重要影响是通过设置`PYTHONBREAKPOINT=0`来禁用所有断点，这是一个很好的工具，可以确保生产中的代码永远不会因为错误留下的`breakpoint()`而中断。

Python `pdb`文档可以在这里找到：[`docs.python.org/3/library/pdb.html`](https://docs.python.org/3/library/pdb.html) `parse`模块的完整文档可以在[`github.com/r1chardj0n3s/parse`](https://github.com/r1chardj0n3s/parse)找到，`requests`的完整文档可以在[`docs.python-requests.org/en/master/`](http://docs.python-requests.org/en/master)找到。

# 另请参阅

+   *学习 Python 解释器基础*配方

+   *使用断点进行调试*配方
