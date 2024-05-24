# Python 渗透测试实用指南（二）

> 原文：[`annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18`](https://annas-archive.org/md5/4B796839472BFAAEE214CCEDB240AE18)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：漏洞扫描器 Python - 第 2 部分

当我们谈论使用开源脚本进行服务扫描时，首先想到的是利用各种 NSE 脚本获取配置的服务的服务版本和相关漏洞。在典型的手动网络渗透测试中，我们不仅使用 NSE 脚本来完成工作，还使用各种 Ruby、Perl 和 Bash 脚本，以及 Java 类文件。我们还运行 Metasploit 辅助模块进行服务扫描和利用模块来利用漏洞并创建 POC。我们还可能运行各种 Kali 工具，比如用于 Web 扫描的 Nikto，或者用于捕获未正确配置的 FTP 或 SSH 服务的明文用户名和密码的 SQLmap、w3af 和 Wireshark。所有这些工具和脚本产生了大量信息，测试人员需要手动枚举和整合。还必须消除误报，以得出哪些服务存在哪些漏洞的结论。手动服务扫描的另一个方面是缺乏标准化，更多地依赖于个人的专业知识和所使用的脚本的选择。重要的是要记住，要使用的脚本大多是相互分离的，以至于一个人必须按顺序运行所有所需的脚本和模块。我们可以实现有限的并行性。

在本章中，我们将看到我们的漏洞扫描器如何自动化所有这些活动，并为整个生态系统带来标准化。我们还将看到自动化扫描器如何调用和编排所有 Kali 工具，以为渗透测试人员生成一个集成报告，供其快速分析使用。我们还将研究漏洞扫描器的图形用户界面版本，该版本具有更高级的功能，并补充了现有的漏洞扫描器，如 Nessus。必须指出的是，当我使用 *补充* 这个词时，我绝不是在将我们的扫描器与 Nessus 或 Qualys 进行比较。它们都是经过多年研发的优秀商业产品，并有一些优秀的工程师在其中工作。然而，我们将构建出一个运行非常出色的东西；了解代码可以让您有机会为扫描器做出贡献，从而帮助它随着时间的推移变得更好更大。

# 架构概述

我们已经在第五章 *漏洞扫描器 Python - 第 1 部分* 中看过了扫描器的架构。让我们重新审视扫描器的服务扫描部分，并思考整个生态系统是如何工作的。以下图表显示了我们的服务扫描架构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a7c2cb8c-65e4-43cf-9b06-f7c6d48a5ff2.png)

项目 ID 将与使用 Nmap 端口扫描完成的所有扫描相关联。用户可以选择要进行服务扫描的项目 ID，并且还可以查看已成功完成端口扫描的所有项目 ID。应该注意，只有已完成的项目的项目 ID 将被显示；暂停端口扫描的项目将不会被显示。

一旦选择了项目 ID，代码就会读取数据库表 `IPtable_history`，显示开放端口和默认配置，这指的是开放端口和相关脚本（取决于服务名称）。用户可以重新配置扫描结果，包括手动添加任何被忽略的开放端口或删除任何显示为开放但实际上不可访问的条目。一旦用户重新配置了结果，我们就可以运行服务扫描了。应该注意，如果用户发现端口扫描结果都正确，可以跳过重新配置步骤。

扫描活动结束后，我们将把所有结果保存在我们的 MySQL 数据库表中。在服务扫描的情况下，根据发现的服务，我们将得到一个配置好的脚本列表，如果找到特定的服务，我们需要执行这些脚本。我们使用一个 JSON 文件来映射服务和相应的要执行的脚本。

在端口扫描的情况下，用户将收到端口扫描结果，并有选择重新配置结果（以减少误报）。最终配置设置后，将开始服务扫描。逻辑是从数据库中逐个选择一个主机，并根据发现的服务，从 JSON 文件中读取适当的脚本，并为该特定主机执行它们。最后，在执行脚本后，结果应保存在数据库中。这将持续到所有主机都扫描其服务为止。最后，将生成一个包含格式化结果和 POC 截图的 HTML 报告。以下截图显示了如何配置 JSON 文件以执行脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/14b16790-646d-4621-b88b-a1d1e4acc5b4.png)

从前面的截图可以看出，JSON 文件中包含各种类别的命令。Metasploit 模板包含用于执行 Metasploit 模块的命令。单行命令用于执行 NSE 脚本以及所有非交互式的模块和脚本，可以用单个命令触发。其他类别包括`interactive_commands`和`single_line_sniffing`（需要在执行脚本的同时嗅探流量）。JSON 文件的一般模板如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/61f06b62-c5e6-4ed3-ad34-75242f926e11.png)

**key**是服务的名称。标题包含文件的描述。`method_id`是应调用的实际 Python 方法，以调用要执行的外部脚本。请注意，对于单行命令，我们还在`args`参数下的第一个参数中指定了一个`timeout`参数，单位为秒。

# 代码的更详细查看

应该注意到整个代码库可以在 GitHub 上找到[`github.com/FurqanKhan1/Dictator`](https://github.com/FurqanKhan1/Dictator)。我们将查看所有构成服务扫描器核心逻辑的基本代码文件。或者，我创建了一个即插即用的 Kali VM 镜像，其中包含所有必需的安装和开箱即用的代码库。可以从以下 URL[`drive.google.com/file/d/1e0Wwc1r_7XtL0uCLJXeLstMgJR68wNLF/view?usp=sharing`](https://drive.google.com/file/d/1e0Wwc1r_7XtL0uCLJXeLstMgJR68wNLF/view?usp=sharing)下载并无忧地执行。默认用户名是`PTO_root`，密码是`PTO_root`。

让我们概览一下我们将使用的基本文件和方法，来构建我们的服务扫描引擎，使用 Python。

# Driver_scanner.py

端口扫描结束后，下一步是执行服务扫描。这个 Python 类调用另一个类`driver_meta.py`，它接受要执行服务扫描的项目名称/ID，如下面的代码片段所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/85fbab57-78e3-484a-8485-0046530ff0e1.png)

# driver_meta.py

这个类显示了端口扫描的默认结果，并给用户重新配置结果的选项。重新配置后，这个类从数据库表中读取要执行服务扫描的项目的主机。对于每个主机，它然后从 JSON 文件中读取要执行的命令，对于要执行的每个命令，它将控制传递给另一个文件`auto_comamnds.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/681da31c-9d55-4caf-8b07-493e0d90a3cf.png)

前面的类代表了这个 Python 模块的主要父类。正如我们所看到的，我们已经导入了其他各种 Python 模块，如 JSON、SYS 和 psutil，以便与这个类一起使用。我们还可以看到，我们已经在这个模块中使用了其他类，如`auto_commands`、`Auto_logger`、`IPexploits`和`IPtable`。这些不是 Python 的内置模块，而是我们自己的类，用于执行我们服务扫描引擎的不同功能。我们将在稍后更详细地讨论这些。

# main()

看一下这个类的`main()`方法，从这里实际上开始执行循环：

`main()`方法是用于 CLI 版本和 GUI 版本的相同代码片段，因此有许多参数只有在以 GUI 模式调用时才相关。我们将在本节讨论在 CLI 模式下需要的参数。我们可以看到`mode`变量在`main()`方法的定义中初始化为`c`。 

在下面的屏幕截图中标记为**(1)**的部分中，我们为`texttable()` Python 模块初始化了一个对象，该模块将用于在控制台窗口上绘制一个表，以显示可以执行服务扫描的项目 ID。第二部分从数据库中收集了所有已完成的项目，第三部分将检索到的行添加到程序变量中，以在屏幕上显示。随后的代码很简单。在第四部分，功能实际上删除了先前已完成服务扫描的项目的详细信息，以便用户可以用新的服务扫描操作覆盖结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ff8386f7-82c6-4c0e-84eb-68faf33667f5.png)

第五部分创建了一个名为`<project_id>`的目录，位于`results`文件夹下。例如，如果当前项目 ID 是`744`，则命令`init_project_directory()`将在`<parent_folder_code_base>/results/<744_data>`下创建一个子文件夹。所有日志文件、扫描配置和最终报告都将放在这个文件夹中。正如我们已经讨论过的，我们有一个预配置的 JSON 文件，其中包含服务名称和要针对该服务执行的测试用例之间的映射。

以下部分显示了 JSON 文件的配置方式。让我们以`http`服务为例，看看如何配置要针对 HTTP 服务执行的测试用例：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2cd0d5fc-1e43-4e3a-adb4-2979fd3bdd44.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2dfa78c5-7d56-4f00-9816-a31c2b49b049.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/540f9725-5a06-4615-a521-68e986493403.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/506435b2-4e03-4bd1-a5fe-807439c928fd.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/81302c92-bbc5-49eb-ade6-91118d91c197.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/21bb1a31-9f5b-4e24-880b-b84f899b0ce9.png)

从前面的分叉中可以看出并分类，名为`http`的服务的所有测试用例将放在一个 JSON 列表中，其键为`Commands`。`Commands`列表中的每个条目都将是一个 JSON 字典，其中包含以下条目：`{"args":[],"id":"","method":"","include":"","title":""}`。每个字典构成一个要执行的测试用例。让我们试着理解每个条目：

+   `args`：`args`参数实际上是一个包含要针对目标执行的实际命令和 NSE 脚本的列表。要执行的所有命令/脚本被分类为我们将在方法部分中看到的五个不同类别。现在，了解`args`包含要在 Kali 控制台上用 Python 执行的实际命令就足够了。

+   `id`：给定要执行的每个命令都有一个唯一的 ID，这使得枚举变得容易。对于所有基于 HTTP 的命令，我们可以看到 ID 是`http_1`，`http_2`，`http_3`等等。

+   `method`: 这个特定的条目非常重要，因为它指的是应该调用的实际 Python 方法来执行这个测试用例。这些方法位于一个名为 `auto_commands.py` 的 Python 文件/模块中，该类别有不同的方法与 JSON 文件进行了映射。通常，要执行的所有脚本被分成五类/类别，并且每个类别都有一个相应的方法与之关联。脚本的类别及其相应的方法如下：

+   `Single_line_comamnds_timeout`: 所有需要一次性调用并为您生成输出的命令/脚本，而不需要在其间进行任何交互的命令/脚本都属于这一分类。例如，可以执行一个 NSE 脚本，命令如下：`nmap -p80 --script <scriptname.nse> 10.0.2.15`；它不需要任何其他输入，只需执行并给出最终输出。或者，可以如下调用一个用于执行目录枚举的 Perl 脚本：`perl http-dir-enum.pl http://10.0.2.15:8000`。同样，所有 Python 脚本、Bash 命令和 Kali 工具，如 Nikto 或 Hoppy，都属于这一类别。所有这些脚本都由一个名为 `singleLineCommands_timeout()` 的 Python 方法处理，该方法位于 `auto_comamnds.py` 模块中。需要注意的是，所有这些脚本还需要一个额外的 `timeout` 参数。有时单个脚本由于某些原因而挂起（主机可能无响应，或者可能遇到未经测试的意外情况），脚本的挂起将导致队列中的其他脚本处于等待状态。为了解决这种情况，我们在 `args[]` 列表中指定一个阈值参数作为第一个参数，这是我们希望脚本执行的最长时间（以秒为单位）。因此，从先前的配置中，我们可以看到为 ID 为 `http_5` 的 NSE 脚本指定了 `500` 秒的超时时间。如果脚本在 `500` 秒内未执行完毕，操作将被中止，并执行队列中的下一个脚本。

+   `General_interactive`: 除了需要执行单行命令并执行的脚本外，我们还有其他需要在执行后进行一些交互的 Bash 命令、Kali 工具和开源脚本。一个典型的例子是 SSH 到远程服务器，通常我们需要传递两组命令。这可以一次完成，但为了更好地理解，让我们举个例子：

+   `ssh root@192.168.250.143 [Command 1]`

+   `password:<my_password> [Command 2]`

另一个例子可能是工具，如 SQLmap 或 w3af_console，需要一定程度的用户交互。请注意，通过这种自动化/扫描引擎，我们可以通过自动调用 Python 来解决脚本的问题。所有需要交互的脚本或测试用例都由一个名为 `general_interactive()` 的方法处理，该方法位于 Python 模块 `auto_comamnds.py` 中。

+   +   `General_commands_timeout_sniff`: 有许多情况下，我们需要执行一个脚本或一个 Bash 命令，同时我们希望 Wireshark 在接口上嗅探流量，以便我们可以找出凭据是否以明文传递。在执行此类别中的脚本时，流量必须被嗅探。它们可以是单行脚本，如 NSE，也可以是交互式命令，如 `ssh root@<target_ip>` 作为第一个命令，`password:<my_password>` 作为第二个命令。所有需要这种调用的脚本都由 Python 方法 `generalCommands_Tout_Sniff()` 处理，该方法同样位于 `auto_comamnds.py` 模块中。

+   Metasploit_Modules：这是执行和处理所有 Metasploit 模块的类别。每当我们需要执行任何 Metasploit 模块时，该模块（无论是辅助还是利用）都将放置在此分类中。执行委托的方法称为`custom_meta()`，放置在`auto_commands.py`下。

+   `HTTP_BASED`：最终类别包含所有需要在目标上发布 HTTP GET/POST 请求进行测试的测试用例，并且这些情况由名为`http_based()`的方法处理，该方法再次放置在`auto_commands.py`模块中。

+   `include`**: **`include`参数有两个值：`True`和`False`）如果我们不希望将测试用例/脚本包含在要执行的测试用例列表中，我们可以设置`include=False`。在选择扫描配置文件时，此功能非常有用。有时我们不希望在目标上运行耗时的测试用例，例如 Nikto 或 Hoppy，并且更喜欢仅运行某些强制性检查或脚本。为了具有该功能，引入了包含参数。我们将在查看我们的扫描仪的 GUI 版本时进一步讨论这一点。

+   `title`：这是一个信息字段，提供有关要执行的基础脚本的信息。

现在我们对将加载到我们的`self.commandsJSON`类变量中的 JSON 文件有了很好的理解，让我们继续进行我们的代码。

突出显示的部分**(6)**读取我们的`all_config_file`程序变量中的 JSON 文件，最终进入`self.commandsJSON`类变量。突出显示的代码部分**(7)，(8)**和**(9)**加载要与扫描一起使用的扫描配置文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/713e7e4b-8050-48d1-9fca-5c71b6923f2f.png)

默认情况下，我们的代码的命令行版本的扫描配置文件是**强制性配置文件**。该配置文件基本上包含应针对目标执行的所有测试用例；它只删除了一些耗时的测试用例。但是，如果我们希望更改`mandatory_profile`的定义，以添加或减去测试用例，我们可以编辑`mandatory.json`文件，该文件位于与我们的代码文件`driver_meta.py`相同的路径上。

以下是`mandatory.json`文件中为`http`服务存在的条目：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/69c995fb-6104-47de-8833-c685ade1fb02.png)

突出显示的部分(9)将加载项目 ID`744`的端口扫描获得的所有结果，结果将保存在数据库表`IPtable_history`中，以下屏幕截图给出了将加载的记录的想法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8817ae65-958f-4a75-bfb8-2f7516511948.png)

我们可以从前面的屏幕截图中看到，基本上有三条记录对应于我们的 ID`744`的扫描。表列的模式是`(record_id,IP,port_range,status,project_id,Services_detected[CSV_format])`。

后端执行的实际查询如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ab761712-4d83-40b8-99ca-4967034874ad.png)

返回的结果将是一个可以迭代的列表。第一个内部列表的第 0 个索引将包含以 CSV 格式加载的检测到的服务。格式将是`(主机;协议;端口;名称;状态;产品;额外信息;原因;版本;配置;cpe)`，可以从前面的屏幕截图中验证。所有这些信息将放在`results_`列表中。

在第**(10)**部分中，如下片段所示，我们正在遍历`results_`列表，并将字符串数据拆分为新行`\n`。我们进一步将返回的列表拆分为`；`，最后将所有结果放在一个列表`lst1 []`中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/468fa19f-5549-44a3-b1f2-8cfbea3e15b6.png)

对于当前示例，在第(11)部分之后，`lst1`将包含以下数据：

```py
lst1=[
[10.0.2.15,tcp,22,ssh,open,OpenSSH,protocol 2.0,syn-ack,OpenSSH-7.2p2 Debian 5,10,cpe:/o:linux:linux_kernel],                                                                    [10.0.2.15,tcp,80,http,open,nginx,,syn-ack,nginx-1.10.2,10,cpe:/a:igor_sysoev:nginx:1.10.2],
  [10.0.2.15,tcp,111,rpcbind,open,,RPC #100000,syn-ack,-2-4,10,],
  [10.0.2.15,tcp,443,https,open,nginx,,syn-ack,nginx-1.10.2,10,cpe:/a:igor_sysoev:nginx:1.10.2],
  [10.0.2.15,tcp,8000,http,open,nginx,,syn-ack,nginx-1.10.2,10,cpe:/a:igor_sysoev:nginx:1.10.2],
  [10.0.2.15,tcp,8002,rtsp,open,,,syn-ack,-,10,]
]
```

因此，`lst1[0][0]`将给我们`10.0.2.15`，`lst1[2][2]=111`等等。

在代码的第**(12)**节中，我们正在按服务类型对`lst1`中的数据进行排序。我们声明了一个字典`lst={}`，并希望根据它们的服务类型对所有主机和端口进行分组，以便第**(12)**，**(13)**节的输出如下：

```py
lst = {
"ssh":[[10.0.2.15,22,open,OpenSSH-7.2p2 Debian 5;10]],
"http":[[10.0.2.15,80,open,nginx-1.10.2],[10.0.2.15,8000,open,nginx-1.10.2]],
"rcpbind":[[10.0.2.15,111,open,-2-4,10]],
"https":[[10.0.2.15,443,open,nginx-1.10.2]],
"rtsp":[[10.0.2.15,8002,open,-]]
}
```

在第**（15）**节中，`ss = set(lst_temp).intersection(set(lst_pre))`，我们对包含字典键的两个结构进行了交集运算。一个结构包含来自字典`lst`的键，该字典包含我们的端口扫描程序发现的所有服务。另一个包含从预配置的 JSON 文件中加载的键。这样做的目的是让我们看到所有已映射测试用例的发现服务。所有已发现和映射的服务键/名称都放在列表**SS**中，代表要扫描的服务。

在第**（16）**节中，`ms=list(set(lst_temp) - set(lst_pre))`，我们正在比较未在 JSON 文件中配置的服务与发现的服务。我们的 JSON 文件在常见服务方面非常详尽，但仍然有时 Nmap 可能会在端口扫描期间发现未在 JSON 文件中预先配置的服务。在本节中，我们试图识别 Nmap 发现但在我们的 JSON 文件中没有针对它们映射测试用例的服务。为此，我们对这两种结构进行了集合差异。我们将标记这些服务为`new`，用户可以对其进行配置测试用例，或者离线分析以执行自定义测试用例。所有这些服务将被放在一个名为`ms`的列表中，其中**ms**代表**未发现的服务**。

在代码片段中显示的第**(17)**和**(18)**节中，我们再次将两个未发现和映射的服务重新构建为两个不同的字典，格式如前所述：`{"ssh":[[10.0.2.15,22,open,OpenSSH-7.2p2 Debian 5;10]],...}`。发现的服务将放在`dic`字典中，然后放入`self.processed_services`类变量中。未发现的服务将放入`ms_dic`，最终放入`self.missed_services`中。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fb45071f-0a2e-464b-92e3-afcd94dc1f62.png)

最后，在第**（19）**节中，我们调用`parse_and_process()`方法，该方法将调用显示发现和未发现服务的逻辑，并为用户提供必要时执行任何重新配置的选项。

重新配置完成后，`parse_and_process()`将调用另一个方法`launchExploits()`，该方法将实际从 JSON 配置文件中读取`method_name`，用发现的适当主机 IP 和端口替换`<host>`和`<port>`，并将控制传递给`auto_command.py`模块的相关方法（根据读取的`method_name`）。

一旦对所有发现的主机和端口执行了所有测试用例，就该生成包含屏幕截图和相关数据的报告了。这部分由第**(20)**和**(21)**节处理，如下面的代码片段所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/de832afc-89f4-4334-bb8a-f0b530f0e418.png)

# 解析和处理()

在接下来的部分中，我们将了解`parse_and_process()`方法的工作原理。值得注意的是，对于 CLI 版本，mode 变量的值为`c`，我们将只关注通向`mode=c`的代码部分。代码的其他分支将用于 GUI 模式，如果您想了解更多，可以自由阅读。

在第**(1)，(2)，(3)**和**(4)**节中的`parse_and_process()`方法开始执行，通过迭代`self.missed_services`和`self.processed_services`。这里的迭代思想是将这些发现的服务、主机、端口和`command_template`放入不同的数据库表`IPexploits`。我们将稍后讨论`command_template`。对于当前的示例，`self.processed_services`将包含以下数据：

```py
self.processed_services= {
"ssh":[[10.0.2.15,22,open,OpenSSH-7.2p2 Debian 5;10]],
"http":[[10.0.2.15,80,open,nginx-1.10.2],[10.0.2.15,8000,open,nginx-1.10.2]],
"rcpbind":[[10.0.2.15,111,open,-2-4,10]],
"https":[[10.0.2.15,443,open,nginx-1.10.2]],
}
self.missed_services ={
"rtsp":[[10.0.2.15,8002,open,-]]
}
```

这是因为除了`rtsp`之外，所有发现的服务都在 JSON 文件中映射了。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7d65d025-09fe-4937-b2d5-69cb6a2c2701.png)

代码的第**(5)**部分遍历此字典，并尝试获取诸如`getTemplate(k)`的内容，其中`k`是当前正在迭代的服务。`getTemplate()`是一个读取 JSON 文件并返回要执行的测试用例的命令 ID 的方法。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/71b39b2a-5e6e-4b57-9c5b-133b20b04f55.png)

以下示例将说明这一点。假设`getTemplate`在`http`上被调用，如`getTemplate('http')`。这将返回以下结构：

```py
entries= {"Entries": {"http_5": [true, "0", "0"], "http_trace_1": [true, "0", "0"], "http_trace_2": [true, "0", "0"], "http_trace_3": [true, "0", "0"], "http_banner_1": [true, "0", "0"], "http_banner_2": [true, "0", "0"], "http_robots_1": [true, "0", "0"], "http_robots_2": [true, "0", "0"], "http_headers_1": [true, "0", "0"], "http_headers_2": [true, "0", "0"], "http_methods_1": [true, "0", "0"], "http_methods_2": [true, "0", "0"], "http_web_dev_1": [true, "0", "0"], "http_web_dev_2": [true, "0", "0"]}}
```

结构如下：`{"http_5"：['include_command,commands_executed,results_obtained]}`。如果`http_5`是键，那么值是一个包含三个条目的列表。第一个条目表示命令是要包含还是执行（取决于所选择的扫描配置文件）。第二个条目保存在终端上执行的实际命令。最初它设置为 0，但一旦执行，`http_5`的`0`将被替换为`nmap -Pn --script=banner.nse -p 80 10.0.2.15`。第三个`0`实际上将被执行命令产生的结果所替换。

代码`entries=getTemplate(k)`将为每种服务类型返回一个类似上述的条目。我们准备一个名为`rows`的列表，其中放置主机、端口、服务、开/关状态和条目/`command_template`。执行该活动的代码片段是`self.rows.append((self.project_id, str(h_p[0]), str(h_p[1]), str(k), 'init', entries, service_status, str(h_p[2]), str(h_p[3])))`。

`type=new`的服务或未映射的服务将由代码部分**(2)**处理。这将在我们的示例条目中放置以下内容：

`entries={"Entries": {"new": true, "unknown": false}}`

代码部分**(6)**检查诸如`if(is_custom==True)`之类的内容。这意味着有一些服务可以与其他服务多次使用。例如，`ssl`的测试用例可以与`https`一起使用，如`[http +ssl]`，`ftps`作为`[ftp + ssl]`，`ssh`作为`[ssh + ssl]`。因此，诸如`https`，`ftps`等服务被标记为`custom`，当发现`https`时，我们应该加载`http`和`ssl`的两个模板。这就是在第**(6)**部分中所做的。

在第(6)部分结束时，`self.rows`将为所有主机和端口的所有服务类型保存类似`[project_id,host,port,service,project_status,command_template,service_type,port_state,version]`的条目。在我们当前的示例中，它将为所有服务类型保存六行。

在第**(7)**部分，`self.IPexploit.insertIPexploits(self.rows)`，我们一次性将`self.rows`的所有数据推送到后端数据库表`IPexploits`中。必须记住，后端数据库中`command_template/entries`的数据类型也标记为 JSON。因此，我们需要 MySQL 版本 5.7 或更高版本，支持 JSON 数据类型。

执行此命令后，我们当前项目`744`的后端数据库将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a7c5a600-cb6f-495c-a35f-04aa627ab35b.png)

必须注意的是，我没有加载`command_template`（在后端命名为`Exploits`），因为数据会变得混乱。让我们尝试加载两个服务的模板，如`rtsp`和`ssh`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cb545040-2968-4d87-815a-460221e76c30.png)

同样，我们还将有`http`，`ssl`和`rcpbind`的条目。应该注意的是，我们预计表中有六行，但实际上有七行。这是因为`https`服务被分为两类`http`和`ssl`，因此，在端口`443`上，我们不是有`https`，而是有两个条目：`http-443`和`ssl-443`。

在下一部分，项目的默认配置（主机、端口、要执行的测试用例）从同一数据库表中获取，并显示给用户。第八部分调用代码使用`launchConfiguration()`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5b5026d0-b02a-484b-929c-fa6bfa035ca2.png)

# launchConfiguration()

在这一节中，让我们来看一下`launchConfiguration()`方法，它加载默认配置，并且还允许用户进行微调或重新配置。此外，它调用了文件的中心逻辑，实际上会启动脚本执行，即`launchExploits()`。

对于 CLI 版本，`launchExploits()`是由`launchConfiguiration()`调用的。然而，在 GUI 版本中，`launchExploits()`只能由`parse_and_process()`方法调用。有关此方法的更多信息可以从前面的截图中看到。

以下代码片段的第 1 节加载了放置在当前项目的`IPexploits`表中的所有细节。我们已经看到了将被拉出并放置在`IPexploits`列表下的七行。请记住，在后端表中，我们只有命令 ID，例如`http_1`或`http_2`放在`Template`下，但是为了显示所选的配置和要执行的命令，我们拉出实际的脚本，它将映射到`http-1`等等。这就是第 2 节在做什么。它读取 JSON 文件以获取实际命令。

在第 3 节中，我们将拉取的细节放在`tab_draw`变量中，它将在控制台窗口上绘制一个表，并表示加载的配置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/990785c3-c2da-44ba-a39b-8c30e0a52216.png)

第 4 节是不言自明的；我们将所有拉取的细节放在一个名为`config_entry`的字典中。这将被保存到一个文件中，因为最终选择的配置与扫描将被启动：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d6554158-8c15-420d-9e66-d22d7e042f83.png)

最后，在第 6 节下，我们调用`launchExploits()`。如果需要执行重新配置，第 7 节调用`self.reconfigure()`方法，该方法很简单，可以从代码库或以下 URL <https://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/driver_meta.py> 中找到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6433c485-b025-4b3f-9c44-0434e0202025.png)

第 5 节将如下显示屏幕上的配置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c51bda78-c507-42b4-b873-91884245dc26.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fb31c123-1961-459a-ad79-f98169b64cdc.png)

# launchExploits()

接下来的部分将讨论`launchExploits()`方法。

以下代码的第 9 节加载了放置在当前项目的`IPexploits`表中的所有细节。我们已经看到了将被拉出并放置在`IPexploits_data`列表下的七行。我们不需要关注`if(concurrent=False)`的`else`块，因为那是指在 GUI 版本中调用的代码。现在，让我们只考虑`if`块，因为对于 CLI 版本，`concurrent=False`。接下来，我们遍历`IPexploits_data: "for exploit in IPexploits_data:"`结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d6763f0f-2643-46cd-aae9-d051b4138781.png)

在第 10 节中，我们从当前正在迭代的服务的 JSON 结构中加载细节。请记住，`self.commandsJSON`保存了整个 JSON 文件数据，我们在其中映射了服务和测试用例。然后，我们加载该特定服务的所有命令和测试用例，并将它们放在一个名为`meta`的列表下。例如，如果`service = http`，那么 meta 将包含`[http_1,http_2,http_3,http_4,http_5 ...]`。现在，请记住，在最后一节中，对于七条记录中的每条记录，`project_status`都是`init`。在下一行（第 11 节），我们将当前记录的`(host,port,service,record_id)`组合的状态更新为`processing`。因为我们已经选择了执行此服务，我们希望更改数据库状态。

在第 12 节中，我们加载了为项目选择的扫描配置所执行的特定服务用例的所有启用服务用例。

还有一些项目/扫描可能需要一些用户定义的参数，例如要使用的用户名、密码等。所有这些参数都放在一个`Project_params.json`文件中，第**(13)**节将要执行的命令中的项目特定用户名和密码替换为适用的项目特定用户名和密码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/041520fe-43b0-49b0-8a05-bbf48c712f04.png)

`Self.commandObj`保存了`auto_commands.pl`类的对象。第**(14)**节初始化了与要执行的当前记录集相关的类的实例变量（主机、端口、服务等）。正如我们之前讨论的，JSON 文件中的`args`参数包含要执行的实际命令。我们将`args`的值加载到程序变量 args 中。我们知道，这是一个包含命令的列表。我们遍历这个列表，并将诸如`<host>`之类的条目替换为要扫描的实际 IP，将`<port>`替换为要扫描的实际端口。我们将逐个为所有测试用例重复这个活动。对于当前示例，如果我们假设`http`是要扫描的当前服务，代码将遍历所有命令`[http_1,http_2..]`。最后，`http_5`和端口`80`的`final_args`列表将被指定为`[500, nmap -Pn --script=banner.nse -P80 10.0.2.5]`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e6ed344b-bd52-4367-a752-f63f7824bf31.png)

在第**(16)**节中，我们实际上是从`auto_comamnds.py`模块中调用适当的方法。让我们思考一下这是如何工作的。`getattr(object, name[, default])`返回`object`的命名属性的值。如果字符串是对象属性之一的名称，则结果是该属性的值。例如，`getattr(x,'Method_name')`等同于`x. Method_name`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b9c3517f-c4db-4c63-bc00-dfbb45d6796d.png)

正如我们已经讨论过的，要执行脚本/模块的方法的名称在 JSON 文件中预先配置，并且在前面的代码中它被读入变量方法。`func = getattr(self.commandObj,method_name)`将返回该方法的引用，并且可以被调用，比如`func(args)`。这就是第**(18)**节中所做的：`func(final_args,grep_commands)`。当执行该方法时，它将自动将结果保存在数据库中。一旦一个服务的所有测试用例都执行完毕，我们希望将该行的状态从`processing`更新为`complete`，这就是第**(20)**节所做的。相同的操作会重复，直到所有主机的所有发现的服务都被扫描。让我们看一下当执行一个测试用例时数据库表是什么样子的。我们将从不同的项目 ID 中取一些例子：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/36cb2886-81b8-4eb0-b265-0a256cb7a1c6.png)

从前面的屏幕截图可以看出，项目 ID 736 的这一行在服务扫描之前的数据如下：`Pid=736,Service='ssl',Exploits={"Entries" :{"ssl_1":[true,0,0]} ... }`。然而，一旦执行结束，第一个 0 将被一个包含执行的命令的列表所替换。第二个 0 的位置，我们有最终结果的字符串形式。

# 自动 _commands.py

在下一节中，我们将看一下实际工作的方式，即调用的方法如何自动化服务扫描的过程。我们将探索 Python 模块或文件`auto_commands.py`。必须记住，在本节中，我们将涵盖该类的基本方法。除此之外，还有一些其他方法是为特定用例定制的。您可以在 GitHub 存储库的确切代码文件中查看[<https://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/auto_commands.py>](http://%3Chttps://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/auto_commands.py%3E)。让我们首先看一下这个类是什么样子的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0fce252f-5930-4159-a26d-36ccbe015f1e.png)

我们导入的模块之一是**pexpect**。在接下来的部分中，让我们试着理解这个模块的作用以及它为什么重要。

# Pexpect

Pexpect 是一个类似 Unix 的 expect 库的 Python 模块。这个库的主要目的是自动化交互式控制台命令和实用程序。Pexpect 是一个纯 Python 模块，用于生成子应用程序、控制它们，并响应其输出中的预期模式。Pexpect 允许您的脚本生成子应用程序并控制它，就像一个人在键入命令一样。Pexpect 可用于自动化交互式应用程序，如 SSH、FTP、passwd、telnet 等。

我们将使用 Pexpect 来使用 Python 自动化 Metasploit，并且还将调用需要用户交互的终端自动化的各种用例。必须注意的是，还有另外两种用 Python 代码调用 Metasploit 的方法："msfrpc"，它调用了建立在 Metasploit 之上的服务 API，以及".rc"脚本。然而，我们观察到使用 Pexpect 模块的成功率最高。

Pexpect 模块有一个 spawn 类，用于生成任何终端命令、进程或工具。生成的工具应作为代码的子进程生成。

spawn 类构造函数的语法如下：

`pexpect.spawn(command, args=[], timeout=30, maxread=2000, searchwindowsize=None, logfile=None, cwd=None, env=None, ignore_sighup=False, echo=True, preexec_fn=None, encoding=None, codec_errors='strict', dimensions=None, use_poll=False)`

`spawn`类构造函数有许多参数，但强制参数是`command`。`command`是我们希望在 Unix 终端上执行的实际命令。如果我们希望传递参数给调用的命令，我们可以在命令本身中指定参数，用空格分隔，或者将参数作为 Python 列表传递到第二个参数`args`下。第三个参数是`timeout`，默认为 30 秒。这意味着如果在 30 秒内未生成进程，整个操作将被终止。如果我们的服务器负载很高，或者我们有性能问题，我们可以增加`timeout`参数。以下代码表示如何使用 Pexpect 调用 SSH 会话：

```py
child = pexpect.spawn('/usr/bin/ftp')
child = pexpect.spawn('/usr/bin/ssh user@example.com')
```

我们还可以使用参数列表构造它，如下所示：

```py
child = pexpect.spawn('/usr/bin/ftp', [])
child = pexpect.spawn('/usr/bin/ssh', ['user@example.com'])
```

当在终端上执行命令时，会创建一个会话，并通过返回的进程进行控制，该进程被放置在`child`变量下，如前面的示例所示。

`pexpect`的另一个重要类是`expect`。如其名称所示，Expect 规定了在成功执行`spawn`命令时可能产生的预期输出或输出。例如，如果`spawn`命令是`pexpect.spawn('/usr/bin/ssh',['user@example.com'])`，我们通常期望 ssh 服务器要求我们输入密码。从先前指定的命令中可能期望的所有可能模式或字符串都作为参数传递给`pexpect.expect`类，如果任何模式匹配，我们可以根据匹配定义要发送到终端的下一个命令。如果没有匹配，我们可以中止操作并尝试调试。

以下语法查找流，直到匹配模式。模式是重载的，可能有多种类型。模式可以是字符串类型、EOF、编译的正则表达式，或者是任何这些类型的列表：

`pexpect.expect(pattern, timeout=-1, searchwindowsize=-1, async_=False, **kw)`

如果传递了模式列表，并且有多个匹配项，则流中选择第一个匹配项。如果此时有多个模式匹配，则选择模式列表中最左边的模式。例如：

```py
# the input is 'foobar'
index = p.expect(['bar', 'foo', 'foobar'])
# returns 1('foo') even though 'foobar' is a "better" match
```

`child.sendLine(command)`是一个方法，它接受要发送到终端的命令，假设一切都按预期模式工作：

```py
child = pexpect.spawn('scp foo user@example.com:.')
child.expect('Password:')
child.sendline(mypassword)
```

让我们通过使用 Pexpect 进行 SSH 自动化的小例子来更清楚地说明问题：

```py
child = pexpect.spawn(ssh root@192.168.250.143)
i=child.expect(['.*Permission denied.*', 'root@.* password:.*','.* Connection refused','.*(yes/no).*',pexpect.TIMEOUT,'[#\$]',pexpect.EOF],timeout=15)
if(i==1):
       child.sendline('root')
       j=child.expect(['root@.* password:.*', '[#\$] ','Permission denied'],timeout=15)
       if(j==1):   
           self.print_Log( "Login Successful with password root")
       else:
           self.print_Log("No login with pw root")
```

在前面的代码中，我们只考虑成功的情况。必须注意，如果终端期望输入列表的第 1 个索引`'root@.* password:.'`，那么我们将使用`sendline`方法将密码作为 root 传递。注意`'root@.* password:.'`表示 root 后面的任何 IP 地址，因为它是一个正则表达式模式。根据匹配的字符串/正则表达式模式的索引，我们可以制定逻辑来指示接下来应该做什么。

# 自定义 _meta()

现在让我们来看一下`custom_meta`方法，它负责处理所有的 Metasploit 模块。它借助 Pexpect 库完成这一工作。

正如在以下片段的第**(1)**部分中所示，我们使用`pexpect.spawn`在我们的终端上调用`"msfconsole -q"`。这将在虚拟终端上调用一个 Metasploit 进程，并将该进程的控制返回给声明为 child 的变量：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3fab3c20-acfd-4dad-a8cf-27e946740955.png)

每当我们调用 msfconole 时，如果没有错误，我们将得到一个 Metasploit 提示符，如`msf>`。这就是我们在第**(2)**部分中指定的，[.*>, .., ..]，作为第 0 个索引。这里暗示的是，我们期望任何`>`之前的内容都能成功执行，因此我们将传递运行 Metasploit 模块所需的命令。如果 child.expect 返回的索引为 0，我们将遍历 JSON 文件的命令列表，并将每个命令发送到我们的 Metasploit 控制台。对于我们的 projectID `744`和`http`服务，我们配置了一些 Metasploit 模块。其中一个如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3641e7b9-2482-4cdc-b45f-a543895132bf.png)

在前面的 JSON 结构的`args`键中的任何内容都将作为列表传递给`custom_meta`方法，并存储在 commands 列表中。在第**(3)**部分，我们遍历 commands 列表，并且，正如我们之前学过的那样，`<host>`和`<port>`实际上将被实际主机和正在扫描的端口替换。

在这一部分中，每个命令都会使用`child.sendline(cmd)`命令逐个发送到 msfconsole 终端。发送每个命令后，我们需要检查控制台是否符合我们的预期，也就是说它应该包含`msf>`提示符。我们调用`pexpect.expect`并将`".*>"`指定为我们输入列表的第 0 个索引。注意，索引 0 定义了我们继续的成功标准。只要我们得到与索引 0 匹配的输出，我们就继续，如第**(4)**部分所指定的那样。如果我们在任何时候观察到除索引 0 之外的任何内容（超时或文件结束-EOF），我们意识到某些事情并没有按预期发生，因此我们将布尔变量设置为 false：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/235e44b2-6881-4aef-adc9-3194a695d5bc.png)

当我们退出这个迭代循环时，我们转到第**(9)**部分，检查 run == True。如果为真，我们假设所有参数都已正确设置以执行 Metasploit 模块。我们使用`sendline`发出`'run'`命令，如第**(10)**部分所示。

最后，如果一切顺利，模块成功执行，那么现在是收集结果的时候了。在第**(11)**部分，如果一切如预期那样进行，我们将在`exploits_results`变量中收集结果，并在`commands_launched`变量中收集命令。如果出现错误，我们将在第**(12)**部分中收集错误详情：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5fc5665f-f413-4ef1-88d2-aaa653010a87.png)

最后，在第**(14)**部分，我们通过调用`saveDetails()`方法将结果保存在数据库表中。必须注意，结果将以与之前讨论的相同的 JSON 结构保存在`"http_headers_2"`键下，这是脚本的 ID。`saveDetails`方法的定义如下。请注意，它将被应用于我们将讨论的所有不同方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3eb32e5f-a63e-4e35-a349-d65ce07842ac.png)

**（1）**部分调用了放置在类文件`IPexploits.py`中的方法，该方法将在数据库中插入详细信息。整个代码文件可以在 GitHub 存储库中找到。

# singleLineCommands_Timeout()

在本节中，我们将看到`singleLineCommands_Timeout`方法的定义。这部分代码解释了线程和多进程的强大之处。我们之前学习了所有概念，但在本节中，我们将看到如何应用线程和进程的概念来解决现实世界的问题。

手头的问题是执行所有可以通过在控制台上输入一行命令来执行的命令和脚本的所有类别。这些产生输出。这可能看起来很简单，但有一个问题。请记住，我们讨论过脚本的执行可能因为某些不可预见的原因而需要很长时间，我们应该设计我们的解决方案，以便所有可能出现这种情况的脚本类别都有一个关联的超时。在这里，我们将使用线程来实现超时功能。线程和进程的组合将帮助我们实现我们的目标。

核心思想是调用一个线程并将其绑定到一个方法"x"。我们在调用的线程上调用`join()`，`join()`的持续时间将是 JSON 文件中指定的超时时间。正如我们之前学过的，当从主线程'm'上的线程't'上调用`join()`方法时，将导致主线程'm'等待，直到't'完成其执行。如果我们在主线程'm'上的线程't'上调用`join(20)`，这将导致主线程'm'等待 20 秒，直到't'完成。20 秒后，主线程将继续执行并退出。我们可以使用相同的类比来实现我们的任务：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bf96f815-d45b-4934-b60f-b72e6c54bafb.png)

在**（1）**和**（2）**部分，我们正在创建一个`thread`对象，并将其附加到`"execute_singleLine"`方法。应该注意的是，有时我们希望从最终输出中提取出一些内容，这就是为什么我们要检查`grep`参数是否设置。如果设置了，我们将`grep`字符串作为参数发送到线程方法；否则，我们只发送方法应该调用的控制台脚本/命令。现在我们不需要担心 grep 条件。

在**（3）**部分，我们可以看到我们正在收集超时参数，该参数始终位于命令列表的索引 0 处，或者位于 JSON 文件的 args 的第 0 个索引处。我们在线程上调用 start 方法，该方法将调用`"execute_singleLine"`方法，并将要执行的命令作为参数传递。之后，我们在调用的线程上调用`join(timeout)`，代码将在那里暂停，直到超时指定的秒数为止。在**（3）**部分之后不会执行任何行，直到`"execute_singleLine"`方法完成或时间超过超时。在继续之前，让我们更仔细地看看`"execute_singleLine"`方法中发生了什么：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5ff0426b-08ff-46f1-bf48-998fd440d39e.png)

如`"execute_singleLine()"`方法的**（1）**部分所述，我们正在利用 Python 的 subprocess 模块来生成一个子进程。进程将由`cmd`变量中的命令指定。因此，如果`cmd`包含"`nmap -Pn --script=banner.nse -p 80 192.168.250.143`"，则相同的命令将在终端上执行，这只是操作系统级别的一个进程。进程类的实例将被返回并放置在`self.process`类变量下。该实例具有各种属性，如`"id"`，`"is_alive()"`等，这些属性给我们提供了有关进程状态的信息。

由于我们确定了传递给进程的参数（因为它们不是直接来自用户），我们可以继续进行。但是，最好使用`shell=False`并将参数指定为列表`[]`，或者使用 Python 的**shelx**实用程序自动将字符串参数转换为列表并使用`shell=False`。

我们希望父进程等待子进程执行，我们也希望子进程将其产生的所有数据返回给父进程。我们可以通过在调用的进程上调用`communicate()`来实现这一点。`communicate()`方法将返回一个元组，其中包含来自进程的输出的第 0 个索引和产生的错误的第一个索引。由于我们指定了`output=subprocess.PIPE`和`error=subprocess.PIPE`，输出和错误都将通过 OS 管道传输到父进程，这就是我们实现进程间通信的方式。这在第(2)部分中有所强调。

我们的下一个挑战是将控制台输出转换为标准的 ASCII 格式，以便我们可以将数据干净地保存在数据库中。需要注意的是，不同的工具和脚本以不同的格式和编码生成数据，这些格式和编码适合控制台显示。控制台支持各种编码，但我们需要将输出保存在数据库表中，因此在推送数据之前，我们需要将其从控制台编码转换为 ASCII 格式。这就是我们在第(3)部分所做的事情。

在第(4)部分中，我们通过调用`process = psutil.Process(self.process.pid).`来控制父进程。

在第(5)部分中，清理数据后，我们通过调用`saveDetails()`方法将执行的两个命令和生成的数据推送到数据库表中。

在第(3)部分之后，我们通过调用`thread.is_alive()`来检查线程是否仍然活动。如果返回`false`，这意味着线程已经成功在指定的时间内执行，通过内部调用`subprocess.Process`命令，并且详细信息也保存在数据库表中。但是，如果`thread.is_alive()`返回`true`，这意味着外部脚本仍在运行，因此我们需要强制将其终止，以免影响其他要执行的脚本的执行。请记住，调用的进程会将我们保存在`self.process`类变量下的进程实例返回给我们。我们将在这里使用该变量来终止进程。Python 有一个非常强大的实用程序叫做`"psutil"`，我们可以使用它来不仅终止进程，还可以终止该进程调用的所有子进程。我们还需要终止子进程，因为我们不希望它们在后台运行并消耗我们的 CPU。例如，诸如 Nikto 之类的工具会调用许多子进程来加快整个操作，我们希望终止所有这些进程，以确保父进程被终止并且所有系统资源都被释放供其他进程使用。一旦我们获取了父进程，我们使用`for`循环迭代其每个子进程，`for proc in process.children(recursive=True):`，并通过发出命令`proc.kill()`来终止每个子进程。这在第(5)部分中有所强调。最后，在第(6)部分，我们通过调用`self.process.kill()`确保终止父进程。

# general_interactive()

在这一部分，我们将了解`general_interactive()`方法的工作原理。虽然我们也可以使用这种方法实现 Metasploit 命令，但为了保持类别的分离，我们单独实现了 Metasploit。

`general_interactive`的目标是自动化交互式工具和 Bash 命令。这意味着 JSON 文件包含了定义执行工作流程的成功模式和失败模式。我们将使用 Pexpect 来实现这一点，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1fac8b47-a996-4614-84aa-b76504f92684.png)

让我们通过进行干运行来更仔细地研究这个方法，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6d93bb4e-20d8-43b1-a924-453ff53dd525.png)

正如我们在`args[]`中看到的，第一个参数是超时时间。第二个索引保存我们希望使用一般交互方法自动化的命令。对于这个类别，第一个参数将始终是`超时时间`，第二个参数将是要执行的命令。从这里开始，定义了一个交替模式。第三个索引将保存预期输出列表和成功标准。如果满足成功标准，第四个索引将保存要发送到控制台的下一个命令。第五个索引将再次保存基于第四个索引发送的命令的预期输出列表，并且它还保存成功标准。模式很简单，根据我们计划自动化的底层命令或工具所需的，同样的交替序列将继续进行。

成功标准在预期输出列表的第一个索引处定义。如果有多个成功结果或索引，它们可以作为逗号分隔的输入给出在第一个索引处。让我们以`rlogin`的上述示例为例，我们正在尝试使用 root 作为用户名和密码进行远程登录，并尝试理解预期输出列表的内容和意义。索引 3 处的列表包含`['0,1','.* password: .*","[$,#]",".*No route.*"]`。在这里，第 0 个索引“0,1”定义了成功标准。这意味着如果终端期望`".* password: .*"`或`"[$,#]"`中的任何一个，我们就假设输出符合预期，因此我们将下一个命令发送到控制台，这在我们的情况下是`"root"`。如果我们得到的不是索引 0 或 1，我们就假设工具或脚本的行为不符合预期，因此中止操作。

要配置属于此类别的命令和脚本，测试人员需要知道脚本在成功和失败条件下的执行方式，并制定配置文件。前面的代码很简单，实现了我们之前讨论的相同逻辑。

# generalCommands_Tout_Sniff()

这里的想法类似于我们如何使用线程实现`singleLineComamnd()`方法。请注意，要执行的命令的类别要么是`interactive`，要么是`"singleLineCommand_Timeout"`，还有一个嗅探操作。我们将创建一个线程，并将嗅探任务委托给它，通过将它附加到`start_sniffing`方法。我们还将重用我们之前创建的方法。我们要么按照**(1)**指定的方式调用`singleLineCommands_Timeout()`，要么按照**(2)**指定的方式调用`general_interactive()`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b39b5a7b-b670-4897-92de-138e071f5b3a.png)

在第**(3)**和**(4)**节中，我们检查嗅探进程是否仍然存活，如果是，则将其终止：

```py
start_sniffing()
```

我们通常使用 Wireshark 来捕获接口上的所有流量。然而，由于 Wireshark 是一个桌面应用程序，在这种情况下，我们将使用**Tshark**。Tshark 代表终端 shark，是 Wireshark 的 CLI 版本。Tshark 调用命令在第(2)部分中指定，我们指定要嗅探流量的端口。我们还指定需要嗅探流量的主机，或目标主机。我们指定主机和端口的原因是我们想要保持结果的完整性；工具的 GUI 版本可以部署在服务器上，并且多个用户可以使用它进行扫描。如果我们指定它应该在接口上嗅探，那么其他用户的其他运行会话的数据也会被嗅探。为了避免这种情况，我们对主机和端口非常具体。我们还指定了它嗅探的超时持续时间。我们将输出保存在指定的文件中`"project_id_host_port_capture-output.pcap"`。

在第(2)部分，我们使用子进程模块调用`tshark`进程，这是我们之前讨论过的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/43e571c8-2181-4798-8e4c-485f7364060e.png)

# HTTP_based()

以下的`http_based`方法很简单。我们使用 Python 的请求库向目标发送 GET 请求，捕获响应，并将其保存在数据库中。目前，我们只是发送 GET 请求，但您可以在自己的时间内调整代码以处理 GET 和 POST。我们将在下一章节中更多地介绍 Python 请求和抓取：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f1f98ec6-8bd3-4733-8eba-a9dec6238b73.png)

# IPexploits.py

服务扫描引擎的数据库层处理另一个重要的代码文件是`IPexploits.py`。这个文件很简单；它包含各种方法，每个方法的目的要么是从数据库表中获取数据，要么是将数据放入数据库表中。我们不会在这里讨论这个模块，但我建议你看一下可以在 GitHub 存储库[`github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/IPexploits.py`](https://github.com/FurqanKhan1/Dictator/blob/master/Dictator_service/IPexploits.py)找到的代码。

# 执行代码

在执行代码之前，请仔细参考 GitHub 存储库[`github.com/FurqanKhan1/Dictator/wiki`](https://github.com/FurqanKhan1/Dictator/wiki)中的安装和设置说明。安装指南还讨论了如何设置后端数据库和表。或者，您可以下载预先安装和预配置了所有内容的即插即用的虚拟机。

要运行代码，请转到以下路径：`/root/Django_project/Dictator/Dictator_Service`。运行代码文件`driver_main_class.py`，如`:python Driver_scanner.py`。必须注意的是，结果是使用 Python 库生成的，该库将控制台输出转换为其 HTML 等效。更多细节可以在以下代码文件[`github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python`](https://github.com/PacktPublishing/Hands-On-Penetration-Testing-with-Python)的`generate_results()`方法中找到。

# 漏洞扫描器的服务扫描部分的数据库模式

要扫描服务扫描的扫描结果，请转到 IPexploits 表，其模式如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/330d9b69-af86-4e96-86d5-d4d3c968b98b.png)

# 漏洞扫描器的 GUI 版本

先前讨论的相同代码库可以进行增强，以开发一个基于 Web 的漏洞扫描仪版本，具有端口扫描和服务扫描功能。该工具具有许多不同的功能，包括四层架构，其中包括 Web 层呈现、Web 层服务器、API 层和 DB 层。从 GitHub 存储库[`github.com/FurqanKhan1/Dictator/wiki`](https://github.com/FurqanKhan1/Dictator/wiki)下载并安装工具的 Web 版本。或者，您可以使用即插即用的虚拟机，只需登录并在`https://127.0.0.1:8888`上打开浏览器即可访问该工具。

扫描仪 GUI 版本的各种功能包括以下内容：

+   并行端口扫描

+   暂停和恢复端口扫描

+   服务扫描

+   所有测试用例自动化

+   暂停和恢复服务扫描 **（不在 CLI 中）**

+   并行服务扫描 **（不在 CLI 中）**

+   Nmap 报告上传和解析 Qualys 和 Nessus 报告

# 使用[PTO-GUI]

以下部分将介绍扫描仪的 GUI 版本的用法。

# 扫描模块

基于正在进行的基础设施上的扫描类型和性质，渗透测试人员有多种可用选项，并且可以选择最适合被测试基础设施的选项。可用的各种使用模式在以下部分中进行了介绍。

# 顺序模式

在顺序模式中，工具将从发现开始，然后重新配置，然后开始服务扫描。因此，这是一个三步过程。请注意，在顺序模式中

+   在所有主机都被扫描之前，无法开始服务扫描

+   一旦服务扫描开始，就无法重新配置

+   一旦开始服务扫描，所有服务都将开始扫描。用户无法控制先扫描哪个服务，后扫描哪个服务

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d1de7f0a-49fd-4838-bc8b-9988831c945b.jpg)

# 发现完成后重新配置

为了减少误报和漏报，请分析端口扫描结果，如果需要，重新配置/更改它们。如果有任何服务/端口被遗漏，您还可以额外添加测试用例。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/be48f0bc-0324-4267-9356-5722ec6de546.jpg)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b05d1ad9-b8a4-4aab-bc9b-0a19cf078f4e.jpg)

在上述截图中，我们将类型为**状态**的服务更改为`ftp`类型。因此，测试用例将为`ftp`运行。注意：只有在确定发现的服务不正确或类型为`Unknown`时才这样做。我们将很快了解服务类型。

如果 nmap 错过了主机/端口/服务，可以手动添加，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/676cb125-e46d-41fa-9f82-2aed49201424.jpg)

添加测试用例后，我们可以点击“开始扫描”选项开始服务扫描。我们可以选择启用线程选项以加快结果的速度，也可以选择不使用线程选项开始服务扫描，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/881bab84-8099-4e57-b6c7-89dc7dbf2044.jpg)

查看中间结果：当用户点击“开始扫描”时，他/她将被重定向到扫描页面。每次执行一个测试用例，UI 都会更新，并且一个蓝色的图标会出现在正在扫描的服务前面的屏幕上。用户可以点击该图标查看测试用例的结果。

当服务的所有“测试用例”都被执行时，图标将变为绿色。

以下图显示了中间测试用例的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4d10429a-985d-431a-b473-8368da06b74d.jpg)

在任何时候，用户都可以离开 UI 而不会影响正在运行的扫描。如果用户希望查看当前正在运行的扫描，可以从顶部的“扫描状态”选项卡中选择正在运行的扫描。将显示以下屏幕：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a388638e-aa90-4bf1-aed4-c3c759ecc6f8.jpg)

根据扫描的状态，它将显示适当的操作。如果扫描正在进行中，**操作**列将显示**进行中**。用户可以点击此按钮以获取其扫描当前状态的 UI 屏幕。

用户可以点击扫描名称以查看扫描最初启动时的配置（主机、端口、开关）。

# 并发模式

在顺序模式中，直到所有端口的端口扫描结果可用并且主机已经扫描完毕，服务扫描才能开始。因此，渗透测试人员可能需要等待获取这些结果。此外，在此模式下，渗透测试人员无法控制哪些服务可以先扫描，哪些可以稍后扫描。所有服务将一次性扫描，限制了对服务扫描的控制粒度。这些是并发模式处理的顺序模式的限制。

并发模式提供了在服务发现完成后立即启动服务扫描的灵活性，并进一步提供了根据渗透测试人员选择启动选择性服务扫描的选项。

1.  点击**扫描**选项卡下的**新扫描**选项卡。

1.  填写扫描参数，并选择**并发**扫描模式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c7ceb7a8-e9ed-4348-9ac1-c1d080a592e9.jpg)

1.  其余步骤将相同，唯一的例外是在此扫描模式中，用户无需等待所有主机和端口都被扫描才能开始服务扫描。此外，用户可以选择希望扫描哪些服务。如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a66c7363-483b-4e59-8cb4-2693bb49781e.jpg)

如前面的屏幕截图所示，用户可以选择先扫描`http`，而不立即扫描 ssh。用户可以决定何时扫描哪项服务。

并发模式也具有重新配置、查看结果等所有功能。

# 顺序默认模式

使用此模式，服务扫描将在发现完成后立即开始，从而跳过重新配置阶段。此模式的实用性在于调度扫描的情况下更为相关，渗透测试人员可以安排扫描在其他时间开始，并且可能无法进行重新配置，同时希望继续使用默认的端口扫描结果进行服务扫描。因此，此扫描模式跳过重新配置阶段，并在获取默认的`nmap`端口扫描结果后直接启动服务扫描。

1.  点击**扫描**选项卡下的**新扫描**选项卡

1.  填写扫描参数，并选择**顺序默认**扫描模式

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2e095c26-7b94-439c-966d-6b2b8a12dc1f.jpg)

当端口扫描结果完成后，它将自行开始服务扫描，无论用户当前是否已登录。

# 暂停和恢复扫描

无论扫描模式如何，任何处于发现或服务扫描状态的扫描都可以暂停。中间结果将被保存，用户可以随时在将来恢复扫描。

必须注意，如果在发现过程中暂停扫描（端口扫描可能正在进行），则已经扫描的端口的端口扫描结果将被保存；用户恢复后，将对未扫描的端口进行扫描。同样，如果在服务扫描过程中暂停扫描，则已经扫描的服务的结果将被保存，用户可以灵活分析将要扫描的服务的结果。扫描恢复后，将对未扫描的服务进行服务扫描。

以下屏幕截图显示了如何暂停正在进行的扫描：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b85ec9f7-aecf-4e07-b8eb-fd8ee0b2dc63.jpg)

要恢复扫描，可以转到**当前扫描**选项卡或**暂停的扫描**选项卡。默认情况下，操作列会有两个按钮：

+   **恢复**：这将从暂停的状态恢复扫描。

+   **分析**：如果扫描在扫描时暂停，渗透测试人员可以分析已经扫描的服务的结果。如果您希望恢复扫描，那么他/她可以选择分析选项。通过这个选项，用户可以看到已完成服务的中间测试用例结果。

如果扫描在端口扫描期间暂停，分析选项可能不会出现，因为如果端口扫描正在进行并且模式不是并发的话，就不会执行`test_cases`来分析。**分析**选项不会出现在并发扫描中，**恢复**按钮将执行并发模式中的恢复和分析扫描的联合功能。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1746627a-0a38-4ff6-bd94-4d17adbd9538.jpg)

# 下载报告或分析扫描何时完成

当扫描完成时，用户将在 UI 上获得**全部下载**的选项。如果用户访问**当前扫描**选项卡，对于所有发现和服务扫描状态为**完成**的扫描，**操作**列将默认具有下载结果的选项，以进行离线分析或在线分析结果，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/45cb5b5b-e634-4eb1-83df-a1c473c50050.jpg)

点击**全部下载**，将下载一个压缩文件夹。它将包括：

+   包含所有测试用例结果的最终 HTML 报告。

+   Pcap 文件可以嗅探需要嗅探的某些服务。Pcap 文件可以用 Wireshark 打开并分析文本/凭据是以明文还是加密格式传递的。注意：Pcap 文件的名称将类似于`<project_id>_capture_output.pcap`。因此，如果在`host1`上对端口`21`和项目 ID`100`进行嗅探，Pcap 文件名称将是`100_host1_21_capture_output.pcap`。

+   下载的文件夹还将包含最终选择的配置（服务-测试用例），用于启动扫描（JSON 格式）

+   另一方面，点击**分析测试**将带我们到用户界面，我们可以在那里看到所有`test_cases`的结果。

# 报告

要上传 Nmap 报告，请转到**上传报告**并选择 Nmap 报告。这是一个结果导入模块，可以读取现有的`Nmap.xml`报告文件中的结果，并将这些发现导入到我们的自定义数据库中，并进一步使用这些发现来启动测试用例/服务扫描。因此，这使用户可以在两种模式下使用我们的工具：

+   发现和服务扫描一起

+   仅服务扫描模式

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4c6d5b56-57cf-432b-b886-c535305a0e6f.jpg)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a18ad171-8f38-4d72-831a-51f19028cc01.jpg)

点击**上传**，报告将被解析和上传。用户可以转到**当前扫描**选项卡，会发现已上传的项目`test_upload_nmap`列在那里，其**发现状态**为**完成**，**服务扫描**状态为**未完成**。用户可以点击**操作**选项卡**进行中**，重新配置结果，然后开始服务扫描。

+   Qualys 和 Nessus 报告解析器

要使用此选项，请转到**上传报告**选项卡，并选择**Qualys**/**Nessus**报告。我们有一个报告合并模块，可以合并从 Qualys、Nessus 和手动测试用例获得的结果。为了合并报告，它们必须首先被解析。我们有 Qualys、Nmap 和 Nessus 报告解析器。它们都将以 XML 格式接收报告，并解析报告并将其放置在本地存储中，以便查询和将结果与其他报告集成变得更容易：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/46df89e3-7ade-4543-bf82-9b8c604d177e.jpg)

在这里上传报告的目的是将其与某个手动项目合并。因此，从下拉列表中选择要将 Nessus/Qualys 报告合并的项目。

+   报告合并：

要使用此选项，请转到**合并报告**选项卡，并选择您希望将 Qualys 和 Nessus 结果集成的手动项目的**ID**/**名称**。

它假定 Nessus 和 Qualys 报告已经被上传并链接到它们应该合并的项目。

该模块合并了手动测试用例、解析的 Qualys 报告、解析的 Nessus 报告，并将 CVE 映射到利用，最后，将为用户提供下载集成报告的选项，格式包括（XML、HTML、CSV、JSON），从而提供一个统一的分析视图。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/34d668d7-9fa8-4f84-b7c1-01476bfd893a.jpg)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f393784d-9279-4b0a-ab86-b6ae5119e0bb.jpg)

最终可下载的报告有四种格式（HTML、CSV、JSON、XML）。

合并报告将根据 Nessus/Qualys 和手动测试用例中发现的共同结果进行合并。它将共同的主机和端口聚合到一组中，以便分析变得更容易。

# 摘要

在本章中，我们讨论了如何使用各种 Python 模块来实现服务扫描自动化的任务。我们还研究了如何使用线程和多进程的组合来解决现实世界的问题。本章讨论的所有概念在前几章中都有所提及。通过本章的学习，读者应该对 Python 在网络安全领域有多么强大以及我们如何使用它来创建自己的扫描器有了很好的理解。我们还在 GUI 模式下概述了漏洞扫描器。

在下一章中，我们将看到如何使用机器学习和自然语言处理来自动化渗透测试阶段的手动报告分析。

# 问题

1.  为什么我们不使用 msfrpc 来自动化 Metasploit？

1.  我们可能还可以做些什么来进一步优化吞吐量？

1.  使用 JSON 文件是强制性的吗？我们可以使用数据库吗？

1.  我们还可以将哪些其他工具与扫描仪集成？

# 进一步阅读

+   Python-nmap 0.6.1：[`pypi.org/project/python-nmap/`](https://pypi.org/project/python-nmap/)

+   从 Python 使用 nmap：[`xael.org/pages/python-nmap-en.html`](https://xael.org/pages/python-nmap-en.html)

+   JSON 编码器和解码器：[`docs.python.org/2/library/json.html`](https://docs.python.org/2/library/json.html)


# 第七章：机器学习和网络安全

如今，**机器学习**（**ML**）是一个我们经常遇到的术语。在本章中，我们将概述机器学习的确切含义，它解决的问题类型，以及它在网络安全生态系统中的应用类型。我们还将研究各种不同类型的机器学习模型，以及在哪些情况下可以使用哪些模型。值得注意的是，本书的范围不是详细介绍机器学习，而是提供对机器学习及其在网络安全领域的应用的扎实理解。

本章将详细介绍以下主题：

+   机器学习

+   基于回归的机器学习模型

+   分类模型

+   自然语言处理

# 机器学习

让我们从一个基本问题开始：*什么是机器学习，为什么我们要使用它？*

我们可以将机器学习定义为数据科学的一个分支，可以有效解决预测问题。假设我们有过去三个月电子商务网站客户的数据，数据包含特定产品的购买历史（`c_id`，`p_id`，`age`，`gender`，`nationality`，`purchased[yes/no]`）。

我们的目标是利用数据集来识别可能购买产品的客户，基于他们的购买历史。我们可能认为一个好主意是考虑购买列，并假设那些先前购买产品的人最有可能再次购买。然而，一个更好的业务解决方案将考虑所有参数，包括发生最多购买的地区，客户的年龄组和性别等。基于所有这些领域的排列，业务所有者可以更好地了解受产品影响最大的客户类型，因此营销团队可以设计更具体、有针对性的活动。

我们可以通过两种不同的方式来做到这一点。第一种解决方案是使用我们选择的编程语言编写软件，并编写逻辑，给每个讨论的参数赋予特定的权重。然后逻辑将能够告诉我们所有潜在的买家是谁。然而，这种方法的缺点是需要大量时间来起草逻辑，如果添加了新的参数（例如客户的职业），逻辑将需要更改。此外，编写的逻辑只能解决一个特定的业务问题。这是在机器学习开发之前采用的传统方法，目前仍被各种企业使用。

第二种解决方案是使用机器学习。基于客户数据集，我们可以训练一个机器学习模型，并让其预测客户是否是潜在的买家。训练模型涉及将所有训练数据提供给一个机器学习库，该库将考虑所有参数并学习购买产品的客户的共同属性，以及未购买产品的客户的属性。模型学到的内容将被保存在内存中，获得的模型被称为经过训练的。如果模型被提供新客户的数据，它将使用其训练并基于学到的通常导致购买的属性进行预测。以前必须用计算机程序和硬编码逻辑解决的同样的业务问题现在用数学机器学习模型解决。这是我们可以使用机器学习的许多案例之一。

重要的是要记住，如果手头的问题是一个预测问题，机器学习可以应用来获得良好的预测。然而，如果问题的目标是自动化手动任务，机器学习将无济于事；我们需要使用传统的编程方法。机器学习通过使用数学模型来解决预测问题。

**人工智能**（**AI**）是另一个我们经常会遇到的词。现在让我们试着回答另一个问题：**什么是人工智能，它和机器学习有什么不同？**

# 在 Kali Linux 中设置机器学习环境

所有的机器学习库都打包在一个叫做`anaconda`的包中。这将安装 Python 3.5 或最新版本的 Python。要运行机器学习代码，我们需要 Python 3 或更高版本：

1.  从以下网址下载 anaconda：[`conda.io/miniconda.html`](https://conda.io/miniconda.html)。

1.  通过运行`bash Anaconda-latest-Linux-x86_64.sh.>`来安装所有的包。

1.  有关更多详细信息，请参考以下网址：[`conda.io/docs/user-guide/install/linux.html`](https://conda.io/docs/user-guide/install/linux.html)。

# 基于回归的机器学习模型

当我们需要预测连续值而不是离散值时，我们使用回归模型。例如，假设数据集包含员工的工作经验年限和工资。基于这两个值，这个模型被训练并期望根据他们的*工作经验年限*来预测员工的工资。由于工资是一个连续的数字，我们可以使用基于回归的机器学习模型来解决这种问题。

我们将讨论的各种回归模型如下：

+   简单线性回归

+   多元线性回归

+   多项式回归

+   支持向量回归

+   决策树回归

+   随机森林回归

# 简单线性回归

**简单线性回归**（**SLR**）对线性数据进行特征缩放，如果需要的话。**特征缩放**是一种用来平衡各种属性影响的方法。所有的机器学习模型都是数学性质的，所以在用数据训练模型之前，我们需要应用一些步骤来确保所做的预测不会有偏差。

例如，如果数据集包含三个属性（`age`，`salary`，和`item_purchased[0/1]`），我们作为人类知道，可能会去商店的年龄段在 10 到 70 之间，工资可能在 10,000 到 100,000 或更高之间。在进行预测时，我们希望同时考虑这两个参数，知道哪个年龄段的人在什么工资水平下最有可能购买产品。然而，如果我们在不将年龄和工资缩放到相同水平的情况下训练模型，工资的值会因为它们之间的巨大数值差异而掩盖年龄的影响。为了确保这种情况不会发生，我们对数据集应用特征缩放来平衡它们。

另一个必需的步骤是数据编码，使用**独热编码器**。例如，如果数据集有一个`国家`属性，这是一个分类值，假设有三个类别：俄罗斯、美国和英国。这些词对数学模型来说没有意义。使用独热编码器，我们将数据集转换成（`id`，`age`，`salary`，`Russia`，`UK`，`USA`，`item_purchased`）。现在，所有购买产品并来自俄罗斯的顾客在名为俄罗斯的列下会有数字 1，在美国和英国的列下会有数字 0。

举个例子，假设数据最初如下所示：

| **ID** | **国家** | **年龄** | **工资** | **购买** |
| --- | --- | --- | --- | --- |
| 1 | 美国 | 32 | 70 K | 1 |
| 2 | 俄罗斯 | 26 | 40 K | 1 |
| 3 | 英国 | 32 | 80 K | 0 |

进行数据转换后，我们会得到以下数据集：

| **ID** | **俄罗斯** | **美国** | **英国** | **年龄** | **工资** | **购买** |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 0 | 1 | - | 0.5 | 0.7 | 1 |
| 2 | 1 | 0 | 0 | 0.4 | 0.4 | 1 |
| 3 | 0 | 0 | 1 | 0.5 | 0.8 | 0 |

可以看到得到的数据集是纯数学的，所以我们现在可以把它交给我们的回归模型来学习，然后进行预测。

需要注意的是，帮助进行预测的输入变量被称为自变量。在前面的例子中，`country`、`age`和`salary`是自变量。定义预测的输出变量被称为因变量，在我们的例子中是`Purchased`列。

# 回归模型如何工作？

我们的目标是在数据集上训练一个机器学习模型，然后要求模型进行预测，以确定应根据员工的工作经验给予的薪资。

我们考虑的例子是基于 Excel 表的。基本上，我们有一家公司的数据，其中薪资结构是基于工作经验年限的。我们希望我们的机器学习模型能够推导出工作经验年限和给定薪资之间的相关性。根据推导出的相关性，我们希望模型能够提供未来的预测并指定建模薪资。机器通过简单线性回归来实现这一点。在简单线性回归中，通过给定的散点数据绘制各种线条（趋势线）。趋势线的理念是它应该最佳拟合（穿过）所有的散点数据。之后，通过计算建模差异来选择最佳的趋势线。这可以进一步解释如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4065a88b-4f56-47b7-8862-add0c9322521.png)

继续使用相同的例子，让我们以员工“e”为例，他在实际工作中拥有 10 年的经验，薪资为 100,000。然而，根据模型，员工实际上应该获得的薪资要低一些，如绿色`+`所示，绿色`+`下方的线实际上低于组织所遵循的线（建模薪资）。绿色虚线表示实际薪资和建模薪资之间的差异（约 80K）。它由*yi -yi^*给出，其中*yi*是实际薪资，*yi^*是模式。

SLR 通过数据绘制所有可能的趋势线，然后计算整条线的*（y-y^）*²*的和。然后找到计算平方的最小值。具有最小平方和的线被认为是最适合数据的线。这种方法称为**最小二乘法**或**欧几里得距离法**。最小二乘法是一种数学回归分析方法，它为数据集找到最佳拟合线，提供了数据点之间关系的可视化演示。

以下屏幕截图表示回归模型绘制的各种预测线：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c2866745-289f-447b-9c1a-6605e57a305b.png)

基于平方和方法，选择了最佳拟合线，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/59bca6d8-6d99-404d-8429-e775a15af39e.png)

基本上，绘制的数据点不在一条直线上，而是在直线的两侧对称绘制，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f05273ca-db2c-4379-a092-95e7ed7a331f.png)

以下部分代表了实现 SLR 的代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/625a4c93-18bf-4808-89c7-8de1604e1995.png)

# 多元线性回归

SLR 适用于具有一个自变量和一个因变量的数据集。它在*XY*维度空间中绘制两者，根据数据集绘制趋势线，最后通过选择最佳拟合线进行预测。然而，现在我们需要考虑的是如果因变量的数量超过*一个*会发生什么。这就是多元线性回归出现的地方。**多元线性回归**（**MLR**）使用多个自变量并在 n 维空间中绘制它们以进行预测。

我们现在将处理一个包含与 50 家初创公司相关信息的不同数据集。数据基本上包括公司在各种垂直领域（如研发、行政和营销）上的支出。它还指示了公司所在的州以及每个垂直领域的净利润。显然，利润是因变量，其他因素是自变量。

在这里，我们将从投资者的角度进行分析，他想要分析各种参数，并预测应该在哪些垂直领域投入更多的收入，并在哪个州，以最大化利润。例如，可能有一些州在其中更多地投入研发会带来更好的结果，或者其他一些州在其中更多地投入营销更有利可图。该模型应该能够预测应该投资哪些垂直领域，如下所示：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f49826c0-9324-4325-a2e5-5da36f4187d5.png)

鉴于我们有多个自变量，如下所示，对于我们来说，识别哪些是实际有用的，哪些是无用的也很重要：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/82204bed-9eeb-48f0-b68f-04c601b37613.png)

虽然一些自变量可能会对最终的因变量产生影响，但其他一些可能不会。为了提高模型的准确性，我们必须消除对因变量影响较小的所有变量。有五种方法可以消除这些变量，如下图所示，但最可靠的是**向后消除**： 

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/38446cdc-c2a3-44bf-9cbd-ea35b7243dae.png)

向后消除的工作原理如下所示：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/35ac9100-ec27-4f8e-a22f-9adfd8722ff8.png)

我们在前面的方法中所说的显著水平是指能够表明正在检查的变量对因变量或最终预测至关重要的最低阈值值。

**P 值**是确定因变量和自变量之间关系是否随机的概率。对于任何给定的变量，如果计算得到的 P 值等于 0.9，这将表明该自变量与最终因变量之间的关系是 90%随机的，因此对自变量的任何改变可能不会直接影响因变量。另一方面，如果另一个变量的 P 值为 0.1，这意味着该变量与因变量之间的关系并非是随机的，对该变量的改变将直接影响输出。

我们应该从分析数据集开始，找出对预测有重要意义的自变量。我们必须只在这些变量上训练我们的数据模型。以下代码片段表示了向后消除的实现，这将让我们了解哪些变量应该被排除，哪些应该被保留：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/035d5bc5-1d47-4097-bfc1-2c07b2c491d1.png)

以下是前面代码片段中使用的主要函数的解释：

+   `X[:,[0,1,2,3,4,5]]`表示我们将所有行和从 90 到 5 的所有列传递给向后消除函数

+   `sm.OLS`是一个内部 Python 库，用于 P 值计算

+   `regressor_OLS.summary()`将在控制台上显示一个摘要，帮助我们决定哪些数据变量要保留，哪些要排除

在下面的示例中，我们正在对所有变量进行模型训练。但是建议使用之前获得的`X_Modeled`，而不是`X`：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8d93203b-2aed-462a-a4cc-539647e36472.png)

在 MLR 中，应该注意的是，预测也是基于最佳拟合线进行的，但在这种情况下，最佳拟合线是在多个维度上绘制的。以下屏幕截图给出了数据集在 n 维空间中的绘制方式：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/83debebc-309c-4c0a-9bad-1bf7706ccca2.png)

还有其他各种回归模型适用于其他类型的数据集，但涵盖它们都超出了本书的范围。然而，提到的两个模型应该让我们了解回归模型的工作原理。在下一节中，我们将讨论**分类模型**。我们将更详细地研究一个分类模型，并看看我们如何在自然语言处理中使用它来应用 ML 在渗透测试生态系统中。

# 分类模型

与回归模型不同，回归模型预测连续数字，分类模型用于预测给定类别列表中的类别。之前讨论的业务问题，我们在过去三个月内有关电子商务网站客户的数据，其中包含特定产品的购买历史（`c_id`，`p_id`，`age`，`gender`，`nationality`，`salary`，`purchased[yes/no]`）。我们的目标与之前一样，是根据他们的购买历史来识别可能购买产品的客户。根据所有独立变量（`age`，`gender`，`nationality`，`salary`）的排列组合，分类模型可以进行 1 和 0 的预测，1 表示给定客户将购买产品的预测，0 表示他们不会。在这种情况下，有两个类别（0 和 1）。然而，根据业务问题，输出类别的数量可能会有所不同。常用的不同分类模型如下所示：

+   朴素贝叶斯

+   逻辑回归

+   K 最近邻

+   支持向量机

+   核 SVM

+   决策树分类器

+   随机森林分类器

# 朴素贝叶斯分类器

让我们尝试通过朴素贝叶斯分类器来理解分类模型的工作原理。为了理解朴素贝叶斯分类器，我们需要理解贝叶斯定理。贝叶斯定理是我们在概率中学习的定理，并可以通过一个例子来解释。

假设我们有两台机器，两台机器都生产扳手。扳手上标有生产它们的机器。M1 是机器 1 的标签，M2 是机器 2 的标签。

假设有一个扳手是有缺陷的，我们想找到有缺陷的扳手是由机器 2 生产的概率。提供 B 已经发生的情况下 A 发生的概率由朴素贝叶斯定理确定。因此，我们使用贝叶斯定理如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/df7a805a-b276-42e2-993c-e7896f01041a.png)

+   P(A)代表事件发生的概率。

+   p(B/A)代表 A 发生的情况下 B 发生的概率。

+   P(B)代表 B 发生的概率。

+   p(A/B)代表 B 发生的情况下 A 发生的概率（假设 B 已经发生的情况下 A 发生的概率）。

+   如果我们用概率来表示数据，我们得到以下结果：

| ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b12e6835-1d4d-4e64-b138-5c5c9ac71843.png) | ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5cdc2f99-b110-44d9-81cd-a87f6fc44aae.png) |
| --- | --- |

假设我们有一个人的数据集，有些人步行上班，有些人开车上班，这取决于他们所属的年龄类别：

| ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f0956274-0f90-4867-a8f2-4dd7a3523508.png) |                     ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7afadd61-6a01-4735-8e3f-114e18432885.png) |
| --- | --- |

如果添加了一个新的数据点，我们应该能够判断那个人是开车上班还是步行上班。这是监督学习；我们正在对数据集进行机器训练，并从中得出一个学习模型。我们将应用贝叶斯定理来确定新数据点属于步行类别和驾驶类别的概率。

为了计算新数据点属于步行类别的概率，我们计算*P(Walk/X)*。这里，*X*代表给定人的特征，包括他们的年龄和工资：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/21e1f515-fb99-4bc9-b9fd-5b76d37e936d.png)

为了计算新数据点属于驾驶类别的概率，我们计算*P(Drives/X)*如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f96b5bbf-4908-41d9-b8b5-7200a42d8b36.png)

最后，我们将比较*P(Walks/X)*和*P(Drives/X)。*基于这个比较，我们将确定在哪个类别中放置新数据点（在概率更高的类别中）。最初的绘图发生在 n 维空间中，取决于独立变量的值。

接下来，我们计算边际似然，如下图所示，即 P(X)：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/68ba163a-89e4-432b-8094-7c2ca7eb70f2.png)

*P(X)*实际上是指将新数据点添加到具有相似特征数据点的概率。该算法将划分或在发现具有与即将添加的数据点相似特征的数据点周围画一个圆。然后，计算特征的概率为*P(X) =相似观察的数量/总观察数量*。

+   圆的半径在这种情况下是一个重要的参数。这个半径作为算法的输入参数给出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/dad55bff-e896-4df6-a2a8-2d5cb5f3efdf.png)

+   在这个例子中，圆内的所有点被假定具有与要添加的数据点相似的特征。假设我们要添加的数据点与一个 35 岁，年薪 40,000 美元的人相关。在这种情况下，圆内的所有人都会被选中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/91023a2b-3bab-4adc-b518-c30bdbe5fe93.png)

+   接下来，我们需要计算似然，即随机选择一个步行者包含 X 的特征的概率。以下将确定*P(X/walks)*：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f67595a3-a52a-4c9d-84b3-a03673837041.png)

+   我们将使用相同的方法来推导数据点属于驾驶部分的概率，假设它具有与步行者相同的特征

+   在这种情况下，P(X)等于落在之前所示圆内的相似观察的数量，除以总观察数量。P(X) = 4/30 = 0.133

+   P(drives) = P(# who drive) / (#total) = 20/30 = 0.666

+   P(X|Drivers) = P(相似的驾驶员观察) / 总驾驶员 = 1/20 = 0.05

+   应用我们得到的值，得到 P(Drivers|X) = 0.05 * 0.666 / 0.133 = 0.25 => 25

对于给定的问题，我们将假设数据点属于步行者的集合。

# 总结朴素贝叶斯分类器

以下项目将迄今讨论的所有概念整合起来，总结了我们对朴素贝叶斯分类器的学习：

+   应该注意的是，朴素贝叶斯分类器在训练后并没有一个计算出的模型。事实上，在预测时，所有数据点只是根据它们属于哪个类别进行简单的标记。

+   在预测时，根据独立变量的值，数据点将在 n 维空间中的特定位置计算并绘制。目标是预测数据点在 N 个类别中属于哪个类别。

+   基于独立变量，数据点将在接近具有相似特征的数据点的向量空间中绘制。然而，这仍然不能确定数据点属于哪个类别。

+   根据最初选择的最佳半径值，将在该数据点周围画一个圆，将圆的半径内的一些其他点包围起来。

+   假设我们有两个类别，A 和 B，我们需要确定新数据点 X 的类别。贝叶斯定理将用于确定 X 属于类 A 的概率和 X 属于类 B 的概率。具有更高概率的那个类别就是预测数据点所属的类别。

# 实现代码

假设我们有一家名为 X 的汽车公司，拥有一些关于人们的数据，包括他们的年龄、薪水和其他信息。它还包括关于这些人是否购买了公司以非常昂贵的价格推出的 SUV 的详细信息。这些数据用于帮助他们了解谁购买了他们的汽车：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/124e9018-1f28-4010-9421-bda54f403750.png)

我们将使用相同的数据来训练我们的模型，以便它可以预测一个人是否会购买一辆汽车，给定他们的`年龄`、`薪水`和`性别`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/db67f62a-5f20-48e8-b463-bf9599ded9c7.png)

以下截图显示了前 12 个数据点的`y_pred`和`y_test`之间的差异：

| ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e31d4c8a-3e8d-4908-96f0-2995a35ed172.png) | ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/fcc87af1-e5dd-423e-986a-75ad337a02e6.png)前面的截图代表了混淆矩阵的输出。

+   单元格[0,0]代表了输出为 0 且被预测为 0 的总案例。

+   单元格[0,1]代表了输出为 0 但被预测为 1 的总案例。

+   单元格[1,0]代表了输出为 1 但被预测为 0 的总案例。

+   单元格[1,1]代表了输出为 1 且被预测为 1 的总案例。

如果我们从先前的数据集中获取统计数据，我们可以看到在 100 次预测中，有 90 次是正确的，10 次是错误的，给出了 90%的准确率。

# 自然语言处理

**自然语言处理**（**NLP**）是关于分析文本、文章并进行对文本数据的预测分析。我们将制作的算法将解决一个简单的问题，但相同的概念适用于任何文本。我们也可以使用 NLP 来预测一本书的类型。

考虑以下的 Tab 分隔值（TSV），这是一个用于应用 NLP 并查看其工作原理的制表符分隔的数据集：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3dfcd7e2-6f90-4a5b-8d50-b606750de3fe.png)

这是我们将要处理的数据的一小部分。在这种情况下，数据代表了关于餐厅的顾客评论。评论以文本形式给出，并且有一个评分，即 0 或 1，表示顾客是否喜欢这家餐厅。1 表示评论是积极的，0 表示不是积极的。

通常，我们会使用 CSV 文件。然而，在这里，我们使用的是 TSV 文件，分隔符是制表符，因为我们正在处理基于文本的数据，所以可能会有逗号，这些逗号并不表示分隔符。例如，如果我们看第 14 条记录，我们可以看到文本中有一个逗号。如果这是一个 CSV 文件，Python 会将句子的前半部分作为评论，后半部分作为评分，而`1`会被视为一个新的评论。这将破坏整个模型。

该数据集大约有 1,000 条评论，并且已经被手动标记。由于我们正在导入一个 TSV 文件，`pandas.read_csv`的一些参数需要更改。首先，我们指定分隔符是制表符分隔的，使用/t。我们还应该忽略双引号，可以通过指定参数 quoting=3 来实现：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/df6b9cce-a6df-4b7b-a18b-b20e9854ad23.png)

导入的数据集如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d1cc2af3-48f2-4eb9-b875-e35a85069898.png)

我们可以看到成功导入了 1,000 条评论。所有评论都在评论列中，所有评分都在**Liked**列中。在 NLP 中，我们必须在使用文本数据之前对其进行清理。这是因为 NLP 算法使用词袋概念工作，这意味着只保留导致预测的单词。词袋实际上只包含影响预测的相关单词。例如`a`，`the`，`on`等单词在这种情况下被认为是不相关的。我们还摆脱点和数字，除非需要数字，并对单词进行词干处理。词干处理的一个例子是用`love`代替`loved`。我们应用词干处理的原因是因为我们不希望最终有太多的单词，并且还要将`loving`和`loved`等单词重新组合成一个单词`love`。我们还去掉大写字母，并将所有内容转换为小写。要应用我们的词袋模型，我们需要应用标记化。这样做后，我们将有不同的单词，因为预处理将消除不相关的单词。

然后，我们取出不同评论的所有单词，并为每个单词创建一列。可能会有许多列，因为评论中可能有许多不同的单词。然后，对于每条评论，每个列将包含一个数字，指示该特定评论中该单词出现的次数。这种类型的矩阵称为稀疏矩阵，因为数据集中可能有许多零。

`dataset['Review'][0]`命令将给出我们的第一条评论：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d3908299-bf7b-4646-935b-bab54b2ad262.png)

我们使用正则表达式的一个子模块，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b6819ab8-f6ae-4d4f-b8a4-4bf010baa0fd.png)

我们正在使用的子模块称为减法函数。这将从我们的输入字符串中减去指定的字符。它还可以将单词组合在一起，并用您选择的字符替换指定的字符。要替换的字符可以输入为字符串，也可以输入为正则表达式格式。在前面的示例中，正则表达式格式中的^符号表示不，[a-zA-Z]表示除 a-z 和 A-Z 之外的所有内容应该被一个空格' '替换。在给定的字符串中，点将被移除并替换为空格，产生以下输出：`Wow Loved this place`。

我们现在删除所有不重要的单词，例如`the`，`a`，`this`等。为此，我们将使用`nltk`库（自然语言工具包）。它有一个名为 stopwords 的子模块，其中包含所有与句子意义获取无关的单词（通用单词）。要下载停用词，我们使用以下命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/49314ee0-a4a3-4823-948d-d286336a9418.png)

这将从当前路径下载停用词，然后可以直接使用它们。首先，我们将评论分成单词列表，然后我们遍历不同的单词，并将它们与下载的停用词进行比较，删除那些不必要的单词：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/15bff5a3-c53b-4677-a0bd-7eac69eff2da.png)

在前面的代码片段中，我们正在使用一个 for 循环。在 review 前面声明`[]`符号表示列表将包含从 for 循环返回的单词，这些单词在这种情况下是停用词。

在`for`循环之前的代码表示我们应该分配字符串单词，并且每次单词出现在评论列表中并且不出现在`stopwords.words('English')`列表中时，更新列表中的新单词。请注意，我们正在使用`set()`函数将给定的停用词列表实际转换为集合，因为在 Python 中，集合上的搜索操作比列表快得多。最后，评论将包含我们的无关紧要的单词。在这种情况下，对于第一条评论，它将包含[`wov`，`loved`，`place`]。

下一步是进行词干提取。我们应用词干提取的原因是为了避免稀疏性，即在我们的矩阵中有大量的零（称为稀疏矩阵）时发生的情况。为了减少稀疏性，我们需要减少矩阵中零的比例。

我们将使用 portstemmer 库对每个单词应用词干提取：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ec31b7c4-d334-4a2f-9abb-efd9a0340a7b.png)

现在，评论将包含[`wov`, `love`, `place`]。

在这一步中，我们将通过调用`join`将列表中转换后的字符串评论连接成一个字符串。我们将使用空格作为`delimiter` `' '.join(review)`将评论列表中的所有单词连接在一起，然后我们使用`' '`作为分隔符来分隔单词。

现在评论是一个包含所有小写相关单词的字符串：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/30639f06-fc93-482a-a023-5c550e3188dc.png)

执行代码后，如果我们比较原始数据集和获得的语料库列表，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b5544e88-4137-4d4a-b4bc-ee9ac777d7e7.png)

由于停用词列表中也有单词`Not`，索引 1 处的字符串`Crust is not good`（`Liked`评分为 0）变为了`crust good`。我们需要确保这不会发生。同样，`would not go back`变成了`would go back`。处理它的一种方法是使用一个停用词列表，如`set(stopwords.words('english'))]`。

接下来，我们将创建一个词袋模型。在这里，将使用获得的语料库（句子列表）中的不同单词，并为每个不同的单词创建一列。不会重复任何单词。

因此，诸如`wov love place`，`crust good`，`tasti textur nasti`等单词将被取出，并为每个单词创建一列。每一列将对应一个不同的单词。我们还将有评论和一个条目编号，指定该特定评论中单词存在的次数。

有了这种设置，我们的表中会有很多零，因为可能有一些单词并不经常出现。目标应该始终是将稀疏性保持到最低，这样只有相关的单词才能指向预测。这将产生一个更好的模型。我们刚刚创建的稀疏矩阵将成为我们的词袋模型，并且它的工作方式就像我们的分类模型一样。我们有一些独立变量取一些值（在这种情况下，独立变量是评论单词），并且根据独立变量的值，我们将预测依赖变量，即评论是积极的还是否定的。为了创建我们的词袋模型，我们将应用一个分类模型来预测每个新评论是积极的还是消极的。我们将使用标记化和一个名为**CountVectoriser**的工具来创建一个词袋模型。

我们将使用以下代码来使用这个库：

```py
from sklearn.feature_extraction.text import CountVectorizer
```

接下来，我们将创建这个类的一个实例。参数中有一个停用词作为其中一个参数，但由于我们已经将停用词应用到我们的数据集中，我们不需要再次这样做。这个类还允许我们控制大小写和标记模式。我们也可以选择使用这个类来执行之前的所有步骤，但是分开执行可以更好地进行细粒度控制。

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cb89493e-113d-4c2b-8dd6-233afab1ec52.png)

请注意，行`cv.fit_transform`实际上会将稀疏矩阵拟合到 cv，并返回一个具有语料库中所有单词的特征矩阵。

到目前为止，我们已经制作了我们的词袋，或者稀疏矩阵，一个独立变量的矩阵。下一步是使用分类模型，并在词袋的一部分-X 上训练模型，以及在相同索引上的依赖变量-Y。在这种情况下，依赖变量是`Liked`列。

执行上述代码将创建一个包含大约 1565 个特征（不同列）的特征矩阵。如果不同特征的数量非常大，我们可以限制最大特征并指定最大阈值。假设我们将阈值数指定为 1500，那么只有 1500 个特征或不同的单词将被纳入稀疏矩阵，那些与前 1500 个相比较少的将被移除。这将更好地相关独立和因变量，进一步减少稀疏性。

现在我们需要在词袋模型单词和因变量上训练我们的分类模型：

提取因变量如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5db0ad4c-bc11-414b-9d54-43e3d95031dd.png)

`X`和`Y`如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9d2394b1-f70c-4465-9d54-a54adc8e28f1.png)

请注意，在前面的情况下，每个索引（0-1499）对应于原始语料库列表中的一个单词。我们现在拥有了分类模型中的内容：独立变量和结果的度量，负面评价为 0，正面评价为 1。然而，我们仍然有相当多的稀疏性。

我们的下一步是利用分类模型进行训练。有两种使用分类模型的方法。一种方法是测试所有分类模型并确定假阳性和假阴性，另一种方法是基于经验和过去的实验。在 NLP 中最常用的模型是朴素贝叶斯和决策树或随机森林分类。在本教程中，我们将使用朴素贝叶斯模型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5cd1b943-ad4e-49b2-822a-965ab3b6baae.png)

整个代码如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f1d38bb1-4220-4957-8226-b5f71e06b262.png)

从上述代码中，我们可以看到我们将训练集和测试集分为 80%和 20%。我们将给训练集 800 个观察值，测试集 200 个观察值，并查看我们的模型将如何表现。执行后的混淆矩阵的值如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/13c1413a-f21b-41c4-97cb-8b840c48a641.png)

负面评价有 55 个正确预测，正面评价有 91 个正确预测。负面评价有 42 个错误预测，正面评价有 12 个错误预测。因此，在 200 次预测中，有 146 次正确预测，相当于 73%。

# 使用自然语言处理处理渗透测试报告

我在网络安全领域中使用 ML 的一个应用是自动化报告分析以发现漏洞。我们现在知道上一章中构建的漏洞扫描器是如何工作的，但所有集成脚本和工具产生的数据量巨大，我们需要手动处理或分析它。在 Typical scanners 如 Nessus 或 Qualys 中，插件实际上是脚本。由于它们是由 Nessus 和 Qualys 内部开发的，这些脚本旨在发现缺陷并以易于理解的方式报告它们。然而，在我们的情况下，我们正在集成许多开源脚本和工具集，并且产生的输出并不是集成的。为了自动化这项任务并获得漏洞的概述，我们需要弄清楚脚本或工具产生的输出，在标记漏洞的情况下，以及在返回安全检查的情况下。根据我们的理解和每个脚本的预期输出模式，我们必须起草我们的 Python 代码逻辑，以发现哪个插件产生了不安全的检查结果，哪个返回了安全检查。这需要大量的工作。每当我们增加集成脚本的数量时，我们的代码逻辑也需要更新，所以你可以选择是否要走这条路。

我们手头还有另一种方法，那就是利用机器学习和 NLP。由于我们可以获得大量的历史渗透测试数据，为什么不将其提供给机器学习模型，并训练它理解什么是不安全的，什么是安全的呢？多亏了我们使用漏洞扫描器执行的历史渗透测试报告，我们的数据库表中有大量数据。我们可以尝试重用这些数据，利用机器学习和 NLP 自动化手动报告分析。我们谈论的是监督学习，它需要一次性的工作来适当地标记数据。假设我们拿过去进行的最后 10 次渗透测试的历史数据，每次测试平均有 3 个 IP。我们还假设每个 IP 平均执行 100 个脚本（取决于开放端口的数量）。这意味着我们有 3000 个脚本的数据。

我们需要手动标记结果。或者，如果测试人员在用户界面中呈现数据时，可以通过复选框选择**易受攻击**/**不易受攻击**，这将作为数据的标记。假设我们能够将所有结果数据标记为 1，表示测试用例或检查结果安全，标记为 0，表示测试用例结果不安全。然后我们将得到标记的数据进行预处理，并提供给我们的 NLP 模型进行训练。一旦模型训练完成，我们就会持久化模型。最后，在实时扫描期间，我们将测试用例的结果传递给我们训练好的模型，让它对结果易受攻击的测试用例进行预测。测试人员只需要专注于易受攻击的测试用例，并准备其利用步骤。

为了演示这个概念的 POC，让我们拿一个项目的结果，并只考虑运行`ssl`和`http`的脚本。让我们看看代码的运行情况。

# 第 1 步-标记原始数据

以下是我们使用漏洞扫描器扫描的一个项目上进行的`ssl`和`http`检查的输出。数据是从后端 IPexploits 表中获取的，并且标记为 0 表示检查不容易受攻击，标记为 1 表示测试不安全。我们可以在以下截图中看到这一点。这是一个带有模式（`command_id`，`recored_id`，`service_result`，`vul[0/1]`）的 TSV 文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/96902653-c1ab-4eba-86c5-fa3b73031522.png)

现在我们已经标记了数据，让我们处理和清理它。之后，我们将用它来训练我们的 NLP 模型。我们将使用 NLP 的朴素贝叶斯分类器。我在当前数据集上使用这个模型取得了不错的成功。测试各种其他模型并看看是否能够获得更好的预测成功率将是一个很好的练习。

# 第 2 步-编写训练和测试模型的代码

以下代码与我们在 NLP 部分讨论的内容完全相同，只是在使用`pickle.dump`将训练好的模型保存到文件中时添加了一些内容。我们还使用`pickle.load`来加载保存的模型：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ee1568fe-3ca7-4213-937c-b9d793dee0b1.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/29912ad7-0f20-4edd-9828-08b7e55b8c10.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ae164868-e89d-4e97-864b-f07ef3f48571.png)

以下截图显示了我们训练模型为数据集提供的混淆矩阵的结果。我们在 80%的数据集上训练了模型，并在 20%的数据集上进行了测试。得到的结果表明，我们的模型预测准确率为 92%。需要注意的是，对于更大的数据集，准确性可能会有所不同。这里的想法是让您了解 NLP 如何与渗透测试报告一起使用。我们可以改进处理以提供更干净的数据，并改变模型选择以获得更好的结果：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/9f2f6f9c-797b-4166-b014-6d0004572b07.png)

# 摘要

在本章中，我们讨论了如何使用 Python 进行机器学习，以及如何将其应用于网络安全领域。在网络安全领域中，数据科学和机器学习有许多其他精彩的应用，涉及日志分析、流量监控、异常检测、数据外泄、URL 分析、垃圾邮件检测等。现代 SIEM 解决方案大多建立在机器学习之上，并且使用大数据引擎来减少人工分析。请参考进一步阅读部分，了解机器学习在网络安全中的其他用例。还必须注意的是，渗透测试人员有必要了解机器学习，以便发现漏洞。在下一章中，用户将了解如何使用 Python 自动化各种网络应用攻击类型，包括 SQLI、XSS、CSRF 和点击劫持。

# 问题

1.  与机器学习相关的各种漏洞是什么？

1.  什么是大数据，有哪些已知漏洞的大数据产品示例？

1.  机器学习和人工智能之间有什么区别？

1.  哪些渗透测试工具使用机器学习，以及原因？

# 进一步阅读

+   使用机器学习检测钓鱼网站：[`github.com/abhishekdid/detecting-phishing-websites`](https://github.com/abhishekdid/detecting-phishing-websites)

+   使用机器学习进行日志分析：[`github.com/logpai`](https://github.com/logpai)

+   网络安全的自然语言处理：[`www.recordedfuture.com/machine-learning-cybersecurity-applications/`](https://www.recordedfuture.com/machine-learning-cybersecurity-applications/)

+   使用机器学习进行垃圾邮件检测：[`github.com/Meenapintu/Spam-Detection`](https://github.com/Meenapintu/Spam-Detection)

+   Python 深度学习：[`www.manning.com/books/deep-learning-with-python`](https://www.manning.com/books/deep-learning-with-python)


# 第八章：自动化 Web 应用程序扫描-第 1 部分

当我们谈论 Web 应用程序扫描时，会想到各种攻击向量，如 SQL 注入、XSS、CSRF、LFI 和 RFI。当我们谈论 Web 应用程序测试时，我们可能会想到 Burp Suite。在本章中，我们将研究如何使用 Python 来尝试自动化 Web 应用程序攻击向量检测。我们还将看看如何使用 Python 来自动化 Burp 扫描，以覆盖我们否则需要手动发现的漏洞。在本章中，我们将研究以下主题：

+   使用 Burp Suite 自动化 Web 应用程序扫描

+   使用 Python 自动化 Burp

+   SQL 注入

+   使用 Python 自动检测 SQL 注入

# 使用 Burp Suite 自动化 Web 应用程序扫描

Burp Suite Professional 在其 API 方面为渗透测试人员提供了额外的功能。借助 Burp Suite Professional API，测试人员可以自动调用扫描并将其发现与其他工具集成。

Burp Suite 目前在其许可版本（burp-suite 专业版）中提供 API 支持。这是所有网络安全专业人员必须拥有的工具之一。我建议获取 Burp Suite 的许可版本，以便充分利用本章内容。

启动 Burp Suite 并按以下方式配置 API：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e4ce8eae-640e-4880-8f32-65e911e0ef72.png)

然后，启动 API 并按以下方式配置 API 密钥：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/06a55de3-a63a-48a4-8061-aea501583b03.png)

单击按钮时，密钥将被复制到剪贴板。我们可以按以下方式使用它：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/f3a7587c-9f78-437f-82bf-efe060c1f24e.png)

我们可以看到 API 正在端口`1337`上监听。我们使用 API 密钥来引用此端点地址。API 公开了三个端点：获取问题定义、启动扫描和获取正在运行扫描的状态。

让我们看看我们需要的参数，以启动对 Damn Vulnerable Web Application 的新扫描。

应用可以从以下 URL 安装：

+   [`www.dvwa.co.uk/`](http://www.dvwa.co.uk/)

+   [`github.com/ethicalhack3r/DVWA`](https://github.com/ethicalhack3r/DVWA)

安装并设置好后，我们可以使用以下`curl`命令来在网站上启动 Burp 的主动扫描：

```py
curl -vgw "\n" -X POST 'http://127.0.0.1:1337/<API KEY>/v0.1/scan' -d '{"application_logins":[{"password":"password","username":"admin"}],"name":"My first project","scan_configurations":[{"name":"Crawl strategy - fastest","type":"NamedConfiguration"}],"scope":{"exclude":[{"rule":"http://192.168.250.1/dvwa/logout.php","type":"SimpleScopeDef"}],"include":[{"rule":"http://192.168.250.1/dvwa","type":"SimpleScopeDef"}]},"urls":["http://192.168.250.1/dvwa/login.php"]}'

```

包含更详尽的爬行和审计测试的更通用请求如下所示：

```py
curl -vgw "\n" -X POST 'http://127.0.0.1:1337/<API KEY>/v0.1/scan' -d '{"application_logins":[{"password":"password","username":"admin"}],"scope":{"exclude":[{"rule":"http://192.168.250.1/dvwa/logout.php","type":"SimpleScopeDef"}],"include":[{"rule":"http://192.168.250.1/dvwa/","type":"SimpleScopeDef"}]},"urls":["http://192.168.250.1/dvwa/"]}'
```

应注意，前面的请求可以通过 Ubuntu 上的终端发送，也可以使用 Burp API 提供的 Web 界面生成请求。应注意，如果以前面显示的方式调用请求，它将不会返回任何内容，而是会创建一个带有任务 ID 的新扫描。

这可以在 Burp Suite 控制台上看到，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d4f2011e-9920-41cf-adfe-9f51337b2faf.png)

在上一张屏幕截图中，我们可以看到创建了一个 ID 为`9`的新任务，并且正在扫描我们本地托管的 Damn Vulnerable Web Application。当截图被捕获时，该任务能够识别出四个高级问题、十个中级问题和三个低级问题。在接下来的部分中，我们可以看到如何使扫描器不断告诉我们扫描的状态。为了做到这一点，我们需要设置一个回调 URL。换句话说，我们需要有一个监听端口，扫描器将不断发送结果。我们可以在控制台上打印如下内容：

```py
curl -vgw "\n" -X POST 'http://127.0.0.1:1337/Sm2fbfwrTQVqwH3VERLKIuXkiVbAwJgm/v0.1/scan' -d '{"application_logins":[{"password":"password","username":"admin"}],"scan_callback":{"url":"http://127.0.0.1:8000"},"scope":{"exclude":[{"rule":"http://192.168.250.1/dvwa/logout.php","type":"SimpleScopeDef"}],"include":[{"rule":"http://192.168.250.1/dvwa/","type":"SimpleScopeDef"}]},"urls":["http://192.168.250.1/dvwa/"]}'
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2919585e-8d65-4874-a61b-8201ed5a2d4d.png)

扫描的状态和所有发现的内容将发送回指定的地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/3a30a396-3b57-489a-96ea-59e76ddd2b6a.png)

鉴于我们现在了解了如何使用 Burp Suite API 自动化扫描，让我们编写一个 Python 脚本来实现这一点。我们将创建一个 Python 脚本来调用扫描，同时该脚本将监听回调请求并解析响应以显示所有高、中和低问题。

# 使用 Python 进行 Burp 自动化

让我们创建一个简单的 Python 脚本并将其命名为`burp_automate.py`。输入以下代码：

```py
import requests
import json
from urlparse import urljoin
import socket
import ast
import time
class Burp_automate():
    def __init__(self):
        self.result=""
        self.api_key="odTOmUX9mNTV3KRQ4La4J1pov6PEES72"
        self.api_url="http://127.0.0.1:1337"

    def start(self):
        try:

            data='{"application_logins":[{"password":"password","username":"admin"}],"scan_callback":{"url":"http://127.0.0.1:8001"},"scope":{"exclude":[{"rule":"http://192.168.250.1/dvwa/logout.php","type":"SimpleScopeDef"}],"include":[{"rule":"http://192.168.250.1/dvwa/","type":"SimpleScopeDef"}]},"urls":["http://192.168.250.1/dvwa/"]}'
            request_url=urljoin(self.api_url,self.api_key)
            request_url=str(request_url)+"/v0.1/scan"
            resp=requests.post(request_url,data=data)

            self.call_back_listener()
        except Exception as ex:
            print("EXception caught : " +str(ex))

    def poll_details(self,task_id):
        try:
            while 1:
                time.sleep(10)
                request_url=urljoin(self.api_url,self.api_key)
                request_url=str(request_url)+"/v0.1/scan/"+str(task_id)
                resp=requests.get(request_url)
                data_json=resp.json()

                issue_events=data_json["issue_events"]
                for issues in issue_events:

                    if issues["issue"]["severity"] != "info":
                        print("------------------------------------")
                        print("Severity : " + issues["issue"].get("severity",""))
                        print("Name : " + issues["issue"].get("name",""))
                        print("Path : " + issues["issue"].get("path",""))
                        print("Description : " + issues["issue"].get("description",""))
                        if issues["issue"].get("evidence",""):
                            print("URL : " + issues["issue"]["evidence"][0]["request_response"]["url"])
                        print("------------------------------------")
                        print("\n\n\n")
                if data_json["scan_status"]=="succeeded":
                    break

        except Exception as ex:
            print(str(ex))

    def call_back_listener(self):
        try:
            if 1 :
                task_id=0
                s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('127.0.0.1', 8001))
                s.listen(10)

                conn, addr = s.accept()

                if conn:
                    while True:
                        data = conn.recv(2048)
                        if not data:
                            break
                        try:
                            index=str(data).find("task_id")
                            task_id=str(data)[index:index+12]
                            task_id=task_id.replace('"',"")
                            splitted=task_id.split(":")
                            t_id=splitted[1]
                            t_id=t_id.lstrip().rstrip()
                            t_id=int(t_id)
                            if t_id:
                                task_id=t_id
                                break
                        except Exception as ex:
                            print("\n\n\nNot found" +str(ex))

                if task_id:
                    print("Task id : " +str(task_id))
                    self.poll_details(task_id)
                else:
                    print("No task id obtaimed,  Exiting : " )

        except Exception as ex:
            print("\n\n\n@@@@Call back exception :" +str(ex))

obj=Burp_automate()
obj.start()

```

当我们执行脚本时，它将显示 Burp 扫描报告的所有问题，这些问题可能是“高”、“中”或“低”性质。

如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/29538d16-d08b-42f5-8fec-9f0fe1fab1fe.png)

以下截图表示扫描的状态和发出的请求总数。脚本将持续运行，直到扫描完成，状态为**成功**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/20dad012-3a34-4b6c-bd3c-378f498f1370.png)

# SQL 注入

**SQL 注入攻击**是一种攻击，通过该攻击可以更改 SQL 查询的执行以满足攻击者的需求。Web 应用程序可能在后端与数据库交互，并且可能接受用户输入，这些输入形成参数或 SQL 查询的一部分，用于插入、删除、更新或检索数据库表中的数据。在这种情况下，开发人员必须非常小心，不要直接将用户提供的参数传递给后端数据库系统，因为这可能导致 SQL 注入。开发人员必须确保使用参数化查询。假设我们在应用程序上有一个登录页面，该页面从用户那里获取用户名和密码，并将此信息传递给后端 SQL 查询，如下所示：`select * from users where email ='"+request.POST['email']+"' and password ='"+request.POST['password']"`.

应用程序中编写的逻辑将检查查询返回的行数。如果有，那么用户是合法的，并且将为用户分配有效的会话，否则将显示错误消息“无效凭据”。

假设用户将其电子邮件地址设置为`admin@abc.com`，密码设置为`admin@123`，在这种情况下，将在后端执行以下查询：`select * from users where email ='admin@abc.com' and password ='admin@123'`。

然而，如果用户将电子邮件输入为`hacker@abc.com'`或`'1'='1`，并且他们的密码为`hacker'`或`'1'='1`，那么将在后端执行以下查询：`select * from users where email ='hacker@abc.com' or '1'='1' and password ='hacker' or '1'='1'`。

因此，返回的数据集的第一条记录将被视为试图登录的用户，由于 SQL 注入而绕过了身份验证。

# 使用 Python 自动检测 SQL 注入

我们的重点是了解如何使用 Python 自动化检测 SQL 注入。每当我们谈论 SQL 注入时，我们想到的工具就是 SQLmap，这是一个非常好的工具，也是我个人在检测 Web 应用程序中的 SQL 注入时的首选。互联网上有许多关于如何使用 SQLmap 检测 SQL 注入的教程。在本节中，我们将看到如何使用 SQLmap 的服务器版本，该版本公开了一个 API，以自动化整个检测 SQL 注入漏洞的过程。我们将使用 Python 脚本来自动化检测过程。

让我们启动 SQLmap 服务器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b05c9931-ed0e-457b-bba4-a87c67eeeb8a.png)

现在服务器在本地主机（端口`8775`）上运行，让我们看看如何使用 cURL 和 API 扫描应用程序（DVWA）进行 SQL 注入：

+   创建一个新任务如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/10c420c5-00d4-47a9-a4dc-70929be7d3a1.png)

+   为新任务设置`scan`选项如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/2aa2f353-fb96-4096-b479-2b5c6fd98aee.png)

+   为新任务设置`list`选项如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a3a34ab3-25e0-4335-91ac-45d222bd999f.png)

+   使用以下`set`选项开始扫描：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/27bda66f-8f89-4d47-ad03-0d193be91bce.png)

+   检查创建的扫描的“状态”，以发现 SQL 注入，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/24549a86-71b3-4da7-8e2f-1caa74dbe25c.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/98393f6a-9bef-47ce-975d-5da6438fb606.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0c836bba-b17f-4ae6-bb41-f625705ee784.png)

前面的屏幕截图验证了后端数据库是 MySQL，参数 ID 容易受到 SQL 注入攻击。

让我们借助 Python 脚本自动化整个过程，如下所示。将脚本命名为`sql_automate.py`：

```py
import requests
import json
import time
import pprint

class SqliAutomate():

 def __init__(self,url,other_params={}):
 self.url=url
 self.other=other_params 

 def start_polling(self,task_id):
 try:
 time.sleep(30)
 poll_resp=requests.get("http://127.0.0.1:8775/scan/"+task_id+"/log")
 pp = pprint.PrettyPrinter(indent=4)
 #print(poll_resp.json())
 pp.pprint(poll_resp.json())
 except Exception as ex:
 print("Exception caught : " +str(ex))

 def start(self):
 try: 
 task_resp=requests.get("http://127.0.0.1:8775/task/new")
 data=task_resp.json()
 if data.get("success","") ==True:
 task_id=data.get("taskid")
 print("Task id : "+str(task_id))
 data_={'url':self.url}
 data_.update(self.other)
 opt_resp=requests.post("http://127.0.0.1:8775/option/"+task_id+"/set",json=data_)
 if opt_resp.json().get("success")==True:
 start_resp=requests.post("http://127.0.0.1:8775/scan/"+task_id+"/start",json=data_)
 if start_resp.json().get("success")==True:
 print("Scan Started successfully .Now polling\n")
 self.start_polling(task_id)
 except Exception as ex:
 print("Exception : "+str(ex))

other={'cookie':'PHPSESSID=7brq7o2qf68hk94tan3f14atg4;security=low'}
obj=SqliAutomate('http://192.168.250.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit',other)
obj.start()

```

让我们执行脚本并获取 SQL 注入的输出，如下所示：

```py
root@thp3:~/sqli_automate# python sqli_automate.py
Task id : d0ba910ae1236ff4
Scan Started successfully .Now polling

{   u'log': [   {   u'level': u'INFO',
                    u'message': u'testing connection to the target URL',
                    u'time': u'13:13:15'},
                {   u'level': u'INFO',
                    u'message': u'checking if the target is protected by some kind of WAF/IPS/IDS',
                    u'time': u'13:13:15'},
                {   u'level': u'INFO',
                    u'message': u'testing if the target URL content is stable',
                    u'time': u'13:13:15'},
                {   u'level': u'INFO',
                    u'message': u'target URL content is stable',
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"testing if GET parameter 'id' is dynamic",
                    u'time': u'13:13:16'},
                {   u'level': u'WARNING',
                    u'message': u"GET parameter 'id' does not appear to be dynamic",
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')",
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks",
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"testing for SQL injection on GET parameter 'id'",
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"testing 'AND boolean-based blind - WHERE or HAVING clause'",
                    u'time': u'13:13:16'},
                {   u'level': u'WARNING',
                    u'message': u'reflective value(s) found and filtering out',
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'",
                    u'time': u'13:13:16'},
                {   u'level': u'INFO',
                    u'message': u"testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'",
                    u'time': u'13:13:17'},
                {   u'level': u'INFO',
                    u'message': u"testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment) (NOT)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u'GET parameter \'id\' appears to be \'OR boolean-based blind - WHERE or HAVING clause (MySQL comment) (NOT)\' injectable (with --not-string="Me")',
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"GET parameter 'id' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable ",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"testing 'MySQL inline queries'",
                    u'time': u'13:13:18'},
                {   u'level': u'INFO',
                    u'message': u"'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test",
                    u'time': u'13:13:28'},
                {   u'level': u'INFO',
                    u'message': u'target URL appears to have 2 columns in query',
                    u'time': u'13:13:29'},
                {   u'level': u'INFO',
                    u'message': u"GET parameter 'id' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable",
                    u'time': u'13:13:29'},
                {   u'level': u'WARNING',
                    u'message': u"in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval",
                    u'time': u'13:13:29'},
                {   u'level': u'INFO',
                    u'message': u'the back-end DBMS is MySQL',
                    u'time': u'13:13:29'}],
    u'success': True}
```

获取的输出可以被解析并打印在屏幕上。

# 总结

在本章中，我们讨论了可以使用 Python 自动化 Web 应用程序扫描和评估的方法。我们看到了如何使用 Burp Suite API 来扫描底层应用程序，并研究了一系列评估结果。我们还讨论了 SQL 注入以及 Python 如何与我们喜爱的工具 SQLmap 一起使用。最后，我们看了一下如何使用 Python 调用 SQLmap 来自动化整个 SQL 注入检测过程。在下一章中，我们将了解使用 Python 自动化检测其他 Web 应用程序漏洞，如 XSS、CSRF、点击劫持和 SSL 剥离。

# 问题

1.  还有哪些使用 Python 代码与 Burp 的方法？

1.  还有哪些 SQL 注入工具可以用 Python 自动化？

1.  使用自动化的 Web 应用程序扫描方法的优缺点是什么？

# 进一步阅读

+   Burp 和 SQL 插件：[`github.com/codewatchorg/sqlipy`](https://github.com/codewatchorg/sqlipy)

+   使用 SQLmap 扩展 Burp 以检测 SQL 注入：[`www.codewatch.org/blog/?p=402`](https://www.codewatch.org/blog/?p=402)

+   Burp 扩展：[`portswigger.net/burp/extender`](https://portswigger.net/burp/extender)


# 第九章：自动 Web 应用程序扫描-第 2 部分

继续我们在上一章的讨论，我们现在将学习如何使用 Python 自动检测**跨站脚本**（**XSS**）、**跨站请求伪造**（**CSRF**）、点击劫持和**安全套接字层**（**SSL**）剥离。本章讨论的所有技术将帮助我们加快 Web 应用程序评估过程。我建议您不要局限于本章讨论的方法。讨论的方法可以作为基线，相同的想法可以扩展和改进，以得到更好的解决方案或开发工具，以帮助渗透测试社区。本章将讨论以下主题：

+   跨站脚本

+   跨站请求伪造

+   点击劫持

+   SSL 剥离（缺少 HSTS 标头）

# XSS

**XSS**攻击属于 Web 应用程序攻击的注入类别。它们主要是由于未对来自最终用户的 Web 应用程序传递的用户输入进行消毒而引起的。这不会导致服务器被攻破，但对用户数据的影响非常严重。攻击发生在攻击者能够将某种 Java 脚本或 HTML 内容注入到将提供给用户的网页中时。这种恶意内容可能会尝试从访问网站的用户那里窃取敏感信息。在接下来的章节中，我们将看看不同类型的 XSS 攻击。

# 存储或 Type 1 XSS 攻击

**存储型 XSS**是攻击，其中来自攻击者的恶意输入被持久化并存储在后端数据库或存储库中。每当检索并呈现该内容以在网页上显示时，浏览器完全不知道它，它要么执行来自数据库的恶意 JavaScript，要么呈现恶意 HTML 标记，而不是将其显示为文本。存储型 XSS 将永久保留在数据库中，并影响访问受影响网页的所有用户。

# 反射型或 Type 2 XSS 攻击

**反射型 XSS**攻击是 XSS 攻击向量的第二种类型，其中恶意的 XSS 有效负载不会存储在数据库表中以进行持久化，但仍然被注入到返回给用户的网页的某些参数中。浏览器对此更改毫不知情，只是简单地呈现注入的恶意 HTML 或执行注入的恶意 JavaScript 代码，再次导致用户数据被泄露。

# 基于 DOM 或 Type 0 XSS 攻击

基于**文档对象模型**的 XSS 是 XSS 攻击的第三类。在这里，XSS 有效负载不会发送到服务器，而是由于实现缺陷和使用客户端 JavaScript 改变网页状态/DOM，攻击者放置有效负载，该有效负载将由负责操纵网页状态的 JavaScript 拾取。

我们的重点是了解如何使用 Python 自动检测 XSS。

# 使用 Python 自动检测 XSS

在这里，我们将看到一种方法，我们将使用 Python、Beautifulsoup、Selenium 和 Phantomjs 自动检测 Web 应用程序中的 XSS。

通过运行以下命令来安装依赖项：

```py
pip install BeautifulSoup
pip install bs4
pip install selenium
sudo apt-get install libfontconfig
apt-get install npm
npm install ghostdriver
wget https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2
tar xvjf phantomjs-2.1.1-linux-x86_64.tar.bz2
sudo cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/bin/
sudo cp phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/
```

让我们了解每个的目标：

+   **BeautifulSoup**是一个出色的 Python 库，用于网页抓取和解析网页。

+   **Selenium**是用于自动测试 Web 应用程序的自动化框架。其功能在安全领域尤为重要，用于浏览器模拟和自动遍历 Web 应用程序的工作流程。

+   **Phantomjs**是一种用于无头浏览的实用程序。它执行浏览器的所有活动，而不实际加载它，而是在后台运行，使其轻巧且非常有用。

安装 Phantomjs 后，我们需要在控制台上执行以下命令：`unset QT_QPA_PLATFORM`。这是用来处理 Ubuntu 16.04 上 Phantomjs 版本抛出的错误的，错误如下：`Message: Service phantomjs unexpectedly exited. Status code was: -6`。

应该注意，这个练习的目的是模拟正常用户行为，并找到 Web 应用程序中的注入点。我们所说的*注入点*是指用户可以提供输入的所有输入字段。为了找到注入点，我们将使用`BeautifulSoup`库。从网页中，我们提取所有类型为文本、密码或文本区域的字段。一旦找到注入点，我们将使用 selenium 在注入点传递我们的有效负载值。一旦有效负载设置在注入点，我们将再次使用`BeautifulSoup`来定位表单的提交按钮。然后，我们将传递提交按钮的 ID 给 selenium，点击它，以提交表单。

我们将使用的有效负载是`<a href=#> Malicious Link XSS </a>`。如果这个被创建了，我们可以推断网站存在 XSS 漏洞。还必须注意的是，在提交有效负载后，我们还捕获了网页的截图，以查看链接是否真的被创建，这将作为概念的证明。

应该注意，我们将在本地 IP`http://192.168.250.1/dvwa`上运行的 DVWA 应用程序上演示我们脚本的概念验证。正如我们所知，该应用程序需要用户登录。我们将首先让我们的脚本自动登录应用程序，然后设置适当的 cookie 和会话。然后，在登录后，我们将导航到存在 XSS 的页面，并执行上述操作。我们还将更新 cookie 值，并设置 security=low，以便在 DVWA 应用程序中可能发生 XSS。应该注意，相同的概念可以扩展并应用于任何 Web 应用程序，因为我们使用了一种非常通用的方法来识别注入点并在其中提交有效负载。根据需要修改脚本并进一步扩展。我将致力于在这个脚本的基础上开发一个功能齐全的 XSS 检测工具，它将位于我的 GitHub 存储库中。请随时为其做出贡献。

在下一节中，我们将看一下极端自动化。

# 脚本在执行

让我们将我们的脚本命名为`Xss_automate.py`，并添加以下截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/484f429d-bd64-41a3-920c-38e3892b6249.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/08909770-f649-4193-b2e3-6416f920f08b.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a024dced-fd3e-4fe9-bd23-81486e046e6d.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c03fe143-c7a6-4041-b336-c4f73782c3fc.png)

现在可以运行脚本如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a24eb513-17ea-4f53-b2e6-58201c03ddd3.png)

让我们去检查当前路径，看看截图是否已经创建：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c8657ffd-643f-4ed4-9469-31216243196c.png)

正如我们之前所指出的，已经创建并捕获了三个截图。让我们打开每一个来验证概念的证明。成功使用我们的脚本登录后，下面的截图就是我们看到的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0d525220-1a2a-4f08-817a-06c5b9d13592.png)

下面的截图显示了反射 XSS 漏洞的利用，创建了链接。请注意，security 的值被设置为 low：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/063194e2-c175-43e2-8fd9-21457c9a288e.png)

下面的截图显示了存储的 XSS 漏洞：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/cfa0cf01-a5eb-4a50-8110-625e472120eb.png)

需要注意的是，我们只将先前的方法应用于检测两个页面中的 XSS，只是为了减少执行时间并展示概念的威力。然而，这可以扩展到应用程序的所有网页。我们需要删除检查从`<a>`标签中获取的 URL 是否存在于列表中的条件：`self.target_links=["vulnerabilities/xss_r/","vulnerabilities/xss_s/"]`。尝试这种方法，删除这个条件，并根据需要修改脚本，看看它覆盖了什么。

# CSRF

**CSRF**是一种攻击，攻击者利用有效的用户会话以允许在当前登录用户的名义下执行某些操作。例如，假设管理员用户已登录应用程序，并在浏览器中设置了有效的会话 cookie。管理员可以通过单击删除所有按钮来删除网站上的所有用户，内部调用 HTTP 请求`http://www.mysite.com/delete?users=all`。Web 浏览器的一个属性是在用户登录到应用程序后，为每个后续请求向服务器发送会话参数/cookie。攻击者可以利用这一点，通过制作一个包含 HTML 图像的伪造页面，例如`<img src"http://www.mysite.com/delete?users=all" style="display:hidden">`。攻击者可以将这个伪造页面的链接发送给当前已登录到他的网站`mysite.com`的管理员。如果管理员用户加载了这个网页，将会以他们的名义触发删除所有用户的 HTTP 请求，并发送有效的会话 cookie，导致服务器删除所有用户。

# 使用 Python 自动检测 CSRF

在这里，我们将介绍一种使用 Python、Beautifulsoup、Selenium 和 Phantomjs 自动检测 Web 应用程序中 CSRF 的方法。然而，在自动化检测之前，让我们讨论一下我们将采取的方法。我们知道可以通过实现反 CSRF 令牌来减轻 CSRF 攻击。

从服务器提供的任何可能修改服务器状态的表单都应该包含一个包含随机加密值的隐藏字段，称为 CSRF 令牌。大多数 CSRF 令牌背后的原则是，这个表单和一个 cookie 也必须设置为一个与在隐藏字段中提供的令牌的相同值的加密值。当表单被提交回服务器时，会提取 cookie 的秘密值并与在隐藏字段中提交回服务器的秘密值进行比较。如果两个秘密匹配，请求被认为是真实的，并进一步处理。

我们将在我们的检测机制中使用相同的方法。对于任何要提交回服务器的表单，我们将提取所有输入字段并将它们与各种技术中常用的 CSRF 隐藏字段参数名称列表进行比较，如 Java、PHP、Python/Django、ASP.NET 和 Ruby。此外，我们还将查看在提交表单之前设置的 cookie 的名称，并将这些 cookie 的名称与所有知名技术堆栈中常用的 CSRF 保护名称进行比较。

需要再次注意的是，脚本将模拟正常的人类行为。它将登录应用程序并保持有效会话，然后尝试查找 CSRF 漏洞。这里显示了最常用的 CSRF 隐藏字段参数以及技术堆栈：

+   `ASP.NET [Hiddenfiled : __RequestVerificationToken, Cookie : RequestVerificationToken]`

+   `PHP [Hiddenfiled : token, Cookie : token], [Hiddenfileld :_csrfToken, Cookie : csrfToken]`

+   `PHP [Hiddenfiled : _csrftoken, Cookie : csrftoken]`

上述列表可能更详尽，但对我们的目的来说已经足够了。我们将使用 DVWA 应用程序来创建我们的概念验证脚本。

# 脚本在执行

让我们继续创建一个名为`Csrf_detection.py`的脚本，其中包含以下屏幕截图中显示的内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/005e85f7-756e-4087-b759-4ccf0ddf62a1.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/30d156ff-af96-4a4d-a911-1326a0eeed0c.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/00ec8910-e107-4368-b0f9-4e654ef280d7.png)

当我们执行脚本时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/b598296e-27e3-4d2f-ab9a-056a8874d1f6.png)

创建的屏幕截图显示在这里：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d9395078-a5a6-4dfc-8569-d01a54dd881a.png)

DVWA 应用程序的捕获屏幕截图显示在这里：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/6f7cec96-632d-491f-a3b8-f6340ce0f9ca.png)

应该注意的是，我们只在一个页面上应用了先前的方法来检测 CSRF，只是为了减少执行时间并展示概念的威力。然而，这可以扩展到应用程序的所有网页。我们需要删除检查从`<a>`标签中获取的 URL 是否在列表中的条件：`self.target_links=["vulnerabilities/csrf"]`。尝试相同的方法，删除此条件，并根据需要修改脚本以查看它覆盖了什么。

# 点击劫持

**点击劫持**是一种攻击，攻击者在合法网站或网页上叠加自制的攻击页面。考虑与 CSRF 攻击案例中提到的相同情景。可以使能够删除所有用户的网页以透明的方式呈现，使用户看不到页面上的按钮。因此，用户看到的是一个透明层下的合法网页的攻击页面。例如，攻击者可以制作一个显示 iPhone 优惠的网页，可能有一个按钮写着**立即赢取 iPhone**，放在透明按钮**删除所有用户**下面。因此，当受害者，**管理员用户**，认为他们点击的是赢取 iPhone 的按钮时，实际上他们点击的是透明按钮，从数据库中删除所有用户。

网站防止点击劫持的一种方法是实施一个名为 X-Frame-Options 的特殊头部，该头部在以下部分中定义。

# X-Frame-Options

网站可以通过特殊的 HTTP 响应头部**X-Frame-Options**声明不应在框架或 iframe 中呈现。客户端浏览器在接收到此头部时，检查设置在框架限制内的值，并根据设置的值采取适当的操作。各种值显示在这里：

+   **DENY**：此值将阻止网页加载到框架或 iFrame 中。这是建议使用的值。

+   **SAMEORIGIN**：如果尝试将页面加载到 iframe 中的页面来自与被加载页面相同的源，则此值将允许页面仅在框架或 iframe 中加载。

+   **ALLOW-FROM**：此值定义了允许将页面加载到框架或 iframe 中的位置。

# 使用 Python 自动检测点击劫持

在这里，我们将看到一种我们将用来查看网站是否容易受到点击劫持的方法。我们将使用一个简单的 Python 脚本，检查应用程序渲染的响应头中是否存在 X-Frame-Options。我们将调用脚本`CJ_detector.py`并添加以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/21e9f24e-ebae-4ab8-9cbb-e3472a0e0793.png)

我们将运行脚本，看看 DVWA 应用程序是否受到点击劫持的保护：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4e8bfe5d-13f7-4f6f-aec8-b5edca533ad8.png)

# SSL 剥离（缺少 HSTS 头部）

**SSL 剥离**，或**SSL 降级**，是一种将 HTTPS 连接降级为 HTTP 的攻击向量。这种攻击是由位于受害者和 Web 服务器之间的攻击者执行的，并充当透明代理。它进一步与受害者保持基于 HTTP 的下行连接，并与服务器保持适当的基于 HTTPS 的上行连接。

因此，攻击是通过 ARP 欺骗、SSL 剥离和在攻击者和受害者之间设置透明代理的组合来进行的。假设一个受害者想要访问一个名为`abc.com`的网站。默认情况下，`abc.com`由 HTTPS 服务器提供，如`https://www.abc.com`，但当用户在浏览器中输入 URL`abc.com`时，浏览器将请求发送为`http://www.abc.com`到服务器，服务器响应 302 响应并将用户重定向到`https://www.abc.com`。重要的是要注意，用户浏览器到服务器的第一个请求是通过纯 HTTP 进行的，因为用户输入了`abc.com`。这就是攻击者使用 SSL 剥离所利用的。

考虑一个放置在同一网络上并且正在 ARP 欺骗受害者和路由器的攻击者。在这种情况下，受害者对`abc.com`的请求首先到达攻击者。攻击者设置了一个透明代理，可以将请求转发到实际服务器。服务器响应 302 响应。攻击者代理发送一个请求到`https://abc.com`并接收响应，这只是一个网页。攻击者代理还有一个额外的功能，可以解析整个响应，用纯 HTTP 替换所有 HTTPS 链接，然后将一个纯页面呈现给受害者。在下一个请求中，受害者发布他们的凭据，却不知道流量是通过攻击者传递的。

为了防止这种攻击，网站必须在发送给客户端的响应中包含一个特殊的头。这个头将保存在浏览器首选项中，因此每当连接到网站时，第一个请求本身将通过 HTTPS 发送；因此，使得攻击者无法窃听流量。

**HTTP 严格传输安全**（**HSTS**）是一种安全机制，浏览器会记住这个主机是一个 HSTS 主机，并将详细信息保存在浏览器首选项中。因此，每当再次访问该站点时，即使用户在浏览器中输入`abc.com`，在向服务器释放请求之前，浏览器也会在内部将请求转换为 HTTPS，因为它检查其 HSTS 列表并发现目标主机或服务器投诉。如果第一个请求是 HTTPS，攻击者就没有机会降级请求。

# 使用 Python 自动检测缺失的 HSTS

在这里，我们将看到一种方法，我们将使用它来确定网站是否容易受到点击劫持的攻击。我们将使用一个简单的 Python 脚本来检查应用程序呈现的响应头中是否存在 Strict-Transport-Security。我们将命名脚本为`HSTS_detector.py`，并将以下内容放入其中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/eca5a805-7183-4545-9e35-5574f75f05e4.png)

让我们运行脚本，看看应用程序 DVWA 是否受到了点击劫持的保护：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/abcd12ce-31c4-460a-b738-686c049c7c47.png)

# 摘要

在本章中，我们讨论了我们可以使用的方法来使用 Python 自动化我们的 Web 应用程序扫描和评估。我们看到了如何使用 Python 自动化检测 Web 应用程序的漏洞，如 XSS、CSRF、点击劫持和 SSL 剥离。所有这些在实际评估中都非常有用，并将帮助您作为渗透测试人员对使用 Python 自动化事物有一个相当好的掌握。

在下一章中，我们将探讨与逆向工程、模糊测试和缓冲区溢出相关的各种概念。

# 问题

1.  还有哪些应用程序安全用例可以使用 Python 自动化处理？

1.  我们如何使用 Python 集成网络扫描和 Web 应用程序扫描？

# 进一步阅读

+   学习 Python 网络渗透测试：[`www.lynda.com/Python-tutorials/Learning-Python-Web-Penetration-Testing/521198-2.html`](https://www.lynda.com/Python-tutorials/Learning-Python-Web-Penetration-Testing/521198-2.html)

+   渗透测试人员的 Python：[`www.pentesteracademy.com/course?id=1`](https://www.pentesteracademy.com/course?id=1)

+   使用 Python 和 Kali Linux 进行渗透测试自动化：[`niccs.us-cert.gov/training/search/pluralsight/penetration-testing-automation-using-python-and-kali-linux`](https://niccs.us-cert.gov/training/search/pluralsight/penetration-testing-automation-using-python-and-kali-linux)


# 第十章：构建自定义爬虫

当我们谈论 Web 应用程序扫描时，我们经常会遇到内置在我们用于 Web 应用程序扫描的自动扫描工具中的爬虫。诸如 Burp Suite、Acunetix、Web Inspect 等工具都有精彩的爬虫，可以浏览 Web 应用程序并针对爬取的 URL 尝试各种攻击向量。在本章中，我们将了解爬虫是如何工作的，以及在幕后发生了什么。本章的目标是使用户了解爬虫如何收集所有信息并形成各种攻击的攻击面。相同的知识可以稍后用于开发可能自动化 Web 应用程序扫描的自定义工具。在本章中，我们将创建一个自定义 Web 爬虫，它将浏览网站并给出一个包含以下内容的列表：

+   网页

+   HTML 表单

+   每个表单中的所有输入字段

我们将看到如何以两种模式爬取 Web 应用程序：

+   无身份验证

+   有身份验证

我们将在 Django（Python 的 Web 应用程序框架）中开发一个小型 GUI，使用户能够在测试应用程序上进行爬取。必须注意，本章的主要重点是爬虫的工作原理，因此我们将详细讨论爬虫代码。我们不会专注于 Django Web 应用程序的工作原理。为此，本章末尾将提供参考链接。我将在我的 GitHub 存储库中分享整个代码库，供读者下载和执行，以便更好地理解该应用程序。

# 设置和安装

要使用的操作系统是 Ubuntu 16.04。该代码在此版本上经过测试，但读者可以自由使用任何其他版本。

通过运行以下命令安装本章所需的先决条件：

```py
pip install django==1.6 pip install beautifulsoup4 pip install requests pip install exrex pip install html5lib pip install psutil sudo apt-get install sqlitebrowser
```

应注意，该代码经过 Python 2.7 的尝试和测试。建议读者在相同版本的 Python 上尝试该代码，但它也应该适用于 Python 3。关于打印语句可能会有一些语法上的变化。

# 开始

典型的 Django 项目遵循基于 MVC 的架构。用户请求首先命中`Urls.py`文件中配置的 URL，然后转发到适当的视图。视图充当后端核心逻辑和呈现给用户的模板/HTML 之间的中间件。`views.py`有各种方法，每个方法对应于`Urls.py`文件中的 URL 映射器。在接收请求时，`views`类或方法中编写的逻辑从`models.py`和其他核心业务模块中准备数据。一旦所有数据准备好，它就会通过模板呈现给用户。因此，模板形成了 Web 项目的 UI 层。

以下图表代表了 Django 请求-响应循环：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d7a2a172-5d51-47c9-ba36-3e0aa1ffbc65.png)

# 爬虫代码

如前所述，我们有一个用户界面，将收集要爬取的 Web 应用程序的用户参数。因此，请求被转发到`views.py`文件，然后我们将调用爬虫驱动文件`run_crawler.py`，然后再调用`crawler.py`。`new_scan`视图方法获取所有用户参数，将它们保存在数据库中，并为爬取项目分配一个新的项目 ID。然后将项目 ID 传递给爬虫驱动程序，以便引用并使用 ID 提取相关项目参数，然后将它们传递给`crawler.py`开始扫描。

# Urls.py 和 Views.py 代码片段

以下是`Urls.py`文件的配置，其中包含 HTTP URL 和映射到该 URL 的`views.py`方法之间的映射关系。该文件的路径是`Chapter8/Xtreme_InjectCrawler/XtremeWebAPP/Urls.py`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/af450762-e9b2-4934-8aac-19e965629f14.png)

前面突出显示的行表示新爬行项目的 URL 与满足请求的`views`方法之间的映射。因此，我们将在`views.py`文件中有一个名为`new_scan`的方法。文件的路径是`Chapter8/Xtreme_InjectCrawler/XtremeWebAPP/xtreme_server/views.py`。方法定义如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/825f44cd-a637-4f6f-98e2-ce6e871a44b2.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/d4b60bba-4872-40cf-b9d2-a2e654f8624e.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1aa217d1-0194-4339-84c8-a4e3bde1596c.png)

# 代码解释

`new_scan`方法将接收用户的`HTTP GET`和`POST`请求。`GET`请求将被解析为提供用户输入项目参数的页面，`POST`请求将把所有参数发布到先前的代码，然后可以进一步处理。正如代码的**（1）**部分所突出显示的那样，项目参数正在从用户请求中检索，并放置在 Python 程序变量中。代码的**（2）**部分也是如此。它还从用户提供的设置中获取一些其他参数，并将它们放在一个名为 settings 的 Python 字典中。最后，当所有数据收集完毕，它将所有细节保存在名为`Project`的后端数据库表中。正如在第 261 行所示，代码初始化了一个名为`Project()`的类，然后从第 262 行到 279 行，它将从用户那里获得的参数分配给`Project()`类的实例变量。最后，在第 280 行，调用了`project.save()`代码。这将把所有实例变量作为单行放入数据库表中。

基本上，Django 遵循开发的 ORM 模型。**ORM**代表**对象关系映射**。Django 项目的模型层是一组类，当使用`python manage.py syncdb`命令编译项目时，这些类实际上会转换为数据库表。我们实际上不在 Django 中编写原始的 SQL 查询来将数据推送到数据库表或提取它们。Django 为我们提供了一个模型包装器，我们可以将其作为类访问，并调用各种方法，如`save()`、`delete()`、`update()`、`filter()`和`get()`，以执行对数据库表的**创建、检索、更新和删除**（**CRUD**）操作。对于当前情况，让我们看一下包含`Project`模型类的`models.py`文件：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/61d66aeb-a4ba-4316-9ec6-3cdee9d63aa4.png)

因此，当代码被编译或数据库同步发生时，使用`python manage.py syncdb`命令，一个名为`<project_name>_Project`的表将在工作数据库中创建。表的架构将根据类中实例变量的定义进行复制。因此，对于项目表的前面情况，将创建 18 个列。表将具有`project_name`的主键，Django 应用程序中其数据类型被定义为`CharField`，但在后端将被转换为类似`varchar(50)`的东西。在这种情况下，后端数据库是 SQLite 数据库，在`settings.py`文件中定义如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/39093f85-29cf-47bf-8a37-82d16ce9e608.png)

代码片段的**（3）**和**（4）**部分很有趣，因为这是工作流执行实际开始的地方。可以在**（3）**部分看到，我们正在检查操作系统环境。如果操作系统是 Windows，那么我们将调用`crawler_driver`代码`run_crawler.py`作为子进程。

如果底层环境是基于 Linux 的，那么我们将使用与 Linux 环境相关的命令来调用相同的驱动文件。正如我们之前可能观察到的那样，我们使用子进程调用来将此代码作为单独的进程调用。拥有这种类型的架构背后的原因是为了能够使用异步处理。用户发送的 HTTP 请求应该能够快速得到响应，指示爬取已经开始。我们不能让相同的请求一直保持，直到整个爬取操作完成。为了适应这一点，我们生成一个独立的进程并将爬取任务卸载到该进程中，HTTP 请求立即返回一个指示爬取已经开始的 HTTP 响应。我们进一步将进程 ID 和后端数据库中的项目名称/ID 进行映射，以持续监视扫描的状态。我们通过将控制权重定向到详细 URL 来将控制权返回给用户，详细 URL 反过来返回模板`details.html`。

# 驱动代码 - run_crawler.py

以下代码是`run_crawler.py`文件的代码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/11d5a06c-c6a0-4c34-8966-c4cd4a0c918a.png)

还记得我们如何从`views.py`代码中调用这个文件吗？我们通过传递一个命令行参数来调用它，这个参数是项目的名称。如第**(1)**部分所示，`run_crawler.py`的前面代码将这个命令行参数加载到一个`project_name`程序变量中。在第**(2)**部分，代码尝试从后端数据库表`project`中读取所有参数，使用`project.objects.get(project_name=project_name)`命令。正如之前提到的，Django 遵循 ORM 模型，我们不需要编写原始的 SQL 查询来从数据库表中获取数据。前面的代码片段将在内部转换为`select * from project where project_name=project_name`。因此，所有项目参数都被提取并传递给本地程序变量。

最后，在第**(3)**部分，我们初始化`crawler`类并将所有项目参数传递给它。一旦初始化，我们调用标记为第**(4)**部分的`c.start()`方法。这是爬取开始的地方。在接下来的部分，我们将看到我们的爬虫类的工作方式。

# 爬虫代码 - crawler.py

以下代码片段代表了`crawler`类的构造函数。它初始化了所有相关的实例变量。`logger`是一个自定义类，用于记录调试消息，因此如果在爬虫执行过程中发生任何错误，它将作为一个子进程被生成并在后台运行，可以进行调试：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/55cc89cf-df18-4999-9384-5e457c77afbd.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/de260b8d-d57a-4452-9f49-d5b450c1253c.png)

现在让我们来看一下`crawler`的`start()`方法，从这里开始爬取实际上开始：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/e3b390e3-51b0-4b62-b8ba-505f7ae87594.png)

在第**(1)**部分可以看到，对于第二次迭代（`auth=True`），我们会向用户提供的登录 URL 发出`HTTP GET`请求。我们使用 Python `requests`库中的`GET`方法。当我们向 URL 发出`GET`请求时，响应内容（网页）会被放入`xx`变量中。

现在，如第**(2)**部分所示，我们使用`xx.content`命令提取网页内容，并将提取的内容传递给`Beautifulsoup`模块的实例。`Beautifulsoup`是一个非常好用的 Python 工具，可以使解析网页变得非常简单。从这里开始，我们将用别名 BS 来表示`Beautifulsoup`。

第三部分使用了 BS 解析库中的`s.findall('form')`方法。`findall()`方法接受要搜索的 HTML 元素类型作为字符串参数，并返回一个包含搜索匹配项的列表。如果一个网页包含十个表单，`s.findall('form')`将返回一个包含这十个表单数据的列表。它看起来如下：`[<Form1 data>,<Form2 data>, <Form3 data> ....<Form10 data>]`。

在代码的第四部分，我们正在遍历之前返回的表单列表。这里的目标是在网页上可能存在的多个输入表单中识别登录表单。我们还需要找出登录表单的操作 URL，因为那将是我们`POST`有效凭据并设置有效会话的地方，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/386c8822-761c-43e9-bfce-9ac845603173.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/917dce6b-b79d-4a19-bb25-c60251913528.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/bcad6b00-4d83-4be4-8761-17be78c8848e.png)

让我们试着分解前面的不完整代码，以了解到目前为止发生了什么。然而，在我们继续之前，让我们看一下用户界面，从中获取爬取参数。这将让我们对先决条件有一个很好的了解，并帮助我们更好地理解代码。以下屏幕显示了用户输入参数的表示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/dc67b572-3501-45f3-b936-264b5b4bdfa3.png)

如前所述，爬虫工作分为两次迭代。在第一次迭代中，它尝试在没有身份验证的情况下爬取 Web 应用程序，在第二次迭代中，它使用身份验证爬取应用程序。身份验证信息保存在`self.auth`变量中，默认情况下初始化为`false`。因此，第一次迭代将始终没有身份验证。

应该注意的是，前面提到的代码的目的是从登录网页/URL 中识别登录表单。一旦识别出登录表单，代码就会尝试识别该表单的所有输入字段。然后，它将制定一个包含合法用户凭据的数据有效载荷，以提交登录表单。提交后，将返回并保存一个有效的用户会话。该会话将用于基于身份验证的第二次爬取迭代。

在代码的第五部分，我们正在调用`self.process_form_action()`方法。在此之前，我们提取了表单的操作 URL，以便知道数据将被*发布*的位置。它还将相对操作 URL 与应用程序的基本 URL 结合起来，这样我们最终会将请求发送到一个有效的端点 URL。例如，如果表单操作指向名为`/login`的位置，当前 URL 为`http://127.0.0.1/my_app`，这个方法将执行以下任务：

1.  检查 URL 是否已经添加到爬虫应该访问的 URL 列表中

1.  将操作 URL 与基本上下文 URL 组合并返回`http://127.0.0.1/my_app/login`

这个方法的定义如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/0ca8d816-05a2-43b1-9257-04195a391ff2.png)

可以看到，在这个方法中首先调用的是另一个方法`self.check_and_add_to_visit`。这个方法检查所讨论的 URL 是否已经被添加到爬虫应该爬取的 URL 列表中。如果已经添加，则执行`no9`操作。如果没有，爬虫将该 URL 添加到稍后重新访问。这个方法还检查许多其他事情，比如 URL 是否在范围内，协议是否被允许等等。这个方法的定义如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8eafa6cb-3962-458a-8816-7d6bc272cc1a.png)

如图所示，如果第 158 行下的`self.already_seen()`返回`false`，那么在当前项目的后端数据库`Page`表中将创建一行。这一行再次通过 Django ORM（模型抽象）创建。`self.already_seen()`方法只是检查`Page`表，看看爬虫是否以当前项目名称和当前认证模式访问了问题 URL。这是通过访问标志来验证的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7a854a93-c9cc-4b7b-a1d5-974ab26aeae7.png)

`Page.objects.filter()`相当于`select * from page where auth_visited=True/False and project='current_project' and URL='current_url'`。

在代码的第**（6）**部分，我们将当前表单的内容传递给一个新创建的 BS 解析模块的实例。这样做的原因是我们将解析并提取当前处理的表单中的所有输入字段。一旦输入字段被提取，我们将比较每个输入字段的名称与用户在`username_field`和`password_field`下提供的名称。我们这样做的原因是可能会有多个表单在登录页面上，比如搜索表单、注册表单、反馈表单和登录表单。我们需要能够识别这些表单中的哪一个是登录表单。当我们要求用户提供**登录用户名/电子邮件**字段名称和**登录密码**字段名称时，我们的方法是从所有表单中提取输入字段并将它们与用户提供的内容进行比较。如果我们两个字段都匹配，我们将`flag1`和`flag2`设置为`True`。如果我们在一个表单中找到匹配，很可能这就是我们的登录表单。这是我们将在其中将用户提供的登录凭据放在适当字段下并在操作 URL 下提交表单的表单。这个逻辑由第**（7）**、**（8）**、**（9）**、**（10）**、**（11）**、**（12）**、**（13）**和**（14）**部分处理。

还有一个重要的考虑因素。登录网页上可能还有注册表单。假设用户已经在我们的代码中指定了`username`和`user_pass`作为用户名和密码参数的字段名称，以便在这些字段名称下提交正确的凭据以获得有效会话。然而，注册表单还包含另外两个字段，也称为`username`和`user_pass`，还包含一些其他字段，如**地址**、**电话**、**电子邮件**等。然而，正如前面讨论的，我们的代码只识别这些提供的字段名称的登录表单，并可能将注册表单视为登录表单。为了解决这个问题，我们将所有获取的表单存储在程序列表中。当所有表单都被解析和存储时，我们应该有两个可能的登录表单候选。我们将比较两者的内容长度，长度较短的将被视为登录表单。这是因为注册表单通常比登录表单有更多的字段。这个条件由代码的第**（15）**部分处理，它枚举了所有可能的表单，并最终将最小的表单放在`payloadforms[]`列表和`actionform[]`列表的索引 0 处。

最后，在第 448 行，我们将提供的用户凭据发布到有效解析的登录表单。如果凭据正确，将返回有效会话并放置在会话变量`ss`下。通过调用`POST`方法进行请求，如下所示：`ss.post(action_forms[0],data=payload,cookie=cookie)`。

用户提供要爬取的 Web 应用程序的起始 URL。第**（16）**部分获取该起始 URL 并开始爬取过程。如果有多个起始 URL，它们应该用逗号分隔。起始 URL 被添加到`Page()`数据库表中，作为爬虫应该访问的 URL：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c24126aa-1811-425f-8e6f-3eb1393bb9ab.png)

在第**(17)**节中，有一个爬行循环调用`there_are_pages_to_crawl()`方法，该方法检查后端的`Page()`数据库表，看看当前项目中是否有任何未被访问的页面，visited flag`set = False`。如果表中有尚未被爬行器访问的页面，此方法将返回`True`。由于我们刚刚在第**(16)**节将起始页面添加到`Page`表中，因此此方法将对起始页面返回`True`。其思想是对该页面进行`GET`请求，并提取所有进一步的链接、表单或 URL，并不断将它们添加到`Page`表中。只要有未被访问的页面，循环将继续执行。一旦页面完全解析并提取了所有链接，visited flag 就会被设置为`True`，以便不会再提取该页面或 URL 进行爬行。该方法的定义如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/648bf440-d99e-46be-bbbb-429276042251.png)

在第**(18)**节中，我们通过调用`get_a_page_to_visit()`方法从后端的`Page`表中获取未访问的页面，该方法的定义在这里给出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4bdcd81c-aafd-4cc8-b4da-c6f87e7c81ce.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4bdcd81c-aafd-4cc8-b4da-c6f87e7c81ce.png)

在第**(19)**节中，我们向该页面发出 HTTP `GET`请求，同时携带会话 cookie `ss`，因为第**(19)**节属于处理`auth=True`的迭代。一旦向该页面发出请求，页面的响应将进一步处理以提取更多链接。在处理响应之前，我们检查应用程序产生的响应代码。

有时候，某些页面会返回重定向（`3XX`响应代码），我们需要适当保存 URL 和表单内容。假设我们向页面 X 发出了`GET`请求，响应中有三个表单。理想情况下，我们将以 X 为标记保存这些表单。但是，假设在向页面 X 发出`GET`请求时，我们得到了一个 302 重定向到页面 Y，并且响应 HTML 实际上属于设置重定向的网页。在这种情况下，我们最终会保存与 URL X 映射的三个表单的响应内容，这是不正确的。因此，在第(20)和(21)节中，我们处理这些重定向，并将响应内容与适当的 URL 进行映射：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4bdcd81c-aafd-4cc8-b4da-c6f87e7c81ce.png)

第(22)和(23)节的代码与前面提到的第(19)、(20)和(21)节完全相同，但(22)和(23)节是针对`authentication=False`的迭代进行的：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/4b6fd524-92c5-423e-96aa-4c230d964ae6.png)

如果在处理当前页面时遇到任何异常，第(24)节将处理这些异常，将当前页面的 visited flag 标记为`True`，并在数据库中放置适当的异常消息。

如果一切顺利，控制将传递到第(26)节，从那里开始处理从当前正在访问的页面上的`GET`请求获取的 HTML 响应内容。此处理的目标是进行以下操作：

+   从 HTML 响应中提取所有进一步的链接（`a href`、`base`标签、`Frame`标签、`iframe`标签）

+   从 HTML 响应中提取所有表单

+   提取 HTML 响应中的所有表单字段

代码的第**(26)**节提取了返回的 HTML 响应内容中`base`标签下（如果有的话）存在的所有链接和 URL。

第**(27)**和**(28)**节使用 BS 解析模块解析内容，提取所有锚标签及其`href`位置。一旦提取，它们将被传递以添加到`Pages`数据库表中，以供爬行器以后访问。必须注意的是，只有在检查它们在当前项目和当前身份验证模式下不存在后，才会添加这些链接。

第（29）节使用 BS 解析模块解析内容，以提取所有`iframe`标签及其`src`位置。一旦提取，它们将被传递以添加到`Pages`数据库表中，以便爬虫以后访问。第（30）节对 frame 标签执行相同的操作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/da96a8bd-6587-478b-a449-c57060376a82.png)

第（31）节使用 BS 解析模块解析内容，以提取所有选项标签，并检查它们是否在`value`属性下有链接。一旦提取，它们将被传递以添加到`Pages`数据库表中，以便爬虫以后访问。

代码的第（32）节尝试探索从网页中提取任何遗漏链接的所有其他选项。以下是检查其他可能性的代码片段：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/7405799b-5114-4547-b285-ed249137023b.png)

第（33）和第（34）节从当前 HTML 响应中提取所有表单。如果识别出任何表单，将提取并保存表单标签的各种属性，例如 action 或 method，保存在本地变量中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/917d3776-7194-4557-b226-ef833763f39d.png)

如果识别出任何 HTML 表单，下一个任务是提取所有输入字段、文本区域、选择标签、选项字段、隐藏字段和提交按钮。这是由第（35）、（36）、（37）、（38）和（39）节执行的。最后，所有提取的字段以逗号分隔的方式放在`input_field_list`变量下。例如，假设识别出一个名为`Form1`的表单，其中包含以下字段：

+   `<input type ="text" name="search">`

+   `<input type="hidden" name ="secret">`

+   `<input type="submit" name="submit_button>`

所有这些都被提取为`"Form1" : input_field_list = "search,text,secret,hidden,submit_button,submit"`**.**

代码的第（40）节检查数据库表中是否已经保存了具有当前项目和当前`auth_mode`相同内容的任何表单。如果没有这样的表单存在，则使用 Django ORM（`models`）包再次将表单保存在`Form`表中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/a2ac4a7f-1ce5-4b73-8e65-93295d283408.png)

先前代码的第（41）节继续并将这些唯一的表单保存在以当前项目名称命名的 JSON 文件中。然后可以使用简单的 Python 程序解析此文件，以列出我们爬取的网页应用程序中存在的各种表单和输入字段。此外，在代码的末尾，我们有一个小片段，将所有发现/爬取的页面放在一个文本文件中，以便以后参考。片段如下所示：

```py
 f= open("results/Pages_"+str(self.project.project_name))
    for pg in page_list:
        f.write(pg+"\n")
 f.close()
```

代码的第（42）节更新了刚刚解析内容的网页的访问标志，并标记为当前`auth`模式的已访问。如果在保存期间发生任何异常，这些异常将由第（43）节处理，该节再次将访问标志标记为`true`，但另外添加异常消息。

在第（42）和第（43）节之后，控制再次回到代码的第（17）节。爬虫尚未访问的下一页从数据库中获取，并重复所有操作。这将持续到爬虫访问了所有网页为止。

最后，我们检查当前迭代是否在第（44）节中进行身份验证。如果没有进行身份验证，则调用爬虫的`start()`方法，并将`auth`标志设置为`True`。

成功完成两次迭代后，假定网页应用程序已完全爬取，并且代码的第（45）节将项目状态标记为**已完成**。

# 代码的执行

我们需要做的第一步是将模型类转换为数据库表。可以通过执行`syncdb()`命令来完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1842a8e9-b78d-44e2-bd63-7ef34f41cdff.png)

创建数据库表后，让我们启动 Django 服务器，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/067049a1-d5ed-40c7-a280-d8fe41064921.png)

我们将测试我们的爬虫针对著名的 DVWA 应用程序，以查看它发现了什么。我们需要启动 Apache 服务器并在本地提供 DVWA。可以通过运行以下命令启动 Apache 服务器：

```py
service Apache2 start
```

现在，让我们浏览爬虫界面，并提供以下扫描参数：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/326f3517-bc7e-443c-ad1d-1e96fe5377f0.png)

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/ee6968ff-bcbe-4af0-8085-2e1d9c3246ea.png)

点击**开始爬取**按钮：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/5f087f8b-e2a5-4e9c-bc82-e4bf95fbe61e.png)

现在让我们浏览应用程序的`results`文件夹，位于`<Xtreme_InjectCrawler/results>`路径，以查看发现的 URL 和表单如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/01f854c9-3497-4f8c-8024-b2ea90fdbbd2.png)

首先打开 JSON 文件查看内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/8c68dfc8-4be7-4ffe-a668-8a77a2e187fc.png)

现在，让我们打开`Pages_Dvwa_test`文件，查看发现的 URL 如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/c77b7d22-a667-4a17-a36c-f38777f48b2a.png)

因此，可以验证爬虫已成功爬取了应用程序，并识别了前一个截图中显示的链接：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/hsn-pentest-py/img/1c9bb08e-c24f-4593-a6f1-7f5507a77805.png)

# 摘要

在本章中，我们看到了如何从头开始编写自定义爬虫。使用 Python 的模块，如 requests，BeautifulSoup 等，可以更轻松地完成这项任务。随意下载整个代码库，并测试爬虫与其他各种网站，以检查其覆盖范围。爬虫可能无法达到 100%的覆盖率。看看爬虫的局限性以及如何改进它。

# 问题

1.  如何改进爬虫以涵盖 JavaScript 和 Ajax 调用？

1.  我们如何使用爬虫结果来自动化 Web 应用程序测试？

# 进一步阅读

+   使用 Python 和 Kali Linux 进行渗透测试自动化：[`www.dataquest.io/blog/web-scraping-tutorial-python/`](https://www.dataquest.io/blog/web-scraping-tutorial-python/)

+   *Requests: 人类使用的 HTTP*：[`docs.python-requests.org/en/master/`](http://docs.python-requests.org/en/master/)

+   *Django 项目*：[`www.djangoproject.com/`](https://www.djangoproject.com/)

+   使用 Python 和 Kali Linux 进行渗透测试自动化：[`scrapy.org/`](https://scrapy.org/)
