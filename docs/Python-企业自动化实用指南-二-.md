# Python 企业自动化实用指南（二）

> 原文：[`zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d`](https://zh.annas-archive.org/md5/0bfb2f4dbc80a06d99550674abb53d0d)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Python 脚本的并行执行

Python 已成为网络自动化的*事实*标准。许多网络工程师已经每天使用它来自动化网络任务，从配置到操作，再到解决网络问题。在本章中，我们将讨论 Python 中的一个高级主题：挖掘 Python 的多进程特性，并学习如何使用它来加速脚本执行时间。

本章将涵盖以下主题：

+   Python 代码在操作系统中的执行方式

+   Python 多进程库

# 计算机如何执行您的 Python 脚本

这是您计算机的操作系统执行 Python 脚本的方式：

1.  当您在 shell 中键入`python <your_awesome_automation_script>.py`时，Python（作为一个进程运行）指示您的计算机处理器安排一个线程（这是处理的最小单位）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00121.jpeg)

1.  分配的线程将开始逐行执行您的脚本。线程可以做任何事情，包括与 I/O 设备交互，连接到路由器，打印输出，执行数学方程等等。

1.  一旦脚本达到**文件结束**（**EOF**），线程将被终止并返回到空闲池中，供其他进程使用。然后，脚本被终止。

在 Linux 中，您可以使用`#strace –p <pid>`来跟踪特定线程的执行。

您为脚本分配的线程越多（并且得到处理器或操作系统允许的线程越多），脚本运行得越快。实际上，有时线程被称为**工作者**或**从属**。

我有一种感觉，你脑海中有这样一个小想法：为什么我们不从所有核心中为 Python 脚本分配大量线程，以便快速完成工作呢？

如果没有特殊处理，将大量线程分配给一个进程的问题是**竞争条件**。操作系统将为您的进程（在本例中是 Python 进程）分配内存，以供运行时所有线程访问 - *同时*。现在，想象一下其中一个线程在另一个线程实际写入数据之前读取了一些数据！您不知道线程尝试访问共享数据的顺序；这就是竞争条件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00122.jpeg)

一种可用的解决方案是使线程获取锁。事实上，默认情况下，Python 被优化为作为单线程进程运行，并且有一个叫做**全局解释器锁**（**GIL**）的东西。为了防止线程之间的冲突，GIL 不允许多个线程同时执行 Python 代码。

但是，为什么不使用多个进程，而不是多个线程呢？

多进程的美妙之处，与多线程相比，就在于你不必担心由于共享数据而导致数据损坏。每个生成的进程都将拥有自己分配的内存，其他 Python 进程无法访问。这使我们能够同时执行并行任务：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00123.jpeg)

此外，从 Python 的角度来看，每个进程都有自己的 GIL。因此，在这里没有资源冲突或竞争条件。

# Python 多进程库

`multiprocessing`模块是 Python 的标准库，随 Python 二进制文件一起提供，并且从 Python 2.6 版本开始可用。还有`threading`模块，它允许您生成多个线程，但它们都共享相同的内存空间。多进程比线程具有更多的优势。其中之一是每个进程都有独立的内存空间，并且可以利用多个 CPU 和核心。

# 开始使用多进程

首先，您需要为 Python 脚本导入模块：

```py
import multiprocessing as mp
```

然后，用 Python 函数包装您的代码；这将允许进程针对此函数并将其标记为并行执行。

假设我们有连接到路由器并使用`netmiko`库在其上执行命令的代码，并且我们希望并行连接到所有设备。这是一个样本串行代码，将连接到每个设备并执行传递的命令，然后继续第二个设备，依此类推：

```py
from netmiko import ConnectHandler
from devices import R1, SW1, SW2, SW3, SW4

nodes = [R1, SW1, SW2, SW3, SW4]   for device in nodes:
  net_connect = ConnectHandler(**device)
  output = net_connect.send_command("show run")
  print output
```

Python 文件`devices.py`创建在与我们的脚本相同的目录中，并以`dictionary`格式包含每个设备的登录详细信息和凭据：

```py
  R1 = {"device_type": "cisco_ios_ssh",
      "ip": "10.10.88.110",
      "port": 22,
      "username": "admin",
      "password": "access123",
      }

SW1 = {"device_type": "cisco_ios_ssh",
       "ip": "10.10.88.111",
       "port": 22,
       "username": "admin",
       "password": "access123",
       }

SW2 = {"device_type": "cisco_ios_ssh",
       "ip": "10.10.88.112",
       "port": 22,
       "username": "admin",
       "password": "access123",
       }

SW3 = {"device_type": "cisco_ios_ssh",
       "ip": "10.10.88.113",
       "port": 22,
       "username": "admin",
       "password": "access123",
       }

SW4 = {"device_type": "cisco_ios_ssh",
       "ip": "10.10.88.114",
       "port": 22,
       "username": "admin",
       "password": "access123",
       } 
```

现在，如果我们想要改用多进程模块，我们需要重新设计脚本并将代码移动到一个函数下；然后，我们将分配与设备数量相等的进程数（一个进程将连接到一个设备并执行命令），并将进程的目标设置为执行此函数：

```py
  from netmiko import ConnectHandler
from devices import R1, SW1, SW2, SW3, SW4
import multiprocessing as mp
from datetime import datetime

nodes = [R1, SW1, SW2, SW3, SW4]    def connect_to_dev(device):    net_connect = ConnectHandler(**device)
  output = net_connect.send_command("show run")
  print output

processes = []   start_time = datetime.now() for device in nodes:
  print("Adding Process to the list")
  processes.append(mp.Process(target=connect_to_dev, args=[device]))   print("Spawning the Process") for p in processes:
  p.start()   print("Joining the finished process to the main truck") for p in processes:
  p.join()   end_time = datetime.now() print("Script Execution tooks {}".format(end_time - start_time))   
```

在前面的例子中，适用以下内容：

+   我们将`multiprocess`模块导入为`mp`。模块中最重要的类之一是`Process`，它将我们的`netmiko connect`函数作为目标参数。此外，它接受将参数传递给目标函数。

+   然后，我们遍历我们的节点，并为每个设备创建一个进程，并将该进程附加到进程列表中。

+   模块中可用的`start()`方法用于生成并启动进程执行。

+   最后，脚本执行时间通过从脚本结束时间减去脚本开始时间来计算。

在幕后，执行主脚本的主线程将开始分叉与设备数量相等的进程。每个进程都针对一个函数，同时在所有设备上执行`show run`，并将输出存储在一个变量中，互不影响。

这是 Python 中进程的一个示例视图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00124.jpeg)

现在，当您执行完整的代码时，还需要做一件事。您需要将分叉的进程连接到主线程/主线程，以便顺利完成程序的执行：

```py
for p in processes:
  p.join()
```

在前面的例子中使用的`join()`方法与原始的字符串方法`join()`无关；它只是用来将进程连接到主线程。

# 进程之间的通信

有时，您将有一个需要在运行时与其他进程传递或交换信息的进程。多进程模块有一个`Queue`类，它实现了一个特殊的列表，其中一个进程可以插入和消耗数据。在这个类中有两个可用的方法：`get()`和`put()`。`put()`方法用于向`Queue`添加数据，而从队列获取数据则通过`get()`方法完成。在下一个示例中，我们将使用`Queue`来将数据从子进程传递到父进程：

```py
import multiprocessing
from netmiko import ConnectHandler
from devices import R1, SW1, SW2, SW3, SW4
from pprint import pprint

nodes = [R1, SW1, SW2, SW3, SW4]   def connect_to_dev(device, mp_queue):
  dev_id = device['ip']
  return_data = {}   net_connect = ConnectHandler(**device)   output = net_connect.send_command("show run")   return_data[dev_id] = output
    print("Adding the result to the multiprocess queue")
  mp_queue.put(return_data)   mp_queue = multiprocessing.Queue() processes = []   for device in nodes:
  p = multiprocessing.Process(target=connect_to_dev, args=[device, mp_queue])
  print("Adding Process to the list")
  processes.append(p)
  p.start()   for p in processes:
  print("Joining the finished process to the main truck")
  p.join()   results = [] for p in processes:
  print("Moving the result from the queue to the results list")
  results.append(mp_queue.get())   pprint(results)
```

在前面的例子中，适用以下内容：

+   我们从`multiprocess`模块中导入了另一个名为`Queue()`的类，并将其实例化为`mp_queue`变量。

+   然后，在进程创建过程中，我们将此队列作为参数与设备一起附加，因此每个进程都可以访问相同的队列并能够向其写入数据。

+   `connect_to_dev()`函数连接到每个设备并在终端上执行`show run`命令，然后将输出写入共享队列。

请注意，在将其添加到共享队列之前，我们将输出格式化为字典项`{ip:<command_output>}`，并使用`mp_queue.put()`将其添加到共享队列中。

+   在进程完成执行并加入主（父）进程之后，我们使用`mp_queue.get()`来检索结果列表中的队列项，然后使用`pprint`来漂亮地打印输出。

# 概要

在本章中，我们学习了 Python 多进程库以及如何实例化和并行执行 Python 代码。

在下一章中，我们将学习如何准备实验室环境并探索自动化选项以加快服务器部署速度。


# 第八章：准备实验室环境

在本章中，我们将使用两个流行的 Linux 发行版 CentOS 和 Ubuntu 来设置实验室。CentOS 是一个以社区驱动的 Linux 操作系统，面向企业服务器，并以其与**Red Hat Enterprise Linux**（**RHEL**）的兼容性而闻名。Ubuntu 是另一个基于著名的 Debian 操作系统的 Linux 发行版；目前由 Canonical Ltd.开发，并为其提供商业支持。

我们还将学习如何使用名为**Cobbler**的免费开源软件安装这两个 Linux 发行版，它将使用`kickstart`为 CentOS 自动引导服务器并使用 Anaconda 为基于 Debian 的系统进行自定义。

本章将涵盖以下主题：

+   获取 Linux 操作系统

+   在 hypervisor 上创建一个自动化机器

+   开始使用 Cobbler

# 获取 Linux 操作系统

在接下来的章节中，我们将在不同的 hypervisors 上创建两台 Linux 机器，CentOS 和 Ubuntu。这些机器将作为我们环境中的自动化服务器。

# 下载 CentOS

CentOS 二进制文件可以通过多种方法下载。您可以直接从世界各地的多个 FTP 服务器下载它们，也可以从种子人员那里以种子方式下载它们。此外，CentOS 有两种版本：

+   Minimal ISO：提供基本服务器和必要软件包

+   Everything ISO：提供服务器和主要存储库中的所有可用软件包

首先，前往 CentOS 项目链接（[`www.centos.org/`](https://www.centos.org/)）并单击获取 CentOS 现在按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00126.jpeg)

然后，选择最小的 ISO 镜像，并从任何可用的下载站点下载它。

CentOS 可用于多个云提供商，如 Google、Amazon、Azure 和 Oracle Cloud。您可以在[`cloud.centos.org/centos/7/images/`](https://cloud.centos.org/centos/7/images/)找到所有云镜像。

# 下载 Ubuntu

Ubuntu 以为为向最终用户提供良好的桌面体验而广为人知。Canonical（Ubuntu 开发者）与许多服务器供应商合作，以在不同的硬件上认证 Ubuntu。Canonical 还为 Ubuntu 提供了一个服务器版本，其中包括 16.04 中的许多功能，例如：

+   Canonical 将在 2021 年之前提供支持

+   能够在所有主要架构上运行-x86、x86-64、ARM v7、ARM64、POWER8 和 IBM s390x（LinuxONE）

+   ZFS 支持，这是一种适用于服务器和容器的下一代卷管理文件系统

+   LXD Linux 容器 hypervisor 增强，包括 QoS 和资源控制（CPU、内存、块 I/O 和存储配额）

+   安装 snaps，用于简单的应用程序安装和发布管理。

+   DPDK 的首个生产版本-线速内核网络

+   Linux 4.4 内核和`systemd`服务管理器

+   作为 AWS、Microsoft Azure、Joyent、IBM、Google Cloud Platform 和 Rackspace 上的客户进行认证

+   Tomcat（v8）、PostgreSQL（v9.5）、Docker v（1.10）、Puppet（v3.8.5）、QEMU（v2.5）、Libvirt（v1.3.1）、LXC（v2.0）、MySQL（v5.6）等的更新

您可以通过浏览至[`www.ubuntu.com/download/server`](https://www.ubuntu.com/download/server)并选择 Ubuntu 16.04 LTS 来下载 Ubuntu LTS：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00127.jpeg)

# 在 hypervisor 上创建一个自动化机器

下载 ISO 文件后，我们将在 VMware ESXi 和 KVM hypervisors 上创建一个 Linux 机器。

# 在 VMware ESXi 上创建一个 Linux 机器

我们将使用 VMware vSphere 客户端创建一个虚拟机。使用 root 凭据登录到可用的 ESXi 服务器之一。首先，您需要将 Ubuntu 或 CentOS ISO 上传到 VMware 数据存储中。然后，按照以下步骤创建机器：

1.  右键单击服务器名称，然后选择新的虚拟机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00128.jpeg)

1.  选择自定义安装，这样您在安装过程中将有更多选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00129.gif)

1.  为 VM 提供一个名称：AutomationServer。

1.  选择机器版本：8。

1.  选择要创建机器的数据存储。

1.  选择客户操作系统：Ubuntu Linux（64 位）或 Red Hat 版本 6/7：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00130.gif)

1.  VM 规格不应少于 2 个 vCPU 和 4GB RAM，以便获得高效的性能。分别在 CPU 和内存选项卡中选择它们。

1.  在“网络”选项卡中，选择两个带有 E1000 适配器的接口。其中一个接口将连接到互联网，第二个接口将管理客户端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00131.gif)

1.  选择系统的默认 SCSI 控制器。在我的情况下，它将是 LSI 逻辑并行。

1.  选择创建一个新的虚拟磁盘，并为 VM 提供 20GB 的磁盘大小。

1.  现在虚拟机已准备就绪，您可以开始 Linux 操作系统的安装。将上传的镜像关联到 CD/DVD 驱动器，并确保选择“开机时连接”选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00132.jpeg)

一旦它开始运行，您将被要求选择一种语言：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00133.jpeg)

按照通常的步骤完成 CentOS/Ubuntu 安装。

# 在 KVM 上创建 Linux 机器

我们将使用 KVM 中提供的`virt-manager`实用程序启动 KVM 的桌面管理。然后我们将创建一个新的 VM：

1.  在这里，我们将选择本地安装媒体（ISO 镜像或 CDROM）作为安装方法：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00134.jpeg)

1.  然后，我们将点击浏览并选择先前下载的镜像（CentOS 或 Ubuntu）。您将注意到 KVM 成功检测到操作系统类型和版本：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00135.jpeg)

1.  然后，我们将根据 CPU、内存和存储选择机器规格：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00136.jpeg)

1.  为您的机器选择适当的存储空间：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00137.jpeg)

1.  最后一步是选择一个名称，然后点击“在安装前自定义配置”选项，以添加一个额外的网络接口到自动化服务器。然后，点击“完成”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00138.jpeg)

打开另一个窗口，其中包含机器的所有规格。点击“添加硬件”，然后选择“网络”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00139.jpeg)

我们将添加另一个网络接口以与客户端通信。第一个网络接口使用 NAT 通过物理无线网卡连接到互联网：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00140.jpeg)

最后，在主窗口上点击“开始安装”，KVM 将开始分配硬盘并将 ISO 镜像附加到虚拟机上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00141.jpeg)

一旦完成，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00142.jpeg)

按照通常的步骤完成 CentOS/Ubuntu 安装。

# 开始使用 Cobbler

Cobbler 是一款用于无人值守网络安装的开源软件。它利用多个工具，如 DHCP、FTP、PXE 和其他开源工具（稍后我们将解释它们），以便您可以一站式自动安装操作系统。目标机器（裸机或虚拟机）必须支持从其**网络接口卡**（NIC）引导。此功能使机器能够发送一个 DHCP 请求，该请求会命中 Cobbler 服务器，后者将处理其余事宜。

您可以在其 GitHub 页面上阅读有关该项目的更多信息（[`github.com/cobbler/cobbler`](https://github.com/cobbler/cobbler)）。

# 了解 Cobbler 的工作原理

Cobbler 依赖于多个工具来为客户端提供**预引导执行环境**（PXE）功能。首先，它依赖于接收客户端开机时的 DHCP 广播消息的 DHCP 服务；然后，它会回复一个 IP 地址、子网掩码、下一个服务器（TFTP），最后是`pxeLinux.0`，这是客户端最初向服务器发送 DHCP 消息时请求的加载程序文件名。

第二个工具是 TFTP 服务器，它托管`pxeLinux.0`和不同的发行版镜像。

第三个工具是模板渲染实用程序。Cobbler 使用`cheetah`，这是一个由 Python 开发的开源模板引擎，并且有自己的 DSL（特定领域语言）格式。我们将使用它来生成`kickstart`文件。

Kickstart 文件用于自动安装基于 Red Hat 的发行版，如 CentOS、Red Hat 和 Fedora。它还有限的支持用于安装基于 Debian 系统的`Anaconda`文件的渲染。

还有其他附加工具。`reposync`用于将在线存储库从互联网镜像到 Cobbler 内的本地目录，使其对客户端可用。`ipmitools`用于远程管理不同服务器硬件的开关机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00143.jpeg)

在以下拓扑中，Cobbler 托管在先前安装的自动化服务器上，并将连接到一对服务器。我们将通过 Cobbler 在它们上安装 Ubuntu 和 Red Hat。自动化服务器还有另一个接口直接连接到互联网，以便下载 Cobbler 所需的一些附加软件包，我们将在下一节中看到：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00144.jpeg)

| **服务器** | **IP 地址** |
| --- | --- |
| 自动化服务器（已安装 cobbler） | `10.10.10.130` |
| 服务器 1（CentOS 机器） | IP 范围为`10.10.10.5`-`10.10.10.10` |
| 服务器 2（Ubuntu 机器） | IP 范围为`10.10.10.5`-`10.10.10.10` |

# 在自动化服务器上安装 Cobbler

我们将首先在我们的自动化服务器（无论是 CentOS 还是 Ubuntu）上安装一些基本软件包，如`vim`、`tcpudump`、`wget`和`net-tools`。然后，我们将从`epel`存储库安装`cobbler`软件包。请注意，这些软件包对于 Cobbler 并不是必需的，但我们将使用它们来了解 Cobbler 的真正工作原理。

对于 CentOS，请使用以下命令：

```py
yum install vim vim-enhanced tcpdump net-tools wget git -y
```

对于 Ubuntu，请使用以下命令：

```py
sudo apt install vim tcpdump net-tools wget git -y
```

然后，我们需要禁用防火墙。Cobbler 与 SELinux 策略不兼容，建议禁用它，特别是如果您对它们不熟悉。此外，我们将禁用`iptables`和`firewalld`，因为我们在实验室中，而不是在生产环境中。

对于 CentOS，请使用以下命令：

```py
# Disable firewalld service
systemctl disable firewalld
systemctl stop firewalld

# Disable IPTables service
systemctl disable iptables.service
systemctl stop iptables.service

# Set SELinux to permissive instead of enforcing
sed -i s/^SELinux=.*$/SELinux=permissive/ /etc/seLinux/config
setenforce 0
```

对于 Ubuntu，请使用以下命令：

```py
# Disable ufw service
sudo ufw disable

# Disable IPTables service 
sudo iptables-save > $HOME/BeforeCobbler.txt 
sudo iptables -X 
sudo iptables -t nat -F 
sudo iptables -t nat -X 
sudo iptables -t mangle -F 
sudo iptables -t mangle -X 
sudo iptables -P INPUT ACCEPT 
sudo iptables -P FORWARD ACCEPT 
sudo iptables -P OUTPUT ACCEPT

# Set SELinux to permissive instead of enforcing
sed -i s/^SELinux=.*$/SELinux=permissive/ /etc/seLinux/config
setenforce 0
```

最后，重新启动自动化服务器机器以使更改生效：

```py
reboot
```

现在，我们将安装`cobbler`软件包。该软件在`epel`存储库中可用（但我们需要先安装它）在 CentOS 的情况下。Ubuntu 在上游存储库中没有该软件可用，因此我们将在该平台上下载源代码并进行编译。

对于 CentOS，请使用以下命令：

```py
# Download and Install EPEL Repo
yum install epel-release -y

# Install Cobbler
yum install cobbler -y

#Install cobbler Web UI and other dependencies
yum install cobbler-web dnsmasq fence-agents bind xinetd pykickstart -y
```

撰写本书时的 Cobbler 当前版本为 2.8.2，发布于 2017 年 9 月 16 日。对于 Ubuntu，我们将从 GIT 存储库克隆最新的软件包，并从源代码构建它：

```py
#install the dependencies as stated in (http://cobbler.github.io/manuals/2.8.0/2/1_-_Prerequisites.html)

sudo apt-get install createrepo apache2 mkisofs libapache2-mod-wsgi mod_ssl python-cheetah python-netaddr python-simplejson python-urlgrabber python-yaml rsync sysLinux atftpd yum-utils make python-dev python-setuptools python-django -y

#Clone the cobbler 2.8 from the github to your server (require internet)
git clone https://github.com/cobbler/cobbler.git
cd cobbler

#Checkout the release28 (latest as the developing of this book)
git checkout release28

#Build the cobbler core package
make install

#Build cobbler web
make webtest
```

成功在我们的机器上安装 Cobbler 后，我们需要自定义它以更改默认设置以适应我们的网络环境。我们需要更改以下内容：

+   选择`bind`或`dnsmasq`模块来管理 DNS 查询

+   选择`isc`或`dnsmaasq`模块来为客户端提供传入的 DHCP 请求

+   配置 TFTP Cobbler IP 地址（在 Linux 中通常是静态地址）。

+   提供为客户端提供 DHCP 范围

+   重新启动服务以应用配置

让我们逐步查看配置：

1.  选择`dnsmasq`作为 DNS 服务器：

```py
vim /etc/cobbler/modules.conf
[dns]
module = manage_dnsmasq
vim /etc/cobbler/settings
manage_dns: 1
restart_dns: 1
```

1.  选择`dnsmasq`来管理 DHCP 服务：

```py
vim /etc/cobbler/modules.conf

[dhcp]
module = manage_dnsmasq
vim /etc/cobbler/settings
manage_dhcp: 1
restart_dhcp: 1
```

1.  将 Cobbler IP 地址配置为 TFTP 服务器：

```py
vim /etc/cobbler/settings
server: 10.10.10.130
next_server: 10.10.10.130
vim /etc/xinetd.d/tftp
 disable                 = no
```

还要通过将`pxe_just_once`设置为`0`来启用 PXE 引导循环预防：

```py
pxe_just_once: 0
```

1.  在`dnsmasq`服务模板中添加客户端`dhcp-range`：

```py
vim /etc/cobbler/dnsmasq.template
dhcp-range=10.10.10.5,10.10.10.10,255.255.255.0
```

注意其中一行写着`dhcp-option=66,$next_server`。这意味着 Cobbler 将把之前在设置中配置为 TFTP 引导服务器的`next_server`传递给通过`dnsmasq`提供的 DHCP 服务请求 IP 地址的任何客户端。

1.  启用并重新启动服务：

```py
systemctl enable cobblerd
systemctl enable httpd
systemctl enable dnsmasq

systemctl start cobblerd
systemctl start httpd
systemctl start dnsmasq
```

# 通过 Cobbler 提供服务器

现在我们离通过 Cobbler 使我们的第一台服务器运行起来只有几步之遥。基本上，我们需要告诉 Cobbler 我们客户端的 MAC 地址以及它们使用的操作系统：

1.  导入 Linux ISO。Cobbler 将自动分析映像并为其创建一个配置文件：

```py

cobbler import --arch=x86_64 --path=/mnt/cobbler_images --name=CentOS-7-x86_64-Minimal-1708

task started: 2018-03-28_132623_import
task started (id=Media import, time=Wed Mar 28 13:26:23 2018)
Found a candidate signature: breed=redhat, version=rhel6
Found a candidate signature: breed=redhat, version=rhel7
Found a matching signature: breed=redhat, version=rhel7
Adding distros from path /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64:
creating new distro: CentOS-7-Minimal-1708-x86_64
trying symlink: /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64 -> /var/www/cobbler/links/CentOS-7-Minimal-1708-x86_64
creating new profile: CentOS-7-Minimal-1708-x86_64
associating repos
checking for rsync repo(s)
checking for rhn repo(s)
checking for yum repo(s)
starting descent into /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64 for CentOS-7-Minimal-1708-x86_64
processing repo at : /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64
need to process repo/comps: /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64
looking for /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/repodata/*comps*.xml
Keeping repodata as-is :/var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/repodata
*** TASK COMPLETE ***
```

在将其导入到挂载点之前，您可能需要挂载 Linux ISO 映像，使用`mount -O loop /root/<image_iso>  /mnt/cobbler_images/`。

您可以运行`cobbler profile report`命令来检查创建的配置文件：

```py
cobbler profile report

Name                           : CentOS-7-Minimal-1708-x86_64
TFTP Boot Files                : {}
Comment                        : 
DHCP Tag                       : default
Distribution                   : CentOS-7-Minimal-1708-x86_64
Enable gPXE?                   : 0
Enable PXE Menu?               : 1
Fetchable Files                : {}
Kernel Options                 : {}
Kernel Options (Post Install)  : {}
Kickstart                      : /var/lib/cobbler/kickstarts/sample_end.ks
Kickstart Metadata             : {}
Management Classes             : []
Management Parameters          : <<inherit>>
Name Servers                   : []
Name Servers Search Path       : []
Owners                         : ['admin']
Parent Profile                 : 
Internal proxy                 : 
Red Hat Management Key         : <<inherit>>
Red Hat Management Server      : <<inherit>>
Repos                          : []
Server Override                : <<inherit>>
Template Files                 : {}
Virt Auto Boot                 : 1
Virt Bridge                    : xenbr0
Virt CPUs                      : 1
Virt Disk Driver Type          : raw
Virt File Size(GB)             : 5
Virt Path                      : 
Virt RAM (MB)                  : 512
Virt Type                      : kvm
```

您可以看到`import`命令自动填充了许多字段，如`Kickstart`、`RAM`、`操作系统`和`initrd/kernel`文件位置。

1.  向配置文件添加任何额外的存储库（可选）：

```py
cobbler repo add --mirror=https://dl.fedoraproject.org/pub/epel/7/x86_64/ --name=epel-local --priority=50 --arch=x86_64 --breed=yum

cobbler reposync 
```

现在，编辑配置文件，并将创建的存储库添加到可用存储库列表中：

```py
cobbler profile edit --name=CentOS-7-Minimal-1708-x86_64 --repos="epel-local"
```

1.  添加客户端 MAC 地址并将其链接到创建的配置文件：

```py
cobbler system add --name=centos_client --profile=CentOS-7-Minimal-1708-x86_64  --mac=00:0c:29:4c:71:7c --ip-address=10.10.10.5 --subnet=255.255.255.0 --static=1 --hostname=centos-client  --gateway=10.10.10.1 --name-servers=8.8.8.8 --interface=eth0
```

`--hostname`字段对应于本地系统名称，并使用`--ip-address`、`--subnet`和`--gateway`选项配置客户端网络。这将使 Cobbler 生成一个带有这些选项的`kickstart`文件。

如果您需要自定义服务器并添加额外的软件包、配置防火墙、ntp 以及配置分区和硬盘布局，那么您可以将这些设置添加到`kickstart`文件中。Cobbler 在`/var/lib/cobbler/kickstarts/sample.ks`下提供了示例文件，您可以将其复制到另一个文件夹，并在上一个命令中提供`--kickstart`参数。

您可以通过在`kickstart`文件中运行 Ansible 来将 Ansible 集成到其中，使用拉模式（而不是默认的推送模式）。Ansible 将从在线 GIT 存储库（如 GitHub 或 GitLab）下载 playbook，并在此之后执行它。

1.  通过以下命令指示 Cobbler 生成为我们的客户端提供服务所需的配置文件，并使用新信息更新内部数据库：

```py
#cobbler sync  task started: 2018-03-28_141922_sync
task started (id=Sync, time=Wed Mar 28 14:19:22 2018)
running pre-sync triggers
cleaning trees
removing: /var/www/cobbler/images/CentOS-7-Minimal-1708-x86_64
removing: /var/www/cobbler/images/Ubuntu_Server-x86_64
removing: /var/www/cobbler/images/Ubuntu_Server-hwe-x86_64
removing: /var/lib/tftpboot/pxeLinux.cfg/default
removing: /var/lib/tftpboot/pxeLinux.cfg/01-00-0c-29-4c-71-7c
removing: /var/lib/tftpboot/grub/01-00-0C-29-4C-71-7C
removing: /var/lib/tftpboot/grub/efidefault
removing: /var/lib/tftpboot/grub/grub-x86_64.efi
removing: /var/lib/tftpboot/grub/images
removing: /var/lib/tftpboot/grub/grub-x86.efi
removing: /var/lib/tftpboot/images/CentOS-7-Minimal-1708-x86_64
removing: /var/lib/tftpboot/images/Ubuntu_Server-x86_64
removing: /var/lib/tftpboot/images/Ubuntu_Server-hwe-x86_64
removing: /var/lib/tftpboot/s390x/profile_list
copying bootloaders
trying hardlink /var/lib/cobbler/loaders/grub-x86_64.efi -> /var/lib/tftpboot/grub/grub-x86_64.efi
trying hardlink /var/lib/cobbler/loaders/grub-x86.efi -> /var/lib/tftpboot/grub/grub-x86.efi
copying distros to tftpboot
copying files for distro: Ubuntu_Server-x86_64
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/netboot/ubuntu-installer/amd64/Linux -> /var/lib/tftpboot/images/Ubuntu_Server-x86_64/Linux
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/netboot/ubuntu-installer/amd64/initrd.gz -> /var/lib/tftpboot/images/Ubuntu_Server-x86_64/initrd.gz
copying files for distro: Ubuntu_Server-hwe-x86_64
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/hwe-netboot/ubuntu-installer/amd64/Linux -> /var/lib/tftpboot/images/Ubuntu_Server-hwe-x86_64/Linux
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/hwe-netboot/ubuntu-installer/amd64/initrd.gz -> /var/lib/tftpboot/images/Ubuntu_Server-hwe-x86_64/initrd.gz
copying files for distro: CentOS-7-Minimal-1708-x86_64
trying hardlink /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/images/pxeboot/vmlinuz -> /var/lib/tftpboot/images/CentOS-7-Minimal-1708-x86_64/vmlinuz
trying hardlink /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/images/pxeboot/initrd.img -> /var/lib/tftpboot/images/CentOS-7-Minimal-1708-x86_64/initrd.img
copying images
generating PXE configuration files
generating: /var/lib/tftpboot/pxeLinux.cfg/01-00-0c-29-4c-71-7c
generating: /var/lib/tftpboot/grub/01-00-0C-29-4C-71-7C
generating PXE menu structure
copying files for distro: Ubuntu_Server-x86_64
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/netboot/ubuntu-installer/amd64/Linux -> /var/www/cobbler/images/Ubuntu_Server-x86_64/Linux
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/netboot/ubuntu-installer/amd64/initrd.gz -> /var/www/cobbler/images/Ubuntu_Server-x86_64/initrd.gz
Writing template files for Ubuntu_Server-x86_64
copying files for distro: Ubuntu_Server-hwe-x86_64
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/hwe-netboot/ubuntu-installer/amd64/Linux -> /var/www/cobbler/images/Ubuntu_Server-hwe-x86_64/Linux
trying hardlink /var/www/cobbler/ks_mirror/Ubuntu_Server-x86_64/install/hwe-netboot/ubuntu-installer/amd64/initrd.gz -> /var/www/cobbler/images/Ubuntu_Server-hwe-x86_64/initrd.gz
Writing template files for Ubuntu_Server-hwe-x86_64
copying files for distro: CentOS-7-Minimal-1708-x86_64
trying hardlink /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/images/pxeboot/vmlinuz -> /var/www/cobbler/images/CentOS-7-Minimal-1708-x86_64/vmlinuz
trying hardlink /var/www/cobbler/ks_mirror/CentOS-7-x86_64-Minimal-1708-x86_64/images/pxeboot/initrd.img -> /var/www/cobbler/images/CentOS-7-Minimal-1708-x86_64/initrd.img
Writing template files for CentOS-7-Minimal-1708-x86_64
rendering DHCP files
rendering DNS files
rendering TFTPD files
generating /etc/xinetd.d/tftp
processing boot_files for distro: Ubuntu_Server-x86_64
processing boot_files for distro: Ubuntu_Server-hwe-x86_64
processing boot_files for distro: CentOS-7-Minimal-1708-x86_64
cleaning link caches
running post-sync triggers
running python triggers from /var/lib/cobbler/triggers/sync/post/*
running python trigger cobbler.modules.sync_post_restart_services
running: service dnsmasq restart
received on stdout: 
received on stderr: Redirecting to /bin/systemctl restart dnsmasq.service

running shell triggers from /var/lib/cobbler/triggers/sync/post/*
running python triggers from /var/lib/cobbler/triggers/change/*
running python trigger cobbler.modules.scm_track
running shell triggers from /var/lib/cobbler/triggers/change/*
*** TASK COMPLETE ***
```

一旦您启动了 CentOS 客户端，您将注意到它进入 PXE 过程并通过`PXE_Network`发送 DHCP 消息。Cobbler 将以 MAC 地址分配一个 IP 地址、一个`PXELinux0`文件和所需的镜像来响应：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00145.jpeg)

在 Cobbler 完成 CentOS 安装后，您将看到主机名在机器中正确配置：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00146.jpeg)

您可以为 Ubuntu 机器执行相同的步骤。

# 摘要

在本章中，您学习了如何通过在虚拟化程序上安装两台 Linux 机器（CentOS 和 Ubuntu）来准备实验室环境。然后，我们探讨了自动化选项，并通过安装 Cobbler 加快了服务器部署速度。

在下一章中，您将学习如何从 Python 脚本直接向操作系统 shell 发送命令并调查返回的输出。


# 第九章：使用 Subprocess 模块

运行和生成新的系统进程对于想要自动化特定操作系统任务或在脚本中执行一些命令的系统管理员非常有用。Python 提供了许多库来调用外部系统实用程序，并与生成的数据进行交互。最早创建的库是`OS`模块，它提供了一些有用的工具来调用外部进程，比如`os.system`，`os.spwan`和`os.popen*`。然而，它缺少一些基本功能，因此 Python 开发人员引入了一个新的库，`subprocess`，它可以生成新的进程，与进程发送和接收，并处理错误和返回代码。目前，官方 Python 文档建议使用`subprocess`模块来访问系统命令，Python 实际上打算用它来替换旧的模块。

本章将涵盖以下主题：

+   `Popen()`子进程

+   读取`stdin`，`stdout`和`stderr`

+   子进程调用套件

# popen()子进程

`subprocess`模块只实现了一个类：`popen()`。这个类的主要用途是在系统上生成一个新的进程。这个类可以接受运行进程的额外参数，以及`popen()`本身的额外参数：

| **参数** | **含义** |
| --- | --- |
| `args` | 一个字符串，或者程序参数的序列。 |
| `bufsize` | 它作为`open()`函数的缓冲参数提供，用于创建`stdin`/`stdout`/`stderr`管道文件对象。 |
| `executable` | 要执行的替换程序。 |
| `stdin`，`stdout`，`stderr` | 这些分别指定了执行程序的标准输入、标准输出和标准错误文件句柄。 |
| `shell` | 如果为`True`，则命令将通过 shell 执行（默认为`False`）。在 Linux 中，这意味着在运行子进程之前调用`/bin/sh`。 |
| `cwd` | 在执行子进程之前设置当前目录。 |
| `env` | 定义新进程的环境变量。 |

现在，让我们专注于`args`。`popen()`命令可以接受 Python 列表作为输入，其中第一个元素被视为命令，后续元素被视为命令`args`，如下面的代码片段所示：

```py
import subprocess
print(subprocess.Popen("ifconfig"))
```

**脚本输出**![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00147.jpeg)

从命令返回的输出直接打印到您的 Python 终端。

`ifconfig`是一个用于返回网络接口信息的 Linux 实用程序。对于 Windows 用户，您可以通过在 cmd 上使用`ipconfig`命令来获得类似的输出。

我们可以重写上面的代码，使用列表而不是字符串，如下面的代码片段所示：

```py
print(subprocess.Popen(["ifconfig"]))
```

使用这种方法允许您将额外的参数添加到主命令作为列表项：

```py
print(subprocess.Popen(["sudo", "ifconfig", "enp60s0:0", "10.10.10.2", "netmask", "255.255.255.0", "up"])) enp60s0:0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 10.10.10.2  netmask 255.255.255.0  broadcast 10.10.10.255
        ether d4:81:d7:cb:b7:1e  txqueuelen 1000  (Ethernet)
        device interrupt 16  
```

请注意，如果您将上一个命令提供为字符串而不是列表，就像我们在第一个示例中所做的那样，命令将失败，如下面的屏幕截图所示。子进程`Popen()`期望在每个列表元素中有一个可执行名称，而不是其他任何参数。![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00148.jpeg)

另一方面，如果您想使用字符串方法而不是列表，您可以将`shell`参数设置为`True`。这将指示`Popen()`在命令之前附加`/bin/sh`，因此命令将在其后执行所有参数：

```py
print(subprocess.Popen("sudo ifconfig enp60s0:0 10.10.10.2 netmask 255.255.255.0 up", shell=True)) 
```

您可以将`shell=True`视为生成一个 shell 进程并将命令与参数传递给它。这可以通过使用`split()`节省您几行代码，以便直接从外部系统接收命令并运行它。

`subprocess`使用的默认 shell 是`/bin/sh`。如果您使用其他 shell，比如`tch`或`csh`，您可以在`executable`参数中定义它们。还要注意，作为 shell 运行命令可能会带来安全问题，并允许*安全注入*。指示您的代码运行脚本的用户可以添加`"; rm -rf /"`，导致可怕的事情发生。

此外，您可以使用`cwd`参数在运行命令之前将目录更改为特定目录。当您需要在对其进行操作之前列出目录的内容时，这将非常有用：

```py
import subprocess
print(subprocess.Popen(["cat", "interfaces"], cwd="/etc/network"))  
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00149.jpeg)Ansible 有一个类似的标志叫做`chdir:`。此参数将用于 playbook 任务中，在执行之前更改目录。

# 读取标准输入(stdin)、标准输出(stdout)和标准错误(stderr)

生成的进程可以通过三个通道与操作系统通信：

1.  标准输入（stdin）

1.  标准输出（stdout）

1.  标准错误（stderr）

在子进程中，`Popen()`可以与三个通道交互，并将每个流重定向到外部文件，或者重定向到一个称为`PIPE`的特殊值。另一个方法叫做`communicate()`，用于从`stdout`读取和写入`stdin`。`communicate()`方法可以从用户那里获取输入，并返回标准输出和标准错误，如下面的代码片段所示：

```py
import subprocess
p = subprocess.Popen(["ping", "8.8.8.8", "-c", "3"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) stdout, stderr = p.communicate() print("""==========The Standard Output is========== {}""".format(stdout))   print("""==========The Standard Error is========== {}""".format(stderr))
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00150.jpeg)

同样，您可以使用`communicate()`中的输入参数发送数据并写入进程：

```py
import subprocess
p = subprocess.Popen(["grep", "subprocess"], stdout=subprocess.PIPE, stdin=subprocess.PIPE) stdout,stderr = p.communicate(input=b"welcome to subprocess module\nthis line is a new line and doesnot contain the require string")   print("""==========The Standard Output is========== {}""".format(stdout))   print("""==========The Standard Error is========== {}""".format(stderr))
```

在脚本中，我们在`communicate()`中使用了`input`参数，它将数据发送到另一个子进程，该子进程将使用`grep`命令搜索子进程关键字。返回的输出将存储在`stdout`变量中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00151.jpeg)

验证进程成功执行的另一种方法是使用返回代码。当命令成功执行且没有错误时，返回代码将为`0`；否则，它将是大于`0`的整数值：

```py
import subprocess

def ping_destination(ip):   p = subprocess.Popen(['ping', '-c', '3'],
  stdout=subprocess.PIPE,
  stderr=subprocess.PIPE)
  stdout, stderr = p.communicate(input=ip)
  if p.returncode == 0:
  print("Host is alive")
  return True, stdout
    else:
  print("Host is down")
  return False, stderr
 while True:
    print(ping_destination(raw_input("Please enter the host:"))) 
```

脚本将要求用户输入一个 IP 地址，然后调用`ping_destination()`函数，该函数将针对 IP 地址执行`ping`命令。`ping`命令的结果（成功或失败）将返回到标准输出，并且`communicate()`函数将使用结果填充返回代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00152.jpeg)

首先，我们测试了 Google DNS IP 地址。主机是活动的，并且命令将成功执行，返回代码`=0`。函数将返回`True`并打印`主机是活动的`。其次，我们使用了`HostNotExist`字符串进行测试。函数将返回`False`到主程序并打印`主机已关闭`。此外，它将打印返回给子进程的命令标准输出（`Name or service not known`）。

您可以使用`echo $?`来检查先前执行的命令的返回代码（有时称为退出代码）。

# 子进程调用套件

子进程模块提供了另一个函数，使进程生成比使用`Popen()`更安全。子进程`call()`函数等待被调用的命令/程序完成读取输出。它支持与`Popen()`构造函数相同的参数，如`shell`、`executable`和`cwd`，但这次，您的脚本将等待程序完成并填充返回代码，而无需`communicate()`。

如果您检查`call()`函数，您会发现它实际上是`Popen()`类的一个包装器，但具有一个`wait()`函数，它会在返回输出之前等待命令结束：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00153.jpeg)

```py
import subprocess
subprocess.call(["ifconfig", "docker0"], stdout=subprocess.PIPE, stderr=None, shell=False) 
```

如果您希望为您的代码提供更多保护，可以使用`check_call()`函数。它与`call()`相同，但会对返回代码进行另一个检查。如果它等于`0`（表示命令已成功执行），则将返回输出。否则，它将引发一个带有返回退出代码的异常。这将允许您在程序流中处理异常：

```py
import subprocess

try:
  result = subprocess.check_call(["ping", "HostNotExist", "-c", "3"]) except subprocess.CalledProcessError:
  print("Host is not found") 
```

使用`call()`函数的一个缺点是，您无法像使用`Popen()`那样使用`communicate()`将数据发送到进程。

# 总结

在本章中，我们学习了如何在系统中运行和生成新进程，以及我们了解了这些生成的进程如何与操作系统通信。我们还讨论了子进程模块和`subprocess`调用。

在下一章中，我们将看到如何在远程主机上运行和执行命令。


# 第十章：使用 Fabric 运行系统管理任务

在上一章中，我们使用了`subprocess`模块在托管我们的 Python 脚本的机器内运行和生成系统进程，并将输出返回到终端。然而，许多自动化任务需要访问远程服务器以执行命令，这不容易使用子进程来实现。使用另一个 Python 模块`Fabric`就变得轻而易举。该库连接到远程主机并执行不同的任务，例如上传和下载文件，使用特定用户 ID 运行命令，并提示用户输入。`Fabric` Python 模块是从一个中心点管理数十台 Linux 机器的强大工具。

本章将涵盖以下主题：

+   什么是 Fabric？

+   执行您的第一个 Fabric 文件

+   其他有用的 Fabric 功能

# 技术要求

以下工具应安装并在您的环境中可用：

+   Python 2.7.1x。

+   PyCharm 社区版或专业版。

+   EVE-NG 拓扑。有关如何安装和配置系统服务器，请参阅第八章“准备实验环境”。

您可以在以下 GitHub URL 找到本章中开发的完整脚本：[`github.com/TheNetworker/EnterpriseAutomation.git`](https://github.com/TheNetworker/EnterpriseAutomation.git)。

# 什么是 Fabric？

Fabric ([`www.fabfile.org/`](http://www.fabfile.org/))是一个高级 Python 库，用于连接到远程服务器（通过 paramiko 库）并在其上执行预定义的任务。它在托管 fabric 模块的机器上运行一个名为**fab**的工具。此工具将查找位于您运行工具的相同目录中的`fabfile.py`文件。`fabfile.py`文件包含您的任务，定义为从命令行调用的 Python 函数，以在服务器上启动执行。Fabric 任务本身只是普通的 Python 函数，但它们包含用于在远程服务器上执行命令的特殊方法。此外，在`fabfile.py`的开头，您需要定义一些环境变量，例如远程主机、用户名、密码以及执行期间所需的任何其他变量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00154.jpeg)

# 安装

Fabric 需要 Python 2.5 到 2.7。您可以使用`pip`安装 Fabric 及其所有依赖项，也可以使用系统包管理器，如`yum`或`apt`。在这两种情况下，您都将在操作系统中准备好并可执行`fab`实用程序。

要使用`pip`安装`fabric`，请在自动化服务器上运行以下命令：

```py
pip install fabric
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00155.gif)

请注意，Fabric 需要`paramiko`，这是一个常用的 Python 库，用于建立 SSH 连接。

您可以通过两个步骤验证 Fabric 安装。首先，确保您的系统中有`fab`命令可用：

```py
[root@AutomationServer ~]# which fab
/usr/bin/fab
```

验证的第二步是打开 Python 并尝试导入`fabric`库。如果没有抛出错误，则 Fabric 已成功安装：

```py
[root@AutomationServer ~]# python
Python 2.7.5 (default, Aug  4 2017, 00:39:18) 
[GCC 4.8.5 20150623 (Red Hat 4.8.5-16)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from fabric.api import *
>>>

```

# Fabric 操作

`fabric`工具中有许多可用的操作。这些操作在 fabfile 中作为任务内的函数，但以下是`fabric`库中最重要操作的摘要。

# 使用运行操作

Fabric 中`run`操作的语法如下：

```py
run(command, shell=True, pty=True, combine_stderr=True, quiet=False, warn_only=False, stdout=None, stderr=None)
```

这将在远程主机上执行命令，而`shell`参数控制是否在执行之前创建一个 shell（例如`/bin/sh`）（相同的参数也存在于子进程中）。

命令执行后，Fabric 将填充`.succeeded`或`.failed`，取决于命令输出。您可以通过调用以下内容来检查命令是否成功或失败：

```py
def run_ops():
  output = run("hostname")  
```

# 使用获取操作

Fabric `get`操作的语法如下：

```py
get(remote_path, local_path)
```

这将从远程主机下载文件到运行 `fabfile` 的机器，使用 `rsync` 或 `scp`。例如，当您需要将日志文件收集到服务器时，通常会使用此功能。

```py
def get_ops():
  try:
  get("/var/log/messages","/root/")
  except:
  pass
```

# 使用 put 操作

Fabric `put` 操作的语法如下：

```py
put(local_path, remote_path, use_sudo=False, mirror_local_mode=False, mode=None)
```

此操作将从运行 `fabfile`（本地）的机器上传文件到远程主机。使用 `use_sudo` 将解决上传到根目录时的权限问题。此外，您可以保持本地和远程服务器上的当前文件权限，或者您可以设置新的权限：

```py
def put_ops():
  try:
  put("/root/VeryImportantFile.txt","/root/")
  except:
  pass
```

# 使用 sudo 操作

Fabric `sudo` 操作的语法如下：

```py
sudo(command, shell=True, pty=True, combine_stderr=True, user=None, quiet=False, warn_only=False, stdout=None, stderr=None, group=None)
```

此操作可以被视为 `run()` 命令的另一个包装器。但是，`sudo` 操作将默认使用 root 用户名运行命令，而不管用于执行 `fabfile` 的用户名如何。它还包含一个用户参数，该参数可用于使用不同的用户名运行命令。此外，`user` 参数使用特定的 UID 执行命令，而 `group` 参数定义 GID：

```py
def sudo_ops():
  sudo("whoami") #it should print the root even if you use another account
```

# 使用提示操作

Fabric `prompt` 操作的语法如下：

```py
prompt(text, key=None, default='', validate=None)
```

用户可以使用 `prompt` 操作为任务提供特定值，并且输入将存储在变量中并被任务使用。请注意，您将为 `fabfile` 中的每个主机提示：

```py
def prompt_ops():
  prompt("please supply release name", default="7.4.1708")
```

# 使用重新启动操作

Fabric `reboot` 操作的语法如下：

```py
reboot(wait=120)
```

这是一个简单的操作，默认情况下重新启动主机。Fabric 将等待 120 秒然后尝试重新连接，但是您可以使用 `wait` 参数将此值更改为其他值：

```py
def reboot_ops():
  reboot(wait=60, use_sudo=True) 
```

有关其他支持的操作的完整列表，请查看 [`docs.fabfile.org/en/1.14/api/core/operations.html`](http://docs.fabfile.org/en/1.14/api/core/operations.html)。您还可以直接从 PyCharm 查看它们，方法是查看在键入 *Ctrl + 空格* 时弹出的所有自动完成函数。从 `fabric.operations` 导入 <*ctrl*+*space*> 在 `fabric.operations` 下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00156.jpeg)

# 执行您的第一个 Fabric 文件

现在我们知道操作的工作原理，所以我们将把它放在 `fabfile` 中，并创建一个可以与远程机器一起工作的完整自动化脚本。`fabfile` 的第一步是导入所需的类。其中大部分位于 `fabric.api` 中，因此我们将全局导入所有这些类到我们的 Python 脚本中：

```py
from fabric.api import *
```

下一步是定义远程机器的 IP 地址、用户名和密码。在我们的环境中，除了自动化服务器之外，我们还有两台机器分别运行 Ubuntu 16.04 和 CentOS 7.4，并具有以下详细信息：

| **机器类型** | **IP 地址** | **用户名** | **密码** |
| --- | --- | --- | --- |
| Ubuntu 16.04 | `10.10.10.140` | `root` | `access123` |
| CentOS 7.4 | `10.10.10.193` | `root` | `access123` |

我们将把它们包含在 Python 脚本中，如下面的片段所示：

```py
env.hosts = [
  '10.10.10.140', # ubuntu machine
  '10.10.10.193', # CentOS machine ]   env.user = "root"  env.password = "access123" 
```

请注意，我们使用名为 `env` 的变量，该变量继承自 `_AttributeDict` 类。在此变量内部，我们可以设置来自 SSH 连接的用户名和密码。您还可以通过设置 `env.use_ssh_config=True` 使用存储在 `.ssh` 目录中的 SSH 密钥；Fabric 将使用这些密钥进行身份验证。

最后一步是将任务定义为 Python 函数。任务可以使用前面的操作来执行命令。

以下是完整的脚本：

```py
from fabric.api import *    env.hosts = [
  '10.10.10.140', # ubuntu machine
  '10.10.10.193', # CentOS machine ]   env.user = "root" env.password = "access123"   def detect_host_type():
  output = run("uname -s")   if output.failed:
  print("something wrong happen, please check the logs")   elif output.succeeded:
  print("command executed successfully")   def list_all_files_in_directory():
  directory = prompt("please enter full path to the directory to list", default="/root")
  sudo("cd {0} ; ls -htlr".format(directory))     def main_tasks():
  detect_host_type()
  list_all_files_in_directory()
```

在上面的示例中，适用以下内容：

+   我们定义了两个任务。第一个任务将执行 `uname -s` 命令并返回输出，然后验证命令是否成功执行。该任务使用 `run()` 操作来完成。

+   第二个任务将使用两个操作：`prompt()` 和 `sudo()`。第一个操作将要求用户输入目录的完整路径，而第二个操作将列出目录中的所有内容。

+   最终任务`main_tasks()`将实际上将前面的两种方法组合成一个任务，以便我们可以从命令行调用它。

为了运行脚本，我们将上传文件到自动化服务器，并使用`fab`实用程序来运行它：

```py
fab -f </full/path/to/fabfile>.py <task_name>
```

在上一个命令中，如果您的文件名不是`fabfile.py`，则`-f`开关是不强制的。如果不是，您将需要向`fab`实用程序提供名称。此外，`fabfile`应该在当前目录中；否则，您将需要提供完整的路径。现在我们将通过执行以下命令来运行`fabfile`：

```py
fab -f fabfile_first.py main_tasks
```

第一个任务将被执行，并将输出返回到终端：

```py
[10.10.10.140] Executing task 'main_tasks'
[10.10.10.140] run: uname -s
[10.10.10.140] out: Linux
[10.10.10.140] out: 

command executed successfully 
```

现在，我们将进入`/var/log/`来列出内容：

```py

please enter full path to the directory to list [/root] /var/log/
[10.10.10.140] sudo: cd /var/log/ ; ls -htlr
[10.10.10.140] out: total 1.7M
[10.10.10.140] out: drwxr-xr-x 2 root   root 4.0K Dec  7 23:54 lxd
[10.10.10.140] out: drwxr-xr-x 2 root   root 4.0K Dec 11 15:47 sysstat
[10.10.10.140] out: drwxr-xr-x 2 root   root 4.0K Feb 22 18:24 dist-upgrade
[10.10.10.140] out: -rw------- 1 root   utmp    0 Feb 28 20:23 btmp
[10.10.10.140] out: -rw-r----- 1 root   adm    31 Feb 28 20:24 dmesg
[10.10.10.140] out: -rw-r--r-- 1 root   root  57K Feb 28 20:24 bootstrap.log
[10.10.10.140] out: drwxr-xr-x 2 root   root 4.0K Apr  4 08:00 fsck
[10.10.10.140] out: drwxr-xr-x 2 root   root 4.0K Apr  4 08:01 apt
[10.10.10.140] out: -rw-r--r-- 1 root   root  32K Apr  4 08:09 faillog
[10.10.10.140] out: drwxr-xr-x 3 root   root 4.0K Apr  4 08:09 installer

command executed successfully
```

如果您需要列出 CentOS 机器上`network-scripts`目录下的配置文件，也是一样的：

```py
 please enter full path to the directory to list [/root] /etc/sysconfig/network-scripts/ 
[10.10.10.193] sudo: cd /etc/sysconfig/network-scripts/ ; ls -htlr
[10.10.10.193] out: total 232K
[10.10.10.193] out: -rwxr-xr-x. 1 root root 1.9K Apr 15  2016 ifup-TeamPort
[10.10.10.193] out: -rwxr-xr-x. 1 root root 1.8K Apr 15  2016 ifup-Team
[10.10.10.193] out: -rwxr-xr-x. 1 root root 1.6K Apr 15  2016 ifdown-TeamPort
[10.10.10.193] out: -rw-r--r--. 1 root root  31K May  3  2017 network-functions-ipv6
[10.10.10.193] out: -rw-r--r--. 1 root root  19K May  3  2017 network-functions
[10.10.10.193] out: -rwxr-xr-x. 1 root root 5.3K May  3  2017 init.ipv6-global
[10.10.10.193] out: -rwxr-xr-x. 1 root root 1.8K May  3  2017 ifup-wireless
[10.10.10.193] out: -rwxr-xr-x. 1 root root 2.7K May  3  2017 ifup-tunnel
[10.10.10.193] out: -rwxr-xr-x. 1 root root 3.3K May  3  2017 ifup-sit
[10.10.10.193] out: -rwxr-xr-x. 1 root root 2.0K May  3  2017 ifup-routes
[10.10.10.193] out: -rwxr-xr-x. 1 root root 4.1K May  3  2017 ifup-ppp
[10.10.10.193] out: -rwxr-xr-x. 1 root root 3.4K May  3  2017 ifup-post
[10.10.10.193] out: -rwxr-xr-x. 1 root root 1.1K May  3  2017 ifup-plusb

<***output omitted for brevity>***
```

最后，Fabric 将断开与两台机器的连接：

```py
[10.10.10.193] out: 

Done.
Disconnecting from 10.10.10.140... done.
Disconnecting from 10.10.10.193... done.
```

# 有关 fab 工具的更多信息

`fab`工具本身支持许多操作。它可以用来列出`fabfile`中的不同任务。它还可以在执行期间设置`fab`环境。例如，您可以使用`-H`或`--hosts`开关定义将在其上运行命令的主机，而无需在`fabfile`中指定。这实际上是在执行期间在`fabfile`中设置`env.hosts`变量：

```py
fab -H srv1,srv2
```

另一方面，您可以使用`fab`工具定义要运行的命令。这有点像 Ansible 的临时模式（我们将在第十三章中详细讨论这个问题，*系统管理的 Ansible*）：

```py
fab -H srv1,srv2 -- ifconfig -a
```

如果您不想在`fabfile`脚本中以明文存储密码，那么您有两个选项。第一个是使用`-i`选项使用 SSH 身份文件（私钥），它在连接期间加载文件。

另一个选项是使用`-I`选项强制 Fabric 在连接到远程机器之前提示您输入会话密码。

请注意，如果在`fabfile`中指定了`env.password`参数，此选项将覆盖该参数。

`-D`开关将禁用已知主机，并强制 Fabric 不从`.ssh`目录加载`known_hosts`文件。您可以使用`-r`或`--reject-unknown-hosts`选项使 Fabric 拒绝连接到`known_hosts`文件中未定义的主机。

此外，您还可以使用`-l`或`--list`在`fabfile`中列出所有支持的任务，向`fab`工具提供`fabfile`名称。例如，将其应用到前面的脚本将生成以下输出：

```py
# fab -f fabfile_first.py -l
Available commands:

    detect_host_type
    list_all_files_in_directory
    main_tasks
```

您可以使用`-h`开关在命令行中查看`fab`命令的所有可用选项和参数，或者在[`docs.fabfile.org/en/1.14/usage/fab.html`](http://docs.fabfile.org/en/1.14/usage/fab.html)上查看。

# 使用 Fabric 发现系统健康

在这种用例中，我们将利用 Fabric 开发一个脚本，在远程机器上执行多个命令。脚本的目标是收集两种类型的输出：`discovery`命令和`health`命令。`discovery`命令收集正常运行时间、主机名、内核版本以及私有和公共 IP 地址，而`health`命令收集已使用的内存、CPU 利用率、生成的进程数量和磁盘使用情况。我们将设计`fabfile`，以便我们可以扩展我们的脚本并向其中添加更多命令：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from fabric.api import * from fabric.context_managers import * from pprint import pprint

env.hosts = [
  '10.10.10.140', # Ubuntu Machine
  '10.10.10.193', # CentOS Machine ]   env.user = "root" env.password = "access123"     def get_system_health():    discovery_commands = {
  "uptime": "uptime | awk '{print $3,$4}'",
  "hostname": "hostname",
  "kernel_release": "uname -r",
  "architecture": "uname -m",
  "internal_ip": "hostname -I",
  "external_ip": "curl -s ipecho.net/plain;echo",      }
  health_commands = {
  "used_memory": "free  | awk '{print $3}' | grep -v free | head -n1",
  "free_memory": "free  | awk '{print $4}' | grep -v shared | head -n1",
  "cpu_usr_percentage": "mpstat | grep -A 1 '%usr' | tail -n1 | awk '{print $4}'",
  "number_of_process": "ps -A --no-headers | wc -l",
  "logged_users": "who",
  "top_load_average": "top -n 1 -b | grep 'load average:' | awk '{print $10 $11 $12}'",
  "disk_usage": "df -h| egrep 'Filesystem|/dev/sda*|nvme*'"    }    tasks = [discovery_commands,health_commands]    for task in tasks:
  for operation,command in task.iteritems():
  print("============================={0}=============================".format(operation))
  output = run(command)
```

请注意，我们创建了两个字典：`discover_commands`和`health_commands`。每个字典都包含 Linux 命令作为键值对。键表示操作，而值表示实际的 Linux 命令。然后，我们创建了一个`tasks`列表来组合这两个字典。

最后，我们创建了一个嵌套的`for`循环。外部循环用于遍历列表项。内部`for`循环用于遍历键值对。使用 Fabric 的`run()`操作将命令发送到远程主机：

```py
# fab -f fabfile_discoveryAndHealth.py get_system_health
[10.10.10.140] Executing task 'get_system_health'
=============================uptime=============================
[10.10.10.140] run: uptime | awk '{print $3,$4}'
[10.10.10.140] out: 3:26, 2
[10.10.10.140] out: 

=============================kernel_release=============================
[10.10.10.140] run: uname -r
[10.10.10.140] out: 4.4.0-116-generic
[10.10.10.140] out: 

=============================external_ip=============================
[10.10.10.140] run: curl -s ipecho.net/plain;echo
[10.10.10.140] out: <Author_Masked_The_Output_For_Privacy>
[10.10.10.140] out: 

=============================hostname=============================
[10.10.10.140] run: hostname
[10.10.10.140] out: ubuntu-machine
[10.10.10.140] out: 

=============================internal_ip=============================
[10.10.10.140] run: hostname -I
[10.10.10.140] out: 10.10.10.140 
[10.10.10.140] out: 

=============================architecture=============================
[10.10.10.140] run: uname -m
[10.10.10.140] out: x86_64
[10.10.10.140] out: 

=============================disk_usage=============================
[10.10.10.140] run: df -h| egrep 'Filesystem|/dev/sda*|nvme*'
[10.10.10.140] out: Filesystem                            Size  Used Avail Use% Mounted on
[10.10.10.140] out: /dev/sda1                             472M   58M  390M  13% /boot
[10.10.10.140] out: 

=============================used_memory=============================
[10.10.10.140] run: free  | awk '{print $3}' | grep -v free | head -n1
[10.10.10.140] out: 75416
[10.10.10.140] out: 

=============================logged_users=============================
[10.10.10.140] run: who
[10.10.10.140] out: root     pts/0        2018-04-08 23:36 (10.10.10.130)
[10.10.10.140] out: root     pts/1        2018-04-08 21:23 (10.10.10.1)
[10.10.10.140] out: 

=============================top_load_average=============================
[10.10.10.140] run: top -n 1 -b | grep 'load average:' | awk '{print $10 $11 $12}'
[10.10.10.140] out: 0.16,0.03,0.01
[10.10.10.140] out: 

=============================cpu_usr_percentage=============================
[10.10.10.140] run: mpstat | grep -A 1 '%usr' | tail -n1 | awk '{print $4}'
[10.10.10.140] out: 0.02
[10.10.10.140] out: 

=============================number_of_process=============================
[10.10.10.140] run: ps -A --no-headers | wc -l
[10.10.10.140] out: 131
[10.10.10.140] out: 

=============================free_memory=============================
[10.10.10.140] run: free  | awk '{print $4}' | grep -v shared | head -n1
[10.10.10.140] out: 5869268
[10.10.10.140] out: 

```

`get_system_health`相同的任务也将在第二台服务器上执行，并将输出返回到终端：

```py
[10.10.10.193] Executing task 'get_system_health'
=============================uptime=============================
[10.10.10.193] run: uptime | awk '{print $3,$4}'
[10.10.10.193] out: 3:26, 2
[10.10.10.193] out: 

=============================kernel_release=============================
[10.10.10.193] run: uname -r
[10.10.10.193] out: 3.10.0-693.el7.x86_64
[10.10.10.193] out: 

=============================external_ip=============================
[10.10.10.193] run: curl -s ipecho.net/plain;echo
[10.10.10.193] out: <Author_Masked_The_Output_For_Privacy>
[10.10.10.193] out: 

=============================hostname=============================
[10.10.10.193] run: hostname
[10.10.10.193] out: controller329
[10.10.10.193] out: 

=============================internal_ip=============================
[10.10.10.193] run: hostname -I
[10.10.10.193] out: 10.10.10.193 
[10.10.10.193] out: 

=============================architecture=============================
[10.10.10.193] run: uname -m
[10.10.10.193] out: x86_64
[10.10.10.193] out: 

=============================disk_usage=============================
[10.10.10.193] run: df -h| egrep 'Filesystem|/dev/sda*|nvme*'
[10.10.10.193] out: Filesystem               Size  Used Avail Use% Mounted on
[10.10.10.193] out: /dev/sda1                488M   93M  360M  21% /boot
[10.10.10.193] out: 

=============================used_memory=============================
[10.10.10.193] run: free  | awk '{print $3}' | grep -v free | head -n1
[10.10.10.193] out: 287048
[10.10.10.193] out: 

=============================logged_users=============================
[10.10.10.193] run: who
[10.10.10.193] out: root     pts/0        2018-04-08 23:36 (10.10.10.130)
[10.10.10.193] out: root     pts/1        2018-04-08 21:23 (10.10.10.1)
[10.10.10.193] out: 

=============================top_load_average=============================
[10.10.10.193] run: top -n 1 -b | grep 'load average:' | awk '{print $10 $11 $12}'
[10.10.10.193] out: 0.00,0.01,0.02
[10.10.10.193] out: 

=============================cpu_usr_percentage=============================
[10.10.10.193] run: mpstat | grep -A 1 '%usr' | tail -n1 | awk '{print $4}'
[10.10.10.193] out: 0.00
[10.10.10.193] out: 

=============================number_of_process=============================
[10.10.10.193] run: ps -A --no-headers | wc -l
[10.10.10.193] out: 190
[10.10.10.193] out: 

=============================free_memory=============================
[10.10.10.193] run: free  | awk '{print $4}' | grep -v shared | head -n1
[10.10.10.193] out: 32524912
[10.10.10.193] out: 
```

最后，`fabric`模块将在执行所有任务后终止已建立的 SSH 会话并断开与两台机器的连接：

```py
Disconnecting from 10.10.10.140... done.
Disconnecting from 10.10.10.193... done.
```

请注意，我们可以重新设计之前的脚本，并将`discovery_commands`和`health_commands`作为 Fabric 任务，然后将它们包含在`get_system_health()`中。当我们执行`fab`命令时，我们将调用`get_system_health()`，它将执行另外两个函数；我们将得到与之前相同的输出。以下是修改后的示例脚本：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from fabric.api import * from fabric.context_managers import * from pprint import pprint

env.hosts = [
  '10.10.10.140', # Ubuntu Machine
  '10.10.10.193', # CentOS Machine ]   env.user = "root" env.password = "access123"     def discovery_commands():
  discovery_commands = {
  "uptime": "uptime | awk '{print $3,$4}'",
  "hostname": "hostname",
  "kernel_release": "uname -r",
  "architecture": "uname -m",
  "internal_ip": "hostname -I",
  "external_ip": "curl -s ipecho.net/plain;echo",      }
  for operation, command in discovery_commands.iteritems():
  print("============================={0}=============================".format(operation))
  output = run(command)   def health_commands():
  health_commands = {
  "used_memory": "free  | awk '{print $3}' | grep -v free | head -n1",
  "free_memory": "free  | awk '{print $4}' | grep -v shared | head -n1",
  "cpu_usr_percentage": "mpstat | grep -A 1 '%usr' | tail -n1 | awk '{print $4}'",
  "number_of_process": "ps -A --no-headers | wc -l",
  "logged_users": "who",
  "top_load_average": "top -n 1 -b | grep 'load average:' | awk '{print $10 $11 $12}'",
  "disk_usage": "df -h| egrep 'Filesystem|/dev/sda*|nvme*'"    }
  for operation, command in health_commands.iteritems():
  print("============================={0}=============================".format(operation))
  output = run(command)   def get_system_health():
  discovery_commands()
  health_commands()
```

# Fabric 的其他有用功能

Fabric 还有其他有用的功能，如角色和上下文管理器。

# Fabric 角色

Fabric 可以为主机定义角色，并仅对角色成员运行任务。例如，我们可能有一堆数据库服务器，需要验证 MySql 服务是否正常运行，以及其他需要验证 Apache 服务是否正常运行的 Web 服务器。我们可以将这些主机分组到角色中，并根据这些角色执行函数：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   from fabric.api import *   env.hosts = [
  '10.10.10.140', # ubuntu machine
  '10.10.10.193', # CentOS machine
  '10.10.10.130', ]   env.roledefs = {
  'webapps': ['10.10.10.140','10.10.10.193'],
  'databases': ['10.10.10.130'], }   env.user = "root" env.password = "access123"   @roles('databases') def validate_mysql():
  output = run("systemctl status mariadb")     @roles('webapps') def validate_apache():
  output = run("systemctl status httpd") 
```

在前面的示例中，我们在设置`env.roledef`时使用了 Fabric 装饰器`roles`（从`fabric.api`导入）。然后，我们将 webapp 或数据库角色分配给每个服务器（将角色分配视为对服务器进行标记）。这将使我们能够仅在具有数据库角色的服务器上执行`validate_mysql`函数：

```py
# fab -f fabfile_roles.py validate_mysql:roles=databases
[10.10.10.130] Executing task 'validate_mysql'
[10.10.10.130] run: systemctl status mariadb
[10.10.10.130] out: ● mariadb.service - MariaDB database server
[10.10.10.130] out:    Loaded: loaded (/usr/lib/systemd/system/mariadb.service; enabled; vendor preset: disabled)
[10.10.10.130] out:    Active: active (running) since Sat 2018-04-07 19:47:35 EET; 1 day 2h ago
<output omitted>
```

# Fabric 上下文管理器

在我们的第一个 Fabric 脚本`fabfile_first.py`中，我们有一个任务提示用户输入目录，然后切换到该目录并打印其内容。这是通过使用`;`来实现的，它将两个 Linux 命令连接在一起。但是，在其他操作系统上运行相同的命令并不总是有效。这就是 Fabric 上下文管理器发挥作用的地方。

上下文管理器在执行命令时维护目录状态。它通常通过`with`语句在 Python 中运行，并且在块内，您可以编写任何以前的 Fabric 操作。让我们通过一个示例来解释这个想法：

```py
from fabric.api import *
from fabric.context_managers import *   env.hosts = [
  '10.10.10.140', # ubuntu machine
  '10.10.10.193', # CentOS machine ]   env.user = "root" env.password = "access123"   def list_directory():
  with cd("/var/log"):
  run("ls")
```

在前面的示例中，首先我们在`fabric.context_managers`中全局导入了所有内容；然后，我们使用`cd`上下文管理器切换到特定目录。我们使用 Fabric 的`run()`操作在该目录上执行`ls`。这与在 SSH 会话中编写`cd /var/log ; ls`相同，但它提供了一种更 Pythonic 的方式来开发您的代码。

`with`语句可以嵌套。例如，我们可以用以下方式重写前面的代码：

```py
def list_directory_nested():
  with cd("/var/"):
  with cd("log"):
  run("ls")
```

另一个有用的上下文管理器是**本地更改目录**（**LCD**）。这与前面示例中的`cd`上下文管理器相同，但它在运行`fabfile`的本地机器上工作。我们可以使用它来将上下文更改为特定目录（例如，上传或下载文件到/从远程机器，然后自动切换回执行目录）：

```py
def uploading_file():
  with lcd("/root/"):
  put("VeryImportantFile.txt")
```

`prefix`上下文管理器将接受一个命令作为输入，并在`with`块内的任何其他命令之前执行它。例如，您可以在运行每个命令之前执行源文件或 Python 虚拟`env`包装器脚本来设置您的虚拟环境：

```py
def prefixing_commands():
  with prefix("source ~/env/bin/activate"):
  sudo('pip install wheel')
  sudo("pip install -r requirements.txt")
  sudo("python manage.py migrate")
```

实际上，这相当于在 Linux shell 中编写以下命令：

```py
source ~/env/bin/activate && pip install wheel
source ~/env/bin/activate && pip install -r requirements.txt
source ~/env/bin/activate && python manage.py migrate
```

最后一个上下文管理器是`shell_env(new_path, behavior='append')`，它可以修改包装命令的 shell 环境变量；因此，在该块内的任何调用都将考虑到修改后的路径：

```py
def change_shell_env():
  with shell_env(test1='val1', test2='val2', test3='val3'):
  run("echo $test1") #This command run on remote host
  run("echo $test2")
  run("echo $test3")
        local("echo $test1") #This command run on local host
```

请注意，在操作完成后，Fabric 将将旧的环境恢复到原始状态。

# 摘要

Fabric 是一个出色且强大的工具，可以自动化任务，通常在远程机器上执行。它与 Python 脚本很好地集成，可以轻松访问 SSH 套件。您可以为不同的任务开发许多 fab 文件，并将它们集成在一起，以创建包括部署、重启和停止服务器或进程在内的自动化工作流程。

在下一章中，我们将学习收集数据并为系统监控生成定期报告。


# 第十一章：生成系统报告和系统监控

收集数据并生成定期系统报告是任何系统管理员的重要任务，并自动化这些任务可以帮助我们及早发现问题，以便为其提供解决方案。在本章中，我们将看到一些经过验证的方法，用于从服务器自动收集数据并将这些数据生成为正式报告。我们将学习如何使用 Python 和 Ansible 管理新用户和现有用户。此外，我们还将深入研究日志分析和监控系统**关键绩效指标**（**KPI**）。您可以安排监视脚本定期运行。

本章将涵盖以下主题：

+   从 Linux 收集数据

+   在 Ansible 中管理用户

# 从 Linux 收集数据

本机 Linux 命令提供有关当前系统状态和健康状况的有用数据。然而，这些 Linux 命令和实用程序都专注于从系统的一个方面获取数据。我们需要利用 Python 模块将这些详细信息返回给管理员并生成有用的系统报告。

我们将报告分为两部分。第一部分是使用`platform`模块获取系统的一般信息，而第二部分是探索 CPU 和内存等硬件资源。

我们将首先利用 Python 内置库中的`platform`模块。`platform`模块包含许多方法，可用于获取 Python 所在系统的详细信息：

```py
import platform
system = platform.system() print(system)
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00157.jpeg)

在 Windows 机器上运行相同的脚本将产生不同的输出，反映当前的系统。因此，当我们在 Windows PC 上运行它时，我们将从脚本中获得`Windows`作为输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00158.gif)

另一个有用的函数是`uname()`，它与 Linux 命令(`uname -a`)执行相同的工作：检索机器的主机名、架构和内核，但以结构化格式呈现，因此您可以通过引用其索引来匹配任何值：

```py
import platform
from pprint import pprint
uname = platform.uname() pprint(uname)
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00159.jpeg)

第一个值是系统类型，我们使用`system()`方法获取，第二个值是当前机器的主机名。

您可以使用 PyCharm 中的自动完成功能来探索并列出`platform`模块中的所有可用函数；您可以通过按下*CTRL* + *Q*来检查每个函数的文档：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00160.jpeg)

设计脚本的第二部分是使用 Linux 文件提供的信息来探索 Linux 机器中的硬件配置。请记住，CPU、内存和网络信息可以从`/proc/`下访问；我们将读取此信息并使用 Python 中的标准`open()`函数进行访问。您可以通过阅读和探索`/proc/`来获取有关可用资源的更多信息。

**脚本：**

这是导入`platform`模块的第一步。这仅适用于此任务：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import platform
```

此片段包含了此练习中使用的函数；我们将设计两个函数 - `check_feature()`和`get_value_from_string()`：

```py
def check_feature(feature,string):
  if feature in string.lower():
  return True
  else:
  return False   def get_value_from_string(key,string):
  value = "NONE"
  for line in string.split("\n"):
  if key in line:
  value = line.split(":")[1].strip()
  return value
```

最后，以下是 Python 脚本的主体，其中包含获取所需信息的 Python 逻辑：

```py
cpu_features = [] with open('/proc/cpuinfo') as cpus:
  cpu_data = cpus.read()
  num_of_cpus = cpu_data.count("processor")
  cpu_features.append("Number of Processors: {0}".format(num_of_cpus))
  one_processor_data = cpu_data.split("processor")[1]
 print one_processor_data
    if check_feature("vmx",one_processor_data):
  cpu_features.append("CPU Virtualization: enabled")
  if check_feature("cpu_meltdown",one_processor_data):
  cpu_features.append("Known Bugs: CPU Metldown ")
  model_name = get_value_from_string("model name ",one_processor_data)
  cpu_features.append("Model Name: {0}".format(model_name))    cpu_mhz = get_value_from_string("cpu MHz",one_processor_data)
  cpu_features.append("CPU MHz: {0}".format((cpu_mhz)))   memory_features = [] with open('/proc/meminfo') as memory:
  memory_data = memory.read()
  total_memory = get_value_from_string("MemTotal",memory_data).replace(" kB","")
  free_memory = get_value_from_string("MemFree",memory_data).replace(" kB","")
  swap_memory = get_value_from_string("SwapTotal",memory_data).replace(" kB","")
  total_memory_in_gb = "Total Memory in GB: {0}".format(int(total_memory)/1024)
  free_memory_in_gb = "Free Memory in GB: {0}".format(int(free_memory)/1024)
  swap_memory_in_gb = "SWAP Memory in GB: {0}".format(int(swap_memory)/1024)
  memory_features = [total_memory_in_gb,free_memory_in_gb,swap_memory_in_gb]  
```

此部分用于打印从上一部分获得的信息：

```py
print("============System Information============")   print(""" System Type: {0} Hostname: {1} Kernel Version: {2} System Version: {3} Machine Architecture: {4} Python version: {5} """.format(platform.system(),
  platform.uname()[1],
  platform.uname()[2],
  platform.version(),
  platform.machine(),
  platform.python_version()))     print("============CPU Information============") print("\n".join(cpu_features))     print("============Memory Information============") print("\n".join(memory_features))
```

在上述示例中，执行了以下步骤：

1.  首先，我们打开了`/proc/cpuinfo`并读取了它的内容，然后将结果存储在`cpu_data`中。

1.  通过使用`count()`字符串函数计算文件中处理器的数量可以找到。

1.  然后，我们需要获取每个处理器可用的选项和特性。为此，我们只获取了一个处理器条目（因为它们通常是相同的），并将其传递给`check_feature()`函数。该方法接受我们想要在一个参数中搜索的特性，另一个是处理器数据，如果处理器数据中存在该特性，则返回`True`。

1.  处理器数据以键值对的形式可用。因此，我们设计了`get_value_from_string()`方法，它接受键名，并通过迭代处理器数据来搜索其对应的值；然后，我们将在每个返回的键值对上使用`:`分隔符进行拆分，以获取值。

1.  所有这些值都使用`append()`方法添加到`cpu_feature`列表中。

1.  然后，我们重复了相同的操作，使用内存信息获取总内存、空闲内存和交换内存。

1.  接下来，我们使用平台的内置方法，如`system()`、`uname()`和`python_version()`，来获取有关系统的信息。

1.  最后，我们打印了包含上述信息的报告。

脚本输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00161.jpeg)表示生成的数据的另一种方法是利用我们在第五章中使用的`matplotlib`库，以便随时间可视化数据。

# 通过电子邮件发送生成的数据

在前一节生成的报告中，提供了系统当前资源的良好概述。但是，我们可以调整脚本并扩展其功能，以便通过电子邮件发送所有细节给我们。这对于**网络运营中心**（**NoC**）团队非常有用，他们可以根据特定事件（硬盘故障、高 CPU 或丢包）从受监控系统接收电子邮件。Python 有一个名为`smtplib`的内置库，它利用**简单邮件传输协议**（**SMTP**）负责与邮件服务器发送和接收电子邮件。

这要求您的计算机上有本地电子邮件服务器，或者您使用其中一个免费的在线电子邮件服务，如 Gmail 或 Outlook。在本例中，我们将使用 SMTP 登录到[`www.gmail.com`](http://www.gmail.com)，并使用我们的数据发送电子邮件。

话不多说，我们将修改我们的脚本，并为其添加 SMTP 支持。

我们将所需的模块导入 Python。同样，`smtplib`和`platform`对于这个任务是必需的：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import smtplib
imp        ort platform
```

这是函数的一部分，包含`check_feature()`和`get_value_from_string()`函数：

```py
def check_feature(feature,string):
  if feature in string.lower():
  return True
  else:
  return False   def get_value_from_string(key,string):
  value = "NONE"
  for line in string.split("\n"):
  if key in line:
  value = line.split(":")[1].strip()
  return value
```

最后，Python 脚本的主体如下，包含了获取所需信息的 Python 逻辑：

```py
cpu_features = [] with open('/proc/cpuinfo') as cpus:
  cpu_data = cpus.read()
  num_of_cpus = cpu_data.count("processor")
  cpu_features.append("Number of Processors: {0}".format(num_of_cpus))
  one_processor_data = cpu_data.split("processor")[1]
 if check_feature("vmx",one_processor_data):
  cpu_features.append("CPU Virtualization: enabled")
  if check_feature("cpu_meltdown",one_processor_data):
  cpu_features.append("Known Bugs: CPU Metldown ")
  model_name = get_value_from_string("model name ",one_processor_data)
  cpu_features.append("Model Name: {0}".format(model_name))    cpu_mhz = get_value_from_string("cpu MHz",one_processor_data)
  cpu_features.append("CPU MHz: {0}".format((cpu_mhz)))   memory_features = [] with open('/proc/meminfo') as memory:
  memory_data = memory.read()
  total_memory = get_value_from_string("MemTotal",memory_data).replace(" kB","")
  free_memory = get_value_from_string("MemFree",memory_data).replace(" kB","")
  swap_memory = get_value_from_string("SwapTotal",memory_data).replace(" kB","")
  total_memory_in_gb = "Total Memory in GB: {0}".format(int(total_memory)/1024)
  free_memory_in_gb = "Free Memory in GB: {0}".format(int(free_memory)/1024)
  swap_memory_in_gb = "SWAP Memory in GB: {0}".format(int(swap_memory)/1024)
  memory_features = [total_memory_in_gb,free_memory_in_gb,swap_memory_in_gb]   Data_Sent_in_Email = "" Header = """From: PythonEnterpriseAutomationBot <basim.alyy@gmail.com> To: To Administrator <basim.alyy@gmail.com> Subject: Monitoring System Report   """ Data_Sent_in_Email += Header
Data_Sent_in_Email +="============System Information============"   Data_Sent_in_Email +=""" System Type: {0} Hostname: {1} Kernel Version: {2} System Version: {3} Machine Architecture: {4} Python version: {5} """.format(platform.system(),
  platform.uname()[1],
  platform.uname()[2],
  platform.version(),
  platform.machine(),
  platform.python_version())     Data_Sent_in_Email +="============CPU Information============\n" Data_Sent_in_Email +="\n".join(cpu_features)     Data_Sent_in_Email +="\n============Memory Information============\n" Data_Sent_in_Email +="\n".join(memory_features)  
```

最后，我们需要为变量赋一些值，以便正确连接到`gmail`服务器：

```py
fromaddr = 'yyyyyyyyyyy@gmail.com' toaddrs  = 'basim.alyy@gmail.com' username = 'yyyyyyyyyyy@gmail.com' password = 'xxxxxxxxxx' server = smtplib.SMTP('smtp.gmail.com:587') server.ehlo() server.starttls() server.login(username,password)   server.sendmail(fromaddr, toaddrs, Data_Sent_in_Email) server.quit()
```

在前面的示例中，适用以下内容：

1.  第一部分与原始示例相同，但是不是将数据打印到终端，而是将其添加到`Data_Sent_in_Email`变量中。

1.  `Header`变量代表包含发件人地址、收件人地址和电子邮件主题的电子邮件标题。

1.  我们使用`smtplib`模块内的`SMTP()`类来连接到公共 Gmail SMTP 服务器并协商 TTLS 连接。这是连接到 Gmail 服务器时的默认方法。我们将 SMTP 连接保存在`server`变量中。

1.  现在，我们使用`login()`方法登录到服务器，最后，我们使用`sendmail()`函数发送电子邮件。`sendmail()`接受三个参数：发件人、收件人和电子邮件正文。

1.  最后，我们关闭与服务器的连接：

**脚本输出**

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00162.jpeg)

# 使用时间和日期模块

很好；到目前为止，我们已经能够通过电子邮件发送从我们的服务器生成的自定义数据。然而，由于网络拥塞或邮件系统故障等原因，生成的数据和电子邮件的传递时间之间可能存在时间差异。因此，我们不能依赖电子邮件将传递时间与实际事件时间相关联。

因此，我们将使用 Python 的`datetime`模块来跟踪监视系统上的当前时间。该模块可以以许多属性格式化时间，如年、月、日、小时和分钟。

除此之外，`datetime`模块中的`datetime`实例实际上是 Python 中的一个独立对象（如 int、string、boolean 等）；因此，它在 Python 内部有自己的属性。

要将`datetime`对象转换为字符串，可以使用`strftime()`方法，该方法作为创建的对象内的属性可用。此外，它提供了一种通过以下指令格式化时间的方法：

| **指令** | **含义** |
| --- | --- |
| `%Y` | 返回年份，从 0001 到 9999 |
| `%m` | 返回月份 |
| `%d` | 返回月份的日期 |
| `%H` | 返回小时数，0-23 |
| `%M` | 返回分钟数，0-59 |
| `%S` | 返回秒数，0-59 |

因此，我们将调整我们的脚本，并将以下片段添加到代码中：

```py
from datetime import datetime
time_now = datetime.now() time_now_string = time_now.strftime("%Y-%m-%d %H:%M:%S")
Data_Sent_in_Email += "====Time Now is {0}====\n".format(time_now_string) 
```

首先，我们从`datetime`模块中导入了`datetime`类。然后，我们使用`datetime`类和`now()`函数创建了`time_now`对象，该函数返回正在运行系统上的当前时间。最后，我们使用`strftime()`，带有一个指令，以特定格式格式化时间并将其转换为字符串以进行打印（记住，该对象有一个`datetime`对象）。

脚本的输出如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/hsn-etp-auto-py/img/00163.jpeg)

# 定期运行脚本

脚本的最后一步是安排脚本在一定时间间隔内运行。这可以是每天、每周、每小时或在特定时间。这可以通过 Linux 系统上的`cron`作业来完成。`cron`用于安排重复事件，如清理目录、备份数据库、旋转日志，或者你能想到的其他任何事情。

要查看当前计划的作业，使用以下命令：

```py
crontab -l
```

编辑`crontab`，使用`-e`开关。如果这是你第一次运行`cron`，系统会提示你使用你喜欢的编辑器（`nano`或`vi`）。

典型的`crontab`由五个星号组成，每个星号代表一个时间条目：

| **字段** | **值** |
| --- | --- |
| 分钟 | 0-59 |
| 小时 | 0-23 |
| 月份的日期 | 1-31 |
| 月份 | 1-12 |
| 星期几 | 0-6（星期日-星期六） |

例如，如果你需要安排一个工作在每周五晚上 9 点运行，你将使用以下条目：

```py
0 21 * * 5 /path/to/command
```

如果你需要每天凌晨 12 点执行一个命令（例如备份），使用以下`cron`作业：

```py
0 0 * * * /path/to/command
```

此外，你可以安排`cron`在*每个*特定的间隔运行。例如，如果你需要每`5`分钟运行一次作业，使用这个`cron`作业：

```py
*/5 * * * * /path/to/command
```

回到我们的脚本；我们可以安排它在每天上午 7:30 运行：

```py
30 7 * * * /usr/bin/python /root/Send_Email.py
```

最后，记得在退出之前保存`cron`作业。

最好提供 Linux 的完整命令路径，而不是相对路径，以避免任何潜在问题。

# 在 Ansible 中管理用户

现在，我们将讨论如何在不同系统中管理用户。

# Linux 系统

Ansible 提供了强大的用户管理模块，用于管理系统上的不同任务。我们有一个专门讨论 Ansible 的章节（第十三章，*系统管理的 Ansible*），但在本章中，我们将探讨其在管理公司基础设施上管理用户帐户的能力。

有时，公司允许所有用户访问 root 权限，以摆脱用户管理的麻烦；这在安全和审计方面不是一个好的解决方案。最佳实践是给予正确的用户正确的权限，并在用户离开公司时撤销这些权限。

Ansible 提供了一种无与伦比的方式来管理多台服务器上的用户，可以通过密码或无密码（SSH 密钥）访问。

在创建 Linux 系统中的用户时，还有一些其他需要考虑的事项。用户必须有一个 shell（如 Bash、CSH、ZSH 等）才能登录到服务器。此外，用户应该有一个主目录（通常在`/home`下）。最后，用户必须属于一个确定其特权和权限的组。

我们的第一个示例将是在远程服务器上使用临时命令创建一个带有 SSH 密钥的用户。密钥源位于`ansible` tower，而我们在`all`服务器上执行命令：

```py
ansible all -m copy -a "src=~/id_rsa dest=~/.ssh/id_rsa mode=0600"
```

第二个示例是使用 Playbook 创建用户：

```py
--- - hosts: localhost
  tasks:
    - name: create a username
      user:
        name: bassem
        password: "$crypted_value$"
        groups:
          - root
        state: present
        shell: /bin/bash
        createhome: yes
  home: /home/bassem
```

让我们来看一下任务的参数：

+   在我们的任务中，我们使用了一个包含多个参数的用户模块，比如`name`，用于设置用户的用户名。

+   第二个参数是`password`，用于设置用户的密码，但是以加密格式。您需要使用`mkpasswd`命令，该命令会提示您输入密码并生成哈希值。

+   `groups`是用户所属的组列表；因此，用户将继承权限。您可以在此字段中使用逗号分隔的值。

+   `state`用于告诉 Ansible 用户是要创建还是删除。

+   您可以在`shell`参数中定义用于远程访问的用户 shell。

+   `createhome`和`home`是用于指定用户主目录位置的参数。

另一个参数是`ssh_key_file`，用于指定 SSH 文件名。此外，`ssh_key_passphrase`将指定 SSH 密钥的密码。

# 微软 Windows

Ansible 提供了`win_user`模块来管理本地 Windows 用户帐户。在创建活动目录域或 Microsoft SQL 数据库（`mssql`）上的用户或在普通 PC 上创建默认帐户时，这非常有用。以下示例将创建一个名为`bassem`的用户，并为其设置密码`access123`。不同之处在于密码是以明文而不是加密值给出的，就像在基于 Unix 的系统中一样：

```py
- hosts: localhost
  tasks:
    - name: create user on windows machine
      win_user:
        name: bassem
        password: 'access123'
  password_never_expires: true
  account_disabled: no
  account_locked: no
  password_expired: no
  state: present
        groups:
          - Administrators
          - Users
```

`password_never_expires`参数将防止 Windows 在特定时间后使密码过期；这在创建管理员和默认帐户时非常有用。另一方面，如果将`password_expired`设置为`yes`，将要求用户在首次登录时输入新密码并更改密码。

`groups`参数将用户添加到列出的值或逗号分隔的组列表中。这将取决于`groups_action`参数，可以是`add`、`replace`或`remove`。

最后，状态将告诉 Ansible 应该对用户执行什么操作。此参数可以是`present`、`absent`或`query`。

# 总结

在本章中，我们学习了如何从 Linux 机器收集数据和报告，并使用时间和日期模块通过电子邮件进行警报。我们还学习了如何在 Ansible 中管理用户。

在下一章中，我们将学习如何使用 Python 连接器与 DBMS 进行交互。


# 第十二章：与数据库交互

在之前的章节中，我们使用了许多 Python 工具和实用程序生成了多种不同的报告。在本章中，我们将利用 Python 库连接到外部数据库，并提交我们生成的数据。然后，外部应用程序可以访问这些数据以获取信息。

Python 提供了广泛的库和模块，涵盖了管理和处理流行的**数据库管理系统**（**DBMSes**），如 MySQL、PostgreSQL 和 Oracle。在本章中，我们将学习如何与 DBMS 交互，并填充我们自己的数据。

本章将涵盖以下主题：

+   在自动化服务器上安装 MySQL

+   从 Python 访问 MySQL 数据库

# 在自动化服务器上安装 MySQL

我们需要做的第一件事是设置一个数据库。在接下来的步骤中，我们将介绍如何在我们在第八章中创建的自动化服务器上安装 MySQL 数据库。基本上，您需要一个具有互联网连接的基于 Linux 的机器（CentOS 或 Ubuntu）来下载 SQL 软件包。MySQL 是一个使用关系数据库和 SQL 语言与数据交互的开源 DBMS。在 CentOS 7 中，MySQL 被另一个分支版本 MariaDB 取代；两者具有相同的源代码，但 MariaDB 中有一些增强功能。

按照以下步骤安装 MariaDB：

1.  使用`yum`软件包管理器（或`apt`，在基于 Debian 的系统中）下载`mariadb-server`软件包，如下摘录所示：

```py
yum install mariadb-server -y
```

1.  安装完成后，启动`mariadb`守护程序。此外，我们需要使用`systemd`命令在操作系统启动时启用它：

```py
systemctl enable mariadb ; systemctl start mariadb

Created symlink from /etc/systemd/system/multi-user.target.wants/mariadb.service to /usr/lib/systemd/system/mariadb.service.
```

1.  通过运行以下命令验证数据库状态，并确保输出包含`Active:active (running)`：

```py
systemctl status mariadb

● mariadb.service - MariaDB database server
 Loaded: loaded (/usr/lib/systemd/system/mariadb.service; enabled; vendor preset: disabled)
 Active: active (running) since Sat 2018-04-07 19:47:35 EET; 1min 34s ago
```

# 保护安装

安装完成后的下一个逻辑步骤是保护它。MariaDB 包括一个安全脚本，可以更改 MySQL 配置文件中的选项，比如创建用于访问数据库的 root 密码和允许远程访问。运行以下命令启动脚本：

```py
mysql_secure_installation
```

第一个提示要求您提供 root 密码。这个 root 密码不是 Linux 的 root 用户名，而是 MySQL 数据库的 root 密码；由于这是一个全新的安装，我们还没有设置它，所以我们将简单地按*Enter*进入下一步：

```py
Enter current password for root (enter for none): <PRESS_ENTER>
```

脚本将建议为 root 设置密码。我们将通过按`Y`并输入新密码来接受建议：

```py
Set root password? [Y/n] Y
New password:EnterpriseAutomation
Re-enter new password:EnterpriseAutomation
Password updated successfully!
Reloading privilege tables..
 ... Success! 
```

以下提示将建议删除匿名用户对数据库的管理和访问权限，这是强烈建议的：

```py
Remove anonymous users? [Y/n] y
 ... Success!
```

您可以从远程机器向托管在自动化服务器上的数据库运行 SQL 命令；这需要您为 root 用户授予特殊权限，以便他们可以远程访问数据库：

```py
Disallow root login remotely? [Y/n] n
 ... skipping.
```

最后，我们将删除任何人都可以访问的测试数据库，并重新加载权限表，以确保所有更改立即生效：

```py
Remove test database and access to it? [Y/n] y
 - Dropping test database...
 ... Success!
 - Removing privileges on test database...
 ... Success!

Reload privilege tables now? [Y/n] y
 ... Success!

Cleaning up...

All done!  If you've completed all of the above steps, your MariaDB
installation should now be secure.

Thanks for using MariaDB!
```

我们已经完成了安装的保护；现在，让我们验证它。

# 验证数据库安装

在 MySQL 安装后的第一步是验证它。我们需要验证`mysqld`守护程序是否已启动并正在侦听端口`3306`。我们将通过运行`netstat`命令和在侦听端口上使用`grep`来做到这一点：

```py
netstat -antup | grep -i 3306
tcp   0   0 0.0.0.0:3306      0.0.0.0:*         LISTEN      3094/mysqld
```

这意味着`mysqld`服务可以接受来自端口`3306`上的任何 IP 的传入连接。

如果您的机器上运行着`iptables`，您需要向`INPUT`链添加一个规则，以允许远程主机连接到 MySQL 数据库。还要验证`SELINUX`是否具有适当的策略。

第二次验证是通过使用`mysqladmin`实用程序连接到数据库。这个工具包含在 MySQL 客户端中，允许您在 MySQL 数据库上远程（或本地）执行命令：

```py
mysqladmin -u root -p ping
Enter password:EnterpriseAutomation 
mysqld is alive
```

| **切换名称** | **含义** |
| --- | --- |
| `-u` | 指定用户名。 |
| `-p` | 使 MySQL 提示您输入用户名的密码。 |
| `ping` | 用于验证 MySQL 数据库是否存活的操作名称。 |

输出表明 MySQL 安装已成功完成，我们准备进行下一步。

# 从 Python 访问 MySQL 数据库

Python 开发人员创建了`MySQLdb`模块，该模块提供了一个工具，可以从 Python 脚本中与数据库进行交互和管理。可以使用 Python 的`pip`或操作系统包管理器（如`yum`或`apt`）安装此模块。

要安装该软件包，请使用以下命令：

```py
yum install MySQL-python
```

按以下方式验证安装：

```py
[root@AutomationServer ~]# python
Python 2.7.5 (default, Aug  4 2017, 00:39:18) 
[GCC 4.8.5 20150623 (Red Hat 4.8.5-16)] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import MySQLdb
>>> 
```

由于模块已经成功导入，我们知道 Python 模块已成功安装。

现在，通过控制台访问数据库，并创建一个名为`TestingPython`的简单数据库，其中包含一个表。然后我们将从 Python 连接到它：

```py
[root@AutomationServer ~]# mysql -u root -p
Enter password: EnterpriseAutomation
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 12
Server version: 5.5.56-MariaDB MariaDB Server

Copyright (c) 2000, 2017, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> CREATE DATABASE TestingPython;
Query OK, 1 row affected (0.00 sec)
```

在前述声明中，我们使用 MySQL 实用程序连接到数据库，然后使用 SQL 的`CREATE`命令创建一个空的新数据库。

您可以使用以下命令验证新创建的数据库：

```py
MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| TestingPython      |
| mysql              |
```

```py
| performance_schema |
+--------------------+
4 rows in set (0.00 sec)
```

在 SQL 命令中不一定要使用大写字母；但是，这是最佳实践，以便将它们与变量和其他操作区分开来。

我们需要切换到新的数据库：

```py
MariaDB [(none)]> use TestingPython;
Database changed
```

现在，执行以下命令在数据库中创建一个新表：

```py
MariaDB [TestingPython]> CREATE TABLE TestTable (id INT PRIMARY KEY, fName VARCHAR(30), lname VARCHAR(20), Title VARCHAR(10));
Query OK, 0 rows affected (0.00 sec)
```

在创建表时，应指定列类型。例如，`fname`是一个最大长度为 30 个字符的字符串，而`id`是一个整数。

验证表的创建如下：

```py
MariaDB [TestingPython]> SHOW TABLES;
+-------------------------+
| Tables_in_TestingPython |
+-------------------------+
| TestTable               |
+-------------------------+
1 row in set (0.00 sec)

MariaDB [TestingPython]> describe TestTable;
+-------+-------------+------+-----+---------+-------+
| Field | Type        | Null | Key | Default | Extra |
+-------+-------------+------+-----+---------+-------+
| id    | int(11)     | NO   | PRI | NULL    |       |
| fName | varchar(30) | YES  |     | NULL    |       |
| lname | varchar(20) | YES  |     | NULL    |       |
| Title | varchar(10) | YES  |     | NULL    |       |
+-------+-------------+------+-----+---------+-------+
4 rows in set (0.00 sec)

```

# 查询数据库

此时，我们的数据库已准备好接受一些 Python 脚本。让我们创建一个新的 Python 文件，并提供数据库参数：

```py
import MySQLdb
SQL_IP ="10.10.10.130" SQL_USERNAME="root" SQL_PASSWORD="EnterpriseAutomation" SQL_DB="TestingPython"   sql_connection = MySQLdb.connect(SQL_IP,SQL_USERNAME,SQL_PASSWORD,SQL_DB) print sql_connection
```

提供的参数（`SQL_IP`、`SQL_USERNAME`、`SQL_PASSWORD`和`SQL_DB`）是建立连接并对端口`3306`上的数据库进行身份验证所需的。

以下表格列出了参数及其含义：

| **参数** | **含义** |
| --- | --- |
| `host` | 具有`mysql`安装的服务器 IP 地址。 |
| `user` | 具有对连接数据库的管理权限的用户名。 |
| `passwd` | 使用`mysql_secure_installation`脚本创建的密码。 |
| `db` | 数据库名称。 |

输出将如下所示：

```py
<_mysql.connection open to '10.10.10.130' at 1cfd430>
```

返回的对象表明已成功打开到数据库的连接。让我们使用此对象创建用于执行实际命令的 SQL 游标：

```py
cursor = sql_connection.cursor() cursor.execute("show tables")
```

您可以有许多与单个连接关联的游标，对一个游标的任何更改都会立即报告给其他游标，因为您已经打开了相同的连接。

游标有两个主要方法：`execute()`和`fetch*()`。

`execute()`方法用于向数据库发送命令并返回查询结果，而`fetch*()`方法有三种不同的用法：

| **方法名称** | **描述** |
| --- | --- |
| `fetchone()` | 从输出中获取一个记录，而不管返回的行数。 |
| `fetchmany(num)` | 返回方法内指定的记录数。 |
| `fetchall()` | 返回所有记录。 |

由于`fetchall()`是一个通用方法，可以获取一个记录或所有记录，我们将使用它：

```py
output = cursor.fetchall()
print(output) # python mysql_simple.py
(('TestTable',),)
```

# 向数据库中插入记录

`MySQLdb`模块允许我们使用相同的游标操作将记录插入到数据库中。请记住，`execute()`方法可用于插入和查询。毫不犹豫，我们将稍微修改我们的脚本，并提供以下`insert`命令：

```py
#!/usr/bin/python __author__ = "Bassim Aly" __EMAIL__ = "basim.alyy@gmail.com"   import MySQLdb

SQL_IP ="10.10.10.130" SQL_USERNAME="root" SQL_PASSWORD="EnterpriseAutomation" SQL_DB="TestingPython"   sql_connection = MySQLdb.connect(SQL_IP,SQL_USERNAME,SQL_PASSWORD,SQL_DB)   employee1 = {
  "id": 1,
  "fname": "Bassim",
  "lname": "Aly",
  "Title": "NW_ENG" }   employee2 = {
  "id": 2,
  "fname": "Ahmed",
  "lname": "Hany",
  "Title": "DEVELOPER" }   employee3 = {
  "id": 3,
  "fname": "Sara",
  "lname": "Mosaad",
  "Title": "QA_ENG" }   employee4 = {
  "id": 4,
  "fname": "Aly",
  "lname": "Mohamed",
  "Title": "PILOT" }   employees = [employee1,employee2,employee3,employee4]   cursor = sql_connection.cursor()   for record in employees:
  SQL_COMMAND = """INSERT INTO TestTable(id,fname,lname,Title) VALUES ({0},'{1}','{2}','{3}')""".format(record['id'],record['fname'],record['lname'],record['Title'])    print SQL_COMMAND
    try:
  cursor.execute(SQL_COMMAND)
  sql_connection.commit()
  except:
  sql_connection.rollback()   sql_connection.close()
```

在前面的例子中，以下内容适用：

+   我们将四个员工记录定义为字典。每个记录都有`id`、`fname`、`lname`和`title`，并具有不同的值。

+   然后，我们使用`employees`对它们进行分组，这是一个`list`类型的变量。

+   创建一个`for`循环来迭代`employees`列表，在循环内部，我们格式化了`insert` SQL 命令，并使用`execute()`方法将数据推送到 SQL 数据库。请注意，在`execute`函数内部不需要在命令后添加分号(`;`)，因为它会自动添加。

+   在每次成功执行 SQL 命令后，将使用`commit()`操作来强制数据库引擎提交数据；否则，连接将被回滚。

+   最后，使用`close()`函数来终止已建立的 SQL 连接。

关闭数据库连接意味着所有游标都被发送到 Python 垃圾收集器，并且将无法使用。还要注意，当关闭连接而不提交更改时，它会立即使数据库引擎回滚所有事务。

脚本的输出如下：

```py
# python mysql_insert.py
INSERT INTO TestTable(id,fname,lname,Title) VALUES (1,'Bassim','Aly','NW_ENG')
INSERT INTO TestTable(id,fname,lname,Title) VALUES (2,'Ahmed','Hany','DEVELOPER')
INSERT INTO TestTable(id,fname,lname,Title) VALUES (3,'Sara','Mosad','QA_ENG')
INSERT INTO TestTable(id,fname,lname,Title) VALUES (4,'Aly','Mohamed','PILOT')
```

您可以通过 MySQL 控制台查询数据库，以验证数据是否已提交到数据库：

```py
MariaDB [TestingPython]> select * from TestTable;
+----+--------+---------+-----------+
| id | fName  | lname   | Title     |
+----+--------+---------+-----------+
|  1 | Bassim | Aly     | NW_ENG    |
|  2 | Ahmed  | Hany    | DEVELOPER |
|  3 | Sara   | Mosaad  | QA_ENG    |
|  4 | Aly    | Mohamed | PILOT     |
+----+--------+---------+-----------+
```

现在，回到我们的 Python 代码，我们可以再次使用`execute()`函数；这次，我们使用它来选择在`TestTable`中插入的所有数据：

```py
import MySQLdb

SQL_IP ="10.10.10.130" SQL_USERNAME="root" SQL_PASSWORD="EnterpriseAutomation" SQL_DB="TestingPython"   sql_connection = MySQLdb.connect(SQL_IP,SQL_USERNAME,SQL_PASSWORD,SQL_DB) # print sql_connection   cursor = sql_connection.cursor() cursor.execute("select * from TestTable")   output = cursor.fetchall() print(output)
```

脚本的输出如下：

```py
python mysql_show_all.py 
((1L, 'Bassim', 'Aly', 'NW_ENG'), (2L, 'Ahmed', 'Hany', 'DEVELOPER'), (3L, 'Sara', 'Mosaa    d', 'QA_ENG'), (4L, 'Aly', 'Mohamed', 'PILOT'))
```

在上一个示例中，`id`值后的`L`字符可以通过再次将数据转换为整数（在 Python 中）来解决，使用`int()`函数。

游标内另一个有用的属性是`.rowcount`。这个属性将指示上一个`.execute()`方法返回了多少行。

# 总结

在本章中，我们学习了如何使用 Python 连接器与 DBMS 交互。我们在自动化服务器上安装了一个 MySQL 数据库，然后进行了验证。然后，我们使用 Python 脚本访问了 MySQL 数据库，并对其进行了操作。

在下一章中，我们将学习如何使用 Ansible 进行系统管理。
