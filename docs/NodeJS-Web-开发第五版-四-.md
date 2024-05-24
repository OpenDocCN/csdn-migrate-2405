# NodeJS Web 开发第五版（四）

> 原文：[`zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA`](https://zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章

第三部分：部署

除了使用 systemd 传统部署 Node.js 应用程序的方法外，新的最佳实践是使用 Kubernetes 或类似的系统。

本节包括以下章节：

+   第十章，将 Node.js 应用程序部署到 Linux 服务器

+   第十一章，使用 Docker 部署 Node.js 微服务

+   第十二章，使用 Terraform 在 AWS EC2 上部署 Docker Swarm

+   第十三章，单元测试和功能测试

+   第十四章，Node.js 应用程序中的安全性


将 Node.js 应用程序部署到 Linux 服务器

现在 Notes 应用程序已经相当完整，是时候考虑如何将其部署到真实服务器上了。我们已经创建了一个合作笔记概念的最小实现，效果相当不错。为了发展，Notes 必须离开我们的笔记本电脑，生活在一个真正的服务器上。

要实现的用户故事是访问托管应用程序，即使您的笔记本电脑关闭，也可以进行评估。开发者的故事是识别几种部署解决方案之一，确保系统在崩溃时具有足够的可靠性，以及用户可以在不占用开发者太多时间的情况下访问应用程序。

在本章中，我们将涵盖以下主题：

+   应用程序架构的讨论，以及如何实施部署的想法

+   在 Linux 服务器上进行传统的 LSB 兼容的 Node.js 部署

+   配置 Ubuntu 以管理后台任务

+   调整 Twitter 应用程序认证的设置

+   使用 PM2 可靠地管理后台任务

+   部署到虚拟 Ubuntu 实例，可以是我们笔记本电脑上的虚拟机（VM）或虚拟专用服务器（VPS）提供商

Notes 应用程序由两个服务组成：Notes 本身和用户认证服务，以及相应的数据库实例。为了可靠地向用户提供这些服务，这些服务必须部署在公共互联网上可见的服务器上，并配备系统管理工具，以保持服务运行，处理服务故障，并扩展服务以处理大量流量。一个常见的方法是依赖于在服务器启动期间执行脚本来启动所需的后台进程。

即使我们的最终目标是在具有自动扩展和所有流行词的基于云的平台上部署，您仍必须从如何在类 Unix 系统上后台运行应用程序的基础知识开始。

让我们通过再次审查架构并思考如何在服务器上最佳部署来开始本章。

# 第十四章：注意应用程序架构和部署考虑事项

在我们开始部署 Notes 应用程序之前，我们需要审查其架构并了解我们计划做什么。我们已将服务分成两组，如下图所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/27cc847a-c683-4bd3-9897-0a95dc242e1e.png)

用户界面部分是 Notes 服务及其数据库。后端，用户认证服务及其数据库需要更多的安全性。在我们的笔记本电脑上，我们无法为该服务创建设想中的保护墙，但我们即将实施一种形式的保护。

增强安全性的一种策略是尽可能少地暴露端口。这减少了所谓的攻击面，简化了我们在加固应用程序防止安全漏洞方面的工作。对于 Notes 应用程序，我们只需要暴露一个端口：用户访问应用程序的 HTTP 服务。其他端口——两个用于 MySQL 服务器，一个用于用户认证服务端口——不应该对公共互联网可见，因为它们仅供内部使用。因此，在最终系统中，我们应该安排暴露一个 HTTP 端口，并将其他所有内容与公共互联网隔离开来。

在内部，Notes 应用程序需要访问 Notes 数据库和用户认证服务。反过来，该服务需要访问用户认证数据库。Notes 服务不需要访问用户认证数据库，用户认证服务也不需要访问 Notes 数据库。按照目前的设想，不需要外部访问任何数据库或认证服务。

这给了我们一个将要实施的感觉。要开始，让我们学习在 Linux 上部署应用程序的传统方式。

# Node.js 服务的传统 Linux 部署

在本节中，我们将探讨传统的 Linux/Unix 服务部署。我们将在笔记本电脑上运行一个虚拟的 Ubuntu 实例来完成这个目标。目标是创建后台进程，这些进程在启动时自动启动，如果进程崩溃，则重新启动，并允许我们监视日志文件和系统状态。

传统的 Linux/Unix 服务器应用部署使用 init 脚本来管理后台进程。它们在系统启动时启动，并在系统停止时干净地关闭。名称“init 脚本”来自系统中启动的第一个进程的名称，其传统名称为`/etc/init`。init 脚本通常存储在`/etc/init.d`中，并且通常是简单的 shell 脚本。一些操作系统使用其他进程管理器，例如`upstart`、`systemd`或`launchd`，但遵循相同的模型。虽然这是一个简单的模型，但具体情况在一个操作系统（OS）到另一个操作系统（OS）之间差异很大。

Node.js 项目本身不包括任何脚本来管理任何操作系统上的服务器进程。基于 Node.js 实现完整的 Web 服务意味着我们必须创建脚本来与您的操作系统上的进程管理集成。

在互联网上拥有 Web 服务需要在服务器上运行后台进程，并且这些进程必须是以下内容：

+   **可靠性**：例如，当服务器进程崩溃时，它们应该能够自动重新启动。

+   **可管理性**：它们应该与系统管理实践很好地集成。

+   **可观察性**：管理员必须能够从服务中获取状态和活动信息。

为了演示涉及的内容，我们将使用 PM2 来实现*Notes*的后台服务器进程管理。PM2 将自己标榜为*进程管理器*，意味着它跟踪它正在管理的进程的状态，并确保这些进程可靠地执行并且可观察。PM2 会检测系统类型，并可以自动集成到本机进程管理系统中。它将创建一个 LSB 风格的 init 脚本（[`wiki.debian.org/LSBInitScripts`](http://wiki.debian.org/LSBInitScripts)），或者根据您的服务器需要创建其他脚本。

本章的目标是探讨如何做到这一点，有几种实现这一目标的途径：

+   传统的虚拟机管理应用程序，包括 VirtualBox、Parallels 和 VMware，让我们在虚拟环境中安装 Ubuntu 或任何其他操作系统。在 Windows 上，Hyper-V 随 Windows 10 Pro 一起提供类似的功能。在这些情况下，您下载引导 CD-ROM 的 ISO 镜像，从该 ISO 镜像引导虚拟机，并运行完整的操作系统安装，就像它是一台普通的计算机一样。

+   您可以从全球数百家网络托管提供商中租用廉价的 VPS。通常选择受限于 Ubuntu 服务器。在这些情况下，您将获得一个预先准备好的服务器系统，可用于安装运行网站的服务器软件。

+   一种新产品 Multipass 是一种基于轻量级虚拟化技术的轻量级虚拟机管理工具，适用于每台台式计算机操作系统。它为您提供了与从托管提供商租用 VPS 或使用 VirtualBox 等 VM 软件获得的完全相同的起点，但对系统的影响要比 VirtualBox 等传统 VM 应用程序低得多。就像在笔记本电脑上获得 VPS 一样。

从启动后台进程的工具和命令的角度来看，这些选择之间没有实际区别。在 VirtualBox 中安装的 Ubuntu 实例与从 Web 托管提供商那里租用的 VPS 上的 Ubuntu 相同，与在 Multipass 实例中启动的 Ubuntu 相同。它是相同的操作系统，相同的命令行工具和相同的系统管理实践。不同之处在于对笔记本电脑性能的影响。使用 Multipass，我们可以在几秒钟内设置一个虚拟的 Ubuntu 实例，并且很容易在笔记本电脑上运行多个实例而几乎不会影响性能。使用 VirtualBox、Hyper-V 或其他 VM 解决方案的体验是，使用笔记本电脑会很快感觉像在糖浆中行走，特别是在同时运行多个 VM 时。

因此，在本章中，我们将在 Multipass 上运行此练习。本章中显示的所有内容都可以轻松转移到 VirtualBox/VMware/等上的 Ubuntu 或从 Web 托管提供商那里租用的 VPS 上。

对于此部署，我们将使用 Multipass 创建两个 Ubuntu 实例：一个用于 Notes 服务，另一个用于用户服务。在每个实例中，都将有一个对应数据库的 MySQL 实例。然后我们将使用 PM2 配置这些系统，在启动时在后台启动我们的服务。

由于 Multipass 和 WSL2 之间存在明显的不兼容性，因此在 Windows 上使用 Multipass 可能会遇到困难。如果遇到问题，我们有一节描述应该怎么做。

第一项任务是复制上一章的源代码。建议您创建一个新目录`chap10`，作为`chap09`目录的同级目录，并将`chap09`中的所有内容复制到`chap10`中。

首先，让我们安装 Multipass，然后我们将开始部署和测试用户认证服务，然后部署和测试 Notes。我们还将涵盖 Windows 上的设置问题。

## 安装 Multipass

Multipass 是由 Canonical 开发的开源工具。它是一个非常轻量级的用于管理 VM 的工具，特别是基于 Ubuntu 的 VM。它足够轻便，可以在笔记本电脑上运行迷你云主机系统。

要安装 Multipass，请从[`multipass.run/`](https://multipass.run/)获取安装程序。它也可能通过软件包管理系统可用。

安装了 Multipass 后，您可以运行以下命令中的一些来尝试它：

```

Because we did not supply a name for the machine, Multipass created a random name. It isn't shown in the preceding snippet, but the first command included the download and setup of a VM image. The `shell` command starts a login shell inside the newly created VM, where you can use tools like `ps` or `htop` to see that there is indeed a full complement of processes running already.

Since one of the first things you do with a new Ubuntu install is to update the system, let's do so the Multipass way:

```

这按预期工作，您会看到`apt-get`首先更新其可用软件包的列表，然后要求您批准下载和安装软件包以进行更新，之后它会这样做。熟悉 Ubuntu 的人会觉得这很正常。不同之处在于从主机计算机的命令行环境中执行此操作。

这很有趣，但我们有一些工作要做，我们对 Multipass 基于野马的机器名称不满意。让我们学习如何删除 Multipass 实例：

```

We can easily delete a VM image with the `delete` command; it is then marked as `Deleted`*.* To truly remove the VM, we must use the `purge` command.

We've learned how to create, manage, and delete VMs using Multipass. This was a lot faster than some of the alternative technologies. With VirtualBox, for example, we would have had to find and download an ISO, then boot a VirtualBox VM instance and run the Ubuntu installer, taking a lot more time. 

There might be difficulties using Multipass on Windows, so let's talk about that and how to rectify it.

### Handling a failure to launch Multipass instances on Windows

The Multipass team makes their application available to on run Windows systems, but issues like the following can crop up:

```

它通过设置实例的所有步骤，但在最后一步，我们收到了这条消息，而不是成功。运行`multipass list`可能会显示实例处于`Running`状态，但没有分配 IP 地址，运行`multipass shell`也会导致超时。

如果在计算机上安装了 WSL2 和 Multipass，则会观察到此超时。WSL2 是 Windows 的轻量级 Linux 子系统，被称为在 Windows 上运行 Linux 命令的极佳环境。同时运行 WSL2 和 Multipass 可能会导致不希望的行为。

在本章中，WSL2 没有用。这是因为 WSL2 目前不支持安装在重启后持续存在的后台服务，因为它不支持`systemd`。请记住，我们的目标是学习设置持久的后台服务。

可能需要禁用 WSL2。要这样做，请使用 Windows 任务栏中的搜索框查找“打开或关闭 Windows 功能”控制面板。因为 WSL2 是一个功能而不是一个安装或卸载的应用程序，所以可以使用此控制面板来启用或禁用它。只需向下滚动以找到该功能，取消选中复选框，然后重新启动计算机。

Multipass 在线文档中有一个用于 Windows 的故障排除页面，其中包含一些有用的提示，网址为[`multipass.run/docs/troubleshooting-networking-on-windows`](https://multipass.run/docs/troubleshooting-networking-on-windows)。

WSL2 和 Multipass 都使用 Hyper-V。这是 Windows 的虚拟化引擎，它还支持以类似于 VirtualBox 或 VMware 的模式安装 VM。可以轻松下载 Ubuntu 或任何其他操作系统的 ISO 并在 Hyper-V 上安装它。这将导致完整的操作系统，可以在其中进行后台进程部署的实验。您可能更喜欢在 Hyper-V 内部运行这些示例。

安装了虚拟机后，本章其余大部分说明都将适用。具体来说，`install-packages.sh`脚本可用于安装完成说明所需的 Ubuntu 软件包，`configure-svc`脚本可用于将服务“部署”到`/opt/notes`和`/opt/userauth`。建议在虚拟机内部使用 Git 克隆与本书相关的存储库。最后，pm2-single 目录中的脚本可用于在 PM2 下运行 Notes 和 Users 服务。

我们的目的是学习如何在 Linux 系统上部署 Node.js 服务，而无需离开我们的笔记本电脑。为此，我们熟悉了 Multipass，因为它是管理 Ubuntu 实例的绝佳工具。我们还了解了诸如 Hyper-V 或 VirtualBox 之类的替代方案，这些替代方案也可以用于管理 Linux 实例。

让我们开始探索使用用户认证服务进行部署。

## 为用户认证服务配置服务器

由于我们希望拥有分段基础架构，并将用户认证服务放在一个隔离区域中，让我们首先尝试构建该架构。使用 Multipass，我们将创建两个服务器实例`svc-userauth`和`svc-notes`。每个实例将包含自己的 MySQL 实例和相应的基于 Node.js 的服务。在本节中，我们将设置`svc-userauth`，然后在另一节中，我们将复制该过程以设置`svc-notes`。

对于我们的 DevOps 团队，他们要求对所有管理任务进行自动化，我们将创建一些 shell 脚本来管理服务器的设置和配置。

这里显示的脚本处理了部署到两个服务器的情况，其中一个服务器保存认证服务，另一个保存*Notes*应用程序。在本书的 GitHub 存储库中，您将找到其他脚本，用于部署到单个服务器。如果您使用的是 VirtualBox 而不是 Multipass 等较重的虚拟化工具，则可能需要单个服务器方案。

在本节中，我们将创建用户认证后端服务器`svc-userauth`，在后面的部分中，我们将创建*Notes*前端的服务器`svc-notes`。由于这两个服务器实例将设置类似，我们可能会质疑为什么要设置两个服务器。这是因为我们决定的安全模型。

涉及几个步骤，包括一些用于自动化 Multipass 操作的脚本，如下所示：

1.  创建一个名为`chap10/multipass`的目录，用于管理 Multipass 实例的脚本。

1.  然后，在该目录中创建一个名为`create-svc-userauth.sh`的文件，其中包含以下内容：

```

On Windows, instead create a file named `create-svc-userauth.ps1` containing the following:

```

这两者几乎相同，只是计算当前目录的方法不同。

Multipass 中的`mount`命令将主机目录附加到给定位置的实例中。因此，我们将`multipass`目录附加为`/build`，将`users`附加为`/build-users`。

``pwd``符号是 Unix/Linux shell 环境的一个特性。它意味着运行`pwd`进程并捕获其输出，将其作为命令行参数提供给`multipass`命令。对于 Windows，我们在 PowerShell 中使用`(get-location)`来达到同样的目的。

1.  通过运行脚本创建实例：

```

Or, on Windows, run this:

```

运行脚本中的命令，将启动实例并从主机文件系统挂载目录。

1.  创建一个名为`install-packages.sh`的文件，其中包含以下内容：

```

This installs Node.js 14.x and sets up other packages required to run the authentication service. This includes a MySQL server instance and the MySQL client.

The Node.js documentation ([`nodejs.org/en/download/package-manager/`](https://nodejs.org/en/download/package-manager/)) has documentation on installing Node.js from package managers for several OSes. This script uses the recommended installation for Debian and Ubuntu systems because that's the OS used in the Multipass instance.

A side effect of installing the `mysql-server` package is that it launches a running MySQL service with a default configuration. Customizing that configuration is up to you, but for our purposes here and now, the default configuration will work.

5.  Execute this script inside the instance like so:

```

正如我们之前讨论的，`exec`命令会导致在主机系统上运行此命令，从而在容器内部执行命令。

1.  在`users`目录中，编辑`user-server.mjs`并更改以下内容：

```

Previously, we had specified a hardcoded `'localhost'` here. The effect of this was that the user authentication service only accepted connections from the same computer. To implement our vision of *Notes* and the user authentication services running on different computers, this service must support connections from elsewhere.

This change introduces a new environment variable, `REST_LISTEN`, where we will declare where the server should listen for connections.

As you edit the source files, notice that the changes are immediately reflected inside the Multipass machine in the `/build-users` directory.

7.  Create a file called `users/sequelize-mysql.yaml` containing the following:

```

这是允许用户服务与本地 MySQL 实例连接的配置。`dbname`、`username`和`password`参数必须与之前显示的配置脚本中的值匹配。

1.  然后，在`users/package.json`文件中，将这些条目添加到`scripts`部分：

```

The `on-server` script contains the runtime configuration we'll use on the server.

9.  Next, in the `users` directory, run this command:

```

由于我们现在正在使用 MySQL，我们必须安装驱动程序包。

1.  现在创建一个名为`configure-svc-userauth.sh`的文件，其中包含以下内容：

```

This script is meant to execute inside the Ubuntu system managed by Multipass. The first section sets a user identity in the database. The second section copies the user authentication service code, from `/build-users` to `/userauth`, into the instance, followed by installing the required packages.

Since the MySQL server is already running, the `mysql` command will access the running server to create the database, and create the `userauth` user. We will use this user ID to connect with the database from the user authentication service.

But, why are some files removed before copying them into the instance? The primary goal is to delete the `node_modules` directory; the other files are simply unneeded. The `node_modules` directory contains modules that were installed on your laptop, and surely your laptop has a different OS than the Ubuntu instance running on the server? Therefore, rerunning `npm install` on the Ubuntu server ensures the packages are installed correctly.

11.  Run the `configure-svc-userauth` script like so:

```

请记住源代码中的`multipass`目录被挂载到实例内部作为`/build`。一旦我们创建了这个文件，它就会出现在`/build`目录中，我们可以在实例内部执行它。

在本书中，我们已经多次谈到了明确声明所有依赖关系和自动化一切的价值。这证明了这个价值，因为现在，我们只需运行几个 shell 脚本，服务器就配置好了。而且我们不必记住如何启动服务器，因为`package.json`中的`scripts`部分。

1.  现在我们可以启动用户认证服务器，就像这样：

```

Notice that our notation is to use `$` to represent a command typed on the host computer, and `ubuntu@svc-userauth:~$` to represent a command typed inside the instance. This is meant to help you understand where the commands are to be executed.

In this case, we've logged into the instance, changed directory to `/opt/userauth`, and started the server using the corresponding npm script.

### Testing the deployed user authentication service

Our next step at this point is to test the service. We created a script, `cli.mjs`, for that purpose. In the past, we ran this script on the same computer where the authentication service was running. But this time, we want to ensure the ability to access the service remotely.

Notice that the URL printed is `http://[::]:5858`. This is shorthand for listening to connections from any IP address.

On our laptop, we can see the following:

```

Multipass 为实例分配了一个 IP 地址。您的 IP 地址可能会有所不同。

在我们的笔记本电脑上有源代码的副本，包括`cli.mjs`的副本。这意味着我们可以在笔记本电脑上运行`cli.mjs`，告诉它访问`svc-userauth`上的服务。这是因为我们提前考虑并添加了`--host`和`--port`选项到`cli.mjs`。理论上，使用这些选项，我们可以在互联网上的任何地方访问这个服务器。目前，我们只需要在笔记本电脑的虚拟环境中进行访问。

在您的笔记本电脑上，而不是在 Multipass 内部的常规命令环境中，运行这些命令：

```

Make sure to specify the correct host IP address and port number.

If you remember, the script retrieves the newly created user entry and prints it out. But we need to verify this and can do so using the `list-users` command. But let's do something a little different, and learn how to access the database server.

In another command window on your laptop, type these commands:

```

这显示了我们创建的用户的数据库条目。请注意，当登录到 Multipass 实例时，我们可以使用任何 Ubuntu 命令，因为我们面前有完整的操作系统。

我们不仅在 Ubuntu 服务器上启动了用户认证服务，而且还验证了我们可以从服务器外部访问该服务。

在本节中，我们设置了我们想要运行的两个服务器中的第一个。我们仍然需要创建`svc-notes`服务器。

但在此之前，我们首先需要讨论在 Windows 上运行脚本。

## 在 Windows 上使用 PowerShell 执行脚本

在本章中，我们将编写几个 shell 脚本。其中一些脚本需要在您的笔记本电脑上运行，而不是在 Ubuntu 托管的服务器上运行。一些开发人员使用 Windows，因此我们需要讨论在 PowerShell 上运行脚本。

在 Windows 上执行脚本是不同的，因为它使用 PowerShell 而不是 Bash，还有许多其他考虑因素。对于这个和接下来的脚本，做出以下更改。

PowerShell 脚本文件名必须以`.ps1`扩展名结尾。对于大多数这些脚本，所需的只是将`.sh`脚本复制为`.ps1`文件，因为脚本非常简单。要执行脚本，只需在 PowerShell 窗口中键入`.\scriptname.ps1`。换句话说，在 Windows 上，刚才显示的脚本必须命名为`configure-svc-userauth.ps1`，并且以`.\configure-svc-userauth.ps1`执行。

要执行这些脚本，您可能需要更改 PowerShell 执行策略：

```

Obviously, there are security considerations with this change, so change the execution policy back when you're done.

A simpler method on Windows is to simply paste these commands into a PowerShell window. 

It was useful to discuss script execution on PowerShell. Let's return to the task at hand, which is provisioning the Notes stack on Ubuntu. Since we have a functioning user authentication service, the remaining task is the Notes service.

## Provisioning a server for the Notes service

So far, we have set up the user authentication service on Multipass. Of course, to have the full Notes application stack running, the Notes service must also be running. So let's take care of that now.

The first server, `svc-userauth`, is running the user authentication service. Of course, the second server will be called `svc-notes`, and will run the Notes service. What we'll do is very similar to how we set up `svc-userauth`.

There are several tasks in the `multipass` directory to prepare this second server. As we did with the `svc-userauth` server, here, we set up the `svc-notes` server by installing and configuring required Ubuntu packages, then set up the Notes application:

1.  Create a script named `multipass/create-svc-notes.sh` containing the following:

```

这个任务是启动 Multipass 实例，并且与`create-svc-userauth`非常相似，但是更改为使用单词`notes`。

对于 Windows，创建一个名为`multipass/create-svc-notes.ps1`的文件，其中包含以下内容：

```

This is the same as before, but using `(get-location)` this time.

2.  Create the instance by running the script as follows:

```

或者，在 Windows 上，运行以下命令：

```

Either one runs the commands in the scripts that will launch the instance and mount directories from the host filesystem.

3.  Install the required packages like so:

```

此脚本安装了 Node.js、MySQL 服务器和其他一些必需的软件包。

1.  现在创建一个文件，`notes/models/sequelize-mysql.yaml`，其中包含以下内容：

```

This is the database name, username, and password credentials for the database configured previously.

5.  Because we are now using MySQL, run this command:

```

我们需要 MySQL 驱动程序包来使用 MySQL。

1.  然后，在`notes/package.json`文件中，将此条目添加到`scripts`部分：

```

This uses the new database configuration for the MySQL server and the IP address for the user authentication service. Make sure that the IP address matches what Multipass assigned to `svc-userauth`.

You'll, of course, get the IP address in the following way:

```

`on-server`脚本将需要相应地更新。

1.  复制`multipass/configure-svc-userauth.sh`以创建一个名为`multipass/configure-svc-notes.sh`的脚本，并将最后两个部分更改为以下内容：

```

This is also similar to what we did for `svc-userauth`. This also changes things to use the word `notes` where we used `userauth` before.

Something not explicitly covered here is ensuring the `.env` file you created to hold Twitter secrets is deployed to this server. We suggested ensuring this file is not committed to a source repository. That means you'll be handling it semi-manually perhaps, or you'll have to use some developer ingenuity to create a process for managing this file securely.

8.  Run the `configure-svc-notes` script like so:

```

请记住，源树中的`multipass`目录被挂载到实例内部作为`/build`。一旦我们创建了这个文件，它就会出现在`/build`目录中，并且我们可以在实例内部执行它。

1.  现在可以使用以下命令运行 Notes 服务：

```

As with `svc-userauth`, we shell into the server, change the directory to `/opt/notes`, and run the `on-server` script. If you want Notes to be visible on port `80`, simply change the `PORT` environment variable. After that, the URL in the `TWITTER_CALLBACK_HOST` variable must contain the port number on which Notes is listening. For that to work, the `on-server` script needs to run as `root`, so therefore we will run the following:

```

更改是使用`sudo`以`root`身份执行命令。

为了测试这一点，我们当然需要使用浏览器连接到 Notes 服务。为此，我们需要使用`svc-notes`的 IP 地址，这是我们之前从 Multipass 学到的。使用这个例子，URL 是`http://172.23.89.142:3000`。

您会发现，由于我们在外观和感觉类别中没有改变任何内容，我们的*Notes*应用程序看起来一直都是这样。从功能上讲，您将无法使用 Twitter 凭据登录，但可以使用我们在测试期间创建的本地帐户之一登录。

一旦两个服务都在运行，您可以使用浏览器与*Notes*应用程序进行交互，并通过其功能运行它。

我们已经构建了两个服务器，`svc-userauth`和`svc-notes`，在这两个服务器上运行 Notes 应用程序堆栈。这给了我们两个 Ubuntu 实例，每个实例都配置了数据库和 Node.js 服务。我们能够手动运行身份验证和 Notes 服务，并从一个 Ubuntu 实例连接到另一个 Ubuntu 实例，每个实例都与其相应的数据库一起工作。要将其作为完全部署的服务器，我们将在后面的部分中使用 PM2。

我们已经学到了一些关于配置 Ubuntu 服务器的知识，尽管运行服务作为后台进程仍然存在问题。在解决这个问题之前，让我们纠正一下 Twitter 登录功能的情况。Twitter 登录的问题在于应用现在位于不同的 IP 地址，因此为了解决这个问题，我们现在必须在 Twitter 的管理后端中添加该 IP 地址。

# 调整 Twitter 身份验证以在服务器上工作

正如我们刚才指出的，当前部署的*Notes*应用程序不支持基于 Twitter 的登录。任何尝试都会导致错误。显然，我们不能这样部署它。

我们之前为*Notes*设置的 Twitter 应用程序将无法工作，因为引用我们笔记本电脑的身份验证 URL 对于服务器来说是不正确的。要使 OAuth 在这个新服务器上与 Twitter 一起工作，请转到`developer.twitter.com/en/apps`并重新配置应用程序以使用服务器的 IP 地址。

该页面是您已在 Twitter 注册的应用程序的仪表板。单击`Details`按钮，您将看到配置的详细信息。单击`Edit`按钮，编辑回调 URL 的列表如下：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/100f13e0-7055-4914-b2b6-19352f3bc230.png)

当然，您必须替换服务器的 IP 地址。如果您的 Multipass 实例被分配了 IP 地址`192.168.64.9`，则此处显示的 URL 是正确的。这将通知 Twitter 使用一个新的正确的回调 URL。同样，如果您已经配置*Notes*监听端口`80`，那么您指向 Twitter 的 URL 也必须使用端口`80`。您必须为将来使用的任何回调 URL 更新此列表。

接下来要做的是更改*Notes*应用程序，以便在`svc-notes`服务器上使用这个新的回调 URL。在`routes/users.mjs`中，默认值是`http://localhost:3000`，用于我们的笔记本电脑。但是现在我们需要使用服务器的 IP 地址。幸运的是，我们事先考虑到了这一点，软件有一个环境变量来实现这个目的。在`notes/package.json`中，将以下环境变量添加到`on-server`脚本中：

```

Use the actual IP address or domain name assigned to the server being used. In a real deployment, we'll have a domain name to use here. 

Additionally, to enable Twitter login support, it is required to supply Twitter authentication tokens in the environment variables:

```

这不应该添加在`package.json`中，而应通过其他方式提供。我们还没有找到合适的方法，但我们确实发现将这些变量添加到`package.json`中意味着将它们提交到源代码存储库，这可能会导致这些值泄漏给公众。

目前，服务器可以这样启动：

```

This is still a semi-manual process of starting the server and specifying the Twitter keys, but you'll be able to log in using Twitter credentials. Keep in mind that we still need a solution for this that avoids committing these keys to a source repository.

The last thing for us to take care of is ensuring the two service processes restart when the respective servers restart. Right now, the services are running at the command line. If we ran `multipass restart`, the service instances will reboot and the service processes won't be running.

In the next section, we'll learn one way to configure a background process that reliably starts when a computer is booted.

# Setting up PM2 to manage Node.js processes

We have two servers, `svc-notes` and `svc-userauth`, configured so we can run the two services making up the Notes application stack. A big task remaining is to ensure the Node.js processes are properly installed as background processes.

To see the problem, start another command window and run these commands:

```

服务器实例正在 Multipass 下运行，`restart`命令导致命名实例`stop`，然后`start`。这模拟了服务器的重启。由于两者都在前台运行，您将看到每个命令窗口退出到主机命令 shell，并且再次运行`multipass list`将显示两个实例处于`Running`状态。最重要的是，两个服务都不再运行。

有许多方法可以管理服务器进程，以确保在进程崩溃时重新启动等。我们将使用**PM2**（[`pm2.keymetrics.io/`](http://pm2.keymetrics.io/)），因为它针对 Node.js 进程进行了优化。它将进程管理和监控捆绑到一个应用程序中。

现在让我们看看如何使用 PM2 来正确地管理 Notes 和用户身份验证服务作为后台进程。我们将首先熟悉 PM2，然后创建脚本来使用 PM2 来管理服务，最后，我们将看到如何将其与操作系统集成，以便正确地将服务作为后台进程进行管理。

## 熟悉 PM2

为了熟悉 PM2，让我们使用`svc-userauth`服务器设置一个测试。我们将创建一个目录来保存`pm2-userauth`项目，在该目录中安装 PM2，然后使用它来启动用户身份验证服务。在此过程中，我们将学习如何使用 PM2。

首先在`svc-userauth`服务器上运行以下命令：

```

The result of these commands is an npm project directory containing the PM2 program and a `package.json` file that we can potentially use to record some scripts.

Now let's start the user authentication server using PM2:

```

这归结为运行`pm2 start ./user-server.mjs`，只是我们添加了包含配置值的环境变量，并且指定了 PM2 的完整路径。这样可以在后台运行我们的用户服务器。

我们可以重复使用`cli.mjs`来列出已知的身份验证服务器用户的测试：

```

Since we had previously launched this service and tested it, there should be user IDs already in the authentication server database. The server is running, but because it's not in the foreground, we cannot see the output. Try this command:

```

因为 PM2 捕获了服务器进程的标准输出，任何输出都被保存起来。`logs`命令让我们查看那些输出。

其他一些有用的命令如下：

+   `pm2 status`：列出 PM2 当前正在管理的所有命令及其状态

+   `pm2 stop SERVICE`：停止命名服务

+   `pm2 start SERVICE`或`pm2 restart SERVICE`：启动命名服务

+   `pm2 delete SERVICE`：使 PM2 忘记命名服务

还有其他几个命令，PM2 网站包含了完整的文档。[`pm2.keymetrics.io/docs/usage/pm2-doc-single-page/`](https://pm2.keymetrics.io/docs/usage/pm2-doc-single-page/)

暂时，让我们关闭它并删除受管进程：

```

We have familiarized ourselves with PM2, but this setup is not quite suitable for any kind of deployment. Let's instead set up scripts that will manage the Notes services under PM2 more cleanly. 

## Scripting the PM2 setup on Multipass

We have two Ubuntu systems onto which we've copied the Notes and user authentication services, and also configured a MySQL server for each machine. On these systems, we've manually run the services and know that they work, and now it's time to use PM2 to manage these services as persistent background processes.

With PM2 we can create a file, `ecosystem.json`, to describe precisely how to launch the processes. Then, with a pair of PM2 commands, we can integrate the process setup so it automatically starts as a background process.

Let's start by creating two directories, `multipass/pm2-notes` and `multipass/pm2-userauth`. These will hold the scripts for the corresponding servers. 

In `pm2-notes`, create a file, `package.json`, containing the following:

```

这为我们记录了对 PM2 的依赖，因此可以轻松安装它，以及一些有用的脚本可以在 PM2 上运行。

然后在同一目录中，创建一个包含以下内容的`ecosystem.json`文件：

```

The `ecosystem.json` file is how we describe a process to be monitored to PM2.

In this case, we've described a single process, called `Notes`. The `cwd` value declares where the code for this process lives, and the `script` value describes which script to run to launch the service. The `env` value is a list of environment variables to set.

This is where we would specify the Twitter authentication tokens. But since this file is likely to be committed to a source repository, we shouldn't do so. Instead, we'll forego Twitter login functionality for the time being. 

The `USER_SERVICE_URL` and `TWITTER_CALLBACK_HOST` variables are set according to the `multipass list` output we showed earlier. These values will, of course, vary based on what was selected by your host system.

These environment variables are the same as we set in `notes/package.json` – except, notice that we've set `PORT` to `80` so that it runs on the normal HTTP port. To successfully specify port `80`, PM2 must execute as root.

In `pm2-userauth`, create a file named `package.json` containing the folllowing:

```

这与`pm2-notes`相同，只是名称不同。

然后，在`pm2-userauth`中，创建一个名为`ecosystem.json`的文件，其中包含以下内容：

```

This describes the user authentication service. On the server, it is stored in the `/userauth` directory and is launched using the `user-server.mjs` script, with that set of environment variables.

Next, on both servers create a directory called `/opt/pm2`. Copy the files in `pm2-notes` to the `/opt/pm2` directory on `svc-notes`, and copy the files in `pm2-userauth` to the `/opt/pm2` directory on `svc-userauth`.

On both `svc-notes` and `svc-userauth`, you can run these commands:

```

这样做会启动两个服务器实例上的服务。 `npm run logs` 命令让我们可以实时查看日志输出。我们已经在更符合 DevOps 的日志配置中配置了两个服务，没有启用 DEBUG 日志，并且使用了*common*日志格式。

对于测试，我们访问与之前相同的 URL，但是端口改为`80`而不是`3000`。

因为`svc-notes`上的 Notes 服务现在在端口`80`上运行，我们需要再次更新 Twitter 应用程序的配置，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/86efbfc1-e3a4-402c-8cce-22a36e1d88da.png)

这将从服务器的 URL 中删除端口`3000`。应用程序不再在端口`3000`上运行，而是在端口`80`上运行，我们需要告诉 Twitter 这个变化。

## 将 PM2 设置集成为持久后台进程

*Notes*应用程序应该完全正常运行。还有一个小任务要完成，那就是将其与操作系统集成。

在类 Unix 系统上的传统方法是在`/etc`目录中的一个目录中添加一个 shell 脚本。Linux 社区为此目的定义了 LSB Init Script 格式，但由于每个操作系统对于管理后台进程的脚本有不同的标准，PM2 有一个命令可以为每个操作系统生成正确的脚本。

让我们从`svc-userauth`开始，运行这些命令：

```

With `npm run save`, we run the `pm2 save` command. This command saves the current configuration into a file in your home directory. 

With `npm run startup`, we run the `pm2 startup` command. This converts the saved current configuration into a script for the current OS that will manage the PM2 system. PM2, in turn, manages the set of processes you've configured with PM2.

In this case, it identified the presence of the `systemd` init system, which is the standard for Ubuntu. It generated a file, `/etc/systemd/system/pm2-root.service`, that tells Ubuntu about PM2\. In amongst the output, it tells us how to use `systemctl` to start and stop the PM2 service.

Do the same on `svc-notes` to implement the background service there as well.

And now we can test restarting the two servers with the following commands:

```

机器应该能够正确重启，并且在我们不进行干预的情况下，服务将会运行。您应该能够对*Notes*应用程序进行测试，并查看它是否正常工作。此时 Twitter 登录功能将无法使用，因为我们没有提供 Twitter 令牌。

在每台服务器上运行这个命令尤其有益：

```

The `monit` command starts a monitoring console showing some statistics including CPU and memory use, as well as logging output.

When done, run the following command:

```

当然，这将关闭服务实例。由于我们所做的工作，您随时可以重新启动它们。

在这一部分，我们学到了很多关于将*Notes*应用程序配置为受管后台进程的知识。通过一系列 shell 脚本和配置文件，我们组建了一个系统，使用 PM2 来管理这些服务作为后台进程。通过编写我们自己的脚本，我们更清楚地了解了底层的工作原理。

有了这些，我们就可以结束本章了。

# 总结

在本章中，我们开始了解将 Node.js 服务部署到生产服务器的过程。目标是学习部署到云托管，但为了达到这个目标，我们学习了在 Linux 系统上获得可靠后台进程的基础知识。

我们首先回顾了 Notes 应用程序的架构，并看到这将如何影响部署。这使我们能够了解服务器部署的要求。

然后我们学习了在 Linux 上使用 init 脚本部署服务的传统方法。为此，我们学习了如何使用 PM2 来管理进程，并将其集成为持久后台进程。PM2 是 Unix/Linux 系统上管理后台进程的有用工具。部署和管理持久性是任何开发 Web 应用程序的关键技能。

虽然这是在您的笔记本电脑上执行的，但完全相同的步骤可以在公共服务器上执行，比如从 Web 托管公司租用的 VPS。通过一点工作，我们可以使用这些脚本在公共 VPS 上设置一个测试服务器。我们需要更好的自动化工作，因为 DevOps 团队需要完全自动化的部署。

即使在云托管平台的时代，许多组织仍然使用我们在本章讨论的相同技术部署服务。他们不使用基于云的部署，而是租用一个或几个 VPS。但即使在使用 Docker、Kubernetes 等云基部署时，开发人员也必须知道如何在类 Unix 系统上实现持久服务。Docker 容器通常是 Linux 环境，必须包含可靠的持久后台任务，这些任务是可观察和可维护的。

在下一章中，我们将转向不同的部署技术：Docker。Docker 是一种流行的系统，用于将应用程序代码打包在一个*容器*中，在我们的笔记本电脑上执行，或者在云托管平台上按比例执行而不改变。


使用 Docker 部署 Node.js 微服务

现在我们已经体验了传统的 Linux 部署应用程序的方式，让我们转向 Docker，这是一种流行的新的应用程序部署方式。

Docker（http://docker.com）是软件行业中一个很酷的新工具。它被描述为*面向开发人员和系统管理员的分布式应用程序的开放平台*。它是围绕 Linux 容器化技术设计的，并专注于描述在任何 Linux 变体上的软件配置。

Docker 容器是 Docker 镜像的运行实例。Docker 镜像是一个包含特定 Linux 操作系统、系统配置和应用程序配置的捆绑包。Docker 镜像使用 Dockerfile 来描述，这是一个相当简单的编写脚本，描述如何构建 Docker 镜像。Dockerfile 首先通过指定一个基础镜像来开始构建，这意味着我们从其他镜像派生 Docker 镜像。Dockerfile 的其余部分描述了要添加到镜像中的文件，要运行的命令以构建或配置镜像，要公开的网络端口，要在镜像中挂载的目录等等。

Docker 镜像存储在 Docker 注册服务器上，每个镜像存储在自己的存储库中。最大的注册表是 Docker Hub，但也有第三方注册表可用，包括您可以安装在自己硬件上的注册服务器。Docker 镜像可以上传到存储库，并且可以从存储库部署到任何 Docker 服务器。

我们实例化一个 Docker 镜像来启动一个 Docker 容器。通常，启动容器非常快速，而且通常情况下，容器会在短时间内实例化，然后在不再需要时被丢弃。

运行的容器感觉像是在虚拟机上运行的虚拟服务器。然而，Docker 容器化与诸如 VirtualBox 或 Multipass 之类的虚拟机系统非常不同。容器不是完整计算机的虚拟化。相反，它是一个极其轻量级的外壳，创建了已安装操作系统的外观。例如，容器内运行的进程实际上是在主机操作系统上运行的，使用某些 Linux 技术（cgroups、内核命名空间等）创建了运行特定 Linux 变体的幻觉。您的主机操作系统可以是 Ubuntu，容器操作系统可以是 Fedora 或 OpenSUSE，甚至是 Windows；Docker 使所有这些都能运行。

虽然 Docker 主要针对 x86 版本的 Linux，但它也适用于几种基于 ARM 的操作系统，以及其他处理器。甚至可以在单板计算机上运行 Docker，比如树莓派，用于面向硬件的物联网（IoT）项目。

Docker 生态系统包含许多工具，它们的数量正在迅速增加。对于我们的目的，我们将专注于以下两个工具：

+   **Docker 引擎**：这是协调一切的核心执行系统。它在 Linux 主机系统上运行，公开一个基于网络的 API，客户端应用程序使用它来进行 Docker 请求，比如构建、部署和运行容器。

+   **Docker Compose**：这有助于您在一个文件中定义一个多容器应用程序及其所有定义的依赖关系。

还有其他与 Docker 密切相关的工具，比如 Kubernetes，但一切都始于构建一个容器来容纳您的应用程序。通过学习 Docker，我们学会了如何将应用程序容器化，这是我们可以在 Docker 和 Kubernetes 中使用的技能。

学习如何使用 Docker 是学习其他流行系统的入门，比如 Kubernetes 或 AWS ECS。这两个是用于在云托管基础设施上大规模管理容器部署的流行编排系统。通常，容器是 Docker 容器，但它们是由其他系统部署和管理的，无论是 Kubernetes、ECS 还是 Mesos。这使得学习如何使用 Docker 成为学习这些其他系统的绝佳起点。

在本章中，我们将涵盖以下主题：

+   在我们的笔记本电脑上安装 Docker

+   开发我们自己的 Docker 容器并使用第三方容器

+   在 Docker 中设置用户认证服务及其数据库

+   在 Docker 中设置 Notes 服务及其数据库

+   在 Docker 中部署 MySQL 实例，并为 Docker 中的应用程序提供数据持久性，例如数据库

+   使用 Docker Compose 描述完整应用程序的 Docker 部署

+   在 Docker 基础设施中扩展容器实例并使用 Redis 来缓解扩展问题

第一项任务是复制上一章的源代码。建议您创建一个新目录`chap11`，作为`chap10`目录的兄弟目录，并将`chap10`中的所有内容复制到`chap11`中。

在本章结束时，您将对使用 Docker、创建 Docker 容器以及使用 Docker Compose 管理 Notes 应用程序所需的服务有扎实的基础。

借助 Docker，我们将在笔记本电脑上设计第十章中显示的系统，*将 Node.js 应用程序部署到 Linux 服务器*。这一章，以及第十二章，*使用 Terraform 在 AWS EC2 上部署 Docker Swarm*，形成了一个覆盖 Node.js 三种部署风格的弧线。

# 第十五章：在您的笔记本电脑或计算机上设置 Docker

学习如何在笔记本电脑上安装 Docker 的最佳地方是 Docker 文档。我们要找的是 Docker **Community Edition**（CE），这就是我们所需要的：

+   macOS 安装：[`docs.docker.com/docker-for-mac/install/`](https://docs.docker.com/docker-for-mac/install/)

+   Windows 安装：[`docs.docker.com/docker-for-windows/install/`](https://docs.docker.com/docker-for-windows/install/)

+   Ubuntu 安装：[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

还有其他几种发行版的安装说明。一些有用的 Linux 后安装说明可在[`docs.docker.com/install/linux/linux-postinstall/`](https://docs.docker.com/install/linux/linux-postinstall/)找到。

Docker 在 Linux 上本地运行，安装只是 Docker 守护程序和命令行工具。要在 macOS 或 Windows 上运行 Docker，您需要安装 Docker for Windows 或 Docker for Mac 应用程序。这些应用程序在轻量级虚拟机中管理一个虚拟 Linux 环境，在其中运行着一个在 Linux 上运行的 Docker Engine 实例。在过去（几年前），我们不得不手工设置这个环境。必须感谢 Docker 团队，他们使得这一切像安装应用程序一样简单，所有复杂性都被隐藏起来。结果非常轻量级，Docker 容器可以在后台运行而几乎不会产生影响。

现在让我们学习如何在 Windows 或 macOS 机器上安装 Docker。

## 使用 Docker for Windows 或 macOS 安装和启动 Docker

Docker 团队使得在 Windows 或 macOS 上安装 Docker 变得非常简单。您只需下载安装程序，并像大多数其他应用程序一样运行安装程序。它会负责安装并为您提供一个应用程序图标，用于启动 Docker。在 Linux 上，安装稍微复杂一些，因此最好阅读并遵循官方说明。

在 Windows 或 macOS 上启动 Docker 非常简单，一旦您遵循了安装说明。您只需找到并双击应用程序图标。有可用的设置，使得 Docker 在每次启动笔记本电脑时自动启动。

在 Docker for Windows 和 Docker for Mac 上，CPU 必须支持**虚拟化**。Docker for Windows 和 Docker for Mac 中内置了一个超轻量级的 hypervisor，而这又需要 CPU 的虚拟化支持。

对于 Windows，这可能需要 BIOS 配置。有关更多信息，请参阅[`docs.docker.com/docker-for-windows/troubleshoot/#virtualization-must-be-enabled`](https://docs.docker.com/docker-for-windows/troubleshoot/#virtualization-must-be-enabled)。

对于 macOS，这需要 2010 年或之后的硬件，具有英特尔对**内存管理单元**（**MMU**）虚拟化的硬件支持，包括**扩展页表**（**EPTs**）和无限制模式。您可以通过运行`sysctl kern.hv_support`来检查此支持。还需要 macOS 10.11 或更高版本。

安装完软件后，让我们尝试并熟悉 Docker。

## 熟悉 Docker

完成设置后，我们可以使用本地 Docker 实例创建 Docker 容器，运行一些命令，并且通常学习如何使用它。

就像许多软件之旅一样，这一切都始于“Hello World”：

```

The `docker run` command downloads a Docker image, named on the command line, initializes a Docker container from that image, and then runs that container. In this case, the image, named `hello-world`, was not present on the local computer and had to be downloaded and initialized. Once that was done, the `hello-world` container was executed and it printed out these instructions.

The `docker run hello-world` command is a quick way to verify that Docker is installed correctly.

Let's follow the suggestion and start an Ubuntu container:

```

“无法找到镜像”这个短语意味着 Docker 尚未下载命名的镜像。因此，它不仅下载了 Ubuntu 镜像，还下载了它所依赖的镜像。任何 Docker 镜像都可以分层构建，这意味着我们总是根据基础镜像定义镜像。在这种情况下，我们看到 Ubuntu 镜像总共需要四层。

镜像由 SHA-256 哈希标识，并且有长格式标识符和短格式标识符。我们可以在此输出中看到长标识符和短标识符。

`docker run`命令下载图像，配置其执行，并执行图像。`-it`标志表示在终端中交互式运行图像。

在`docker run`命令行中，图像名称后面要执行的部分作为命令选项传递到容器中以执行。在这种情况下，命令选项表示要运行`bash`，这是默认的命令 shell。事实上，我们得到了一个命令提示符，可以运行 Linux 命令。

您可以查询您的计算机，看到`hello-world`容器已经执行并完成，但它仍然存在：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/fc4a87f1-2ca6-44b6-aa62-a8b206cf9a98.png)

`docker ps`命令列出正在运行的 Docker 容器。正如我们在这里看到的，`hello-world`容器不再运行，但 Ubuntu 容器在运行。使用`-a`开关，`docker ps`还会显示那些存在但当前未运行的容器。

最后一列是容器名称。由于在启动容器时我们没有指定容器名称，Docker 为我们创建了一个半随机的名称。

使用容器后，您可以使用以下命令进行清理：

```

The `clever_napier` name is the container name automatically generated by Docker. While the image name was `hello-world`, that was not the container name. Docker generated the container name so that you have a more user-friendly identifier for the containers than the hex ID shown in the `CONTAINER ID` column:

```

也可以指定十六进制 ID。但是，相对于十六进制 ID，为容器指定一个名称当然更加用户友好。在创建容器时，可以轻松地指定任何您喜欢的容器名称。

我们已经在笔记本电脑或计算机上安装了 Docker，并尝试了一些简单的命令来熟悉 Docker。现在让我们开始一些工作。我们将首先在 Docker 容器中设置用户认证服务。

# 在 Docker 中设置用户认证服务

在我们的脑海中有这么多理论，现在是时候做一些实际的事情了。让我们首先设置用户认证服务。我们将称之为 AuthNet，并且它包括一个用于存储用户数据库的 MySQL 实例，认证服务器和一个私有子网来连接它们。

最好让每个容器专注于提供一个服务。每个容器提供一个服务是一个有用的架构决策，因为我们可以专注于为特定目的优化每个容器。另一个理由与扩展有关，因为每个服务有不同的要求来满足其提供的流量。在我们的情况下，根据流量负载，我们可能需要一个单独的 MySQL 实例和 10 个用户认证实例。

Docker Hub（[`hub.docker.com`](https://hub.docker.com)）上有大量预定义的 Docker 镜像库。最好重用其中一个镜像作为构建我们所需服务的起点。

Docker 环境不仅让我们定义和实例化 Docker 容器，还可以定义容器之间的网络连接。这就是我们之前所说的*私有子网*。通过 Docker，我们不仅可以管理容器，还可以配置子网、数据存储服务等等。

在接下来的几节中，我们将仔细地将用户认证服务基础架构 docker 化。我们将学习如何为 Docker 设置一个 MySQL 容器，并在 Docker 中启动一个 Node.js 服务。

让我们首先学习如何在 Docker 中启动一个 MySQL 容器。

## 在 Docker 中启动一个 MySQL 容器

在公开可用的 Docker 镜像中，有超过 11,000 个适用于 MySQL 的镜像。幸运的是，MySQL 团队提供的`mysql/mysql-server`镜像易于使用和配置，所以让我们使用它。

可以指定 Docker 镜像名称，以及通常是软件版本号的*标签*。在这种情况下，我们将使用`mysql/mysql-server:8.0`，其中`mysql/mysql-server`是镜像存储库 URL，`mysql-server`是镜像名称，`8.0`是标签。截至撰写本文时，MySQL 8.x 版本是当前版本。与许多项目一样，MySQL 项目使用版本号标记 Docker 镜像。

按照以下方式下载镜像：

```

The `docker pull` command retrieves an image from a Docker repository and is conceptually similar to the `git pull` command, which retrieves changes from a `git` repository.

This downloaded four image layers in total because this image is built on top of three other images. We'll see later how that works when we learn how to build a Dockerfile. 

We can query which images are stored on our laptop with the following command:

```

目前有两个可用的镜像——我们刚刚下载的`mysql-server`镜像和之前运行的`hello-world`镜像。

我们可以使用以下命令删除不需要的镜像：

```

Notice that the actual `delete` operation works with the SHA256 image identifier.

A container can be launched with the image, as follows:

```

`docker run`命令接受一个镜像名称，以及各种参数，并将其作为运行中的容器启动。

我们在前台启动了这项服务，当 MySQL 初始化其容器时，会有大量的输出。由于`--name`选项，容器的名称是`mysql`。通过环境变量，我们告诉容器初始化`root`密码。

既然我们有一个运行中的服务器，让我们使用 MySQL CLI 来确保它实际上正在运行。在另一个窗口中，我们可以在容器内运行 MySQL 客户端，如下所示：

```

The **`docker exec`** command lets you run programs inside the container. The `-it` option says the command is run interactively on an assigned terminal. In this case, we used the `mysql` command to run the MySQL client so that we could interact with the database. Substitute `bash` for `mysql`, and you will land in an interactive `bash` command shell.

This `mysql` command instance is running inside the container. The container is configured by default to not expose any external ports, and it has a default `my.cnf` file. 

Docker containers are meant to be ephemeral, created and destroyed as needed, while databases are meant to be permanent, with lifetimes sometimes measured in decades. A very important discussion on this point and how it applies to database containers is presented in the next section.

It is cool that we can easily install and launch a MySQL instance. However, there are several considerations to be made:

*   Access to the database from other software, specifically from another container
*   Storing the database files outside the container for a longer lifespan
*   Custom configuration, because database admins love to tweak the settings
*   We need a path to connect the MySQL container to the AuthNet network that we'll be creating

Before proceeding, let's clean up. In a terminal window, type the following:

```

这关闭并清理了我们创建的容器。重申之前提到的观点，容器中的数据库已经消失了。如果那个数据库包含重要信息，你刚刚丢失了它，没有机会恢复数据。

在继续之前，让我们讨论一下这对我们服务设计的影响。

## Docker 容器的短暂性

Docker 容器被设计为易于创建和销毁。在试验过程中，我们已经创建并销毁了三个容器。

在过去（几年前），设置数据库需要提供特别配置的硬件，雇佣具有特殊技能的数据库管理员，并仔细地为预期的工作负载进行优化。在短短几段文字中，我们已经实例化和销毁了三个数据库实例。这是多么崭新的世界啊！

在数据库和 Docker 容器方面，数据库相对是永恒的，而 Docker 容器是短暂的。数据库预计会持续数年，甚至数十年。在计算机年代，那几乎是不朽的。相比之下，一个被使用后立即丢弃的 Docker 容器只是与数据库预期寿命相比的短暂时间。

这些容器可以快速创建和销毁，这给了我们很大的灵活性。例如，编排系统，如 Kubernetes 或 AWS ECS，可以自动增加或减少容器的数量以匹配流量，重新启动崩溃的容器等等。

但是数据库容器中的数据存放在哪里？在前一节中运行的命令中，数据库数据目录位于容器内部。当容器被销毁时，数据目录也被销毁，我们数据库中的任何数据都被永久删除。显然，这与我们在数据库中存储的数据的生命周期要求不兼容。

幸运的是，Docker 允许我们将各种大容量存储服务附加到 Docker 容器。容器本身可能是短暂的，但我们可以将永久数据附加到短暂的容器。只需配置数据库容器，使数据目录位于正确的存储系统上。

足够的理论，现在让我们做点什么。具体来说，让我们为身份验证服务创建基础架构。

## 定义身份验证服务的 Docker 架构

Docker 支持在容器之间创建虚拟桥接网络。请记住，Docker 容器具有已安装的 Linux 操作系统的许多功能。每个容器都可以有自己的 IP 地址和公开的端口。Docker 支持创建类似虚拟以太网段的东西，称为**桥接网络**。这些网络仅存在于主机计算机中，并且默认情况下，外部计算机无法访问它们。

因此，Docker 桥接网络的访问受到严格限制。连接到桥接网络的任何 Docker 容器都可以与连接到该网络的其他容器进行通信，并且默认情况下，该网络不允许外部流量。容器通过主机名找到彼此，并且 Docker 包含一个嵌入式 DNS 服务器来设置所需的主机名。该 DNS 服务器配置为不需要域名中的点，这意味着每个容器的 DNS/主机名只是容器名称。我们将在后面发现，容器的主机名实际上是`container-name.network-name`，并且 DNS 配置允许您跳过使用`network-name`部分的主机名。使用主机名来标识容器的策略是 Docker 对服务发现的实现。

在`users`和`notes`目录的同级目录中创建名为`authnet`的目录。我们将在该目录中处理`authnet`。

在该目录中创建一个名为`package.json`的文件，我们将仅使用它来记录管理 AuthNet 的命令：

```

We'll be adding more scripts to this file. The `build-authnet` command builds a virtual network using the `bridge` driver, as we just discussed. The name for this network is `authnet`.

Having created `authnet`, we can attach containers to it so that the containers can communicate with one another.

Our goal for the Notes application stack is to use private networking between containers to implement a security firewall around the containers. The containers will be able to communicate with one another, but the private network is not reachable by any other software and is, therefore, more or less safe from intrusion.

Type the following command:

```

这将创建一个 Docker 桥接网络。长编码字符串是此网络的标识符。`docker network ls`命令列出当前 Docker 系统中的现有网络。除了短十六进制 ID 外，网络还具有我们指定的名称。

使用以下命令查看有关网络的详细信息：

```

At the moment, this won't show any containers attached to `authnet`. The output shows the network name, the IP range of this network, the default gateway, and other useful network configuration information. Since nothing is connected to the network, let's get started with building the required containers:

```

此命令允许我们从 Docker 系统中删除网络。但是，由于我们需要此网络，重新运行命令以重新创建它。

我们已经探讨了设置桥接网络，因此我们的下一步是用数据库服务器填充它。

## 为身份验证服务创建 MySQL 容器

现在我们有了一个网络，我们可以开始将容器连接到该网络。除了将 MySQL 容器连接到私有网络外，我们还将能够控制与数据库一起使用的用户名和密码，并且还将为其提供外部存储。这将纠正我们之前提到的问题。

要创建容器，可以运行以下命令：

```

This does several useful things all at once. It initializes an empty database configured with the named users and passwords, it mounts a host directory as the MySQL data directory, it attaches the new container to `authnet`, and it exposes the MySQL port to connections from outside the container.

The `docker run` command is only run the first time the container is started. It combines building the container by running it for the first time. With the MySQL container, its first run is when the database is initialized. The options that are passed to this `docker run` command are meant to tailor the database initialization.

The `--env` option sets environment variables inside the container. The scripts driving the MySQL container look to these environment variables to determine the user IDs, passwords, and database to create.

In this case, we configured a password for the `root` user, and we configured a second user—`userauth`—with a matching password and database name.

There are many more environment variables available.

The official MySQL Docker documentation provides more information on configuring a MySQL Docker container ([`dev.mysql.com/doc/refman/8.0/en/docker-mysql-more-topics.html`](https://dev.mysql.com/doc/refman/8.0/en/docker-mysql-more-topics.html)).

The MySQL server recognizes an additional set of environment variables ([`dev.mysql.com/doc/refman/8.0/en/environment-variables.html`](https://dev.mysql.com/doc/refman/8.0/en/environment-variables.html)).

The MySQL server recognizes a long list of configuration options that can be set on the command line or in the MySQL configuration file ([`dev.mysql.com/doc/refman/8.0/en/server-option-variable-reference.html`](https://dev.mysql.com/doc/refman/8.0/en/server-option-variable-reference.html)).

The `--network` option attaches the container to the `authnet` network.

The `-p` option exposes a TCP port from inside the container so that it is visible outside the container. By default, containers do not expose any TCP ports. This means we can be very selective about what to expose, limiting the attack surface for any miscreants seeking to gain illicit access to the container.

The `--mount` option is meant to replace the older `--volume` option. It is a powerful tool for attaching external data storage to a container. In this case, we are attaching a host directory, `userauth-data`, to the `/var/lib/mysql` directory inside the container. This ensures that the database is not inside the container, and that it will last beyond the lifetime of the container. For example, while creating this example, we deleted this container several times to fine-tune the command line, and it kept using the same data directory.

We should also mention that the `--mount` option requires the `src=` option be a full pathname to the file or directory that is mounted. We are using ``pwd`` to determine the full path to the file. However, this is, of course, specific to Unix-like OSes. If you are on Windows, the command should be run in PowerShell and you can use the `$PSScriptRoot` variable. Alternatively, you can hardcode an absolute pathname.

It is possible to inject a custom `my.cnf` file into the container by adding this option to the `docker run` command:

```

换句话说，Docker 不仅允许您挂载目录，还允许您挂载单个文件。

命令行遵循以下模式：

```

So far, we have talked about the options for the `docker run` command. Those options configure the characteristics of the container. Next on the command line is the image name—in this case, `mysql/mysql-server:8.0`. Any command-line tokens appearing after the image name are passed into the container. In this case, they are interpreted as arguments to the MySQL server, meaning we can configure this server using any of the extensive sets of command-line options it supports. While we can mount a `my.cnf` file in the container, it is possible to achieve most configuration settings this way.

The first of these options, `--bind_address`, tells the server to listen for connections from any IP address.

The second, `--socket=/tmp/mysql.sock`, serves two purposes. One is security, to ensure that the MySQL Unix domain socket is accessible only from inside the container. By default, the scripts inside the MySQL container put this socket in the `/var/lib/mysql` directory, and when we attach the data directory, the socket is suddenly visible from outside the container.

On Windows, if this socket is in `/var/lib/mysql`, when we attach a data directory to the container, that would put the socket in a Windows directory. Since Windows does not support Unix domain sockets, the MySQL container will mysteriously fail to start and give a misleadingly obtuse error message. The `--socket` option ensures that the socket is instead on a filesystem that supports Unix domain sockets, avoiding the possibility of this failure. 

When experimenting with different options, it is important to delete the mounted data directory each time you recreate the container to try a new setting. If the MySQL container sees a populated data directory, it skips over most of the container initialization scripts and will not run. A common mistake when trying different container MySQL configuration options is to rerun `docker run` without deleting the data directory. Since the MySQL initialization doesn't run, nothing will have changed and it won't be clear why the behavior isn't changing.

Therefore, to try a different set of MySQL options, execute the following command:

```

这将确保您每次都从新数据库开始，并确保容器初始化运行。

这也暗示了一个行政模式要遵循。每当您希望更新到较新的 MySQL 版本时，只需停止容器，保留数据目录。然后，删除容器，并使用新的`mysql/mysql-server`标签重新执行`docker run`命令。这将导致 Docker 使用不同的镜像重新创建容器，但使用相同的数据目录。使用这种技术，您可以通过拉取更新的镜像来更新 MySQL 版本。

一旦 MySQL 容器运行，输入以下命令：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/f8b581a3-5b69-4a4c-9725-32697e2a774b.png)

这将显示当前容器状态。如果我们使用`docker ps -a`，我们会看到`PORTS`列显示`0.0.0.0:3306->3306/tcp, 33060/tcp`。这表示容器正在监听从任何地方（`0.0.0.0`）到端口`3306`的访问，这个流量将连接到容器内部的端口`3306`。此外，还有一个端口`33060`可用，但它没有暴露到容器外部。

尽管它配置为监听整个世界，但容器附加到`authnet`，限制了连接的来源。限制可以连接到数据库的进程的范围是一件好事。但是，由于我们使用了`-p`选项，数据库端口暴露给了主机，这并不像我们想要的那样安全。我们稍后会修复这个问题。

### 数据库容器中的安全性

一个要问的问题是是否像这样设置`root`密码是一个好主意。`root`用户对整个 MySQL 服务器有广泛的访问权限，而其他用户，如`userauth`，对给定数据库的访问权限有限。由于我们的目标之一是安全性，我们必须考虑这是否创建了一个安全或不安全的数据库容器。

我们可以使用以下命令以`root`用户身份登录：

```

This executes the MySQL CLI client inside the newly created container. There are a few commands we can run to check the status of the `root` and `userauth` user IDs. These include the following:

```

连接到 MySQL 服务器包括用户 ID、密码和连接的来源。这个连接可能来自同一台计算机内部，也可能来自另一台计算机的 TCP/IP 套接字。为了批准连接，服务器会在`mysql.user`表中查找与`user`、`host`（连接来源）和`password`字段匹配的行。用户名和密码是作为简单的字符串比较进行匹配的，但主机值是一个更复杂的比较。与 MySQL 服务器的本地连接将与主机值为`localhost`的行匹配。

对于远程连接，MySQL 会将连接的 IP 地址和域名与`host`列中的条目进行比较。`host`列可以包含 IP 地址、主机名或通配符模式。SQL 的通配符字符是`%`。单个`%`字符匹配任何连接源，而`172.%`的模式匹配第一个 IPv4 八位是`172`的任何 IP 地址，或者`172.20.%.%`匹配`172.20.x.x`范围内的任何 IP 地址。

因此，由于`userauth`的唯一行指定了`%`的主机值，我们可以从任何地方使用`userauth`。相比之下，`root`用户只能在`localhost`连接中使用。

下一个任务是检查`userauth`和`root`用户 ID 的访问权限：

```

This says that the `userauth` user has full access to the `userauth` database. The `root` user, on the other hand, has full access to every database and has so many permissions that the output of that does not fit here. Fortunately, the `root` user is only allowed to connect from `localhost`.

To verify this, try connecting from different locations using these commands:

```

我们展示了访问数据库的四种模式，表明`userauth` ID 确实可以从同一容器或远程容器访问，而`root` ID 只能从本地容器使用。

使用`docker run --it --rm ... container-name ..`启动一个容器，运行与容器相关的命令，然后在完成后退出容器并自动删除它。

因此，通过这两个命令，我们创建了一个单独的`mysql/mysql-server:8.0`容器，连接到`authnet`，以运行`mysql`CLI 程序。`mysql`参数是使用给定的用户名（`root`或`userauth`）连接到名为`db-userauth`的主机上的 MySQL 服务器。这演示了从一个独立的连接器连接到数据库，并显示我们可以使用`userauth`用户远程连接，但不能使用`root`用户。

然后，最终的访问实验涉及省略`--network`选项：

```

This demonstrates that if the container is not attached to `authnet`, it cannot access the MySQL server because the `db-userauth` hostname is not even known.

Where did the `db-userauth` hostname come from? We can find out by inspecting a few things:

```

换句话说，`authnet`网络具有`172.20.0.0/16`网络号，而`db-userauth`容器被分配了`172.20.0.2`IP 地址。这种细节很少重要，但在第一次仔细检查设置时是有用的，这样我们就能理解我们正在处理的内容。

存在一个严重的安全问题，违反了我们的设计。即，数据库端口对主机是可见的，因此，任何可以访问主机的人都可以访问数据库。这是因为我们在错误的认为下使用了`-p 3306:3306`，以为这是必需的，这样`svc-userauth`才能在下一节中访问数据库。我们将通过删除该选项来解决这个问题。

现在我们已经为认证服务设置了数据库实例，让我们看看如何将其 Docker 化。

## Docker 化认证服务

*Dockerize*一词意味着为软件创建一个 Docker 镜像。然后可以与他人共享 Docker 镜像，或部署到服务器上。在我们的情况下，目标是为用户认证服务创建一个 Docker 镜像。它必须连接到`authnet`，以便可以访问我们刚刚在`db-userauth`容器中配置的数据库服务器。

我们将命名这个新容器为`svc-userauth`，以表示这是用户认证 REST 服务，而`db-userauth`容器是数据库。

Docker 镜像是使用 Dockerfile 定义的，Dockerfile 是描述在服务器上安装应用程序的文件。它们记录了 Linux 操作系统的设置，安装的软件以及 Docker 镜像中所需的配置。这实际上是一个名为`Dockerfile`的文件，其中包含 Dockerfile 命令。Dockerfile 命令用于描述镜像的构建方式。

请参考[`docs.docker.com/engine/reference/builder/`](https://docs.docker.com/engine/reference/builder/)获取文档。

### 创建认证服务 Dockerfile

在`users`目录中，创建一个名为`Dockerfile`的文件，其中包含以下内容：

```

The `FROM` command specifies a pre-existing image, called the base image, from which to derive a given image. Frequently, you define a Docker image by starting from an existing image. In this case, we're using the official Node.js Docker image ([`hub.docker.com/_/node/`](https://hub.docker.com/_/node/)), which, in turn, is derived from `debian`.

Because the base image, `node`, is derived from the `debian` image, the commands available are what are provided on a Debian OS. Therefore, we use `apt-get` to install more packages. 

The `RUN` commands are where we run the shell commands required to build the container. The first one installs required Debian packages, such as the `build-essential` package, which brings in compilers required to install native-code Node.js packages.

It's recommended that you always combine `apt-get update`, `apt-get upgrade`, and `apt-get install` in the same command line like this because of the Docker build cache. Docker saves each step of the build to avoid rerunning steps unnecessarily. When rebuilding an image, Docker starts with the first changed step. Therefore, in the set of Debian packages to install changes, we want all three of those commands to run.

Combining them into a single command ensures that this will occur. For a complete discussion, refer to the documentation at [`docs.docker.com/develop/develop-images/dockerfile_best-practices/`](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/).

The `ENV` commands define environment variables. In this case, we're using the same environment variables that were defined in the `package.json` script for launching the user authentication service.

Next, we have a sequence of lines to create the `/userauth` directory and to populate it with the source code of the user authentication service. The first line creates the `/userauth` directory. The `COPY` command, as its name implies, copies the files for the authentication service into that directory. The `WORKDIR` command changes the working directory to `/userauth`. This means that the last `RUN` command, `npm install`, is executed in `/userauth`, and therefore, it installs the packages described in `/userauth/package.json` in `/userauth/node_modules`.

There is a new `SEQUELIZE_CONNECT` configuration file mentioned: `sequelize-docker-mysql.yaml`. This will describe the Sequelize configuration required to connect to the database in the `db-userauth` container.

Create a new file named `users/sequelize-docker-mysql.yaml` containing the following:

```

不同之处在于，我们使用`db-userauth`而不是`localhost`作为数据库主机。之前，我们探索了`db-userauth`容器，并确定这是容器的主机名。通过在这个文件中使用`db-userauth`，认证服务将使用容器中的数据库。

`EXPOSE`命令通知 Docker 容器监听指定的 TCP 端口。这不会将端口暴露到容器之外。`-p`标志是将给定端口暴露到容器之外的方式。

最后，`CMD`命令记录了在执行容器时启动的过程。`RUN`命令在构建容器时执行，而`CMD`表示容器启动时执行的内容。

我们本可以在容器中安装`PM2`，然后使用`PM2`命令来启动服务。然而，Docker 能够实现相同的功能，因为它自动支持在服务进程死掉时重新启动容器。

### 构建和运行认证服务 Docker 容器

现在我们已经在 Dockerfile 中定义了镜像，让我们来构建它。

在`users/package.json`中，将以下行添加到`scripts`部分：

```

As has been our habit, this is an administrative task that we can record in `package.json`, making it easier to automate this task.

We can build the authentication service as follows:

```

`docker build`命令从 Dockerfile 构建一个镜像。请注意，构建一步一步进行，每个步骤都与 Dockerfile 中的命令完全对应。

每个步骤都存储在缓存中，因此不必重新运行。在后续构建中，执行的唯一步骤是更改的步骤和所有后续步骤。

在`authnet/package.json`中，我们需要相当多的脚本来管理用户认证服务：

```

This is the set of commands that were found to be useful to manage building the images, starting the containers, and stopping the containers.

Look carefully and you will see that we've added `--detach` to the `docker run` commands. So far, we've used `docker run` without that option, and the container remained in the foreground. While this was useful to see the logging output, it's not so useful for deployment. With the `--detach` option, the container becomes a background task.

On Windows, for the -`-mount` option, we need to change the `src= parameter` (as discussed earlier) to use a Windows-style hard-coded path. That means it should read:

```

此选项需要绝对路径名，并且以这种方式指定路径在 Windows 上有效。

另一个需要注意的是`-p 3306:3306`选项的缺失。有两个原因确定这是不必要的。首先，该选项将数据库暴露给主机，`db-userauth`的安全模型要求不这样，因此删除该选项可以获得所需的安全性。其次，`svc-userauth`在删除此选项后仍然能够访问`db-userauth`数据库。

有了这些命令，我们现在可以输入以下内容来构建，然后运行容器：

```

These commands build the pieces required for the user authentication service. As a side effect, the containers are automatically executed and will launch as background tasks.

Once it is running, you can test it using the `cli.mjs` script as before. You can shell into the `svc-userauth` container and run `cli.mjs` there; or, since the port is visible to the host computer, you can run it from outside the container.

Afterward, we can manage the whole service as follows:

```

这将停止并启动构成用户认证服务的两个容器。

我们已经创建了托管用户认证服务的基础设施，以及一系列脚本来管理该服务。我们的下一步是探索我们创建的内容，并了解 Docker 为我们创建的基础设施的一些情况。

## 探索 AuthNet

请记住，AuthNet 是认证服务的连接介质。为了了解这个网络是否提供了我们正在寻找的安全性增益，让我们探索一下我们刚刚创建的内容：

```

This prints out a large JSON object describing the network, along with its attached containers, which we've looked at before. If everything went well, we will see that there are now two containers attached to `authnet` where there'd previously have just been one.

Let's go into the `svc-userauth` container and poke around:

```

`/userauth`目录位于容器内，包含使用`COPY`命令放置在容器中的文件，以及`node_modules`中安装的文件：

```

We can run the `cli.mjs` script to test and administer the service. To get these database entries set up, use the `add` command with the appropriate options:

```

进程列表是值得研究的。进程`PID 1`是 Dockerfile 中的`node ./user-server.mjs`命令。我们在`CMD`行中使用的格式确保`node`进程最终成为进程 1。这很重要，以便正确处理进程信号，从而允许 Docker 正确管理服务进程。以下博客文章的末尾有关于这个问题的很好讨论：

[`www.docker.com/blog/keep-nodejs-rockin-in-docker/`](https://www.docker.com/blog/keep-nodejs-rockin-in-docker/)

`ping`命令证明两个容器作为与容器名称匹配的主机名可用：

```

From outside the containers, on the host system, we cannot ping the containers. That's because they are attached to `authnet` and are not reachable.

We have successfully Dockerized the user authentication service in two containers—`db-userauth` and `svc-userauth`. We've poked around the insides of a running container and found some interesting things. However, our users need the fantastic Notes application to be running, and we can't afford to rest on our laurels.

Since this was our first time setting up a Docker service, we went through a lot of details. We started by launching a MySQL database container, and what is required to ensure that the data directory is persistent. We then set up a Dockerfile for the authentication service and learned how to connect containers to a common Docker network and how containers can communicate with each other over the network. We also studied the security benefits of this network infrastructure, since we can easily wall off the service and its database from intrusion.

Let's now move on and Dockerize the Notes application, making sure that it is connected to the authentication server.

# Creating FrontNet for the Notes application

We have the back half of our system set up in Docker containers, as well as the private bridge network to connect the backend containers. It's now time to do the same for the front half of the system: the Notes application (`svc-notes`) and its associated database (`db-notes`). Fortunately, the tasks required to build FrontNet are more or less the same as what we did for AuthNet.

The first task is to set up another private bridge network, `frontnet`. Like `authnet`, this will be the infrastructure for the front half of the Notes application stack.

Create a directory, `frontnet`, and in that directory, create a `package.json` file that will contain the scripts to manage `frontnet`: 

```

与`authnet`一样，这只是起点，因为我们还有几个脚本要添加。

让我们继续创建`frontnet`桥接网络：

```

We have two virtual bridge networks. Over the next few sections, we'll set up the database and Notes application containers, connect them to `frontnet`, and then see how to manage everything.

## MySQL container for the Notes application

As with `authnet`, the task is to construct a MySQL server container using the `mysql/mysql-server` image. We must configure the server to be compatible with the `SEQUELIZE_CONNECT` file that we'll use in the `svc-notes` container. For that purpose, we'll use a database named `notes` and a `notes` user ID.

For that purpose, add the following to the `scripts` section of the `package.json` file:

```

这与`db-userauth`几乎相同，只是将`notes`替换为`userauth`。请记住，在 Windows 上，`-mount`选项需要 Windows 风格的绝对路径名。

现在让我们运行脚本： 

```

This database will be available in the `db-notes` domain name on `frontnet`. Because it's attached to `frontnet`, it won't be reachable by containers connected to `authnet`. To verify this, run the following command:

```

由于`db-notes`位于不同的网络段，我们已经实现了隔离。但我们可以注意到一些有趣的事情。`ping`命令告诉我们，`db-userauth`的完整域名是`db-userauth.authnet`。因此，可以推断`db-notes`也被称为`db-notes.frontnet`。但无论如何，我们无法从`authnet`上的容器访问`frontnet`上的容器，因此我们已经实现了所需的隔离。

我们能够更快地移动以构建 FrontNet，因为它非常类似于 AuthNet。我们只需要做以前做过的事情，并微调名称。

在本节中，我们创建了一个数据库容器。在下一节中，我们将为 Notes 应用程序创建 Dockerfile。

## Docker 化 Notes 应用程序

我们的下一步当然是将 Notes 应用程序 Docker 化。这始于创建一个 Dockerfile，然后添加另一个 Sequelize 配置文件，最后通过向`frontnet/package.json`文件添加更多脚本来完成。

在`notes`目录中，创建一个名为`Dockerfile`的文件，其中包含以下内容：

```

This is similar to the Dockerfile we used for the authentication service. We're using the environment variables from `notes/package.json`, plus a new one: `NOTES_SESSION_DIR`.

The most obvious change is the number of `COPY` commands. The Notes application is a lot more involved, given the number of sub-directories full of files that must be installed. We start by creating the top-level directories of the Notes application deployment tree. Then, one by one, we copy each sub-directory into its corresponding sub-directory in the container filesystem.

In a `COPY` command, the trailing slash on the destination directory is important. Why? Because the Docker documentation says that the trailing slash is important, that's why.

The big question is *why use multiple *`COPY`* commands like this*? This would have been incredibly simple:

```

然而，多个`COPY`命令让我们可以精确控制复制的内容。避免复制`node_modules`目录是最重要的。不仅是主机上的`node_modules`文件很大，如果复制到容器中会使容器膨胀，而且它是为主机操作系统而不是容器操作系统设置的。`node_modules`目录必须在容器内部构建，安装过程发生在容器的操作系统上。这个约束导致选择明确地将特定文件复制到目标位置。

我们还有一个新的`SEQUELIZE_CONNECT`文件。创建`models/sequelize-docker-mysql.yaml`，其中包含以下内容：

```

This will access a database server on the `db-notes` domain name using the named database, username, and password. 

Notice that the `USER_SERVICE_URL` variable no longer accesses the authentication service at `localhost`, but at `svc-userauth`. The `svc-userauth` domain name is currently only advertised by the DNS server on AuthNet, but the Notes service is on FrontNet. Therefore, this will cause a failure for us when we get to running the Notes application, and we'll have to make some connections so that the `svc-userauth` container can be accessed from `svc-notes`.

In Chapter 8*,* *Authenticating Users with a Microservice*, we discussed the need to protect the API keys supplied by Twitter. We could copy the `.env` file to the Dockerfile, but this may not be the best choice, and so we've left it out of the Dockerfile.

Unfortunately, this does not protect the Twitter credentials to the level required. The `.env` file is available as plaintext inside the container. Docker has a feature, Docker Secrets, that can be used to securely store data of this sort. Unfortunately, it is only available when using Swarm mode, which we are not doing at this time; but we will use this feature in Chapter 12, *Deploying a Docker Swarm to AWS EC2 Using Terraform*.

The value of `TWITTER_CALLBACK_HOST` needs to reflect where Notes is deployed. Right now, it is still on your laptop, but if it is deployed to a server, this variable will require the IP address or domain name of the server.

In `notes/package.json`, add the following `scripts` entry:

```

与身份验证服务器一样，这使我们能够为 Notes 应用程序服务构建容器镜像。

然后，在`frontnet/package.json`中添加这些脚本：

```

Now, we can build the container image:

```

这将创建容器镜像，然后启动容器。

注意，暴露的端口`3000`与`-p 80:3000`映射到正常的 HTTP 端口。由于我们准备在真实服务上部署，我们可以停止使用端口`3000`。

此时，我们可以将浏览器连接到`http://localhost`并开始使用 Notes 应用程序。但是，我们很快就会遇到一个问题：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/11e5e001-7757-4392-9277-62ce82f78a64.png)

用户体验团队将对这个丑陋的错误消息大声疾呼，所以把它放在您的待办事项中，生成一个更漂亮的错误屏幕。例如，一群鸟将鲸鱼从海洋中拉出是很受欢迎的。

这个错误意味着 Notes 无法访问名为`svc-userauth`的主机上的任何内容。该主机确实存在，因为容器正在运行，但它不在`frontnet`上，并且无法从`notes`容器中访问。相反，它在`authnet`上，目前无法被`svc-notes`访问：

```

We can reach `db-notes` from `svc-notes` but not `svc-userauth`. This is as expected since we have attached these containers to different networks.

If you inspect FrontNet and AuthNet, you'll see that the containers attached to each do not overlap:

```

在第十章中呈现的架构图中，*将 Node.js 应用程序部署到 Linux 服务器*，我们展示了`svc-notes`和`svc-userauth`容器之间的连接。这种连接是必需的，以便 Notes 可以对其用户进行身份验证。但是这种连接尚不存在。

Docker 要求您采取第二步将容器连接到第二个网络：

```

With no other change, the Notes application will now allow you to log in and start adding and editing notes. Furthermore, start a shell in `svc-notes` and you'll be able to ping both `svc-userauth` and `db-userauth`.

There is a glaring architecture question staring at us. Do we connect the `svc-userauth` service to `frontnet`, or do we connect the `svc-notes` service to `authnet`? We just connected `svc-notes` to `authnet`, but maybe that's not the best choice. To verify which network setup solves the problem, run the following commands:

```

第一次，我们将`svc-notes`连接到`authnet`，然后将其从`authnet`断开连接，然后将`svc-userauth`连接到`frontnet`。这意味着我们尝试了两种组合，并且如预期的那样，在这两种情况下，`svc-notes`和`svc-userauth`都能够通信。

这是一个安全专家的问题，因为考虑到任何入侵者可用的攻击向量。假设 Notes 存在安全漏洞，允许入侵者访问。我们如何限制通过该漏洞可达到的内容？

主要观察是通过将`svc-notes`连接到`authnet`，`svc-notes`不仅可以访问`svc-userauth`，还可以访问`db-userauth`。要查看这一点，请运行以下命令：

```

This sequence reconnects `svc-notes` to `authnet` and demonstrates the ability to access both the `svc-userauth` and `db-userauth` containers. Therefore, a successful invader could access the `db-userauth` database, a result we wanted to prevent. Our diagram in Chapter 10, *Deploying Node.js Applications to Linux Servers,* showed no such connection between `svc-notes` and `db-userauth`.

Given that our goal for using Docker was to limit the attack vectors, we have a clear distinction between the two container/network connection setups. Attaching `svc-userauth` to `frontnet` limits the number of containers that can access `db-userauth`. For an intruder to access the user information database, they must first break into `svc-notes`, and then break into `svc-userauth`; unless, that is, our amateur attempt at a security audit is flawed.

For this and a number of other reasons, we arrive at this final set of scripts for `frontnet/package.json`:

```

主要是添加一个命令`connect-userauth`，将`svc-userauth`连接到`frontnet`。这有助于我们记住如何加入容器的决定。我们还借此机会进行了一些重新组织。

在本节中，我们学到了很多关于 Docker 的知识——使用 Docker 镜像，从镜像创建 Docker 容器，并在考虑一些安全约束的情况下配置一组 Docker 容器。我们在本节中实现了我们最初的架构想法。我们有两个私有网络，容器连接到它们适当的网络。唯一暴露的 TCP 端口是 Notes 应用程序，可在端口`80`上看到。其他容器使用不可从容器外部访问的 TCP/IP 连接相互连接。

在继续下一部分之前，您可能希望关闭我们启动的服务。只需执行以下命令：

```

Because we've automated many things, it is this simple to administer the system. However, it is not as automated as we want it to be. To address that, let's learn how to make the Notes stack more easily deployable by using Docker Compose to describe the infrastructure.

# Managing multiple containers with Docker Compose

It is cool that we can create encapsulated instantiations of the software services that we've created. In theory, we can publish these images to Docker repositories, and then launch the containers on any server we want. For example, our task in Chapter 10, *Deploying Node.js Applications to Linux Servers*, would be greatly simplified with Docker. We could simply install Docker Engine on the Linux host and then deploy our containers on that server, and not have to deal with all those scripts and the PM2 application.

But we haven't properly automated the process. The promise was to use the Dockerized application for deployment on cloud services. In other words, we need to take all this learning and apply it to the task of simplifying deployment.

We've demonstrated that, with Docker, Notes can be built using four containers that have a high degree of isolation from each other and from the outside world. 

There is a glaring problem: our process in the previous section was partly manual, partly automated. We created scripts to launch each portion of the system, which is good practice. However, we did not automate the entire process to bring up Notes and the authentication services, nor is this solution scalable beyond one machine.

Let's start with the last issue first—scalability. Within the Docker ecosystem, several **Docker orchestrator** services are available. An orchestrator automatically deploys and manages Docker containers over a group of machines. Some examples of Docker orchestrators are Docker Swarm, Kubernetes, CoreOS Fleet, and Apache Mesos. These are powerful systems that can automatically increase/decrease resources as needed to move containers from one host to another, and more. We mention these systems for you to further study as your needs grow. In Chapter 12, *Deploying a Docker Swarm to AWS EC2 with Terraform*, we will build on the work we're about to do in order to deploy Notes in a Docker Swarm cluster that we'll build on AWS EC2 infrastructure.

Docker Compose ([`docs.docker.com/compose/overview/`](https://docs.docker.com/compose/overview/)) will solve the other problems we've identified. It lets us easily define and run several Docker containers together as a complete application. It uses a YAML file, `docker-compose.yml`, to describe the containers, their dependencies, the virtual networks, and the volumes. While we'll be using it to describe deployment on a single host machine, Docker Compose can be used for multi-machine deployments. Namely, Docker Swarm directly uses compose files to describe the services you launch in a swarm. In any case, learning about Docker Compose will give you a headstart on understanding the other systems.

Before proceeding, ensure that Docker Compose is installed. If you've installed Docker for Windows or Docker for Mac, everything that is required is installed. On Linux, you must install it separately by following the instructions in the links provided earlier.

## Docker Compose file for the Notes stack

We just talked about Docker orchestration services, but Docker Compose is not itself such a service. Instead, Docker Compose uses a specific YAML file structure to describe how to deploy Docker containers. With a Docker Compose file, we can describe one or more containers, networks, and volumes involved in launching a Docker-based service.

Let's start by creating a directory, `compose-local`, as a sibling to the `users` and `notes` directories. In that directory, create a file named `docker-compose.yml`:

```

这是整个 Notes 部署的描述。它在相当高的抽象级别上，大致相当于我们迄今为止使用的命令行工具中的选项。它相当简洁和自解释，正如我们将看到的，`docker-compose`命令使这些文件成为管理 Docker 服务的便利方式。

`version`行表示这是一个版本 3 的 Compose 文件。版本号由`docker-compose`命令检查，以便它可以正确解释其内容。完整的文档值得阅读，网址是[`docs.docker.com/compose/compose-file/`](https://docs.docker.com/compose/compose-file/)。

这里使用了三个主要部分：`services`、`volumes`和`networks`。`services`部分描述了正在使用的容器，`networks`部分描述了网络，`volumes`部分描述了卷。每个部分的内容都与我们之前创建的容器相匹配。我们已经处理过的配置都在这里，只是重新排列了一下。

有两个数据库容器——`db-userauth`和`db-notes`——以及两个服务容器——`svc-userauth`和`svc-notes`。服务容器是从`build`属性中指定的目录中的 Dockerfile 构建的。数据库容器是从 Docker Hub 下载的镜像实例化的。两者都直接对应于我们之前所做的，使用`docker run`命令创建数据库容器，并使用`docker build`生成服务的镜像。

`container_name`属性等同于`--name`属性，并为容器指定了一个用户友好的名称。我们必须指定容器名称，以便指定容器主机名以实现 Docker 风格的服务发现。

`networks`属性列出了此容器必须连接的网络，与`--net`参数完全相同。即使`docker`命令不支持多个`--net`选项，我们可以在 Compose 文件中列出多个网络。在这种情况下，网络是桥接网络。与之前一样，网络本身必须单独创建，在 Compose 文件中，这是在`networks`部分完成的。

`ports`属性声明要发布的端口及其与容器端口的映射。在`ports`声明中，有两个端口号，第一个是要发布的端口号，第二个是容器内部的端口号。这与之前使用的`-p`选项完全相同。

`depends_on`属性允许我们控制启动顺序。依赖于另一个容器的容器将等待直到被依赖的容器正在运行。

`volumes`属性描述了容器目录到`host`目录的映射。在这种情况下，我们定义了两个卷名称——`db-userauth-data`和`db-notes-data`——然后将它们用于卷映射。但是，当我们部署到 AWS EC2 上的 Docker Swarm 时，我们需要改变这个实现方式。

请注意，我们没有为卷定义主机目录。Docker 会为我们分配一个目录，我们可以使用`docker volume inspect`命令了解这个目录。

`restart`属性控制容器死亡时或者何时发生的情况。当容器启动时，它运行`CMD`指令中指定的程序，当该程序退出时，容器也退出。但是，如果该程序是要永远运行的，Docker 不应该知道它应该重新启动该进程吗？我们可以使用后台进程监视器，如 Supervisord 或 PM2。但是，Docker 的`restart`选项会处理这个问题。

`restart`属性可以取以下四个值之一：

+   `no`: 不重新启动。

+   `on-failure:count`: 最多重新启动*N*次。

+   `always`: 总是重新启动。

+   `unless-stopped`: 除非明确停止，否则启动容器。

在本节中，我们学习了如何通过创建描述 Notes 应用程序堆栈的文件来构建 Docker Compose 文件。有了这个，让我们看看如何使用这个工具来启动容器。

## 使用 Docker Compose 构建和运行 Notes 应用程序

使用 Docker Compose CLI 工具，我们可以管理任何可以在`docker-compose.yml`文件中描述的 Docker 容器集。我们可以构建容器，启动和关闭它们，查看日志等。在 Windows 上，我们可以无需更改地运行本节中的命令。

我们的第一个任务是通过运行以下命令来创建一个干净的状态：

```

We first needed to stop and delete any existing containers left over from our previous work. We can also use the scripts in the `frontnet` and `authnet` directories to do this. `docker-compose.yml` used the same container names, so we need the ability to launch new containers with those names.

To get started, use this command:

```

这将构建`docker-compose.yml`中列出的镜像。请注意，我们最终得到的镜像名称都以`compose-local`开头，这是包含该文件的目录的名称。因为这相当于在每个目录中运行`docker build`，它只构建镜像。

构建了容器之后，我们可以使用`docker-compose up`或`docker-compose start`一次性启动它们所有：

```

We can use `docker-compose stop` to shut down the containers. With `docker-compose start`, the containers run in the background.

We can also run `docker-compose up` to get a different experience:

```

如果需要，`docker-compose up`将首先构建容器。此外，它将保持所有容器在前台运行，以便我们可以查看日志。它将所有容器的日志输出合并在一起，每行开头显示容器名称。对于像 Notes 这样的多容器系统，这非常有帮助。

我们可以使用此命令检查状态：

```

This is related to running `docker ps`, but the presentation is a little different and more compact.

In `docker-compose.yml`, we insert the following declaration for `svc-userauth`:

```

这意味着`svc-userauth`的 REST 服务端口已经发布。确实，在状态输出中，我们看到端口已经发布。这违反了我们的安全设计，但它确实让我们可以从笔记本电脑上使用`users/cli.mjs`运行测试。也就是说，我们可以像以前那样向数据库添加用户。

只要它保持在我们的笔记本电脑上，这种安全违规是可以接受的。`compose-local`目录的命名是专门用于在我们的笔记本电脑上与 Docker Compose 一起使用的。

或者，我们可以像以前一样在`svc-userauth`容器内运行命令：

```

We started the Docker containers using `docker-compose`, and we can use the `docker-compose` command to interact with the containers. In this case, we demonstrated using both the `docker-compose` and `docker` commands to execute a command inside one of the containers. While there are slight differences in the command syntax, it's the same interaction with the same results.

Another test is to go into the containers and explore:

```

从那里，我们可以尝试 ping 每个容器，以查看哪些容器可以被访问。这将作为一个简单的安全审计，以确保我们创建的内容符合我们期望的安全模型。

在执行此操作时，我们发现`svc-userauth`可以 ping 通每个容器，包括`db-notes`。这违反了安全计划，必须更改。

幸运的是，这很容易解决。只需通过更改配置，我们可以在`docker-compose.yml`中添加一个名为`svcnet`的新网络：

```

`svc-userauth` is no longer connected to `frontnet`, which is how we could ping `db-notes` from `svc-userauth`. Instead, `svc-userauth` and `svc-notes` are both connected to a new network, `svcnet`, which is meant to connect the service containers. Therefore, both service containers have exactly the required access to match the goals outlined at the beginning.

That's an advantage of Docker Compose. We can quickly reconfigure the system without rewriting anything other than the `docker-compose.yml` configuration file. Furthermore, the new configuration is instantly reflected in a file that can be committed to our source repository.

When you're done testing the system, simply type *CTRL* +* C* in the terminal:

```

如图所示，这将停止整组容器。偶尔，它会退出用户到 shell，并且容器仍然在运行。在这种情况下，用户将不得不使用其他方法来关闭容器：

```

The `docker-compose` commands—`start`, `stop`*,* and `restart`—all serve as ways to manage the containers as background tasks. The default mode for the `docker-compose up` command is, as we've seen, to start the containers in the foreground. However, we can also run `docker-compose up` with the `-d` option, which says to detach the containers from the terminal to run in the background.

We're getting closer to our end goal. In this section, we learned how to take the Docker containers we've designed and create a system that can be easily brought up and down as a unit by running the `docker-compose` command.

While preparing to deploy this to Docker Swarm on AWS EC2, a horizontal scaling issue was found, which we can fix on our laptop. It is fairly easy with Docker Compose files to test multiple `svc-notes` instances to see whether we can scale Notes for higher traffic loads. Let's take a look at that before deploying to the swarm.

# Using Redis for scaling the Notes application stack

In the previous section, we learned how to use Docker Compose to manage the Notes application stack. Looking ahead, we can see the potential need to use multiple instances of the Notes container when we deploy to Docker Swarm on AWS EC2\. In this section, we will make a small modification to the Docker Compose file for an ad hoc test with multiple Notes containers. This test will show us a couple of problems. Among the available solutions are two packages that fix both problems by installing a Redis instance.

A common tactic for handling high traffic loads is to deploy multiple service instances as needed. This is called horizontal scaling, where we deploy multiple instances of a service to multiple servers. What we'll do in this section is learn a little about horizontal scaling in Docker by starting two Notes instances to see how it behaves.

As it currently exists, Notes stores some data—the session data—on the local disk space. As orchestrators such as Docker Swarm, ECS, and Kubernetes scale containers up and down, containers are constantly created and destroyed or moved from one host to another. This is done in the name of handling the traffic while optimizing the load on the available servers. In this case, whatever active data we're storing on a local disk will be lost. Losing the session data means users will be randomly logged out. The users will be rightfully upset and will then send us support requests asking what's wrong and whether we have even tested this thing!

In this section, we will learn that Notes does not behave well when we have multiple instances of `svc-notes`. To address this problem, we will add a Redis container to the Docker Compose setup and configure Notes to use Redis to solve the two problems that we have discovered. This will ensure that the session data is shared between multiple Notes instances via a Redis server.

Let's get started by performing a little ad hoc testing to better understand the problem.

## Testing session management with multiple Notes service instances

We can easily verify whether Notes properly handles session data if there are multiple `svc-notes` instances. With a small modification to `compose-local/docker-compose.yml`, we can start two `svc-notes` instances, or more. They'll be on separate TCP ports, but it will let us see how Notes behaves with multiple instances of the Notes service.

Create a new service, `svc-notes-2`, by duplicating the `svc-notes` declaration. The only thing to change is the container name, which should be `svc-notes-2`, and the published port, which should be port `3020`.

For example, add the following to `compose-local/docker-compose.yml`:

```

这是我们刚刚描述的`svc-notes-2`容器的服务定义。因为我们设置了`PORT`变量，所以容器将在端口`3020`上监听，这也是在`ports`属性中宣传的端口。

与以前一样，当我们快速重新配置网络配置时，注意到只需对 Docker Compose 文件进行简单编辑就足以改变事物。

然后，按照以下步骤重新启动 Notes 堆栈：

```

In this case, there was no source code change, only a configuration change. Therefore, the containers do not need to be rebuilt, and we can simply relaunch with the new configuration.

That will give us two Notes containers on different ports. Each is configured as normal; for example, they connect to the same user authentication service. Using two browser windows, visit both at their respective port numbers. You'll be able to log in with one browser window, but you'll encounter the following situation:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/642669ba-4d37-4eda-b870-a164aa968cc7.png)

The browser window on port `3020` is logged out, while the window open to port `3000` is logged in. Remember that port `3020` is `svc-notes-2`, while port `3000` is `svc-notes`. However, as you use the two windows, you'll observe some flaky behavior with regard to staying logged in. 

The issue is that the session data is not shared between `svc-notes` and `svc-notes-2`. Instead, the session data is in files stored within each container.

We've identified a problem whereby keeping the session data inside the container makes it impossible to share session data across all instances of the Notes service. To fix this, we need a session store that shares the session data across processes.

## Storing Express/Passport session data in a Redis server

Looking back, we saw that we might have multiple instances of `svc-notes` deployed on Docker Swarm. To test this, we created a second instance, `svc-notes-2`, and found that user sessions were not maintained between the two Notes instances. This told us that we must store session data in a shared data storage system.

There are several choices when it comes to storing sessions. While it is tempting to use the `express-session-sequelize` package, because we're already using Sequelize to manage a database, we have another issue to solve that requires the use of Redis. We'll discuss this other issue later.

For a list of Express session stores, go to [`expressjs.com/en/resources/middleware/session.html#compatible-session-stores`](http://expressjs.com/en/resources/middleware/session.html#compatible-session-stores).

Redis is a widely used key-value data store that is known for being very fast. It is also very easy to install and use. We won't have to learn anything about Redis, either.

Several steps are required in order to set up Redis:

1.  In `compose-local/docker-compose.yml`, add the following definition to the `services` section:

```

这在一个名为`redis`的容器中设置了一个 Redis 服务器。这意味着想要使用 Redis 的其他服务将在名为`redis`的主机上访问它。

对于您定义的任何`svc-notes`服务（`svc-notes`和`svc-notes-2`），我们现在必须告诉 Notes 应用程序在哪里找到 Redis 服务器。我们可以通过使用环境变量来实现这一点。

1.  在`compose-local/docker-compose.yml`中，向任何此类服务添加以下环境变量声明：

```

Add this to both the `svc-notes` and `svc-notes-2` service declarations. This passes the Redis hostname to the Notes service.

3.  Next, install the package:

```

这将安装所需的软件包。`redis`软件包是用于从 Node.js 使用 Redis 的客户端，而`connect-redis`软件包是 Redis 的 Express 会话存储。

1.  我们需要更改`app.mjs`中的初始化，以使用`connect-redis`包来存储会话数据：

```

This brings in the Redis-based session store provided by `connect-redis`.

The configuration for these packages is taken directly from the relevant documentation.

For `connect-redis`, refer to [`www.npmjs.com/package/connect-redis`](https://www.npmjs.com/package/connect-redis). [](https://www.npmjs.com/package/connect-redis) For `redis`, refer to [`github.com/NodeRedis/node-redis`](https://github.com/NodeRedis/node-redis).

This imports the two packages and then configures the `connect-redis` package to use the `redis` package. We consulted the `REDIS_ENDPOINT` environment variable to configure the `redis` client object. The result landed in the same `sessionStore` variable we used previously. Therefore, no other change is required in `app.mjs`.

If no Redis endpoint is specified, we instead revert to the file-based session store. We might not always deploy Notes in a context where we can run Redis; for example, while developing on our laptop. Therefore, we require the option of not using Redis, and, at the moment, the choice looks to be between using Redis or the filesystem to store session data.

With these changes, we can relaunch the Notes application stack. It might help to relaunch the stack using the following command:

```

由于源文件发生了更改，需要重新构建容器。这些选项确保了这一点。

现在我们将能够连接到`http://localhost:3000`（`svc-notes`）上的 Notes 服务和`http://localhost:3020`（`svc-notes-2`）上的服务，并且它将处理两个服务上的登录会话。

然而，还应该注意另一个问题，即实时通知在两个服务器之间没有发送。要看到这一点，设置四个浏览器窗口，两个用于每个服务器。将它们全部导航到相同的笔记。然后，添加和删除一些评论。只有连接到相同服务器的浏览器窗口才会动态显示评论的更改。连接到另一个服务器的浏览器窗口不会。

这是第二个水平扩展问题。幸运的是，它的解决方案也涉及使用 Redis。

## 使用 Redis 分发 Socket.IO 消息

在测试多个`svc-notes`容器时，我们发现登录/注销不可靠。我们通过安装基于 Redis 的会话存储来解决了这个问题，以便将会话数据存储在可以被多个容器访问的地方。但我们也注意到另一个问题：基于 Socket.IO 的消息传递并不能可靠地在所有浏览器窗口中引发更新。

请记住，我们希望在浏览器中发生的更新是由对`SQNotes`或`SQMessages`表的更新触发的。更新任一表时由服务器进行更新时发出的事件。发生在一个服务容器中的更新（比如`svc-notes-2`）将从该容器发出一个事件，但不会从另一个容器（比如`svc-notes`）发出。没有机制让其他容器知道它们应该发出这样的事件。

Socket.IO 文档谈到了这种情况：

[`socket.io/docs/using-multiple-nodes/`](https://socket.io/docs/using-multiple-nodes/)

Socket.IO 团队提供了`socket.io-redis`包作为解决这个问题的方案。它确保通过 Socket.IO 由任何服务器发出的事件将传递到其他服务器，以便它们也可以发出这些事件。

由于我们已经安装了 Redis 服务器，我们只需要按照说明安装包并进行配置。再次强调，我们不需要学习有关 Redis 的任何内容：

```

This installs the `socket.io-redis` package.

Then, we configure it in `app.mjs`, as follows:

```

唯一的变化是添加粗体字中的行。`socket.io-redis`包是 Socket.IO 团队称之为适配器的东西。通过使用`io.adapter`调用，可以将适配器添加到 Socket.IO 中。

只有在指定了 Redis 端点时，我们才连接这个适配器。与以前一样，这是为了需要时可以在没有 Redis 的情况下运行 Notes。

不需要其他任何东西。如果重新启动 Notes 应用程序堆栈，现在将在连接到 Notes 服务的每个实例的每个浏览器窗口中接收更新。

在这一部分，我们提前考虑了部署到云托管服务的情况。知道我们可能想要实现多个 Notes 容器，我们在笔记本上测试了这种情况，并发现了一些问题。通过安装 Redis 服务器并添加一些包，这些问题很容易解决。

我们准备完成本章，但在此之前有一项任务要处理。`svc-notes-2`容器对于临时测试很有用，但不是部署多个 Notes 实例的正确方式。因此，在`compose-local/docker-compose.yml`中，注释掉`svc-notes-2`的定义。

这让我们对一个广泛使用的新工具——Redis 有了宝贵的了解。我们的应用现在似乎也已经准备好部署。我们将在下一章处理这个问题。

# 总结

在本章中，我们迈出了一个巨大的步伐，朝着在云托管平台上部署 Notes 的愿景迈进。Docker 容器在云托管系统上被广泛用于应用程序部署。即使我们最终不使用 Docker Compose 文件，我们仍然可以进行部署，并且我们已经解决了如何将 Notes 堆栈的每个方面都 Docker 化。

在本章中，我们不仅学习了如何为 Node.js 应用程序创建 Docker 镜像，还学习了如何启动包括 Web 应用程序在内的一整套服务系统。我们了解到，Web 应用程序不仅涉及应用程序代码，还涉及数据库、我们使用的框架，甚至其他服务，比如 Redis。

为此，我们学习了如何创建自己的 Docker 容器以及如何使用第三方容器。我们学习了如何使用`docker run`和 Docker Compose 启动容器。我们学习了如何使用 Dockerfile 构建自定义 Docker 容器，以及如何自定义第三方容器。

为了连接容器，我们学习了关于 Docker 桥接网络。这在单主机 Docker 安装中非常有用，它是一个私有通信通道，容器可以在其中找到彼此。作为一个私有通道，桥接网络相对安全，可以让我们安全地将服务绑定在一起。我们有机会尝试 Docker 内部的不同网络架构，并探索每种架构的安全影响。我们了解到 Docker 提供了一个在主机系统上安全部署持久服务的绝佳方式。

展望将 Notes 部署到云托管服务的任务，我们对 Notes 服务的多个实例进行了一些临时测试。这凸显了多个实例可能出现的一些问题，我们通过将 Redis 添加到应用程序堆栈中来解决了这些问题。

这使我们全面了解了如何准备 Node.js 服务以在云托管提供商上部署。请记住，我们的目标是将 Notes 应用程序作为 Docker 容器部署到 AWS EC2 上，作为云部署的一个示例。在本章中，我们探讨了 Docker 化 Node.js 应用程序堆栈的不同方面，为我们提供了在 Docker 上部署服务的坚实基础。我们现在已经准备好将这个应用程序部署到公共互联网上的服务器上。

在下一章中，我们将学习两种非常重要的技术。第一种是**Docker Swarm**，它是一个与 Docker 捆绑在一起的 Docker 编排器。我们将学习如何在 AWS EC2 基础设施上构建的 Swarm 中将我们的 Docker 堆栈部署为服务。我们将学习的第二种技术是 Terraform，它是一种用于描述云托管系统上服务配置的开源工具。我们将使用它来描述 Notes 应用程序堆栈的 AWS EC2 配置。


使用 Terraform 将 Docker Swarm 部署到 AWS EC2

到目前为止，在本书中，我们已经创建了一个基于 Node.js 的应用程序堆栈，包括两个 Node.js 微服务、一对 MySQL 数据库和一个 Redis 实例。在上一章中，我们学习了如何使用 Docker 轻松启动这些服务，打算在云托管平台上这样做。Docker 被广泛用于部署我们这样的服务，对于在公共互联网上部署 Docker，我们有很多可用的选项。

由于 Amazon Web Services（AWS）是一个成熟且功能丰富的云托管平台，我们选择在那里部署。在 AWS 上有许多可用于托管 Notes 的选项。我们在第十一章《使用 Docker 部署 Node.js 微服务》中的工作中，最直接的路径是在 AWS 上创建一个 Docker Swarm 集群。这使我们能够直接重用我们创建的 Docker compose 文件。

Docker Swarm 是可用的 Docker 编排系统之一。这些系统管理一个或多个 Docker 主机系统上的一组 Docker 容器。换句话说，构建一个 Swarm 需要为一个或多个服务器系统进行配置，安装 Docker Engine，并启用 Swarm 模式。Docker Swarm 内置于 Docker Engine 中，只需几个命令即可将这些服务器加入到 Swarm 中。然后，我们可以将基于 Docker 的服务部署到 Swarm 中，Swarm 会在服务器系统之间分发容器，监视每个容器，重新启动任何崩溃的容器等。

Docker Swarm 可以在具有多个 Docker 主机系统的任何情况下使用。它不受 AWS 的限制，因为我们可以从世界各地的数百家 Web 托管提供商那里租用合适的服务器。它足够轻量级，以至于您甚至可以在笔记本电脑上使用虚拟机实例（Multipass、VirtualBox 等）来尝试 Docker Swarm。

在本章中，我们将使用一组 AWS Elastic Compute Cloud（EC2）实例。EC2 是 AWS 的虚拟专用服务器（VPS）的等价物，我们可以从 Web 托管提供商那里租用。EC2 实例将部署在 AWS 虚拟私有云（VPC）中，以及我们将在其上实施之前概述的部署架构的网络基础设施。

让我们谈谈成本，因为 AWS 可能成本高昂。AWS 提供了所谓的免费层，对于某些服务，只要保持在一定阈值以下，成本就为零。在本章中，我们将努力保持在免费层内，除了我们将有三个 EC2 实例部署一段时间，这超出了 EC2 使用的免费层。如果您对成本敏感，可以通过在不需要时销毁 EC2 实例来将其最小化。我们将在稍后讨论如何做到这一点。

本章将涵盖以下主题：

+   注册 AWS 并配置 AWS 命令行界面（CLI）

+   要部署的 AWS 基础设施概述

+   使用 Terraform 创建 AWS 基础设施

+   在 AWS EC2 上设置 Docker Swarm 集群

+   为 Notes Docker 镜像设置 Elastic Container Registry（ECR）存储库

+   为部署到 Docker Swarm 创建 Docker 堆栈文件

+   为完整的 Docker Swarm 配置 EC2 实例

+   将 Notes 堆栈文件部署到 Swarm

在本章中，您将学到很多东西，从如何开始使用 AWS 管理控制台，设置 AWS 上的身份和访问管理（IAM）用户，到如何设置 AWS 命令行工具。由于 AWS 平台如此庞大，重要的是要对其内容和我们在本章中将使用的功能有一个概述。然后，我们将学习 Terraform，这是一种在各种云平台上配置服务的主要工具。我们将学习如何使用它来配置 AWS 资源，如 VPC、相关的网络基础设施，以及如何配置 EC2 实例。接下来，我们将学习 Docker Swarm，这是内置在 Docker 中的编排系统，以及如何设置一个 Swarm，以及如何在 Swarm 中部署应用程序。

为此，我们将学习 Docker 镜像注册表、AWS 弹性容器注册表（ECR）、如何将镜像推送到 Docker 注册表，以及如何在 Docker 应用程序堆栈中使用来自私有注册表的镜像。最后，我们将学习创建 Docker 堆栈文件，该文件允许您描述要在群集中部署的 Docker 服务。

让我们开始吧。

# 第十六章：注册 AWS 并配置 AWS CLI

要使用 AWS 服务，当然必须拥有 AWS 账户。AWS 账户是我们向 AWS 进行身份验证的方式，也是 AWS 向我们收费的方式。

首先，访问[`aws.amazon.com`](https://aws.amazon.com)并注册一个账户。

Amazon 免费套餐是一种零成本体验 AWS 服务的方式：[`aws.amazon.com/free/`](https://aws.amazon.com/free/)。文档可在[`docs.aws.amazon.com`](https://docs.aws.amazon.com)找到。

AWS 有两种我们可以使用的账户，如下：

+   **根账户**是我们注册 AWS 账户时创建的账户。根账户对 AWS 服务拥有完全访问权限。

+   IAM 用户账户是您可以在根账户中创建的权限较低的账户。根账户的所有者创建 IAM 账户，并为每个 IAM 账户分配权限范围。

直接使用根账户是不好的行为，因为根账户对 AWS 资源拥有完全访问权限。如果根账户的凭据泄露给公众，可能会对您的业务造成重大损害。如果 IAM 用户账户的凭据泄露，损害仅限于该用户账户控制的资源以及该账户被分配的权限。此外，IAM 用户凭据可以随时被撤销，然后生成新的凭据，防止持有泄霩凭据的任何人进一步造成损害。另一个安全措施是为所有账户启用多因素身份验证（MFA）。

如果您还没有这样做，请前往上述链接之一的 AWS 网站并注册一个账户。请记住，以这种方式创建的账户是您的 AWS 根账户。

我们的第一步是熟悉 AWS 管理控制台。

## 找到 AWS 账户的方法

由于 AWS 平台上有如此多的服务，看起来就像是一个迷宫。但是，稍微了解一下，我们就能找到自己的路。

首先，看一下窗口顶部的导航栏。右侧有三个下拉菜单。第一个是您的账户名称，并有与账户相关的选项。第二个可以让您选择 AWS 区域的默认设置。AWS 将其基础设施划分为*区域*，基本上意味着 AWS 数据中心所在的世界地区。第三个可以让您联系 AWS 支持。

左侧是一个标有“服务”的下拉菜单。这会显示所有 AWS 服务的列表。由于服务列表很长，AWS 为您提供了一个搜索框。只需输入服务的名称，它就会显示出来。AWS 管理控制台首页也有这个搜索框。

在我们找到自己的路的同时，让我们记录根帐户的帐户号。我们以后会需要这些信息。在帐户下拉菜单中，选择“我的帐户”。帐户 ID 在那里，以及您的帐户名称。

建议在 AWS 根帐户上设置 MFA。MFA 简单地意味着以多种方式对人进行身份验证。例如，服务可能使用通过短信发送的代码号作为第二种身份验证方法，同时要求输入密码。理论上，如果服务验证了我们输入了正确的密码并且我们携带了其他日子携带的同一部手机，那么服务对我们的身份更加确定。

要在根帐户上设置 MFA，请转到“我的安全凭据”仪表板。在 AWS 管理控制台菜单栏中可以找到指向该仪表板的链接。这将带您到一个页面，控制与 AWS 的所有形式的身份验证。从那里，您可以按照 AWS 网站上的说明进行操作。有几种可能的工具可用于实施 MFA。最简单的工具是在智能手机上使用 Google Authenticator 应用程序。设置 MFA 后，每次登录到根帐户都需要从验证器应用程序输入代码。

到目前为止，我们已经处理了在线 AWS 管理控制台。我们真正的目标是使用命令行工具，为此，我们需要在笔记本电脑上安装和配置 AWS CLI。让我们接下来处理这个问题。

## 使用 AWS 身份验证凭据设置 AWS CLI

AWS CLI 工具是通过 AWS 网站提供的下载。在幕后，它使用 AWS 应用程序编程接口（API），并且还要求我们下载和安装身份验证令牌。

一旦您有了帐户，我们就可以准备 AWS CLI 工具。

AWS CLI 使您能够从笔记本电脑的命令行与 AWS 服务进行交互。它具有与每个 AWS 服务相关的广泛的子命令集。

安装 AWS CLI 的说明可以在此处找到：[`docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html`](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)。

配置 AWS CLI 的说明可以在此处找到：[`docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html`](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)。

一旦在笔记本电脑上安装了 AWS CLI 工具，我们必须配置所谓的*配置文件*。

AWS 提供了支持广泛的工具来操作 AWS 基础架构的 AWS API。AWS CLI 工具使用该 API，第三方工具如 Terraform 也使用该 API。使用 API 需要访问令牌，因此 AWS CLI 和 Terraform 都需要相同的令牌。

要获取 AWS API 访问令牌，请转到“我的安全凭据”仪表板，然后单击“访问密钥”选项卡。

单击此按钮，将显示两个安全令牌，即访问密钥 ID 和秘密访问密钥。您将有机会下载包含这些密钥的逗号分隔值（CSV）文件。CSV 文件如下所示：

```

You will receive a file that looks like this. These are the security tokens that identify your account. Don't worry, as no secrets are being leaked in this case. Those particular credentials have been revoked. The good news is that you can revoke these credentials at any time and download new credentials.

Now that we have the credentials file, we can configure an AWS CLI profile.

The `aws configure` command, as the name implies, takes care of configuring your AWS CLI environment. This asks a series of questions, the first two of which are those keys. The interaction looks like this:

```

对于前两个提示，粘贴您下载的密钥。区域名称提示选择您的服务将在其中提供服务的默认 Amazon AWS 数据中心。AWS 在世界各地都有设施，每个地点都有一个代码名称，例如`us-west-2`（位于俄勒冈州）。最后一个提示询问您希望 AWS CLI 如何向您呈现信息。

对于区域代码，在 AWS 控制台中，查看区域下拉菜单。这会显示可用的区域，描述区域和每个区域的区域代码。对于这个项目，最好使用靠近您的 AWS 区域。对于生产部署，最好使用最接近您的受众的区域。可以配置跨多个区域工作的部署，以便您可以为多个地区的客户提供服务，但这种实现远远超出了我们在本书中涵盖的范围。

通过使用`--profile`选项，我们确保创建了一个命名的配置文件。如果我们省略该选项，我们将创建一个名为`default`的配置文件。对于任何`aws`命令，`--profile`选项选择要使用的配置文件。顾名思义，默认配置文件是如果我们省略`--profile`选项时使用的配置文件。

在使用 AWS 身份时，最好始终明确。一些指南建议根本不创建默认的 AWS 配置文件，而是始终使用`--profile`选项以确保始终使用正确的 AWS 配置文件。

验证 AWS 配置的一种简单方法是运行以下命令：

```

The AWS **Simple Storage Service** (**S3**) is a cloud file-storage system, and we are running these commands solely to verify the correct installation of the credentials.  The `ls` command lists any files you have stored in S3\. We don't care about the files that may or may not be in an S3 bucket, but whether this executes without error.

The first command shows us that execution with no `--profile` option, and no `default` profile, produces an error. If there were a `default` AWS profile, that would have been used. However, we did not create a `default` profile, so therefore no profile was available and we got an error. The second shows the same command with an explicitly named profile. The third shows the `AWS_PROFILE` environment variable being used to name the profile to be deployed.

Using the environment variables supported by the AWS CLI tool, such as `AWS_PROFILE`, lets us skip using command-line options such as `--profile` while still being explicit about which profile to use.

As we said earlier, it is important that we interact with AWS via an IAM user, and therefore we must learn how to create an IAM user account. Let's do that next.

## Creating an IAM user account, groups, and roles

We could do everything in this chapter using our root account but, as we said, that's bad form. Instead, it is recommended to create a second user—an IAM user—and give it only the permissions required by that user. 

To get to the IAM dashboard, click on Services in the navigation bar, and enter `IAM`. IAM stands for Identity and Access Management. Also, the My Security Credentials dashboard is part of the IAM service, so we are probably already in the IAM area.

The first task is to create a role. In AWS, roles are used to associate privileges with a user account. You can create roles with extremely limited privileges or an extremely broad range of privileges.

In the IAM dashboard, you'll find a navigation menu on the left. It has sections for users, groups, roles, and other identity management topics. Click on the Roles choice. Then, in the Roles area, click on Create Role. Perform the following steps:

1.  Under Type of trusted identity, select Another AWS account. Enter the account ID, which you will have recorded earlier while familiarizing yourself with the AWS account. Then, click on Next.
2.  On the next page, we select the permissions for this role. For our purpose, select `AdministratorAccess`, a privilege that grants full access to the AWS account. Then, click on Next.
3.  On the next page, you can add tags to the role. We don't need to do this, so click Next.
4.  On the last page, we give a name to the role. Enter `admin` because this role has administrator permissions. Click on Create Role.

You'll see that the role, admin, is now listed in the Role dashboard. Click on admin and you will be taken to a page where you can customize the role further. On this page, notice the characteristic named Role ARN. Record this **Amazon Resource Name** (**ARN**) for future reference.

ARNs are identifiers used within AWS. You can reliably use this ARN in any area of AWS where we can specify a role. ARNs are used with almost every AWS resource.

Next, we have to create an administrator group. In IAM, users are assigned to groups as a way of passing roles and other attributes to a group of IAM user accounts. To do this, perform the following steps:

1.  In the left-hand navigation menu, click on Group, and then, in the group dashboard, click on Create Group. 
2.  For the group name, enter `Administrators`. 
3.  Skip the Attach Policy page, click Next Step*,* and then, on the Review page, simply click Create Group.
4.  This creates a group with no permissions and directs you back to the group dashboard. 
5.  Click on the Administrators group, and you'll be taken to the overview page. Record the ARN for the group.
6.  Click on Permissions to open that tab, and then click on the Inline policies section header. We will be creating an inline policy, so click on the Click here link.
7.  Click on Custom Policy, and you'll be taken to the policy editor.
8.  For the policy name, enter `AssumeAdminRole`. Below that is an area where we enter a block of **JavaScript Object Notation** (**JSON**) code describing the policy. Once that's done, click the Apply Policy button.

The policy document to use is as follows:

```

这描述了为管理员组创建的策略。它为该组提供了我们之前在管理员角色中指定的权限。资源标签是我们输入之前创建的管理员组的 ARN 的地方。确保将整个 ARN 放入此字段。

导航回到组区域，然后再次点击创建组。我们将创建一个名为`NotesDeveloper`的组，供分配给 Notes 项目的开发人员使用。它将为这些用户帐户提供一些额外的特权。执行以下步骤：

1.  输入`NotesDeveloper`作为组名。然后，点击下一步。

1.  对于“附加策略”页面，有一个要考虑的策略长列表；例如，`AmazonRDSFullAccess`，`AmazonEC2FullAccess`，`IAMFullAccess`，`AmazonEC2ContainerRegistryFullAccess`，`AmazonS3FullAccess`，`AdministratorAccess`和`AmazonElasticFileSystemFullAccess`。

1.  然后，点击下一步，如果在审阅页面上一切看起来都正确，请点击**创建组**。

这些策略涵盖了完成本章所需的服务。AWS 错误消息指出用户没有足够的特权访问该功能时，很好地告诉您所需的特权。如果这是用户需要的特权，那么回到这个组并添加特权。

在左侧导航中，点击用户，然后点击创建用户。这开始了创建 IAM 用户所涉及的步骤，如下所述：

1.  对于用户名，输入`notes-app`，因为此用户将管理与 Notes 应用程序相关的所有资源。对于访问类型，点击程序访问和 AWS 管理控制台访问，因为我们将同时使用两者。第一个授予使用 AWS CLI 工具的能力，而第二个涵盖了 AWS 控制台。然后，点击下一步。

1.  对于权限，选择将用户添加到组，并选择管理员和 NotesDeveloper 两个组。这将用户添加到您选择的组。然后，点击下一步。

1.  没有其他事情要做，所以继续点击下一步，直到您到达审阅页面。如果您满意，请点击创建用户。

您将被带到一个宣布成功的页面。在这个页面上，AWS 提供了可以与此帐户一起使用的访问令牌（也称为安全凭证）。在您做任何其他操作之前，请下载这些凭证。您随时可以撤销这些凭证并生成新的访问令牌。

您新创建的用户现在列在用户部分。点击该条目，因为我们有一些数据项要记录。第一个显然是用户帐户的 ARN。第二个是一个**统一资源定位符**（**URL**），您可以使用它以此用户身份登录到 AWS。对于该 URL，请点击安全凭证选项卡，登录链接将在那里。

建议还为 IAM 帐户设置 MFA。AWS 任务栏中的“My Security Credentials”选项可让您进入包含设置 MFA 按钮的屏幕。请参阅前几页关于为根帐户设置 MFA 的讨论。

要测试新用户帐户，请注销，然后转到登录网址。输入帐户的用户名和密码，然后登录。

在完成本节之前，返回命令行并运行以下命令：

```

This will create another AWS CLI profile, this time for the `notes-app` IAM user.

Using the AWS CLI, we can list the users in our account, as follows:

```

这是验证 AWS CLI 是否正确安装的另一种方法。此命令从 AWS 查询用户信息，如果执行无误，则已正确配置 CLI。

AWS CLI 命令遵循类似的结构，其中有一系列子命令，后面跟着选项。在这种情况下，子命令是`aws`，`iam`和`list-users`。AWS 网站为 AWS CLI 工具提供了广泛的在线文档。

### 创建 EC2 密钥对

由于我们将在此练习中使用 EC2 实例，我们需要一个 EC2 密钥对。这是一个加密证书，其作用与我们用于无密码登录到服务器的普通**安全外壳**（**SSH**）密钥相同。实际上，密钥对文件具有相同的作用，允许使用 SSH 无密码登录到 EC2 实例。执行以下步骤：

1.  登录到 AWS 管理控制台，然后选择您正在使用的区域。

1.  接下来，导航到 EC2 仪表板，例如，通过在搜索框中输入`EC2`。

1.  在导航侧边栏中，有一个名为“网络和安全”的部分，其中包含一个名为“密钥对”的链接。

1.  单击该链接。右上角有一个标有“创建密钥对”的按钮。单击此按钮，您将进入以下屏幕：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/dfe865a3-6172-4b2b-ad97-760498cd6af6.png)

1.  输入密钥对的所需名称。根据您使用的 SSH 客户端，使用`.pem`（用于`ssh`命令）或`.ppk`（用于 PuTTY）格式的密钥对文件。

1.  单击“创建密钥对”，您将返回到仪表板，并且密钥对文件将在浏览器中下载。

1.  下载密钥对文件后，需要将其设置为只读，可以使用以下命令：

```

Substitute here the pathname where your browser downloaded the file.

For now, just make sure this file is correctly stored somewhere. When we deploy EC2 instances, we'll talk more about how to use it.

We have familiarized ourselves with the AWS Management Console, and created for ourselves an IAM user account. We have proved that we can log in to the console using the sign-in URL. While doing that, we copied down the AWS access credentials for the account.

We have completed the setup of the AWS command-line tools and user accounts. The next step is to set up Terraform.

# An overview of the AWS infrastructure to be deployed

AWS is a complex platform with dozens of services available to us. This project will touch on only the part required to deploy Notes as a Docker swarm on EC2 instances. In this section, let's talk about the infrastructure and AWS services we'll put to use.

An AWS VPC is what it sounds like—namely, a service within AWS where you build your own private cloud service infrastructure. The AWS team designed the VPC service to look like something that you would construct in your own data center, but implemented on the AWS infrastructure. This means that the VPC is a container to which everything else we'll discuss is attached.

The AWS infrastructure is spread across the globe into what AWS calls regions. For example, `us-west-1` refers to Northern California, `us-west-2` refers to Oregon, and `eu-central-1` refers to Frankfurt. For production deployment, it is recommended to use a region nearer your customers, but for experimentation, it is good to use the region closest to you. Within each region, AWS further subdivides its infrastructure into **availability zones** (a.k.a. **AZs**). An AZ might correspond to a specific building at an AWS data center site, but AWS often recommends that we deploy infrastructure to multiple AZs for reliability. In case one AZ goes down, the service can continue in the AZs that are running.

When we allocate a VPC, we specify an address range for resources deployed within the VPC. The address range is specified with a **Classless Inter-Domain Routing** (**CIDR**) specifier. These are written as `10.3.0.0/16` or `10.3.20.0/24`, which means any **Internet Protocol version 4** (**IPv4**) address starting with `10.3` and `10.3.20`, respectively.

Every device we attach to a VPC will be attached to a subnet, a virtual object similar to an Ethernet segment. Each subnet will be assigned a CIDR from the main range. A VPC assigned the `10.3.0.0/16` CIDR might have a subnet with a CIDR of `10.3.20.0/24`. Devices attached to the subnet will have an IP address assigned within the range indicated by the CIDR for the subnet.

EC2 is AWS's answer to a VPS that you might rent from any web hosting provider. An EC2 instance is a virtual computer in the same sense that Multipass or VirtualBox lets you create a virtual computer on your laptop. Each EC2 instance is assigned a **central processing unit** (**CPU**), memory, disk capacity, and at least one network interface. Hence, an EC2 instance is attached to a subnet and is assigned an IP address from the subnet's assigned range.

By default, a device attached to a subnet has no internet access. The internet gateway and **network address translation** (**NAT**) gateway resources on AWS play a critical role in connecting resources attached to a VPC via the internet. Both are what is known as an internet router, meaning that both handle the routing of internet traffic from one network to another. Because a VPC contains a VPN, these gateways handle traffic between that network and the public internet, as follows:

*   **Internet gateway**: This handles two-way routing, allowing a resource allocated in a VPC to be reachable from the public internet. An internet gateway allows external traffic to enter the VPC, and it also allows resources in the VPC to access resources on the public internet.

*   **NAT gateway**: This handles one-way routing, meaning that resources on the VPC will be able to access resources on the public internet, but does not allow external traffic to enter the VPC. To understand the NAT gateway, think about a common home Wi-Fi router because they also contain a NAT gateway. Such a gateway will manage a local IP address range such as `192.168.0.0/16`, while the **internet service provider** (**ISP**) might assign a public IP address such as `107.123.42.231` to the connection. Local IP addresses, such as `192.168.1.45`, will be assigned to devices connecting to the NAT gateway. Those local IP addresses do not appear in packets sent to the public internet. Instead, the NAT gateway translates the IP addresses to the public IP address of the gateway, and then when reply packets arrive, it translates the IP address to that of the local device. NAT translates IP addresses from the local network to the IP address of the NAT gateway. 

In practical terms, this determines the difference between a private subnet and a public subnet. A public subnet has a routing table that sends traffic for the public internet to an internet gateway, whereas a private subnet sends its public internet traffic to a NAT gateway.

Routing tables describe how to route internet traffic. Inside any internet router, such as an internet gateway or a NAT gateway, is a function that determines how to handle internet packets destined for a location other than the local subnet. The routing function matches the destination address against routing table entries, and each routing table entry says where to forward matching packets.

Attached to each device deployed in a VPC is a security group. A security group is a firewall controlling what kind of internet traffic can enter or leave that device. For example, an EC2 instance might have a web server supporting HTTP (port `80`) and HTTPS (port `443`) traffic, and the administrator might also require SSH access (port `22`) to the instance. The security group would be configured to allow traffic from any IP address on ports `80` and `443` and to allow traffic on port `22` from IP address ranges used by the administrator.

A network **access control list** (**ACL**) is another kind of firewall that's attached to subnets. It, too, describes which traffic is allowed to enter or leave the subnet. The security groups and network ACLs are part of the security protections provided by AWS.

If a device connected to a VPC does not seem to work correctly, there might be an error in the configuration of these parts. It's necessary to check the security group attached to the device, and to the NAT gateway or internet gateway, and that the device is connected to the expected subnet, the routing table for the subnet, and any network ACLs.

# Using Terraform to create an AWS infrastructure

Terraform is an open source tool for configuring a cloud hosting infrastructure. It uses a declarative language to describe the configuration of cloud services. Through a long list of plugins, called providers, it has support for a variety of cloud services. In this chapter, we'll use Terraform to describe AWS infrastructure deployments.

To install Terraform, download an installer from [`www.terraform.io/downloads.html`](https://www.terraform.io/downloads.html).

Alternatively, you will find the Terraform CLI available in many package management systems.

Once installed, you can view the Terraform help with the following command:

```

Terraform 文件具有`.tf`扩展名，并使用相当简单、易于理解的声明性语法。Terraform 不关心您使用的文件名或创建文件的顺序。它只是读取所有具有`.tf`扩展名的文件，并寻找要部署的资源。这些文件不包含可执行代码，而是声明。Terraform 读取这些文件，构建依赖关系图，并确定如何在使用的云基础设施上实现这些声明。

一个示例声明如下：

```

The first word, `resource` or `variable`, is the block type, and in this case, we are declaring a resource and a variable. Within the curly braces are the arguments to the block, and it is helpful to think of these as attributes.

Blocks have labels—in this case, the labels are `aws_vpc` and `main`. We can refer to this specific resource elsewhere by joining the labels together as `aws_vpc.main`. The name, `aws_vpc`, comes from the AWS provider and refers to VPC elements. In many cases, a block—be it a resource or another kind—will support attributes that can be accessed. For example, the CIDR for this VPC can be accessed as `aws_vpc.main.cidr_block`.

The general structure is as follows:

```

区块类型包括资源（resource），声明与云基础设施相关的内容，变量（variable），声明命名值，输出（output），声明模块的结果，以及其他一些类型。

区块标签的结构因区块类型而异。对于资源区块，第一个区块标签指的是资源的类型，而第二个是该资源的特定实例的名称。

参数的类型也因区块类型而异。Terraform 文档对每个变体都有广泛的参考。

Terraform 模块是包含 Terraform 脚本的目录。当在目录中运行`terraform`命令时，它会读取该目录中的每个脚本以构建对象树。

在模块内，我们处理各种值。我们已经讨论了资源、变量和输出。资源本质上是与云托管平台上的某些东西相关的对象值。变量可以被视为模块的输入，因为有多种方法可以为变量提供值。输出值如其名称所示，是模块的输出。当执行模块时，输出可以打印在控制台上，或保存到文件中，然后被其他模块使用。与此相关的代码可以在以下片段中看到：

```

This is what the `variable` and `output` declarations look like. Every value has a data type. For variables, we can attach a description to aid in their documentation. The declaration uses the word `default` rather than `value` because there are multiple ways (such as Terraform command-line arguments) to specify a value for a variable. Terraform users can override the default value in several ways, such as the `--var` or `--var-file` command-line options.

Another type of value is local. Locals exist only within a module because they are neither input values (variables) nor output values, as illustrated in the following code snippet:

```

在这种情况下，我们定义了与要在 VPC 中创建的子网的 CIDR 相关的几个本地变量。`cidrsubnet`函数用于计算子网掩码，例如`10.1.1.0/24`。

Terraform 的另一个重要特性是提供者插件。Terraform 支持的每个云系统都需要一个定义如何使用 Terraform 与该平台的具体细节的插件模块。

提供者插件的一个效果是 Terraform 不会尝试成为平台无关的。相反，给定平台的所有可声明资源都是唯一的。您不能直接在另一个系统（如 Azure）上重用 AWS 的 Terraform 脚本，因为资源对象都是不同的。您可以重用的是 Terraform 如何处理云资源声明的知识。 

另一个任务是在你的编程编辑器中寻找一个 Terraform 扩展。其中一些支持 Terraform，包括语法着色、检查简单错误，甚至代码补全。

尽管如此，这已经足够的理论了。要真正学会这个，我们需要开始使用 Terraform。在下一节中，我们将从实现 VPC 结构开始，然后在其中部署 Notes 应用程序堆栈。

## 使用 Terraform 配置 AWS VPC

AWS VPC 就像它的名字一样，是 AWS 内的一个服务，用来容纳您定义的云服务。AWS 团队设计了 VPC 服务，看起来有点像您在自己的数据中心构建的东西，但是在 AWS 基础设施上实现。

在本节中，我们将构建一个包含公共子网和私有子网、互联网网关和安全组定义的 VPC。

在项目工作区中，创建一个名为`terraform-swarm`的目录，它是`notes`和`users`目录的同级目录。

在该目录中，创建一个名为`main.tf`的文件，其中包含以下内容：

```

This says to use the AWS provider plugin. It also configures this script to execute using the named AWS profile. Clearly, the AWS provider plugin requires AWS credential tokens in order to use the AWS API. It knows how to access the credentials file set up by `aws configure`.

To learn more about configuring the AWS provider plugin, refer to [`www.terraform.io/docs/providers/aws/index.html`](https://www.terraform.io/docs/providers/aws/index.html).

As shown here, the AWS plugin will look for the AWS credentials file in its default location, and use the `notes-app` profile name.

In addition, we have specified which AWS region to use. The reference, `var.aws_region`, is a Terraform variable. We use variables for any value that can legitimately vary. Variables can be easily customized to any value in several ways.

To support the variables, we create a file named `variables.tf`, starting with this:

```

`default`属性为变量设置了默认值。正如我们之前看到的，声明也可以指定变量的数据类型和描述。

有了这个，我们现在可以运行我们的第一个 Terraform 命令，如下所示：

```

This initializes the current directory as a Terraform workspace. You'll see that it creates a directory, `.terraform`, and a file named `terraform.tfstate` containing data collected by Terraform. The `.tfstate` files are what is known as state files. These are in JSON format and store the data Terraform collects from the platform (in this case, AWS) regarding what has been deployed. State files must not be committed to source code repositories because it is possible for sensitive data to end up in those files. Therefore, a `.gitignore` file listing the state files is recommended.

The instructions say we should run `terraform plan`, but before we do that, let's declare a few more things.

To declare the VPC and its related infrastructure, let's create a file named `vpc.tf`. Start with the following command:

```

这声明了 VPC。这将是我们正在创建的基础设施的容器。

`cidr_block`属性确定将用于此 VPC 的 IPv4 地址空间。CIDR 表示法是一个互联网标准，例如`10.0.0.0/16`。该 CIDR 将覆盖以`10.0`开头的任何 IP 地址。

`enable_dns_support`和`enable_dns_hostnames`属性确定是否为连接到 VPC 的某些资源生成**域名系统**（**DNS**）名称。DNS 名称可以帮助一个资源在运行时找到其他资源。

`tags`属性用于将名称/值对附加到资源上。名称标签被 AWS 用来为资源设置显示名称。每个 AWS 资源都有一个计算生成的、用户不友好的名称，带有一个长编码的字符串，当然，我们人类需要友好的名称。名称标签在这方面很有用，AWS 管理控制台将通过在仪表板中使用这个名称来做出响应。

在`variables.tf`中，添加以下内容以支持这些资源声明：

```

These values will be used throughout the project. For example, `var.project_name` will be widely used as the basis for creating name tags for deployed resources.

Add the following to `vpc.tf`:

```

`resource`块声明了托管平台上的某些内容（在本例中是 AWS），`data`块从托管平台检索数据。在这种情况下，我们正在检索当前选择区域的 AZ 列表。以后在声明某些资源时会用到这个数据。

### 配置 AWS 网关和子网资源

请记住，公共子网与互联网网关相关联，私有子网与 NAT 网关相关联。这种区别决定了附加到每个子网的互联网访问设备的类型。

创建一个名为`gw.tf`的文件，其中包含以下内容：

```

This declares the internet gateway and the NAT gateway. Remember that internet gateways are used with public subnets, and NAT gateways are used with private subnets.

An **Elastic IP** (**EIP**) resource is how a public internet IP address is assigned. Any device that is to be visible to the public must be on a public subnet and have an EIP. Because the NAT gateway faces the public internet, it must have an assigned public IP address and an EIP.

For the subnets, create a file named `subnets.tf` containing the following:

```

这声明了公共和私有子网。请注意，这些子网分配给了特定的 AZ。通过添加名为`public2`、`public3`、`private2`、`private3`等子网，很容易扩展以支持更多子网。如果这样做，最好将这些子网分布在不同的 AZ 中。建议在多个 AZ 中部署，这样如果一个 AZ 崩溃，应用程序仍在仍在运行的 AZ 中运行。

带有`[0]`的这种表示是什么样子的——一个数组。值`data.aws_availability_zones.available.names`是一个数组，添加`[0]`确实访问了该数组的第一个元素，就像你期望的那样。数组只是 Terraform 提供的数据结构之一。

每个子网都有自己的 CIDR（IP 地址范围），为了支持这一点，我们需要在`variables.tf`中列出这些 CIDR 分配，如下所示：

```

These are the CIDRs corresponding to the resources declared earlier.

For these pieces to work together, we need appropriate routing tables to be configured. Create a file named `routing.tf` containing the following:

```

要为公共子网配置路由表，我们修改连接到 VPC 的主路由表的路由表。我们在这里做的是向该表添加一条规则，指定公共互联网流量要发送到互联网网关。我们还有一个路由表关联声明，公共子网使用这个路由表。

对于`aws_route_table.private`，私有子网的路由表，声明指定将公共互联网流量发送到 NAT 网关。在路由表关联中，此表用于私有子网。

之前，我们说公共子网和私有子网的区别在于公共互联网流量是发送到互联网网关还是 NAT 网关。这些声明就是实现这一点的方式。

在这一部分中，我们声明了 VPC、子网、网关和路由表，换句话说，我们将部署 Docker Swarm 的基础架构。

在连接容纳 Swarm 的 EC2 实例之前，让我们将其部署到 AWS 并探索设置的内容。

## 使用 Terraform 将基础架构部署到 AWS

我们现在已经声明了我们需要的 AWS 基础架构的基本结构。这是 VPC、子网和路由表。让我们将其部署到 AWS，并使用 AWS 控制台来探索创建了什么。

之前，我们运行了`terraform init`来初始化我们的工作目录中的 Terraform。这样做时，它建议我们运行以下命令：

```

This command scans the Terraform files in the current directory and first determines that everything has the correct syntax, that all the values are known, and so forth. If any problems are encountered, it stops right away with error messages such as the following:

```

Terraform 的错误消息通常是不言自明的。在这种情况下，原因是决定只使用一个公共子网和一个私有子网。这段代码是从两个子网的情况遗留下来的。因此，这个错误指的是容易删除的陈旧代码。

`terraform plan`的另一个作用是构建所有声明的图表并打印出一个列表。这让你了解 Terraform 打算部署到所选云平台上的内容。因此，这是你检查预期基础架构并确保它是你想要使用的机会。

一旦您满意了，请运行以下命令：

```

With `terraform apply`, the report shows the difference between the actual deployed state and the desired state as reflected by the Terraform files. In this case, there is no deployed state, so therefore everything that is in the files will be deployed. In other cases, you might have deployed a system and have made a change, in which case Terraform will work out which changes have to be deployed based on the changes you've made. Once it calculates that, Terraform asks for permission to proceed. Finally, if we have said yes, it will proceed and launch the desired infrastructure.

Once finished, it tells you what happened. One result is the values of the `output` commands in the scripts. These are both printed on the console and are saved in the backend state file.

To see what was created, let's head to the AWS console and navigate to the VPC area, as follows:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/bc4b8bd0-aacc-43e7-a56f-4ff0618101aa.png)

Compare the VPC ID in the screenshot with the one shown in the Terraform output, and you'll see that they match. What's shown here is the main routing table, and the CIDR, and other settings we made in our scripts. Every AWS account has a default VPC that's presumably meant for experiments. It is a better form to create a VPC for each project so that resources for each project are separate from other projects.

The sidebar contains links for further dashboards for subnets, route tables, and other things, and an example dashboard can be seen in the following screenshot:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/89c715eb-9688-48ac-a145-33b8d9ed7835.png)

For example, this is the NAT gateway dashboard showing the one created for this project.

Another way to explore is with the AWS CLI tool. Just because we have Terraform doesn't mean we are prevented from using the CLI. Have a look at the following code block:

```

这列出了创建的 VPC 的参数。

记得要么配置`AWS_PROFILE`环境变量，要么在命令行上使用`--profile`。

要列出子网上的数据，请运行以下命令：

```

To focus on the subnets for a given VPC, we use the `--filters` option, passing in the filter named `vpc-id` and the VPC ID for which to filter.

Documentation for the AWS CLI can be found at [`docs.aws.amazon.com/cli/latest/reference/index.html`](https://docs.aws.amazon.com/cli/latest/reference/index.html). [](https://docs.aws.amazon.com/cli/latest/reference/index.html) For documentation relating to the EC2 sub-commands, refer to [`docs.aws.amazon.com/cli/latest/reference/ec2/index.html`](https://docs.aws.amazon.com/cli/latest/reference/ec2/index.html).

The AWS CLI tool has an extensive list of sub-commands and options. These are enough to almost guarantee getting lost, so read carefully.

In this section, we learned how to use Terraform to set up the VPC and related infrastructure resources, and we also learned how to navigate both the AWS console and the AWS CLI to explore what had been created.

Our next step is to set up an initial Docker Swarm cluster by deploying an EC2 instance to AWS.

# Setting up a Docker Swarm cluster on AWS EC2

What we have set up is essentially a blank slate. AWS has a long list of offerings that could be deployed to the VPC that we've created. What we're looking to do in this section is to set up a single EC2 instance to install Docker, and set up a single-node Docker Swarm cluster. We'll use this to familiarize ourselves with Docker Swarm. In the remainder of the chapter, we'll build more servers to create a larger swarm cluster for full deployment of Notes.

A Docker Swarm cluster is simply a group of servers running Docker that have been joined together into a common pool. The code for the Docker Swarm orchestrator is bundled with the Docker Engine server but it is disabled by default. To create a swarm, we simply enable swarm mode by running `docker swarm init` and then run a `docker swarm join` command on each system we want to be part of the cluster. From there, the Docker Swarm code automatically takes care of a long list of tasks. The features for Docker Swarm include the following:

*   **Horizontal scaling**: When deploying a Docker service to a swarm, you tell it the desired number of instances as well as the memory and CPU requirements. The swarm takes that and computes the best distribution of tasks to nodes in the swarm.
*   **Maintaining the desired state**: From the services deployed to a swarm, the swarm calculates the desired state of the system and tracks its current actual state. Suppose one of the nodes crashes—the swarm will then readjust the running tasks to replace the ones that vaporized because of the crashed server.
*   **Multi-host networking**: The overlay network driver automatically distributes network connections across the network of machines in the swarm.
*   **Secure by default**: Swarm mode uses strong **Transport Layer Security** (**TLS**) encryption for all communication between nodes.
*   **Rolling updates**: You can deploy an update to a service in such a manner where the swarm intelligently brings down existing service containers, replacing them with updated newer containers.

For an overview of Docker Swarm, refer to [`docs.docker.com/engine/swarm/`](https://docs.docker.com/engine/swarm/).

We will use this section to not only learn how to set up a Docker Swarm but to also learn something about how Docker orchestration works.

To get started, we'll set up a single-node swarm on a single EC2 instance in order to learn some basics, before we move on to deploying a multi-node swarm and deploying the full Notes stack.

## Deploying a single-node Docker Swarm on a single EC2 instance

For a quick introduction to Docker Swarm, let's start by installing Docker on a single EC2 node. We can kick the tires by trying a few commands and exploring the resulting system.

This will involve deploying Ubuntu 20.04 on an EC2 instance, configuring it to have the latest Docker Engine, and initializing swarm mode.

### Adding an EC2 instance and configuring Docker

To launch an EC2 instance, we must first select which operating system to install. There are thousands of operating system configurations available. Each of these configurations is identified by an **AMI** code, where AMI stands for **Amazon Machine Image**.

To find your desired AMI, navigate to the EC2 dashboard on the AWS console. Then, click on the Launch Instance button, which starts a wizard-like interface to launch an instance. You can, if you like, go through the whole wizard since that is one way to learn about EC2 instances. We can search the AMIs via the first page of that wizard, where there is a search box.

For this exercise, we will use Ubuntu 20.04, so enter `Ubuntu` and then scroll down to find the correct version, as illustrated in the following screenshot:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/a3ad87a9-eb2c-4c6e-9ae8-995fd25d532d.png)

This is what the desired entry looks like. The AMI code starts with `ami-` and we see one version for x86 CPUs, and another for **ARM** (previously **Advanced RISC Machine**). ARM processors, by the way, are not just for your cell phone but are also used in servers. There is no need to launch an EC2 instance from here since we will instead do so with Terraform.

Another attribute to select is the instance size. AWS supports a long list of sizes that relate to the amount of memory, CPU cores, and disk space. For a chart of the available instance types, click on the Select button to proceed to the second page of the wizard, which shows a table of instance types and their attributes. For this exercise, we will use the `t2.micro` instance type because it is eligible for the free tier.

Create a file named `ec2-public.tf` containing the following:

```

在 Terraform AWS 提供程序中，EC2 实例的资源名称是`aws_instance`。由于此实例附加到我们的公共子网，我们将其称为`aws_instance.public`。因为它是一个公共的 EC2 实例，`associate_public_ip_address`属性设置为`true`。

属性包括 AMI ID、实例类型、子网 ID 等。`key_name`属性是指我们将用于登录 EC2 实例的 SSH 密钥的名称。我们稍后会讨论这些密钥对。`vpc_security_group_ids`属性是指我们将应用于 EC2 实例的安全组。`depends_on`属性导致 Terraform 等待数组中命名的资源的创建。`user_data`属性是一个 shell 脚本，一旦创建实例就在实例内执行。

对于 AMI、实例类型和密钥对数据，请将这些条目添加到`variables.tf`，如下所示：

```

The AMI ID shown here is specifically for Ubuntu 20.04 in `us-west-2`. There will be other AMI IDs in other regions. The `key_pair` name shown here should be the key-pair name you selected when creating your key pair earlier.

It is not necessary to add the key-pair file to this directory, nor to reference the file you downloaded in these scripts. Instead, you simply give the name of the key pair. In our example, we named it `notes-app-key-pair`, and downloaded `notes-app-key-pair.pem`.

The `user_data` feature is very useful since it lets us customize an instance after creation. We're using this to automate the Docker setup on the instances. This field is to receive a string containing a shell script that will execute once the instance is launched. Rather than insert that script inline with the Terraform code, we have created a set of files that are shell script snippets. The Terraform `file` function reads the named file, returning it as a string. The Terraform `join` function takes an array of strings, concatenating them together with the delimiter character in between. Between the two we construct a shell script. The shell script first installs Docker Engine, then initializes Docker Swarm mode, and finally changes the hostname to help us remember that this is the public EC2 instance.

Create a directory named `sh` in which we'll create shell scripts, and in that directory create a file named `docker_install.sh`. To this file, add the following:

```

此脚本源自 Ubuntu 上安装 Docker Engine **Community Edition** (**CE**)的官方说明。第一部分是支持`apt-get`从 HTTPS 存储库下载软件包。然后将 Docker 软件包存储库配置到 Ubuntu 中，之后安装 Docker 和相关工具。最后，确保`docker`组已创建并确保`ubuntu`用户 ID 是该组的成员。Ubuntu AMI 默认使用此用户 ID `ubuntu` 作为 EC2 管理员使用的用户 ID。

对于此 EC2 实例，我们还运行`docker swarm init`来初始化 Docker Swarm。对于其他 EC2 实例，我们不运行此命令。用于初始化`user_data`属性的方法让我们可以轻松地为每个 EC2 实例设置自定义配置脚本。对于其他实例，我们只运行`docker_install.sh`，而对于此实例，我们还将初始化 swarm。

回到`ec2-public.tf`，我们还有两件事要做，然后我们可以启动 EC2 实例。看一下以下代码块：

```

This is the security group declaration for the public EC2 instance. Remember that a security group describes the rules of a firewall that is attached to many kinds of AWS objects. This security group was already referenced in declaring `aws_instance.public`.

The main feature of security groups is the `ingress` and `egress` rules. As the words imply, `ingress` rules describe the network traffic allowed to enter the resource, and `egress` rules describe what's allowed to be sent by the resource. If you have to look up those words in a dictionary, you're not alone.

We have two `ingress` rules, and the first allows traffic on port `22`, which covers SSH traffic. The second allows traffic on port `80`, covering HTTP. We'll add more Docker rules later when they're needed.

The `egress` rule allows the EC2 instance to send any traffic to any machine on the internet.

These `ingress` rules are obviously very strict and limit the attack surface any miscreants can exploit.

The final task is to add these output declarations to `ec2-public.tf`, as follows:

```

这将让我们知道公共 IP 地址和公共 DNS 名称。如果我们感兴趣，输出还会告诉我们私有 IP 地址和 DNS 名称。

### 在 AWS 上启动 EC2 实例

我们已经添加了用于创建 EC2 实例的 Terraform 声明。

现在我们已经准备好将其部署到 AWS 并查看我们可以做些什么。我们已经知道该怎么做了，所以让我们运行以下命令：

```

If the VPC infrastructure were already running, you would get output similar to this. The addition is two new objects, `aws_instance.public` and `aws_security_group.ec2-public-sg`. This looks good, so we proceed to deployment, as follows:

```

这构建了我们的 EC2 实例，我们有了 IP 地址和域名。因为初始化脚本需要几分钟才能运行，所以最好等待一段时间再进行系统测试。

`ec2-public-ip`值是 EC2 实例的公共 IP 地址。在以下示例中，我们将放置文本`PUBLIC-IP-ADDRESS`，当然您必须替换为您的 EC2 实例分配的 IP 地址。

我们可以这样登录到 EC2 实例：

```

On a Linux or macOS system where we're using SSH, the command is as shown here. The `-i` option lets us specify the **Privacy Enhanced Mail** (**PEM**) file that was provided by AWS for the key pair. If on Windows using PuTTY, you'd instead tell it which **PuTTY Private Key** (**PPK**) file to use, and the connection parameters will otherwise be similar to this.

This lands us at the command-line prompt of the EC2 instance. We see that it is Ubuntu 20.04, and the hostname is set to `notes-public`, as reflected in Command Prompt and the output of the `hostname` command. This means that our initialization script ran because the hostname was the last configuration task it performed.

### Handling the AWS EC2 key-pair file

Earlier, we said to safely store the key-pair file somewhere on your computer.  In the previous section, we showed how to use the PEM file with SSH to log in to the EC2 instance. Namely, we use the PEM file like so:

```

每次使用 SSH 时记住添加`-i`标志可能会不方便。为了避免使用此选项，运行此命令：

```

As the command name implies, this adds the authentication file to SSH. This has to be rerun on every reboot of the computer, but it conveniently lets us access EC2 instances without remembering to specify this option.

### Testing the initial Docker Swarm

We have an EC2 instance and it should already be configured with Docker, and we can easily verify that this is the case as follows:

```

设置脚本也应该已经将此 EC2 实例初始化为 Docker Swarm 节点，以下命令验证了是否发生了这种情况：

```

The `docker info` command, as the name implies, prints out a lot of information about the current Docker instance. In this case, the output includes verification that it is in Docker Swarm mode and that this is a Docker Swarm manager instance.

Let's try a couple of swarm commands, as follows:

```

`docker node`命令用于管理集群中的节点。在这种情况下，只有一个节点 - 这个节点，并且它被显示为不仅是一个管理者，而且是集群的领导者。当你是集群中唯一的节点时，成为领导者似乎很容易。

`docker service`命令用于管理集群中部署的服务。在这种情况下，服务大致相当于 Docker compose 文件中`services`部分的条目。换句话说，服务不是正在运行的容器，而是描述启动给定容器一个或多个实例的配置的对象。 

要了解这意味着什么，让我们启动一个`nginx`服务，如下所示：

```

We started one service using the `nginx` image. We said to deploy one replica and to expose port `80`. We chose the `nginx` image because it has a simple default HTML file that we can easily view, as illustrated in the following screenshot:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/28a6d679-cfef-4fbf-a8b4-6d7413d2e3b8.png)

Simply paste the IP address of the EC2 instance into the browser location bar, and we're greeted with that default HTML.

We also see by using `docker node ls` and `docker service ps` that there is one instance of the service. Since this is a swarm, let's increase the number of `nginx` instances, as follows:

```

一旦服务部署完成，我们可以使用`docker service update`命令来修改部署。在这种情况下，我们告诉它使用`--replicas`选项增加实例的数量，现在`notes-public`节点上运行了三个`nginx`容器的实例。

我们还可以运行正常的`docker ps`命令来查看实际的容器，如下面的代码块所示：

```

This verifies that the `nginx` service with three replicas is actually three `nginx` containers.

In this section, we were able to launch an EC2 instance and set up a single-node Docker swarm in which we launched a service, which gave us the opportunity to familiarize ourselves with what this can do.

While we're here, there is another thing to learn—namely, how to set up the remote control of Docker hosts.

## Setting up remote control access to a Docker Swarm hosted on EC2

A feature that's not well documented in Docker is the ability to control Docker nodes remotely. This will let us, from our laptop, run Docker commands on a server. By extension, this means that we will be able to manage the Docker Swarm from our laptop.

One method for remotely controlling a Docker instance is to expose the Docker **Transmission Control Protocol** (**TCP**) port. Be aware that miscreants are known to scan an internet infrastructure for Docker ports to hijack. The following technique does not expose the Docker port but instead uses SSH.

The following setup is for Linux and macOS, relying on features of SSH. To do this on Windows would rely on installing OpenSSH. From October 2018, OpenSSH became available for Windows, and the following commands may work in PowerShell (failing that, you can run these commands from a Multipass or **Windows Subsystem for Linux** (**WSL**) 2 instance on Windows):

```

退出 EC2 实例上的 shell，这样你就可以在笔记本电脑的命令行上了。

运行以下命令：

```

We discussed this command earlier, noting that it lets us log in to EC2 instances without having to use the `-i` option to specify the PEM file.  This is more than a simple convenience when it comes to remotely accessing Docker hosts. The following steps are dependent on having added the PEM file to SSH, as shown here. 

To verify you've done this correctly, use this command:

```

通常在 EC2 实例上，我们会使用`-i`选项，就像之前展示的那样。但是在运行`ssh-add`之后，就不再需要`-i`选项了。

这使我们能够创建以下环境变量：

```

The `DOCKER_HOST` environment variable enables the remote control of Docker hosts. It relies on a passwordless SSH login to the remote host. Once you have that, it's simply a matter of setting the environment variable and you've got remote control of the Docker host, and in this case, because the host is a swarm manager, a remote swarm.

But this gets even better by using the Docker context feature. A *context* is a configuration required to access a remote node or swarm. Have a look at the following code snippet:

```

我们首先删除环境变量，因为我们将用更好的东西来替代它，如下所示：

```

We create a context using `docker context create`, specifying the same SSH URL we used in the `DOCKER_HOST` variable. We can then use it either with the `--context` option or by using `docker context use` to switch between contexts.

With this feature, we can easily maintain configurations for multiple remote servers and switch between them with a simple command.

For example, the Docker instance on our laptop is the *default* context. Therefore, we might find ourselves doing this:

```

有时候我们必须意识到当前的 Docker 上下文是什么，以及何时使用哪个上下文。在下一节中，当我们学习如何将镜像推送到 AWS ECR 时，这将是有用的。

我们在本节中学到了很多知识，所以在进行下一个任务之前，让我们清理一下我们的 AWS 基础设施。没有必要保持这个 EC2 实例运行，因为我们只是用它进行了一个快速的熟悉之旅。我们可以轻松地删除这个实例，同时保留其余的基础设施配置。最有效的方法是将`ec2-public.tf`重命名为`ec2-public.tf-disable`，然后重新运行`terraform apply`，如下面的代码块所示：

```

The effect of changing the name of one of the Terraform files is that Terraform will not scan those files for objects to deploy. Therefore, when Terraform maps out the state we want Terraform to deploy, it will notice that the deployed EC2 instance and security group are not listed in the local files, and it will, therefore, destroy those objects. In other words, this lets us undeploy some infrastructure with very little fuss. 

This tactic can be useful for minimizing costs by turning off unneeded facilities. You can easily redeploy the EC2 instances by renaming the file back to `ec2-public.tf` and rerunning `terraform apply`.

In this section, we familiarized ourselves with Docker Swarm by deploying a single-node swarm on an EC2 instance on AWS. We first added suitable declarations to our Terraform files. We then deployed the EC2 instance on AWS. Following deployment, we set about verifying that, indeed, Docker Swarm was already installed and initialized on the server and that we could easily deploy Docker services on the swarm. We then learned how to set up remote control of the swarm from our laptop.

Taken together, this proved that we can easily deploy Docker-based services to EC2 instances on AWS. In the next section, let's continue preparing for a production-ready deployment by setting up a build process to push Docker images to image repositories.

# Setting up ECR repositories for Notes Docker images

We have created Docker images to encapsulate the services making up the Notes application. So far, we've used those images to instantiate Docker containers on our laptop. To deploy containers on the AWS infrastructure will require the images to be hosted in a Docker image repository.

This requires a build procedure by which the `svc-notes` and `svc-userauth` images are correctly pushed to the container repository on the AWS infrastructure. We will go over the commands required and create a few shell scripts to record those commands. 

A site such as Docker Hub is what's known as a Docker Registry. Registries are web services that store Docker images by hosting Docker image repositories. When we used the `redis` or `mysql/mysql-server` images earlier, we were using Docker image repositories located on the Docker Hub Registry. 

The AWS team offers a Docker image registry, ECR. An ECR instance is available for each account in each AWS region. All we have to do is log in to the registry, create repositories, and push images to the repositories.

It is extremely important to run commands in this section in the default Docker context on your laptop. The reason is that Docker builds must not happen on the Swarm host but on some other host, such as your laptop.

Because it is important to not run Docker build commands on the Swarm infrastructure, execute this command:

```

这个命令将 Docker 上下文切换到本地系统。

为了保存与管理 AWS ECR 存储库相关的脚本和其他文件，创建一个名为`ecr`的目录，作为`notes`，`users`和`terraform-swarm`的同级目录。

构建过程需要几个命令来创建 Docker 镜像，对其进行标记，并将其推送到远程存储库。为了简化操作，让我们创建一些 shell 脚本以及 PowerShell 脚本来记录这些命令。

第一个任务是连接到 AWS ECR 服务。为此，创建一个名为`login.sh`的文件，其中包含以下内容：

```

This command, and others, are available in the ECR dashboard. If you navigate to that dashboard and then create a repository there, a button labeled View Push Command is available. This and other useful commands are listed there, but we have substituted a few variable names to make this configurable.

If you are instead using Windows PowerShell, AWS recommends the following:

```

这依赖于 PowerShell 的 AWS 工具包（参见[`aws.amazon.com/powershell/`](https://aws.amazon.com/powershell/)），它似乎提供了一些有用于 AWS 服务的强大工具。然而，在测试中，这个命令并没有表现得很好。

相反，发现以下命令效果更好，你可以将其放在一个名为`login.ps1`的文件中：

```

This is the same command as is used for Unix-like systems, but with Windows-style references to environment variables.  

You may wish to explore the `cross-var` package, since it can convert Unix-style environment variable references to Windows. For the documentation, refer to [`www.npmjs.com/package/cross-var`](https://www.npmjs.com/package/cross-var).

Several environment variables are being used, but just what are those variables being used and how do we set them?

## Using environment variables for AWS CLI commands

Look carefully and you will see that some environment variables are being used. The AWS CLI commands know about those environment variables and will use them instead of command-line options. The environment variables we're using are the following:

*   `AWS_PROFILE`: The AWS profile to use with this project. 
*   `AWS_REGION`: The AWS region to deploy the project to.
*   `AWS_USER`: The numeric user ID for the account being used. This ID is available on the IAM dashboard page for the account.

The AWS CLI recognizes some of these environment variables, and others. For further details, refer to [`docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html).

The AWS command-line tools will use those environment variables in place of the command-line options. Earlier, we discussed using the `AWS_PROFILE` variable instead of the `--profile` option. The same holds true for other command-line options.

This means that we need an easy way to set those variables. These Bash commands can be recorded in a shell script like this, which you could store as `env-us-west-2`:

```

当然，这个脚本遵循 Bash shell 的语法。对于其他命令环境，你必须适当地进行转换。要在 Bash shell 中设置这些变量，请运行以下命令：

```

For other command environments, again transliterate appropriately. For example, in Windows and in PowerShell, the variables can be set with these commands:

```

这些值应该是相同的，只是在 Windows 中被识别的语法。

我们已经定义了正在使用的环境变量。现在让我们回到定义构建 Docker 镜像并将其推送到 ECR 的过程。

## 定义一个构建 Docker 镜像并将其推送到 AWS ECR 的过程

我们正在探索一个将 Docker 容器推送到 ECR 存储库的构建过程，直到我们开始谈论环境变量。让我们回到手头的任务，那就是轻松地构建 Docker 镜像，创建 ECR 存储库，并将镜像推送到 ECR。

正如本节开头提到的，确保切换到*default* Docker 上下文。我们必须这样做，因为 Docker Swarm 的政策是不使用集群主机来构建 Docker 镜像。

要构建镜像，让我们添加一个名为`build.sh`的文件，其中包含以下内容：

```

This handles running `docker build` commands for both the Notes and user authentication services. It is expected to be executed in the `ecr` directory and takes care of executing commands in both the `notes` and `users` directories.

Let's now create and delete a pair of registries to hold our images. We have two images to upload to the ECR, and therefore we create two registries. 

Create a file named `create.sh` containing the following:

```

还要创建一个名为`delete.sh`的伴随文件，其中包含以下内容：

```

Between these scripts, we can create and delete the ECR repositories for our Docker images. These scripts are directly usable on Windows; simply change the filenames to `create.ps1` and `delete.ps1`.

In `aws ecr delete-repository`, the `--force` option means to delete the repositories even if they contain images.

With the scripts we've written so far, they are executed in the following order:

```

`aws ecr create-repository`命令会输出这些镜像存储库的描述符。需要注意的重要数据是`repositoryUri`值。这将在稍后的 Docker 堆栈文件中用于命名要检索的镜像。

`create.sh` 脚本只需要执行一次。

除了创建仓库，工作流程如下：

+   构建图像，我们已经创建了一个名为 `build.sh` 的脚本。

+   使用 ECR 仓库的**统一资源标识符**（**URI**）标记图像。

+   将图像推送到 ECR 仓库。

对于后两个步骤，我们仍然有一些脚本要创建。

创建一个名为 `tag.sh` 的文件，其中包含以下内容：

```

The `docker tag` command we have here takes `svc-notes:latest`, or `svc-userauth:latest`, and adds what's called a target image to the local image storage area. The target image name we've used is the same as what will be stored in the ECR repository.

For Windows, you should create a file named `tag.ps1` using the same commands, but with Windows-style environment variable references.

Then, create a file named `push.sh` containing the following:

```

`docker push` 命令会将目标图像发送到 ECR 仓库。同样，对于 Windows，创建一个名为 `push.ps1` 的文件，其中包含相同的命令，但使用 Windows 风格的环境变量引用。

在 `tag` 和 `push` 脚本中，我们使用了仓库 URI 值，但插入了两个环境变量。这将使其在我们将 Notes 部署到另一个 AWS 区域时变得通用。

我们已经将工作流程实现为脚本，现在让我们看看如何运行它，如下：

```

This builds the Docker images. When we run `docker build`, it stores the built image in an area on our laptop where Docker maintains images. We can inspect that area using the `docker images` command, like this:

```

如果我们没有指定标签，`docker build` 命令会自动添加标签 `latest`。

然后，要将图像推送到 ECR 仓库，我们执行以下命令：

```

Since the images are rather large, it will take a long time to upload them to the AWS ECR. We should add a task to the backlog to explore ways to trim Docker image sizes. In any case, expect this to take a while. 

After a period of time, the images will be uploaded to the ECR repositories, and you can inspect the results on the ECR dashboard.

Once the Docker images are pushed to the AWS ECR repository, we no longer need to stay with the default Docker context. You will be free to run the following command at any time:

```

请记住，不要使用 swarm 主机构建 Docker 图像。在本节开始时，我们切换到默认上下文，以便构建发生在我们的笔记本电脑上。

在本节中，我们学习了如何设置构建过程，将我们的 Docker 图像推送到 AWS ECR 服务的仓库。这包括使用一些有趣的工具，简化了在 `package.json` 脚本中构建复杂构建过程。

我们的下一步是学习如何使用 Docker compose 文件来描述在 Docker Swarm 上的部署。

# 为部署到 Docker Swarm 创建 Docker stack 文件

在之前的章节中，我们学习了如何使用 Terraform 设置 AWS 基础架构。我们设计了一个将容纳 Notes 应用程序堆栈的 VPC，我们在单个 EC2 实例上构建了单节点 Docker Swarm 集群，并设置了一个将 Docker 图像推送到 ECR 的过程。

我们的下一个任务是为部署到 swarm 准备一个 Docker stack 文件。一个 stack 文件几乎与我们在第十一章中使用的 Docker compose 文件相同，*使用 Docker 部署 Node.js 微服务*。Compose 文件用于普通的 Docker 主机，而 stack 文件用于 swarm。为了使其成为一个 stack 文件，我们添加了一些新的标签并更改了一些内容，包括网络实现。

之前，我们使用 `docker service create` 命令测试了 Docker Swarm，以在 swarm 上启动一个服务。虽然这很容易，但它并不构成可以提交到源代码库的代码，也不是一个自动化的过程。

在 swarm 模式下，服务是在 swarm 节点上执行任务的定义。每个服务由若干任务组成，这个数量取决于副本设置。每个任务是部署到 swarm 中的节点上的容器。当然，还有其他配置参数，如网络端口、卷连接和环境变量。

Docker 平台允许使用 compose 文件将服务部署到 swarm。这种情况下，compose 文件被称为 stack 文件。有一组用于处理 stack 文件的 `docker stack` 命令，如下：

+   在普通的 Docker 主机上，`docker-compose.yml` 文件称为 compose 文件。我们在 compose 文件上使用 `docker-compose` 命令。

+   在 Docker swarm 上，`docker-compose.yml` 文件称为 stack 文件。我们在 stack 文件上使用 `docker stack` 命令。

请记住，Compose 文件有一个`services`标签，该标签中的每个条目都是要部署的容器配置。当用作堆栈文件时，`services`标签中的每个条目当然是刚才描述的服务。这意味着就像`docker run`命令和 Compose 文件中的容器定义之间有很多相似之处一样，`docker service create`命令和堆栈文件中的服务条目之间也有一定程度的相似性。

一个重要的考虑是构建不应该发生在 Swarm 主机上的策略。相反，这些机器必须仅用于部署和执行容器。这意味着堆栈文件中列出的服务中的任何`build`标签都会被忽略。相反，有一个`deploy`标签，用于在 Swarm 中部署的参数，当文件与 Compose 一起使用时，`deploy`标签会被忽略。更简单地说，我们可以将同一个文件同时用作 Compose 文件（使用`docker compose`命令）和堆栈文件（使用`docker stack`命令），具有以下条件：

+   当用作 Compose 文件时，使用`build`标签，忽略`deploy`标签。

+   当用作堆栈文件时，忽略`build`标签，使用`deploy`标签。

这一政策的另一个后果是根据需要切换 Docker 上下文的必要性。我们已经讨论过这个问题——我们在笔记本上使用*默认*的 Docker 上下文构建镜像，当与 AWS EC2 实例上的 Swarm 进行交互时，我们使用 EC2 上下文。

要开始，创建一个名为`compose-stack`的目录，它是`compose-local`，`notes`，`terraform-swarm`和其他目录的同级目录。然后，将`compose-local/docker-compose.yml`复制到`compose-stack`中。这样，我们可以从我们知道工作良好的东西开始。

这意味着我们将从我们的 Compose 文件创建一个 Docker 堆栈文件。这涉及到几个步骤，我们将在接下来的几个部分中进行介绍。这包括添加部署标签，为 Swarm 配置网络，控制 Swarm 中服务的位置，将秘密存储在 Swarm 中，以及其他任务。

## 从 Notes Docker compose 文件创建 Docker 堆栈文件

有了这个理论基础，现在让我们来看看现有的 Docker compose 文件，并了解如何使其对部署到 Swarm 有用。

由于我们将需要一些高级的`docker-compose.yml`功能，将版本号更新为以下内容：

```

For the Compose file we started with, version `'3'` was adequate, but to accomplish the tasks in this chapter the higher version number is required, to enable newer features.

Fortunately, most of this is straightforward and will require very little code.

*Deployment parameters*: These are expressed in the `deploy` tag, which covers things such as the number of replicas, and memory or CPU requirements. For documentation, refer to [`docs.docker.com/compose/compose-file/#deploy`](https://docs.docker.com/compose/compose-file/#deploy).

For the deployment parameters, simply add a `deploy` tag to each service. Most of the options for this tag have perfectly reasonable defaults. To start with, let's add this to every service, as follows:

```

这告诉 Docker 我们想要每个服务的一个实例。稍后，我们将尝试添加更多的服务实例。我们稍后会添加其他参数，比如放置约束。稍后，我们将尝试为`svc-notes`和`svc-userauth`添加多个副本。将服务的 CPU 和内存限制放在服务上是很诱人的，但这并不是必要的。

很高兴得知，使用 Swarm 模式，我们可以简单地更改`replicas`设置来更改实例的数量。

接下来要注意的是镜像名称。虽然存在`build`标签，但要记住它会被忽略。对于 Redis 和数据库容器，我们已经在 Docker Hub 中使用镜像，但对于`svc-notes`和`svc-userauth`，我们正在构建自己的容器。这就是为什么在本章的前面，我们设置了将镜像推送到 ECR 存储库的程序。现在我们可以从堆栈文件中引用这些镜像。这意味着我们必须进行以下更改：

```

If we use this with `docker-compose`, it will perform the build in the named directories, and then tag the resulting image with the tag in the `image` field. In this case, the `deploy` tag will be ignored as well. However, if we use this with `docker stack deploy`, the `build` tag will be ignored, and the images will be downloaded from the repositories listed in the `image` tag. In this case, the `deploy` tag will be used.

For documentation on the `build` tag, refer to [`docs.docker.com/compose/compose-file/#build`](https://docs.docker.com/compose/compose-file/#build). For documentation on the `image` tag, refer to [`docs.docker.com/compose/compose-file/#image`](https://docs.docker.com/compose/compose-file/#image)[.](https://docs.docker.com/compose/compose-file/#build)

When running the compose file on our laptop, we used `bridge` networking. This works fine for a single host, but with swarm mode, we need another network mode that handles multi-host deployments. The Docker documentation clearly says to use the `overlay` driver in swarm mode, and the `bridge` driver for a single-host deployment. 

*Virtual networking for containers*: Since `bridge` networking is designed for a single-host deployment, we must use `overlay` networking in swarm mode. For documentation, refer to [`docs.docker.com/compose/compose-file/#network-configuration-reference`](https://docs.docker.com/compose/compose-file/#network-configuration-reference).

To use overlay networking, change the `networks` tag to the following:

```

为了支持在 Swarm 中使用这个文件，或者用于单主机部署，我们可以保留`bridge`网络设置，但将其注释掉。然后，根据上下文的不同，我们可以更改哪个被注释掉，从而改变`overlay`或`bridge`网络的活动状态。

`overlay`网络驱动程序在 Swarm 节点之间设置了一个虚拟网络。这个网络支持容器之间的通信，也方便访问外部发布的端口。

`overlay`网络配置了集群中的容器自动分配与服务名称匹配的域名。与之前使用的`bridge`网络一样，容器通过域名相互找到。对于部署多个实例的服务，`overlay`网络确保可以将请求路由到该容器的任何实例。如果连接到一个容器，但在同一主机上没有该容器的实例，`overlay`网络将请求路由到另一台主机上的实例。这是一种简单的服务发现方法，通过使用域名，但在集群中跨多个主机进行扩展。

这解决了将 compose 文件转换为堆栈文件的简单任务。然而，还有一些其他任务需要更多的注意。

### 在集群中放置容器

我们还没有这样做，但我们将向集群添加多个 EC2 实例。默认情况下，集群模式会在集群节点上均匀分配任务（容器）。然而，我们有两个考虑因素，应该强制一些容器部署在特定的 Docker 主机上，即以下：

1.  我们有两个数据库容器，需要为数据文件安排持久存储。这意味着数据库必须每次部署到相同的实例，以便它可以使用相同的数据目录。

1.  名为`notes-public`的公共 EC2 实例将成为集群的一部分。为了维护安全模型，大多数服务不应该部署在这个实例上，而是应该部署在将附加到私有子网的实例上。因此，我们应该严格控制哪些容器部署到`notes-public`。

Swarm 模式允许我们声明任何服务的放置要求。有几种实现方式，例如匹配主机名或分配给每个节点的标签。

有关堆栈文件`placement`标签的文档，请参阅[`docs.docker.com/compose/compose-file/#placement`](https://docs.docker.com/compose/compose-file/#placement)。[](https://docs.docker.com/compose/compose-file/#placement) `docker stack create`命令的文档包括对部署参数的进一步解释：[ ](https://docs.docker.com/compose/compose-file/#placement)[`docs.docker.com/engine/reference/commandline/service_create`](https://docs.docker.com/engine/reference/commandline/service_create)。

将`deploy`标签添加到`db-userauth`服务声明中：

```

The `placement` tag governs where the containers are deployed. Rather than Docker evenly distributing the containers, we can influence the placement with the fields in this tag. In this case, we have two examples, such as deploying a container to a specific node based on the hostname or selecting a node based on the labels attached to the node.

To set a label on a Docker swarm node, we run the following command:

```

此命令将标签命名为`type`，值为`public`，附加到名为`notes-public`的节点上。我们使用这个来设置标签，正如你所看到的，标签可以有任何名称和任何值。然后可以使用标签和其他属性来影响容器在集群节点上的放置。

对于堆栈文件的其余部分，添加以下放置约束：

```

This gives us three labels to assign to our EC2 instances: `db`, `svc`, and `public`. These constraints will cause the databases to be placed on nodes where the `type` label is `db`, the user authentication service is on the node of type `svc`, the Notes service is on the `public` node, and the Redis service is on any node that is not the `public` node.

The reasoning stems from the security model we designed. The containers deployed on the private network should be more secure behind more layers of protection. This placement leaves the Notes container as the only one on the public EC2 instance. The other containers are split between the `db` and `svc` nodes. We'll see later how these labels will be assigned to the EC2 instances we'll create.

### Configuring secrets in Docker Swarm

With Notes, as is true for many kinds of applications, there are some secrets we must protect. Primarily, this is the Twitter authentication tokens, and we've claimed it could be a company-ending event if those tokens were to leak to the public. Maybe that's overstating the danger, but leaked credentials could be bad. Therefore, we must take measures to ensure that those secrets do not get committed to a source repository as part of any source code, nor should they be recorded in any other file.

For example, the Terraform state file records all information about the infrastructure, and the Terraform team makes no effort to detect any secrets and suppress recording them. It's up to us to make sure the Terraform state file does not get committed to source code control as a result.

Docker Swarm supports a very interesting method for securely storing secrets and for making them available in a secure manner in containers.

The process starts with the following command:

```

这就是我们在 Docker 集群中存储秘密的方法。`docker secret create`命令首先需要秘密的名称，然后是包含秘密文本的文件的说明符。这意味着我们可以将秘密的数据存储在文件中，或者—就像在这种情况下一样—我们使用`-`来指定数据来自标准输入。在这种情况下，我们使用`printf`命令，它适用于 macOS 和 Linux，将值发送到标准输入。

Docker Swarm 安全地记录加密数据作为秘密。一旦您将秘密交给 Docker，您就无法检查该秘密的价值。

在`compose-stack/docker-compose.yml`中，在最后添加此声明：

```

This lets Docker know that this stack requires the value of those two secrets. 

The declaration for `svc-notes` also needs the following command:

```

这通知了集群 Notes 服务需要这两个秘密。作为回应，集群将使秘密的数据在容器的文件系统中可用，如`/var/run/secrets/TWITTER_CONSUMER_KEY`和`/var/run/secrets/TWITTER_CONSUMER_SECRET`。它们被存储为内存文件，相对安全。

总结一下，所需的步骤如下：

+   使用`docker secret create`在 Swarm 中注册秘密数据。

+   在堆栈文件中，在顶级秘密标签中声明`secrets`。

+   在需要秘密的服务中，声明一个`secrets`标签，列出此服务所需的秘密。

+   在服务的环境标签中，创建一个指向`secrets`文件的环境变量。

Docker 团队对环境变量配置有一个建议的约定。您可以直接在环境变量中提供配置设置，例如`TWITTER_CONSUMER_KEY`。但是，如果配置设置在文件中，则文件名应该在不同的环境变量中给出，其名称附加了`_FILE`。例如，我们将使用`TWITTER_CONSUMER_KEY`或`TWITTER_CONSUMER_KEY_FILE`，具体取决于值是直接提供还是在文件中。

这意味着我们必须重写 Notes 以支持从文件中读取这些值，除了现有的环境变量。

为了支持从文件中读取，将此导入添加到`notes/routes/users.mjs`的顶部：

```

Then, we'll find the code corresponding to these environment variables further down the file. We should rewrite that section as follows:

```

这与我们已经使用过的代码类似，但组织方式有点不同。它首先尝试从环境中读取 Twitter 令牌。如果失败，它会尝试从命名文件中读取。因为这段代码是在全局上下文中执行的，所以我们必须使用`readFileSync`来读取文件。

如果令牌可以从任一来源获取，则设置`twitterLogin`变量，然后我们启用对`TwitterStrategy`的支持。否则，Twitter 支持将被禁用。我们已经组织了视图模板，以便如果`twitterLogin`为`false`，则 Twitter 登录按钮不会出现。

这就是我们在第八章中所做的，*使用微服务对用户进行身份验证*，但增加了从文件中读取令牌。

### 在 Docker Swarm 中持久化数据

我们在第十一章中使用的数据持久化策略，*使用 Docker 部署 Node.js 微服务*，需要将数据库文件存储在卷中。卷的目录位于容器之外，并且在我们销毁和重新创建容器时仍然存在。

该策略依赖于有一个单一的 Docker 主机来运行容器。卷数据存储在主机文件系统的目录中。但在 Swarm 模式下，卷不以兼容的方式工作。

使用 Docker Swarm，除非我们使用放置标准，否则容器可以部署到任何 Swarm 节点。 Docker 中命名卷的默认行为是数据存储在当前 Docker 主机上。如果容器被重新部署，那么卷将在一个主机上被销毁，并在新主机上创建一个新的卷。显然，这意味着该卷中的数据不是持久的。

有关在 Docker Swarm 中使用卷的文档，请参阅[`docs.docker.com/compose/compose-file/#volumes-for-services-swarms-and-stack-files`](https://docs.docker.com/compose/compose-file/#volumes-for-services-swarms-and-stack-files)。

文档中建议的做法是使用放置标准来强制这些容器部署到特定的主机。例如，我们之前讨论的标准将数据库部署到具有`type`标签等于`db`的节点。

在下一节中，我们将确保 Swarm 中恰好有一个这样的节点。为了确保数据库数据目录位于已知位置，让我们更改`db-userauth`和`db-notes`容器的声明，如下所示：

```

In `docker-local/docker-compose.yml`, we used the named volumes, `db-userauth-data` and `db-notes-data`. The top-level `volumes` tag is required when doing this. In `docker-swarm/docker-compose.yml`, we've commented all of that out. Instead, we are using a `bind` mount, to mount specific host directories in the `/var/lib/mysql` directory of each database.

Therefore, the database data directories will be in `/data/users` and `/data/notes`, respectively.

This result is fairly good, in that we can destroy and recreate the database containers at will and the data directories will persist. However, this is only as persistent as the EC2 instance this is deployed to. The data directories will vaporize as soon as we execute `terraform destroy`.

That's obviously not good enough for a production deployment, but it is good enough for a test deployment such as this. 

It is preferable to use a volume instead of the `bind` mount we just implemented. Docker volumes have a number of advantages, but to make good use of a volume requires finding the right volume driver for your needs. Two examples are as follows:

1.  In the Docker documentation, at [`docs.docker.com/storage/volumes/`](https://docs.docker.com/storage/volumes/), there is an example of mounting a **Network File System** (**NFS**) volume in a Docker container. AWS offers an NFS service—the **Elastic Filesystem** (**EFS**) service—that could be used, but this may not be the best choice for a database container.
2.  The REX-Ray project ([`github.com/rexray/rexray`](https://github.com/rexray/rexray)) aims to advance the state of the art for persistent data storage in various containerization systems, including Docker.

Another option is to completely skip running our own database containers and instead use the **Relational Database Service** (**RDS**). RDS is an AWS service offering several **Structured Query Language** (**SQL**) database solutions, including MySQL. It offers a lot of flexibility and scalability, at a price. To use this, you would eliminate the `db-notes` and `db-userauth` containers, provision RDS instances, and then update the `SEQUELIZE_CONNECT` configuration in `svc-notes` and `svc-userauth` to use the database host, username, and password you configured in the RDS instances.

For our current requirements, this setup, with a `bind` mount to a directory on the EC2 host, will suffice. These other options are here for your further exploration.

In this section, we converted our Docker compose file to be useful as a stack file. While doing this, we discussed the need to influence which swarm host has which containers. The most critical thing is ensuring that the database containers are deployed to a host where we can easily persist the data—for example, by running a database backup every so often to external storage. We also discussed storing secrets in a secure manner so that they may be used safely by the containers.

At this point, we cannot test the stack file that we've created because we do not have a suitable swarm to deploy to. Our next step is writing the Terraform configuration to provision the EC2 instances. That will give us the Docker swarm that lets us test the stack file.

# Provisioning EC2 instances for a full Docker swarm

So far in this chapter, we have used Terraform to create the required infrastructure on AWS, and then we set up a single-node Docker swarm on an EC2 instance to learn about Docker Swarm. After that, we pushed the Docker images to ECR, and we have set up a Docker stack file for deployment to a swarm. We are ready to set up the EC2 instances required for deploying a full swarm.

Docker Swarm is able to handle Docker deployments to large numbers of host systems. Of course, the Notes application only has delusions of grandeur and doesn't need that many hosts. We'll be able to do everything with three or four EC2 instances. We have declared one so far, and will declare two more that will live on the private subnet. But from this humble beginning, it would be easy to expand to more hosts.

Our goal in this section is to create an infrastructure for deploying Notes on EC2 using Docker Swarm. This will include the following:

*   Configuring additional EC2 instances on the private subnet, installing Docker on those instances, and joining them together in a multi-host Docker Swarm
*   Creating semi-automated scripting, thereby making it easy to deploy and configure the EC2 instances for the swarm
*   Using an `nginx` container on the public EC2 instance as a proxy in front of the Notes container

That's quite a lot of things to take care of, so let's get started.

## Configuring EC2 instances and connecting to the swarm

We have one EC2 instance declared for the public subnet, and it is necessary to add two more for the private subnet. The security model we discussed earlier focused on keeping as much as possible in a private secure network infrastructure. On AWS, that means putting as much as possible on the private subnet.

Earlier, you may have renamed `ec2-public.tf` to `ec2-public.tf-disable`. If so, you should now change back the filename to `ec2-public.tf`. Remember that this tactic is useful for minimizing AWS resource usage when it is not needed.

Create a new file in the `terraform-swarm` directory named `ec2-private.tf`, as follows:

```

这声明了两个附加到私有子网的 EC2 实例。除了名称之外，这些实例之间没有区别。因为它们位于私有子网上，所以它们没有分配公共 IP 地址。

因为我们将`private-db1`实例用于数据库，所以我们为根设备分配了 50GB 的空间。`root_block_device`块用于自定义 EC2 实例的根磁盘。在可用的设置中，`volume_size`设置其大小，以 GB 为单位。

`private-db1`中的另一个区别是`instance_type`，我们已经将其硬编码为`t2.medium`。问题在于将两个数据库容器部署到此服务器。`t2.micro`实例有 1GB 内存，而观察到两个数据库会压倒这台服务器。如果您想要调试这种情况，将此值更改为`var.instance_type`，默认为`t2.micro`，然后阅读本章末尾关于调试发生的情况的部分。

请注意，对于`user_data`脚本，我们只发送安装 Docker 支持的脚本，而不是初始化 swarm 的脚本。swarm 是在公共 EC2 实例中初始化的。其他实例必须使用`docker swarm join`命令加入 swarm。稍后，我们将介绍如何初始化 swarm，并看看如何完成这个过程。对于`public-db1`实例，我们还创建了`/data/notes`和`/data/users`目录，用于保存数据库数据目录。

将以下代码添加到`ec2-private.tf`中：

```

This is the security group for these EC2 instances. It allows any traffic from inside the VPC to enter the EC2 instances. This is the sort of security group we'd create when in a hurry and should tighten up the ingress rules, since this is very lax.

Likewise, the `ec2-public-sg` security group needs to be equally lax. We'll find that there is a long list of IP ports used by Docker Swarm and that the swarm will fail to operate unless those ports can communicate. For our immediate purposes, the easiest option is to allow any traffic, and we'll leave a note in the backlog to address this issue in Chapter 14, *Security in Node.js Applications*.

In `ec2-public.tf`, edit the `ec2-public-sg` security group to be the following:

```

这实际上不是最佳实践，因为它允许来自任何 IP 地址的任何网络流量到达公共 EC2 实例。但是，这确实给了我们在此时开发代码而不担心协议的自由。我们稍后会解决这个问题并实施最佳安全实践。看一下以下代码片段：

```

This outputs the useful attributes of the EC2 instances.

In this section, we declared EC2 instances for deployment on the private subnet. Each will have Docker initialized. However, we still need to do what we can to automate the setup of the swarm.

## Implementing semi-automatic initialization of the Docker Swarm

Ideally, when we run `terraform apply`, the infrastructure is automatically set up and ready to go. Automated setup reduces the overhead of running and maintaining the AWS infrastructure. We'll get as close to that goal as possible.

For this purpose, let's revisit the declaration of `aws_instance.public` in `ec2-public.tf`. Let's rewrite it as follows:

```

这基本上与以前一样，但有两个更改。第一个是向`depends_on`属性添加对私有 EC2 实例的引用。这将延迟公共 EC2 实例的构建，直到其他两个实例正在运行。

另一个更改是扩展附加到`user_data`属性的 shell 脚本。该脚本的第一个添加是在`notes-public`节点上设置`type`标签。该标签与服务放置一起使用。

最后的更改是一个脚本，我们将用它来设置 swarm。我们将生成一个脚本来创建 swarm，而不是直接在`user_data`脚本中设置 swarm。在`sh`目录中，创建一个名为`swarm-setup.sh`的文件，其中包含以下内容：

```

This generates a shell script that will be used to initialize the swarm. Because the setup relies on executing commands on the other EC2 instances, the PEM file for the AWS key pair must be present on the `notes-public` instance. However, it is not possible to send the key-pair file to the `notes-public` instance when running `terraform apply`. Therefore, we use the pattern of generating a shell script, which will be run later.

The pattern being followed is shown in the following code snippet:

```

`<<EOF`和`EOF`之间的部分作为`cat`命令的标准输入提供。因此，`/home/ubuntu/swarm-setup.sh`最终会以这些标记之间的文本结束。另一个细节是一些变量引用被转义，如`PEM=\$1`。这是必要的，以便在设置此脚本时不评估这些变量，但在生成的脚本中存在。

此脚本使用`templatefile`函数进行处理，以便我们可以使用模板命令。主要是使用`%{for .. }`循环生成配置每个 EC2 实例的命令。您会注意到每个实例都有一个数据数组，通过`templatefile`调用传递。

因此，`swarm-setup.sh`脚本将包含每个 EC2 实例的以下一对命令的副本：

```

The first line uses SSH to execute the `swarm join` command on the EC2 instance. For this to work, we need to supply the AWS key pair, which must be specified on the command file so that it becomes the `PEM` variable. The second line adds the `type` label with the named value to the named swarm node.

What is the `$join` variable? It has the output of running `docker swarm join-token`, so let's take a look at what it is.

Docker uses a swarm join token to facilitate connecting Docker hosts as a node in a swarm. The token contains cryptographically signed information that authenticates the attempt to join the swarm. We get the token by running the following command:

```

这里的`manager`一词意味着我们正在请求一个作为管理节点加入的令牌。要将节点连接为工作节点，只需将`manager`替换为`worker`。

一旦 EC2 实例部署完成，我们可以登录到`notes-public`，然后运行此命令获取加入令牌，并在每个 EC2 实例上运行该命令。然而，`swarm-setup.sh`脚本会为我们处理这一切。一旦 EC2 主机部署完成，我们所要做的就是登录到`notes-public`并运行此脚本。

它运行`docker swarm join-token manager`命令，通过一些`sed`命令将用户友好的文本提取出来。这样就留下了`join`变量，其中包含`docker swarm join`命令的文本，然后使用 SSH 在每个实例上执行该命令。

在本节中，我们研究了如何尽可能自动化 Docker swarm 的设置。

现在让我们来做吧。

## 在部署 Notes 堆栈之前准备 Docker Swarm

当您制作煎蛋卷时，最好在加热平底锅之前切好所有的蔬菜和香肠，准备好黄油，将牛奶和鸡蛋搅拌成混合物。换句话说，我们在进行关键操作之前准备好了所有的配料。到目前为止，我们已经准备好了成功将 Notes 堆栈部署到 AWS 上使用 Docker Swarm 的所有要素。现在是时候打开平底锅，看看它的效果如何了。

我们在 Terraform 文件中声明了所有内容，可以使用以下命令部署我们的完整系统：

```

This deploys the EC2 instances on AWS. Make sure to record all the output parameters. We're especially interested in the domain names and IP addresses for the three EC2 instances.

As before, the `notes-public` instance should have a Docker swarm initialized. We have added two more instances, `notes-private-db1` and `notes-private-svc1`. Both will have Docker installed, but they are not joined to the swarm. Instead, we need to run the generated shell script for them to become nodes in the swarm, as follows:

```

我们已经在我们的笔记本电脑上运行了`ssh-add`，因此 SSH 和**安全复制**（**SCP**）命令可以在不明确引用 PEM 文件的情况下运行。然而，`notes-public` EC2 实例上的 SSH 没有 PEM 文件。因此，为了访问其他 EC2 实例，我们需要 PEM 文件可用。因此，我们使用了`scp`将其复制到`notes-public`实例上。

如果您想验证实例正在运行并且 Docker 处于活动状态，请输入以下命令：

```

In this case, we are testing the private EC2 instances from a shell running on the public EC2 instance. That means we must use the private IP addresses printed when we ran Terraform. This command verifies SSH connectivity to an EC2 instance and verifies its ability to download and execute a Docker image.

Next, we can run `swarm-setup.sh`. On the command line, we must give the filename for the PEM file as the first argument, as follows:

```

我们可以使用 SSH 在每个 EC2 实例上执行`docker swarm join`命令来看到这一点，从而使这两个系统加入到 swarm 中，并在实例上设置标签，如下面的代码片段所示：

```

Indeed, these systems are now part of the cluster. 

The swarm is ready to go, and we no longer need to be logged in to `notes-public`. Exiting back to our laptop, we can create the Docker context to control the swarm remotely, as follows:

```

我们已经看到了这是如何工作的，这样做之后，我们将能够在我们的笔记本电脑上运行 Docker 命令；例如，看一下下面的代码片段：

```

From our laptop, we can query the state of the remote swarm that's hosted on AWS. Of course, this isn't limited to querying the state; we can run any other Docker command.

We also need to run the following commands, now that the swarm is set up:

```

请记住，新创建的 swarm 没有任何秘密。要安装秘密，需要重新运行这些命令。

如果您希望创建一个 shell 脚本来自动化这个过程，请考虑以下内容：

```

This script executes the same commands we just went over to prepare the swarm on the EC2 hosts. It requires the environment variables to be set, as follows:

*   `AWS_KEY_PAIR`: The filename for the PEM file
*   `NOTES_PUBLIC_IP`: The IP address of the `notes-public` EC2 instance
*   `TWITTER_CONSUMER_KEY`, `TWITTER_CONSUMER_SECRET`: The access tokens for Twitter authentication

In this section, we have deployed more EC2 instances and set up the Docker swarm. While the process was not completely automated, it's very close. All that's required, after using Terraform to deploy the infrastructure, is to execute a couple of commands to get logged in to `notes-public` where we run a script, and then go back to our laptop to set up remote access.

We have set up the EC2 instances and verified we have a working swarm. We still have the outstanding issue of verifying the Docker stack file created in the previous section. To do so, our next step is to deploy the Notes app on the swarm.

# Deploying the Notes stack file to the swarm

We have prepared all the elements required to set up a Docker Swarm on the AWS EC2 infrastructure, we have run the scripts required to set up that infrastructure, and we have created the stack file required to deploy Notes to the swarm.

What's required next is to run `docker stack deploy` from our laptop, to deploy Notes on the swarm. This will give us the chance to test the stack file created earlier. You should still have the Docker context configured for the remote server, making it possible to remotely deploy the stack. However, there are four things to handle first, as follows:

1.  Install the secrets in the newly deployed swarm.
2.  Update the `svc-notes` environment configuration for the IP address of `notes-public`.
3.  Update the Twitter application for the IP address of `notes-public`.
4.  Log in to the ECR instance.

Let's take care of those things and then deploy the Notes stack.

## Preparing to deploy the Notes stack to the swarm

We are ready to deploy the Notes stack to the swarm that we've launched. However, we have realized that we have a couple of tasks to take care of.

The environment variables for `svc-notes` configuration require a little adjustment. Have a look at the following code block:

```

我们的主要要求是调整`TWITTER_CALLBACK_HOST`变量。`notes-public`实例的域名在每次部署 AWS 基础设施时都会更改。因此，`TWITTER_CALLBACK_HOST`必须更新以匹配。

同样，我们必须转到 Twitter 开发者仪表板并更新应用程序设置中的 URL。正如我们已经知道的那样，每当我们在不同的 IP 地址或域名上托管 Notes 时，都需要这样做。要使用 Twitter 登录，我们必须更改 Twitter 识别的 URL 列表。

更新`TWITTER_CALLBACK_HOST`和 Twitter 应用程序设置将让我们使用 Twitter 帐户登录到 Notes。

在这里，我们应该审查其他变量，并确保它们也是正确的。

最后的准备步骤是登录到 ECR 存储库。要做到这一点，只需执行以下命令：

```

This has to be rerun every so often since the tokens that are downloaded time out after a few hours.

We only need to run `login.sh`, and none of the other scripts in the `ecr` directory.

In this section, we prepared to run the deployment. We should now be ready to deploy Notes to the swarm, so let's do it.

## Deploying the Notes stack to the swarm

We just did the final preparation for deploying the Notes stack to the swarm. Take a deep breath, yell out *Smoke Test*, and type the following command:

```

这部署了服务，swarm 通过尝试启动每个服务来做出响应。`--with-registry-auth`选项将 Docker Registry 身份验证发送到 swarm，以便它可以从 ECR 存储库下载容器映像。这就是为什么我们必须先登录到 ECR。

### 验证 Notes 应用程序堆栈的正确启动

使用以下命令来监视启动过程将会很有用：

```

The `service ls` command lists the services, with a high-level overview. Remember that the service is not the running container and, instead, the services are declared by entries in the `services` tag in the stack file. In our case, we declared one replica for each service, but we could have given a different amount. If so, the swarm will attempt to distribute that number of containers across the nodes in the swarm.

Notice that the pattern for service names is the name of the stack that was given in the `docker stack deploy` command, followed by the service name listed in the stack file. When running that command, we named the stack `notes`; so, the services are `notes_db-notes`, `notes_svc-userauth`, `notes_redis`, and so on.

The `service ps` command lists information about the tasks deployed for the service. Remember that a task is essentially the same as a running container. We see here that one instance of the `svc-notes` container has been deployed, as expected, on the `notes-public` host.

Sometimes, the `notes_svc-notes` service doesn't launch, and instead, we'll see the following message:

```

错误`no suitable node`意味着 swarm 无法找到符合放置条件的节点。在这种情况下，`type=public`标签可能没有正确设置。

以下命令很有帮助：

```

Notice that the `Labels` entry is empty. In such a case, you can add the label by running this command:

```

一旦运行了这个命令，swarm 将在`notes-public`节点上放置`svc-notes`服务。

如果发生这种情况，将以下命令添加到`aws_instance.public`的`user_data`脚本中可能会有用（在`ec2-public.tf`中），就在设置`type=public`标签之前：

```

It would appear that this provides a small window of opportunity to allow the swarm to establish itself.

### Diagnosing a failure to launch the database services

Another possible deployment problem is that the database services might fail to launch, and the `notes-public-db1` node might become `Unavailable`. Refer back to the `docker node ls` output and you will see a column marked `Status`. Normally, this column says `Reachable`, meaning that the swarm can reach and communicate with the swarm agent on that node. But with the deployment as it stands, this node might instead show an `Unavailable` status, and in the `docker service ls` output, the database services might never show as having deployed.

With remote access from our laptop, we can run the following command:

```

输出将告诉您当前的状态，例如部署服务时的任何错误。但是，要调查与 EC2 实例的连接，我们必须登录到`notes-public`实例，如下所示：

```

That gets us access to the public EC2 instance. From there, we can try to ping the `notes-private-db1` instance, as follows:

```

这应该可以工作，但是`docker node ls`的输出可能会显示节点为`Unreachable`。问问自己：如果一台计算机内存不足会发生什么？然后，认识到我们已经将两个数据库实例部署到只有 1GB 内存的 EC2 实例上——这是写作时` t2.micro` EC2 实例的内存容量。问问自己，您是否可能已经部署到给定服务器的服务已经超负荷了该服务器。

要测试这个理论，在`ec2-private.tf`中进行以下更改：

```

This changes the instance type from `t2.micro` to `t2.medium`, or even `t2.large`, thereby giving the server more memory.

To implement this change, run `terraform apply` to update the configuration. If the swarm does not automatically correct itself, then you may need to run `terraform destroy` and then run through the setup again, starting with `terraform apply`. 

Once the `notes-private-db1` instance has sufficient memory, the databases should successfully deploy.

In this section, we deployed the Notes application stack to the swarm cluster on AWS. We also talked a little about how to verify the fact that the stack deployed correctly, and how to handle some common problems.

Next, we have to test the deployed Notes stack to verify that it works on AWS.

## Testing the deployed Notes application

Having set up everything required to deploy Notes to AWS using Docker Swarm, we have done so. That means our next step is to put Notes through its paces. We've done enough ad hoc testing on our laptop to have confidence it works, but the Docker swarm deployment might show up some issues.

In fact, the deployment we just made very likely has one or two problems. We can learn a lot about AWS and Docker Swarm by diagnosing those problems together.

The first test is obviously to open the Notes application in the browser. In the outputs from running `terraform apply` was a value labeled `ec2-public-dns`. This is the domain name for the `notes-public` EC2 instance. If we simply paste that domain name into our browser, the Notes application should appear.

However, we cannot do anything because there are no user IDs available to log in with.

### Logging in with a regular account on Notes

Obviously, in order to test Notes, we must log in and add some notes, make some comments, and so forth. It will be instructive to log in to the user authentication service and use `cli.mjs` to add a user ID.

The user authentication service is on one of the private EC2 instances, and its port is purposely not exposed to the internet. We could change the configuration to expose its port and then run `cli.mjs` from our laptop, but that would be a security problem and we need to learn how to access the running containers anyway.

We can find out which node the service is deployed on by using the following command:

```

`notes_svc-userauth`任务已部署到`notes-private-svc1`，正如预期的那样。

要运行`cli.mjs`，我们必须在容器内部获得 shell 访问权限。由于它部署在私有实例上，这意味着我们必须首先 SSH 到`notes-public`实例；然后从那里 SSH 到`notes-private-svc1`实例；然后在那里运行`docker exec`命令，在运行的容器中启动一个 shell，如下面的代码块所示：

```

We SSHd to the `notes-public` server and, from there, SSHd to the `notes-private-svc1` server. On that server, we ran `docker ps` to find out the name of the running container. Notice that Docker generated a container name that includes a coded string, called a *nonce*, that guarantees the container name is unique. With that container name, we ran `docker exec -it ... bash` to get a root shell inside the container.

Once there, we can run the following command:

```

这验证了用户认证服务器的工作，并且它可以与数据库通信。为了进一步验证这一点，我们可以访问数据库实例，如下所示：

```

From there, we can explore the database and see that, indeed, Ashildr's user ID exists.

With this user ID set up, we can now use our browser to visit the Notes application and log in with that user ID.

### Diagnosing an inability to log in with Twitter credentials

The next step will be to test logging in with Twitter credentials. Remember that earlier, we said to ensure that the `TWITTER_CALLBACK_HOST` variable has the domain name of the EC2 instance, and likewise that the Twitter application configuration does as well. 

Even with those settings in place, we might run into a problem. Instead of logging in, we might get an error page with a stack trace, starting with the message: `Failed to obtain request token`. 

There are a number of possible issues that can cause this error. For example, the error can occur if the Twitter authentication tokens are not deployed. However, if you followed the directions correctly, they will be deployed correctly.

In `notes/appsupport.mjs`, there is a function, `basicErrorHandler`, which will be invoked by this error. In that function, add this line of code:

```

这将打印完整的错误，包括导致失败的原始错误。您可能会看到打印的以下消息：`getaddrinfo EAI_AGAIN api.twitter.com`。这可能令人困惑，因为该域名肯定是可用的。但是，由于 DNS 配置的原因，它可能在`svc-notes`容器内部不可用。

从`notes-public`实例，我们将能够 ping 该域名，如下所示：

```

However, if we attempt this inside the `svc-notes` container, this might fail, as illustrated in the following code snippet:

```

理想情况下，这也将在容器内部起作用。如果在容器内部失败，这意味着 Notes 服务无法访问 Twitter 以处理使用 Twitter 凭据登录所需的 OAuth 过程。

问题在于，在这种情况下，Docker 设置了不正确的 DNS 配置，容器无法为许多域名进行 DNS 查询。在 Docker Compose 文档中，建议在服务定义中使用以下代码：

```

These two DNS servers are operated by Google, and indeed this solves the problem. Once this change has been made, you should be able to log in to Notes using Twitter credentials.

In this section, we tested the Notes application and discussed how to diagnose and remedy a couple of common problems. While doing so, we learned how to navigate our way around the EC2 instances and the Docker Swarm.

Let's now see what happens if we change the number of instances for our services.

## Scaling the Notes instances

By now, we have deployed the Notes stack to the cluster on our EC2 instances. We have tested everything and know that we have a correctly functioning system deployed on AWS. Our next task is to increase the number of instances and see what happens.

To increase the instances for `svc-notes`, edit `compose-swarm/docker-compose.yml` as follows:

```

这会增加副本的数量。由于现有的放置约束，两个实例都将部署到具有`type`标签`public`的节点上。要更新服务，只需要重新运行以下命令：

```

Earlier, this command described its actions with the word *Creating*, and this time it used the word *Updating*. This means that the services are being updated with whatever new settings are in the stack file.

After a few minutes, you may see this:

```

确实，它显示了`svc-notes`服务的两个实例。`2/2`表示两个实例当前正在运行，而请求的实例数为两个。

要查看详细信息，请运行以下命令：

```

As we saw earlier, this command lists to which swarm nodes the service has been deployed. In this case, we'll see that both instances are on `notes-public`, due to the placement constraints.

Another useful command is the following:

```

最终，部署到 Docker 集群的每个服务都包含一个或多个正在运行的容器。

您会注意到这显示`svc-notes`正在端口`3000`上监听。在环境设置中，我们没有设置`PORT`变量，因此`svc-notes`将默认监听端口`3000`。回到`docker service ls`的输出，您应该会看到这个：`*:80->3000/tcp`，这意味着 Docker 正在处理从端口`80`到端口`3000`的映射。

这是由`docker-swarm/docker-compose.yml`中的以下设置引起的：

```

这表示要发布端口`80`并将其映射到容器上的端口`3000`。

在 Docker 文档中，我们了解到在集群中部署的服务可以通过所谓的“路由网格”访问。连接到已发布端口会将连接路由到处理该服务的容器之一。因此，Docker 充当负载均衡器，在您配置的服务实例之间分发流量。

在本节中，我们终于将 Notes 应用程序堆栈部署到了我们在 AWS EC2 实例上构建的云托管环境。我们创建了一个 Docker Swarm，配置了该 Swarm，创建了一个堆栈文件来部署我们的服务，并将其部署到该基础设施上。然后我们测试了部署的系统，并发现它运行良好。

有了这些，我们可以结束本章了。

# 总结

本章是学习 Node.js 应用部署的旅程的最高潮。我们开发了一个仅存在于我们的笔记本电脑上的应用，并添加了许多有用的功能。为了在公共服务器上部署该应用以获得反馈，我们进行了三种类型的部署。在第十章《将 Node.js 应用部署到 Linux 服务器》中，我们学习了如何在 Linux 上使用 PM2 启动持久后台任务。在第十一章《使用 Docker 部署 Node.js 微服务》中，我们学习了如何将 Notes 应用程序堆叠进行 Docker 化，并如何使用 Docker 运行它。

在本章中，我们建立在此基础上，学习了如何在 Docker Swarm 集群上部署我们的 Docker 容器。AWS 是一个功能强大且全面的云托管平台，拥有长长的可用服务列表。我们在 VPC 中使用了 EC2 实例和相关基础设施。

为了实现这一目标，我们使用了 Terraform，这是一种流行的工具，用于描述云部署，不仅适用于 AWS，还适用于许多其他云平台。AWS 和 Terraform 在各种大小的项目中被广泛使用。

在这个过程中，我们学到了很多关于 AWS、Terraform 以及如何使用 Terraform 在 AWS 上部署基础设施；如何设置 Docker Swarm 集群；以及如何在该基础设施上部署多容器服务。

我们首先创建了 AWS 账户，在笔记本电脑上设置了 AWS CLI 工具，并设置了 Terraform。然后我们使用 Terraform 定义了一个 VPC 和网络基础设施，用于部署 EC2 实例。我们学会了如何使用 Terraform 自动化大部分 EC2 配置细节，以便快速初始化 Docker Swarm。

我们了解到 Docker Compose 文件和 Docker 堆栈文件是非常相似的东西。后者与 Docker Swarm 一起使用，是描述 Docker 服务部署的强大工具。

在下一章中，我们将学习单元测试和功能测试。虽然测试驱动开发的核心原则是在编写应用程序之前编写测试，但我们却反其道而行之，将关于单元测试的章节放在了书的最后。这并不是说单元测试不重要，因为它确实很重要。
