# Docker Windows 教程（三）

> 原文：[`zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64`](https://zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：准备将 Docker 用于生产环境

使用 Docker 会导致您的流程和工具发生变化，以便进行生产部署。这样做有很多好处，但也有新的东西需要学习。到*第三部分*结束时，读者将对将他们的应用程序部署到生产环境感到自信。

本节包括以下章节：

+   第八章，*管理和监控 Docker 化解决方案*

+   第九章，*了解 Docker 的安全风险和好处*

+   第十章，*使用 Docker 构建持续部署流水线*


# 第八章：管理和监控 Docker 化解决方案

基于 Docker 构建的应用程序本质上是可移植的，部署过程对于每个环境都是相同的。当您将应用程序从系统测试和用户测试推广到生产环境时，您每次都会使用相同的构件。您在生产环境中使用的 Docker 镜像与在测试环境中签署的完全相同版本的镜像，任何环境差异都可以在 compose-file 覆盖、Docker 配置对象和 secrets 中捕获。

在后面的章节中，我将介绍 Docker 的持续部署工作原理，因此您的整个部署过程可以自动化。但是当您采用 Docker 时，您将会转移到一个新的应用平台，而通往生产环境的道路不仅仅是部署过程。容器化应用程序的运行方式与部署在虚拟机或裸机服务器上的应用程序有根本的不同。在本章中，我将讨论管理和监控在 Docker 中运行的应用程序。

今天您用来管理 Windows 应用程序的一些工具在应用程序迁移到 Docker 后仍然可以使用，我将从一些示例开始。但是在容器中运行的应用程序有不同的管理需求和机会，本章的主要重点将是特定于 Docker 的管理产品。

在本章中，我将使用简单的 Docker 化应用程序来向您展示如何管理容器，包括：

+   将**Internet Information Services** (**IIS**)管理器连接到运行在容器中的 IIS 服务

+   连接 Windows Server Manager 到容器，查看事件日志和功能

+   使用开源项目查看和管理 Docker 集群

+   使用**Universal Control Plane** (**UCP**)与**Docker Enterprise**

# 技术要求

您需要在 Windows 10 更新 18.09 或 Windows Server 2019 上运行 Docker，以便跟随示例。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch08`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch08)找到。

# 使用 Windows 工具管理容器

许多 Windows 中的管理工具都能够管理远程机器上运行的服务。IIS 管理器、服务器管理器和**SQL Server Management Studio** (**SSMS**)都可以连接到网络上的远程服务器进行检查和管理。

Docker 容器不同于远程机器，但它们可以被设置为允许从这些工具进行远程访问。通常情况下，您需要显式地为工具设置访问权限，通过公开管理端口、启用 Windows 功能和运行 PowerShell cmdlets。这些都可以在您的应用程序的 Dockerfile 中完成，我将为每个工具的设置步骤进行介绍。

能够使用熟悉的工具可能是有帮助的，但你应该对它们的使用有所限制；记住，容器是可以被丢弃的。如果您使用 IIS Manager 连接到 Web 应用程序容器并调整应用程序池设置，当您使用新的容器映像更新应用程序时，这些调整将会丢失。您可以使用图形工具检查运行中的容器并诊断问题，但您应该在 Dockerfile 中进行更改并重新部署。

# IIS Manager

IIS Web 管理控制台是一个完美的例子。在 Windows 基础映像中，默认情况下不允许远程访问，但您可以使用一个简单的 PowerShell 脚本进行配置。首先，需要安装 Web 管理功能：

```
Import-Module servermanager
Add-WindowsFeature web-mgmt-service
```

然后，您需要使用注册表设置启用远程访问，并启动 Web 管理 Windows 服务：

```
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1
Start-Service wmsvc
```

您还需要在 Dockerfile 中添加一个`EXPOSE`指令，以允许流量进入预期端口`8172`的管理服务。这将允许您连接，但 IIS 管理控制台需要远程机器的用户凭据。为了支持这一点，而不必将容器连接到**Active Directory**（**AD**），您可以在设置脚本中创建用户和密码：

```
net user iisadmin "!!Sadmin*" /add
net localgroup "Administrators" "iisadmin" /add
```

这里存在安全问题。您需要在镜像中创建一个管理帐户，公开一个端口，并运行一个额外的服务，所有这些都会增加应用程序的攻击面。与其在 Dockerfile 中运行设置脚本，不如附加到一个容器并交互式地运行脚本，如果您需要远程访问。

我已经在一个镜像中设置了一个简单的 Web 服务器，并在`dockeronwindows/ch08-iis-with-management:2e`的 Dockerfile 中打包了一个脚本以启用远程管理。我将从这个镜像中运行一个容器，发布 HTTP 和 IIS 管理端口：

```
docker container run -d -p 80 -p 8172 --name iis dockeronwindows/ch08-iis-with-management:2e
```

当容器运行时，我将在容器内执行`EnableIisRemoteManagement.ps1`脚本，该脚本设置了 IIS 管理服务的远程访问：

```
> docker container exec iis powershell \EnableIisRemoteManagement.ps1
The command completed successfully.
The command completed successfully.

Success Restart Needed Exit Code      Feature Result
------- -------------- ---------      --------------
True    No             Success        {ASP.NET 4.7, Management Service, Mana...

Windows IP Configuration
Ethernet adapter vEthernet (Ethernet):
   Connection-specific DNS Suffix  . : localdomain
   Link-local IPv6 Address . . . . . : fe80::583a:2cc:41f:f2e4%14
   IPv4 Address. . . . . . . . . . . : 172.27.56.248
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 172.27.48.1
```

安装脚本最后运行`ipconfig`，所以我可以看到容器的内部 IP 地址（我也可以从`docker container inspect`中看到这一点）。

现在我可以在 Windows 主机上运行 IIS 管理器，选择“开始页面|连接到服务器”，并输入容器的 IP 地址。当 IIS 要求我进行身份验证时，我使用了在安装脚本中创建的`iisadmin`用户的凭据：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/789fefbf-e5c3-4b47-8fd9-1504fc86ae7e.png)

在这里，我可以像连接到远程服务器一样浏览应用程序池和网站层次结构：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/e325acd8-cdab-4b78-8936-40753d777478.png)

这是检查在 IIS 上运行的 IIS 或 ASP.NET 应用程序配置的良好方法。您可以检查虚拟目录设置、应用程序池和应用程序配置，但这应该仅用于调查目的。

如果我发现应用程序中的某些内容配置不正确，我需要回到 Dockerfile 中进行修复，而不是对正在运行的容器进行更改。当您将现有应用程序迁移到 Docker 时，这种技术可能非常有用。如果您在 Dockerfile 中安装了带有 Web 应用程序的 MSI，您将无法看到 MSI 实际执行的操作，但您可以连接到 IIS 管理器并查看结果。

# SQL Server 管理工作室（SSMS）

SSMS 更为直接，因为它使用标准的 SQL 客户端端口`1433`。您不需要公开任何额外的端口或启动任何额外的服务；来自 Microsoft 和本书的 SQL Server 镜像已经设置好了一切。您可以使用在运行容器时使用的`sa`凭据使用 SQL Server 身份验证进行连接。

此命令运行 SQL Server 2019 Express Edition 容器，将端口`1433`发布到主机，并指定`sa`凭据：

```
docker container run -d -p 1433:1433 `
 -e sa_password=DockerOnW!nd0ws `
 --name sql `
 dockeronwindows/ch03-sql-server:2e
```

这将发布标准的 SQL Server 端口`1433`，因此您有三种选项可以连接到容器内部的 SQL Server。

+   在主机上，使用`localhost`作为服务器名称。

+   在主机上，使用容器的 IP 地址作为服务器名称。

+   在远程计算机上，使用 Docker 主机的计算机名称或 AP 地址。

我已经获取了容器的 IP 地址，所以在 Docker 主机上的 SSMS 中，我只需指定 SQL 凭据：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/0f7b835a-5d10-4170-ad44-d20e7d961ce5.png)

您可以像任何 SQL Server 一样管理这个 SQL 实例——创建数据库，分配用户权限，还原 Dacpacs，并运行 SQL 脚本。请记住，您所做的任何更改都不会影响镜像，如果您希望这些更改对新容器可用，您需要构建自己的镜像。

这种方法允许您通过 SSMS 构建数据库，如果这是您的首选，并在容器中运行而无需安装和运行 SQL Server。您可以完善架构，添加服务帐户和种子数据，然后将数据库导出为脚本。

我为一个简单的示例数据库做了这个，将架构和数据导出到一个名为`init-db.sql`的单个文件中。`dockeronwindows/ch08-mssql-with-schema:2e`的 Dockerfile 将 SQL 脚本打包到一个新的镜像中，并使用一个引导 PowerShell 脚本在创建容器时部署数据库：

```
# escape=` FROM dockeronwindows/ch03-sql-server:2e SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"] ENV sa_password DockerOnW!nd0ws VOLUME C:\mssql  WORKDIR C:\init
COPY . . CMD ./InitializeDatabase.ps1 -sa_password $env:sa_password -Verbose HEALTHCHECK CMD powershell -command ` try { ` $result = invoke-sqlcmd -Query 'SELECT TOP 1 1 FROM Authors' -Database DockerOnWindows; ` if ($result[0] -eq 1) {return 0} ` else {return 1}; ` } catch { return 1 }
```

这里的 SQL Server 镜像中有一个`HEALTHCHECK`，这是一个好的做法——它让 Docker 检查数据库是否正常运行。在这种情况下，如果架构尚未创建，测试将失败，因此在架构部署成功完成之前，容器将不会报告为健康状态。

我可以以通常的方式从这个镜像运行一个容器：

```
docker container run -d -p 1433 --name db dockeronwindows/ch08-mssql-with-schema:2e
```

通过发布端口`1433`，数据库容器可以在主机上的随机端口上使用，因此我可以使用 SQL 客户端连接到数据库，并从脚本中查看架构和数据。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/86e5cff3-5407-4e0f-a8f1-ae1bd82b2e7b.png)

这代表了一个应用数据库的新部署，在这种情况下，我使用了 SQL Server 的开发版来制定我的架构，但是实际数据库使用了 SQL Server Express，所有这些都在 Docker 中运行，没有本地 SQL Server 实例。

如果您认为使用 SQL Server 身份验证是一个倒退的步骤，您需要记住 Docker 可以实现不同的运行时模型。您不会有一个运行多个数据库的单个 SQL Server 实例；如果凭据泄露，它们都可能成为目标。每个 SQL 工作负载将在一个专用容器中，具有自己的一组凭据，因此您实际上每个数据库都有一个 SQL 实例，并且您可能每个服务都有一个数据库。

通过在 Docker 中运行，可以增加安全性。除非您需要远程连接到 SQL Server，否则无需从 SQL 容器发布端口。需要数据库访问的任何应用程序都将作为容器在与 SQL 容器相同的 Docker 网络中运行，并且可以访问端口 `1433` 而无需将其发布到主机。这意味着 SQL 仅对在相同 Docker 网络中运行的其他容器可访问，在生产环境中，您可以使用 Docker 机密来获取连接详细信息。

如果您需要在 AD 帐户中使用 Windows 身份验证，您仍然可以在 Docker 中执行。容器在启动时可以加入域，因此您可以使用服务帐户来代替 SQL Server 身份验证。

# 事件日志

您可以将本地计算机上的事件查看器连接到远程服务器，但目前 Windows Server Core 或 Nano Server 映像上未启用远程事件日志服务。这意味着您无法使用事件查看器 UI 连接到容器并读取事件日志条目，但您可以使用服务器管理器 UI 进行操作，我将在下一节中介绍。

如果您只想读取事件日志，可以针对正在运行的容器执行 PowerShell cmdlet 以获取日志条目。此命令从我的数据库容器中读取 SQL Server 应用程序的两个最新事件日志条目：

```
> docker exec db powershell `
 "Get-EventLog -LogName Application -Source MSSQL* -Newest 2 | Format-Table TimeWritten,Message"

TimeWritten          Message
-----------          -------
6/27/2017 5:14:49 PM Setting database option READ_WRITE to ON for database '...
6/27/2017 5:14:49 PM Setting database option query_store to off for database...
```

如果您遇到无法以其他方式诊断的容器问题，读取事件日志可能会很有用。但是，当您有数十个或数百个容器运行时，这种方法并不适用。最好将感兴趣的事件日志中继到控制台，以便 Docker 平台收集它们，并且您可以使用 `docker container logs` 或可以访问 Docker API 的管理工具来读取它们。

中继事件日志很容易做到，采用了与 第三章 *开发 Docker 化的 .NET Framework 和 .NET Core 应用程序* 中中继 IIS 日志类似的方法。对于写入事件日志的任何应用程序，您可以使用启动脚本作为入口点，该脚本运行应用程序，然后进入读取循环，从事件日志中获取条目并将其写入控制台。

这对于作为 Windows 服务运行的应用程序非常有用，这也是 Microsoft 在 SQL Server Windows 映像中使用的方法。Dockerfile 使用 PowerShell 脚本作为 `CMD`，该脚本以循环结束，调用相同的 `Get-EventLog` cmdlet 将日志中继到控制台：

```
$lastCheck = (Get-Date).AddSeconds(-2) 
while ($true) { 
 Get-EventLog -LogName Application -Source "MSSQL*" -After $lastCheck | `
 Select-Object TimeGenerated, EntryType, Message 
 $lastCheck = Get-Date 
 Start-Sleep -Seconds 2 
}
```

该脚本每 2 秒读取一次事件日志，获取自上次读取以来的任何条目，并将它们写入控制台。该脚本在 Docker 启动的进程中运行，因此日志条目被捕获并可以通过 Docker API 公开。

这并不是一个完美的方法——它使用了定时循环，只选择了日志中的一些数据，并且意味着在容器的事件日志和 Docker 中存储数据。如果您的应用程序已经写入事件日志，并且您希望将其 Docker 化而不需要重新构建应用程序，则这是有效的。在这种情况下，您需要确保您有一种机制来保持应用程序进程运行，比如 Windows 服务，并且在 Dockerfile 中进行健康检查，因为 Docker 只监视事件日志循环。

# 服务器管理器

服务器管理器是一个很好的工具，可以远程管理和监控服务器，并且它与基于 Windows Server Core 的容器配合良好。您需要采用类似的方法来管理 IIS 控制台，配置容器中具有管理员访问权限的用户，然后从主机连接。

就像 IIS 一样，您可以向镜像添加一个启用访问的脚本，这样您可以在需要时运行它。这比在镜像中始终启用远程访问更安全。该脚本只需要添加一个用户，配置服务器以允许管理员帐户进行远程访问，并确保**Windows 远程管理**（**WinRM**）服务正在运行：

```
net user serveradmin "s3rv3radmin*" /add
net localgroup "Administrators" "serveradmin" /add

New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
 -Name LocalAccountTokenFilterPolicy -Type DWord -Value 1
Start-Service winrm
```

我有一个示例镜像展示了这种方法，`dockeronwindows/ch08-iis-with-server-manager:2e`。它基于 IIS，并打包了一个脚本来启用服务器管理器的远程访问。Dockerfile 还公开了 WinRM 使用的端口`5985`和`5986`。我可以启动一个在后台运行 IIS 的容器，然后启用远程访问：

```
> > docker container run -d -P --name iis2 dockeronwindows/ch08-iis-with-server-manager:2e
9c097d80c08b5fc55cfa27e40121d240090a1179f67dbdde653c1f93d3918370

PS> docker exec iis2 powershell .\EnableRemoteServerManagement.ps1
The command completed successfully.
... 
```

您可以使用容器的 IP 地址连接到服务器管理器，但容器没有加入域。服务器管理器将尝试通过安全通道进行身份验证并失败，因此您将收到 WinRM 身份验证错误。要添加一个未加入域的服务器，您需要将其添加为受信任的主机。受信任的主机列表需要使用容器的主机名，而不是 IP 地址，所以首先我会获取容器的主机名：

```
> docker exec iis2 hostname
9c097d80c08b
```

我将在我的服务器的`hosts`文件中添加一个条目，位于`C:\Windows\system32\drivers\etc\hosts`：

```
#ch08 
172.27.59.5  9c097d80c08b
```

现在，我可以将容器添加到受信任的列表中。此命令需要在主机上运行，而不是在容器中运行。您正在将容器的主机名添加到本地计算机的受信任服务器列表中。我在我的 Windows Server 2019 主机上运行此命令：

```
Set-Item wsman:\localhost\Client\TrustedHosts 9c097d80c08b -Concatenate -Force
```

我正在运行 Windows Server 2019，但您也可以在 Windows 10 上使用服务器管理器。安装**远程服务器管理工具**（**RSAT**），您可以在 Windows 10 上以相同的方式使用服务器管理器。

在服务器管理器中，导航到所有服务器 | 添加服务器，并打开 DNS 选项卡。在这里，您可以输入容器的主机名，服务器管理器将解析 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/281c2292-4fc3-4a73-a045-1267e090f3a5.png)

选择服务器详细信息，然后单击“确定” - 现在服务器管理器将尝试连接到容器。您将在“所有服务器”选项卡中看到更新的状态，其中显示服务器已上线，但访问被拒绝。现在，您可以右键单击服务器列表中的容器，然后单击“以...身份管理”以提供本地管理员帐户的凭据。您需要将主机名指定为用户名的域部分。脚本中创建的本地用户名为`serveradmin`，但我需要使用`9c097d80c08b\serveradmin`进行身份验证：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/35b53a20-2065-4844-b52e-ec397a9106d4.png)

现在连接成功了，您将在服务器管理器中看到来自容器的数据，包括事件日志条目、Windows 服务以及所有安装的角色和功能：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/73b37959-9d87-40bc-a0b8-dce0d6f392e9.png)

您甚至可以从远程服务器管理器 UI 向容器添加功能-但这不是一个好的做法。像其他 UI 管理工具一样，最好用它们进行探索和调查，而不是在 Dockerfile 中进行任何更改。

# 使用 Docker 工具管理容器

您已经看到可以使用现有的 Windows 工具来管理容器，但是这些工具可以做的事情并不总是适用于 Docker 世界。一个容器将运行一个单独的 Web 应用程序，因此 IIS Manager 的层次结构导航并不是很有用。在服务器管理器中检查事件日志可能是有用的，但将条目中继到控制台更有用，这样它们可以从 Docker API 中显示出来。

您的应用程序镜像还需要明确设置，以便访问远程管理工具，公开端口，添加用户和运行其他 Windows 服务。所有这些都增加了正在运行的容器的攻击面。您应该将这些现有工具视为在开发和测试环境中调试有用，但它们并不适合生产环境。

Docker 平台为在容器中运行的任何类型的应用程序提供了一致的 API，这为一种新类型的管理员界面提供了机会。在本章的其余部分，我将研究那些了解 Docker 并提供替代管理界面的管理工具。我将从一些开源工具开始，然后转向 Docker 企业中商业**容器即服务**（**CaaS**）平台。

# Docker 可视化工具

**可视化工具**是一个非常简单的 Web UI，显示 Docker 集群中节点和容器的基本信息。它是 GitHub 上`dockersamples/docker-swarm-visualizer`存储库中的开源项目。它是一个 Node.js 应用程序，并且它打包在 Linux 和 Windows 的 Docker 镜像中。

我在 Azure 中为本章部署了一个混合 Docker Swarm，其中包括一个 Linux 管理节点，两个 Linux 工作节点和两个 Windows 工作节点。我可以在管理节点上将可视化工具作为 Linux 容器运行，通过部署绑定到 Docker Engine API 的服务：

```
docker service create `
  --name=viz `
  --publish=8000:8080/tcp `
  --constraint=node.role==manager `
  --mount=type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock `
  dockersamples/visualizer
```

该约束条件确保容器仅在管理节点上运行，由于我的管理节点运行在 Linux 上，我可以使用`mount`选项让容器与 Docker API 进行通信。在 Linux 中，您可以将套接字视为文件系统挂载，因此容器可以使用 API 套接字，而无需将其公开到**传输控制协议**（**TCP**）上。

您还可以在全 Windows 集群中运行可视化工具。Docker 目前支持 Windows 命名管道作为单个服务器上的卷，但在 Docker Swarm 中不支持；但是，您可以像我在第七章中使用 Traefik 一样，通过 TCP 挂载 API。

可视化工具为您提供了对集群中容器的只读视图。UI 显示主机和容器的状态，并为您提供了一种快速检查集群中工作负载分布的方式。这是我在 Azure 中部署 NerdDinner 堆栈的 Docker 企业集群的外观：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/732dc814-28a2-4751-83f3-b518681e96ba.png)

我一眼就能看到我的节点和容器是否健康，我可以看到 Docker 已经尽可能均匀地分布了容器。可视化器使用 Docker 服务中的 API，该 API 使用 RESTful 接口公开所有 Docker 资源。

Docker API 还提供了写访问权限，因此您可以创建和更新资源。一个名为**Portainer**的开源项目使用这些 API 提供管理功能。

# Portainer

Portainer 是 Docker 的轻量级管理 UI。它作为一个容器运行，可以管理单个 Docker 主机和以集群模式运行的集群。它是一个托管在 GitHub 上的开源项目，位于`portainer/portainer`存储库中。Portainer 是用 Go 语言编写的，因此它是跨平台的，您可以将其作为 Linux 或 Windows 容器运行。

Portainer 有两个部分：您需要在每个节点上运行一个代理，然后运行管理 UI。所有这些都在容器中运行，因此您可以使用 Docker Compose 文件，例如本章源代码中的`ch08-portainer`中的文件。Compose 文件定义了一个全局服务，即 Portainer 代理，在集群中的每个节点上都在容器中运行。然后是 Portainer UI：

```
portainer:
  image: portainer/portainer
  command: -H tcp://tasks.agent:9001 --tlsskipverify
  ports:
   - "8000:9000"
  volumes:
   - portainer_data:/data
  networks:
   - agent_network
  deploy: 
    mode: replicated
    replicas: 1
    placement:
      constraints: [node.role == manager]
```

Docker Hub 上的`portainer/portainer`镜像是一个多架构镜像，这意味着您可以在 Linux 和 Windows 上使用相同的镜像标签，Docker 将使用与主机操作系统匹配的镜像。您无法在 Windows 上挂载 Docker 套接字，但 Portainer 文档会向您展示如何在 Windows 上访问 Docker API。

当您首次浏览到 Portainer 时，您需要指定管理员密码。然后，服务将连接到 Docker API 并显示有关所有资源的详细信息。在集群模式下，我可以看到集群中节点的数量，堆栈的数量，正在运行的服务和容器的数量，以及集群中的镜像、卷和网络。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/179bc3ae-5b55-4487-b2c8-dad341998b9d.png)

集群可视化器链接显示了一个非常类似于 Docker Swarm 可视化器的 UI，显示了每个节点上运行的容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/8b3a9fe6-5690-4bbc-af88-1fb2d3191700.png)

服务视图向我展示了所有正在运行的服务，从这里，我可以深入了解服务的详细信息，并且有一个快速链接来更新服务的规模：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3f0d001c-3a79-4cf4-8f68-f0028ca0fe9e.png)

Portainer 随着新的 Docker 功能不断发展，您可以从 Portainer 部署堆栈和服务并对其进行管理。您可以深入了解服务日志，连接到容器的控制台会话，并从内置 UI 中部署 Docker Compose 模板的常见应用程序。

您可以在 Portainer 中创建多个用户和团队，并对资源应用访问控制。您可以创建仅限于某些团队访问的服务。认证由 Portainer 通过本地用户数据库或连接到现有的轻量级目录访问协议（LDAP）提供者进行管理。

Portainer 是一个很棒的工具，也是一个活跃的开源项目，但在采用它作为管理工具之前，您应该评估最新版本。Portainer 最初是一个 Linux 工具，仍然有一些 Windows 功能不完全支持的地方。在撰写本文时，代理容器需要在 Windows 节点上进行特殊配置，这意味着您无法将其部署为跨整个群集的全局服务，并且没有它，您无法在 Portainer 中看到 Windows 容器。

在生产环境中，您可能需要运行具有支持的软件。Portainer 是开源的，但也提供了商业支持选项。对于企业部署或具有严格安全流程的环境，Docker Enterprise 提供了完整的功能集。

# 使用 Docker Enterprise 的 CaaS

Docker Enterprise 是 Docker，Inc.的商业版本。它是一个完整的 CaaS 平台，充分利用 Docker 提供单一的管理界面，用于管理任意数量的运行在任意数量主机上的容器。

Docker Enterprise 是一个在数据中心或云中运行的生产级产品。集群功能支持多个编排器，包括 Kubernetes 和 Docker Swarm。在生产中，您可以拥有一个包含 100 个节点的集群，使用与您的开发笔记本相同的应用程序平台作为单节点集群运行。

Docker Enterprise 有两个部分。其中一个是**Docker Trusted Registry**（**DTR**），它类似于运行您自己的私有 Docker Hub 实例，包括图像签名和安全扫描。当我在 Docker 的安全性方面进行讨论时，我将在第九章中涵盖 DTR，*理解 Docker 的安全风险和好处*。管理组件称为**Universal Control Plane**（**UCP**），它是一种新型的管理界面。

# 理解 Universal Control Plane

UCP 是一个基于 Web 的界面，用于管理节点、图像、服务、容器、秘密和所有其他 Docker 资源。UCP 本身是一个分布式应用程序，运行在 swarm 中连接的服务中的容器中。UCP 为您提供了一个统一的地方来以相同的方式管理所有 Docker 应用程序。它提供了基于角色的访问控制，以便您可以对谁可以做什么进行细粒度的控制。

Docker Enterprise 运行 Kubernetes 和 Docker Swarm。Kubernetes 将在未来的版本中支持 Windows 节点，因此您将能够在单个 Docker Enterprise 集群上将 Windows 容器部署到 Docker Swarm 或 Kubernetes。您可以使用 Docker Compose 文件将堆栈部署到 UCP，将目标设置为 Docker Swarm 或 Kubernetes，UCP 将创建所有资源。

UCP 为您提供了完整的管理功能：您可以创建、扩展和删除服务，检查并连接到运行服务的任务，并管理运行 swarm 的节点。您需要的所有其他资源，如 Docker 网络、配置、秘密和卷，都以相同的方式在 UCP 中进行管理。

您可以在 UCP 和 DTR 的 Linux 节点上运行混合 Docker Enterprise 集群，并在 Windows 节点上运行用户工作负载。作为 Docker 的订阅服务，您可以得到 Docker 团队的支持，他们将为您设置集群并处理任何问题，涵盖所有的 Windows 和 Linux 节点。

# 导航 UCP UI

您可以从主页登录到 UCP。您可以使用 Docker Enterprise 内置的身份验证，手动管理 UCP 中的用户，或者连接到任何 LDAP 身份验证存储。这意味着您可以设置 Docker Enterprise 来使用您组织的 AD，并让用户使用他们的 Windows 帐户登录。

UCP 主页是一个仪表板，显示了集群的关键性能指标，节点数、服务数，以及在那一刻运行的 Swarm 和 Kubernetes 服务，以及集群的整体计算利用率：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6daec606-9f03-42a5-bc82-c6ed29acc086.png)

从仪表板，您可以导航到资源视图，按资源类型分组访问：服务、容器、镜像、节点、网络、卷和秘密。对于大多数资源类型，您可以列出现有资源、检查它们、删除它们，并创建新的资源。

UCP 是一个多编排器容器平台，因此您可以在同一集群中在 Kubernetes 中运行一些应用程序，而在 Docker Swarm 中运行其他应用程序。导航栏中的共享资源部分显示了编排器之间共享的资源，包括镜像、容器和堆栈。这是支持异构交付的一个很好的方法，或者在受控环境中评估不同的编排器。

UCP 为所有资源提供了基于角色的访问控制（RBAC）。您可以将权限标签应用于任何资源，并根据该标签来保护访问。团队可以被分配到标签的权限，从无访问权限到完全控制权限不等，这样可以确保团队成员对拥有这些标签的所有资源的访问权限。

# 管理节点

节点视图显示了集群中的所有节点，列出了操作系统和 CPU 架构、节点状态和节点管理器状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/65b4a710-75ef-4d74-acd5-78405f58ec28.png)

我的集群中有六个节点：

+   用于混合工作负载的两个 Linux 节点：这些节点可以运行 Kubernetes 或 Docker Swarm 服务

+   仅配置为 Docker Swarm 服务的两个 Linux 节点

+   两个仅用于 Docker Swarm 的 Windows 节点

这些节点正在运行所有 UCP 和 DTR 容器。Docker Enterprise 可以配置免除管理节点运行用户工作负载，也可以对运行 DTR 进行同样的配置。这是一个很好的方法，可以为 Docker Enterprise 服务划定计算资源的边界，以确保您的应用工作负载不会使管理组件资源匮乏。

在节点管理中，您可以以图形方式查看和管理您可以访问的集群服务器。您可以将节点放入排水模式，从而可以运行 Windows 更新或升级节点上的 Docker。您可以将工作节点提升为管理节点，将管理节点降级为工作节点，并查看加入新节点到集群所需的令牌。

深入了解每个节点，您可以查看服务器的总 CPU、内存和磁盘使用情况，并显示使用情况的图表，您可以将其聚合为 30 分钟到 24 小时的时间段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/58297ff5-c3fc-4b0c-b5df-a7744e6acdd6.png)

在指标选项卡中，列出了节点上的所有容器，显示它们的当前状态以及容器正在运行的镜像。从容器列表中，您可以导航到容器视图，我将很快介绍。

# 卷

**卷**存在于节点级别而不是集群级别，但您可以在 UCP 中管理它们跨所有集群节点。您在集群中管理卷的方式取决于您使用的卷的类型。本地卷适用于诸如将日志和指标写入磁盘然后将其集中转发的全局服务等场景。

作为集群服务运行的持久数据存储也可以使用本地存储。您可以在每个节点上创建一个本地卷，但在具有高容量 RAID 阵列的服务器上添加标签。创建数据服务时，您可以使用约束将其限制为 RAID 节点，因此其他节点永远不会在其上安排任务，并且任务运行的地方将数据写入 RAID 阵列上的卷。

对于本地数据中心和云中，您可以使用卷插件与共享存储。使用共享存储，即使容器移动到不同的集群节点，服务也可以继续访问数据。服务任务将读取和写入数据到持久保存在共享存储设备上的卷中。Docker Store 上有许多卷插件可用，包括用于云服务的 AWS 和 Azure，来自 HPE 和 Nimble 的物理基础设施，以及 vSphere 等虚拟化平台。

Docker Enterprise 使用 Cloudstor 插件提供集群范围的存储，如果您使用 Docker Certified Infrastructure 部署，那么这将为您配置。在撰写本文时，该插件仅受 Linux 节点支持，因此 Windows 节点受限于运行本地卷。在 Docker Swarm 中仍然有许多有状态的应用程序架构可以很好地工作，但您需要仔细配置它们。

存储是容器生态系统中受到很多关注的领域。正在出现的技术可以创建集群范围的存储选项，而无需特定的基础设施。随着这些技术的成熟，您将能够通过汇集集群上的磁盘来运行具有高可用性和可扩展性的有状态服务。

卷有有限数量的选项，因此创建它们是指定驱动程序并应用任何驱动程序选项的情况：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2b4af10f-fd2f-4090-99e7-480862e189a9.png)

权限可以应用于卷，如其他资源一样，通过指定资源所属的集合。集合是 UCP 如何强制基于角色的访问控制以限制访问的方式。

本地卷在每个节点上创建，因此需要命名卷的容器可以在任何节点上运行并仍然找到卷。在 UCP 创建的混合 Swarm 中，本地卷在每个节点上创建，并显示挂载卷数据的服务器的物理位置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/adff0283-7fa3-42ee-b1bc-5260cf8f8a29.png)

UCP 为您提供了集群中所有资源的单一视图，包括每个节点上的卷和可用于运行容器的图像。

# 图像

UCP 不是图像注册表。DTR 是 Docker Enterprise 中的企业私有注册表，但您可以使用 UCP 管理在每个节点上的 Docker 缓存中的图像。在图像视图中，UCP 会显示已在集群节点上拉取的图像，并允许您拉取图像，这些图像会下载到每个节点上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/c64c83a7-f56b-46e5-ab53-05edf617388c.png)

Docker 图像经过压缩以进行分发，当您拉取图像时，Docker 引擎会解压缩图层。有特定于操作系统的优化，可以在拉取完成后立即启动容器，这就是为什么您无法在 Linux 主机上拉取 Windows 图像，反之亦然。UCP 将尝试在每个主机上拉取图像，但如果由于操作系统不匹配而导致某些主机失败，它将继续进行剩余节点。如果存在不匹配，您将看到错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/03333dcf-1a6d-49b1-ba17-063ec6e62f06.png)

在图像视图中，您可以深入了解图像的详细信息，包括图层的历史记录，健康检查，任何环境变量和暴露的端口。基本详细信息还会显示图像的操作系统平台，虚拟大小和创建日期：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/161ff9ad-3d91-44d2-8864-8b1606fbcbe7.png)

在 UCP 中，您还可以从集群中删除图像。您可能有一个保留集群上当前和先前图像版本的策略，以允许回滚。其他图像可以安全地从 Docker Enterprise 节点中删除，将所有先前的图像版本留在 DTR 中，以便在需要时拉取。

# 网络

网络管理很简单，UCP 呈现与其他资源类型相同的界面。网络列表显示了集群中的网络，这些网络可以添加到应用了 RBAC 的集合中，因此您只能看到您被允许看到的网络。

有几个网络的低级选项，允许您指定 IPv6 和自定义 MTU 数据包大小。Swarm 模式支持加密网络，在节点之间的流量被透明加密，可以通过 UCP 启用。在 Docker Enterprise 集群中，您将使用覆盖驱动程序允许服务在集群节点之间的虚拟网络中进行通信：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/fb40e1e0-5d11-45d4-8471-8326cb0fe93e.png)

Docker 支持一种特殊类型的 Swarm 网络，称为**入口网络**。入口网络具有用于外部请求的负载平衡和服务发现。这使得端口发布非常灵活。在一个 10 节点的集群上，您可以在具有三个副本的服务上发布端口`80`。如果一个节点收到端口`80`的传入请求，但它没有运行服务任务，Docker 会智能地将其重定向到运行任务的节点。

入口网络是 Docker Swarm 集群中 Linux 和 Windows 节点的强大功能。我在第七章中更详细地介绍了它们，*使用 Docker Swarm 编排分布式解决方案*。

网络也可以通过 UCP 删除，但只有在没有附加的容器时才能删除。如果您定义了使用网络的服务，那么如果您尝试删除它，您将收到警告。

# 部署堆栈

使用 UCP 部署应用程序有两种方式，类似于使用`docker service create`部署单个服务和使用`docker stack deploy`部署完整的 compose 文件。堆栈是最容易部署的，可以让您使用在预生产环境中验证过的 compose 文件。

在本章的源代码中，文件夹`ch08-docker-stack`包含了在 Docker Enterprise 上运行 NerdDinner 的部署清单，使用了 swarm 模式。`core docker-compose.yml`文件与第七章中提到的相同，*使用 Docker Swarm 编排分布式解决方案*，但在覆盖文件中有一些更改以部署到我的生产集群。我正在利用我在 Docker Enterprise 中拥有的混合集群，并且我正在为所有开源基础设施组件使用 Linux 容器。

要使服务使用 Linux 容器而不是 Windows，只有两个更改：镜像名称和部署约束，以确保容器被安排在 Linux 节点上运行。以下是文件`docker-compose.hybrid-swarm.yml`中 NATS 消息队列的覆盖：

```
message-queue:
  image: nats:1.4.1-linux
  deploy:
    placement:
      constraints: 
       - node.platform.os == linux
```

我使用了与第七章相同的方法，*使用 Docker Swarm 编排分布式解决方案*，使用`docker-compose config`将覆盖文件连接在一起并将它们导出到`docker-swarm.yml`中。我可以将我的 Docker CLI 连接到集群并使用`docker stack deploy`部署应用程序，或者我可以使用 UCP UI。从堆栈视图中，在共享资源下，我可以点击创建堆栈，并选择编排器并上传一个 compose YML 文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/def85847-d39d-44ba-b2ff-f6d639a85227.png)

UCP 验证内容并突出显示任何问题。有效的组合文件将部署为堆栈，并且您将在 UCP 中看到所有资源：网络、卷和服务。几分钟后，我的应用程序的所有图像都被拉到集群节点上，并且 UCP 为每个服务安排了副本。服务列表显示所有组件都以所需的规模运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/e94a002b-0c9d-437a-bb82-48eae1560c01.png)

我的现代化 NerdDinner 应用程序现在在一个六节点的 Docker Enterprise 集群中运行了 15 个容器。我在受支持的生产环境中实现了高可用性和扩展性，并且将四个开源组件从我的自定义镜像切换到了官方的 Docker 镜像，而不需要对我的应用程序镜像进行任何更改。

堆栈是首选的部署模型，因为它们继续使用已知的 compose 文件格式，并自动化所有资源。但堆栈并不适用于每种解决方案，特别是当您将传统应用程序迁移到容器时。在堆栈部署中，无法保证服务创建的顺序；Docker Compose 使用的 `depends_on` 选项不适用。这是一种有意设计的决策，基于服务应该具有弹性的想法，但并非所有服务都是如此。

现代应用程序应该设计成可以容忍故障。如果 web 组件无法连接到数据库，它应该使用基于策略的重试机制来重复连接，而不是无法启动。传统的应用程序通常期望它们的依赖可用，并没有优雅的重试机制。NerdDinner 就是这样，所以如果我从 compose 文件部署一个堆栈，web 应用可能会在数据库服务创建之前启动，然后失败。

在这种情况下，容器应该退出，这样 Docker 就知道应用程序没有在运行。然后它将安排一个新的容器运行，并在启动时，依赖项应该是可用的。如果不是，新容器将结束，Docker 将安排一个替代品，并且这将一直持续下去，直到应用程序正常工作。如果您的传统应用程序没有任何依赖检查，您可以将这种逻辑构建到 Docker 镜像中，使用 Dockerfile 中的启动检查和健康检查。

在某些情况下，这可能是不可能的，或者可能是新容器的重复启动会导致您的传统应用程序出现问题。您仍然可以手动创建服务，而不是部署堆栈。UCP 也支持这种工作流程，这样可以手动确保所有依赖项在启动每个服务之前都在运行。

这是管理应用程序的命令式方法，你真的应该尽量避免使用。更好的方法是将应用程序清单封装在一组简单的 Docker Compose 文件中，这样可以在源代码控制中进行管理，但对于一些传统的应用程序可能会很难做到这一点。

# 创建服务

`docker service create`命令有数十个选项。UCP 在引导式 UI 中支持所有这些选项，您可以从服务视图中启动。首先，您需要指定基本细节，比如用于服务的镜像名称；服务名称，其他服务将通过该名称发现此服务；以及命令参数，如果您想要覆盖镜像中的默认启动命令。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6fc4a829-65d8-4dbd-8560-d98948433217.png)

我不会覆盖所有细节；它们与`docker service create`命令中的选项相对应，但是值得关注的是调度选项卡。这是您设置服务模式为复制或全局，添加所需副本数量以及滚动更新配置的地方。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/9053565b-46a2-4e08-a97f-f66405add85c.png)

重启策略默认为始终。这与副本计数一起工作，因此如果任何任务失败或停止，它们将被重新启动以维持服务水平。您可以配置自动部署的更新设置，还可以添加调度约束。约束与节点标签一起工作，限制可以用于运行服务任务的节点。您可以使用此功能将任务限制为高容量节点或具有严格访问控制的节点。

在其他部分，您可以配置服务与集群中其他资源的集成方式，包括网络和卷、配置和秘密，还可以指定计算保留和限制。这使您可以将服务限制在有限的 CPU 和内存量上，并且还可以指定每个容器应具有的 CPU 和内存的最小份额。

当您部署服务时，UCP 会负责将镜像拉取到需要的任何节点上，并启动所需数量的容器。对于全局服务，每个节点将有一个容器，对于复制服务，将有指定数量的任务。

# 监控服务

UCP 允许您以相同的方式部署任何类型的应用程序，可以使用堆栈组合文件或创建服务。该应用程序可以使用多个服务，任何技术组合都可以——NerdDinner 堆栈的部分现在正在我的混合集群中的 Linux 上运行。我已经部署了 Java、Go 和 Node.js 组件作为 Linux 容器，以及.NET Framework 和.NET Core 组件作为 Windows 容器在同一个集群上运行。

所有这些不同的技术平台都可以通过 UCP 以相同的方式进行管理，这就是使其成为对于拥有大型应用程序资产的公司如此宝贵的平台。服务视图显示了所有服务的基本信息，例如总体状态、任务数量以及上次报告错误的时间。对于任何服务，您都可以深入到详细视图，显示有关服务的所有信息。

这是核心 NerdDinner ASP.NET Web 应用程序的概述选项卡：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/a5081765-3382-4623-a3bf-5e2a7dfb6feb.png)

我已经滚动了这个视图，这样我就可以看到服务可用的秘密，以及环境变量（在这种情况下没有），标签，其中包括 Traefik 路由设置和约束，包括平台约束，以确保其在 Windows 节点上运行。指标视图向我显示了 CPU 和内存使用情况的图表，以及所有正在运行的容器的列表。

您可以使用服务视图来检查服务的总体状态并进行更改-您可以添加环境变量，更改网络或卷，并更改调度约束。对服务定义所做的任何更改都将通过重新启动服务来实施，因此您需要了解应用程序的影响。无状态应用程序和优雅处理瞬态故障的应用程序可以在运行时进行修改，但可能会有应用程序停机时间-这取决于您的解决方案架构。

您可以调整服务的规模，而无需重新启动现有任务。只需在调度选项卡中指定新的规模级别，UCP 将创建或删除容器以满足服务水平：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/aced9423-5414-406d-98d8-8d9b2c5f2c91.png)

当您增加规模时，现有的容器将被保留，新的容器将被添加，因此这不会影响您的应用程序的可用性（除非应用程序将状态保留在单独的容器中）。

从服务视图或容器列表中，在共享资源下，您可以选择一个任务来深入了解容器视图，这就是一致的管理体验，使得管理 Docker 化应用程序变得如此简单。显示了运行容器的每个细节，包括配置和容器内的实际进程列表。这是我的 Traefik 代理的容器，它只运行了`traefik`进程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/77b433fa-222e-45e8-9eed-97b20eebef3f.png)

您可以阅读容器的日志，其中显示了容器标准输出流的所有输出。这些是 Elasticsearch 的日志，它是一个 Java 应用程序，因此这些日志是以`log4j`格式的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/718b5db5-c0cf-4b0e-88cf-9bf978e7995f.png)

您可以以相同的方式查看集群中任何容器的日志，无论是在最小的 Linux 容器中运行的新 Go 应用程序，还是在 Windows 容器中运行的传统 ASP.NET 应用程序。这就是为什么构建 Docker 镜像以便将应用程序的日志条目中继到控制台是如此重要的原因。

甚至可以连接到容器中运行的命令行 shell，如果需要排除问题。这相当于在 Docker CLI 中运行`docker container exec -it powershell`，但都是从 UCP 界面进行的，因此您不需要连接到集群上的特定节点。您可以运行容器镜像中安装的任何 shell，在 Kibana Linux 镜像中，我可以使用`bash`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/8a0a0818-0629-407e-83b2-8b2022582d98.png)

UCP 为您提供了一个界面，让您可以从集群的整体健康状态，通过所有运行服务的状态，到特定节点上运行的个别容器。您可以轻松监视应用程序的健康状况，检查应用程序日志，并连接到容器进行调试 - 这一切都在同一个管理界面中。您还可以下载一个**客户端捆绑包**，这是一组脚本和证书，您可以使用它们来从远程 Docker **命令行界面**（**CLI**）客户端安全地管理集群。

客户端捆绑脚本将您的本地 Docker CLI 指向在集群管理器上运行的 Docker API，并为安全通信设置客户端证书。证书标识了 UCP 中的特定用户，无论他们是在 UCP 中创建的还是外部 LDAP 用户。因此，用户可以登录到 UCP UI 或使用`docker`命令来管理资源，对于这两种选项，他们将具有 UCP RBAC 策略定义的相同访问权限。

# RBAC

UCP 中的授权为您提供对所有 Docker 资源的细粒度访问控制。UCP 中的 RBAC 是通过为主体创建对资源集的访问授权来定义的。授权的主体可以是单个用户、一组用户或包含许多团队的组织。资源集可以是单个资源，例如 Docker Swarm 服务，也可以是一组资源，例如集群中的所有 Windows 节点。授权定义了访问级别，从无访问权限到完全控制。

这是一种非常灵活的安全方法，因为它允许您在公司的任何级别强制执行安全规则。我可以采用应用程序优先的方法，其中我有一个名为`nerd-dinner`的资源集合，代表 NerdDinner 应用程序，这个集合是其他代表部署环境的集合的父级：生产、UAT 和系统测试。集合层次结构在此图表的右侧：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/5fcce0e5-c3dd-4779-8b2c-af4ada0805ec.png)

集合是资源的组合 - 因此，我会将每个环境部署为一个堆栈，其中所有资源都属于相关的集合。组织是用户的最终分组，在这里我在左侧显示了一个**nerd-dinner**组织，这是所有在 NerdDinner 上工作的人的分组。在组织中，有两个团队：**Nerd Dinner Ops**是应用程序管理员，**Nerd Dinner Testers**是测试人员。在图表中只显示了一个用户**elton**，他是**Nerd Dinner Ops**团队的成员。

这种结构让我可以创建授权，以便在不同级别为不同资源提供访问权限：

+   **nerd-dinner**组织对**nerd-dinner**集合具有**仅查看**权限，这意味着组织中任何团队的任何用户都可以列出并查看任何环境中任何资源的详细信息。

+   **Nerd Dinner Ops**团队还对**nerd-dinner**集合具有**受限控制**，这意味着他们可以在任何环境中运行和管理资源。

+   **Nerd Dinner Ops**团队中的用户**elton**还对**nerd-dinner-uat**集合拥有**完全控制**，这为 UAT 环境中的资源提供了完全的管理员控制。

+   **Nerd Dinner Testers**团队对**nerd-dinner-test**集合具有**调度程序**访问权限，这意味着团队成员可以管理测试环境中的节点。

Docker Swarm 集合的默认角色是**仅查看**，**受限控制**，**完全控制**和**调度器**。您可以创建自己的角色，并为特定类型的资源设置特定权限。

您可以在 UCP 中创建授权以创建将主体与一组资源链接起来的角色，从而赋予它们已知的权限。我已在我的 Docker Enterprise 集群中部署了安全访问图表，并且我可以看到我的授权以及默认的系统授权：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6c89cc56-1c9d-4066-a684-0a8fd8b70d1a.png)

您可以独立于要保护的资源创建授权和集合。然后，在创建资源时，通过添加标签指定集合，标签的键为`com.docker.ucp.access.label`，值为集合名称。您可以在 Docker 的创建命令中以命令方式执行此操作，在 Docker Compose 文件中以声明方式执行此操作，并通过 UCP UI 执行此操作。在这里，我指定了反向代理服务属于`nerd-dinner-prod`集合：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/9b6f6205-6a0e-484f-bc98-825d666d4b17.png)

如果我以 Nerd Dinner Testers 团队成员的身份登录 UCP，我只会看到一个服务。测试用户无权查看默认集合中的服务，只有代理服务明确放入了`nerd-dinner-prod`集合中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/0e34116f-3197-4748-addd-5e1249dd100d.png)

作为这个用户，我只有查看权限，所以如果我尝试以任何方式修改服务，比如重新启动它，我会收到错误提示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6b0cd91d-15b3-40d0-bdd5-ae53ebf017a1.png)

团队可以对不同的资源集拥有多个权限，用户可以属于多个团队，因此 UCP 中的授权系统足够灵活，适用于许多不同的安全模型。您可以采用 DevOps 方法，为特定项目构建集合，所有团队成员都可以完全控制项目资源，或者您可以有一个专门的管理员团队，完全控制一切。或者您可以拥有单独的开发团队，团队成员对他们工作的应用程序有受限控制。

RBAC 是 UCP 的一个重要功能，它补充了 Docker 更广泛的安全故事，我将在第九章中介绍，*理解 Docker 的安全风险和好处*。

# 总结

本章重点介绍了运行 Docker 化解决方案的操作方面。我向您展示了如何将现有的 Windows 管理工具与 Docker 容器结合使用，以及这对于调查和调试是如何有用的。主要重点是使用 Docker Enterprise 中的 UCP 来管理各种工作负载的新方法。

您学会了如何使用现有的 Windows 管理工具，比如 IIS 管理器和服务器管理器，来管理 Docker 容器，您也了解了这种方法的局限性。在开始使用 Docker 时，坚持使用您已知的工具可能是有用的，但专门的容器管理工具是更好的选择。

我介绍了两种开源选项来管理容器：简单的可视化工具和更高级的 Portainer。它们都作为容器运行，并连接到 Docker API，它们是在 Linux 和 Windows Docker 镜像中打包的跨平台应用程序。

最后，我向您介绍了 Docker Enterprise 中用于管理生产工作负载的主要功能。我演示了 UCP 作为一个单一的管理界面，用于管理在同一集群中以多种技术堆栈在 Linux 和 Windows 容器上运行的各种容器化应用程序，并展示了 RBAC 如何让您安全地访问所有 Docker 资源。

下一章将重点介绍安全性。在容器中运行的应用程序可能提供了新的攻击途径。您需要意识到风险，但安全性是 Docker 平台的核心。Docker 让您可以轻松地建立端到端的安全性方案，其中平台在运行时强制执行策略——这是在没有 Docker 的情况下很难做到的。


# 第九章：了解 Docker 的安全风险和好处

Docker 是一种新型的应用平台，它在建设过程中始终专注于安全性。您可以将现有应用程序打包为 Docker 镜像，在 Docker 容器中运行，并在不更改任何代码的情况下获得显著的安全性好处。

在基于 Windows Server Core 2019 的 Windows 容器上运行的.NET 2.0 WebForms 应用程序将在不进行任何代码更改的情况下愉快地在.NET 4.7 下运行：这是一个立即应用了 16 年安全补丁的升级！仍然有大量运行在不受支持的 Server 2003 上或即将不受支持的 Server 2008 上的 Windows 应用程序。转移到 Docker 是将这些应用程序引入现代技术栈的绝佳方式。

Docker 的安全涵盖了广泛的主题，我将在本章中进行介绍。我将解释容器和镜像的安全方面，**Docker Trusted Registry**（**DTR**）中的扩展功能，以及在 swarm 模式下的 Docker 的安全配置。

在本章中，我将深入研究 Docker 的内部，以展示安全性是如何实现的。我将涵盖：

+   了解容器安全性

+   使用安全的 Docker 镜像保护应用程序

+   使用 DTR 保护软件供应链

+   了解 swarm 模式下的安全性

# 了解容器安全性

Windows Server 容器中运行的应用程序进程实际上是在主机上运行的。如果在容器中运行多个 ASP.NET 应用程序，您将在主机机器的任务列表中看到多个`w3wp.exe`进程。在容器之间共享操作系统内核是 Docker 容器如此高效的原因——容器不加载自己的内核，因此启动和关闭时间非常快，对运行时资源的开销也很小。

在容器内运行的软件可能存在安全漏洞，安全人员关心的一个重要问题是：Docker 容器之间的隔离有多安全？如果 Docker 容器中的应用程序受到攻击，这意味着主机进程受到了攻击。攻击者能否利用该进程来攻击其他进程，潜在地劫持主机或在主机上运行的其他容器？

如果操作系统内核存在攻击者可以利用的漏洞，那么可能会打破容器并危害其他容器和主机。Docker 平台建立在深度安全原则之上，因此即使可能存在这种情况，平台也提供了多种方法来减轻风险。

Docker 平台在 Linux 和 Windows 之间几乎具有功能上的平等，但 Windows 方面还存在一些差距，正在积极解决中。但 Docker 在 Linux 上有更长的生产部署历史，许多指导和工具，如 Docker Bench 和 CIS Docker Benchmark，都是针对 Linux 的。了解 Linux 方面是有用的，但许多实际要点不适用于 Windows 容器。

# 容器进程

所有 Windows 进程都由用户帐户启动和拥有。用户帐户的权限决定了进程是否可以访问文件和其他资源，以及它们是否可用于修改或仅用于查看。在 Windows Server Core 的 Docker 基础映像中，有一个名为**容器管理员**的默认用户帐户。您在容器中从该映像启动的任何进程都将使用该用户帐户-您可以运行`whoami`工具，它只会输出当前用户名：

```
> docker container run mcr.microsoft.com/windows/servercore:ltsc2019 whoami
user manager\containeradministrator
```

您可以通过启动 PowerShell 来运行交互式容器，并找到容器管理员帐户的用户 ID（SID）：

```
> docker container run -it --rm mcr.microsoft.com/windows/servercore:ltsc2019 powershell

> $user = New-Object System.Security.Principal.NTAccount("containeradministrator"); `
 $sid = $user.Translate([System.Security.Principal.SecurityIdentifier]); `
 $sid.Value
S-1-5-93-2-1
```

您会发现容器用户的 SID 始终相同，即`S-1-5-93-2-1`，因为该帐户是 Windows 映像的一部分。由于这个原因，它在每个容器中都具有相同的属性。容器进程实际上是在主机上运行的，但主机上没有**容器管理员**用户。实际上，如果您查看主机上的容器进程，您会看到用户名的空白条目。我将在后台容器中启动一个长时间运行的`ping`进程，并检查容器内的**进程 ID**（PID）：

```
> docker container run -d --name pinger mcr.microsoft.com/windows/servercore:ltsc2019 ping -t localhost
f8060e0f95ba0f56224f1777973e9a66fc2ccb1b1ba5073ba1918b854491ee5b

> docker container exec pinger powershell Get-Process ping -IncludeUserName
Handles      WS(K)   CPU(s)     Id UserName               ProcessName
-------      -----   ------     -- --------               -----------
     86       3632     0.02   7704 User Manager\Contai... PING
```

这是在 Windows Server 2019 上运行的 Docker 中的 Windows Server 容器，因此`ping`进程直接在主机上运行，容器内的 PID 将与主机上的 PID 匹配。在服务器上，我可以检查相同 PID 的详细信息，本例中为`7704`：

```
> Get-Process -Id 7704 -IncludeUserName
Handles      WS(K)   CPU(s)     Id UserName               ProcessName
-------      -----   ------     -- --------               -----------
     86       3624     0.03   7704                        PING
```

由于容器用户在主机上没有映射任何用户，所以没有用户名。实际上，主机进程是在匿名用户下运行的，并且它在主机上没有权限，它只有在一个容器的沙盒环境中配置的权限。如果发现了允许攻击者打破容器的 Windows Server 漏洞，他们将以无法访问主机资源的主机进程运行。

可能会有更严重的漏洞允许主机上的匿名用户假定更广泛的权限，但这将是核心 Windows 权限堆栈中的一个重大安全漏洞，这通常会得到微软的非常快速的响应。匿名主机用户方法是限制任何未知漏洞影响的良好缓解措施。

# 容器用户帐户和 ACLs

在 Windows Server Core 容器中，默认用户帐户是容器管理员。该帐户在容器中是管理员组，因此可以完全访问整个文件系统和容器中的所有资源。在 Dockerfile 中指定的`CMD`或`ENTRYPOINT`指令中指定的进程将在容器管理员帐户下运行。

如果应用程序存在漏洞，这可能会有问题。应用程序可能会受到损害，虽然攻击者打破容器的机会很小，但攻击者仍然可以在应用程序容器内造成很大的破坏。管理访问权限意味着攻击者可以从互联网下载恶意软件并在容器中运行，或者将容器中的状态复制到外部位置。

您可以通过以最低特权用户帐户运行容器进程来减轻这种情况。Nano Server 映像使用了这种方法 - 它们设置了一个容器管理员用户，但容器进程的默认帐户是一个没有管理员权限的用户。您可以通过在 Nano Server 容器中回显用户名来查看这一点：

```
> docker container run mcr.microsoft.com/windows/nanoserver:1809 cmd /C echo %USERDOMAIN%\%USERNAME%
User Manager\ContainerUser
```

Nano Server 镜像没有`whoami`命令，甚至没有安装 PowerShell。它只设置了运行新应用程序所需的最低限度。这是容器安全性的另一个方面。如果`whoami`命令中存在漏洞，那么您的容器应用程序可能会受到威胁，因此 Microsoft 根本不打包该命令。这是有道理的，因为您不会在生产应用程序中使用它。在 Windows Server Core 中仍然存在它，以保持向后兼容性。

`ContainerUser`帐户在容器内没有管理员访问权限。如果需要管理员权限来设置应用程序，可以在 Dockerfile 中使用`USER ContainerAdministrator`命令切换到管理员帐户。但是，如果您的应用程序不需要管理员访问权限，应该在 Dockerfile 的末尾切换回`USER ContainerUser`，以便容器启动命令以最低特权帐户运行。

来自 Microsoft 的**Internet Information Services**（**IIS**）和 ASP.NET 镜像是运行最低特权用户的其他示例。外部进程是运行在`IIS_IUSRS`组中的本地帐户下的 IIS Windows 服务。该组对 IIS 根路径`C:\inetpub\wwwroot`具有读取访问权限，但没有写入访问权限。攻击者可能会破坏 Web 应用程序，但他们将无法写入文件，因此下载恶意软件的能力已经消失。

在某些情况下，Web 应用程序需要写入访问权限以保存状态，但可以在 Dockerfile 中以非常细的级别授予。例如，开源**内容管理系统**（**CMS**）Umbraco 可以打包为 Docker 镜像，但 IIS 用户组需要对内容文件夹进行写入权限。您可以使用`RUN`指令设置 ACL 权限，而不是更改 Dockerfile 以将服务作为管理帐户运行。

```
RUN $acl = Get-Acl $env:UMBRACO_ROOT; `
 $newOwner = System.Security.Principal.NTAccount; `
 $acl.SetOwner($newOwner); `
 Set-Acl -Path $env:UMBRACO_ROOT -AclObject $acl; `
 Get-ChildItem -Path $env:UMBRACO_ROOT -Recurse | Set-Acl -AclObject $acl
```

我不会在这里详细介绍 Umbraco，但它在容器中运行得非常好。您可以在我的 GitHub 存储库[`github.com/sixeyed/dockerfiles-windows`](https://github.com/sixeyed/dockerfiles-windows)中找到 Umbraco 和许多其他开源软件的示例 Dockerfile。

应该使用最低特权用户帐户来运行进程，并尽可能狭隘地设置 ACL。这限制了任何攻击者在容器内部获得进程访问权限的范围，但仍然存在来自容器外部的攻击向量需要考虑。

# 使用资源约束运行容器

您可以运行没有约束的 Docker 容器，容器进程将使用主机资源的尽可能多。这是默认设置，但可能是一个简单的攻击向量。恶意用户可能会在容器中对应用程序产生过多的负载，尝试占用 100%的 CPU 和内存，使主机上的其他容器陷入饥饿状态。如果您运行着为多个应用程序工作负载提供服务的数百个容器，这一点尤为重要。

Docker 有机制来防止单个容器使用过多的资源。您可以启动带有显式约束的容器，以限制它们可以使用的资源，确保没有单个容器占用大部分主机的计算能力。您可以将容器限制为显式数量的 CPU 核心和内存。

我有一个简单的.NET 控制台应用程序和一个 Dockerfile，可以将其打包到`ch09-resource-check`文件夹中。该应用程序被设计为占用计算资源，我可以在容器中运行它，以展示 Docker 如何限制恶意应用程序的影响。我可以使用该应用程序成功分配 600MB 的内存，如下所示：

```
> docker container run dockeronwindows/ch09-resource-check:2e /r Memory /p 600
I allocated 600MB of memory, and now I'm done.
```

控制台应用程序在容器中分配了 600MB 的内存，实际上是在 Windows Server 容器中从服务器中分配了 600MB 的内存。我在没有任何约束的情况下运行了容器，因此该应用程序可以使用服务器拥有的所有内存。如果我使用`docker container run`命令中的`--memory`限制将容器限制为 500MB 的内存，那么该应用程序将无法分配 600MB：

```
> docker container run --memory 500M dockeronwindows/ch09-resource-check:2e /r Memory /p 600 
Unhandled Exception: OutOfMemoryException.
```

示例应用程序也可以占用 CPU。它计算 Pi 的小数点位数，这是一个计算成本高昂的操作。在不受限制的容器中，计算 Pi 到 20000 位小数只需要在我的四核开发笔记本上不到一秒钟：

```
> docker container run dockeronwindows/ch09-resource-check:2e /r Cpu /p 20000
I calculated Pi to 20000 decimal places in 924ms. The last digit is 8.
```

我可以通过在`run`命令中指定`--cpu`限制来使用 CPU 限制，并且 Docker 将限制可用于此容器的计算资源，为其他任务保留更多的 CPU。相同的计算时间超过了两倍：

```
> docker container run --cpus 1 dockeronwindows/ch09-resource-check:2e /r Cpu /p 20000
I calculated Pi to 20000 decimal places in 2208ms. The last digit is 8.
```

生产 Docker Swarm 部署可以使用部署部分的资源限制来应用相同的内存和 CPU 约束。这个例子将新的 NerdDinner REST API 限制为可用 CPU 的 25%和 250MB 的内存：

```
nerd-dinner-api:
  image: dockeronwindows/ch07-nerd-dinner-api:2e
  deploy: resources:
      limits:
        cpus: '0.25'
        memory: 250M
...
```

验证资源限制是否生效可能是具有挑战性的。获取 CPU 计数和内存容量的底层 Windows API 使用操作系统内核，在容器中将是主机的内核。内核报告完整的硬件规格，因此限制似乎不会在容器内生效，但它们是强制执行的。您可以使用 WMI 来检查限制，但输出将不如预期：

```
> docker container run --cpus 1 --memory 1G mcr.microsoft.com/windows/servercore:ltsc2019 powershell `
 "Get-WmiObject Win32_ComputerSystem | select NumberOfLogicalProcessors, TotalPhysicalMemory"

NumberOfLogicalProcessors TotalPhysicalMemory
------------------------- -------------------
                        4         17101447168
```

在这里，容器报告有四个 CPU 和 16 GB 的 RAM，尽管它被限制为一个 CPU 和 1 GB 的 RAM。实际上已经施加了限制，但它们在 WMI 调用的上层操作。如果容器内运行的进程尝试分配超过 1 GB 的 RAM，那么它将失败。

请记住，只有 Windows Server 容器才能访问主机的所有计算能力，容器进程实际上是在主机上运行的。Hyper-V 容器每个都有一个轻量级的虚拟机，进程在其中运行，该虚拟机有自己的 CPU 和内存分配。您可以使用相同的 Docker 命令应用容器限制，并且这些限制适用于容器的虚拟机。

# 使用受限制的功能运行容器

Docker 平台有两个有用的功能，可以限制容器内应用程序的操作。目前，它们只适用于 Linux 容器，但如果您需要处理混合工作负载，并且对 Windows 的支持可能会在未来版本中推出，那么了解它们是值得的。

Linux 容器可以使用 `read-only` 标志运行，这将创建一个具有只读文件系统的容器。此选项可与任何镜像一起使用，并将启动一个具有与通常相同入口进程的容器。不同之处在于容器没有可写文件系统层，因此无法添加或更改文件 - 容器无法修改镜像的内容。

这是一个有用的安全功能。Web 应用程序可能存在漏洞，允许攻击者在服务器上执行代码，但只读容器严重限制了攻击者的操作。他们无法更改应用程序配置文件，更改访问权限，下载新的恶意软件或替换应用程序二进制文件。

只读容器可以与 Docker 卷结合使用，以便应用程序可以写入已知位置以记录日志或缓存数据。如果您有一个写入文件系统的应用程序，那么您可以在只读容器中运行它而不改变功能。您需要意识到，如果您将日志写入卷中的文件，并且攻击者已经访问了文件系统，他们可以读取历史日志，而如果日志写入标准输出并被 Docker 平台消耗，则无法这样做。

当您运行 Linux 容器时，您还可以明确添加或删除容器可用的系统功能。例如，您可以启动一个没有`chown`功能的容器，因此容器内部的任何进程都无法更改文件访问权限。同样，您可以限制绑定到网络端口或写入内核日志的访问。

`只读`，`cap-add`和`cap-drop`选项对 Windows 容器没有影响，但是在未来的 Docker on Windows 版本中可能会提供支持。

Docker 的一个很棒的地方是，开源组件内置在受支持的 Docker Enterprise 版本中。您可以在 GitHub 的`moby/moby`存储库中提出功能请求和跟踪错误，这是 Docker 社区版的源代码。当功能在 Docker CE 中实现后，它们将在随后的 Docker Enterprise 版本中可用。

# Windows 容器和 Active Directory

大型组织使用**Active Directory**（**AD**）来管理他们 Windows 网络中的所有用户，组和机器。应用服务器可以加入域，从而可以访问 AD 进行身份验证和授权。这通常是.NET 内部 Web 应用程序部署的方式。该应用程序使用 Windows 身份验证为用户提供单一登录，而 IIS 应用程序池则以访问 SQL Server 的服务帐户运行。

运行 Docker 的服务器可以加入域，但是机器上的容器不能。您可以在容器中运行传统的 ASP.NET 应用程序，但是在默认部署中，您会发现 Windows 身份验证对用户不起作用，应用程序本身也无法连接到数据库。

这是一个部署问题，您可以使用**组管理服务帐户**（**gMSA**）为 Windows 容器提供对 AD 的访问权限，这是一种无需密码即可使用的 AD 帐户类型。Active Directory 很快就会变成一个复杂的话题，所以我在这里只是给出一个概述，让您知道您可以在容器内部使用 AD 服务：

+   域管理员在 Active Directory 中创建 gMSA。这需要一个域控制器在运行 Windows Server 2012 或更高版本。

+   为 gMSA 授予对 Docker 服务器的访问权限。

+   使用`CredentialSpec` PowerShell 模块为 gMSA 生成 JSON 格式的凭据规范。

+   使用`security-opt`标志运行容器，指定 JSON 凭据规范的路径。

+   容器中的应用程序实际上是加入域的，并且可以使用已分配给 gMSA 的权限来使用 AD。

从容器内部访问 AD 服务在 Windows Server 2019 中要容易得多。以前，您在 Docker Swarm 中运行时必须使用特定名称的 gMSA，这使得在运行时应用凭据规范变得困难。现在，您可以为 gMSA 使用任何名称，并且一个 gMSA 可以用于多个容器。Docker Swarm 通过使用`credential_spec`值在 compose 文件中支持凭据规范。

在 Microsoft 的 GitHub 容器文档中有一个完整的创建和使用 gMSA 和凭据规范的演练：[`github.com/MicrosoftDocs/Virtualization-Documentation/tree/live/windows-server-container-tools/ServiceAccounts`](https://github.com/MicrosoftDocs/Virtualization-Documentation/tree/live/windows-server-container-tools/ServiceAccounts)。

# Hyper-V 容器中的隔离

Windows 上的 Docker 具有一个大的安全功能，Linux 上的 Docker 没有：使用 Hyper-V 容器进行扩展隔离。运行在 Windows Server 2019 上的容器使用主机的操作系统内核。当您运行容器时，可以在主机的任务管理器上看到容器内部的进程。

在 Windows 10 上，默认行为是不同的。通过 Windows 1809 更新，您可以通过在 docker 容器运行命令中添加`--isolation=process`标志在 Windows 10 上以进程隔离的方式运行 Windows Server 容器。您需要在命令中或 Docker 配置文件中指定隔离级别，因为在 Windows 10 上默认值是`hyperv`。

具有自己内核的容器称为**Hyper-V**容器。它们是使用轻量级虚拟机实现的，提供服务器内核，但这不是完整的虚拟机，也没有典型的虚拟机开销。Hyper-V 容器使用普通的 Docker 镜像，并且它们以与所有容器相同的方式在普通的 Docker 引擎中运行。它们不会显示在 Hyper-V 管理工具中，因为它们不是完整的虚拟机。

Hyper-V 容器也可以在 Windows Server 上使用`isolation`选项运行。此命令将 IIS 镜像作为 Hyper-V 容器运行，将端口`80`发布到主机上的随机端口：

```
docker container run -d -p 80 --isolation=hyperv `
  mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019
```

容器的行为方式相同。外部用户可以浏览主机上的`80`端口，流量由容器处理。在主机上，您可以运行`docker container inspect`来查看 IP 地址并直接进入容器。Docker 网络、卷和集群模式等功能对 Hyper-V 容器也适用。

Hyper-V 容器的扩展隔离提供了额外的安全性。没有共享内核，因此即使内核漏洞允许容器应用程序访问主机，主机也只是在自己的内核中运行的薄型 VM 层。在该内核上没有其他进程或容器运行，因此攻击者无法危害其他工作负载。

由于有单独的内核，Hyper-V 容器有额外的开销。它们通常启动时间较慢，并且默认情况下会施加内存和 CPU 限制，限制容器在内核级别无法超过的资源。在某些情况下，这种权衡是值得的。在多租户情况下，您对每个工作负载都假定零信任，扩展隔离可以是一种有用的防御。

Hyper-V 容器的许可证不同。普通的 Windows Server 容器在主机级别获得许可，因此您需要为每台服务器获得许可，然后可以运行任意数量的容器。每个 Hyper-V 容器都有自己的内核，并且有限制您可以在每个主机上运行的容器数量的许可级别。

# 使用安全的 Docker 镜像保护应用程序

我已经涵盖了许多关于运行时保护容器的方面，但 Docker 平台在任何容器运行之前就提供了深度安全性。您可以通过保护打包应用程序的镜像来开始保护您的应用程序。

# 构建最小化镜像

攻击者不太可能破坏您的应用程序并访问容器，但如果发生这种情况，您应该构建您的映像以减轻损害。构建最小映像至关重要。理想的 Docker 映像应该只包含应用程序和运行所需的依赖项。

这对于 Windows 应用程序比 Linux 应用程序更难实现。 Linux 应用程序的 Docker 映像可以使用最小的发行版作为基础，在其上只打包应用程序二进制文件。该映像的攻击面非常小。即使攻击者访问了容器，他们会发现自己处于一个功能非常有限的操作系统中。

相比之下，使用 Windows Server Core 的 Docker 映像具有完整功能的操作系统作为基础。最小的替代方案是 Nano Server，它具有大大减少的 Windows API，甚至没有安装 PowerShell，这消除了可以被利用的大量功能集。理论上，您可以在 Dockerfile 中删除功能，禁用 Windows 服务，甚至删除 Windows 二进制文件，以限制最终映像的功能。但是，您需要进行大量测试，以确保您的应用程序在定制的 Windows 版本中能够正确运行。

Docker 对专家和社区领袖的认可是 Captain 计划。 Docker Captains 就像 Microsoft MVPs，Stefan Scherer 既是 Captain 又是 MVP。 Stefan 通过创建带有空文件系统并添加最小一组 Windows 二进制文件的镜像来减小 Windows 镜像大小，做了一些有前途的工作。

您无法轻松限制基本 Windows 映像的功能，但可以限制您在其上添加的内容。在可能的情况下，您应该只添加您的应用程序内容和最小的应用程序运行时，以便攻击者无法修改应用程序。一些编程语言对此的支持要比其他语言好，例如：

+   Go 应用程序可以编译为本机二进制文件，因此您只需要在 Docker 映像中打包可执行文件，而不是完整的 Go 运行时。

+   .NET Core 应用程序可以发布为程序集，因此您只需要打包.NET Core 运行时来执行它们，而不是完整的.NET Core SDK。

+   .NET Framework 应用程序需要在容器映像中安装匹配的.NET Framework，但您仍然可以最小化打包的应用程序内容。您应该以发布模式编译应用程序，并确保不打包调试文件。

+   Node.js 使用 V8 作为解释器和编译器，因此，要在 Docker 中运行应用程序，镜像需要安装完整的 Node.js 运行时，并且需要打包应用程序的完整源代码。

您将受到应用程序堆栈支持的限制，但最小镜像是目标。如果您的应用程序将在 Nano Server 上运行，那么与 Windows Server Core 相比，Nano Server 肯定更可取。完整的.NET 应用程序无法在 Nano Server 上运行，但.NET Standard 正在迅速发展，因此将应用程序移植到.NET Core 可能是一个可行的选择，然后可以在 Nano Server 上运行。

当您在 Docker 中运行应用程序时，您使用的单元是容器，并且使用 Docker 进行管理和监控。底层操作系统不会影响您与容器的交互方式，因此拥有最小的操作系统不会限制您对应用程序的操作。

# Docker 安全扫描

最小的 Docker 镜像仍然可能包含已知漏洞的软件。Docker 镜像使用标准的开放格式，这意味着可以可靠地构建工具来导航和检查镜像层。一个工具是 Docker 安全扫描，它检查 Docker 镜像中的软件是否存在漏洞。

Docker 安全扫描检查镜像中的所有二进制文件，包括应用程序依赖项、应用程序框架甚至操作系统。每个二进制文件都会根据多个**通用漏洞和利用**（**CVE**）数据库进行检查，寻找已知的漏洞。如果发现任何问题，Docker 会报告详细信息。

Docker 安全扫描可用于 Docker Hub 的官方存储库以及 Docker Trusted Registry 的私有存储库。这些系统的 Web 界面显示了每次扫描的输出。像 Alpine Linux 这样的最小镜像可能完全没有漏洞：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/9f1d7121-06c6-4dcf-baa3-ab74a483095f.png)

官方 NATS 镜像有一个 Nano Server 2016 变体，您可以看到该镜像中存在漏洞：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/ecb59cef-aa94-407c-85a5-92798a94e8c8.png)

在存在漏洞的地方，您可以深入了解到底有哪些二进制文件被标记，并且链接到 CVE 数据库，描述了漏洞。在`nats:nanoserver`镜像的情况下，Nano Server 基础镜像中打包的 zlib 和 SQLite 版本存在漏洞。

这些扫描结果来自 Docker Hub 上的官方镜像。Docker Enterprise 还在 DTR 中提供安全扫描，您可以按需运行手动扫描，或配置任何推送到存储库的操作来触发扫描。我已经为 NerdDinner web 应用程序创建了一个存储库，该存储库配置为在每次推送图像时进行扫描：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/41764876-a665-4d54-b05c-9c8d25b49bf1.png)

对该存储库的访问基于第八章中相同的安全设置，即*管理和监控 Docker 化解决方案*，使用**nerd-dinner**组织和**Nerd Dinner Ops**团队。DTR 使用与 UCP 相同的授权，因此您可以在 Docker Enterprise 中构建组织和团队一次，并将它们用于保护图像和运行时资源。用户**elton**属于**Nerd Dinner Ops**团队，对**nerd-dinner-web**存储库具有读写访问权限，这意味着可以推送和拉取图像。

当我向这个存储库推送图像时，Docker Trusted Registry 将开始进行安全扫描，从而识别图像每个层中的所有二进制文件，并检查它们是否存在 CVE 数据库中已知的漏洞。NerdDinner web 应用程序基于 Microsoft 的 ASP.NET 镜像，在撰写本文时，该镜像中的组件存在已知漏洞：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/8e898f88-e3e4-420f-b52a-84e193d4f88a.png)

`System.Net.Http`中的问题只能在 ASP.NET Core 应用程序中被利用，所以我可以自信地说它们在我的.NET Framework 应用程序中不是问题。然而，`Microsoft.AspNet.Mvc`的跨站脚本（XSS）问题确实适用，我想要更多地了解有关利用的信息，并在我的 CI 流程中添加测试来确认攻击者无法通过我的应用程序利用它。

这些漏洞不是我在 Dockerfile 中添加的库中的漏洞——它们在基础镜像中，并且实际上是 ASP.NET 和 ASP.NET Core 的一部分。这与在容器中运行无关。如果您在任何版本的 Windows 上运行任何版本的 ASP.NET MVC 从 2.0 到 5.1，那么您的生产系统中就存在这个 XSS 漏洞，但您可能不知道。

当您在图像中发现漏洞时，您可以准确地看到它们的位置，并决定如何加以减轻。如果您有一个可以自信地用来验证您的应用程序是否仍然可以正常工作的自动化测试套件，您可以尝试完全删除二进制文件。或者，您可能会决定从您的应用程序中没有漏洞代码的路径，并保持图像不变，并添加测试以确保没有办法利用漏洞。

无论您如何管理它，知道应用程序堆栈中存在漏洞非常有用。Docker 安全扫描可以在每次推送时工作，因此如果新版本引入漏洞，您将立即得到反馈。它还链接到 UCP，因此您可以从管理界面上看到正在运行的容器的图像中是否存在漏洞。

# 管理 Windows 更新

管理应用程序堆栈更新的过程也适用于 Docker 镜像的 Windows 更新。您不会连接到正在运行的容器来更新其使用的 Node.js 版本，也不会运行 Windows 更新。

微软通常会发布一组综合的安全补丁和其他热修复程序，通常每月一次作为 Windows 更新。同时，他们还会在 Docker Hub 和 Microsoft 容器注册表上发布新版本的 Windows Server Core 和 Nano Server 基础镜像以及任何依赖镜像。镜像标签中的版本号与 Windows 发布的热修复号匹配。

在 Dockerfile 的`FROM`指令中明确声明要使用的 Windows 版本，并使用安装的任何依赖项的特定版本是一个很好的做法。这使得您的 Dockerfile 是确定性的-在将来任何时候构建它，您将得到相同的镜像，其中包含所有相同的二进制文件。

指定 Windows 版本还清楚地表明了如何管理 Docker 化应用程序的 Windows 更新。.NET Framework 应用程序的 Dockerfile 可能是这样开始的：

```
FROM mcr.microsoft.com/windows/servercore:1809_KB4471332
```

这将镜像固定为带有更新`KB4471332`的 Windows Server 2019。这是一个可搜索的知识库 ID，告诉您这是 Windows 2018 年 12 月的更新。随着新的 Windows 基础镜像的发布，您可以通过更改`FROM`指令中的标签并重新构建镜像来更新应用程序，例如使用发布`KB4480116`，这是 2019 年 1 月的更新：

```
FROM mcr.microsoft.com/windows/servercore:1809_KB4480116
```

我将在第十章中介绍自动构建和部署，*使用 Docker 打造持续部署流水线*。通过一个良好的 CI/CD 流水线，您可以使用新的 Windows 版本重新构建您的镜像，并运行所有测试以确认更新不会影响任何功能。然后，您可以通过使用`docker stack deploy`或`docker service update`在没有停机时间的情况下将更新推出到所有正在运行的应用程序，指定应用程序镜像的新版本。整个过程可以自动化，因此 IT 管理员在*补丁星期二*时的痛苦会随着 Docker 的出现而消失。

# 使用 DTR 保护软件供应链

DTR 是 Docker 扩展 EE 提供的第二部分。（我在第八章中介绍了**Universal Control Plane**（**UCP**），*管理和监控 Docker 化解决方案*。）DTR 是一个私有的 Docker 注册表，为 Docker 平台的整体安全性故事增添了一个重要组成部分：一个安全的软件供应链。

您可以使用 DTR 对 Docker 镜像进行数字签名，并且 DTR 允许您配置谁可以推送和拉取镜像，安全地存储用户对镜像应用的所有数字签名。它还与 UCP 一起工作，以强制执行**内容信任**。通过 Docker 内容信任，您可以设置集群，使其仅运行由特定用户或团队签名的镜像中的容器。

这是一个强大的功能，符合许多受监管行业的审计要求。公司可能需要证明生产中运行的软件实际上是从 SCM 中的代码构建的。没有软件供应链，这是非常难以做到的；您必须依赖手动流程和文件记录。使用 Docker，您可以在平台上强制执行它，并通过自动化流程满足审计要求。

# 仓库和用户

DTR 使用与 UCP 相同的身份验证模型，因此您可以使用您的**Active Directory**（**AD**）帐户登录，或者您可以使用在 UCP 中创建的帐户。DTR 使用与 UCP 相同的组织、团队和用户的授权模型，但权限是分开的。用户可以对 DTR 中的镜像仓库和从这些镜像中运行的服务具有完全不同的访问权限。

DTR 授权模型的某些部分与 Docker Hub 相似。用户可以拥有公共或私人存储库，这些存储库以他们的用户名为前缀。管理员可以创建组织，组织存储库可以对用户和团队进行细粒度的访问控制。

我在第四章中介绍了镜像注册表和存储库，*使用 Docker 注册表共享镜像*。存储库的完整名称包含注册表主机、所有者和存储库名称。我在 Azure 中使用 Docker Certified Infrastructure 搭建了一个 Docker Enterprise 集群。我创建了一个名为`elton`的用户，他拥有一个私人存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/016f0d1b-a23f-4268-b118-5a272601c40e.png)

要将镜像推送到名为`private-app`的存储库，需要使用完整的 DTR 域标记它的存储库名称为用户`elton`。我的 DTR 实例正在运行在`dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com`，所以我需要使用的完整镜像名称是`dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app`：

```
docker image tag sixeyed/file-echo:nanoserver-1809 `
 dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app
```

这是一个私人存储库，所以只能被用户`elton`访问。DTR 呈现与任何其他 Docker 注册表相同的 API，因此我需要使用`docker login`命令登录，指定 DTR 域作为注册表地址：

```
> docker login dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com
Username: elton
Password:
Login Succeeded

> docker image push dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app
The push refers to repository [dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app]
2f2b0ced10a1: Pushed
d3b13b9870f8: Pushed
81ab83c18cd9: Pushed
cc38bf58dad3: Pushed
af34821b76eb: Pushed
16575d9447bd: Pushing [==================================================>]  52.74kB
0e5e668fa837: Pushing [==================================================>]  52.74kB
3ec5dbbe3201: Pushing [==================================================>]  1.191MB
1e88b250839e: Pushing [==================================================>]  52.74kB
64cb5a75a70c: Pushing [>                                                  ]  2.703MB/143MB
eec13ab694a4: Waiting
37c182b75172: Waiting
...
...
```

如果我将存储库设为公开，任何有权访问 DTR 的人都可以拉取镜像，但这是一个用户拥有的存储库，所以只有`elton`账户有推送权限。

这与 Docker Hub 相同，任何人都可以从我的`sixeyed`用户存储库中拉取镜像，但只有我可以推送它们。对于需要多个用户访问推送镜像的共享项目，您可以使用组织。

# 组织和团队

组织用于共享存储库的所有权。组织及其拥有的存储库与拥有存储库权限的用户是分开的。特定用户可能具有管理员访问权限，而其他用户可能具有只读访问权限，特定团队可能具有读写访问权限。

DTR 的用户和组织模型与 Docker Hub 的付费订阅层中的模型相同。如果您不需要完整的 Docker Enterprise 生产套件，但需要具有共享访问权限的私人存储库，您可以使用 Docker Hub。

我在 nerd-dinner 组织下为 NerdDinner 堆栈的更多组件创建了存储库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/8a5e090e-42bb-443a-aa48-b0592e29a4b2.png)

我可以向个别用户或团队授予对存储库的访问权限。**Nerd Dinner Ops**团队是我在 UCP 中创建的管理员用户组。这些用户可以直接推送图像，因此他们对所有存储库具有读写权限：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/efec642a-563b-4090-80e9-737e9293866a.png)

Nerd Dinner 测试团队只需要对存储库具有读取权限，因此他们可以在本地拉取图像进行测试，但无法将图像推送到注册表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d3812ad2-757f-48e7-9a60-ea678de03287.png)

在 DTR 中组织存储库取决于您。您可以将所有应用程序存储库放在一个组织下，并为可能在许多项目中使用的共享组件（如 NATS 和 Elasticsearch）创建一个单独的组织。这意味着共享组件可以由专门的团队管理，他们可以批准更新并确保所有项目都使用相同的版本。项目团队成员具有读取权限，因此他们可以随时拉取最新的共享图像并运行其完整的应用程序堆栈，但他们只能将更新推送到其项目存储库。

DTR 具有无、读取、读写和管理员的权限级别。它们可以应用于团队或个别用户的存储库级别。DTR 和 UCP 的一致身份验证但分离授权模型意味着开发人员可以在 DTR 中具有完全访问权限以拉取和推送图像，但在 UCP 中可能只有读取权限以查看运行中的容器。

在成熟的工作流程中，您不会让个人用户推送图像 - 一切都将自动化。您的初始推送将来自构建图像的 CI 系统，然后您将为图像添加来源层，从推广政策开始。

# DTR 中的图像推广政策

许多公司在其注册表中使用多个存储库来存储应用程序生命周期不同阶段的图像。最简单的例子是`nerd-dinner-test/web`存储库，用于正在经历各种测试阶段的图像，以及`nerd-dinner-prod/web`存储库，用于已获得生产批准的图像。

DTR 提供了图像推广政策，可以根据您指定的标准自动将图像从一个存储库复制到另一个存储库。这为安全软件供应链增加了重要的链接。CI 流程可以从每次构建中将图像推送到测试存储库，然后 DTR 可以检查图像并将其推广到生产存储库。

您可以根据扫描中发现的漏洞数量、镜像标签的内容以及镜像中使用的开源组件的软件许可证来配置推广规则。我已经为从`nerd-dinner-test/web`到`nerd-dinner-prod/web`的镜像配置了一些合理的推广策略：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/cf81e705-c28b-4049-9b36-131360593401.png)

当我将符合所有标准的镜像推送到测试仓库时，它会被 DTR 自动推广到生产仓库：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2218ea06-00d5-4f85-ab96-a2ce137c079f.png)

配置生产仓库，使得没有最终用户可以直接推送到其中，意味着镜像只能通过 DTR 的推广等自动化流程到达那里。

Docker Trusted Registry 为您提供了构建安全交付流水线所需的所有组件，但它并不强制执行任何特定的流程或技术。来自 DTR 的事件可以触发 webhooks，这意味着您可以将您的注册表与几乎任何 CI 系统集成。触发 webhook 的一个事件是镜像推广，您可以使用它来触发新镜像的自动签名。

# 镜像签名和内容信任

DTR 利用 UCP 管理的客户端证书对镜像进行数字签名，可以追踪到已知用户帐户。用户从 UCP 下载客户端捆绑包，其中包含其客户端证书的公钥和私钥，该证书由 Docker CLI 使用。

您可以使用相同的方法处理其他系统的用户帐户，因此您可以为您的 CI 服务创建一个帐户，并设置仓库，以便只有 CI 帐户可以访问推送。这样，您可以将镜像签名集成到您的安全交付流水线中，从 CI 流程应用签名，并使用它来强制执行内容信任。

您可以通过环境变量打开 Docker 内容信任，并且当您将镜像推送到注册表时，Docker 将使用来自您客户端捆绑包的密钥对其进行签名。内容信任仅适用于特定的镜像标签，而不适用于默认的`latest`标签，因为签名存储在标签上。

我可以给我的私有镜像添加`v2`标签，在 PowerShell 会话中启用内容信任，并将标记的镜像推送到 DTR：

```
> docker image tag `
    dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app `
    dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app:v2

> $env:DOCKER_CONTENT_TRUST=1

> >docker image push dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app:v2The push refers to repository [dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app]
2f2b0ced10a1: Layer already exists
...
v2: digest: sha256:4c830828723a89e7df25a1f6b66077c1ed09e5f99c992b5b5fbe5d3f1c6445f2 size: 3023
Signing and pushing trust metadata
Enter passphrase for root key with ID aa2544a:
Enter passphrase for new repository key with ID 2ef6158:
Repeat passphrase for new repository key with ID 2ef6158:
Finished initializing "dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app"
Successfully signed dtrapp-dow2e-hvfz.centralus.cloudapp.azure.com/elton/private-app:v2
```

推送图像的行为会添加数字签名，在这种情况下使用`elton`帐户的证书并为存储库创建新的密钥对。DTR 记录每个图像标签的签名，在 UI 中我可以看到`v2`图像标签已签名：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2dfc1580-d358-4b20-ada7-acac29c0dd88.png)

用户可以推送图像以添加自己的签名。这使得批准流水线成为可能，授权用户拉取图像，运行他们需要的任何测试，然后再次推送以确认他们的批准。

DTR 使用 Notary 来管理访问密钥和签名。与 SwarmKit 和 LinuxKit 一样，Notary 是 Docker 集成到商业产品中的开源项目，添加功能并提供支持。要查看图像签名和内容信任的实际操作，请查看我的 Pluralsight 课程*Getting Started with Docker Datacenter*。

UCP 与 DTR 集成以验证图像签名。在管理设置中，您可以配置 UCP，使其可以运行已由组织中已知团队签名的图像的容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/1e574805-ce05-490b-b97e-c170869b6550.png)

我已经配置了 Docker 内容信任，以便 UCP 只运行已由 Nerd Dinners Ops 团队成员签名的容器。这明确捕获了发布批准工作流程，并且平台强制执行它。甚至管理员也不能运行未经所需团队用户签名的图像的容器——UCP 将抛出错误，指出图像未满足签名策略：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/94659751-ead8-47c1-b879-881b3dbb21c3.png)

构建安全的软件供应链是关于建立一个自动化流水线，您可以保证图像已由已知用户帐户推送，它们满足特定的质量标准，并且已由已知用户帐户签名。DTR 提供了所有集成这一点到 CI 流水线中的功能，使用诸如 Jenkins 或 Azure DevOps 之类的工具。您可以使用任何自动化服务器或服务，只要它可以运行 shell 命令并响应 webhook——这几乎是每个系统。

有一个 Docker 参考架构详细介绍了安全供应链，以 GitLab 作为示例 CI 服务器，并向您展示如何将安全交付流水线与 Docker Hub 或 DTR 集成。您可以在[`success.docker.com/article/secure-supply-chain`](https://success.docker.com/article/secure-supply-chain)找到它。

# 黄金图像

镜像和注册表的最后一个安全考虑是用于应用程序镜像的基础镜像的来源。在生产中运行 Docker 的公司通常限制开发人员可以使用的基础镜像集，该集已获得基础设施或安全利益相关者的批准。可供使用的这组黄金镜像可能仅在文档中记录，但使用私有注册表更容易强制执行。

在 Windows 环境中，黄金镜像可能仅限于两个选项：Windows Server Core 的一个版本和 Nano Server 的一个版本。运维团队可以从 Microsoft 的基础镜像构建自定义镜像，而不是允许用户使用公共 Microsoft 镜像。自定义镜像可能会添加安全或性能调整，或设置一些适用于所有应用程序的默认值，例如打包公司的证书颁发机构证书。

使用 DTR，您可以为所有基础镜像创建一个组织，运维团队对存储库具有读写访问权限，而所有其他用户只有读取权限。检查镜像是否使用有效的基础镜像只意味着检查 Dockerfile 是否使用了来自 base-images 组织的镜像，这是在 CI/CD 过程中轻松自动化的测试。

黄金镜像为您的组织增加了管理开销，但随着您将越来越多的应用程序迁移到 Docker，这种开销变得更加值得。拥有自己的 ASP.NET 镜像，并使用公司的默认配置部署，使安全团队可以轻松审计基础镜像。您还拥有自己的发布节奏和注册表域，因此您不需要在 Dockerfile 中使用古怪的镜像名称。

# 了解集群模式中的安全性

Docker 的深度安全性方法涵盖了整个软件生命周期，从构建时的镜像签名和扫描到运行时的容器隔离和管理。我将以概述在集群模式中实施的安全功能结束本章。

分布式软件提供了许多有吸引力的攻击向量。组件之间的通信可能会被拦截和修改。恶意代理可以加入网络并访问数据或运行工作负载。分布式数据存储可能会受到损害。建立在开源 SwarmKit 项目之上的 Docker 集群模式在平台级别解决了这些向量，因此您的应用程序默认在安全基础上运行。

# 节点和加入令牌

您可以通过运行`docker swarm init`切换到集群模式。此命令的输出会给您一个令牌，您可以使用它让其他节点加入集群。工作节点和管理节点有单独的令牌。节点没有令牌无法加入集群，因此您需要像保护其他秘密一样保护令牌。

加入令牌由前缀、格式版本、根密钥的哈希和密码学强随机字符串组成。

Docker 使用固定的`SWMTKN`前缀用于令牌，因此您可以运行自动检查，以查看令牌是否在源代码或其他公共位置上被意外共享。如果令牌受到损害，恶意节点可能会加入集群，如果它们可以访问您的网络。集群模式可以使用特定网络进行节点流量，因此您应该使用一个不公开可访问的网络。

加入令牌可以通过`join-token rotate`命令进行旋转，可以针对工作节点令牌或管理节点令牌进行操作：

```
> docker swarm join-token --rotate worker
Successfully rotated worker join token.

To add a worker to this swarm, run the following command:

 docker swarm join --token SWMTKN-1-0ngmvmnpz0twctlya5ifu3ajy3pv8420st...  10.211.55.7:2377
```

令牌旋转是集群的完全托管操作。所有现有节点都会更新，并且任何错误情况，如节点离线或在旋转过程中加入，都会得到优雅处理。

# 加密和秘密

集群节点之间的通信使用**传输层安全性**（**TLS**）进行加密。当您创建集群时，集群管理器会将自身配置为认证机构，并在节点加入时为每个节点生成证书。集群中的节点之间的通信使用相互 TLS 进行加密。

相互 TLS 意味着节点可以安全地通信并相互信任，因为每个节点都有一个受信任的证书来标识自己。节点被分配一个在证书中使用的随机 ID，因此集群不依赖于主机名等属性，这些属性可能会被伪造。

节点之间的可信通信是集群模式中 Docker Secrets 的基础。秘密存储在管理节点的 Raft 日志中并进行加密，只有当工作节点要运行使用该秘密的容器时，才会将秘密发送给工作节点。秘密在传输过程中始终使用相互 TLS 进行加密。在工作节点上，秘密以明文形式在临时 RAM 驱动器上可用，并作为卷挂载到容器中。数据永远不会以明文形式持久保存。

Windows 没有本地的 RAM 驱动器，因此目前的秘密实现将秘密数据存储在工作节点的磁盘上，并建议使用 BitLocker 来保护系统驱动器。秘密文件在主机上受 ACLs 保护。

在容器内部，对秘密文件的访问受到限制，只能由特定用户帐户访问。在 Linux 中可以指定具有访问权限的帐户，但在 Windows 中，目前有一个固定的列表。我在第七章的 ASP.NET Web 应用程序中使用了秘密，*使用 Docker Swarm 编排分布式解决方案*，您可以在那里看到我配置了 IIS 应用程序池以使用具有访问权限的帐户。

当容器停止、暂停或删除时，容器可用的秘密将从主机中删除。在 Windows 上，秘密目前被持久化到磁盘，如果主机被强制关闭，那么在主机重新启动时秘密将被删除。

# 节点标签和外部访问

一旦节点被添加到集群中，它就成为容器工作负载的候选对象。许多生产部署使用约束条件来确保应用程序在正确类型的节点上运行，并且 Docker 将尝试将请求的约束与节点上的标签进行匹配。

在受监管的环境中，您可能需要确保应用程序仅在已满足所需审核级别的服务器上运行，例如用于信用卡处理的 PCI 合规性。您可以使用标签识别符合条件的节点，并使用约束条件确保应用程序仅在这些节点上运行。集群模式有助于确保这些约束得到适当执行。

集群模式中有两种类型的标签：引擎标签和节点标签。引擎标签由 Docker 服务配置中的机器设置，因此，如果工作节点受到攻击者的攻击，攻击者可以添加标签，使他们拥有的机器看起来合规。节点标签由集群设置，因此只能由具有对集群管理器访问权限的用户创建。节点标签意味着您不必依赖于各个节点提出的声明，因此，如果它们受到攻击，影响可以得到限制。

节点标签在隔离对应用程序的访问方面也很有用。您可能有仅在内部网络上可访问的 Docker 主机，也可能有访问公共互联网的主机。使用标签，您可以明确记录它作为一个区别，并根据标签运行具有约束的容器。您可以在容器中拥有一个仅在内部可用的内容管理系统，但一个公开可用的 Web 代理。

# 与容器安全技术的集成

Docker Swarm 是一个安全的容器平台，因为它使用开源组件和开放标准，所以与第三方工具集成得很好。当应用程序在容器中运行时，它们都暴露相同的 API——您可以使用 Docker 来检查容器中运行的进程，查看日志条目，浏览文件系统，甚至运行新命令。容器安全生态系统正在发展强大的工具，利用这一点在运行时增加更多的安全性。

如果您正在寻找 Windows 容器的扩展安全性，有两个主要供应商可供评估：Twistlock 和 Aqua Security。两者都有包括镜像扫描和秘密管理、运行时保护在内的全面产品套件，这是为您的应用程序增加安全性的最创新方式。

当您将运行时安全产品部署到集群时，它会监视容器并构建该应用程序的典型行为文件，包括 CPU 和内存使用情况，以及进出的网络流量。然后，它会寻找该应用程序实例中的异常情况，即容器开始表现出与预期模型不同的方式。这是识别应用程序是否被入侵的强大方式，因为攻击者通常会开始运行新进程或移动异常数量的数据。

以 Aqua Security 为例，它为 Windows 上的 Docker 提供了全套保护，扫描镜像并为容器提供运行时安全控制。这包括阻止从不符合安全标准的镜像中运行的容器——标记为 CVE 严重程度或平均分数、黑名单和白名单软件包、恶意软件、敏感数据和自定义合规性检查。

Aqua 还强制执行容器的不可变性，将运行的容器与其原始图像进行比较，并防止更改，比如安装新的可执行文件。这是防止恶意代码注入或尝试绕过图像管道控制的强大方式。如果您从一个包含许多实际上不需要的组件的大型基础图像构建图像，Aqua 可以对攻击面进行分析，并列出实际需要的功能和能力。

这些功能适用于遗留应用程序中的容器，就像新的云原生应用程序一样。能够为应用程序部署的每一层添加深度安全，并实时监视可疑妥协，使安全方面成为迁移到容器的最有力的原因之一。

# 总结

本章讨论了 Docker 和 Windows 容器的安全考虑。您了解到 Docker 平台是为深度安全而构建的，并且容器的运行时安全只是故事的一部分。安全扫描、图像签名、内容信任和安全的分布式通信可以结合起来，为您提供一个安全的软件供应链。

你研究了在 Docker 中运行应用程序的实际安全方面，并了解了 Windows 容器中的进程是如何在一个上下文中运行的，这使得攻击者很难逃离容器并侵入其他进程。容器进程将使用它们所需的所有计算资源，但我还演示了如何限制 CPU 和内存使用，这可以防止恶意容器耗尽主机的计算资源。

在 docker 化的应用程序中，您有更多的空间来实施深度安全。我解释了为什么最小化的镜像有助于保持应用程序的安全，以及您如何使用 Docker 安全扫描来在您的应用程序使用的任何依赖关系中发现漏洞时收到警报。您可以通过数字签名图像并配置 Docker，以便它只运行已获得批准用户签名的图像中的容器，来强制执行良好的实践。

最后，我看了一下 Docker Swarm 中的安全实现。Swarm 模式拥有所有编排层中最深入的安全性，并为您提供了一个稳固的基础，让您可以安全地运行应用程序。使用 secrets 来存储敏感的应用程序数据，使用节点标签来识别主机的合规性，使您可以轻松地运行一个安全的解决方案，而开放的 API 使得集成第三方安全增强，如 Aqua 变得很容易。

在下一章中，我们将使用分布式应用程序，并着眼于构建 CI/CD 的流水线。Docker 引擎可以配置为提供对 API 的远程访问，因此很容易将 Docker 部署与任何构建系统集成。CI 服务器甚至可以在 Docker 容器内运行，您可以使用 Docker 作为构建代理，因此对于 CI/CD，您不需要任何复杂的配置。


# 第十章：使用 Docker 推动持续部署管道

Docker 支持构建和运行可以轻松分发和管理的组件。该平台还适用于开发环境，其中源代码控制、构建服务器、构建代理和测试代理都可以从标准镜像中运行在 Docker 容器中。

在开发中使用 Docker 可以让您在单一硬件集中 consoli 许多项目，同时保持隔离。您可以在 Docker Swarm 中运行具有高可用性的 Git 服务器和镜像注册表的服务，这些服务由许多项目共享。每个项目可以配置有自己的管道和自己的构建设置的专用构建服务器，在轻量级 Docker 容器中运行。

在这种环境中设置新项目只是在源代码控制存储库中创建新存储库和新命名空间，并运行新容器进行构建过程。所有这些步骤都可以自动化，因此项目入职变成了一个只需几分钟并使用现有硬件的简单过程。

在本章中，我将带您完成使用 Docker 设置**持续集成和持续交付**（**CI/CD**）管道。我将涵盖：

+   使用 Docker 设计 CI/CD

+   在 Docker 中运行共享开发服务

+   在 Docker 中使用 Jenkins 配置 CI/CD

+   使用 Jenkins 部署到远程 Docker Swarm

# 技术要求

您需要在 Windows 10 更新 18.09 或 Windows Server 2019 上运行 Docker，以便按照示例进行操作。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch10`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch10)上找到。

# 使用 Docker 设计 CI/CD

该管道将支持完整的持续集成。当开发人员将代码推送到共享源代码存储库时，将触发生成发布候选版本的构建。发布候选版本将被标记为存储在本地注册表中的 Docker 镜像。CI 工作流从构建的图像中部署解决方案作为容器，并运行端到端测试包。

我的示例管道具有手动质量门。如果测试通过，图像版本将在 Docker Hub 上公开可用，并且管道可以在远程 Docker Swarm 上运行的公共环境中启动滚动升级。在完整的 CI/CD 环境中，您还可以在管道中自动部署到生产环境。

流水线的各个阶段都将由运行在 Docker 容器中的软件驱动：

+   源代码控制：Gogs，一个用 Go 编写的简单的开源 Git 服务器

+   构建服务器：Jenkins，一个基于 Java 的自动化工具，使用插件支持许多工作流

+   构建代理：将.NET SDK 打包成一个 Docker 镜像，以在容器中编译代码

+   测试代理：NUnit 打包成一个 Docker 镜像，用于对部署的代码进行端到端测试

Gogs 和 Jenkins 可以在 Docker Swarm 上或在单独的 Docker Engine 上运行长时间运行的容器。构建和测试代理是由 Jenkins 运行的任务容器，用于执行流水线步骤，然后它们将退出。发布候选将部署为一组容器，在测试完成时将被删除。

设置这个的唯一要求是让容器访问 Docker API——在本地和远程环境中都是如此。在本地服务器上，我将使用来自 Windows 的命名管道。对于远程 Docker Swarm，我将使用一个安全的 TCP 连接。我在第一章中介绍了如何保护 Docker API，*在 Windows 上使用 Docker 入门*，使用`dockeronwindows/ch01-dockertls`镜像生成 TLS 证书。您需要配置本地访问权限，以便 Jenkins 容器可以在开发中创建容器，并配置远程访问权限，以便 Jenkins 可以在公共环境中启动滚动升级。

这个流水线的工作流是当开发人员将代码推送到运行 Gogs 的 Git 服务器时开始的，Gogs 运行在一个 Docker 容器中。Jenkins 被配置为轮询 Gogs 存储库，如果有任何更改，它将开始构建。解决方案中的所有自定义组件都使用多阶段的 Dockerfile，这些文件存储在项目的 Git 存储库中。Jenkins 对每个 Dockerfile 运行`docker image build`命令，在同一 Docker 主机上构建镜像，Jenkins 本身也在一个容器中运行。

构建完成后，Jenkins 将解决方案部署到本地，作为同一 Docker 主机上的容器。然后，它运行端到端测试，这些测试打包在一个 Docker 镜像中，并作为一个容器在与被测试的应用程序相同的 Docker 网络中运行。如果所有测试都通过了，那么最终的流水线步骤将把这些图像作为发布候选推送到本地注册表中，而注册表也在一个 Docker 容器中运行。

当您在 Docker 中运行开发工具时，您将获得与在 Docker 中运行生产工作负载时相同的好处。整个工具链变得可移植，您可以在任何地方以最小的计算要求运行它。

# 在 Docker 中运行共享开发服务

诸如源代码控制和镜像注册表之类的服务是很适合在多个项目之间共享的候选项。它们对于高可用性和可靠存储有类似的要求，因此可以部署在具有足够容量的集群上，以满足许多项目的需求。CI 服务器可以作为共享服务运行，也可以作为每个团队或项目的单独实例运行。

我在第四章中介绍了在 Docker 容器中运行私有注册表，*使用 Docker 注册表共享镜像*。在这里，我们将看看如何在 Docker 中运行 Git 服务器和 CI 服务器。

# 将 Git 服务器打包到 Windows Docker 镜像中

Gogs 是一个流行的开源 Git 服务器。它是用 Go 语言编写的，跨平台，可以将其打包为基于最小 Nano Server 安装或 Windows Server Core 的 Docker 镜像。Gogs 是一个简单的 Git 服务器；它通过 HTTP 和 HTTPS 提供远程存储库访问，并且具有 Web UI。Gogs 团队在 Docker Hub 上提供了 Linux 的镜像，但您需要构建自己的镜像以在 Windows 容器中运行。

将 Gogs 打包到 Docker 镜像中非常简单。这是在 Dockerfile 中编写安装说明的情况，我已经为`dockeronwindows/ch10-gogs:2e`镜像完成了这个过程。该镜像使用多阶段构建，从 Windows Server Core 开始，下载 Gogs 发布并展开 ZIP 文件。

```
#escape=` FROM mcr.microsoft.com/windows/servercore:ltsc2019 as installer SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"] ARG GOGS_VERSION="0.11.86" RUN Write-Host "Downloading: $($env:GOGS_VERSION)"; `
 Invoke-WebRequest -Uri "https://cdn.gogs.io/$($env:GOGS_VERSION)...zip" -OutFile 'gogs.zip'; RUN  Expand-Archive gogs.zip -DestinationPath C:\;
```

这里没有什么新东西，但有几点值得关注。Gogs 团队提供了一个 CDN 来发布他们的版本，并且 URL 使用相同的格式，所以我已经将版本号参数化为可下载。`ARG`指令使用默认的 Gogs 版本`0.11.86`，但我可以通过指定构建参数来安装不同的版本，而无需更改 Dockerfile。

为了清楚地表明正在安装的版本，我在下载 ZIP 文件之前写出了版本号。下载在单独的`RUN`指令中进行，因此下载的文件被存储在 Docker 缓存中的自己的层中。如果我需要编辑 Dockerfile 中的后续步骤，我可以再次构建镜像，并从缓存中获取已下载的文件，因此不需要重复下载。

最终镜像可以基于 Nano Server，因为 Gogs 是一个跨平台技术，但它依赖于难以在 Nano Server 中设置的 Git 工具。使用 Chocolatey 很容易安装依赖项，但在 Nano Server 中无法使用。我正在使用`sixeyed/chocolatey`作为基础应用程序镜像，这是 Docker Hub 上的一个公共镜像，在 Windows Server Core 上安装了 Chocolatey，然后我为 Gogs 设置了环境：

```
FROM sixeyed/chocolatey:windowsservercore-ltsc2019 ARG GOGS_VERSION="0.11.86" ARG GOGS_PATH="C:\gogs"

ENV GOGS_VERSION=${GOGS_VERSION} `GOGS_PATH=${GOGS_PATH} EXPOSE 3000 VOLUME C:\data C:\logs C:\repositories CMD ["gogs", "web"]
```

我正在捕获 Gogs 版本和安装路径作为`ARG`指令，以便它们可以在构建时指定。构建参数不会存储在最终镜像中，所以我将它们复制到`ENV`指令中的环境变量中。Gogs 默认使用端口`3000`，我为所有数据、日志和存储库目录创建卷。

Gogs 是一个 Git 服务器，但它的发布版本中不包括 Git，这就是为什么我使用了安装了 Chocolatey 的镜像。我使用`choco`命令行来安装`git`：

```
RUN choco install -y git
```

最后，我从安装程序阶段复制了扩展的`Gogs`目录，并从本地的`app.ini`文件中捆绑了一组默认配置：

```
WORKDIR ${GOGS_PATH} COPY app.ini ./custom/conf/app.ini COPY --from=installer ${GOGS_PATH} .
```

构建这个镜像给我一个可以在 Windows 容器中运行的 Git 服务器。

使用比所需更大的基础镜像以及包括 Chocolatey 等安装工具的应用程序镜像并不是最佳实践。如果我的 Gogs 容器受到攻击，攻击者将可以访问`choco`命令以及 PowerShell 的所有功能。在这种情况下，容器不会在公共网络上，因此风险得到了缓解。

# 在 Docker 中运行 Gogs Git 服务器

您可以像运行任何其他容器一样运行 Gogs：将其设置为分离状态，发布 HTTP 端口，并使用主机挂载将卷存储在容器之外已知位置：

```
> mkdir C:\gogs\data; mkdir C:\gogs\repos

> docker container run -d -p 3000:3000 `
    --name gogs `
    -v C:\gogs\data:C:\data `
    -v C:\gogs\repos:C:\gogs\repositories `
    dockeronwindows/ch10-gogs:2e
```

Gogs 镜像内置了默认配置设置，但当您第一次运行应用程序时，您需要完成安装向导。我可以浏览到`http://localhost:3000`，保留默认值，并点击安装 Gogs 按钮：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/25fa9119-bc6b-4f11-9fe2-edabd0b2d520.png)

现在，我可以注册用户并登录，这将带我到 Gogs 仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/729ae508-9bc9-46ae-9fdb-1e3c84e7b997.png)

Gogs 支持问题跟踪和拉取请求，除了通常的 Git 功能，因此它非常类似于 GitHub 的精简本地版本。我继续创建了一个名为`docker-on-windows`的存储本书源代码的存储库。为了使用它，我需要将 Gogs 服务器添加为我的本地 Git 存储库的远程。

我使用`gogs`作为容器名称，所以其他容器可以通过该名称访问 Git 服务器。我还在我的主机文件中添加了一个与本地机器指向相同名称的条目，这样我就可以在我的机器和容器内使用相同的`gogs`名称（这在`C:\Windows\System32\drivers\etc\hosts`中）：

```
#ch10 
127.0.0.1  gogs
```

我倾向于经常这样做，将本地机器或容器 IP 地址添加到我的主机文件中。我设置了一个 PowerShell 别名，使这一过程更加简单，它可以获取容器 IP 地址并将该行添加到主机文件中。我在[`blog.sixeyed.com/your-must-have-powershell-aliases-for-docker`](https://blog.sixeyed.com/your-must-have-powershell-aliases-for-docker)上发表了这一点以及我使用的其他别名。

现在，我可以像将源代码推送到 GitHub 或 GitLab 等其他远程 Git 服务器一样，从我的本地机器推送源代码到 Gogs。它在本地容器中运行，但对于我笔记本上的 Git 客户端来说是透明的。

```
> git remote add gogs http://gogs:3000/docker-on-windows.git

> git push gogs second-edition
Enumerating objects: 2736, done.
Counting objects: 100% (2736/2736), done.
Delta compression using up to 2 threads
Compressing objects: 100% (2058/2058), done.
Writing objects: 100% (2736/2736), 5.22 MiB | 5.42 MiB/s, done.
Total 2736 (delta 808), reused 2089 (delta 487)
remote: Resolving deltas: 100% (808/808), done.
To http://gogs:3000/elton/docker-on-windows.git
 * [new branch]      second-edition -> second-edition
```

Gogs 在 Docker 容器中是稳定且轻量的。我的实例在空闲时通常使用 50MB 的内存和少于 1%的 CPU。

运行本地 Git 服务器是一个好主意，即使你使用托管服务如 GitHub 或 GitLab。托管服务会出现故障，尽管很少，但可能会对生产力产生重大影响。拥有一个本地次要运行成本很低的服务器可以保护你免受下一次故障发生时的影响。

下一步是在 Docker 中运行一个 CI 服务器，该服务器可以从 Gogs 获取代码并构建应用程序。

# 将 CI 服务器打包成 Windows Docker 镜像

Jenkins 是一个流行的自动化服务器，用于 CI/CD。它支持具有多种触发类型的自定义作业工作流程，包括计划、SCM 轮询和手动启动。它是一个 Java 应用程序，可以很容易地在 Docker 中打包，尽管完全自动化 Jenkins 设置并不那么简单。

在本章的源代码中，我有一个用于`dockersamples/ch10-jenkins-base:2e`映像的 Dockerfile。这个 Dockerfile 使用 Windows Server Core 在安装阶段下载 Jenkins web 存档文件，打包了一个干净的 Jenkins 安装。我使用一个参数来捕获 Jenkins 版本，安装程序还会下载下载的 SHA256 哈希并检查下载的文件是否已损坏：

```
WORKDIR C:\jenkins  RUN Write-Host "Downloading Jenkins version: $env:JENKINS_VERSION"; `
 Invoke-WebRequest  "http://.../jenkins.war.sha256" -OutFile 'jenkins.war.sha256'; `
   Invoke-WebRequest "http://../jenkins.war" -OutFile 'jenkins.war' RUN $env:JENKINS_SHA256=$(Get-Content -Raw jenkins.war.sha256).Split(' ')[0]; `
    if ((Get-FileHash jenkins.war -Algorithm sha256).Hash.ToLower() -ne $env:JENKINS_SHA256) {exit 1}
```

检查下载文件的哈希值是一个重要的安全任务，以确保您下载的文件与发布者提供的文件相同。这是人们通常在手动安装软件时忽略的一步，但在 Dockerfile 中很容易自动化，并且可以为您提供更安全的部署。

Dockerfile 的最后阶段使用官方的 OpenJDK 映像作为基础，设置环境，并从安装程序阶段复制下载的文件：

```
FROM openjdk:8-windowsservercore-1809 ARG JENKINS_VERSION="2.150.3" ENV JENKINS_VERSION=${JENKINS_VERSION} ` JENKINS_HOME="C:\data" VOLUME ${JENKINS_HOME} EXPOSE 8080 50000 WORKDIR C:\jenkins ENTRYPOINT java -jar C:\jenkins\jenkins.war COPY --from=installer C:\jenkins .
```

干净的 Jenkins 安装没有太多有用的功能；几乎所有功能都是在设置 Jenkins 之后安装的插件提供的。其中一些插件还会安装它们所需的依赖项，但其他一些则不会。对于我的 CI/CD 流水线，我需要在 Jenkins 中安装 Git 客户端，以便它可以连接到在 Docker 中运行的 Git 服务器，并且我还希望安装 Docker CLI，以便我可以在构建中使用 Docker 命令。

我可以在 Jenkins 的 Dockerfile 中安装这些依赖项，但这将使其变得庞大且难以管理。相反，我将从其他 Docker 映像中获取这些工具。我使用的是`sixeyed/git`和`sixeyed/docker-cli`，这些都是 Docker Hub 上的公共映像。我将这些与 Jenkins 基础映像一起使用，构建我的最终 Jenkins 映像。

`dockeronwindows/ch10-jenkins:2e`的 Dockerfile 从基础开始，并从 Git 和 Docker CLI 映像中复制二进制文件：

```
# escape=` FROM dockeronwindows/ch10-jenkins-base:2e  WORKDIR C:\git COPY --from=sixeyed/git:2.17.1-windowsservercore-ltsc2019 C:\git . WORKDIR C:\docker COPY --from=sixeyed/docker-cli:18.09.0-windowsservercore-ltsc2019 ["C:\\Program Files\\Docker", "."]
```

最后一行只是将所有新的工具位置添加到系统路径中，以便 Jenkins 可以找到它们：

```
RUN $env:PATH = 'C:\docker;' + 'C:\git\cmd;C:\git\mingw64\bin;C:\git\usr\bin;' + $env:PATH; `   [Environment]::SetEnvironmentVariable('PATH', $env:PATH, [EnvironmentVariableTarget]::Machine)
```

使用公共 Docker 映像来获取依赖项，可以让我得到一个包含所有所需组件的最终 Jenkins 映像，但使用一组可重用的源映像编写一个可管理的 Dockerfile。现在，我可以在容器中运行 Jenkins，并通过安装插件完成设置。

# 在 Docker 中运行 Jenkins 自动化服务器

Jenkins 使用端口`8080`用于 Web UI，因此您可以使用以下命令从本章的映像中运行它，该命令映射端口并挂载本地文件夹到 Jenkins 根目录：

```
mkdir C:\jenkins

docker run -d -p 8080:8080 `
 -v C:\jenkins:C:\data `
 --name jenkins `
 dockeronwindows/ch10-jenkins:2e
```

Jenkins 为每个新部署生成一个随机的管理员密码。我可以在浏览网站之前从容器日志中获取该密码：

```
> docker container logs jenkins
...
*******************************************************
Jenkins initial setup is required. An admin user has been created and a password generated.
Please use the following password to proceed to installation:

6467e40d9c9b4d21916c9bdb2b05bba3

This may also be found at: C:\data\secrets\initialAdminPassword
*******************************************************
```

现在，我将浏览本地主机上的端口`8080`，输入生成的密码，并添加我需要的 Jenkins 插件。作为最简单的示例，我选择了自定义插件安装，并选择了文件夹、凭据绑定和 Git 插件，这样我就可以获得大部分所需的功能：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/70485e78-a4b8-4455-bde2-bb6d97d03c8a.png)

我需要一个插件来在构建作业中运行 PowerShell 脚本。这不是一个推荐的插件，因此它不会显示在初始设置列表中。一旦 Jenkins 启动，我转到“管理 Jenkins | 管理插件”，然后从“可用”列表中选择 PowerShell 并单击“无需重启安装”：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/fb15f9c8-c31c-4d2b-a3b7-3c6d8d03dfaa.png)

完成后，我拥有了运行 CI/CD 流水线所需的所有基础设施服务。但是，它们运行在已经定制过的容器中。Gogs 和 Jenkins 容器中的应用程序经历了手动设置阶段，并且与它们运行的镜像不处于相同的状态。如果我替换容器，我将丢失我所做的额外设置。我可以通过从容器创建镜像来解决这个问题。

# 从运行的容器中提交镜像

您应该从 Dockerfile 构建您的镜像。这是一个可重复的过程，可以存储在源代码控制中进行版本控制、比较和授权。但是有一些应用程序在部署后需要额外的设置步骤，并且这些步骤需要手动执行。

Jenkins 是一个很好的例子。您可以使用 Jenkins 自动安装插件，但这需要额外的下载和一些 Jenkins API 的脚本编写。插件依赖关系并不总是在安装时解决，因此手动设置插件并验证部署可能更安全。完成后，您可以通过提交容器来保持最终设置，从容器的当前状态生成新的 Docker 镜像。

在 Windows 上，您需要停止容器才能提交它们，然后运行`docker container commit`，并提供容器的名称和要创建的新镜像标签：

```
> docker container stop jenkins
jenkins

> docker container commit jenkins dockeronwindows/ch10-jenkins:2e-final
sha256:96dd3caa601c3040927459bd56b46f8811f7c68e5830a1d76c28660fa726960d
```

对于我的设置，我已经提交了 Jenkins 和 Gogs，并且有一个 Docker Compose 文件来配置它们，以及注册表容器。这些是基础设施组件，但这仍然是一个分布式解决方案。Jenkins 容器将访问 Gogs 和注册表容器。所有服务都具有相同的 SLA，因此在 Compose 文件中定义它们可以让我捕获并一起启动所有服务。

# 在 Docker 中使用 Jenkins 配置 CI/CD

我将配置我的 Jenkins 构建作业来轮询 Git 存储库，并使用 Git 推送作为新构建的触发器。

Jenkins 将通过 Gogs 的存储库 URL 连接到 Git，并且构建、测试和部署解决方案的所有操作都将作为 Docker 容器运行。Gogs 服务器和 Docker 引擎具有不同的身份验证模型，但 Jenkins 支持许多凭据类型。我可以配置构建作业以安全地访问源存储库和主机上的 Docker。

# 设置 Jenkins 凭据

Gogs 与外部身份提供者集成，还具有自己的基本用户名/密码身份验证功能，我在我的设置中使用了它。这在 HTTP 上不安全，因此在真实环境中，我将使用 SSH 或 HTTPS 进行 Git，可以通过在镜像中打包 SSL 证书，或者在 Gogs 前面使用代理服务器来实现。

在 Gogs 管理界面的“用户”部分，我创建了一个`jenkins`用户，并为其赋予了对`docker-on-windows`Git 存储库的读取权限，这将用于我的示例 CI/CD 作业：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2f498d84-eb8f-4736-98db-af02df316ae2.png)

Jenkins 将作为`jenkins`用户进行身份验证，从 Gogs 拉取源代码存储库。我已将用户名和密码添加到 Jenkins 作为全局凭据，以便任何作业都可以使用：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/7340759f-72e0-4e85-813e-65ba10c4dee1.png)

Jenkins 在输入密码后不显示密码，并记录使用凭据的所有作业的审计跟踪，因此这是一种安全的身份验证方式。我的 Jenkins 容器正在运行，它使用一个卷将 Windows 主机的 Docker 命名管道挂载，以便它可以在不进行身份验证的情况下与 Docker 引擎一起工作。

作为替代方案，我可以通过 TCP 连接到远程 Docker API。要使用 Docker 进行身份验证，我将使用在保护 Docker 引擎时生成的**传输层安全性**（**TLS**）证书。有三个证书——**证书颁发机构**（**CA**），客户端证书和客户端密钥。它们需要作为文件路径传递给 Docker CLI，并且 Jenkins 支持使用可以保存为秘密文件的凭据来存储证书 PEM 文件。

# 配置 Jenkins CI 作业

在本章中，示例解决方案位于`ch10-nerd-dinner`文件夹中。这是现代化的 NerdDinner 应用程序，在前几章中已经发展过了。每个组件都有一个 Dockerfile。这使用了多阶段构建，并且有一组 Docker Compose 文件用于构建和运行应用程序。

这里的文件夹结构值得一看，以了解分布式应用程序通常是如何排列的——`src`文件夹包含所有应用程序和数据库源代码，`docker`文件夹包含所有 Dockerfile，`compose`文件夹包含所有 Compose 文件。

我在 Jenkins 中创建了一个自由风格的作业来运行构建，并配置了 Git 进行源代码管理。配置 Git 很简单，我使用的是在笔记本电脑上 Git 存储库中使用的相同存储库 URL，并且我已经选择了 Gogs 凭据，以便 Jenkins 可以访问它们：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3830a303-627f-4ede-bf31-101c321f60ff.png)

Jenkins 正在 Docker 容器中运行，Gogs 也在同一 Docker 网络的容器中运行。我正在使用主机名`gogs`，这是容器名称，以便 Jenkins 可以访问 Git 服务器。在我的笔记本电脑上，我已经在 hosts 文件中添加了`gogs`作为条目，这样我就可以在开发和 CI 服务器上使用相同的存储库 URL。

Jenkins 支持多种类型的构建触发器。在这种情况下，我将定期轮询 Git 服务器。我使用`H/5 * * * *`作为调度频率，这意味着 Jenkins 将每五分钟检查存储库。如果自上次构建以来有任何新的提交，Jenkins 将运行作业。

这就是我需要的所有作业配置，所有构建步骤现在将使用 Docker 容器运行。

# 在 Jenkins 中使用 Docker 构建解决方案

构建步骤使用 PowerShell 运行简单的脚本，因此不依赖于更复杂的 Jenkins 插件。有一些特定于 Docker 的插件，可以包装多个任务，比如构建镜像并将其推送到注册表，但我可以使用基本的 PowerShell 步骤和 Docker CLI 来完成我需要的一切。第一步构建所有的镜像：

```
cd .\ch10\ch10-nerd-dinner

docker image build -t dockeronwindows/ch10-nerd-dinner-db:2e `
                   -f .\docker\nerd-dinner-db\Dockerfile .
docker image build -t dockeronwindows/ch10-nerd-dinner-index-handler:2e `
                   -f .\docker\nerd-dinner-index-handler\Dockerfile .
docker image build -t dockeronwindows/ch10-nerd-dinner-save-handler:2e `
                   -f .\docker\nerd-dinner-save-handler\Dockerfile .
...
```

使用`docker-compose build`和覆盖文件会更好，但是 Docker Compose CLI 存在一个未解决的问题，这意味着它在容器内部无法正确使用命名管道。当这个问题在未来的 Compose 版本中得到解决时，构建步骤将更简单。

Docker Compose 是开源的，您可以在 GitHub 上查看此问题的状态：[`github.com/docker/compose/issues/5934`](https://github.com/docker/compose/issues/5934)。

Docker 使用多阶段 Dockerfile 构建镜像，构建的每个步骤在临时 Docker 容器中执行。Jenkins 本身运行在一个容器中，并且它的镜像中有 Docker CLI。我不需要在构建服务器上安装 Visual Studio，甚至不需要安装.NET Framework 或.NET Core SDK。所有的先决条件都在 Docker 镜像中，所以 Jenkins 构建只需要源代码和 Docker。

# 运行和验证解决方案

Jenkins 中的下一个构建步骤将在本地部署解决方案，运行在 Docker 容器中，并验证构建是否正常工作。这一步是另一个 PowerShell 脚本，它首先通过`docker container run`命令部署应用程序：

```
docker container run -d `
  --label ci ` --name nerd-dinner-db `
 dockeronwindows/ch10-nerd-dinner-db:2e; docker container run -d `
  --label ci `
  -l "traefik.frontend.rule=Host:nerd-dinner-test;PathPrefix:/"  `
  -l "traefik.frontend.priority=1"  `
  -e "HomePage:Enabled=false"  `
  -e "DinnerApi:Enabled=false"  `
 dockeronwindows/ch10-nerd-dinner-web:2e; ... 
```

在构建中使用 Docker CLI 而不是 Compose 的一个优势是，我可以按特定顺序创建容器，这样可以给慢启动的应用程序（如 NerdDinner 网站）更多的时间准备好，然后再进行测试。我还给所有的容器添加了一个标签`ci`，以便稍后清理所有的测试容器，而不会删除其他容器。

完成这一步后，所有的容器应该都在运行。在运行可能需要很长时间的端到端测试套件之前，我在构建中有另一个 PowerShell 步骤，运行一个简单的验证测试，以确保应用程序有响应。

```
Invoke-WebRequest  -UseBasicParsing http://nerd-dinner-test
```

请记住，这些命令是在 Jenkins 容器内运行的，这意味着它可以通过名称访问其他容器。我不需要发布特定的端口或检查容器以获取它们的 IP 地址。脚本使用名称`nerd-dinner-test`启动 Traefik 容器，并且所有前端容器在其 Traefik 规则中使用相同的主机名。Jenkins 作业可以访问该 URL，如果构建成功，应用程序将做出响应。

此时，应用程序已经从最新的源代码构建，并且在容器中全部运行。我已经验证了主页是可访问的，这证明了网站正在运行。构建步骤都是控制台命令，因此输出将被写入 Jenkins 作业日志中。对于每个构建，您将看到所有输出，包括以下内容：

+   Docker 执行 Dockerfile 命令

+   NuGet 和 MSBuild 步骤编译应用程序

+   Docker 启动应用程序容器

+   PowerShell 向应用程序发出 Web 请求

`Invoke-WebRequest`命令是一个简单的构建验证测试。如果构建或部署失败，它会产生错误，但是，如果成功，这仍不意味着应用程序正常工作。为了增强对构建的信心，我在下一个构建步骤中运行端到端集成测试。

# 在 Docker 中运行端到端测试

在本章中，我还添加了 NerdDinner 解决方案的另一个组件，即使用模拟浏览器与 Web 应用程序进行交互的测试项目。浏览器向端点发送 HTTP 请求，实际上将是一个容器，并断言响应包含正确的内容。

`NerdDinner.EndToEndTests`项目使用 SpecFlow 来定义功能测试，说明解决方案的预期行为。使用 Selenium 执行 SpecFlow 测试，Selenium 自动化浏览器测试，以及 SimpleBrowser，提供无头浏览器。这些都是可以从控制台运行的 Web 测试，因此不需要 UI 组件，并且可以在 Docker 容器中执行。

如果这听起来像是要添加到您的测试基础设施中的大量技术，实际上这是一种非常巧妙的方式，可以对应用程序进行完整的集成测试，这些测试已经在使用人类语言的简单场景中指定了：

```
Feature: Nerd Dinner Homepage
    As a Nerd Dinner user
    I want to see a modern responsive homepage
    So that I'm encouraged to engage with the app

Scenario: Visit homepage
    Given I navigate to the app at "http://nerd-dinner-test"
    When I see the homepage 
    Then the heading should contain "Nerd Dinner 2.0!"
```

我有一个 Dockerfile 来将测试项目构建成`dockeronwindows/ch10-nerd-dinner-e2e-tests:2e`镜像。它使用多阶段构建来编译测试项目，然后打包测试程序集。构建的最后阶段使用了 Docker Hub 上安装了 NUnit 控制台运行器的镜像，因此它能够通过控制台运行端到端测试。Dockerfile 设置了一个`CMD`指令，在容器启动时运行所有测试：

```
FROM sixeyed/nunit:3.9.0-windowsservercore-ltsc2019 WORKDIR /e2e-tests CMD nunit3-console NerdDinner.EndToEndTests.dll COPY --from=builder C:\e2e-tests .
```

我可以从这个镜像中运行一个容器，它将启动测试套件，连接到`http://nerd-dinner-test`，并断言响应中包含预期的标题文本。这个简单的测试实际上验证了我的新主页容器和反向代理容器都在运行，它们可以在 Docker 网络上相互访问，并且代理规则已经正确设置。

我的测试中只有一个场景，但因为整个堆栈都在容器中运行，所以很容易编写一套执行应用程序关键功能的高价值测试。我可以构建一个包含已知测试数据的自定义数据库镜像，并编写简单的场景来验证用户登录、列出晚餐和创建晚餐的工作流。我甚至可以在测试断言中查询 SQL Server 容器，以确保新数据已插入。

Jenkins 构建的下一步是运行这些端到端测试。同样，这是一个简单的 PowerShell 脚本，它构建端到端 Docker 镜像，然后运行一个容器。测试容器将在与应用程序相同的 Docker 网络中执行，因此无头浏览器可以使用 URL 中的容器名称访问 Web 应用程序：

```
cd .\ch10\ch10-nerd-dinner docker image build ` -t dockeronwindows/ch10-nerd-dinner-e2e-tests:2e ` -f .\docker\nerd-dinner-e2e-tests\Dockerfile . $e2eId  = docker container run -d dockeronwindows/ch10-nerd-dinner-e2e-tests:2e
```

NUnit 生成一个包含测试结果的 XML 文件，将其添加到 Jenkins 工作空间中会很有用，这样在所有容器被移除后可以在 Jenkins UI 中查看。PowerShell 步骤使用`docker container cp`将该文件从容器复制到 Jenkins 工作空间的当前目录中，使用从运行命令中存储的容器 ID：

```
docker container cp "$($e2eId):C:\e2e-tests\TestResult.xml" .
```

在这一步中还有一些额外的 PowerShell 来从该文件中读取 XML 并确定测试是否通过（您可以在本章的源文件夹中的`ci\04_test.ps1`文件中找到完整的脚本）。当完成时，NUnit 的输出将被回显到 Jenkins 日志中：

```
[ch10-nerd-dinner] $ powershell.exe ...
30bc931ca3941b3357e3b991ccbb4eaf71af03d6c83d95ca6ca06faeb8e46a33
* E2E test results:
type          : Assembly
id            : 0-1002
name          : NerdDinner.EndToEndTests.dll
fullname      : NerdDinner.EndToEndTests.dll
runstate      : Runnable
testcasecount : 1
result        : Passed
start-time    : 2019-02-19 20:48:09Z
end-time      : 2019-02-19 20:48:10Z
duration      : 1.305796
total         : 1
passed        : 1
failed        : 0
warnings      : 0
inconclusive  : 0
skipped       : 0
asserts       : 2

* Overall: Passed
```

当测试完成时，数据库容器和所有其他应用程序容器将在测试步骤的最后部分被移除。这使用`docker container ls`命令列出所有具有`ci`标签的容器的 ID - 这些是由此作业创建的容器 - 然后强制性地将它们删除：

```
docker rm -f $(docker container ls --filter "label=ci" -q)
```

现在，我有一组经过测试并已知良好的应用程序图像。这些图像仅存在于构建服务器上，因此下一步是将它们推送到本地注册表。

# 在 Jenkins 中标记和推送 Docker 图像

在构建过程中如何将图像推送到您的注册表是您的选择。您可以从为每个图像打上构建编号的标签并将所有图像版本推送到注册表作为 CI 构建的一部分开始。使用高效的 Dockerfile 的项目在构建之间将具有最小的差异，因此您可以从缓存层中受益，并且您在注册表中使用的存储量不应过多。

如果您有大型项目，开发变动很多，发布周期较短，存储需求可能会失控。您可以转向定期推送，每天为图像打上标签并将最新构建推送到注册表。或者，如果您有一个具有手动质量门的流水线，最终发布阶段可以推送到注册表，因此您存储的唯一图像是有效的发布候选者。

对于我的示例 CI 作业，一旦测试通过，我将在每次成功构建后将其推送到本地注册表，使用 Jenkins 构建编号作为图像标签。标记和推送图像的构建步骤是另一个使用 Jenkins 的`BUILD_TAG`环境变量进行标记的 PowerShell 脚本。

```
$images = 'ch10-nerd-dinner-db:2e', 'ch10-nerd-dinner-index-handler:2e',  'ch10-nerd-dinner-save-handler:2e', ...  foreach ($image  in  $images) {
   $sourceTag  =  "dockeronwindows/$image"
   $targetTag  =  "registry:5000/dockeronwindows/$image-$($env:BUILD_TAG)"

  docker image tag $sourceTag  $targetTag
  docker image push $targetTag }
```

这个脚本使用一个简单的循环来为所有构建的图像应用一个新的标签。新标签包括我的本地注册表域，`registry:5000`，并将 Jenkins 构建标签作为后缀，以便我可以轻松地识别图像来自哪个构建。然后，它将所有图像推送到本地注册表 - 再次强调，这是在与 Jenkins 容器相同的 Docker 网络中运行的容器中，因此可以通过容器名称`registry`访问。

我的注册表只配置为使用 HTTP，而不是 HTTPS，因此需要在 Docker Engine 配置中显式添加为不安全的注册表。我在第四章中介绍了这一点，*与 Docker 注册表共享镜像*。Jenkins 容器正在使用主机上的 Docker Engine，因此它使用相同的配置，并且可以将镜像推送到在另一个容器中运行的注册表。

在完成了几次构建之后，我可以从开发笔记本上对注册表 API 进行 REST 调用，查询`dockeronwindows/nerd-dinner-index-handler`存储库的标签。API 将为我提供我的消息处理程序应用程序镜像的所有标签列表，以便我可以验证它们是否已由 Jenkins 使用正确的标签推送：

```
> Invoke-RestMethod http://registry:5000/v2/dockeronwindows/ch10-nerd-dinner-index-handler/tags/list |
>> Select tags

tags
----
{2e-jenkins-docker-on-windows-ch10-nerd-dinner-20, 2e-jenkins-docker-on-windows-ch10-nerd-dinner-21,2e-jenkins-docker-on-windows-ch10-nerd-dinner-22}
```

Jenkins 构建标签为我提供了创建镜像的作业的完整路径。我也可以使用 Jenkins 提供的`GIT_COMMIT`环境变量来为镜像打标签，标签中包含提交 ID。这样标签会更短，但 Jenkins 构建标签包括递增的构建编号，因此我可以通过对标签进行排序来找到最新版本。Jenkins web UI 显示每个构建的 Git 提交 ID，因此很容易从作业编号追溯到确切的源代码修订版。

构建的 CI 部分现在已经完成。对于每次对 Git 服务器的新推送，Jenkins 将编译、部署和测试应用程序，然后将良好的镜像推送到本地注册表。接下来是将解决方案部署到公共环境。

# 使用 Jenkins 部署到远程 Docker Swarm

我的示例应用程序的工作流程使用手动质量门和分离本地和外部工件的关注点。在每次源代码推送时，解决方案会在本地部署并运行测试。如果测试通过，镜像将保存到本地注册表。最终部署阶段是将这些镜像推送到外部注册表，并将应用程序部署到公共环境。这模拟了一个项目方法，其中构建在内部进行，然后批准的发布被推送到外部。

在这个示例中，我将使用 Docker Hub 上的公共存储库，并部署到在 Azure 中运行的多节点 Docker Enterprise 集群。我将继续使用 PowerShell 脚本并运行基本的`docker`命令。原则上，将镜像推送到其他注册表（如 DTR）并部署到本地 Docker Swarm 集群的操作是完全相同的。

我为部署步骤创建了一个新的 Jenkins 作业，该作业被参数化为接受要部署的版本号。版本号是 CI 构建的作业编号，因此我可以随时部署已知版本。在新作业中，我需要一些额外的凭据。我已经添加了用于 Docker Swarm 管理器的 TLS 证书的秘密文件，这将允许我连接到在 Azure 中运行的 Docker Swarm 的管理节点。

作为发布步骤的一部分，我还将推送图像到 Docker Hub，因此我在 Jenkins 中添加了一个用户名和密码凭据，我可以使用它来登录到 Docker Hub。为了在作业步骤中进行身份验证，我在部署作业中添加了凭据的绑定，这将用户名和密码暴露为环境变量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/ccdcae51-bcc9-4a2b-af46-a54243d3c2b6.png)

然后，我设置了命令配置，并在 PowerShell 构建步骤中使用`docker login`，指定了环境变量中的凭据：

```
docker login --username $env:DOCKER_HUB_USER --password "$env:DOCKER_HUB_PASSWORD"
```

注册表登录是使用 Docker CLI 执行的，但登录的上下文实际上存储在 Docker Engine 中。当我在 Jenkins 容器中运行此步骤时，运行该容器的主机使用 Jenkins 凭据登录到 Docker Hub。如果您遵循类似的流程，您需要确保作业在每次运行后注销，或者构建服务器运行的引擎是安全的，否则用户可能会访问该机器并以 Jenkins 帐户身份推送图像。

现在，对于构建的每个图像，我从本地注册表中拉取它们，为 Docker Hub 打标签，然后将它们推送到 Hub。初始拉取是为了以防我想部署以前的构建。自从构建以来，本地服务器缓存可能已被清除，因此这可以确保来自本地注册表的正确图像存在。对于 Docker Hub，我使用更简单的标记格式，只需应用版本号。

此脚本使用 PowerShell 循环来拉取和推送所有图像：

```
$images  =  'ch10-nerd-dinner-db:2e',  'ch10-nerd-dinner-index-handler:2e',  'ch10-nerd-dinner-save-handler:2e',  ...  foreach ($image  in  $images) { 
 $sourceTag  =  "registry:5000/dockeronwindows/$image...$($env:VERSION_NUMBER)"
  $targetTag  =  "dockeronwindows/$image-$($env:VERSION_NUMBER)"

 docker image pull $sourceTag docker image tag $sourceTag  $targetTag
 docker image push $targetTag }
```

当此步骤完成时，图像将在 Docker Hub 上公开可用。现在，部署作业中的最后一步是使用这些公共图像在远程 Docker Swarm 上运行最新的应用程序版本。我需要生成一个包含图像标记中最新版本号的 Compose 文件，并且我可以使用`docker-compose config`与覆盖文件来实现：

```
cd .\ch10\ch10-nerd-dinner\compose

docker-compose `
  -f .\docker-compose.yml `
  -f .\docker-compose.hybrid-swarm.yml `
  -f .\docker-compose.latest.yml `
  config > docker-stack.yml
```

`docker-compose.latest.yml`文件是添加的最后一个文件，并且使用`VERSION_NUMBER`环境变量，该变量由 Jenkins 填充以创建图像标签：

```
 services: nerd-dinner-db:
     image: dockeronwindows/ch10-nerd-dinner-db:2e-${VERSION_NUMBER}

   nerd-dinner-save-handler:
     image: dockeronwindows/ch10-nerd-dinner-save-handler:2e-${VERSION_NUMBER} ...
```

`config`命令不受影响，无法使用 Docker Compose 在使用命名管道的容器内部署容器的问题。`docker-compose config`只是连接和解析文件，它不与 Docker Engine 通信。

现在，我有一个 Docker Compose 文件，其中包含我混合使用最新版本的应用程序镜像从 Docker Hub 的 Linux 和 Windows Docker Swarm 的所有设置。最后一步使用`docker stack deploy`来实际在远程 swarm 上运行堆栈：

```
$config = '--host', 'tcp://dow2e-swarm.westeurope.cloudapp.azure.com:2376', '--tlsverify', `
 '--tlscacert', $env:DOCKER_CA,'--tlscert', $env:DOCKER_CERT, '--tlskey', $env:DOCKER_KEY

& docker $config `
  stack deploy -c docker-stack.yml nerd-dinner
```

这个最后的命令使用安全的 TCP 连接到远程 swarm 管理器上的 Docker API。`$config`对象设置了 Docker CLI 需要的所有参数，以便建立连接：

+   `host`是管理节点的公共完全限定域名

+   `tlsverify`指定这是一个安全连接，并且 CLI 应该提供客户端证书

+   `tlscacert`是 swarm 的证书颁发机构

+   `tlscert`是用户的客户端证书

+   `tlskey`是用户客户端证书的密钥

当作业运行时，所有证书都作为 Jenkins 秘密文件呈现。当 Docker CLI 需要时，这些文件在工作空间中可用；因此，这是一个无缝的安全连接。

当工作完成时，更新后的服务将已部署。Docker 会将堆栈定义与正在运行的服务进行比较，就像 Docker Compose 对容器进行比较一样，因此只有在定义发生更改时才会更新服务。部署工作完成后，我可以浏览到公共 DNS 条目（这是我的 Docker Swarm 集群的 CNAME），并查看应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/10d36d30-f70c-4886-8c31-c846ed9233b5.png)

我的工作流程使用了两个作业，因此我可以手动控制对远程环境的发布，这可能是一个 QA 站点，也可能是生产环境。这可以自动化为完整的 CD 设置，并且您可以轻松地在 Jenkins 作业上构建更多功能-显示测试输出和覆盖率，将构建加入管道，并将作业分解为可重用的部分。

# 总结

本章介绍了在 Jenkins 中配置的 Docker 中的 CI/CD，以及一个示例部署工作流程。我演示的过程的每个部分都在 Docker 容器中运行：Git 服务器、Jenkins 本身、构建代理、测试代理和本地注册表。

你看到了使用 Docker 运行自己的开发基础设施是很简单的，这为你提供了一个托管服务的替代方案。对于你自己的部署工作流程来说，使用这些服务也是很简单的，无论是完整的 CI/CD 还是带有门控手动步骤的单独工作流程。

你看到了如何在 Docker 中配置和运行 Gogs Git 服务器和 Jenkins 自动化服务器来支持工作流程。我在 NerdDinner 代码的最新版本中为所有镜像使用了多阶段构建，这意味着我可以拥有一个非常简单的 Jenkins 设置，而无需部署任何工具链或 SDK。

我的 CI 流水线是由开发人员推送 Git 更改触发的。构建作业拉取源代码，编译应用程序组件，将它们构建成 Docker 镜像，并在 Docker 中运行应用程序的本地部署。然后在另一个容器中运行端到端测试，如果测试通过，就会给所有镜像打标签并推送到本地注册表。

我演示了一个用户启动的作业，指定要部署的构建版本的手动部署步骤。这个作业将构建的镜像推送到公共 Docker Hub，并通过在 Azure 上运行的 Docker Swarm 上部署堆栈来更新公共环境。

在本章中，我使用的技术没有任何硬性依赖。我用 Gogs、Jenkins 和开源注册表实现的流程可以很容易地使用托管服务（如 GitHub、AppVeyor 和 Docker Hub）来实现。这个流程的所有步骤都使用简单的 PowerShell 脚本，并且可以在支持 Docker 的任何堆栈上运行。

在下一章中，我将回到开发人员的体验，看看在容器中运行、调试和故障排除应用程序的实际操作。


# 第四部分：开始您的容器之旅

开始使用 Docker 很容易。到*第四部分*结束时，读者将知道如何将现有应用程序迁移到 Docker，如何在 Visual Studio 中开始使用它们，以及如何添加仪器，使它们准备好投入生产。

本节包括以下最后两章：

+   第十一章，*调试和仪器化应用容器*

+   第十二章，*将你所知的内容容器化-实施 Docker 的指导*


# 第十一章：调试和为应用程序容器添加仪器

Docker 可以消除典型开发人员工作流程中的许多摩擦，并显著减少在诸如依赖管理和环境配置等开销任务上花费的时间。当开发人员使用与最终产品相同的应用程序平台运行他们正在处理的更改时，部署错误的机会就会大大减少，升级路径也是直接且易于理解的。

在开发过程中在容器中运行应用程序会为您的开发环境增加另一层。您将使用不同类型的资产，如 Dockerfiles 和 Docker Compose 文件，如果您的集成开发环境支持这些类型，那么这种体验会得到改善。此外，在 IDE 和应用程序之间有一个新的运行时，因此调试体验会有所不同。您可能需要改变您的工作流程以充分利用平台的优势。

在本章中，我将介绍使用 Docker 的开发过程，涵盖 IDE 集成和调试，以及如何为您的 Docker 化应用程序添加仪器。您将了解：

+   在集成开发环境中使用 Docker

+   Docker 化应用程序中的仪器

+   Docker 中的故障修复工作流程

# 技术要求

您需要在 Windows 10 更新 18.09 或 Windows Server 2019 上运行 Docker，以便跟随示例。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch11`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch11)上找到。

# 在集成开发环境中使用 Docker

在上一章中，我演示了一个容器化的“外部循环”，即编译和打包的 CI 过程，当开发人员推送更改时，它会从中央源代码控制中触发。集成开发环境（IDE）开始支持容器化工作流程的“内部循环”，这是开发人员在将更改推送到中央源代码控制之前编写、运行和调试应用程序的过程。

Visual Studio 2017 原生支持 Docker 工件，包括 Dockerfile 的智能感知和代码完成。ASP.NET 项目在容器中运行时也有运行时支持，包括.NET Framework 和.NET Core。在 Visual Studio 2017 中，您可以按下*F5*键，您的 Web 应用程序将在 Windows 上的 Docker 桌面中运行的容器中启动。应用程序使用与您在所有其他环境中使用的相同的基本映像和 Docker 运行时。

Visual Studio 2015 有一个插件，提供对 Docker 工件的支持，Visual Studio Code 有一个非常有用的 Docker 扩展。Visual Studio 2015 和 Visual Studio Code 不提供在 Windows 容器中运行.NET 应用程序的集成*F5*调试体验，但您可以手动配置，我将在本章中演示。

在容器内调试时存在一个折衷之处-这意味着在内部循环和外部循环之间创建了一个断开。您的开发过程使用与 CI 过程不同的一组 Docker 工件，以使调试器可用于容器，并将应用程序程序集映射到源代码。好处是您可以在开发中以相同的开发人员构建和调试体验在容器中运行。缺点是您的开发 Docker 映像与您将推广到测试的映像不完全相同。

缓解这种情况的一个好方法是在快速迭代功能时，使用本地 Docker 工件进行开发。然后，在推送更改之前，您可以使用 CI Docker 工件进行最终构建和端到端测试。

# 在 Visual Studio 2017 中的 Docker

Visual Studio 2017 是所有.NET IDE 中对 Docker 支持最完整的。您可以在 Visual Studio 2017 中打开一个 ASP.NET Framework Web API 项目，右键单击该项目，然后选择添加|容器编排器支持：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/b3921071-0b2f-487b-9b25-193543b06c6b.png)

只有一个编排器选项可供选择，即 Docker Compose。然后，Visual Studio 会生成一组 Docker 工件。在`Web`项目中，它创建一个看起来像这样的 Dockerfile：

```
FROM microsoft/aspnet:4.7.2-windowsservercore-1803
ARG source
WORKDIR /inetpub/wwwroot
COPY ${source:-obj/Docker/publish} .
```

Dockerfile 语法有完整的智能感知支持，因此您可以将鼠标悬停在指令上并查看有关它们的信息，并使用*Ctrl* +空格键打开所有 Dockerfile 指令的提示。

生成的 Dockerfile 使用`microsoft/aspnet`基础镜像，其中包含已完全安装和配置的 ASP.NET 4.7.2。在撰写本文时，Dockerfile 使用了旧版本的 Windows 基础镜像，因此您需要手动更新为使用最新的 Windows Server 2019 基础镜像，即`mcr.microsoft.com/dotnet/framework/aspnet:4.7.2-windowsservercore-ltsc2019`。

Dockerfile 看起来很奇怪，因为它使用构建参数来指定源文件夹的位置，然后将该文件夹的内容复制到容器镜像内的 web 根目录`C:\inetpub\wwwroot`。

在解决方案根目录中，Visual Studio 创建了一组 Docker Compose 文件。有多个文件，Visual Studio 会使用它们与 Docker Compose 的`build`和`up`命令来打包和运行应用程序。当您按下*F5*键运行应用程序时，这些文件在后台运行，但值得看看 Visual Studio 如何使用它们；它向您展示了如何将此级别的支持添加到不同的 IDE 中。

# 在 Visual Studio 2017 中使用 Docker Compose 进行调试

生成的 Docker Compose 文件显示在顶级解决方案对象下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/0b2f32c1-dfa2-431e-8f3b-4ae277474b2a.png)

有一个基本的`docker-compose.yml`文件，其中将 Web 应用程序定义为一个服务，并包含 Dockerfile 的构建细节：

```
version: '3.4'

services:
  webapi.netfx:
    image: ${DOCKER_REGISTRY-}webapinetfx
    build:
      context: .\WebApi.NetFx
      dockerfile: Dockerfile
```

还有一个`docker-compose.override.yml`文件，它添加了端口和网络配置，以便可以在本地运行：

```
version: '3.4'

services:
  webapi.netfx:
    ports:
      - "80"
networks:
  default:
    external:
      name: nat
```

这里没有关于构建应用程序的内容，因为编译是在 Visual Studio 中完成而不是在 Docker 中。构建的应用程序二进制文件存储在您的开发计算机上，并复制到容器中。当您按下*F5*时，容器会启动，Visual Studio 会在容器的 IP 地址上启动浏览器。您可以在 Visual Studio 中的代码中添加断点，当您从浏览器导航到该代码时，将会进入 Visual Studio 中的调试器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/8a0d0f97-90fe-43fb-b674-05d152804d08.png)

这是一个无缝的体验，但不清楚发生了什么——Visual Studio 调试器在您的计算机上如何连接到容器内的二进制文件？幸运的是，Visual Studio 会将所有发出的 Docker 命令记录到输出窗口，因此您可以追踪它是如何工作的。

在构建输出窗口中，您会看到类似以下的内容：

```
1>------ Build started: Project: WebApi.NetFx, Configuration: Debug Any CPU ------
1>  WebApi.NetFx -> C:\Users\Administrator\source\repos\WebApi.NetFx\WebApi.NetFx\bin\WebApi.NetFx.dll
2>------ Build started: Project: docker-compose, Configuration: Debug Any CPU ------
2>docker-compose  -f "C:\Users\Administrator\source\repos\WebApi.NetFx\docker-compose.yml" -f "C:\Users\Administrator\source\repos\WebApi.NetFx\docker-compose.override.yml" -f "C:\Users\Administrator\source\repos\WebApi.NetFx\obj\Docker\docker-compose.vs.debug.g.yml" -p dockercompose1902887664513455984 --no-ansi up -d
2>dockercompose1902887664513455984_webapi.netfx_1 is up-to-date
========== Build: 2 succeeded, 0 failed, 0 up-to-date, 0 skipped ==========
```

您可以看到首先进行构建，然后使用`docker-compose up`启动容器。我们已经看到的`docker-compose.yml`和`docker-compose.override.yml`文件与一个名为`docker-compose.vs.debug.g.yml`的文件一起使用。Visual Studio 在构建时生成该文件，您需要显示解决方案中的所有文件才能看到它。它包含额外的 Docker Compose 设置：

```
services:
  webapi.netfx:
    image: webapinetfx:dev
    build:
      args:
        source: obj/Docker/empty/
    volumes:
      - C:\Users\Administrator\source\repos\WebApi.NetFx\WebApi.NetFx:C:\inetpub\wwwroot
      - C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\IDE\Remote Debugger:C:\remote_debugger:ro
    entrypoint: cmd /c "start /B C:\\ServiceMonitor.exe w3svc & C:\\remote_debugger\\x64\\msvsmon.exe /noauth /anyuser /silent /nostatus /noclrwarn /nosecuritywarn /nofirewallwarn /nowowwarn /timeout:2147483646"
```

这里发生了很多事情：

+   Docker 镜像使用`dev`标签来区分它与发布版本的构建

+   源位置的构建参数指定一个空目录

+   一个卷用于从主机上的项目文件夹中挂载容器中的 Web 根目录

+   第二个卷用于从主机中挂载 Visual Studio 远程调试器到容器中

+   入口点启动`ServiceMonitor`来运行 IIS，然后启动`msvsmon`，这是远程调试器

在调试模式下，源代码环境变量的参数是一个空目录。Visual Studio 使用一个空的`wwwroot`目录构建 Docker 镜像，然后将主机中的源代码文件夹挂载到容器中的 Web 根目录，以在运行时填充该文件夹。

当容器运行时，Visual Studio 会在容器内运行一些命令来设置权限，从而使远程调试工具能够工作。在 Docker 的输出窗口中，您会看到类似以下的内容：

```
========== Debugging ==========
docker ps --filter "status=running" --filter "name=dockercompose1902887664513455984_webapi.netfx_" --format {{.ID}} -n 1
3e2b6a7cb890
docker inspect --format="{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}" 3e2b6a7cb890
172.27.58.105 
docker exec 3e2b6a7cb890 cmd /c "C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.applicationHost/applicationPools /[name='DefaultAppPool'].processModel.identityType:LocalSystem /commit:apphost & C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.webServer/security/authentication/anonymousAuthentication /userName: /commit:apphost"
Applied configuration changes to section "system.applicationHost/applicationPools" for "MACHINE/WEBROOT/APPHOST" at configuration commit path "MACHINE/WEBROOT/APPHOST"
Applied configuration changes to section "system.webServer/security/authentication/anonymousAuthentication" for "MACHINE/WEBROOT/APPHOST" at configuration commit path "MACHINE/WEBROOT/APPHOST"
Launching http://172.27.58.105/ ...
```

这是 Visual Studio 获取使用 Docker Compose 启动的容器的 ID，然后运行`appcmd`来设置 IIS 应用程序池以使用管理员帐户，并设置 Web 服务器以允许匿名身份验证。

当您停止调试时，Visual Studio 2017 会使容器在后台运行。如果对程序进行更改并重新构建，则仍然使用同一个容器，因此没有启动延迟。通过将项目位置挂载到容器中，重新构建时会反映出内容或二进制文件的任何更改。通过从主机挂载远程调试器，您的镜像不会包含任何开发工具；它们保留在主机上。

这是内部循环过程，您可以获得快速反馈。每当您更改并重新构建应用程序时，您都会在容器中看到这些更改。但是，调试模式下的 Docker 镜像对于外部循环 CI 过程是不可用的；应用程序不会被复制到镜像中；只有在将应用程序从本地源挂载到容器中时才能工作。

为了支持外部循环，还有一个用于发布模式的 Docker Compose 覆盖文件，以及第二个隐藏的覆盖文件，`docker-compose.vs.release.g.yml`。

```
services:
  webapi.netfx:
    build:
      args:
        source: obj/Docker/publish/
    volumes:
      - C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\IDE\Remote Debugger:C:\remote_debugger:ro
    entrypoint: cmd /c "start /B C:\\ServiceMonitor.exe w3svc & C:\\remote_debugger\\x64\\msvsmon.exe /noauth /anyuser /silent /nostatus /noclrwarn /nosecuritywarn /nofirewallwarn /nowowwarn /timeout:2147483646"
    labels:
      com.microsoft.visualstudio.debuggee.program: "C:\\app\\WebApi.NetFx.dll"
      com.microsoft.visualstudio.debuggee.workingdirectory: "C:\\app"
```

这里的区别在于没有将本地源位置映射到容器中的 Web 根目录。在发布模式下编译时，源参数的值是包含 Web 应用程序的发布位置。Visual Studio 通过将发布的应用程序打包到容器中来构建发布映像。

在发布模式下，您仍然可以在 Docker 容器中运行应用程序，并且仍然可以调试应用程序。但是，您会失去快速反馈循环，因为要更改应用程序，Visual Studio 需要重新构建 Docker 映像并启动新的容器。

这是一个公平的妥协，而 Visual Studio 2017 中的 Docker 工具为您提供了无缝的开发体验，以及 CI 构建的基础。Visual Studio 2017 没有使用多阶段构建，因此项目编译仍然发生在主机而不是容器内。这使得生成的 Docker 工件不够便携，因此您需要不仅仅是 Docker 来在服务器上构建此应用程序。

# Visual Studio 2015 中的 Docker

Visual Studio 2015 在市场上有一个名为**Visual Studio Tools for Docker**的插件。这为 Dockerfile 提供了语法高亮显示，但它并没有将 Visual Studio 与.NET Framework 应用程序的 Docker 集成。在 Visual Studio 2015 中，您可以为.NET Core 项目添加 Docker 支持，但是您需要手动编写自己的 Dockerfile 和 Docker Compose 文件以支持完整的.NET 应用程序。

此外，没有集成的调试功能用于在 Windows 容器中运行的应用程序。您仍然可以调试在容器中运行的代码，但是您需要手动配置设置。我将演示如何使用与 Visual Studio 2017 相同的方法以及一些相同的妥协来做到这一点。

在 Visual Studio 2017 中，您可以将包含远程调试器的文件夹从主机挂载到容器中。当您运行项目时，Visual Studio 会启动一个容器，并从主机执行`msvsmon.exe`，这是远程调试器代理。您不需要在图像中安装任何内容来提供调试体验。

Visual Studio 2015 中的远程调试器并不是很便携。你可以从主机中将调试器挂载到容器中，但当你尝试启动代理时，你会看到有关缺少文件的错误。相反，你需要将远程调试器安装到你的镜像中。

我在一个名为`ch11-webapi-vs2015`的文件夹中设置了这个。在这个镜像的 Dockerfile 中，我使用了一个构建时参数来有条件地安装调试器，如果`configuration`的值设置为`debug`。这意味着我可以在本地构建时安装调试器，但当我为部署构建时，镜像就不会有调试器了：

```
ARG configuration

 RUN if ($env:configuration -eq 'debug') `
 { Invoke-WebRequest -OutFile c:\rtools_setup_x64.exe -UseBasicParsing -Uri http://download.microsoft.com/download/1/2/2/1225c23d-3599-48c9-a314-f7d631f43241/rtools_setup_x64.exe; `
 Start-Process c:\rtools_setup_x64.exe -ArgumentList '/install', '/quiet' -NoNewWindow -Wait }
```

当以调试模式运行时，我使用与 Visual Studio 2017 相同的方法将主机上的源目录挂载到容器中，但我创建了一个自定义网站，而不是使用默认的网站：

```
ARG source
WORKDIR C:\web-app
RUN Remove-Website -Name 'Default Web Site';`
New-Website -Name 'web-app' -Port 80 -PhysicalPath 'C:\web-app'
COPY ${source:-.\Docker\publish} .
```

`COPY`指令中的`:-`语法指定了一个默认值，如果未提供`source`参数。默认值是从发布的 web 应用程序复制，除非在`build`命令中指定了它。我有一个核心的`docker-compose.yml`文件，其中包含基本的服务定义，还有一个`docker-compose.debug.yml`文件，它挂载主机源位置，映射调试器端口，并指定`configuration`变量。

```
services:
  ch11-webapi-vs2015:
    build:
      context: ..\
      dockerfile: .\Docker\Dockerfile
    args:
      - source=.\Docker\empty
      - configuration=debug
  ports:
    - "3702/udp"
    - "4020"
    - "4021"
  environment:
    - configuration=debug
  labels:
    - "com.microsoft.visualstudio.targetoperatingsystem=windows"
  volumes:
    - ..\WebApi.NetFx:C:\web-app
```

在 compose 文件中指定的标签将一个键值对附加到容器。该值在容器内部不可见，不像环境变量，但对主机上的外部进程可见。在这种情况下，它被 Visual Studio 用来识别容器的操作系统。

要以调试模式启动应用程序，我使用两个 Compose 文件来启动应用程序：

```
docker-compose -f docker-compose.yml -f docker-compose.debug.yml up -d
```

现在，容器正在使用**Internet Information Services** (**IIS**)在容器内部运行我的 web 应用程序，并且 Visual Studio 远程调试器代理也在运行。我可以连接到 Visual Studio 2015 中的远程进程，并使用容器的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3909f411-ca1a-4d71-a1c8-f10ecdc8607e.png)

Visual Studio 中的调试器连接到容器中运行的代理，并且我可以添加断点和查看变量，就像调试本地进程一样。在这种方法中，容器使用主机挂载来获取 web 应用的内容。我可以停止调试器，进行更改，重新构建应用程序，并在同一个容器中看到更改，而无需启动新的容器。

这种方法与 Visual Studio 2017 中集成的 Docker 支持具有相同的优缺点。我正在容器中运行我的应用程序进行本地调试，因此我可以获得 Visual Studio 调试器的所有功能，并且我的应用程序在其他环境中使用的平台上运行。但我不会使用相同的映像，因为 Dockerfile 具有条件分支，因此它会为调试和发布模式生成不同的输出。

在 Docker 构件中手动构建调试器支持有一个优势。您可以构建具有条件的 Dockerfile，以便默认的`docker image build`命令生成无需任何额外构件即可用于生产的图像。但是，这个例子仍然没有使用多阶段构建，因此 Dockerfile 不具备可移植性，应用程序在打包之前需要进行编译。

在开发中，您可以以调试模式构建图像一次，运行容器，然后在需要时附加调试器。您的集成测试构建并运行生产图像，因此只有内部循环具有额外的调试器组件。

# Visual Studio Code 中的 Docker

Visual Studio Code 是一个新的跨平台 IDE，用于跨平台开发。C#扩展安装了一个可以附加到.NET Core 应用程序的调试器，但不支持调试完整的.NET Framework 应用程序。

Docker 扩展添加了一些非常有用的功能，包括将 Dockerfiles 和 Docker Compose 文件添加到已知平台的现有项目中，例如 Go 和.NET Core。您可以将 Dockerfile 添加到.NET Core 项目中，并选择在 Windows 或 Linux 容器之间进行选择作为基础-点击* F1 *，键入`docker`，然后选择将 Docker 文件添加到工作区：

！[](Images/d6ee79a9-f1d5-4c77-81bf-dbee789ba6b1.png)

以下是.NET Core Web API 项目的生成的 Dockerfile：

```
FROM microsoft/dotnet:2.2-aspnetcore-runtime-nanoserver-1803 AS base WORKDIR /app EXPOSE 80 FROM microsoft/dotnet:2.2-sdk-nanoserver-1803 AS build WORKDIR /src COPY ["WebApi.NetCore.csproj", "./"] RUN dotnet restore "./WebApi.NetCore.csproj" COPY . . WORKDIR  "/src/." RUN dotnet build "WebApi.NetCore.csproj" -c Release -o /app FROM build AS publish RUN dotnet publish "WebApi.NetCore.csproj" -c Release -o /app  FROM base AS final WORKDIR /app COPY --from=publish /app .
ENTRYPOINT ["dotnet", "WebApi.NetCore.dll"]
```

这是使用旧版本的.NET Core 基础映像，因此第一步是将`FROM`行中的`nanoserver-1803`标签替换为`nanoserver-1809`。该扩展程序生成了一个多阶段的 Dockerfile，使用 SDK 映像进行构建和发布阶段，以及 ASP.NET Core 运行时用于最终映像。VS Code 在 Dockerfile 中生成了比实际需要更多的阶段，但这是一个设计选择。

VS Code 还会生成一个`.dockerignore`文件。这是一个有用的功能，可以加快 Docker 镜像的构建速度。在忽略文件中，您列出任何在 Dockerfile 中未使用的文件或目录路径，并且这些文件将被排除在构建上下文之外。排除所有`bin`、`obj`和`packages`文件夹意味着当您构建图像时，Docker CLI 向 Docker Engine 发送的有效负载要小得多，这可以加快构建速度。

您可以使用 F1 | docker tasks 来构建图像并运行容器，但是没有功能以生成 Docker Compose 文件的方式，就像 Visual Studio 2017 那样。

Visual Studio Code 具有非常灵活的系统，可以运行和调试您的项目，因此您可以添加自己的配置，为在 Windows 容器中运行的应用程序提供调试支持。您可以编辑`launch.json`文件，以添加新的配置以在 Docker 中进行调试。

在`ch11-webapi-vscode`文件夹中，我有一个示例.NET Core 项目，可以在 Docker 中运行该应用程序并附加调试器。它使用与 Visual Studio 2017 相同的方法。.NET Core 的调试器称为`vsdbg`，并且与 Visual Studio Code 中的 C#扩展一起安装，因此我使用`docker-compose.debug.yml`文件将`vsdbg`文件夹从主机挂载到容器中，以及使用源位置：

```
volumes:
 - .\bin\Debug\netcoreapp2.2:C:\app
 - ~\.vscode\extensions\ms-vscode.csharp-1.17.1\.debugger:C:\vsdbg:ro
```

此设置使用特定版本的 C#扩展。在我的情况下是 1.17.1，但您可能有不同的版本。检查您的用户目录中`.vscode`文件夹中`vsdbg.exe`的位置。

当您通过使用调试覆盖文件在 Docker Compose 中运行应用程序时，它会启动.NET Core 应用程序，并使来自主机的调试器可用于在容器中运行。这是在 Visual Studio Code 的`launch.json`文件中配置的调试体验。`Debug Docker container`配置指定要调试的应用程序类型和要附加的进程的名称：

```
  "name": "Debug Docker container",
  "type": "coreclr",
  "request": "attach",
  "sourceFileMap": {
    "C:\\app": "${workspaceRoot}"
 }, "processName": "dotnet"
```

此配置还将容器中的应用程序根映射到主机上的源代码位置，因此调试器可以将正确的源文件与调试文件关联起来。此外，调试器配置指定了如何通过在命名容器上运行`docker container exec`命令来启动调试器：

```
"pipeTransport": {
  "pipeCwd": "${workspaceRoot}",
  "pipeProgram": "docker",
  "pipeArgs": [
   "exec", "-i", "webapinetcore_webapi_1"
 ],  "debuggerPath": "C:\\vsdbg\\vsdbg.exe",
  "quoteArgs": false }
```

要调试我的应用程序，我需要使用 Docker Compose 和覆盖文件在调试配置中构建和运行它：

```
docker-compose -f .\docker-compose.yml -f .\docker-compose.debug.yml build docker-compose -f .\docker-compose.yml -f .\docker-compose.debug.yml up -d 
```

然后，我可以使用调试操作并选择调试 Docker 容器来激活调试器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/64e9ad65-f404-4292-a022-36536a415a3a.png)

Visual Studio Code 在容器内启动.NET Core 调试器`vsdbg`，并将其附加到正在运行的`dotnet`进程。您将看到.NET Core 应用程序的输出被重定向到 Visual Studio Code 中的 DEBUG CONSOLE 窗口中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/c219df7a-a5ca-44a1-956d-acc2d5e697fe.png)

在撰写本文时，Visual Studio Code 尚未完全与在 Windows Docker 容器内运行的调试器集成。您可以在代码中设置断点，调试器将暂停进程，但控制权不会传递到 Visual Studio Code。这是在 Nano Server 容器中运行 Omnisharp 调试器的已知问题-在 GitHub 上进行跟踪：[`github.com/OmniSharp/omnisharp-vscode/issues/1001`](https://github.com/OmniSharp/omnisharp-vscode/issues/1001)。

在容器中运行应用程序并能够从您的常规 IDE 进行调试是一个巨大的好处。这意味着您的应用程序在相同的平台上运行，并且具有与在所有其他环境中使用的相同部署配置，但您可以像在本地运行一样进入代码。

IDE 中的 Docker 支持正在迅速改善，因此本章中详细介绍的所有手动步骤将很快内置到产品和扩展中。JetBrains Rider 是一个很好的例子，它是一个与 Docker 很好配合的第三方.NET IDE。它与 Docker API 集成，并可以将自己的调试器附加到正在运行的容器中。

# Docker 化应用程序中的仪器

调试应用程序是在逻辑不按预期工作时所做的事情，您正在尝试跟踪出现问题的原因。您不会在生产环境中进行调试，因此您需要您的应用程序记录其行为，以帮助您跟踪发生的任何问题。

仪器经常被忽视，但它应该是您开发的一个关键组成部分。这是了解应用程序在生产环境中的健康状况和活动的最佳方式。在 Docker 中运行应用程序为集中日志记录和仪器提供了新的机会，这样您可以获得对应用程序不同部分的一致视图，即使它们使用不同的语言和平台。

向您的容器添加仪表化可以是一个简单的过程。Windows Server Core 容器已经在 Windows 性能计数器中收集了大量的指标。使用.NET 或 IIS 构建的 Docker 镜像也将具有来自这些堆栈的所有额外性能计数器。您可以通过将性能计数器值暴露给指标服务器来为容器添加仪表化。

# 使用 Prometheus 进行仪表化

围绕 Docker 的生态系统非常庞大和活跃，充分利用了平台的开放标准和可扩展性。随着生态系统的成熟，一些技术已经成为几乎所有 Docker 化应用程序中强有力的候选项。

Prometheus 是一个开源的监控解决方案。它是一个灵活的组件，您可以以不同的方式使用，但典型的实现方式是在 Docker 容器中运行一个 Prometheus 服务器，并配置其读取您在其他 Docker 容器中提供的仪表化端点。

您可以配置 Prometheus 来轮询所有容器端点，并将结果存储在时间序列数据库中。您可以通过简单地添加一个 REST API 来向您的应用程序添加一个 Prometheus 端点，该 API 会响应来自 Prometheus 服务器的`GET`请求，并返回您感兴趣的指标列表。

对于.NET Framework 和.NET Core 项目，有一个 NuGet 包可以为您完成这项工作，即向您的应用程序添加一个 Prometheus 端点。它默认公开了一组有用的指标，包括关键的.NET 统计数据和 Windows 性能计数器的值。您可以直接向您的应用程序添加 Prometheus 支持，或者您可以在应用程序旁边运行一个 Prometheus 导出器。

您采取的方法将取决于您想要为其添加仪表化的应用程序类型。如果是要将传统的.NET Framework 应用程序移植到 Docker 中，您可以通过在 Docker 镜像中打包一个 Prometheus 导出器来添加基本的仪表化，这样就可以在不需要更改代码的情况下获得有关应用程序的指标。对于新应用程序，您可以编写代码将特定的应用程序指标暴露给 Prometheus。

# 将.NET 应用程序指标暴露给 Prometheus

`prometheus-net` NuGet 包提供了一组默认的指标收集器和一个`MetricServer`类，该类提供了 Prometheus 连接的仪表端点。该包非常适合为任何应用程序添加 Prometheus 支持。这些指标由自托管的 HTTP 端点提供，您可以为您的应用程序提供自定义指标。

在`dockeronwindows/ch11-api-with-metrics`镜像中，我已经将 Prometheus 支持添加到了一个 Web API 项目中。配置和启动指标端点的代码在`PrometheusServer`类中。

```
public  static  void  Start() { _Server  =  new  MetricServer(50505);
  _Server.Start(); }
```

这将启动一个新的`MetricServer`实例，监听端口`50505`，并运行`NuGet`包提供的默认一组.NET 统计和性能计数器收集器。这些是按需收集器，这意味着它们在 Prometheus 服务器调用端点时提供指标。

`MetricServer`类还将返回您在应用程序中设置的任何自定义指标。Prometheus 支持不同类型的指标。最简单的是计数器，它只是一个递增的计数器—Prometheus 查询您的应用程序的指标值，应用程序返回每个计数器的单个数字。在`ValuesController`类中，我设置了一些计数器来记录对 API 的请求和响应：

```
private  Counter  _requestCounter  =  Metrics.CreateCounter("ValuesController_Requests", "Request count", "method", "url"); private  Counter  _responseCounter  =  Metrics.CreateCounter("ValuesController_Responses", "Response count", "code", "url");
```

当请求进入控制器时，控制器动作方法通过在计数器对象上调用`Inc()`方法来增加 URL 的请求计数，并增加响应代码的状态计数：

```
public IHttpActionResult Get()
{
  _requestCounter.Labels("GET", "/").Inc();
  _responseCounter.Labels("200", "/").Inc();
  return Ok(new string[] { "value1", "value2" });
}
```

Prometheus 还有各种其他类型的指标，您可以使用它们来记录有关应用程序的关键信息—计数器只增加，但是仪表可以增加和减少，因此它们对于记录快照非常有用。Prometheus 记录每个指标值及其时间戳和您提供的一组任意标签。在这种情况下，我将添加`URL`和`HTTP`方法到请求计数，以及 URL 和状态代码到响应计数。我可以使用这些在 Prometheus 中聚合或过滤指标。

我在 Web API 控制器中设置的计数器为我提供了一组自定义指标，显示了哪些端点正在使用以及响应的状态。这些由服务器组件在`NuGet`包中公开，以及用于记录系统性能的默认指标。在此应用的 Dockerfile 中，还有两行额外的代码用于 Prometheus 端点：

```
EXPOSE 50505
RUN netsh http add urlacl url=http://+:50505/metrics user=BUILTIN\IIS_IUSRS; `
    net localgroup 'Performance Monitor Users' 'IIS APPPOOL\DefaultAppPool' /add
```

第一行只是暴露了我用于度量端点的自定义端口。第二行设置了该端点所需的权限。在这种情况下，度量端点托管在 ASP.NET 应用程序内部，因此 IIS 用户帐户需要权限来监听自定义端口并访问系统性能计数器。

您可以按照通常的方式构建 Dockerfile 并从镜像运行容器，即通过使用 `-P` 发布所有端口：

```
docker container run -d -P --name api dockeronwindows/ch11-api-with-metrics:2e
```

为了检查度量是否被记录和暴露，我可以运行一些 PowerShell 命令来抓取容器的端口，然后对 API 端点进行一些调用并检查度量：

```
$apiPort = $(docker container port api 80).Split(':')[1]
for ($i=0; $i -lt 10; $i++) {
 iwr -useb "http://localhost:$apiPort/api/values"
}

$metricsPort = $(docker container port api 50505).Split(':')[1]
(iwr -useb "http://localhost:$metricsPort/metrics").Content
```

您将看到按名称和标签分组的度量的纯文本列表。每个度量还包含 Prometheus 的元数据，包括度量名称、类型和友好描述：

```
# HELP process_num_threads Total number of threads
# TYPE process_num_threads gauge
process_num_threads 27
# HELP dotnet_total_memory_bytes Total known allocated memory
# TYPE dotnet_total_memory_bytes gauge
dotnet_total_memory_bytes 8519592
# HELP process_virtual_memory_bytes Virtual memory size in bytes.
# TYPE process_virtual_memory_bytes gauge
process_virtual_memory_bytes 2212962820096
# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 1.734375
...
# HELP ValuesController_Requests Request count
# TYPE ValuesController_Requests counter
ValuesController_Requests{method="GET",url="/"} 10
# HELP ValuesController_Responses Response count
# TYPE ValuesController_Responses counter
ValuesController_Responses{code="200",url="/"} 10
```

完整的输出要大得多。在这个片段中，我展示了线程总数、分配的内存和 CPU 使用率，这些都来自容器内部的标准 Windows 和 .NET 性能计数器。我还展示了自定义的 HTTP 请求和响应计数器。

此应用程序中的自定义计数器显示了 URL 和响应代码。在这种情况下，我可以看到对值控制器的根 URL 的 10 个请求，以及带有 OK 状态码 `200` 的十个响应。在本章后面，我将向您展示如何使用 Grafana 可视化这些统计信息。

将 `NuGet` 包添加到项目并运行 `MetricServer` 是源代码的简单扩展。它让我记录任何有用的度量，但这意味着改变应用程序，因此只适用于正在积极开发的应用程序。

在某些情况下，您可能希望添加监视而不更改要检测的应用程序。在这种情况下，您可以在应用程序旁边运行一个**导出器**。导出器从应用程序进程中提取度量并将其暴露给 Prometheus。在 Windows 容器中，您可以从标准性能计数器中获取大量有用的信息。

# 在现有应用程序旁边添加 Prometheus 导出器

在 Docker 化解决方案中，Prometheus 将定期调用从容器中暴露的度量端点，并存储结果。对于现有应用程序，您无需添加度量端点 - 您可以在当前应用程序旁边运行一个控制台应用程序，并在该控制台应用程序中托管度量端点。

我在第十章中为 NerdDinner Web 应用程序添加了一个 Prometheus 端点，*使用 Docker 支持持续部署流水线*，而没有更改任何代码。在`dockeronwindows/ch11-nerd-dinner-web-with-metrics`镜像中，我添加了一个导出 ASP.NET 性能计数器并提供指标端点的控制台应用程序。ASP.NET 导出程序应用程序来自 Docker Hub 上的公共镜像。NerdDinner 的完整 Dockerfile 复制了导出程序的二进制文件，并为容器设置了启动命令：

```
#escape=` FROM dockeronwindows/ch10-nerd-dinner-web:2e EXPOSE 50505 ENV COLLECTOR_CONFIG_PATH="w3svc-collectors.json"  WORKDIR C:\aspnet-exporter COPY --from=dockersamples/aspnet-monitoring-exporter:4.7.2-windowsservercore-ltsc2019 C:\aspnet-exporter . ENTRYPOINT ["powershell"] CMD Start-Service W3SVC; ` Invoke-WebRequest http://localhost -UseBasicParsing | Out-Null; `
 Start-Process -NoNewWindow C:\aspnet-exporter\aspnet-exporter.exe; ` netsh http flush logbuffer | Out-Null; `  Get-Content -path 'C:\iislog\W3SVC\u_extend1.log' -Tail 1 -Wait 
```

`aspnet-exporter.exe`控制台应用程序实现了一个自定义的指标收集器，它读取系统上运行的命名进程的性能计数器值。它使用与 NuGet 包中默认收集器相同的一组计数器，但它针对不同的进程。导出程序读取 IIS `w3wp.exe`进程的性能计数器，并配置为导出关键的 IIS 指标。

导出程序的源代码都在 GitHub 的`dockersamples/aspnet-monitoring`存储库中。

控制台导出程序是一个轻量级组件。它在容器启动时启动，并在容器运行时保持运行。只有在调用指标端点时才使用计算资源，因此在 Prometheus 计划运行时影响最小。我按照通常的方式运行 NerdDinner（这里，我只运行 ASP.NET 组件，而不是完整的解决方案）：

```
docker container run -d -P --name nerd-dinner dockeronwindows/ch11-nerd-dinner-web-with-metrics:2e
```

我可以按照通常的方式获取容器端口并浏览 NerdDinner。然后，我还可以浏览导出程序端口上的指标端点，该端点发布 IIS 性能计数器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/45dac49c-d499-475b-b061-7b0d59893237.png)

在这种情况下，没有来自应用程序的自定义计数器，所有指标都来自标准的 Windows 和.NET 性能计数器。导出程序应用程序可以读取运行的`w3wp`进程的这些性能计数器值，因此应用程序无需更改即可向 Prometheus 提供基本信息。

这些是运行时指标，告诉您 IIS 在容器内的工作情况。您可以看到活动线程的数量，内存使用情况以及 IIS 文件缓存的大小。还有关于 IIS 响应的 HTTP 状态代码百分比的指标，因此您可以看到是否有大量的 404 或 500 错误。

要记录自定义应用程序度量，您需要为您的代码添加仪器，并明确记录您感兴趣的数据点。您需要为此付出努力，但结果是一个已经仪器化的应用程序，在其中您可以看到关键性能度量，除了.NET 运行时度量。

为 Docker 化的应用程序添加仪器意味着为 Prometheus 提供度量端点以进行查询。Prometheus 服务器本身在 Docker 容器中运行，并且您可以配置它以监视您想要监视的服务。

# 在 Windows Docker 容器中运行 Prometheus 服务器

Prometheus 是一个用 Go 编写的跨平台应用程序，因此它可以在 Windows 容器或 Linux 容器中运行。与其他开源项目一样，团队在 Docker Hub 上发布了一个 Linux 镜像，但你需要构建自己的 Windows 镜像。我正在使用一个现有的镜像，该镜像将 Prometheus 打包到了来自 GitHub 上相同的`dockersamples/aspnet-monitoring`示例中的 Windows Server 2019 容器中，我用于 ASP.NET 导出器。

Prometheus 的 Dockerfile 并没有做任何在本书中已经看到过很多次的事情——它下载发布文件，提取它，并设置运行时环境。Prometheus 服务器有多个功能：它运行定期作业来轮询度量端点，将数据存储在时间序列数据库中，并提供一个 REST API 来查询数据库和一个简单的 Web UI 来浏览数据。

我需要为调度器添加自己的配置，我可以通过运行一个容器并挂载一个卷来完成，或者在集群模式下使用 Docker 配置对象。我的度量端点的配置相当静态，因此最好将一组默认配置捆绑到我的自己的 Prometheus 镜像中。我已经在`dockeronwindows/ch11-prometheus:2e`中做到了这一点，它有一个非常简单的 Dockerfile：

```
FROM dockersamples/aspnet-monitoring-prometheus:2.3.1-windowsservercore-ltsc2019 COPY prometheus.yml /etc/prometheus/prometheus.yml
```

我已经有从我的仪器化 API 和 NerdDinner web 镜像运行的容器，这些容器公开了供 Prometheus 消费的度量端点。为了在 Prometheus 中监视它们，我需要在`prometheus.yml`配置文件中指定度量位置。Prometheus 将按可配置的时间表轮询这些端点。它称之为**抓取**，我已经在`scrape_configs`部分中添加了我的容器名称和端口：

```
global:
  scrape_interval: 5s   scrape_configs:
 - job_name: 'Api'
    static_configs:
     - targets: ['api:50505']

 - job_name: 'NerdDinnerWeb'
    static_configs:
     - targets: ['nerd-dinner:50505']
```

要监视的每个应用程序都被指定为一个作业，每个端点都被列为一个目标。Prometheus 将在同一 Docker 网络上的容器中运行，因此我可以通过容器名称引用目标。

这个设置是为单个 Docker 引擎设计的，但您可以使用相同的方法使用 Prometheus 监视跨多个副本运行的服务，只需使用不同的配置设置。我在我的 Pluralsight 课程*使用 Docker 监视容器化应用程序健康状况*中详细介绍了 Windows 和 Linux 容器。 

现在，我可以在容器中启动 Prometheus 服务器：

```
docker container run -d -P --name prometheus dockeronwindows/ch11-prometheus:2e
```

Prometheus 轮询所有配置的指标端点并存储数据。您可以将 Prometheus 用作丰富 UI 组件（如 Grafana）的后端，将所有运行时 KPI 构建到单个仪表板中。对于基本监控，Prometheus 服务器在端口`9090`上有一个简单的 Web UI。

我可以转到 Prometheus 容器的发布端口，对其从我的应用程序容器中抓取的数据运行一些查询。Prometheus UI 可以呈现原始数据，或者随时间聚合的图表。这是由 REST API 应用程序发送的 HTTP 响应：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/51c842d2-ccef-4050-804c-944af2e34719.png)

您可以看到每个不同标签值的单独行，因此我可以看到不同 URL 的不同响应代码。这些是随着容器的寿命而增加的计数器，因此图表将始终上升。Prometheus 具有丰富的功能集，因此您还可以绘制随时间变化的变化率，聚合指标并选择数据的投影。

来自 Prometheus `NuGet`软件包的其他计数器是快照，例如性能计数器统计信息。我可以从 NerdDinner 容器中看到 IIS 处理的每秒请求的数量：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/9cc9e9fb-a94b-4fb5-a7ea-a988d49eb640.png)

在 Prometheus 中，指标名称非常重要。如果我想比较.NET 控制台和 ASP.NET 应用程序的内存使用情况，那么如果它们具有相同的指标名称，比如`process_working_set`，我可以查询两组值。每个指标的标签标识提供数据的服务，因此您可以对所有服务进行聚合或对特定服务进行筛选。您还应该将每个容器的标识符作为指标标签包括在内。导出器应用程序将服务器主机名添加为标签。实际上，这是容器 ID，因此在大规模运行时，您可以对整个服务进行聚合或查看单个容器。

在第八章中，《管理和监控 Docker 化解决方案》，我演示了 Docker Enterprise 中的**Universal Control Plane**（**UCP**），这是**Containers-as-a-Service**（**CaaS**）平台。启动和管理 Docker 容器的标准 API 使该工具能够提供集中的管理和管理体验。Docker 平台的开放性使开源工具可以采用相同的方法进行丰富的、集中的监控。

Prometheus 就是一个很好的例子。它作为一个轻量级服务器运行，非常适合在容器中运行。您可以通过向应用程序添加指标端点或在现有应用程序旁边运行指标导出器来为应用程序添加对 Prometheus 的支持。Docker 引擎本身可以配置为导出 Prometheus 指标，因此您可以收集有关容器和节点健康状况的低级指标。

这些指标是您需要的全部内容，可以为您提供关于应用程序健康状况的丰富仪表板。

# 在 Grafana 中构建应用程序仪表板

Grafana 是用于可视化数据的 Web UI。它可以从许多数据源中读取，包括时间序列数据库（如 Prometheus）和关系数据库（如 SQL Server）。您可以在 Grafana 中构建仪表板，显示整个应用程序资产的健康状况，包括业务 KPI、应用程序和运行时指标以及基础设施健康状况。

通常，您会将 Grafana 添加到容器化应用程序中，以呈现来自 Prometheus 的数据。您也可以在容器中运行 Grafana，并且可以打包您的 Docker 镜像，以便内置仪表板、用户帐户和数据库连接。我已经为本章的最后部分做了这样的处理，在`dockeronwindows/ch11-grafana:2e`镜像中。Grafana 团队没有在 Docker Hub 上发布 Windows 镜像，因此我的 Dockerfile 从示例镜像开始，并添加了我设置的所有配置。

```
# escape=` FROM dockersamples/aspnet-monitoring-grafana:5.2.1-windowsservercore-ltsc2019 SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"] COPY datasource-prometheus.yaml \grafana\conf\provisioning\datasources\ COPY dashboard-provider.yaml \grafana\conf\provisioning\dashboards\ COPY dashboard.json \var\lib\grafana\dashboards\

COPY init.ps1 . RUN .\init.ps1 
```

Grafana 有两种自动部署方法。第一种只是使用已知位置的文件，我用它来设置 Prometheus 数据源、仪表板和仪表板提供程序，它只是将 Grafana 指向仪表板目录。第二种使用 REST API 进行身份验证和授权，我的`init.ps1`脚本使用它来创建一个只读用户，该用户可以访问仪表板。

使用 Grafana 创建自己的仪表板很简单。您可以为特定类型的可视化创建面板——支持数字、图形、热图、交通灯和表格。然后，您将面板连接到数据源并指定查询。通常，您会使用 Prometheus UI 来微调查询，然后将其添加到 Grafana 中。为了节省时间，我的镜像带有一个现成的仪表板。

我将使用`ch11`文件夹中的 Docker Compose 文件启动监控解决方案，然后浏览 API 和网站以生成一些流量。现在，我可以浏览 Grafana，并使用用户名`viewer`和密码`readonly`登录，然后我会看到仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/a8ac5193-aa9c-433f-811e-5e25f9899cfa.png)

这只是一个示例仪表板，但它让您了解可以呈现多少信息。我为 REST API 设置了一行，显示了 HTTP 请求和响应的细分，以及 CPU 使用情况的整体视图。我还为 NerdDinner 设置了一行，显示了来自 IIS 的性能指标和缓存使用的头条统计数据。

您可以轻松地向所有应用程序添加工具，并构建详细的仪表板，以便深入了解解决方案中发生的情况。而且，您可以在每个环境中具有完全相同的监视设施，因此在开发和测试中，您可以看到与生产中使用的相同指标。这在追踪性能问题方面非常有用。开发人员可以为性能问题添加新的指标和可视化，解决问题，当更改生效时，它将包括可以在生产中跟踪的新指标。

我将在本章中讨论的最后一件事是如何修复 Docker 中的错误，以及容器化如何使这变得更加容易。

# Docker 中的错误修复工作流程

在修复生产缺陷时最大的困难之一是在开发环境中复制它们。这是确认您有错误并深入查找问题的起点。这也可能是问题中最耗时的部分。

大型.NET 项目往往发布不频繁，因为发布过程复杂，并且需要大量手动测试来验证新功能并检查任何回归。一年可能只有三到四次发布，并且开发人员可能发现自己不得不在发布过程的不同部分支持应用程序的多个版本。

在这种情况下，您可能在生产中有 1.0 版本，在用户验收测试（UAT）中有 1.1 版本，在系统测试中有 1.2 版本。开发团队可能需要跟踪和修复任何这些版本中提出的错误，而他们目前正在处理 1.3 版本，甚至是 2.0 的重大升级。

# 在 Docker 之前修复错误

我经常处于这种境地，不得不从我正在工作的重构后的 2.0 代码库切换回即将发布的 1.1 代码库。上下文切换是昂贵的，但是设置开发环境以重新创建 1.1 UAT 环境的过程更加昂贵。

发布过程可能会创建一个带版本号的 MSI，但通常你不能在开发环境中直接运行它。安装程序可能会打包特定环境的配置。它可能已经以发布模式编译并且没有 PDB 文件，因此没有附加调试器的选项，它可能具有我在开发中没有的先决条件，比如证书、加密密钥或其他软件组件。

相反，我需要重新编译源代码中的 1.1 版本。希望发布过程提供了足够的信息，让我找到用于构建发布的确切源代码，然后在本地克隆它（也许 Git 提交 ID 或 TFS 变更集记录在构建的程序集中）。然后，当我尝试在我的本地开发环境中重新创建另一个环境时，真正的问题开始了。

工作流程看起来有点像这样，在我的设置和 1.1 环境之间存在许多差异：

+   在本地编译源代码。我将在 Visual Studio 中构建应用程序，但发布版本使用的是 MSBuild 脚本，它做了很多额外的事情。

+   在本地运行应用程序。我将在 Windows 10 上使用 IIS Express，但发布使用的是部署到 Windows Server 2012 上的 IIS 8 的 MSI。

+   我的本地 SQL Server 数据库设置为我正在使用的 2.0 架构。发布中有从 1.0 升级到 1.1 的升级脚本，但没有从 2.0 降级到 1.1 的脚本，因此我需要手动修复本地架构。

+   对于我无法在本地运行的任何依赖项，例如第三方 API，我有存根。发布使用真实的应用程序组件。

即使我可以获得版本 1.1 的确切源代码，我的开发环境与 UAT 环境存在巨大差异。这是我能做的最好的，可能需要数小时的努力。为了减少这段时间，我可以采取捷径，比如利用我对应用程序的了解来运行版本 1.1 与 2.0 数据库架构，但采取捷径意味着我的本地环境与目标环境更不相似。

在这一点上，我可以以调试模式运行应用程序并尝试复制问题。如果错误是由 UAT 中的数据问题或环境问题引起的，那么我将无法复制它，可能需要花费整整一天的时间才能找出这一点。如果我怀疑问题与 UAT 的设置有关，我无法在我的环境中验证这一点；我需要与运维团队合作，查看 UAT 配置。

但希望我可以通过按照错误报告中的步骤重现问题。当我弄清楚手动步骤后，我可以编写一个失败的测试来复制问题，并且在更改代码并且测试运行成功时，我可以确信我已经解决了问题。我的环境与 UAT 之间存在差异，因此可能是我的分析不正确，修复无法修复 UAT，但直到下一个发布之前我才能发现这一点。

如何将该修复发布到 UAT 环境是另一个问题。理想情况下，完整的 CI 和打包过程已经为 1.1 分支设置好，因此我只需推送我的更改，然后就会出现一个准备部署的新 MSI。在最坏的情况下，CI 仅从主分支运行，因此我需要在修复分支上设置一个新的作业，并尝试配置该作业与上次 1.1 发布时相同。

如果在 1.1 和 2.0 之间的任何工具链部分发生了变化，那么这将使整个过程的每一步都变得更加困难，从配置本地环境，运行应用程序，分析问题到推送修复。

# 使用 Docker 修复错误

使用 Docker 的过程要简单得多。要在本地复制 UAT 环境，我只需要从在 UAT 中运行的相同镜像中运行容器。将有一个描述整个解决方案的 Docker Compose 或堆栈文件进行版本控制，因此通过部署版本 1.1，我可以获得与 UAT 完全相同的环境，而无需从源代码构建。

我应该能够在这一点上复制问题并确认它是编码问题还是与数据或环境有关的问题。如果是配置问题，那么我应该看到与 UAT 相同的问题，并且我可以使用更新的 Compose 文件测试修复。如果是编码问题，那么我需要深入了解代码。

在这一点上，我可以从版本 1.1 标签中克隆源代码并以调试模式构建 Docker 镜像，但除非我相当确定这是应用程序中的问题，否则我不会花时间这样做。如果我在 Dockerfile 中使用多阶段构建，并且所有版本都在其中固定，那么本地构建将产生与在 UAT 中运行的相同镜像，但会有额外的用于调试的工件。

现在，我可以找到问题，编写测试并修复错误。当新的集成测试通过时，它是针对我将在 UAT 中部署的相同 Docker 化解决方案执行的，因此我可以非常确信该错误已经被修复。

如果 1.1 分支没有配置 CI，那么设置它应该很简单，因为构建任务只需要运行`docker image build`或`docker-compose build`命令。如果我想要快速反馈，我甚至可以将本地构建的镜像推送到注册表，并部署一个新的 UAT 环境来验证修复，同时配置 CI 设置。新环境将只是测试集群上的不同堆栈，因此我不需要为部署再委托更多的基础设施。

Docker 的工作流程更加清洁和快速，但更重要的是，风险要小得多。当您在本地复制问题时，您使用的是与 UAT 环境上完全相同的应用程序组件在完全相同的平台上运行。当您测试您的修复时，您知道它将在 UAT 中起作用，因为您将部署相同的新构件。

将您投入 Docker 化应用程序的时间将通过节省支持应用程序多个版本的时间而多次偿还。

# 总结

本章讨论了在容器中运行的应用程序的故障排除，以及调试和仪器化。Docker 是一个新的应用程序平台，但是容器中的应用程序作为主机上的进程运行，因此它们仍然是远程调试和集中监控的合适目标。

Visual Studio 的所有当前版本都支持 Docker。Visual Studio 2017 具有最完整的支持，涵盖 Linux 和 Windows 容器。Visual Studio 2015 和 Visual Studio Code 目前具有提供 Linux 容器调试的扩展。您可以轻松添加对 Windows 容器的支持，但完整的调试体验仍在不断发展。

在本章中，我还介绍了 Prometheus，这是一个轻量级的仪器和监控组件，您可以在 Windows Docker 容器中运行。Prometheus 存储它从其他容器中运行的应用程序提取的指标。容器的标准化性质使得配置诸如这样的监控解决方案非常简单。我使用 Prometheus 数据来驱动 Grafana 中的仪表板，该仪表板在容器中运行，这是呈现应用程序健康状况的综合视图的简单而强大的方式。

下一章是本书的最后一章。我将以分享一些在您自己的领域中开始使用 Docker 的方法结束，包括我在现有项目中在 Windows 上使用 Docker 的案例研究。
