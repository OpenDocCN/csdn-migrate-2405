# Jenkins 持续集成学习手册（三）

> 原文：[`zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17`](https://zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：分布式构建

Jenkins 的主从架构使得在多个从机器上分发工作变得更容易。本章节主要讨论在不同平台配置 Jenkins 从节点的相关内容。以下是我们将要涵盖的主题：

+   Jenkins 节点管理器概览

+   在独立的 Linux 机器上安装 Jenkins 从节点

+   在独立的 Windows 机器上安装 Jenkins 从节点

+   安装和配置 Docker 插件用于创建按需的 Jenkins 从节点

# 分布式构建和测试

在接下来的章节中，让我们简单了解一下分布式构建和测试。想象一下，你有一个非常庞大的单元测试或集成测试套件。如果你可以将它们分为小部分，然后并行运行，那就可以了。要并行运行它们，你需要多个克隆的构建/测试机器。如果你已经设置好了，无论是使用 Docker 还是其他机制，那么剩下的就是将它们变成 Jenkins 从节点代理了。

以下示例展示了 Jenkins 流水线如何利用 Jenkins 中的分布式构建/测试农场进行构建、单元测试和集成测试。你会看到，我们有两类 Jenkins 从节点代理：用于构建和单元测试的独立 Jenkins 从节点，以及用于集成测试的独立 Jenkins 从节点。

单元测试分布在三个用于构建和单元测试的 Jenkins 从节点代理中（第一类），而集成测试分布在两个用于集成测试的 Jenkins 从节点代理中（第二类）。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/717a6c52-f11d-47d3-be93-718225fdb5fd.png)

使用 Jenkins 独立从节点进行分布式构建和测试

Jenkins 从节点代理使用**标签**进行分类。我们将在接下来的章节中详细了解标签的内容。

使用 Docker 按需生成 Jenkins 从节点也更好、更容易。如下图所示，这是我们之前讨论的相同概念的 Docker 版本。这里使用 Docker 镜像按需创建 Jenkins 从节点。

你可以看到在以下示例中，我们有两种类型的 Docker 镜像：用于构建和单元测试的 Docker 镜像，以及用于集成测试的 Docker 镜像。这些 Docker 从节点代理是使用这些 Docker 镜像创建的。单元测试分布在三个用于构建和单元测试的 Docker 从节点代理中（第一类），而集成测试则分布在两个用于集成测试的 Docker 从节点代理中（第二类）。

同样在这里，Docker 从节点代理使用标签进行分类。我们将在接下来的章节中详细了解标签的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/61f3d4e8-b854-4484-ae97-a33c1f11cf00.png)

使用 Jenkins 和 Docker 从节点代理进行分布式构建和测试

# Jenkins 管理节点页面

在接下来的章节中，我们将看一下 Jenkins **管理节点**页面：

1.  从 Jenkins 仪表盘上，点击**管理 Jenkins** | **管理节点**。

1.  在左侧，你会看到一个菜单；选项如以下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/28dc83ba-a19f-4211-a012-6c05e799ccb7.png)

Jenkins 管理节点页面

1.  在右侧，您还将看到一个显示可用 Jenkins 从机列表的表格，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e1a18e07-2033-48e3-b60f-2b5136a9ec61.png)

可用节点列表

1.  由于我们尚未配置任何 Jenkins 从机，列表（如前面的截图所示）只包含一个条目：即主机。

1.  表格除了节点的名称外，还显示有关节点的其他有用信息，例如架构、可用磁盘空间量和响应时间。

1.  要启用/禁用有关每个节点显示的信息量，点击配置链接（请参阅*Jenkins 管理节点页面*截图）。这将带您前往下一页，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8624581a-3562-4e27-89cb-538d2bfb5536.png)

预防性节点监控选项

1.  选中/取消选中相关选项以启用/禁用它们。“空闲空间阈值”选项很重要。如果可用磁盘空间和临时空间的空闲量低于指定值（默认为`1GB`），则节点将离线。这可以防止 Jenkins 流水线在磁盘空间不足的从机上运行导致最终失败。

# 添加 Jenkins 从机 – 独立的 Linux 机器/虚拟机

在接下来的部分，我们将尝试将一个独立的 Linux 机器添加为 Jenkins 从机。确保您即将添加的 Jenkins 从机上已安装了 Java。按照以下步骤操作：

1.  从 Jenkins 仪表板中，点击**管理 Jenkins** | **管理节点**。

1.  从左侧菜单中，点击**新建节点**。在生成的页面上，您将被要求为您的节点提供一个名称并选择类型，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d030bc67-453f-4a2f-b62a-b5b86d60d91b.png)

添加名称和选择代理类型（从机类型）

1.  在**节点名称**字段下添加一个有意义的名称，并选择代理类型。目前，只有一种类型的代理可供选择：即永久代理。这些代理主要是物理机器和虚拟机。

1.  点击**确定**按钮继续。

1.  在生成的页面上，您将看到以下配置选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7808491f-1b30-4647-85e2-acb14ccc6416.png)

Jenkins 从机配置

让我们逐一查看它们：

1.  我们已经使用了“名称”字段为我们的 Jenkins 从机命名。

1.  使用“描述”字段添加有关 Jenkins 从机的一些注释：例如，用途、类型、可构建或测试的内容以及已安装的工具。

1.  “执行器数量”字段用于描述 Jenkins 从机（代理）被允许同时运行的平行构建数量。选择大于`1`的值，比如`3`，将允许 Jenkins 从机并行运行三个构建。这可能导致每个构建所需时间比平常长。请明智选择。

1.  远程根目录字段 用于定义 Jenkins 从机上的目录路径，该路径将作为 Jenkins 执行构建活动的专用工作空间。

1.  标签字段 是最重要的。您可以向 Jenkins 从机添加多个标签（用空格分隔）。为了在特定的从机上运行流水线，您将使用其标签，如前面的屏幕截图所示。我们添加了一个 `maven-build-1` 标签，表示它是一个 Jenkins 从机用于构建 Maven 项目。

1.  使用字段 用于定义 Jenkins 如何在此节点上安排构建。它包含两个选项，如下所示：

    +   尽可能使用此节点：这是默认选项。此模式使当前 Jenkins 从机对所有未配置为在特定 Jenkins 从机上运行的流水线开放。

    +   仅构建与该节点匹配标签表达式的作业：在此模式下，Jenkins 将仅在此节点上构建项目，当该项目被限制在特定节点上使用标签表达式，并且该表达式与此节点的名称和/或标签匹配时。

1.  启动方法字段 描述了 Jenkins 如何启动此 Jenkins 从机。它包含四个选项，如下所示。在下面的示例中，我们将使用 SSH 方法启动我们的 Jenkins 从机。请参阅 *通过 SSH 启动 Jenkins 从机* 部分：

    +   通过 Java Web Start 启动代理：这允许使用 Java Web Start 启动代理。在这种情况下，必须在代理机器上打开一个 Java 网络启动协议（JNLP）文件，该文件将建立到 Jenkins 主机的 TCP 连接。如果您通过配置全局安全页面启用了安全性，您可以自定义 Jenkins 主机将监听传入 JNLP 代理连接的端口。

    +   通过在主机上执行命令来启动代理：这通过让 Jenkins 从主机执行一个命令来启动一个代理。当主机能够在另一台机器上远程执行进程时，例如，通过 SSH 或远程 shell（RSH）时，使用此选项。

    +   通过 SSH 启动从机代理：这通过安全的 SSH 连接发送命令来启动从机代理。从机需要从主机可达，并且您将需要提供一个可以登录目标机器的帐户。不需要 root 权限。

    +   让 Jenkins 作为 Windows 服务控制此 Windows 从机：这通过内置到 Windows 中的远程管理设施启动 Windows 从机。适用于管理 Windows 从机。从机需要从主机可达。

1.  可用性字段定义了 Jenkins 如何启动、停止和使用 Jenkins 从机。它有三个选项，如下所示：

    +   尽可能保持此代理在线：在此模式下，Jenkins 将尽可能保持此代理在线。如果代理下线，例如，由于临时网络故障，Jenkins 将定期尝试重新启动它。

    +   在特定时间在线和离线此代理：在此模式下，Jenkins 将在预定时间将此代理上线，保持在线一段指定时间。如果代理在预定上线时间内离线，Jenkins 将定期尝试重新启动它。在此代理在线时间达到“预定上线时间”字段指定的分钟数后，它将被下线。如果选中了“在构建运行时保持在线”复选框，并且预定将代理下线，Jenkins 将等待正在进行的任何构建完成。

    +   当需求时上线此代理，并在空闲时下线：在此模式下，如果有需求，即如果有排队构建符合以下条件：它们至少已在队列中等待指定的需求延迟时间段

    +   它们可以由此代理执行（例如，具有匹配的标签表达式）

如果：

1.  1.  +   此代理上没有正在运行的活动构建

        +   此代理至少已处于指定的空闲延迟时间段中空闲

# 将环境变量传递给 Jenkins 的节点

按照给定的步骤传递环境变量：

1.  你将看到一个名为节点属性的部分。使用这些选项，你可以将预定义的环境变量传递给 Jenkins 的节点和工具位置。

1.  如下图所示，你可以将环境变量传递给 Jenkins 的节点。可以传递多个环境变量（通过点击**添加**按钮）。这些环境变量在 Jenkins 管道执行期间可用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5c88759c-f83e-4644-bbf0-be08e2a3dbdc.png)

将环境变量传递给 Jenkins 的节点

随着 Jenkins 中 *Pipeline as Code* 功能的推出，可以在 Jenkins 管道代码（管道脚本/Jenkinsfile）中定义和使用环境变量。因此，定义环境变量选项（如前面的截图所示）变得不太重要。

# 将工具位置传递给 Jenkins 的节点

如下图所示，你可以指定 Jenkins 节点上某些工具的位置，覆盖全局配置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6b6704f0-5295-4c5d-b77d-53f98ce2425c.png)

将工具位置传递给 Jenkins 的节点

# 通过 SSH 启动 Jenkins 节点代理

要通过 SSH 启动节点代理，请按照以下步骤：

1.  当你选择通过 SSH 启动节点代理选项时，会出现以下选项，如下图所示。

1.  主机字段是你可以定义 Jenkins 节点代理机器的 IP 地址或主机名的地方。

1.  凭据字段允许你选择保存在 Jenkins 内的相关凭据，以验证 Jenkins 节点代理。要创建新凭据，请点击凭据字段旁边的“添加”按钮（创建一个用户名和密码类型的凭据）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d4fa369b-876b-41e3-8c2b-35269b125a3d.png)

配置通过 SSH 属性启动从属代理

您用于验证 Jenkins 从属代理的用户应该对远程根目录字段下定义的目录路径具有读/写权限。

1.  最后一个选项，主机密钥验证策略，定义了 Jenkins 在连接时验证远程主机呈现的 SSH 密钥的方式。此选项仅在使用以下凭据时有效：种类：SSH 用户名与私钥。有四个可用选项，如下所示：

    +   已知主机文件验证策略：这将检查用户 Jenkins 在其下执行的 `known_hosts` 文件（`~/.ssh/known_hosts`），以查看是否存在与当前连接匹配的条目。此方法不会对 `known_hosts` 文件进行任何更新，而是将文件用作只读源，并期望拥有适当访问权限的人员根据需要更新文件，可能使用 `ssh 主机名` 命令启动连接并适当地更新文件。

    +   手动提供密钥验证策略：这检查远程主机提供的密钥是否与配置此连接的用户设置的密钥匹配。

    +   已知受信任密钥验证策略：这将检查远程密钥是否与当前为此主机标记为受信任的密钥匹配。根据配置，密钥将自动受信任于第一次连接，或者将要求授权用户批准该密钥。将要求授权用户批准远程主机呈现的任何新密钥。

    +   无验证验证策略：这不对远程主机呈现的 SSH 密钥执行任何验证，允许所有连接，而不管它们呈现的密钥是什么。

1.  一旦您完成了所有选项的配置，请单击保存按钮。

# 关于活动 Jenkins 从属代理的更多信息

在接下来的部分，我们将看看我们刚刚添加的 Jenkins 从属代理可用的各种其他可配置选项。Jenkins 还提供了关于其从属代理的许多常规信息，我们将在这里看到。按照以下步骤：

1.  从 Jenkins 仪表板中，单击管理 Jenkins | 管理节点。

1.  在右侧，您还将看到一个表格，其中显示了可用的 Jenkins 从属代理列表。新添加到列表中的是我们新添加的 Jenkins 从属代理。

1.  单击 Jenkins 从属代理名称以访问其配置和元数据。

1.  在结果页面（Jenkins 从属代理状态页面）上，您将在左侧菜单中看到一些选项，如下图所示：

![img/0110ad53-fefb-415b-b8c1-07a7259ca3b2.png](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0110ad53-fefb-415b-b8c1-07a7259ca3b2.png)

Jenkins 从属代理页面

1.  大多数前述链接（来自前述屏幕截图）是不言自明的。但是，让我们详细查看其中一些。

1.  日志链接是您将找到与 Jenkins 从属节点相关的所有日志的地方。在添加 Jenkins 从属节点后，如果它没有上线，您需要查看日志。连接到 Jenkins 从属节点时遇到的认证问题、权限问题以及其他所有问题都会在此列出。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/75e9461b-266b-4728-9ae9-199714b159f0.png)

Jenkins 从属节点日志

1.  系统信息链接将向您显示有关相应 Jenkins 从属节点的大多数系统信息，例如系统属性和环境变量。请参阅上述屏幕截图。您不会经常访问此处。尽管如此，在调试由于系统工具、环境变量等引起的构建错误时，这很有用：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/13597da5-9afd-4d48-8e55-a820df9d3f41.png)

Jenkins 从属节点系统信息

1.  构建历史链接将向您显示在相应的 Jenkins 从属节点上执行的所有构建的时间线。

1.  在 Jenkins 从属节点状态页面上，您将看到附加到相应 Jenkins 从属节点的标签，以及与以下 Jenkins 从属节点关联的项目的信息。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/3baed5fb-2918-44a3-8754-16f6c407c07f.png)

Jenkins 从属节点状态页面

1.  有一个选项可以通过点击“将此节点暂时脱机”按钮将 Jenkins 从属节点临时脱机。当您点击该按钮时，将会要求您在将 Jenkins 从属节点脱机之前添加一个注释（可选）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a2b42a63-8020-4717-b83e-0b5afd1ab36a.png)

使 Jenkins 从属节点脱机

1.  要将脱机节点重新上线，请从 Jenkins 状态页面上点击“使此节点重新上线”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/338fb9ee-1fab-4f4e-a7e9-7e412e0fdf7f.png)

启动 Jenkins 从属节点

# 添加 Jenkins 从属节点 – 独立的 Windows 机器/虚拟机

在以下部分，我们将尝试将独立的 Windows 机器添加为 Jenkins 从属节点。确保您的即将成为 Jenkins 从属节点的机器上已安装了 Java。按照以下步骤操作：

1.  从左侧菜单中，点击“新建节点”。在生成的页面上，您将被要求为您的节点提供名称并选择类型，如下面的屏幕截图所示：

1.  从 Jenkins 仪表板中，点击**管理 Jenkins** | **管理节点**。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/368c6f20-7c9f-4c0b-bfff-a130f5eb8508.png)

添加名称并选择代理类型（从属类型）

1.  在“节点名称”字段下添加有意义的名称，并将代理类型选择为永久代理。这些代理类型主要是物理机器和虚拟机。还有一种选项可以克隆现有的 Jenkins 从属节点。要这样做，请选择“复制现有节点”选项，并在“从字段”下输入 Jenkins 从属节点源的名称。

1.  然而，在以下示例中，我们将选择永久代理选项。

1.  单击“确定”按钮继续。

1.  在生成的页面上，您将看到以下配置选项，如下面的屏幕截图所示。我们已经在之前看过它们：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a40ecb00-809b-4338-8daf-86bcbd42700e.png)

Jenkins 从节点配置

1.  由于这是一个 Windows 构建代理，我们有两种方式可以启动 Jenkins 从节点，如下所示：

    +   通过 Java Web Start 启动代理：这允许使用 Java Web Start 启动代理。在这种情况下，必须在代理机器上打开一个 JNLP 文件，该文件将建立到 Jenkins 主服务器的 TCP 连接。如果您通过配置全局安全性页面启用了安全性，您可以自定义 Jenkins 主服务器将监听传入 JNLP 代理连接的端口。

    +   让 Jenkins 作为 Windows 服务控制此 Windows 从节点：这将通过 Windows 内置的远程管理功能启动 Windows 从节点。适用于管理 Windows 从节点。从节点需要从主服务器可达的 IP。

# 通过 Java Web Start 启动 Jenkins 从节点

在下一节中，我们将学习如何使用 Java Web Start 方法在 Windows 上启动 Jenkins 从节点。

1.  对于 启动方法 字段，请选择通过 Java Web Start 启动代理。

1.  点击保存按钮。

1.  从 Jenkins 管理节点页面，点击 Jenkins 从节点名称。在我们的示例中，它是`standalone-windows-slave`。

1.  在结果页面（Jenkins 从节点状态页面）上，您将看到以下选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e759d255-6a0c-4490-b307-4fe948e361f4.png)

Jenkins 从节点连接方法（Java Web Start）

1.  在 Jenkins 服务器上不执行任何操作。

1.  现在，登录到您准备用作 Jenkins 从节点的机器（Windows）并打开 Jenkins 仪表板。

1.  从 Jenkins 仪表板，点击管理 Jenkins | 管理节点。

1.  从 Jenkins 管理节点页面，点击 Jenkins 从节点名称。在我们的示例中，它是`standalone-windows-slave`。

1.  现在，要么按照以下截图中所示运行命令，要么点击启动按钮。

1.  如果选择点击启动按钮，则会看到以下弹出窗口，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/785440f2-11d0-4324-9932-0b72cfbad081.png)

打开 slave-agent.jnlp 文件

1.  选择 打开方式 选项为 Java(TM) Web Start Launcher（默认）选项，然后点击 确定按钮。

1.  您将收到另一个弹出窗口，询问您是否希望运行此应用程序。如下截图所示，点击运行：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ecd49b99-5d32-45cd-9d03-8d5bfcb3c875.png)

运行 Jenkins 远程代理

1.  最后，您将看到一个小窗口显示 Jenkins 从节点连接状态为已连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/72c099b7-890c-484d-ab55-334c0e420c1a.png)

Jenkins 从节点代理窗口。

1.  您的 Jenkins 从节点（Windows）现在已连接。要将其作为 Windows 服务，点击文件（上一张截图），然后选择安装为服务。

1.  打开运行实用程序并输入命令`services.msc`以打开 Windows 服务实用程序。在服务列表中，您会发现 Jenkins 从节点代理服务，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7276900d-8174-46d6-bd08-9d8ae475fddd.png)

Jenkins 从节点列为 Windows 服务。

1.  右键单击 Jenkins 从机 Windows 服务，选择属性。

1.  在属性窗口中，转到*登录*选项卡。在*登录为*部分下，选择*此账户*选项，并提供管理员账户的详细信息（在 Jenkins 从机上具有管理员特权的用户），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5a306aab-9b75-4ce0-8af3-a1e674f00289.png)

Jenkins 从机服务属性

1.  您的 Jenkins 从机（Windows 上）现已安装。

# 添加 Jenkins 从机 - Docker 容器

在接下来的部分中，我们将学习如何安装和配置 Docker 插件，该插件将允许我们从 CI 流水线生成按需的 Jenkins 从机（Docker 容器）。 Docker 容器由 CI 流水线启动，一旦构建完成，它们将被销毁。在接下来的部分中，我们只会看到配置部分。在下一章中，我们将看到这个过程的实际运行。

# 先决条件

在我们开始之前，请确保您准备好以下内容：

+   在以下任一平台上运行 Jenkins 服务器：Docker、独立、云、虚拟机、servlet 容器等（参考第二章，*安装 Jenkins*）。

+   您的 Jenkins 服务器应该有访问互联网的权限。这是下载和安装插件所必需的。

+   您的 Jenkins 服务器可以使用 GitHub 插件与 GitHub 进行交互（请参考第三章中的*在 Jenkins 中添加 GitHub 凭证*和*从 Jenkins 配置 GitHub 上的 Webhooks*部分， *全新的 Jenkins*）。

+   您的 Jenkins 服务器还可能需要配置 Java、Git 和 Maven。（请参考第三章中*全局工具配置页面*部分下的*全新 Jenkins 流水线任务*子部分， *全新的 Jenkins*）。

+   一个 Docker 服务器。

# 设置 Docker 服务器

要安装 Docker，您需要拥有以下 Ubuntu 操作系统之一（64 位）的计算机：Yakkety Yak 16.10、Xenial Xerus 16.04 或 Trusty Tahr 14.04。确保还安装了`curl`。按照给定的步骤设置 Docker 服务器。

# 设置仓库

按照以下给出的步骤设置仓库：

1.  执行以下命令让`apt`使用一个仓库：

```
 sudo apt-get install apt-transport-https ca-certificates
```

1.  使用以下命令添加 Docker 的官方 GPG 密钥：

```
 curl -fsSL https://yum.dockerproject.org/gpg | sudo apt-key add -
```

1.  验证密钥 ID 是否完全是`58118E89F3A912897C070ADBF76221572C52609D`，使用以下命令：

```
 apt-key fingerprint 58118E89F3A912897C070ADBF76221572C52609D
```

1.  您应该看到类似的输出：

```
 pub 4096R/2C52609D 2015-07-14
 Key fingerprint = 5811 8E89 F3A9 1289 7C07 0ADB F762 2157 2C52 609D
 Uid Docker Release Tool (releasedocker) docker@docker.com
```

1.  使用以下命令设置一个稳定的仓库来下载 Docker：

```
 sudo add-apt-repository \
        "deb https://apt.dockerproject.org/repo/ubuntu-$(lsb_release -cs) \
        main"
```

建议始终使用仓库的稳定版本。

# 使用 apt-get 安装 Docker

现在您已经设置好了仓库，请执行以下步骤安装 Docker：

1.  使用以下命令更新`apt`软件包索引：

```
 sudo apt-get update
```

1.  要安装最新版本的 Docker，请执行以下命令：

```
 sudo apt-get -y install docker-engine
```

1.  然而，如果您希望安装特定版本的 Docker，请执行以下命令：

```
 apt-cache madison docker-engine
```

1.  这将给出可用版本的列表：

```
 docker-engine | 1.16.0-0~trusty |
        https://apt.dockerproject.org/repo
        ubuntu-trusty/main amd64 Packages
 docker-engine | 1.13.3-0~trusty |
        https://apt.dockerproject.org/repo
        ubuntu-trusty/main amd64 Packages 
```

前面命令的输出取决于在前一部分配置的仓库类型，即*设置仓库*。

1.  接下来，执行以下命令来安装特定版本的 Docker：

```
 sudo apt-get -y install docker-engine=<VERSION_STRING>
```

例子：`sudo apt-get -y install docker-engine=1.16.0-0~trusty`

1.  `docker`服务会自动启动。要验证 Docker 是否已安装并运行，请运行以下命令：

```
 sudo docker run hello-world 
```

1.  如果前面的命令运行没有任何错误，并且你看到了`hello world`消息，那意味着 Docker 已经安装并运行。

```
 Hello from Docker!
 This message shows that your installation appears to be
        working correctly.
```

# 使用 .deb 软件包安装 Docker

如果由于某些原因，你无法使用上述的仓库方法安装 Docker，你可以下载`.deb`包。

1.  从[`apt.dockerproject.org/repo/pool/main/d/docker-engine/`](https://apt.dockerproject.org/repo/pool/main/d/docker-engine/)下载你选择的`.deb`软件包。

1.  要安装下载的软件包，请输入以下内容：

```
 sudo dpkg -i /<path to package>/<docker package>.deb
```

1.  运行以下命令验证你的 Docker 安装：

```
 sudo docker run hello-world
```

1.  如果前面的命令运行没有任何错误，并且你看到了`hello world`消息，那意味着 Docker 已经安装并运行。

```
 Hello from Docker!
 This message shows that your installation appears to be
        working correctly.
```

# 启用 Docker 远程 API

Jenkins（通过 Docker 插件）使用*Docker 远程 API*与 Docker 服务器进行通信。Docker 远程 API 允许外部应用程序使用 REST API 与 Docker 服务器通信。Docker 远程 API 也可以用于获取 Docker 服务器内所有运行的容器的信息。

要启用 Docker 远程 API，我们需要修改 Docker 的配置文件。根据你的操作系统版本和在你的计算机上安装 Docker 的方式，你可能需要选择正确的配置文件进行修改。以下是适用于 Ubuntu 的两种方法。

# 修改 docker.conf 文件

遵循以下步骤修改 `docker.conf` 文件。这些配置是允许 Jenkins 与 Docker 主机通信的重要配置：

1.  登录到你的 Docker 服务器，确保你有`sudo`权限。

1.  执行以下命令来编辑`docker.conf`文件：

```
 sudo nano /etc/init/docker.conf
```

1.  在 `docker.conf` 文件中，找到包含 `DOCKER_OPTS=`的行。

你会在 `docker.conf` 文件中找到两处包含`DOCKER_OPTS=`变量的地方。首先，在预启动脚本部分，然后在后启动脚本部分。在预启动脚本部分使用`DOCKER_OPTS=`变量。

1.  将`DOCKER_OPTS`的值设置为以下内容：

```
        DOCKER_OPTS='-H tcp://0.0.0.0:4243 -H unix:///var/run/docker.sock'
```

1.  前面的设置将将 Docker 服务器绑定到 Unix 套接字，以及 TCP 端口`4243`。`0.0.0.0`，这使得 Docker 引擎接受来自任何地方的连接。

如果你希望你的 Docker 服务器仅接受来自你的 Jenkins 服务器的连接，则将`0.0.0.0`替换为你的 Jenkins 服务器 IP。

1.  使用以下命令重新启动 Docker 服务器：

```
 sudo service docker restart
```

1.  要检查配置是否生效，请输入以下内容：

```
 curl -X GET http://<Docker server IP>:4243/images/json
```

前面的命令将列出 Docker 服务器上存在的所有镜像，如果有的话。

# 修改 docker.service 文件

按照以下步骤修改`docker.service`文件：

1.  执行以下命令编辑`docker.service`文件：

```
 sudo nano /lib/systemd/system/docker.service
```

1.  在`docker.service`文件中，转到包含`ExecStart=`的行。

1.  将`ExecStart=`的值设置如下：

```
        ExecStart=/usr/bin/docker daemon -H fd:// -H tcp://0.0.0.0:4243
```

1.  上述设置将 Docker 服务器绑定到 Unix 套接字。此外，在 TCP 端口`4243`上。`0.0.0.0`，它使 Docker 引擎接受来自任何地方的连接。

如果您希望您的 Docker 服务器仅接受来自您的 Jenkins 服务器的连接，请将`0.0.0.0`替换为您的 Jenkins 服务器 IP。

1.  执行以下命令使 Docker 守护进程注意到修改后的配置：

```
 systemctl daemon-reload
```

1.  使用以下命令重新启动 Docker 服务器：

```
 sudo service docker restart
```

1.  要检查配置是否生效，请输入以下内容：

```
 curl -X GET http://<Docker server IP>:4243/images/json
```

如果有的话，上述命令将列出您的 Docker 服务器上存在的所有镜像。

# 安装 Docker 插件

要动态创建 Docker 容器（构建代理），我们需要为 Jenkins 安装 Docker 插件。为此，请按照以下步骤操作：

1.  从 Jenkins 仪表板中，单击“管理 Jenkins | 管理插件 | 可用”选项卡。您将进入 Jenkins 管理插件页面。

1.  在过滤字段中输入`Docker Plugin`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b75bf3f0-c19e-4feb-88c5-19c5ffffec1a.png)

安装 Docker 插件

1.  从列表中选择**Docker 插件**，然后单击**无需重启安装**按钮。

1.  如果需要，请重新启动 Jenkins。

# 配置 Docker 插件

现在我们已经安装了 Docker 插件，让我们对其进行配置：

1.  从 Jenkins 仪表板中，单击“管理 Jenkins | 配置系统”。

1.  一旦进入配置系统页面，请滚动到底部的 Cloud 部分（参见下图）。

1.  单击“添加新云”按钮，然后从可用选项中选择 Docker。

1.  在结果页面上，您将找到许多要配置的设置。

1.  使用“名称”字段为您的 Docker 服务器命名。

1.  在 Docker URL 字段下添加您的 Docker 服务器 URL。

1.  单击“测试连接”按钮以检查 Jenkins 是否可以与 Docker 服务器通信：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/fa494748-28b3-46bb-9054-1aaa218a2273.png)

配置 Docker 插件以与 Docker 服务器通信

1.  在页面底部，单击**应用**和**保存**按钮。稍后我们会再次回到这里进行进一步的配置。

# 创建 Docker 镜像 - Jenkins 从属

启用 Docker 远程 API 使 Jenkins 与 Docker 服务器之间的通信成为可能。现在我们需要在 Docker 服务器上有一个 Docker 镜像。Jenkins 将使用此 Docker 镜像动态创建 Docker 容器（Jenkins 从属）。为此，请按照如下步骤操作：

1.  登录到您的 Docker 服务器。输入以下命令以检查可用的 Docker 镜像：

```
 sudo docker images
```

1.  从下图中，您可以看到我们的 Docker 服务器上已经有两个`docker images`（`ubuntu`和`hello-world`）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5f8fffd9-65b6-481d-a65e-4ebf3e152c99.png)

列出 Docker 镜像

1.  如果您的 Docker 服务器是一台刚刚备份的机器，则此时您将看不到任何镜像。

1.  我们将从`ubuntu` Docker 镜像构建一个用于我们的用途的 Docker 镜像。为此，请使用以下命令下载`ubuntu`的 Docker 镜像：

```
 docker pull ubuntu
```

您可以在[`hub.docker.com/`](https://hub.docker.com/)找到更多不同操作系统的 Docker 镜像。

1.  拉取完成后，再次执行`sudo docker images`命令。现在，您应该可以看到一个用于 Ubuntu 的 Docker 镜像，如前面的截图所示。

1.  现在，我们将使用我们需要运行构建所需的所有必要应用程序来升级我们的 Ubuntu Docker 镜像。它们如下所示：

    +   Java JDK（最新版本）

    +   Git

    +   Maven

    +   用于登录到 Docker 容器的用户账户

    +   `sshd`（用于接受 SSH 连接）

1.  使用以下命令运行 Docker 容器，使用 Ubuntu Docker 镜像。这将创建一个容器，并打开其 bash shell：

```
 sudo docker run -i -t ubuntu /bin/bash
```

1.  现在，安装所有所需的应用程序，就像您在任何普通的 Ubuntu 机器上执行的操作一样。让我们从创建`jenkins`用户开始：

    1.  执行以下命令，并按照下图中显示的用户创建步骤进行操作：

```
 adduser jenkins
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6924bed0-dcd8-437e-813a-7457b4bdd3b7.png)

创建用户

1.  1.  使用切换用户命令检查新用户：

```
 su jenkins
```

1.  通过键入`exit`切换回根用户。

1.  接下来，我们将安装 SSH 服务器。按顺序执行以下命令：

```
 apt-get update
 apt-get install openssh-server
 mkdir /var/run/sshd
```

1.  接下来，使用以下命令安装 Git：

```
 apt-get install git
```

1.  使用以下命令安装 Java JDK：

```
 apt-get install openjdk-8-jdk
```

1.  使用以下命令安装 Maven：

```
 apt-get install maven
```

1.  接下来，键入`exit`退出容器。

1.  我们需要保存（`commit`）我们对 Docker 容器所做的所有更改。

1.  通过列出所有未活动容器，获取我们最近工作的容器的`CONTAINER ID`，如下图所示：

```
 sudo docker ps -a
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/574a41b9-0acc-41e4-b8d2-815bdb493a0a.png)

未活动容器列表

1.  注意`CONTAINER ID`，并执行`commit`命令，以提交我们对容器所做的更改，如下所示：

```
 sudo docker commit <CONTAINER ID> <new name for the container>
```

1.  如下图所示，我们将容器命名为`maven-build-slave-0.1`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/74b68bd5-87e1-42ee-b84a-2b004a2a1197.png)

Docker commit 命令

1.  一旦您提交了更改，将创建一个新的 Docker 镜像。

1.  执行以下 Docker 命令列出镜像：

```
 sudo docker images
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1f4bfdbd-03f3-4e18-856d-46d24a2b123c.png)

列出 Docker 镜像

1.  您可以看到我们的新 Docker 镜像，名称为`maven-build-slave-0.1`。现在，我们将配置我们的 Jenkins 服务器以使用 Docker 镜像来创建 Jenkins 从节点（构建代理）。

# 在 Jenkins 中添加 Docker 容器凭据

按照给定的步骤在 Jenkins 中添加凭据，以允许其与 Docker 通信：

1.  从 Jenkins 仪表板导航到凭据 | 系统 | 全局凭据（无限制）。

1.  点击左侧菜单上的**添加凭据**链接以创建新凭据（请参阅下图）。

1.  选择`用户名与密码`作为**类型**。

1.  将范围字段保留为其默认值。

1.  在 Username 字段下为你的 Docker 镜像添加一个用户名（按照我们的示例，是 `jenkins`）。

1.  在 Password 字段下，添加密码。

1.  在 ID 字段下添加一个 ID，并在描述字段下添加一些描述。

1.  完成后，点击确定按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/798bfc0c-bb19-487e-b92d-161c409f9539.png)

在 Jenkins 中创建凭据

# 更新 Jenkins 中的 Docker 设置

按照给定步骤更新 Jenkins 中的 Docker 设置：

1.  从 Jenkins 仪表板上，点击 Manage Jenkins | Configure System。

1.  滚动到底部找到 Cloud 部分（见下图）。

1.  在 Cloud 部分，点击添加 Docker 模板按钮，然后选择 Docker 模板。

1.  你将会看到许多设置需要配置。然而，为了保持这个演示简单，让我们专注于重要的设置：

    1.  在 Docker Image 字段下，输入我们之前创建的 Docker 镜像的名称。在我们的案例中，它是 `maven-build-slave-0.1`。

    1.  在 Labels 字段下，添加一个标签。Jenkins 流水线将使用此标签识别 Docker 容器。添加一个 `docker` 标签。

    1.  启动方法应该是 Docker SSH 计算机启动器。

    1.  在 **Credentials** 字段下，选择我们创建的用于访问 Docker 容器的凭据。

    1.  确保 Pull 策略选项设置为 Never pull。

    1.  将其余选项保留为默认值。

    1.  完成后，点击应用然后保存：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ebebf3fa-3f71-40b1-a538-c2ee9dddfd4b.png)

配置 Docker 插件设置

1.  现在你的 Jenkins 服务器已经设置好了，可以使用 Docker 随需创建 Jenkins 从节点。

# 摘要

在本章中，我们学习了如何在独立的 Windows 和 Linux 机器（物理/虚拟机）上添加和配置 Jenkins 从节点，使用了两种广泛使用的方法：通过 SSH 启动 Jenkins 从节点和通过 Java Web Start 启动 Jenkins 从节点。我们还学习了如何安装和配置 Jenkins 的 Docker 插件，该插件允许我们为 CI 创建按需的 Docker 容器（Jenkins 从节点）。

在下一章中，我们将学习如何使用 Jenkins 实现持续集成，并且我们将利用 Jenkins Docker 容器（Jenkins 从节点）来执行我们的 CI。


# 第六章：安装 SonarQube 和 Artifactory

在本章中，我们将学习 SonarQube，这是一个流行的开源工具，用于静态代码分析。我们还将学习 Artifactory，这是另一个流行的开源工具，用于版本控制二进制文件。在本章中，您将学习以下主题：

+   安装独立的 SonarQube 服务器

+   在 SonarQube 内创建项目

+   为 SonarQube 安装构建破坏插件

+   创建质量门和质量配置文件

+   在 Jenkins 中安装和配置 SonarQube 插件

+   安装独立的 Artifactory 服务器

+   在 Artifactory 中创建存储库

+   在 Jenkins 中安装和配置 Artifactory 插件

# 安装和配置 SonarQube

除了连续集成代码外，CI 流水线现在还包括执行连续检查的任务 —— 以连续的方式检查代码的质量。

连续检查涉及检查和避免质量低劣的代码。诸如 SonarQube 的工具帮助我们实现这一点。每次代码提交时，都会对代码进行代码分析。

此分析基于代码分析工具定义的一些规则。如果代码通过了错误阈值，它被允许进入其生命周期的下一步。但是，如果它超过了错误阈值，它就会被丢弃。

有些组织更喜欢在开发人员尝试提交代码时立即检查代码质量。如果分析结果良好，则允许提交代码，否则取消提交并要求开发人员重新处理代码。

SonarQube 是一个代码质量管理工具，允许团队管理、跟踪和改善其源代码的质量。它是一个基于 Web 的应用程序，包含可配置的规则、警报和阈值。它涵盖了七种代码质量参数，包括架构和设计、重复、单元测试、复杂度、潜在错误、编码规则和注释。

SonarQube 是一个开源工具，通过插件支持几乎所有流行的编程语言。SonarQube 还可以与 CI 工具（如 Jenkins）集成，以执行持续检查，我们很快就会看到。

那么，首先让我们学习如何安装 SonarQube。在接下来的部分中，我们将学习如何在 Ubuntu 16.04 上安装 SonarQube。

# 安装 Java

按照以下步骤安装 Java：

1.  更新软件包索引：

```
sudo apt-get update
```

1.  接下来，安装 Java。以下命令将安装 JRE：

```
sudo apt-get install default-jre
```

1.  要设置 `JAVA_HOME` 环境变量，首先获取 Java 安装位置。通过执行以下命令执行此操作：

```
update-java-alternatives –l
```

1.  您应该会得到类似的输出：

```
java-1.8.0-openjdk-amd64 1081 /usr/lib/jvm/java-1.8.0-openjdk-amd64
```

1.  上述输出中的路径是 `JAVA_HOME` 的位置。复制它。

1.  打开 `/etc/environment` 文件进行编辑：

```
sudo nano /etc/environment
```

1.  将以下行添加到 `/etc/environment` 文件中，如下所示：

```
JAVA_HOME="/usr/lib/jvm/java-1.8.0-openjdk-amd64"
```

1.  输入 *Ctrl* + *X* 并选择 *Y* 以保存并关闭文件。

1.  接下来，使用以下命令重新加载文件：

```
 sudo source /etc/environment
```

# 下载 SonarQube 包

以下步骤将帮助您下载 SonarQube 包：

1.  通过访问[`www.sonarqube.org/downloads/`](https://www.sonarqube.org/downloads/)下载最新版本的 SonarQube 安装包。

建议您始终安装最新的 LTS* 版本 SonarQube。

1.  移动至 `/tmp` 文件夹：

```
cd /tmp
```

1.  使用 `wget` 下载 SonarQube ZIP 包，如下所示的命令。在这里，我下载 SonarQube 版本 5.6.7（LTS*）：

```
wget https://sonarsource.bintray.com/Distribution/sonarqube/
sonarqube-5.6.7.zip
```

1.  接下来，在 `/opt` 目录下解压 SonarQube ZIP 包，使用以下命令：

```
unzip sonarqube-5.6.7.zip -d /opt/
```

要使用 `unzip` 命令，请确保您的 Ubuntu 机器上安装了压缩工具。要安装 ZIP 工具，请执行以下命令：

`**sudo apt-get install zip**`

您也可以在另一台机器上下载 SonarQube ZIP 包，然后使用 WinSCP 将其移动到您的 SonarQube 服务器上。

1.  移动到已解压的文件夹并列出其内容：

```
cd /opt/sonarqube-5.6.7/ 
ls -lrt
```

`bin/`文件夹包含了所有安装和启动 SonarQube 的脚本，而 `logs/`文件夹包含了 SonarQube 的日志。

# 运行 SonarQube 应用程序

按照以下步骤启动 SonarQube 服务器：

1.  移动至 `/opt/sonarqube-5.6.6/bin/linux-x86-64/`。在我们当前的示例中，我们在 64 位 Linux 操作系统上启动 SonarQube：

```
cd /opt/sonarqube-5.6.6/bin/linux-x86-64/
```

1.  运行 `sonar.sh` 脚本以启动 SonarQube，如下所示的命令：

```
./sonar.sh start
```

1.  您应该会看到类似的输出：

```
Starting SonarQube... Started SonarQube.
```

1.  要访问 SonarQube，请在您喜爱的网络浏览器中使用以下链接：`http://localhost:9000/` 或 `http://<IP-Address>:9000`。

目前在 SonarQube 中没有配置用户帐户。但是，默认情况下有一个用户名为`admin`、密码为`admin`的管理员帐户。

确保您至少有 4GB 的内存来运行 64 位版本的 SonarQube。

# 重置默认凭据并生成令牌

按照以下步骤重置凭据并生成一个令牌：

1.  在您喜欢的浏览器中打开 SonarQube 链接并切换到管理员用户。

1.  从 SonarQube 仪表板上，点击 Administrator | My Account | Security（选项卡）。

1.  在结果页面下，执行以下操作来更改密码部分：

    1.  在 旧密码 字段下添加您的旧密码（`admin`）。

    1.  在 新密码 字段下添加一个新密码。

    1.  在 确认密码 字段中重新输入新密码。

    1.  完成后，点击更改密码按钮。

1.  在同一页的令牌部分下，有一个选项来生成一个令牌。Jenkins 可以使用此令牌访问 SonarQube。执行以下步骤生成一个新令牌：

    1.  在令牌部分下，通过点击生成按钮在 生成令牌 字段下为您的新令牌添加一个名称。

    1.  新的令牌将会生成，如下截图所示。

1.  1.  复制并保存此令牌，因为我们稍后会用到它：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d5b34192-d78e-4fa6-9402-c744e8bc6bac.png)

在 SonarQube 中创建一个令牌

# 在 SonarQube 中创建项目

在接下来的部分中，我们将在 SonarQube 中创建一个项目。该项目将用于显示静态代码分析：

1.  从 SonarQube 仪表板，点击管理| 项目（选项卡）| 管理。

1.  在结果页面上，点击“创建项目”按钮。

1.  在结果窗口中，填写相应的详细信息，如下面的步骤所示：

    1.  在“名称”字段下添加一个名称。

    1.  在“键”字段下添加一个键。

    1.  点击“创建”按钮创建项目：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/df4e7d76-06d5-4d93-b709-ac3b166cd0bd.png)

在 SonarQube 中创建一个项目

1.  你可以在项目管理页面上看到你新创建的项目，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/f10bbd70-475c-4265-bce1-8faa6f2a5e83.png)

SonarQube 中新创建的项目

# 为 SonarQube 安装构建破坏插件

构建破坏插件适用于 SonarQube。它是专门为 SonarQube 设计的插件，而不是 Jenkins 插件。此插件允许 CI 系统（Jenkins）在质量门限条件不满足时强制失败 Jenkins 构建。要安装构建破坏插件，请执行以下步骤：

1.  在下载插件之前，先参考兼容性表。这将帮助我们下载正确的插件版本。兼容性表可在[`github.com/SonarQubeCommunity/sonar-build-breaker`](https://github.com/SonarQubeCommunity/sonar-build-breaker)上找到。

1.  从[`github.com/SonarQubeCommunity/sonar-build-breaker/releases`](https://github.com/SonarQubeCommunity/sonar-build-breaker/releases)下载构建破坏插件。

1.  移动到`/tmp`目录并下载构建破坏插件，使用以下命令：

```
cd /tmp

wget https://github.com/SonarQubeCommunity/
sonar-build-breaker/releases/download/2.2/
sonar-build-breaker-plugin-2.2.jar
```

1.  将下载的`.jar`文件移动到位置`opt/sonarqube-5.6.7/extensions/plugins/`：

```
cp sonar-build-breaker-plugin-2.2.jar \
/opt/sonarqube-5.6.7/extensions/plugins/
```

1.  使用以下命令重新启动 SonarQube：

```
cd /opt/sonarqube-5.6.7/bin/linux-x86-64

sudo ./sonar.sh restart
```

1.  你应该看到类似的输出：

```
Stopping SonarQube... Waiting for SonarQube to exit... Stopped SonarQube. Starting SonarQube... Started SonarQube.
```

1.  成功重新启动后，转到 SonarQube 仪表板，并以管理员身份登录。

1.  点击菜单栏上的管理链接。

1.  在管理页面上，您将在“类别”侧边栏下看到“构建破坏器”选项，如下图所示；不需要操作：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0c2b47ca-93ec-4bbf-9f43-2f5f0780f35f.png)

在 SonarQube 中的构建破坏插件设置

1.  构建破坏插件已成功安装。

# 创建质量门限

为了使构建破坏插件正常工作，我们需要创建一个*质量门限*；它只是一条带有一些条件的规则。当 Jenkins 流水线运行时，它将执行*质量配置文件*和质量门限。如果质量门限检查成功通过，则 Jenkins 流水线继续运行，但如果失败，则 Jenkins 流水线中止。尽管如此，分析仍然会发生。

按照以下步骤在 SonarQube 中创建一个质量门限：

1.  从 SonarQube 仪表板，点击菜单栏上的“质量门限”链接。

1.  在结果页面上，点击左上角的“创建”按钮。

1.  您将看到一个弹出窗口，如下面的屏幕截图所示。在名称字段下添加您的质量门名称，并点击创建按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/377644cd-07c3-4848-affc-31adfd284e89.png)

创建一个新的质量门

1.  您将在质量门页面上看到您的新质量门，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6b3b4f0a-47a2-47ea-b51b-0efc1e5c3373.png)

新质量门

1.  现在让我们通过从添加条件菜单中选择一个来为我们的质量门添加一个条件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d990542b-515b-4d37-84ae-aea4e6f663b5.png)

条件菜单

1.  下面的屏幕截图显示了一个名为主要问题的条件。如果大于`1`但小于`50`，则是警告，如果大于`50`，则是错误，如下面的屏幕截图所示。这只是一个示例；您可以配置任意数量的条件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c6cb40f3-a870-4e92-9953-f753e9fb2611.png)

配置质量门

1.  接下来，让我们确保我们之前在 SonarQube 中创建的示例项目使用我们新创建的质量门。为此，请从 SonarQube 仪表板点击管理 | 项目（选项卡）| 管理。

1.  在结果页面上，您将看到我们之前在 SonarQube 中创建的示例项目。点击它。

1.  在结果页面上，点击管理（选项卡）| 质量门。

1.  在质量门部分下，您将看到一个选项，可以从 SonarQube 中的可用质量门列表中选择质量门。选择我们最近创建的一个并点击更新按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a554e7c0-38c9-447e-9efb-2e577b520d39.png)

将质量门关联到项目

# 更新默认质量配置

在下一节中，我们将修改 Java（Sonar way）的默认质量配置，我们打算用于我们的静态代码分析。请按照以下步骤操作：

1.  从 SonarQube 仪表板，点击菜单栏中的质量配置链接。在结果页面上，您将看到所有存在于 SonarQube 上的质量配置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e9449540-e547-4202-bcc1-f7f3ad4922e4.png)

SonarQube 中的质量配置列表

1.  从上一个屏幕截图中，您可以看到 Java 的默认质量配置：Sonar way 包含 254 个活动规则。让我们尝试添加更多规则。

1.  点击激活更多按钮。

1.  在结果页面上，您将看到一些内容，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d12868b9-ea7c-43c4-aceb-bfcd2864b2f1.png)

未激活规则列表

1.  这是您可以向质量配置添加和删除规则的地方。让我们激活所有 Java 的未激活规则。

1.  要做到这一点，从页面右上角，点击批量更改 | 在 Sonar way 中激活，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7ae29d7e-75a0-42e8-bf47-459b8cb9c0c1.png)

批量激活规则

1.  您将看到一个弹出窗口询问您确认更改。点击应用按钮并继续。

1.  接下来，从菜单栏中点击“质量配置文件”链接。 在结果页面上，点击 Java 的 **Sonar way** 质量配置文件，现在您应该看到比以前更多的规则。

在 SonarQube 上可见的规则列表和默认质量配置文件取决于安装的插件。 要获取所需语言的规则，请安装相应的 SonarQube 插件。

# 在 Jenkins 中安装 SonarQube 插件

按照以下步骤为 Jenkins 安装 SonarQube 插件：

1.  从 Jenkins 仪表板中，点击“管理 Jenkins | 管理插件 | 可用（选项卡）”。 您将进入 Jenkins 管理插件页面。

1.  在“过滤器”字段中输入`SonarQube`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a07538d6-68a3-4249-aec2-44e4e19f5b35.png)

安装 SonarQube 插件

1.  从列表中选择“Jenkins 的 SonarQube 扫描仪”，然后点击“无需重新启动安装”按钮。

1.  如有需要，请重新启动 Jenkins。

# 在 Jenkins 中配置 SonarQube 插件

现在我们已经安装了 SonarQube 插件，让我们来配置它：

1.  从 Jenkins 仪表板中，点击“管理 Jenkins | 配置系统”。

1.  一旦进入“配置系统”页面，请向下滚动到 SonarQube 服务器部分。

1.  在 SonarQube 服务器部分，点击“添加 SonarQube”按钮。 您将看到要配置的设置，如下面的截图所示。 让我们逐一了解它们。

1.  在“名称”字段中为您的 SonarQube 服务器命名。

1.  在“服务器 URL”字段下输入 SonarQube 服务器的 URL。

1.  在“默认部署者凭据”下添加 Artifactory 凭据。

1.  在“服务器身份验证令牌”字段下输入我们在 SonarQube 中创建的令牌。

1.  点击“测试连接”按钮以测试 Jenkins 与 Artifactory 的连接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/264deaab-f537-40b7-9a3f-fb4106b72280.png)

配置 SonarQube 插件

1.  完成后，点击页面底部的“保存”按钮保存设置。

# 安装和配置 Artifactory

持续集成导致频繁的构建和打包。 因此，需要一种机制来存储所有这些二进制代码（构建、包、第三方插件等），这种机制类似于版本控制系统。

由于像 Git、TFS 和 SVN 这样的版本控制系统存储的是代码而不是二进制文件，我们需要一个二进制存储库工具。 一个与 Jenkins 紧密集成的二进制存储库工具（如 Artifactory 或 Nexus）提供了以下优势：

+   跟踪构建（谁触发？ 构建了什么代码？）

+   依赖项

+   部署历史

下图描述了二进制存储库工具（如 Artifactory）与 Jenkins 如何一起工作以存储构建产物。 在接下来的话题中，我们将学习如何通过创建一个 Jenkins 作业将代码上传到 Artifactory 来实现这一点：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/feadc99b-1d20-434f-9521-e0b083eeab26.png)

Jenkins 流水线将构建产物推送到 Artifactory

在当前书籍中，我们将处理 Artifactory 来存储我们的构建。 Artifactory 是一个用于版本控制二进制文件的工具。 这些二进制文件可以是任何内容，从构建代码、软件包、可执行文件、Maven 插件等等。

在接下来的部分中，我们将在 Ubuntu 16.04 上设置 Artifactory。

# 安装 Java

按照以下步骤安装 Java：

1.  更新软件包索引：

```
sudo apt-get update
```

1.  接下来，安装 Java。以下命令将安装 JRE：

```
sudo apt-get install default-jre
```

1.  要设置 `JAVA_HOME` 环境变量，首先获取 Java 安装位置。 通过执行以下命令执行此操作：

```
update-java-alternatives –l
```

1.  您应该得到类似的输出：

```
java-1.8.0-openjdk-amd64 1081 /usr/lib/jvm/java-1.8.0-openjdk-amd64
```

1.  在前面的输出中的路径是 `JAVA_HOME` 的位置。复制它。

1.  打开 `/etc/environment` 文件进行编辑：

```
sudo nano /etc/environment
```

1.  在 `/etc/environment` 文件中添加以下行，如下所示：

```
JAVA_HOME="/usr/lib/jvm/java-1.8.0-openjdk-amd64"
```

1.  输入 *Ctrl* + *X* 并选择 *Y* 保存并关闭文件。

1.  接下来，使用以下命令重新加载文件：

```
 sudo source /etc/environment
```

# 下载 Artifactory 包

按照以下步骤下载 Artifactory 包：

1.  从 [`www.jfrog.com/open-source/`](https://www.jfrog.com/open-source/) 或 [`bintray.com/jfrog/artifactory/jfrog-artifactory-oss-zip`](https://bintray.com/jfrog/artifactory/jfrog-artifactory-oss-zip) 下载 Artifactory 的最新版本（开源）。

1.  要下载 Artifactory Pro，请访问 [`bintray.com/jfrog/artifactory-pro/`](https://bintray.com/jfrog/artifactory-pro/) 或 [`bintray.com/jfrog/artifactory-pro/jfrog-artifactory-pro-zip`](https://bintray.com/jfrog/artifactory-pro/jfrog-artifactory-pro-zip)。

建议您始终安装 Artifactory 的最新 LTS 版本。

在下一章中，我们将使用 Artifactory Pro 演示代码推广，使用即将到来的章节中的属性。

参考 [`www.jfrog.com/confluence/display/RTF/Artifactory+Pro#ArtifactoryPro-ActivatingArtifactoryPro`](https://www.jfrog.com/confluence/display/RTF/Artifactory+Pro#ArtifactoryPro-ActivatingArtifactoryPro) 了解激活 Artifactory Pro 的过程。

1.  移动到 `/tmp` 文件夹：

```
cd /tmp
```

1.  使用 `wget` 下载 Artifactory Pro ZIP 包，如下代码所示。这里，我正在下载 Artifactory 版本 5.5.2（LTS*）：

```
wget https://jfrog.bintray.com/artifactory-pro/org/artifactory/pro/jfrog-artifactory-pro/5.5.2/jfrog-artifactory-pro-5.5.2.zip
```

您可以从不同的机器（从浏览器）下载 Artifactory ZIP 包，然后使用 WinSCP 将其移动到即将成为 Artifactory 服务器的位置。

1.  接下来，在 `/opt` 目录中解压 SonarQube ZIP 包，如下所示：

```
sudo unzip jfrog-artifactory-pro-5.5.2.zip -d /opt/
```

或者，如果下载的 ZIP 包有奇怪的名字：

```
sudo unzip \
download_file\?file_path\=jfrog-artifactory-pro-5.5.2.zip \
–d /opt/
```

要使用 `unzip` 命令，请确保已在您的 Ubuntu 机器上安装了压缩工具。 要安装 ZIP 工具，请执行以下命令：

`**sudo apt-get install zip**`

1.  移动到提取的文件夹并列出其内容：

```
cd /opt/artifactory-pro-5.5.2/ 
ls -lrt
```

`bin/` 文件夹包含所有安装和启动 Artifactory 的脚本，`logs/` 文件夹包含 Artifactory 日志。

# 运行 Artifactory 应用程序

按照给定的步骤启动 Artifactory 服务器：

1.  进入 `/opt/artifactory-pro-5.5.2/bin/` 目录并运行 `installService.sh` 脚本：

```
sudo ./installService.sh
```

1.  您应该看到类似的输出：

```
Installing artifactory as a Unix service that will run as user artifactory Installing artifactory with home /opt/artifactory-pro-5.5.2
Creating user artifactory...creating... DONE

Checking configuration link and files in /etc/opt/jfrog/artifactory...
Moving configuration dir /opt/artifactory-pro-5.5.2/etc /opt/artifactory-pro-5.5.2/etc.original...creating the link and updating dir... DONE
Creating environment file /etc/opt/jfrog/artifactory/default...creating... DONE
** INFO: Please edit the files in /etc/opt/jfrog/artifactory to set the correct environment
Especially /etc/opt/jfrog/artifactory/default that defines ARTIFACTORY_HOME, JAVA_HOME and JAVA_OPTIONS
Initializing artifactory.service service with systemctl... DONE

Setting file permissions... DONE

************ SUCCESS ****************
Installation of Artifactory completed

Please check /etc/opt/jfrog/artifactory, /opt/artifactory-pro-5.5.2/tomcat and /opt/artifactory-pro-5.5.2 folders

You can activate artifactory with:
> systemctl start artifactory.service
```

1.  启动 Artifactory 服务，使用以下任何命令之一：

```
sudo service artifactory start
```

或者：

```
sudo /etc/init.d/artifactory start
```

或者：

```
sudo systemctl start artifactory
```

1.  您可以通过执行以下任何命令来检查 Artifactory 的安装：

```
service artifactory check
```

或者：

```
/etc/init.d/artifactory check 
```

或者：

```
sudo ./artifactoryctl check
```

1.  通过导航至 `http://<服务器 IP 地址>:8081/` 访问 Artifactory 仪表板。

目前在 Artifactory 中未配置任何用户帐户。但是，默认情况下存在一个 admin 帐户，用户名为 `admin`，密码为 `password`。

确保您至少有 4 GB 的内存来运行 Artifactory 的 64 位版本。

# 重置默认凭据并生成 API 密钥

按照给定步骤重置 Artifactory 凭据：

1.  使用以下链接访问 Artifactory 仪表板：`http://<服务器 IP 地址>:8081/`。

1.  使用 admin 的初始默认凭据登录。

1.  从 Artifactory 仪表板，单击 Welcome, admin | Edit Profile。

1.  在当前密码字段中输入您当前的密码，然后点击解锁按钮。

1.  在生成的页面上，在个人设置下，添加您的电子邮件 ID。

1.  在 Change Password 部分下，添加一个新密码以重置 admin 用户的默认凭据。

1.  接下来，在 Authentication Settings 部分下，单击生成密钥（齿轮图标）以生成新的 API 密钥。

1.  通过单击复制按钮复制生成的 API 密钥（参见下图）。

1.  以后可能需要此 API 密钥进行身份验证：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0636b012-51d8-4008-8a0b-03ccc76fd7f3.png)

Artifactory API 密钥

1.  完成后，单击保存按钮。

# 在 Artifactory 中创建仓库

在接下来的部分中，我们将在 Artifactory 中创建一个通用仓库。该仓库将用于存储构建产物：

1.  从 Artifactory 仪表板，在左侧菜单中，单击 Admin | Repositories | Local，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b114abf2-e612-4867-a627-d8a28eb7a930.png)

在 Artifactory 中创建一个本地仓库

1.  生成的页面将显示当前可用的所有本地仓库，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/cd5132ff-23dc-413c-8a2c-7022506f3884.png)

所有本地仓库的列表

1.  在右上角单击 New 按钮创建一个新的本地仓库（参见下图）。

1.  将出现一个弹出窗口，列出各种类型的仓库供选择，如下图所示。选择 Generic 类型（参见下图）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/55f13735-d54a-4cfe-8108-ba77f31f6928.png)

选择各种类型仓库的选项

1.  在 Repository Key 字段下添加一个值，为您的仓库命名，如下图所示。将其余设置保留为默认值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/80196f7a-711c-4f57-a07b-0744e800a211.png)

命名我们的新本地仓库

1.  完成后，单击保存 & 完成按钮。

1.  现在我们有了新的本地仓库，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0c63f480-8313-4043-9833-6d7d2c327934.png)

我们新创建的本地仓库

# 在 Jenkins 中添加 Artifactory 凭据

按照给定步骤在 Jenkins 中创建与 Artifactory 通信的凭据：

1.  从 Jenkins 仪表板中，点击“凭据 | 系统 | 全局凭据（无限制）”。

1.  在左侧菜单中点击“添加凭据”链接以创建一个新凭据（见下图）。

1.  选择类型为用户名和密码。

1.  将范围字段保留为其默认值。

1.  在用户名字段下添加 Artifactory 用户名。

1.  在密码字段下，添加密码。

1.  在 ID 字段下添加一个 ID，在描述字段下添加一个描述。

1.  完成后，点击“确定”按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d5107130-d5ae-4ef0-a630-1f593f84b85a.png)

在 Jenkins 中添加 Artifactory 凭据

# 在 Jenkins 中安装 Artifactory 插件

按照给定步骤安装 Jenkins 的 Artifactory 插件：

1.  从 Jenkins 仪表板中，点击“管理 Jenkins | 管理插件 | 可用（选项卡）”。你将被带到 Jenkins 管理插件页面。

1.  在过滤字段中输入`Artifactory`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ae9aade4-de56-41cb-af18-7bf9a541a195.png)

安装 Artifactory 插件

1.  从列表中选择 Artifactory 插件，然后点击“无需重新启动”按钮进行安装。

1.  如有必要，重新启动 Jenkins。

# 配置 Artifactory 插件

现在我们已经安装了 Artifactory 插件，让我们来配置它：

1.  从 Jenkins 仪表板中，点击“管理 Jenkins | 配置系统”。

1.  进入“配置系统”页面后，一直向下滚动到“Artifactory”部分。

1.  在 Artifactory 部分，点击“添加”按钮。你将看到以下设置以配置，如下图所示。让我们一一来看看它们。

1.  使用服务器 ID 字段给你的 Artifactory 服务器命名。

1.  在 URL 字段下输入 Artifactory 服务器 URL。

1.  在“默认部署者凭据”下添加 Artifactory 凭据，如下图所示。

1.  点击“测试连接”按钮测试 Jenkins 与 Artifactory 的连接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/bbf8604f-29dd-4ff9-a997-7f9655a14d34.png)

配置 Artifactory 插件

1.  完成后，点击页面底部的“保存”按钮以保存设置。

# 摘要

在本章中，我们学习了如何安装和配置 SonarQube 和 Artifactory。在今天的世界中，静态代码分析形成了 CI 流水线的重要组成部分（尽管不是必需的）。同样，Artifactory 是一个流行的工具，用于存储 CI 流水线生成的所有构建工件。一旦 CI 流水线完成，Artifactory 就成为了焦点。所有构建的工件都从 Artifactory 部署到各种测试环境中，并且我们通过 Artifactory 执行代码推进。

我们将在下一章中更多地了解这些工具，该章是关于使用 Jenkins 实现持续集成。


# 第七章：使用 Jenkins 进行持续集成

我们将从涵盖以下方面的**持续集成**（**CI**）设计开始：

+   一个分支策略

+   一份 CI 工具清单

+   一个 Jenkins 流水线结构

CI 设计将作为一个蓝图，指导读者回答 CI 的实施如何、为什么以及在哪里的问题。设计将涵盖实施端到端 CI 流水线所涉及的所有必要步骤。

本章讨论的 CI 设计应被视为实施 CI 的模板，而不是最终的模型。分支策略和所使用的工具都可以修改和替换以适应目的。

# Jenkins CI 设计

几乎每个组织在甚至开始探索 CI 和 DevOps 工具之前都会创建一个。在本节中，我们将介绍一个非常通用的 CI 设计。

持续集成不仅包括 Jenkins 或任何其他类似的 CI 工具，它还涉及到代码版本控制方式、分支策略等方面。

不同的组织可能采用不同类型的策略来实现 CI，因为这完全取决于项目的需求和类型。

# 分支策略

拥有分支策略总是很好的。分支有助于组织您的代码。这是将您的工作代码与正在开发的代码隔离开来的一种方式。在我们的 CI 设计中，我们将从三种类型的分支开始：

+   主分支

+   集成分支

+   功能分支

这个分支策略是 GitFlow 工作流分支模型的简化版本。

# 主分支

也可以称之为**生产分支**。它保存了已交付的代码的工作副本。该分支上的代码已通过了所有测试。在这个分支上不进行开发。

# 集成分支

集成分支也被称为**主干分支**。这是所有功能集成、构建和测试集成问题的地方。同样，在这里不进行开发。然而，开发人员可以从集成分支创建功能分支并在其上工作。

# 功能分支

最后，我们有功能分支。这是实际开发发生的地方。我们可以从集成分支创建多个功能分支。

以下插图显示了我们将作为 CI 设计一部分使用的典型分支策略。我们将创建两个功能分支，它们从**集成/主干分支**延伸出来，而这个分支本身则从主分支延伸出来：

![图示](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a84c0478-d3f6-458c-8940-f72357ae5915.png)

分支策略

在功能分支或集成分支上的提交（合并会创建一个提交）将经过构建、静态代码分析和集成测试阶段。如果代码成功通过这些阶段，结果包将被上传到 Artifactory（二进制存储库）。

# CI 流水线

我们现在来到了 CI 设计的核心。我们将在 Jenkins 中创建一个多分支流水线，其中将包含以下阶段：

1.  在推送事件（CI 流水线的初始化）上从**版本控制系统**（**VCS**）获取代码。

1.  构建和单元测试代码，并在 Jenkins 上发布单元测试报告。

1.  对代码进行静态代码分析，并将结果上传到 SonarQube。如果错误数量超过质量门限的定义，则流水线失败。

1.  在 Jenkins 上执行集成测试并发布单元测试报告。

1.  将构建的工件与一些有意义的属性一起上传到 Artifactory。

前一 CI 流水线的目的是自动化持续构建、测试（单元测试和集成测试）、进行静态代码分析以及上传构建的工件到二进制存储库的过程。每个步骤的失败/成功都有报告。让我们详细讨论这些流水线及其组成部分。

# CI 的工具集

我们正在实现 CI 的示例项目是一个简单的 Maven 项目。在这一章中，我们将看到 Jenkins 与许多其他工具密切合作。以下表格包含了我们将要看到的一切所涉及的工具和技术的列表：

| **技术** | **特点** |
| --- | --- |
| Java | 用于编码的主要编程语言 |
| Maven | 构建工具 |
| JUnit | 单元测试和集成测试工具 |
| Jenkins | 持续集成工具 |
| GitHub | 版本控制系统 |
| SonarQube | 静态代码分析工具 |
| Artifactory | 二进制存储库管理器 |

# 创建 CI 流水线

在本节中，我们将学习如何创建上一节中讨论的 CI 流水线。我们将执行以下步骤：

+   我们将在 GitHub 上创建一个源代码存储库

+   我们将创建一个 Jenkinsfile 来描述我们构建、单元测试、执行静态代码分析、集成测试和发布构建工件到 Artifactory 的方式

+   我们将利用 Docker 生成构建代理来运行我们的 CI 流水线

+   我们将在 Jenkins 中创建一个多分支流水线

非常重要的是，您已经配置了来自第三章的 *Jenkins 从 GitHub 配置 Webhook* 部分。

# 在 GitHub 上创建一个新的存储库

让我们在 GitHub 上创建一个新的存储库。确保您的机器上安装了 Git，以执行以下步骤：

1.  登录到您的 GitHub 帐户。

1.  在本章中，我们将使用来自 [`github.com/nikhilpathania/hello-world-greeting.git`](https://github.com/nikhilpathania/hello-world-greeting.git) 的源代码作为示例。

1.  尝试从上一个链接中提到的存储库中分叉。要做到这一点，只需从您的互联网浏览器访问存储库，然后点击 **Fork** 按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/64b5022d-1083-416e-b2ba-5392fdc1da63.png)

分叉一个 GitHub 项目

1.  完成后，仓库的副本将会出现在您的 GitHub 账户下。

# 使用 SonarQube 用于 Maven 的扫描器。

理想情况下，我们需要 SonarQube 扫描器对项目进行静态代码分析。但是，我们将改为使用 Maven 的 SonarQube 扫描器实用程序，因为我们在当前章节中使用的示例源代码是一个 Maven 项目。

为此，在您的 `.pom` 文件中添加以下代码：

```
<properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    <sonar.language>java</sonar.language>
</properties>
```

如果您已经 fork 了以下仓库，那么您不需要执行上一步：

[`github.com/nikhilpathania/hello-world-greeting.git`](https://github.com/nikhilpathania/hello-world-greeting.git)。

# 为 CI 编写 Jenkinsfile。

在接下来的章节中，我们将学习如何为我们的持续集成编写流水线代码。

# 生成一个 Docker 容器 - 构建代理。

首先，让我们创建流水线代码来创建一个 Docker 容器（Jenkins 从机），这将作为我们的构建代理。

如果你还记得，在*添加 Jenkins 从机 - Docker 容器*章节中来自第五章的 *分布式构建*，我们学习了如何创建一个用于创建 Docker 容器（Jenkins 从机）的 Docker 镜像(`maven-build-slave-0.1`)。我们将在此处使用相同的 Docker 镜像来生成 Jenkins 从机代理用于我们的 CI 流水线。

在我们的 Jenkinsfile 中，为了生成一个 Docker 容器（Jenkins 从机），我们需要编写一个代码块，标签为 `docker`：

```
node('docker') {
}
```

`docker` 是 `maven-build-slave-0.1` Docker 模板的标签。

我们希望在`docker`节点上执行以下任务：

+   执行构建。

+   执行单元测试并发布单元测试报告。

+   执行静态代码分析并将结果上传到 SonarQube。

+   执行集成测试并发布集成测试报告。

+   将产物发布到 Artifactory。

所有前面的任务都是我们 CI 流水线的各个阶段。让我们为每一个编写流水线代码。

# 从 VCS 中下载最新的源代码。

我们希望我们的 Jenkins 流水线下载推送到 GitHub 仓库主分支的最新更改：

```
scm checkout
```

将上一步包装在一个名为 `轮询` 的阶段中：

```
stage('Poll') {
    scm checkout
}
```

# 执行构建和单元测试的流水线代码。

我们在当前章节中使用的示例项目是一个 Maven 项目。因此，用于构建的流水线代码是一个简单的 shell 脚本，运行 `mvn clean` 命令：

```
sh 'mvn clean verify -DskipITs=true';
junit '**/target/surefire-reports/TEST-*.xml'
archive 'target/*.jar'
```

其中 `-DskipITs=true` 是跳过集成测试并仅执行构建和单元测试的选项。

命令 `junit '**/target/surefire-reports/TEST-*.xml'` 让 Jenkins 能够在 Jenkins 流水线页面上发布 JUnit 单元测试报告。`**/target/surefire-reports/TEST-*.xml` 是生成单元测试报告的目录位置。

您的 Maven `.pom` 文件应该包含`maven-surefire-plugin`和`maven-failsafe-plugin`以使上一个命令工作。

您还需要 Jenkins JUnit 插件（默认安装）。

将上一步包装在一个名为 `构建 & 单元测试` 的阶段中：

```
stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
}
```

# 执行静态代码分析的流水线代码

执行静态代码分析的流水线代码是一个简单的 shell 脚本，将运行 Maven 命令，如下所示的命令块。这是通过 Maven 的 SonarQube 扫描器实用程序实现的。记住我们在 *使用 SonarQube scanner for Maven* 部分看到的配置：

```
sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
-Dsonar.projectKey=example-project -Dsonar.projectVersion=$BUILD_NUMBER';
```

`-Dsonar.projectName=example-project` 选项是传递 SonarQube 项目名称的选项。通过这种方式，我们所有的结果都将显示在我们在上一章中创建的 `projectName=example-project` 下。

类似地，`-Dsonar.projectKey=example-project` 选项允许 Maven 的 SonarQube 扫描器确认与 SonarQube 的 `projectKey=example-project`。

`-Dsonar.projectVersion=$BUILD_NUMBER` 选项允许我们将 Jenkins 构建号与我们执行和上传到 SonarQube 的每个分析关联起来。`$BUILD_NUMBER` 是 Jenkins 的构建号环境变量。

将前一步骤包装在名为 `Static Code Analysis` 的阶段中：

```
stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project -Dsonar.projectVersion=$BUILD_NUMBER';}
```

# 执行集成测试的流水线代码

执行集成测试的流水线代码是一个 shell 脚本，将运行 Maven 命令，如下所示的命令块：

```
sh 'mvn clean verify -Dsurefire.skip=true';
junit '**/target/failsafe-reports/TEST-*.xml'
archive 'target/*.jar'
```

其中 `-Dsurefire.skip=true` 是跳过单元测试仅执行集成测试的选项。

`junit '**/target/failsafe-reports/TEST-*.xml'` 命令使 Jenkins 能够在 Jenkins 流水线页面上发布 JUnit 单元测试报告。`**/target/failsafe-reports/TEST-*.xml` 是生成集成测试报告的目录位置。

将前一步骤包装在名为 `Integration Test` 的阶段中：

```
stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
}
```

要使上述命令生效，你的 Maven `.pom` 文件应包含 `maven-surefire-plugin` 和 `maven-failsafe-plugin`。

您还需要 Jenkins JUnit 插件（默认安装）。

# 执行将构建工件发布到 Artifactory 的流水线代码

要将构建工件上传到 Artifactory，我们将使用 *File Specs*。下面是 File Specs 代码的示例：

```
"files": [
    {
      "pattern": "[Mandatory]",
      "target": "[Mandatory]",
      "props": "[Optional]",
      "recursive": "[Optional, Default: 'true']",
      "flat" : "[Optional, Default: 'true']",
      "regexp": "[Optional, Default: 'false']"
    }
  ]
```

以下表格说明了前述代码的参数：

| **参数** | **条件** | **描述** |
| --- | --- | --- |
| `pattern` | `[必填]` | 指定应上传到 Artifactory 的本地文件系统路径。您可以通过使用通配符或正则表达式来指定多个工件，正则表达式由 `regexp` 属性指定。如果使用 `regexp`，则需要使用反斜杠 `\` 对表达式中使用的任何保留字符（例如 `.`, `?` 等）进行转义。自 Jenkins Artifactory 插件版本 2.9.0 和 TeamCity Artifactory 插件版本 2.3.1 起，模式格式已简化，并对包括 Windows 在内的所有操作系统使用相同的文件分隔符 `/`。 |
| `target` | `[必填]` | 以以下格式指定 Artifactory 中的目标路径：`[repository_name]/[repository_path]`。如果模式以斜杠结尾，例如，`repo-name/a/b/`，那么`b`被视为 Artifactory 中的一个文件夹，并且文件将上传到其中。在`repo-name/a/b`的情况下，上传的文件将在 Artifactory 中重命名为`b`。为了灵活地指定上传路径，您可以包含形式为`{1}, {2}, {3}...`的占位符，它们被对应的括号中的源路径中的令牌所替换。有关更多详细信息，请参考 *使用占位符* 文章（[`www.jfrog.com/confluence/display/RTF/Using+File+Specs#UsingFileSpecs-UsingPlaceholders`](https://www.jfrog.com/confluence/display/RTF/Using+File+Specs#UsingFileSpecs-UsingPlaceholders))**。** |
| `props` | `[可选]` | 以分号(`;`)分隔的`key=value`对的列表，作为附加到上传属性的属性。如果任何键可以接受多个值，则每个值用逗号(`,`)分隔。例如，`key1=value1;key2=value21,value22;key3=value3`。 |
| `flat` | `[默认: true]` | 如果为`true`，构件将上传到指定的精确目标路径，并且源文件系统中的层次结构将被忽略。如果为`false`，构件将上传到目标路径，同时保留其文件系统层次结构。 |
| `recursive` | `[默认: true]` | 如果为`true`，则还会从源目录的子目录中收集构建产物进行上传。如果为`false`，则仅上传源目录中明确定义的构建产物。 |
| `regexp` | `[默认: false]` | 如果为`true`，命令将按照正则表达式解释描述要上传的构件的本地文件系统路径的模式属性。如果为`false`，命令将将模式属性解释为通配符表达式。 |

下面是我们在流水线中将使用的文件规范代码：

```
def server = Artifactory.server 'Default Artifactory Server'
def uploadSpec = """{
  "files": [
    {
       "pattern": "target/hello-0.0.1.war",
       "target": "example-project/${BUILD_NUMBER}/",
       "props": "Integration-Tested=Yes;Performance-Tested=No"
    }
  ]
}"""
server.upload(uploadSpec)
```

下表列出了上述代码中的参数：

| **参数** | **描述** |
| --- | --- |
| `def server = Artifactory.server 'Default Artifactory Server'` | 这行代码告诉 Jenkins 要使用 Jenkins 中配置的现有 Artifactory 服务器。在我们的例子中，它是默认的 Artifactory 服务器。 |
| `Default Artifactory Server` | 这是 Jenkins 内配置的 Artifactory 服务器的名称。 |
| `"pattern": "target/hello-0.0.1.war",` | 这行代码会查找目录`target`中名为`hello-0.0.1.war`的文件，而`target`目录又位于 Jenkins 工作目录内部。 |
| `"target": "example-project/${BUILD_NUMBER}/",` | 这行代码尝试将构建产物上传到名为`helloworld-greeting-project`的 Artifactory 仓库。它将构建产物放置在 Artifactory 仓库内的一个以构建编号命名的文件夹内。 |
| `${BUILD_NUMBER}` | 构建编号的 Jenkins 环境变量。 |
| `"props": "Integration-Tested=Yes;Performance-Tested=No"` | 此代码创建两个键值对并将它们分配给上载的工件。这些键值对可用作 Artifactory 中代码推广的标签。 |

将上一步放入名为`Publish`的阶段中：

```
stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "helloworld-greeting-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
  server.upload(uploadSpec)
}
```

# 组合的 CI 管道代码

以下是将在 `docker` 节点内运行的完整组合代码：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "example-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
}
```

# 使用 Jenkinsfile

Jenkins 多分支管道使用 Jenkinsfile。在本节中，我们将学习如何创建 Jenkinsfile。我们将使用上一节中创建的示例管道脚本来创建我们的 Jenkinsfile。请按照以下步骤操作：

1.  登录到您的 GitHub 帐户。

1.  转到分叉的存储库*.*

1.  进入存储库页面后，点击**创建新文件**按钮以创建一个新的空文件，这将是我们的 Jenkinsfile，如下截图所示：![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a2506300-1e55-4349-8790-560d4add5e0b.png)

在 GitHub 上创建一个新文件

1.  在空文本框中填写`Jenkinsfile`作为您的新文件名称，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/79391053-cd83-43c1-b21e-9837c8009dfe.png)

在 GitHub 上为您的新文件命名

1.  在您的 Jenkinsfile 中添加以下代码：

```
node('docker') {
  stage('Poll') {
    checkout scm
  }
  stage('Build & Unit test'){
    sh 'mvn clean verify -DskipITs=true';
    junit '**/target/surefire-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage('Static Code Analysis'){
    sh 'mvn clean verify sonar:sonar
    -Dsonar.projectName=example-project
    -Dsonar.projectKey=example-project
    -Dsonar.projectVersion=$BUILD_NUMBER';
  }
  stage ('Integration Test'){
    sh 'mvn clean verify -Dsurefire.skip=true';
    junit '**/target/failsafe-reports/TEST-*.xml'
    archive 'target/*.jar'
  }
  stage ('Publish'){
    def server = Artifactory.server 'Default Artifactory Server'
    def uploadSpec = """{
      "files": [
        {
          "pattern": "target/hello-0.0.1.war",
          "target": "example-project/${BUILD_NUMBER}/",
          "props": "Integration-Tested=Yes;Performance-Tested=No"
        }
      ]
    }"""
    server.upload(uploadSpec)
  }
}
```

1.  完成后，通过添加有意义的评论提交新文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/08ecdfe7-3f64-4510-ab9a-5df45fa8ef3d.png)

在 GitHub 上提交您的新文件

# 在 Jenkins 中创建一个多分支管道

按以下步骤创建一个新的 Jenkins 管道作业：

1.  从 Jenkins 仪表板中，点击**新建项目**链接。

1.  在结果页面上，您将看到各种类型的 Jenkins 作业供您选择。

1.  选择**多分支** **管道**，并使用**输入项目名称**字段为您的管道命名。

1.  完成后，点击页面底部的确定按钮。

1.  滚动到 **分支来源** 部分。这是我们配置要使用的 GitHub 存储库的地方。

1.  点击**添加源**按钮，选择 GitHub。您将看到一个配置字段的列表。我们逐一看一下它们（见下面的截图）。

1.  对于凭据字段，选择我们在上一节中创建的 GitHub 帐户凭据（种类：带有用户名和密码的用户名）。

1.  在所有者字段下，指定您的 GitHub 组织或 GitHub 用户帐户的名称。

1.  一旦这样做，存储库字段将列出您 GitHub 帐户上的所有存储库。

1.  在存储库字段下选择 hello-world-greeting

1.  将其余选项保留为默认值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8352c68e-83e1-49b8-b609-bc8357372200.png)

配置多分支管道

1.  滚动到底部的构建配置部分。确保 Mode 字段设置为按 Jenkinsfile，Script Path 字段设置为`Jenkinsfile`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d1d71555-36df-4e7a-b61e-b3a1971774e6.png)

构建配置

1.  滚动到底部，点击**保存**按钮。

# 重新注册 Webhooks

现在，让我们重新注册所有 Jenkins 流水线的 Webhooks。为此，请执行以下步骤：

1.  在 Jenkins 仪表板上，点击**管理 Jenkins** | **配置系统**。

1.  在 Jenkins 配置页面上，向下滚动到 GitHub 部分。

1.  在 GitHub 部分下，点击**高级…**按钮（您将看到两个按钮；点击第二个）。

1.  这将显示更多字段和选项。点击**重新注册所有作业的 hooks**按钮。

1.  上一步将为您在 GitHub 帐户内相应存储库上的我们的多分支流水线创建新的 Webhooks。请按照以下步骤在 GitHub 上查看 Webhooks：

    1.  登录您的 GitHub 帐户。

    1.  转到您的 GitHub 存储库，在我们的案例中是 `hello-world-greeting`。

    1.  点击存储库设置按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ea7a448f-a912-4c05-b68a-776cf1297a73.png)

存储库设置

1.  1.  在存储库设置页面上，点击左侧菜单中的 Webhooks。您应该看到您的 Jenkins 服务器的 Webhooks，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e60e4c18-80ec-4069-bfc2-468181edf9db.png)

GitHub 存储库上的 Webhooks

# 正在进行的持续集成

按照给定的步骤操作：

1.  从 Jenkins 仪表板上，点击您的多分支流水线。

1.  在 Jenkins 多分支流水线页面上，从左侧菜单中，点击**立即扫描存储库**链接。这将扫描分支和 Jenkinsfiles，并立即为每个具有 Jenkinsfile 的分支运行一个流水线，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1191e0c3-04e5-4126-bb7c-a0bbdcaf3038.png)

主分支的流水线

1.  在多分支流水线页面上，从左侧菜单中，点击**扫描存储库日志**。您将看到类似以下输出。注意高亮代码。您可以看到主分支符合条件，因为它有一个 Jenkinsfile，并为其安排了一个流水线。由于测试分支上没有 Jenkinsfile，因此没有为其安排流水线：

```
Started by user nikhil pathania
[Sun Nov 05 22:37:19 UTC 2017] Starting branch indexing...
22:37:19 Connecting to https://api.github.com using nikhilpathania@hotmail.com/****** (credentials to access GitHub account)
22:37:20 Connecting to https://api.github.com using nikhilpathania@hotmail.com/****** (credentials to access GitHub account)
Examining nikhilpathania/hello-world-greeting Checking branches...  
  Getting remote branches...    
    Checking branch master  
  Getting remote pull requests... ‘Jenkinsfile’ found    
    Met criteria
Changes detected: master (c6837c19c3906b0f056a87b376ca9afdff1b4411 1e5834a140d572f4d6f9665caac94828b779e2cd)Scheduled build for branch: master  
1 branches were processed  
Checking pull-requests...  
0 pull requests were processed
Finished examining nikhilpathania/hello-world-greeting
[Sun Nov 05 22:37:21 UTC 2017] Finished branch indexing. Indexing took 2.1 sec
Finished: SUCCESS
```

您不需要总是扫描存储库。GitHub Webhooks 已配置为在您的 GitHub 存储库上推送或新建分支时自动触发流水线。请记住，相应分支上还应该存在 Jenkinsfile，以告诉 Jenkins 在发现存储库中的更改时应该执行什么操作。

1.  从您的 Jenkins 多分支流水线页面 (`<Jenkins URL>/job/<Jenkins Multi-branch pipeline name>/`)，点击相应的分支流水线（见下图）。

1.  在结果页面上，您将看到主分支流水线的阶段视图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e5ee84d3-e56a-4487-84a8-309386750bfb.png)

流水线阶段视图

1.  要查看单元测试和集成测试结果，请点击页面下方**最新测试结果**链接，该链接在与阶段视图相同的页面上，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d089eb2f-b0f8-4b0a-9f1a-43e4ee7c50a9.png)

1.  在结果页面上，你将看到关于单元测试和集成测试执行的详细报告，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/70400369-0ac2-40f1-a2c8-13c4a877c0e3.png)

使用 JUnit 插件的测试报告

1.  你可以点击各个测试以获取更多细节。

1.  在同一页面上，在左侧菜单中有一个名为“History”的链接，它提供了一段时间内与测试执行相关的指标数量的历史图表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/73efe47d-5080-4d6f-b25e-ab83f4c34c70.png)

测试执行历史

# 在 SonarQube 中查看静态代码分析

让我们来看看作为我们 CI 流水线一部分执行的静态代码分析报告。按照以下步骤操作：

1.  使用你喜欢的浏览器打开 SonarQube 链接。你应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e90f47c6-2fe9-4c33-b8d8-6ece576f93c1.png)

SonarQube 主页

1.  从 SonarQube 仪表板，使用菜单选项，点击登录链接。

1.  输入你的 SonarQube 凭据。

1.  在结果页面上，在“PROJECTS”小部件下，点击`example-project`项目。

1.  你将看到项目的静态代码分析概览（参见以下截图）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c9bd2038-3014-4e97-bb31-5aa3ba3c136c.png)

静态代码分析概述

1.  点击“Measures | Coverage”。在结果页面上，你将得到你的代码覆盖率和单元测试结果报告的良好概览，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/61a44fa4-2629-47e3-b837-e7f5a459699c.png)

代码覆盖率报告和单元测试报告

# 直接从 Jenkins 访问 SonarQube 分析

你可以直接从 CI 流水线中访问你的静态代码分析报告。按照以下步骤操作：

1.  从你的 Jenkins 仪表板，点击你的多分支流水线。接下来，点击相应的分支流水线（我们示例中的 master）。

1.  一旦你进入你的分支流水线，将鼠标悬停在“Static Code Analysis”阶段上，然后点击“Logs”。参见以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7db067ed-9cfb-4a21-b084-b395c2531571.png)

获取单个阶段日志

1.  在名为“Stage Logs（静态代码分析）”的弹出窗口中向下滚动到底部。你应该看到一个链接，指向 SonarQube 分析页面。参见以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b2b94a51-ea3b-4362-bf30-c555d7afe146.png)

从 Jenkins 日志中的 SonarQube 分析链接

1.  点击前述截图中显示的链接将直接带您到相应项目的 SonarQube 仪表板。

# 在 Artifactory 中查看构件

让我们看看上传到 Artifactory 后我们的构件是什么样子。按照以下步骤操作：

1.  从你喜爱的浏览器访问 Artifactory 链接。从 Artifactory 仪表板，使用登录链接登录。

1.  在左侧菜单中点击“Artifacts”选项卡。你应该在“Artifact Repository Browser”下看到你的仓库，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a2a4d822-acbf-428c-8060-37a9c4fc8f8d.png)

构件库浏览器

1.  展开仓库，您应该看到构建的构件和属性，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/069781a4-5c14-4f7d-bbf0-1e981654cee5.png)

CI 管道生成的构件

# 当质量门标准不符合时构建失败

在以下部分，我们将微调在上一章中创建的 SonarQube 质量门，使其应该使 Jenkins CI 管道失败。按照以下步骤模拟此场景：

1.  登录到您的 SonarQube 服务器，然后从菜单栏中点击质量门。

1.  从左侧菜单中，点击上一章中创建的质量门：`example-quality-gate`。

1.  现在，将 ERROR 字段的值从 `50` 改为 `3`。

1.  点击更新。最后，一切都应该如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d63005f3-1445-4c3b-b04f-37e58c628235.png)

更新 SonarQube 质量门

1.  接下来，在 GitHub 仓库上进行一些更改，以触发 Jenkins 中的 CI 管道。

1.  登录到 Jenkins，并导航到您的 Jenkins 多分支 CI 管道。您应该看到类似以下截图的内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/07e485d5-9c07-4e70-b65a-984f42a0e102.png)

失败的 CI 管道

1.  点击相应管道的失败阶段以获取其日志。在弹出窗口中，滚动到底部。您应该看到管道失败的原因，如下截图所示（箭头）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/276fc79d-0046-4daf-b2c4-5d08c7251ee3.png)

带有质量门状态的 SonarQube 日志

# 摘要

在这一章中，我们学习了如何创建一个多分支 CI 管道，通过推送事件触发，执行构建、静态代码分析、集成测试，并将成功测试的二进制构件上传到 Artifactory。最后，我们从开发者的角度看到了整个 CI 管道的运行。

书中讨论的 CI 设计可以修改以适应任何类型项目的需求；用户只需确定可以与 Jenkins 一起使用的正确工具和配置。

在下一章中，我们将扩展我们的 CI 管道，在 QA 领域做更多事情。
