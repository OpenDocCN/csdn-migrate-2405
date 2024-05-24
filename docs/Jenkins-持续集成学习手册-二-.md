# Jenkins 持续集成学习手册（二）

> 原文：[`zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17`](https://zh.annas-archive.org/md5/AC536FD629984AF68C1E5ED6CC796F17)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：新 Jenkins

在本章中，我们将看一些现在是 Jenkins 2.x 发行版的一部分的新功能。完成本章后，你将了解以下内容：

+   新的 Jenkins 设置向导

+   Jenkins 作为代码的流水线（Jenkins 流水线作业）

+   Jenkins 阶段视图

+   Jenkins 声明式流水线语法

+   Jenkins 多分支流水线

+   Jenkins 流水线语法工具（片段生成器）

+   Jenkins 凭据

+   Jenkinsfile

+   Jenkins Blue Ocean

+   在 Jenkins Blue Ocean 中创建流水线

# Jenkins 设置向导

当你首次访问 Jenkins 时，会显示“入门向导”。我们已经在前一章节中完成了这个练习；尽管如此，在接下来的部分，我们将更深入地了解其中一些重要部分。

# 先决条件

在我们开始之前，请确保你已准备好以下内容：

+   在前一章节讨论的任何平台上运行的 Jenkins 服务器（Docker、独立、云、虚拟机、Servlet 容器等）。

+   确保你的 Jenkins 服务器可以访问互联网。这是下载和安装插件所必需的。

# 解锁 Jenkins

当你首次访问 Jenkins 时，会要求你使用一个秘密的初始管理员密码解锁它。这个密码存储在 `initialAdminPassword` 文件中，该文件位于你的 `jenkins_home` 目录内。该文件及其完整路径显示在 Jenkins 页面上，如下截图所示：

+   **在 Windows 上**：你可以在 `C:\Program Files (x86)\Jenkins\secrets` 下找到该文件。如果你选择在其他位置安装 Jenkins，则在 `<Jenkins 安装目录>\secrets` 下寻找该文件。

+   **在 Linux 上**：你可以在 `/var/jenkins_home/secrets` 下找到该文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8a772edd-f225-4c4a-a8ff-729360dc0125.png)

解锁 Jenkins

从 `initialAdminPassword` 文件中获取密码，粘贴到管理员密码字段下，然后点击继续。

你始终可以使用 `intialAdminPassword` 文件中的密码和用户名 `admin` 登录 Jenkins。

# 自定义 Jenkins

接下来，会显示两个选项来安装 Jenkins 插件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b79b0471-a5d9-4cad-99b5-9ddc0506d4a2.png)

自定义 Jenkins

选择安装建议的插件将安装 Jenkins 的所有通用插件，如 Git、Pipeline as Code 等（由 Jenkins 社区建议）。

选择“选择要安装的插件”将允许你安装你选择的插件。

在接下来的部分，我们将继续选择安装插件的选项。当你这样做时，你应该看到以下截图中显示的屏幕。以下页面将列出一些最受欢迎的插件，尽管这不是 Jenkins 插件的完整列表。你会注意到建议的插件已默认选中（打勾）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a72f15ab-db44-47c7-ae53-2dd78dc4cede.png)

选择要安装的插件

您可以选择全部、无、或建议的插件。

选择完插件后，点击页面底部的安装按钮。以下截图显示了 Jenkins 插件安装：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a28850e3-50a0-4695-894d-4e72883a215c.png)

安装 Jenkins 插件

# 创建第一个管理员用户

安装插件后，您将被要求创建管理员用户帐户，如下截图所示。以下管理员帐户与设置向导开始时使用的临时管理员用户帐户不同（初始管理员帐户）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c006f56d-abf5-48ac-9211-d912bdb16c23.png)

创建您的第一个 Jenkins 用户

适当填写字段并点击“保存并完成”按钮。或者，您也可以选择忽略创建新的管理员用户，继续使用初始管理员用户，点击“继续作为管理员”。

接下来，在下一页上，您将看到一条消息，上面写着“Jenkins 准备就绪！您的 Jenkins 设置已完成。”点击“开始使用 Jenkins”以进入 Jenkins 仪表板。

# 新的 Jenkins 流水线任务

那些已经熟悉 Jenkins 的人都很清楚 freestyle Jenkins 任务。在 Jenkins 中创建流水线的经典方法是使用 *freestyle job*，其中每个 CI 阶段都使用 Jenkins 任务（freestyle）表示。

Jenkins freestyle 任务是基于 Web 的、GUI 驱动的配置。对 CI 流水线的任何修改都需要您登录 Jenkins 并重新配置每个 Jenkins freestyle 任务。

**Pipeline as Code** 的概念重新思考了我们创建 CI 流水线的方式。其思想是将整个 CI/CD 流水线编写为一段代码，提供一定程度的编程，并且可以进行版本控制。

以下是采用 Pipeline as Code 路线的一些优点：

+   它是可编程的

+   所有的 CI/CD 流水线配置都可以使用一个文件（Jenkinsfile）描述。

+   它可以进行版本控制，就像任何其他代码一样

+   它提供了使用声明性流水线语法定义流水线的选项，这是一种简单而优雅的编码流水线的方式

让我们来看看 Jenkins 流水线任务。我们将通过创建一个简单的 CI 流水线来看一下它并感受一下。

# 先决条件

在开始之前，请确保您准备好以下事项：

+   在前一章讨论的任何平台上运行 Jenkins 服务器（Docker、独立、云、虚拟机、Servlet 容器等）。

+   确保您的 Jenkins 服务器可以访问互联网。这是下载和安装插件所必需的。

+   确保您的 Jenkins 服务器已安装所有建议的插件。请参阅 *Customizing Jenkins* 部分。

# 创建 Jenkins 流水线任务

按照以下步骤创建 Jenkins 流水线任务：

1.  从 Jenkins 仪表板上，点击“新建项目”链接。

1.  在结果页面上，您将看到各种类型的 Jenkins 任务供您选择。

1.  选择管道，并使用`输入项目名称`字段为管道命名。

1.  完成后，点击页面底部的确定按钮。

1.  所有种类的 Jenkins 作业（自由形式、管道、多分支等）现在都带有一个特色标签，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a2812c0a-85ae-4326-a547-5628397a63e2.png)

Jenkins 作业中的新标签功能

1.  通过点击管道选项卡，快速导航到管道部分。

1.  以下截图描述了管道部分。让我们详细看看这个部分：

    +   `Definition`字段提供两个选择——管道脚本和来自 SCM 的管道脚本。如果选择管道脚本选项，那么在脚本字段内定义你的管道代码。但是，如果选择来自 SCM 的管道脚本选项（截图中未显示），那么你的管道脚本（Jenkinsfile）将自动从版本控制系统中提取（我们将在接下来的部分中探讨这个选项）。

    +   要获取关于任何选项的简短描述，可以点击问号图标。

    +   管道语法是一个实用工具，帮助你将 GUI 配置转换为代码。（我们将在接下来的部分中探讨这个选项）。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7f7ae013-b35a-4166-89cd-e29aaee573dd.png)

管道部分

1.  现在让我们在脚本字段内编写一些代码，看看管道是如何工作的。我们将尝试一些 Jenkins 提供的示例代码。

1.  为此，点击`尝试示例管道…`字段，并选择 GitHub + Maven 选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/30171bc2-e4c7-4125-b765-23a3a72c3c41.png)

选择一个示例管道脚本。

1.  这将在脚本字段中填充样本代码。

1.  代码如下所示。它以声明性管道语法形式呈现：

```
      node { 
        def mvnHome 
        stage('Preparation') { // for display purposes 
          // Get some code from a GitHub repository 
          git 'https://github.com/jglick/
          simple-maven-project-with-tests.git' 
          // Get the Maven tool. 
          // ** NOTE: This 'M3' Maven tool must be configured 
          // **       in the global configuration.            
          mvnHome = tool 'M3' 
        } 
        stage('Build') { 
          // Run the maven build 
          if (isUnix()) { 
            sh "'${mvnHome}/bin/mvn'
            -Dmaven.test.failure.ignore clean package" 
          } else { 
            bat(/"${mvnHome}\bin\mvn"
            -Dmaven.test.failure.ignore clean package/) 
          }  
        } 
        stage('Results') { 
          junit '**/target/surefire-reports/TEST-*.xml' 
          archive 'target/*.jar' 
        } 
      } 
```

1.  让我们快速浏览一下管道脚本（我们将在接下来的部分中详细探讨声明性管道语法）：

    +   `node{}` 是告诉 Jenkins 在 Jenkins 主服务器上运行整个管道脚本的主要容器。

    +   在`node{}`容器内部，还有三个更多的容器，如下所示：

```
                  stage('Preparation') {...} 
                  stage('Build') {...} 
                  stage('Results') {...}
```

1.  +   `准备`阶段将从 GitHub 存储库下载 Maven 源代码，并告诉 Jenkins 使用在全局配置中定义的 M3 Maven 工具（在运行管道之前我们需要这样做）。

    +   `构建`阶段将构建 Maven 项目。

    +   `结果`阶段将存档构建产物以及 JUnit 测试结果。

1.  点击页面底部的保存按钮保存对管道作业的更改。

# 全局工具配置页面

在运行管道之前，重要的是我们查看 Jenkins 中的全局工具配置页面。这是你配置工具的地方，你认为这些工具将在所有管道中全局使用：例如 Java、Maven、Git 等等。

假设您有多个构建代理（Jenkins 从代理），用于构建您的 Java 代码，并且您的构建流水线需要 Java JDK、Maven 和 Git。您只需在全局工具配置中配置这些工具，Jenkins 将在构建代理（Jenkins 从代理）上构建您的代码时自动调用它们。您无需在任何构建代理上安装这些工具。

让我们在全局工具配置中配置 Maven 工具，以使我们的流水线工作起来。按照以下步骤进行操作：

1.  要访问全局工具配置页面，请执行以下操作之一：

    1.  从 Jenkins 仪表板中，单击“管理 Jenkins” | “全局工具配置”。

    1.  或者，在浏览器中粘贴 URL `http://<您的 Jenkins 服务器的 IP 地址>:8080/configureTools/`。

1.  滚动到底部，找到 Maven 部分，然后单击“添加 Maven”按钮。然后，您将看到一系列选项，如下图所示。按照以下信息填写：

    1.  通过填写“名称”字段为您的 Maven 安装提供一个唯一的名称。（例如，我们的示例流水线中将其命名为 `M3`。）

    1.  默认情况下将显示“从 Apache 安装”。这将使 Jenkins 从 Apache 下载 Maven 应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e1607e85-369d-418e-94a3-399cd3dc06fc.png)

在“全局工具配置”中配置 Maven

1.  1.  使用“版本”字段选择最新的 Maven 版本；我选择使用 Maven 3.5.0，如前面的截图所示。

首先，选择不同的安装程序，通过单击“删除安装程序”按钮删除现有的安装程序。接下来，单击“添加安装程序”下拉菜单，并选择不同的安装程序。除了从 Apache 安装之外，其他选项还有“运行批处理命令”、“运行 Shell 命令”和“提取 *.zip/*.tar.gz”（在截图中未显示）。

1.  构建 Maven 项目还需要 Java 工具，但由于我们正在 Jenkins 主服务器上构建我们的代码（该服务器已安装了 Java JDK），因此我们现在可以跳过安装 Java 工具。

1.  配置 Maven 完成后，滚动到页面底部，然后单击“保存”按钮。

# Jenkins 流水线阶段视图

Jenkins *阶段视图* 是 2.x 版本的新功能。它仅适用于 Jenkins 流水线和 Jenkins 多分支流水线作业。

Jenkins 阶段视图可以实时可视化流水线各个阶段的进度。让我们通过运行示例流水线来看看它的运作情况：

1.  在 Jenkins 仪表板上，在“所有视图”选项卡下，您将看到您的流水线。

1.  单击构建触发图标来运行流水线，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/87a1a20e-2e55-474c-b8d1-9dfee98ea1a4.png)

在 Jenkins 仪表板上查看流水线

1.  要进入“阶段视图”，请单击您的流水线名称（同时也是指向流水线项目页面的链接）。

1.  或者，您可以将鼠标悬停在流水线名称上，以获取包含一系列操作项和链接的下拉菜单，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/116beaf2-76f9-4a74-8e84-3c65d644f288.png)

流水线菜单的视图

1.  舞台视图页面将看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/522cf1f9-2c0f-436f-b373-b74eb20e6517.png)

舞台视图

1.  要查看特定阶段的构建日志，请将鼠标悬停在色彩编码的状态框上，您应该看到查看日志的选项。单击它将打开一个小弹出窗口显示日志，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e6abe66d-9f7f-45ed-9499-cd539bfc45db.png)

Jenkins 单个阶段日志

1.  要查看完整的构建日志，请在左侧查找“构建历史”。构建历史选项卡将列出所有已运行的构建。右键单击所需的构建编号，然后单击“控制台输出”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7ec8e5c8-9f21-4e0f-bb5e-eb2e9e2b1f81.png)

访问控制台输出

# 声明性流水线语法

在先前的部分中，我们创建了一个 Jenkins 流水线，以查看和感受其各种组件。我们利用了遵循声明性语法的流水线脚本来定义我们的流水线。

声明性流水线语法是 Groovy 语法的更简化和结构化版本，后者由于其可编程性而更强大。在本节中，我们将更详细地了解声明性流水线语法。这很重要，因为在接下来的章节中，我们将使用相同的语法来定义我们的 CI 和 CD 流水线。

# 声明性流水线的基本结构

简而言之，声明性流水线是多个 `node` 块（节点）、`stage` 块（阶段）、指令和步骤的集合。一个 `node` 块可以有多个 `stage` 块，反之亦然。我们还可以并行运行多个阶段。让我们逐个详细了解各个部分。

# `node` 块

`node` 块定义了 Jenkins 代理，其中包括其组成部分（阶段块、指令和步骤）应运行在其中。`node` 块结构如下所示：

```
node ('<parameter>') {<constituents>} 
```

以下提供了有关`node` 块的更多信息：

+   **定义**：`stage`、指令或步骤应运行的节点

+   **组成部分**：多个 `stage` 块、指令或步骤

+   **必需**：是

+   **参数**：任意、标签

# 阶段块

`stage` 块是一组紧密相关的步骤和指令的集合，具有共同的目标。`stage` 块结构如下所示：

```
stage ('<parameter>') {<constituents>} 
```

以下提供了有关 `stage` 块的更多信息：

+   **定义**：一组步骤和指令

+   **组成部分**：多个 `node` 块、指令或步骤

+   **必需**：是

+   **参数**：阶段名称的字符串（必填）

# 指令

指令的主要目的是通过提供以下任何元素来协助 `node` 块、`stage` 块和步骤：环境、选项、参数、触发器、工具。

以下提供了有关 `stage` 块的更多信息：

+   **定义**：`stage` 应在其中运行的节点

+   **组成部分**：环境、选项、参数、触发器、工具

+   **必需**：不，但每个 CI/CD 流水线都有它

+   **参数**：无

# 步骤

步骤是构成声明式流水线的基本元素。步骤可以是批处理脚本、shell 脚本或任何其他可执行命令。步骤有各种用途，例如克隆存储库、构建代码、运行测试、将构件上传到存储库服务器、执行静态代码分析等。在接下来的部分中，我们将看到如何使用 Jenkins 管道语法工具生成步骤。

以下提供了关于`stage`块的更多信息：

+   **定义**: 它告诉 Jenkins 要做什么

+   **构成**: 命令、脚本等。这是流水线的基本块

+   **必需**：不，但每个 CI/CD 流水线都有它

+   **参数**：无

以下是我们之前使用的管道代码。`node`块、`stage`块、指令和步骤都使用注释（`//`）进行了突出显示。正如你所见，`node`块内有三个`stage`块。一个`node`块可以有多个`stage`块。除此之外，每个`stage`块都包含多个步骤，其中一个还包含一个指令：

```
// Node block
node ('master') {
  // Directive 1
  def mvnHome

  // Stage block 1
  stage('Preparation') {    // Step 1
    git 'https://github.com/jglick/simple-maven-project-with-tests.git'
    // Directive 2
    mvnHome = tool 'M3' 
   }

   // Stage block 2 
   stage('Build') {
     // Step 2 
     sh "'${mvnHome}/bin/mvn' clean install" 
   } 

   // Stage block 3
   stage('Results') {
     // Step 3 
     junit '**/target/surefire-reports/TEST-*.xml'
     // Step 4
     archive 'target/*.jar' 
   } 

} 
```

在上述代码中，请注意以下行：`node ('master') {`。这里，字符串`master`是一个参数（`label`），告诉 Jenkins 使用 Jenkins 主节点来运行`node`块的内容。

如果您将参数值选择为任意，则所有阶段节点及其各自的步骤和指令将在任一可用 Jenkins 从属代理上执行。

在接下来的章节中，我们将更多地了解声明式流水线，在那里我们将尝试使用它编写一个 CI/CD 流水线。

有关声明式流水线语法的更多信息，请参阅[`jenkins.io/doc/book/pipeline/syntax/#declarative-sections`](https://jenkins.io/doc/book/pipeline/syntax/#declarative-sections)。

要获取与声明式流水线兼容的所有可用步骤的列表，请参考[`jenkins.io/doc/pipeline/steps/`](https://jenkins.io/doc/pipeline/steps/)。

# Jenkins 管道语法工具

Jenkins 管道语法工具是创建管道代码的一种快速简便的方法。管道语法工具可在 Jenkins 管道任务内部使用；参见*在创建 Jenkins 管道任务部分的*屏幕截图：*管道部分*。

在本节中，我们将重新创建我们在上一节中创建的管道，但这次使用管道语法工具。

# 先决条件

在我们开始之前，请确保你准备好了以下事项：

+   在全局工具配置页面配置的 Maven 工具（参见*全局工具配置页面*部分）

+   安装 Pipeline Maven Integration Plugin

+   为构建 Maven 项目还需要 Java 工具，但由于我们在 Jenkins 主节点上构建我们的代码（该节点已经安装了 Java JDK），我们可以跳过安装 Java 工具

# 安装 Pipeline Maven Integration 插件

按照给定的步骤安装 Pipeline Maven Integration 插件。以下插件将允许我们在管道代码中使用 Maven 工具：

1.  从 Jenkins 仪表板中，单击“管理 Jenkins”|“管理插件”|“可用”选项卡。

1.  在“过滤器”字段中键入`Pipeline Maven Integration`以搜索相应的插件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e0dc9e79-b757-4d80-ba9a-a2dde9275ed9.png)

插件管理器页面

1.  单击复选框以选择相应的插件，然后单击“无需重启安装”按钮进行安装。

1.  单击“无需重启安装”按钮后，您将看到插件正在安装，如下截图所示。Jenkins 将首先检查网络连接，然后安装依赖项，最后安装插件。

1.  某些插件可能需要重启才能使用。要这样做，请检查选项“在安装完成且没有作业运行时重新启动 Jenkins”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e725c942-5e2a-467f-8021-e4a130881ba2.png)

插件安装中

# 使用管道语法实用程序创建 Jenkins 管道

按照以下步骤创建新的 Jenkins 管道作业：

1.  从 Jenkins 仪表板中，单击“新项目”链接。

1.  在生成的页面上，您将看到各种类型的 Jenkins 作业供选择。

1.  选择管道，并使用“输入项目名称”字段为管道命名。

1.  完成后，单击页面底部的“确定”按钮。

1.  我们将通过单击“管道”选项卡快速导航到管道部分。

1.  在“管道”选项卡下，单击名为“管道语法”的链接。这将打开一个新选项卡，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/74eda867-bec6-4849-989a-41596806e3f2.png)

管道语法页面

1.  我们将使用以下片段生成器为各种块和步骤创建管道代码。

1.  首先让我们生成一个`node`块的代码：

    1.  在管道语法页面上，在“步骤”部分下，选择`node`：使用“示例步骤”字段分配节点，如下所示。

    1.  在“标签”字段中添加字符串`master`。这样做告诉 Jenkins 使用 Jenkins 主节点作为执行我们管道的首选节点。

    1.  单击“生成管道脚本”按钮生成代码。

    1.  复制生成的代码并将其保存在文本编辑器中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/cc01527d-c048-4819-964c-d52ed9b33490.png)

生成`node`块的代码

1.  现在，让我们创建两个名为`Preparation`和`Build`的`stage`块：

    1.  在管道语法页面上，在“步骤”部分下，选择`stage`：使用“示例步骤”字段，如下所示。

    1.  在“阶段名称”字段中添加字符串`Preparation`。

    1.  单击“生成管道脚本”按钮生成代码。

    1.  复制生成的代码并将其粘贴到我们之前生成的`node`块中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/89be1a2d-475d-46e3-b6b9-f507b6756641.png)

为阶段块生成代码

1.  类似地，重复*步骤 9*以创建一个名为 `构建` 的 `stage` 块。 将生成的代码粘贴到 `准备`（`stage` 块）之后的 `node` 块中。

1.  到目前为止，我们的管道代码应该看起来像以下内容（不包括 `// some block` 行）：

```
      node('master') {

        stage('Preparation') {
        }

        stage('Build') {
        }

      }
```

1.  现在让我们创建一个步骤来从 GitHub 下载源代码：

    1.  在管道语法页面的步骤部分，在示例步骤字段下选择 git: 使用 Git 的步骤，如以下截图所示。

    1.  在 Repository URL 字段中，添加示例 GitHub 仓库的链接：`https://github.com/jglick/simple-maven-project-with-tests.git`。

    1.  其余选项保持不变。

    1.  点击生成管道脚本按钮生成代码。

    1.  复制生成的代码，并将其粘贴到我们之前生成的 `准备`（`stage` 块）中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/044110f3-342c-495a-bc73-239692bb3861.png)

为 Git 步骤生成代码

1.  接下来，让我们生成一个指令，告诉 Jenkins 使用我们在全局工具配置中配置的 M3 Maven 工具：

    1.  在管道语法页面的步骤部分，在示例步骤字段下选择 withMaven: 使用 Maven 环境 的步骤，如以下截图所示。

    1.  在 Maven 字段中，选择 `M3`，这是我们在全局工具配置中配置的 Maven 工具。

    1.  其余选项保持不变。

    1.  点击生成管道脚本按钮生成代码。

    1.  复制生成的代码，并将其粘贴到我们之前生成的 `构建`（`stage` 块）中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/e9fff868-cfb0-4208-87e6-cc922892cd65.png)

为 withMaven 指令生成代码

1.  最后，为我们的 Maven 构建命令生成一个管道代码：

    1.  在管道语法页面的步骤部分，在示例步骤字段下选择 sh: 使用 Shell 脚本 的步骤，如以下截图所示。 这是创建 Shell 脚本的步骤。

    1.  在 Shell 脚本字段中，键入 `mvn -Dmaven.test.failure.ignore clean package`，这是构建、测试和打包代码的 Maven 命令。 这将是我们的 Shell 脚本的内容。

    1.  点击生成管道脚本按钮生成代码。

    1.  复制生成的代码，并将其粘贴到我们之前生成的 `withMaven`（指令）中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/542c5aa3-1b45-4499-a082-36084c5439b1.png)

为 Maven 构建生成代码

1.  我们最终的管道脚本应该看起来像以下内容（不包括 `// some block` 行）：

```
      node('master') {

        stage('Preparation') {
          git 'https://github.com/jglick/
          simple-maven-project-with-tests.git'
        }

        stage('Build') {
          withMaven(maven: 'M3') {
            sh 'mvn -Dmaven.test.failure.ignore clean
            package'
          }
        }

      }
```

1.  现在切换到管道作业配置页面。

1.  滚动到管道部分，并将上述管道代码粘贴到脚本字段中。

1.  点击页面底部的保存按钮。

在接下来的章节中，当我们尝试使用声明性管道语法创建 CI/CD 管道时，我们将看到更多示例，利用管道语法工具。

# 多分支管道

在本节中，我们将了解 Jenkins 中的多分支管道作业。 这是 Jenkins 发布 2.x 版本中添加的新功能之一。

多分支管道允许你自动为源代码仓库上的每个分支创建一个管道。如下截图所示。多分支管道使用存储在版本控制仓库中与你的源代码一起的 **Jenkinsfile** 进行工作。**Jenkinsfile** 只是定义了你的 CI 管道的管道脚本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d2f51380-f683-4e9f-8807-0eaf756fcbd7.png)

为新分支自动生成管道

除此之外，多分支管道设计用于在 Git/GitHub 仓库的任何分支上有新的代码更改时触发构建。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d2fdbec6-baaa-4e51-b6f1-795ee8ff8af7.png)

使用多分支管道进行持续集成

# 先决条件

在我们开始之前，请确保你已准备好以下内容：

+   配置在全局工具配置页面中的 Maven 工具（参考：*全局工具配置页面*）。

+   安装 Pipeline Maven Integration 插件。

+   为了构建 Maven 项目还需要 Java 工具，但由于我们正在 Jenkins 主节点上构建我们的代码（它已经安装了 Java JDK），我们可以跳过安装 Java 工具。

+   安装 GitHub 插件（如果你在 Jenkins 设置向导中选择安装了推荐的插件，则已安装）。

+   确保你的 Jenkins URL 可以从互联网访问。如果你正在使用一个临时或者开发环境来进行这个练习，并且你的 Jenkins 服务器没有域名，那么你的 Jenkins 服务器可能无法从互联网访问。要使你的 Jenkins URL 在互联网上可访问，参考附录中的 *将你的本地服务器暴露在互联网上* 部分，*支持工具和安装指南*。

# 在 Jenkins 中添加 GitHub 凭据

为了使 Jenkins 与 GitHub 通信，我们需要在 Jenkins 中添加 GitHub 账户凭据。我们将使用 Jenkins 凭据插件来完成这个任务。如果你已经按照本章开始时讨论的 Jenkins 设置向导的步骤进行操作，你会在 Jenkins 仪表板上找到凭据功能（请参阅左侧菜单）。

按照给定的步骤将 GitHub 凭据添加到 Jenkins 中：

1.  从 Jenkins 仪表板，点击凭据 | 系统 | 全局凭据（无限制）。

1.  在全局凭据（无限制）页面上，从左侧菜单中点击添加凭据链接。

1.  你将看到一堆字段需要配置（参见下面的截图）：

    1.  在 Kind 字段中选择用户名与密码。

    1.  在 Scope 字段中选择 Global（Jenkins、节点、项目、所有子项目等）。

    1.  将你的 GitHub 用户名添加到用户名字段。

    1.  将你的 GitHub 密码添加到密码字段。

    1.  通过在 ID 字段中输入一个字符串给你的凭据添加一个唯一的 ID。

    1.  在描述字段中添加一些有意义的描述。

    1.  完成后点击保存按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ab96cc1d-13fe-418d-860d-318c863d1a6c.png)

在 Jenkins 中添加 GitHub 凭据

1.  这就是您如何在 Jenkins 中保存凭据。我们马上就会用到这些 GitHub 凭据。

# 在 Jenkins 中配置 GitHub 的 Webhooks

现在我们已经在 Jenkins 中保存了 GitHub 帐户凭据，让我们配置 Jenkins 以与 GitHub 进行通信。我们将通过在 Jenkins 配置中配置 GitHub 设置来实现这一点。

仔细遵循给定的步骤，在 Jenkins 中配置 GitHub 设置：

1.  从 Jenkins 仪表板上，点击“管理 Jenkins” | “配置系统”。

1.  在结果 Jenkins 配置页面上，向下滚动到 GitHub 部分。

1.  在 GitHub 部分下，点击“添加 GitHub 服务器”按钮，然后从可用的下拉列表中选择 GitHub 服务器。这样做会显示一系列选项供您配置。

1.  让我们逐一配置它们，如下所示：

    1.  通过向 Name 字段添加字符串来为您的 GitHub 服务器命名。

    1.  在 API URL 字段下，如果您使用的是公共 GitHub 帐户，请添加`https://api.github.com`（默认值）。否则，如果您使用的是 GitHub Enterprise，则指定其相应的 API 终端点。

    1.  确保已选中“管理钩子”选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/407bb3e5-3b11-4c33-8364-c5f27b796175.png)

配置 GitHub 服务器

1.  1.  点击高级按钮（你会看到两个按钮；点击第二个）。这样做会显示一些更多的字段来配置。

    1.  在“附加操作”字段下，点击“管理其他 GitHub 操作”，然后从可用列表中选择“将登录名和密码转换为令牌”（您只会看到一个选择）。

    1.  这将进一步揭示新的字段以进行配置。

    1.  选择“来自凭据”选项（默认情况下处于活动状态）。使用凭据字段，选择我们在上一节中创建的 GitHub 凭据（`ID: github_credentials`）。

    1.  接下来，点击“创建令牌凭据”按钮。这将在您的 GitHub 帐户上生成一个新的个人访问令牌：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/31cab72b-5fe6-4a14-9f59-f4d729a712ea.png)

将 GitHub 凭据转换为令牌

1.  1.  要查看您在 GitHub 上的个人访问令牌，请登录到您的 GitHub 帐户，然后导航到设置 | 开发人员设置 | 个人访问令牌：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8b88000f-8f24-4110-9184-e875520405de.png)

GitHub 上的个人访问令牌

1.  1.  完成后，点击 Jenkins 配置页面底部的保存按钮。

    1.  同时在 Jenkins 凭据中还将添加相应个人访问令牌的条目。要查看它，请导航到 Jenkins 仪表板 | 凭据 | 系统 | `api.github.com`，然后您应该会看到一条 Kind 为 secret text 的凭据条目。

1.  我们在 Jenkins 中的 GitHub 配置还没有完成。按照以下剩余步骤进行：

    1.  从 Jenkins 仪表板上，点击“管理 Jenkins” | “配置系统”。

    1.  向下滚动到 GitHub 部分。

    1.  使用凭据字段，选择新生成的凭据的密钥类型（Jenkins 中的个人访问令牌条目）。

    1.  现在，点击测试连接按钮来测试 Jenkins 和 GitHub 之间的连接。

    1.  完成后，在你的 Jenkins 配置页面底部点击保存按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/dc71186f-4385-417c-a19b-c75ca5c3ba4d.png)

测试 Jenkins 和 GitHub 之间的连接

1.  我们现在已经完成了在 Jenkins 中配置 GitHub 设置的步骤。

# 在 GitHub 上创建一个新仓库

在这个部分，我们将在 GitHub 上创建一个新的仓库。确保你已经在执行以下步骤的机器上安装了 Git（参考 附录 中的 *在 Windows/Linux 上安装 Git* 部分，*支持工具和安装指南*）。

按照以下步骤在 GitHub 上创建一个仓库：

1.  登录你的 GitHub 账户。

1.  为了保持简单，我们将重用仓库中的源代码 [`github.com/jglick/simple-maven-project-with-tests.git`](https://github.com/jglick/simple-maven-project-with-tests.git)。这是我们一直在使用的用于创建 Jenkins 管道的仓库。

1.  重新使用 GitHub 仓库的最简单方法是分叉它。要这样做，只需从你的互联网浏览器访问上述仓库，然后点击分叉按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/dcdbf242-72bd-4929-a677-3c9b47c1511f.png)

分叉一个 GitHub 项目

1.  完成后，你的 GitHub 账户上将会看到上述仓库的复制品。

# 使用 Jenkinsfile

Jenkins 多分支管道利用 Jenkinsfile。在接下来的部分中，我们将学习如何创建 Jenkinsfile。我们将重用我们在上一部分创建的示例管道脚本来创建我们的 Jenkinsfile。按照给定的步骤：

1.  登录你的 GitHub 账户。

1.  导航到分叉后的仓库 `simple-maven-project-with-tests`。

1.  进入仓库页面后，点击创建新文件按钮来创建一个新的空文件，这将成为我们的 Jenkinsfile，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/cf8502d2-a1d9-4b0e-8315-570ea32d2fcc.png)

在 GitHub 上创建一个新文件

1.  通过填写空文本框，命名你的新文件为 `Jenkinsfile`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/06937fdb-4d28-4e9c-85c3-bed014c2ade2.png)

在 GitHub 上命名你的新文件

1.  将以下代码添加到你的 `Jenkinsfile` 中：

```
      node ('master') { 
        checkout scm 
        stage('Build') { 
          withMaven(maven: 'M3') { 
            if (isUnix()) { 
              sh 'mvn -Dmaven.test.failure.ignore clean package' 
            }  
            else { 
              bat 'mvn -Dmaven.test.failure.ignore clean package' 
            } 
          } 
        }   
        stage('Results') { 
          junit '**/target/surefire-reports/TEST-*.xml' 
          archive 'target/*.jar' 
        } 
      } 
```

1.  完成后，通过添加有意义的评论来提交新文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7dd6182e-ff2a-4851-bd85-3fe1f7a95f5d.png)

在 GitHub 上提交你的新文件

# 在 Jenkins 中创建一个多分支管道

按照以下步骤创建一个新的 Jenkins 管道作业：

1.  从 Jenkins 仪表板中，点击新项目链接。

1.  在生成的页面上，你将看到各种类型的 Jenkins 作业供选择。

1.  选择多分支管道，并使用输入项目名称字段为你的管道命名。

1.  完成后，点击页面底部的 OK 按钮。

1.  滚动到分支源部分。这是我们配置要使用的 GitHub 仓库的地方。

1.  点击添加源按钮并选择 GitHub。你将被呈现一个配置字段列表。让我们一个接一个地看看它们（见下面的截图）：

    1.  对于凭证字段，选择我们在前一节创建的 GitHub 账户凭据（类型为用户名和密码）。

    1.  在所有者字段下，指定你的 GitHub 组织或 GitHub 用户账户的名称。

    1.  一旦你这样做了，仓库字段将列出你 GitHub 账户上的所有仓库。

    1.  在仓库字段下选择 `simple-maven-project-with-tests`。

    1.  将其余选项保留为默认值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/16eb4ab3-f25c-45ed-b5ef-1c31886e807c.png)

配置多分支流水线

1.  滚动到底部并点击保存按钮。

# 重新注册 Webhooks

在我们继续之前，让我们重新注册所有 Jenkins 流水线的 Webhooks：

1.  要这样做，请从 Jenkins 仪表盘上点击 管理 Jenkins | 配置系统。

1.  在 Jenkins 配置页面上，向下滚动到 GitHub 部分。

1.  在 GitHub 部分，点击高级…按钮（你会看到两个，点击第二个）。

1.  这将显示一些额外的字段和选项。点击重新注册所有作业的钩子按钮。

1.  前述操作将在你的 GitHub 账户内的相应仓库上为我们的多分支流水线创建新的 Webhooks。按以下步骤查看 GitHub 上的 Webhooks：

    1.  登录到你的 GitHub 账户。

    1.  转到你的 GitHub 仓库，我们这里是 `simple-maven-project-with-tests`。

    1.  点击仓库设置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5cc912af-7a37-47d9-bbac-4a0d8dcda61e.png)

仓库设置

1.  1.  在仓库设置页面，从左侧菜单中点击 Webhooks。你应该看到你的 Jenkins 服务器的 Webhooks，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/276529b2-d674-4ed9-a73f-68b62a1e3197.png)

GitHub 仓库上的 Webhooks

# Jenkins 多分支流水线运行中

按照给定的步骤：

1.  从 Jenkins 仪表盘上，点击你的多分支流水线。

1.  在你的 Jenkins 多分支流水线页面上，从左侧菜单中点击 扫描仓库现在 链接。这将扫描具有 Jenkinsfile 的分支的仓库，并将立即为每个具有 Jenkinsfile 的分支运行一个流水线，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/04880dcc-7390-4e9e-850a-b00ff65e51ee.png)

用于主分支的流水线

1.  在您的多分支流水线页面上，从左侧菜单中，点击"Scan Repository Log"。您将看到类似于以下所示的内容。注意高亮显示的代码。您可以看到`master`分支符合标准，因为它有一个 Jenkinsfile，为其安排了一个流水线。由于测试分支上没有 Jenkinsfile，因此没有为其安排流水线：

```
Started by user nikhil pathania 
[Mon Aug 14 22:00:57 UTC 2017] Starting branch indexing... 
22:00:58 Connecting to https://api.github.com using ******/****** (credentials to access GitHub account) 
22:00:58 Connecting to https://api.github.com using ******/****** (credentials to access GitHub account) 
Examining nikhilpathania/simple-maven-project-with-tests 

 Checking branches... 

 Getting remote branches... 

 Checking branch master 

 Getting remote pull requests... 
 'Jenkinsfile' found 
 Met criteria 
Scheduled build for branch: master 

 Checking branch testing 
 'Jenkinsfile' not found 
 Does not meet criteria 

 2 branches were processed 

  Checking pull-requests... 

  0 pull requests were processed 

Finished examining nikhilpathania/simple-maven-project-with-tests 

[Mon Aug 14 22:01:00 UTC 2017] Finished branch indexing. Indexing took 2.3 sec 
Finished: SUCCESS 
```

1.  您不需要始终扫描存储库。GitHub Webhooks 已配置为在 GitHub 存储库上进行推送或创建新分支时自动触发流水线。请记住，各个分支上也应该存在 Jenkinsfile，以告诉 Jenkins 在发现存储库变化时需要执行什么操作。

# 创建一个新的特性分支来测试多分支流水线

现在让我们从主分支创建一个特性分支，并查看 Jenkins 是否能够为其运行一个流水线：

1.  为此，请登录到您的 GitHub 帐户。

1.  转到您的 GitHub 仓库; 在我们的情况下是`simple-maven-project-with-tests`。

1.  点击"Branch: master"按钮，在空文本框中输入一个新分支的名称。接下来，点击"Create branch: feature"选项来创建一个名为 feature 的新分支，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ee2f6d60-778f-4fa8-b432-bcbea4c1d48f.png)

创建一个特性分支

1.  这应该会立即在 Jenkins 中触发一个用于我们的新特性分支的流水线：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5fe7c47e-611e-420e-9ce7-307594a00458.png)

新特性分支的流水线

# Jenkins 蓝色海洋

Jenkins Blue Ocean 是与 Jenkins 交互的全新方式。它更像是主要 Jenkins 应用程序的 UI 助手。以下是 Jenkins Blue Ocean 的一些特性：

+   改进的可视化效果

+   流水线编辑器

+   个性化

+   用于 Git 和 GitHub 的快速简易流水线设置向导

您使用经典 Jenkins 界面创建的流水线可以在新的 Jenkins 蓝色海洋中进行可视化，反之亦然。正如我之前所说，Jenkins 蓝色海洋是主要 Jenkins 应用程序的 UI 助手。

在接下来的部分中，我们将在 Blue Ocean 中可视化我们在上一部分中创建的 Jenkins 流水线。我们还将创建一个新的流水线，只是为了看看并感受一下新的 Jenkins Blue Ocean 界面。

# 安装 Jenkins 蓝色海洋插件

为了使用 Jenkins 蓝色海洋插件，我们需要为 Jenkins 安装 Blue Ocean 插件。按照以下步骤操作：

1.  从 Jenkins 仪表板，点击"Manage Jenkins | Manage Plugins"。

1.  在插件管理器页面上，点击"Available"选项卡。

1.  使用过滤选项，搜索`Blue Ocean`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/caac1ef5-8704-4f73-b1ff-78fe35e852a7.png)

安装 Jenkins 蓝色海洋插件

1.  从项目列表中选择 Blue Ocean 并点击"Install without restart"。你只需要 Blue Ocean 而不需要其他东西。

1.  Blue Ocean 的依赖列表很长，因此您将在安装插件/升级页面上看到许多与 Blue Ocean 插件一起安装的东西。

# 在 Blue Ocean 中查看您的常规 Jenkins 流水线。

在本节中，我们将尝试可视化我们在前几节中创建的现有 Jenkins 流水线：

1.  在 Jenkins 仪表板上，您现在应该看到左侧菜单上有一个名为“打开蓝色海洋”的新链接。

1.  单击“打开蓝色海洋”链接以转到 Jenkins Blue Ocean 仪表板。 您应该看到以下内容（请参阅以下屏幕截图）：

    1.  管理链接将带您进入“管理 Jenkins”页面。

    1.  Pipelines 链接将带您进入您当前看到的 Jenkins Blue Ocean 仪表板。

    1.  图标（方形内的箭头）将带您进入经典 Jenkins 仪表板。

    1.  新建流水线按钮将打开基于 Git 和 GitHub 的项目的流水线创建向导。

    1.  流水线列表（**e**高亮显示）：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1cb007db-8457-4c84-b1b4-b087b367e199.jpg)

Jenkins 蓝色海洋仪表板

1.  让我们来看看我们的多分支流水线。 从 Jenkins Blue Ocean 仪表板中点击您的多分支流水线。 这样做将打开相应的多分支流水线页面，如下所示：

    1.  按钮（**a**高亮显示）将带您进入流水线配置页面。

    1.  活动标签将列出所有当前和过去的流水线。

    1.  分支标签将为您显示每个分支的流水线的汇总视图。

    1.  Pull Requests 标签将列出分支上所有开放的拉取请求。

    1.  按钮（**e**高亮显示）用于重新运行流水线：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/90868ba9-9b9d-47ac-aadc-2823937899c6.png)

在 Blue Ocean 中的多分支流水线。

1.  现在让我们看看个别的构建页面。 要这样做，请从 Jenkins 流水线页面（请参阅前面的屏幕截图）中单击任何构建，然后您将进入相应流水线的构建页面，如下所示：

    1.  Changes 标签将列出触发构建的代码更改。

    1.  Artifacts 标签将列出构建生成的所有工件。

    1.  按钮（**c**高亮显示）将重新运行您的构建。

    1.  此部分（**d**高亮显示）显示有关您的构建的一些指标。

    1.  此阶段视图（**e**高亮显示）将列出所有顺序和并行阶段。

    1.  步骤结果部分将向您显示您选择的特定阶段的所有步骤（在下面的屏幕截图中，我选择了阶段“结果”）。

    1.  每个列出的步骤（**g**高亮显示）都可以展开并查看其日志：

![图片](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/858f6f25-7150-457a-a1ca-8c8718c4196c.png)

在 Blue Ocean 中的构建页面

这是您的 Jenkins 流水线在 Blue Ocean 中的简短概述（使用经典 Jenkins UI 创建的流水线）。 它几乎展示了所有内容。 但是，我鼓励读者继续探索。

# 在 Blue Ocean 中创建流水线。

在这一部分中，我们将看到如何从 Jenkins 蓝色海洋仪表板创建一个新的流水线。我们将查看 Blue Ocean 中的新流水线创建向导。在开始之前，请准备好以下事项：

+   Fork 以下存储库：[`github.com/nikhilpathania/hello-world-example.git`](https://github.com/nikhilpathania/hello-world-example.git) 到您的 GitHub 帐户中。我们将在接下来描述的示例中使用它

+   为 Jenkins 安装 JUnit 插件（[`plugins.jenkins.io/junit`](https://plugins.jenkins.io/junit)）

按照给定的步骤：

1.  从 Jenkins 蓝色海洋仪表板中，点击新的流水线按钮。Jenkins 将要求您在 Git 和 GitHub 之间进行选择。对于我们当前的练习，我们将选择 GitHub：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/be77336b-9115-4a4a-8d4e-17c57c49749a.png)

在 Git 和 GitHub 仓库之间进行选择

1.  接下来，Jenkins 将要求您为您的 GitHub 帐户提供 GitHub 访问令牌。点击这里创建一个访问密钥的链接以创建一个新的访问密钥：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5ff0eeed-f4d9-4898-bebd-70a21507e379.png)

GitHub 访问令牌字段

1.  在一个新的选项卡中，系统会要求您登录到您的 GitHub 帐户。

1.  登录后，您将直接进入 GitHub 设置页面以创建一个新的个人访问令牌。

1.  在令牌描述字段中键入一个简短的描述，以标识您的令牌。保留选择范围部分下的选项默认值：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/3549184c-d257-4359-b6ad-1f12a6dbc9f9.png)

创建一个 GitHub 个人访问令牌

1.  点击页面底部的生成新令牌按钮以生成一个新的个人访问令牌：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c6bd151e-aa70-4820-8434-b1e8f7c9c57c.png)

GitHub 个人访问令牌

1.  复制新创建的个人访问令牌并将其粘贴到您的 GitHub 访问令牌字段中，然后点击连接按钮（参见以下截图）。

1.  接下来，点击列出的组织：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/4c5b3274-88d7-49d9-8209-3c1bd9837584.png)

选择 GitHub 帐户

1.  您可以在新流水线和自动发现 Jenkinsfile 之间进行选择。在以下示例中，我们将选择新流水线选项：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/9fdce913-e10c-4b74-b977-22b2917eeae0.png)

在创建和发现流水线之间进行选择

1.  接下来，系统将要求您从 GitHub 帐户的可用存储库列表中选择一个存储库。如果列表中没有列出所需的存储库，您可以使用搜索选项来查找所需的存储库。在我们当前的示例中，我们将选择`hello-world-example`存储库：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/32090f0e-7c8f-420a-b026-58cb8c3ddaa3.png)

选择一个存储库

1.  Jenkins 接下来会要求你创建一个流水线。由于在相应的仓库中找不到 Jenkinsfile，请点击创建流水线按钮以创建一个 Jenkinsfile：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ff10b159-86ec-40df-be8d-b01061ce0111.png)

创建一个新的流水线

1.  创建流水线的页面如下所示。在左侧，你会看到流水线的可视化，右侧找到选择块、阶段和步骤的工具（类似于我们在上一部分看到的流水线语法工具）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ef7846e1-9049-4198-bf91-f15ef634bc9b.png)

Blue Ocean 流水线编辑器

1.  让我们首先选择一个代理来运行我们的流水线。从“流水线设置”中，使用代理字段，选择标签选项。然后在标签字段下键入 `master`，如下截图所示。通过这种方式，我们告诉 Jenkins 在 Jenkins 主服务器上运行我们的流水线：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/9e5f51aa-9c1d-4343-9939-41e2cf3f7d7d.png)

创建一个节点块

1.  接下来，让我们创建一个名为 `Build` 的阶段，用来构建我们的源代码。点击流水线可视化上的 + 按钮即可。

1.  你将被要求命名新的阶段。在“命名你的阶段”字段下输入 `Build`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/03f37030-2c3a-4982-985c-0fac38ccc1ad.png)

创建一个构建阶段

1.  接下来，我们将添加一个构建我们的 Maven 代码的步骤。点击+ 添加步骤按钮。 

1.  你将被要求从可用步骤列表中选择，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a53f8bfa-15a5-445d-9acf-0e7c3cb0ddb4.png)

步骤菜单

1.  我们的是一个 Maven 项目。因此，我们可能需要先设置 Maven 环境，告诉 Jenkins 可以使用哪个 Java 和 Maven 工具。

1.  为此，请使用搜索框搜索“提供 Maven 环境”（按名称查找步骤）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/85f46033-e09b-4615-9a27-aa2c8ff92dc7.png)

选择提供 Maven 环境步骤

并非所有的 Jenkins 插件都与 Jenkins Blue Ocean 兼容。目前这个列表还很小。但预计随着时间的推移会不断增长。

1.  点击“提供 Maven 环境”步骤时，会显示一个字段配置列表，如下截图所示。在 Maven 字段下键入 `M3`，其余选项保持不变：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/0bde4efe-b020-4f50-894d-d9f05a273a4a.png)

配置提供 Maven 环境步骤

1.  在配置页面底部，点击+ 添加步骤按钮以创建一个构建我们的 Maven 代码的新子步骤。

1.  如果你的 Jenkins 主服务器是 Linux 机器，从可用步骤列表中选择 Shell 脚本。如果是 Windows 机器，选择 Windows 批处理脚本。

1.  在 Shell 脚本/Windows 批处理脚本的文本框中键入以下代码：

```
        mvn clean install 
```

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/bc2cba34-769a-4d46-baa7-b0e761b702c4.png)

配置 shell 脚本子步骤

1.  点击返回箭头返回到上一个菜单。现在你应该在子步骤部分看到你的新步骤，即 Shell 脚本，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/45f426a5-bccc-4b67-9bef-dc4a9065305e.png)

Shell 脚本作为一个子步骤

1.  点击返回箭头返回到上一个菜单。

1.  接下来，让我们创建一个名为 Results 的阶段，在此阶段我们将存档我们构建的构件和 XML 结果报告。 要这样做，请点击可视化流水线上的+按钮。

1.  您将被要求为新阶段命名。 请在“命名您的阶段”字段下键入`Results`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b77a50b6-e9b1-4240-8282-6d810f915442.png)

创建一个结果阶段

1.  接下来，我们将在新阶段上添加一些步骤。 第一个将是发布我们的测试结果报告的步骤。 要这样做，请点击“+ 添加步骤”按钮。

1.  从可用步骤列表中选择发布 JUnit 测试结果报告。 您将看到一系列配置选项：

    1.  在“测试结果”字段下添加`**/target/surefire-reports/TEST-*.xml`。

    1.  将其余选项保持不变：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6121d63c-a160-4d77-a9a3-1aac84e4d4db.png)

配置发布 JUnit 测试结果报告步骤

1.  点击返回箭头以返回到上一个菜单。

1.  再次点击“+ 添加步骤”按钮以添加新步骤。

1.  从可用步骤列表中选择存档构件。 您将看到一系列配置选项：

    1.  在“构件”字段下添加`target/*.jar`。

    1.  将其余选项保持不变：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/00a94942-270b-439e-bc33-3fb2e087a827.png)

配置存档构件步骤

1.  点击返回箭头以返回到上一个菜单。

1.  最后，点击页面右上角的保存按钮以保存您的流水线配置。

1.  弹出窗口将要求您添加一些描述并选择提交流水线配置的分支。

1.  完成后，点击保存并运行按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/dbcf67c9-5078-48b2-a26a-d594178d7a85.png)

保存流水线

1.  这将立即在相应分支上运行流水线，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/706e7583-47b3-4db5-b944-425924ab3213.png)

主分支上的成功构建

1.  您会注意到在主分支下的存储库中创建了一个新文件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1e821bb2-57ef-4e99-be7f-4365c4dcdf91.png)

源代码中列出的 Jenkinsfile

1.  文件内容应为：

```
pipeline { 
  agent { 
    node { 
      label 'master' 
    } 

  } 
  stages { 
    stage('Build') { 
      steps { 
        withMaven(maven: 'M3') { 
          sh 'mvn clean install' 
        } 

      } 
    } 
    stage('Results') { 
      steps { 
        junit '**/target/surefire-reports/TEST-*.xml' 
        archiveArtifacts 'target/*.jar' 
      } 
    } 
  } 
}
```

# 摘要

在前一章中，我们几乎体验了 Jenkins 的所有新功能。 我们选择了适度的示例以保持我们的流水线简单。 然而，在接下来的章节中，我们将学习如何使用 Jenkins 的所有新功能创建一个完整的 CI/CD 流水线。

在下一章中，我们将探讨 Jenkins 中的一些管理任务。


# 第四章：配置 Jenkins

在本章中，我们将学习如何执行一些基本的 Jenkins 管理任务，如下所示：

+   更新/安装/卸载/降级 Jenkins 插件

+   手动安装 Jenkins 插件

+   执行 Jenkins 备份和恢复

+   在各个平台（Windows/Linux/servlet）上升级 Jenkins

+   升级运行在 Docker 容器中的 Jenkins

+   在 Jenkins 中创建和管理用户

+   在 Jenkins 中学习各种身份验证方法

+   在 Jenkins 中配置各种授权方法

Jenkins 配置项繁多。 安装的插件越多，需要配置的就越多。 在本章中，我们将仅涵盖 Jenkins 中的基本管理任务。 我们将在接下来的章节中更多地了解 Jenkins 配置，在那里我们将尝试添加更多插件到 Jenkins 以实现**持续集成**（**CI**）和**持续交付**（**CD**）。

# Jenkins 插件管理器

Jenkins 的大部分功能来自插件。 Jenkins 插件是安装后增强 Jenkins 功能的软件片段。 在 Jenkins 中安装的插件表现为 Jenkins 作业内的参数或可配置项，或者作为*声明性流水线语法*的步骤下的一部分。

以下截图显示了 Jenkins 系统配置。 这是配置 SonarQube 工具（一个静态代码分析工具）的设置。 只有安装了 SonarQube 的 Jenkins 插件后才能使用相应的配置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d3c961a3-4b8c-48a6-950b-d44df9021f26.png)

Jenkins 系统配置中的 SonarQube 设置

在 Jenkins 中有一个特殊的部分来管理插件。 在本节中，我们将学习如何使用 Jenkins 插件管理器管理插件：

1.  从 Jenkins 仪表板中单击**管理 Jenkins**。

1.  进入管理 Jenkins 页面后，单击**管理插件**。 您还可以使用`<Jenkins URL>/pluginManager`链接访问相同的 Jenkins 插件管理器页面。

1.  您将看到以下四个选项卡：更新、可用、已安装和高级。

# 更新 Jenkins 插件

**更新**选项卡列出了所有需要更新的插件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/30cbbc4e-258f-4614-90b7-86239c75ad5d.png)

更新 Jenkins 插件

要更新插件，请通过单击相应复选框选择它，然后单击**立即下载并在重启后安装**按钮。

要更新**更新**选项卡下列出的所有插件，请单击页面底部的**全部**。 这将选择所有插件。 然后，单击**立即下载并在重启后安装**按钮以安装更新。

在**更新**选项卡上，在页面底部，您会看到一个名为**立即检查**的按钮。 单击它以刷新在**更新**选项卡下显示的插件列表。 这将检查插件更新。

# 安装新的 Jenkins 插件

**可用**标签列出了所有可用于 Jenkins 的插件。已安装在你的 Jenkins 实例上的插件不会在这里列出。

下面的屏幕截图显示了 Jenkins 的可用插件列表：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a78bf775-0f8f-459c-8aa8-3cdc49ce6843.png)

插件根据其功能分组

要安装插件，请通过点击其相应复选框来选择它。然后，在页面底部点击**立即安装**按钮（立即安装插件）或者**立即下载并在重启后安装**按钮（名字已经很清楚了）。

就像**更新**标签一样，在这里你也会看到一个名为**立即检查**的按钮。点击它将刷新**可用**标签下的插件列表。

# 卸载或降级 Jenkins 插件

**已安装**标签列出了当前安装在你的 Jenkins 实例上的所有插件。如下面的屏幕截图所示，你可以看到卸载插件以及降级插件的选项。

如果你的 Jenkins 实例变得不稳定或 CI/CD 流水线在插件更新后没有良好表现，你可以选择降级插件：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/2418c781-8498-4498-b877-fa0743ad6873.png)

已安装的 Jenkins 插件列表

# 配置 Jenkins 的代理设置

在**高级**标签下，你将看到一个名为 HTTP 代理配置的部分。这是你配置代理设置以便 Jenkins 从互联网获取更新的地方：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5948748e-4024-4099-9db2-7be2cb9e4899.png)

HTTP 代理配置设置

如果你的 Jenkins 服务器没有在任何防火墙后面，并且可以直接访问互联网，那么请将这些字段留空。

当你尝试安装或升级 Jenkins 插件时，Jenkins 使用 HTTP 代理配置详细信息。它还使用这些信息来更新“更新”标签和“可用”标签中的 Jenkins 插件列表。

要测试你的代理设置，请按照以下步骤进行：

1.  在**HTTP 代理配置**部分，点击**高级...**按钮。

1.  在**测试 URL**字段中添加一个网址，并点击**验证代理**按钮。

1.  你应该看到一个消息：成功，如下面的屏幕截图所示。

1.  点击**提交**按钮保存设置：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8351e74a-5ba7-49a7-9fd2-9f856ee465af.png)

检查代理设置

# 手动安装 Jenkins 插件

在**高级**标签下，在**HTTP 代理配置**部分之后，你将看到另一个名为**上传插件**的部分。它提供了一个安装或升级 Jenkins 插件的功能。

当您的 Jenkins 实例无法访问互联网并且您需要一个新的插件或需要升级现有插件时，此功能非常有用。想象一下，您有一个运行在本地局域网内但无法访问互联网的 Jenkins 实例，或者我们可以说是 Jenkins 的在线插件仓库。在这种情况下，您将首先从在线 Jenkins 仓库下载所需的 Jenkins 插件，然后使用可移动介质将其传输到 Jenkins 主服务器，并最终使用**上传插件**部分来安装所需的 Jenkins 插件。

让我们尝试按照给定步骤手动安装插件：

1.  从可以访问互联网的计算机上，打开网站：[`updates.jenkins-ci.org/download/plugins/`](https://updates.jenkins-ci.org/download/plugins/)。

1.  上述网站包含了所有可用于 Jenkins 的插件列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/a2beda43-f4d7-4cf8-a7ca-a04e664ea5d7.png)

Jenkins 插件索引

1.  在以下示例中，我们将安装一个名为`logstash`的插件。

1.  在索引页面上，搜索`logstash`并点击它。

1.  您将看到相应插件的所有可用版本。点击您需要的版本（我选择安装最新版本）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/dd8ac73e-9be4-4e7b-8dc3-05eb011557aa.png)

插件可用版本列表

1.  这将在您的系统上下载一个`.hpi`文件。

1.  下载插件时，同样重要的是下载它的依赖项（其他 Jenkins 插件）。

1.  必须在安装所需插件之前安装所有依赖项（Jenkins 插件）。

1.  将此`.hpi`文件（`logstash.hpi`）复制到您的 Jenkins 服务器或任何可以访问您的 Jenkins 仪表板的计算机上。

1.  现在，请登录到您的 Jenkins 服务器。从 Jenkins 仪表板，导航到**管理 Jenkins** | **管理插件** | **高级**。

1.  在**高级**选项卡下的**上传插件**部分，执行以下操作（如下面的屏幕截图所示）：

1.  单击**文件**字段下的**浏览...**按钮。

1.  从结果窗口中，上传已下载的`.hpi`文件。

1.  完成后，点击**上传**按钮：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/f68e3f67-10c9-4109-a8c7-3db079818704.png)

手动上传 Jenkins 插件

1.  Jenkins 现在将继续进行插件安装。

# Jenkins 备份和恢复

如果有人意外删除了重要的 Jenkins 配置会发生什么？尽管可以通过我们将在*用户管理*部分中看到的严格的用户权限来避免这种情况，但想象一下这样一种情况：某人正在处理 Jenkins 配置，希望将其恢复到之前稳定的 Jenkins 配置。

从我们目前了解的内容来看，我们知道整个 Jenkins 配置存储在 Jenkins 主目录下。它是`C:\jenkins`（Windows），`/var/jenkins_home`（Apache Tomcat），`/var/lib/jenkins`（Linux）。在接下来的部分中，我们将学习如何使用插件来备份和恢复 Jenkins 配置，即周期性备份插件。

# 安装周期性备份插件

按照以下步骤安装周期性备份插件：

1.  从 Jenkins 仪表板上，点击**管理 Jenkins** | **管理插件**。

1.  在**插件管理器**页面上，点击**可用**选项卡。

1.  使用**过滤器**选项，搜索`周期性备份`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1c0318be-9128-46d6-84b9-d3b385f2e707.png)

安装周期性备份插件

1.  从项目列表中选择周期性备份并点击**无需重启安装**。你只需要蓝色海洋和其他什么都不需要。

# 配置周期性备份插件

在我们开始使用之前，我们需要告诉周期性备份插件要备份什么，备份到哪里以及备份频率是多少。按照以下步骤操作：

1.  从 Jenkins 仪表板转到**管理 Jenkins** | **周期性备份管理器**。

1.  当你第一次访问周期性备份管理器时，你会看到以下通知：

周期性备份插件尚未配置。点击这里进行配置。

1.  点击**单击此处进行配置**链接。

1.  你将被带到周期性备份管理器页面，并且你会发现很多配置选项。让我们逐一查看它们（如下面的截图所示）。

1.  根目录，`<你的 Jenkins 主目录>`，是你的 Jenkins 主目录。

1.  **临时目录**字段应该是位于 Jenkins 服务器机器上的一个目录。正如其名称所示，该目录用作备份/恢复过程中执行归档/解档操作的临时位置。它可以是任何目录，并且应该位于 Jenkins 主目录之外。

1.  **备份计划（cron）**字段是你定义何时或多频繁进行备份的地方。不要将此字段留空。请注意，该字段接受 cron 语法。例如，要每天午夜备份一次，请使用以下不带引号的 cron 语法：`0 0 * * *`。

1.  **验证 cron 语法**按钮用于验证你在**备份计划（cron）**字段中输入的 cron 语法是否正确。

1.  **位置中的最大备份数**字段告诉 Jenkins 不要存储大于此处描述的数量的备份。

1.  **存储时间不超过（天）**字段告诉 Jenkins 删除任何早于此值的备份。

1.  在**文件管理策略**下，你有两个选择：仅配置（ConfigOnly）和完全备份（FullBackup）。如果你选择了仅配置选项，Jenkins 将备份 Jenkins 主目录中的所有`.xml`文件以及所有作业的`config.xml`文件。但是，如果选择完全备份，则 Jenkins 将备份整个 Jenkins 主目录。

1.  在 存储策略 下，您有三个选择： NullStorage，TarGzStorage 和 ZipStorage（支持多卷）。您可以选择适合您需求的选项。

1.  在 备份位置 下，您可以添加多个备份位置来存储您的备份。要这样做，请点击**添加位置**按钮并选择本地目录。接下来，在 备份目录路径 字段下，添加您希望 Jenkins 存储备份的位置。同时，不要忘记勾选**启用此位置**复选框。您可以选择多个位置并将它们全部启用。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d0faaace-2f45-4a7b-8506-6ad8d2c20a45.png)

周期性备份配置

# 创建 Jenkins 备份

现在我们已经配置了周期性备份插件，让我们运行一个备份以测试我们的设置。为此，请在周期性备份管理器页面上，点击左侧菜单中的立即备份！链接。

在备份进行中，您将在周期性备份管理器页面上看到通知，显示为 Creating backup…。

一旦备份完成，您将在同一页面上看到它列在备份列表中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/36f2c2eb-3c25-4f7e-b793-f30febb61293.png)

备份列表

# 恢复 Jenkins 备份

现在，让我们测试恢复 Jenkins 备份。但在我们这样做之前，让我们进行一些配置更改，以查看恢复操作是否有效。我们将通过在配置系统页面上进行一些配置更改来实现这一点：

1.  从 Jenkins 仪表板，点击**管理 Jenkins | 配置系统**。

1.  在**配置系统**页面上，更改以下字段的值。

1.  将 # of executors 字段的值从`2`更改为`5`。

1.  将安静期字段的值从`5`更改为`10`。

1.  点击页面底部的**保存**按钮。

1.  现在，让我们将 Jenkins 恢复到上述更改之前的状态。

1.  从 Jenkins 仪表板，点击**管理 Jenkins | 周期性备份管理器**。

1.  在结果页面上，选择我们在前一节中创建的备份，并点击**恢复选定的备份**按钮。

1.  您将看到以下消息：

恢复备份…

1.  刷新页面，在 Jenkins 仪表板上点击**管理 Jenkins | 配置系统**。

1.  您将会发现 # of executors 字段的值为两个，安静期字段的值为五。

# 查看备份和恢复日志

您可以查看关于 Jenkins 备份和恢复的完整日志。要查看详细日志，请执行以下步骤：

1.  从 Jenkins 仪表板，点击**管理 Jenkins | 系统日志**。

1.  在日志页面，转至日志记录器部分，点击`org.jenkinsci.plugins.periodicbackup`。

1.  您将在此找到备份和恢复操作的完整日志，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/3eeb250d-f852-432e-8fb4-fb06b6166658.png)

Jenkins 周期性备份日志

# 升级 Jenkins

Jenkins 有两种发布版本：*LTS 发布* 和 *每周发布*。 *Jenkins 每周发布* 包含新功能和错误修复，而 *LTS（长期支持）* *发布* 是特殊的发布版本，在 12 周的时间内被视为稳定。建议您始终为您的 Jenkins 服务器选择一个 *LTS 发布*：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b70677e5-6337-4f2e-a625-8d5b7014741e.png)

Jenkins 下载页面

Jenkins 本身会在有新版本可用时通知您（前提是您的 Jenkins 服务器可以访问互联网），如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/5cf66ecb-2dc9-43fe-8457-18344b00f90d.png)

Jenkins 通知有新版本可用

# 升级运行在 Tomcat 服务器上的 Jenkins

在接下来的部分中，我们将学习如何更新运行在 servlet 内的 Jenkins（Apache Tomcat）。按照给定的步骤操作：

1.  以 root 用户身份登录到您的 Apache Tomcat 服务器机器。

1.  使用以下命令在 `/tmp` 目录下下载最新的（LTS）版本的 `jenkins.war`：

```
 cd /tmp 
 wget http://mirrors.jenkins.io/war-stable/latest/jenkins.war
```

要下载特定版本的 Jenkins（LTS），请转到以下链接：[`mirrors.jenkins.io/war-stable/`](http://mirrors.jenkins.io/war-stable/) 并选择所需的 Jenkins 版本（例如，[`mirrors.jenkins.io/war-stable/2.73.1/jenkins.war`](http://mirrors.jenkins.io/war-stable/2.73.1/jenkins.war)）。

要下载特定版本的 Jenkins（每周发布），请转到以下链接：[`mirrors.jenkins.io/war/`](http://mirrors.jenkins.io/war/) 并选择所需的 Jenkins 版本（例如，[`mirrors.jenkins.io/war/2.78/jenkins.war`](http://mirrors.jenkins.io/war/2.78/jenkins.war)）。

1.  在我们升级 Jenkins 之前，重要的是我们备份我们的 `jenkins_home` 目录。请参考*创建 Jenkins 备份*部分。

在升级 Jenkins 之前始终运行 Jenkins 的备份。

1.  现在，使用以下命令停止 `tomcat` 服务：

```
 systemctl stop tomcat
```

1.  接下来，前往当前 `jenkins.war` 文件所在的位置。在我们的情况下，它是 `/opt/tomcat/webapps`：

```
 cd /opt/tomcat/webapps/
```

如果您选择仅使用 Tomcat 服务器运行 Jenkins，则可能在 `webapps` 目录下找到 `ROOT.war` 而不是 `jenkins.war`。请参考*在 Apache Tomcat 服务器上独立安装 Jenkins*部分，来自第二章，*安装 Jenkins*。

1.  备份您现有的 `jenkins.war` 或 `ROOT.war` 并将其放置在 `webapps` 目录之外的某个位置（例如，`/tmp` 目录）：

```
 cp jenkins.war /tmp/jenkins.war.last.stable.version
```

或者：

```
 cp ROOT.war /tmp/ROOT.war.last.stable.version
```

1.  现在，在 webapps 目录内删除当前的 `jenkins.war` 或 `ROOT.war` 文件：

```
 rm –r jenkins.war
```

或者：

```
 rm –r ROOT.war
```

1.  接下来，将您从 `/tmp` 目录下载的新的 `jenkins.war` 移动到 `webapps` 目录。如果您仅使用 Apache Tomcat 服务器运行 Jenkins，则将 `destination.war` 文件重命名为 `ROOT.war`：

```
 mv /tmp/jenkins.war /opt/tomcat/webapps/jenkins.war
```

或者：

```
 mv /tmp/jenkins.war /opt/tomcat/webapps/ROOT.war
```

1.  现在，使用以下命令启动 Tomcat 服务：

```
 systemctl start tomcat
```

1.  登录到您的 Jenkins 实例。要确认 Jenkins 版本，请查看 Jenkins 仪表板的右下角，您将找到一个新的 Jenkins 版本号。

# 升级运行在 Windows 上的独立 Jenkins

在 Windows 上升级独立 Jenkins 服务器是一个简单的任务。按照给定的步骤进行：

1.  从[`jenkins.io/download/`](https://jenkins.io/download/)下载最新的`jenkins.war`。或者，如果您正在寻找要升级到的特定 Jenkins 版本，则从以下链接下载：[`mirrors.jenkins.io/war-stable/`](http://mirrors.jenkins.io/war-stable/)。

1.  在我们升级 Jenkins 之前，重要的是我们备份我们的`jenkins_home`目录。参考*创建 Jenkins 备份*部分下的*Jenkins 备份和恢复*部分。

在升级 Jenkins 之前始终运行 Jenkins 备份。

在 Jenkins 独立实例（运行在 Windows 机器上）上，`jenkins.war`文件位于`jenkins_home`目录内。因此，备份`jenkins_home`目录就足够了。

1.  接下来，停止 Jenkins 服务。要执行此操作，请从 Windows 运行执行`services.msc`。这将打开 Windows 服务页面。

1.  搜索 Jenkins 服务（通常命名为 Jenkins）。停止 Jenkins 服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/35a27889-be95-47b7-bea9-5bb2bdd978fb.png)

停止 Jenkins 服务

1.  或者，您也可以使用以下命令从 Windows 命令提示符（以管理员身份运行）停止 Jenkins 服务：

```
 net stop Jenkins
```

输出如下：

```
 The Jenkins service is stopping.
 The Jenkins service was stopped successfully.
```

1.  接下来，将位于`C:\Program Files (x86)\Jenkins\`下的`jenkins.war`文件替换为新下载的`jenkins.war`文件。

1.  替换`jenkins.war`文件后，从服务窗口启动 Jenkins 服务，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b683c11b-e08c-4f8d-b4c4-05119f8d0ef6.png)

启动 Jenkins 服务

1.  或者，您也可以使用以下命令从 Windows 命令提示符（以管理员身份运行）启动 Jenkins 服务：

```
 net start Jenkins
```

输出如下：

```
 The Jenkins service is starting.
 The Jenkins service was started successfully.
```

1.  登录到您的 Jenkins 实例。要确认 Jenkins 版本，请查看 Jenkins 仪表板的右下角，您应该看到一个新的 Jenkins 版本号。

# 升级运行在 Ubuntu 上的独立 Jenkins

在接下来的章节中，我们将学习如何更新运行在 Ubuntu 上的 Jenkins。按照给定的步骤进行：

1.  以 root 用户身份登录到您的 Jenkins 服务器机器。

1.  使用以下命令在`/tmp`目录下下载最新的（LTS）版本`jenkins.war`文件：

```
 cd /tmp 
 wget http://mirrors.jenkins.io/war-stable/latest/jenkins.war
```

要下载特定版本的 Jenkins（LTS），请转到以下链接：[`mirrors.jenkins.io/war-stable/`](http://mirrors.jenkins.io/war-stable/)，并选择所需的 Jenkins 版本（例如，[`mirrors.jenkins.io/war-stable/2.73.1/jenkins.war`](http://mirrors.jenkins.io/war-stable/2.73.1/jenkins.war)）。

要下载特定版本的 Jenkins（Weekly），请转到以下链接：[`mirrors.jenkins.io/war/`](http://mirrors.jenkins.io/war/)，然后选择所需版本的 Jenkins（例如，[`mirrors.jenkins.io/war/2.78/jenkins.war`](http://mirrors.jenkins.io/war/2.78/jenkins.war)）。

1.  在我们升级 Jenkins 之前，重要的是我们备份我们的`jenkins_home`目录。参考*Jenkins 备份和还原*部分下的*创建 Jenkins 备份*部分。

在升级 Jenkins 之前，始终运行 Jenkins 备份。

1.  现在，使用以下命令停止`jenkins`服务：

```
 systemctl stop jenkins
```

1.  接下来，转到当前`jenkins.war`文件存在的位置。在我们的情况下，它是`/usr/share/jenkins/`：

```
 cd /usr/share/jenkins/
```

1.  对您现有的`jenkins.war`进行备份，并将其放置在`jenkins`目录之外的某个地方（例如，`/tmp`目录）：

```
 cp jenkins.war /tmp/jenkins.war.last.stable.version
```

1.  现在，删除`jenkins`目录中的当前`jenkins.war`文件：

```
 rm –r jenkins.war
```

1.  接下来，将您从`/tmp`目录下载的新`jenkins.war`文件移动到`jenkins`目录：

```
 mv /tmp/jenkins.war /usr/share/jenkins/jenkins.war
```

1.  现在，使用以下命令启动`jenkins`服务：

```
 systemctl start jenkins
```

1.  登录到您的 Jenkins 实例。要确认 Jenkins 版本，请查看 Jenkins 仪表板的右下角，您将找到一个新的 Jenkins 版本号。

# 升级运行在 Docker 容器上的 Jenkins

在下一节中，我们将学习如何更新运行在 Docker 容器内的 Jenkins 实例：

如果您正在使用数据卷为您的`jenkins_home`目录运行 Jenkins 实例，则以下部分适用。参见第二章中的*在 Docker 上运行 Jenkins，使用数据卷运行 Jenkins 容器*部分，*安装 Jenkins*。

1.  登录到您的 Docker 主机机器。

1.  使用以下命令查找正在运行的 Jenkins 容器：

```
 sudo docker ps --format "{{.ID}}: {{.Image}} {{.Names}}"
```

输出如下所示：

```
 d52829d9da9e: jenkins/jenkins:lts jenkins_prod
```

1.  您应该会收到类似于先前片段的输出。注意 Jenkins 容器名称，在我的示例中是`jenkins_prod`。

1.  我们将使用以下 Docker 命令停止然后删除正在运行的 Jenkins 容器。但是，在您停止和删除 Jenkins 实例之前，请确保 Jenkins 服务器上没有作业在运行：

```
 sudo docker stop <your jenkins container name>
 sudo docker rm <your jenkins container name>
```

1.  使用以下命令列出您的 Docker 主机上可用的 Docker 镜像。您可以看到我们有一个 Jenkins Docker 镜像：`jenkins/jenkins:lts`。但是，那已经不是最新的了：

```
 sudo docker images
```

输出如下所示：

```
 REPOSITORY        TAG      IMAGE ID        CREATED             SIZE
 jenkins/jenkins   lts      6376a2961aa6    7 weeks ago         810MB
 hello-world       latest   1815c82652c0    3 months ago        1.84kB
```

1.  使用以下命令下载最新的 Jenkins Docker 镜像：

```
 sudo docker image pull jenkins/jenkins:2.73.1
```

上述命令可能需要一段时间来下载 Jenkins Docker 镜像。

在编写本章时，2.73.1 是最新的 Jenkins 发布版本（LTS）。通过修改命令选择所需版本的 Jenkins。

1.  下载完成后，再次执行`sudo docker images`命令，如以下片段所示。注意新的 Jenkins Docker 镜像。在我的示例中，它是`jenkins/jenkins:2.73.1`：

```
 sudo docker images
```

输出如下所示：

```
 REPOSITORY          TAG     IMAGE ID       CREATED             SIZE jenkins/jenkins     2.73.1  c8a24e6775ea   24 hours ago        814MB jenkins/jenkins     lts     6376a2961aa6   7 weeks ago         810MB hello-world         latest  1815c82652c0   3 months ago        1.84kB
```

1.  现在让我们使用新下载的 Jenkins Docker 镜像启动一个新的 Jenkins 容器（我们将重用旧的 Jenkins 容器名称）：

```
 sudo docker run -d --name jenkins_prod \
      -p 8080:8080 -p 50000:50000 \ 
      -v jenkins-home-prod:/var/jenkins_home \
      jenkins/jenkins:2.73.1
```

1.  以下表格解释了我们之前使用的 Docker 命令：

| `docker` | 用于调用 Docker 实用程序。 |
| --- | --- |
| `run` | 这是一个运行容器的 Docker 命令。 |
| `-d` | 此选项在后台运行容器。 |
| `--name` | 此选项为容器命名。 |
| `-p` | 此选项用于将容器的端口映射到主机。 |
| `jenkins/jenkins:2.73.1` | 用于创建容器的 Docker 镜像及其版本的名称。`jenkins/jenkins` 是 Jenkins Docker 镜像，`2.73.1` 是该镜像的特定版本。 |

1.  登录到您的 Jenkins 实例。您应该看到所有的作业/设置都完好无损。要确认 Jenkins 版本，请查看 Jenkins 仪表板的右下角，您将找到一个新的 Jenkins 版本号。

# 用户管理

让我们看看 Jenkins 在用户管理领域提供了什么。从 Jenkins 仪表板中，点击“管理 Jenkins | 配置全局安全”以访问“配置全局安全”页面。

您还可以通过使用 `<Jenkins URL>/configureSecurity/` 链接访问“配置全局安全”页面。

在接下来的部分，我们将坚持与用户身份验证和权限相关的选项。我们将在即将到来的章节中查看其他安全选项。

# 启用/禁用 Jenkins 的全局安全

一旦进入“配置全局安全”页面，您会看到“启用安全性”选项已经启用。应始终将“启用安全性”选项设置为启用状态；禁用它将使 Jenkins 对于任何拥有 Jenkins URL 的人都可访问，而不受任何限制。

# 启用/禁用计算机记住用户凭据

当用户尝试访问 Jenkins 时，他们将被提供在他们各自的计算机上被记住的选项，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7904f347-7f7b-4906-bc12-5d42d721ac52.png)

在此计算机上记住我选项

这个行为默认启用。要禁用此功能，请勾选“**禁用记住我**”选项，该选项位于“配置全局安全”页面下。

# 身份验证方法

Jenkins 提供了多种可供选择的身份验证方法。以下是可用选项的列表：

+   委派给 Servlet 容器

+   Jenkins 自己的用户数据库

+   LDAP

+   Unix 用户/组数据库

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/1e461503-6663-4b58-b44d-02fa04fd0b2e.png)

Jenkins 的身份验证方法

默认情况下启用了 Jenkins 自己的用户数据库选项。我们在 Jenkins 设置向导期间创建的初始用户都存储在 Jenkins 自己的用户数据库中。没有任何实际的数据库，所有用户信息都保存为 XML 文件。让我们快速查看每种身份验证方法。

# 委派给 Servlet 容器

该选项仅在您从 servlet 容器（如 Apache Tomcat 等）运行 Jenkins 服务器时才能使用。启用此选项将允许 Jenkins 使用 servlet 容器的领域对用户进行身份验证。

例如，在 第二章的 *安装 Jenkins* 中 *在 servlet 容器中运行 Jenkins* 小节下的 *配置 Apache Tomcat 服务器* 子节中，我们修改了 `tomcat-user.xml` 文件以创建用户和访问。这是一个`UserDatabaseRealm`的示例。

这意味着，如果您的 Jenkins 服务器正在 Apache Tomcat 服务器上运行，并且您已配置了`UserDatabaseRealm`，那么在`tomcat-user.xml`文件中定义的所有用户都将能够访问 Jenkins。

请参考以下网站，查看 Apache Tomcat 支持的所有领域类型：[`tomcat.apache.org/tomcat-8.0-doc/realm-howto.html#Standard_Realm_Implementations.`](http://tomcat.apache.org/tomcat-8.0-doc/realm-howto.html#Standard_Realm_Implementations)

# Jenkins 的自有用户数据库

此选项默认启用。在此方案下，Jenkins 将所有用户信息存储在 XML 文件中。这个选项适用于小型组织或者如果您正在探索 Jenkins 并且尚未将其纳入组织。

还有一个选项可以允许用户在登录页面注册。要启用它，请在 Jenkins 的自有用户数据库中选中**允许用户注册**选项。

这将在 Jenkins 登录页面上启用一个名为**创建帐户**的链接，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6af0a744-f7f3-422d-81a9-4fca5744b0dc.png)

允许用户注册选项

作为新用户，当您点击**创建帐户**链接时，将要求您填写一些关于自己的基本信息，例如用户名、密码、电子邮件、全名等。一旦您填写完必要信息，就可以访问 Jenkins。

作为新用户，您在 Jenkins 上被允许看到/执行的操作取决于 Jenkins 内的**授权**设置。我们将在本章后面学习有关**授权**设置的更多信息。

# LDAP

这是大多数组织中最广泛使用的身份验证方法之一。如果在**访问控制** | **安全领域**部分下未看到**LDAP**选项，请检查**LDAP 插件**。

如下面的截图所示，以下选项允许 Jenkins 使用 LDAP 服务器对用户进行身份验证。请联系您组织中的 IT 管理团队提供 LDAP 服务器详细信息（如果您的组织使用 LDAP）。

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/28a9fbb7-38a9-4ab6-94ce-24e63f8d1259.png)

有关 LDAP 配置的更多信息，请参阅 LDAP 插件页面：[`wiki.jenkins.io/display/JENKINS/LDAP+Plugin`](https://wiki.jenkins.io/display/JENKINS/LDAP+Plugin)。

# Unix 用户/组数据库

如果 Jenkins 安装在 Unix/Linux 机器上，则以下选项有效。当启用时，Jenkins 将权限委托给底层操作系统。换句话说，配置在底层操作系统上的所有用户/组都可以访问 Jenkins。

您无需在 Jenkins 中配置任何内容即可使此选项生效。但是，底层操作系统上的所有用户都应该能够访问`/etc/shadow`文件*。*

使用以下命令使`/etc/shadow`文件对所有用户可访问：

```
sudo chmod g+r /etc/shadow
```

# 在 Jenkins 中创建新用户

如果您使用 Jenkins 自己的用户数据库作为认证方法，则以下部分仅适用。执行以下步骤手动将用户添加到您的 Jenkins 服务器中。

1.  从 Jenkins 仪表板中，单击**管理 Jenkins | 管理用户**。

1.  在**管理用户**页面上，从左侧菜单中，单击**创建用户**。

1.  在结果页面上，您将被要求提供有关用户的一些基本信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/77dccbc9-a126-4781-9437-1f5b79ed21ef.png)

在 Jenkins 中创建用户

1.  填写相应值的字段，然后单击**创建用户**按钮。

只有在使用 Jenkins 自己的用户数据库作为认证方法时，才会提供“管理用户”链接。

# 人员页面

人员页面显示所有可以访问 Jenkins 服务器的用户，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/d5c6bb50-da5d-4e75-926c-0411f5cdcb1f.png)

Jenkins 人员页面

# Jenkins 中的用户信息和设置

单击任何特定用户 ID 或名称（参见下图）以获取有关相应用户的信息。您将被带到用户状态页面，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/ffa8caf4-1644-4929-863d-fcb6b34ed212.png)

用户状态页面

在用户的状态页面的左侧菜单中，您将看到以下选项：**状态**、**构建**、**配置**、**我的视图**和**凭据**。让我们详细探讨其中一些：

+   **构建**页面将显示由当前用户运行的所有 Jenkins 构建的信息。

+   **我的视图**页面将带您进入当前用户可以访问的视图。如果没有为当前用户配置视图，则**我的视图**页面将显示默认的全部视图（Jenkins 仪表板）。

+   凭据链接将带您进入**凭据**页面。但是，凭据页面将显示与当前用户相关的其他信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/8f5db5c3-8ee0-4fe7-bc64-46a7ffcaf1f8.png)

Jenkins 凭据作用域限制为一个用户

# 授权方法

Jenkins 提供了各种授权方法供选择。以下是可用选项的列表：

+   任何人都可以做任何事情

+   传统模式

+   已登录用户可以做任何事情

+   基于矩阵的

+   基于项目的矩阵授权策略

默认情况下启用了已登录用户可以做任何事情选项。让我们快速浏览一下每种授权方法。

要访问 Jenkins 授权设置，请从 Jenkins 仪表板导航到**管理 Jenkins | 配置全局安全 | 访问控制**。

# 任何人都可以做任何事

当您选择此选项时，Jenkins 不执行任何授权。任何具有对 Jenkins 的访问权限的人都可以获得完全控制权，包括匿名用户。不推荐此选项。

# 兼容模式

当您选择此选项时，Jenkins 的行为方式与发布 1.164 版之前的方式相同。简单来说，Jenkins 将寻找一个名为`Admin`的用户（无论您使用的是什么身份验证方法）。这个`Admin`用户将被赋予管理员特权，而其余用户将被视为匿名用户。再次强调，不推荐此选项。

# 已登录用户可以做任何事

这是您安装和设置新 Jenkins 服务器时 Jenkins 默认附带的身份验证设置。名称不言自明，即已登录用户默认为管理员。同样，不推荐此选项。

在**已登录用户可以做任何事**字段下，有一个名为允许匿名读取访问的选项（默认情况下已禁用）。当选中（启用）此选项时，任何具有对 Jenkins URL 的访问权限的人都将直接进入 Jenkins 仪表板，具有对所有 Jenkins 作业的只读访问权限。但是，您需要登录才能编辑 Jenkins 作业或查看 Jenkins 的配置。

# 基于矩阵的安全性

这是 Jenkins 中最广泛使用的授权方法之一。让我们通过以下步骤详细探讨它：

1.  通过选择它启用基于矩阵的安全授权方法。您将看到以下矩阵：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/c1df46a8-b178-4657-a133-727ebd636d54.png)

基于矩阵的安全配置

1.  从前面的屏幕截图中，您可以看到列代表 Jenkins 中的各种项目，而行代表各种用户。在矩阵底部有一个选项可添加用户。

1.  让我们添加一些用户并为他们提供一些权限。

1.  要添加用户，请在**要添加的用户/组**字段中输入用户的确切用户名，然后单击**添加**按钮。

1.  您可以从以下屏幕截图中看到，我已添加了四个用户（请参阅*People page*部分以查看您可以在此处添加的用户列表）。如果您正在使用 Jenkins 的自己的用户数据库，则创建一些用户（请参阅*在 Jenkins 内部创建新用户*部分）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/b880a897-95a6-4653-afef-83117295df5a.png)

将用户添加到矩阵中

1.  现在，让我们通过选择适当的复选框为它们授予权限。您可以从以下屏幕截图中看到，我已经给用户`jenkins_admin`完全访问权限。用户`jenkins_developer`和`jenkins_tester`已被授予读取和执行 Jenkins 作业的访问权限，而用户`jenkins_user`仅被授予读取权限：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/924c015c-dd88-45da-b66b-239d8c01f1e1.png)

使用矩阵提供权限

1.  将其余设置保持不变，然后单击页面底部的保存按钮。

1.  为了检查配置，请以每个用户的身份登录，并确认在 Jenkins 仪表板上看到的内容。

# 基于项目的矩阵授权策略

在前一节中，我们看到了基于矩阵的安全授权功能，它使我们对用户和权限有了相当大的控制能力。

但是，想象一种情况，你的 Jenkins 服务器已经发展到包含数百个 Jenkins 作业和许多用户的阶段，并且你希望在作业级别（项目级别）上控制用户权限。

在这种情况下，我们需要基于项目的矩阵授权策略：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/6ecdc314-dceb-4878-ac42-055baa7cf532.png)

作业级别的用户权限

让我们学习如何配置基于项目的矩阵授权策略。执行以下步骤：

1.  要访问 Jenkins 授权设置，请从 Jenkins 仪表板导航到**管理 Jenkins | 配置全局安全 | 访问控制**。

1.  选择基于项目的矩阵授权策略选项。你将看到以下矩阵：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/7bd98a77-5268-43d7-b7cd-513e7d68f99f.png)

基于项目矩阵授权策略配置

1.  现在，添加一个用户并给予其完全权限。要添加用户，请在“要添加的用户/组”字段中输入用户的完整用户名，然后单击“**添加**”按钮。

1.  从以下屏幕截图中可以看到，我为用户`jenkins_admin`添加了完全权限：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/658d04c6-e015-4bd6-a911-3c0fc68b87ec.png)

将用户添加到矩阵中

1.  将其余设置保持不变，然后单击页面底部的**保存**按钮。

1.  接下来，在 Jenkins 仪表板上右键单击任何一个 Jenkins 作业，然后选择**配置**。

1.  在作业配置页面，向下滚动到启用基于项目的安全选项并启用它。

1.  当你启用基于项目的安全性时，将出现一个矩阵表格，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/dd1355de-4c12-4620-a2a9-0f15078d3120.png)

Jenkins 作业中的基于项目的安全配置

1.  让我们添加一些用户并为他们分配权限。

1.  要添加用户，请在“要添加的用户/组”字段中输入用户的完整用户名，然后单击“**添加**”按钮。

1.  从以下屏幕截图中可以看到，我给用户`jenkins_developer`添加了一些权限：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/lrn-ci-jks-2e/img/f40c3688-14a8-4d28-8ea1-e518b87afeb8.png)

使用矩阵提供权限

1.  完成后，单击页面底部的**保存**按钮。

1.  现在以刚刚为相应的 Jenkins 作业赋予权限的用户登录（在我们的示例中为`jenkins_developer`）。

1.  你会发现用户只能看到它具有访问权限的 Jenkins 作业。

1.  同样，你可以在 Jenkins 中为你创建的每个作业配置用户权限。

# 概要

在本章中，我们看到了如何通过一些实际示例来配置 Jenkins 中的一些基本但重要的元素。Jenkins 升级、Jenkins 备份和 Jenkins 用户管理是本章中我们学到的一些重要内容。

下一章将介绍 Jenkins 主从架构以及 Jenkins *分布式构建系统*。
