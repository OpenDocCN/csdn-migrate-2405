# Node-Red 实战编程（二）

> 原文：[`zh.annas-archive.org/md5/C5AA5862C03AC3F75583D0632C740313`](https://zh.annas-archive.org/md5/C5AA5862C03AC3F75583D0632C740313)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：从 Node-RED 调用 Web API

在本章中，让我们从 Node-RED 调用 Web API。基本上，在 Node-RED 中，处理是根据创建的流程进行的，但连接处理的是 JSON 数据。从这个意义上说，它与 Web API 非常兼容。

让我们从以下四个主题开始：

+   学习节点的输入/输出参数

+   学习节点的输入/输出参数

+   如何在节点上调用 Web API

+   如何使用 IBM Watson API

到本章结束时，你将掌握如何从 Node-RED 调用任何类型的 Web API。

# 技术要求

要在本章中继续进行，你将需要以下内容：

+   Node-RED（v1.1.0 或更高版本）

本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter07`文件夹中找到。

# 学习 RESTful API

阅读本书的许多人可能已经熟悉 Web API。然而，为了使用 Node-RED 调用 Web API，让我们回顾一下 RESTful API。

**REST**代表**表述性状态转移**。RESTful API 基本上指的是根据“REST 原则”实现的 Web 系统的 HTTP 调用接口。因此，广义上来说，可以说 REST API 和 RESTful API 是相同的东西。那么，RESTful API 究竟是什么？我们将在本节中学习 RESTful API 的概述和原则，以及使用 RESTful API 的优缺点。

REST 是由 HTTP 协议创造者之一 Roy Fielding 在 2000 年左右提出的，是一组（或一种思维方式）适用于构建分布式应用程序时链接多个软件的设计原则。此外，RESTful API 是根据以下四个 REST 原则设计的 API：

+   **可寻址性**：它具有能够通过 URI 直接指向资源的属性。所有信息都应该由唯一的 URI 表示，这样你就可以一目了然地看到 API 版本，是否获取数据，更新等。

+   **无状态性**：所有 HTTP 请求必须完全分离。不应执行会话等状态管理。

+   **连接性**：这指的是在一条信息中包含“链接到其他信息”的能力。通过包含链接，你可以“连接到其他信息”。

+   **统一接口**：使用 HTTP 方法进行所有操作，如信息获取、创建、更新和删除。在这种情况下，HTTP 方法是获取（“GET”）、创建（“POST”）、更新（“PUT”）和删除（“DELETE”）。

这些是四个原则。从这四个原则中可以看出，REST 的一个主要特点是它更有效地利用了 HTTP 技术，并且与 Web 技术有很高的亲和性。因此，它目前被用于开发各种 Web 服务和 Web 应用程序。

随着智能手机的广泛使用，业务系统不仅可以在 PC 上使用，还可以在移动设备上使用，这一点变得越来越明显。此外，用户不仅选择一个系统，而是选择可以与多个系统和各种 Web 服务链接的系统。RESTful API 作为解决这些问题的不可或缺的工具受到了极大的关注。

如下图所示，可以从任何地方通过互联网调用 Web API：

![图 7.1 - RESTful API 图表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.1_B16353.jpg)

图 7.1 - RESTful API 图表

现在，让我们回顾一下 Node-RED 是什么。它的工作流工具样式类似于一个独立的工具，但 Node-RED 当然也是 Web 应用程序之一。换句话说，它是一个非常适合与此处描述的 RESTful API 一起使用的应用程序。

接下来，让我们再次介绍 Node-RED 节点具有哪些参数。

# 学习节点的输入/输出参数

在 Node-RED 中有许多节点，但适合调用 Web API（REST API）的并不多。调用 Web API 时常用的节点是`http request`节点。

要在 Node-RED 上调用外部 API，只需将 API 的端点 URL 设置为`http request`节点的 URL 属性。

例如，在调用 API 时需要在端点 URL 中设置参数时，可以设置连接的前一个节点的输出值。这种方法非常简单。在参数的值设置部分，可以设置`{{payload}}`变量，而不是字面字符串。

在`{{payload}}`中，输入从前一个处理节点继承的字符串。

以以下示例为例（请注意，此 URL 不存在）：`http://api-test.packt.com/foo?username={{payload}}&format=json`：

![图 7.2 – 使用{{payload}}作为参数设置 API 端点 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.2_B16353.jpg)

图 7.2 – 使用{{payload}}作为参数设置 API 端点 URL

`http request`节点的过程不能仅由`http request`节点执行。在`http request`节点之前，需要连接触发过程，例如`inject`节点。在那时，如果有要传递给 API 调用的参数，也就是`http request`节点，请在`msg.payload`中设置它。

如果要在`http request`节点中调用的 API 是`POST`，则通过在预处理节点中创建 JSON 数据，并将其存储在`msg.payload`中，然后连接到`http request`节点，可以将其作为请求参数满足。

通过像这样使用`http request`节点，可以轻松实现 API 协作。API 调用对于在 Node-RED 上链接多个服务非常重要。例如，Node-RED 的**function**节点基本上是通过 JavaScript 处理的，但是通过将用其他开发语言开发的程序制作成 API，可以通过从 Node-RED 调用来使用。

# 如何在节点上调用 Web API

到目前为止，我们已经了解了什么是 RESTful API，以及哪个节点适合调用 API。

在这部分，让我们创建一个实际从 Node-RED 调用 API 的流程，并学习如何调用 API 以及如何处理 API 的结果值。

首先要考虑一些事情，比如要调用哪个 API。幸运的是，互联网上发布了各种 API。

这次，我想使用 OpenWeatherMap API。在 OpenWeatherMap 中，例如，准备了以下用于数据获取的 API：

+   当前天气数据

+   每小时预报 4 天

+   每日预报 16 天

+   气候预报 30 天

+   天气警报

+   等等...

有关更多信息，请参阅 OpenWeatherMap 的官方网站：[`openweathermap.org/`](https://openweathermap.org/)。

好的，让我们准备使用 OpenWeatherMap API。

## 创建账户

要使用 OpenWeatherMap API，我们需要创建一个账户。请访问以下 URL：[`openweathermap.org/`](https://openweathermap.org/)。

如果您已经有账户，请直接登录，无需进行以下步骤。

对于第一次使用的人，请点击**登录**按钮，然后点击**创建账户**链接。注册很容易。只需按照指示操作，并在注册后确认 OpenWeatherMap 发送给您的电子邮件。这是创建账户页面的样子：

![图 7.3 – 创建 OpenWeatherMap 账户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.3_B16353.jpg)

图 7.3 – 创建 OpenWeatherMap 账户

接下来，让我们创建一个 API 密钥。

## 创建 API 密钥

当您登录 OpenWeatherMap 时，可以看到**API 密钥**选项卡，请点击它。您已经有一个默认的 API 密钥，但请为本教程创建一个特定的 API 密钥。输入任何密钥字符串，然后点击**生成**按钮。

请注意，本书中显示的 API 密钥是我创建的示例，不能使用。请务必在您的账户中创建一个新的 API 密钥：

![图 7.4 – 生成 API 密钥](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.4_B16353.jpg)

图 7.4 - 生成 API 密钥

重要提示

创建 API 密钥后，密钥将在 10 分钟到几个小时内不会激活。如果在访问下一节中描述的 API 端点 URL 时返回 Web 响应错误，例如 401，则指定的 API 密钥可能尚未激活，请等待并重试。

## 检查 API 端点 URL

要检查您的 API 端点 URL，请按照以下步骤操作：

1.  单击菜单栏上的**API**按钮。您可以在那里看到一些 API。

1.  在本教程中，我们将使用**当前天气数据**，所以请点击**当前天气数据**下的**API 文档**按钮：![图 7.5 - 打开当前天气数据的 API 文档](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.5_B16353.jpg)

图 7.5 - 打开当前天气数据的 API 文档

1.  这个 API 有一些类型的参数，比如**按城市**，**按城市 ID**，**按邮政编码**等等。请选择带有城市名称和 API 密钥参数的**按城市名称**。

**API 文档**，**城市名称**，**州代码**和**国家代码**来自 ISO 3166。**API 调用**区域下的 URL 是使用此 API 的端点 URL。请将此 URL 复制到剪贴板：

![图 7.6 - 带参数的 API 端点 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.6_B16353.jpg)

图 7.6 - 带参数的 API 端点 URL

接下来，让我们看看我们是否可以运行这个 API。

## 检查 API 是否可以运行

让我们尝试使用这个 API。您只需打开浏览器，粘贴 URL，并用您自己的城市名称和 API 密钥替换它。您可以选择任何城市名称，但 API 密钥是您在上一节中创建的特定密钥：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.7_B16353.jpg)

图 7.7 - 调用 API 并获取结果

我现在已经确认这个 API 可以正常工作。现在让我们从 Node-RED 调用这个 API 并使用它。

## 创建调用 API 的流程

现在让我们创建一个在 Node-RED 上调用 OpenWeatherMap API 的流程。在您的环境中启动 Node-RED。您可以使用独立的 Node-RED 或 IBM Cloud 上的 Node-RED：

![图 7.8 - 使用 API 的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.8_B16353.jpg)

图 7.8 - 使用 API 的流程

对于这个，流程非常简单，很容易制作。请按照以下步骤制作流程：

1.  在调色板上放置一个**注入**节点和两个**调试**节点。这些节点可以使用默认设置。这里不需要更改设置。

1.  在调色板上放置**http 请求**节点，然后打开**http 请求**节点的设置面板，并在设置面板的**URL**文本框中使用您的参数（城市名称和 API 密钥）设置 API 端点 URL，如下图所示：![图 7.9 - 使用您的参数设置 API 端点 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.9_B16353.jpg)

图 7.9 - 使用您的参数设置 API 端点 URL

1.  在调色板上放置一个**json**节点。此节点可以与默认设置一起使用。这里不需要更改设置。但是，以防万一，让我们确保**json**节点的**Action**属性设置为**在 JSON 字符串和对象之间转换**。这是一个选项，将把作为输入参数传递的 JSON 数据转换为 JavaScript 对象：![图 7.10 - 检查 Action 属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.10_B16353.jpg)

图 7.10 - 检查 Action 属性

1.  将所有节点连接如下图所示：![图 7.11 - 连接所有节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.11_B16353.jpg)

图 7.11 - 连接所有节点

请将**时间戳**节点和**http 请求**节点连接起来。**http 请求**节点的输出连接到**json**节点和**调试**节点。最后，请将**json**节点的输出连接到另一个**调试**节点。

1.  更改设置并连接所有节点后，您需要部署并单击**注入**节点的开关。现在您可以在右侧面板的**调试**窗口中看到数据：

![图 7.12 - 在调试窗口上的结果数据（JSON）](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.12_B16353.jpg)

图 7.12 - 在调试窗口上的结果数据（JSON）

您还可以在与以下屏幕截图相同的**调试**窗口上查看结果数据的 JSON 对象：

![图 7.13 – 调试窗口上的结果数据（对象）](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.13_B16353.jpg)

图 7.13 – 调试窗口上的结果数据（对象）

恭喜！您已成功通过调用 OpenWeatherMap API 创建了一个示例流程。如果您没有完全成功创建此流程，您也可以在此处下载此流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/open-weather-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/open-weather-flows.json)。

在下一节中，我们将学习在 IBM Cloud 上使用 Node-RED 的便利性以及 IBM Watson API。

# 如何使用 IBM Watson API

在上一节中，您学习了如何调用 API 并处理 API 的结果值。

在本节中，我们将创建一个实际从 Node-RED 调用 API 的流程，但我们将学习如何调用 IBM 提供的 Watson API。我们还将创建一个实际从 Node-RED 调用 API 的流程，但我们将学习如何调用 IBM 提供的 Watson API。

为什么要使用 Watson？Watson 是 IBM 提供的人工智能服务和 API 的品牌。

所有 Watson API 都可以从 IBM Cloud 上使用。因此，通过在 IBM Cloud 上运行 Node-RED，您可以有效地使用 Watson 的服务。这样做的好处是，当从 Node-RED 调用 Watson API 时，可以省略身份验证的实现。

Watson 可以从 IBM Cloud 以外的环境调用，因此可以直接从树莓派调用，也可以从 AWS 和 Azure 等云平台或本地环境中使用。请参见下图，显示 Watson API 的外观：

![图 7.14 – Watson API 图表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.14_B16353.jpg)

图 7.14 – Watson API 图表

有关更多信息，请参阅 IBM Watson 官方网站：[`www.ibm.com/watson`](https://www.ibm.com/watson)。

好的，让我们看看在 IBM Cloud 上使用 Node-RED 上的 Watson API 有多容易。

## 登录 IBM Cloud

如果您已经按照第一章的步骤进行操作，您应该已经有了 IBM Cloud 帐户。只需登录 IBM Cloud ([`cloud.ibm.com`](https://cloud.ibm.com))。

如果您没有 IBM Cloud 帐户，请从以下网址创建一个并登录 IBM Cloud。有关详细说明，请参阅*第六章*，*在云中实现 Node-RED*：[`ibm.biz/packt-nodered`](http://ibm.biz/packt-nodered)。

## 在 IBM Cloud 上启动 Node-RED

在上一节中，我们使用独立的 Node-RED 或 IBM Cloud 上的 Node-RED 创建了一个示例流程。当然，您可以使用独立版本的 Node-RED 来调用 Watson API，但会丢失一些好处。因此，在本部分中，我们将使用 IBM Cloud 上的 Node-RED。

与上一步一样，如果您还没有在 IBM Cloud 上使用 Node-RED，请返回到*第六章*，*在云中实现 Node-RED*，并按照其中的步骤激活 IBM Cloud 上的 Node-RED，然后再进行下一步。

## 创建 Watson API

接下来，在 IBM Cloud 上创建 Watson 的服务。严格来说，这意味着创建一个作为服务的实例，以便您可以调用 IBM Cloud 上提供的 Watson API 服务作为您自己的 API。

Watson 有几个 API，例如语音识别、图像识别、自然语言分析、情感分析等。这次，我想使用情感分析 API。

按照以下步骤创建 Watson Tone Analyzer API 服务：

1.  从目录中搜索 Watson。在仪表板上，请单击`tone analyzer`，然后选择**Tone Analyzer**面板：![图 7.15 – 搜索 Watson 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.15_B16353.jpg)

图 7.15 – 搜索 Watson 服务

1.  请参考以下列表和*图 7.16*填写每个属性：

a. `默认`（您可以将其修改为任何您想要使用的名称）

d. **资源组**：**默认**（对于 Lite 账户，您无法选择其他内容）

e. **标签**：N/A

1.  在输入/选择所有属性后，点击**创建**按钮：![图 7.16 – 创建 Tone Analyzer 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.16_B16353.jpg)

图 7.16 – 创建 Tone Analyzer 服务

1.  当创建并激活时，您可以在**Tone Analyzer**实例仪表板上看到状态为**活动**。请检查 API 密钥和 URL。API 密钥和 URL 在从任何应用程序调用 API 时使用。但是，在本教程中不使用这些，因为 IBM Cloud 上的 Node-RED 可以在不需要认证编码的情况下调用 Watson API。

您可以从此屏幕上的**管理**菜单中检查 API 密钥和 URL：

![图 7.17 – 检查您的凭证](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.17_B16353.jpg)

图 7.17 – 检查您的凭证

在下一节中，我们将连接 Node-RED 和 Tone Analyzer 服务。

## 连接 Node-RED 和 Tone Analyzer 服务

正如您已经知道的，Node-RED 可以在不需要认证编码的情况下调用 Watson API。在使用 Node-RED 与 Watson API 之前，我们需要连接 Node-RED 和 Watson API 实例。在上一步中，我们创建了**Tone Analyzer** API 实例，所以让我们按照以下步骤连接这两个实例：

1.  点击左上角的**IBM Cloud**标志按钮，转到主仪表板。

1.  点击**资源摘要**面板上的**查看全部**按钮。

1.  在**Cloud Foundry 应用**区域点击 Node-RED 实例（应用）名称：![图 7.18 – 选择您创建的 Node-RED 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.18_B16353.jpg)

图 7.18 – 选择您创建的 Node-RED 服务

1.  点击**连接**菜单，然后点击**创建连接**按钮：![图 7.19 – 为 Node-RED 和 Watson 创建连接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.19_B16353.jpg)

图 7.19 – 为 Node-RED 和 Watson 创建连接

1.  检查**Tone Analyzer**服务并点击**下一步**按钮：![图 7.20 – 点击下一步按钮选择连接服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.20_B16353.jpg)

图 7.20 – 点击下一步按钮选择连接服务

1.  对于访问角色和服务 ID，无需进行修改。点击**连接**按钮：![图 7.21 – 点击连接按钮完成连接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.21_B16353.jpg)

图 7.21 – 点击连接按钮完成连接

1.  我们需要重新启动 Node-RED 以激活连接。点击**重新启动**按钮：![图 7.22 – 点击重新启动按钮开始重新启动 Node-RED 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.22_B16353.jpg)

图 7.22 – 点击重新启动按钮开始重新启动 Node-RED 服务

1.  请等待直到您的 Node-RED 实例的重新设置完成。完成后，您将获得**运行**状态的成功连接。之后，请通过**访问应用 URL**链接打开 Node-RED 流程编辑器：

![图 7.23 – 检查 Node-RED 服务的 Node.js 运行时状态](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.23_B16353.jpg)

图 7.23 – 检查 Node-RED 服务的 Node.js 运行时状态

您已成功准备好 Node-RED 和 Watson API 流程。接下来，让我们通过调用 Tone Analyzer API 来创建流程。

## 通过调用 Tone Analyzer API 创建流程

现在，让我们创建一个在 Node-RED 上调用 Watson Tone Analyzer API 的流程。您已经在 IBM Cloud 上启动了 Node-RED。可以使用独立的 Node-RED 或 IBM Cloud 上的 Node-RED。

为了继续本教程，您需要安装以下两个节点：

+   **node-red-node-twitter**：这是一个获取和发布推文到 Twitter 的节点。

![图 7.24 – 安装 node-red-node-twitter](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.24_B16353.jpg)

图 7.24 – 安装 node-red-node-twitter

+   `msg.payload`。在向 Watson Tone Analyzer API 传递参数时使用：

![图 7.25 – 安装 node-red-node-sentiment](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.25_B16353.jpg)

图 7.25 - 安装 node-red-node-sentiment

在调色板中搜索这些节点并将它们安装到您的 Node-RED 流编辑器中。之后，按照下图所示创建一个流程：

![图 7.26 - 使用 Tone Analyzer API 的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.26_B16353.jpg)

图 7.26 - 使用 Tone Analyzer API 的流程

在这个流程中，功能节点处理从 Twitter 获取的结果值中包含的文本、语调和情感，以便将它们作为单独的调试输出。这样可以更容易地查看结果。

这个流程比您在上一步创建的流程要复杂一些。请按照以下步骤进行流程：

1.  创建一个 Twitter ID（Twitter 账户）并在您的 Twitter 开发者帐户上创建一个应用程序，以便通过您的 Twitter 账户验证访问推文。

1.  在 Twitter 开发者的**项目和应用**下访问**概述**，然后单击**创建应用**按钮：![图 7.27 - 在 Twitter 开发者上创建应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.27_B16353.jpg)

图 7.27 - 在 Twitter 开发者上创建应用程序

1.  使用任何字符串设置**应用程序名称**，然后单击**完成**按钮。![图 7.28 - 设置您的应用程序名称](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.28_B16353.jpg)

图 7.28 - 设置您的应用程序名称

1.  之后，请检查**访问令牌和访问令牌密钥**区域。

您将看到令牌。请注意并保存您的访问令牌和访问令牌密钥。这些也将用于**twitter in**节点的设置：

![图 7.29 - 记下您的令牌和令牌密钥](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.29_B16353.jpg)

图 7.29 - 记下您的令牌和令牌密钥

1.  将**twitter in**节点放置在您的工作区，并双击它以打开设置窗口：![图 7.30 - 放置 twitter in 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.30_B16353.jpg)

图 7.30 - 放置 twitter in 节点

1.  单击设置窗口上的编辑（铅笔图标）按钮以编辑您的 Twitter 信息：![图 7.31 - 编辑 Twitter 属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.31_B16353.jpg)

图 7.31 - 编辑 Twitter 属性

1.  设置您的 Twitter ID，API 密钥和令牌。

**API 密钥**、**API 密钥密钥**、**访问令牌**和**访问令牌密钥**的值应从*步骤 8*中的文本编辑器中获取。

1.  设置这些设置后，请单击**添加**按钮返回到**twitter in**节点的主设置窗口：![图 7.32 - 配置您的 Twitter 信息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.32_B16353.jpg)

图 7.32 - 配置您的 Twitter 信息

1.  选择`#nodered`作为标签。您可以为**名称**设置任何名称。

1.  最后，单击**完成**按钮以完成添加这些设置并关闭窗口：![图 7.33 - 完成节点中 Twitter 的设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.33_B16353.jpg)

图 7.33 - 完成节点中 Twitter 的设置

1.  将**情感**节点放置在您的工作区。它将在**twitter in**节点之后连接。

对于这个节点，不需要设置或更改任何属性：

![图 7.34 - 放置情感节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.34_B16353.jpg)

图 7.34 - 放置情感节点

1.  按顺序在您的工作区上的**情感**节点之后放置**情感分析器 v3**节点：![图 7.35 - 放置情感分析器 v3 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.35_B16353.jpg)

图 7.35 - 放置情感分析器 v3 节点

1.  打开**情感分析器 v3**节点的设置面板，并将**方法**和**URL**属性设置如下：

a. **名称**：您想要命名的任何字符串

b. **方法**：**一般语调**

c. **version_date**：**多个语调**

d. **语调**：**全部**

e. **句子**：**真**

f. **内容类型**：**文本**：

![图 7.36 - 配置情感分析器 v3 节点属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.36_B16353.jpg)

图 7.36 - 配置情感分析器 v3 节点属性

1.  按顺序在您的工作区上的**情感分析器 v3**节点之后放置**功能**节点：![图 7.37 - 放置功能节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.37_B16353.jpg)

图 7.37 - 放置功能节点

1.  打开**function**节点的设置面板，并使用以下源代码编写 JavaScript：

```js
msg.payload = {
    "text" : msg.payload,
    "tone" : msg.response,
    "sentiment" : msg.sentiment
};
return msg;
```

有关**function**节点的编码，请参考以下屏幕截图：

![图 7.38 - 功能节点的 JavaScript 源代码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.38_B16353.jpg)

图 7.38 - 功能节点的 JavaScript 源代码

您可以在这里获取代码：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/format-payload.js`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/format-payload.js)。

1.  最后，放置三个`msg.payload.text`：对于`msg.payload.tone`：对于`msg.payload.sentiment`：对于**调试**选项卡

有关布线说明，请参阅*图 7.26*。我们已经完成了流程节点的配置。

## 测试流程

流程现在已经完成。当您点击`twitter in`节点连接到您的 Twitter 帐户时，它将自动检索符合您标准的推文并处理后续流程。

这是自动完成的，因此您无需采取任何特殊操作。

在这里，它被设置为获取所有具有`#nodered`作为标签的推文。如果您没有收到很多推文，这意味着没有创建包含指定标签的推文，请更改`twitter in`节点中设置的标签并重试。

此流程的所有处理结果将显示在**调试**选项卡中。

从获取的推文中提取推文正文并显示的是`msg.payload.text`：

![图 7.39 - 获取推文正文的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.39_B16353.jpg)

图 7.39 - 获取推文正文的结果

从获取的推文中提取和显示检测到的情绪的是`msg.payload.tone`：

![图 7.40 - 从推文中的语调分析结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.40_B16353.jpg)

图 7.40 - 从推文中的语调分析结果

从获取的推文中判断情感是积极还是消极的是`msg.payload.sentiment`：

![图 7.41 - 推文情感的结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_7.41_B16353.jpg)

图 7.41 - 推文情感的结果

恭喜！您已成功调用 Watson API 创建了一个示例流。如果您没有完全成功创建此流程，您也可以在此处下载此流程定义文件：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/get-sentiment-twitter-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter07/get-sentiment-twitter-flows.json)。

# 总结

在本章中，我们学习了如何创建调用两种类型的 Web API 的示例流（应用程序）。我们逐渐习惯于创建复杂的流程。在 Node-RED 中经常发现调用 Web API 的用例。我们在这里学到的流程创建方法将帮助我们将来创建更复杂的流程。

在下一章中，让我们了解一个可以与 GitHub 等存储库集成的项目功能，这是从 Node-RED 版本 1.0 添加的功能。


# 第八章：使用 Git 的项目功能

在本章中，您将学习到一个非常有用的**项目**功能。Node-RED 的项目功能是一种使用 Git 在 Node-RED 流程编辑器上进行版本管理的工具/功能。实际上，默认情况下是禁用的。启用此功能可以让您以一种新的方式管理您的流程。我相信许多开发人员熟悉 GitHub 和 GitLab 等 Git 服务。Node-RED 的项目功能使用 Git 和 GitHub 进行版本控制，因此我认为这非常容易理解。

以下是本章将涵盖的主题：

+   启用项目功能

+   使用 Git 存储库

+   连接远程存储库

在本章结束时，您将能够了解如何使用项目功能，如何将您自己的 Git 存储库连接到 Node-RED 流程编辑器，并如何使用版本控制工具 Git 管理流程作为项目。

在本章结束时，您将掌握如何使用项目功能并使用它制作应用程序。您可以在 GitHub 或 GitLab 等任何托管的 Git 服务中使用它。

# 技术要求

要在本章中取得进展，您将需要以下内容：

+   您可以通过官方网站创建 GitHub 帐户：[`github.com/`](https://github.com/)。

+   需要通过官方网站安装的 Git 客户端工具：[`git-scm.com/downloads`](https://git-scm.com/downloads)。

# 启用项目功能

例如，在您想要管理自己的流程同时与他人共享它，或者您想要更新他人创建的流程的情况下，当团队仅使用 Node-RED 流程编辑器时，开发会很困难。

Node-RED 的项目功能是一种管理与您制作的每个流程相关的文件的方法/功能。它涵盖了使用 Node-RED 可共享的创建应用程序所需的所有文件。

这些都受 Git 存储库支持。也就是说，所有文件都有版本。这使开发人员能够与其他用户合作。

在 Node-RED 版本 1.x 上，默认情况下禁用项目功能，因此必须在名为`settings.js`的`config`文件中启用它。

重要提示

在 Node-RED 的本地环境中创建项目时，到目前为止创建的流程可能会被覆盖为空白表格。您可以通过互联网下载此文档中创建的所有流程的流程配置的 JSON 文件，但是如果您在本地环境中的 Node-RED 中创建了自己的流程，则建议导出流程配置文件。

我们在本书中创建的所有流程定义和 JSON 文件都可以在此处下载：[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)。

现在让我们尝试项目功能。我们将在本地环境（如 macOS 或 Windows）上使用独立版本的 Node-RED。为了使用项目功能，我们首先需要启用它。让我们按照以下步骤启用它：

1.  需要重写`settings.js`文件以启用/禁用项目功能。首先找到此文件。`settings.js`文件可以在存储所有用户配置的 Node-RED 用户目录中找到。

在 Mac 上，默认情况下，此文件位于以下路径下：

`/Users/<User Name>/.node-red/settings.js`。

在 Windows 上，默认情况下，此文件位于以下路径下：

`C:\Users\<User Name>\.node-red\settings.js`

1.  编辑`settings.js`文件。可以使用任何文本编辑器打开`settings.js`。我在这里使用了`vi`。使用以下命令打开`settings.js`：

```js
$ vi /Users/<User Name>/.node-red/settings.js 
```

重要提示

请将命令替换为适用于您的环境的命令。

1.  编辑您的`settings.js`文件，并在`module.exports`块内的`editorTheme`块中设置`true`，以启用项目功能：

```js
module.exports = {
   uiPort: process.env.PORT || 1880,
   …
   editorTheme: {
       projects: {
           enabled: true
       }
   },
   …
}
```

1.  保存并关闭`settings.js`文件。

1.  通过运行以下命令重新启动 Node-RED 以启用我们修改的设置：

```js
$ node-red 
```

我们现在已成功启用了 Node-RED 的项目功能。

要使用此功能，您需要访问 Git 和 ssh-keygen 命令行工具。Node-RED 在启动时检查它们，并在缺少任何工具时通知您。

如果设置完成没有任何问题，并且您已重新启动 Node-RED，则项目功能将可用。接下来，让我们设置 Git 存储库以供使用。

# 使用 Git 存储库

我们在上一节中启用了项目功能。重新打开流程编辑器，您将被提示使用当时创建的流程内容创建您的第一个项目。这将是欢迎屏幕：

![图 8.1 - 欢迎屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.1_B16353.jpg)

图 8.1 - 欢迎屏幕

我们需要设置 Git 等版本控制客户端。如前所述，Node-RED 的项目功能使用 Git 作为版本控制工具。与常规 Git 一样，您可以根据项目管理文件更改，并根据需要与远程存储库同步。

Git 跟踪谁做出了更改。它与您的用户名和电子邮件地址一起工作。用户名不必是您的真实姓名；您可以使用任何您喜欢的名称。

如果您的本地设备已经配置了 Git 客户端，Node-RED 将查找这些设置。

首先，在您的本地环境中执行版本控制。它利用了您本地环境中安装的 Git 客户端的功能。如果您尚未安装 Git，请提前安装。

现在，按照以下步骤在 Node-RED 流程编辑器上创建项目：

1.  首先，让我们创建一个项目。这非常容易。在项目创建窗口中输入项目名称和描述。

1.  命名流程文件。默认情况下，它已命名为`flow.json`。

换句话说，Node-RED 会自动将当前在流程编辑器上配置的流程迁移到一个新项目中。保持默认名称即可。当然，如果您愿意，也可以在此处选择重命名。

如果您将项目发布在 GitHub 等公共网站上，加密凭据文件是个好主意。

如果选择加密，必须创建一个用于加密的密钥。该密钥不包括在项目中，因此如果与某人共享项目，则需要单独向克隆项目的用户提供凭据文件解密密钥。

1.  在添加所需信息后，单击**创建项目**按钮：![图 8.2 - 项目屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.2_B16353.jpg)

图 8.2 - 项目屏幕

恭喜！您已创建了您的第一个项目。

1.  接下来，检查项目历史。我们可以在 Node-RED 流程编辑器上使用版本控制功能。您可以通过单击右上角的**项目历史**按钮访问项目历史面板：![图 8.3 - 项目历史面板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.3_B16353.jpg)

图 8.3 - 项目历史面板

1.  您可以在此面板上看到没有更改的项目。要检查更改历史功能是否已启用，请在此工作区上创建一个流程。

如果您经常使用 Git 或 GitHub，您应该能够通过查看此面板的结构来理解每个项目的含义和作用。如果项目下的文件结构或内容发生变化，目标文件将显示在**本地更改**区域。当您将更改移动到提交阶段（即添加时），目标文件的显示将移动到**要提交的更改**区域。如果输入提交消息并完成提交，版本将增加一次。

这与 Git 客户端所做的完全相同。

1.  创建一个简单的流程。您可以创建任何您选择的流程，例如，我在`flow.json`文件中使用了一个`flow.json`文件，这是整个流程的配置文件，已经更新。因此，`flow.json`已被识别为 Git 管理中要更改的文件：![图 8.5 - Node-RED 认识到 flow.json 已更改](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.5_B16353.jpg)

图 8.5-Node-RED 已经意识到 flow.json 已更改

1.  现在，让我们遵循 Git 的规范并继续进行。首先，将更改的文件放在提交阶段。这是 Git 的`git add`命令。

1.  单击`flow.json`文件已从**本地更改**区域移动到**提交**区域。

1.  接下来，让我们提交`flow.json`中的更改。单击`git commit`命令：![图 8.7-单击提交按钮提交文件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.7_B16353.jpg)

图 8.7-单击提交按钮提交文件

1.  单击**提交**按钮后，将打开提交注释窗口。请在此处输入提交注释，然后单击**提交**按钮：![图 8.8-单击提交按钮完成提交过程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.8_B16353.jpg)

图 8.8-单击提交按钮完成提交过程

1.  提交现在已完成。最后，让我们检查**提交历史**区域。您会看到已创建一个新版本作为更改历史：

![图 8.9-已添加新历史](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.9_B16353.jpg)

图 8.9-已添加新历史

在创建项目后，您可以像往常一样使用 Node-RED 编辑器。

现在，让我们为 Node-RED 流编辑器添加一个新的用户界面以实现项目功能。

## 访问项目设置

您正在处理的项目将显示在右侧窗格的顶部。在项目名称旁边，还有一个**显示项目设置**按钮：

![图 8.10-信息面板上的项目信息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.10_B16353.jpg)

图 8.10-信息面板上的项目信息

您还可以从主菜单下的“项目 | 项目设置”选项中访问**项目设置**屏幕：

![图 8.11-如何通过主菜单访问项目设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.11_B16353.jpg)

图 8.11-如何通过主菜单访问项目设置

当显示**项目设置**面板时，您会看到每个设置有三个选项卡：

+   此项目的`README.md`文件

+   **依赖项**：管理项目的节点列表

+   **设置**：管理项目设置和远程存储库：

![图 8.12-项目设置面板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.12_B16353.jpg)

图 8.12-项目设置面板

如果要检查和修改 Git 设置，可以通过主菜单访问设置面板：

![图 8.13-用户设置面板上的 Git 配置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.13_B16353.jpg)

![图 8.13-用户设置面板上的 Git 配置现在您知道如何在本地环境中进行版本控制。下一步是了解如何连接远程存储库，比如 GitHub 服务。# 连接远程存储库现在，让我们学习如何将 Node-RED 连接到 GitHub 等远程存储库。在这里，我们将使用 GitHub 服务作为远程存储库。这就像通过 Node-RED 连接本地 Git 和远程 GitHub 一样。这并没有什么特别之处。对于经常使用 Git/GitHub 的人来说，这是很熟悉的，但它与 GitHub 用作客户端工具的情况非常相似。您可以很容易地使用 Node-RED 管理版本。通过以下步骤在 GitHub 上创建 Node-RED 项目的远程存储库：1.  首先，转到您的 GitHub 帐户并创建一个存储库。最好使用与您的本地存储库类似的项目名称。我们不会在这里详细介绍如何使用 GitHub，但由于它是一个可以直观使用的服务，我相信任何人都可以在没有任何问题的情况下使用它：![图 8.14-在 GitHub 上创建存储库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.14_B16353.jpg)

图 8.14-在 GitHub 上创建存储库

1.  配置您的 Node-RED 项目设置。要做到这一点，请返回到 Node-RED 流编辑器，然后转到**项目设置**以连接本地和远程存储库。打开**项目设置**面板后，单击**添加远程**按钮以配置远程存储库信息：![图 8.15 - 在项目设置面板上点击添加远程按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.15_B16353.jpg)

图 8.15 - 在项目设置面板上点击添加远程按钮

1.  请输入您在 GitHub 上创建的存储库 URL，然后单击**添加远程**按钮：![图 8.16 - 设置您的 GitHub 存储库的 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.16_B16353.jpg)

图 8.16 - 设置您的 GitHub 存储库的 URL

1.  单击设置面板右上角的**关闭**按钮以完成此配置。

1.  接下来，合并存储库。

GitHub 上的远程存储库现在已连接到您本地环境中的 Git 存储库。但它们尚未同步。您只需在本地拉取远程并进行合并。要做到这一点，请在侧边信息菜单中选择**历史**面板，然后在**提交历史**面板上单击**管理远程分支**按钮以连接到您的远程存储库：

![图 8.17 - 设置您的 GitHub 存储库的 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.17_B16353.jpg)

图 8.17 - 设置您的 GitHub 存储库的 URL

1.  选择您要推送的远程分支。通常会选择**origin/master**分支：![图 8.18 - 选择您的远程分支](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.18_B16353.jpg)

图 8.18 - 选择您的远程分支

这里，远程和本地之间存在差异，因为我们已经在本地创建了流程，并使用本地 Git 进行了版本控制。在这种情况下，您需要在将本地内容推送到远程之前，将远程内容拉取到本地。

1.  单击**pull**按钮：![图 8.19 - 从远程存储库拉取提交](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.19_B16353.jpg)

图 8.19 - 从远程存储库拉取提交

在途中会显示冲突的消息，但请继续进行合并。在合并过程中，将会询问您是要应用远程更改还是本地更改。在这种情况下，请应用本地端的更改以完成合并。

操作完成后，您将看到您的本地分支已与**提交历史**面板上的远程分支合并：

![图 8.20 - 合并远程和本地存储库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.20_B16353.jpg)

图 8.20 - 合并远程和本地存储库

1.  在此之后，选择**管理远程分支**按钮（上下箭头）：![图 8.21 - 点击管理远程分支按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.21_B16353.jpg)

图 8.21 - 点击管理远程分支按钮

1.  选择要推送的分支，然后单击**push**按钮将这些更改发送（推送）到远程存储库：

![图 8.22 - 将更改发送到远程存储库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_8.22_B16353.jpg)

图 8.22 - 将更改发送到远程存储库

恭喜！现在您已经学会了如何在 Node-RED 上使用项目功能，您还可以将 Node-RED 的本地存储库连接到远程存储库。

# 摘要

在本章中，您学会了如何启用 Node-RED 的项目功能，并使用 GitHub 上创建的远程存储库集成本地版本控制 Git。在未来使用 Node-RED 开发团队时，这将非常有用。

在下一章中，我们将使用此项目功能在本地克隆待办事项应用程序的存储库。通过一起学习本章和下一章，您应该对项目功能有更深入的了解。


# 第三部分：实际问题

在本节中，读者将掌握使用 Node-RED 制作逼真且可用的应用程序。Node-RED 中的实际应用程序通过分别执行 Node.js 的详细处理来传递数据。在本节的所有实践教程之后，您将掌握如何使用 Node-RED。

在本节中，我们将涵盖以下章节：

+   *第九章*, [*使用 Node-RED 创建待办事项应用程序*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=512953ef-6dfc-814f-371f-5ed08ccc50fa)

+   *第十章*, [*处理树莓派上的传感器数据*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=a94f46a1-0f4c-b0bf-dbd3-5ed08cde062b)

+   *第十一章*, [*在 IBM Cloud 中创建服务器端应用程序可视化数据*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=1aa76ff2-754e-80de-c7a6-5ed08cda9fb3)

+   *第十二章*, [*使用 Slack 和 IBM Watson 开发聊天机器人应用程序*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=1de3a1d9-b6a5-941e-946d-5ed08cd623d0)

+   *第十三章*, [*创建并发布自己的 Node-RED 库中的节点*](https://epic.packtpub.com/index.php?module=oss_Chapters&action=DetailView&record=33a4c174-083a-60db-b0d9-5ed08c751c25)


# 第九章：使用 Node-RED 创建 ToDo 应用程序

在本章中，我们将在 Node-RED 中创建一个简单的 ToDo 应用程序。这是一个简单直接的教程，可以帮助你在 Node-RED 中创建应用程序（流程）。我们将使用上一章中介绍的项目功能，因此本章也将作为该功能的复习。

让我们从以下四个主题开始：

+   为什么应该使用 Node-RED 进行 Web 应用程序

+   创建数据库

+   如何连接数据库

+   运行应用程序

到本章结束时，你将掌握如何在 Node-RED 上制作一个带有数据库的简单 Web 应用程序。

# 技术要求

要完成本章，你需要以下内容：

+   Node.js 12.x 或更高版本 ([`nodejs.org/`](https://nodejs.org/)).

+   CouchDB 3.x ([`couchdb.apache.org/`](https://couchdb.apache.org/)).

+   一个 GitHub 账户，可从[`github.com/`](https://github.com/)获取。

+   本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter09`中找到。

# 为什么应该使用 Node-RED 进行 Web 应用程序

到目前为止，本书已经解释了 Node-RED 是**物联网**(**IoT**)的易于使用的工具。在物联网领域，Node-RED 被用作解决方案的情况很多。

然而，最近，Node-RED 被认为是一个用于创建 Web 应用程序以及物联网的工具。

我认为其中一个原因是*无代码*和*低代码*的理念已经在世界范围内得到了广泛传播。如今，了解基于流的编程工具和可视化编程工具的人数正在增加，并且它们正在被用于各个领域。

Node-RED 是使用 Node.js 制作的，自然而然地可以用于 Web 应用程序。

我们在上一章学习的项目功能，与 Git/GitHub 合作，也可能成为 Web 应用程序开发文化流程的一部分。

在本章中，我们将创建一个非常适合作为教程开发的 ToDo 应用程序。

要创建的应用程序的整体图景如下：

![图 9.1 – 我们将创建的应用程序概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.1_B16353.jpg)

图 9.1 – 我们将创建的应用程序概述

*图 9.1*概述了应用程序的概况。该应用程序将从客户端 PC 浏览器访问。该应用程序的用户界面是使用 Node.js 框架**TodoMVC**和**Todo-Backend**制作的。数据处理编程是通过将 CouchDB 连接为存储数据的 Node-RED 构建的。

在这个应用程序中，用户界面和后端应用程序都不是基于 Node-RED 构建的。

该应用程序是直接在本地主机上作为 Node.js 应用程序实现的。我们将在稍后的步骤中介绍这一点，当访问 Node-RED 运行的本地主机端口时，我们将设置它重定向到本地主机 Node.js 应用程序。

在我们进行实际操作示例之前，我们应该了解一下这个应用程序使用了两个框架。我们将在这个实际操作教程中使用 Node-RED 制作我们的 ToDo 应用程序。该应用程序是通过这两个 Node.js 框架实现的：

+   **TodoMVC**: [`todomvc.com/`](http://todomvc.com/)

![图 9.2 – TodoMVC](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.2_B16353.jpg)

图 9.2 – TodoMVC

+   **Todo-Backend**: [`todobackend.com/`](https://todobackend.com/)

![图 9.3 – Todo-Backend](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.3_B16353.jpg)

图 9.3 – Todo-Backend

正如你可以从可以通过链接 Web 应用程序框架创建 Node-RED 流的事实中看出来，Node-RED 与使用 Node.js 实现的 Web 应用程序及其周围的框架非常配合。这个实际操作教程将帮助你了解为什么 Node-RED 在以无代码/低代码方式开发 Web 应用程序方面如此受欢迎。

接下来，我们将进行实际操作步骤。

# 创建数据库

我们在上一节介绍了应用程序的整体情况，但更具体地，这个应用程序使用 CouchDB 作为数据库。在这个实践教程中，我们将创建一个在本地主机上运行的 Node-RED 应用程序。因此，你也需要在自己的本地机器上安装 CouchDB。

让我们按照以下步骤安装它：

1.  访问 CouchDB 网站[`couchdb.apache.org/`](https://couchdb.apache.org/)，然后点击**DOWNLOAD**按钮：![图 9.4 - 点击 DOWNLOAD 按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.4_B16353.jpg)

图 9.4 - 点击 DOWNLOAD 按钮

1.  根据本地机器上运行的系统选择一个文件：![图 9.5 - 选择文件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.5_B16353.jpg)

图 9.5 - 选择文件

1.  解压下载的 ZIP 文件并运行应用程序文件以启动 CouchDB，一旦文件下载完成：![图 9.6 - 启动 CouchDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.6_B16353.jpg)

图 9.6 - 启动 CouchDB

1.  运行 CouchDB 应用程序文件会启动浏览器并打开 CouchDB 管理控制台。如果没有自动打开，也可以从应用程序菜单手动打开：![图 9.7 - 打开 CouchDB 管理控制台](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.7_B16353.jpg)

图 9.7 - 打开 CouchDB 管理控制台

1.  在 CouchDB 管理控制台中创建一个新的数据库。使用名称`todos`创建它。不需要分区。最后，点击**Create**按钮完成：![图 9.8 - 创建名为"todos"的新数据库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.8_B16353.jpg)

图 9.8 - 创建名为"todos"的新数据库

现在你可以在 CouchDB 管理控制台上看到名为**todos**的数据库：

![图 9.9 - 检查你创建的数据库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.9_B16353.jpg)

图 9.9 - 检查你创建的数据库

1.  创建一个管理员用户来访问这个数据库。为此，访问`admin`设置为用户名，`adminpass`设置为密码：

![图 9.10 - 创建服务器管理员用户账户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.10_B16353.jpg)

图 9.10 - 创建服务器管理员用户账户

这完成了所有与 CouchDB 相关的设置。接下来，让我们继续设置我们的 Node-RED 端。

# 如何连接到数据库

现在数据库实际上已经创建了，我们将朝着实践教程迈进，我们将从 GitHub 克隆 Node-RED 流，并实现从 Node-RED 流连接到该数据库。使用你在上一章学到的项目功能连接到你的 GitHub 存储库，加载准备好的流定义文件，并在本地环境中在 Node-RED 上实现它。由于你在上一章已经做过这个操作，这次不需要创建新的流。

## 配置 Node-RED

你需要做的第一件事是更改 Node-RED 流编辑器的本地主机路径（URL）。目前，你可以在`localhost:1880`访问流编辑器，但为了将由这个实践教程创建的 Web 应用程序的路径（URL）更改为`localhost:1880`，我们需要将流编辑器的路径更改为`localhost:1880/admin`。

这是因为你必须将 Node-RED 流编辑器的根路径移动到本地主机上运行的 Node.js ToDo 应用程序的相同端口上。

要配置 Node-RED，请按照以下步骤操作：

1.  打开设置文件（`~/.node-red/settings.js`）。

1.  找到你打开的`settings.js`文件中的`httpAdminRoot`设置。

这会更改你访问 Node-RED 流编辑器的路径。默认情况下，它使用根路径`/`，但是我们想要将其用于我们的应用程序，所以我们可以使用这个设置来移动编辑器。默认情况下是注释掉的，所以通过删除行首的`//`取消注释：

![图 9.11 - 取消注释 httpAdminRoot 以启用流编辑器路径](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.11_B16353.jpg)

图 9.11 - 取消注释 httpAdminRoot 以启用流编辑器路径

1.  您现在已将流程编辑器移至`/admin`。在本地计算机上重新启动 Node-RED，并访问`http://localhost:1880/admin` URL 以运行您的 Node-RED 流程编辑器。

接下来，让我们克隆项目。

## 克隆 Node-RED 项目

这个实践教程为您提供了一个 Node-RED 项目的示例。在将其克隆到本地 Node-RED 实例之前，您应该首先分叉该项目，以便您有自己的副本可供使用。

分叉后，您需要将项目克隆到您的 Node-RED 实例中。

要克隆您的项目，请按照以下步骤进行：

1.  在[`github.com/taijihagino/node-red-todo-app`](https://github.com/taijihagino/node-red-todo-app)上打开示例项目。

1.  单击**fork**按钮以创建存储库的自己的副本。

1.  复制您分叉的存储库的 URL。

1.  通过`http://127.0.0.1:1880/admin/`访问 Node-RED 编辑器。

1.  在**项目欢迎**屏幕上单击**克隆存储库**按钮。如果您已经关闭了该屏幕，可以从主菜单中使用**项目 | 新建**重新打开它：![图 9.12 - 单击项目菜单下的新建以克隆存储库](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.12_B16353.jpg)

图 9.12 - 单击项目菜单下的新建以克隆存储库

1.  在**项目**屏幕上，提供您的存储库 URL、用户名和密码。这些在提交更改到项目时使用。如果您的本地 Git 客户端已配置，它将选择这些值。将**凭据加密密钥**字段留空是可以的：![图 9.13 - 提供您的 GitHub 存储库信息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.13_B16353.jpg)

图 9.13 - 提供您的 GitHub 存储库信息

1.  这将克隆存储库到一个新的本地项目并开始运行它。在工作区中，您可以看到实现应用程序的每个部分的流程。

您将在所有**cloudant**节点上看到一些错误，但这些错误的原因来自连接设置。这些设置将在后续步骤中进行设置，所以现在不是问题：

![图 9.14 - 您克隆的流程概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.14_B16353.jpg)

图 9.14 - 您克隆的流程概述

1.  该项目还包括一些需要由运行时提供的静态资源。为此，需要对如何访问此 Web 应用程序的设置文件进行一些更改。

首先，您必须在本地文件系统中找到您新克隆的项目。它将在`<node-red root>/projects/<name-of-project>`中。在该文件夹中，您将找到一个名为`public`的文件夹。这包含了此 ToDo 应用程序项目的静态资源，例如以下内容：

```js
/Users/taiji/.node-red/projects/node-red-todo-app
```

以下图像是一个示例。请在检查您自己的文件路径时使用它作为参考：

![图 9.15 - ToDo 应用程序项目文件夹](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.15_B16353.jpg)

图 9.15 - ToDo 应用程序项目文件夹

1.  编辑您的设置文件（`~/.node-red/settings.js`），并在该文件中找到`httpStatic`属性。通过删除行首的`//`来取消注释，并使用绝对路径到`public`文件夹来设置其值。以下图像中的路径仅为示例；请用您的路径替换它：![图 9.16 - 取消注释 httpStatic 并设置您的应用程序项目路径](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.16_B16353.jpg)

图 9.16 - 取消注释 httpStatic 并设置您的应用程序项目路径

1.  重新启动 Node-RED。

通过重新启动 Node-RED，更改的`settings.js`内容将被重新加载和应用。

接下来，让我们配置 Node-RED 和 CouchDB 连接。

## 配置 Node-RED 和 CouchDB 连接

正如您所知，我们正在使用**cloudant**节点连接到 CouchDB，对吗？

Cloudant 是基于 Apache CouchDB 的 JSON 数据库。Cloudant 具有 CouchDB 风格的复制和同步功能，因此您可以使用 Node-RED 提供的**cloudant**节点连接到 CouchDB。

如前所述，Node-RED 上的**cloudant**节点出现错误。这是因为从 GitHub 克隆时，本地系统对 CouchDB 的连接信息未正确设置。

在这里，我们将纠正 Node-RED 上**cloudant**节点的设置。

现在，根据以下步骤进行设置：

1.  双击任何**cloudant**节点以打开设置屏幕。如果您在其中设置了一个**cloudant**节点，则同一流程上的所有**cloudant**节点的设置都将被更新，因此您选择哪个**cloudant**节点并不重要：![图 9.17–双击任何 cloudant 节点打开设置屏幕](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.17_B16353.jpg)

图 9.17–双击任何 cloudant 节点打开设置屏幕

1.  点击**cloudant**节点设置屏幕上**服务器**右侧的**铅笔标记**按钮，打开 CouchDB 的连接信息设置屏幕：![图 9.18–点击铅笔标记按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.18_B16353.jpg)

图 9.18–点击铅笔标记按钮

1.  当打开 CouchDB 的连接信息设置屏幕时，转到`http://localhost:5984`（如果您的 CouchDB 安装在不同的端口上，请相应地替换），并将**用户名**设置为您之前设置的 CouchDB 服务器管理员用户。对于**密码**，输入服务器管理员密码。

1.  在输入所有内容后，点击右上角的**更新**按钮返回到上一个屏幕：![图 9.19–设置您的 CouchDB URL 和服务器管理员用户名/密码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.19_B16353.jpg)

图 9.19–设置您的 CouchDB URL 和服务器管理员用户名/密码

1.  点击**完成**按钮并返回到您的 Node-RED 流程编辑器的工作区。您将看到所有**cloudant**节点旁边的**连接**上有一个绿色方块的消息：

![图 9.20–检查所有 cloudant 节点是否无错误](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.20_B16353.jpg)

图 9.20–检查所有 cloudant 节点是否无错误

完美，您已成功配置了在 Node-RED 中启动 ToDo 应用程序的设置。接下来，让我们运行这个 ToDo 应用程序。

# 运行应用程序

如果一切正常，您应该能够在浏览器中打开`http://localhost:1880`并看到应用程序。

现在，让我们通过以下步骤确认 ToDo 应用程序是否正常工作：

1.  访问`http://localhost:1880`打开您的 ToDo 应用程序。

如果您在打开`localhost:1880`时看到 Node-RED 流程编辑器，则表示`httpAdminRoot`设置未启用，请再次检查您的`settings.js`文件。

当您访问此 URL 时，应显示以下屏幕：

![图 9.21–打开您的 ToDo 应用程序](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.21_B16353.jpg)

图 9.21–打开您的 ToDo 应用程序

1.  对于此测试，任何 ToDo 项目都可以，因此输入任何单词作为示例任务。在这里，我输入了`报告我的任务`：![图 9.22–输入一个示例 ToDo 项目](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.22_B16353.jpg)

图 9.22–输入一个示例 ToDo 项目

1.  在文本框中输入值时，如果按下*Enter*键，该值将被注册为一个 ToDo 项目。在下面的截图中，我们可以看到它看起来已经在应用程序中注册了：![图 9.23–您输入的 ToDo 项目已被注册](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.23_B16353.jpg)

图 9.23–您输入的 ToDo 项目已被注册

让我们检查一下屏幕上显示为已注册的 ToDo 项目是否在数据库中注册。

1.  打开 CouchDB 管理控制台。

如果您忘记如何打开它，可以从 CouchDB 应用程序菜单中选择**打开管理控制台**选项打开它。如果重新打开管理控制台，或者时间已过，可能会要求您登录。在这种情况下，请使用您设置的服务器管理员用户名和密码登录。

1.  在侧边菜单中选择**数据库**选项，然后点击**todos**。您将看到您在 ToDo 应用程序上注册的记录。点击记录以查看更多细节：![图 9.24–检查您的 todos 数据库上的记录](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.24_B16353.jpg)

图 9.24 - 检查您的待办事项数据库中的记录

1.  您将看到您选择的记录的详细信息。数据是您通过 ToDo 应用程序注册的确切项目，即**报告我的任务**：

![图 9.25 - 检查结果](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_9.25_B16353.jpg)

图 9.25 - 检查结果

恭喜！这完成了从 GitHub 克隆 ToDo 应用程序并在 Node-RED 中实现的实践教程。

本教程的重点是使用 Node-RED 的项目功能从 GitHub 存储库克隆和执行应用程序项目。

这个实践教程帮助我们了解，我们不一定需要在使用 Node-RED 制作的 Web 应用程序中实现用户界面和服务器端业务逻辑。我们看到 Node-RED 的一个特点是，我们构建的 Web 应用程序的用户界面和服务器端业务逻辑位于 Node-RED 之外，而仅数据处理功能（如访问数据库）由 Node-RED 内部完成。

我们使用的 GitHub 存储库包含两件事，即处理数据的 Node-RED 流程和在 Node-RED 之外运行的 ToDo 应用程序。这里的重点是使用 Node-RED 的项目功能从 GitHub 存储库克隆和执行应用程序项目。

# 摘要

在本章中，我们通过实践教程的形式体验了如何使用项目功能在 Node-RED 上实际运行 Web 应用程序。当然，这只是在 Node-RED 上创建 Web 应用程序（包括 UI，使用模板节点等）的一种方式。然而，记住这种模式对于您未来的开发任务肯定会有用。

在下一章中，我们将看到一个实际场景，我们将使用 Node-RED 将传感器数据从边缘设备发送到服务器端（云）。


# 第十章：在树莓派上处理传感器数据

在本章中，我们将学习在**物联网**（**IoT**）中使用 Node-RED 处理来自边缘设备的数据的处理过程。我们不仅将涵盖数据处理，还将从边缘设备向服务器应用程序发送数据。对于设备，我想使用树莓派。完成本章中的教程后，你将能够处理边缘设备获取的传感器数据。

让我们从以下四个主题开始：

+   从树莓派上的传感器模块获取传感器数据

+   学习 MQTT 协议并使用 MQTT 节点

+   连接到 MQTT 代理

+   检查本地主机上数据的状态

# 技术要求

要在本章中取得进展，你需要以下内容：

+   从[`www.raspberrypi.org/`](https://www.raspberrypi.org/)获取的树莓派

+   本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter10`文件夹中找到

# 从树莓派上的传感器模块获取传感器数据

在本章中，我们将学习如何使用 Node-RED 在树莓派上处理从传感器设备获取的数据，并将数据发布到 MQTT 代理。

对于传感器设备，我们将使用在*第五章*中使用的温湿度传感器，*本地实现 Node-RED*。有关连接和如何在树莓派上启用传感器设备的详细信息，请参阅*第五章*中的每个步骤，*本地实现 Node-RED*。

准备将你的温湿度传感器连接到你的树莓派。这就是边缘设备。你已经在*第五章*中购买并配置了你的边缘设备，*本地实现 Node-RED*。本章不使用光传感器：

+   边缘设备：**树莓派 3** (https://www.raspberrypi.org/)

+   传感器模块：**Grove 树莓派底板，Grove 温湿度传感器（SHT31）** ([`www.seeedstudio.com/Grove-Base-Hat-for-Raspberry-Pi.html`](https://www.seeedstudio.com/Grove-Base-Hat-for-Raspberry-Pi.html), [`www.seeedstudio.com/Grove-Temperature-Humidity-Sensor-SHT31.html`](https://www.seeedstudio.com/Grove-Temperature-Humidity-Sensor-SHT31.html))

## 准备设备

请准备好设备，以收集树莓派上的温湿度传感器数据，步骤如下：

1.  将传感器模块连接到你的树莓派。

当所有设备准备就绪时，连接树莓派和 Grove 树莓派底板，并将 Grove 温湿度传感器（SHT31）连接到 I2C 端口（任何 I2C 端口都可以）：

![图 10.1 – 连接温湿度传感器到你的树莓派](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.1_B16353.jpg)

图 10.1 – 连接温湿度传感器到你的树莓派

1.  将你的树莓派连接到互联网。

我们将继续从树莓派连接到服务器端，所以请确保通过 Wi-Fi 连接到互联网。当然，你也可以通过使用 LAN 电缆连接到调制解调器来访问互联网。树莓派默认具有 LAN 电缆端口，所以你只需插入 LAN 电缆即可：

![图 10.2 – 将你的树莓派连接到互联网](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.2_B16353.jpg)

图 10.2 – 将你的树莓派连接到互联网

这就是我们继续所需的全部内容。接下来，我们将看到如何从传感器节点获取数据。

## 检查 Node-RED 以从传感器设备获取数据

正如你在*第五章*中已经学到的，*本地实现 Node-RED*，从 Grove 树莓派温湿度传感器模块获取数据应该很容易。

以下是从传感器节点获取数据的步骤：

1.  创建一个简单的流程来获取数据。从流程编辑器左侧的调色板中选择三个节点，即一个**inject**节点，一个**grove-temperature-humidity-sensor-sht3x**节点和一个**debug**节点，并将它们拖放到工作区中放置。

1.  放置它们后，请按照以下图示将它们依次连接：![图 10.3 - 放置和连接节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.3_B16353.jpg)

图 10.3 - 放置和连接节点

1.  检查**grove-temperature-humidity-sensor-sht3x**节点的设置。要检查设置，请双击**grove-temperature-humidity-sensor-sht3x**节点以打开设置屏幕。

在此设置屏幕上没有要设置的值或项目。您只需确保端口显示为**I2C**。检查后，关闭设置屏幕。

确保您看到一个蓝色的方形图标和**grove-temperature-humidity-sensor-sht3x**节点下方的**I2C**文本。这表示 Grove Base 温度/湿度传感器模块已成功连接到您的树莓派。如果此图标的颜色变为红色，则表示模块未正确连接到**I2C**端口，请重新正确连接硬件：

![图 10.4 - 检查端口是否设置为 I2C](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.4_B16353.jpg)

图 10.4 - 检查端口是否设置为 I2C

1.  执行流程并通过单击流程编辑器右上角的**部署**按钮来检查结果以完成部署。

1.  部署成功后，单击**inject**节点上的开关以启动流程：

![图 10.5 - 部署并单击注入节点上的按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.5_B16353.jpg)

图 10.5 - 部署并单击注入节点上的按钮

如果您可以确认在流程编辑器的**debug**选项卡中以 JSON 格式显示了收集到的传感器数据的值，那么它已成功工作。这样，可以从传感器模块获取数据：

![图 10.6 - 确保从传感器模块中可见数据](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.6_B16353.jpg)

图 10.6 - 确保从传感器模块中可见数据

现在我们知道树莓派上的 Node-RED 可以处理传感器数据。让我们学习将这些数据发布到 MQTT 代理的过程。

# 学习 MQTT 协议并使用 MQTT 节点

现在传感器数据已成功获取，让我们将数据发送到服务器。

我们通常选择适合传输内容的协议；例如，在交换邮件时，我们使用 SMTP。目前，HTTP 被用作互联网上的通用协议。

例如，HTTP 用于互联网上的各种通信，如在浏览器中显示网页和在服务器之间交换数据。HTTP 是为在互联网上交换内容而创建的协议。在许多情况下，互联网上的网络设备，如路由器和防火墙，被设置为允许使用 HTTP 通信以用于各种目的，并且 HTTP 与互联网兼容。

在物联网世界中，MQTT 通常用作 HTTP 的通用协议。这意味着 MQTT 协议是物联网世界的标准，就像 HTTP 协议是网络世界的标准一样。

**MQTT**（**MQ Telemetry Transport**的缩写）是由 IBM 和 Eurotech 于 1999 年首次创建的通信协议。2013 年，这一协议的标准化由一个名为 OASIS 的国际标准化组织推动。

MQTT 旨在在 TCP/IP 上使用。简而言之，它专门用于互联网上的**机器对机器**（**M2M**）通信，以及机器与互联网上的其他资源之间的通信。这里所指的*机器*是微型计算机板，如个人电脑和小型 Linux 板（包括树莓派）。

自 1999 年以来，M2M 已经发展，出现了**IoT**这个词，当传统机器通过互联网进行通信时，现在很常用 MQTT。因此，MQTT 是物联网的最佳协议。MQTT 重要的原因之一是它提供了一种轻量级协议来处理窄带网络和低性能设备上的数据：

![图 10.7 – 典型 M2M 通信的概念图](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.7_B16353.jpg)

图 10.7 – 典型 M2M 通信的概念图

从前面的信息中，您可以看到为什么在物联网中使用 MQTT 协议。现在让我们思考 Node-RED 如何使用 MQTT 协议传输数据。

Node-RED 默认提供以下两个与 MQTT 相关的节点：

+   **mqtt in**：**mqtt in**节点连接到 MQTT 代理并订阅指定主题上的消息。

+   **mqtt out**：**mqtt out**节点连接到 MQTT 代理并发布消息：

![图 10.8 – mqtt in 节点和 mqtt out 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.8_B16353.jpg)

图 10.8 – mqtt in 节点和 mqtt out 节点

您可以在 Node-RED 流编辑器的侧边栏的**网络**类别下找到这些。

如果您想为 MQTT 代理设置服务器地址和主题，并使用发布和订阅，可以使用这两个节点。

现在让我们尝试将传感器数据发送到本地 MQTT 代理。

# 连接到 MQTT 代理

现在，让我们通过 Node-RED 将树莓派上的传感器数据发送到 MQTT 代理。在这里，我们将使用流行的 MQTT 代理**Mosquitto**。在本章中，我们将准备设备以将设备数据发送到服务器。实际在服务器端接收和处理数据的任务将在下一章的实际示例中进行演示。因此，在这里，我们将使用 Mosquitto 仅用于检查数据传输是否正确执行。

## Mosquitto

Mosquitto 是根据开源 BSD 许可发布的，并为 MQTT V3.1/v3.1.1 提供代理功能。

它适用于主要的 Linux 发行版，如 RedHat Enterprise Linux，CentOS，Ubuntu 和 OpenSUSE，以及 Windows。它也适用于树莓派等小型计算机。

在本章中，我们将验证边缘设备的传感器数据是否可以通过 MQTT 代理发送到树莓派的本地主机。这非常容易。我相信，如果我们可以以这种方式将数据发送到 MQTT 代理，我们将能够立即在服务器端看到边缘设备的传感器数据。

以下是一个通用配置图，显示了 Mosquitto 的示例用法：

![图 10.9 – Mosquitto 概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.9_B16353.jpg)

图 10.9 – Mosquitto 概述

在本章中，我们将实现从边缘设备到 Mosquitto 发送数据的 Node-RED 流程。下一章将实现使用 IBM Cloud 进行数据可视化。

重要提示

Mosquitto 是一个非常重要和有用的工具，是在 Node-RED 中实现物联网机制的平台。深入了解 Mosquitto 将帮助您使 Node-RED 更广泛地可用。

您可以在[`mosquitto.org/`](https://mosquitto.org/)了解更多关于 Mosquitto 的信息。

现在，让我们在您的树莓派上准备 Mosquitto。

## 准备您的树莓派上的 Mosquitto

在本节中，我们将启用 Mosquitto，以便它可以在树莓派上运行。流程很简单。只需安装 Mosquitto 并启动服务。请按照以下步骤在您的树莓派上准备：

1.  要安装 Mosquitto，请在终端上执行以下命令：

```js
$ sudo apt install mosquitto
```

1.  要启动 Mosquitto 服务，请在终端上执行以下命令：

```js
sudo systemctl start mosquitto
```

启动后，您可以使用以下命令检查 Mosquitto 服务的状态：

```js
sudo systemctl status mosquitto
```

在终端上看起来是这样的：

![图 10.10 – Mosquitto 运行状态](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.10_B16353.jpg)

图 10.10 – Mosquitto 运行状态

1.  要安装 Mosquitto 客户端工具，请在终端上执行以下命令：

```js
$ sudo apt install mosquitto-clients
```

1.  要检查发布和订阅功能，请运行`packt`作为**主题**：

```js
$ sudo apt install mosquitto-clients
$ mosquitto_sub -d -t packt
```

在终端中的显示如下：

![图 10.11 - 开始订阅 Mosquitto 与主题 packt](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.11_B16353.jpg)

图 10.11 - 开始订阅 Mosquitto 与主题 packt

1.  使用另一个终端发送一些文本到这个代理的以下命令：

```js
$ mosquitto_pub -d -t packt -m "Hello Packt!"
```

在终端中的显示如下：

![图 10.12 - 使用主题 packt 发布消息到 Mosquitto](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.12_B16353.jpg)

图 10.12 - 使用主题 packt 发布消息到 Mosquitto

您将在终端订阅到您发布的消息。

现在，您可以使用 Mosquitto 了。接下来，我们将在您的树莓派上的 Node-RED 上实现发布/订阅。

## 制作一个流程来获取传感器数据并将其发送到 MQTT 代理

现在，在您的树莓派上启动 Node-RED 流编辑器，并按照以下步骤创建一个流程：

1.  在之前*检查 Node-RED 是否可以从传感器设备获取数据*部分创建的流程中，在**grove-temperature-humidity-sensor-sht3x**节点之后放置**mqtt out**节点，并将**mqtt in**节点和**debug**节点与**mqtt out 流**分开。请按照以下图示连接它们：![图 10.13 - 放置这些节点并连接它们](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.13_B16353.jpg)

图 10.13 - 放置这些节点并连接它们

1.  编辑`localhost`

1.  端口：`1883`

*可以编辑`packt`

1.  `1`

1.  `true`

设置窗口应该是这样的：

![图 10.14 - 设置 mqtt out 节点的属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.14_B16353.jpg)

图 10.14 - 设置 mqtt out 节点的属性

1.  编辑`localhost`

1.  `1883`

*可以编辑`packt`

1.  `1`

1.  **输出**：**自动检测（字符串或缓冲区）**

设置窗口应该是这样的：

![图 10.15 - 设置 mqtt in 节点的属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.15_B16353.jpg)

图 10.15 - 设置 mqtt in 节点的属性

有了这个，我们已经完成了通过**Mosquitto** MQTT 代理在您的树莓派 localhost 上订阅和发布主题`packt`的流程。接下来，我们将检查我们在 localhost 上的数据状态。

# 检查 localhost 上的数据状态

在本节中，我们将检查从您的树莓派发送的传感器数据是否可以通过 Node-RED 接收到 Mosquitto。

1.  在您的树莓派上的 Node-RED 实例上运行您在上一节中创建的流程。

1.  单击**inject**节点的开关以运行此流程并发布 Grove 温湿度传感器数据：![图 10.16 - 运行发布数据的流](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.16_B16353.jpg)

图 10.16 - 运行发布数据的流

1.  检查已订阅的数据。

当前在这个 Node-RED 实例中有两个流。一个是将数据发布到 Mosquitto MQTT 代理的流，另一个是从该代理订阅数据的流。订阅的流通常处于待机状态，因此当数据被发布时，订阅的数据会自动输出到**debug**选项卡。

1.  检查**debug**选项卡。您应该看到您发布的数据：

![图 10.17 - 检查发布和订阅的结果\](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_10.17_B16353.jpg)

图 10.17 - 检查发布和订阅的结果\

恭喜！现在您知道如何处理树莓派和 Grove Base 传感器模块在边缘设备上获取的传感器数据，并将其发送到 MQTT 代理。

# 摘要

在本章中，通过实际操作教程的形式，我们体验了如何在边缘设备上处理传感器数据并将其发送到 MQTT 代理。这是使用 Node-RED 为物联网创建边缘设备端应用程序的一种方式。

在下一章中，我们将看一个实际的例子，接收传感器数据并通过 Node-RED 在服务器端（云端）进行可视化。


# 第十一章：通过在 IBM Cloud 中创建服务器端应用程序来可视化数据

在本章中，我们将创建一个服务器应用程序，用于可视化从物联网边缘设备发送的数据，使用 Node-RED。对于服务器端应用程序，我想在这里使用 IBM Cloud。通过本章中的教程，您将掌握如何在服务器应用程序上可视化传感器数据。

让我们从以下主题开始：

+   准备一个公共 MQTT 代理服务

+   在边缘设备上从 Node-RED 发布数据

+   在云端 Node-RED 上订阅和可视化数据

在本章结束时，您将掌握如何在云平台上可视化传感器数据。

# 技术要求

要在本章中取得进展，您将需要以下内容：

+   IBM Cloud 帐户：[`cloud.ibm.com/`](https://cloud.ibm.com/)

+   CloudMQTT 帐户：[`cloudmqtt.com/`](https://cloudmqtt.com/)

+   本章中使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter11`文件夹中找到。

# 准备一个公共 MQTT 代理服务

回想一下上一章，*第十章*，*在树莓派上处理传感器数据*。我们将连接到边缘设备（树莓派）的温度/湿度传感器的数据发送到云端，并确认可以在云端观察到数据。

在上一章中，我们检查了如何使用名为**Mosquitto**的服务操作 MQTT 代理。这是为了专注于*从边缘设备发送数据*到 MQTT 代理。

然而，这是一个在树莓派上本地完成的机制。基本上，在尝试实现物联网机制时，MQTT 代理应该位于公共位置，并且可以通过互联网从任何地方访问。

在公共云中托管自己的**Mosquitto** MQTT 代理是可能的，但这会增加一些额外的复杂性，涉及设置和维护。有许多公共 MQTT 服务可用，可以使入门变得更容易。

在本章中，我们将使用名为**CloudMQTT**的服务作为 MQTT 代理，但您可以用您喜欢的服务替换 MQTT 代理部分。您还可以在 IaaS 上发布自己的 MQTT 代理，例如**Mosquitto**，而不是使用 SaaS：

![图 11.1 - CloudMQTT 概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.1_B16353.jpg)

图 11.1 - CloudMQTT 概述

重要提示

MQTT 代理是一个服务器，它接收来自发布者的消息并将其发送给订阅者。

在 PubSub 中传递消息的服务器称为 MQTT 代理。

PubSub 是*发布者*和*订阅者*这两个词的结合：

a) 发布者是传递消息的人。

b) 订阅者是订阅消息的人。

您可以将其视为从客户端接收消息并将其分发给客户端的服务器。

MQTT 与普通的套接字通信不同，它是一对多的通信。换句话说，它有一种机制，可以将一个客户端的消息分发给许多人。这个系统允许我们实时同时向许多人传递消息。

我们现在将学习如何准备**CloudMQTT**。如前所述，**CloudMQTT**是作为 SaaS 发布的 MQTT 代理。如果您不使用**CloudMQTT**，想要使用另一个 SaaS MQTT 代理或在 IaaS 上发布 MQTT 代理，您可以跳过此步骤。但是，使用 MQTT 代理的基本配置信息保持不变，因此我相信这一步将帮助您配置任何 MQTT 代理。

执行以下步骤在**CloudMQTT**上创建一个 MQTT 代理服务：

1.  登录到[`cloudmqtt.com/`](https://cloudmqtt.com/)的**CloudMQTT**。

当您访问网站时，点击窗口右上角的**登录**按钮：

![图 11.2 - CloudMQTT 网站](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.2_B16353.jpg)

图 11.2 - CloudMQTT 网站

如果你已经有了 CloudMQTT 账户，请通过输入你的电子邮件地址和密码登录你的账户：

![图 11.3 - 登录到 CloudMQTT](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.3_B16353.jpg)

图 11.3 - 登录到 CloudMQTT

如果你还没有你的账户，请通过窗口底部的**Sign up**按钮创建一个新账户：

![图 11.4 - 创建你的账户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.4_B16353.jpg)

图 11.4 - 创建你的账户

1.  创建一个实例。

登录后，单击窗口右上角的**Create New Instance**按钮：

![图 11.5 - 创建一个新实例](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.5_B16353.jpg)

图 11.5 - 创建一个新实例

1.  选择一个名称和付款计划。

这个名称是为了你的 MQTT 代理服务。你可以给它任何你想要的名字。我用了`Packt MQTT Broker`。

不幸的是，免费计划**Cute Cat**已经不再可用。所以，我们将在这里选择最便宜的计划**Humble Hedgehog**。这个计划每月需要 5 美元。

使用这个付费服务取决于你。如果你想避免计费，你需要寻找一个免费的 MQTT 代理服务。

选择名称和付款计划后，单击**Select Region**按钮：

![图 11.6 - 选择名称和付款计划](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.6_B16353.jpg)

图 11.6 - 选择名称和付款计划

1.  选择一个区域和数据中心。

这个服务正在**AWS**上运行。所以，你可以选择数据中心所在的区域。你可以选择任何区域。在这里，我们使用**US-East-1**。

1.  做出选择后，点击**Review**按钮：![图 11.7 - 选择区域和数据中心](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.7_B16353.jpg)

图 11.7 - 选择区域和数据中心

1.  接下来，完成 MQTT 代理实例的创建。

请检查付款计划、服务名称、服务提供商和数据中心区域。之后，点击**Create instance**按钮完成此实例的创建：

![图 11.8 - 完成 MQTT 代理实例创建](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.8_B16353.jpg)

图 11.8 - 完成 MQTT 代理实例创建

# 在边缘设备上发布来自 Node-RED 的数据

在本节中，我们将配置我们的树莓派。首先，启动树莓派并打开 Node-RED 流编辑器。这个 Node-RED 流编辑器应该仍然有一个流来发送传感器数据，实现在*第十章*，*在树莓派上处理传感器数据*中。如果你已经删除了这个流，或者你还没有创建它，请参考*第十章*，*在树莓派上处理传感器数据*来重新执行它。双击组成流的**mqtt out**节点以打开设置窗口。我们上次使用了**Mosquitto**，但这次我们将连接到**CloudMQTT**。

执行以下步骤配置树莓派上的 Node-RED 连接到 CloudMQTT：

1.  访问你在*第十章*中创建的流程，*在树莓派上处理传感器数据*。

在本章中，我们只使用了一个带有**mqtt out**节点的流，因为这个场景只是为了向树莓派发送数据：

![图 11.9 - 访问我们在上一章中创建的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Image86736.jpg)

图 11.9 - 访问我们在上一章中创建的流程

1.  编辑`packt`

1.  `1`

1.  `true`

1.  单击**Edit**按钮（铅笔标记）右侧的**Server**以打开凭证属性：![图 11.11 - 单击“编辑”按钮打开属性设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.11_B16353.jpg)

图 11.11 - 单击“编辑”按钮打开属性设置

1.  在服务器设置面板上，选择`driver.cloudmqtt.com`

1.  `18913`

**Connection**选项卡中的其他属性不应该被更改，必须保持它们的默认值。

你可以参考以下截图来设置**Connection**选项卡：

![图 11.12 - MQTT 代理服务器设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.12_B16353.jpg)

图 11.12 – MQTT 代理服务器设置

1.  接下来，选择**安全**选项卡来编辑配置以连接 MQTT 代理，并填写每个属性如下：

+   **用户名**：您从 CloudMQTT 获得的用户。

+   **密码**：您从 CloudMQTT 获得的密码。

您可以参考以下截图来设置**安全**选项卡：

![图 11.13 – MQTT 代理用户和密码设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.13_B16353.jpg)

图 11.13 – MQTT 代理用户和密码设置

您可以在 CloudMQTT 管理菜单中检查这些属性。此菜单可以通过 CloudMQTT 仪表板的实例列表访问：[`customer.cloudmqtt.com/instance`](https://customer.cloudmqtt.com/instance)

![图 11.14 – CloudMQTT 实例列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.14_B16353.jpg)

图 11.14 – CloudMQTT 实例列表

这完成了树莓派端的设置。接下来，让我们设置 Node-RED 流编辑器，以便可以在云端的 Node-RED 上获取（订阅）数据。

# 在云端 Node-RED 上订阅和可视化数据

在本节中，我们将看到如何使用 Node-RED 在云端可视化接收到的数据。这使用了我们在*第六章*中学到的仪表板节点之一，但这次，我们将选择 Gauge 的 UI，使其看起来更好一些。

这次使用的云端 Node-RED 运行在 IBM Cloud（PaaS）上，但是之前创建了 MQTT 代理服务的 CloudMQTT 是一种与 IBM Cloud 不同的云服务。

在本章中，我们将学习到 MQTT 代理存在的原因，以便可以从各个地方访问它，并且发布者（数据分发者）和订阅者（数据接收者）都可以在不知道它在哪里的情况下使用它。

## 在 IBM Cloud 上准备 Node-RED

现在，让我们通过以下步骤创建一个连接到 CloudMQTT 的 Node-RED 流。在这里，我们将在 IBM Cloud 上使用 Node-RED。请注意，这不是树莓派上的 Node-RED：

1.  打开 Node-RED 流编辑器，登录到您的 IBM Cloud，并从仪表板中调用您已经创建的 Node-RED 服务。

1.  要么点击**查看全部**，要么点击**Cloud Foundry 服务**在**资源摘要**仪表板上的瓷砖。点击任一选项都会带您到您在 IBM Cloud 上创建的资源列表：![图 11.15 – 打开资源列表](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.15_B16353.jpg)

图 11.15 – 打开资源列表

如果您在 IBM Cloud 上尚未创建 Node-RED 服务，请参考*第六章*，*在云中实现 Node-RED*，在继续之前创建一个。

1.  在**资源列表**屏幕上显示的**Cloud Foundry 应用**下，点击您创建的 Node-RED 服务以打开 Node-RED 流编辑器：![图 11.16 – 选择您创建的 Node-RED 服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.16_B16353.jpg)

图 11.16 – 选择您创建的 Node-RED 服务

1.  然后，点击**访问应用 URL**来访问 Node-RED 流编辑器：![图 11.17 – 点击访问应用 URL](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.17_B16353.jpg)

图 11.17 – 点击访问应用 URL

1.  当 Node-RED 流编辑器的顶部屏幕显示时，点击**转到您的 Node-RED 流编辑器**按钮来打开 Node-RED 流编辑器：![图 11.18 – 点击转到您的 Node-RED 流编辑器按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.18_B16353.jpg)

图 11.18 – 点击转到您的 Node-RED 流编辑器按钮

1.  创建一个流来可视化数据。

当您在 IBM Cloud 上访问您的 Node-RED 流编辑器时，请按以下步骤创建一个流。在每个**change**节点之后放置**mqtt in**节点，**json**节点，两个**change**节点和**gauge**节点。如果您想要获取此流的调试日志，请在任何节点之后添加**debug**节点。在本例中，在**mqtt in**节点和第一个**change**节点之后放置了两个**debug**节点。

您已经拥有**仪表板**节点，包括**仪表**节点。如果没有，请返回到*第六章*中的*为用例 2 制作流程-可视化数据*教程中，*在云中实现 Node-RED*，以获取**仪表板**节点：

![图 11.19 – 制作流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.19_B16353.jpg)

图 11.19 – 制作流程

1.  编辑`packt`

1.  `1`

1.  `auto-detect`（字符串或缓冲区）

1.  单击**右侧的编辑**按钮（铅笔图标）以打开凭据属性：![图 11.20 – 单击编辑按钮打开属性设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.20_B16353.jpg)

图 11.20 – 单击编辑按钮打开属性设置

1.  在服务器设置面板上，选择`driver.cloudmqtt.com`

1.  `18913`

**连接**选项卡的其他属性不应更改，必须保持其默认值。

您可以参考以下截图进行**连接**选项卡设置：

![图 11.21 – MQTT 代理服务器设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.21_B16353.jpg)

图 11.21 – MQTT 代理服务器设置

1.  接下来，选择**安全**选项卡以编辑连接 MQTT 服务器的配置，并使用以下值填写每个属性：

+   **用户名**：您从 CloudMQTT 获取的用户。

+   **密码**：您从 CloudMQTT 获取的密码。

您可以参考以下截图进行**安全**选项卡设置：

![图 11.22 – MQTT 代理用户和密码设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.22_B16353.jpg)

图 11.22 – MQTT 代理用户和密码设置

正如您可能已经注意到的那样，这些属性具有您在树莓派 Node-RED 上为**mqtt out**节点设置的相同值。如有必要，请参考 CloudMQTT 仪表板。

1.  现在，编辑 json 节点。双击**属性**中的`msg.payload`：![图 11.23 – 设置 json 节点属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.23_B16353.jpg)

图 11.23 – 设置 json 节点属性

1.  编辑**规则**区域下**to**框中的`msg.payload.temperature`的设置。然后，单击**完成**按钮关闭设置窗口：![图 11.24 – 设置第一个更改节点的属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.24_B16353.jpg)

图 11.24 – 设置第一个更改节点的属性

1.  此外，在**规则**区域的**to**框中编辑第二个`msg.payload.humidity`的设置，然后单击**完成**按钮关闭设置窗口：![图 11.25 – 设置第二个更改节点的属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.25_B16353.jpg)

图 11.25 – 设置第二个更改节点的属性

1.  编辑第一个**仪表**节点的设置。双击第一个**仪表**节点以打开**设置**窗口，然后单击**右侧的编辑**按钮（铅笔图标）以打开属性：![图 11.26 – 单击编辑按钮打开属性设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.26_B16353.jpg)

图 11.26 – 单击编辑按钮打开属性设置

1.  在仪表板的组设置面板中，使用以下值填写每个属性：

+   `树莓派传感器数据`

* 在此处提供任何名称都可以。此名称将显示在我们将创建的图表网页上。

其他属性不应更改，必须保持其默认值。您可以参考以下截图：

![图 11.27 – 设置组名](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.27_B16353.jpg)

图 11.27 – 设置组名

1.  返回到`Temperature`的主面板

1.  `°C`（如果您希望使用华氏度，请使用°F）

1.  **范围**：-**15 ~ 50**（如果您希望使用华氏度，请相应调整范围）

其他属性不应更改其默认值。您可以参考以下截图进行设置：

![图 11.28 – 设置仪表节点属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.28_B16353.jpg)

图 11.28 – 设置仪表节点属性

1.  编辑第二个`湿度`的设置

1.  `％`

1.  **范围**：**0 ~ 100**

其他属性不应更改其默认值。您可以参考以下屏幕截图进行设置：

![图 11.29 – 设置表盘节点属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.29_B16353.jpg)

图 11.29 – 设置表盘节点属性

请确保在 Node-RED 上部署流程。

这完成了 IBM Cloud 上的 Node-RED 配置。这意味着此流程已经订阅（等待数据）使用主题`packt`进行 CloudMQTT 服务。接下来是发布和订阅数据的时间。

## 在 IBM Cloud 上可视化数据

在边缘设备端，即树莓派上，我们已准备好使用主题`packt`将传感器数据发布到 CloudMQTT。在云端，流程已经使用`packt`主题进行 CloudMQTT 服务。

对于树莓派，执行以下步骤发布您的数据：

1.  从您的树莓派发布数据。

访问您的树莓派上的 Node-RED 流程编辑器。单击**注入**节点的按钮以运行此流程以发布槽温度和湿度传感器数据：

![图 11.30 – 运行发布数据的流程](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.30_B16353.jpg)

图 11.30 – 运行发布数据的流程

1.  检查 IBM Cloud 上数据的接收情况。

您将能够通过 CloudMQTT 接收（订阅）数据。您可以在 IBM Cloud 上的 Node-RED 流程编辑器的**调试**选项卡上检查：

![图 11.31 – 检查数据的订阅情况](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.31_B16353.jpg)

图 11.31 – 检查数据的订阅情况

1.  通过 IBM Cloud 上的 Node-RED 流程编辑器的**图表**选项卡打开图表网页，然后单击**打开**按钮（对角箭头图标）打开它：

![图 11.32 – 打开图表网页](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.32_B16353.jpg)

图 11.32 – 打开图表网页

您将看到显示数据的网页表盘图表：

![图 11.33 – 显示图表网页](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_11.33_B16353.jpg)

图 11.33 – 显示图表网页

恭喜！现在您知道如何观察从树莓派发送到服务器的数据并将其可视化为图表。

如果您希望在 Node-RED 上进行流程配置文件以使此流程生效，您可以在这里获取：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter11/getting-sensordata-with-iotplatform.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter11/getting-sensordata-with-iotplatform.json)。

# 总结

在本章中，我们体验了如何接收从边缘设备发送的传感器数据并在服务器端进行可视化。

在本章中，我们在 IBM Cloud 上使用了 CloudMQTT 和 Node-RED。Node-RED 可以在任何云平台和本地运行，并且您可以尝试在任何环境中制作这种应用。因此，记住这种模式对于您未来在其他云 IoT 平台上的开发肯定会有用。

在下一章中，我们将介绍如何使用 Node-RED 制作一个聊天机器人应用的实际场景。这将为您介绍 Node-RED 的新用法。


# 第十二章：使用 Slack 和 IBM Watson 开发聊天机器人应用程序

在这一章中，我们将使用 Node-RED 创建一个聊天机器人应用程序。对于聊天机器人应用程序的用户界面，我们将使用 Slack，并且我们将使用 IBM Watson AI 来进行技能。完成本章的教程后，您将学会如何将 Node-RED 与外部 API 结合起来创建一个应用程序。这将帮助您在未来使用 Node-RED 创建可扩展的 Web 应用程序。

让我们从以下主题开始：

+   创建 Slack 工作区

+   创建 Watson 助手 API

+   从 Node-RED 启用与 Slack 的连接

+   构建聊天机器人应用程序

在本章结束时，您将掌握如何使用 Node-RED 制作 Slack 聊天机器人应用程序。

# 技术要求

要在本章中取得进展，您将需要以下内容：

+   IBM Cloud 账户：[`cloud.ibm.com/`](https://cloud.ibm.com/)。

+   本章使用的代码可以在[`github.com/PacktPublishing/-Practical-Node-RED-Programming`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming)的`Chapter12`文件夹中找到。

# 创建 Slack 工作区

这个实践教程使用**Slack**作为您的聊天机器人应用程序的用户界面。Node-RED 负责控制聊天机器人应用程序背后的消息交换。

这个聊天机器人应用程序的整体视图如下：

![图 12.1 – 应用程序概述](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.1_B16353.jpg)

图 12.1 – 应用程序概述

首先，使用以下步骤为此应用程序创建一个 Slack 工作区。如果您已经有一个 Slack 工作区，可以使用现有的工作区。在这种情况下，跳过以下步骤，并在您的工作区中创建一个名为`learning-node-red`的频道：

1.  访问[`slack.com/create`](https://slack.com/create)，输入您的电子邮件地址，然后点击**下一步**按钮：![图 12.2 – 输入您的电子邮件地址](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.2_B16353.jpg)

图 12.2 – 输入您的电子邮件地址

1.  从 Slack 收到的电子邮件中检查六位数验证码：![图 12.3 – 检查六位数验证码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.3_B16353.jpg)

图 12.3 – 检查六位数验证码

1.  在您点击**下一步**并输入您的电子邮件地址后显示的窗口中输入验证码。输入验证码后，您将被自动重定向到下一个窗口：![图 12.4 – 输入验证码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.4_B16353.jpg)

图 12.4 – 输入验证码

1.  给您的工作区取一个名字，然后点击**下一步**按钮：![图 12.5 – 给您的工作区取一个名字](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.5_B16353.jpg)

图 12.5 – 给您的工作区取一个名字

1.  在您的工作区中创建一个频道。您可以使用`Learning Node-RED`：![图 12.6 – 您的工作区名字](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.6_B16353.jpg)

图 12.6 – 您的工作区名字

1.  点击**暂时跳过**而不添加队友：![图 12.7 – 本教程不需要队友](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.7_B16353.jpg)

图 12.7 – 本教程不需要队友

1.  点击**在 Slack 中查看您的频道**打开您创建的工作区：

![图 12.8 – 在 Slack 中查看您的频道](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.8_B16353.jpg)

图 12.8 – 在 Slack 中查看您的频道

您已为本教程创建了工作区：

![图 12.9 – 您已创建了工作区](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.9_B16353.jpg)

图 12.9 – 您已创建了工作区

重要提示

聊天机器人所在的频道最好是只有您参与的频道，除非有公共目的。这是因为聊天机器人的活动可能会对不喜欢（或对聊天机器人不感兴趣的）参与者造成干扰。

此时，您已经准备好在 Slack 中运行您的聊天机器人的工作区和频道。接下来，我们将创建一个将成为聊天机器人引擎的机制。

# 创建 Watson 助手 API

这个实践教程使用 IBM 的**Watson 助手 API**作为聊天机器人的引擎。Watson 助手可以使用自然语言分析来解释自然对话的意图和目的，并返回适当的答案。

有关 Watson 助手的详细信息，请访问以下网址：[`www.ibm.com/cloud/watson-assistant-2/`](https://www.ibm.com/cloud/watson-assistant-2/)。

要使用 Watson 助手 API，您需要在 IBM Cloud 上创建 Watson 助手 API 的实例。按照以下步骤创建它：

1.  登录到 IBM Cloud 仪表板，并在**目录**中搜索`助手`。单击搜索结果中的**助手**图块：![图 12.10 – 搜索 Watson 助手](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.10_B16353.jpg)

图 12.10 – 搜索 Watson 助手

1.  创建 Watson 助手 API 服务。为 Watson 助手服务数据中心选择一个**区域**。达拉斯很稳定，所以我们选择了**达拉斯**。

1.  选择**Lite**作为定价计划。其他项目，如服务名称和资源组，可以保留其默认值。

1.  单击**创建**按钮：![图 12.11 – 创建 Watson 助手服务](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.11_B16353.jpg)

图 12.11 – 创建 Watson 助手服务

1.  启动 Watson 助手工具。单击**启动 Watson 助手**按钮打开 Watson 助手控制台：![图 12.12 – 启动 Watson 助手控制台](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.12_B16353.jpg)

图 12.12 – 启动 Watson 助手控制台

1.  在您的**Watson 助手**服务中创建一个**技能**。

当您第一次打开 Watson 助手控制台时，您将自动转到**我的第一个技能**屏幕。

通常，您会在这里创建一个 Watson 助手技能，但是这个实践教程将专注于 Node-RED 而不是如何使用 Watson 助手。因此，通过导入预先准备的定义文件在 Watson 助手中创建一个技能。

如果您想创建自己的技能，那很好。在这种情况下，官方的 Watson 助手文档会帮助您：[`cloud.ibm.com/apidocs/assistant/assistant-v2`](https://cloud.ibm.com/apidocs/assistant/assistant-v2)。

1.  点击`告诉我一个笑话`。

1.  为此框架创建一个助手，将助手的名称设置为`Respond Joke Phrase`，然后单击**创建助手**按钮：![图 12.14 – 创建助手](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.14_B16353.jpg)

图 12.14 – 创建助手

1.  导入**对话**。创建助手后，将显示所创建助手的设置屏幕。在该设置屏幕上的**对话**区域中，单击**添加对话技能**按钮：![图 12.15 – 添加对话技能](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.15_B16353.jpg)

图 12.15 – 添加对话技能

1.  选择**导入技能**选项卡，并选择要导入的技能的 JSON 文件。在[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter12/skill-Respond-Joke-Phrase.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter12/skill-Respond-Joke-Phrase.json)下载此 JSON 文件。

1.  选择 JSON 文件后，单击**导入**按钮：![图 12.16 – 导入对话技能文件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.16_B16353.jpg)

图 12.16 – 导入对话技能文件

您将在**对话**区域看到**Respond Joke Phrase**：

![图 12.17 – 导入对话技能](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.17_B16353.jpg)

图 12.17 – 导入对话技能

1.  技能导入完成。您可以返回简单的问候和笑话短语，因此尝试使用 Watson 助手控制台中提供的**试一试**功能进行对话：

![图 12.18 – 试一试](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.18_B16353.jpg)

图 12.18 – 试一试

单击**试一试**按钮时，将打开聊天窗口。在聊天窗口中尝试输入以下对话：

`"你好`*"; "*`嗨";` `"告诉` `我` `笑话";` `"你` `知道` `笑话吗?"`*; 等等…

![图 12.19 – 测试对话](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.19_B16353.jpg)

图 12.19 – 测试对话

如果您得不到一个好的答案，请尝试另一个短语。Watson 自然语言理解将在 Watson 助手的**试一试**窗口中说的对话分成意图或实体的类。如果对话没有分成所需的类，您可以在**试一试**窗口中训练助手 API。

现在您已经使用 Watson Assistant 创建了自动回答对话，还有一件事要做，那就是确认技能 ID。这是您以后需要从 Node-RED 操作 Watson Assistant 作为 API 所需的 ID。

通过以下步骤从**技能**屏幕检查技能 ID：

1.  在您创建的**技能**瓦片的右上角的**技能**菜单下点击**查看 API 详细信息**：![图 12.20 - 访问查看 API 详细信息菜单](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.20_B16353.jpg)

图 12.20 - 访问查看 API 详细信息菜单

1.  记下显示的**技能 ID**：

![图 12.21 - 检查并记录技能 ID](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.21_B16353.jpg)

图 12.21 - 检查并记录技能 ID

我们现在已经创建了一个自动回复聊天的聊天机器人服务。接下来，让我们将其与 Slack 用户界面集成。

# 启用从 Node-RED 到 Slack 的连接

接下来，让我们继续在您的 Node-RED 环境中准备一个 Slack 节点。启动在 IBM Cloud 上创建的 Node-RED 流程编辑器。

在这一步中，您要做的是在您的 Node-RED 环境中安装一个连接到 Slack 的节点。这种方法很简单。您所要做的就是在**管理调色板**窗口中找到并安装节点，这在其他章节中已经做过多次。

按照以下步骤继续：

重要提示

我相信您在 IBM Cloud 上的 Node-RED 流程编辑器已经作为服务（作为 Node.js 应用程序）创建好了，但如果您还没有这样做，请参考*第六章**，在云中实现 Node-RED*，在继续本章之前在 IBM Cloud 上创建一个 Node-RED 服务。

1.  您需要安装**node-red-contrib-slack**节点才能从 Node-RED 中使用 Slack，因此点击**管理调色板**：![图 12.22 - 打开管理调色板窗口](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.22_B16353.jpg)

图 12.22 - 打开管理调色板窗口

1.  搜索`node-red-contrib-slack`节点并点击**安装**按钮：![图 12.23 - 安装 node-red-contrib-slack 节点](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.23_B16353.jpg)

图 12.23 - 安装 node-red-contrib-slack 节点

1.  您将在调色板上看到属于**node-red-contrib-slack**的四个节点。您必须为构建此示例应用程序准备 Slack 节点：![图 12.24 - Slack 节点将出现在您的调色板上](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.24_B16353.jpg)

图 12.24 - Slack 节点将出现在您的调色板上

1.  通过在 Slack 应用程序（桌面或 Web）上通过**设置和管理** | **管理应用**访问**Slack App 目录**，在您的 Slack 工作区中创建一个机器人：![图 12.25 - 选择管理应用](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.25_B16353.jpg)

图 12.25 - 选择管理应用

1.  移动到 Slack App 目录网站后，点击`https://<your workspace>.slack.com/apps`。

以下 URL 仅供参考：[`packtnode-red.slack.com/apps`](https://packtnode-red.slack.com/apps)。

此 URL 根据 Slack 上每个工作区的名称自动生成。

1.  点击**获取基本应用程序**按钮，转到应用程序搜索窗口：![图 12.27 - 点击获取基本应用程序按钮](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.27_B16353.jpg)

图 12.27 - 点击获取基本应用程序按钮

1.  搜索单词`bots`并点击结果中的**Bots**：![图 12.28 - 搜索 Bots 并选择它](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.28_B16353.jpg)

图 12.28 - 搜索 Bots 并选择它

1.  在**Bots**应用程序屏幕上点击**添加到 Slack**按钮：![图 12.29 - 将 Bots 应用添加到您的工作区](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.29_B16353.jpg)

图 12.29 - 将 Bots 应用添加到您的工作区

1.  设置`packt-bot`。

1.  点击**添加机器人集成**按钮：![图 12.30 - 设置您的机器人名称](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.30_B16353.jpg)

图 12.30 – 设置您的机器人名称

1.  在下一个屏幕上，将生成并显示用于使用机器人的 API 令牌。记下这个令牌，以免忘记。创建 Node-RED 流程时会使用这个 API 令牌：

重要提示

在与应用程序共享机器人用户令牌时要小心。不要在公共代码存储库中发布机器人用户令牌。这是因为任何人都可以使用这个 API 令牌访问机器人。

![图 12.31 – 确认您的 API 令牌](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.31_B16353.jpg)

图 12.31 – 确认您的 API 令牌

1.  点击**保存集成**按钮完成 Bot 应用程序的集成：

![图 12.32 – Bot 应用程序集成完成](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.32_B16353.jpg)

图 12.32 – Bot 应用程序集成完成

现在您已经准备好了。让我们继续进行流程创建过程。

# 构建一个聊天机器人应用程序

到目前为止，您已经在 Watson 助手中创建了一个聊天机器人引擎，创建了一个 Slack 工作区，并集成了 Bot 应用程序，您可以在该 Slack 工作区中使用。

在这里，我们将把这些服务与 Node-RED 结合起来，并创建一个机制，使得在 Slack 工作区中说话时，机器人会在 Node-RED 中回答。

按照以下步骤创建一个流程：

1.  将 Watson 助手连接到 Node-RED。通过 IBM Cloud 上的**资源列表**访问您的 Node-RED 服务仪表板。选择**连接**选项卡，然后点击**创建连接**按钮：![图 12.33 – 在 Node-RED 上创建新连接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.33_B16353.jpg)

图 12.33 – 在 Node-RED 上创建新连接

1.  选择您创建的 Watson 助手服务，然后点击**下一步**按钮：![图 12.34 – 在 Node-RED 上创建新连接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.34_B16353.jpg)

图 12.34 – 在 Node-RED 上创建新连接

1.  点击**连接**按钮，使用默认选项完成连接设置。执行此操作将重新启动 Node-RED 应用程序，这将需要几分钟来完成：![图 12.35 – 完成在 Node-RED 上创建新连接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.35_B16353.jpg)

图 12.35 – 完成在 Node-RED 上创建新连接

1.  创建处理 Slack 上对话的流程。

您已经有了 Slack 节点和 Watson 节点，可以在这个实践教程中使用。

1.  放置一个**slack-rtm-in**节点，两个**function**节点，一个**assistant**节点，**slack-rtm-out**和一个**debug**节点。放置它们后，按照以下图示将它们依次连接起来：![图 12.36 – 放置节点并连接它们](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.36_B16353.jpg)

图 12.36 – 放置节点并连接它们

1.  为每个节点设置参数。

按照以下步骤设置每个节点的参数。对于需要编码的节点，请按照以下方式进行编码：

+   **slack-rtm-in**节点：

a) 点击编辑按钮（铅笔图标）打开**属性**面板：

![图 12.37 – 打开属性面板](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.38_B16353.jpg)

图 12.37 – 打开属性面板

b) 输入`packt-bot`：

![图 12.38 – 设置连接 Slack 应用程序的配置属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.39_B16353.jpg)

图 12.38 – 设置连接 Slack 应用程序的配置属性

当您返回到此节点的主面板时，您会看到**Slack 客户端**属性中的配置已经设置。

c) 点击**完成**按钮关闭此设置：

![图 12.39 – 完成设置 slack-rtm-in 节点的属性](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.39_B163531.jpg)

图 12.39 – 完成设置 slack-rtm-in 节点的属性

+   **function**节点（第一个）：

a) 在第一个**function**节点中，输入以下内容：

```js
global.set("channel",msg.payload.channel);
msg.topic = "message";
msg.payload = msg.payload.text;
return msg
```

您也可以参考以下图示：

![图 12.40 – 第一个 function 节点编码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.40_B16353.jpg)

图 12.40 – 第一个 function 节点编码

在这个 function 节点中，从 Slack 发送的消息被从 Slack 发送的 JSON 数据中取出，并再次放入`msg.payload`中。

另一个重要的过程是将从 Slack 发送的频道信息存储在 Node-RED 的全局变量中。这里存储的频道信息将在稍后向 Slack 发送响应消息时使用。

+   **助手**节点：

在上一步中，您将 Watson 助手连接到了 Node-RED。这意味着您可以从 Node-RED 调用助手 API，而无需使用 API 密钥或密码。

当我双击**助手**节点以打开设置面板时，我没有看到任何属性，比如 API 密钥。如果您在设置面板中看到它们，这意味着 Watson 助手和 Node-RED 连接过程失败了。在这种情况下，请重新执行连接过程。

这里只有一个属性需要设置。在**assistant**节点的设置面板中，将您之前写下的 Watson 助手技能 ID 设置为**工作区 ID**属性：

![图 12.41 - 将技能 ID 设置为工作区 ID](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.41_B16353.jpg)

图 12.41 - 将技能 ID 设置为工作区 ID

这完成了**助手**节点的设置。保存您的设置并关闭设置面板。

+   **功能**节点（第二个节点）：

在第一个**功能**节点中，输入以下代码：

```js
var g_channel=global.get("channel");
msg.topic = "message";
msg.payload = {
    channel: g_channel,
    text: msg.payload.output.text[0]
}
return msg
```

您还可以参考以下图：

![图 12.42 - 第二个功能节点编码](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.42_B16353.jpg)

图 12.42 - 第二个功能节点编码

第二个功能节点将 Watson 助手返回的自动回复消息存储在`msg.payload.text`中，并获取保存在第一个功能节点中的 Slack 频道信息，并将其存储在`msg.payload.channel`中。

+   您创建的`packt-bot`已经放置在此节点属性中。如果尚未设置，请从下拉列表中手动选择。单击**完成**后，设置将完成：

![图 12.43 - 检查 slack-rtm-out 节点的属性设置](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.43_B16353.jpg)

图 12.43 - 检查 slack-rtm-out 节点的属性设置

+   **调试**节点：

这里的调试节点只是简单地输出日志。不需要设置。

1.  在 Slack 上检查机器人应用。

使用 Slack 创建了一个自动回答聊天机器人。让我们尝试对话。

1.  在您的 Slack 工作区创建的频道上，添加您集成的机器人应用程序，并单击频道上的**添加应用**链接：![图 12.44 - 单击添加应用链接](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.44_B16353.jpg)

图 12.44 - 单击添加应用链接

1.  单击**添加**按钮将机器人应用添加到您的频道中：

![图 12.45 - 添加您创建的机器人应用](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.45_B16353.jpg)

图 12.45 - 添加您创建的机器人应用

现在，让我们真正进行一次对话。在您添加了这个机器人应用的频道上提及并与您的机器人（例如`packt-bot`）交谈。由于我们这次学习的唯一对话是问候和听笑话，我们将从 Slack 发送一条看起来与这两者之一相关的消息。

首先，让我们打个招呼。您将看到一种问候的回应：

![图 12.46 - 与聊天机器人交换问候](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.46_B16353.jpg)

图 12.46 - 与聊天机器人交换问候

然后发送一条消息，比如`请` `告诉` `我` `一个` `笑话`。它会随机回复一个机器人选定的笑话：

![图 12.47 - 机器人回答一些笑话](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/prac-node-red-prog/img/Figure_12.47_B16353.jpg)

图 12.47 - 机器人回答一些笑话

干得好！您终于用 Node-RED 创建了聊天机器人应用。

如果您希望在 Node-RED 环境中创建此流程的流程配置文件，可以在此处获取：[`github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter12/slack-watson-chatbot-flows.json`](https://github.com/PacktPublishing/-Practical-Node-RED-Programming/blob/master/Chapter12/slack-watson-chatbot-flows.json)。

# 总结

在本章中，我们体验了如何使用 Slack、Watson 和 Node-RED 制作聊天机器人应用程序。这次，我们使用 Slack 作为聊天平台，但您可以使用任何具有 API 的聊天平台，例如 LINE、Microsoft Teams 等，而不是 Slack。

本章对于创建任何非物联网应用程序也非常有帮助。Node-RED 可以通过与任何 Web API 链接来开发各种应用程序。

在下一章中，让我们开发自己的节点。当然，它可以在任何环境中使用。使用 Node-RED 开发自己的节点意味着开发一个无法通过现有节点完成的新节点。这无疑是 Node-RED 高级用户的第一步。
