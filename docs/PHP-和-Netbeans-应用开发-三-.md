# PHP 和 Netbeans 应用开发（三）

> 原文：[`zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606`](https://zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 在 NetBeans 7.2 中引入 Symfony2 支持

> Symfony 是一个用于开发 Web 应用程序的 PHP 框架。它在构建 PHP 中的复杂 Web 应用程序方面非常有帮助。虽然 Symfony 是设计用于从命令行工作，但 NetBeans 7.2 对 Symfony 的支持允许您在 NetBeans 图形用户界面中使用它。

本教程演示了 NetBeans IDE 7.2 对 PHP 中 Symfony 框架的内置支持。它展示了如何设置 IDE 以使用 Symfony，如何创建使用 Symfony 框架的 PHP 项目，以及有关导航项目和设置 IDE 选项的一些提示。

# 下载和集成最新的 Symfony 标准版

Symfony 标准版是启动新项目时使用的最佳发行版。它包含最常见的 bundles，并配有一个简单的配置系统。

# 创建 Symfony2 与 NetBeans 的时间

在本节中，我们将下载标准版并将存档集成到 IDE 中。所以让我们试一试。

1.  从[`symfony.com/download`](http://symfony.com/download)下载最新的 Symfony 标准 2.x.x.zip。将`.zip`存档保存到您的磁盘上；您不需要解压`.zip`文件。

1.  检查已添加到 IDE 的所有项目的 PHP 5 解释器。选择**工具 | 选项 | PHP | 通用**，并验证**PHP 5 解释器**字段中添加的解释器路径。需要添加 PHP 解释器以从 NetBeans 运行 Symfony 命令。

1.  现在，在 IDE 中提供 Symfony 标准版（`.zip`文件）的路径。选择**工具 | 选项 | PHP | Symfony2**。浏览下载的`symfony2 .zip`存档，并按**确定**保存设置。

## 刚刚发生了什么？

IDE 将每次使用添加的`symfony2`存档来提取和转储新的 Symfony 项目。下载的框架版本包含演示 Symfony 应用程序。我们可以稍后玩这些演示应用程序，以更好地掌握 Symfony 框架。

### 注意

您可以从[`symfony.com/download`](http://symfony.com/download)中选择多个下载选项。

# 创建一个新的 Symfony2 项目

由于我们已经将 Symfony2 框架安装存档与 IDE 集成，因此创建新的 Symfony2 项目与在 NetBeans 中创建新的 PHP 项目完全相同。IDE 使用安装存档并在其中创建一个带有 Symfony 框架的新 PHP 项目。

# 创建 Symfony2 项目使用 NetBeans 的时间

我们将创建一个具有 Symfony2 框架支持的新 PHP 项目。在 IDE 创建项目目录结构之后，我们将配置我们的 Symfony2 网站。所以让我们按照以下步骤进行：

1.  以通常的方式创建一个全新的 PHP 项目，在要求选择**PHP 框架**的步骤中，勾选**Symfony2 PHP Web Framework**复选框，如下截图所示：![创建 Symfony2 项目使用 NetBeans 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_01.jpg)

1.  一旦在**新项目创建**对话框中单击**完成**，IDE 将生成一个新的 Symfony 项目并将提取的框架转储到其中。创建的项目目录可能类似于以下内容：![创建 Symfony2 项目使用 NetBeans 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_02.jpg)

1.  现在，将浏览器指向`http://localhost/symfony2/web/config.php`（将`symfony2`替换为您的项目目录名称）。新的 Symfony2 项目配置页面将类似于以下截图：![创建 Symfony2 项目使用 NetBeans 的时间](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_03.jpg)

您应该看到来自 Symfony 的欢迎消息，可能还有一些它检测到的问题列表。在继续之前，尝试解决**建议**部分下列出的任何主要环境问题。

1.  Symfony 框架提供了一个网站配置向导。要进入向导，请访问**Configure your Symfony Application online**链接，并为应用程序配置数据库凭据。在此页面，您可以选择您的数据库驱动程序（`MySQL - PDO`），更新您的数据库信息，如主机名、数据库名称、用户名和密码，并继续下一步。

如果您已经配置了应用程序，可以选择**Bypass configuration and go to the Welcome page**链接。

1.  在下一步中，您可以为您的 Web 应用程序生成和更新全局秘密代码（随机字母数字字符串）。此秘密代码用于安全目的，如 CSRF 保护。

1.  最后一步显示了一个成功的配置消息，例如**Your distribution is configured!**实际上，这样的配置已经覆盖了`/app/config/`目录中的`parameters.ini`文件。

1.  现在，将浏览器指向`http://localhost/symfony2/web/app_dev.php/`（将`symfony2`替换为您的项目目录名称）。新的 Symfony2 项目登陆页面将类似于以下截图：![Time for action — creating a Symfony2 project using NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_04.jpg)

## 刚刚发生了什么？

我们已成功创建和配置了一个新的 Symfony 项目以及演示应用程序。Symfony2 项目的基本目录结构如下所述：

+   `app/:` 这包括应用程序配置文件、日志、缓存等。

+   `src/:` 这包括项目的 PHP 代码和您的代码所在的目录。很可能里面已经有一个演示。

+   `vendor/:` 这包括第三方依赖项。

+   `web/:` 这包括 web 根目录。

### 注意

开始使用 Symfony：

[`symfony.com/get_started`](http://symfony.com/get_started)

了解 Symfony 目录结构：

[`symfony.com/doc/current/quick_tour/the_architecture.html`](http://symfony.com/doc/current/quick_tour/the_architecture.html)

# 在 NetBeans 中运行 Symfony2 控制台命令

NetBeans IDE 支持运行 Symfony2 命令。要从 IDE 中运行命令，请从项目的上下文菜单中选择**Symfony2 | Run Command...**以启动**Run Symfony2 Command**对话框。在对话框中，您可以选择所需的 Symfony 命令并添加参数。

例如：

```php
generate:bundle [--namespace="..."] [--dir="..."] [--bundle-name="..."] [--format="..."] [--structure]

```

`generate:bundle`命令帮助您生成新的 bundle。默认情况下，该命令与开发人员交互以调整生成。任何传递的选项都将用作交互的默认值（如果遵循约定，则只需要`--namespace`）：

```php
php app/console generate:bundle --namespace=Acme/BlogBundle

```

在这里，`Acme`是您的标识符或公司名称，`BlogBundle`是以`Bundle`字符串为后缀的 bundle 名称。

## 创建一个 bundle

**bundle**类似于其他软件中的插件，但更好。关键区别在于 Symfony2 中的一切都是 bundle，包括核心框架功能和为您的应用程序编写的代码。bundle 在 Symfony2 中是一等公民。这使您可以灵活地使用打包在第三方 bundle 中的预构建功能，或者分发您自己的 bundle。这使得您可以轻松地选择要在应用程序中启用的功能，并按照您想要的方式对其进行优化。

bundle 只是一个实现单个功能的目录中的一组结构化文件。您可以创建**BlogBundle**、**ForumBundle**或用于用户管理的 bundle（许多这样的 bundle 已经存在作为开源 bundle）。每个目录包含与该功能相关的所有内容，包括 PHP 文件、模板、样式表、JavaScript、测试等。功能的每个方面都存在于 bundle 中，每个功能都存在于 bundle 中。

# 采取行动 — 使用 Symfony2 控制台命令创建一个 bundle

我们将使用 IDE 的**Run Symfony2 Command**对话框使用`generate:bundle`命令创建一个新的 bundle。所以让我们试试看...

1.  在**项目**窗格中，右键单击**项目**节点，从上下文菜单中选择**Symfony2 | Run Command...**以启动**Run Symfony2 Command**对话框，如下所示：![Time for action — creating a bundle using the Symfony2 console command](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_05.jpg)

您将能够在**匹配任务**框中看到可用命令的列表。您可以为这些命令添加参数，并在**命令**对话框中查看完整的命令。

1.  从前面的对话框中，选择`generate:bundle`命令，然后单击**Run**，或双击列出的名称以运行命令。IDE 的图形控制台打开以提示命名空间。![Time for action — creating a bundle using the Symfony2 console command](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_06.jpg)

1.  输入**Bundle namespace**的值，比如`Application/FooBundle`。

1.  输入**Bundle name**的值，或按*Enter*接受默认的 bundle 名称为`ApplicationFooBundle`。

1.  在`Target`目录处按*Enter*接受默认的 bundle 路径为`/src`。

1.  您可以输入**Configuration format**的值`(yml, xml, php`，或`annotation)`为`yml`；默认值为`annotation`。

1.  输入**Yes**以生成 bundle 的整个目录结构[no]?**，以生成 bundle 的整个目录结构；默认为 no。

1.  再次输入**Yes**确认 bundle 生成。

1.  在**确认自动更新您的内核 [yes]?**和**确认自动更新路由 [yes]?**处，按*Enter*接受默认值，即 yes。这样 bundle 就可以在 Symfony 内核中注册，并且 bundle 路由文件链接到默认的路由配置文件。

1.  现在，正如你所看到的，在`/src`目录内创建了一个新的 bundle；`bundle`目录结构看起来类似于以下内容：![Time for action — creating a bundle using the Symfony2 console command](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_Appendix_A_07.jpg)

请注意，默认的控制器、路由文件、模板等与 bundle 同时创建。

1.  现在，要测试您的 bundle，请将浏览器指向`http://localhost/symfony2/web/app_dev.php/hello/tonu`，您可能会看到类似**Hello Tonu!**的输出。

1.  在`/src/Application/FooBundle/Resources/config/routing.yml`处查看 bundle 路由文件，您将看到 URL 与默认控制器的索引操作（`ApplicationFooBundle:Default:index`）映射的模式`/hello/{name}`。在这个例子中，该操作显示作为 URL 参数传递的名称，而不是`{name}`。

## 刚刚发生了什么？

每个 bundle 都托管在一个命名空间下（例如`Acme/Bundle/BlogBundle`或`Acme/BlogBundle`）。命名空间应以“供应商”名称开头，例如您的公司名称、项目名称或客户名称，后面跟着一个或多个可选的类别子命名空间，最后以 bundle 名称本身结尾（必须以`Bundle`作为后缀）。

### 注意

请参阅`http://symfony.com/doc/current/cookbook/bundles/best_practices.html#index-1`，了解有关 bundle 命名约定的更多详细信息。

我们已经看到了交互式控制台，它要求参数并自动创建整个`bundle`目录结构。此外，它将 bundle 注册到 Symfony 的`/app/AppKernel.php`中，并将 bundle 路由配置文件链接到`default/app/config/routing.yml`中。

### 注意

Symfony 学习资源：

[`symfony.com/doc/current/book/index.html`](http://symfony.com/doc/current/book/index.html)


# 附录 B. NetBeans 键盘快捷键

NetBeans IDE 的常用键盘快捷键如下。

# 文件菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Ctrl* + *Shift* + *N* | **新建** | 使用**新建项目**向导创建新项目 |
| *Ctrl* + *N* | **新建** | 使用**新建文件**向导创建新文件 |
| *Ctrl* + *Shift* + *O* | **打开文件** | 打开现有项目 |
| *Ctrl* + *S* | **保存** | 保存当前文件 |
| *Ctrl* + *Shift* + *S* | **全部保存** | 保存所有文件 |

# 编辑菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Ctrl* + *Z* | **撤销** | 撤销（一次）编辑操作序列，除了**保存** |
| *Ctrl* + *Y* | **重做** | 撤销（一次）**撤销**命令序列 |
| *Ctrl* + *X* | **剪切** | 删除当前选择并将其放置在剪贴板上 |
| *Ctrl* + *C* | **复制** | 将当前选择复制到剪贴板 |
| *Ctrl* + *V* | **粘贴** | 将剪贴板的内容粘贴到插入点 |
| *Ctrl* + *Shift* + *V* | **粘贴格式** | 将剪贴板的格式内容粘贴到插入点 |
| *Delete* | **删除** | 删除当前选择 |
| *Ctrl* + *A* | **全选** | 选择当前文档或窗口中的所有内容 |
| *Alt* + *Shift* + *J* | **选择标识符** | 选择当前标识符 |
| *Ctrl* + *F3* | **查找选择** | 查找当前选择的实例 |
| *F3* | **查找下一个** | 查找下一个找到的文本实例 |
| *Shift* + *F3* | **查找上一个** | 查找上一个找到的文本实例 |
| *Ctrl* + *F* | **查找** | 查找文本字符串 |
| *Ctrl* + *H* | **替换** | 查找文本字符串并用指定的字符串替换它 |
| *Alt* + *F7* | **查找用法** | 查找所选代码的用法和子类型 |
| *Ctrl* + *Shift* + *F* | **在项目中查找** | 在项目中查找指定的文本、对象名称和对象类型 |
| *Ctrl* + *Shift* + *H* | **在项目中替换** | 替换项目中的文本、对象名称和对象类型 |

# 视图菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Ctrl* + *-* (减号) | **折叠折叠** | 如果插入点在可折叠的文本部分中，则将这些行折叠成一行 |
| *Ctrl* + *+* (加号) | **展开折叠** | 如果**源编辑器**窗口中当前选择的行代表几行折叠的文本，则展开折叠以显示所有行 |
| *Ctrl* + *Shift* + *-* (减号) | **折叠全部** | 折叠**源编辑器**窗口中所有可折叠的文本部分 |
| *Ctrl* + *Shift* + *+* (plus) | **展开全部** | 展开**源编辑器**窗口中所有可折叠的文本部分 |
| *Alt* + *Shift* + *Enter* | **全屏** | 将窗口展开到屏幕的全长和全宽 |

# 导航菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Alt* + *Shift* + *O* | **转到文件** | 查找并打开特定文件 |
| *Ctrl* + *O* | **转到类型** | 查找并打开特定的类或接口 |
| *Ctrl* + *Alt* + *Shift* + *O* | **转到符号** | 查找并打开特定符号 |
| *Ctrl* + *Shift* + *T* | **转到测试** | 查找并打开特定测试 |
| *Ctrl* + 反引号 | **转到上一个文档** | 打开当前文档之前打开的文档 |
| *Ctrl* + *Shift* + *B* | **转到源** | 显示包含所选类定义的源文件 |
| *Ctrl* + *B* | **转到声明** | 跳转到光标下项目的声明 |
| *Ctrl* + *Shift* + *P* | **转到超级实现** | 跳转到光标下项目的超级实现 |
| *Ctrl* + *Q* | **上次编辑位置** | 将编辑器滚动到上次编辑发生的地方 |
| *Alt* + 左箭头键 | **返回** | 后退 |
| *Alt* + 右箭头键 | **前进** | 前进 |
| *Ctrl* + *G* | **转到行** | 跳转到指定行 |
| *Ctrl* + *Shift* + *M* | **切换书签** | 在代码行上设置书签 |
| *Ctrl* + *Shift* +. (句号) | **下一个书签** | 通过书签向前循环 |
| *Ctrl* + *Shift* + , (逗号) | **上一个书签** | 通过书签向后循环 |
| *Ctrl* +. (句号) | **下一个错误** | 将**源代码编辑器**窗口滚动到包含下一个构建错误的行 |
| *Ctrl* +, (逗号) | **上一个错误** | 将**源代码编辑器**窗口滚动到包含上一个构建错误的行 |
| *Ctrl* + *Shift* + *1* | **在项目中选择** | 打开**项目**窗口并在其中选择当前文档 |
| *Ctrl* + *Shift* + *2* | **在文件中选择** | 打开**文件**窗口并在其中选择当前文档 |
| *Ctrl* + *Shift* + *3* | **在收藏夹中选择** | 打开**收藏夹**窗口并在其中选择当前文档 |

# 源菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Alt* + *Shift* + *F* | **格式** | 格式化所选代码或整个文件（如果未选择任何内容） |
| *Alt* + *Shift* + 左箭头键 | **向左移动** | 将所选行或多行向左移动一个制表符 |
| *Alt* + *Shift* + 右箭头键 | **向右移动** | 将所选行或多行向右移动一个制表符 |
| *Alt* + *Shift* + 上箭头键 | **向上移动** | 将所选行或多行向上移动一行 |
| *Alt* + *Shift* + 下箭头键 | **向下移动** | 将所选行或多行向下移动一行 |
| *Ctrl* + *Shift* + 上箭头键 | **向上复制** | 复制所选行或多行一行向上 |
| *Ctrl* + *Shift* + 下箭头键 | **向下复制** | 复制所选行或多行一行向下 |
| *Ctrl* + */* (斜杠) 或 *Ctrl* + *Shift* + *C* | **切换注释** | 切换当前行或所选行的注释 |
| *Ctrl* + *空格键* | **完成代码** | 显示代码完成框 |
| *Alt* + *插入* | **插入代码** | 弹出一个上下文感知菜单，您可以使用它来生成常见结构，如构造函数、getter 和 setter |
| *Alt* + *Enter* | **修复代码** | 显示编辑器提示，并在显示灯泡时，IDE 会在提示可用时通知您 |
| *Ctrl* + *Shift* + *I* | **修复导入** | 生成文件中指定类所需的导入语句 |
| *Ctrl* + *P* | **显示方法参数** | 选择下一个参数；您必须选择（高亮显示）一个参数，此快捷键才能起作用 |
| *Ctrl* + *Shift* + *空格* | **显示文档** | 显示光标下项目的文档 |
| *Ctrl* + *Shift* + K | **插入下一个匹配的单词** | 当您键入其开始字符时，生成代码中其他地方使用的下一个单词 |
| *Ctrl* + *K* | **插入上一个匹配的单词** | 当您键入其开始字符时，生成代码中其他地方使用的上一个单词 |

# 重构菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *Ctrl* + *R* | **重命名** | 原地重命名 |
| *Ctrl* + *M* | **移动** | 原地移动 |
| *Alt* + *删除* | **安全删除** | 删除之前，显示引用 |

# 运行菜单

| 键 | 命令 | 动作 |
| --- | --- | --- |
| *F6* | **运行主项目** | 运行主项目 |
| *Alt* + *F6* | **测试项目** | 为项目启动 PHP 单元测试 |
| *Shift* + *F6* | **运行文件** | 运行当前选择的文件 |
| *Ctrl* + *F6* | **测试文件** | 为当前文件启动 PHP 单元测试 |
| *F11* | **构建主项目** | 编译文件；如果选择文件夹，IDE 将编译所有文件，而不管它们自上次编译以来是否发生了更改 |
| *Shift* + *F11* | **清理并构建主项目** | 编译文件；如果选择文件夹，IDE 将编译所有文件，而不管它们自上次编译以来是否发生了更改 |
| *F9* | **编译文件** | 编译文件；如果选择文件夹，IDE 仅编译自上次编译以来新的或已更改的文件 |

# 调试菜单

| 键 | 命令 | 操作 |
| --- | --- | --- |
| *Ctrl* + *F5* | **调试主项目** | 调试主项目 |
| *Ctrl* + *Shift* + *F5* | **调试文件** | 开始当前选定文件的调试会话 |
| *Ctrl* + *Shift* + *F6* | **为文件调试测试** | 开始 PHPUnit 中文件的调试测试 |
| *Shift* + *F5* | **结束调试会话** | 结束调试会话 |
| *F5* | **继续** | 恢复调试直到下一个断点或程序结束 |
| *F8* | **跳过** | 执行程序的一行源代码。如果该行是一个方法调用，执行整个方法然后停止 |
| *Shift* + *F8* | **跳过表达式** | 跳过表达式然后停止调试 |
| *F7* | **步入** | 执行程序的一行源代码；如果该行是一个方法调用，执行程序直到方法的第一条语句然后停止 |
| *Ctrl* + *F7* | **跳出** | 执行程序的一行源代码；如果该行是一个方法调用，执行该方法并返回控制权给调用者 |
| *F4* | **运行到光标** | 运行当前项目到文件中光标的位置，然后停止程序执行 |
| *Shift* + *F7* | **运行到方法** | 运行当前项目到指定方法，然后进入该方法 |
| *Ctrl* + *Alt* + 上箭头键 | **使被调用者为当前** | 使被调用方法成为当前调用；仅在**调用堆栈**窗口中选择调用时可用 |
| *Ctrl* + *Alt* + 下箭头键 | **使调用者为当前** | 使调用方法成为当前调用；仅在**调用堆栈**窗口中选择调用时可用 |
| *Ctrl* + *F8* | **切换行断点** | 在程序中光标位置添加或移除断点 |
| *Ctrl* + *Shift* + *F8* | **新断点** | 在指定行、异常或方法设置新断点 |
| *Ctrl* + *Shift* + *F7* | **新建监视** | 添加指定变量以监视 |
| *Ctrl* + *F9* | **评估表达式** | 打开**评估表达式**对话框 |

# 窗口菜单

| 键 | 命令 | 操作 |
| --- | --- | --- |
| *Ctrl* + *0* | **源代码编辑器** | 切换到**源代码编辑器**窗口 |
| *Ctrl* + *1* | **项目** | 打开**项目**窗口 |
| *Ctrl* + *2* | **文件** | 打开**文件**窗口 |
| *Ctrl* + *3* | **收藏夹** | 打开**收藏夹**窗口 |
| *Ctrl* + *4* | **输出窗口** | 打开**输出**窗口 |
| *Ctrl* + *5* | **服务** | 打开**服务**窗口 |
| *Ctrl* + *Shift* + *5* | **HTTP 监视器** | 打开**HTTP 监视器**窗口 |
| *Ctrl* + *6* | **任务列表** | 打开**任务列表**窗口 |
| *Ctrl* + *7* | **导航器** | 打开**导航器** |
| *Alt* + *Shift* + *1* | **调试 &#124;** 变量 | 打开**变量调试器**窗口 |
| *Alt* + *Shift* + *2* | **调试 &#124; 监视** | 打开**监视调试器**窗口 |
| *Alt* + *Shift* + *3* | **调试 &#124; 调用堆栈** | 打开**调用堆栈调试器**窗口 |
| *Alt* + *Shift* + *4* | **调试 &#124; 类** | 打开**类调试器**窗口 |
| *Alt* + *Shift* + *5* | **调试 &#124; 断点** | 打开**断点调试器**窗口 |
| *Alt* + *Shift* + *6* | **调试 &#124; 会话** | 打开**会话调试器**窗口 |
| *Alt* + *Shift* + *7* | **调试 &#124; 线程** | 打开**线程调试器**窗口 |
| *Alt* + *Shift* + *8* | **调试 &#124; 源代码** | 打开**源代码**窗口 |
| *Ctrl* + *W* | **关闭** | 关闭当前窗口中的当前选项卡；如果窗口没有选项卡，则关闭整个窗口 |
| *Shift* + *Esc* | **最大化窗口** | 最大化**源代码编辑器**窗口或当前窗口 |
| *Alt* + *Shift* + *D* | **取消停靠窗口** | 从 IDE 中分离窗口 |
| Ctrl + *Shift* + *W* | **关闭所有文档** | 关闭**源代码编辑器**窗口中的所有打开文档 |
| *Shift* + *F4* | **文档** | 打开**文档**对话框，您可以在其中保存和关闭打开的文档组 |
| *Ctrl* + *Tab* (*Ctrl* + *')* | **切换到最近的窗口** | 以它们最后使用的顺序切换打开的窗口；对话框显示所有打开的窗口和**源编辑器**窗口中的每个打开文档 |

# 滚动和选择

| 键 | 动作 |
| --- | --- |
| *Ctrl* + 下箭头键 | 在不移动插入点的情况下向上滚动窗口 |
| *Ctrl* + 上箭头键 | 在不移动插入点的情况下向下滚动窗口 |
| *Ctrl* + *[* | 将插入点移动到突出显示的匹配括号处；此快捷键仅在插入点紧跟在开放或关闭括号之后时才起作用 |
| *Ctrl* + *Shift* + *[* | 选择一对括号之间的代码块；此快捷键仅在插入点紧跟在开放或关闭括号之后时才起作用 |
| *Ctrl* + *G* | 跳转到指定行 |
| *Ctrl* + *A* | 选择文件中的所有文本 |

# 修改文本

| 键 | 动作 |
| --- | --- |
| *Insert* | 在插入文本和覆盖文本模式之间切换 |
| *Ctrl* + *Shift* + *J* | 打开国际化对话框，您可以在插入点插入国际化字符串 |
| *Ctrl* + *U, U* | 将所选字符或插入点右侧的字符转换为大写 |
| *Ctrl* + *U, L* | 将所选字符或插入点右侧的字符转换为小写 |
| *Ctrl* + *U, S* | 反转所选字符的大小写或插入点右侧的字符的大小写 |

# 代码折叠

| 键 | 动作 |
| --- | --- |
| *Ctrl* + *-* (减号) | 折叠插入点所在的代码块 |
| *Ctrl* + *+* (加号) | 展开插入点旁边的代码块 |
| *Ctrl* + *Shift* + *-* (减号) | 折叠所有代码块 |
| *Ctrl* + *Shift* + *+* (加号) | 展开所有代码块 |

# 搜索文本

| 键 | 动作 |
| --- | --- |
| *Ctrl* + *F3* | 搜索插入点所在的单词并突出显示该单词的所有出现 |
| *F3* | 选择当前搜索中单词的下一个出现 |
| *Shift* + *F3* | 选择当前搜索中单词的上一个出现 |
| *Alt* + *Shift* + *H* | 打开或关闭搜索结果的高亮显示 |
| *Ctrl* + *F* | 打开**查找**对话框 |
| *Ctrl* + *H* | 打开**查找和替换**对话框 |

# 设置制表位

| 键 | 动作 |
| --- | --- |
| *Tab* | 将插入点右侧的所有文本向右移动 |
| *Alt* + *Shift* + *Right* | 将包含插入点的行中的文本向右移动 |
| *Alt* + *Shift* + *Left* | 将包含插入点的行中的文本向左移动 |

IDE 还为那些习惯于其他编辑器和 IDE 键盘快捷键的用户提供了不同的预配置快捷键配置文件。您可以复制和修改任何键盘快捷键配置文件。IDE 提供以下快捷键配置文件：

+   Eclipse

+   Emacs

+   IDEA

+   NetBeans

+   NetBeans 5.5

由于 NetBeans IDE 5.5 和 NetBeans IDE 6.0 之间的快捷键映射发生了重大变化，您可以选择切换回 NetBeans IDE 5.5 中可用的快捷键。要这样做，请从**工具 | 选项 | 键盘映射**中选择 NetBeans 5.5 快捷键配置文件。

### 注意

有关 Mac OS 键盘快捷键，请参阅**NetBeans 帮助 | IDE 基础知识 | 键盘快捷键 | Mac OS 键盘快捷键**。


# 附录 C. 弹出测验答案

每章的弹出测验答案都在这里提供，供您参考。你得了多少分？

# 第二章，使用 PHP 编辑器提高编码效率

## 弹出测验 - 熟悉基本 IDE 功能

| 1 | d |
| --- | --- |
| 2 | d |
| 3 | c |
| 4 | c |
| 5 | b |

## 弹出测验 - 探索 PHP 编辑器

| 1 | d |
| --- | --- |
| 2 | d |
| 3 | b |
| 4 | d |

## 弹出测验 - 使用重命名重构和即时重命名

| 1 | a |
| --- | --- |
| 2 | b |

## 弹出测验 - 使用代码补全

| 1 | c |
| --- | --- |
| 2 | d |
| 3 | b |

## 弹出测验 - 使用代码生成器

| 1 | a |
| --- | --- |
| 2 | d |

# 第三章，使用 NetBeans 构建类似 Facebook 的状态发布器

## 弹出测验 - 理解 PDO

| 1 | c |
| --- | --- |

## 弹出测验 - 理解 CSS

| 1 | b |
| --- | --- |
| 2 | a |
| 3 | b |

## 弹出测验 - 复习 jQuery 知识

| 1 | c |
| --- | --- |
| 2 | d |
| 3 | c |
| 4 | c |
| 5 | b |
| 6 | d |

# 第四章，使用 NetBeans 进行调试和测试

## 弹出测验 - 使用 XDebug 进行调试

| 1 | a, c, d |
| --- | --- |
| 2 | b |
| 3 | b |

## 弹出测验 - PEAR

| 1 | b |
| --- | --- |

## 弹出测验 - 单元测试和代码覆盖率

| 1 | d |
| --- | --- |
| 2 | c |
| 3 | c |
| 4 | c |

# 第五章，使用代码文档

## 弹出测验 - 复习标签

| 1 | c |
| --- | --- |
| 2 | b |
| 3 | a |

# 第六章，了解 Git，NetBeans 方式

## 弹出测验 - 理解 Git

| 1 | a |
| --- | --- |
| 2 | b |
| 3 | b |
| 4 | b |

## 弹出测验 - 使用 Git

| 1 | a |
| --- | --- |
| 2 | b |
| 3 | b |
| 4 | d |

## 弹出测验 - 使用远程存储库和分支

| 1 | b |
| --- | --- |
| 2 | b |
| 3 | d |

第七章，构建用户注册、登录和注销

## 弹出测验 - 复习 PDO

| 1 | c |
| --- | --- |

## 弹出测验 - 使用命名空间

| 1 | a, b, c |
| --- | --- |
| 2 | b |

## 弹出测验 - 应用架构

| 1 | c |
| --- | --- |
| 2 | b |
| 3 | a |
