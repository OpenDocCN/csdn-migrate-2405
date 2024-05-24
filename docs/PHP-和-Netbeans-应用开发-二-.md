# PHP 和 Netbeans 应用开发（二）

> 原文：[`zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606`](https://zh.annas-archive.org/md5/3257ea46483c2860430cdda1bc8d9606)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 NetBeans 进行调试和测试

> 如果调试被定义为从程序中消除错误的艺术，那么编程必须是将错误放入其中。

在本章中，我们将学习使用 NetBeans IDE 调试和测试 PHP Web 应用程序。我们将处理示例项目，以学习捕虫和测试的过程。本章将讨论以下主题：

+   配置 XDebug

+   使用 XDebug 调试 PHP 源代码

+   使用 PHPUnit 和 Selenium 进行单元测试

+   代码覆盖率

让我们去找猎人，做一些真正的技巧...

# 调试古老的编程艺术

编写程序后，下一步是测试程序，以查找程序是否按预期工作。有时，当我们第一次运行刚写好的代码时，可能会产生错误，如语法错误、运行时错误和逻辑错误。调试是逐步查找错误的过程，以便修复错误，使程序按预期工作。

现代编辑器几乎可以检测到所有语法错误，因此我们可以在输入代码时修复它们。还有一些可以与 IDE 集成的工具来查找错误，它们被称为调试器。有许多优秀的调试器，如 XDebug 和 FirePHP（适用于 FireBug 粉丝），适用于 PHP。这些调试器还带有应用程序分析器。在本章中，我们将尝试使用 NetBeans 调试 PHP 项目的 XDebug。

# 使用 XDebug 调试 PHP 源代码

**XDebug**是高度可配置的，适应各种情况。您可以检查本地变量，设置监视，设置断点，并实时评估代码。您还可以使用**转到**快捷方式和超文本链接导航到声明、类型和文件。为所有项目使用全局 PHP`include`路径，或者根据项目自定义它。

PHP 的 NetBeans IDE 还提供了命令行调试。PHP 程序的输出会显示在 IDE 本身的命令行显示中，您可以在不切换到浏览器的情况下检查生成的 HTML。

您可以在本地或远程调试脚本和网页。NetBeans PHP 调试器集成允许您将服务器路径映射到本地路径，以启用远程调试。

XDebug 提供以下功能：

+   错误发生时自动堆栈跟踪

+   函数调用日志

+   增强`var_dump()`输出和代码覆盖信息

堆栈跟踪显示错误发生的位置，允许您跟踪函数调用和原始行号。`var_dump()`输出以更详细的方式显示在 XDebug 中。

### 提示

XDebug 覆盖了 PHP 的默认`var_dump()`函数，用于显示变量转储。XDebug 的版本包括不同颜色的不同变量类型，并对数组元素/对象属性的数量、最大深度和字符串长度进行限制。

# 配置 XDebug

在每个单独的操作系统上配置 XDebug 都非常容易。在本节中，让我们在我们的开发环境（XAMPP、LAMP 和 MAMP）中配置 XDebug。您只需在`php.ini`中启用一些行或按一些命令。由于我们已经安装了开发包，我们将在这些堆栈上激活 XDebug。首先，我们将使工具在我们的本地主机系统上运行，然后将其添加到 NetBeans 中。

# 行动时间-在 Windows 上安装 XDebug

XDebug 扩展默认包含在 XAMPP 捆绑包中。您只需从加载的`.ini`文件中启用它。请注意，可能存在多个`php.ini`文件，并且文件位置在不同操作系统之间可能不同。所以，让我们试试看...

1.  通过将浏览器指向[`localhost/xampp/phpinfo.php`](http://localhost/xampp/phpinfo.php)来查找加载的`php.ini`文件。![行动时间-在 Windows 上安装 XDebug](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_01.jpg)

您可以看到位于`D:\xampp\php\php.ini`的加载的`php.ini`文件。

1.  打开位于`D:\xampp\php\php.ini`的`php.ini`文件，并找到以下行：

```php
[XDebug]
;zend_extension = "D:\xampp\php\ext\php_xdebug.dll"

```

1.  找到并取消注释以下行，删除前导分号：

```php
zend_extension = "D:\xampp\php\ext\php_xdebug.dll"
xdebug.remote_enable = 1
xdebug.remote_handler = "dbgp"
xdebug.remote_host = "localhost"
xdebug.remote_port = 9000

```

1.  保存`php.ini`文件，并从 XAMPP 控制面板重新启动 Apache Web 服务器，以启用 XDebug 扩展。

1.  要验证 XDebug 对象是否已启用，请刷新您的`phpinfo()`页面，并查找已启用的 XDebug，如下面的屏幕截图所示：![操作时间-在 Windows 上安装 XDebug](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_02.jpg)

1.  如果启用了 XDebug，它将覆盖 PHP 中的`var_dump()`。您可以在代码中转储变量，如`var_dump($var)`，浏览器将显示增强的`var_dump`，如下所示（字符串以红色打印）：![操作时间-在 Windows 上安装 XDebug](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_03.jpg)

太棒了！您刚刚在开发环境中加载了 XDebug。

## 刚刚发生了什么？

我们刚刚在 Windows 的 XAMPP 捆绑包中启用了 XDebug，并验证了加载的扩展和配置。请注意，可以遵循此类通用步骤来启用`php.ini`中的其他内置扩展以启用 XDebug。您只需取消注释`php.ini`中的扩展并重新启动 Web 服务器以使更改生效。在 LAMP 或 MAMP 堆栈中启用 XDebug 也是非常相似的。

### 提示

始终检查`phpinfo()`页面加载的`php.ini`路径。

## 在 Ubuntu 上启用 XDebug

在 Ubuntu 中启用 XDebug 非常容易。我们可以通过**apt-get**软件包安装程序安装它，并更新`xdebug.ini`以加载配置。

# 操作时间-在 Ubuntu 上安装 XDebug

从控制台运行以下命令：

1.  使用以下命令安装 XDebug：

```php
**sudo apt-get install php5-xdebug** 

```

1.  使用内置编辑器`gedit`更新`xdebug.ini`。

```php
**sudo gedit /etc/php5/apache2/conf.d/xdebug.ini** 

```

1.  更改`xdebug.ini`，使其如下所示：

```php
**zend_extension=/usr/lib/php5/20090626+lfs/xdebug.so
xdebug.remote_enable=1
xdebug.remote_handler=dbgp
xdebug.remote_mode=req
xdebug.remote_host=127.0.0.1
xdebug.remote_port=9000** 

```

请注意，这些配置的第一行可能在`xdebug.ini`中可用，并且您可能需要添加其余行。

1.  重新启动 Apache。

```php
**sudo service apache2 restart** 

```

1.  刷新`phpinfo()`页面，找到安装的最新 XDebug 版本号。

## 刚刚发生了什么？

我们刚刚在 Ubuntu 的 LAMP 中启用了 XDebug，并验证了加载的扩展和配置。请注意，可以遵循此类通用步骤来启用`php.ini`中的其他内置扩展以启用 XDebug。您只需取消注释`php.ini`中的扩展并重新启动 Web 服务器以使更改生效。

## 在 Mac OS X 上启用 XDebug

修改加载的`php.ini`文件的适当版本以在 Mac 上启用 XDebug，取消注释以下行，并从 MAMP 控制面板重新启动 Apache 服务器。

```php
**[xdebug]
zend_extension="/Applications/MAMP/bin/php5.3/lib/php/extensions/no-debug-non-zts-20090626/xdebug.so"
xdebug.remote_enable=on
xdebug.remote_handler=dbgp
xdebug.remote_host=localhost
xdebug.remote_port=9000** 

```

XDebug 现在在您的 Mac OSX 上运行。MAMP Pro 用户可以轻松从 MAMP Pro 控制面板编辑`php.ini`，方法是从菜单中选择**文件|编辑模板|PHP 5.3.2 php.ini**。

最后，我们在本地开发环境中启用了 XDebug。

# 使用 NetBeans 调试 PHP 源代码

要继续，我们想检查 NetBeans 所需的调试设置。选择**工具|选项|PHP|调试**选项卡：

![使用 NetBeans 调试 PHP 源代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_04.jpg)

在此窗口中，取消选中**在第一行停止**复选框，因为我们希望在所需行停止，并选中**监视和气球评估**复选框。此选项使您能够在调试时观察自定义表达式或变量。

现在，让我们看一下在 NetBeans 窗口中运行的调试会话：

![使用 NetBeans 调试 PHP 源代码](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_05.jpg)

在此屏幕截图中，调试工具栏和按钮由功能名称表示。

### 注意

从[`netbeans.org/kb/docs/php/debugging.html#work`](http://netbeans.org/kb/docs/php/debugging.html#work)了解有关调试工具栏的更多信息。

## 调试器窗口

当您开始调试会话时，一组调试器窗口会在主编辑器窗口下方打开。要添加新窗口，请选择**窗口|调试**。以下窗口可用：

+   **本地变量**显示了已初始化变量、它们的类型和值的列表

+   **监视**显示了用户定义表达式及其值的列表

+   **调用堆栈**显示了以相反顺序调用的函数列表；最后调用的函数位于列表顶部

+   **断点**显示了设置断点的文件和行号的列表

+   **会话**显示了当前活动调试会话的列表

+   **线程**窗口指示了当前活动的 PHP 脚本以及它是否在断点处暂停或运行。如果脚本正在运行，您需要转到浏览器窗口并与脚本交互。

+   **源**窗口显示了调试会话加载的所有文件和脚本。**源**窗口目前不适用于 PHP 项目。

### 基本调试工作流程

以下是基本的调试工作流程：

1.  用户在应该暂停 PHP 源代码执行的行处设置断点。

1.  当达到该行时，用户通过按下*F7*和*F8*按钮逐行执行脚本，并检查变量的值。

### 注意

有关 NetBeans IDE 调试和测试的键盘快捷键，请参见*附录*。

# 进行操作的时间 — 运行调试会话

本节介绍了标准的调试会话，并且我们将创建一个示例项目来练习调试：

1.  创建一个 NetBeans PHP 项目。对于我们的示例，我们将其命名为`chapter4`。

1.  在`index.php`文件中输入以下代码：

```php
<?php
$fruits = array("Apple", "Banana", "Berry", "Watermelon");
$myfruit = "";
fruit_picker(); //first time call
echo "My fruit is : " . $myfruit . "<br />\n";
fruit_picker(); //second time call
echo "My fruit is now: " . $myfruit . "<br />\n";
fruit_picker(); //third time call
echo "My fruit is finally: " . $myfruit . "<br />\n";
function fruit_picker () {
Global $myfruit, $fruits;
$myfruit = $fruits[rand(0, 3)];
}
?>

```

前面的代码包含：

+   一个包含水果名称的`$fruits`数组。

+   一个包含单个水果名称的字符串的变量`$myfruit`，最初为空字符串。

+   一个`fruit_picker()`方法，它从`$fruits`数组中随机选择一个水果名称并更改`$myfruit`的值。此外，`$fruits`和`$myfruit`在函数内被定义为`全局`，以便函数可以在其全局范围内使用和修改它们。

1.  为了测试调试步骤，我们可以通过按下*Ctrl+F8*在 PHP 块的开头设置断点，如下截图所示，或者简单地点击该行的行号添加断点：![进行操作的时间 — 运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_06.jpg)

1.  要开始调试会话，请按下*Ctrl+F5*，或者从**调试**工具栏中点击**调试项目（第四章）**按钮，或者右键单击项目名称，在项目窗口中选择**调试**。调试器将在断点处停止。浏览器以项目调试 URL 的页面加载模式打开，该 URL 是`http://localhost/chapter4/index.php?XDEBUG_SESSION_START=netbeans-xdebug`。

1.  按下*F7*三次，从断点处进入第三个执行点。调试器将在第一次调用`fruit_picker()`函数的行停止。**变量**窗口显示了变量`$fruits`和`$myfruit`及其值，类似于以下截图：![进行操作的时间 — 运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_07.jpg)

在我们的代码中，您可以看到`fruit_picker()`函数将连续被调用三次。

1.  要进入`fruit_picker()`函数，请按下*F7*，调试器将开始执行`fruit_picker()`内部的代码，如下截图所示：![进行操作的时间 — 运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_08.jpg)

1.  按下*F7*两次，`fruit_picker()`的执行将结束。现在，在**变量**窗口中检查`$myfruit`的新值：![进行操作的时间 — 运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_09.jpg)

1.  再次按下*F7*三次，从第二次调用`fruit_picker()`函数的行进入该函数。由于您已经验证了该函数完美运行，您可能想要取消函数的执行。要**跳出**并返回到下一行，请按下*Ctrl+F7*。![进行操作的时间 — 运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_10.jpg)

请注意，`$myfruit`的值保持变化，您可以将鼠标悬停在该变量上查看它。

1.  由于您刚刚检查并发现您的代码正在正确运行，因此您可以通过按下*F8*来跳过当前行。

1.  最后，您可以通过按下*F7*来浏览下一行，或者通过按下*F8*来跳过并到达末尾。再次，如果您希望结束会话，可以按下*Shift+F5*或单击**完成调试会话**按钮。在会话结束时，浏览器将显示结果（代码输出）。![执行步骤-运行调试会话](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_11.jpg)

## 刚刚发生了什么？

已经进行了调试会话的练习，希望我们已经掌握了使用 NetBeans 进行调试。您还可以添加多个断点以跟踪程序的执行。因此，您可以跟踪程序中的所有变量、表达式、方法调用顺序、程序控制跳转等。这是找出代码内部出现问题的过程。主要是，您现在已经准备好在编码时征服一些不需要的情况或错误。

## 添加监视

通过在代码执行中观察表达式，添加监视表达式可以帮助您捕捉错误。现在，让我们来玩一玩...

# 执行步骤-添加要监视的表达式

例如，我们想要测试`fruit_picker()`函数是否再次选择了相同的水果名称。我们可以在每次选择新的随机水果名称之前保存`$myfruit`的值，并使用表达式比较这两个水果名称。因此，让我们通过以下步骤添加表达式监视器：

1.  修改`fruit_picker()`函数如下：

```php
function fruit_picker() {
Global $myfruit, $fruits;
$old_fruit = $myfruit;
$myfruit = $fruits[rand(0, 3)];
}

```

我们刚刚添加了一行`$old_fruit = $myfruit;`来保存`$myfruit`的先前值，以便我们可以在函数结束时比较`$old_fruit`中的先前选择和`$myfruit`中的新选择。我们实际上想要检查是否选择了相同的水果。

1.  选择**调试|新建监视**或按*Ctrl+Shift+F7*。打开**新建监视**窗口。![执行步骤-添加要监视的表达式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_12.jpg)

1.  输入以下表达式，然后单击**确定**。

```php
($old_fruit == $myfruit)

```

我们将在`fruit_picker()`函数的闭括号（}）处观察此表达式结果。如果表达式在函数闭括号处产生（bool）1，那么我们将知道新选择的水果是否与旧的相同，或者再次选择了相同的水果。添加的监视表达式可以在**监视**和**变量**窗口中找到。

1.  运行调试会话，如前一节所示。当调试器停在`fruit_picker()`函数的闭括号处时，检查表达式值是否为（bool）`0`，如果新选择与旧选择不同，则该值为（bool）`1`，如果是连续选择相同的话，则该值为（bool）`1`。![执行步骤-添加要监视的表达式](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_13.jpg)

通过这种方式，您可以继续观察表达式以查找错误。

## 刚刚发生了什么？

在调试会话中添加监视表达式很有趣。您可以添加多个监视以分析一些编程缺陷。简而言之，调试使您能够查看变量、函数、表达式、执行流程等，因此可以轻松地发现错误并清除它。

### 注意

有关 NetBeans IDE 调试和测试的键盘快捷键，请参阅*附录*。

## 突发测验-使用 XDebug 进行调试

1.  以下哪些是 XDebug 的功能？

1.  出现错误时自动堆栈跟踪

1.  自动修复错误

1.  函数调用日志记录

1.  增强的`var_dump()`

1.  当 NetBeans 中出现断点时会发生什么？

1.  IDE 将跳过断点并显示结果

1.  IDE 将在那一点停止代码执行，让您看看窗口调试中发生了什么

1.  IDE 将终止调试会话并重置正在调试的窗口的结果

1.  以上都不是

1.  监视的目的是什么？

1.  在 NetBeans 中显示时间

1.  在代码执行中观察表达式

1.  观察表达式时间

1.  检查调试会话

## 尝试一下——探索 NetBeans 调试功能

在**调试**窗口中，启用名为**显示请求的 URL**的功能。启用后，在调试期间将出现一个新的**输出**窗口，并显示当前处理的 URL。还要启用另一个名为**PHP 调试器控制台**的**输出**窗口，以查看其中调试脚本的输出。请记住在您的`php.ini`文件中设置`output_buffering = Off`，以立即看到它。

# 使用 PHPUnit 进行测试

源代码测试在测试驱动开发方法中是必不可少的。测试描述了检查代码是否按预期行为的方式，使用一组可运行的代码片段。单元测试测试软件部分（单元）的正确性，其可运行的代码片段称为单元测试。NetBeans IDE 支持使用 PHPUnit 和 Selenium 测试框架进行自动化单元测试。

## 配置 PHPUnit

在 Windows 框中运行 XAMPP 时，它提供了一个内置的 PHPUnit 包。请注意，如果您的项目在 PHP 5.3 中运行，则应使用 PHPUnit 3.4.0 或更新版本。在我们的情况下，最新的 XAMPP 1.7.7（带有 PHP 5.3.8）堆栈中安装了 PHPUnit 2.3.6，这与 PHP 5.3 不兼容。您还需要升级现有的 PHP 扩展和应用程序存储库（PEAR）安装，以安装最新的 PHPUnit 和所需的 PEAR 包。

要检查已安装的 PEAR、PHP 和 Zend 引擎的版本，请从命令提示符或终端中浏览 PHP 安装目录`D:\xampp\php`，并输入`pear version`命令，将得到以下输出：

```php
**PEAR Version: 1.7.2
PHP Version: 5.3.8
Zend Engine Version: 2.3.0
Running on: Windows NT....** 

```

所以现在是安装最新的 PHPUnit 的时候了。为了做到这一点，首先应该升级 PEAR。

# 行动时间——通过 PEAR 安装 PHPUnit

在接下来的步骤中，我们将升级 PEAR 并通过 PEAR 在相应的环境中安装 PHPUnit：

1.  以管理员身份运行命令提示符，转到`pear.bat`文件所属的 PHP 安装目录（D:\xampp\php），并执行以下命令：

```php
**pear upgrade pear** 

```

这将升级现有的 PEAR 安装。在 Ubuntu 或 Mac OS X 系统中，运行以下命令：

```php
**sudo pear upgrade pear** 

```

在 MAMP 的情况下，如果遇到错误 sudo: pear: command not found，则请参阅*配置 MAMP*部分的问题。

1.  要安装最新的 PHPUnit，请输入以下两个命令：

```php
**pear config-set auto_discover 1
pear install pear.phpunit.de/PHPUnit** 

```

它会自动发现下载频道并安装最新的 PHPUnit 以及可用的包。

1.  要检查 PHPUnit 安装，请运行以下命令：

```php
**phpunit version** 

```

您将看到类似以下的命令：

```php
**PHPUnit 3.6.10 by Sebastian Bergmann**.

```

1.  要列出 PHPUnit 的远程包，请运行以下命令：

```php
**pear remote-list -c phpunit** 

```

## 刚才发生了什么？

我们使用`pear upgrade pear`命令升级了 PEAR 安装。我们启用了 PEAR 频道、自动发现配置，并使用这些自动安装频道安装了最新的 PHPUnit。其他 PHP 扩展可以通过这种方式轻松地从扩展存储库中安装。

再次，如果您已经升级了 PEAR 安装并且之前已启用了自动发现功能，那么只有`pear install pear.phpunit.de/PHPUnit`命令就可以完成 PHPUnit 的安装。

### 提示

在 Windows 中以管理员身份运行命令提示符，以便更轻松地处理目录权限。您可以右键单击程序并选择**以管理员身份运行**。

### 配置 MAMP 问题

在使用 MAMP 时，如果在终端中使用 PEAR 命令时遇到错误`pear: command not found`，那么运行`which php`将指向 OS X 的默认版本。

```php
**$ pear -bash: pear: command not found $ which php /usr/bin/php** 

```

您可能需要修复它。为了纠正这一点，我们需要将 PHP 的`bin`目录添加到我们的路径中。`PATH`是一个环境变量，表示要查找命令的目录。可以通过编辑`home`目录下的`.profile`文件来修改`PATH`。我们在本教程中使用了`PHP5.3 bin`版本路径，但您可以从可用的版本中进行选择。

从终端运行以下命令，将所需的 PHP 的`bin`目录添加到`php, pear`和其他相关可执行文件的使用中：

```php
**$ echo "export PATH=/Applications/MAMP/bin/php/php5.3/bin:$PATH" >> ~/.profile** 

```

如您所见，在用户的`home`目录中的`.profile`文件中添加了一行，其中包括`php5.3 bin`目录路径到环境变量`PATH`。

现在，停止 MAMP 并使用以下命令更改文件的权限，使这些文件可执行：

```php
**chmod 774 /Applications/MAMP/bin/php5.3/bin/pear chmod 774 /Applications/MAMP/bin/php5.3/bin/php** 

```

`chmod`命令更改文件模式或访问控制列表。`774`表示文件的“所有者”和文件用户的“组”将被允许读取，写入和执行文件。其他人只能读取它，但不能写入或执行文件。

在编写时，最新的 MAMP 1.9 版本带有损坏的 PHP 版本的`pear.conf`文件。因此，使用以下命令将该文件重命名以防止其加载到系统中：

```php
**mv /Applications/MAMP/conf/php5.3/pear.conf /Applications/MAMP/conf/php5.3/backup_pear.conf** 

```

实际上，在给定的`pear.conf`文件中，PHP 路径字符串包含`php5`而不是`php5.3`或`php5.2`。

现在，重新启动 MAMP 并重新启动您的终端会话。因此，MAMP 的问题已经解决，您可以通过从终端运行`which php`或`which pear`命令来测试它。为了使用 MAMP 安装 PHPUnit，您现在可以继续本章的*安装 PHPUnit via PEAR 的行动时间-步骤 1*。

### 将 PHPUnit 添加到 NetBeans

要将 PHPUnit 设置为 NetBeans IDE 的默认单元测试器，请选择**工具 | 选项 | PHP 选项卡 | 单元测试**选项卡，使用**搜索**自动在**PHPUnit 脚本**字段中输入 PHPUnit 的`.bat`脚本路径，并单击**确定**。

![将 PHPUnit 添加到 NetBeans](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_14.jpg)

同样，对于 Mac OS X，PHPUnit 的路径将类似于`/Applications/MAMP/bin/php5.3/bin/phpunit`。

## PEAR 的小测验

1.  PEAR 代表什么？

1.  PHP 扩展应用程序存储库

1.  PHP 扩展和应用程序存储库

1.  PHP 扩展社区库

1.  PHP 额外适用的存储库

## 创建和运行 PHPUnit 测试

在本节中，我们将学习创建和运行 PHPUnit 测试。NetBeans IDE 可以为文件中的所有 PHP 类创建测试脚本并运行 PHPUnit 测试。IDE 自动化测试脚本生成和整个测试过程。为了确保测试脚本生成器能够正常工作，请将 PHP 文件命名为文件中的第一个类相同的名称。

# 行动时间-使用 PHPUnit 进行测试

在本教程中，我们将创建一个新的 NetBeans 项目，使用 PHPUnit 从 IDE 中测试我们的 PHP 类。为了做到这一点，请按照以下步骤进行操作：

1.  创建一个名为`Calculator`的新项目，在项目中添加一个名为`Calculator`的 PHP 类（右键单击项目节点，然后选择**新建 | PHP 类**，然后插入类名），并为`Calculator`类输入以下代码：

```php
<?php
class Calculator {
public function add($a, $b) {
return $a + $b;
}
}
?>

```

您可以看到`add()`方法只是执行两个数字的加法并返回总和。我们将对这个方法进行单元测试，以查看它是否返回了正确的总和。

1.  在下面的代码中添加一个带有`@assert`注释和一些示例输入和输出的注释块。请注意，以下示例中包含一个不正确的断言：

```php
<?php
class Calculator {
/**
* @assert (0, 0) == 0
* @assert (0, 1) == 1
* @assert (1, 0) == 1
* @assert (1, 1) == 2
* @assert (1, 2) == 4
*/
public function add($a, $b) {
return $a + $b;
}
}
?>

```

1.  在**项目**窗口中，右键单击`Calculator.php`节点，然后选择**工具 | 创建 PHPUnit 测试**。请注意，您可以使用**源文件**节点中的上下文菜单为项目中的所有文件创建测试。![行动时间-使用 PHPUnit 进行测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_15.jpg)

1.  第一次创建测试时，会打开一个对话框，询问您要存储测试脚本的目录。在本例中，可以使用**浏览**功能（按钮）创建一个`tests`目录。![行动时间-使用 PHPUnit 进行测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_16.jpg)

我们可以将测试文件与源文件夹分开。此外，如果您希望将这些测试脚本排除在未来的源代码版本控制之外，可以将它们分开。

1.  IDE 会在名为`CalculatorTest.php`的文件中生成一个测试类，该文件将显示在**项目**窗口中并在编辑器中打开。![行动时间-使用 PHPUnit 进行测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_17.jpg)

请注意，为类内的每个`@assert`注释创建了测试方法。

1.  要测试`Calculator.php`文件，请右键单击文件节点并选择**测试**，或按*Ctrl+F6*。IDE 会运行测试并在**测试结果**窗口中显示结果。![行动时间-使用 PHPUnit 进行测试](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_18.jpg)

正如您所看到的，由于不正确的输入，其中一个测试失败了。这在**测试结果**窗口中用黄色感叹号标记。此外，您可以看到通过和失败的测试数量。因此，可以获得总体通过测试百分比（用绿色条表示）。

1.  请注意，您也可以对整个项目运行测试。右键单击项目节点并选择**测试**，或按*Alt+F6*。还要考虑检查**输出**窗口，以获取更详细的文本输出。

## 刚刚发生了什么？

PHP 类或项目可以部分测试，使用 PHPUnit。这里最好的部分是你不需要担心生成测试脚本并以图形方式显示测试结果，因为 IDE 会处理它。您可以在[`www.phpunit.de/manual/current/en/`](http://www.phpunit.de/manual/current/en/)了解更多关于 PHPUnit 测试的信息。

### 请注意

在[`www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html#writing-tests-for-phpunit.assertions`](http://www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html#writing-tests-for-phpunit.assertions)了解更多关于断言的例子。

## 使用 PHPUnit 处理代码覆盖

NetBeans IDE 通过 PHPUnit 提供了代码覆盖功能。代码覆盖检查 PHPUnit 测试是否覆盖了所有方法。在本节中，我们将看到代码覆盖是如何与我们现有的`Calculator`类一起工作的。

# 使用代码覆盖的行动时间

按照以下步骤查看 NetBeans 中代码覆盖功能的工作方式：

1.  打开`Calculator.php`，添加一个重复的`add`函数，并将其命名为`add2`。`Calculator`类现在看起来类似于以下内容：

```php
<?php
class Calculator {
/**
* @assert (0, 0) == 0
* @assert (0, 1) == 1
* @assert (1, 0) == 1
* @assert (1, 1) == 2
* @assert (1, 2) == 4
*/
public function add($a, $b) {
return $a + $b;
}
public function add2($a, $b) {
return $a + $b;
}
}
?>

```

1.  右键单击项目节点。从**上下文**菜单中选择**代码覆盖|收集和显示代码覆盖**。默认情况下，也会选择**显示编辑器栏**。![行动时间-使用代码覆盖](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_19.jpg)

1.  编辑器现在在底部有一个代码覆盖率编辑器栏。由于代码覆盖率尚未经过测试，编辑器栏报告了`0.0%`的覆盖率（在单击**清除**以清除测试结果后，它还会显示这样的百分比）。![行动时间-使用代码覆盖](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_20.jpg)

1.  单击**测试**以测试已打开的文件，或单击**所有测试**以运行项目的所有测试。测试结果将显示。此外，**代码覆盖**栏会告诉您有多少百分比的方法已被测试覆盖。在编辑器窗口中，覆盖的代码会以绿色突出显示，未覆盖的代码会以红色突出显示。查看以下代码覆盖会话：![行动时间-使用代码覆盖](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_04_21.jpg)

1.  在**代码覆盖率**栏中，点击**报告...**。**代码覆盖率**报告打开，显示了在项目上运行的所有测试的结果。栏中的按钮让你清除结果，重新运行所有测试，并停用代码覆盖率（点击**完成**）。

如你所见，`add2()`方法没有被单元测试覆盖，所以报告显示`50%`的代码覆盖率，否则将显示`100%`的覆盖率。

## 刚刚发生了什么？

我们已经完成了使用 NetBeans 代码覆盖功能与 PHPUnit，因此我们可以确定哪些单元没有被 PHPUnit 测试覆盖。因此，当你为代码单元创建 PHPUnit 测试并希望确保所有单元都已被测试覆盖时，可以应用代码覆盖。但是，预期有一个最大的代码覆盖百分比。

### 提示

重构测试脚本时，也要重构代码。

# 使用 Selenium 框架进行测试

Selenium 是一个用于 Web 应用程序和自动化浏览器的便携式软件测试框架。主要用于跨多个平台自动化测试目的的 Web 应用程序。NetBeans IDE 具有一个包含 Selenium 服务器的插件。通过此插件，你可以在 PHP、Web 应用程序或 Maven 项目上运行 Selenium 测试。要在 PHP 上运行 Selenium 测试，你需要将**Testing_Selenium**包安装到你的 PHP 环境中。

## 安装 Selenium

由于我们已经升级了 PEAR 并安装了最新的 PHPUnit，我们应该已经安装了`Testing_Selenium-beta`。要检查 Selenium 安装，请从终端运行以下命令，你将能够查看已安装的版本：

```php
**pear info Testing_Selenium-beta** 

```

否则，运行以下命令以安装 Selenium：

```php
**pear install Testing_Selenium-0.4.4** 

```

# 运行 Selenium 测试的时间

让我们通过以下步骤使用 Selenium 运行测试：

1.  要安装插件，打开**工具 | 插件**，并为 PHP 安装**Selenium 模块**。

1.  在**项目**窗口中，右键单击**计算器**项目的项目节点。选择**新建 | 其他**。**新建文件**向导打开。选择**Selenium**，然后点击**下一步**。

第一次创建 Selenium 测试时，会打开一个对话框，询问你为 Selenium 测试文件设置一个目录。这应该是一个与 PHPUnit 测试文件分开的目录；否则，每次运行单元测试时都会运行 Selenium 测试。运行功能测试，如 Selenium，通常比运行单元测试需要更多时间。因此，你可能不想每次运行单元测试时都运行这些测试。

1.  在**名称**和**位置**页面中接受默认设置，然后点击**完成**。新的 Selenium 测试文件将在编辑器中打开，并出现在**项目**窗口中。

1.  **运行 Selenium 测试**项现在已添加到项目的上下文菜单中。点击此项，Selenium 测试结果将显示在**测试结果**窗口中，与 PHPUnit 测试相同。

你还可以修改 Selenium 服务器的设置。Selenium 服务器被添加为**服务**选项卡中的新服务器。

## 刚刚发生了什么？

我们刚刚使用了 Selenium 测试框架进行测试，用于 PHP 应用程序。它为开发人员提供了跨多个操作系统、浏览器和编程语言的测试支持，并允许录制、编辑和调试测试。简而言之，这是测试人员的完整测试解决方案。你可以使用 Selenium 随着代码结构的演变来演变你的测试。该软件基于 PHPUnit 框架，并继承了其大部分功能。

### 注意

你可以从这里了解更多关于 Selenium 测试：[`seleniumhq.org/`](http://seleniumhq.org/)。

## 小测验 — 单元测试和代码覆盖率

1.  什么是单元测试？

1.  测试代码的最小可测试部分

1.  测试类的各个方法

1.  测试，您知道输入和输出是什么

1.  以上所有

1.  减去两个数字的测试中哪个断言会失败？

1.  `@assert (0, 0) == 0`

1.  `@assert (2, 3) == -1`

1.  `@assert (4, 2) == 3`

1.  `@assert (5, 1) == 4`

1.  如果在一个只包含一个方法的类中测试单元时通过了六个测试并且失败了四个测试，那么代码覆盖百分比将是多少？

1.  `60%`

1.  `50%`

1.  `100%`

1.  `40%`

1.  Selenium 测试框架的特性不包括哪个？

1.  自动化浏览器

1.  通过手动测试遗漏的缺陷

1.  观察表达式

1.  无限次执行测试用例

## 尝试一下 —— 学习测试依赖关系

一个单元测试通常涵盖一个函数或方法，并且也可以依赖于其他单元测试。现在，使用`@depends`注释来表示单元测试的依赖关系，并借助[`www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html#writing-tests-for-phpunit.test-dependencies`](http://www.phpunit.de/manual/current/en/writing-tests-for-phpunit.html#writing-tests-for-phpunit.test-dependencies)进行实践。

### 注意

查看*附录*以获取 NetBeans IDE 调试和测试的键盘快捷键。

# 摘要

在本章中，我们已经学会了使用 NetBeans 调试和测试 PHP 应用程序。该 IDE 已经以有效的方式与这些调试和测试工具集成在一起。此外，对于自动化测试，生成的脚本使该过程变得轻松和简单。

具体来说，我们已经专注于：

+   各种操作系统上的 XDebug 配置

+   使用 NetBeans 和 XDebug 运行调试会话

+   安装 PHPUnit

+   使用 PHPUnit 进行单元测试

+   使用 PHPUnit 和 NetBeans 进行代码覆盖率

+   使用 NetBeans 引入 Selenium 测试框架

现在使用调试和测试工具变得更加容易。在下一章中，我们将强调源代码和 API 文档，以使我们的源代码更易理解。


# 第五章：使用代码文档

> 代码告诉你如何做，注释告诉你为什么 - Jeff Atwood

在这一章中，我们将使用 NetBeans IDE 来记录我们的 PHP 源代码。我们将学习如何快速记录变量、方法、类或整个项目，并讨论以下问题：

+   源文档的约定

+   如何记录源代码

+   PHP 项目 API 文档

# 编写优秀的文档

编码是指导机器的艺术，当涉及到人类可读性时，代码应该是表达性的、自解释的和美观的。代码应该是可重用和可理解的，这样你可以在几个月后再次使用它。一个好的实践者会尽可能地简化代码，只在真正需要的地方保留代码文档。

代码文档是编码的激励部分，特别是当你在协作团队环境中工作时；文档应该以一种明智的方式完成，这样学习代码的意图在协作者之间可以更快地进行。

记录源代码的常规做法是在代码中放置符合**PHPDoc**格式的注释，这样你的代码就变得更有意义，外部文档生成器可以解析这样的注释。

# PHPDoc——PHP 的注释标准

PHPDoc 是针对 PHP 编程语言的 Javadoc 的一种适应。由于它是 PHP 代码的标准注释，它允许外部文档生成器，如 phpDocumentor 和 ApiGen 为 API 生成 HTML 文档。它有助于各种 IDE，如 NetBeans，PhpStorm，Zend Studio 和 Aptana Studio，解释变量类型并提供改进的代码完成、类型提示和调试。根据 PHPDoc，文档是使用名为**DocBlock**的文本块编写的，这些文本块位于要记录的元素之前。作为描述编程构造的一种方式，例如类、接口、函数、方法等，标签注释被用在 DocBlock 内部。

## DocBlock 的例子

DocBlock 是一个扩展的 C++风格的 PHP 注释，以"/**"开头，每一行都以"*"开头。

```php
/**
* This is a DocBlock comment
*/

```

DocBlock 包含三个基本部分，按照以下顺序：

+   简短描述

+   长描述

+   标签

例子：

```php
/**
* Short description
*
* Long description first sentence starts here
* and continues on this line for a while
* finally concluding here at the end of
* this paragraph
*
* The blank line above denotes a paragraph break
*/

```

简短描述从第一行开始，可以用空行或句号结束。单词中的句号（例如`example.com`或`0.1 %)`会被忽略。如果简短描述超过三行，那么只有第一行会被采用。长描述可以继续多行，并且可以包含用于显示格式的 HTML 标记。外部文档解析器将在长描述中将所有空格转换为单个空格，并可能使用段落分隔符来定义换行，或者`<pre>`，如下一节所述。

DocBlock 的长描述和简短描述会被解析为一些选定的 HTML 标签，这些标签使用以下标签进行附加格式化：

+   `<b>:` 这个标签用于强调/加粗文本

+   `<code>:` 这个标签用于包围 PHP 代码；一些转换器会对其进行高亮显示

+   `<br>:` 这个标签用于提供硬换行，并且可能会被一些转换器忽略

+   `<i>:` 这个标签用于将文本标记为重要的斜体

+   `<kbd>:` 这个标签用于表示键盘输入/屏幕显示

+   `<li>:` 这个标签用于列出项目

+   `<ol>:` 这个标签用于创建有序列表

+   `<ul>:` 这个标签用于创建无序列表

+   `<p>:` 这个标签用于包含所有段落；否则，内容将被视为文本

+   `<pre>:` 这个标签用于保留换行和间距，并假定所有标签都是文本（就像 XML 的 CDATA）

+   `<samp>:` 这个标签用于表示样本或示例（非 PHP）

+   `<var>:` 这个标签用于表示变量名

在罕见的情况下，如果需要在 DocBlock 中使用文本`"<b>"`，请使用双定界符，如`<<b>>`。外部文档生成器将自动将其转换为物理文本`"<b>"`。

## 熟悉 PHPDoc 标签

PHPDoc 标签是以`@`符号为前缀的单词，并且只有在它们是 DocBlock 新行上的第一件事情时才会被解析。DocBlock 在结构元素之前，这些元素可以是编程构造，如命名空间、类、接口、特征、函数、方法、属性、常量和变量。

一些常见的标签列表及详细信息已分成组，以便更好地理解，如下所示：

### 数据类型标签

| 标签 | 用法 | 描述 |
| --- | --- | --- |
| `@param` | 类型`[$varname]` 描述 | 记录函数或方法的参数。 |
| `@return` | `类型描述` | 文档化函数或方法的返回类型。此标记不应用于构造函数或返回类型为`void`的方法。 |
| `@var` | `类型` | 记录类变量或常量的数据类型。 |

### 法律标签

| 标签 | 用法 | 描述 |
| --- | --- | --- |
| `@author` | 作者名称`<author@email>` | 记录当前元素的作者 |
| `@copyright` | `名称日期` | 记录版权信息 |
| `@license` | `URL 名称` | 用于指示适用于相关结构元素的许可证 |

### 版本标签

| 标签 | 用法 | 描述 |
| --- | --- | --- |
| `@version` | `版本字符串` | 提供类或方法的版本号 |
| `@since` | `版本字符串` | 记录发布版本 |
| `@deprecated` | `版本描述` | 用于指示哪些元素已被弃用并将在将来的版本中被移除 |
| `@todo` | `信息字符串` | 记录需要在以后的日期对代码进行的事情 |

### 其他标签

| 标签 | 用法 | 描述 |
| --- | --- | --- |
| `@example` | `/path/to/example` | 记录外部保存示例文件的位置 |
| `@link` | `URL 链接文本` | 记录 URL 引用 |
| `@see` | `逗号分隔的元素名称` | 记录任何元素 |
| `@uses` | `元素名称` | 记录元素的使用方式 |
| `@package` | `包的名称` | 记录一组相关的类和函数 |
| `@subpackage` | `子包的名称` | 记录一组相关的类和函数 |

在最常用的标签中，`@param`和`@return`只能用于函数和方法，`@var`用于属性和常量，`@package`和`@subpackage`用于过程页面或类，而其他标签，如`@author，@version`等，可以用于任何元素。除了这些标签，`@example`和`@link`可以用作内联标签。

### 注意

您可以在[`www.phpdoc.org/docs/latest/for-users/list-of-tags.html`](http://www.phpdoc.org/docs/latest/for-users/list-of-tags.html)找到标签列表。

现在，我们将深入使用 NetBeans 来记录我们的 PHP 源代码。

# 记录源代码

在本节中，我们将学习如何记录函数、方法、类、接口、全局变量、常量等，并讨论使用此类代码文档的好处。如前所述，在协作开发环境中，方法、类等的描述对于了解代码的意图非常重要，我们将在本节中实际实现这一点。

现在，在 NetBeans 中创建一个名为`Chapter5`的新 PHP 项目，并将其用于所有接下来的教程。

## 记录函数和方法

在本节中，我们将学习如何在 PHP 函数或方法的开头使用 NetBeans 自动文档功能。

# 行动时间 - 文档化 PHP 函数或方法

在本教程中，让我们创建一个简单的 PHP 函数或方法，其中传入一些参数，并在其中声明不同类型的变量。我们只是在练习，看看 NetBeans 自动生成文档生成器在这些常用的结构元素上是如何工作的。让我们按照以下步骤进行：

1.  在项目中添加一个名为`sample1.php`的 PHP 文件，并输入一个 PHP 函数，如下所示：

```php
function testFunc(DateTime $param1, $param2, string $param3 = NULL)
{
$number = 7;
return $number;
}

```

在这个函数中，我们可以看到有三个参数传递到`testFunc`方法中-`$param1`作为`DateTime`，`$param2`没有类型提示，因为它可能具有混合类型的值，`$param3`是可选的，默认值为`NULL`。此外，在函数体内，函数包含一个整数类型变量，并且也返回该整数类型。

1.  在`testFunc`函数之前的行中键入`/**`，然后按*Enter*。您会看到 NetBeans 解析函数并在函数之前根据 PHPDoc 标准生成文档，看起来类似于以下内容：

```php
**/**
*
* @param DateTime $param1
* @param type $param2
* @param string $param3
* @return int
*/**
function testFunc(DateTime $param1, $param2, string $param3 = NULL)
{
$number = 7;
return $number;
}

```

在前面的代码片段中，我们可以看到 NetBeans 生成了文档，其中提到了参数和返回类型，列举如下：

+   参数用`@param`标记注释，并且从给定的类型提示中获取参数类型

返回类型用`@return`进行注释

您可以看到每个标签旁边的类型和名称之间用空格分隔。如果类型提示不可用，那么 NetBeans 会将其保留为简单的`type`，例如`$param2`。在文档中通常使用的词是当真实数据类型未知时使用`"mixed"`，您也可以编辑该`"type"`。

1.  您可以在文档中为每个变量添加描述；在变量名旁边，只需加上一个前导空格的描述，如下所示：

```php
/**
*
* @param DateTime $param1 this is parameter1
* @param array $param2 this is parameter2
* @param string $param3 this is parameter3 which is optional
* @return int what is returned, goes here
*/

```

1.  此外，您可能希望为文档添加一个简短的描述，看起来类似于以下内容：

```php
/**
* a short description goes here
*
* @param DateTime $param1 this is parameter1
* @param array $param2 this is parameter2
* @param string $param3 this is parameter3 which is optional
* @return int what is returned, goes here
*/

```

1.  现在，让我们看看这个 NetBeans 生成的文档是什么样子，当有人试图从项目中的任何地方调用这个`testFunc`时。尝试在任何地方输入函数名。比如，在项目内的`index.php`文件中开始输入函数名，你会看到 NetBeans 自动提示该函数名以及参数提示和文档，如下所示：![操作时间-记录 PHP 函数或方法](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_01.jpg)

如果函数或任何元素有文档可用，那么 NetBeans 在自动建议过程中显示文档，就像前面的截图中所示的那样。

## 刚刚发生了什么？

我们刚刚学会了如何使用 NetBeans 自动生成文档生成器。通过在函数之前键入`/**`并按*Enter*，我们可以解析元数据并生成文档。我们也可以更新文档。同样，外部文档生成器可以提取这样的 DocBlocks 来创建项目 API 文档。现在，我们将在下一节中在 PHP 类之前添加文档。

## 记录类

在类之前的文档非常重要，可以了解类及其用法。最佳实践是使用适当的注释对前面的文档进行装饰，例如`@package, @author, @copyright, @license, @link`和`@version`，并对类进行适当的描述。

# 操作时间-记录 PHP 类和类变量

在这一部分，我们将使用 NetBeans 添加一个 PHP 类，并使用类文档标签更新前面的 DocBlock。所以让我们开始吧...

1.  右键单击`Chapter5`项目选择**新建|PHP 类...**，在**文件名**框中插入类名`Test`，然后点击**完成**，如下所示：![操作时间-记录 PHP 类和类变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_02.jpg)

1.  `Test`类应该看起来类似于以下内容：![操作时间-记录 PHP 类和类变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_03.jpg)

在上一张截图中，您可以看到打开的`Test class`在顶部添加了一个带有示例类描述和`@author`标签的 DocBlock。

1.  您可能希望在包含`@author`标签的行之前添加 PHPDoc 标签；假设您想要在键入`@p`时立即添加`@package`标签。NetBeans 代码自动完成功能显示以`@p`开头的标签，其描述看起来类似于以下截图：![执行时间-记录 PHP 类和类变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_04.jpg)

1.  使用您自己的方式更新 DocBlock，使其看起来类似于以下内容：

```php
**/**
* Short description of the Test Class
*
* Long multiline description of the Test Class goes here
*
* Note: any notes required
* @package Chapter5
* @author M A Hossain Tonu
* @version 1.0
* @copyright never
* @link http://mahtonu.wordpress.com
*/**

```

1.  在上述文档中，您可以看到已为类添加了相应的标签，因此在尝试使用代码完成实例化类对象时，可以使用类信息，如下所示：![执行时间-记录 PHP 类和类变量](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_05.jpg)

此外，可以使用外部 API 文档生成器提取这样的类 DocBlock。

1.  现在，按照以下方式在`Test`类中输入一个名为`$variable`的类变量：

```php
public $variable;

```

1.  要添加类变量文档，请键入`/**`，并在声明它的行之前按*Enter*，以便文档看起来类似于以下内容：

```php
/**
*
* @var type
*/

```

1.  在这里，您可以按照以下方式更新块：

```php
/**
* example of documenting a variable's type
* @var string
*/

```

1.  为了在以后的部分查看类层次结构树，您可以在我们的项目中添加一个名为`TestChild`的子类，扩展`Test`类，看起来类似于以下内容：

```php
/**
* Short description of the TestChild Class
*
* Long multiline description of the TestChild Class goes here
*
* Note: any notes required
* @package Chapter5
* @author M A Hossain Tonu
* @version 1.0
* @copyright never
* @link http://mahtonu.wordpress.com
*/
class TestChild extends Test {
}

```

## 刚刚发生了什么？

我们已经练习了如何在 PHP 函数、类及其属性之前添加文档，并测试了这些文档信息如何在整个项目中可用。相同风格的 DocBlock 或适当的标签也适用于文档化 PHP 接口。

## 记录 TODO 任务

您可以使用`@todo`标签为元素添加计划更改的文档，这些更改尚未实施，该标签几乎可以用于可以文档化的任何元素（全局变量、常量、函数、方法、定义、类和变量）。

# 执行时间-使用@todo 标签

在本教程中，我们将学习如何使用`@todo`标签记录我们的未来任务，并将从 NetBeans 任务或操作项窗口查看任务列表：

1.  在`TestChild`PHP 类内或类的前面文档块中，我们可以使用`@todo`标签；在多行注释或 DocBlock 中，添加类似于以下内容的标签：

```php
/**
* @todo have to add class variable and functions
*/

```

在上面的文档块中，我们可以看到任务已经被描述在标签旁，用空格分隔。此外，可以使用单行注释添加`@todo`标签，如下所示：

```php
//TODO need to add class variable and functions

```

1.  因此，`TestChild`类可能看起来类似于以下内容：

```php
class TestChild extends Test {
//TODO have to add class variable and functions
}

```

1.  当我们在文件中添加任务时，任务应该在 NetBeans 的**任务**或**操作项**窗口中可见；按下*Ctrl* + *6*打开窗口，添加的任务应该在**任务**窗口中列出，如下截图所示：![执行时间-使用@todo 标签](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_06.jpg)

## 刚刚发生了什么？

使用`TODO`任务标记添加新任务后，NetBeans 会立即更新**任务**窗口中的任务列表，并且您可以在该窗口中列出整个项目或所有在 NetBeans 中打开的项目的所有任务。当我们有想要实现但没有足够时间编写代码的想法时，可以使用这些标签，考虑到其未来的实现。因此，您可以使用`@todo`标签在适当的位置放下这个想法。

到目前为止，我们已经学会了如何使用 PHPDoc 标准标签来记录 PHP 源元素，并处理了 DocBlock 来编写源文档。已经讨论了有关源文档的基本概念。因此，在我们的下一节中，我们将学习如何提取这样的 DocBlock，以为整个项目或 API 生成 HTML 文档。

# 记录 API

正如我们已经讨论过源代码文档的重要性，文档应以一种井然有序的方式呈现给一般用户，或者使用 HTML 页面进行图形化阐述。这样的 API 文档，从源 DocBlocks 转换而来，可以作为了解源代码的技术文档。NetBeans 支持使用**ApiGen**自动文档工具从整个项目的 PHP 源代码生成 API 文档。

ApiGen 是使用 PHPDoc 标准创建 API 文档的工具，并支持最新的 PHP 5.3 功能，如命名空间、包、文档之间的链接、对 PHP 标准类和一般文档的交叉引用、高亮源代码的创建，以及对 PHP 5.4 traits 的支持。它还为项目生成了一个包含类、接口、traits 和异常树的页面。

### 提示

查看 ApiGen 的功能：`http://apigen.org/##features`。

在下一节中，我们将讨论如何安装 ApiGen 并在 NetBeans 中配置它。

## 配置 ApiGen

我们将首先通过 PEAR 安装 ApiGen 并在 NetBeans 中配置它，以便我们可以从 IDE 生成 API 文档。我们可以启用 PEAR 自动发现功能，自动安装 ApiGen 及其所有依赖项。启用发现功能不仅会自动将 ApiGen 添加到系统路径，还允许轻松更新每个 ApiGen 组件。

# 操作时间-安装 ApiGen 并在 NetBeans 中配置

我们已经熟悉了通过 PEAR 安装 PHP 库（在上一章中讨论过），并且可能已经将 PEAR 配置`auto_discover`设置为 ON。在本节中，我们将使用以下步骤在 NetBeans 中安装和配置 ApiGen：

1.  从终端或命令提示符中运行以下命令安装 ApiGen：

```php
**pear config-set auto_discover 1
pear install pear.apigen.org/apigen**

```

`install`命令将自动下载并安装 ApiGen 以及其所有依赖项。如果您已经启用了 PEAR`auto_discover`，则跳过第一个命令。

1.  现在，我们需要将 ApiGen 可执行文件添加到 IDE 中。从**工具|选项**中打开**IDE 选项**窗口，选择**PHP 选项卡|ApiGen**选项卡，然后单击**搜索...**按钮搜索 ApiGen 脚本。ApiGen 脚本应该会自动列出，如下图所示：![操作时间-安装 ApiGen 并在 NetBeans 中配置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_07.jpg)

1.  从上一张截图中，选择`apigen.bat`（Windows 操作系统）或`apigen`（其他操作系统），然后按**确定**，将 ApiGen 脚本集成到 IDE 中，如下图所示：![操作时间-安装 ApiGen 并在 NetBeans 中配置](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_08.jpg)

您也可以在那里浏览 ApiGen 脚本路径。

1.  按**确定**保存设置。

## 刚刚发生了什么？

到目前为止，我们已经在 NetBeans 中配置了 ApiGen 工具，该工具已准备好用于 PHP 项目。一旦您将该工具与 IDE 集成，您可能希望从 IDE 中使用它为您的 PHP 项目生成 HTML 文档。在我们的下一个教程中，我们将学习如何从 IDE 中使用该工具。

## 生成 API 文档

我们将使用 ApiGen 为示例 PHP 项目`Chapter5`生成 HTML 文档，并且该工具从项目中可用的 DocBlocks 中提取文档。生成过程可以在 IDE 的**输出**窗口中查看。最后，生成的 HTML 文档将在 Web 浏览器中打开。

# 操作时间-使用 ApiGen 生成文档

使用 IDE 集成的 ApiGen，我们将运行文档生成器。请注意，我们需要定义目标目录以存储 HTML 文档。根据以下步骤为我们的示例项目创建 HTML 文档：

1.  右键单击`chapter5`项目节点。从上下文菜单中，选择**属性 | ApiGen**，将显示以下**项目属性**窗口：![Time for action — generating documentation using ApiGen](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_09.jpg)

1.  从上一个**项目属性**窗口中，定义 HTML 页面将存储的**目标目录**，并取消选中**PHP**框以排除文档中的 PHP 默认元素。在此项目中，让我们在项目内创建一个名为`doc`的目录作为目标目录，以便可以在`http://localost/chapter5/doc/`上浏览文档。

1.  点击**确定**保存设置。

1.  现在，右键单击`chapter5`项目节点。这将生成一个菜单，看起来类似于以下屏幕截图：![Time for action — generating documentation using ApiGen](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_10.jpg)

1.  从上一个项目上下文菜单中，选择**生成文档**以开始从给定的 DocBlocks 生成 HTML 文档的过程。

1.  在上一步中选择**生成文档**后，HTML 文档生成器开始进行进展，并完成了 HTML 文档。生成过程总结在**输出**窗口中，如下所示：![Time for action — generating documentation using ApiGen](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_11.jpg)

1.  此外，整个项目的 HTML 文档也已在浏览器中打开，看起来类似于以下内容：![Time for action — generating documentation using ApiGen](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_12.jpg)

在上面的屏幕截图中，我们可以看到已为整个项目创建了 HTML 文档。文档按照包、类和函数在左侧框架中的顺序进行组织。

1.  浏览为项目创建的链接，并探索类和方法在那里是如何表示的。您可以点击上一个窗口中的**TestChild**类链接，以获取以下屏幕截图：![Time for action — generating documentation using ApiGen](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_05_13.jpg)

1.  在上面的屏幕截图中，我们可以看到类继承也使用树形图表示，并且根据其 DocBlock 适当装饰了类的文档。

## 刚刚发生了什么？

我们从源代码注释块中创建了专业的 API 文档，并发现了类在最终文档中是如何被正确组织的。请注意，ApiGen 在生成的 HTML 界面上为类、函数等提供了搜索功能，并提供了可自定义的模板功能，以修改整体文档的外观。我们现在有足够的信心有效地为 PHP 源代码进行文档化。

## 快速测验 —— 复习标签

1.  以下哪个标签仅适用于函数或方法？

1.  `@author`

1.  `@package`

1.  `@param`

1.  `@link`

1.  以下哪个标签可用于文档化任何元素的发布版本？

1.  `@version`

1.  `@since`

1.  `@deprecated`

1.  `@todo`

1.  以下哪个标签可以用作内联标签？

1.  `@example`

1.  `@param`

1.  `@version`

1.  `@see`

## 尝试更多的英雄 —— 处理文档

每次运行 NetBeans 文档生成器时，它都会清除目标目录并在那里创建一组新的 HTML 文档。尝试对接口、常量、特性等进行注释，并运行文档生成器以测试生成的 API 文档。

# 总结

在本章中，我们已经讨论并练习了如何使用 NetBeans 为 PHP 应用程序文档化源代码。

我们特别关注了以下主题：

+   PHPDoc 标准和标签

+   文档化 PHP 函数/方法、类及其变量

+   文档化 TODO 任务

+   使用 NetBeans 配置 ApiGen

+   使用 ApiGen 进行 API 文档

最后，使用自动文档生成器非常有趣，并且在几秒钟内生成了 HTML 文档。

在我们下一章进行协作 PHP 开发时，需要这样的源代码文档，以便在开发团队内保持良好的实践。在下一章中，我们将学习如何从 NetBeans 使用版本控制系统（Git）。


# 第六章：了解 Git，NetBeans 方式

> 尽早提交，经常提交。

在本章中，我们将介绍版本控制系统，以管理我们源代码中的更改。为此，我们将学习使用**Git**，一个免费的开源分布式版本控制系统。我们将逐步从 NetBeans 中使用 Git。特别是，我们将讨论以下问题：

+   版本控制系统

+   **分布式版本控制系统**（**DVCS**）

+   Git-快速和分布式版本控制系统

+   初始化 Git 存储库

+   克隆 Git 存储库

+   将文件暂存到 Git 存储库

+   将更改提交到 Git 存储库

+   比较文件修订版，并恢复更改

+   与远程存储库一起工作-获取、拉取和推送

+   使用分支-创建、检出、切换、合并和删除

# 版本控制系统

版本控制系统（**源代码管理**或**SCM**的一个方面）是一种技术和实践的组合，用于跟踪和控制对项目文件的更改，特别是对于源代码、文档和网页。

版本控制如此普遍的原因是它几乎涵盖了项目运行的每个方面-开发者之间的沟通、发布管理、错误管理、代码稳定性和实验性开发工作，以及特定开发人员的更改归因和授权。版本控制系统在所有这些领域提供了一个中央协调力量。

版本控制的核心活动是**变更管理**-识别对项目文件所做的每个离散更改，用其元数据注释每个更改，例如更改的时间戳和作者，然后以任何方式回放这些事实给询问的人。这是一种通信机制，其中变更是信息的基本单元，这些变更可以与某些类型的合并文件进行比较和恢复。

![版本控制系统](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_01.jpg)

现在让我们讨论常见的版本控制系统术语：

+   **存储库：**存储库，也称为**repo**，是文件的当前和历史数据存储的地方。版本控制系统的核心是存储库，该存储库可以集中或分布式存储该系统的数据。存储库通常以文件系统树的形式存储信息，这是文件和目录的层次结构。

+   **工作副本：**工作副本是开发者的私有目录树，包含项目的源代码文件，可能还包括其网页或其他文档。工作副本还包含一些由版本控制系统管理的元数据，告诉工作副本来自哪个存储库，文件的“修订版”是什么，等等。通常，每个开发者都有自己的工作副本，他在其中进行更改和测试，并从中提交。

在分散式版本控制系统中，每个工作副本本身就是一个存储库，更改可以推送到（或拉入）任何愿意接受它们的存储库。

+   **工作树：**这是实际的、已检出的文件树。工作树通常等于 HEAD，再加上您所做的但尚未提交的本地更改。

+   **Origin：**这指的是原始存储库，或默认的上游存储库。大多数项目至少有一个上游项目进行跟踪。默认情况下，origin 用于此目的。

+   **Master：**这指的是默认的开发分支。

+   **HEAD：**这是分支中的最新版本。

+   **提交：**用于对项目进行更改；更正式地说，以一种可以合并到项目未来发布中的方式将更改存储在版本控制数据库中。提交创建一个新版本，本质上是项目中文件的快照在特定时间点上。

+   **索引：**这是一个带有统计信息的文件集，其内容被存储。

索引被用作工作目录和存储库之间的暂存区。您可以使用索引来积累一组要一起提交的更改。当您创建一个提交时，提交的是当前在索引中的内容，而不是在您的工作目录中的内容。

+   **修订：**“修订”通常是指特定文件或目录的特定版本。例如，如果项目从文件`F`的修订`6`开始，然后有人对`F`进行了更改，这将产生`F`的修订`7`。

+   **检出：**检出是从存储库获取项目、文件、修订等的过程。检出通常会生成一个名为“工作副本”的目录树，可以将更改提交回原始存储库。

+   **分支：**这是项目的一个副本，在版本控制下，但是被隔离了，所以对分支的更改不会影响项目的其余部分。分支也被称为**开发线**。即使项目没有明确的分支，开发仍然被认为是在“主分支”上进行的，也被称为“主线”或“主干”。

+   **合并：**合并需要将一个分支的更改复制到另一个分支。这涉及从主干到其他分支的合并，或者反之亦然。

合并还有第二个相关的含义——当版本控制系统发现两个人以非重叠方式更改了同一个文件时，它会执行合并。由于这两个更改不会相互干扰，当一个人更新他们的文件副本（已包含他们自己的更改）时，另一个人的更改将自动合并进来。这是非常常见的，特别是在多人同时修改同一代码的项目中。当两个不同的更改重叠时，结果就是**冲突**。

+   **冲突：**当两个人试图对代码中的同一区域进行不同的更改时，就会发生冲突。所有版本控制系统都会自动检测冲突，并通知至少一个涉及的人，他们的更改与其他人的冲突。然后由该人解决冲突并将解决方案通知给版本控制系统。

+   **还原：**为了回滚到上一个修订版本，我们会还原更改；也就是说，我们放弃更改并返回到上次更新的点。当你破坏了本地构建并且无法弄清楚如何让它再次工作时，这是很方便的。有时候还原比调试更快，特别是如果你最近已经检查过。

+   **差异：**这是一个可查看的更改表示，它显示了哪些行发生了更改，以及如何更改，以及两侧周围上下文的几行。已经熟悉某些代码的开发人员通常可以阅读针对该代码的差异，理解更改的作用，甚至发现错误。

+   **标签：**标签是指定修订的特定文件集的标签。标签通常用于保留项目的有趣快照。例如，通常为每个公共发布制作一个标签，以便可以直接从版本控制系统获取组成该发布的确切文件/修订。

## 分布式版本控制

一些版本控制系统是集中式的——有一个单一的主存储库，存储了对项目所做的所有更改。其他是分散式的——每个开发者都有自己的存储库，更改可以在存储库之间任意交换。

在分布式版本控制系统（如 Git、Mercurial 或 Bazaar）中，开发者（客户端）不仅仅是检出文件的最新快照，还完全镜像存储库。

让我们看一下分布式版本控制的示意图：

![分布式版本控制](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_02.jpg)

# Git 快速分布式版本控制系统

Git 是一个免费的开源分布式版本控制系统，旨在以速度和效率处理从小型到非常大型的项目。在 Git 中，您可以拥有自己的本地存储库，并几乎所有操作都在本地进行。

每个 Git 克隆都是一个完整的存储库，具有完整的历史记录和完整的修订跟踪功能，不依赖于网络访问或中央服务器。分支和合并都很快且易于操作。

Git 用于对文件进行版本控制，类似于 Mercurial、Subversion、CVS、Perforce 等工具（[`git-scm.com/`](http://git-scm.com/)）。

### 注意

Git 最初是由*Linus Torvalds*为 Linux 内核开发而设计和开发的。

# 了解 Git，NetBeans 的方式

NetBeans IDE 为 Git 版本控制客户端提供了出色的支持。IDE 的 Git 支持允许您直接从 IDE 中的项目执行版本控制任务。您可以通过两种方法拥有 Git 存储库，第一种方法是将现有项目或目录导入 Git，第二种方法是从另一台服务器计算机克隆现有的 Git 存储库。

在接下来的章节中，我们将使用 NetBeans 尝试初始化一个 Git 存储库，并学习如何克隆一个 Git 存储库。为此，我们将创建一个名为`Chapter6`的示例 NetBeans 项目，其中项目元数据存储在一个单独的目录中，因为我们不需要将项目元数据纳入版本控制，并将在项目目录中进行练习。

## 初始化 Git 存储库

如果您要在 Git 中跟踪现有项目，或者希望将现有项目纳入版本控制，则需要初始化 Git 存储库。

# 操作时间-初始化 Git 存储库

要从现有项目或尚未纳入版本控制的源文件初始化 Git 存储库，可以按照以下步骤进行：

1.  右键单击项目`Chapter6`，然后从上下文菜单中选择**版本控制|初始化 Git 存储库**。![操作时间-初始化 Git 存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_03.jpg)

1.  现在，在**初始化 Git 存储库**对话框中指定存储库将被创建的目录路径。在我们的情况下，我们选择相同的项目路径。

1.  点击**确定**，您可以在**输出**窗口（*Ctrl*+*4*）中检查存储库创建的进度或状态，如下所示：![操作时间-初始化 Git 存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_04.jpg)

在您的项目目录下将创建一个`.git`子目录，其中存储了项目快照的所有数据。Git 开始对指定目录中的所有文件进行版本控制。

您可以看到项目文件都标记为`-/Added`。要查看文件状态，只需将鼠标悬停在文件名上，如下截图所示：

![操作时间-初始化 Git 存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_05.jpg)

我们可以看到文件状态显示为绿色，位于斜杠右侧。

还要注意，`index.php`文件中新增的行以绿色标记，如前面的截图所示。您可以在绿色高亮上悬停以查看自上一版本以来新增的行数。一旦 Git 存储库创建完成，IDE 中的所有 Git 选项都可以直接在**团队**菜单或当前项目的**团队|Git**子菜单下使用。

## 刚刚发生了什么？

我们已成功使用 NetBeans 初始化了 Git 存储库，将现有项目文件纳入版本控制。因此，我们拥有了自己的完整的本地 Git 存储库。

要使用远程仓库，您可以将远程 Git 仓库添加为此初始化仓库的源。这样，您可以将本地仓库与远程仓库同步。现在，我们可以添加文件或直接将它们提交到本地 Git 仓库；但在此之前，让我们尝试通过克隆 Git 仓库的第二种方法。请注意，除了克隆仓库，我们还可以创建另一个新项目。

## 克隆 Git 仓库

假设您已被添加为 Git 下维护的现有项目的合作者。如果您想获取现有 Git 仓库的副本或者您想要贡献的项目，您将需要该仓库的 Git 克隆。直接合作者是由仓库所有者添加的值得信赖的有经验的开发者，他们为项目做出贡献并可以在原始仓库中执行常规的 Git 操作。

在本教程中，我们已经在 GitHub.com（免费的 Git 托管）上创建了一个名为`chapter6demo`的 Git 仓库（[`github.com/mahtonu/chapter6demo`](https://github.com/mahtonu/chapter6demo)），并且为测试目的，我们已经将另一个账户添加为合作者。现在，我们将从 GitHub.com 克隆该仓库，并使用合作者账户在 NetBeans IDE 中练习常规的 Git 功能。要通过 SSH 进行克隆并作为 GitHub 项目的合作者，您需要一个 GitHub 账户，并且需要被相应项目所有者添加为项目成员。

### 注意

要在 GitHub.com 上托管您的源代码，请注册并在那里创建您自己的仓库。

此外，您需要在**设置 | SSH 密钥**（[`github.com/settings/ssh`](https://github.com/settings/ssh)）中添加您的公钥，以便从您的计算机通过**安全外壳**（**SSH**）进行 Git 操作。

对于 Windows 操作系统，您可以使用**PuTTYgen** ([`www.chiark.greenend.org.uk/~sgtatham/putty/download.html`](http://www.chiark.greenend.org.uk/~sgtatham/putty/download.html)) 生成您的密钥，并且在 IDE 中使用之前必须将其转换为**OpenSSH**格式。

在进行以下教程之前，您可以在 GitHub 上创建一个示例仓库，并将另一个 GitHub 测试账户添加为合作者（从**ADMIN | Collaborators)**，并记得为这些相应的账户添加公钥。

# 操作时间-通过 SSH 协议从 GitHub 克隆 Git 仓库

在本教程中，我们将作为 GitHub 项目的合作者，并且我们的 SSH 公钥已添加到 GitHub 账户中。我们将使用 NetBeans 添加我们的 SSH 私钥。除了仓库克隆，NetBeans 还提供了创建一个全新项目的选项：

1.  选择**Team | Git | Clone...**，将显示**克隆仓库**向导。

1.  在**仓库 URL**字段中指定所需仓库的路径，例如`git@github.com:mahtonu/chapter6demo.git`。

1.  验证**用户名**为`git`。

1.  浏览**私钥文件**的位置。

1.  添加在密钥生成期间创建的**Passphrase**，并（可选）选择**保存 Passphrase**复选框。**克隆仓库**向导中的**远程仓库**页面看起来类似于以下截图：![操作时间-通过 SSH 协议从 GitHub 克隆 Git 仓库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_06.jpg)

1.  点击**下一步**，并在**远程分支**页面选择需要获取（下载）到本地仓库的仓库分支，例如`master`。![操作时间-通过 SSH 协议从 GitHub 克隆 Git 仓库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_07.jpg)

1.  点击**下一步**，并填写或浏览**父目录**，克隆目录将放置在**目标目录**页面。仓库名称会自动填写在**克隆名称**字段中，这将是本地克隆目录的名称。![操作时间-通过 SSH 协议从 GitHub 克隆 Git 仓库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_08.jpg)

1.  在此屏幕截图中，默认情况下**Checkout Branch**设置为`master*`，**Remote Name**设置为`origin`，这意味着这是我们要克隆的原始存储库。同时，保持**克隆后扫描 NetBeans 项目**复选框选中。

1.  单击**完成**，看看 NetBeans **输出** 窗口中发生了什么。您将被提示从克隆源创建一个新的 NetBeans 项目，如下面的屏幕截图所示：![行动时间——通过 SSH 协议从 GitHub 克隆 Git 存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_09.jpg)

我们还从克隆的源中创建了 NetBeans 项目，方法是选择**新项目**并选择现有源选项，并将 NetBeans 项目元数据存储到单独的目录中，因为我们不希望它们在 Git 下。此外，您将在项目中找到一个`README`文件，它已经被跟踪，并来自远程源存储库。

## 刚刚发生了什么？

我们已经通过 NetBeans 使用 SSH 协议克隆了一个存储库。这些克隆中的每一个都充当一个完全成熟的存储库，它们内部包含所有的修订信息。因此，现在我们有一个可用的本地存储库，并且也可以使用远程源。我们已经将我们的 GitHub 帐户之一添加到 GitHub 项目中作为协作者，因为我们获得了对该项目的访问权限，所以我们使用 NetBeans IDE 从那里克隆了它。您可以从 IDE 执行大多数 Git 操作，并且可以在**输出**窗口中看到这些操作的结果。

从这一点开始，我们将学习如何从 IDE 使用 Git 操作。接下来的部分是从协作者的角度进行说明，包括添加、编辑、比较、提交文件、推送更改到远程等等。

## 小测验——理解 Git

1.  哪个是 Git 的正确功能？

1.  分布式版本控制系统

1.  问题跟踪器

1.  集中式存储库

1.  始终依赖网络

1.  哪个不是 Git 存储库的功能？

1.  每个 Git 克隆都是一个完全成熟的存储库

1.  本地 Git 存储库是原始存储库的子集

1.  所有提交都是本地的

1.  可能有一个远程源

1.  在我们之前的部分中，哪个关键文件被添加到 IDE 中？

1.  公钥文件

1.  私钥文件

1.  两个关键文件

1.  打开 SSH 文件

1.  在 NetBeans IDE 中，对于新创建的文件，在存储库的上下文中，文件状态符号将是什么？

1.  `已添加/-`

1.  `-/已添加`

1.  `已添加/+`

1.  `+/已添加`

# 将文件分段到 Git 存储库

要开始跟踪新文件，并且还要对 Git 存储库中已经跟踪的文件进行分段更改，您需要将其添加到存储库中。**分段**意味着在 Git 下添加新文件或修改文件以进行“待提交的更改”。

将文件添加到 Git 存储库时，IDE 首先在**索引**中组合和保存项目的快照。在执行提交后，IDE 将这些快照保存在 HEAD 中。

# 行动时间——将文件分段到 Git 存储库

在本教程中，我们将学习如何将文件分段到我们的本地 Git 存储库。分段是将更改添加到待提交状态。以下文件可以称为分段文件：

+   向存储库添加了一个新创建的文件

+   修改并添加到存储库的现有文件

首先，我们将向存储库添加一个新创建的文件，然后我们将向存储库添加一个修改后的文件：

1.  首先，我们将打开 NetBeans Git 的**显示更改**查看器窗口。右键单击`chapter6demo`项目节点，然后选择**Git | 显示更改**。NetBeans 将扫描存储库并在窗口中显示任何更改。现在，可以实时从此窗口查看存储库中的任何更改。

1.  现在，以通常的方式将一个新文件添加到 NetBeans 项目中，即`test.php`。您可以看到新的`test.php`文件已经在编辑器中打开；在**项目**窗格上悬停在文件名上会显示 Git 的文件状态。![行动时间——将文件分段到 Git 存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_10.jpg)

在这个截图中，我们可以看到 Git 窗口底部显示`test.php`作为新添加的文件，标记为`-/Added`，这意味着它尚未添加到仓库中。

1.  右键单击`test.php`，然后从上下文菜单中选择**Git | Add**。现在，`test.php`文件可以在 Git 下进行跟踪。您可以在 Git 窗口中看到文件状态为`Added/-`，这意味着文件已准备好提交或已暂存。此外，您还可以在输出窗口中查看 Git 操作状态。

1.  现在，我们将打开现有的`README`文件，尝试在其中添加一些行，并保存，以观察其在本地仓库中的影响。请注意，该文件来自原始远程仓库。我们还可以立即在 Git 窗口中查看任何更改。![操作时间-将文件暂存到 Git 仓库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_11.jpg)

在这个截图中，我们可以看到文件中添加了一行新行（标记为绿色），开头说明新行已从较早版本添加。此外，在 Git 窗口中，您可以看到文件状态显示为`-/Modified`，这意味着文件已被修改，但尚未添加到暂存区。

1.  右键单击**README**，然后从上下文菜单中选择**Git | Add**。现在，`README`文件的更改已经暂存以进行提交。您可以在 Git 窗口中看到文件状态为`Modified/-`，这意味着文件已准备好提交或已暂存。请注意，每次完成文件的修改后，您都可以重复此步骤，以将更改暂存以进行下一次提交。此外，修改后的文件名在 NetBeans **Projects**窗格中变为蓝色，新添加的文件名变为绿色。

## 刚刚发生了什么？

我们刚刚学习了如何为本地仓库中已做的更改暂存文件，这些更改将被提交。因此，每次有更改时，我们可以对这些文件应用**Git | Add**，以便使它们可以用于下一次提交。此外，我们已经看到 Git 窗口显示了文件的实时状态，与仓库的状态相对比。

请注意，**Team**菜单包含了用于当前项目所使用的特定版本控制系统的所有选项。例如，在我们的情况下，我们可以看到所有 Git 选项都在**Team**菜单和**Team | Git**子菜单下都可用。

## 在源代码编辑器中查看更改

当您在 IDE 的源代码编辑器中打开一个有版本的文件时，您可以在修改文件时查看文件发生的实时变化，与 Git 仓库中的基本版本进行对比。当您工作时，IDE 会在源代码编辑器的边距中使用颜色代码传达以下信息：

+   蓝色：表示自较早版本以来已更改的行

+   绿色：表示自较早版本以来已添加的行

+   红色：表示自较早版本以来已删除的行

源代码编辑器的左边缘显示了逐行发生的更改。当您修改给定行时，更改会立即显示在左边缘中。

源代码编辑器的右边缘为您提供了一个概览，显示了对文件的整体所做的更改，从上到下。当您对文件进行更改时，颜色编码会立即生成。您可以在右边缘的特定位置单击，立即将内联光标移动到文件中的该位置。

## Git 窗口

您已经在 Git 窗口中实时查看了本地工作树中所选文件夹中文件的所有更改的列表，如下截图所示：

![Git 窗口](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_12.jpg)

在此版本窗口中，您可以看到带有按钮的工具栏，它使您能够在列表中显示的所有文件上调用最常见的 Git 任务。使用工具栏中的按钮，您可以选择显示在索引或 HEAD 中具有差异的文件列表，工作树和索引中的文件，或工作树和 HEAD 中的文件。您还可以单击列标题，按名称、状态或位置对文件进行排序。

## 尝试一下-取消暂存的文件

假设您已更改了两个文件，并希望将它们作为两个单独的更改提交，但无意中将它们都暂存了。尝试使用“Team | Git | Reset...”取消暂存的文件；您可以从那里重置 HEAD。

# 提交更改到存储库

在本节中，我们将学习如何提交已暂存的更改。在上一节中所做的更改将提交到本地存储库中。

# 行动时间-将更改提交到本地存储库

要将更改提交到本地存储库，请按照以下步骤进行：

1.  选择要提交到本地存储库的文件；即`test.php`。右键单击它们，然后从上下文菜单中选择“Git | Commit...”。将显示提交对话框，如下图所示：![行动时间-将更改提交到本地存储库](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_13.jpg)

在此屏幕截图中，您可以看到“提交消息”框。 “要提交的文件”列表显示要提交的暂存文件。

1.  在“提交消息”文本区域中键入一条消息，描述源代码提交的意图。提交消息应传达更改的有意义描述以及原因。

1.  您可以通过取消选中行来排除要提交的文件，或者可以通过右键单击行来指定一些附加操作。完成后单击“提交”。

## 刚才发生了什么？

IDE 执行了提交并将快照存储到存储库中。IDE 的状态栏位于界面右下角，在提交操作发生时显示。成功提交后，“项目、文件”和“收藏夹”窗口中的版本控制徽章消失，已提交文件的颜色代码恢复正常。还要注意，Git 窗口中的文件清除了，这意味着存储库是最新的，没有可用的更改。

## 尝试一下-一起添加和提交所有文件

我们已经将新文件放入存储库，然后提交了这些更改。现在，直接提交新文件，让它们从 IDE 中自动暂存。您可以将新文件添加到项目中；尝试直接提交它们，然后查看差异。

## 比较文件修订

比较文件版本是在使用版本控制项目时的常见工作。IDE 使您能够使用`Diff`命令比较修订版本。文件修订可以进行比较，以查看从一个修订到另一个修订的源更改。

# 行动时间-使用 IDE 进行差异

为了比较文件修订，您可以使用 IDE 的`Diff`功能，并按照以下步骤进行：

1.  选择一个名为`README`的版本化文件，并修改文件的一些行。

1.  右键单击文件，然后从上下文菜单中选择“Git | Diff”。IDE 的主窗口中打开了一个图形“Diff”查看器，用于所选文件和修订的比较。 “Diff”查看器在并排面板中显示两个副本。较新的副本显示在右侧。因此，如果您要比较存储库修订与您的工作树，工作树将显示在右侧面板中：![行动时间-使用 IDE 进行差异](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_14.jpg)

`Diff`查看器使用与其他地方相同的颜色代码来显示版本控制更改。在上一张屏幕截图中，绿色块表示已添加到更高版本的内容。红色块表示从较早版本中删除了内容。蓝色块表示在突出显示的行中发生了更改。

## 刚刚发生了什么？

**Diff**查看器工具栏还包括按钮，使您能够调用列表中显示的所有文件的最常见的 Git 任务。如果您正在对工作树中的本地副本进行差异比较，编辑器使您能够直接从**Diff**查看器中进行更改。为此，您可以将光标放在**Diff**查看器的右窗格内，并相应地修改文件。否则，使用显示在每个突出显示的更改旁边的内联图标。

## 撤销存储库的本地更改

撤销是为了丢弃对工作树中选定文件所做的本地更改，并用索引或 HEAD 中的文件替换这些文件。

# 行动时间 - 撤销工作树的更改

要撤销更改，请按以下步骤进行：

1.  从前一节中，修改后的`README`文件的**Diff**窗口提供了一个撤销修改的功能。此外，Git 窗口提供了撤销修改的按钮。

1.  右键单击`README`文件，然后从上下文菜单中选择**Git | Revert | Revert Modifications**，或者从**Diff**窗口单击**Revert Modifications**按钮。类似于以下对话框将打开：![行动时间 - 撤销工作树的更改](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_15.jpg)

1.  指定附加选项（例如**仅将索引中未提交的更改撤消到 HEAD)**。

1.  单击**Revert**。

## 刚刚发生了什么？

IDE 撤消了指定的更改，并用索引或 HEAD 中的文件替换了这些文件。通过这种方式，您可以轻松地撤销修改或撤销提交。

## 快速测验 - 使用 Git

1.  将文件添加到 Git 存储库时，IDE 首先会在以下哪个地方组成并保存项目的快照？

1.  索引

1.  头

1.  存储库

1.  主分支

1.  源编辑器左边距中的哪种颜色表示自较早版本以来已更改的行？

1.  绿色

1.  蓝色

1.  红色

1.  黄色

1.  **Diff**用于以下哪些操作？

1.  查看文件历史记录

1.  比较两个版本

1.  比较两个文件的两个版本

1.  以上所有

1.  在撤销更改的情况下可以做什么？

1.  撤销工作树和索引中的所有未提交更改

1.  将未提交的更改撤消到工作树中的 HEAD 状态

1.  仅将未提交的更改撤消到索引中的 HEAD

1.  以上所有

## 英雄尝试者 - 撤销提交

尝试使用提交 ID 从 IDE 中撤销特定的提交。为此，您可以从 IDE 中选择**Revert | Revert Commit...**。

# 与远程存储库一起工作

与其他开发人员一起工作或在协作开发环境中，每个人都希望分享自己的工作，这涉及到从互联网或网络上托管的远程存储库中获取、推送和拉取数据。

## 获取源代码更新

获取会从您尚未拥有的原始远程存储库中获取更改。它不会更改任何您的本地分支。获取会获取远程存储库中的所有分支，您可以随时将其合并到您的分支中或仅进行检查。

# 行动时间 - 获取源代码更新

要获取更新，请按以下步骤进行：

1.  右键单击项目节点，选择**Git | Remote | Fetch**，然后显示**从远程存储库获取**向导。![行动时间 - 获取源代码更新](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_16_New.jpg)

1.  在向导的**远程存储库**页面，我们将使用配置的存储库（使用之前配置的存储库路径）并单击**下一步**。

1.  在向导的**远程分支**页面上，选择要获取更改的分支，然后单击**完成**。在存储库浏览器窗口**（TEAM | Git | 存储库浏览器）**中找到远程分支的本地副本。![执行操作的时间-获取源代码更新](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_17.jpg)

## 刚刚发生了什么？

创建了远程分支的本地副本。所选分支已在**Git 存储库浏览器**中的**分支 | 远程**目录中更新。接下来，获取的更新将合并到本地分支中。

## 从远程存储库拉取更新

从远程 Git 存储库拉取一些更新时，会从中获取更改，并将其合并到本地存储库的当前 HEAD。

# 执行操作的时间-从远程存储库拉取更新

要执行拉取，完成以下步骤：

1.  右键单击项目节点，选择**Git | 远程 | 拉取**，然后显示**从远程存储库拉取**向导。![执行操作的时间-从远程存储库拉取更新](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_18.jpg)

1.  在向导的**远程存储库**页面上，我们将使用配置的存储库（使用之前配置的存储库路径），然后单击**下一步**。

1.  在向导的**远程分支**页面上，选择分支，即`master -> origin/master`（远程分支`origin/master`将合并到当前分支），以拉取更改，然后单击**完成**。

## 刚刚发生了什么？

您的本地存储库与原始存储库同步。在**远程分支**页面上，我们选择的分支，即`master -> origin/master`，将合并到我们的当前分支。您还可以在 IDE 的右下角或输出窗口中看到拉取状态。

简单来说，`Git Pull`执行`Git Fetch`，然后执行`Git Merge`。

## 将源代码更改推送到远程存储库

为了分享到目前为止所做的出色提交，您希望将更改推送到远程存储库。再次，您可以将新分支和数据推送到远程存储库。

# 执行操作的时间-推送源代码更改

要将本地 Git 存储库中的更改贡献到公共/远程 Git 存储库中，请执行以下步骤：

1.  右键单击项目节点，选择**Git | 远程 | 推送**，然后显示**推送到远程存储库**向导。![执行操作的时间-推送源代码更改](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_19.jpg)

1.  在向导的**远程存储库**页面上，我们将使用配置的存储库（使用之前配置的存储库路径），然后单击**下一步**。

1.  在向导的**选择本地分支**页面上，选择要将更改推送到的本地分支，即`master -> master`，然后单击**完成**。

1.  在**更新本地引用**页面上，选择要在本地存储库的**远程**目录中更新的分支（即`master -> origin/master`），然后单击**完成**。

## 刚刚发生了什么？

指定的远程存储库分支已使用本地分支的最新状态进行更新。您的本地存储库的**分支 | 远程**目录也已更新。因此，您的更改已在远程存储库中生效，其他协作者可以将更改拉取到他们自己的存储库中。

# 使用分支工作

意图启动一条替代的开发线路会在源代码管理系统中生成一个分支。**分支**帮助您管理工作上下文并提供单独的工作空间。通常，**主分支**是最好的代码所在地；除此之外，还可能有一个**开发分支**，其中可以存放持续开发的代码。同样，明智的软件开发使用分支来维护功能、发布、热修复等。

为了开发新版本和维护旧版本，分支是必不可少的。在下图中，描述了一个通用的 Git 分支模型：

![使用分支工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_20.jpg)

在这个图表中，我们可以看到**开发分支**与**主分支**合并为一个新版本，并且一个新功能已经与**开发分支**合并。

NetBeans 支持您使用 Git 分支执行以下操作：

+   创建分支

+   检出分支

+   切换分支

+   合并分支

+   删除分支

## 创建分支

如果您想要在不干扰主干的情况下为稳定性或实验目的创建文件系统的单独版本，可以创建一个分支。

# 执行操作-创建分支

要创建一个本地分支，请完成以下步骤：

1.  右键单击项目节点，选择**Git | 分支 | 创建分支**，将显示**创建分支**对话框。![执行操作-创建分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_21.jpg)

1.  在**分支名称**字段中，键入要创建的所需分支名称，即`development`。

1.  您可以通过在**修订**字段中输入提交 ID、现有分支或标签名称，或按**选择**查看存储库中维护的修订列表来输入所选项目的特定修订。默认的**修订**是来自主分支的最新修订。

1.  可选地，在**选择修订**对话框中，展开**分支**并选择所需的分支，在相邻列表中指定提交 ID，并按**选择**。

1.  查看与分支来源的**提交 ID，作者**和**消息**字段信息，并单击**创建**。该分支将添加到**Git 存储库浏览器**中**分支 | 本地**文件夹中。![执行操作-创建分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_22.jpg)

## 刚刚发生了什么？

我们在本地存储库中创建了一个新分支。新分支包含了主分支的最新快照。新创建的分支还不是我们的工作分支。主分支仍然是工作分支；我们将选择检出新分支使其成为工作分支。请注意，我们可以从任何现有修订版本创建新分支。

## 检出分支

如果您想要编辑已经存在的分支上的文件，可以检出需要使用的分支以将文件复制到您的工作树。这将简单地切换到所需的分支。

# 执行操作-检出分支

检出修订版本

1.  右键单击项目节点，选择**Git | 检出 | 检出修订版本**，将显示**检出修订版本**对话框。![执行操作-检出分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_23.jpg)

1.  再次右键单击**分支 | 本地 | 分支名称**，在**存储库浏览器**窗口中从上下文菜单中选择，如下图所示。选择**检出修订版本**，将显示相同的对话框，并显示从该分支选择的最新修订版本。![执行操作-检出分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_24.jpg)

1.  可选地，通过在**修订**字段中输入提交 ID、现有分支或标签名称，或按**选择**查看存储库中维护的修订列表来指定所需的修订。请注意，如果指定的修订引用有效的提交但未标记为分支名称，则您的 HEAD 将变为分离状态，您将不再位于任何分支上。

1.  可选地，在**选择修订**对话框中，展开**分支**并选择所需的分支，在相邻列表中指定提交 ID，并按**选择**。

1.  查看与所检出修订版本相关的**提交 ID，作者**和**消息**字段信息。

1.  要从所检出的修订版本创建一个新分支，请选择**作为新分支检出**选项，并在**分支名称**字段中输入名称。

1.  按**检出**以检出修订版本。

## 刚刚发生了什么？

工作树和索引中的文件已更新以匹配指定修订版本中的版本。

## 切换到分支

如果要将文件切换到已经存在的分支（例如，到一个不在您的分支顶部的提交），可以使用**Team | Git | Branch | 切换到分支**命令，在**切换到所选分支**对话框中指定分支，作为新分支进行检出（可选），然后按**切换**。

![切换到分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_25.jpg)

## 检出文件

IDE 支持对 IDE 中当前选择的文件、文件夹或项目进行上下文敏感的检出。要从索引中检出一些文件（而不是分支），请从主菜单中选择**Team | Git | Checkout | Checkout Files**，然后显示**Checkout Selected Paths**对话框。

![检出文件](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_26.jpg)

从此对话框中，选择**使用条目更新索引**从**所选修订版**选项。如果选择，索引将在检出本身之前使用所选修订版的状态进行更新（即，工作树和索引中的所选文件都将得到更新）。

指定所需的属性并进行检出。

## 合并

将分支上下文合并到当前分支。一旦在分支中隔离了工作，您最终会想要将其合并到主分支中。您可以将任何分支合并到当前分支。

# 行动时间-合并到当前分支

要将修改从存储库修订版传输到工作树，请执行以下操作：

1.  从主菜单中选择**Team | Git | 合并修订版**。显示**合并修订版**对话框。![行动时间-合并到当前分支](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_06_27.jpg)

1.  （可选）在**修订**字段中输入所需的修订版，或按**选择**以查看存储库中维护的修订版列表。

1.  （可选）在**选择修订版**对话框中，展开**分支**并选择所需的分支，指定相邻列表中的提交 ID，然后按**选择**。

1.  查看与正在合并的修订版相关的**提交 ID、作者**和**消息**字段信息。

1.  按**合并**。

## 刚刚发生了什么？

在当前分支、您的工作树内容和指定分支之间进行三向合并。如果发生合并冲突，冲突文件将标有红色标记以指示这一点。合并后，您仍然可以提交更改，以便将其添加到 HEAD 中。

## 删除分支

要删除不必要的本地分支，请从主菜单中选择**Team | Git | Repository Browser**。在**Git 存储库浏览器**中，选择需要删除的分支。请注意，该分支应为非活动状态，这意味着它当前未在工作树中检出。

右键单击所选分支，并从弹出菜单中选择**删除分支**。在**删除分支**对话框中，按**确定**以确认删除分支。该分支将从本地存储库以及**Git 存储库浏览器**中删除。

## 远程存储库和分支的工作小测验

1.  哪些 Git 操作对于远程存储库最相关？

1.  提交、合并和还原

1.  获取、拉取和推送

1.  获取、拉取、推送和检出

1.  添加、提交和推送

1.  从远程存储库拉取更改后会发生什么？

1.  从远程存储库获取更改

1.  从中获取更改并将其合并到本地存储库的当前 HEAD 中

1.  从中获取更改并将其合并到远程存储库的当前 HEAD 中

1.  以上都不是

1.  检出分支后会发生什么？

1.  它立即切换到该分支，并且分支文件将可用于您的工作树

1.  它将文件复制到您的工作树

1.  创建一个新分支，并将其作为您的工作分支

1.  以上所有

## 尝试一下英雄-创建标签

Git 使用两种主要类型的标签——轻量级和注释型。轻量级标签非常像一个不会改变的分支——它只是指向一个特定的提交。然而，注释型标签存储为 Git 数据库中的完整对象。这些标签检查总和包含标记者的姓名、电子邮件和日期以及标记消息。通常建议创建注释型标签，这样你就可以获得所有这些信息。现在，创建一个新标签，你可以从 IDE 中选择**Git | Tag | Create Tag...**。

# 良好的实践和工作流程

以下讨论了一些指导方针和工作流程，以维护 Git 的良好实践：

+   无论你在做什么，都要保持一个单独的分支。现在，当你想要将你的更改合并回主分支时，只需进行 Git 合并。

+   尽可能保持你的分支最新，这涉及到检出或拉取更改。

+   分支可以推送到原始仓库。这样做有几个原因。首先，如果你的工作站崩溃了，你不会丢失你的更改——这是版本控制系统的一个主要原因。其次，其他开发人员可以在需要时快速切换到你的分支。

+   经常提交你的更改；当然，应该总是以逻辑片段提交更改。由于你的更改是在本地提交的，而不是到原始/主服务器（可以通过推送完成），你应该以有组织的方式提交更改。

+   为每个提交消息和对修订历史进行更改的每个操作提供消息/注释。

+   经常推送你的更改。如果你在自己的分支上开发，与其他人分开，你的更改不会影响其他人。

首选的 Git 工作流程：

+   从主节点创建一个分支，检出它，并进行你的工作

+   测试并提交你的更改

+   可选地，将你的分支推送到远程仓库（origin）

+   检出主分支，确保它与上游更改保持最新

+   将你的分支合并到主分支

+   再次测试（再次再次）

+   将你的本地主分支推送到远程仓库的主分支（origin/master）

+   删除你的分支（如果发布了，也要删除远程分支）

此外，即使是对于本地独立项目，使用版本控制系统也是值得的，因为代码更改可以很容易地在本地进行审查、回滚和备份。

# 总结

在本章中，我们讨论了版本控制系统以及它为何如此重要。此外，我们选择了 Git 作为分布式版本控制系统，并学习了如何在 NetBeans 中使用它。

我们特别关注了以下内容：

+   分布式版本控制系统或 DVCS

+   初始化一个 Git 仓库

+   克隆一个 Git 仓库

+   将文件暂存到 Git 仓库

+   提交更改到 Git 仓库

+   比较文件修订版本并撤销更改

+   与远程仓库一起工作——获取、拉取和推送

+   使用分支——创建、检出、切换、合并和删除。

最后，我们讨论了 Git 的实践和首选工作流程。现在，我们更有信心加入使用 Git 和 NetBeans 进行协作开发。

在下一章中，我们将创建一个新的 PHP 项目，包括用户注册、登录和注销，以提升我们的 PHP 应用程序开发技能到一个新的水平。


# 第七章：构建用户注册，登录和注销

> 提前规划。当诺亚建造方舟时，天空并没有下雨 - 理查德 C.库欣。

从本章开始，我们将亲自动手进行专业的 PHP 项目。我们将设计和开发一个 Web 应用程序，用户可以在其中注册自己，注册后可以登录到应用程序，查看和更新自己的配置文件等。

在本章中，我们将解决以下主题：

+   应用程序架构

+   设计 API

+   用户注册

+   用户登录和注销

+   用户配置文件查看和更新

# 规划项目

项目规划总是被视为对未来的规划，这意味着项目应该被规划，因为它可以很容易地扩展或可重用，更模块化，甚至可扩展。对于这个项目，我们将以现实的方式设计应用程序架构，以便用户注册，登录和注销应用程序也可以在我们未来的项目中轻松使用。

我们将设计**应用程序编程接口**（**API**）并使用该 API 构建应用程序。该 API 将为任何类型的用户注册或登录相关任务提供便利，因此项目的核心是 API。一旦 API 准备就绪，我们就可以轻松地使用该 API 构建多个应用程序。

首先，让我们考虑 API 设计。记住，我们将使用一些架构模式，即**数据访问对象**（**DAO**）模式用于我们的项目。

### 提示

强烈建议在此项目中具有**面向对象编程**（**OOP**）概念的先验知识。

# 理解应用程序架构

架构需要在数据存储，数据访问，应用服务和应用程序中构建层。这在以下截图中有所体现：

![理解应用程序架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_01.jpg)

每个层都可以被指定为一组类似的逻辑任务，因为数据存储层充当数据源，如关系数据库，文件系统或任何其他数据源。**数据访问层**与数据源通信，从**存储层**获取或存储数据，并在数据源中提供良好的抽象以交付给**服务层**。服务层是与**应用层**进行数据持久化的媒介，并提供其他服务，如验证服务。**数据访问对象**位于数据访问层，**业务对象**位于**服务层**。最后，**应用程序**位于应用层，直接与最终用户打交道。因此，在这样的分层设计中，服务层可以成为我们 API 的表面层。

现在，让我们考虑特定的功能，比如注册，登录，验证和数据抽象到每个单元或模块中。因此，每个层都将有强制单元，如下图所示：

![理解应用程序架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_02.jpg)

我们可以很容易地理解每个层都包含其适当的模块。例如，DAO 模块位于数据访问层，服务层具有其服务单元，如验证和用户服务模块，应用层包含用户登录，用户注册，用户配置文件和管理员模块。为了快速掌握架构概念，我们将尝试将每个模块保持为一个简单的 PHP 类，并附带代码。

因此，让我们快速看一下最终我们将要构建的内容。

以下截图代表了**用户注册**屏幕，包括**姓名，电子邮件，密码**和**电话**字段：

![理解应用程序架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_03.jpg)

以下截图代表了**用户登录**屏幕，包括**下次记住我**选项：

![理解应用程序架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_04.jpg)

以下截图代表了**用户配置文件**视图，顶部有**注销**和**编辑帐户**菜单：

![理解应用程序架构](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_05.jpg)

## 理解 DAO 模式

DAO 用于抽象和封装对数据源的所有访问。DAO 管理与数据源的连接，以获取和存储数据。

> “DAO 实现了与数据源一起工作所需的访问机制。数据源可以是像 RDBMS 这样的持久存储，像 B2B 交换这样的外部服务，像 LDAP 数据库这样的存储库，或者像业务服务或低级套接字这样的业务服务。依赖 DAO 的业务组件使用 DAO 为其客户端提供的更简单的接口。
> 
> DAO 完全隐藏了数据源的实现细节，使其客户端（数据客户端）无法看到。因为 DAO 向客户端公开的接口在基础数据源实现更改时不会改变，所以该模式允许 DAO 适应不同的存储方案，而不会影响其客户端或业务组件。基本上，DAO 充当组件与数据源之间的适配器。该模式源自核心 J2EE 模式。”
> 
> [`java.sun.com/blueprints/corej2eepatterns/Patterns/DataAccessObject.html`](http://java.sun.com/blueprints/corej2eepatterns/Patterns/DataAccessObject.html)。

使用 DAO 的目的相对简单，如下所示：

+   它可以在大部分应用程序中使用，无论何时需要数据存储

+   它将所有数据存储的细节隐藏在应用程序的其余部分之外

+   它充当您的应用程序与数据库之间的中介

+   它允许将可能的持久性机制更改的连锁效应限制在特定区域

## 审查面向对象编程问题

让我们来看一下一些面向对象编程关键字，用于访问修饰符或属性：

+   公共：此属性或方法可以在脚本的任何地方使用。

+   私有：此属性或方法只能被其所属的类或对象使用；它不能在其他地方被访问。

+   `受保护：`此属性或方法只能由其所属的类中的代码或该类的子类使用。

+   最终：此方法或类不能在子类中被覆盖。

+   摘要：这种方法或类不能直接使用，你必须对其进行子类化；它不能被实例化。

+   `静态：`此属性或方法属于类本身，而不属于其任何实例。您也可以将静态属性视为全局变量，它们位于类内部，但可以通过类从任何地方访问。可以使用`::`运算符在类名之后访问静态成员。

## 命名空间

> “命名空间（有时也称为名称范围）是一个抽象的容器或环境，用于保存一组唯一标识符或符号（即名称）。在命名空间中定义的标识符仅与该命名空间相关联。相同的标识符可以在多个命名空间中独立定义。”
> 
> - 维基百科

**命名空间**从 PHP 5.3 版本开始引入。在 PHP 中，命名空间是使用命名空间块定义的。

在 PHP 世界中，命名空间旨在解决两个问题，即库和应用程序的作者在创建可重用的代码元素（如类或函数）时遇到的问题：

+   能够避免您创建的代码与内部 PHP 类/函数/常量或第三方类/函数/常量之间的名称冲突

+   能够别名（或缩短）设计用于缓解第一个问题的超长名称，提高源代码的可读性

PHP 命名空间提供了一种将相关类、接口、函数和常量分组的方法。以下是 PHP 中命名空间使用的示例：

```php
namespace My;
class Foo {
...
}
namespace Your;
class Foo {
...
}

```

我们可以使用相同名称的类，并通过 PHP 命名空间引用，如下所示：

```php
$myFoo = new \My\Foo();
$yourFoo = new \Your\Foo();

```

### 提示

我们将使用`My`作为整个应用程序的常见根命名空间，`My\Dao`用于我们的数据访问层类，`My\Service`用于我们的服务层类。

## API

在面向对象的语言中，API 通常包括一组类定义的描述，以及与这些类相关联的一组行为。行为是指对象从该类派生后在特定情况下的行为规则。这个抽象概念与类方法（或更一般地说，与所有公共组件，因此所有公共方法，但也可能包括任何公开的内部实体，如字段、常量和嵌套对象）实现的真实功能相关联。

例如，表示堆栈的类可以简单地公开两个方法-`push()`（向堆栈添加新项）和`pop()`（提取最后一项，理想情况下放在堆栈顶部）。

在这种情况下，API 可以解释为两种方法-`pop()`和`push()`。更一般地说，这个想法是，可以使用实现堆栈行为的`Stack`类的方法（堆栈暴露其顶部以添加/删除元素）。

到目前为止，一切都很好。我们对项目的概念有了了解，并且我们对 NetBeans 的功能非常了解。现在，让我们开始开发...

# 设计数据库

在本节中，我们将设计我们的 MySQL 数据库。由于我们已经学会了如何在 NetBeans 中创建数据库连接、新数据库、新表，以及如何运行 MySQL 查询，我们不会再讨论它们，但我们会看一下数据库模式定义。

```php
CREATE TABLE 'users' (
'id' bigint(20) NOT NULL AUTO_INCREMENT,
'useremail' varchar(50) NOT NULL,
'password' char(32) NOT NULL,
'userhash' char(32) NOT NULL,
'userlevel' tinyint(4) NOT NULL,
'username' varchar(100) NOT NULL,
'phone' varchar(20) NULL,
'timestamp' int(11) unsigned NOT NULL,
PRIMARY KEY ('id'),
UNIQUE KEY 'useremail' ('useremail')
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

```

如您所见，我们在`users`表中有`id`（每个条目自动递增）作为主键，`useremail`作为唯一键。我们有一个`password`字段，用于存储用户的密码，最多 32 个字符；`userhash`有 32 个字符，用于存储用户的登录会话标识符；`userlevel`用于定义用户的访问级别，例如，普通用户为`1`，管理员用户为`9`，等等；一个`username`字段，支持最多 100 个字符；一个`phone`字段，用于存储用户的联系电话；以及一个`timestamp`字段，用于跟踪用户的注册时间。所选择的数据库引擎是**InnoDB**，因为它支持事务和外键，而**MyISAM**引擎不支持在任何用户进行`insert`和`update`操作时避免表锁定。

因此，您只需要创建一个名为`user`的新数据库，只需在 NetBeans 查询编辑器中键入 MySQL 查询，然后运行查询，即可在`user`数据库中准备好您的表。

现在，创建一个 NetBeans PHP 项目，并开始用户 API 开发以及后续部分。

# 创建数据访问层

数据访问层将包括一个 User DAO 类，用于提供数据库抽象，以及一个抽象的 Base DAO 类，用于提供抽象方法，这是 User DAO 类需要实现的。此外，我们将创建抽象类，以提供 DAO 类在我们未来项目中创建的抽象方法。请注意，我们将使用 PHP 命名空间`My\Dao`用于数据访问层类。

## 创建 BaseDao 抽象类

这个抽象类将用于为子类实现方法提供基本框架。简单地说，基本的数据库操作是`CRUD`或`create, read, update`和`delete`。因此，抽象类将提供这些类型的抽象方法，以及每个子类都需要的方法。`BaseDao`抽象类将包含用于数据库连接的`final`方法，因此子类不需要再次编写它。为了更好地理解这一点，我们将把我们的 DAO 类放在一个名为`Dao`的单独目录中。

# 行动时间-创建 BaseDao 类

为了与数据库连接一起使用，我们将保留数据库访问凭据作为它们自己的类常量。此外，我们将使用 PDO 进行各种数据库操作。要创建`Base`类，请按照以下步骤进行：

1.  在`Dao`目录中创建一个名为`BaseDao.php`的新 PHP 文件，并键入以下类：

```php
<?php
namespace My\Dao;
abstract class BaseDao {
private $db = null;
const DB_SERVER = "localhost";
const DB_USER = "root";
const DB_PASSWORD = "root";
const DB_NAME = "user";
}
?>

```

您可以看到这个类`使用命名空间 My\Dao;`，并且在类名之前还有一个`abstract`关键字，这将类定义为抽象类。这意味着该类不能被实例化，或者至少在内部有一个抽象方法。此外，您可以看到添加的类常量，其中包含数据库信息和一个私有类变量`$db`来保存数据库连接。您可以根据需要修改这些常量。

1.  现在，在类中添加以下`getDb()`方法：

```php
protected final function getDb(){
$dsn = 'mysql:dbname='.self::DB_NAME.';host='.self::DB_SERVER;
try {
$this->db = new \PDO($dsn, self::DB_USER, self::DB_PASSWORD);
} catch (PDOException $e) {
throw new \Exception('Connection failed: ' . $e->getMessage());
}
return $this->db;
}

```

`protected final function getDb()`函数使用 PDO 连接到 MySQL 数据库。类的私有变量存储了可以用于数据库连接的 PDO 实例。此外，`getDb()`方法是`final`和`protected`的，因此子类继承此方法并且无法覆盖它。

`$dsn`变量包含**数据源名称（DSN）**，其中包含连接到数据库所需的信息。以下行创建一个 PDO 实例，表示与请求的数据库的连接，并在成功时返回一个 PDO 对象：

```php
$this->db = new \PDO($dsn, self::DB_USER, self::DB_PASSWORD);

```

请注意，如果尝试连接到请求的数据库失败，DSN 会抛出`PDOException`异常。我们在 PDO 前面加上反斜杠\，这样 PHP 就知道它在全局命名空间中。

1.  在类中添加以下`abstract`方法：

```php
abstract protected function get($uniqueKey);
abstract protected function insert(array $values);
abstract protected function update($id, array $values);
abstract protected function delete($uniqueKey);

```

您可以看到子类要实现的方法被标记为`abstract protected`，`get()`方法将用于根据唯一表键从表中选择单个条目，`insert()`将在表中插入一行，`update()`将用于更新表中的一行，`delete()`将用于删除一个条目。因此，所有这些方法都被保留为抽象方法（没有方法体），因为它们将通过子类来实现。

## 刚刚发生了什么？

我们已经准备好继承 DAO 类的`BaseDao`抽象类。从该方法中创建并返回 PDO 实例，因此所有子类都将具有`getDb()`方法，并且可以使用此返回的实例来执行某种数据库任务。最后，子类将根据需要实现`abstract`方法。例如，在下一个教程中，User DAO 类将实现`get()`方法，以选择并返回与用户的电子邮件地址匹配的单个用户注册信息，或者 Product DAO 类将实现`get()`方法，以选择并返回与产品 ID 匹配的单个产品信息。因此，使用这样的抽象类的意图是为 Dao 类提供基本框架。

### 提示

使用 PDO 的最大优势之一是，如果我们想迁移到其他 SQL 解决方案，我们只需要调整 DSN 参数。

## 创建 User DAO 类

在本教程中，我们将创建 User DAO 类，该类将在其中提供各种数据库任务。这个类将隐藏数据库，不让连续的层次访问到它，也就是服务层类。因此，所有连续的层次类将调用这个类的方法，并且由这个类完成所有必要的数据库工作，而数据存储细节对它们完全隐藏。因此，这个类将充当数据库和应用程序之间的中介。

# 行动时间——创建 User Dao 类

我们将保留相关的用户常量作为类常量。我们将在这个类中编写`BaseDao`抽象类中方法的实现。简单地说，我们将把这些抽象方法的主体和我们自己所需的方法添加到类中。因此，请按照以下步骤进行操作：

1.  在`Dao`目录中创建一个名为`UserDao.php`的新 PHP 文件，并键入以下代码：

```php
<?php
namespace My\Dao;
class UserDao extends BaseDao {
private $db = null;
public function __construct() {
$this->db = $this->getDb();
}
}
$userDao = new \My\Dao\UserDao;
?>

```

正如您所看到的，该类位于`My\Dao`命名空间下，并扩展到`BaseDao`类，因此该类将具有从父类继承的方法。Dao 类有自己的私有`$db`，它存储了从继承的`getDb()`方法返回的 PDO 实例；正如您所看到的，这个`$db`变量被分配给了类构造函数。

另外，您可能已经注意到`UserDao`类已在底部实例化。

1.  键入`get()`方法的实现（将该方法添加到类中），使其看起来类似于以下内容：

```php
public function get($useremail) {
$statement = $this->db->prepare("SELECT * FROM users WHERE useremail = :useremail LIMIT 1 ");
$statement->bindParam(':useremail', $useremail);
$statement->execute();
if ($statement->rowCount() > 0) {
$row = $statement->fetch();
return $row;
}
}

```

您可以看到，`prepare()`方法准备了要由`PDOStatement::execute()`方法执行的 SQL 语句。正如您所看到的，以下语句查询用于从`users`表中选择一行的所有列，而`：useremail`中的给定电子邮件地址（与`bindParam()`绑定的参数）匹配`useremail`列。

```php
SELECT * FROM users WHERE useremail = :useremail LIMIT 1;

```

最后，如果找到匹配的行，则获取包含用户详细信息的数组并返回。

1.  键入`insert()`方法的实现，使其看起来类似于以下内容：

```php
public function insert(array $values) {
$sql = "INSERT INTO users ";
$fields = array_keys($values);
$vals = array_values($values);
$sql .= '('.implode(',', $fields).') ';
$arr = array();
foreach ($fields as $f) {
$arr[] = '?';
}
$sql .= 'VALUES ('.implode(',', $arr).') ';
$statement = $this->db->prepare($sql);
foreach ($vals as $i=>$v) {
$statement->bindValue($i+1, $v);
}
return $statement->execute();
}

```

该方法接受传入的用户信息数组，准备`users`表的 MySQL `insert`查询，并执行该查询。请注意，我们已经将字段名称保留在`$fields`数组中，并将字段值保留在`$vals`数组中，这些值分别从传递的数组的键和值中提取。我们在准备的语句中使用？代替所有给定值，这些值将被绑定到`PDOStatement::bindValue()`方法中。`bindValue()`将一个值绑定到一个参数。

1.  在`update()`方法的实现中键入代码，使其看起来类似于以下内容：

```php
public function update($id, array $values) {
$sql = "UPDATE users SET ";
$fields = array_keys($values);
$vals = array_values($values);
foreach ($fields as $i=>$f) {
$fields[$i] .= ' = ? ';
}
$sql .= implode(',', $fields);
$sql .= " WHERE id = " . (int)$id ." LIMIT 1 ";
$statement = $this->db->prepare($sql);
foreach ($vals as $i=>$v) {
$statement->bindValue($i+1, $v);
}
$statement->execute();
}

```

它以与*步骤 3*相同的方式准备了 MySQL `UPDATE`查询语句，并执行了该查询以更新具有给定 ID 的行中的相应列值。

1.  您可以将其他实现留空，如下所示，或根据需要添加自己的代码：

```php
public function delete($uniqueKey) { }

```

由于我们可能会在将来实现删除用户的方法，因此我们留空了`delete()`方法的主体。

1.  现在，我们需要在类中编写一些额外的方法。在注册用户时，我们可以检查我们的数据库，看看表中是否已经存在该电子邮件地址。键入以下方法：

```php
public function useremailTaken($useremail) {
$statement = $this->db->prepare("SELECT id FROM users WHERE useremail = :useremail LIMIT 1 ");
$statement->bindParam(':useremail', $useremail);
$statement->execute();
return ($statement->rowCount() > 0 );
}

```

`useremailTaken()`方法接受一个电子邮件地址作为参数，以检查该电子邮件 ID 是否存在。它通过在`WHERE`子句中使用给定的电子邮件地址运行`SELECT`查询来执行该任务。如果找到任何行，则意味着该电子邮件地址已经存在，因此该方法返回`true`，否则返回`false`。通过这种方法，我们可以确保系统中一个电子邮件地址只能使用一次，并且不允许重复的电子邮件地址，因为这是一个唯一的字段。

1.  为了在登录时确认用户的密码，请键入以下`checkPassConfirmation()`方法：

```php
public function checkPassConfirmation($useremail, $password) {
$statement = $this->db->prepare("SELECT password FROM users WHERE useremail = :useremail LIMIT 1 ");
$statement->bindParam(':useremail', $useremail);
$statement->execute();
if ($statement->rowCount() > 0) {
$row = $statement->fetch();
return ($password == $row['password']);
}
return false;
}

```

该方法以`$useremail`和`$password`作为参数，并选择`password`列以匹配用户的电子邮件。现在，如果找不到匹配条件的行，则意味着用户的电子邮件在表中不存在，并返回`false 1`；如果找到匹配的行，则从结果中获取数组以获得密码。最后，将从数据库中获取的密码与第二个参数中给定的密码进行比较。如果它们匹配，则返回`true`。因此，我们可以使用这个方法来确认给定对应用户的电子邮件的密码，当用户尝试使用它们登录时，可以轻松跟踪返回的布尔值的状态。

1.  此外，我们已经在`users`表中添加了一个名为`userhash`的字段。该字段存储每个登录会话的哈希值（随机的字母数字字符串），因此我们希望确认`userhash`，以验证用户当前是否已登录。输入以下方法：

```php
public function checkHashConfirmation($useremail, $userhash) {
$statement = $this->db->prepare("SELECT userhash FROM users WHERE useremail = :useremail LIMIT 1");
$statement->bindParam(':useremail', $useremail);
$statement->execute();
if ($statement->rowCount() > 0) {
$row = $statement->fetch();
return ($userhash == $row['userhash']);
}
return false;
}

```

`checkHashConfirmation()`方法与*步骤 7*中的先前方法相同，以`$useremail`和`$useremail`作为参数，为给定的电子邮件地址获取`useremail`，并将其与给定的`useremail`进行比较。因此，可以用来比较`useremail`的方法对于会话和数据库都是相同的。如果相同，则意味着用户当前已登录，因为每次新登录都会更新表中对应的`useremail`。

## 刚刚发生了什么？

对于多次使用不同参数值发出的语句，调用`PDO::prepare()`和`PDOStatement::execute()`可以优化应用程序的性能，通过允许驱动程序协商查询计划和元信息的客户端和/或服务器端缓存，并帮助防止 SQL 注入攻击，通过消除手动引用参数的需要。

现在，我们已经准备好了 User DAO 类，并且 DAO 层也在我们 NetBeans 项目的`Dao`目录中完成。因此，User DAO 类已准备好提供所需的数据库操作。可以以我们所做的方式处理数据库操作，以便其他后续类不需要访问或重写数据库功能，因此已实现对数据库的抽象。我们可以在这个类中添加任何类型的与数据库相关的方法，以便让它们可用于 Service 类。现在，实例化的对象将作为数据访问对象，这意味着该对象可以访问数据源中的数据，任何人都可以通过该对象读取或写入数据。

## 小测验-回顾 PDO

1.  `bindValue()`和`bindParam()`方法的哪一个是正确的？

1.  您只能使用`bindParam`传递变量，使用`bindValue`可以同时传递值和变量

1.  您只能使用`bindParam`传递值，只能使用`bindValue`传递变量

1.  您可以使用`bindParam`传递变量，使用`bindValue`可以传递值

1.  两者是相同的

现在，让我们为我们的 API 创建 Service 层。

# 创建 Service 层

Service 层包含用于为应用程序提供服务的类，或者简单地为应用程序提供框架。应用程序层将与该层通信，以获得各种应用程序服务，例如用户身份验证、用户信息注册、登录会话验证和表单验证。为了更好地理解，我们将把我们的服务类放在一个名为`Service`的单独目录中，并为该层的类使用命名空间`My\Service`。

## 创建 ValidatorService 类

该类将执行验证任务，例如表单验证和登录信息验证，并保存以提供表单错误消息和字段值。

# 行动时间-创建 ValidatorService 类

我们将在类本身中保留一些验证常量，并且该类将使用`My\Service`作为其命名空间。按照以下步骤创建`ValidatorService`类：

1.  在项目目录下创建一个名为`Service`的新目录。Service 类将位于此目录中。

1.  在`Service`目录中创建一个名为`ValidatorService.php`的新 PHP 文件，并输入以下类：

```php
<?php
namespace My\Service;
use My\Dao\UserDao;
class ValidatorService {
private $values = array();
private $errors = array();
public $statusMsg = null;
public $num_errors;
const NAME_LENGTH_MIN = 5;
const NAME_LENGTH_MAX = 100;
const PASS_LENGTH_MIN = 8;
const PASS_LENGTH_MAX = 32;
public function __construct() {
}
public function setUserDao(UserDao $userDao){
$this->userDao = $userDao;
}
}
$validator = new \My\Service\ValidatorService;
$validator->setUserDao($userDao);
?>

```

请注意，该类位于`My\Service`命名空间下，并导入`My\Dao\UserDao`类。

您可以看到类变量`$values`，它保存了提交的表单数值；`$errors`，它保存了提交的表单错误消息；`$statusMsg`，它保存了提交的状态消息，可以是成功或临时信息；以及`$num_errors`，它保存了提交表单中的错误数量。

我们还为验证目的添加了类常量。我们将用户名长度保持在 5 到 100 个字符之间，将`password`字段长度保持在 8 到 32 个字符之间。

由于该类依赖于 UserDao 类，我们使用`setter`方法`setUserDao()`将`$userDao`对象注入其中；传递的`$userDao`对象存储在一个类变量中，以便 DAO 也可以在其他方法中使用。

1.  现在，填写类构造函数，使其看起来类似于以下内容：

```php
public function __construct() {
if (isset($_SESSION['value_array']) && isset($_SESSION['error_array'])) {
$this->values = $_SESSION['value_array'];
$this->errors = $_SESSION['error_array'];
$this->num_errors = count($this->errors);
unset($_SESSION['value_array']);
unset($_SESSION['error_array']);
} else {
$this->num_errors = 0;
}
if (isset($_SESSION['statusMsg'])) {
$this->statusMsg = $_SESSION['statusMsg'];
unset($_SESSION['statusMsg']);
}
}

```

您可以看到，`$_SESSION['value_array']`和`$_SESSION['error_array']`都已经被最初检查。如果它们有一些值设置，那么将它们分配给相应的类变量，如下例所示：

```php
$this->values = $_SESSION['value_array'];
$this->errors = $_SESSION['error_array'];
$this->num_errors = count($this->errors);

```

还调整了`num_errors`与`errors`数组的计数。请注意，`$_SESSION['value_array']`和`$_SESSION['error_array']`中的值将由应用程序类设置，该类将使用此服务 API。立即在抓取其值后取消设置这些会话变量，以便为下一个表单提交做好准备。如果这些变量尚未设置，则`num_errors`应为`0`（零）。

它还检查`$_SESSION['statusMsg']`变量。如果已设置任何状态消息，请将消息抓取到相应的类变量中并取消设置。

1.  现在，按照以下方式在类中输入表单和错误处理方法：

```php
public function setValue($field, $value) {
$this->values[$field] = $value;
}
public function getValue($field) {
if (array_key_exists($field, $this->values)) {
return htmlspecialchars(stripslashes($this->values[$field]));
} else {
return "";
}
}
private function setError($field, $errmsg) {
$this->errors[$field] = $errmsg;
$this->num_errors = count($this->errors);
}
public function getError($field) {
if (array_key_exists($field, $this->errors)) {
return $this->errors[$field];
} else {
return "";
}
}
public function getErrorArray() {
return $this->errors;
}

```

在这些类方法中，您可以看到`setValue($field, $value)`和`getValue($field)`方法分别用于设置和获取单个相应字段的值。同样，`setError($field, $errmsg)`和`getError($field)`在验证时设置和获取相应表单字段值的错误消息，同时 setError 增加`num_errors`的值。最后，`getErrorArray()`返回完整的错误消息数组。

1.  现在，按照以下方式输入表单字段的值验证方法：

```php
public function validate($field, $value) {
$valid = false;
if ($valid == $this->isEmpty($field, $value)) {
$valid = true;
if ($field == "name")
$valid = $this->checkSize($field, $value, self::NAME_LENGTH_MIN, self::NAME_LENGTH_MAX);
if ($field == "password" || $field == "newpassword")
$valid = $this->checkSize($field, $value, self::PASS_LENGTH_MIN, self::PASS_LENGTH_MAX);
if ($valid)
$valid = $this->checkFormat($field, $value);
}
return $valid;
}
private function isEmpty($field, $value) {
$value = trim($value);
if (empty($value)) {
$this->setError($field, "Field value not entered");
return true;
}
return false;
}
private function checkFormat($field, $value) {
switch ($field) {
case 'useremail':
$regex = "/^[_+a-z0-9-]+(\.[_+a-z0-9-]+)*"
. "@[a-z0-9-]+(\.[a-z0-9-]{1,})*"
. "\.([a-z]{2,}){1}$/i";
$msg = "Email address invalid";
break;
case 'password':
case 'newpassword':
$regex = "/^([0-9a-z])+$/i";
$msg = "Password not alphanumeric";
break;
case 'name':
$regex = "/^([a-z ])+$/i";
$msg = "Name must be alphabetic";
break;
case 'phone':
$regex = "/^([0-9])+$/";
$msg = "Phone not numeric";
break;
default:;
}
if (!preg_match($regex, ( $value = trim($value)))) {
$this->setError($field, $msg);
return false;
}
return true;
}
private function checkSize($field, $value, $minLength, $maxLength) {
$value = trim($value);
if (strlen($value) < $minLength || strlen($value) > $maxLength) {
$this->setError($field, "Value length should be within ".$minLength." & ".$maxLength." characters");
return false;
}
return true;
}

```

验证方法可以描述如下：

+   `validate($field, $value)`是验证的入口函数。可以从该方法调用输入验证的方法，例如空字符串检查、正确的输入格式或输入大小范围，并且如果验证通过，则返回`true`，否则返回`false`。

+   `isEmpty($field, $value)`检查字符串是否为空，然后为该字段设置错误消息并返回`false`或`true`。

+   `checkFormat($field, $value)`测试字段的值是否符合为每个字段格式编写的适当正则表达式，设置错误（如果有），并返回`false`，否则返回`true`。

+   `checkSize($field, $value, $minLength, $maxLength)`检查输入是否在给定的最小大小和最大大小之间。

1.  我们希望验证登录凭据，以检查用户电子邮件是否存在，或者密码是否属于与该用户电子邮件匹配的用户。因此，按照以下方式添加`validateCredentials()方法`：

```php
public function validateCredentials($useremail, $password) {
$result = $this->userDao->checkPassConfirmation($useremail, md5($password));
if ($result === false) {
$this->setError("password", "Email address or password is incorrect");
return false;
}
return true;
}

```

该方法接受`$useremail`和`$password`作为登录凭据验证。您可以看到以下行使用`user Dao`来确认与`useremail`关联的密码。Dao 的`checkPassConfirmation()`方法返回`true`表示确认，返回`false`表示电子邮件地址或密码不正确。

```php
$result = $this->userDao->checkPassConfirmation($useremail, md5($password));

```

1.  当用户想要注册到我们的应用程序时，我们可以验证电子邮件地址是否已经存在。如果电子邮件地址在数据库中尚未注册，则用户可以自由注册该电子邮件。因此，输入以下方法：

```php
public function emailExists($useremail) {
if ($this->userDao->useremailTaken($useremail)) {
$this->setError('useremail', "Email already in use");
return true;
}
return false;
}

```

您可以看到该方法在`$this->userDao->useremailTaken($useremail);`中使用`userDao`来检查用户电子邮件是否已被使用。如果已被使用，则设置错误，并返回`true`表示该电子邮件已存在。

1.  当用户想要更新当前密码时，再次需要密码确认。因此，让我们添加另一个方法来验证当前密码：

```php
public function checkPassword($useremail, $password) {
$result = $this->userDao->checkPassConfirmation($useremail, md5($password));
if ($result === false) {
$this->setError("password", "Current password incorrect");
return false;
}
return true;
}

```

## 刚刚发生了什么？

我们已经准备好支持表单、登录凭据和密码验证，甚至通过`userDao`与数据库通信的验证器服务类。此外，验证器服务允许应用程序检索用于访客或用户的临时状态消息，以及表单输入字段的错误消息。因此，它处理各种验证任务，并且如果发现错误，则验证方法设置错误，并在成功时返回`true`，在失败时返回`false`。这样的错误消息可以在相应的表单字段旁边查看，以及字段值。因此，它还有助于创建数据持久性表单。

## 尝试英雄-添加多字节编码支持

现在，我们的验证器服务无法支持多字节字符编码。为了使应用程序能够支持不同的字符编码，如 UTF-8，您可以在验证方法中实现多字节支持，例如设置内部编码、多字节字符串的正则表达式匹配，以及使用`mb_strlen()`而不是`strlen()`。多字节字符串函数可以在[`php.net/manual/en/ref.mbstring.php`](http://php.net/manual/en/ref.mbstring.php)找到。

## 创建 UserService 类

`UserService`类支持所有应用程序任务，如登录、注册或更新用户详细信息。它与`UserDao`类对应于任何类型的数据相关函数，并与`ValidatorService`服务类对应于任何类型的验证函数。应用程序要求任务，如登录或注册，首先调用验证，然后执行任务，同时可能根据需要使用 DAO。最后，如果任务已完成，则返回`true`，如果失败，则返回`false`，例如验证失败或其他任何模糊性。简单地说，应用程序将从`UserService`类调用方法来登录、注册等，并可以了解操作的状态。

# 行动时间-创建 UserService 类

我们将使用`My\Service`作为该类的命名空间，并将任何常量保留在类中。`UserService`类属性将包含用户信息，如用户电子邮件、用户 ID、用户名或电话，并且构造函数将检查已登录用户和从会话加载的类变量中的用户详细信息。此外，该类将利用 PHP cookie 来存储用户的登录数据。该类将充当登录会话管理器。因此，最初，该类将检查会话中或 cookie 中的登录数据，以确定用户是否已登录。

### 提示

建议您熟悉 PHP 会话和 cookie。

因此，让我们按照以下步骤创建`UserService`类：

1.  在`Service`目录中创建一个名为`UserService.php`的新 PHP 文件，并输入以下类：

```php
<?php
namespace My\Service;
use My\Dao\UserDao;
use My\Service\ValidatorService;
class UserService {
public $useremail;
private $userid;
public $username;
public $userphone;
private $userhash;
private $userlevel;
public $logged_in;
const ADMIN_EMAIL = "admin@mysite.com";
const GUEST_NAME = "Guest";
const ADMIN_LEVEL = 9;
const USER_LEVEL = 1;
const GUEST_LEVEL = 0;
const COOKIE_EXPIRE = 8640000;
const COOKIE_PATH = "/";
public function __construct(UserDao $userDao, ValidatorService $validator) {
$this->userDao = $userDao;
$this->validator = $validator;
$this->logged_in = $this->isLogin();
if (!$this->logged_in) {
$this->useremail = $_SESSION['useremail'] = self::GUEST_NAME;
$this->userlevel = self::GUEST_LEVEL;
}
}
}
$userService = new \My\Service\UserService($userDao, $validator);
?>

```

您可以看到该类使用`namespace My\Service;`，并且可以使用`\My\Service\UserService`来访问 Service User 类。

检查存储用户数据的类变量，如果用户已登录，则 `$logged_in` 为 `true`。

为了区分用户，已添加了与用户相关的常量。用你自己的邮箱更新 `ADMIN_EMAIL`；用户中的管理员将由 `ADMIN_EMAIL` 和 `ADMIN_LEVEL` 等于 `9` 来定义。一般注册用户将被定义为 `USER_LEVEL` 等于 1，非注册用户将被定义为 `GUEST_LEVEL` 等于 `0` 或 `GUEST_NAME` 为 Guest。因此，使用邮箱地址 `<admin@mysite.com>` 注册的用户在我们实现管理员功能时将具有管理员访问权限。

在 cookie 常量部分，`COOKIE_EXPIRE` 默认将 cookie 过期时间设置为 `100` 天（8640000 秒），`COOKIE_PATH` 表示 cookie 将在整个应用程序域中可用。

cookie（用户计算机上的文本文件）将用于将 `useremail` 存储为 `cookname`，将 `userhash` 存储为 `cookid`。这些 cookie 将在用户启用“记住我”选项的情况下设置。因此，我们将首先检查用户本地计算机上是否存在与数据库匹配的 cookie，如果是，则将用户视为已登录用户。

请注意，构造函数注入了 `UserDao` 和 `ValidatorService` 对象，因此类可以在内部使用这些依赖项。

现在，通过 `$this->logged_in = $this->isLogin();` 这一行，构造函数检查用户是否已登录。`private` 方法 `isLogin()` 检查登录数据，如果找到则返回 true，否则返回 false。实际上，`isLogin()` 检查会话和 cookie 是否有用户的登录数据，如果有，则加载类变量。

未登录用户将是访客用户，因此 `useremail` 和 `userlevel` 分别设置为 `Guest` 和 `Guest Level 0`。

```php
if (!$this->logged_in) {
$this->useremail = $_SESSION['useremail'] = self::GUEST_NAME;
$this->userlevel = self::GUEST_LEVEL;
}

```

1.  现在，让我们创建 `isLogin()` 方法，如下所示：

```php
private function isLogin() {
if (isset($_SESSION['useremail']) && isset($_SESSION['userhash']) &&
$_SESSION['useremail'] != self::GUEST_NAME) {
if ($this->userDao->checkHashConfirmation($_SESSION['useremail'], $_SESSION['userhash']) === false) {
unset($_SESSION['useremail']);
unset($_SESSION['userhash']);
unset($_SESSION['userid']);
return false;
}
$userinfo = $this->userDao->get($_SESSION['useremail']);
if(!$userinfo){
return false;
}
$this->useremail = $userinfo['useremail'];
$this->userid = $userinfo['id'];
$this->userhash = $userinfo['userhash'];
$this->userlevel = $userinfo['userlevel'];
$this->username = $userinfo['username'];
$this->userphone = $userinfo['phone'];
return true;
}
if (isset($_COOKIE['cookname']) && isset($_COOKIE['cookid'])) {
$this->useremail = $_SESSION['useremail'] = $_COOKIE['cookname'];
$this->userhash = $_SESSION['userhash'] = $_COOKIE['cookid'];
return true;
}
return false;
}

```

如果 `$_SESSION` 具有 `useremail, userhash,` 和 `useremail` 不是 guest，则意味着用户已经登录到数据中。如果是这样，我们希望使用 `UserDao` 的 `checkHashConfirmation()` 方法来确认 `userhash` 和关联的 `useremail` 的安全性。如果未确认，则取消设置 `$_SESSION` 变量，并将其视为未登录，返回 false。

最后，如果一切顺利，使用 `Dao` 加载已登录用户的详细信息，`$userinfo = $this->userDao->get($_SESSION['useremail']);` 加载类和会话变量，并将其返回为 true。

同样，如果 `$_SESSION` 没有已登录的数据，那么我们将选择检查 cookie，因为用户可能已启用“记住我”选项。如果在 cookie 变量中找到必要的数据，则从中加载类和会话变量。

1.  现在，为应用程序创建登录服务如下：

```php
public function login($values) {
$useremail = $values['useremail'];
$password = $values['password'];
$rememberme = isset($values['rememberme']);
$this->validator->validate("useremail", $useremail);
$this->validator->validate("password", $password);
if ($this->validator->num_errors > 0) {
return false;
}
if (!$this->validator->validateCredentials($useremail, $password)) {
return false;
}
$userinfo = $this->userDao->get($useremail);
if(!$userinfo){
return false;
}
$this->useremail = $_SESSION['useremail'] = $userinfo['useremail'];
$this->userid = $_SESSION['userid'] = $userinfo['id'];
$this->userhash = $_SESSION['userhash'] = md5(microtime());
$this->userlevel = $userinfo['userlevel'];
$this->username = $userinfo['username'];
$this->userphone = $userinfo['phone'];
$this->userDao->update($this->userid, array("userhash" => $this->userhash));
if ($rememberme == 'true') {
setcookie("cookname", $this->useremail, time() + self::COOKIE_EXPIRE, self::COOKIE_PATH);
setcookie("cookid", $this->userhash, time() + self::COOKIE_EXPIRE, self::COOKIE_PATH);
}
return true;
}

```

这个方法接受登录详情，比如 `useremail, password,` 和 `rememberme`，并将它们传递到应用程序的 `$values` 数组中。它调用给定输入的验证，如果发现错误则返回 false，并在之后验证访问凭证的关联。如果所有情况都通过了验证，它将从 Dao 中加载用户信息。请注意，在下一行中，`md5(microtime())` 创建一个随机的包含字母数字字符的字符串，并分配给类变量。

```php
$this->userhash = $_SESSION['userhash'] = md5(microtime());

```

最后，为了启动新的登录会话，更新表中对应用户的 `userhash`，这将是当前会话的标识符。

```php
$this->userDao->update($this->userid, array("userhash" => $this->userhash));

```

因此，`$_SESSION userhash` 和数据库 `userhash` 应该对于一个活跃的、已登录的会话是相同的。

此外，您可以看到，如果 `$rememberme` 为 `true`，则使用 PHP 的 `setcookie()` 方法设置 cookie，并设置名称、值和过期时间。

1.  现在，添加用户注册服务方法如下：

```php
public function register($values) {
$username = $values['name'];
$useremail = $values['useremail'];
$password = $values['password'];
$phone = $values['phone'];
$this->validator->validate("name", $username);
$this->validator->validate("useremail", $useremail);
$this->validator->validate("password", $password);
$this->validator->validate("phone", $phone);
if ($this->validator->num_errors > 0) {
return false;
}
if($this->validator->emailExists($useremail)) {
return false;
}
$ulevel = (strcasecmp($useremail, self::ADMIN_EMAIL) == 0) ? self::ADMIN_LEVEL : self::USER_LEVEL;
return $this->userDao->insert(array(
'useremail' => $useremail, 'password' => md5($password),
'userlevel' => $ulevel, 'username' => $username,
'phone' => $phone, 'timestamp' => time()
));
}

```

该方法接受用户注册的详细信息，将它们传递到`$values`数组中，并对其进行验证。如果验证通过，它将用户注册详细信息打包到一个数组中，并使用 User Dao 的`insert()`方法将其保存到数据库中。

请注意，用户级别是通过将注册者的电子邮件地址与`ADMIN_EMAIL`进行比较来确定的。

1.  添加`getUser()`方法如下，以提供与给定的`useremail`参数匹配的用户信息：

```php
public function getUser($useremail){
$this->validator->validate("useremail", $useremail);
if ($this->validator->num_errors > 0) {
return false;
}
if (!$this->validator->emailExists($useremail)) {
return false;
}
$userinfo = $this->userDao->get($useremail);
if($userinfo){
return $userinfo;
}
return false;
}

```

请注意，在提供用户信息之前，`useremail`已经过验证。因此，每当需要用户信息时，应用程序将使用此方法。

1.  现在，添加`update()`方法来修改用户的详细信息。

```php
public function update($values) {
$username = $values['name'];
$phone = $values['phone'];
$password = $values['password'];
$newPassword = $values['newpassword'];
$updates = array();
if($username) {
$this->validator->validate("name", $username);
$updates['username'] = $username;
}
if($phone) {
$this->validator->validate("phone", $phone);
$updates['phone'] = $phone;
}
if($password && $newPassword){
$this->validator->validate("password", $password);
$this->validator->validate("newpassword", $newPassword);
}
if ($this->validator->num_errors > 0) {
return false;
}
if($password && $newPassword){
if ($this->validator->checkPassword($this->useremail, $password)===false) {
return false;
}
$updates['password'] = md5($newPassword);
}
$this->userDao->update($this->userid, $updates);
return true;
}

```

请注意，该方法首先验证给定的信息（如果有）。如果它通过了验证标准，相应的列值将通过 User Dao 更改到数据库表中。

1.  `logout()`方法可以添加如下：

```php
public function logout() {
if (isset($_COOKIE['cookname']) && isset($_COOKIE['cookid'])) {
setcookie("cookname", "", time() - self::COOKIE_EXPIRE, self::COOKIE_PATH);
setcookie("cookid", "", time() - self::COOKIE_EXPIRE, self::COOKIE_PATH);
}
unset($_SESSION['useremail']);
unset($_SESSION['userhash']);
$this->logged_in = false;
$this->useremail = self::GUEST_NAME;
$this->userlevel = self::GUEST_LEVEL;
}

```

`logout`方法取消所有 cookie 和会话变量，将`$this->logged_in`设置为`false`，用户再次成为访客用户。

## 刚刚发生了什么？

现在我们可以检查用户是否已登录，以及用户是否被要求记住登录详细信息，这样用户就不需要再次使用`记住我`选项登录。该类用于登录、注销、用户注册以及更新或检索用户信息到应用程序层。它在进行 Dao 层之前使用验证器服务。因此，该类还确保了数据安全性，使得`UserService`类在服务层准备就绪。

最后，我们的 API 已经准备好工作，通过使用这个 API，我们可以构建一个用户注册、用户资料更新、登录和注销的应用程序。我们有我们的数据访问层和服务层正在运行。现在，让我们来看看我们的 NetBeans 项目目录。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_06.jpg)

为了更好地理解，我们为每个层使用了一个单独的目录和一个单独的命名空间。现在，我们将在我们的应用程序文件中包含 API，并通过使用 User Service 对象，我们将实现我们应用程序的目标。

## 快速测验——使用命名空间

1.  PHP 命名空间支持哪些特性？

1.  给类名取别名

1.  给接口名称取别名

1.  给命名空间名称取别名

1.  导入函数或常量

1.  哪一个将导入名为`foo`的全局类？

1.  命名空间 foo;

1.  使用 foo;

1.  导入 foo;

1.  以上都不是

# 构建应用程序

在本教程中，我们将构建一个能够处理用户注册任务的应用程序，例如处理注册表单、通过 API 保存用户数据或显示错误消息，以及用户登录和注销任务。在下一节中，我们将构建 PHP 应用程序，然后添加应用程序用户界面。

在继续之前，请记住我们只有服务层类。我们将选择以这样的方式构建应用程序，使我们的应用程序建立在服务层之上。对于本节，我们不需要考虑底层数据库或 Dao，而是需要从应用程序开发人员的角度思考。

# 行动时间——创建用户应用程序

我们将把 API 集成到我们的用户应用程序文件中，这将是主要的应用程序文件；每个应用程序目的可能会有接口或视图文件。让我们按照以下步骤进行：

1.  在项目目录中创建一个名为`UserApplication.php`的新 PHP 文件，并输入以下`UserApplication`类：

```php
<?php
namespace My\Application;
use My\Service\UserService;
use My\Service\ValidatorService;
session_start();
require_once "Dao/BaseDao.php";
require_once "Dao/UserDao.php";
require_once "Service/ValidatorService.php";
require_once "Service/UserService.php";
class UserApplication {
public function __ construct (UserService $userService, ValidatorService $validator) {
$this->userService = $userService;
$this->validator = $validator;
if (isset($_POST['login'])) {
$this->login();
}
else if (isset($_POST['register'])) {
$this->register();
}
else if (isset($_POST['update'])) {
$this->update();
}
else if ( isset($_GET['logout']) ) {
$this->logout();
}
}
}
$userApp = new \My\Application\UserApplication($userService, $validator);
?>

```

在文件顶部，您可以看到在构造函数声明之后，PHP 会话以`session_start()`开始。API 文件已被包含，并且类构造函数已注入了`User`和`Validator Service`对象，因此这些对象在整个应用程序中都可用。

您可以看到，根据用户的请求，适当的方法是从构造函数中调用的，例如如果设置了`$_POST['login']`，则调用`$this->login();`。因此，所有方法都是从构造函数中调用的，并且应具有以下功能：

+   `login()`

+   `register()`

+   `update()`

+   `logout()`

在文件底部，我们有一行`$userApp = new \My\Application\UserApplication($userService, $validator);`，它实例化了`UserApplication`类以及依赖注入。

1.  在下面键入以下`login()`方法：

```php
public function login() {
$success = $this->userService->login($_POST);
if ($success) {
$_SESSION['statusMsg'] = "Successful login!";
} else {
$_SESSION['value_array'] = $_POST;
$_SESSION['error_array'] = $this->validator->getErrorArray();
}
header("Location: index.php");
}

```

您可以看到，该方法调用用户服务，并使用用户界面发布的登录凭据在以下行中：

```php
$success = $this->userService->login($_POST);

```

如果登录尝试成功，则在`$_SESSION['statusMsg']`会话变量中设置成功状态消息，如果失败，则将用户通过`$_POST`数组设置为`$_SESSION['value_array']`，并将从验证器对象中获取的错误数组设置为`$_SESSION['error_array']`。最后，它将重定向到`index.php`页面。

1.  在下面键入以下`register()`方法：

```php
public function register() {
$success = $this->userService->register($_POST);
if ($success) {
$_SESSION['statusMsg'] = "Registration was successful!";
header("Location: index.php");
} else {
$_SESSION['value_array'] = $_POST;
$_SESSION['error_array'] = $this->validator->getErrorArray();
header("Location: register.php");
}
}

```

您可以看到，如果注册尝试失败，则会重置相应的会话变量，并重定向到`register.php`页面，这是用户注册页面。

1.  在下面键入以下`update()`方法：

```php
public function update() {
$success = $this->userService->update($_POST);
if ($success) {
$_SESSION['statusMsg'] = "Successfully Updated!";
header("Location: profile.php");
} else {
$_SESSION['value_array'] = $_POST;
$_SESSION['error_array'] = $this->validator->getErrorArray();
header("Location: profileedit.php");
}
}

```

您可以看到，如果用户资料更新尝试失败，则会重置相应的会话变量，并重定向到`profileedit.php`页面，这是资料编辑页面，或者在成功时重定向到`profile.php`。因此，这些页面将是我们的用户资料查看和更新页面。

1.  在下面键入以下`logout()`方法，它只是调用注销服务：

```php
public function logout(){
$success = $this->userService->logout();
header("Location: index.php");
}

```

## 刚刚发生了什么？

现在我们的主应用程序类已经准备就绪，功能也已经准备就绪。因此，我们可以使用应用程序注册、登录、更新和注销用户。请注意，我们的应用程序只是通过服务对象进行通信，您可以感觉到应用程序对数据源不感兴趣；它所做的只是利用为其设计的服务。通过这种方式，我们可以为用户编写更有趣的应用程序，例如查看注册用户列表；开发管理员功能，例如更新任何用户或删除任何用户，甚至通过更新`userlevel`将用户从普通用户提升为管理员。通过在不同层中编写更多有趣的方法，我们可以获得特定的应用程序。

在我们的下一个和最后一节中，我们将为特定功能添加用户界面或页面。

## 创建用户界面

我们将为用户注册和登录创建简单的用户界面和表单。此外，我们还将为查看用户资料、更新资料和注销提供一些用户菜单。我们将在我们的界面文件的顶部集成`UserApplication.php`。我们的界面文件将包含简单的 HTML，其中包含内部集成的 PHP 代码。

# 行动时间-创建用户界面

我们将在每个界面文件的开头集成用户应用程序文件。因此，请按照以下步骤创建各种用户界面：

1.  打开`index.php`并集成`UserApplication`类，使其如下所示：

```php
<?php
require_once 'UserApplication.php';
?>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title></title>
</head>
<body>
</body>
</html>

```

所有界面代码都可以在 body 标记内。

1.  现在，让我们创建一个已登录用户菜单，显示状态消息（如果有），已登录用户名，并在每个页面顶部显示菜单。创建一个名为`menu.php`的新 PHP 文件，并键入以下代码：

```php
<?php
if (isset($validator->statusMsg)) {
echo "<span style=\"color:#207b00;\">" . $validator->statusMsg . "</span>";
}
if ($userService->logged_in) {
echo "<h2>Welcome $userService->username!</h2>";
echo "<a href='profile.php'>My Profile</a> | "
. "<a href='profileedit.php'>Edit Profile</a> | "
. "<a href='UserApplication.php?logout=1'>Logout</a> ";
}
?>

```

您可以看到，如果`$validator->statusMsg`可用，则我们将其显示在彩色的`span`标记内。此外，如果用户已登录，则它会在`<h2>`标记内显示用户名，并显示用于查看资料、编辑资料和注销的`anchor`标记。现在，在我们的页面中，我们将在`<body>`标记内包含此菜单，如下所示：

```php
include 'menu.php';

```

1.  现在，让我们创建用户注册页面`register.php`，并键入以下代码：

```php
<?php
require_once 'UserApplication.php';
?>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title></title>
</head>
<body>
<?php
include 'menu.php';
if (!$userService->logged_in) {
?>
<h2>User Registration</h2><br />
<?php
if ($validator->num_errors > 0) {
echo "<span style=\"color:#ff0000;\">" . $validator->num_errors . " error(s) found</span>";
}
?> **<form action="UserApplication.php" method="POST">
Name: <br />
<input type="text" name="name" value="<?= $validator->getValue("name") ?>"> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("name")."</span>"; ?>
<br />
Email: <br />
<input type="text" name="useremail" value="<?= $validator->getValue("useremail") ?>"> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("useremail")."</span>"; ?>
<br />
Password:<br />
<input type="password" name="password" value=""> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("password")."</span>"; ?>
<br />
Phone: <br />
<input type="text" name="phone" value="<?= $validator->getValue("phone") ?>"> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("phone")."</span>"; ?>
<br /><br />
<input type="hidden" name="register" value="1">
<input type="submit" value="Register">
</form>**
<br />
Already registered? <a href="index.php">Login here</a>
<?php
}
?>
</body>
</html>

```

您可以看到，当用户未登录时，显示了用户注册表单。如果有任何错误，则在表单之前显示`错误数量`，使用`$validator->num_errors`。

在下一行中，您可以看到表单将被发布到 UserApplication.php 文件：

```php
<form action="UserApplication.php" method="POST">

```

该表单由四个输入框组成，用于姓名、电子邮件、密码和电话号码，以及一个提交按钮用于提交表单。表单带有一个隐藏的输入字段，其中包含预加载的值。这个隐藏字段的值将用于通过`UserApplication`类构造函数来识别登录任务，以便调用适当的方法。

1.  现在，让我们看一个输入字段，如下所示：

```php
Name: <br />
<input type="text" name="name" value="<?= $validator-> getValue("name") ?>"> <? echo "<span style= \"color:#ff0000;\">".$validator->getError("name")."</span>"; ?>

```

您可以看到字段值已被转储（如果可用，则使用`$validator->getValue("name")`），并显示在`value`属性中。在表单验证期间，可以使用字段名称在`validator`方法中找到字段值。此外，通过使用`$validator->getError("name")`，可以显示与`name`字段相关的任何错误。因此，其余字段被设计为相似。

1.  要测试表单验证，请使用`register.php`指向您的浏览器；单击**注册**按钮以在不填写任何字段的情况下提交表单。表单看起来类似于以下屏幕截图，每个字段旁边都有一个错误指示。![操作时间-创建用户界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_07.jpg)

您可以看到，表单显示了每个字段的错误，并在表单顶部显示了错误数量。因此，我们的验证器和用户服务正在工作。因此，您可以测试注册表单以进行书面验证，并最终填写表单以注册自己，并检查数据库表以获取您提交的信息。

1.  现在，让我们在`index.php`文件中的`<body>`标记内创建登录表单，并选择`记住我`选项，以便`body`标记包含以下代码：

```php
<?php
include 'menu.php';
if (!$userService->logged_in) {
?>
<h2>User Login</h2>
<br />
<?php
if ($validator->num_errors > 0) {
echo "<span style=\"color:#ff0000;\">" . $validator->num_errors . " error(s) found</span>";
}
?> **<form action="UserApplication.php" method="POST">
Email: <br />
<input type="text" name="useremail" value="<?= $validator->getValue("useremail") ?>"> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("useremail")."</span>"; ?>
<br />
Password:<br />
<input type="password" name="password" value=""> <? echo "<span style=\"color:#ff0000;\">".$validator->getError("password")."</span>"; ?>
<br />
<input type="checkbox" name="rememberme" <?=($validator->getValue("rememberme") != "")?"checked":""?>>
<font size="2">Remember me next time </font>
<br />
<input type="hidden" name="login" value="1">
<input type="submit" value="Login">
</form>**
<br />
New User? <a href="register.php">Register here</a>
<?php
}
?>

```

1.  查看登录表单；字段已以与注册表单相同的方式组织。表单包含一个名为`login`的隐藏字段和值设置为`1`。因此，当表单被发布时，应用程序类可以确定已提交登录表单，因此调用了应用程序登录方法。登录表单页面看起来类似于以下内容：![操作时间-创建用户界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_08.jpg)

1.  使用您注册的数据测试登录表单并登录。成功登录后，您将被重定向到同一页，如下所示：![操作时间-创建用户界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_09.jpg)

您可以看到页面顶部显示了绿色的**成功登录**状态，并且用户已登录，因此不再需要登录表单。

1.  现在，创建`profile.php`个人资料页面（您可以通过选择**文件|另存为...**从菜单中的任何界面页面创建文件，并在`body`标记内进行修改），因为它应该在`body`标记内包含以下代码：

```php
<?php
include 'menu.php';
if ($userService->logged_in) {
echo '<h2>User Profile</h2>';
echo "Name : " . $userService->username . "<br />";
echo "Email: " . $userService->useremail . "<br />";
echo "Phone: " . $userService->userphone . "<br />";
}
?>

```

在此代码片段中，您可以看到已转储已登录用户的个人资料信息，看起来类似于以下内容：

![操作时间-创建用户界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_10.jpg)

1.  现在，创建个人资料编辑页面`profileedit.php`，并键入以下代码：

```php
<?php
include 'menu.php';
if ($userService->logged_in) {
?>
<h2>Edit Profile</h2><br />
<?php
if ($validator->num_errors > 0) {
echo "<span style=\"color:#ff0000;\">" . $validator->num_errors . " error(s) found</span>";
}
?> **<form action="UserApplication.php" method="POST">
Name: <br />
<input type="text" name="name" value="<?= ($validator->getValue("name") != "") ? $validator->getValue("name") : $userService->username ?>"> <? echo "<span style=\"color:#ff0000;\">" . $validator->getError("name") . "</span>"; ?>
<br />
Password:<br />
<input type="password" name="password" value=""> <? echo "<span style=\"color:#ff0000;\">" . $validator->getError("password") . "</span>"; ?>
<br />
New Password: <font size="2">(Leave blank to remain password unchanged)</font><br />
<input type="password" name="newpassword" value=""> <? echo "<span style=\"color:#ff0000;\">" . $validator->getError("newpassword") . "</span>"; ?>
<br />
Phone: <br />
<input type="text" name="phone" value="<?= ($validator->getValue("phone") != "") ? $validator->getValue("phone") : $userService->userphone ?>"> <? echo "<span style=\"color:#ff0000;\">" . $validator->getError("phone") . "</span>"; ?>
<br /><br />
<input type="hidden" name="update" value="1">
<input type="submit" value="Save">
</form>**
<?php
}
?>

```

该表单包含用户个人资料更新字段，如姓名、密码和电话；请注意，如果任何字段（如密码）保持空白，则该字段将不会被更新。最后，在测试时，表单看起来类似于以下内容：

![操作时间-创建用户界面](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-app-dev-ntbn/img/5801_07_11.jpg)

1.  现在我们可以测试注销功能。查看菜单文件以获取注销的`anchor`标签，如下所示：

```php
<a href='UserApplication.php?logout=1'>Logout</a>

```

您可以看到它直接将`UserApplication.php`文件与`logout=1` URL 段锚定，因此`UserApplication`构造函数发现已使用`$_GET['logout']`调用了注销，并调用应用程序注销。注销后将重定向到索引页面。

## 刚刚发生了什么？

我们刚刚创建并测试了我们新建的用户界面。在注册用户、登录或更新用户资料时，测试非常有趣。请记住，我们可以在未来的项目中使用这个登录应用，或者可以以最小成本轻松集成新功能。我们的目标是创建分层架构，并根据该设计构建应用程序已经实现。

### 注意

本章的完整项目源代码可以从 Packt Publishing 网站下载。您还可以在 GitHub 上 fork 这个项目的扩展版本：[`github.com/mahtonu/login-script`](http://https://github.com/mahtonu/login-script)。

## 小测验——应用架构

1.  我们的应用架构中有多少层？

1.  2

1.  3

1.  4

1.  5

1.  数据库抽象是在哪一层实现的？

1.  数据存储层

1.  数据访问层

1.  抽象层

1.  以上所有内容

1.  在我们的应用程序中，哪个方法直接与数据库通信以检查电子邮件地址是否存在？

1.  `useremailTaken()`

1.  `emailExists()`

1.  `checkEmail()`

1.  确认电子邮件()

## 尝试一下——创建管理员功能

正如您已经注意到的，我们已经创建了一个数据库表列来定义管理员用户。因此，在用户服务中实现管理员功能，比如一个方法来确定用户是否是管理员；如果他/她是管理员，那么添加管理员页面/接口方法来从用户 Dao 获取所有用户列表，并显示这些用户详情，等等。同样，您可以实现管理员功能，将普通用户提升为管理员用户，通过更新`userlevel`列。

# 摘要

在本章中，我们使用分层设计开发了用户注册、登录和注销应用。我们现在对企业系统架构有信心，并且可以轻松地向开发的应用程序中添加或删除功能。

我们特别关注了：

+   设计应用架构

+   理解 DAO 模式

+   创建 DAO 类

+   创建服务类

+   创建用户注册、登录和注销应用

+   开发用户界面

因此，我们已经进入了专业的 PHP 项目开发和 IDE 功能的实践，这帮助了我们很多。我们可以在未来的 Web 应用程序中使用这个项目，其中需要用户登录功能；这就是“开发一次，稍微更新，一直使用”的优势。
