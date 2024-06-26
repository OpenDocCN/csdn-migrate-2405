# 精通 PHPMyAdmin 3.4 高效 MySQL 管理（四）

> 原文：[`zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1`](https://zh.annas-archive.org/md5/3B102B7D75B6F6D265E7C3CE6613ECC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 故障排除和支持

这个附录 A 提出了解决一些常见问题的指南，并提供了如何避免这些问题的提示。它还解释了如何与开发团队互动以获取支持、错误报告和贡献。

# 故障排除

多年来，开发团队收到了许多支持请求，其中许多请求只需进行简单的验证就可以避免。

## 系统要求

`Documentation.html`文件的开头部分（包含在 phpMyAdmin 软件中）讨论了我们正在使用的特定 phpMyAdmin 版本的系统要求。这些要求必须得到满足，并且环境必须得到正确配置，以避免出现问题。

一些看起来像是 phpMyAdmin 错误的问题实际上是由服务器环境引起的。有时，Web 服务器没有正确配置来解释`.php`文件，或者 Web 服务器内部的 PHP 组件没有使用`mysql`或`mysqli`扩展运行。MySQL 帐户可能配置错误。这种情况可能发生在家庭服务器和托管服务器上。

当我们怀疑出现问题时，我们可以尝试一个简单的 PHP 脚本`test.php`，其中包含以下代码块，以检查 PHP 组件是否正确回答：

```sql
<?php
echo 'hello';
?>

```

我们应该看到**hello**消息。如果这个有效，我们可以尝试另一个脚本：

```sql
<?php
phpinfo();
?>

```

这个脚本显示了关于 PHP 组件的信息，包括可用的扩展。我们至少应该看到一个关于 MySQL 的部分（证明`mysql`扩展可用），其中提供了关于 MySQL**客户端 API 版本**的信息。

我们还可以尝试其他连接到 MySQL 的 PHP 脚本，以查看问题是否比 phpMyAdmin 不工作更普遍。一般来说，我们应该运行每个组件的最新稳定版本。

## 验证基本配置

我们应该始终仔细检查我们执行安装的方式，包括正确的权限和所有权。在修改`config.inc.php`时可能会出现拼写错误。

## 解决常见错误

为了帮助解决问题，我们应该首先确定错误消息的来源。以下是可能生成错误消息的各种组件：

+   MySQL 服务器：这些消息是由 phpMyAdmin 中继的，显示**MySQL said**后跟着消息

+   Web 服务器的 PHP 组件：例如，**解析器错误**

+   Web 服务器：错误可以从浏览器中看到，或者在 Web 服务器的日志文件中看到

+   Web 浏览器：例如，JavaScript 错误

# 寻求支持

支持的起点是 phpMyAdmin 官方网站[`phpmyadmin.net`](http://phpmyadmin.net)，其中有关于文档和支持的部分。在那里你会找到链接到讨论论坛和各种跟踪器的链接，比如：

+   错误跟踪器

+   功能请求跟踪器

+   翻译跟踪器

+   补丁跟踪器

+   支持跟踪器

## 常见问题

产品的`Documentation.html`文件包含了一个详尽的常见问题解答部分，其中有编号的问题和答案。建议首先查阅这个常见问题解答部分以获取帮助。

## 帮助论坛

开发团队建议您使用产品的论坛搜索遇到的问题，然后在打开错误报告之前开始一个新的论坛讨论。

### 创建 SourceForge 帐户

强烈建议创建（免费）SourceForge 用户帐户并在论坛上使用它。这样可以更好地跟踪问题和答案。

### 选择主题标题

在开始新的论坛主题时，仔细选择摘要标题非常重要。像“帮帮我！”、“帮助新手！”、“问题”或“phpMyAdmin 错误！”这样的标题很难处理，因为答案都是针对这些标题的，进一步的参考变得困难。在帮助论坛中使用过的更好的标题包括：

+   “使用 UploadDir 导入”

+   “用户无法登录但 root 可以”

+   “我可以期望表有多大”

+   “持续登录提示”

+   “无法添加外键”

### 阅读答案

由于人们会阅读并几乎总是回答您的问题，因此在论坛中对答案进行反馈确实可以帮助回答问题的人，也可以帮助其他遇到相同问题的人。

## 使用支持跟踪器

支持跟踪器是另一个寻求支持的地方。此外，如果我们提交了一个实际上是支持请求的错误报告，该报告将被移动到支持跟踪器。如果您在您的个人资料中配置了电子邮件转发的 SourceForge 用户帐户，您将收到此跟踪器更改的通知。

## 使用错误跟踪器

在这个跟踪器中，我们看到尚未修复的错误，以及已经为下一个版本修复的错误。为下一个版本修复的错误保持“打开”状态，以避免重复的错误报告，但它们的优先级降低。

### 环境描述

由于开发人员将尝试重现提到的问题，因此描述您的环境有助于解决问题。这个描述可以很简短，但应包含以下内容：

+   phpMyAdmin 版本（团队，但是期望它是当前稳定版本）

+   Web 服务器名称和版本

+   PHP 版本

+   MySQL 版本

+   浏览器名称和版本

通常情况下，除非我们注意到错误只涉及一个操作系统，否则不需要指定服务器或客户端正在运行的操作系统。例如，FAQ 5.1 描述了一个问题，用户无法创建超过十四个字段的表。这只发生在 Windows 98 下。

### 错误描述

我们应该准确描述发生了什么（包括任何错误消息、预期结果和实际结果）。如果报告只描述一个问题（除非问题明显相关），那么它们将更容易管理。

有时，附加一个简短的导出文件到错误报告可能有助于开发人员重现问题。欢迎截图。

# 项目的贡献

自 1998 年 phpMyAdmin 成立以来，数百人贡献了翻译、新功能的代码、建议和错误修复。

## 代码库

开发团队维护着一个不断发展的代码库，他们定期发布版本。在[`phpmyadmin.net`](http://phpmyadmin.net)上，“改进”页面解释了任何人如何贡献，并提供了关于项目的`git`源代码库的指针。如果贡献（翻译更新、补丁、新功能等）是针对最新的代码库而不是过时的 phpMyAdmin 版本，那么它将被视为更高优先级。另一个有关使用 Git 的有用指南页面位于[`wiki.phpmyadmin.net/pma/Git`](http://wiki.phpmyadmin.net/pma/Git)。

## 翻译更新

查看项目当前的 65 种语言列表，您会注意到它们的维护程度并不相同。自从项目迁移到基于`gettext`的本地化系统以来，鼓励每个人贡献翻译。该项目正在使用一个配备`Pootle`软件的翻译服务器，位于[`l10n.cihar.com/projects/phpmyadmin`](http://https://l10n.cihar.com/projects/phpmyadmin)。也可以使用该服务器来翻译 phpMyAdmin 的`Documentation.html`。

## 补丁

如果以`git format-patch`的形式提交到当前代码库的补丁，并解释解决的问题或实现的新功能，开发团队可以更轻松地管理补丁。主要贡献者将在`Documentation.html`中得到官方认可。
