# jQueryUI 1.10：jQuery 的用户界面库（六）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 帮助与支持

在本书的各处，您可能已经注意到我们专注于使用 jQuery 版本 2.0 作为与 jQuery UI 兼容的最新版本。然而，默认情况下，jQuery UI 1.10 捆绑了 jQuery 1.9.1——如果 jQuery UI 1.10 捆绑了版本 1.9.1，我们为什么要使用版本 2.0 呢？

这样做的原因很简单，与 jQuery 2.0 版本中的一个重要更改有关，即删除了对 Internet Explorer (IE) 6-8 的支持。删除对这些旧版浏览器的支持使 jQuery 团队能够删除库的重要部分，因为这些部分只是为了为浏览器提供解决方法而被包含进来的！

虽然由于安全漏洞的原因，退役 IE 6 曾经是一场大规模的行动，但仍然有必要支持它；考虑到这一点，jQuery 团队仍然在支持 1.x 分支的 jQuery 版本，只要这些旧版浏览器仍然在使用。

# 下载 jQuery

在代码下载的每个章节练习文件夹中，都包含了两个版本的 jQuery —— 版本 2.0.3 的副本已经添加到了正常下载的 jQuery 中的 `JS` 文件夹中（其中包含 1.9.1）。

如果您需要获取 jQuery 2.x 版本的最新副本，您可以通过浏览到[`www.jquery.com/download`](http://www.jquery.com/download)来获取。在这里，您将找到 jQuery 2.x 的未压缩和压缩版本的链接。为了练习的目的，我建议使用未压缩版本。您需要右键单击链接，并选择**另存为…**（或您浏览器的等效选项），以便将文件保存到 `JS` 子文件夹中。

## 更新代码示例

所有代码示例都已默认设置为使用 jQuery 2.0.3。如果我们查看一个使用 Tabs 小部件的示例，我们应该看到类似于这样的内容，位于我们示例的头部：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset=”utf-8”>
  <title>Tabs</title>
  <link rel=”stylesheet” href=”development-bundle/themes/base/jquery.ui.all.css”>
 <script src=”js/jquery-2.0.3.js”></script>
  <script src=”development-bundle/ui/jquery.ui.core.js”></script>
  <script src=”development-bundle/ui/jquery.ui.widget.js”></script>
  <script src=”development-bundle/ui/jquery.ui.tabs.js”></script>
...
```

这里的突出显示的行对我们很重要；您需要确保您刚下载的文件已被保存为 `jquery-2.0.3.js` 文件名，以便每个示例正常工作。

# 获取帮助

有时候了解一个新库可能会让人望而生畏，尤其是像 jQuery UI 这样庞大的库——让我们看看可用的一些选项，您可以从哪里获取有关该库的提示、技巧、帮助和支持。

# 更改主题

在本书的各处，我们都涵盖了 jQuery UI 中主题的使用——一个你可以将其合并到你的页面中的有用工具是 Super Theme Switcher (STS) 插件，可以从[`github.com/harborhoffer/Super-Theme-Switcher`](https://github.com/harborhoffer/Super-Theme-Switcher)获取。一旦实施，您可以随意在不同主题之间切换；这是查看当主题更改时您网站的小部件将如何显示的绝佳方式，然后再将更改永久化。

如果您需要编辑现有主题，这尤其有用；最好的做法是将您的编辑放入一个覆盖文件中，并单独调用此文件；编辑核心 UI CSS 文件意味着在升级到下一个版本的 jQuery UI 时可能会遇到问题，因为定制可能会丢失。

# 从社区获得帮助

jQuery UI 有各种演示，您可以在其中看到每个插件提供的元素。这是由详尽的 API 文档附带的，该文档涵盖了 jQuery UI 提供的小部件、效果、方法和选择器。您可以从 [`api.jqueryui.com`](http://api.jqueryui.com) 查看此文档；另一个好的浏览位置是 [`learn.jquery.com/jquery-ui/getting-started/`](http://learn.jquery.com/jquery-ui/getting-started/) 提供的文档。

# 需要提问吗？

这也不是问题；有许多可用于 jQuery UI 的公共论坛：

+   **使用 jQuery UI**：对于所有使用 jQuery UI 的人来说，提出关于所有 UI 组件的问题和建议的最佳位置，包括 Themeroller，请访问 [`forum.jquery.com/using-jquery-ui`](http://forum.jquery.com/using-jquery-ui)。

+   **开发 jQuery UI**：对于更高级的开发人员想要开发 jQuery UI 库和网站的人，可以从 [`forum.jquery.com/developing-jquery-ui`](http://forum.jquery.com/developing-jquery-ui) 获取帮助。

+   **jQuery 辅助功能**：对于因辅助功能问题而无法使用正常论坛的任何人，可在 [`groups.google.com/forum/#!forum/jquery-a11y`](https://groups.google.com/forum/#!forum/jquery-a11y) 上找到另一种可用的论坛。

# 通过 IRC 聊天获取帮助

您甚至可以通过 IRC 聊天获取帮助，官方 IRC 支持频道是`#jquery`，位于 [irc.freenode.net](http://irc.freenode.net)。有关 jQuery UI 开发的讨论，请加入`#jqueryui-dev`频道。

# 在 Stack Overflow 提问

您甚至可以在 Stack Overflow 上提问和回答 jQuery（和 jQuery UI）的问题，网址为 [`stackoverflow.com/tags/jquery/info`](http://stackoverflow.com/tags/jquery/info)。这是一个大型网站，人们可以提问、寻求建议，并在任何涉及 jQuery UI 的问题上提供一般帮助。

# 报告库中的错误

软件并不完美；通常要感谢开发了库的贡献者，例如 jQuery UI，今天仍然活跃使用。如果您发现了一个错误，您可以在 [`bugs.jqueryui.com`](http://bugs.jqueryui.com) 报告它。

### 小贴士

强烈建议您阅读笔记并浏览已记录的错误，以防某人已经报告了相同的问题！
