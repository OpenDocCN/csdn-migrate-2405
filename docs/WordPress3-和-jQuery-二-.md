# WordPress3 和 jQuery（二）

> 原文：[`zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8`](https://zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：用更少的东西做更多的事情：利用 jQuery 和 WordPress 的插件

在这一点上，你已经足够了解 jQuery 和 WordPress 基础知识，以及将它们整合在一起的不同方法，你可以开始在解决方案中真正发挥创造力。在本章和接下来的三章中，我们将卷起袖子，为一些经常请求的项目制定解决方案，并开始让 jQuery 在我们的 WordPress 网站中执行一些有用且很酷的工作。

我们将把 WordPress 和 jQuery 的所有可用组件结合起来。在本章中，我们将：

+   使用非常强大和受欢迎的 jQuery 插件 ColorBox，由*Jack Moore* 的 Color Powered 提供。

+   我们还将使用由*Oliver Seidel* 的 Deliciousdays 提供的强大且受欢迎的 WordPress 插件 cforms II。

+   然后，我们将自定义我们的默认主题，使其与 cforms II 和 ColorBox 无缝配合，为我们的网站提供无缝的活动注册体验。

+   我们还没有完成！然后，我们将通过 jQuery 来增强 cform II 已经很棒的验证，以获得流畅的用户体验。

准备好让你的 WordPress 网站发挥作用！

# 项目概述：无缝活动注册

虽然我们将继续使用默认主题，但我们将为这一章的 jQuery 增强设想一个不同的假想客户和情景。

在这种情况下，“客户”是一个非营利性/意识组织。他们在他们的 WordPress 网站中创建了一个**活动**类别，每当计划举办新活动时，每个活动的协调员都可以将有关即将举办活动的信息发布到活动类别。

他们大多数的活动都是免费的，但非常混乱，因为每个协调员决定如何接受活动的注册，通过电子邮件或电话。人们感到困惑，向网站上的错误人发送电子邮件，然后无法确定谁参加了哪些活动，以便组织的领导者可以从忙碌的活动协调员那里收集统计数据，以跟踪活动对其事业的有效性。

好消息是，我们仍然可以帮助他们解决所有这些问题。

## “客户”想要什么

在坐下来讨论所有选项之后，最终，他们希望有一个简单的注册表单，可以将活动名称传递给它，然后通过电子邮件发送给活动管理员，后者将 RSVP 分配给各个活动组织者。

他们还收到了注册者的反馈，抱怨活动的发布日期使他们困惑：他们不注册活动，因为除非协调员将日期加粗或将其放在标题中，否则看起来就像活动是在那一天发生的，或者已经过去了。因此，客户希望重新设计并清理一下他们的活动发布模板，以便更容易识别它们为活动，而不是网站上的其他帖子。

最后，也是最重要的是，他们对最近在几个网站上看到的反馈和其他形式印象深刻并受到影响，他们真的很希望他们的注册表单在模态框中打开，这样人们就可以在停留在**活动**页面的同时注册活动。当他们完成活动注册后，他们可以继续浏览**活动**类别并轻松注册更多活动。

# 第一部分：准备好所有设置

幸运的是，有了一点 WordPress 和 jQuery 知识，这个任务并不像听起来那么复杂。在上一章中，我赞美了将设计和功能分开以及将您的 jQuery 增强功能包装在 WordPress 插件中的优点。我还提到了总有例外的事实。好吧，这里有一个场景，我们倾向于直接将我们的增强功能应用于主题的几个原因：

+   我们将调整主题以创建一个用于活动的自定义类别页面。

+   而且，我们还需要为可以加载到模态框中的表单创建一个自定义页面模板，而不需要重新加载站点的页眉和页脚

因为这些请求要求客户端明白，如果他们想要更新或替换他们的主题，他们就需要小心，我们可能会充分利用 WordPress 主题 API 为这一增强功能提供的全部功能。

## 我们需要什么

让我们从增强的主要部分开始：我们需要一个具有电子邮件功能的表单和一个加载它的模态框。其余的我们将通过几个自定义的 jQuery 脚本和对 WordPress 主题的自定义来完成。

### ColorBox

对于模态框，有几个很好的 jQuery 插件。你可能听说过很好的 ThickBox，但我个人更喜欢 ColorBox，因为有几个使用和美观的原因。

你可以从这里下载 jQuery ColorBox 插件：[`www.colorpowered.com/colorbox/`](http://www.colorpowered.com/colorbox/)。

### 注意

**为什么选择 ColorBox 而不是 ThickBox？**

ThickBox 插件与 WordPress 捆绑在一起，我是 ThickBox 的忠实粉丝，但我也更喜欢 jQuery LightBox 的简洁性（jQuery LightBox 仅适用于图像）。当我发现 ColorBox 时，我感到非常惊讶，有几个原因：

+   ThickBox 和 ColorBox 插件都提供了不仅仅是图像的模态窗口。

+   你可以调用内联元素、外部文件和 iFrame，以及基本的 AJAX 调用。一点问题都没有。

然而，与 ThickBox 相比，ColorBox 有一些优势。对于 ColorBox，*Jack Moore* 确实花了一些时间和精力设计了五种非常漂亮的模态窗口样式，以及一套不错的回调和扩展函数供更高级的开发者使用。其次，模态窗口组件（透明背景、关闭、**下一步**和**上一步**按钮）的所有图像加载都完全在样式表中处理，因此设计师很容易自定义模态窗口的样式。有几次，我不得不手动编辑 `thickbox js` 文件，以便让图像正确加载，如果它们不是相对于插件 js 文件的方式，那是 ThickBox 的意图，或者如果我需要添加新图像。

最后，ThickBox 依赖于您手动向要从中启动模态窗口的元素添加 `.thickbox` 类属性。虽然这种方法对于有幸手工编码所有内容的 Web 开发者来说效果很好，但对于在 WordPress 等发布平台内实现的 less 技术性用户来说是一种痛苦。必须指导（和劝说）客户将他们的管理面板编辑器设置为**HTML**并自定义添加 `class` 属性到他们的标记中，这简直是一种痛苦。对于 ColorBox 来说，这一切都是不必要的。它可以轻松通过 jQuery 选择器进行控制，因此主题或插件开发者可以根据 WordPress 的 HTML 输出进行选择，从而使内容编辑者只需专注于他们的内容而不需要任何 HTML 理解。

### Cforms II

要创建注册表单，我们有许多 WordPress 插件可供选择，但我发现最好的是 **cforms II**。Cforms II 在一开始就声明：“诚然，cforms 不是最容易的表单邮件插件，但它可能是最灵活的。” 他们是对的。并且在使用一次后，你会发现它比你想象的要简单得多。

您可以从这里下载 WordPress 的 cformsII 插件：[`www.deliciousdays.com/cforms-plugin/`](http://www.deliciousdays.com/cforms-plugin/)。

### 安装 WordPress 插件

下载 cforms II 插件后，请按照开发者提供的说明进行安装和激活。

本质上，这意味着解压包，将 `cforms` 目录放置在您的 WordPress 安装的 `wp-content/plugins` 目录中，然后导航到管理员的 **管理插件** 页面。然后您将为插件选择 **激活**。

![安装 WordPress 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_01.jpg)

安装并激活插件后，让我们开始使用它。

### 使用 cforms II 设置注册表单

cforms II 插件为不那么技术性的 WordPress 管理员提供了许多强大的表单构建功能。作为一个更技术性的 WordPress 开发者，它可以帮你节省大量时间。cforms 管理界面确实需要一些时间来适应，但它是我在 WordPress 中使用过的最强大和灵活的表单插件。

CformsII 是一个复杂的插件，需要大量的管理空间和多个屏幕页面。因此，一旦你激活了该插件，你会发现在左侧管理区域有一个全新的面板可用。

![使用 cforms II 设置注册表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_02.jpg)

出厂设置中，cformsII 允许使用 AJAX，在不重新加载页面的情况下提交和更新表单。它还允许非常轻松地创建所有基本类型的表单元素：`input、select、check`和`radio`框以及`textarea`框。你可以用`legend`文本标签包装自定义的`fieldset`标签，方便对相关表单元素进行分组。

内置了强大的服务器端验证。很容易将字段指定为必填项并检查有效的电子邮件地址。除此之外，你还可以轻松地为自定义验证分配自己的自定义正则表达式。cforms **帮助！**面板甚至为你提供了可以使用的有用的正则表达式示例。

![使用 cforms II 设置注册表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_03.jpg)

### 小贴士

**安全地设置 cforms II**

你会想要查阅 cforms 文档，并且如果可能的话，与网站管理员或托管提供商的技术支持进行交谈。你需要仔细查看**全局设置**面板，并确保你的 cforms II 安装对你的表单需求尽可能安全。

如果可能的话，尽量使用验证码字段来减少垃圾邮件，并在不需要时关闭文件上传功能。

#### 平衡：表单应该简短易懂，同时检索到有用的信息。

表单的目标是在尽可能从用户那里获取尽可能多的信息的同时，不让他们感觉到你在要求过多的个人信息，或者至少不让他们因为填写过多字段而感到无聊。

我把这个注册表单保持得非常简短和简洁。首先，我填写了表单名称，并将其设置为**启用 Ajax**。这将对我们有所帮助，因为页面将在模态框中加载，所以当它刷新时，它不会弹出到一个新页面，在模态窗口之外。

![平衡：表单应该简短易懂，同时检索到有用的信息](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_04.jpg)

接下来，使用已提供的默认表单集，让我们设置一个带有`legend`文本和事件协调员需要了解的五个表单输入的`fieldset`。

首先是事件，即事件名称将通过邮政传递，而不是由用户填写，但我想显示它，并且需要将其放在表单元素中以便发送给管理员。

在事件字段之后，我们需要询问用户的姓名。由于没有交换金钱，而且这个表单更多是为了统计人数，所以我将其保留为单个字段。这是一个必填字段，但我允许用户随意或正式填写。

接下来，我们将要求输入电子邮件地址。这是必填项，我选择了使用右侧的复选框进行服务器端验证。如果用户表示他们可以为活动带来一些东西，活动协调员可能希望回复他们并与他们保持联系。此外，可能需要向注册者广播有关活动的更新，因此有效的电子邮件至关重要。

现在，让我们设置一个下拉框，询问注册者可以带多少位客人参加活动。

![取得平衡：表单应该简短易懂，同时提供有用信息](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_05.jpg)

最后，消息区域是一个文本区域，其中包含一些文本，建议注册者提供一些东西，并且如果他们可以的话，在消息区域中说明他们可以提供什么。

好了。所以这是我们的表单。为了查看它，现在需要将它放在 WordPress 页面或帖子中。我们将把它放在自己的页面中，这意味着我们应该在 WordPress 中创建该页面。

### 使用 WordPress 3.0 的自定义菜单选项创建注册页面

如果您查看管理面板左侧的页面列，您现在会发现 pageMash 插件是选项之一。

我们只需从 **页面** 下的左侧菜单中选择 **添加新**，并创建一个名为 **注册** 的页面。我们将内容区域留空，但是您现在会注意到，在 **编辑** 视图中，编辑面板中有一个 **cforms** 按钮用于页面/帖子。

![使用 WordPress 3.0 的自定义菜单选项创建注册页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_06.jpg)

单击该按钮将允许您选择要放置在页面上的表单（您可以在 cforms II 中创建多个表单，甚至在单个帖子或页面中放置多个表单，但这对我们来说太过了）。选择表单后，您应该会看到一个用于占位符的空间。

![使用 WordPress 3.0 的自定义菜单选项创建注册页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_07.jpg)

您现在应该在站点上的 **注册** 页面中看到您的表单，如下截图所示：

![使用 WordPress 3.0 的自定义菜单选项创建注册页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_08.jpg)

## 使用 WordPress 3.0 的自定义菜单选项

然而，我们不希望 **注册** 页面出现在我们的页面导航中，并且我们需要它在自己的模板页面中，以便更好地加载到我们的模态框中，而不带有主题的页眉和页脚图形和样式。我们需要修改我们的模板，但首先，让我们在 WordPress 3.0 中创建一个自定义菜单，该菜单将覆盖 **页面** 菜单，然后我们可以轻松指定应显示哪些页面，以便注册页面不会出现在我们站点的导航中。

首先，您需要在管理面板中导航至**外观 | 菜单**。一旦进入，您可以点击 +（加号）选项卡创建一个新菜单，然后从右侧选择要添加到菜单的选项。然后，您可以在右上面板中设置菜单为您的“主要导航”，这将覆盖 Twenty Ten 默认主题页眉中的标准页面导航。以下屏幕截图说明了设置新的主导航并将其分配为站点主导航的三个主要步骤：

![使用 WordPress 3.0 的自定义菜单选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_09.jpg)

您还可以将**事件**类别包括在菜单中，如下面的屏幕截图所示（稍后我们将需要访问此页面）：

![使用 WordPress 3.0 的自定义菜单选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_10.jpg)

好了！现在我们有一个“隐藏”的页面，保存着我们的注册表单。让我们开始进行主题自定义。

## 自定义主题

再次，我们需要以两种方式自定义主题：首先，我们需要一个自定义页面模板来容纳我们的注册表单，该表单将加载到模态框中；其次，我们需要创建一个自定义分类模板并修改它，以便仅显示分配给**事件**类别的帖子，并在其中启动包含注册表单的模态框。

### 创建自定义页面模板

首先，我们需要创建一个新的页面模板，以便将我们的注册页面分配给它。我们将从创建**page.php**模板的副本开始，并将其重命名为**registration-page.php**。

![创建自定义页面模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_11.jpg)

此表单的整个目的是加载 ColorBox 模态窗口，因此使用我们主题的页眉和页脚样式会有些分散注意力。我们将从此模板页面中简单地删除`get_header()`和`get_footer()` WordPress 模板标记命令。

接下来，虽然我们不需要页眉和页脚样式，但我们需要页面成为一个格式正确的 HTML 页面，可以加载 jQuery。我们将手动添加一个 doctype，并从`header.php`文件中借用一些 WordPress 页眉代码，从一个`body`标记到这个模板的循环的开头，如下所示：

```js
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  <?php language_attributes(); ?>>
<head profile="http://gmpg.org/xfn/11">
<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
<title><?php wp_title('&laquo;', true, 'right'); ?> <?php bloginfo('name'); ?></title>
<link rel="stylesheet" href="<?php bloginfo('stylesheet_url'); ?>" type="text/css" media="screen" />
<link rel="pingback" href="<?php bloginfo('pingback_url'); ?>" />
<?php wp_enqueue_script("jquery"); ?>
<?php wp_head(); ?>
<style type="text/css">
<!--
.cform fieldset{
border:1px solid #036;
}
.success{
font-size: 140%;
font-weight: bold;
}
-->
</style>
</head>
<body>
...

```

您会注意到，与`header.php`文件的`head`标签代码相比，我们简化了它很多。我们不需要担心此页面上的注释或侧边栏，因此这些 PHP WordPress 代码块已被删除。我们确实需要加载 jQuery，我还额外添加了一些手动样式，以美化我们的表单。

然后，我们将在此模板页面的循环正下方添加这个新的页脚标记；即在模板页面的循环的下方添加关闭的`body`和 HTML 标记：

```js
...
<?php wp_footer(); ?>
</body>
</html>

```

### 提示

**在自定义模板页面时不要忘记插件挂钩**

注意，我确保`wp_head()`和`wp_footer()`手动放置在我们的注册模板页面中。许多插件需要这些钩子在主题中才能正常工作。如果你正在创建自定义页面，请确保它们包含在页眉或页脚中，或者如果主题的`header.php`和`footer.php`文件不会被包含，则手动放置它们，就像这个模板页面一样。

最后，为了使这个新页面被识别为 WordPress 的特殊模板，我们必须在文档的最顶部添加一个**模板头部**，以 PHP 的注释形式添加，如下所示：

```js
<?php
/*
Template Name: Register Form
*/
?>
...

```

### 注意

与我们在第三章中的插件一样，*深入挖掘：理解 WordPress 和 jQuery*，请确保在`<?php`标记之前没有空格或硬回车。否则，你可能会收到已发送头文件的错误信息。

现在，如果我们回到管理面板中的**注册**页面，在右侧，我们将看到我们的新页面模板可以分配给该页面。

![创建自定义页面模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_12.jpg)

我们现在可以看到，如果我们使用浏览器的地址栏导航到我们**注册**页面的 URL，它会加载而没有任何其他 WordPress 样式，并且已经准备好加载到我们的 ColorBox 模态窗口中。

![创建自定义页面模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_13.jpg)

这是我们解决方案的第一半。现在让我们完成它。

### 创建自定义分类模板

现在我们需要为**活动**类别创建一个特殊的分类模板。同样，我们希望每个事件都有一个注册链接。该链接将事件的标题传递给注册表单。

![创建自定义分类模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_14.jpg)

要开始这个过程，如果你还记得第三章中的模板层次结构，*深入挖掘：理解 WordPress 和 jQuery*，`category.php`模板页面优先于`archive.php`模板页面。事实证明，我们正在使用的默认模板没有`category.php`页面。我们只需通过复制`archive.php`页面并将其命名为`category.php`来创建一个。

但等等；我们不只是想让这个页面显示*任何*类别。我们只想显示**活动**类别。你还会记得在第三章中，*深入挖掘：理解 WordPress 和 jQuery*，你可以通过特定的`category-ID.php`模板页面进一步取代`category.php`模板，例如**category-3.php**。

在我的本地 WordPress 设置中，事件类别的 ID 恰好是 3，所以我们将文件命名为这个。

![创建自定义分类模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_15.jpg)

### 注意

**查找你的分类 ID**

在您自己的 WordPress 安装中工作的人，类别 ID 号是在创建类别时分配的。首先，您需要确定您的**Events**类别的 ID 号是多少。您可以通过在管理面板中导航到**Posts | Categories**页面，然后在**Events**类别下选择**编辑**来执行此操作。然后您可以检查该类别**编辑**页面中的 URL。在 URL 的最后，您将看到该类别的 ID 号。

![创建自定义类别模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_16.jpg)

现在我们准备好自定义 **Events** 页面的`category-3.php`模板了。

首先，正如我们在上一章节中看到的，这个页面调用了`get_template_part( 'loop', 'category' )`函数，来自`loop.php`模板页面。我们实际上只想要一个自定义、非常简单的设置，仅限于**Events**类别。虽然我们确实可以更新`loop.php`中的`if...else`语句，添加一个额外的自定义循环（这略微超出了本书的范围，敬请期待 Packt 出版社即将推出的 **WordPress 3.0 主题设计** 书籍！），但对于这个自定义客户项目，我们只需注释掉对该循环的调用，并添加我们自己非常简单的循环，多亏了模板层次结构，这个循环只会在我们的**Events**类别页面上起作用。

```js
<?php
//start the loop:
while (have_posts()) : the_post(); ?>
<div <?php post_class() ?>>
<h2 id="post-<?php the_ID(); ?>" class="entry-title">
<a href="<?php the_permalink() ?>" rel="bookmark"
title="Permanent Link to
<?php the_title_attribute(); ?>">
<?php the_title(); //adds the title ?></a></h2>
<div class="entry">
<?php
//add the content
the_content() ?>
</div>
<?php //add the registration button ?>
<p><a class="register"
href="/wp-jqury/register/?evnt=<?php the_title(); ?>">
Register</a>
</p>
<div class="register-separate"></div>
</div>
<?php endwhile; ?>

```

### 注意

如果您还没有这样做，您可能想要停用我们在上一章节中构建的 **添加作者简介** 插件。这对这个项目不是必需的，虽然激活它不会有什么坏处（它将只是坐在那里，在活动的帖子中）。

注意在底部的循环中，我们制作了一个引用注册表单的`link`标签。我修改了一个名为`evnt`的 **变量字符串** 到该链接，并使用`get_title()`模板标签添加了事件的标题，如下所示：

```js
...
<p><a class="register"
href="/wp-jqury/register/?evnt=<?php the_title(); ?>">
Register</a>
</p>
<div class="register-separate"></div>
...

```

现在我们将回到模板页面的顶部，确保标题的设置是合理的。顶部有一堆`if...else`语句，检查返回的内容是否来自存档、类别或标签（请记住，这个页面是从默认模板的`archive.php`页面复制的）。由于这个模板页面现在只会加载事件帖子，所以我们实际上不需要所有那些 PHP，但也没什么坏处。主要是，我们将想要添加一个带有以下标记和代码的主标题：

```js
...
<h1 class="pagetitle"> Upcoming Events <?php single_cat_title(); ?></h1>
...

```

这将在页面上给我们一个名为**即将举行的活动**的标题（或者实际上您给自己的**Events**类别命名的任何名称，即，Shows、Parties 等等——您可以自己命名。那个 `single_cat_title()` 模板标签会为您提取它）。

在主题的`style.css`样式表的最底部，我们将添加以下规则来为我们的注册链接设置样式，并将其浮动到右侧：

```js
...
.register {
display:block;
background-color: #ccc;
border: 1px solid #069;
width: 100px;
padding: 10px;
text-align: center;
}
p a.register{
float: right;
}
.register-separate{
clear:both;
padding-top: 10px;
border-bottom:1px solid #999;
}

```

现在当我们查看一个事件帖子时，我们会看到我们的事件帖子底部有一个动态链接到**注册**的链接：

![创建自定义类别模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_17.jpg)

## 将 jQuery 纳入规划

好了！我不知道你怎么想，但我觉得这是相当多的准备工作。当我们加载 ColorBox 插件并编写最后几个自定义 jQuery 脚本时，一切都会结合在一起。

### 包括 ColorBox 插件

在我们的主题中，让我们创建一个 `js` 目录，在该目录中，让我们创建一个名为 **colorbox** 的附加目录。这将允许我们放置 ColorBox 插件的 CSS 表和图像资产，并保持一切整洁和按照它喜欢在 **colorbox.css** 表中工作的方式进行。

![包括 ColorBox 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_18.jpg)

我们将解压缩我们的 ColorBox 插件，并将缩小版移到我们的 `js/colorbox` 目录中。然后，我们将从 `example1` 文件夹中获取样式表和资产（我最喜欢它，有条纹的，透明的背景和圆角非常棒），并将它们放入 **colorbox** 目录中。然后，我们将转到我们主题的 `header.php` 文件，并像下面所示，在主题的主样式表下方包括 **colorbox.css** 样式表：

```js
...
<link rel="stylesheet" type="text/css" media="all"
href="<?php bloginfo( 'stylesheet_url' ); ?>" />
<link rel="stylesheet" href="<?php bloginfo('stylesheet_directory'); ?>/js/colorbox/colorbox.css" type="text/css" media="screen" />
...

```

然后，在 `wp_head` 函数的上方，我们将按照前几章学到的方法添加我们的主要 jQuery 包括以及 ColorBox 插件，利用脚本 API 如下所示：

```js
...
wp_enqueue_script( 'jquery' );
wp_enqueue_script('colorbox', get_bloginfo('stylesheet_directory') . '/js/colorbox/jquery.colorbox-min.js', array('jquery'), '20100516' );
...

```

### 编写自定义 jQuery 脚本

现在，在我们的 `js` 目录的根目录中，让我们创建一个新的 `custom-jquery.js` 文件，并确保在我们的 `header.php` 文件中包含它，在我们的 ColorBox 包含项 *下方*，如下所示：

```js
...
wp_enqueue_script('custom-jquery', get_bloginfo('stylesheet_directory') . '/js/custom-jquery.js', array('jquery'), '20100510' );
...

```

现在准备一些 jQuery 的乐趣。由于我们辛苦地手动将 ColorBox 插件包含到我们的 WordPress 主题中，我们也可以确保它能够加载图像，以及我们的注册表单。

为了确保 ColorBox 只加载图片，而不是页面上的每个链接，我们会想到一些在第二章中的示例，*在 WordPress 中使用 jQuery*，并进行一些创造性的选择。我们将把这个规则添加到我们的 `custom-jquery.js` 文件中：

```js
jQuery(function(){
jQuery(".entry-content a:has(img)").colorbox({height:"98%"});
});//end docReady

```

此选择仅适用于帖子中位于 `.entry` 类中的标签链接，其中 *有* 缩略图 `img` 标签。没有其他链接会触发 ColorBox。

![编写自定义 jQuery 脚本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_19.jpg)

现在，为了让注册页面启动 ColorBox，我们要聪明一点。虽然我已经添加了一个 `.registration` 类，但我不想依赖它来启动 ColorBox。唯一应该触发模态窗口的链接是指向注册表单的链接，所以我一定要为此选择。在我的 `cb-registration.js` 文件中，在我的文档就绪函数内以及在我的图片选择 `colorbox` 函数之后，我将添加此脚本：

```js
...
jQuery("a[href*='register']")
.colorbox({iframe:true, width:"500px", height: "600px"});
...

```

那个特定的 jQuery 选择器将确保只有包含（这就是星号 `*` 的作用）`href` 属性中包含 `register` 一词的链接才会触发 ColorBox 模态窗口，在 ColorBox 的 iframe 模式下。

你会注意到我还使用了 ColorBox 提供的参数来为注册表单的模态框设置约束的高度和宽度。

现在，只有我们的注册链接和带缩略图的图片链接启动 ColorBox：

![编写自定义 jQuery 脚本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_20.jpg)

## 总结：需要一个微小的 cforms II hack

你还记得我们设置了我们的注册链接通过**GET 调用**（有时称为**变量字符串**）将事件的名称以 URL 方式传递到注册表单。

目前，cforms 管理面板无法捕获该变量，但对于 cforms 来说，有一个快速且相当常用的"hack"可以确保您可以向表单传递自定义变量。

cforms II 为它可以捕捉的变量创建了有小括号括起来的模板名称，比如添加变量模板：`{Title}`将显示表单所在的帖子或页面标题。我们希望传递一个来自另一页的文章标题（而不是手动将此表单添加到每个事件帖子），因此我们将向 cformsII 插件添加我们自己的变量模板。

### 提示

**定制插件？记笔记！**

WordPress 和 jQuery 开发者通常会不断更新和改进他们的插件。你最好的选择是尽量寻找一个不需要你编辑实际插件源文件的解决方案。然而，就像在这种情况下一样，如果你发现你确实编辑了插件的源文件，那就在目录中添加你自己的`customization-readMe.txt`文件，并详细记录你在插件中修改或编辑的内容。当开发者发布并升级他们的插件时，尤其是有时需要更新以跟上当前 WordPress 核心版本的 WordPress 插件，当你更新插件时，你会丢失你的修改和黑客。你的笔记将使重新整合它们变得容易。

在 cforms II 插件目录中，定位`lib_aux.php`文件。在大约第 421 行，就在看起来像`...$m = str_replace( '{BLOGNAME}',..`的代码之后，添加这行代码：

```js
...
$m = str_replace( '{Event}', esc_attr($_GET['evnt']), $m );
...

```

然后，在我的注册表单的 cforms 管理面板中，我们现在可以向`lib_aux.php`页面中的**{Event}**变量添加到`Event`字段。让我们还确保该字段设置为"只读"。

![总结：需要一个微小的 cforms II hack](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_21.jpg)

为了清晰起见，我希望事件名称也显示在表单的标题中。标题不是 cforms 的一部分，而是页面模板的一部分。在我的主题目录中，我将打开`registration-page.php`，在第 41 行的标题`the_title()`模板标签旁边，我将添加以下代码：

```js
...
<h2><?php the_title(); ?> for: <?php $evnt = esc_attr($_GET['evnt']); echo $evnt;?></h2>
...

```

当表单启动时，你现在会在标题和事件字段中看到事件的名称，该字段设置为只读，不可由用户编辑。现在表单提交并发送给管理员时，清楚地显示了注册是为哪个事件。

![总结：需要一个微小的 cforms II hack](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_22.jpg)

现在我们有了一个事件页面，显示用户即将到来的事件，并让他们无缝注册参加这些活动，这将在一个模态窗口中加载。干得好！让我们看看如何使这种体验变得更好。

# 第二部分：表单验证——确保提交的内容是正确的

令人振奋的消息是，cformsII 已经内置并准备好了漂亮、令人赞叹的 CSS 样式的服务器端验证。您可以看到，如果我在未填写必填详细信息或格式不正确的电子邮件地址的情况下点击**提交**，表单将重新加载，显示我填写错误的字段。

![第二部分：表单验证——确保提交的内容是正确的](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_23.jpg)

但为什么要等到用户点击**提交**按钮呢？虽然**服务器端验证**是必不可少的，也是唯一正确验证数据的方法，但通过添加一些**客户端**验证，使用 jQuery，我们可以很容易地提升并加快用户的流程，通过在用户填写表单时提醒他们丢失细节或数据格式不正确。

### 注意

**为什么服务器端验证很重要？**

使用 JavaScript 和 jQuery 进行客户端验证绝不能全部依赖于数据验证或防止提交不正确格式的信息到服务器。用户始终可以在浏览器中禁用 JavaScript，然后提交他们想要的任何值（有时使用不正确格式的值通过表单入侵您的服务器）。出于这个原因，客户端验证应该仅用于*增强*用户体验，而不是实际保护服务器或数据完整性。

## 客户端验证的技巧：不要只告诉他们错误时发生了什么！

每个人都对积极的反馈做出回应。与其等待用户弄错或忘记一个字段，借助 jQuery 和一些样式，您可以通知他们已经正确填写了字段，并可以继续进行。

使用 Inkscape，我做了一组简单的“√”和“×”图标，可以作为由 jQuery 添加的 span 的背景图应用。使用 CSS 精灵图像技术来调整背景位置显示“√”或“×”图标，用户将迅速看到表单字段是否被正确填写，并且可以继续。

![客户端验证的技巧：不要只告诉他们错误时发生了什么！](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_24.jpg)

### 空输入验证

为了设置基本验证，我们将编写一个 jQuery 脚本，该脚本选择输入项目，并在`blur`时启动一个功能。让我们把这个脚本放在`registration-page.php`中，就在循环代码下面，`wp-footer()`挂钩上面，如下所示（注意代码中粗体的注释，以便跟踪每个 jQuery 语句的操作）：

```js
...
jQuery(".cform :input").blur(function(){
/*this "if" makes sure we don't target the submit button or email field*/
if (jQuery(this).val() != "Submit") {
/*this "if" targets only empty fields*/
if (jQuery(this).val().length == 0) {
jQuery(this).after('<span class="wrong"> ! </span>');
}else{
/*"else" otherwise field is fine*/
jQuery(this).after('<span class="correct"> thanks. </span>');
}//end if no length
}//end ifelse !submit
});//end blur function
...

```

以前的代码对于无效的、空的字段会附加一个感叹号 (`!`)，对于有效的、填写完整的字段则附加一个快速的 `thanks`。然而，当用户焦点和模糊输入字段时，`span` 会不断地附加上 `after` 函数。为了补偿这一点，我们将在我们的 `blur` 脚本下方添加一个工作于 `focus` 上的自定义脚本。它将删除附加的 `after` spans，如下所示：

```js
...
jQuery(".cform :input").focus(function(){
jQuery(this).next("span").remove();
});//end focus function
...

```

这给了我们一些非常好的基本验证，检查空输入。您会注意到我们的 `span` 标签已经添加了类。我已经将 "check" 和 "x" 图像添加到我的主题的图像目录中，现在，在我的主题的 `style.css` 样式表的最底部，我将添加以下类规则：

```js
...
/*for registration form*/
.wrong{
display:block;
float:right;
margin-right: 120px;
height: 20px;
width: 20px;
background: url(images/form-icons.png) no-repeat 0 -20px;
text-indent: -3000px;
}
.correct{
display:block;
float:right;
margin-right: 120px;
height: 20px;
width: 20px;
background: url(images/form-icons.png) no-repeat 0 0;
text-indent: -3000px;
}

```

最终结果是在你鼠标或者通过字段切换时，留下两个必填字段为空，然后再点击 **Submit** 按钮时发生的一个非常好的、明显的视觉显示。

![空输入验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_25.jpg)

### 正确格式的电子邮件验证

让我们再向前迈进一小步。留下电子邮件地址为空是一回事，但我们也可以指出它是否格式良好。史蒂夫·雷诺兹在他的网站上有一篇关于使用 jQuery 验证电子邮件地址的绝佳文章。你可以在这里阅读：[`www.reynoldsftw.com/2009/03/live-email-validation-with-jquery/`](http://www.reynoldsftw.com/2009/03/live-email-validation-with-jquery/)。

史蒂夫的代码演示特别有趣，值得一看，因为他使用 jQuery 的 `keyup` 函数实时检查电子邮件表达式的验证。

对于我们的目的，我们将借用史蒂夫的正则表达式函数，并将其适应到我们已经开始的验证检查中，这个检查是在 `blur` 函数上工作的。

首先，在我们现有的脚本下面，我们将添加史蒂夫的 `isValidEmailAddress` 函数，如下所示：

```js
...
function isValidEmailAddress(emailAddress) {
form validatione-mail address, validatingvar pattern = new RegExp(/^(("[\w-\s]+")|([\w-]+(?:\.[\w-]+)*)|("[\w-\s]+")([\w-]+(?:\.[\w-]+)*))(@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$)|(@\[?((25[0-5]\.|2[0-4][0-9]\.|1[0-9]{2}\.|[0-9]{1,2}\.))((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\.){2}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9]{1,2})\]?$)/i);
return pattern.test(emailAddress);
}//is valid e-mail
...

```

接下来，我们将仔细检查我们现有的脚本。我们想要做的是，在检查到没有值（`val().length == 0`）之后，我们会再次检查输入字段是否不是电子邮件字段。

使用 Firefox 和 Firebug，我探索了 DOM 并发现电子邮件字段表单具有一个名为 `.fldemail` 的唯一类。

我们将把我们的新语句作为我们当前的 if 语句的扩展，并在我们一般的 else 语句之前使用一个 `else if` 语句。

我们更新的 `blur` 脚本现在如下所示（注意加粗的新的电子邮件验证，`if...else` 语句）：

```js
...
jQuery(".cform :input").blur(function(){
/*this if makes sure we don't target the submit button or email field*/
if (jQuery(this).val() != "Submit") {
/*this "if" targets empty fields*/
if (jQuery(this).val().length == 0) {
jQuery(this).after('<span class="wrong"> ! </span>');
/*This "else if" targets if the field is the email field*/
}else if(jQuery(this).hasClass("fldemail") == true){
var email = jQuery(this).val();
/*Run's Steve's function and return true or false*/
if(isValidEmailAddress(email)){
//This shows the user the form is valid
jQuery(this).after(
'<span class="correct"> thanks. </span>');
}else{
//This shows the user the form is invalid
jQuery(this).after('<span class="wrong"> ! </span>');
}//if...else
//end email check
}else{
/*otherwise field is fine*/
jQuery(this).after('<span class="correct"> thanks. </span>');
}//end if no length
}//end if...else !submit
});//end blur function
...

```

现在我们不仅可以检查空字段，还可以在字段输入的 `blur` 时检查有效的电子邮件地址：

![正确格式的电子邮件验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_26.jpg)

### 提示

**验证提示：不要过度使用！**

cforms II 插件的服务器端验证已经足够了。再次强调，我们只是想通过一点客户端验证来加快速度，并且不想因为为数据创建了一堆严格的格式化规则而让用户感到沮丧。有些人的电话号码或邮政编码的格式可能与您预期的有所不同，但就大多数情况而言，这是可以接受的。您最好使用 jQuery 验证来提示提示和内联帮助，并指导用户，而不是强迫他们遵守精确的数据格式。

# 最后的想法和项目总结：一切都关乎优雅的降级

与您使用 jQuery 所做的一切一样，您需要记住，您正在创建的是非常有用的增强功能，这些功能很棒，但如果某个用户由于某种原因没有启用或可用 JavaScript，流程或站点不会中断。

我们的客户对我们无缝的注册解决方案非常满意。禁用 JavaScript 进行注册过程时，注册过程使用标准浏览器返回键完全可以正常工作。我唯一发现的缺点是，注册表单会*在* WordPress 主题之外加载，这是我们必须做的，以便它可以很好地加载到 ColorBox 模态窗口中。

总的来说，我不认为这是一个很大的问题。浏览了我的各种网站统计数据后，我很难找到一个没有启用 JavaScript 的访客。那两三个没有启用 JavaScript 的可能是在纯文本浏览器中，所以缺少 WordPress 主题可能根本不会被注意到（事实上，对于使用文本转语音浏览器的残障用户来说，不必费力浏览头部信息以到达表单可能是一件好事）。

因为在这个标题中我们总是考虑假设情况，如果恰好，客户决定在事件 JavaScript 被禁用的情况下，希望表单在 WordPress 模板之外正常工作，我想出了以下解决方案：

首先，您需要将表单加载到*两个* WordPress 页面中。一个命名为`register`，就像我们在特殊模板中所做的一样，另一个命名为`register-b`（这只是永久链接的缩略名，标题仍然可以在两个页面上都是**Register**）。对于`register-b`页面，您不会分配特殊模板；您会将**页面模板**保留为**默认模板**。您可以在尽可能多的页面和文章中放置一个 cform，因此在两个位置放置此表单绝对不会成为问题。

接下来，您将进入`category-3.php`事件模板页面，并更改链接以调用替代的默认主题页面，如下所示（请注意，粗体的`-b`是与我们原始链接唯一的不同之处）：

```js
...
<p><a class="register" href="/wp-jqury/register-b/?evnt=<?php the_title(); ?>">Register</a></p>
...

```

最后，在你的 `custom-jquery.js` 文件中，你只需创建一个 jQuery 脚本，将 `href` 链接重写为删除 `-b` 的模态页面表单。确保将此脚本 *放在* 您的 colorBox 功能脚本之前，只是为了确保在设置 colorBox 功能之前 `href` 转换。

```js
...
jQuery("a[href*='register']").each(function(){
this.src = this.src.replace(/register\-b/, "/register/");
});
...

```

如果启用了 JavaScript，jQuery 将更改所有注册的 `href` 实例，并且整个流程将按计划使用 ColorBox 插件进行。如果没有，用户将使用标准的 WordPress 主题表单注册，而不会受到任何影响。

正如您在以下截图中所见，如果 JavaScript 被禁用，表单将只作为站点的一部分加载：

![最终思考和项目总结：一切都关乎优雅的退化](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_04_27.jpg)

# 摘要

我们现在学会了如何：

+   真正利用主题来帮助 jQuery 增强。

+   使用 jQuery ColorBox 插件和一些自定义脚本增强非常强大的 cforms II WordPress 插件。

而这只是许多实现这个特定解决方案的方法之一！由于本书的目标是在 WordPress 中使用 jQuery，我选择了更注重 jQuery 和易于访问的 WordPress 功能的路线。但当然，我们可以将 ColorBox 插件制作成插件；我们可以将整个东西制作成插件！或者制作一个仅扩展 cforms 插件的插件。解决方案策略的列表几乎是无穷无尽的。

再次，您需要查看每个项目并据此评估。在下一章中，准备好通过一些流畅的基于 HTML 和 CSS 的图表动画以及图库幻灯片和旋转器，以及一些其他巧妙的方法来吸引用户的注意力。


# 第五章：在 WordPress 中的 jQuery 动画

我们将继续在 jQuery 和 WordPress 的知识基础上深入探讨使用 jQuery 进行动画处理。动画是 jQuery 的强项之一，虽然您可能认为动画是轻浮的或者是廉价的技巧，只是为了“眼睛糖果”，但如果正确实现，它确实非常有用。

通过对 CSS 属性、颜色和界面元素进行 jQuery 动画处理，可以确保用户清楚地看到警报、错误和确认消息。动画还使界面对象能够淡入和淡出以获得更好的用户体验。最重要的是，一点点“眼睛糖果”肯定不会影响网站对用户的兴趣和受欢迎程度。

在本章中，我们将使用动画来实现：

+   吸引用户的注意力并将其引导到警报

+   节省空间并通过一系列旋转的置顶帖子进行动画处理

+   创建一些流畅的、动画的鼠标悬停效果和简单的动画图表

让我们开始将实用的、高端的动画应用到我们的 WordPress 站点上。

# jQuery 动画基础

首先，我们已经有一点 jQuery 动画的经验。让我们回顾一下：在第二章，*在 WordPress 中使用 jQuery*，在*事件和效果*部分，我们了解了以下函数：`show(), hide(), fadeIn(), fadeOut(), fadeTo(), slideUp(), slideDown()`和`slideToggle()`。我还提到了`animate()`和`stop()`函数。

我们在之前的项目中已经使用过几种这些函数，分别是第二章，*在 WordPress 中使用 jQuery*；第三章，*深入挖掘：理解 jQuery 和 WordPress*；和第四章，*以更少的工作做更多事情：利用 jQuery 和 WordPress 的插件*，特别是，`show()`和`hide()`，以及`fadeTo()`和`slideToggle()`。正如我们所看到的，这些快捷函数可以轻松满足您的大部分动画需求，但同时也受到它们的限制。现在让我们更仔细地看一下`animate()`函数，并掌握一些对我们的 jQuery 动画具有精细控制的方法。

## CSS 属性的魔法

`.animate()`函数允许您对任何*数字*CSS 属性进行动画处理。`px`是大多数数字属性值的理解规范，但您可以指定`em`和`%`（百分比）单位。几乎您可以放置在便捷的`.css()`函数中的任何东西，都可以在`.animate()`函数中使用。

此外，您可以将快捷字符串`"show", "hide"`和`"toggle"`添加到任何属性中，而不是数值。它们基本上会将值从 0 变为 100，或者反之，或者从 0 或 100 切换到相反的数字。

让我们快速看一下这个聪明函数的一个简单示例。记住，你会想把你编写的任何 jQuery 脚本放在`document ready` 函数内：`jQuery(function(){//code here})`；同样也要放在`<script>` 标签内，这样你的 jQuery 将在 DOM 加载完成时启动：

```js
...
jQuery('.post p').animate({ fontSize: '140%',
border: '1px solid #ff6600',}, 3000);
...

```

此代码片段将为页面上的所有`.post p`段落标签添加动画效果，增大字体大小并添加边框。

你会注意到我添加了一个没有单一数值的`border` 属性。当你在你的网站上测试这段代码时，你还会注意到，边框不会动画显示出来；相反，在动画完成时，它只会在最后一刻出现。添加不是基本数字值的 CSS 属性（如边框或背景颜色、十六进制值）将不会进行动画处理，但是你可以使用`.animate()` 函数添加所有 CSS 属性，一旦完成运行，它将像`.css()` 函数一样运行。这可能不是添加常规 CSS 属性的最佳方法，但如果你无论如何都要进行动画处理，只要知道你可以添加其他非数值 CSS 属性，它们只是不会动画显示。

### 小贴士

**你的属性不起作用吗？**

你可能早在第二章 *在 WordPress 中使用 jQuery* 就注意到了这一点，使用`.css()` 函数时，但以防万一你没有注意到：属性名称必须采用**驼峰命名法**才能被`.animate()` 和`.css()` 函数使用。这可能有点令人困惑，因为你可能只把它们当作在实际 CSS 样式表中使用的属性，但是你需要指定`paddingBottom` 而不是`padding-bottom`，`marginRight` 而不是`margin-right`。

### 使它多姿多彩

你可能同意，尽管`.animate()` 函数很酷，但如果没有颜色（并且颜色突然在动画结束时发生变化，这样会有点刺眼），它并不那么令人印象深刻。你渴望在灿烂的颜色中交叉淡入。谁不希望呢？不幸的是，核心的 animate 函数并不够强大，无法计算单个十六进制网络颜色中的所有变化，更不用说两个十六进制颜色之间的变化了（让我们只说，这涉及到一些严重的数学问题）。这比从 0 到 100 移动一个值，或者再次移动回来要复杂得多。

好消息是，`animate` 函数可以通过 Color 插件进行*扩展*。更好的消息？是的，这个插件已经捆绑在 WordPress 中了！

让我们像这样使用`wp_enqueue_script` 将这个插件添加到我们的主题中：

```js
...
<?php wp_enqueue_script("jquery-color"); ?>
<?php wp_head(); ?>
...

```

### 小贴士

**注册并包含一个只需要在特定页面加载的脚本？**

在第二章中，*在 WordPress 中使用 jQuery*，你会记得，你可以将你的`wp_enqueue_script()`函数包裹在`if`语句中，这些语句使用 WordPress 的条件标签来检查站点所在的页面：`is_home()`，或`is_front_page()`，或`is_admin()`等等。一定要善用这些条件标签，帮助你的站点尽可能地保持优化，并且不要通过加载不需要的脚本来不必要地减慢网站速度。要了解更多关于条件标签的信息，请查看它们在第二章中与脚本 API 一起使用的情况，以及在第九章中的条件标签快速参考，*jQuery 和 WordPress 参考指南*。你也可以查看 WordPress 的 Codex 网址：[`codex.wordpress.org/Conditional_Tags`](http://codex.wordpress.org/Conditional_Tags)。

再次强调，这个插件*扩展*了现有的`.animate()`函数，所以没有新的属性需要学习！一旦你将 Color 插件包含到你的项目中，你就可以随心所欲地动画化背景颜色了。

```js
...
jQuery('.post p').animate({'backgroundColor':'#99ccff'}, 2000);
...

```

现在你应该看到`.post`段落优雅地淡化成一个漂亮的浅蓝色，就像下一个截图中所示的那样：

![让它丰富多彩](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_01.jpg)

## 放松一下，用缓动控制

如果你熟悉使用各种视频编辑工具或 Adobe Flash 进行动画制作，你可能听说过缓动。**缓动**是动画中加速和减速的控制。它最常见的用途是给动画一个更自然的感觉，模仿现实世界中发现的各种物理属性，而不是计算和刚性的运动。

几乎与动画化十六进制颜色值一样复杂，缓动将虚拟物理属性应用于被动画化的对象，使用各种算法来控制动画的速度，使其在开始和结束时加速。这确实是严肃的数学。jQuery 带有一种内置的缓动类型，所以我们不必真正考虑其中的任何问题。

jQuery 的默认缓动选项称为“swing”。从技术上讲，有两个选项——“linear”和“swing”。**线性缓动**简单地沿着从点 A 到点 B 的值动画对象，就像一个良好的编程脚本应该做的那样。没有加速或减速，所以是的，它有点“僵硬”。

**Swing 缓动**开始时速度较慢，达到最大速度，然后随着动画完成而再次减慢。jQuery 选择 swing 作为默认的缓动选项，因为它在大多数情况下看起来最好。这可能是因为这就是我们现实世界中大多数物体的反应方式；在达到最大速度时稍微缓慢启动，然后在靠近停止时减速和减慢（前提是物体在最大速度时没有撞到任何东西）。

由于摆动缓动是*默认*的，让我们看看我们之前用来使文章段落背景色动画的脚本，并看看我们能否检测到差异：

```js
...
jQuery('.post p').animate({'backgroundColor':'#99ccff'
}, 2000, 'linear');
...

```

这是微妙的，但明显的差异在那里。线性缓动更加严格。

### 小贴士

**高级缓动：有一个插件可以做到！**

正如你可能猜到的，许多“数学派”的人已经找出了各种各样的缓动算法变体，以模仿各种不同的物理环境，是的，有一个 jQuery 插件可以做到这一点。虽然这个插件没有与 WordPress 捆绑在一起，但这不应该阻止你下载并尝试它。你可以在这里下载并测试所有可用的缓动选项：[`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/)。

这个插件，就像 Color 插件一样，*扩展了* `.animate()` 函数，并为你提供了超过 25 个缓动选项，其中包括一些非常酷的选项，比如 jswing bounce 和 elastic，以及一系列向量缓动路径，如圆形和正弦波。

大多数项目中这些选项都有点过度了，但我确实喜欢弹性和弹跳的缓动选项。顺便说一下，如果你是我刚才提到的那些“数学派”的人之一，你会喜欢查看这里缓动算法背后的魔力：[`www.robertpenner.com/easing/`](http://www.robertpenner.com/easing/)。

## 时间把控至关重要：顺序、延迟和控制动画队列

如果你对动画很熟悉，无论是传统动画、视频，还是与 Flash 进行多媒体工作，你可能已经了解——*时间把控至关重要*。你对动画的时间和播放控制得越多，越好。例如，缓动效果取决于给对象动画和移动多少时间。无论你想让一个对象移动得有多“平滑”，如果你只给它一秒钟或更少的时间来穿过屏幕，它看起来都会相当颠簸。让我们看看掌握时间和播放的三种主要方法。

### 让你的事情井然有序：把它们链接起来

我们在之前的章节中讨论了函数链，你很可能知道你在 jQuery 语句中链接在一起的任何事件会按照它们被*附加*到链中的顺序启动。据我所知，并根据专家的说法，你可以链接任意多的函数，无限地（或直到浏览器崩溃）。

总的来说，我发现将 jQuery 函数分布在单独的行中，具有它们自己的选择器集，可能会占用一些空间，但会使您的 jQuery 脚本更有组织和可管理性。请记住，您始终从包装器集的初始选择器开始执行 jQuery 语句，但基于额外的链式函数，可以使您在 DOM 中移动并获取其自己的选择器，您会发现您可以仅通过一个语句在 DOM 中移动和影响很多。沿途，可能会生成一些相当壮观的“意大利面代码”，很难跟踪，并且会让任何不得不与您合作的开发人员憎恨您的内心。

但是，对于需要在单个初始选择器集上运行的函数，特别是动画函数，我真的很喜欢 jQuery 链，因为它们有助于保持我的动画序列按照我想要的顺序开始，而且很明确哪个包装器集将受到链的影响。

以下是一个示例：

```js
...
jQuery('.post:first').hide().slideDown(5000, 'linear').fadeTo('slow', .5);
...

```

现在，即使最初简明的动画链也可能变得有点复杂。没关系；与一些脚本语言不同，JavaScript 和 jQuery 依赖于分号 ";" 作为清晰的结束语句，而不是实际行的结尾。因此，您可以将链组织成单独的行，以便更容易跟踪和编辑，如下所示：

```js
...
jQuery('.post:first')
.hide()
.slideDown(5000, 'linear')
.fadeTo('slow', .5);
...

```

### 延迟订单！

因为时间至关重要，我经常发现我希望函数的动画完成，然而，根据缓动选项，特别是*弹性*或*反弹*，我并不一定希望下一个函数就这么快开始！从 jQuery 1.4 开始，使用`.delay()`函数可以轻松**暂停**链。让我们在我们的链中放置一个三秒的暂停，如下所示：

```js
...
jQuery('.post:first')
.hide()
.slideDown(5000, 'linear')
.delay(3000)
.fadeTo('slow', .5);
...

```

### 提示

**检查您的 jQuery 版本！** `delay()` **需要 1.4+**

一旦此功能可用，我就在我的 jQuery 动画中以各种无价的方式使用它。但是，如果您发现延迟函数不起作用，那么您可能正在使用版本 1.3.2 或更早的 jQuery。延迟函数仅在版本 1.4+中可用。您可能想回到第二章，*在 WordPress 中使用 jQuery*并查看关于从 Google CDN 注册 jQuery 或直接将其包含在主题中的内容。

### 插队

队列——这些令人烦恼的队列确保每个人或每件事都按照它们到达的顺序公平处理。jQuery 的动画队列工作方式类似，只处理每个对象的动画请求，按分配给对象的顺序进行处理。有时会出现不应该被迫在队列中浪费时间的特殊需求和要求。

到目前为止，我们已经看到`.animate()`函数，除了 CSS 属性之外，还可以传递各种可选参数，指定 *持续时间*（slow、fast 或数字毫秒）和 *缓动* 类型（swing、linear 或插件扩展缓动）。

`que`参数是一个**真或假**布尔值，如果你不想让动画函数等待其轮到，则可以设置它。对于你希望一个对象同时运行多个动画以与彼此并行的实例，比如同时滑动*和*淡化，禁用`queue`在你的动画函数中将起作用。

为了在你的代码中设置`queue`选项，而不是使用我们之前一直在使用的语法，你将不得不*将*所有其他选项包装到更高级的语法中，清楚地标记每个可选参数，像这样：

```js
...
jQuery animationqueue, jumpingjQuery('.post:first')
.hide()
.fadeTo(0, .1)
.css("height","5px")
.animate({
height: '+=500px',
},
{
duration: 4000,
easing: 'swing',
queue: false
}
)
.fadeTo(4000, 1);
...

```

以下屏幕截图显示了帖子在淡出*同时*同时改变高度：

![跳过队列](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_02.jpg)

通过前面的屏幕截图可以看出，我们刚刚编写的代码在下滑时淡化了第一个`.post` div。如果你将`false`改为`true`，然后重新加载页面，你会发现第一个`.post` div 滑动到`500`像素高度后*然后*淡入。

### 完成跳转

可以传递到`.animate()`函数的最终选项是`step`和`complete`。`step`参数允许你设置一个额外的函数，在每个动画步骤完成后调用它（有时对于你正在动画化的多个 CSS 属性很有用）。`complete`参数允许你指定一个回调函数，当整个动画函数完成时调用。请记住，你可以链接多个动画函数，而具有完成参数的步骤是属于它们所属的每个动画函数的唯一实例。

如果你有一个动画绝对不应该在当前动画函数完成之前启动的情况，`.delay()`函数可能不是最好的方法。你可以使用`step`和`complete`参数按照你希望的确切顺序启动其他函数和动画。

```js
...
jQuery('.post:first')
.hide()
.fadeTo(0, .1)
.css("height","5px")
.animate({
height: '+=500px',
},
{
duration: 4000,
easing: 'swing',
queue: false,
step: function() {alert('step done!');},
complete: function() {alert('completely done!');}
}
)
.fadeTo(4000, 1);
...

```

前面的代码片段将在`.animate()`函数完全完成后在完成的步骤中生成 JavaScript 警报。

![完成跳转](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_03.jpg)

我个人从未需要钩入 WordPress 项目的`step`参数，但我可以看出它如何在钩入和创建一系列级联类型效果方面非常有用。我发现完整的`parameter`对我的许多动画非常有用。

# 吸引用户的注意力

好了，除了示例代码片段，现在是时候开始工作了！回到“假设的世界”，我们的前一些客户热情地向几位同事推荐了我们的 jQuery 解决方案，现在我们收到了很多有关 WordPress 网站的帮助请求。让我们看看一些新的假设客户情况，看看我们是否能解决他们的问题。

首先：许多网站采用的一种常见方法是“置顶”帖子以及如何利用一点 jQuery 动画来增强它们。

## 项目：动画提示置顶帖子

这是一个快速简单的情况。你有一个客户，他有一个好朋友，经营着一个非营利性教育组织的网站，他们需要一个帮助（意思是：请"免费"做这个，请）。

组织的课后照顾根据公立学校的时间表运行（因为许多孩子是从不同的学校乘坐校车过来的）。如果公立学校系统放假或发生其他紧急情况，课后项目也会关闭。组织尽力通过他们的 WordPress 站点通知人们。

尽管向家长明确表示他们有责任查看网站或致电了解中心的时间表，但是有一些人声称他们查看了网站但 *"没有看到关闭警报"*。显然，即使他们将帖子设置为 "sticky"，使其保持在顶部，但这些帖子看起来与网站的其他内容非常相似。

你很乐意帮忙（特别是因为他们是由一个有高薪工作的客户推荐给你的）。这是一个真正容易解决的问题。首先，你可以简单地在他们主题的 `style.css` 文件中添加几个 `.sticky` 样式，这样在网站上粘性帖子就会更加突出。

他们明确表示，他们只使用 "sticky" 功能来发布日托和其他影响组织中心建筑对公众开放的警示，因此你决定快速搜索 "creative `commons, public domain, alert icon svg`"，并从 [`commons.wikimedia.org/wiki/File:Nuvola_apps_important.svg`](http://commons.wikimedia.org/wiki/File:Nuvola_apps_important.svg) 下载了一个非常漂亮的 SVG 文件。

让我们将 SVG 文件打开到 Inkscape 中，并将其缩小到 48 像素宽以保存一个透明的 `.png` 文件（我冒昧地给阴影加了一点模糊，但你可能不想要）。将 PNG 命名为 `sticky-alert.png`。

![项目：为警示粘性帖子添加动画效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_04.jpg)

然后，你将新的 `sticky-alert.png` 图像添加到他们主题的图像目录，并在样式表的最底部*或下面*已存在的 `.sticky` 类之后，如果存在的话，用一些 `.sticky` 调用的类规则更新它，如下所示：

```js
...
/*change the .sticky background */
.home .sticky { background-color: #ffff9c;}
/*add the icon to the entry-content div inside the sticky post*/
.home .sticky .entry-content{
background: url(images/sticky-alert.png) no-repeat 0 20px; }
/*nudge the paragraph and lists out of the way of the icon*/
.home .sticky .entry-content p,
.sticky .entry-content ul{margin-left: 60px;}
...

```

以下截图展示了新样式的粘性帖子：

![项目：为警示粘性帖子添加动画效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_05.jpg)

这已经足够好了。现在无论是否可用 JavaScript，任何访问站点的人都肯定会注意到。但是，嘿，既然你已经在主题中挖掘了，而且决定注册 jQuery，从 WordPress 捆绑包中添加 jQuery Color 插件，并将 `custom-jquery.js` 页面包含到他们的 `header.php` 文件中，你也可以加入这几行漂亮而简单的代码。

```js
jQuery(function(){
jQuery('.home .sticky')
.animate({'backgroundColor':'#ff6600'}, 'slow')
.animate({'backgroundColor':'#ffff99'}, 'slow')
.animate({'backgroundColor':'#ff6600'}, 'slow')
.animate({'backgroundColor':'#ffff99'}, 'slow');
});

```

前面的代码将我们的粘性帖子从浅黄色渐变为较深的橙色，然后再次*重复*以突出显示。以下图像显示了帖子渐变为较深的橙色：

![项目：为警示粘性帖子添加动画效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_06.jpg)

在书中很难看到动画效果，但我们确保了警报 `.sticky` 帖子在加载时会淡入到橙色 (`#ff9900`)，然后再淡出到黄色 (`#ffffcc`)，然后再重复一次，产生了相当明显的 "橙色警报" 效果。

现在警报帖子非常明显了，组织对你感激不尽！这已经足够补偿你几分钟的工作了。

## 创建简单、动态的图表

这个非营利组织对你的警报粘性帖子解决方案印象深刻，他们已经调拨了一些资金，并向你提出了另一个请求。他们注意到你如何使用 Inkscape 修复了警报图标，并询问你为另一个他们发布的帖子生成一个月度图表会有多大麻烦。这篇帖子是关于他们的绿色回收项目的前五个统计数据。

虽然项目符号列表对网站管理员来说非常容易实施，但人们并不真正注意或记住信息，因此他们正在考虑在网站上发布图表，但需要有人来绘制或以某种方式生成它们。

浏览他们的网站，你注意到编辑总是一贯地格式化发布的信息。所有的帖子标题都包含 **"... 月度统计"**，所有的信息都是用项目符号列出的，百分比数字始终位于冒号 "**:**" 之后。管理员一直保持如此一致是很好的。这将使得解决方案的制定变得非常容易，让编辑继续做他们一直以来做的事情。当前的帖子看起来像这样：

![创建简单、动态的图表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_07.jpg)

你告诉管理员只要他/她继续一贯地格式化帖子，你可以为他们撰写一个 jQuery 脚本来为他们绘制图表。他们几乎不相信你，很高兴让你继续进行。

要开始，我们首先需要确保我们只针对 **月度统计** 的正确帖子。我们将通过设置一个 jQuery 选择器来实现这一点，如下所示：

```js
...
jQuery('
.post h2:contains(Monthly Stats)')
.siblings('.entry-content')
.children('ul:first')
.css({background: '#ccffee'});
...

```

如我们所见，这个小的 "测试" 选择抓取了所有包含 "月度统计" 文本的 `.posts` 内部的 `h2` 标签。然后我们沿着 DOM 移动并定位 `.entry-content` div，然后定位其中的 **第一个** `ul`。我们可以通过改变背景颜色来看到先前的代码正确地定位了我们在这些帖子中想要的内容，如下一张截图所示：

![创建简单、动态的图表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_08.jpg)

现在我们可以针对特定的帖子进行定位，而无需更改主题的输出或让我们的客户做任何工作，让我们开始着手处理剩下的图表吧！

首先，因为我们将加载一个背景图片，而这些图片从主题的样式表中加载起来会更加顺畅（更容易定位图片），让我们再次使用 Inkscape 来帮助我们创建一个基本的背景，大约 450 像素宽，显示从 "刚刚开始" 到 "Yes!" 的进展，如下所示：

![创建简单、动态的图表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_09.jpg)

让我们导出该图形的 PNG 并将其添加到客户主题的图像目录中。然后，使用 jQuery，让我们动态地向所有目标`ul`添加一个类：

```js
...
jQuery('.post h2:contains(Monthly Stats)')
.siblings('.entry-content').children('ul').addClass('greenStats');
...

```

现在，我们可以进入客户主题的样式表，并且就像我们为粘性警报发布的那样，为我们的新类创建自定义 CSS 规则。打开主题的`style.css`样式表，并在末尾添加以下规则：

```js
...
.entry-content .greenStats{
margin: 0;
background:url(images/greenBackground.png) no-repeat;
border: 1px solid #006633;
padding: 40px 20px 5px 20px;
}
.entry-content .greenStats li:before{content:none;}
.entry-content .greenStats li{padding-left: 10px; margin: 0}
...

```

第一条规则添加了我们的新的`greenBackground.png`图表图像，并设置了一些基本属性，以便列表项可以开始适应我们即将添加的 jQuery。接下来的两条规则修复了客户主题（在本例中为默认主题）放置在每个`.entry-content` div 中的每个`li`元素上的特定`.entry-content li`问题。我们不希望在我们的图表项目之前有“小方块”，我们希望每个`li`的填充再多`10px`。同样，我们只想在 jQuery 添加了我们的`.greenStats`类时才影响`.entry-content` li 项，所以务必将该类名添加到 CSS 规则中。

现在，我们准备进行一些严肃的 jQuery 魔术了。我希望你到目前为止已经对选择器和 DOM 遍历非常熟悉了。我们将不得不运用相当多的这方面的知识来完成接下来的几项任务。

我们想要在我们的目标`li`上放置一个`.each()`函数项，并开始操纵其中的内容。

我们将从设置这个 jQuery 语句开始：

```js
...
jQuery('.post h2:contains(Monthly Stats)')
.siblings('.entry-content').children('ul').children('li')
.each(function(){
//code here
});//end jQ li
...

```

接下来，在我们的`.each()`函数*内部*，我们将放置一些代码，开始操纵每个`li`对象内部的 HTML 和文本。我们想要查找冒号“:”，并将其用作在其后的数字周围包装一个`div`的点。之后，我们将寻找结束的`</li>`标签，并使用它作为关闭我们开始的`div`的点。我们将使用`.text()`和`.replace()`函数来实现这一点，代码如下：

```js
...
var string1 =
jQuery(this).text().replace(': ',':<div class="nVal">');
var string2 = string1.replace('</li>','</div></li>');
//place back into the li element as html markup and text:
jQuery(this).html(string2);
...

```

前面的代码片段现在为我们提供了自定义带有类`.nVal`的`div`，我们可以开始使用它。`.nVal` div 最终将成为我们绿色统计图中的“柱形”。在上一个代码下面，我们将继续完善我们的`.each()`函数，并再次在`.each()`函数中*内部*放置以下代码：

```js
...
//set the default css values of each nVal div:
jQuery(this).children('.nVal').css({width: '0',
padding: '10px 0 10px 20px', fontSize: '130%',
color: '#ffffff', marginBottom: '5px'});
//retrieve the number text from inside the nVal div:
var nVar = jQuery(this).children('.nVal').text();
//animate the nVal divs with the nVar values:
jQuery(this).children('.nVal').delay(600)
.animate({backgroundColor: '#006600', width: nVar*(3.8)}, 2000);
...

```

在前面的代码片段中，请注意我使用了`.delay()`函数。如果您没有使用 jQuery 1.4.2 或更高版本的库，则该函数是可选的。我只是认为，为了确保用户注意到动画，有一个大约半秒的暂停是有帮助的。

我们再次使用`.text()`函数从`.nVal` div 中提取文本，并将其用于数学方程以计算`.animate()`函数中 div 的`width`。我们将`nVar`乘以`3.8`，因为在我们的图表设计中，大约 380 像素宽的 div 相当于 100%。如果您的图表尺寸不同，您需要相应地更改这些尺寸，以确保图表柱正确地延伸出去。

结果看起来很棒！这是我们开始动画的图表：

![创建简单、动画图表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_10.jpg)

在完成时，这就是它的样子，一个有趣、视觉清晰的组织绿色统计图的展示：

![创建简单、动画图表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_11.jpg)

# 深入了解动画

多亏了你的动态绿色统计图表，你已经准备好应对一些稍微复杂的请求了：客户*坚持*要求 Flash 开发。作为一个在 90 年代通过 Flash 进入 Web 开发的人，Flash 开发的请求没有问题。无论你抱怨多么多，你都必须承认，Flash 确实可以做动画。

然而，Flash 确实需要一个插件，尽管它是最流行的桌面浏览器插件，但并不总是显示你希望确保每个人都能看到的核心内容的好方法，更不用说像网站导航这样的基本元素了。此外，虽然 Flash 是最受欢迎的*桌面/笔记本浏览器*插件，但在 iPhone 的 Safari 移动版和大多数智能手机的基于 WebKit 的浏览器中，Flash 是“不适用”的。

在当今浏览器中，随着 CSS 和 JavaScript 在浏览器中的支持不断进步（尤其是移动浏览器），我对 Flash 请求的第一个问题总是：“好的。首先，告诉我你想要做什么，然后我们再看看。”确实，我们的客户希望他们的主导航面板具有动画效果。

Flash 当然可以做到这一点，但 jQuery 也可以，而当 JavaScript 不是一个选择时，它会优雅地退化为漂亮的样式化 CSS 元素，并且在最坏的情况下，没有 CSS，页面将加载我们的 WordPress 主题的干净、语义化的 XHTML 到纯文本浏览器中。

虽然有很多种方法来提供 Flash 内容和应用程序，使它们优雅地退化为符合 HTML 标准的替代方案（并且当使用 Flash 播放器时，你应该*总是*提供这些替代方案），但如果这不是必要的，为什么要增加额外的开发和复杂性呢？客户不需要提供流媒体视频，也不需要定制卡通角色动画，更不用说想要一个深度的、多媒体浸润和混搭的**丰富界面应用程序**（**RIA**）。因此，让我们把 Flash 留给 Flash 最擅长的事情，并使用 jQuery 来增强我们客户的 WordPress 网站已经做得最好的事情。

幸运的是，客户是理性的，并且愿意在我们诉诸 Flash 之前看看 jQuery 能做些什么。让我们通过一点 jQuery 的灵感展示一下他们的 WordPress 网站是由什么组成的。

## 项目：创建时髦的导航

我们受到 Flash 启发的客户经营着一个回收和翻新 NASA 和其他空间机构废弃并出售的材料的业务。他们希望他们的导航面板能够向用户展示这种未来主义（同时也是复古）的感觉，并提供一个页面导航，根据客户的说法：“具有流畅的动画和我们的徽标/图标火箭作为指针”。

让我们继续准备主题，以便我们可以开始。我们将继续使用默认主题，并使用我们在第二章中制作的页面导航 CSS 更改，*在 WordPress 中使用 jQuery 工作*。我们将增强导航栏的效果，使其在菜单项上悬停时触发平滑的缩进和释放动画。最后，我们将添加一个酷炫的浮动指针选择器（也是站点的太空飞船图标）。

首先，我们需要将客户的标志中使用的太空飞船图标追踪成基本的轮廓形式，以便我们可以创建一个浮动指针。同样，这可以很容易地通过 Inkscape 完成：

![项目：创建时髦的导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_13.jpg)

我们会在这里多做一步，旋转飞船，并且由于它将成为一个透明的 PNG 文件，添加一个漂亮的阴影和光泽效果，使其更有深度：

![项目：创建时髦的导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_14.jpg)

我们将把这张图片导出为一个宽度为 37 像素的透明`.png`文件。接下来，我们需要准备我们主题的样式表以接受这个背景图片。我们将在 jQuery 中创建一个名为`#shipSlide`的`div`来容纳这张图片，因此我们的样式表需要适应那个`id`名称：

```js
...
#shipSlide{
position: absolute; margin-top: 12px; margin-left: -7px;
width: 37px; height: 20px;
background: url(images/spaceship-icon.png) no-repeat;
}
...

```

### 注意

同样，就像本书中的许多示例一样，为了保持流程简洁易懂，我们将尽可能直接地进行操作，但不一定尽可能优化。在实际项目中，您可能想为此类项目创建一个单独的样式表，或者将您的 jQuery 工作包装到一个插件中，甚至在 WordPress 插件中使用我们在第三章中介绍的技术，*深入了解 jQuery 和 WordPress*。这完全取决于您希望增强的 jQuery 后续功能有多灵活和可移植。

现在，我们将在 jQuery 中开始工作。像往常一样，对于每个项目，您都要确保将 jQuery 包含到主题中，并且已经包含并设置为工作的`custom-jquery.js`文件。此外，对于此导航，我们将使用 Color 和 Easing 插件。您可以注册捆绑的 Color 插件，但是您需要手动从以下位置下载并包含自定义 Easing 插件到您的主题中。获取地址：[`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/)。

在我们特定的默认主题中，我们将使用一些 jQuery 来使我们的导航条更清晰一些。

我们的第一部分 jQuery 看起来像这样：

```js
...
//this adds our #shipSlide div
//under the twenty ten theme's menu header div
jQuery('.menu-header').prepend('<div id="shipSlide"> </div>');
//this fades the ship div to 40%
jQuery('#shipSlide').fadeTo('slow', 0.4);
...

```

在我使用 jQuery 的`.fadeTo()`函数淡化`#shipSlide` div 之前，我将其加载到浏览器中检查并确保背景图片是从 CSS 中加载的。下面的截图显示了船图像被我们初步的 jQuery 脚本加载并淡化：

![项目：创建时髦的导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_15.jpg)

好的，接下来，让我们设置一个基本动画，将导航`li.page_item`对象从左侧推入 35 像素，相对于它们的位置。 然后，我们将针对标签，并更改它们的背景颜色。 我们将使用`.hover`函数确保这发生在`li.page_item`对象的悬停和移出时：

```js
...
jQuery('li.menu-item')
.hover(function() {
//animates each menu item to the right (from the left)
jQuery(this).animate({paddingLeft: '+=25px'}, 400, 'swing');
//this over rides the style sheet's background on hover
jQuery(this).find('a').css('background','none');
//ship move code will go here
}, function(){
//returns the menu item to it's location
jQuery(this).animate({paddingLeft: '-=25px'}, 400, 'swing');
});//end hover
...

```

最后，在第一个悬停函数*内*，在 a 对象的颜色动画的*下方*，我们将添加以下代码片段，它将将`#shipSlide`对象移动到`li.item_page`的位置（注意只有粗体代码）：

```js
...
//this custom moves the ship image
var p = jQuery(this);
var position = p.position();
jQuery("#shipSlide").fadeTo('slow', 1)
.animate({marginLeft: position.left-175},
{duration: 600, easing: 'easeOutBack', queue: false});
...

```

在这里，我们设置了一个名为`position`的变量，并且还使用了一个名为`.position()`的函数，以便能够从`li.page_item`对象中提取一系列信息。

`#shipSlide`对象的动画函数将船向左移动到`page_item`的`position.left`，减去 175 个像素的`marginLeft`位置。

在前面的代码片段中，您还会注意到我们将`animate`函数中的`queue`设置为`false`，并且我们正在使用`easeOutBack`缓动方法，这仅因为我们包含了缓动插件。

我们需要的最后一小部分代码，在`li.page_item .hover()`代码的*下方*是另一个 jQuery 选择和`.hover()`函数，它将在`#mainNav`对象悬停时使`#shipSlide`对象淡入和淡出。同样，将此 jQuery 放置在所有其他导航代码的下方：

```js
...
//this fades and moves the ship back to it's starting point
jQuery('.menu-header').hover(function(){
jQuery("#shipSlide").fadeIn(1000);
}, function(){
jQuery("#shipSlide").fadeTo('slow', .4)
.animate({marginLeft: '-5px'},
{duration: 600, easing: 'easeOutBack', queue: false});
});//end hover
...

```

最终结果看起来很棒，船和菜单项目动画流畅，客户对他们新的时髦导航非常满意。

![项目：创建时髦导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_16.jpg)

## 项目：创建旋转的置顶帖子

早些时候，我们发现使用 WordPress 的特色帖子非常简单！这很好，因为我们的“我想要 Flash”客户现在请求了一个额外的增强解决方案。 他们使用 WordPress 的特色帖子来让网站观众了解他们正在推广的产品。 牢记这些帖子的内容，使他们的产品推广置于前列（通常一次两到四篇），而他们的常规新闻帖子和更新则在产品功能下方流动。

但是，当他们要展示两个以上的产品时（尤其是当他们要展示三个或更多产品时），他们当前的帖子会被推到下面，有时甚至被推到页面底部以下。 他们担心只偶尔瞥一眼网站的人如果不花时间向下滚动并查看当前的帖子，可能会觉得网站过时。

他们已经看到了许多网站示例，这些网站具有非常酷的图像旋转器，带有幻灯片或交叉淡入淡出效果，位于特色项目的顶部，并且他们想在他们的网站中加入类似的东西。 他们最初认为他们会在 Flash 中完成这个过程并放弃方便，但是由于 jQuery 导航面板效果很好，他们想要创建一个解决方案：

+   节省空间，避免将其他帖子推至“折叠”下方

+   看起来非常漂亮，并且引人注目的吸引注意力的特色文章

+   这意味着他们的营销管理员仍然很容易实现新的特色项目（只需要创建一个帖子并将其标记为“置顶”！）

这个客户的主题已经稍微改变了置顶帖子的 CSS 样式，在底部的 `style.css` 样式表中，我们可以找到简单的背景，使帖子具有暗色渐变以及一些字体颜色变化。

```js
...
.sticky { background: #000 url(images/sticky-background.png)
repeat-x; color: #ccc;}
.sticky small.date{display:none;}
.sticky h2 a{color: #0099ff;}
...

```

结果看起来像这样，你可以看到只有三个置顶帖子不留任何空间供查看下面的当前帖子，并且使用户需要滚动相当多的距离：

![项目：创建旋转置顶帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_17.jpg)

本质上，我们希望将这些置顶帖子叠在一起，如果可能的话，可能使它们稍微缩短一点，隐藏除了*第一个*置顶帖子之外的所有帖子，然后开始逐渐显示*第一个帖子上方的*其余帖子。

首先，这似乎是显而易见的，但再次确保你已经注册并将 jQuery 与之前讨论过的 Color 和 Easing 插件一起包含到主题中。你可以以任何你想要的方式包含 jQuery，但我将使用 WordPress 3.0 包中讨论的 1.4.2 版本，正如第二章中讨论的那样，*在 WordPress 中使用 jQuery*。另外，你还需要确保在主题中包含一个 `custom.js` 文件，这样你就可以将 jQuery 代码从 WordPress 的 `header.php` 模板中移出（这也在第二章中有所涉及，*在 WordPress 中使用 jQuery*）。

一旦 jQuery 和你的插件包含在主题中，我们将开始使用 jQuery。因为网站的功能是完全符合要求的，而且客户也接受这种替代视图，我们将保持主题和 `style.css` 不变，并确保我们所有的增强都是通过 jQuery 完成的。

### 注意

再次说明，下面的代码可能不是实现客户目标最优雅的方式，但它是写成的，以确保发生的每一步都是清晰可见的。

让我们首先改变置顶帖子的 CSS 属性，使它们都堆叠在一起。这样做的最简单的方法？将 `.sticky` 类的 `position: absolute`。让我们也确保宽度和高度正确，并且任何溢出都被隐藏，像这样：

```js
jQuery(function(){
jQuery(".sticky")
.css({
position: 'absolute',
top: '0',
margin: '0',
width: '650px',
height: '320px',
overflow: 'hidden'
});
...

```

接下来，我们将把 `h2` 标题向上移动一点，最重要的是，由于我们实际的帖子是*处于*定位绝对的 `.sticky` 帖子下面，我们将把它们移下来，使它们显示在即将动画化的置顶帖子下面。我们还将调整图片的右侧边距一点以便放置。

```js
...
//move the header back over if it's affected by the css
//you could also do this in the CSS directly
jQuery('.sticky h2').css({margin: '0', padding: '0'});
//move the margin over a bit
//you could also do this in the CSS directly
jQuery('.sticky img').css('marginRight','30px');
//this pushes the other posts down out of the way
jQuery('.post:not(.sticky):first').css('margin-top','360px');
...

```

特别注意前一个代码片段中粗体的 jQuery 选择器。如果需要复习选择器的使用方法，你可以参考第三章，*深入挖掘：了解 jQuery 和 WordPress*。基本上，我们在定位*第一个*未分配`.sticky`类的`.post` div。很好！

结果如下所示：

![项目：创建旋转粘性帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_18.jpg)

好的！jQuery 有一个我们之前看过的非常好的函数，叫做`.each`，它将在包装集合中的每个对象上运行附加函数。如果我们只想遍历每个项目一次，我们可以使用这段代码：

```js
...
jQuery('.sticky')
.hide()/*hide each post*/
.each( function (i){
/*i = numeric value that will increase with each loop*/
jQuery(this)
/*make sure each div is on it's own z-index*/
.css('z-index','i+10')
//using the animate function to fade in each div
//3 seconds apart*/
.animate({'backgroundColor': '#000000'}, i*3000, function(){
/*actual div fade in*/
jQuery(this).fadeIn('slow');
}
);//end animate
});//end each
...

```

看起来不错！然而，一旦最后一个`div`淡入，它就停止了，不再继续。

![项目：创建旋转粘性帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_19.jpg)

没有，没有超级流畅的 jQuery 方法来保持`.each()`函数的继续。然而，一个`.each()`函数如此容易设置，不利用它，即使是用于“无限循环”，也是一种遗憾。

现在，这里快速解释一下：如果你敢的话，你可以通过谷歌搜索`"infinite animation loops jquery"`，看看约一万条结果中，看起来有大约一万种 JavaScript 开发人员喜欢设置重复或无限循环的方法，每个开发人员似乎都认为（当然！）他们的方法是可用的最好方法。我更倾向于求助于常规 JavaScript，并使用一个`setInterval`函数和一些自定义变量设置的方式，这样可以很容易地利用我的现有 jQuery`.each()`语句和函数。

要开始创建我们的循环，我们将采用我们现有的 jQuery 语句，并将其放置在*自己的*函数内。你需要确保这个函数**位于**你的主要`jQuery(function(){...`文档准备好函数之外。否则，`setInterval`函数将无法正确启动它。

让我们称之为我们的新函数`loopStickies`。除了第一个语句之外，你会觉得它很熟悉：

```js
...
function loopStickies(duration){
/*note the variable "duration" being passed*/
///we'll need to make sure everything fades out
//except the first sticky post*/
jQuery('.sticky:not(:first)').fadeOut();
/*this should look almost the same*/
jQuery('.sticky')
.each( function (i){
/*i = numeric value that will increase with each loop*/
jQuery(this)
/*make sure each div is on it's own z-index*/
.css('z-index','i+10')
/*using the animate function & "duration" var for timing*/
.animate({'backgroundColor': '#000000'}, i*duration,
function(){
jQuery(this).fadeIn('slow');
}
);//end animate
}); //end each
}//end loopStickies

```

好的，这只是一个开始，现在我们有了我们的`loopStickies`函数，位于 jQuery 文档准备好函数之外，让我们将剩下的代码放回**jQuery(function(){...**文档准备好函数内。跟随粗体中的注释：

```js
...
/*set the stickies in a wrapper set to overflow hidden*/
jQuery('.sticky').wrapAll('<div id="stickyRotate"
style="position: absolute; padding: 0; margin-top: 5px;
width: 650px; height: 320px; border: 2px solid #000;
overflow:hidden;"></div>');
//make sure the first .sticky post fades in:
jQuery('.sticky:first').fadeIn();
//set the "duration" length to 6 seconds for each slide:
//(this is the var our function uses)
var duration = 6000;
/*create the interval duration length, based on the duration:*/
var intervalDuration = duration * jQuery('.sticky').length;
/*the function needs to run once before the setInterval kicks in*/
loopStickies(duration);
//the setInterval will kick off loopStickies in
//18 seconds: (6secs x number of sticky posts) */
setInterval( 'loopStickies("'+duration+'")', intervalDuration
);
...

```

这个工作原理是，我们的原始 jQuery 语句和`.each()`函数通过调用`loopStickies`函数在 jQuery 选择中的每个粘性帖子上运行。*同时*，`setInterval`函数被启动，但由于我们将`intervalDuration`变量设置为计算我们的`duration`变量乘以粘性帖子数量，它将不会在 18 秒后启动。正好是我们的原始函数完成的时候！`setInterval`函数会接管并将我们的粘性帖子循环到无限远。

好的，让我们来看看；我们现在有一组非常好的便签，持续六秒钟，然后淡出到下一个便签！

![项目：创建旋转便签](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_20.jpg)

### 添加一点额外的努力：添加循环指示器

旋转便签非常棒！然而，尽管客户一次只会有三到四个便签在旋转，但至少让用户知道他们要查看所有旋转的时间大致是个好习惯。大多数旋转幻灯片都会在某个地方添加指示器，让用户知道将显示多少个面板，并允许用户在面板之间导航。

让我们看看如何将此功能添加到我们的旋转便签中。首先，我们需要创建一个小的界面。在我们之前创建的`#stickyRotate`包装器内，添加在最后一个便签对象后的一个带有内联样式的`div`。再次强调，这对于一个工作项目来说不一定理想，但我想让每一步都清晰明了。实际上，你可能会创建自定义样式表或修改你正在工作的主题。无论如何，这是我们的交互容器。我把这段代码放在了我的前一个代码的底部，在 jQuery 文档准备好函数内部：

```js
...
jQuery('.sticky:last')
.after('<div id="stickyNav"
style="position: absolute; padding: 10px 0 0 0; margin-top: 280px;
height: 25px; width: 650px; color: #eee; background: #000;
text-align: center"></div>');
...

```

并在那段代码下面，我们将添加一些更多的 jQuery 代码，这些代码将把每个便签的编号插入到我们刚刚创建的`#stickyNav` div 中：

```js
...
rotating sticky postsloop indicator, addingjQuery('.sticky')
.each( function (i){
jQuery('#stickyNav').fadeTo(0, 0.8)
.append("<div class='sN'
style='display:inline; margin: 0 5px;
border: 1px solid #999;
padding: 2px 5px;'>"+(i+1)+"</div> ");
});
...

```

这段代码使用了另一个`each`函数，但我们只需要，并且希望它运行一次，并将数字 1 到 3（或者我们有多少个便签）附加到`#stickyNav` div 中。

最后，为了真正完成这个效果，我们需要回到我们的`loopStickies`函数内部。在`.animate`函数的回调函数内部，我们将添加以下粗体代码：

```js
...
jQuery('.sticky')
.each( function (i){
/*i = numeric value that will increase with each loop*/
jQuery(this)
/*make sure each div is on it's own z-index*/
.css('z-index','i+10')
/*using the animate function for timing*/
.animate({'backgroundColor': '#000000'}, i*duration, function(){
jQuery(this).fadeIn('slow');
//interactivity
jQuery("#stickyNav .sN").css('color','#666666');
jQuery('#stickyNav .sN:eq('+i+')').css('color','#ffffff');
}
);//end animate
}); //end each
...

```

在前面的代码中使用`:eq()`选择器，我们能够定位到界面显示中的相应编号，并使其与其他编号突出显示。这样可以让用户看到有多少个幻灯片，以及他们在哪个幻灯片上。

![添加一点额外的努力：添加循环指示器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_05_21.jpg)

# 总结

你现在已经是使用 jQuery 处理动画的专家了！通过这些示例，你可能会发现几种方法来进一步增强你的 WordPress 站点。你现在应该知道如何：

+   使用动画引导用户注意关键信息

+   生成动画条形图

+   创建一些非常流畅、带有动画的页面导航

+   开发旋转便签

接下来，让我们看看 jQuery UI 插件以及它如何使 WordPress 站点受益的许多方法。


# 第六章：WordPress 和 jQuery 的 UI

我们现在准备好去看看 jQuery 最受欢迎的插件了：UI。当然，UI 代表**用户界面**。jQuery UI 插件简化了已经通过 jQuery 简化的许多最受欢迎的任务。我知道，很难想象它会变得更简单，但这正是这个插件所做的。最重要的是，虽然增强的效果很好，但 UI 插件提供了界面小部件以及一种简单的方式来对其进行样式化或“主题化”，而无需编写特定的界面元素代码，如选项卡、对话框等等。

在本章中，我们将：

+   快速了解 UI 插件的内容和入门方式

+   学习如何将 jQuery UI 小部件应用到我们的 WordPress 站点中，使其更加直观、易于理解内容，并鼓励用户采取行动。

+   学习如何使用常见的 WordPress 功能实现流行的 UI 功能和小部件

让我们开始吧。

# 了解 jQuery 的 UI 插件

您可以访问 [`www.jqueryui.com`](http://www.jqueryui.com) 了解 jQuery UI 插件的使用方法。

![了解 jQuery 的 UI 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_01.jpg)

UI 插件提供了一组标准化的小部件、交互和效果。让我们详细看看每种类型的提供内容。

## 小部件

jQuery 中的“小部件”一词与 WordPress 的小部件有些不同，WordPress 的小部件是设计成在主题的侧边栏中很好地显示的小插件。在 jQuery 的 UI 插件中，小部件描述了一组完整功能的用户界面控件，这些控件在项目中通常是必需的，并由 jQuery 开发人员创建。UI 小部件为 jQuery 开发人员节省了大量时间，他们不再需要编写 jQuery 语句和链接函数来创建相同的界面和效果。以下是 jQuery UI 提供的界面小部件：

+   **手风琴**：此小部件通过点击每个部分的标题来展开和折叠被划分为逻辑部分的内容。在任何给定时间只能打开一个部分。

+   **自动完成**（1.8+）：这是 1.8 版本中提供的新功能。**自动完成**小部件在您输入时提供建议。建议源以基本的 JavaScript 数组形式提供。

+   **按钮**（1.8+）：1.8 版本中的新功能是**按钮**小部件。这使您可以采用不同类型的标记并将 UI 的按钮样式和功能应用于它。

+   **日期选择器**：**日期选择器**小部件可以应用于标准表单输入字段。聚焦输入字段会在一个小叠加层中打开一个交互式日历。

+   **对话框**：此小部件是页面内的一个叠加层。它有一个标题栏和一个内容区域，并且可以通过默认情况下的“x”图标或通过传递给它的额外按钮参数来移动、调整大小和关闭。

+   **进度条：** **进度条** 小部件旨在通过传递给它的值参数简单显示当前进度完成的百分比。它默认缩放以适应其父容器内。

+   **滑块：** jQuery UI **滑块** 小部件将对象（例如空的`div`标签）转换为滑块。有各种选项，例如多个手柄和范围，然后可以将其传递给其他对象和函数。您可以使用鼠标或箭头键来更改滑块的位置。

+   **选项卡：** **选项卡** 小部件用于将内容分成多个部分，可以通过单击选项卡标题来交换，以节省空间，就像手风琴一样。

## 交互

jQuery UI 交互采用了一组更常见的复杂 jQuery 行为，开发人员通常需要为项目创建，然后将它们打包成方便易用的函数，如下所示：

+   **可拖动：** 这种交互使所选元素可通过鼠标拖动。

+   **可放置：** 这种交互与可拖动元素配合使用，并使所选元素可放置（即它们接受可拖动元素放置在其上）。

+   **可调整大小：** 这种交互通过在对象上添加可视的“手柄”使所选元素可调整大小。您可以指定一个或多个手柄，以及最小和最大宽度和高度。

+   **可选择：** 这种交互允许通过在元素上用鼠标拖动“套索”或框选来选择元素。

+   **可排序：** 这使所选元素可通过鼠标拖动进行排序。

## 特效

主要特点是`.effect()`函数，但 jQuery 中可用的标准动画函数和快捷方式都已经通过 jQuery UI 插件的“效果核心”进行了增强。该核心还包括对颜色、动画的能力，还包括额外的缓动选项；因此，如果将其包含到项目中，您将不再需要之前我们一直在使用的 Color 或 Easing 插件。jQuery 效果包括：

+   **效果：** 此函数允许您为任何对象分配来自 15 种效果中的一个。

+   **显示：** 这种增强型显示方法可选择接受 jQuery UI 高级效果。

+   **隐藏：** 这种增强型隐藏方法可选择接受 jQuery UI 高级效果。

+   **切换：** 这种增强型切换方法可选择接受 jQuery UI 高级效果。

+   **颜色动画：** 我们在第五章中学到的 Color 插件被包含到 jQuery UI 效果核心中。同样，它简单地扩展了`animate`函数，以便能够同时动画化颜色。

+   **添加类：** 将指定的类添加到一组匹配元素中的每个元素，可选择在状态之间进行可选的过渡。

+   **删除类：** 从一组匹配元素中删除所有或指定的类，可选择在状态之间进行可选的过渡。

+   **切换类：** 如果不存在指定的类，则添加指定的类，并在存在指定的类时删除指定的类，使用可选的过渡。

+   **切换类：** 从第一个参数中定义的类切换到第二个参数中定义的类，使用可选的过渡。

## WordPress 中捆绑的 jQuery UI 插件版本

大多数 jQuery UI 插件的主要**小部件**和**交互**核心都捆绑到了你的 WordPress 安装中。如果你正在使用 WordPress 2.9.2，你已经捆绑了 jQuery 1.3.2，并且 UI 插件核心是 1.7.1，并且你还可以使用以下 jQuery UI 小部件和交互：**对话框、可拖动、可放置、可调整大小、可选择、可排序**和**选项卡**。

如果你正在使用 WordPress 3.0+，你的安装中已经捆绑了 jQuery 1.4.2，并且捆绑了 UI 核心 1.7.3。同样，这是与上一段提到的相同的小部件和交互。

如果你想利用 UI 插件的*效果*，或者如果你正在使用 jQuery 1.4.2 并想利用 UI 插件的 1.8+ 功能，你需要通过从 jQuery UI 网站或 Google 的 CDN 单独下载 UI 插件版本 1.8+ 的副本。

## 从 jQuery UI 网站挑选和选择

从 jQuery UI 网站下载的优点是你可以为你的项目挑选你需要的内容。如果你去下载页面[`www.jqueryui.com/download`](http://www.jqueryui.com/download)，你会在右侧看到可以选择版本**1.7.3**或**1.8.4**并单击**下载**按钮；这将给你一切。

![从 jQuery UI 网站挑选和选择](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_02.jpg)

为了开发目的，你可以直接下载整个文件。ZIP 文件超过 4 MB，但其中包含一个充满示例和文档的开发捆绑目录；这些内容都不会加载到你的项目中。

选择所有选项后，你加载到 WordPress 项目中的实际 UI 插件的 `.js` 文件约为 200 KB，根据你从网站选择了什么或者你如何自己创建，你可以添加大约另外 100 KB 到项目中的 CSS 主题中。如果你确切地知道你要使用哪些功能，你可以通过只选择你想要使用的内容来减少一些千字节。

下载页面很棒，因为它不会让你取消选择依赖于你选择的另一个功能的任何内容，而你想要使用它。这是一个关于选择你需要的东西的警报的截图：

![从 jQuery UI 网站挑选和选择](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_03.jpg)

### 提示

**确保下载与你的 jQuery 版本相匹配的正确 UI 插件版本！**

如果你的项目使用的是 WordPress 2.9.2，捆绑的版本是 jQuery 1.3.2，所以你需要确保下载 UI 插件版本 1.7.3。如果你使用的是 Google CDN 或你自己的 jQuery 下载版本是 1.4+，你可以下载并使用 jQuery UI 插件版本 1.8+。

## 让它看起来正确：简易 UI 主题化

无论你从哪里引入 UI 插件，你自己的下载，Google CDN，还是 WordPress 捆绑的 UI 选项，你都需要为其提供自己的样式。你可以在你的项目中包含许多出色的主题，或者轻松地自己“创建”一个以最好地匹配你站点设计的主题。

在 jQuery 的 UI 网站上从导航栏中选择 **Themes**，或者访问：[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)。

![让它看起来正确：简易 UI 主题化](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_04.jpg)

你可以直接调整生成的主题的 CSS 样式表，或者简单地在你的 WordPress 样式表之前加载 jQuery UI 样式表。在 Firefox 中使用 WebDeveloper 的 **Toolbar** 或 **Firebug**，可以很容易地查看 UI 生成的样式并在主 WordPress 样式表中覆盖它们。

## 将 jQuery UI 插件功能包含到你的 WordPress 站点中

到目前为止，你应该已经非常熟悉将 jQuery 插件包含到你的 WordPress 站点中。因为 UI 插件的 *特定组件* 已经捆绑在 WordPress 中，我们将以几种不同的方式讨论将它们包含到你的项目中。

### 从 WordPress 的捆绑包含 jQuery 的 UI

WordPress 捆绑的 jQuery 的 UI 插件被拆分成单独的 `.js` 文件。你首先必须在你的项目中注册 UI 核心文件，以及你想要包含在项目中的每个小部件或特定交互。再次强调，唯一可用的小部件和交互是：**Dialog、Draggable、Droppable、Resizable、Selectable、Sortable** 和 **Tabs**。

在你的 WordPress 主题中注册核心：

```js
...
<?php
if (!is_admin()) {//checking for is_admin makes sure that the UI doesn't load in admin
//adding array('jquery') means the ui-core requires jquery
wp_enqueue_script("jquery-ui-core", array('jquery'));
}//end of is_admin
?>
...

```

然后，注册你想要的特定小部件：

```js
...
<?php
if (!is_admin()) {//checking for is_admin makes sure that the UI doesn't load in admin
//requires jquery AND the ui-core
wp_enqueue_script("jquery-ui-dialog",
array('jquery','jquery-ui-core'));
}//end of is_admin()
?>
...

```

只需重复上述代码以添加额外的小部件。小部件 `.js` 文件名称如下：

```js
jquery-ui-tabs
jquery-ui-sortable
jquery-ui-draggable
jquery-ui-droppable
jquery-ui-selectable
jquery-ui-resizable
jquery-ui-dialog

```

### 注意

再次，WordPress 的捆绑 JavaScript 的完整列表可以在 Codex 中找到：[`codex.wordpress.org/Function_Reference/wp_enqueue_script`](http://codex.wordpress.org/Function_Reference/wp_enqueue_script)。

### 从 Google CDN 包含

你可以非常类似于通过 Google CDN 包含 jQuery，包含 jQuery 的 UI 插件。UI 插件路径是：[`ajax.googleapis.com/ajax/libs/jqueryui/1.8.0/jquery-ui.min.js`](http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.0/jquery-ui.min.js)。注意这里的粗体版本号。你可以将它更改为你需要的 UI 插件版本。如果你使用的是 jQuery 版本 1.3.2，请确保目标是 1.7.2。如果你使用的是 1.4.2，你可以选择 1.8.0。

让我们回顾一下如何使用 `wp_register_script` 来调用从捆绑包或从 Google 的 CDN 可用的脚本：

```js
...
if (!is_admin()) {//checking for is_admin makes sure that UI doesn't load in admin
wp_deregister_script( 'jquery-ui-core' );
wp_register_script( 'jquery-ui-core', 'http://ajax.googleapis.com/ajax/libs/jqueryui/1.8.0/jquery-ui.min.js');
/*this brings over the entire 1.8 core and all widgets, interactions and effects from the Google CDN*/
}//end of is_admin
...

```

您应该注意，虽然我们正在注销捆绑的 `jquery-ui-core` 文件，但我们从 Google CDN 加载的是 *完整的* jQuery UI 插件，可以访问其所有小部件、交互和效果。最好在您的代码中添加注释，以便其他开发人员知道他们无需在项目中注册单独的小部件和交互。

### 从您的主题或插件目录加载您自己的自定义下载

如果您已将 UI 包含到您的主题或插件目录中，您将通过以下方法重新加载，再次使用 `wp_enqueue_script`：

从主题中包含 UI 插件的本地副本：

```js
...
if (!is_admin()) {//checking for is_admin() makes sure that UI doesn't load in admin
wp_enqueue_script('jquery-ui-1.8.custom.min', get_bloginfo('stylesheet_directory') . '/js/jquery-ui-1.8.custom.min.js', array('jquery'), '20100410' );
}//end of is_admin()
...

```

同样，在脚本末尾添加 `array('jquery')`，这让 WordPress 知道 jQuery 是必需的，以防尚未注册。

要从 WordPress 插件中包含 UI 插件的本地副本，请使用以下 `wp_register_script` 函数：

```js
...
function myPluginFunction(){
if (!is_admin()) {//checking for is_admin makes sure that the UI doesn't load in admin
wp_register_script('jquery-ui-1.8.custom.min',
WP_PLUGIN_URL . '/js/jquery-ui-1.8.custom.min.js');
}//end of is_admin
}//end of myPluginFunction()
add_action('wp_head', 'myPluginFunction');
...

```

### 不要忘记您的样式！

无论您从哪里获取 UI 插件，WordPress、Google 的 CDN 还是您自己的下载，您都需要为 UI 插件包含 CSS 样式。如果之前没有玩过主题设置器，请返回并进行操作。选择一个主题或修改其中一个主题使用主题设置器，或者从头开始创建自定义的主题，以创建与网站现有设计相匹配的小部件。

完成后，您可以选择您的主题或自定义的主题并将其放置在您的主题或插件目录中。请确保包含随主题提供的图片目录。然后，您可以将其包含在`header.php` 主题文件中或使用我们之前使用的 `wp_enqueue_style` 函数将其包含到插件或主题中，通过 `functions.php` 页面：

要直接在您的 WordPress 主题中直接包含 UI 主题，请使用以下链接：

```js
...
<link rel="stylesheet" href="<?php bloginfo('stylesheet_directory'); ?>/js/smoothness/jquery-ui-1.8.custom.css" type="text/css" media="screen" />
...

```

从主题的 `functions.php` 页面使用 `wp_enqueue_style` 将 UI 主题包含到 WordPress 主题中：

```js
...
<?php
function addUIstyles(){
wp_enqueue_style('ui-theme', bloginfo('stylesheet_directory')
'/js/smoothness/jquery-ui-1.8.custom.css', array('style'), '1.0', 'screen');
}
add_action('init', 'addUIstyles');
?>
...

```

将 UI 主题包含到 WordPress 插件中使用 `wp_enqueue_style` 与上面的示例类似，但请确保使用 `WP_PLUGIN_DIR` 以定位您的插件目录。

```js
...
wp_enqueue_style('ui-theme', WP_PLUGIN_DIR .
.'/js/smoothness/jquery-ui-1.8.custom.css',
array('style'), '1.0', 'screen');
...

```

# 使用 jQuery UI 增强效果

您可能会认为在选择主题或创建自定义主题后，我们会立即开始使用小部件。我们会的！但是，在我们从 第五章 中仍然清楚地记得动画和交互的时间内（尽管，如果您在跳来跳去，不用担心），您会感兴趣了解，设置大部分那些动画和效果是这么容易，事情可以变得更加引人注目很多次，使用 UI 插件。

首先，目前 *这些效果未捆绑* 在 WordPress 中。因此，为了使用这些 UI 效果，您需要通过您自己的下载或从 Google CDN 导入 UI 插件。

## 轻松制作效果

插件所做的是添加一个名为`.effect()`的新函数，提供了大约 15 个新的、时髦的动画效果。特别是，`blind`，像百叶窗一样卷起物体；`shake`，稍微晃动一下；以及`explode`，它成功地“打破”了对象并将其片段分散在几个方向上。

让我们在鼠标悬停在标题上时对我们的文章应用`shake`效果。除了在我们的 WordPress 项目中注册和/或包含必要的 jQuery 和 jQuery UI 插件文件之外，你还应该将一个`custom-jquery.js`文件包含到你的主题中以使用。完成这些步骤后，包含以下代码：

```js
jQuery(function(){
jQuery(".post h2").hover(function(){
jQuery(this).effect('shake', 200);
}, function(){
jQuery(this).effect('shake', 200);
});
});

```

你可以（在某种程度上）在以下截图中看到这个效果：

![轻松创建效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_05.jpg)

## 缓动同样容易

除了`.effects`函数外，UI 插件还*扩展了* jQuery 的现有`.animate`函数以及快捷函数，例如`.hide, .show, .toggle, .addClass, .removeClass`和`.toggleClass`。与我们在第五章中介绍的优秀的缓动插件（由*罗伯特·彭纳*引入）一起，*在 WordPress 中使用 jQuery 动画*。因此，如果你使用 jQuery UI 插件并将效果核心包含在下载中，那么在项目中单独包含缓动插件是没有必要的。

## 使用 jQuery UI 进行颜色动画

除了包含的缓动插件外，jQuery UI 还内置了颜色动画插件。在第五章，*在 WordPress 中使用 jQuery 动画* 中，我们使用了与我们的 WordPress 安装捆绑在一起的 Color 插件。但是，如果你打算使用已下载的版本或 Google CDN 版本的 UI 插件，就像使用缓动插件一样，你就不需要单独使用或从 WordPress 捆绑包中注册它了。

为了在我们的项目中测试它，我们没有注册 Color 插件，但正在引用我们下载的 UI 插件版本 1.8，让我们应用`easeOutBounce`缓动选项来动画化我们标题文本的颜色：

```js
...
jQuery(".post h2").hover(function(){
jQuery(this).animate({'backgroundColor':'#ccccff'}, 2000,
'easeOutBack');
}, function(){
jQuery(this).animate({'backgroundColor': '#999999'}, 2000,
'easeOutBack');
});
...

```

然后，它会动画到浅蓝色，如下截图所示：

![使用 jQuery UI 进行颜色动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_06.jpg)

然后，回到灰色：

![使用 jQuery UI 进行颜色动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_07.jpg)

你注意到，在 jQuery UI 插件的效果核心中使用颜色动画和缓动功能与使用独立的 Color 动画或缓动插件没有区别。同样，除了哪个版本更方便和有用外，即独立插件还是 UI 插件，应该没有任何区别，对你的 WordPress 项目而言。

# 提升 WordPress 站点的用户界面

我们可以看到 jQueryUI.com 上的 UI 演示确实看起来很酷，但是既然我们已经将 UI 插件加载到我们的项目中，那么我们如何真正地在 WordPress 项目中使用这些功能呢？不同类型的界面可以帮助我们更轻松地组织和关联各种类型的信息，并减少混淆。WordPress 的主题 API 允许以逻辑块的形式在网站设计中显示各种类型的信息，主要是帖子和列表。让我们看看我们是否可以使用 UI 功能来增强其中的任何信息。

我们已经看到 UI 插件提供了：手风琴、选项卡、对话框、日期选择器，以及实现拖放和排序的简单方法。此外，如果您使用的是最新版本，即 1.8 或更高版本（本章示例使用的是），还有像**自动完成**和**按钮**这样的酷炫小部件。让我们再假设有另一个客户，并看看一些小的界面增强如何帮助他们的网站。

## 项目：将帖子转换为选项卡

你可能最近在网站上看到越来越多地使用选项卡。在您的网站中使用选项卡的主要原因是，它允许用户轻松地一次查看一组相关内容（这就是为什么“选项卡样式”网站导航也很受欢迎的原因）。作为设计师，它还允许您将内容放入一个方便的模块中，节省宝贵的屏幕空间。

在我们的第五章中，*在 WordPress 中使用 jQuery 动画*，我们学会了如何堆叠置顶帖子，使它们以幻灯片方式旋转。虽然对不相关的内容进行动画处理很有效，以确保每个人都能一瞥，但将内容加载到选项卡中意味着内容是相关的，是的，您还想节省空间，也许将信息放在折叠部分之上，以便用户更有可能接受它。

你最新的假设性客户有三个与了解他们公司相关的信息。这些内容变化不大，但他希望网站的用户能够在一开始就获得信息概览，并有下载白皮书的选项，而无需滚动。

客户已经在他的网站上有了这些内容。这些帖子被分配到一个名为**我们的结构**的唯一类别中。这些帖子现在已经相当陈旧，甚至在网站的主页上都没有显示出来，所以客户一直在手动在网站的各个其他页面中链接到这些帖子的永久链接。

要开始，我们决定从 WordPress 主题中获取一点帮助会对我们有所裨益。

### 在 WordPress 主题中设置自定义循环

让我们从进入客户主题开始，并设置一个仅从 **我们的结构** 类别中提取的循环。然后，使用 jQuery UI，我们将以一组选项卡的形式显示这些帖子，这样大部分内容都可以在“折叠”部分查看，确保站点访问者可以首先获得组织的最重要信息概述，而一般的帖子项目将会在下方流动。

首先，在 `index.php` 页面中，我们将创建一个新循环，在现有的仅显示 **我们的结构** 类别的 `loop.php` 包含之上。不过，在我们这样做之前，我们将转到 jQuery UI 网站，并查看选项卡设置的演示：[`jqueryui.com/demos/tabs/`](http://jqueryui.com/demos/tabs/)。

本质上，我们看到演示选项卡具有列出标题的 `ul`，包裹在调用指向内容 `div` 的 `href` 的锚点中。这意味着我们的主题实际上将需要 *两个* 自定义 WordPress 循环来适应此小部件。

我们将在我们的 `index.php` 模板文件中设置它们，就在我们的主要内容 `loop.php` 包含的上方，*在*我们正在使用的主题中的 `#content` div 内部，这是默认主题。第一个循环将设置我们的自定义 `#ourStructure` div，其中包含标题的 `ul` 列表：

```js
...
<div id="ourStructure">
<ul>
<?php//start custom loop
//get posts in the proper category
$postList = get_posts('category=4');
foreach($postList as $post):
setup_postdata($post);
?>
//set up a list item with a unique anchor link
<li>
<a href="#post-<?php the_ID(); ?>">
<?php the_title(); ?></a>
</li>
<?php endforeach; ?>
</ul>
<!--//second loop goes here-->
</div><!--//end of ourStructure-->
...

```

接下来，在上一个循环之下，但仍在 `#ourStructure` div 内部，我们将再次运行循环，现在专注于帖子的标题和内容，如下所示：

```js
...
<!--//second loop goes here-->
<?php
//again, call correct category
$postContent = get_posts('category=4');
foreach($postContent as $post):
setup_postdata($post);
?>
//assign a unique ID to div
<div id="post-<?php the_ID(); ?>">
<h2><?php the_title(); ?></h2>
//add content:
<div class="entry">
<?php the_content('Read the rest of this entry &raquo;'); ?>
</div>
</div>
<?php endforeach; ?>
</div><!--//end of ourStructure-->
...

```

这给我们带来了一个看起来像下一个屏幕截图的结果。虽然不是非常漂亮，但它是功能齐全的，而且肯定能将重要信息展示出来，并允许用户链接到 `id` 实例的锚点名称。

![在 WordPress 主题中设置自定义循环](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_08.jpg)

然后，我们将使用 jQuery 的 UI 选项卡增强该标记，如下所示，通过针对 `#ourStructure` div，我们在我们的 `custom.js` 文件中设置以下 jQuery 语句：

```js
...
jQuery("#ourStructure").tabs();
...

```

是的。难以置信，但多亏了 WordPress 的灵活性和我们使主题为我们完成的工作，这就是我们需要的 *全部* jQuery！

![在 WordPress 主题中设置自定义循环](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_09.jpg)

不错！现在内容使用我们选择的 jQuery UI 主题 "Smoothness" 包含在顶部（再次强调，我们正在使用撰写本书时随 3.0 一起提供的默认 WordPress 主题）。让我们看一些 UI 插件的其他用法。

### 使用 jQuery 完全实现选项卡

通过调整 WordPress 主题，我们实现了上述选项卡方案，包括在 HTML 中包含标题的 `ul` 列表，然后在下面使用 div 标签包裹帖子内容。这样做很有效，因为它生成了一个 `ul` 列表，其中包含指向锚点名称的 `href` 链接，即使在未启用 JavaScript 的浏览器中，仍然可以呈现内容并正常工作。

但是，对于其他情况，例如 WordPress 已经呈现您需要的内容（例如，一篇帖子或页面中已经包含了一组`h2`或`h3`标题和内容），或者您只是无法编辑主题，可能更容易通过在前面应用一点 jQuery 来生成 UI `.tab`功能所需的 DOM 对象。

对于在单个页面或 WordPress 帖子中添加的`h3`标题和`p`段落标签的列表，我们仍然可以将该内容包装在 UI 标签小部件中。

下一张屏幕截图描述了**关于**页面，其中已经包含了所有内容；我们只需“调整”它以尽可能满足 jQuery UI 标签的要求：

![完全使用 jQuery 实现标签](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_10.jpg)

首先，我们将目标页面。WordPress 也可以输出唯一的页面 ID 以及一系列类名；您将不得不在浏览器中查看 WordPress 主题的 HTML 输出的**查看源代码**，看看主题是否利用了这个功能（大多数良好的 WordPress 主题都会这样）。这种能力可以帮助我们仅针对我们想要影响的内容进行定位。例如，如果我们只想增强我们的**关于**页面，我们可以查看源代码，并看到帖子的唯一 ID 是`#post-104`。这样我们就可以通过首先在`ul`标题列表前面添加一个`ul`列表来定位我们想要添加标签的帖子。

一旦我们有了`ul`列表，我们需要将所有内容包装在一个新的、可选的带有 ID 为`#aboutUs`的 div 中。然后，我们将循环遍历每个`h3`项，创建带有锚链接的单独的`li`列表项，并将每个后续的`h3`和`p`标签都包装在其自己的带有锚点命名的`id`div 中。

阅读代码中的粗体注释以便跟踪：

```js
...
//add in a ul list on the About page only, before the first h3
jQuery("#post-104 h3:first").before("<ul></ul>");
//select the ul, the h3's AND the h3's p tags
//and wrap them in a new div
//use the .add() function to make sure everything is selected
jQuery("#post-104 ul").add("#post-104 h3")
.add("#post-104 h3+p").wrapAll("<div id='aboutUs'></div>");
//for EACH h3 item:
jQuery("#post-104 h3").each(function(i){
//add text to the ul list w/ anchor links
var titleTxt = jQuery(this).text();
var htmlTxt = "<li>
<a href='#name-"+i+"'>"+titleTxt+"</a></li>";
jQuery("#post-104 ul").append(htmlTxt);
//wrap each h3 AND p in a div with anchor names
//this time, use .andSelf to make sure everything is selected
jQuery(this).next("p").andSelf()
.wrapAll("<div id='name-"+i+"'></div>");
});
//remove .entry class so list items don't have right quotes
//this is a list style in the default theme
jQuery("#post-104 .entry").removeClass('entry');
//Last, create the tabs widget
jQuery("#post-104 #aboutUs").tabs();
...

```

现在刷新页面显示如下：

![完全使用 jQuery 实现标签](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_11.jpg)

再次强调，您对 WordPress 主题和 jQuery 的了解越多，您就越能决定哪种路线在决定是否操纵主题以帮助您的 jQuery 增强功能，或者是否更好地使用纯 jQuery 方面更快或更好。。

## 项目：使边栏成为手风琴

手风琴几乎具有与标签相同的功能。大多数情况下，它们只是垂直而不是水平的。与标签一样，您将希望将它们用于将相似的信息组合到一个更整洁的空间中，从而使站点用户能够按逻辑块查看信息，而不必沿着站点或滚动条向下浏览。

在我们一直使用的默认主题中，边栏上的页面导航有一些信息，我们希望人们能够一目了然地看到，并且不会将标题推到可能错过它们的地方。通过将各节分组成可以展开并显示附加信息和链接的手风琴，我们可以节省一些空间，并确保当页面加载时用户至少可以看到重要的组织标题，并知道可能需要展开并查看更多信息。

手风琴小部件与列表非常配合，这就是侧边栏的用途。正如您可以通过[`jQueryUI.com/demos/accordion`](http://jQueryUI.com/demos/accordion)的示例代码看到的那样，该小部件识别并与一致的、分层次顺序设置的标题和段落或 `div` 标签一起工作。您还可以使用各种选项将特定的 DOM 对象设置为标题和导航元素。

我们默认主题的 WordPress 侧边栏是一个大的 `ul` 列表，位于一个 `div` 内。这对手风琴小部件来说是完美的，但由于我们设置了一些自定义 CSS，使页面列表显示更像导航按钮，我们想要针对导航列表项 *下面* 的下两个列表进行定位。不用担心，很容易选择并应用手风琴小部件到下列项目中，如下所示：

```js
...
//select the proper li level and exclude the inner ul lists then wrap in a targetable div
jQuery(".xoxo ul li:gt(10)").not(".xoxo ul li ul li")
.wrapAll('<div id="sideAccordion"></div>');
//select the new target and assign the widget
jQuery('.xoxo').accordion().css({'marginTop':'30px'});
...

```

小部件的默认状态是显示顶部手风琴打开。客户希望它完全关闭。为了实现这一点，我们将向小部件添加一些参数，包括 `active: -1`，通常用于选择要打开的条，但通过将其设置为 `-1`，它们都将关闭：

```js
...
jQuery('.xoxo')
//options for the accordion
.accordion({header: 'h2', collapsible: true, active: -1})
.css({'marginTop':'30px'});
//last, some extra styles to the headers and ul lists
//to line them up
jQuery(".xoxo h3")
.css({'padding':'5px 0 5px 25px', 'height':'15px'});
jQuery(".xoxo ul").css({'height': 'auto', 'margin': '0px',
'paddingLeft': '25px', 'paddingTop': '5px',
'paddingBottom': '5px'});
...

```

我们页面导航下的侧边栏现在以一种漂亮的样式成为手风琴式，与我们页面的标签相匹配。

![项目：使侧边栏成为手风琴式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_12.jpg)

当页面加载时，这些手风琴标题是关闭的，这样网站用户就可以选择要探索的内容。

![项目：使侧边栏成为手风琴式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_13.jpg)

现在让我们继续进行我们客户的最后一个增强。

## 项目：向下载按钮添加带图标的对话框

对话框是提醒和引导人们注意非常重要信息的好方法，确保他们理解下一步需要采取的步骤，以及确认操作。

我们的客户对主页的选项卡信息和精简的手风琴侧边栏非常满意。他们只需要进行一个增强。主页上的第一个选项卡提供了一个关于他们的方法、产品以及各种用途信息的白皮书的 PDF 下载。正如您可以从下一个截图看到的那样，客户希望用户了解他们正在下载有版权的信息，并且该文档不能自由分发。

正如您可以在接下来的截图中看到的那样，他们在 PDF 文件的下载链接之前放置了一些免责声明语言：

![项目：向下载按钮添加带图标的对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_14.jpg)

一般来说，这就是他们的法律部门声称他们需要的全部，但他们希望更清晰一些。我们可以通过使用按钮小部件使下载过程更加突出，并将以前的 **免责声明** 文本变成对话框来进一步增强这一下载过程。用户随后必须在对话框上选择 **同意** 才能继续 PDF 下载，客户可以放心，通过启用 JavaScript 的浏览器下载他们的白皮书的大多数人肯定意识到免责声明。

首先，让我们设置好将 **免责声明** 文本放在我们的对话框内。我们将定位段落并如下所示应用对话框小部件：

```js
...
//select p that contains the disclaimer text
jQuery("#post-98 p:contains(Disclaimer:)")
.wrapAll("<div id='disclaimer'></div>");
//create the disclaimer dialog widget
jQuery("#disclaimer").dialog();
...

```

如果重新加载页面，您会看到 **免责声明** 文本现在以对话框的形式出现如下：

![项目：为下载按钮添加带图标的对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_15.jpg)

对话框的默认设置是将文本“居中”对齐。对于单行文本来说很好，但我们的段落看起来有点奇怪，所以我们已经向我们的 `.wrapAll` HTML 添加了样式，如下所示：

```js
...wrapAll("<div id='disclaimer' style='text-align:justify'></div>");...

```

接下来，我们真的不希望对话框立即出现，所以我们将其选项 `autoOpen` 设置为 `false`。我们还希望确认按钮出现，以及对话框顶部栏上的标题。对话框小部件还可以容纳按钮，所以我们将它们添加进去，并为其添加功能，如下所示：

```js
...
//create the disclaimer dialog widget
jQuery("#disclaimer").dialog({
//set the dialog to close
autoOpen: false,
//set the title
title: 'Download Agreement',
// set up two buttons
buttons: {
//activates the URL placed in the a href
"I Agree": function() {
//get the URL of the PDF
var pdfFile = jQuery("#post-98 a").attr('href');
//direct the browser to that URL
window.location.href = pdfFile;
},
//close the dialog box
"Close" : function() {
jQuery(this).dialog("close");
}
},
});
...

```

上面的方法效果很好——或者至少我们认为是这样。现在对话框的 `autoOpen` 选项已设置为 `false`，我们无法确定！我们需要 **下载 PDF** 链接来启动对话框，顺便说一句，我们需要确保链接的 `href` 不会触发 PDF 下载。

如果你有在关注，你可能已经准备好使用 `.removeAttr()` 函数从链接中移除 `href` 属性并使其无效。这是一个好主意；然而，在前面的代码片段中，我们引用了链接的 `href` 属性。该引用直到对话框出现后才会触发，这意味着在我们将其从对象中移除之后，我们的 `window.location.href` JavaScript 将不知道要去哪里。

我们最好使用另一个称为 `preventDefault()` 的出色函数，它将保留链接的所有属性，但阻止其像点击链接一样操作。让我们添加这个新的链接功能：

```js
...
jQuery("#post-98 a")
//set up a click function on the link
.click(function(event){
//open the dialog box
jQuery("#disclaimer").dialog("open");
//ensures that the link to the href is disabled
event.preventDefault();
});
...

```

最后，在刷新页面并查看之前，让我们先把 PDF 下载链接变得更“可点击”一点。因为我们使用的是来自 Google CDN 的 jQuery 版本 1.4.2，以及 jQuery UI 插件的 1.8 版本，我们可以通过选择链接并为其添加按钮小部件来实现这一点。

### 注意

如果您没有使用 UI 插件的 1.8 版本，则此步骤是可选的。您可以简单地使用 CSS 样式或 `.css()` 函数来自定义链接的样式。

我们将简单地在现有的链接选择之后 *链式* 使用 `.button()` 小部件函数，*在* `.click()` 函数之后，如下所示：

```js
...
jQuery("#post-98 a")
//set up a click function on the link
.click(function(event){
//open the dialog box
jQuery("#disclaimer").dialog("open");
//ensures that the link to the href is disabled
event.preventDefault();
})
//add the button widget
.button();
...

```

你可以刷新页面并查看新按钮，如下截图所示：

![项目：向带有图标的下载按钮添加对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_16.jpg)

尽管按钮化的链接看起来很棒，但只需稍加努力，再添加一些图标，就可以清楚地表明点击按钮将给人们带来什么，并鼓励他们采取行动。

jQuery UI 插件主题附带一系列 **框架图标**。如果你将 `image` 目录相对于你的 jQuery UI 样式表，你就可以访问它们。

按钮小部件允许将图标放置在“主要”和“次要”位置。主要位置位于按钮左侧，次要位置位于按钮文本之后的右侧。让我们按照以下方式将“circle-arrow-s”图标和“document”图标添加到我们的按钮中：

```js
...
jQuery("#post-98 a")
//set up a click function on the link
.click(function(event){
//open the dialog box
jQuery("#disclaimer").dialog("open");
//ensures that the link to the href is disabled
event.preventDefault();
})
//add the button widget
.button({
//add the icons
icons: {primary:'ui-icon-circle-arrow-s',
secondary:'ui-icon-document'}
});
...

```

一旦人们点击按钮，我们的“标志性”按钮和对话框如下所示：

![项目：向带有图标的下载按钮添加对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_17.jpg)

### 小贴士

想找出小部件可用的图标？请查看主题定制器：[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)。在页面底部，你会看到所有框架图标。将鼠标悬停在它们上面将显示它们的 `title` 标签信息，其中包含你要在 jQuery 语句中引用的名称。

![项目：向带有图标的下载按钮添加对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_18.jpg)

通过此增强功能进行测试的最后一项任务是，点击 **我同意** 将启动下载，如下截图所示，功能正常！

![项目：向带有图标的下载按钮添加对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_06_19.jpg)

这实际上是向网站添加的大量互动性，同时，它也会很好地降级，而且没有 JavaScript 的情况下也能正常工作。这真是很好地利用了 jQuery 和 jQuery UI 插件。

# 总结

这是我们对 jQuery UI 插件的看法，以及它如何真正有益于 WordPress 网站的一些方式。有数十种，甚至数百种方法，这取决于你的站点或项目及其需求。

请记住，jQuery 在客户端、浏览器中运行，WordPress 为浏览器提供成品 HTML 页面。这意味着你不仅可以增强 WordPress 内容，还可以增强大多数 WordPress 插件，例如 cforms II，大多数边栏小部件应该很容易通过 jQuery 和 jQuery UI 插件来增强。

在本章中，我们看到了：

+   UI 插件及各种在 WordPress 中包含它并开始使用它的方法

+   理解将 UI 元素应用于我们的 WordPress 网站如何使其更直观、更易理解，并鼓励用户采取行动。

+   使用常见的 WordPress 功能实现流行的 UI 功能的常见方法

现在让我们继续下一章，看看如何使用 jQuery 来帮助我们创建 AJAX 交互。
