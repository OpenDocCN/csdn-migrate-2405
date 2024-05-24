# WordPress3 和 jQuery（三）

> 原文：[`zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8`](https://zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 jQuery 和 WordPress 进行 AJAX

AJAX 是 *杰西·詹姆斯·加勒特* 在 2005 年创立的用户体验专家，他是[www.AdaptivePath.com](http://www.AdaptivePath.com)的创始人，AJAX 是一个缩写词。 它很快就变成了一个流行词，其描述性（以及动词性）远远超出了其实际缩写定义。 我们将快速了解 AJAX 究竟是什么，以及它有多容易实现，更不用说为我们的“假想”客户想出更多酷炫的解决方案。

在本章中，我们将重点讨论以下内容：

+   使用 jQuery 的 AJAX `.load()` 函数和更健壮的 `.ajax()` 函数的基础知识

+   使用 JSON 和连接到其他站点的 API

+   创建自定义 AJAX 增强首页和评论表单

+   使用动画和事件来优化该功能

让我们开始看看 jQuery 为 AJAX 做了什么。

# AJAX 是什么，不是什么：一个快速入门

首先，如果您对 AJAX 不熟悉，我只想指出 **AJAX** 其实并不是一种技术或语言！ 这个缩写代表 **Asynchronous JavaScript and XML**。 它是使用 JavaScript 和 XML 在 Web 浏览器和 Web 服务器之间发送和接收数据的技术。 这种技术最明显（也是最酷的）的用途是，您可以通过调用服务器动态更新网页上的一部分内容，而无需重新加载整个页面。

此技术的实施使许多 Web 开发人员明白他们可以开始创建高级 Web 应用程序（有时称为 **Rich Interface Applications(RIAs)**），这些应用程序的工作方式和感觉更像是桌面软件应用程序，而不是网页。

如上所述，AJAX 这个词开始拥有自己的含义（正如您在本书和其他书籍中偶尔看到的一样，以及网络上到处都是的正式名词：“Ajax”，而不是全大写的缩写）。 例如，一个主要使用 Microsoft 技术的 Web 开发人员可能会使用名为 VBScript 的浏览器脚本语言，而不是 JavaScript，来对内容进行排序和显示，这些内容转换成了称为 JSON 的轻量级数据格式，而不是 XML。 你猜对了，该开发人员的站点仍然会被视为 AJAX 站点，而不是 “AVAJ” 站点（承认吧，AJAX 听起来更酷）。

实际上，正如我们在 第五章 中所指出的 *jQuery Animation within WordPress*，现在几乎网站上的任何东西（不是 Flash 中的）都会被视为“具有 AJAX 特性”的网站，包括滑动、移动、淡入、弹出而不会渲染新的浏览器窗口。 实际上，大多数这样的网站并不真正符合使用 AJAX 的标准，如果你在 WordPress 站点中仅使用本书中的几个 jQuery 示例，它可能会被认为是具有 AJAX 特性的，尽管没有异步调用服务器。 但在本章之后，它将是。

# AJAX：使用 jQuery 更好

在过去，当我为 AJAX 撰写介绍或者与我的客户讨论在他们的项目中使用 AJAX 的利弊时，我过去常常为使用 AJAX 技术提供长篇的、深入的免责声明和警告：讲述最坏情况的故事和对于特殊需求用户而言丧失的浏览器功能，更不用说破坏了可访问性。虽然其中一些担忧仍然存在，但使用 jQuery 的“实施恐惧”基本上已经消失了。

就像我们到目前为止学到的所有 jQuery 东西一样，重点是创建出色的*增强功能*，逐渐降级到基本的、可工作的 HTML 功能。只要以 jQuery 深思熟虑地实现了 AJAX 技术，你会发现同样适用。如果你的网站的核心内容或功能可以在浏览器中启用 JavaScript 的情况下访问和检索，你会发现所有用户，无论他们的浏览器或可访问性要求是什么，都应该能够享受你的内容并有效地使用你的网站。你的大部分用户将能够使用你的网站，并且能够使用使网站更易于使用并且甚至可以帮助理解内容的时髦、视觉上令人愉悦的增强功能。

## 评估 AJAX 是否适合你的网站——一个较短的免责声明

当然，除了可访问性和合规性之外，还有一些考虑因素要考虑你网站的用户。尤其是，当你开始意识到 AJAX 技术可以为你的网站带来的强大功能时，你将希望努力遵守*标准网络实践的惯例*。基本上，大多数网络用户希望网页，即使是非常酷的网页，都简单地像网页一样运行！

这并不意味着你不能打破标准惯例，尤其是如果你的网站更像是一个 RIA 而不是一个纯内容网站。只要确保你告诉用户可以期待什么。例如，如果导航面板不在网站的顶部或侧边栏，你需要找到一些方法提前告诉人们它在哪里以及为什么你认为将其放置在那里更加方便。如果你使用的不是下划线和按钮框之类的不同指示符来指示可点击对象，告诉人们要寻找什么，这样他们就知道什么是可点击的，什么是不可点击的。

话虽如此，让我们来看看我们最新一批假设客户向我们提出了什么问题，并开始工作。

# 开始使用 jQuery 的 AJAX 功能

jQuery 的 AJAX 功能的核心是`.ajax()`函数。这个小家伙让你能够完成一些繁重的工作，并且为你所有的**XML HTTP 请求** (**XHR**) 需求提供了一切。

对于那些有一点 AJAX 经验的人来说，你会高兴地发现，这个函数符合 jQuery 的真正形式，它消除了设置传统的`if/else`语句来测试对`XMLHTTPRequest`对象的支持以及如果没有的话，则是对`ActiveXObject`（对于 IE 浏览器）的需要。

## 使用`.ajax()`函数

让我们快速看一下`.ajax`调用中可用的一些功能：

```js
jQuery.ajax({
type: //"GET" or "POST",
url: //"url/to/file.php",
dataType: //"script", "xml", "json", or "html"
data: //a query string "name=FileName&type=PDF"
beforeSend://a callback function
function(){
alert("Starting Request");
}
success: //a callback function
function(){
alert("Request successful");
}
complete: //a callback function
function(){
alert("Request complete");
}
error: //a callback function
function(){
alert("Request returned and error!");
}
});
...

```

例如，在 WordPress 中实现，一个`.ajax()`调用可能是这样的：

```js
...
jQuery(".ajaxIt").click(function(){
//.ajaxIt is a class assigned to link in the first post
jQuery.ajax({
//url to the about page:
url: "/wp-jquery/about/",
data: "html",
success: function(data){
//limit the overflow and height on the first post
jQuery('.post:first')
.css({overflow: "hidden", height: "310px"})
//add in the data
.html(data);
//alert just shows the function kicked off
alert('loaded up content');
}
});
});
...

```

在给定的代码中，当用户在下一张截图中看到的那样点击`.ajaxIt`对象的 jQuery 选择器时，`.ajax`函数将整个**关于**页面加载到第一篇文章的`.post` div 中：

![使用`.ajax()`函数](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_01.jpg)

通过改变 div 上的 CSS 属性来隐藏溢出并设置高度，我们可以避免它看起来太凌乱：

![使用`.ajax()`函数](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_02.jpg)

就是这样！这是你在 WordPress 中使用 AJAX 的第一次！不过，你可能会想：“为了某事我在现实生活中可能并不想做的事情，这也太费事了。（将整个网站重新加载到一个包括头部在内的 div 中？呃！）”

你说得对。让我们来看看如何在一些更易访问和更有用的功能上快捷操作。

### 缩短路径

你可以看到`.ajax()`函数相当强大和灵活。尽管它很酷，但你可能已经希望有一个快捷方式。不用担心，与我们已经使用过的`.animate()`函数类似，jQuery 已经很好地将一些更“常规”的任务分解成了更易于使用和利用的小函数。以下是对 WordPress 用户最重要的几个：

+   `.load`—你可以通过这个函数进行 POST 和 GET 调用，然后从中提取特定的、经过 jQuery 选择的内容，并将其轻松地塞进其他 jQuery 选择的区域。

+   `.get`—和`.load`类似，但只执行 get 请求。

+   `.post`—和`.load`一样，但专注于 POST 请求。

+   `.getJSON`—允许你拉取 JSON 数据（如果你进行跨站点脚本编写，即从其他 URL 中拉取数据，比如`twitter.com`，那么这是一个好方法）。

+   `.getScript`—允许你启动一个不附加到你的 WordPress 主题的脚本中隐藏的操作。（如果您想添加不希望其他人轻易找到和搜索的功能，这将非常有用，您还可以从其他域中引入 JavaScript 以进行操作。）

在大多数 WordPress 项目中，你会发现你根本不需要使用`.ajax()`函数。你会使用`.load, .post`或`.get`，有时是`.getJSON`或`.getScript`。但是，就像`.animate()`函数一样，偶尔会出现需要`.ajax`函数的灵活性和细粒度控制的情况。

所有这些快捷功能中最有用的，也是我们将重点关注的功能是`.load`函数。

### 指定`.load()`位置

我们可以通过这里简化的代码获得我们在完整的`.ajax()`函数中得到的完全相同的效果：

```js
...
jQuery('.post:first').css({overflow: "hidden",
height: "310px"}).load('about-2/');
...

```

再次，有点酷，代码片段变得简单多了。这就是 AJAX；页面本身不重新加载，但为什么你*想*要这样做呢？（为了避免示例太凌乱，我使用了 `.css` 函数来改变 CSS 属性，隐藏溢出和锁定 `.post` div 的高度。）

这似乎很少有项目会对这有用（如果有用的话，一个`iframe`会实现相同的效果）。我们真正想做的是能够将另一页中的关键内容加载到我们当前页面中。好消息是，我们可以很容易实现：

```js
...
jQuery('.post:first').load('about-2/ #post-104');
...

```

通过扩展 `.load` 函数的 `url` 参数，给定的代码片段将用关于页面**关于**的 `#post-104` div 的内容替换我们的第一个 `.post` div。结果是这样的：

![指定.load()它的位置](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_03.jpg)

你还会注意到我能够删除 `.css` 函数，因为只有有用的内容被加载进来，清爽而干净。

### 转换加载的内容

假设我们需要转换一些我们加载进来的内容。没问题。有一个基本的“成功”回调函数可用。我们可以这样利用它：

```js
...
jQuery('.post:first').load('about-2/ #post-104', function(){
jQuery('h3').css("color","#ff6600");
jQuery('#post-104 p:first').css("font-weight","bold");
});
...

```

![转换加载内容.ajax()函数，使用.load 函数，使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_04.jpg)

正如你所看到的，内容现在“成为”了我们页面的一部分，并且在 ajaxed 内容中被更改的 DOM 对象集，以及页面上的其他选定匹配项（例如 h3），也随之改变。现在这似乎更有用。我打赌你可以想出很多像这样的功能用途！猜猜——我们的“客户”也可以。

# 项目：使帖子 AJAX 化

假设你有一个客户（放松，这是*最后*一个假设的客户！），他是一位“开源媒体设计师”，想要一个非常简洁和稀少的首页。如此稀少，他只想让两个特定类别中最新帖子的标题列表出现。（在理想的世界中，像这样的决定将确保他们网站出色的设计能在用户面前沉淀下来，然后再向他们提供内容。）

他们当然想要它看起来漂亮。当你点击一篇文章的标题时，它会通过 AJAX 加载，非常流畅。没有重新加载到单独的内容页面。

要开始处理这个请求，我们必须参考我们对模板层次结构和自定义循环的理解。我们将创建一个 `home.php` 模板页面，它将成为默认的主页，仅显示 "WordPress 设计" 和 "Inkscape 插图" 类别中最近的五篇帖子。听起来很简单，让我们开始吧。

首先创建一个名为 `home.php` 的新自定义模板页面，并插入你的 `#content` div 标记以及主题的页眉和页脚（以及其他任何你想要的内容）。

```js
<?php get_header(); ?>
<div id="content" role="main">
</div><!--//content-->
<?php get_footer(); ?>

```

接下来，在我们的 `#content` div 内部，我们将放置加载"WordPress 主题"和"Inkscape 插图"类别的自定义循环。我们知道类别 ID 分别为 `5` 和 `6` ，因此我们的自定义"迷你循环"看起来是这样的：

```js
...
<div style="float:left; width: 380px;">
<h2>What's new in WordPress Themes:</h2>
<ul>
<?php global $post;
$wpposts = get_posts('numberposts=5&category=6');
foreach($wpposts as $post):
setup_postdata($post);?>
<li><a href="<?php the_permalink() ?>">
<?php the_title(); ?></a></li>
<?php endforeach; ?>
</ul>
</div>
<div style="float:right; width: 380px;">
<h2>Inkscape: Draw freely covers it all</h2>
<ul>
<?php global $post;
$inkposts = get_posts('numberposts=5&category=7');
foreach($inkposts as $post):
setup_postdata($post);?>
<li><a href="<?php the_permalink() ?>">
<?php the_title(); ?></a></li>
<?php endforeach; ?>
</ul>
</div>
<div style="clear:both;">&nbsp;</div>
...

```

自定义循环将导致一个看起来像这样的页面：

![项目：Ajax 化帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_05.jpg)

因为我们设置了我们的循环以在单页布局的 `href` 链接内显示标题，如果我们在 WordPress 中检查到目前为止的内容，我们将看到帖子标题，如果点击它们，我们将被带到完整的帖子页面，如下一个截图所示：

![项目：Ajax 化帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_06.jpg)

这就是我们想要的。如果用户由于任何原因未启用 JavaScript，则站点仍将正常工作并向他们提供所需的信息。这总是我们使用 jQuery 时要从基础、可工作的 HTML 和 CSS 开始的地方。目标始终是 *增强* 而不是排除那些由于各种原因不使用最新浏览器或没有启用 JavaScript 的酷手机的人。

此时，我们将利用我们在第六章中略微尝试过的技术。我们将“劫持”帖子的链接（这种技术通常称为“劫持”），并在 jQuery 的 `.load` 命令中利用 URL 以获取优势。

首先，我们需要将内容加载到某个地方，因此在我们的 `custom-jquery.js` 文件中，我们将一个新的 `div` 追加到 `#content` div 的底部。

```js
...
jQuery('.home #content').append('<div class="displayPost"></div>');
...

```

现在，正如我们在先前的示例中看到的那样，我们当然不希望加载从开头的 body 标记到结尾的 *所有* 内容！我们真正想要的只是 `.post div`。因此，让我们设置我们的 `.load` 函数并缩小加载内容的范围如下：

```js
...
jQuery('#content li a').click(function(event){
//This keeps the href from reloading the page
event.preventDefault();
//grab the page link
var page = jQuery(this).attr('href');
jQuery('.displayPost')
//use the grabbed link in the load function
.load(page+' .post')
.fadeOut()//fade out the previous content
.slideDown(2000);//slide in the new content
});
...

```

你能相信这是多么简单吗？点击的任何链接都会 *淡出* 加载的内容，并 *滑入* 新内容！我们现在在我们的首页上有了一个非常简单地使用 AJAX 的超级流畅效果。

![项目：Ajax 化帖子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_07.jpg)

# .getJSON：小鸟获得最多转发

如今，Twitter 极其受欢迎，因此已经有大量出色的 jQuery 插件可以连接到它。我个人最喜欢的是：*Damien du Toit* 的 **jQuery Plugin for Twitter：** [`coda.co.za/blog/2008/10/26/jquery-plugin-for-twitter`](http://coda.co.za/blog/2008/10/26/jquery-plugin-for-twitter)。如果你真的想要对你的 Twitter 显示有很好的控制权，那么这个插件绝对不会让你失望。

然而，Twitter 搜索和用户时间线 API 方法对于 JSON 来说相当简单；因此，这对于如何使用 jQuery 的 `.getJSON` 函数进行“快速教程”非常适合。

另外，你猜对了，我们假想的客户认为初始首页布局可能“太稀疏”，询问我们是否可以只添加他们用户名下的三条最新推文。

## JSON 和 jQuery 基础知识

在我们深入了解 Twitter 和其他服务之前，让我们先了解 JSON 的基础知识以及如何与 jQuery 结合使用。

JSON（经常发音为 Jason）是**JavaScript 对象表示法**的首字母缩写。本质上，它是一种简单的机器可读数据交换格式，使在 JavaScript 中构建和处理 API 应用程序变得轻而易举（它也可以与其他编程语言一起使用）。如果您想了解其历史，可以访问[`json.org`](http://json.org)了解更多信息。

### JSON 是什么样的

您会惊喜地发现，JSON 标记语法看起来与您到目前为止在 jQuery 中或与 CSS 一起使用的大多数参数/值语法相同。它基于大多数 C 语言对象表示法，如 Java 和 JavaScript，因此在处理 JavaScript 和 jQuery 时非常方便。

例如，jQuery 的`.css()`函数可以在`{}`大括号内传递多个值，如下所示：

```js
.css({background: '#ff6600', color: '#333333', height: '300px'});

```

以同样的方式，JSON 数据可以设置如下：

```js
{"results":[{"text":"text string here",
"to_user_id":0001,"user_name":"ThunderCat"}]}

```

非常相似对吧！让我们看看如何在 jQuery 中使用它。

### 在 jQuery 中使用 JSON

让我们仔细看看`.getJSON`函数。

```js
jQuery.getJSON(
url, //the location of the data
data, //if you need to send anything to the service POST
function(){
//callbackfunction
}
);
...

```

此函数的第一个参数与`.load`函数非常相似；您将放置您计划阅读的 URL。如果您需要将数据 POST 到 URL（您可以在查询字符串或数组对象中执行此操作），则使用`data`参数。回调函数不是必需的，除非您从自己的服务器以外的服务器调用 URL。

现在让我们看看如何在我们的 WordPress 网站中使用`.getJSON`。

### 使用 .getJSON 与 Twitter

首先，在处理其他服务的 API 时，没有理由不阅读并使用它们的文档。服务经常更新其 API 以使其更好、更快，但连接到它们并使用它们的方法有时会发生变化。要使代码与 API 保持最新有时需要相当多的努力。Twitter 的 API 文档可以在这里找到：[`apiwiki.twitter.com/Twitter-API-Documentation`](http://apiwiki.twitter.com/Twitter-API-Documentation)。

另外，许多 API 服务要求您注册为开发者，并使用 OAuth 使用其中一些或全部服务（或他们自己的身份验证系统来保护您的用户登录和数据）。

### 注意

**OAuth 是什么？**

OAuth 是一种开放标准，允许用户向托管数据的服务提供商提供令牌而不是用户名和密码。许多 API 服务提供商使用它，您可以从他们的网站了解更多信息：[`oauth.net/about/`](http://oauth.net/about/)。

在本节中，我将介绍在 Twitter API 中连接到用户时间线方法的基础知识。只要用户有一个公开可见的 Twitter 流，此方法就不需要 OAuth，因此您不需要注册 OAuth 应用程序（但是注册也不会有害）。

### 使用 Twitter 的用户时间线方法

我们的`.getJSON`函数中的 URL 参数将包含以下 API，格式化的 URL：

```js
http://api.twitter.com/1/statuses/user_timeline/username.format

```

你可以选择以下格式（但猜猜我们将使用哪一个！）：

+   atom

+   **json**

+   rss

+   xml

首先，我们需要将我们的推文放在主页上。

这里我们有两个选项，我们可以进入`home.php`模板文件并创建一个“实际的”`div`和`ul`列表，或者我们可以完全使用 jQuery 创建它。

说实话，这样的调用完全取决于你。在本书的这一部分，你应该已经非常熟悉编辑和调整你的主题文件，或者使用 jQuery 生成有用的 DOM 对象了。

因为推文完全依赖于 JavaScript 的启用，并且我们不试图使用模板标签定制显示任何 WordPress 内容，所以我很乐意在 jQuery 中完成所有工作。

我们将从我们的`custom-jquery.js`文件开始，在文档准备就绪的语句内，像这样创建推文的空间：

```js
...
//we'll want to make sure we add our div to the home page only,
//referencing the WordPress body class .home (make sure your theme is
//using the template tag body_class() in the body HTML tag!)
jQuery('.home #content')
//this .append string is a div, h2 heading, and three list items
//in a ul with a Follow Us link:
.append('<div class="tweets"><h2>Our Tweets:</h2>
<ul><li></li><li></li><li></li></ul>
<p>
<a href="http://twitter.com/ozoopa">Follow Us!</a>
</p></div>');
...

```

接下来，我们将使用我们“客户”的 Twitter API URL 作为一个变量（我们将使用我的其中一个：ozoopa）。

```js
...
var tweetURL = 'http://api.twitter.com/1/statuses/user_timeline/ozoopa.json?callback=?';
...

```

现在我们可以设置我们的`getJSON`调用：

```js
jQuery.getJSON(tweetURL, function(twitter){
//'twitter' is the callback function that returns the tweets
//for each li in the twees class we'll drop in the text
jQuery('.tweets li').each(function(i){
//we only want the tweet text, nothing else
jQuery(this).html(twitter[i].text);
});
});
...

```

正如你在下一张屏幕截图中所看到的，我们的推文显示得非常好！

![使用 Twitter 的用户时间线方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_08.jpg)

#### 推特在发送什么？

我们注意到，我们只专注于获取“推文”文本本身。以下是推特实际通过 JSON 在 URL 中发送的内容（粗体部分是我们实际使用的）：

```js
[{"coordinates":null,"in_reply_to_screen_name":null,"geo":null,"favorited":false,"truncated":false,"in_reply_to_status_id":null,"source":"web","in_reply_to_user_id":null,"contributors":null,"user":{"profile_background_image_url":"http://s.twimg.com/a/1274899949/images/themes/theme1/bg.png","profile_link_color":"0000ff","url":"http://ozoopa.com","description":"","followers_count":14,"profile_background_tile":false,"profile_sidebar_fill_color":"e0ff92","location":"","notifications":null,"friends_count":3,"profile_image_url":"http://s.twimg.com/a/1274899949/images/default_profile_3_normal.png","statuses_count":10,"profile_sidebar_border_color":"87bc44","lang":"en","favourites_count":0,"screen_name":"ozoopa","contributors_enabled":false,"geo_enabled":false,"profile_background_color":"9ae4e8","protected":false,"following":null,"time_zone":"Central Time (US & Canada)","created_at":"Tue Sep 15 21:54:45 +0000 2009","name":"ozoopa open source","verified":false,"profile_text_color":"000000","id":74567461,"utc_offset":-21600},"created_at":"Tue May 11 19:34:09 +0000 2010","id":13805349673,"place":null,"text":"Thanks for the Aptana 2.x install on Ubuntu freedomcreations.com, right up our alley!"}, ...//more tweets follow...]

```

正如你所看到的，你得到了很多数据可以使用！再次强调，深入研究 API 并查看可利用的内容是值得的；你也可以花几个小时尝试显示 JSON 源中可用的各种项目，这也很有趣。

### 使用 Flickr 的 getJSON

客户喜欢它！当然，他们现在认为主页“文字太多”。那么在边栏中添加来自 Flickr 图像标记为`"wordpress theme"`的最新的六张图片如何？这应该平衡一下。

幸运的是，这也不是一个问题。

再次强调，你的首选应该是 Flickr API 文档：[`www.flickr.com/services/api/`](http://www.flickr.com/services/api/)。

但我们将继续开始，在主页边栏中为图像创建一些空间：

```js
...
jQuery('.home).append('<div class="flickr">
<h2>Latest Flickr:</h2></div>');
...

```

这里有他们的公共照片流方法 URL：

```js
...
var flickrURL = 'http://api.flickr.com/services/feeds/photos_public.gne?tags=wordpress,themes&tagmode=all&format=json&jsoncallback=?';
...

```

现在我们可以设置我们的`getJSON`调用：

```js
...
jQuery.getJSON(flickrURL, function(flickrImgs){
jQuery('.flickr li').each(function(i){
jQuery(this)
.html('<img src='+flickrImgs.items[i].media.m+'
width="100" height="100" />');
});
});
...

```

Flickr 的 JSON 字符串返回一个名为`items`的数组，其中提供了各种各样的数据。你会注意到，当定位我们想要的信息时，与 Twitter API 相比，情况有所不同。通过将`media.m`的 URL 拉取到缩略图，我们能够创建一个快速的图像列表。

它看起来像是这样的，在**我们的推文**下面：

![使用 Flickr 的 getJSON](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_09.jpg)

## 提供 JSON 格式的其他受欢迎的服务

乐趣不必止步于此！现在您熟悉了如何使用`.getJSON`，您的世界就可以在您的 WordPress 站点中实现各种自定义跨站混搭和解决方案。理解 JSON 和`.getJSON`函数还使您更能熟练地将良好的 WordPress 或 jQuery 插件"调整"以更好地处理您的定制需求。

以下流行的服务提供带有 JSON 支持的 API：

+   YouTube：[`code.google.com/apis/youtube/2.0/developers_guide_json.html`](http://code.google.com/apis/youtube/2.0/developers_guide_json.html)

+   Netflix：[`developer.netflix.com/`](http://developer.netflix.com/)

+   delicious：[`delicious.com/help/api`](http://delicious.com/help/api)

+   bitly：[`code.google.com/p/bitly-api/wiki/ApiDocumentation`](http://code.google.com/p/bitly-api/wiki/ApiDocumentation)

+   goodreads：[`www.goodreads.com/api`](http://www.goodreads.com/api)

+   LibraryThing：[`www.librarything.com/api`](http://www.librarything.com/api)

环顾四周！如果您使用的优秀服务提供任何类型的"社交"功能，它们可能会提供以 JSON 格式提供数据的 API。您可能需要向该服务注册为开发者，以便验证您的请求（通常使用 OAuth），但如果您得到的最终结果是一个 JSON 字符串，您就可以使用 jQuery 和您的 WordPress 项目了！

# 项目：Ajax-化内置评论表单

从我们到目前为止完成的`.load`和`.getJSON`的工作样本中，您可能会想到许多极其酷的方式来在您的 WordPress 站点中实现 AJAX。其中最有用的应用是评论表单。

首先，我们甚至不需要修改任何模板页面 HTML 或 WordPress 模板标签、PHP 代码。这很棒，因为我们总是希望我们的站点尽可能（实际上是一直）在没有 jQuery 增强的情况下工作。

Ajax 化 WordPress 评论表单其实很简单。对于您这些"高级"主题开发者来说，这是一种吸引人们下载您主题的好方法："内置 AJAX 评论！"。这是我们希望完全控制的东西，因此我们将使用`.ajax()`函数而不是`.load`（看，我告诉过您`.ajax`偶尔会派上用场）。

首先，在尝试评论表单的实验中，我们希望将其 CSS 属性更改为警示用户错误。我发现最好将表单的 CSS 设置为一致的内容，然后可以轻松在 jQuery 中进行其他用途的更改。将以下代码添加到您的`custom-jquery.js`文件中，以更改默认主题评论表单样式的 CSS 属性。

```js
...
jQuery('#commentform input')
.css({border: '1px solid #ccc', padding: '5px'});
jQuery('#commentform textarea')
.css({border: '1px solid #ccc', padding: '5px'});
...

```

现在我们准备"控制"表单。提交后，我们希望我们的 jQuery 发挥作用，而不是表单的"action"属性。因此，我们将使用一个方便的函数叫做`.submit()`，如下所示：

```js
jQuery('#commentform').submit(function(){
//turns all the form info into an object
var formData = jQuery("#commentform").serialize();
//so we can display the comment back to the user
var comment = jQuery('textarea#comment').val();
});
...

```

注意我们使用了另一个方便但不太知名的 jQuery 函数叫 `.serialize()`。这个函数将我们的 `#commentform` 表单中的所有数据在提交时转换为一个方便的对象，现在我们可以将其传递给我们的 `.ajax` 函数。

在 `.submit` 函数内，*在* comment 变量之下，让我们添加我们的 `.ajax` 调用。我们将使用这个函数，因为我们需要一点额外的控制，并且将利用其`success:` 和 `error:` 回调函数。阅读代码中粗体注释以跟随：

```js
...
jQuery.ajax({
type: "POST",
//this is the script that the comment form submits to:
url: "/wp-jqury/wp-comments-post.php",
//formData is our serialized content object
data: formData,
success: function(){
//on success load content and fade in:
},
error: function(){
//on error, inform user of what to do:
}
});
//this makes sure the page doesn't reload!
return false;
...

```

这就是要点。我们现在准备通过设置 `success:` 和 `error:` 函数来开始工作。让我们从 `success:` 函数开始。

我们首先要创建一个包含消息的 `div`。然后，我们将我们的消息添加到该 div 中，以及我们稍早设置的 `comment` 变量（在我们的 `formData` 序列化对象之下）来将表单中输入的评论拉入我们的代码中。

我们还会确保添加一点 jQuery 的“闪光”，并利用 第五章 中的一些动画技巧，*在 WordPress 中使用 jQuery 动画*，以确保`success`响应加载得顺畅而漂亮。*在* `success: function()` 大括号内，插入以下代码：

```js
...
//on success load content and fade in:
//create the div that the message goes in
jQuery('#respond').prepend('<div class="message"></div>');
jQuery('#respond .message')
.html("<div style='border: 1px solid #ccc; padding: 5px 10px'>
<b>Thank you.</b><br/>
<span style='font-size: 90%;'>
<i>Your comment may be pending moderation.</i>
</span><br/> "+comment+"</div>")
.hide() //then hide it!
.fadeIn(2000); //then fade it in nicely
...

```

当表单填写正确时，最终结果是这样一个淡入的消息：

![项目：将内置评论表单转为 Ajax](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_10.jpg)

现在我们准备处理那些没有正确填写表单的人。如果必填字段没有填写，`wp-comments-post.php` 文件会抛出一个错误。我们可以利用这一点，只需使用 `error:` 函数检查错误即可。

![项目：将内置评论表单转为 Ajax](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_07_11.jpg)

Nice，我们刚刚使用 AJAX 为我们的 WordPress 站点创建了一些流畅的评论功能！

### 小贴士

**难道这些例子中应该有一些是 WordPress 插件吗？**

如 第三章 所述，*深入挖掘：理解 jQuery 和 WordPress*，如果你创建了一个不需要对 WordPress 主题进行任何调整或编辑，并且适用于大多数公开发布的主题的 jQuery 增强功能，你可能需要考虑将你的脚本打包成一个单独的 WordPress 插件。

如果你很忙，不想每次更换主题时都要修改新主题的所有自定义 jQuery 脚本，或者如果你是一个较大项目的一部分，有很多人，或者你只是想与不太懂技术的 WordPress 用户分享你的 jQuery 工作，那么这是一个方便的做法。按照 第三章 中的步骤，将你的 jQuery 脚本和插件打包成简单的 WordPress 插件，以便任何不太懂技术的管理员可以轻松地将它们添加到他们的项目中或将其移除。

还要记住，第三章也向您展示了如何创建 jQuery 插件。你可能可以通过将代码放入一个 jQuery 插件中，然后将其包装成一个 WordPress 插件来压缩和清理你的代码。这样也可以更轻松地管理脚本的更新和增强功能。然后，你将拥有更好组织的代码，可以与两个世界分享和共享：jQuery 开发人员和 WordPress 爱好者。

不过想想看：如果一个 jQuery 增强功能*依赖于*你编辑主题生成的任何自定义特殊标记（例如我们在本章开头的文章列表示例），最好将该 jQuery 脚本作为主题的一部分留下，因为它在外部无法正常工作。这对于超级自定义或高级主题来说是一件好事。通过将您的增强功能作为主题的一部分，您可以吸引人们下载它，因为它提供了他们无需再去寻找单独的 WordPress 插件的功能。

# 概要

谁知道 AJAX 如此容易呢？正如你所看到的，利用 WordPress 主题的优势和 jQuery 的 AJAX 事件和请求，可以非常容易地创建一些功能强大的动态站点。在本章中，我们了解了以下内容：

+   创建自定义加载内容并劫持（hijack）链接以按照我们的意愿操作

+   使用`.getJSON`和其他站点的 API

+   创建我们自己的自定义 AJAX 加载评论表单（可能是 WordPress 站点所有者最受欢迎的增强主题功能和插件之一）

+   进一步增强我们的 AJAX 工作，使用简单的 jQuery 动画功能

现在你已经了解了如何将 jQuery 应用于 WordPress 站点的特定增强功能和特性。我们从基础知识开始，真正学习了如何利用选择器，以便您的 WordPress 编辑工作流程不必中断，并将其应用于一些非常令人兴奋的增强功能，包括流畅的动画、UI 插件和 AJAX。我们还介绍了如何将这些解决方案集成到 WordPress 站点的主题、WordPress 插件以及 jQuery 插件中。对于你大多数的 WordPress 和 jQuery 开发需求，你已经准备好了！

在下一章中，我们将看一些与 jQuery 和 WordPress 一起工作的技巧和诀窍；本书的最后附录是一个精简的“速查表”，包含关键的 jQuery 函数以及重要的 WordPress 函数和模板标记和类，都是为了帮助您进行 jQuery 和 WordPress 的开发。


# 第八章：jQuery 与 WordPress 工作的技巧和诀窍

您现在已准备好将您的 jQuery 知识应用到 WordPress 的世界中。但首先，让我们看看本章将涵盖的内容：

+   适当加载我们的 jQuery 脚本的技巧和诀窍，确保它们与其他脚本、库和插件兼容

+   一些使用 Firefox 和 Firebug 以加速和帮助您 jQuery 开发的技巧和诀窍

+   有效的 WordPress 标记的优点以及如何让网站的内容编辑人员更轻松

以下是使用 jQuery 和 WordPress 所需的技巧和诀窍。

# 保持一个代码武器库

“片段集合”，或者我称之为“代码武器库”，将帮助您大有作为，不仅仅是与 jQuery 和 WordPress 代码相关，还可以帮助您处理一般 HTML 标记甚至您创建的 CSS 解决方案，更不用说您工作的其他任何代码语言了。

我很不擅长记住代码，标记和 CSS 的语法。我经常知道我需要什么，但从来不记得应该如何正确地编写。我过去常常花费数小时查看以前项目的各种样式表，标记和代码，将它们复制到我当前的项目中，还要不断地在网页上搜索（并“再次搜索”）我需要的语法示例。

如果您经常发现自己处于类似情况，常用的 HTML/代码编辑器中通常具备的“片段”或“剪辑”功能将为您摆脱这个乏味（和非常耗时）的任务。您只需在编辑器中的“片段”或“剪辑”面板中键入或粘贴 WordPress 模板标签，功能，PHP 代码，关键的 CSS 规则和 jQuery 函数（以及您发现最需要使用的任何其他代码语法），应用程序会为您保存它，以备将来使用。

当您参与不同的项目时，您可能会提出您可能希望在将来再次使用的解决方案，比如，用于无序列表的一组 CSS 规则，以使之成为一个漂亮的画廊视图，或两个 jQuery 函数的非常巧妙的使用。每当您创建您认为可能会派上用场的东西（它确实会再次派上用场），请务必立即保存它，供将来参考。

诸如 Dreamweaver、HTML-Kit 和 Coda 等优秀的编辑器通常具有组织片段的功能，可使它们逻辑分组，易于访问。一些编辑器甚至允许您分配自定义的“键快捷键”，或直接将片段拖放到您的工作文件中。多么简单呀！

## 解放您的武器库

一旦你发现这有多方便，你可能想要让你的工具箱在你使用的其他程序中也可用，特别是如果你在多个编辑器和创作环境之间切换。我建议你投资一个多剪贴板应用程序，它可以让你保存和组织你的代码片段。当我使用 PC 时，我用了一个叫做 Yankee Clipper 3 的很棒的小应用（免费，网址是 [`www.intelexual.com/products/YC3/`](http://www.intelexual.com/products/YC3/)），现在在 Mac 上，我使用 iPaste（价格适中；网址是 [`www.iggsoftware.com/ipaste/`](http://www.iggsoftware.com/ipaste/)）。除了可以从任何应用程序方便地使用你的工具箱之外，当你在项目上工作时，能够回溯最近复制到剪贴板的大约 10 个项目，真的可以节省时间。

## 你的随身工具箱

最后，我发现我喜欢随身携带大部分工具。如果你使用手持设备或者有一个笔记应用程序，可以让你对笔记进行分类和搜索（尤其是那种可以从桌面或网络服务同步的应用程序），你可能会发现把你的部分或所有工具箱都放在其中是很有用的，这样你可以随时轻松查找你的工具箱中的语法。我偶尔会在需要我使用他们的计算机而不是我的笔记本电脑的地方做自由职业工作，所以在我的设备上访问我的工具箱非常有用。

多年来，Palm 的原生笔记应用非常适合我；现在我把大部分工具都存放在 Google 文档中，并使用一个名叫 NoteSync 的小桌面应用，它让你可以快速写作和查看 Google 文档的笔记（他们很快就会推出安卓应用，但目前我在安卓设备上使用 Gdocs 来查看我的笔记）。我有很多朋友都对 EverNote 的系统赞不绝口（尽管他们的移动应用目前仅在 iPhone 上离线可用，而在安卓上尚未支持）。

一旦你所有经常使用的和创造性的一次性解决方案都位于一个方便的（希望是分类和关键字可搜索的）地方，你会惊讶于你的开发速度提高了多少，以及这样做会让你的开发更加轻松。

# 在 WordPress 中使用 jQuery 的技巧和诀窍

让我们先来谈谈我喜欢的一些 jQuery 技巧和诀窍，然后再关注 WordPress。这些项目中的大多数已经在书中详细讨论过了，这是为了提醒你它们很重要（在某种程度上，这是第一个“提示”，不要省略基本要点）。这里还有一些尚未涵盖的小贴士，将帮助你加快 jQuery 开发速度。

## 尝试使用最新版本的 jQuery

这是使用捆绑的 WordPress 版本的缺点之一：它可能会落后于当前版本的 jQuery，直到下一个 WordPress 版本出来为止。我完全赞成保持在最新版本上，因为 jQuery 版本发布的主要目标不仅是提供新功能，而且不断简化和改进现有功能的性能和速度。如果 CDN 上提供的最新版本的 jQuery 大于捆绑的版本，请务必先`deregister` jQuery，或者使用我们在第三章学到的`if else`语句限制您的新版本，以便它仅在所需页面上的站点前端加载。否则，您可能会在使用捆绑的 WordPress 版本的插件中出现问题。

### 与谷歌 CDN 保持最新

保持最新的最佳方式就是简单地使用谷歌的 CDN。我在第二章和附录 A 中介绍了这一点。这里还有从谷歌 CDN 加载的额外优势。您的站点可以同时从谷歌 CDN 加载主要库以及其他本地 jQuery 脚本和附件，而不必从您的服务器一次加载 JavaScript、库和资源。好处是对于访问过其他加载自谷歌 CDN 的站点的用户，jQuery 将被缓存。务必查看附录 A，获取有关`wp_enque_script`的完整参考。

## 保持在**无冲突**模式下

WordPress 的一个伟大之处在于一个站点可以有很多人以许多不同的方式为其做贡献：撰写内容、工作在主题上，并添加 WordPress 插件。WordPress 的一个最糟糕之处在于，许多人可以轻松地根据他们的管理员状态为站点做出贡献，一些其他的合作者可以向他们添加，或者他们可以安装什么样的插件。

对于 WordPress 来说，保持在**无冲突**模式下是必须的。这与使用`wp_enque_script`来在 WordPress 中加载确保 jQuery 不会被“挤出”是一起的，如果有人加载任何其他使用 MooTools 或 Scriptaculous 或甚至只是旧版本 jQuery 的插件。

保持在`noConflict`模式下很容易。最简单的方法就是我们在整本书中一直在做的！只需在脚本前使用`jQuery`，而不是快捷符号`$`。

```js
jQuery('.selector').function();

```

## 确保主题或插件中的其他脚本使用 Script API

如果你正在使用第三方的主题或插件，请浏览主题的 `header.php` 文件或插件的 PHP 页面，并仔细检查所有的脚本是否已经使用 `register` 和 `wp_enqueu_script` 方法加载。我曾经遇到过一些相当令人沮丧的情况，导致一些头发被拔掉，因为我们试图弄清楚为什么我的 jQuery 脚本无法工作，或者想知道我是如何在将它们转移到现场时"破坏"它们的。事实证明，现场网站安装了一个我的沙箱网站没有的插件，并且你猜对了，该插件包含了一个旧版本的 jQuery 和一个使用硬编码 `script` 标签而不是 `wp_enqueue_script` 方法的自定义脚本文件。一旦这个问题被找到并解决了，将所有东西设置为 `noConflict` 模式，一切都恢复正常了！

## 检查你的 jQuery 语法

这个总是让我困扰。你编写了一个漂亮的 jQuery 链，对它进行了一些调整，然后这该死的东西就停止工作了。而且你知道它是对的！嗯，至少，你认为它是对的。对吧？这就是一个好的代码编辑器派上用场的地方。你会希望有一些不错的**查找**功能，让你逐步查看并查看每一个返回的**查找**，以及让你不仅可以对整个文档进行查找，还可以对单个选择进行查找。我喜欢选择 "有问题的链" 并对其运行以下**查找**功能，看看会出现什么情况。

### 冒号和分号

对于 `:`（冒号）进行**查找**，你可能会发现一些意外地设置为`;`（分号）在你的函数的各种对象参数中，或者你可能在应该是分号的地方输入了冒号。

### `闭合括号`

我还会运行一次对于闭合括号 `)` 的**查找**，并确保每一个出现的括号都是一个持续的链的一部分，或者是用 `;` 标记的链的结束。

### 不匹配的双引号和单引号

最后，快速检查匹配的单引号和双引号有时会显示我哪里搞错了。Panic's Coda 允许你在**查找**中放入"通配符"，因此搜索 `"'*` 或 `'*"'` 通常会发现一个讨厌的问题。

大多数优秀的代码编辑器都有颜色编码语法，这在识别语法错误时非常有帮助，比如根本没有闭合引号或括号。但是，上面的问题往往很棘手，因为它们通常会显示为正确的颜色编码语法，所以在运行脚本之前你不知道有什么问题。

## 使用 Firefox 和 Firebug 来帮助调试

`Firebug 有一个名为“控制台日志”的功能。在我看来，这是 Firebug 的众多优秀功能之一。多年来，我经常借助 JavaScript 的“alert”语句来尝试显示“内部”工作，但 Firebug 控制台处理的远不止于此。这真的很有用，因为有时您必须调试“实时”站点，并设置 JavaScript 警报有点冒险，因为您可能会使站点的访问者感到困惑。使用 Firebug 的控制台日志可以消除这种困惑。`

`首先，有 `console.log` 和 `console.info` 语句，您可以将它们添加到您的 jQuery 脚本中，以将信息传递给您，并返回有关您的脚本的大量有用（有时是不那么有用，但有趣的）信息。`

``console.profile` 和 `console.time` 对于测量浏览器处理脚本的速度非常有用。`

`要全面了解 Firebug 控制台的所有功能，请查看：[`www.getfirebug.com/logging`](http://www.getfirebug.com/logging)。`

## `了解 jQuery 对 DOM 的影响`

`再爱 Firefox 也不为过，尽管我喜欢 Opera 和 Chrome，但是当我无法选择页面上的文本和对象，并右键单击**查看选定的源**时，我感到无助和盲目。`

`如果您的 jQuery 脚本在运行时动态创建了新的 DOM 对象或者在操作对象，则右键单击**查看页面源代码**将仅显示服务器提供的内容，而不会显示 jQuery 和 JavaScript 在浏览器中创建的内容。`

`这是一个很好、快速且简单的方法，可以查看 jQuery 是否添加了该类，或者是否将所选元素包装在您的新 div 中。选择由 jQuery 生成的内容或者应该受到您的 jQuery 脚本影响的内容，并右键单击**查看选定的源**以查看 DOM 中实际内容。`

`![了解 jQuery 对 DOM 的影响](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_08_01.jpg)`

#### `Web 开发工具包：查看生成的源代码`

`如果您发现必须进行选择限制，并且希望查看整个“生成的”源代码是什么样子，您可以使用 Web 开发工具包来查看 jQuery 影响的页面。`

`![Web 开发工具包：查看生成的源代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_08_02.jpg)`

#### `查看 Firebug 的视图`

`查看 DOM 中生成的 HTML 对象的最可靠方式来自于使用 Firebug 的**HTML**视图。通过选择**HTML**标签以及**单击页面中的元素以检查**标签，您可以在 HTML 视图中将鼠标悬停在任何元素上，并立即查看其在嵌套下拉对象中的外观。`

`起初，我发现这个视图有点繁琐，因为我通常只是试图确认新对象或操作的属性是否存在，但我很快就习惯了它的强大之处，它能帮助我调试 jQuery 脚本，我们将在下一个提示中看到，甚至编写选择器。`

`![查看 Firebug 的视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_08_03.jpg)`

## `编写优秀选择器的技巧`

如果你碰巧只是浏览或跳过了第二章，*在 WordPress 中使用 jQuery（或者还没有看过的话）*，你会想要回去仔细复习一下。你还会发现接下来的附录有顶级“备忘单”选择器过滤器要点，一旦你了解了选择器的基本原理，这会很有帮助。

熟悉了你的选择器意味着你能够用 jQuery 做任何你想做的事情。真的！我还没有遇到过必须推迟回到 WordPress 内容编辑器的问题。但有时当涉及开始我的 jQuery 脚本时，定位我需要的选择器可能会有一点挑战，特别是当与一个陌生的自定义主题一起工作时。

再次，Firebug 拯救。还记得我们之前用 HTML 视图的技巧吗？你可以使用那个视图来选择你想要用 jQuery 影响的内容，并轻松看到如何为其构建一个选择器。

例如，看一下以下截图的高亮区域：

![编写出色选择器的提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_08_04.jpg)

如果我们想选择那个段落`<p>`标签，很明显我们只需编写我们的 jQuery 选择器：

```js
jQuery('**.entry p**')... 
```

我们还可以看到，我们可以更具体地定位 id 为`#post-125`，如果我们只想影响那个特定的帖子中的`<p>`标签。通过点击显示 ID 和类名层次结构的顶部区域中的特定类或 ID，它将扩展具有该类或 ID 的对象，这样我们就可以完全看到我们的选项。例如，我们也可以定位`category-inkscape-illustration`中的段落。

![编写出色选择器的提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_08_05.jpg)

### 不要忘记你的选择过滤器！

记住：有时候告诉 jQuery 你不想选择什么使用`:not`过滤器，或者告诉它你特别想选择什么，比如`:first`或`:has()`过滤器。附录 A,"jQuery 和 WordPress 参考指南" 中有关于在 WordPress 中使用的最佳选择器过滤器概述，当然，第二章，“在 WordPress 中使用 jQuery”，有一个全面的列表和示例集。

就是这样。简单易懂的 jQuery 选择器！你在使用 jQuery 选择方面越有经验，你会发现生成你自己的 HTML 和对象来辅助你的 jQuery 增强会更容易。这很有用，因为我们的下一个技巧是让网站的编辑者简化一切。

## 让 WordPress 编辑器的工作流“流畅”

几年前，当我第一次开始使用其他知名的 JavaScript 库时，我发现它们对于我自己编写的项目或前端界面项目非常有用，但是在像 WordPress 这样的 CMS 网站上实现它们及其插件通常令人失望。大多数脚本都依赖于向 HTML 中添加特殊的标记或属性。这意味着网站编辑必须知道如何将这些标记添加到他们的文章和页面中，如果他们想要这个功能，而他们大多数人都做不到，导致我面对沮丧的客户，他们不得不推迟回到我或其他网络管理员，只是为了实现内容。

另外，这会增加我的工作量，消耗了我本来可以用来为网站编写其他功能的时间（输入内容到网站的 CMS 中，并不是我喜欢的网站开发的一部分）。jQuery 改变了这一切，使编写增强功能非常容易，这些功能可以轻松地与页面上已有的任何 HTML 一起工作！

尽管如今几乎所有东西都在线上 "云" 上，但大多数人并不擅长 HTML。事实上，随着我们从 Web 2.0 完全进入 Web 3.0，以及更远的未来，越来越少的人会知道任何 HTML，或者根本不需要知道，这是因为有了众多优秀的基于网络的应用程序，如 WordPress 和各种社交网络平台，它们将用户的原始信息组织好，以及样式化和展示给世界。

如果你的增强功能要求用户转到**HTML**视图，并手动添加特殊的标签或属性，那就不是有效的 jQuery 增强！不要这样做！

用户应该能够添加内容并使用内置的**可视化**所见即所得编辑器进行格式化。你，伟大的 jQuery 和 WordPress 开发者，将开发一个与现有 HTML 兼容的解决方案，而不是强加要求，你的客户和编辑将为此而惊叹，并永远爱你。

### 但是我的 jQ 脚本或插件需要具体的元素！

正如我们在本书的几章中所看到的，事实上，你的 jQuery 插件可能需要 DOM 中存在某些元素才能将内容转换为小部件或交互。

记住这件事：*如果 HTML 元素可以构建以使增强功能正常工作，你可以使用 jQuery 在 DOM 中动态创建这些 HTML 元素*。你不必强迫你的客户在编辑器中创建它们！

查看我们在第六章中的工作，*WordPress 和 jQuery 的 UI*，使用 UI 插件，我们将简单的基本`h3`标题和段落动态包装在适当的 jQueryUI 标签小部件中。或者，甚至在之前的第五章中，*WordPress 中的 jQuery 动画*，我们拿客户的独特帖子文本（与 HTML 没有任何关系！）并且能够用它构建一个可爱的动画图表。

`jQuery 的核心在于选择器，这是真实的。有时，要开始工作，您需要首先选择清晰而独特的内容！在进行增强时与网站的编辑者合作。对于大多数内容编辑者来说，仅需为某些帖子应用唯一的类别或标签即可使增强效果生效，或者甚至手动添加关键字到帖子的标题或以特定方式格式化内容（例如 第五章 中的图表示例，*在 WordPress 中安装 jQuery*）。首先与网站的编辑者一起查看所有这些选项，以确保增强确实对所有人都是增强。`

`# 为最佳 jQuery 增强提供的 WordPress 小贴士和技巧

只是因为您已经掌握了 jQuery 并不意味着您可以忽略在 WordPress 安装中发生的服务器端情况。让我们来看看处理 WordPress 时需要记住的一些关键事项。

## 始终使用 wp_enqueue_script 加载 jQuery，并为自定义脚本的插件使用 wp_register_script。

我们在 第三章 中详细讨论过这一点，*深入了解 jQuery 和 WordPress*，但再次强调，您将希望确保为您所有的 jQuery 加载需求使用 `wp_enqueue_script`。`wp_enqueue_script` 和 `wp_register_script` 是 WordPress 解决多个版本脚本不必要加载或取消其他版本的解决方案。

您可以使用 `wp_enqueue_script` 轻松加载 jQuery 和 WordPress 捆绑的插件，甚至可以从 Google CDN 加载。如果您有自己的自定义脚本，您可以使用 `wp_register_script` 将您的自定义脚本注册到 WordPress 中，然后可以使用 `wp_enqueue_script` 加载它，使其依赖于 jQuery 或其他 jQuery 插件或 JavaScript 库。

附录 A, *jQuery 和 WordPress 参考指南*，向您展示了如何为所有顶级 jQuery 和 WordPress 实现使用 `wp_enqueue_script` 的快速简便方法。

## 始终从基本的、工作正常的“纯 HTML”WordPress 站点开始

我已经说了几百遍了（或者看起来是这样），但游戏的名字是增强。不要编写任何在某种方式下禁用 JavaScript 或不可用时将会中断的内容。大多数 WordPress 主题已经以这种方式工作，显示使用简单的 `http` 调用链接到其他内容页面或锚点名称的内容和链接。如果您正在从头开始开发一个将通过 jQuery 增强的主题，请尽可能完整地开发它，以便在添加 jQuery 增强之前，它可以与基本的 `http` 功能一起正常工作。这将确保您的内容无论通过何种浏览器或设备访问都可以看到。

越来越多的高级主题都内置了 jQuery 和其他 JavaScript 增强功能。你需要在浏览器中关闭 JavaScript，看看在没有增强功能的情况下该内容如何处理。如果网站在没有 JavaScript 的情况下完全“崩溃”并且无法正确显示内容，那取决于你打算部署到哪些设备，你可能不想使用该主题！

## 验证，验证，验证！

如果你的 HTML 不规范或损坏，jQuery 很难进行选择。通常修复方法是修复损坏的 HTML 标记。

验证的最简单方法是转到 [`validator.w3.org/`](http://validator.w3.org/)，如果你的文件在服务器上，你可以直接输入 URL 地址。如果你是在本地工作，从浏览器中，你需要选择 **另存为** 并保存一个 HTML 文件，该文件是项目的 WordPress 输出，并使用提供的上传字段将该完整的 HTML 文件输出上传到验证器。

另外，Firebug 的主控制台视图会自动验证加载到页面上的标记。Firebug 的好处是，你可以选择错误，然后立即跳转到有问题的代码行。我发现 Firebug 对错误的解释比 W3C 的某些网站更容易理解，但是 Firebug 还会发现所有种类的 W3C 没有发现的“小问题”，据我所知，它并不影响我的 jQuery 开发，所以使用 W3C 验证器通常更简单一些。

## 检查你的 PHP 语法

就像 jQuery 语法一样，即使经过多年的经验，小而简单的 PHP 语法错误和拼写错误也总是会让我困扰。

如果你遇到 PHP 错误，大多数情况下 PHP 只会显示错误消息并注明有问题的脚本页面和代码行号，而不会渲染整个页面。这样很容易找到并修复 PHP 问题。

仍然可能存在一个 PHP 语法问题，而不会抛出错误。如果你已经检查了其他所有内容，请快速浏览以下关于 PHP 经常出现的常见问题。

### PHP 速记法

双重检查，确保你没有使用任何 PHP 的速记法。确保你有开启和闭合的 `<?php ?>` 括号，并确保在第一个括号后面有 `php`。有些系统没有开启速记法，你在沙盒托管服务器或本地服务器上运行的内容可能在实际服务器上无法运行。避免使用 PHP 的速记法以防止此类问题。

### 检查是否有适当的分号

与 jQuery 一样，因为语法相似，你最好使用代码编辑器的**查找**功能，双重检查语句结束的分号是否写成冒号 `:` 或逗号 `,`，或者根本就没有写。

### `拼接`

`当从 JavaScript 和 jQuery 转到 PHP 时，情况就变得棘手了；语法非常相似！然而，在 PHP 中，串联是用 .（点）而不是 `+`（加号）处理的。在 JavaScript 和 jQuery 上工作一段时间，然后尝试在 WordPress 主题上工作，并继续使用 JavaScript 语法是很容易的。`

`# 概要`

就是这样。我希望这份关于 jQuery 和 WordPress 的技巧和窍门清单对您有所帮助。我们看了一下：

+   与 WordPress 最大程度兼容其他脚本、库和插件的最佳 jQuery 集成方法

+   所有 Firefox 和 Firebug 在开发中为您提供的各种方式

+   确保您保持 WordPress 用户的工作轻松，并且您的 WordPress HTML 有效且易于处理的提示和技巧

接下来是我们的最后一章！如果你甚至想称之为“章节”，附录 A, *jQuery 和 WordPress 参考指南*，提供了丰富而简单的快速参考，涵盖了您在大多数 jQuery 增强工作中所需的顶级 jQuery 和 WordPress 知识和语法。


# 附录 A. jQuery 和 WordPress 参考指南

好的！欢迎来到本书的最后一部分！这个附录与其他附录不同，因为它实际上是一个快速参考指南，旨在在您阅读和理解在 WordPress 站点中使用 jQuery 的基本原理、应用和最佳实践之后帮助您。把这一章当作您的“备忘单”。

在适当的情况下，我会指向本书中详细描述该函数或技术的位置，以及指向任何其他有用链接的地方，如果您对更多细节感兴趣的话。

在本附录中，我们将涵盖的主题包括：

+   顶级、基本的 jQuery 选择器和函数

+   使用模板层次结构，以及关键模板标记和 WordPress 函数

+   WordPress 短代码

# WordPress 的 jQuery 参考

在接下来的几个部分中，我们将看一下您在 WordPress 中进行 jQuery 开发时最需要的顶级参考资料。让我们从保持在 `noConflict` 模式下并查看最有用的 `selector` 过滤器开始。

## noConflict 模式语法

最简单的方法就是在所有的选择语句中只使用 jQuery 变量：

```js
jQuery('.selector').function();

```

您还可以设置自己的变量：

```js
<script type="text/javascript">
var $jq = jQuery.noConflict();
$jq(document).ready(function() {
$jq("p").click(function() {
alert("Hello world!");
});
});
</script>

```

如果设置正确，甚至可以安全地使用 `$` 变量：

```js
jQuery(function ($) {
/* jQuery only code using $ can safely go here */
$("p").css('border','#ff6600');
});

```

## 用于在 WordPress 中工作的有用选择器过滤器

记住：有时将不想要的内容从选择集中 *排除* 出来比选择您想要的一切更容易。

### 选择过滤器语法

这是使用选择器过滤器的基本语法：

```js
jQuery('.selector:filter(params if any)').function();

```

### 选择器过滤器

这是您在 WordPress 中工作时最有用的顶级选择器过滤器（`:not` 是我个人最喜欢的）：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :not(selector) | `jQuery(".post img:not(.pIcon)").jqFn();` | 过滤掉所有匹配给定选择器的元素。 |
| :header | `jQuery(".post :header").jqFn();` | 筛选出所有标题元素，例如 h1、h2、h3 等。 |
| :first | `jQuery(".post:first").jqFn();` | 仅筛选到第一个选择的元素。 |
| :last | `jQuery(".post:last").jqFn();` | 仅筛选到最后选择的元素。 |
| :even | `jQuery(".post:even").jqFn();` | 仅筛选到偶数元素。注意：数组索引从零开始！零被视为偶数，因此您的第一个项目将被选中！ |
| :odd | `jQuery(".post:odd").jqFn();` | 仅筛选到奇数元素。注意：数组索引从零开始！零被视为偶数，因此您的第二个项目将被选中！ |
| :eq(number) | `jQuery(".post:eq(0)").jqFn();` | 通过其索引筛选出单个元素，索引从零开始。 |
| :gt(number) | `jQuery(".post:gt(0)").jqFn();` | 筛选出所有索引 **大于** 给定值的元素，这也是从零开始的。 |
| :lt(number) | `jQuery(".post:lt(2)").jqFn();` | 筛选出所有索引小于给定值的元素。 |
| :animated | `jQuery(".post:animated").jqFn();` | 筛选为当前正在执行动画的所有元素（我们将在本章后面讨论动画）。 |

### 内容过滤器语法

在常规选择器过滤器之后，您会发现这些内容过滤器非常有用（特别是`:has()`）。

```js
jQuery(".selector:content-filter(params if any)").function();

```

### 内容过滤器

几乎所有内容过滤器都与 WordPress 配合使用非常方便。它们帮助您很好地处理页面和文章所见即所得编辑器的输出。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :has(selector) | `jQuery(".post:has(.entry)").css("background", "#f60");` | 筛选为至少有一个匹配元素的元素。 |
| :contains(text) | `jQuery(".post:contains('Hello world')").css("background", "#f60");` | 筛选包含特定文本的元素。注意：**区分大小写！** |
| :empty | `jQuery(":empty')").css("background", "#f60");` | 筛选为空的元素。这包括文本节点。 |
| :parent | `jQuery(":parent')").css("background", "#f60");` | 筛选为其他元素的父元素。这包括文本节点。 |

### 子过滤器语法

这是使用子元素过滤器语法的基本语法：

```js
jQuery(".selector:child-filter(params if any)").function();

```

### 子过滤器

当处理 WordPress 输出的各种列表标记时，您会发现子过滤器非常有用。类别、页面、画廊页面，您将能够使用这些过滤器控制它们并选择特定元素。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :nth-child(number/even/odd) | `jQuery(".linkcat li:nth-child(1)").css("background", "#f60");` | 筛选为其选择器的“nth”子元素。注意，这不是零索引！1 和 odd 选择第一个元素。 |
| :first-child | `jQuery(".linkcat li:first-child").css("background", "#f60");` | 筛选为其父元素的第一个子元素。 |
| :last-child | `jQuery(".linkcat li:last-child").css("background", "#f60");` | 筛选为其父元素的最后一个子元素。 |
| :only-child | `jQuery(".pagenav li:only-child").css("background", "#f60");` | 筛选为其父元素的唯一子元素。如果父元素有多个子元素，则不选择任何元素。 |

### 表单过滤器语法

这是表单过滤器的语法：

```js
jQuery(":form-filter").function();

```

### 表单过滤器

WordPress 本地具有简单的内容表单和单个输入字段。但是，WordPress Cforms II 插件对大多数项目非常有用，如果您使用该插件，您会发现大多数这些过滤器都很有用：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :input | `jQuery("form:input").css("background", "#f60");` | 筛选为所有输入、文本区域、选择和按钮元素。 |
| :text | `jQuery("form:text").css("background", "#f60");` | 筛选为类型为 text 的所有输入元素。 |
| :password | `jQuery("form:password").css("background", "#f60");` | 筛选为类型为 password 的所有输入元素。 |
| :radio | `jQuery("form:radio").css("background", "#f60");` | 过滤所有类型为单选按钮的输入元素。 |
| :checkbox | `jQuery("form:checkbox").css("background", "#f60");` | 过滤所有类型为复选框的输入元素。 |
| :submit | `jQuery("form:submit").css("background", "#f60");` | 过滤所有类型为提交的输入元素。 |
| :image | `jQuery("form:image").css("background", "#f60");` | 过滤所有图像元素（分类为表单过滤器，但对常规图像也很有用）。 |
| :reset | `jQuery("form:reset").css("background", "#f60");` | 过滤所有类型为重置的输入元素。 |
| :button | `jQuery("form:button").css("background", "#f60");` | 过滤所有类型为按钮的输入元素。 |
| :file | `jQuery("form:file").css("background", "#f60");` | 过滤所有类型为文件的输入元素。 |

## jQuery：用于在 WordPress 中工作的有用函数

虽然我已经对大多数选择器过滤器进行了简要总结，因为它们非常有用，但在下一节中，我将介绍您在 WordPress 项目中最常使用的顶级函数的语法和用法。

不用担心，你可以快速浏览第二章，《在 WordPress 中使用 jQuery》以获取完整列表，以及这里未涉及的函数的使用方法。

### 处理类和属性

使用 jQuery 可以快速地通过更改它们的 CSS 属性来转换对象中最简单但最强大的事物之一。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .css('property', 'value') | `jQuery(".post") .css("background", "#f60");` | 添加或更改所选元素的 CSS 属性。 |
| .addClass('className') | `jQuery(".post") .addClass("sticky");` | 将列出的类（们）添加到所选元素的每个中。 |
| .removeClass('className') | `jQuery(".post") .removeClass("sticky");` | 从所选元素的每个中删除列出的类（们）。 |
| .toggleClass('className', switch-optional) | `jQuery(".post") .toggleClass("sticky");` | 根据它们当前的状态从所选元素的每个中切换列出的类（们）。如果存在类，则删除它；如果不存在，则添加它。 |
| .hasClass('className') | `jQuery(".post") .hasClass("sticky");` | 如果所选元素的列出的类（们）存在，则返回 true；否则返回 false。 |
| .attr | `jQuery(".post").attr();` | 检索所选元素的第一个元素的属性值。 |

## 遍历 DOM

`.append`和`.prepend`将成为您在 DOM 函数中最常用的。但是，您会发现`.wrapAll`对于帮助包含您创建的任何新元素非常宝贵。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .append(html & text) | `jQuery(".post") .append("<b>帖子到此结束</b>");` | 将参数中的内容插入到每个选定元素的末尾。 |
| .appendTo(selector) | `jQuery("<b>帖子在这里结束</b>").appendTo(" .post");` | 做的事情与 append 相同，只是反转了元素选择和内容参数。 |
| .prepend(html & text) | `jQuery(".post") .prepend("<b>帖子从这里开始</b>");` | 将参数中的内容插入到每个所选元素的开头。 |
| .prependTo(selector) | `jQuery("<b>帖子从这里开始</b>").prependTo(" .post");` | 做的事情与 prepend 相同，只是反转了元素选择和内容参数。 |
| .after(string) | `jQuery(".post") .after("<b>这个在后面</b>");` | 将参数中的内容插入到每个所选元素之后，并在外部插入。 |
| .insertAfter(selector) | `jQuery("<b>这个在后面</b>").insertAfter(" .post");` | 做的事情与 after 相同，只是反转了元素选择和内容参数。 |
| .before(html & text) | `jQuery(".post") .before("<b>这个在前面</b>");` | 将参数中的内容插入到每个所选元素之前，并在外部插入。 |
| .insertBefore(selector) | `jQuery("<b>这个在前面</b>") .insertBefore("class");` | 做的事情与 before 相同，只是反转了元素选择和内容参数。 |
| .wrap(html or functionName) | `jQuery(".post").wrap("<div class=".fun" />");` | 在每个所选元素周围包装 HTML 结构。您还可以构造一个将每个元素包装在 HTML 中的函数。 |
| .wrapAll(html) | `jQuery(".post") .wrapAll("<div class=" .fun" />");` | 类似于 wrap，但将 HTML 结构放置在所有元素周围，而不是每个单独的元素。 |
| .wrapInner(selector) | `jQuery(".post") .wrapInner("<div class=" .fun" />");` | 类似于 wrap，但是它将 HTML 结构放置在所选元素的每个文本或子元素周围。 |
| .html(html & text) | `jQuery(".post") .html("<h2>替换文本</h2>");` | 用参数中的内容替换所选项的任何内容和子元素。 |
| .text(text only html chars will be escaped) | `jQuery(".post") .text("替换文本");` | 类似于 HTML，但仅限文本。任何 HTML 字符都将转义为 ASCII 码。 |

## 重要的 jQuery 事件

大多数情况下在 WordPress 中，都是关于`.click`和`.hover`，但`.toggle`和`.dbclick`也很方便。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .click(functionName) | `jQuery(".post") .click(function(){//code});` | 将函数绑定到单击事件类型，单击时执行。 |
| .dbclick(functionName) | `jQuery(".post") .dbclick(function(){//code});` | 将函数绑定到双击事件类型，双击时执行。 |
| .hover(functionName1, functionName2) | `jQuery(".post") .hover(function(){//code});` | 与 mouseenter/mouseleave 事件类型配合使用，并将两个函数绑定到所选元素，分别在 mouseenter 和 mouseleave 时执行。 |
| .toggle(函数名 1, 函数名 2, 函数名 3, ...) | `jQuery(".post") .toggle(function(){//code});` | 与点击事件类型一起工作，并将两个或多个函数绑定到选定的元素上，以便在交替点击时执行。 |

## 最佳的动画效果

任何进行动画的元素都会看起来很酷。确保您知道如何处理这些函数以获得一些一流的 jQuery 增强功能。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .slideUp(速度, 函数名) | `jQuery(".post") .slideUp('slow', function() { // code });` | 将选定元素从底部向上滑动，直到它被隐藏。速度可以是 "快速" 或 "慢速" 或毫秒。动画完成时可以调用函数。 |
| .slideDown(速度, 函数名) | `jQuery(".post") .slideDown('slow', function() { // code });` | 从顶部向下滑动隐藏的选定元素，直到它达到定义的大小。速度可以是 "快速" 或 "慢速" 或毫秒。动画完成时可以调用函数。 |
| .slideToggle() | `jQuery(".post") .slideToggle('slow', function() { // code });` | 使用滑动动画切换选定元素的可见性。速度可以是 "快速" 或 "慢速" 或毫秒。动画完成时可以调用函数。 |
| .fadeOut(速度, 函数名) | `jQuery(".post") .fadeOut("slow", function(){//code});` | 将可见的选定元素淡出或透明度设置为 1 到 0。 |
| .fadeIn(速度, 函数名) | `jQuery(".post") .fadeIn("slow", function(){//code});` | 将选定的元素淡入，其可见性为隐藏或透明度设置为 0 到 1。 |
| .fadeTo(速度, 透明度, 函数名) | `jQuery(".post") .fadeTo("slow", .3, function(){//code});` | 将选定的元素淡出到指定的透明度，范围从 0 到 1。 |
| .animate(css 属性, 持续时间, 缓动, 函数名) | `jQuery(".post") .animate({width: 200, opacity: .25}, 1000, function(){//code});` | 在选定的元素上创建自定义的 CSS 属性过渡效果。 |
| .stop() | `jQuery(".post") .stop();` | 停止选定元素上的动画。 |

# 充分利用 WordPress

这些是您需要了解 jQuery 的顶级元素，现在让我们看看如何在 WordPress 方面保持运行流畅。首先，您了解如何利用主题层次结构，就可以更轻松地创建视图和页面以与 jQuery 结合使用。

## WordPress 模板层次结构

需要稍微调整主题？了解模板层次结构可以帮助您以最少的编程头痛创建所需的视图。下面的列表包含一般模板层次结构的规则。您可以拥有的绝对最简单的主题必须包含一个 `index.php` 页面。如果不存在其他特定的模板页面，则 `index.php` 是默认页面。

接下来，您可以通过添加以下页面来开始扩展您的主题：

+   `archive.php` 当查看类别、标签、日期或作者页面时优先于 `index.php`。

+   当查看主页时，`home.php`优先于`index.php`。

+   当查看单独的文章时，`single.php`优先于`index.php`。

+   当查看搜索结果时，`search.php`优先于`index.php`。

+   当 URI 地址找不到现有内容时，`404.php`优先于`index.php`。

+   查看静态页面时，`page.php`优先于`index.php`。

    +   当通过页面的**管理**面板选择时，自定义**模板**页面，例如：`page_about.php`，优先于查看特定页面时的`page.php`，这又优先于`index.php`。

+   当查看分类页面时，`category.php`优先于`archive.php`。这又优先于`index.php`。

    +   自定义**分类-ID**页面，例如：`category-12.php`优先于`category.php`。这又优先于`archive.php`，优先于`index.php`。

+   当查看标签页面时，`tag.php`优先于`archive.php`。这又优先于`index.php`。

    +   自定义**标签-tagname**页面，例如：`tag-reviews.php`优先于`tag.php`。这又优先于`archive.php`，优先于`index.php`。

+   查看作者页面时，`author.php`优先于`archive.php`。当查看作者页面时，这又优先于`index.php`。

+   当查看日期页面时，`date.php`优先于`archive.php`。这又优先于`index.php`。![WordPress 模板层次结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_AppA_01.jpg)

    ### 注

    您可以在这里了解有关 WordPress 主题模板层次结构的更多信息：[`codex.wordpress.org/Template_Hierarchy`](http://codex.wordpress.org/Template_Hierarchy)。

## 顶级 WordPress 模板标签

以下是我发现在 jQuery 和主题开发中最有用的顶级 WordPress 模板标签：

| 模板标签 | 描述 | 参数 |
| --- | --- | --- |
| `bloginfo()`示例：`bloginfo('name');` | 显示您的博客信息，由您的用户配置文件和管理面板中的一般选项提供。**更多信息：**[`codex.wordpress.org/Template_Tags/bloginfo`](http://codex.wordpress.org/Template_Tags/bloginfo)。 | 您想在标签前后以及它们之间显示的任何文本字符，以及分隔它们的字符 — `name，description，url，rdf_url，rss_url，rss2_url，atom_url，comments_rss2_url，pingback_url，admin_email，charset，version`。默认：不带参数将不显示任何内容。您必须使用参数。 |
| `wp_title()`示例：`wp_title('——',true,'');` | 显示页面或单独文章的标题。**注意：**在循环外的任何地方使用此标签。**更多信息：**[`codex.wordpress.org/Template_Tags/wp_title`](http://codex.wordpress.org/Template_Tags/wp_title)。 | 您想用来分隔标题的任何文本字符 — " `--` "。您可以设置一个布尔值来显示标题 — " `--`，`false` "。从版本 2.5+ 开始：您可以决定分隔符是在标题之前还是之后 — " `--`，`true`，`right` "。默认：如果分隔符分配了默认值，则不带参数将在左边显示页面标题与分隔符。 |
| `the_title()`示例：`the_title('<h2>', '</h2>');` | 显示当前帖子的标题。**注意：**在循环中使用此标签（见第三章，“深入了解 jQuery 和 WordPress”以了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/the_title`](http://codex.wordpress.org/Template_Tags/the_title)。 | 您希望出现在标题之前和之后的任何文本字符 ——`（"<h2>",``"</h2>"）`。您还可以设置一个布尔值将显示关闭为 false ——`（"<h2>",``"</h2>", "false"）`。默认：如果没有参数，将显示没有标记的标题。 |
| `the_content()`示例：`the_content('more_link_text', strip_teaser, 'more_file');` | 显示您编辑到当前文章中的内容和标记。**注意：**在循环中使用此标签（见第三章，“深入了解 jQuery 和 WordPress”以了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/the_content`](http://codex.wordpress.org/Template_Tags/the_content)。 | 你可以添加文本以显示“更多链接”，一个布尔值以显示或隐藏“预告文本”，还有一个第三个参数用于更多文件，目前不起作用——`（"继续阅读" . the_title（））`。你还可以设置一个布尔值将显示关闭为 false ——`（"<h2>",``"</h2>", "false"）`。默认：如果没有参数，将显示具有通用“阅读更多”链接的内容。 |
| `the_category()`示例：`the_category(', ');` | 显示帖子分配给的类别或类别的链接。**注意：**在循环中使用此标签（见第三章，“深入了解 jQuery 和 WordPress”以了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/the_category`](http://codex.wordpress.org/Template_Tags/the_category)。 | 如果有多个类别，则可以包含文本分隔符 ——`('&gt;')`。默认：如果有多个类别分配，将显示逗号分隔。 |
| `the_author_meta()`示例：`the_author_meta();` | 显示帖子或页面的作者。**注意：**在循环中使用此标签（见第三章，“深入了解 jQuery 和 WordPress”以了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/the_author_meta`](http://codex.wordpress.org/Template_Tags/the_author_meta)。 | 此标签接受大量参数。它们在前面的部分中涵盖了，您还可以查看 codex。 |
| `wp_list_pages()`示例：`wp_list_pages('title_li=');` | 以链接形式显示 WordPress 页面列表。**更多信息：**[`codex.wordpress.org/Template_Tags/wp_list_pages`](http://codex.wordpress.org/Template_Tags/wp_list_pages)。 | `title_li` 是最有用的，因为它将页面名称和链接包裹在列表标签`<li>`中。其他参数可以通过用`&`分隔来设置：`depth, show_date, date_format`,`child_of, exclude, echo, authors`,`sort_column`。默认：没有参数将在`<li>`列表中显示每个标题链接，并在列表周围包含一个`<ul>`标签（如果您想要向页面导航添加自定义项目，则不建议使用）。 |
| `wp_nav_menu()`；示例：`wp_nav_menu( array('menu' => '主导航' ));` | 以链接形式显示分配给 WordPress 3.0+ 菜单的菜单项列表。**更多信息：**[`codex.wordpress.org/Function_Reference/wp_nav_menu`](http://codex.wordpress.org/Function_Reference/wp_nav_menu)。 | 此标记接受大量参数，最常见的参数是在管理面板的菜单工具中设置的菜单的名称。如果没有可用的菜单，该函数将默认为`wp_list_pages();`标记。请参阅 codex 以获取更多参数。 |
| `next_post_link()`示例：`next_post_link('<strong> %title </strong>');` | 显示到当前文章的时间顺序中存在的下一篇文章的链接。**注意：**在循环中使用此标记。 （参见第三章，*深入挖掘：了解 jQuery 和 WordPress*，了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/next_post_link`](http://codex.wordpress.org/Template_Tags/next_post_link)。 | 想要出现任意标记和文本字符—(`<strong>%title</strong>`）。`%link` 将显示永久链接，`%title` 下一篇文章的标题。默认：没有参数将显示下一篇文章标题的链接，并在后面加上尖括号（`>>`）。 |
| `previous_post_link()`示例：`previous_post_link('<strong> %title </strong>');` | 显示到当前文章的时间顺序中存在的上一篇文章的链接。**注意：**在循环中使用此标记。 （参见第三章，*深入挖掘：了解 jQuery 和 WordPress*，了解如何设置循环）。**更多信息：**[`codex.wordpress.org/Template_Tags/previous_post_link`](http://codex.wordpress.org/Template_Tags/previous_post_link)。 | 想要出现任意标记和文本字符—`(<strong>%title</strong>)`。`%link` 将显示永久链接，`%title` 下一篇文章的标题。默认：没有参数将显示上一篇文章标题的链接，并在前面加上尖括号（`<<`）。 |
| `comments_number()`示例：`comments_number('暂无回应', '1 条回应', '% 条回应');` | 显示帖子的评论总数、引用和 Pingback。**注意：**在循环中使用此标签。（见第三章，*深入了解 jQuery 和 WordPress*关于如何设置循环。）**更多信息：**[`codex.wordpress.org/Template_Tags/comments_number`](http://codex.wordpress.org/Template_Tags/comments_number)。 | 允许您指定如果没有评论，只有 1 条评论或有许多评论时如何显示—`('暂无回应','1 条回应','% 条回应')`。您还可以用额外的标记包装项目—`("暂无评论","<span class="bigNum">1</span> 条回应","<span class="bigNum">%</span> 条评论")`。默认：不带参数将显示：没有评论，或 1 条评论，或?条评论。 |
| `comments_popup_link()`示例：`comments_popup_link('发表你的想法');` | 如果未使用`comments_popup_script`，则显示到评论的普通链接。**注意：**在循环中使用此标签。（见第三章，*深入了解 jQuery 和 WordPress*关于如何设置循环。）**更多信息：**[`codex.wordpress.org/Template_Tags/comments_popup_link`](http://codex.wordpress.org/Template_Tags/comments_popup_link)。 | 允许您指定如果没有评论，只有 1 条评论或有许多评论时如何显示—`("还没有评论", "到目前为止 1 条评论", "到目前为止%条评论（这算多吗？）", "评论链接", "此帖子的评论已关闭")`。默认：不带参数将显示与`comments_number()`标签相同的默认信息。 |
| `edit_post_link()`示例：`edit_post_link('编辑', '<p>', '</p>');` | 如果用户已登录且有权限编辑帖子，则显示链接以编辑当前帖子。**注意：**在循环中使用此标签。（见第三章，*深入了解 jQuery 和 WordPress*关于如何设置循环。）**更多信息：**[`codex.wordpress.org/Template_Tags/edit_post_link`](http://codex.wordpress.org/Template_Tags/edit_post_link)。 | 任何您想要放在链接名称中的文本，以及您想要放在其之前和之后的标记—`("编辑我！", "<strong>", "</strong>")`。默认：不带参数将显示一个没有额外标记的链接，上面写着“编辑”。 |
| `the_permalink()`示例：`the_permalink();` | 显示当前文章的永久链接的 URL。**注意：**在循环中使用此标记。（参见第三章 *深入了解 jQuery 和 WordPress 的使用方式* 如何设置循环。）**更多信息：**[`codex.wordpress.org/Template_Tags/the_permalink`](http://codex.wordpress.org/Template_Tags/the_permalink)。 | 这个标记没有参数。 |
| `the_ID()`示例：`the_ID();` | 显示当前文章的数字 ID。**注意：**在循环中使用此标记。（参见第三章 *深入了解 jQuery 和 WordPress 的使用方式* 如何设置循环。）**更多信息：**[`codex.wordpress.org/Template_Tags/the_ID`](http://codex.wordpress.org/Template_Tags/the_ID)。 | 这个标记没有参数。 |
| `wp_get_archives()`示例：`wp_get_archives('type=monthly');` | 显示基于日期的存档列表。**更多信息：**[`codex.wordpress.org/Template_Tags/wp_get_archives`](http://codex.wordpress.org/Template_Tags/wp_get_archives)。 | 你可以通过用一个“`&`”来分隔它们来设置参数- （'type=monthly&limit=12'）。另外的参数有`type, limit, format, before, after, show_post_count`。默认：没有参数将以 HTML 格式显示所有的月度存档列表，不包含前后标记，并且`show_post_count`设置为 false。 |
| `get_calendar()`示例：`get_calendar(false);` | 显示当前月份/年份的日历。**更多信息：**[`codex.wordpress.org/Template_Tags/get_calendar`](http://codex.wordpress.org/Template_Tags/get_calendar)。 | 可以设置一个布尔值，如果设置为 true，将显示单个字母的缩写（`S = 星期日`）。否则，它将根据本地化显示缩写（`Sun = 星期日`）- （真）默认：没有参数将显示单个字母的缩写。 |

### 条件标签

条件标签可以用于你的模板文件中，根据页面匹配的条件来更改所显示的内容以及如何显示该内容。例如，你可能希望在你的博客主页面上方显示一小段文本，但只在你的博客的主页面上。使用`is_home()`条件标签，这个任务就变得很容易。

几乎所有的操作都有条件标签，其中，这七个是我在主题开发中最需要的：

+   `is_admin()`

+   `is_page()`

+   `is_single()`

+   `is_sticky()`

+   `is_home()`

+   `is_category()`

+   `in_category()`

所有这些功能都可以使用以下参数：`文章 ID`或`页面 ID`数字，文章或页面`标题`，或文章或页面`slug`。

第一个条件标签，`is_admin()`，你会注意到我们在这个标题中多次使用，以及 `is_home()` 一起加载我们的 `wp_enqueue_scripts`，以便我们可以避免在从管理面板查看主题时加载脚本（例如审核主题）。脚本可能会与管理面板中的脚本冲突，因此最好确保它们只在不从管理面板加载主题时加载。

另外，如果您有任何仅影响主页的 jQuery 脚本，比如说，“置顶帖子轮播器”脚本或类似的脚本，您可能希望考虑将`wp_enqueue_script`调用放在一个 `if(is_home()){wp_enqueue_script(//)}` 调用内。这样，脚本将仅在您需要它的页面上加载，而不是在站点的每个页面上，即使它没有被使用时也是如此。

至于其余的条件标签，尽管主题很棒，但我相信你一定遇到过这样的困境，你或者你的客户不希望每个页面或帖子上都有完全相同的侧边栏。

我使用这些条件标签，以便特定页面可以打开或关闭特定样式或内容 div，并显示或不显示特定内容。这七个标签确实有助于使我的客户的定制主题网站具有真正的、定制的网站感觉，而不是标准的：“设计不错，但每个页面都有完全相同的侧边栏，这可能是另一个 WordPress 站点”的感觉。

条件标签的乐趣并不止于此。在这里列出了许多您可能发现在辅助主题定制方面非常有用的标签：[`codex.wordpress.org/Conditional_Tags`](http://codex.wordpress.org/Conditional_Tags)。

## 循环函数的快速概述

所有这些模板和条件标签是一回事，将它们应用在循环中是另一回事。在本书的许多章节中，我们不得不在主题的模板文件中修改循环或创建一个自定义循环。以下表格包含了对循环的每个部分的描述。

| 循环函数 | 描述 |
| --- | --- |
| `<?php if(have_posts()) : ?>` | 此函数检查是否有帖子可以显示。如果有，代码将继续到下面的下一个函数。 |
| `<?php while(have_posts()) : the_post(); ?>` | 此函数显示可用的帖子，并继续到下面的下一个函数。 |
| `<?php endwhile; ?>` | 此函数关闭了上面打开的`while(have_posts...`循环，一旦显示了可用帖子，就会关闭。 |
| `<?php endif; ?>` | 此函数在上面打开的`if(have_posts...`语句一旦`while(have_posts..`循环完成时结束。 |

## 设置 WordPress 短代码

整个附录都是关于有用的参考资料。我们应该快速浏览一下短代码。它们首次在版本 2.5 中引入。如果你熟悉在 WordPress 中编写函数，短代码可以帮助你将较长的代码片段（如自定义循环和复杂的模板标签字符串）或甚至只是你在主题（或插件）中感觉会经常使用的标记和文本压缩成更干净、更简单的可重复使用的代码片段。你可以将短代码添加到你主题的`functions.php`文件中。

你可能已经熟悉了短代码，但可能没有意识到。如果你曾经研究过 WordPress 的媒体管理器如何在图像中插入标题，你可能会注意到类似于：

```js
...
[caption id="attachment_12" align="alignleft" width="150"
caption="this is my caption"]<img src.../>[/caption]
...

```

那是 WordPress 中用于标题和对齐的内置短代码。

要创建一个短代码，你确实需要在你主题的`functions.php`文件中创建一个 PHP 函数。如果你的主题没有`functions.php`文件，只需创建一个新文件并命名为`functions.php`，然后将其放置在你主题目录的根目录下。

### 创建一个基本的短代码

我们首先打开我们的`functions.php`文件，在文件末尾创建一个简单的函数，返回文本和标记的字符串，就像这样：

```js
<?php
...
function quickadd() {
//code goes here
$newText = 'This page is brought to you by
<a href="#">the letter Z</a>';
return $newText;
}
?>

```

现在，要真正利用短代码，你确实需要了解一些 PHP，而要完全覆盖，这有点超出了本标题的范围。但即使没有太多的 PHP 经验，如果你跟随这个示例，你会开始看到这个 WordPress 功能在节省时间方面有多灵活，不仅在你的主题中，还在你日常使用 WordPress 中。

在上一个示例中，在我们的函数括号`{}`内部，我设置了一个非常基本的变量**`$donateText`**，并为其分配了一串文本和标记。

`return`语句是一个非常基本的 PHP 函数，它将确保我们的`quickadd`函数返回分配给该变量的任何内容。

现在我们已经准备好使用 WordPress 的`add_shortcode()`函数了，只需将其添加到我们之前设置的`quickadd`函数*下方*即可。`add_shortcode`函数有两个参数。对于第一个参数，你将输入你的短代码的引用名称，在第二个参数中，你将输入你希望你的短代码调用的函数名称，就像这样：

```js
...
add_shortcode('broughtby', 'quickadd');
?>

```

现在是有趣的部分：在你的主题中选择任何模板页面，并通过简单添加`broughtby`短代码来使用它：

```js
...
[broughtby]
...

```

无论你在主题的模板文件中粘贴`[broughtby]`短代码在哪里，都会出现**本页面由字母 Z 提供**的文字，带有指向该字母页面的链接！

**奖励:** 你不仅限于在你的模板文件中使用这个短代码！直接通过管理面板将其粘贴到文章或页面中，你会得到相同的结果。而且，你猜对了，短代码的输出可以很容易地利用和增强 jQuery！

如果您的增强功能需要比 WordPress 的所见即所得编辑器处理的 HTML 标记更多，而网站内容编辑器在切换到 HTML 视图时不知所措，那么使用短代码创建解决方案可能正是您所需要的！例如，对于您的客户来说，添加一组带有一些参数的方括号要比标记定义列表更容易，而基本的所见即所得编辑器不允许这样做。

这将转变为：

```js
...
<dl>
<dt><a href='#'>Event Name and Location</a></dt>
<dl>Event description</dl>
</dl>
...

```

转变为更简单的：

```js
...
[event title="Event Name and Location"
description="Event description" url="#"]
...

```

除了帮助 WordPress 内容编辑人员处理标记外，如果您是一个忙碌的 WordPress 内容作者，短代码也是节省时间的好方法。即使您不是从头开始创建自己的主题，也可以轻松地将自己的短代码添加到任何主题的 `functions.php` 文件中，从而提高您的生产力。

如果您更熟悉 PHP，可以查看 WordPress 的短代码 API，了解如何通过为其添加参数来扩展和增强您的短代码功能：[`codex.wordpress.org/Shortcode_API`](http://codex.wordpress.org/Shortcode_API)。

# 总结

希望您在阅读本附录后能够标记它，并相信您将随时在使用或语法方面遇到与 jQuery 和 WordPress 相关的主要问题时再次查阅。我们还快速浏览了 WordPress 核心功能和短代码的“内幕”，希望这能让您了解为 WordPress 网站创建有用增强功能的无限可能性。希望您喜欢本书，并发现它在帮助您通过 jQuery 创作和增强 WordPress 网站方面非常有用。
