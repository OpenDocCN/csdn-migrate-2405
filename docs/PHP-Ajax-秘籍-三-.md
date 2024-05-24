# PHP Ajax 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88`](https://zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章.高级工具

在本章中，我们将涵盖以下主题：

+   使用 Comet 技术构建 Ajax 聊天系统

+   使用 JavaScript 绘制图表

+   通过画布解码验证码

+   在网格中显示数据

在本章中，我们将看看如何使用 Comet 技术构建一个简单的 Ajax 聊天应用程序。**Comet**是 Web 应用程序中的一种技术，可以在不需要客户端显式请求的情况下从 Web 服务器向客户端推送数据。在这个应用程序中，我们将使用这种简单的 Comet 技术，将聊天消息从服务器推送到浏览器，而不使用任何特殊的 Comet 服务器。

在*使用 JavaScript 绘制图表*部分，我们将看看如何使用 Google Visualization API 来使用 JavaScript 构建交互式图表。

之后，我们将展示如何使用 Firefox Greasemonkey 脚本，通过画布来解码浏览器上的简单验证码。

### 注意

这里使用的聊天应用程序不使用任何 Comet 服务器，如 APE（[`www.ape-project.org`](http://www.ape-project.org)）或 Livestreamer（[`www.livestream.com`](http://www.livestream.com)）。我们在这里只是试图展示如何使用 Ajax 进行长轮询，而不是传统的轮询来从服务器获取信息。

# 使用 Comet 技术构建 Ajax 聊天系统

现在，让我们看看如何使用长轮询技术构建一个简单的 Ajax 聊天系统。我们大部分使用了 JavaScript 的 jQuery 框架来编写 JavaScript 代码。在传统的 Ajax 轮询系统中，会定期向服务器发送请求；因此，无论是否有新数据，服务器都必须处理 HTTP 请求。但是在 Ajax 中，使用长轮询技术，请求会一直保持开放，直到服务器有新数据发送到浏览器。

然而，在我们的聊天示例中，我们将 Ajax 请求保持开放 90 秒。如果服务器没有收到新的聊天消息，连接将被关闭，并打开一个新的 Ajax 轮询。

## 准备工作

首先，让我们看看这个应用程序的界面是什么样子的：

![准备工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_04_01.jpg)

这个聊天工具有一个非常简单的界面。您需要设置一个用户名来发送聊天消息。

## 如何做...

与这个 Comet 聊天系统相关的代码有不同类型。让我们逐个部分来看：

1.  以下 HTML 代码构成了聊天系统的布局：

```php
<form name="chatform" id="chatform">
<div id="chatwrapper">
<h2>Ajax Chat Utility</h2>
<div>
User Name: <input id="username" type="text" maxlength="14" />
</div>
<div id="chattext" class="chatbox"> </div>
<div>
<input id="message" name="message" type="text" maxlength="100" />
<input type="submit" name="submit" id="send" value="Send" />
</div>
</div>
</form>

```

1.  现在让我们看看保存消息到文本文件并保持 Ajax 请求开放直到文件中保存了新消息的 PHP 代码。您可以在`chat-backend.php`文件中找到这段代码。

```php
//set the maximum execution time to 90 seconds
set_time_limit(91);
//make sure this file is writable
$file_name = 'chatdata.txt';
//get the script entrance time
$entrance_time = time();
// store new message in the file
//used for ajax call to store the mesage
if(!empty($_GET['msg']) && !empty($_GET['user_name']))
{
$user_name = htmlentities($_GET['user_name'],ENT_QUOTES);
$message = htmlentities(stripslashes($_GET['msg']),ENT_QUOTES);
$message = '<div><b>'.$user_name.'</b> : '.$message.'</div>';
file_put_contents($file_name,$message);
exit();
}
//user for getting chat messages
// infinite loop until the data file is not modified
$last_modif = !empty($_GET['ts']) ? $_GET['ts'] : 0;
$curr_ftime = filemtime($filename);
//now get the difference
while ($curr_ftime <= $last_modif && time()-$entrance_time<90) // check if the data file has been modified
{
//sleep for 500 micro seconds
usleep(500000);
//clear the file status cache
clearstatcache();
//get the file modified time
$curr_ftime = filemtime($file_name);
}
// return a json encoded value
$response = array();
$response['msg'] = file_get_contents($file_name);
$response['ts'] = $curr_ftime;
echo json_encode($response);

```

1.  现在，让我们看看使聊天功能生效的 JavaScript 代码。

```php
var Comet ={
ts : 0 ,
url : 'chat-backend.php',
//to display the response
show_response : function(message){
$('#chattext').append(message);
$('#chattext').scrollTop( $('#chattext').attr('scrollHeight') );
},
//validation fuction for empty user name or message
validate : function()
{
if($.trim( $('#username').val() )=='')
{
alert('Please enter the username');
return false;
}
else if($.trim( $('#message').val() )=='')
{
alert('Please enter chat message');
return false;
}
else
{
return true;
}
},
send_message : function()
{
if(this.validate())
{
var request_data = 'user_name='+$('#username').val()+'&msg='+$('#message').val();
var request_url = this.url+'?'+request_data;
//make the ajax call
$.get(request_url);
$('#message').val('');
$('#message').focus();
}
cometused, for building Ajax chat},
connect : function()
{
//call the ajax now to get the response
$.ajax({
url: this.url,
data: 'ts='+this.ts,
cache : false,
dataType : 'json',
success: function(data){
//only add the response if file time has been modified
if(data.ts>Comet.ts)
{
Comet.ts = data.ts;
Comet.show_response(data.msg);
}
Comet.connect();
},
error : function(data)
{
//wait for 5 second before sending another request
setTimeout(function(){
Comet.connect()
}, 5000);
}
});
}
};
//event handler for DOM ready
$(document).ready(function()
{
//call the comet connection function
Comet.connect();
//submit event handlder of the form
$('#chatform').submit(function()
{
Comet.send_message();
return false;
});
});

```

### 它是如何工作的...

现在，让我们看看这个 Ajax 聊天是如何与 Comet 实现一起工作的。它的一些方面如下：

1.  将聊天消息保存到文件中：

聊天消息被保存到文件中。在我们的应用程序中，只有最新的聊天消息被保存到文件中。之前的聊天消息被最新消息替换。

```php
$user_name = htmlentities(stripslashes($_$_GET['user_name']),ENT_QUOTES);
$message = htmlentities(stripslashes($_GET['msg']),ENT_QUOTES);
$message = '<div><b>'.$user_name.'</b> : '.$message.'</div>';
file_put_contents($file_name,$message);

```

消息的特殊字符被转换为 HTML 实体，以转换 HTML 特殊字符并避免聊天字符串中的格式错误。然后，带有用户名的消息存储在`$file_name`变量中。

1.  使用长 Ajax 轮询实现 Comet：

现在，让我们看看我们如何使用长 Ajax 轮询实现 Comet。

```php
$entrance_time = time();

```

在代码的第一行，我们将 PHP 脚本的进入时间存储在`$entrance_time`变量中，以防止脚本执行超过 90 秒，如下所示：

```php
set_time_limit(91);

```

在`chat-backend.php`代码的第一行中，我们将脚本的最大执行时间设置为`91`（秒），这样 PHP 在脚本的长时间执行时不会抛出致命错误；因为默认情况下，PHP 脚本的`max_execution_time`在`php.ini`文件中设置为`30`。

现在，让我们来看看主要的`while`循环，它会阻塞 Ajax 调用，直到接收到新的聊天消息为止：

```php
$last_modif = !empty($_GET['ts']) ? $_GET['ts'] : 0;
$curr_ftime = filemtime($filename);
while ($curr_ftime <= $last_modif && time()-$entrance_time<90) {
usleep(500000);
clearstatcache();
$curr_ftime = filemtime($file_name);
}

```

我们将最后一次文件修改时间值存储在`$last_modif`变量中，将当前文件修改时间存储在`$curre_ftime`变量中。`while`循环一直执行，直到满足两个条件：第一个条件是文本文件的最后修改时间应大于或等于当前文件修改时间，第二个条件检查脚本执行时间是否达到 90 秒。因此，如果文件已被修改或脚本执行时间为 90 秒，则请求完成并将响应发送到浏览器。否则，请求将被长时间的 Ajax 轮询阻塞。

在 JavaScript 端，当 DOM 准备好进行操作时，我们调用`Comet.connect()`函数。此函数向`chat-backend.php`文件发出 Ajax 请求。现在，让我们看看这里如何处理 Ajax 响应：

```php
success: function(data){
if(data.ts>Comet.ts)
{
Comet.ts = data.ts;
Comet.show_response(data.msg);
}
Comet.connect();
},
error : function(data)
{
setTimeout(function(){
Comet.connect()
}, 5000);
}

```

当我们收到成功的 Ajax 响应时，我们会检查文件修改时间是否大于发送到服务器进行检查的时间戳。如果文件的修改时间已经改变，则满足此条件。在这种情况下，我们将`ts`变量赋值为文件修改时间的当前时间戳，并调用`show_response()`函数将最新的聊天消息显示给浏览器。然后立即调用`Comet.function()`。

如果 Ajax 请求出现错误，它会在发送另一个请求到`connect()`函数之前等待 5 秒。

1.  显示响应：

现在，让我们看一下响应是如何显示的：

```php
show_response : function(message){
$('#chattext').append(message);
$('#chattext').scrollTop( $('#chattext').attr('scrollHeight') );
},

```

在这个函数中，我们将 Ajax 响应附加到具有 ID`chattext`的`div`。之后，我们将`scrollTop`的值（如果存在滚动条，则表示滚动条的垂直位置）设置为`scrollHeight`。`ScrollHeight`属性给出元素的滚动视图的高度。

# 使用 JavaScript 制作图表

在本节中，我们将看一个示例，演示如何使用 Google 可视化的 JavaScript API 创建交互式图表。**Google 可视化 API**提供了一组强大的函数，用于创建不同类型的图表，如饼图、折线图、条形图等。在本节中，我们将简要地看一下如何使用此 API 来创建它们。

## 准备就绪

现在，让我们看一下使用 Google 可视化 API 创建不同样式的图表的基本步骤。我们将看一个示例，在其中我们在页面上创建条形图、折线图和饼图。现在，让我们通过使用可视化 API 来创建图表的初步步骤。

1.  放置图表容器：

首先，我们需要在网页中放置一个包含图表的 HTML 元素。通常，它应该是一个块级元素。让我们从流行的块级元素<div>开始，如下所示：

```php
<div id="chart"></div>

```

请确保为此 HTML 元素分配一个 ID 属性，因为可以使用`document.getElementById()` JavaScript 函数传递此元素的引用。

1.  加载 Google 可视化 API：

创建图表容器后，让我们尝试在这里加载 Google 可视化 API，如下所示：

```php
<script type="text/javascript" src="https://www.google.com/jsapi"></script>

```

在前面的代码片段中，我们在网页中包含了 Google JavaScript API。在包含 JavaScript 文件之后，我们现在需要加载 Google API 的可视化模块：

```php
google.load("visualization", "1", {packages:["corechart"]});

```

在`load()`函数中，第一个参数是我们想要加载的模块的名称；在我们的情况下是`visualization`模块。第二个参数是模块的版本；这里是 1 是最新版本。在第三个参数中，我们指定了从模块中加载哪个特定的包。在我们的情况下，是`corechart`包。`corechart`库支持常见图表类型，如条形图、折线图和饼图。

一旦 JavaScript 库完全加载，我们需要使用 JavaScript API 的函数。为了帮助解决这种情况，Google 的 JavaScript API 提供了一个名为 setOnloadCallback()的函数；它允许我们在特定模块加载时添加回调函数：

```php
google.setOnLoadCallback(draw_line_chart));

```

在上面的例子中，当 Google Visualization 库加载时，会调用名为`draw_line_chart`的用户定义函数。

学习如何加载 Google Visualization API 之后，让我们看一下绘制柱状图、折线图和饼图的示例。

## 工作原理...

现在，让我们看看使用可视化 API 创建的不同图表的外观：

![工作原理...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_04_02.jpg)

### 绘制折线图

现在我们知道创建的图表是什么样子的，让我们首先创建折线图。可以在上面的图像中看到折线图。完整的代码可以在代码包中提供的`line-chart.html`文件中找到。现在，让我们逐步创建折线图。

在本节中，我们将看到如何创建线图，以显示世界上两个主要城市纽约和伦敦的人口增长，并将它们与线图进行比较。

1.  为图表准备数据：

+   为了为图表准备数据，我们首先需要将数据存储在 Google Visualization API 中的`DataTable`类的对象中，以表示数组的二维数据。

```php
var data = new google.visualization.DataTable();

```

+   现在，下一步是为图表添加列。我们在图表上显示两条线，显示纽约和伦敦的人口增长，以十年为单位。为此，我们需要使用`addColumn()`函数为`DataTable`对象创建三列：

```php
data.addColumn('string', 'Year');
data.addColumn('number', 'New York');
data.addColumn('number', 'London');

```

+   接下来，使用`addRows()`函数创建三行空行。您还可以将数组传递给`addRows()`函数，以创建带有数据的行。我们将在创建柱状图时看到如何做到这一点。

```php
data.addRows(3);

```

+   在创建空行之后，让我们使用`setValue()`函数在这些空行上设置值，如下所示：

```php
data.setValue(0, 0, '1980');
data.setValue(0, 1, 7071639);
data.setValue(0, 2, 6805000);
data.setValue(1, 0, '1990');
data.setValue(1, 1, 7322564);
data.setValue(1, 2, 6829300);
data.setValue(2, 0, '2000');
data.setValue(2, 1, 8008278);
data.setValue(2, 2, 7322400);

```

`setValue()`函数的第一个和第二个参数表示矩阵的行和列。例如，值`1,2`表示矩阵的第二行和第三列。

1.  显示折线图：

在 data 变量中创建图表数据后，现在创建并显示图表：

```php
var chart = new google.visualization.LineChart(document.getElementById('chart'));

```

在上面的代码中，我们正在使用 Google Visualization API 的 LineChart()函数在 ID.chart 的 div 中创建折线图。现在，图表对象已经创建，并且可以在 chart 变量中使用。

```php
chart.draw(data, {width: 600, height: 360, title: 'Population by Years'});

```

现在，使用 draw()函数绘制图表，该函数接受两个参数：

+   第一个是图表的数据，它是`DataTable`类的对象。

+   第二个参数指定不同的选项，如宽度、高度、图表标题等。可以在[`code.google.com/apis/visualization/documentation/gallery/linechart.html`](http://code.google.com/apis/visualization/documentation/gallery/linechart.html)找到参数的完整列表。

图表是自动在 X 轴和 Y 轴上表示各自的值。

### 绘制柱状图

在本节中，我们将看到如何使用 Google Visualization API 绘制柱状图。在这个例子中，我们将使用与前一个例子中相同的数据来可视化伦敦和纽约的人口增长。

这个图表可以在上面图像的右侧看到。

1.  准备数据：

让我们看一下使用柱状图可视化创建数据的代码。为了保存图表数据，我们需要创建`DataTable()`类的实例，如下所示：

```php
var data = new google.visualization.DataTable();
data.addColumn('string', 'Year');
data.addColumn('number', 'New York');
data.addColumn('number', 'London');
data.addRows([
['1980', 7071639,6805000],
['1990', 7322564,6829300],
['2000', 8008278,7322400]
]);

```

如前面的代码中所示，在为数据表添加列之后，我们使用`addRows()`函数添加了行。我们之前以不同的方式使用了这个函数，创建了空行。在这里，它将直接创建三行，带有数组的数据。

1.  显示柱状图：

准备好数据后，让我们在网页上绘制它：

```php
var chart = new google.visualization.ColumnChart(document.getElementById('chart'));
chart.draw(data, {width: 600, height: 360, title: 'Population by Years', hAxis: {title: 'Year'} , vAxis : {title: 'Population'}
});

```

我们正在绘制一个宽度为 600 像素，高度为 360 像素的条形图，使用`object ColumnChart()`类。使用`hAxis`和`vAxix`选项，我们在水平轴上显示标签`Year`，在垂直轴上显示标签`Population`。您可以在[`code.google.com/apis/chart/interactive/docs/gallery/columnchart.html`](http://code.google.com/apis/chart/interactive/docs/gallery/columnchart.html)了解有关柱状图 API 的更多选项。

### 提示

`BarChart()`类也在 Google Visualization API 中可用，但它创建的是水平条形图。您可以在[`code.google.com/apis/chart/interactive/docs/gallery/barchart.html`](http://code.google.com/apis/chart/interactive/docs/gallery/barchart.html)找到更多关于这种类型图表的信息。

### 绘制 3D 饼图

在这一部分，我们将看到如何使用 Google Visualization API 创建饼图。此示例生成的饼图显示在前图的左侧。

在这个例子中，我们将分解开发简单网站所需的时间，并使用饼图进行可视化。

1.  准备数据：

让我们看看如何创建用于项目可视化的饼图数据。和往常一样，我们需要创建`DataTable()`类的实例来存储需要填充的数据。

```php
var data = new google.visualization.DataTable();
data.addColumn('string', 'Phase');
data.addColumn('number', 'Hours spent');
data.addRows([
['Analysis', 10],
['Designing', 25],
['Coding', 70],
['Testing', 15],
['Debugging', 30]
]);

```

如您在上面的代码中所见，我们正在创建两列来存储项目不同阶段所花费的时间的数据。第一列是`Phase`，第二列是`Hours spent`（在项目的特定阶段花费的时间）。

1.  展示饼图：

现在，让我们看一下实际的代码，它将在 ID 为 chart 的 div 上绘制饼图：

```php
var chart = new google.visualization.PieChart(document.getElementById('chart'));
chart.draw(data, {width: 600, height: 360, is3D: true, title: 'Project Overview'});

```

在上面的代码中，首先创建了`PieChart()`类的对象。然后，使用`draw()`函数绘制图表。饼图是通过将第 2 列中给定的总小时数作为 100%来绘制的。请注意，我们将`is3D`选项设置为`true`，以显示 3D 饼图。

# 通过 canvas 解码 CAPTCHA

**CAPTCHA**（或**Captcha**）是**C**ompletely **A**utomated **P**ublic **T**uring test to tell **C**omputers and **H**umans **A**part 的缩写，基于单词'capture'。它最初是由 Luis von Ahn，Manuel Blum，Nicholas J. Hopper 和 John Langford 创造的。**CAPTCHA**旨在阻止机器和机器人访问网页功能；通常放置在网页的注册表单中，以确保只有人类才能注册网站。通常，它基于计算机难以识别图像形式的文本。更多关于**OCR（光学字符识别）**的研究和先进技术正在削弱 Captcha 的概念，这反过来迫使对 Captcha 进行进一步研究。HTML5 的`canvas`元素通过 JavaScript 编程打开了通过解码的可能性。

### 注意

`canvas`元素是 HTML5 规范的一部分。它是由苹果在 WebKit 组件中引入的。之后，它被 Gecko 内核的浏览器采用，比如 Mozilla Firefox。目前，大多数浏览器都原生支持它或通过插件支持。早些时候，SVG 被推广为绘制形状的标准，但由于其速度和低级协议，canvas 变得更受欢迎。

## 准备工作

我们需要一个支持`canvas`的浏览器。一般来说，Firefox 和 Safari 内置支持 canvas。在 Internet Explorer 中显示 canvas，可能需要来自 Mozilla 或 Google 的插件。

### 注意

Google Chrome Frame（可在[`code.google.com/chrome/chromeframe/)`](http://code.google.com/chrome/chromeframe/)找到）是一个插件，它将 Chrome 的 JavaScript 引擎添加到 Internet Explorer；它也支持`canvas`。

`explorercanvas`（可在[`code.google.com/p/explorercanvas/)`](http://code.google.com/p/explorercanvas/)找到）是一个 JavaScript 库，添加后将`canvas`转换为 VML 并在 IE 上支持它。

## 如何做...

当一个由 Shaun 开发的 Greasemonkey 脚本能够识别 MegaUpload（文件共享网站）的验证码时，JavaScript 的 OCR 概念引起了人们的关注。对于文件共享网站，验证码是避免机器下载的一种方式，这可能来自竞争对手或盗版者。这里的 Greasemonkey 脚本使用了`canvas`及其通过 JavaScript 访问的能力。

### 注意

Greasemonkey 最初是一个 Firefox 扩展，用于在特定域和 URL 上执行用户脚本，当页面显示时改变外观或功能。现在，其他浏览器也开始在一定程度上支持 Greasemonkey 脚本。

完整的源代码可以在 Greasemonkey 的网站上找到—[`www.userscripts.org/scripts/review/38736`](http://www.userscripts.org/scripts/review/38736)。在这里，我们将使用`canvas`的 JavaScript 来审查这个概念：

1.  验证码图像加载到`canvas`并通过`getImageData()`读取图像数据。

1.  然后将图像转换为灰度。

1.  图像进一步分成三部分，每部分一个字符。对于 MegaUpload 的验证码来说，这更容易，因为它的距离是固定的。

1.  图像进一步处理以将其转换为两种颜色—黑色和白色

1.  进一步裁剪分割的图像以获得一种受体。

1.  然后将受体数据传递给神经网络以识别字符。神经网络数据预先使用以前运行的数据进行种植，以获得更好的匹配。

## 它是如何工作的...

以下图像显示了在 MegaUpload 网站上找到的一个示例验证码：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_04_03.jpg)

在这里，描述的每个处理阶段对于更好地识别验证码至关重要：

1.  将验证码图像加载到`canvas`：

验证码图像通过 Greasemonkey 的 Ajax 调用加载到画布上以获取图像：

```php
var image = document.getElementById('captchaform').parentNode.getElementsByTagName('img')[0];
GM_xmlhttpRequest( {
method: 'GET',
url: image.src,
overrideMimeType: 'text/plain; charset=x-user-defined',
onload: function (response) {
load_image(response.responseText);
}
});

```

1.  将图像转换为灰度：

```php
for (var x = 0; x < image_data.width; x++) {
for (var y = 0; y < image_data.height; y++) {
var i = x * 4 + y * 4 * image_data.width;
var luma = Math.floor(image_data.data[i] * 299 / 1000 + image_data.data[i + 1] * 587 / 1000 + image_data.data[i + 2] * 114 / 1000);
image_data.data[i] = luma;
image_data.data[i + 1] = luma;
image_data.data[i + 2] = luma;
image_data.data[i + 3] = 255;
}
}

```

如前面的代码块所示，图像数据是逐像素采取的。每个像素的颜色值取平均值。最后，通过调整颜色值将图像转换为灰度。

1.  将图像转换为只有黑色和白色颜色：

```php
for (var x = 0; x < image_data.width; x++) {
for (var y = 0; y < image_data.height; y++) {
var i = x * 4 + y * 4 * image_data.width;
// Turn all the pixels of the certain colour to white
if (image_data.data[i] == colour) {
image_data.data[i] = 255;
image_data.data[i + 1] = 255;
image_data.data[i + 2] = 255;
// Everything else to black
}
else {
image_data.data[i] = 0;
image_data.data[i + 1] = 0;
image_data.data[i + 2] = 0;
}
}
}

```

在这里，其他颜色可以称为“噪音”。通过保留只有黑色和白色颜色来去除“嘈杂”的颜色。

1.  裁剪不必要的图像数据：

由于图像的尺寸固定且文本距离固定，矩阵的矩形大小设置为去除不必要的数据，因此图像被裁剪。

```php
cropped_canvas.getContext("2d").fillRect(0, 0, 20, 25);
var edges = find_edges(image_data[i]);
cropped_canvas.getContext("2d").drawImage(canvas, edges[0], edges[1], edges[2] - edges[0], edges[3] - edges[1], 0, 0, edges[2] - edges[0], edges[3] - edges[1]);

```

1.  应用神经网络：

**ANN（人工神经网络）**（或简称神经网络）是一种自学习的数学模型。它是一个自适应系统，根据其外部或内部信息流改变其结构。设计是模仿动物大脑的，因此每个处理器单元都有本地存储器和学习组件。

处理后的图像数据充当神经网络的受体。当传递给预先种植数据的神经网络时，它可以帮助我们找出验证码图像中的字符：

```php
image_data[i] = cropped_canvas.getContext("2d").getImageData(0, 0, cropped_canvas.width, cropped_canvas.height);

```

根据验证码的复杂性，甚至可以在字符识别的最后一步使用线性代数。应用线性代数而不是神经网络可能会提高检测速度。但是，神经网络在各个方面表现相对更好。

## 还有更多...

`Canvas`还有其他有趣的应用。它预计将取代 Flash 组件。一些值得注意的画布应用程序如下：

+   CanvasPaint（[`canvaspaint.org/`](http://canvaspaint.org/)），界面类似于 MS Paint 应用程序

+   Highcharts（[`highcharts.com/)`](http://highcharts.com/)），一个使用`canvas`进行渲染的 JavaScript 图表 API

随机的验证码图像很难在没有人类干预的情况下破解。谷歌的

**reCAPTCHA API**围绕着使用数字化旧书的问题构建

OCR。当我们使用这个 reCAPTCHA API 时，它提供了一个带有 2 个文本的验证码：

1.  随机“已知”的验证码文本

1.  来自旧扫描书籍的“未知”文本-通过 OCR 很难辨认。用户填写这些验证码时，“已知”文本将用于验证。输入的文本与“未知”文本相匹配，用于数字化扫描的书籍。

一些网站提供 API 上的人类 Captcha 解码服务。验证码图像通过 API 上传；在另一部分，“数据输入”人类解码器将输入文本，然后将其发送回来。这些服务通常被自动机器人而不是人类使用。提供此类服务的一些网站如下：

+   Death By Captcha ([`www.deathbycaptcha.com/`](http://www.deathbycaptcha.com/))

+   DeCaptcher ([`www.decaptcher.com/`](http://www.decaptcher.com/))

# 在网格中显示数据

在 Web 2.0 网站中，“数据网格”一词通常指的是使用 HTML 表格的类似于电子表格/MS Excel 的显示。数据网格为用户提供了可用性和易于访问数据。数据网格的一些常见特性包括：

+   能够对数据进行分页

+   能够对列进行排序

+   能够对行进行排序

+   能够快速搜索或过滤数据字段

+   能够拥有冻结/固定行或标题

+   能够冻结列或标题

+   能够突出显示任何感兴趣的列

+   能够从不同的数据源加载，如 JSON、JavaScript 数组、DOM 和 Hijax

+   能够将数据导出到不同的格式

+   能够打印格式化数据

## 准备工作

我们将需要来自[`datatables.net/`](http://datatables.net/)的 DataTables jQuery 插件，以及 jQuery 核心。根据我们的需求，有时我们可能需要额外的插件。

## 如何做...

在简单的实现中（不使用任何其他数据源），将数据显示在 HTML 表格中就足够了。DataTables，不使用任何插件和额外选项，可以将其转换为类似电子表格的 UI，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_04_04.jpg)

在 HTML 表格中，以正常的表格格式显示数据就足够了。在这里，我们使用以下代码显示具有姓名、电话号码、城市、邮政编码和国家名称的用户记录：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="css/style.css" />
<script src="js/jquery.js" type="text/javascript">
</script>
<script src="js/jquery.dataTables.min.js" type="text/javascript">
</script>
<script src="js/script.js" type="text/javascript">
</script>
<title>jQuery DataTables</title>
</head>
<body>

<table id="grid" cellpadding="0" cellspacing="0" border="0"
class="display">
<thead>
<tr>
<th>Name</th>
<th>Phone</th>
<th>City</th>
<th>Zip</th>
<th>Country</th>
</tr>
</thead>
<tbody>
<tr>
<td>Garrett</td>
<td>1-606-901-3011</td>
<td>Indio</td>
<td>Q3R 3C6</td>
<td>Guatemala</td>
</tr>
<tr>
<td>Talon</td>
<td>1-319-542-9085</td>
<td>Kent</td>
<td>51552</td>
<td>Slovakia</td>
</tr>
</tr>
...
<tr>
<td>Bevis</td>
<td>1-710-939-1878</td>
<td>Lynwood</td>
<td>49756</td>
<td>El Salvador</td>
</tr>
<tr>
<td>Edward</td>
<td>1-431-901-7662</td>
<td>Guthrie</td>
<td>95899</td>
<td>Singapore</td>
</tr>
</tbody>
<tfoot>
<tr>
<th>Name</th>
<th>Phone</th>
<th>City</th>
<th>Zip</th>
<th>Country</th>
</tr>
</tfoot>
</table>
</body>
</html>

```

注意：在原始代码中，我们有 100 行。在这里，为简洁起见，许多行被剪掉了。

像往常一样，只需通过 jQuery 插件调用附加数据网格行为即可：

```php
jQuery(document).ready(function($){
 $('#grid').dataTable(); 

});

```

## 它是如何工作的...

DataTables 解析 HTML 表格中的数据，并将其保存在 JavaScript 对象数组中。在需要时，它会在其 HTML 模板中呈现内容。如前面的屏幕截图所示，它添加了一个搜索框、分页链接和一个下拉菜单，用于选择每页显示的记录数。包含在`thead`元素中的表头使用排序图标和链接进行装饰。当在搜索框中输入任何文本时，它会扫描保存的对象数组并重新绘制网格。对于快速将普通数据表转换为网格，这可能是相当足够的，但是 DataTables 除了选项和插件之外还提供了许多其他功能。

当需要关闭 DataTables 提供的某些功能时，我们可以通过选项来具体禁用它们，如下所示：

```php
$('#grid').dataTable({
'bPaginate':false,
'bSort':false
});

```

在这里，我们已禁用了分页元素和排序功能。同样，我们可以禁用任何其他功能。当我们不需要网格功能时，最好不要初始化 DataTables，而不是使用选项禁用功能，因为这会影响性能。

DataTables 的默认配置与 jQuery UI 主题框架不兼容；为了使其兼容，我们必须将`bJQueryUI`标志设置为`true:`

```php
$('#grid').dataTable({
'bJQueryUI': true
});

```

这样做的主要优势是更容易为所有 JavaScript 组件提供一致的主题/外观。

当用户滚动数据时，我们可能希望提供冻结的标题，以便值能够轻松地进行对应。为此，DataTables 提供了`FixedHeader`附加组件。设置固定标题很容易：

```php
var oTable = $('#grid').dataTable();
new FixedHeader(oTable);

```

使用 jQuery 的插件架构，我们可以轻松扩展 DataTables，从而添加任何网格功能。

## 还有更多...

不同的数据网格插件提供不同的用户界面和不同的功能。了解它们的区别总是很好的。有时，在一个繁重的 Ajax 网站上，我们可能想要显示数百万条记录。让我们看看有哪些工具可用于这些目的：

### 其他数据网格插件

我们有很多 jQuery 插件可用于数据网格。其中，以下是相对受欢迎并提供许多功能的：

+   jQuery Grid: [`www.trirand.com/blog/`](http://www.trirand.com/blog/)

+   Flexigrid: [`flexigrid.info/`](http://flexigrid.info/)

+   jqGridView: [`plugins.jquery.com/project/jqGridView`](http://plugins.jquery.com/project/jqGridView)

+   Ingrid: [`reconstrukt.com/ingrid/`](http://reconstrukt.com/ingrid/)

+   SlickGrid: [`github.com/mleibman/SlickGrid`](http://github.com/mleibman/SlickGrid)

+   TableSorter: [`tablesorter.com/`](http://tablesorter.com/)

当需要类似于这些插件中的任何一个的用户界面时，明智的做法是使用它们，而不是自定义 DataTables，如前一节所述。

### 显示数百万条数据项

在撰写本文时，并非所有数据网格实现都能容纳大量记录，除了 SlickGrid。有关其无限行的补丁和讨论可在[`github.com/mleibman/SlickGrid/tree/unlimited-rows`](http://https://github.com/mleibman/SlickGrid/tree/unlimited-rows)找到。


# 第五章：调试和故障排除

在这一章中，我们将涵盖以下主题：

+   使用 Firebug 和 FirePHP 进行调试

+   使用 IE 开发者工具栏进行调试

+   避免框架$冲突

+   使用 JavaScript 的匿名函数

+   修复 JavaScript 中的内存泄漏

+   修复内存泄漏

+   顺序化 Ajax 请求

如果您不知道如何有效地使用 Ajax 进行调试，调试和故障排除可能会给您带来很大的麻烦。在本章中，我们将学习一些工具和技术来调试和故障排除 Ajax 应用程序。

首先，我们将研究为 Mozilla Firefox 浏览器构建的强大工具—Firebug 和 FirePHP。这两个工具可能是用于调试 Ajax 请求和响应最受欢迎的工具。在接下来的部分中，我们将研究另一个重要但不太复杂的工具—IE 开发者工具栏。

之后，我们将研究一种避免在单个网页中同时使用 jQuery 和 Mootools 时常见的美元（`$`）冲突的技术。

我们还将研究如何对 Ajax 应用程序的 Ajax 请求进行排序，这些应用程序需要定期更新数据。然后，我们将研究如何使用 Douglas Crockford 的 JSMin 或 Dean Edward 的 Packer 工具压缩的 JavaScript 的美化工具。最后，在本章中，我们将研究跨浏览器实现 Ajax 的技巧。

### 注意

当 Firebug 和 FirePHP 安装在 Mozilla Firefox 上时，它会比正常情况下占用更多的内存；因此，如果您的计算机内存较低，它可能会使您的系统不稳定。在这种情况下，建议您在 Firefox 的不同配置文件中安装 Firebug 和 FirePHP，您可以专门在 Web 开发期间使用它。

# 使用 Firebug 和 FirePHP 进行调试

当 Ajax 技术在复杂的 Web 应用程序中被广泛使用时，如果开发人员没有正确的工具，调试这些应用程序将成为一个头痛的问题。这就是 Firebug 和 FirePHP 派上用场的地方。**Firebug**是 Mozilla Firefox 用于调试基于 Ajax 的应用程序的一款优雅、简单、强大的附加组件。它允许您清晰地查看 Ajax 请求、响应以及通过 POST 或 GET 方法发送到服务器的数据的概况。此外，您甚至可以编辑 HTML 和 CSS 代码，并在浏览器中实时预览更改。除此之外，Firebug 还显示了网页发出的整个 HTTP 请求。它还允许您对 JavaScript 代码进行性能分析。**FirePHP**是 Firebug 的扩展，通过在 Firebug 控制台上记录信息或消息来扩展 Firebug 的功能。

### 注意

请注意，在 Firebug 中编辑的 CSS 或 HTML 代码是临时的，不会影响真实的代码。当 Mozilla Firefox 刷新时，更改会消失。

## 使用 Firebug 进行调试

**Firebug**可能是 Mozilla Firefox 浏览器中最受欢迎的附加组件之一。它允许调试、监视和编辑 CSS、HTML 和 JavaScript，以及 DOM。它有很多功能，但其中，我们将更多地讨论如何使用 JavaScript 控制台记录值或错误。

## 如何做...

所以，让我们首先安装 Firebug 来开始使用 Firebug 调试 Ajax/PHP 应用程序。

Firebug 可以从[`getfirebug.com/`](http://getfirebug.com/)下载。一旦您点击**安装 Firebug**按钮并按照网站上的步骤操作，您将看到以下弹出窗口开始安装。一旦您点击**立即安装**按钮，Firebug 就会安装在 Firefox 中。安装完成后，您可能需要重新启动 Mozilla Firefox 浏览器以完成 Firebug 的安装。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_01.jpg)

一旦安装了 Firebug，您可以通过按下*F12*或点击 Firefox 窗口右下角的 Firebug 图标来启用它。以下截图显示了启用 Firebug 时的外观：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_02.jpg)

正如您在前面的屏幕截图中所看到的，Firebug 中有六个不同的面板。让我们简要讨论每个面板：

+   **Console:** 这是 Firebug 中最有用的面板，用于调试富 Ajax 应用程序。您可以在此选项卡中记录不同的消息、信息或警告，来自 JavaScript 和 PHP（使用 FirePHP）。在这里，您有一个名为**Profile**的选项，它允许用户在指定的时间段内记录 JavaScript 活动。此外，您还可以在此面板上执行自己的代码。

+   **HTML:** 通常，添加或附加到网页的任何 HTML 元素都无法通过浏览器的**查看源代码**选项查看。但是，**HTML**窗格显示了可能已被执行的 JavaScript 代码添加的网页的实时 HTML 元素。该面板还可用于在浏览器中动态编辑 HTML/CSS 代码并实时查看输出。

+   **CSS:** 在此面板中，您可以查看网页使用的**CSS**脚本列表。此外，您还可以从此面板虚拟编辑 CSS 脚本，并直接在浏览器中查看更改属性的输出。

+   **Script:** 使用此面板，您可以找出当前网页正在使用的脚本。此面板还允许您通过设置断点并在调试时观察表达式或变量来调试 JavaScript 代码。在断点之后，您可以始终使用*F8*继续脚本执行，并且可以使用*F10*键逐步执行脚本。这是您在 Firebug 中找到的一个重要功能，通常存在于许多编程语言的**IDE（集成开发环境）**中。

+   **DOM:** 使用此面板，您可以探索网页的**文档对象模型（DOM）**。DOM 是一组对象和函数的层次结构，可以通过 JavaScript 调用或处理。此面板使您可以轻松地探索和修改 DOM 对象。

+   **Net:** 此面板被称为网页的**网络活动监视**面板。启用时，此面板会显示页面发出的每个 HTTP 请求以及加载对象（如 CSS 文件、图像或 JavaScript 文件）所花费的时间。除此之外，您还可以检查每个 HTTP 请求和响应的 HTTP 标头。除此之外，还可以在此面板和控制台面板中找到`XMLHttpRequest`的详细信息，以及其他信息，如 Ajax 请求、响应、HTTP 方法以及通过 GET 或 POST 方法提供的数据。

## 它是如何工作的...

Firebug API 提供了一个非常强大的对象**console**，可以直接将数据记录到**Console**面板。它可以记录任何类型的 JavaScript 数据和对象到控制台。您可以使用流行的`console.log()`函数轻松地将数据写入控制台，看起来像`console.log('testing')`；。您可以向此函数传递尽可能多的参数，如下所示：

```php
console.log(2,5,10,'testing');

```

当您使用`console.log(document.location)`在 Firebug 控制台中记录对象时，您可以在**Console**面板中看到对象列表，并链接到其属性和方法。您可以单击对象以查看属性和方法的详细信息。除了`console.log()`之外，还有其他函数可以在 Firebug 控制台中显示消息，具有不同的视觉效果。其中一些是`console.debug(), console.info(), console.warn()`和`console.error()`。

让我们看一个简单示例中信息记录的工作方式：

```php
$(document).ready(function()
{
console.log('log message');
console.debug('debug message');
console.info('info message');
console.warn('warning message');
console.error('Error message');
console.log(document.location);
});

```

前面的代码片段是使用 JavaScript 的 jQuery 框架的简单示例。

### 注意

您可以在本书的第二章*基本实用程序*中找到有关 jQuery 的更多信息。有关 jQuery 的更多信息可以在[`www.jquery.com`](http://www.jquery.com)找到。

所有控制台的不同功能都会在**Firebug**的**Console**面板中执行并显示，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_03.jpg)

您可以看到上述代码的执行在控制台中产生了不同类型的消息，并且具有不同的颜色。您还可以注意到`console.log(document.location)`；产生了该对象的不同属性的超链接。

### 注意

如果您在 JavaScript 代码的开发环境中使用`console.log()`或任何其他控制台函数，请确保 Firebug 已激活；否则，当代码中遇到这些函数时，JavaScript 代码的执行可能会被中断，导致意外的结果。在 Internet Explorer 7 或更早版本中也可能发生同样的情况。请确保在将网站移至生产环境时删除所有控制台函数。

## 更多内容...

现在，让我们看看 Firebug 如何帮助您调试`XMLHttpRequest`，使用另一个例子，其中来自 PHP 脚本的 Ajax 响应是不可预测的。

以下 JavaScript 代码发出了 Ajax 请求：

```php
$(document).ready(function()
{
$.ajax({
type: "POST",
url: "test.php",
data: "start=1&end=200",
success: function(msg) {
console.log('number is '+msg); msg = parseInt(msg);
if(msg%2==0)
console.info('This is even number');
else
console.info('This is odd number');
}
});
});

```

上述代码是 jQuery JavaScript 代码。我们正在向`test.php`发出 Ajax 请求（POST 方法），并使用值为`1`和`200`的`start`和`end`作为 POST 数据。现在，让我们看看 PHP 中的服务器端脚本：

```php
<?php
echo rand($_POST['start'],$_POST['end']);
?>

```

服务器端代码只是在`start`和`end`参数之间选择一个随机数，这些参数在 PHP 中作为 POST 数据可用。

现在，让我们回头看看上述 JavaScript 代码中 Ajax 的`success`函数。它首先将来自服务器端脚本的数字记录到 Firebug 控制台。然后，使用`parseInt()`函数将这个数字严格转换为整数类型。来自 Ajax 的数字基本上是`String`数据类型，不能进行数学运算；因此，首先将其转换为整数。

之后，使用模数运算符检查这个数字，以查看它是奇数还是偶数，并相应地在**Firebug**控制台中显示信息。让我们看看 Firebug 控制台中的结果：

![更多内容...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_04.jpg)

如您在屏幕截图中所见，日志和消息会相应地显示。这些都是琐碎的，但您可以在控制台的第一行中看到一些新的东西，并且您可以轻松猜到这是 Ajax 请求，左侧有一个**+**符号。

让我们尝试通过点击**+**符号来探索 Ajax 请求和响应的细节。结果如下：

![更多内容...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_05.jpg)

如您在上述屏幕截图中所见，第一个选项卡是**Headers**；它显示了请求和响应的 HTTP 头部。

**Post**部分显示了通过 POST 方法向服务器发送的数据。

**Response**选项卡显示了 Ajax 请求的响应。

此外，最后一个选项卡显示了 HTML 格式的数据，如果响应是 HTML 格式的话。这个最后一个选项卡可以是 XML、JSON 或 HTML，具体取决于来自服务器端脚本的数据响应。

## 使用 FirePHP 进行调试

Firebug 允许您从 JavaScript 将调试消息记录到控制台。然而，在一个 Ajax 应用程序的非常复杂的服务器端脚本中，如果我们使用`console.log()`函数将所有消息记录为单个字符串，调试应用程序可能会变得非常困难。当我们需要调试涉及非常复杂 PHP 脚本的富 Ajax 应用程序时，FirePHP 就派上用场了。FirePHP 是 Firebug 的扩展，Firebug 本身是 Mozilla Firefox 浏览器的热门附加组件。FirePHP 允许您使用 FirePHP 库将调试消息和信息记录到 Firebug 控制台。

### 注意

如果您从 PHP 代码中传递 JSON 或 XML 数据作为 Ajax 响应，并使用 JavaScript 和 FirePHP 解析它，然后将一些消息记录到控制台，您可能会担心会破坏应用程序。不会；FirePHP 通过特殊的 HTTP 响应头将调试消息发送到浏览器，因此通过 FirePHP 记录的消息不会破坏应用程序。

## 准备就绪

要安装 FirePHP，您需要在 Mozilla Firefox 浏览器中安装 FireBug。您可以从其官方网站[`www.firephp.org/`](http://www.firephp.org/)安装 FirePHP。您需要点击**获取 FirePHP**按钮并按照安装 FirePHP 的步骤进行安装。安装了 FirePHP 后，您需要下载 PHP 库以与 FirePHP 一起使用。您可以从[`www.firephp.org/HQ/Install.htm`](http://www.firephp.org/HQ/Install.htm)下载 PHP 库。

现在，FirePHP 已安装并启用，您还已经下载了 FirePHP 的 PHP 库。让我们看看如何使用它：

![准备就绪](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_06.jpg)

## 它是如何工作的...

要开始使用 FirePHP，首先需要在您的 PHP 代码中包含核心 FirePHP 类，如下所示：

```php
require_once('FirePHPCore/FirePHP.class.php');

```

在包含库后，您需要开始输出缓冲，因为已登录的消息将作为 HTTP 响应头发送：

```php
ob_start();

```

### 提示

如果在`php.ini`指令中打开了输出缓冲，您不需要显式调用`ob_start()`函数。有关**输出缓冲**配置的更多信息，请访问[`us.php.net/manual/en/outcontrol.configuration.php#ini.output-buffering`](http://us.php.net/manual/en/outcontrol.configuration.php#ini.output-buffering)。

现在，在此之后，让我们创建 FirePHP 对象的实例：

```php
$fp = FirePHP::getInstance(true);

```

之后，让我们使用 FirePHP 将一些消息记录到 FireBug 控制台中：

```php
$var = array('id'=>10, 'name'=>'Megan Fox','country'=>'US');
$fp->log($var, 'customer');

```

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_07.jpg)

正如您在前面的屏幕截图中所看到的，数组以详细格式显示在 Firebug 控制台中。现在，让我们尝试以更加花哨的方式记录更多的变量。

### 注意

当鼠标光标移动到控制台中的已登录变量上时，FirePHP 的变量查看器（参见前面的屏幕截图）会显示出来。

此外，让我们尝试使用不同的函数将不同类型的调试消息记录到 FireBug 控制台中，如下所示：

```php
$fp->info($var,'Info Message');
$fp->warn($var,'Warn Message');
$fp->error($var,'Error Message');

```

上述函数与 Firebug 的控制台函数非常相似。这些函数的输出在 Firebug 控制台中如下所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_08.jpg)

正如您在前面的屏幕截图中所看到的，FirePHP 库的`info()、warn()`或`error()`函数可以以不同的样式记录消息，用于调试 PHP 代码。

### 注意

请确保在生产模式下使用网站时禁用 FirePHP 日志记录，否则任何安装了 FirePHP 和 Firebug 的人都可以轻松查看网站中的敏感信息。您可以通过在创建 FirePHP 对象实例后立即调用`$fp->setEnabled(false)`函数来禁用 FirePHP 日志记录。

## 还有更多...

FirePHP 还有**Procedural API**。要使用 FirePHP 的 Procedural API，您需要在代码中包含`fb.php`（FirePHP PHP 库提供），如下所示：

```php
require_once('FirePHPCore/fb.php');

```

然后，您可以通过使用`fb()`函数简单地将消息记录到 Firebug 控制台。例如，您可以使用以下代码将消息记录到控制台中：

```php
fb('logged message');
fb($var, 'customer');

```

### 提示

当您在代码中包含了`fb.php`后，您可以直接使用`fb`类调用`info()、warn()、error()`或`log()`函数。例如，您可以使用`FB::info($var,'Info Message')`来将`info`消息显示到控制台中。

# 使用 IE 开发者工具栏进行调试

与 Firebug 类似，Internet Explorer 也包含一个开发者工具栏，用于调试和编辑网页的 HTML、CSS 和 JavaScript 代码。**IE 开发者工具栏**内置于 Internet Explorer 8 中。在以前的版本中，它可以作为 Internet Explorer 的附加组件使用。如果您使用的是 Internet Explorer 7 或更低版本，则可以从 Microsoft 网站下载 IE 开发者工具栏，网址为[`www.microsoft.com/downloads/en/details.aspx?familyid=95E06CBE-4940-4218-B75D-B8856FCED535&displaylang=en`](http://www.microsoft.com/downloads/en/details.aspx?familyid=95E06CBE-4940-4218-B75D-B8856FCED535&displaylang=en)。但是，在本主题中，我们将讨论 Internet Explorer 8 中可用的 IE 开发者工具栏。

### 提示

除了 Firefox 之外，您始终可以在任何浏览器中使用 Firebug Lite。以下是有关如何在任何浏览器中使用 Firebug Lite 的说明：[`getfirebug.com/firebuglite`](http://getfirebug.com/firebuglite)。

## 准备就绪

Internet Explorer **开发者工具**主要由四个不同的面板组成，用于调试和编辑 HTML、CSS 和 JavaScript。

![准备就绪](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_09.jpg)

它们如下：

+   **HTML**面板：此面板用于查看网站的 HTML 代码。使用此面板，您可以查看单个 HTML 元素的大纲，更改它们的属性和 CSS 属性，并在浏览器中实时预览输出。

+   **CSS**面板：这与 Firebug 的 CSS 面板非常相似。在这里，您可以查看和编辑与网页关联的不同样式表下的 CSS 属性。您还可以实时预览 CSS 属性的更改。

+   **Script**面板：此面板允许您调试网页的 JavaScript 代码。此外，您可以在 JavaScript 代码上设置断点，并逐步执行代码并观察变量。

+   **Profiler**面板：IE 开发者工具栏的**Profiler**面板允许您分析网页中使用的 JavaScript 函数的性能。它记录执行这些函数所需的时间以及它们被调用的次数；因此，如果其中一些函数编写得很差，调试这些函数就变得容易。

## 如何做...

开发者工具栏的**Script**面板允许通过设置断点、逐步执行代码和观察变量来调试脚本。此外，与 Firebug 一样，您还可以使用控制台函数向控制台记录消息。

例如，以下 JavaScript 控制台函数将分别向 IE 开发者工具的控制台发送日志、信息、警告和错误消息：

```php
console.log('log message');
console.info('info message');
console.warn('warning message');
console.error('Error message');

```

代码的输出在 IE 开发者工具的控制台中看起来像下面的截图：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_10.jpg)

您可以看到消息以与 Firebug 中相似的方式显示在控制台中。但是，遗憾的是，直到今天为止，Internet Explorer 还没有像 FirePHP 这样的附加组件。

# 避免框架$冲突

`$`在许多 JavaScript 框架中都是一个常用的函数名或变量名。当两个不同的 JavaScript 库一起使用时，使用$符号可能会发生冲突的可能性很高，因为它们可能会用于不同的目的。假设在一个页面中使用了两个框架，它们是 jQuery 和`prototype.js:`

```php
<script type="text/javascript" src="prototype.js"></script>
<script type="text/javascript" src="jquery.js"></script>

```

当两个框架一起使用并且两个框架都使用`$`符号时，结果可能是不可预测的，并且可能会中断，因为 jQuery 将`$`视为 jQuery 对象，而在`prototype.js`中，它是一个 DOM 访问函数。代码`$('mydiv').hide()`;在包含前面 JavaScript 框架用法的网页中可能无法正常工作。这是因为 jQuery 包含在最后一行，但代码`$('mydiv').hide()`;是来自`prototype.js`框架的代码，这会导致意外的结果。

## 准备就绪

如果你正在使用 jQuery 与其他框架，没有问题。jQuery 有一个神奇的`noConflict()`函数，允许你在其他框架中使用 jQuery。

## 如何做...

现在，让我们尝试使用 jQuery 的`noConflict()`函数来使用上述代码：

```php
<script type="text/javascript" src="prototype.js"></script>
<script type="text/javascript" src="jquery.js"></script>
<script type="text/javascript" ></script
var $jq = jQuery.noConflict();
$jq(document).ready(function(){
$jq("p.red").hide();
});
$('mydiv').hide();
</script>

```

## 它是如何工作的...

如你在上述代码中所见，我们创建了另一个别名`$jq`来代替`$`来引用 jQuery 对象。现在在剩下的代码中，可以使用`$jq`来引用 jQuery 对象。`$`可以被`prototype.js`库使用，用于其余的代码。

# 使用 JavaScript 的匿名函数

JavaScript 的**匿名函数**非常有用，可以避免 JavaScript 库中的冲突。

## 如何做...

让我们首先通过一个例子了解匿名函数：

```php
(function(msg)
{ alert(msg); })
('Hello world');

```

当我们在浏览器中执行上述代码时，它将显示警报`Hello world`。现在，这很有趣！一个函数被定义并执行！让我们简化相同的代码片段，看看它是如何工作的：

```php
Var t = function(msg){
alert(msg);
};
t('Hello world');

```

如果你看到等效的代码，那很简单。唯一的区别是这个简化的代码将变量名`t`与函数关联起来，而在另一个代码中，函数名是匿名的。匿名函数在声明后立即执行。

匿名函数在创建 JavaScript 框架的插件时非常有用，因为你不必担心与其他插件的函数同名而产生冲突。记住，给两个函数起相似的名字会导致 JavaScript 错误，并可能破坏应用程序。

现在，让我们看看如何使用 jQuery 的匿名函数来避免`$`的冲突：

```php
(function($) {
$(function() {
$('#mydiv').hide();
});
})(jQuery);

```

## 它是如何工作的...

在上述函数中，jQuery 对象作为`$`参数传递给函数。现在，匿名函数内部有一个局部作用域，因此可以在匿名函数内部自由使用`$`，以避免冲突。这种技术经常用于创建 jQuery 插件，并在插件代码中使用`$`符号。

## 还有更多...

现在，让我们在 Mootools 框架中类似地使用匿名函数来避免`$`的冲突。在 Mootools 框架中，`$`符号指的是`document.id`对象。

```php
(function($){
$('mydiv').setStyle('width', '300px');
})(document.id);

```

在上述函数中，`$`可以在本地使用，它指的是 Mootools 框架的`document.id`对象。

# 修复 JavaScript 中的内存泄漏

如果 JavaScript 代码没有考虑内存使用，可能会导致内存泄漏成为 JavaScript 中繁琐的问题。这样的代码可能会通过过载内存使你的浏览器变得不稳定。

## 什么是内存泄漏？

**内存泄漏**是指 JavaScript 分配的内存占用了物理内存，但无法释放内存。JavaScript 是一种进行垃圾回收的语言。当创建对象时，内存被分配给对象，一旦对象没有更多的引用，内存就会被释放。

## 可能导致内存泄漏的原因是什么？

内存泄漏可能有很多原因，但让我们探讨两个主要可能性：

+   你创建了大量未使用的元素或 JavaScript 对象而没有清理它们。

+   你的 JavaScript 代码中使用了循环引用。循环引用是指 DOM 对象和 JavaScript 对象相互循环引用。

# 修复内存泄漏

首先，让我们了解如何找出脚本生成了不需要的元素；我们可以使用 Firebug 控制台来做到这一点。你可以将以下代码放入 Firebug 的控制台中，如下面的屏幕截图所示：

```php
console.log( document.getElementsByTagName('*').length )

```

![修复内存泄漏](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_11.jpg)

### 提示

上述代码将记录 DOM 中元素的所有计数。因此，如果你看到页面后续使用中计数呈指数增长，那么你的代码存在问题，你应该尝试删除或移除不再使用的元素。

## 如何做...

找到了不需要的脚本创建的元素后，我们如何调试？

假设有一个 JavaScript 函数一遍又一遍地被调用，创建了一个巨大的堆栈。让我们尝试使用`console.trace()`函数来调试这样的代码：

```php
<html >
<head>
<script type="text/javascript">
var i=0
function LeakMemory(){
i++;
console.trace();
if(i==50)
return;
LeakMemory();
}
</script>
</head>
<body>
<input type="button"
value="Memory Leaking Test" onclick="LeakMemory()" />
</body>
</html>

```

当你点击按钮时，它会调用函数`LeakMemory()`。该函数调用自身 50 次。我们还使用`console.trace()`函数来跟踪函数调用。你可以在 Firebug 控制台中看到以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_12.jpg)

## 它是如何工作的...

你可以清楚地看到`console.trace()`函数跟踪每个函数调用。它让你调试和跟踪 JavaScript 应用程序，该应用程序正在创建一个不需要的函数调用堆栈。

接下来，让我们用一个例子来讨论 JavaScript 中的循环引用内存泄漏模式：

```php
<html>
<body>
<script type="text/javascript">
document. Write("Circular references between JavaScript and DOM!");
var obj;
window.onload = function(){
obj=document.getElementById("DivElement");
document.getElementById("DivElement").expandoProperty=obj;
obj.bigString=new Array(1000).join(new Array(2000).join("XXXXX"));
};
</script>
<div id="DivElement">Div Element</div>
</body>
</html>

```

### 注意

上述例子摘自 IBM 网站上关于内存泄漏的一篇很棒的文章：[`www.ibm.com/developerworks/web/library/wa-memleak/`](http://www.ibm.com/developerworks/web/library/wa-memleak/)。

如你在上面的例子中所见，JavaScript 对象`obj`引用了一个 ID 为`DivElement`的 DOM 对象。`DivElement`引用了 JavaScript 对象`obj`，从而在两个元素之间创建了循环引用，并且由于这种循环引用，两个元素都没有被销毁。

当你运行上述代码时，让我们看看在 Windows 任务管理器中内存消耗如何上升：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_13.jpg)

正如你所看到的，当我同时运行包含上述代码的网页 4-5 次时，内存使用曲线在中间上升。

## 还有更多...

修复循环引用内存泄漏非常容易。只需在执行代码后将对象分配给`null`元素。让我们看看如何在上面的例子中修复它：

```php
var obj;
window.onload = function(){
obj=document.getElementById("DivElement");
document.getElementById("DivElement").expandoProperty=obj;
obj.bigString=new Array(1000).join(new Array(2000).join("XXXXX"));
};
obj = null.

```

现在，在一个网页中执行上述代码时，同时查看任务管理器。你不会看到内存使用量有显著的波动。

# 对 Ajax 请求进行排序

顾名思义，Ajax 是异步的，因此代码的顺序可能不会被遵循，因为大部分逻辑活动是在 HTTP 请求完成时完成的。

## 如何做...

让我们尝试用一个例子来理解 Ajax 请求：

```php
$(document).ready(function()
{
$.ajax({
type: "POST",
url: "test.php",
data:'json',
data: "bar=foo",
success: function(msg){
console.log('first log');
}
});
console.log('second log')
});

```

执行后，上述代码在 Firebug 控制台中显示如下：

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_05_14.jpg)

## 它是如何工作的...

尽管`$.ajax`函数首先被调用，但由于代码的异步性质，**第二个日志**会先被打印出来（因为这行代码直接跟在`$.ajax`函数后面）。然后，当 HTTP 请求完成时，`success: function`被执行，之后**第一个日志**被打印到控制台。

对 Ajax 请求进行排序是实时应用中广泛使用的一种技术。在下面的例子中，让我们使用一个简单的使用 jQuery 的函数来对 Ajax 请求进行排序，以在浏览器中显示服务器时间。首先，让我们看一下将发送 Ajax 请求序列的 JavaScript 函数：

```php
function get_time()
{
//make another request
$.ajax({
cache: false,
type: "GET",
url: "ajax.php",
error: function () {
setTimeout(get_time, 5000);
},
success: function (response)
{
$('#timer_div').html(response);
//make another request instantly
get_time();
}
});
}

```

该函数很简单。在每次成功的 Ajax 请求后，它再次调用相同的函数。请注意，我们一次只向服务器发送一个请求。完成后，会发送另一个请求。

如果出现错误，或者说 Ajax 请求没有完成，我们将在等待 5 秒后重试发送另一个 Ajax 请求。通过这种方式，如果服务器面临无法完成请求的问题，我们可以最小化向服务器发送请求的次数。

现在，让我们看一下`ajax.php`中的 PHP 代码：

```php
<?php
sleep(1);
echo date('Y-m-d H:i:s');
?>

```

如你在上面的 PHP 代码中所见，服务器在打印当前时间之前等待一秒。这通常是实时 Web 应用中服务器端脚本的工作方式。例如，实时聊天应用程序会等待直到新的聊天消息进入数据库。一旦新消息在数据库中，应用程序会将最新的聊天消息发送到浏览器以显示它。

# 跨浏览器和 Ajax

+   我们都知道 Ajax 技术的核心是 JavaScript 中可用的`XMLHttpRequest`对象。但是这个对象在你的浏览器中不一定可用，特别是在 Internet Explorer 中，这取决于浏览器和平台。

+   它可以在 Mozilla Firefox、Google Chrome、Safari 甚至支持原生`XMLHttpRequest`对象的 IE7 或更高版本中本地实例化如下：

```php
var xmlHttpObj = new XMLHttpRequest();

```

+   现在，在 Internet Explorer 6 或 5 中，要使用`XMLHttpRequest`对象，它必须在 JavaScript 中作为 ActiveX 对象创建：

```php
var xmlHttpObj = new ActiveXObject("MSXML2.XMLHTTP.3.0");

```

+   但是即使是 ActiveX 对象类在不同的 Windows 平台上也可能不同，所以我们可能还需要使用以下代码：

```php
var xmlHttpObj = new ActiveXObject("Microsoft.XMLHTTP");

```

+   现在，让我们创建一个 Ajax 函数，它将在跨浏览器平台中返回`XMLHttpRequest`对象：

```php
function getAjaxObj()
{
var xmlHttpObj = null;
// use the ActiveX control for IE5 and IE6
try
{
xmlHttpObj = new ActiveXObject("MSXML2.XMLHTTP.3.0");
}
catch (e)
{
try
{
xmlHttpObj = new ActiveXObject("Microsoft.XMLHTTP");
}
catch(e)
{
// for IE7, Mozilla, Safari
xmlHttpObj = new XMLHttpRequest();
}
}
return xmlHttpObj;
}

```

+   由于除了 Internet Explorer 之外的浏览器都不支持 ActiveX 对象，因此使用`try`和`catch`块语句创建`XMLHTTPRequest`对象的实例，以便没有 JavaScript 错误，代码可以在跨浏览器中使用。

### 注意

如果你的网页已经使用了像 jQuery 或 Mootools 这样的 JavaScript 框架，你可以使用它们的核心 Ajax 函数。这些库通常发布了支持多个浏览器和平台的函数，并且随着时间的推移进行更新，因此强烈建议使用这样的 JavaScript 库。

# 美化 JavaScript

我们已经在上一章中看到了如何使用 JSMin 来压缩 JavaScript 代码。现在，让我们尝试反向工程压缩的 JavaScript 代码并美化它。我们可以使用工具**JsBeautifier**来解压缩和美化 JavaScript 代码。它可以直接从 URL [`jsbeautifier.org/`](http://jsbeautifier.org/)使用，或者你可以使用 URL [`github.com/einars/js-beautify/zipball/master`](http://github.com/einars/js-beautify/zipball/master)从 Github 下载代码。让我们首先看一下在使用 JSMin 压缩时`get_time()`函数中的代码是什么样的：

```php
function get_time(){$.ajax({cache:false,type:"GET",url:"ajax.php",error:function(){setTimeout(get_time,5000);},success:function(response){$('#timer_div').html(response);get_time();}});}

```

当 JavaScript 代码被压缩时，文件占用的空间更小，在网页中加载速度更快，但是当我们需要向该文件添加新功能时，编辑代码变得非常困难。在这种情况下，我们需要美化 JavaScript 代码并进行编辑。现在，让我们使用[`jsbeautifier.org/:`](http://jsbeautifier.org/)来获取美化后的 JavaScript 代码。

```php
function get_time() {
$.ajax({
cache: false,
type: "GET",
url: "ajax.php",
error: function () {
setTimeout(get_time, 5000);
},
success: function (response) {
$('#timer_div').html(response);
get_time();
}
});
}

```

### 注意

在生产服务器中，建议我们使用压缩的 JavaScript 代码，因为它占用的空间更小，加载速度比美化的代码格式更快。但是在开发服务器中，建议始终使用美化的代码，以便以后可以更改或编辑。


# 第六章：优化

在本章中，我们将涵盖以下主题：

+   对象的缓存

+   使用 YSlow 获取优化提示

+   通过自动压缩和浏览器缓存加快 JavaScript 交付

+   提前触发 JavaScript/在 DOM 加载时

+   图像的延迟加载

+   通过 Apache 模块/Google mod_pagespeed 自动优化 Ajax 应用程序

作为 JavaScript 开发人员，我们经常面临性能问题——页面加载缓慢、页面响应不佳、浏览器窗口冻结等。大多数情况下，这些问题都是由于脚本中的瓶颈或我们采取的方法/算法引起的。在本章中，让我们讨论解决这些问题的可能方法。

# 对象缓存

由于 JavaScript 代码必须在客户端机器上运行，所以代码级的优化非常重要。其中最重要的是缓存或缓冲计算和对象。这种基本的优化经常被忽视。

## 准备工作

我们需要识别重复的函数调用以缓存结果；这将加快代码的性能。

## 如何做…

```php
var a = Math.sqrt(10);
var b = Math.sqrt(10);

```

在这种情况下，我们反复计算相同的`sqrt(10)`并将其存储在不同的变量中。这是多余的；正如你所知，它可以写成如下形式：

```php
var sqrt_10 = Math.sqrt(10);
var a = sqrt_10, b = sqrt_10;

```

同样，在基于选择器的框架中，建议缓存或缓冲选择器对象。例如，考虑以下 HTML 标记：

```php
<a href="#" id="trigger">Trigger</a>
<div id="container">
Container
</div>

```

以下是隐藏容器的 jQuery 代码；当点击触发链接时，它显示容器如下：

```php
$('#trigger').click(function(){
});

```

## 它是如何工作的…

如你在前面的代码片段中所看到的，我们两次使用了`$('#container')`；这意味着我们为相同的目的运行了两次`$()`。如果你看一下 jQuery 代码，`$()`调用有其他函数，最终是多余的。因此，建议将`$('#container')`缓存到另一个变量中，并按如下方式使用：

```php
var $container = $('#container'); // cache the object
$container.hide();
$('#trigger').click(function(){
$container.show();
});

```

在某些情况下，对象的缓存（如前面的代码片段所示）可以将页面的响应速度提高一倍。当将缓存应用于缓慢/复杂的选择器（如`$('div p a')`）时，速度的提高很容易感受到。

# 使用 YSlow 获取优化提示

当我们遇到性能问题时，我们需要知道该怎么做。来自 Yahoo!的**YSlow**是一个速度诊断工具，它可以根据各种因素快速列出建议。

## 准备工作

我们需要使用安装了 Firebug 插件的 Firefox 浏览器。YSlow 是 Firebug 的一个附加组件，也需要安装才能获取优化提示。安装后，它会在 Firebug 内添加另一个选项卡，如下图所示：

![准备工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_06_01.jpg)

## 如何做…

在任何页面上执行时，YSlow 都会给出一个特定于页面的优化建议报告。它还捆绑了一些优化工具，可以帮助我们快速解决性能问题。由于它是基于浏览器的工具，它无法对服务器端代码提出建议——它只能建议服务器设置，如`gzip`和`expire`头。

在安装 YSlow 时，最好将其自动运行模式关闭。否则，它将为每个页面执行，这将减慢其他页面的浏览体验。

在[`developer.yahoo.com/yslow/:`](http://    http://developer.yahoo.com/yslow/:)上执行时的报告示例截图如下：

![如何做…](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_06_03.jpg)

报告基于以下 22 条规则：

1.  最小化 HTTP 请求：

当页面有大量样式表和 JavaScript 引用时，加载时间会受到影响。每个文件都需要单独下载。解决方法是将所有 JavaScript 代码合并到一个文件中，将所有样式表合并到一个文件中。至于众多的 CSS 背景图片，我们可以使用一种称为 CSS Sprites 的技术。这样，我们可以最小化 HTTP 请求。YSlow 帮助我们识别了许多这样的 HTTP 请求，并给出了建议。

### 注意

**CSS Sprites**—是一种技术，通过它我们可以从多个 CSS 背景图形成一个称为*sprite*的单个 CSS 背景图像，通过调整 CSS 样式属性来使用相同的*sprite*图像。我们通过`background-position`属性在`sprite`中引用每个图像。

1.  使用内容交付网络：

**内容交付网络（CDN）**是一个第三方托管解决方案，用于提供静态内容和图像，其交付速度将比普通服务器设置更高，因为它是在云设置上运行的。YSlow 识别 CDN 的使用，如果我们没有使用任何 CDN，它建议我们为更好的性能使用 CDN。

1.  添加`Expires`或`Cache-Control`头：

如果在浏览器中缓存静态内容，将会提高加载速度，因为这些内容不需要再次下载。我们必须确保不对动态内容应用浏览器缓存。当我们有单个 JavaScript 和单个 CSS 文件时，为了避免 HTTP 请求，我们至少可以在浏览器级别对它们进行缓存。为此，我们可以使用`Expires`或`Cache-Control` HTTP 头。YSlow 识别 HTTP 头并建议我们在没有使用时使用浏览器缓存头。

1.  `Gzip`组件：

强烈建议通过 PHP 或 Apache 进行页面内容的`gzip`—Apache 的`mod_deflate`更可取，因为它易于配置，并且可以在交付过程中实时压缩。YSlow 可以识别`gzip`的使用，并建议我们在没有使用时使用`gzip`。

1.  将样式表放在顶部：

根据浏览器行为，如果样式表在顶部引用，用户将有更好的加载体验。如果它们在底部引用，用户将根据其下载速度看到样式的应用速度较慢。YSlow 根据样式表引用对页面进行评分。

1.  将脚本放在底部：

当脚本放在顶部时，它们会阻塞页面的加载。这在我们要链接外部脚本时非常重要，比如谷歌分析、Facebook 库等等。这些脚本可以在`</body>`标签结束之前被引用。另一个解决方案是在链接外部脚本时使用`async`属性。YSlow 根据我们链接脚本的位置对页面进行评分，并帮助我们提高速度。

1.  避免 CSS 表达式：

CSS 表达式是 Internet Explorer 在 8 版本之前将 JavaScript 与 CSS 混合的提供。根据研究，表达式经常被触发，并导致页面响应速度变慢。YSlow 检测到使用并对页面进行评分。

1.  使 JavaScript 和 CSS 外部化：

最好将 JavaScript 和 CSS 文件保持外部化，而不是内联和内部化。这样，外部文件可以在浏览器级别进行缓存，以便页面加载更快。将脚本分离到外部文件是**不显眼的 JavaScript**和基于选择器的 JavaScript 框架（如 jQuery、YUI 等）的主要关注点。

1.  减少 DNS 查找：

如果网站从不同的域引用图像、样式表和 JavaScript，DNS 查找次数会增加。尽管 DNS 查找被缓存，但当引用了许多域时，网站的加载时间会增加。YSlow 识别 URL 中不同主机名的引用。

1.  压缩 JavaScript 和 CSS：

如下一条建议所述，由于文件大小减小，经过压缩的 JavaScript 和 CSS 文件可以更快地下载。YSlow 还有一个选项/工具来压缩 JavaScript 和 CSS 文件。

1.  避免重定向：

不必要的页面重定向会影响加载速度。

1.  删除重复的脚本

不必要的重复脚本是多余的。

1.  配置 ETags：

**ETag**类似于其他浏览器缓存选项。虽然它可以避免不必要的往返，但在服务器之间不一致。因此，最好彻底禁用它，以减少 HTTP 请求头大小。

1.  使 Ajax 可缓存：

甚至 Ajax 请求也可以在浏览器端进行缓存。这样做可以增加应用的响应速度。

1.  对 Ajax 请求使用`GET`：

雅虎团队指出，对于 Ajax 请求，`POST`操作是一个两步过程，`GET`请求只需要一个 TCP 数据包。根据 HTTP 规范，`GET`操作用于检索内容，而 POST 用于发布或更新。

1.  减少 DOM 元素的数量：

如果我们在页面呈现时尝试应用 JavaScript 效果或事件，而页面包含大量 HTML 标记，那么由于 JavaScript 代码必须遍历每个 DOM 元素，页面速度会变慢。YSlow 建议我们将 DOM 元素数量保持在最小限度。

1.  没有 404：

损坏的链接会导致不必要的请求。它们通常是由于引用链接中的拼写错误或错误引起的。YSlow 会识别损坏的链接并对页面进行评分。

1.  减少 cookie 大小：

Cookie 总是在 HTTP 请求中发送。因此，如果有很多信息存储在 cookie 中，它将影响 HTTP 请求-响应时间。

1.  为组件使用无 cookie 的域：

没有必要引用 cookie 来传递静态内容。因此，更明智的做法是通过某个子域引用所有静态内容，并避免为该域设置 cookie。

1.  避免使用过滤器：

在 Internet Explorer 中使用过滤器来处理 PNG 文件是很常见的，但是使用过滤器通常会减慢页面速度。解决方案是使用 IE 已经支持的 PNG8 文件。

1.  不要在 HTML 中缩放图像：

使用大图像并将其缩小，使用“高度”和“宽度”属性并不是明智的选择。这会迫使浏览器加载大图像，即使它们必须以较小的尺寸显示。解决方案是在服务器级别调整图像大小。

1.  使`favicon.ico`图标小且可缓存：

与图像类似，favicon 图标的大小必须小且可缓存。

## 它是如何工作的...

YSlow 内置支持 JavaScript 代码最小化和通过 Yahoo！的 Smush 进行图像压缩。这是一个网络服务。它还有一个代码美化工具，可以帮助我们以格式化的方式查看 JavaScript 源代码，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_06_02.jpg)

报告及其有用的提示帮助我们寻找性能基础设施，如 CDN、无 cookie 的静态内容传递等。注意：这需要开发人员额外的努力来修复问题。

## 还有更多...

谷歌的 Page Speed 扩展可以在[`code.google.com/speed/page-speed/docs/extension.html`](http://code.google.com/speed/page-speed/docs/extension.html)下载，它提供类似的速度诊断和自动建议。在下面的屏幕截图中，我们可以看到它是如何在[`www.packtpub.com/`](http://www.packtpub.com/)网站上执行的，它提供了速度得分和建议：

![还有更多...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_06_04.jpg)

谷歌在速度诊断方面的倡议并不令人意外，因为页面速度可能会影响其搜索引擎爬虫；请记住，网站速度是谷歌 PageRankTM 中的决定性因素之一。YSlow 对页面进行从 A 到 F 的评分，而 Page Speed 提供一个 0 到 100 的分数。这两个插件使用类似的规则集来提供优化建议。

# 通过自动压缩和浏览器缓存加快 JavaScript 交付速度

JavaScript 最初是一种解释语言，但 V8 和 JIT 编译器现在正在取代解释器。V8 JavaScript 引擎最初是在 Google Chrome 和 Chromium 中引入的，它将 JavaScript 编译为本机机器代码。随着 Web 的不断发展，可能会有更强大的 JavaScript 编译器出现。

无论浏览器是否具有编译器或解释器，JavaScript 代码都必须在客户端机器上下载后才能执行。这需要更快的下载，这反过来意味着更少的代码大小。实现更少的代码空间和更快加载的最快和最常见的方法是：

+   去除空格、换行和注释——这可以通过 JSMin、Packer、Google Closure 编译器等最小化工具实现。

+   通过`gzip`进行代码压缩——所有现代浏览器都支持`gzip`内容编码，这允许内容以压缩格式从服务器传输到客户端；这反过来减少了需要下载的字节数，并提高了加载时间。

+   浏览器缓存以避免每次请求都下载脚本——我们可以强制将静态脚本在浏览器中缓存一段时间。这将避免不必要的往返。

在这个教程中，我们将快速比较 JavaScript 最小化工具，然后看看如何应用它们。

## 准备就绪

为了比较，我们需要以下最小化工具：

+   **JSMin**由 Douglas Crockford：[`www.crockford.com/javascript/jsmin.html`](http://www.crockford.com/javascript/jsmin.html)

+   **JSMin+**由 Tweakers.net（基于 Narcissus JavaScript 引擎）：[`crisp.tweakblogs.net/blog/cat/716`](http://crisp.tweakblogs.net/blog/cat/716)

+   **Packer**由 Dean Edwards：[`dean.edwards.name/packer/`](http://dean.edwards.name/packer/)

+   **YUI Compressor:**[`developer.yahoo.com/yui/compressor/`](http://developer.yahoo.com/yui/compressor/)

+   **Google Closure Compiler:**[`closure-compiler.appspot.com/`](http://closure-compiler.appspot.com/)

+   **UglifyJS:** [`github.com/mishoo/UglifyJS`](https://github.com/mishoo/UglifyJS)（PHP 版本：[`github.com/kbjr/UglifyJS.php`](http://https://github.com/kbjr/UglifyJS.php)）

对于 JavaScript 和 CSS 的自动最小化，我们将使用 Minify PHP 应用程序来自[`github.com/mrclay/minify`](http://https://github.com/mrclay/minify)。

为了比较最小化工具，让我们看看以下代码片段，重量为`931`字节。请注意，此代码包含注释、空格、换行和较长的变量和函数名称：

```php
/**
* Calculates the discount percentage for given price and discounted price
* @param (Number) actual_price Actual price of a product
* @param (Number) discounted_price Discounted price of a product
* @return (Number) Discount percentage
*/
function getDiscountPercentage(actual_price, discounted_price) {
var discount_percentage = 100 * (actual_price - discounted_price)/ actual_price;
return discount_percentage;

alert(discount_percentage); //unreachable code
}
// Let's take the book1's properties and find out the discount percentage...
var book1_actual_price = 50;
var book1_discounted_price = 48;
alert(getDiscountPercentage(book1_actual_price, book1_discounted_price));
// Let's take the book2's properties and find out the discount percentage...
var book2_actual_price = 45;
var book2_discounted_price = 40;
alert(getDiscountPercentage(book2_actual_price, book2_discounted_price));

```

1.  JSMin 由 Douglas Crockford 创建。

输出：

```php
function getDiscountPercentage(actual_price,discounted_price){var discount_percentage=100*(actual_price-discounted_price)/actual_price;return discount_percentage;alert(discount_percentage);}var book1_actual_price=50;var book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45;var book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price));

```

1.  JSMin+由 Tweakers.net（基于 Narcissus JavaScript 引擎）。

输出：

```php
function getDiscountPercentage(actual_price,discounted_price){var discount_percentage=100*(actual_price-discounted_price)/actual_price;return discount_percentage;alert(discount_percentage)};var book1_actual_price=50,book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45,book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price))

```

1.  Dean Edwards 的 Packer。

输出：

```php
function getDiscountPercentage(a,b){var c=100*(a-b)/a;return c;alert(c)}var book1_actual_price=50;var book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45;var book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price));

```

使用 Base62 编码选项输出（混淆代码）：

```php
eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('7 1(a,b){0 c=8*(a-b)/a;9 c;2(c)}0 3=d;0 4=e;2(1(3,4));0 5=f;0 6=g;2(1(5,6));',17,17,'var|getDiscountPercentage|alert|book1_actual_price|book1_discounted_price|book2_actual_price|book2_discounted_price|function|100|return||||50|48|45|40'.split('|'),0,{}))

```

1.  YUI Compressor。

输出：

```php
function getDiscountPercentage(b,c){var a=100*(b-c)/b;return a;alert(a)}var book1_actual_price=50;var book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45;var book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price));

```

1.  Google Closure Compiler。

输出：

```php
function getDiscountPercentage(a,b){return 100*(a-b)/a}var book1_actual_price=50,book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45,book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price));

```

1.  UglifyJS。

输出：

```php
function getDiscountPercentage(a,b){var c=100*(a-b)/a;return c}var book1_actual_price=50,book1_discounted_price=48;alert(getDiscountPercentage(book1_actual_price,book1_discounted_price));var book2_actual_price=45,book2_discounted_price=40;alert(getDiscountPercentage(book2_actual_price,book2_discounted_price))

```

931 字节 JavaScript 代码的表格化结果如下：

| 工具 | 删除无法到达的代码 | 压缩大小（字节） | 代码节省 |   |
| --- | --- | --- | --- | --- |
| JSMin 由 Douglas Crockford | 否 | 446 | 52.09% |   |
| JSMin+由 Tweakers.net | 否 | 437 | 53.06% |   |
| Packer 由 Dean Edwards Normal | 否 | 328 | 64.77% |   |
| 使用 Base62 编码 | 否 | 515 | 44.68% |   |
| YUI Compressor | 否 | 328 | 64.77% |   |
| Google Closure Compiler | 是 | 303 | 67.45% |   |
| UglifyJS | 是 | 310 | 66.70% |   |

所有这些工具都会去除空格、换行和不必要的注释，以减少 JavaScript 的大小。Dean Edwards 的 Packer 既有代码混淆又有最小化组件。它的 Base62 编码或代码混淆不建议使用，因为解包必须在浏览器中进行，因此会有很大的开销。

YUI Compressor 的压缩相对较好，因为它使用 Java Rhino 引擎来分析代码。Google Closure Compiler 看起来非常有前途，因为它有一个内置的编译器，可以检测到无法到达的代码，并进一步优化代码。UglifyJS 更快，因为它是用`Node.js`编写的。如前文所示，无论是 UglifyJS 还是 Google Closure Compiler 都可以删除无法到达的代码以改善代码最小化。

## 如何做…

来自[`github.com/mrclay/minify`](http://https://github.com/mrclay/minify)的**Minify**应用程序可用于自动化以下操作：

+   代码最小化

+   通过`gzip`压缩

+   通过`Last-Modified`或`ETag` HTTP 头进行浏览器缓存

我们必须将 Minify 应用程序的`min`文件夹放在文档根目录下。该文件夹包含以下内容：

+   `index.php：` 交付最小化代码的前端脚本

+   `config.php：`Minify 应用程序的设置文件

+   `groupConfig.php：`命名可以轻松压缩的文件组的设置文件

在`config.php`中，我们必须指定我们选择的压缩工具，如下所示：

```php
$min_serveOptions['minifiers']['application/x-javascript'] = array('Minify_JS_ClosureCompiler', 'JSMinPlus');

```

前面代码片段中显示的设置将首先尝试使用 Google 的 Closure 编译器，在任何错误时将使用 JSMinPlus 库。

有了这些配置，只需从以下更改 JavaScript，包括语法：

```php
<script type="text/javascript" src="/script1.js"></script>
<script type="text/javascript" src="/script2.js"></script>
<script type="text/javascript" src="/script3.js"></script>

```

到：

```php
<script type="text/javascript" src="/min/?f=script1.js,script2.js,script3.js"></script>

```

这将实现以下目标：

+   组合`script1.js，script2.js`和`script3.js`

+   压缩组合脚本

+   自动处理`gzip`内容编码

+   自动处理浏览器缓存

当有大量文件需要压缩时，我们可以利用`groupConfig.php`将文件分组到一个键中，如下所示：

```php
return array(
'js' => array('//script1.js', '//script2.js', '//script2.js')
);

```

我们可以通过键名简单地将它们引用到`g`查询字符串中，如下所示：

```php
<script type="text/javascript" src="/min/?g=js"></script>

```

## 它是如何工作的...

前端`index.php`脚本通过查询字符串`g`接收要压缩的文件。然后，逗号分隔的文件通过我们选择的压缩库进行合并和压缩：

```php
$min_serveOptions['minifiers']['application/x-javascript'] = array('Minify_JS_ClosureCompiler', 'JSMinPlus');

```

为了提高未来交付的性能，Minify 应用程序将以下版本存储到其缓存中：

+   合并压缩的 JavaScript 文件

+   合并压缩的 JavaScript 文件的 gzip 版本

存储在其缓存中的文件用于避免在压缩库上重复处理 JavaScript 文件。该应用程序还处理`Accept-Encoding` HTTP 标头，从而检测客户端浏览器对`gzip`、deflate 和传递相应内容的偏好。

该应用程序的另一个有用功能是设置`Last-Modified`或`ETag` HTTP 标头。这将使脚本在浏览器端进行缓存。只有在时间戳或内容发生变化时，Web 服务器才会向浏览器提供完整的脚本。因此，它节省了大量下载，特别是静态 JavaScript 文件内容。

请注意，jQuery 的 Ajax 方法默认情况下避免对脚本和`jsonp`数据类型的 Ajax 请求进行缓存。为此，它在查询字符串中附加了`_=[timestamp]`。当我们想要强制缓存时，我们必须显式启用它，这将禁用时间戳附加。操作如下：

```php
$.ajax({
url: "script.js",
dataType: "script",
cache: true
});

```

## 还有更多...

我们还有一些用于检查和加速交付选项的服务和应用程序。

### 比较 JavaScript 压缩工具

可以使用[`compressorrater.thruhere.net/`](http://compressorrater.thruhere.net/)上找到的基于 Web 的服务来比较许多压缩工具，从而我们可以为我们的代码选择合适的工具。

### 自动加速工具

对于自动加速，我们可以使用：

+   来自[`aciddrop.com/php-speedy/`](http://aciddrop.com/php-speedy/)的 PHP Speedy 库；它类似于 Minify 应用程序。

+   来自 Google 的`mod_pagespeed` Apache 模块。在本章的*通过 Apache 模块/Google mod_pagespeed 自动优化 Ajax 应用程序*中有解释。

# 尽早触发 JavaScript/在 DOM 加载时

在具有容器和动画的 Web 2.0 网站中，我们希望 JavaScript 代码尽快执行，以便用户在应用隐藏、显示或动画效果时不会看到闪烁效果。此外，当我们通过 JavaScript 或 JavaScript 框架处理任何事件时，我们希望诸如单击、更改等事件尽快应用于 DOM。

## 准备工作

早期，JavaScript 开发人员将 JavaScript 和 HTML 混合在一起。这种做法称为*内联脚本*。随着 Web 的发展，出现了更多的标准和实践。*不侵入式 JavaScript*实践通常意味着 JavaScript 代码与标记代码分开，并且 JavaScript 以*不侵入式*的方式处理。

以下是一些快速编写的代码，用于在单击名称字段时向用户发出消息`输入您的姓名！`：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<title>Inline JavaScript</title>
</head>
<body>
<form method="post" action="action.php">
<fieldset>
<legend>Bio</legend>
<label for="name">Name</label><br />
<input type="text" id="name" onclick=
"alert('Enter your name!')" /><br />

<input type="submit" value="Submit" />
</fieldset>
</form>
</body>
</html>

```

如前面的代码所示，JavaScript 是在`input`标记内部编写和混合的。

内联 JavaScript 方法存在一些问题，例如：

+   JavaScript 代码无法被缓存。如果我们使用单个 JavaScript 文件（一个被压缩、`gzipped`并具有适当的 HTTP 标头以在浏览器中缓存的文件），我们可以感受到速度的提升。

+   代码不能轻易维护，特别是如果有许多程序员在同一个项目上工作。对于每个 JavaScript 功能，HTML 代码都必须更改。

+   网站可能存在可访问性问题，因为 JavaScript 代码可能会阻止非 JavaScript 设备上的功能。

+   HTML 脚本大小增加。如果由于动态内容等原因 HTML 不应该被缓存，这将影响页面的速度。

## 如何做到...

可以通过将 JavaScript 代码移动到`<head>`标记来实现 JavaScript 的分离。最好将 JavaScript 代码移动到一个单独的外部文件中，并在`<head>`标记中进行链接。

在下面的代码中，我们尝试将 JavaScript 代码与前面的清单分离如下：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="script.js">
</script>
<title>Unobtrusive JavaScript</title>
</head>
<body>
<form method="post" action="action.php">
<fieldset>
<legend>Bio</legend>
<label for="name">Name</label><br />
<input type="text" id="name" /><br />
<input type="submit" value="Submit" />
</fieldset>
</form>
</body>
</html>

```

在 JavaScript 代码中，我们添加了以下代码片段：

```php
window.onload = function(){
document.getElementById('name').onclick = function(){
alert('Enter your name!');
}
}

```

如前面的代码片段所示，我们通过`document.getElementById('name')`引用元素来附加了`click`事件。请注意，我们还将其包装在`window.onload`下；否则，`document.getElementById('name')`将不可用。这是因为`<head>`标记中的脚本在 DOM 准备就绪之前首先执行。`window.onload`确保在文档完全下载并可用时执行代码。

## 它是如何工作的...

`onload`事件的问题在于它只会在文档和相关文件（如 CSS 和图像）下载完成时触发。当页面包含任何大型图像文件或内容时，它会显著减慢 JavaScript 代码的触发速度。因此，当我们必须将任何事件附加到任何元素（如前面的代码所示），或者在页面加载期间隐藏任何`div`容器时，它不会按预期工作。用户将根据其下载速度看到一个无响应或闪烁的网站。

### DOMContentLoaded 和解决方法

幸运的是，基于 Gecko 的浏览器，如 Mozilla Firefox，有一个特殊的事件称为`DOMContentLoaded`。该事件将在 DOM 准备就绪时触发，而在图像、样式表和子框架完全下载之前。将 JavaScript 代码包装在`DOMContentLoaded`事件中将改善用户体验，因为 JavaScript 将在 DOM 准备就绪时立即触发。

使用`DOMContentLoaded`事件的修改后的代码如下：

```php
document.addEventListener('DOMContentLoaded',function(){
document.getElementById('name').addEventListener('click', function(){
alert('Enter your name!');
},false);
},false);

```

`DOMContentLoaded`事件首次在 Mozilla 的版本 1 中引入，最近其他浏览器（包括 Internet Explorer 版本 9）也开始支持它。由于它也是 HTML5 规范的一部分，更多的浏览器可能很快开始支持它。在那之前，有很多`DOMContentLoaded`的解决方法。例如，jQuery 的`ready`函数是为了支持许多浏览器而做出的努力。以下代码显示了如何使用浏览器兼容性（在 jQuery 中）重新编写前面的代码：

```php
jQuery(document).ready(function($){
$('#name').click(function(){
alert('Enter your name!');
});
});

```

## 还有更多...

即使我们对`DOMContentLoaded`事件使用了与浏览器兼容的 hack，也可能存在一些情况，这些 hack 可能无法按预期工作。在这种情况下，我们可以通过将初始化脚本放置在`</body>`标记之前来触发`load`函数。

# 图像的延迟加载

当加载大量图像时，它会减慢客户端浏览器；太多的图像请求甚至会减慢 Web 服务器。一个常见的方法是分割页面并平均分配图像和内容。另一种方法是利用 JavaScript 的功能，并在客户端级别避免不必要的图像请求。后一种技术称为**延迟加载**。在延迟加载中，图像请求被阻止，直到图像进入浏览器视口，也就是说，直到用户实际看到图像。

## 准备工作

我们需要一个较长的图像库页面来查看页面上大量图像对加载体验的影响。然后，我们必须在懒加载实现的不同方法之间做出决定。

## 如何做到...

我们可以通过以下方法解决懒加载问题：

+   纯 JavaScript

+   篡改的 HTML 标记

### 纯 JavaScript 方法

在这种方法中，图像不会在 HTML 中引用；它们只会在 JavaScript 中引用——要么是硬编码的，要么是从 JSON URL 加载的。图像元素将会动态形成，如下面的代码所示：

```php
// create img element
var img = document.createElement('img');
img.src = '/foo.jpg';
img.height = 50;
img.width = 100;
// append the img element to 'container' element
var container = document.getElementById('container');
container.appendChild(img);

```

这种方法的问题在于图像在 HTML 标记中没有定义，因此在不支持 JavaScript 的设备上无法工作。因此，这最终违反了可访问性标准。纯 JavaScript 应用程序在搜索引擎中难以索引，如果应用程序的营销基于**SEO**（即搜索引擎优化），这种方法将无法起作用。

### 篡改的 HTML 标记

另一种方法是将实际图像放在`rel`或`alt`属性中，并动态形成`src`属性。当图像必须在从`rel`或`alt`设置值后显示时，才会执行此操作。部分 HTML 标记和 JavaScript 如下：

```php
<img alt="/foo.jpg" />
<img alt="/bar.jpg" />
$('img').each(function(){
$(this).attr('src', $(this).attr('alt')); // assign alt data to src
});

```

请注意，篡改的 HTML 标记方法仍然不是一种整洁和可访问的方法。

## 它是如何工作的...

前面的方法不符合渐进增强原则，并且在 JavaScript 引擎不可用或关闭时停止显示图像。根据渐进增强方法，HTML 标记不应更改。当 DOM 准备就绪时，图像视口外的`src`属性将被动态篡改，以使图像不会被下载。篡改图像`src`属性以停止下载的部分代码如下：

```php
<img src="/foo.jpg" />
<img src="/bar.jpg" />
$('img').each(function(){
$(this).attr('origSrc',$(this).attr('src')); // assign src data to origSrc
$(this).removeAttr('src'); // then remove src
});

```

当需要加载图像时，使用以下代码片段：

```php
$('img').each(function(){
$(this).attr('src', $(this).attr('origSrc')); // assign origSrc data to src
});

```

尽管（到目前为止）这是最好的方法，尽管很容易通过任何 JavaScript 片段引入懒加载，但一些最新的浏览器在 DOM 准备好之前就开始下载图像。因此，这种方法并不适用于所有最新的浏览器。随着 Web 的发展，这种功能可能会在不久的将来直接添加到浏览器中。

## 还有更多...

我们有许多懒加载插件。我们还可以采用类似的方法——延迟脚本加载技术——来加载外部脚本。

### 懒加载插件

一些流行 JavaScript 框架可用的图像懒加载插件如下：

+   YUI 的图像加载器：[`developer.yahoo.com/yui/3/imageloader/`](http://developer.yahoo.com/yui/3/imageloader/)

+   jQuery 的 Lazy Load：[`www.appelsiini.net/projects/lazyload`](http://www.appelsiini.net/projects/lazyload)

+   MooTools 的 LazyLoad：[`www.davidwalsh.name/lazyload`](http://www.davidwalsh.name/lazyload)

+   Prototype 的 LazierLoad：[`www.bram.us/projects/js_bramus/lazierload/`](http://www.bram.us/projects/js_bramus/lazierload/)

### 懒惰/延迟脚本加载

虽然懒惰/延迟脚本加载与图像懒加载功能并不直接相关，但可以与上述技术结合，以获得更好的加载体验。当 JavaScript 文件通常链接在`<head>`标签中时，当脚本被执行时，Web 浏览器将暂停解析 HTML 代码。这种行为会使浏览器暂停一段时间，因此用户会感受到速度变慢。之前的建议是将脚本链接放在`</body>`标签之前。HTML5 引入了`script`标签的`async`属性；当使用时，浏览器将继续解析 HTML 代码，并在下载后执行脚本。脚本加载是异步的。

由于 Gecko 和基于 WebKit 的浏览器支持`async`属性，因此以下语法有效：

```php
<script type="text/javascript" src="foo.js" async></script>

```

对于其他浏览器，`async`仅在通过 DOM 注入时起作用。这是使用 DOM 注入的 Google Analytics 代码，以使所有浏览器中的异步加载可行：

```php
<script type="text/javascript">
var _gaq = _gaq || [];
_gaq.push(['_setAccount', 'UA-XXXXX-X']);
_gaq.push(['_trackPageview']);
(function(){
var ga = document.createElement('script');
ga.type = 'text/javascript';

ga.async = true;
ga.src = ('https:'==document.location.protocol?'https://ssl':'http://www')+'.google-analytics.com/ga.js';
var s = document.getElementsByTagName('script')[0];
s.parentNode.insertBefore(ga,s);
})();
</script>

```

当用于外部脚本时，例如 Google Analytics、Facebook 库等，这将提高加载速度。

# 通过 Apache 模块/Google mod_pagespeed 自动优化 Ajax 应用程序

自动优化 Ajax 应用程序-无需手动努力-是任何开发人员最想要的工具。为此目的发明了一些工具。在这个配方中，我们将看到一些这样的自动工具。

## 准备就绪

我们需要一个在 Apache Web 服务器上运行的 Web 应用程序。对于自动优化，我们需要以下 Apache 模块：

+   `mod_deflate`，可在[`httpd.apache.org/docs/2.0/mod/mod_deflate.html`](http://httpd.apache.org/docs/2.0/mod/mod_deflate.html)上找到

+   `mod_expires`，可在[`httpd.apache.org/docs/2.0/mod/mod_expires.html`](http://httpd.apache.org/docs/2.0/mod/mod_expires.html)上找到

+   `mod_pagespeed`，可在[`code.google.com/p/modpagespeed/`](http://code.google.com/p/modpagespeed/)上找到

## 如何操作...

我们必须安装这些模块，然后为它们设置配置，以自动处理请求。我们将看到每个模块的配置：

1.  `mod_deflate:`

要启用 JavaScript、CSS 和 HTML 代码的自动 gzip 处理，我们可以使用 AddOutputFilterByType 并指定它们的 MIME 类型：

```php
<IfModule mod_deflate.c>
AddOutputFilterByType
DEFLATE application/javascript text/css text/html
</IfModule>

```

1.  `mod_expires:`

要在静态内容上启用自动浏览器缓存，例如 JavaScript、CSS、图像文件、SWF 文件和 favicon，我们可以指定它们的 MIME 类型和过期时间，如下所示：

```php
<IfModule mod_expires.c>
FileETag None
ExpiresActive On
ExpiresByType application/javascript "access plus 1 month"
ExpiresByType text/css "access plus 1 month"
ExpiresByType image/gif "access plus 1 month"
ExpiresByType image/jpeg "access plus 1 month"
ExpiresByType image/png "access plus 1 month"
ExpiresByType application/x-shockwave-flash
"access plus 1 month"
# special MIME type for icons
AddType image/vnd.microsoft.icon .ico
# now we have icon MIME type, we can use it
ExpiresByType image/vnd.microsoft.icon "access plus 3 months"
</IfModule>

```

在上述代码片段中，我们已经为图标文件注册了一个 MIME 类型，并且使用了 MIME 类型，我们已经设置了三个月的过期时间。这主要是针对 favicon 文件。对于静态内容，我们可以安全地设置 1 到 6 个月或更长的过期时间。上述代码将通过`Last-Modified`标头处理浏览器缓存，而不是通过 ETag，因为我们已经禁用了 ETag 支持。YSlow 建议我们完全禁用 ETag，以减少 HTTP 请求标头的大小。

### 注意

**ETag**据称现在被误用来唯一标识用户，因为许多用户出于隐私原因禁用了 cookie。因此，有努力在浏览器中禁用 ETag。

1.  `mod_pagespeed:`

`mod_pagespeed` Apache 模块是 Google 的页面速度倡议。Google 的倡议始于 Page Speed Firefox 扩展，类似于 YSlow。这是一个旨在找出瓶颈并提出建议的页面速度诊断工具。目前，Page Speed 扩展也适用于 Chrome。

现在，Page Speed 诊断工具可以作为基于 Web 的服务在[`pagespeed.googlelabs.com/`](http://pagespeed.googlelabs.com/)上使用，因此我们可以在不安装浏览器插件的情况下进行速度诊断。

Google 在这个领域的杰出努力的一个例子是发明了`mod_pagespeed` Apache 扩展，通过优化资源通过重写 HTML 内容自动执行速度建议。当正确配置时，它可以最小化、gzip、转换 CSS 精灵，并处理 Page Speed 浏览器扩展提供的许多其他建议。

当我们在 PageSpeed 中启用仪器时，它将注入跟踪器 JavaScript 代码，并将通过`mod_pagespeed`动态添加的信标图像进行跟踪。通过访问服务器中的`/mod_pagespeed_statistics`页面，我们可以找到有关使用情况的统计信息。

以下是要放置在`pagespeed.conf`文件中的`pagespeed_module`的快速配置代码：

```php
LoadModule pagespeed_module /usr/lib/httpd/modules/mod_pagespeed.so
# Only attempt to load mod_deflate if it hasn't been loaded already.
<IfModule !mod_deflate.c>
LoadModule deflate_module /usr/lib/httpd/modules/mod_deflate.so
</IfModule>
<IfModule pagespeed_module>
ModPagespeed on
AddOutputFilterByType MOD_PAGESPEED_OUTPUT_FILTER text/html
# The ModPagespeedFileCachePath and
# ModPagespeedGeneratedFilePrefix directories must exist and be
# writable by the apache user (as specified by the User
# directive).
ModPagespeedFileCachePath "/var/mod_pagespeed/cache/"
ModPagespeedGeneratedFilePrefix "/var/mod_pagespeed/files/"
# Override the mod_pagespeed 'rewrite level'. The default level
# "CoreFilters" uses a set of rewrite filters that are generally
# safe for most web pages. Most sites should not need to change
# this value and can instead fine-tune the configuration using the
# ModPagespeedDisableFilters and ModPagespeedEnableFilters
# directives, below. Valid values for ModPagespeedRewriteLevel are
# PassThrough and CoreFilters.
#
ModPagespeedRewriteLevel CoreFilters
# Explicitly disables specific filters. This is useful in
# conjuction with ModPagespeedRewriteLevel. For instance, if one
# of the filters in the CoreFilters needs to be disabled for a
# site, that filter can be added to
# ModPagespeedDisableFilters. This directive contains a
# comma-separated list of filter names, and can be repeated.
#
# ModPagespeedDisableFilters rewrite_javascript
# Explicitly enables specific filters. This is useful in
# conjuction with ModPagespeedRewriteLevel. For instance, filters
# not included in the CoreFilters may be enabled using this
# directive. This directive contains a comma-separated list of
# filter names, and can be repeated.
#
ModPagespeedEnableFilters combine_heads
ModPagespeedEnableFilters outline_css,outline_javascript
ModPagespeedEnableFilters move_css_to_head
ModPagespeedEnableFilters convert_jpeg_to_webp
ModPagespeedEnableFilters remove_comments
ModPagespeedEnableFilters collapse_whitespace
ModPagespeedEnableFilters elide_attributes
ModPagespeedEnableFilters remove_quotes
# Enables server-side instrumentation and statistics. If this rewriter is
# enabled, then each rewritten HTML page will have instrumentation javacript
# added that sends latency beacons to /mod_pagespeed_beacon. These
# statistics can be accessed at /mod_pagespeed_statistics. You must also
# enable the mod_pagespeed_statistics and mod_pagespeed_beacon handlers
# below.
#
ModPagespeedEnableFilters add_instrumentation
# ModPagespeedDomain
# authorizes rewriting of JS, CSS, and Image files found in this
# domain. By default only resources with the same origin as the
# HTML file are rewritten. For example:
#
# ModPagespeedDomain cdn.myhost.com
#
# This will allow resources found on http://cdn.myhost.com to be
# rewritten in addition to those in the same domain as the HTML.
#
# Wildcards (* and ?) are allowed in the domain specification. Be
# careful when using them as if you rewrite domains that do not
# send you traffic, then the site receiving the traffic will not
# know how to serve the rewritten content.
ModPagespeedDomain *
ModPagespeedFileCacheSizeKb 102400
ModPagespeedFileCacheCleanIntervalMs 3600000
ModPagespeedLRUCacheKbPerProcess 1024
ModPagespeedLRUCacheByteLimit 16384
ModPagespeedCssInlineMaxBytes 2048
ModPagespeedImgInlineMaxBytes 2048
ModPagespeedJsInlineMaxBytes 2048
ModPagespeedCssOutlineMinBytes 3000
ModPagespeedJsOutlineMinBytes 3000
ModPagespeedImgMaxRewritesAtOnce 8
# This handles the client-side instrumentation callbacks which are injected
# by the add_instrumentation filter.
# You can use a different location by adding the ModPagespeedBeaconUrl
# directive; see the documentation on add_instrumentation.
#
<Location /mod_pagespeed_beacon>
SetHandler mod_pagespeed_beacon
</Location>
# This page lets you view statistics about the mod_pagespeed module.
<Location /mod_pagespeed_statistics>
Order allow,deny
# You may insert other "Allow from" lines to add hosts you want to
# allow to look at generated statistics. Another possibility is
# to comment out the "Order" and "Allow" options from the config
# file, to allow any client that can reach your server to examine
# statistics. This might be appropriate in an experimental setup or
# if the Apache server is protected by a reverse proxy that will
# filter URLs in some fashion.
Allow from localhost
SetHandler mod_pagespeed_statistics
</Location>
</IfModule>

```

### 工作原理...

作为 Apache 的模块，这些模块在 Apache 级别处理优化。这意味着我们不必修改任何 PHP 或 JavaScript 代码。

1.  `mod_deflate:`

`mod_deflate`作用于指定的内容类型。每当应用程序命中指定的内容类型时，它会处理文件并根据浏览器请求进行 gzip 处理。

1.  `mod_expires:`

此模块还根据配置设置进行操作。它可以根据内容类型或文件扩展名进行处理。配置正确后，它将添加`Last-Modified`标头以避免缓存资源。根据每天的总点击量，它可以显着避免下载静态内容资源以加快站点加载速度。

1.  `mod_pagespeed：`

由于此模块通过重写来优化 HTML 代码，因此需要在服务器上缓存文件。路径必须在`pagespeed.conf`配置文件中配置。重写设置通过`ModPagespeedRewriteLevel`进行调整，默认设置为`CoreFilters`。使用 CoreFilters，以下过滤器将自动启用：

+   `add_head：`如果尚未存在，则向文档添加`<head>`元素。

+   `combine_css：`将多个 CSS 元素合并为一个。

+   `rewrite_css：`重写 CSS 文件以删除多余的空白和注释。

+   `rewrite_javascript：`重写 JavaScript 文件以删除多余的空白和注释。

+   `inline_css：`将小的 CSS 文件嵌入到 HTML 中。

+   `inline_javascript`将小的 JavaScript 文件嵌入到 HTML 中。

+   `rewrite_images：`优化图像，重新编码它们，删除多余的像素，并将小图像嵌入。

+   `insert_image：`由`rewrite_images`隐含。向缺少宽度和高度属性的`<img>`标签添加宽度和高度属性。

+   `inline_images：`由`rewrite_images`隐含。用内联数据替换小图像。

+   `recompress_images：`由`rewrite_images`隐含。重新压缩图像，删除多余的元数据，并将 GIF 图像转换为 PNG。

+   `resize_images：`由`rewrite_images`隐含。当相应的`<img>`标签指定的宽度和高度小于图像大小时，调整图像大小。

+   `extend_cache：`通过使用内容哈希签名 URL，延长所有资源的缓存寿命。

+   `trim_urls：`通过使它们相对于基本 URL 来缩短 URL。

还有一些其他未在`CoreFilters`中启用的过滤器：

+   `combine_heads：`将文档中找到的多个`<head>`元素合并为一个。

+   `strip_scripts：`从文档中删除所有脚本标记，以帮助运行实验。

+   `outline_css：`将大块的 CSS 外部化为可缓存的文件。

+   `outline_javascript：`将大块的 JavaScript 外部化为可缓存的文件。

+   `move_css_to_head：`将所有 CSS 元素移动到`<head>`标记中。

+   `make_google_analytics_async：`将 Google Analytics API 的同步使用转换为异步使用。

+   `combine_javascript：`将多个脚本元素合并为一个。

+   `convert_jpeg_to_webp：`向兼容的浏览器提供 WebP 而不是 JPEG。**WebP**，发音为'weppy'，是谷歌推出的一种图像格式，它比 JPEG 具有更好的压缩效果而不会影响质量。

+   `remove_comments：`删除 HTML 文件中的注释，但不包括内联 JS 或 CSS。

+   `collapse_whitespace：`除了`<pre>, <script>, <style>`和`<textarea>`内部之外，删除 HTML 文件中的多余空白。

+   `elide_attributes：`根据 HTML 规范删除不重要的属性。

+   `rewrite_domains：`根据`pagespeed.conf`中的`ModPagespeedMapRewriteDomain`和`ModPagespeedShardDomain`设置，重写`mod_pagespeed`未触及的资源的域。

+   `remove_quotes：`删除不是词法上必需的 HTML 属性周围的引号。

+   `add_instrumentation：`向页面添加 JavaScript 以测量延迟并发送回服务器。

可以通过`ModPagespeedEnableFilters`启用这些过滤器。同样，可以通过`ModPagespeedDisableFilters`禁用在 CoreFilters 中启用的任何过滤器。我们必须注意，由于此模块重写所有页面，服务器会有轻微的开销。我们可以选择性地禁用过滤器，并手动修改我们的 HTML 代码，以便进行重写。

如果我们所有的页面都是静态的，随着时间的推移，我们可以用缓存中可用的重写 HTML 代码替换 HTML 文件。然后我们可以完全禁用这个模块，以避免 CPU 开销。这个模块也是一个很好的学习工具，我们可以学习需要在 HTML、JavaScript 和 CSS 中进行哪些改变以提高性能。

### 还有更多...

为了检查我们是否正确配置了模块，或者检查性能，有一些在线服务可用。

#### 测试 HTTP 头

为了确保我们启用的`gzip`和浏览器缓存正常工作，我们可以使用：

+   使用 Firefox 扩展 Firebug 的 Net 标签来手动分析 HTTP 头

+   使用 YSlow 和 PageSpeed 扩展来检查等级/分数

+   一个基于网页的服务，可在[`www.webpagetest.org/`](http://www.webpagetest.org/)上使用，提供类似于 YSlow 和 Page Speed 的建议

+   一个基于网页的服务，可在[`redbot.org/`](http://redbot.org/)上使用，用于分析 HTTP 头，可能是最简单的选择。

#### 在不安装 mod_pagespeed 的情况下进行测试

使用[`www.webpagetest.org/compare`](http://www.webpagetest.org/compare)上的在线服务，我们可以快速测试通过安装`mod_pagespeed`可能获得的速度改进。视频功能可以实时反馈差异。

#### 页面速度服务

谷歌提供了网页速度服务。如果我们使用这项服务，就不需要在服务器上安装`mod_pagespeed`。服务器上唯一需要更改的是将`DNS CNAME`条目指向`ghs.google.com`。
