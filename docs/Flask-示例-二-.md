# Flask 示例（二）

> 原文：[`zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD`](https://zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：将 Google 地图添加到我们的犯罪地图项目

在上一章中，我们设置了一个数据库，并讨论了如何通过 Flask 向其中添加和删除数据。现在有了一个可以进行长期存储的输入和输出的网络应用程序，我们现在拥有了几乎所有网络应用程序所需的基本组件，只受我们想象力的限制。

在本章中，我们将比上一章的纯文本界面添加更多功能；我们将添加嵌入式 Google 地图，允许用户以直观的方式查看和选择地理坐标。

Google Maps 是用 JavaScript 编写的，我们需要编写一些 JavaScript 代码来适应我们的需求。与往常一样，我们将为以前从未使用过 JavaScript 的读者做一个快速教程，但如果您有兴趣巩固您的全面网络应用知识，现在是快速浏览一些特定于 JavaScript 的教程的好时机。如果您以前从未见过任何 JavaScript 代码，可以在[`www.w3schools.com/js/default.asp`](http://www.w3schools.com/js/default.asp)找到一个类似于我们之前提供链接的 HTML 和 CSS 教程的简单介绍。

可以说，犯罪地图最重要的部分是地图本身。我们将使用 Google Maps API，这对开发人员来说简单而强大，对用户来说直观。作为第一步，我们将只添加一个基本地图，加载到我们选择的区域和缩放级别。一旦我们完成了这一步，我们将添加功能以允许标记。标记对我们的地图有两个目的：首先，我们将在地图上显示我们在数据库中保存的每起犯罪的位置；其次，当用户点击地图时，它将添加一个新的标记，并允许用户提交新的犯罪报告（最终通过在表单字段中添加描述和日期）。

然而，首先我们需要能够再次在本地运行我们的应用程序进行开发和调试。将其链接到数据库，这有点棘手；因此，我们将看看如何解决这个常见问题。

在本章中，我们将涵盖以下主题：

+   在本地运行数据库应用程序

+   将嵌入式 Google 地图小部件添加到我们的应用程序

+   为新犯罪添加一个输入表单

+   在地图上显示现有的犯罪

# 在本地运行数据库应用程序

为了在本地开发和调试，我们需要能够运行应用程序。然而，目前这是不可能的，因为 MySQL 只安装在我们的 VPS 上。有三种主要选项来在本地开发我们的数据库应用程序：

+   即使在本地机器上运行 Flask，也要连接到我们 VPS 上的数据库

+   在本地机器上安装 MySQL

+   使用 Python 在内存中创建我们数据库的“模拟”

虽然任何一个都可以工作，但我们将选择第三个选项。连接到我们的生产数据库会导致我们受到延迟的影响，如果我们在离我们的 VPS 很远的地方开发，这也意味着我们将对我们的生产数据库运行测试代码，这绝不是一个好主意。第二个选项将限制我们开发环境的可移植性，增加切换到新开发环境时的设置时间，并且在最坏的情况下，会消耗大量的本地资源。

## 创建我们数据库的模拟

如果您尝试在本地运行`crimemap.py`文件，您将看到的第一个错误是`ImportError`，因为我们没有`dbconfig.py`文件。在上一章中，我们直接在我们的 VPS 上创建了这个文件，并且没有将其检入 git，因为它包含敏感的数据库凭据。我们将创建`dbconfig.py`的本地副本，这表明我们的应用程序应该使用模拟数据库。我们将在我们的 VPS 上更新`dbconfig.py`文件，以指示在那里运行应用程序时应使用真实的数据库。我们将使用一个简单的布尔标志来实现这一点。

### 添加一个测试标志

在您的本地`crimemap`目录中，创建一个新的`dbconfig.py`文件，并添加一行代码：

```py
test = True
```

现在，SSH 进入您的 VPS，并将标志添加到生产配置中；尽管这里，值应设置为`False`，如下所示：

```py
ssh user@123.456.789.123
cd /var/www/crimemap
nano dbconfig.py

```

在文件顶部添加以下内容：

```py
test = False
```

然后，键入*Ctrl* + *X*，然后*Y*保存并退出文件

现在，退出 SSH 会话。这将解决`ImportError`（`dbconfig.py`文件现在存在于我们的 VPS 和本地），并且我们的应用程序现在知道它是在测试还是生产环境中运行。

### 编写模拟代码

尽管我们的标志目前实际上并没有做任何事情，我们也不想在测试应用程序时触发所有的异常。相反，我们将编写我们数据库代码的“模拟”（`dbhelper.py`文件中的代码），它将返回基本静态数据或`None`。当我们的应用程序运行时，它将能够正常调用数据库函数，但实际上并没有数据库。相反，我们将有几行 Python 来模拟一个非常基本的数据库。在您的`crimemap`目录中创建`mockdbhelper.py`文件，并添加以下代码：

```py
class MockDBHelper:

  def connect(self, database="crimemap"):
    pass

  def get_all_inputs(self):
    return []

  def add_input(self, data):
    pass

  def clear_all(self):
    pass
```

正如您所注意到的，我们用于基本数据库应用程序的方法都存在，但并没有做任何事情。`get_all_inputs()`方法返回一个空列表，我们仍然可以将其传递给我们的模板。现在，我们只需要告诉我们的应用程序在测试环境中使用这个方法，而不是真正的`DBHelper`类。在`crimemap.py`的导入部分的末尾添加以下代码，确保删除现有的`import` for `DBHelper`：

```py
import dbconfig
if dbconfig.test:
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper
```

我们使用`dbconfig`中的测试标志来指定是否导入真正的`DBHelper`（它依赖于与 MySQL 的连接）或导入模拟的`DBHelper`（它不需要数据库连接）。如果我们导入模拟助手，我们可以更改名称，以便代码的其余部分可以继续运行而无需对测试标志进行条件检查。

### 验证我们的期望

现在，您应该能够像以前添加数据库依赖项之前一样在本地运行代码。在您的终端中运行：

```py
python crimemap.py

```

然后，在浏览器中访问`localhost:5000`，查看您的应用程序加载情况。检查终端的输出，确保没有触发异常（如果您尝试运行真正的`DBHelper`代码而不是我们刚刚制作的模拟代码，就会触发异常）。尽管我们的应用程序不再“工作”，但至少我们可以运行它来测试不涉及数据库的代码。然后，当我们部署到生产环境时，一切应该与我们的测试一样正常工作，但实际上插入了一个真正的数据库。

# 将嵌入式谷歌地图小部件添加到我们的应用程序

现在，我们想要在我们的应用程序中添加地图视图，而不是基本输入框。谷歌地图允许您创建地图而无需注册，但您只能进行有限次数的 API 调用。如果您创建了这个项目，在网上发布了一个链接，并且它变得火爆，您有可能达到限制（目前每天最多 2500 次地图加载）。如果您认为这将是一个限制因素，您可以注册地图 API，并有选择向谷歌支付更多容量。然而，免费版本对于开发甚至生产来说都足够了，如果您的应用程序不太受欢迎的话。

## 将地图添加到我们的模板

我们想在我们应用程序的主页上显示地图，这意味着编辑我们`templates`目录中的`home.html`文件中的代码。删除所有现有代码，并用以下代码替换：

```py
<!DOCTYPE html>
<html lang="en">
  <head>
    <script type="text/javascript"
      src="img/js">
    </script>

    <script type="text/javascript">
      function initialize() { 
        var mapOptions = {
          center: new google.maps.LatLng(- 33.30578381949298, 26.523442268371582),
          zoom: 15
        };
        var map = new
        google.maps.Map(document.getElementById("map- canvas"),mapOptions);
      }
     </script>

  </head>
    <body onload="initialize()">
    <div id="map-canvas" style="width:80%; height:500px;"></div>
    </body>
</html>
```

### 引入 JavaScript

让我们看看这里发生了什么。第一行告诉我们的用户浏览器，我们正在使用 HTML5。第 4 到 6 行包括我们页面中需要的地图资源。请注意，这是在`<script>`标签之间，表示这是 JavaScript。在这种特殊情况下，我们实际上并没有编写 JavaScript 代码 - 我们只是链接到它托管在谷歌服务器上的位置。把它想象成 Python 的`import`语句，除了我们甚至不需要在本地安装包；它只是在您的用户浏览器运行时“导入”。

紧随其后的是我们的设置脚本，用于显示基本地图。同样，这是在`<script>`标签之间，以表明这是 JavaScript 而不是 HTML。尽管在括号、大括号和`for`循环方面，它的语法与 Java 类似，但除此之外，它与 Java 之间几乎没有关系。

我们的 JavaScript 代码的第一行是一个函数定义；类似于 Python 的“`def`”，我们使用`function`关键字来定义一个名为`initialise()`的新函数。我们声明了一个变量`var mapOptions =`，并将一个类似于 Python 字典的新 JavaScript 对象分配给了这个变量。我们使用经纬度元组的方式定义了一个位置，这是因为我们可以访问到第 4 到 6 行的内容，该对象还包含一个“`zoom`”级别。这些选项描述了我们的初始地图：应该显示哪个区域以及以什么缩放级别。

最后，我们创建了一个新变量`map`，并初始化了一个 Google 地图对象，传入了一个 HTML 元素的 ID（我们将在下一节中详细解释）和我们刚刚定义的地图选项。然后我们到达了 JavaScript 代码的末尾，所以我们关闭了`<script>`标签。

### 我们的 HTML 代码的主体

虽然我们的`<body>`部分只有几行，但其中有一些微妙之处。第一行打开了`<body>`标签，并定义了`onload`参数。此参数接受一个 JavaScript 函数的名称，该函数将在页面加载时自动调用。请注意，函数名称（在我们的例子中是“`initialize`”）被引号括起来。如果你想到 Python，这可能有些反直觉，因为引号主要用于字符串字面量。将其视为将函数*名称*传递给 body 块，但请注意我们仍然使用开闭括号作为名称的一部分。

下一行创建了一个`<div>`元素。通常，`<div>`除了包含更多的 HTML 之外什么也不做，但这并不意味着空的`<div>`块，就像我们这里有的一样，是毫无意义的。请注意我们给`<div>`的 ID，`map-canvas`。这与我们 JavaScript 代码中的名称相匹配；也就是说，JavaScript 函数将查找一个名为`map-canvas`的 HTML 元素（使用`document.getElementById()`）并将其转换为 Google 地图小部件。因此，使用`<div>`元素是有意义的，因为我们希望 JavaScript 代码使用一个空元素。

最后，我们的`<div>`元素还包括一些内联 CSS。我们可以使用 CSS 的`height`和`width`属性来定义地图的宽度和高度（这是 Google Maps API 的要求）。在这种情况下，我们将地图的`height`值定义为常量`500`像素，`width`值定义为页面的`80%`。宽度的百分比很有用，因为滚动功能通常会与缩放功能重叠。也就是说，如果用户想要在触摸板或鼠标滚轮上向下滚动页面，并且光标位于地图上，地图将放大而不是页面向下滚动。因此，右侧的 20%的“空白”空间为用户提供了滚动时移动鼠标的位置。同样，对于触摸屏，用户在尝试滚动时会在地图周围“平移”，但可以利用这个空间来放置手指。

### 测试和调试

我们现在应该能够在本地运行我们的 Web 应用程序并查看嵌入的 Google 地图。如果您的应用程序尚未运行，请使用终端再次启动它，并在浏览器中导航到`localhost:5000`。由于我们不在本地存储 Google 地图的代码，因此需要从 Google 的服务器获取，因此我们的本地机器需要在线才能正常工作（类似于获取我们 Headlines 应用程序所需的数据）。

调试 JavaScript 代码有点棘手，因为任何错误都不会被 Flask 注册，因此不会在应用程序输出中看到。如果您的网页是空白的或执行任何意外操作，首先要查看的地方是您的浏览器开发者控制台。这是开发人员的工具，在所有主要浏览器中都可以找到，通常通过按下*Ctrl* + *Shift* + *C*并导航到出现的窗口或侧边栏中的“**控制台**”选项卡。在这里，您将注意到代码触发的任何 JavaScript 错误或警告，因此此工具在调试 Web 应用程序中非常宝贵。

尽管控制台应该报告错误以及行号，但有时确切地追踪出错的地方可能有些困难。JavaScript 是一种动态类型的语言，以其一些相当古怪和反直觉的行为而臭名昭著。如果有必要，您还可以在 HTML 的`<script>`标签之间添加 JavaScript 行，这些行除了在开发人员工具控制台中记录外什么也不做。要做到这一点，请使用以下内容：

```py
console.log("A message");
```

这类似于 Python 的`print`语句，您可以传递变量和大多数对象，以查看它们的字符串表示形式记录到输出中。使用`+`符号进行连接。例如，如果您有一个名为“`a`”的变量，并且想要在代码的特定点看到它的值，可以添加以下行：

```py
console.log("The value of a is: " + a);
```

对于更复杂的调试方法，请查看开发人员工具窗口（或浏览器中的等效窗口）中的**调试器**选项卡，并尝试在 JavaScript 中设置断点。开发人员工具通常是一套功能强大的工具，很遗憾，其全部功能超出了本书的范围。以下屏幕截图显示了 Mozilla Firefox 开发人员控制台，在加载地图之前设置了断点：

![测试和调试](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_01.jpg)

一旦所有错误都被消除（或者如果您非常细心和幸运，可以立即看到），您应该在浏览器中看到一个包含嵌入的 Google 地图的页面，该地图以**格雷厄姆斯敦**，南非为中心。通过使用 JavaScript 代码中的`mapOptions`变量设置的缩放级别和坐标来获取您选择的初始地图。单击并在地图上按住将允许“平移”或在世界各地移动。通过使用您的中间鼠标滚轮滚动，使用触摸板或在触摸屏上进行“捏合缩放”来进行缩放。结果应该与以下屏幕截图类似：

![测试和调试](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_02.jpg)

现在让我们继续使我们的地图更加交互和有用。

## 使我们的地图交互起来

我们将为我们的应用程序添加的第一个功能允许用户在地图上放置一个标记。这将最终允许用户通过指示犯罪发生地点来添加犯罪报告，从而增加我们的众包犯罪数据库。我们还将在 JavaScript 中实现标记功能，使用“侦听器”。

### 添加标记

JavaScript 是*事件驱动*的。诸如鼠标移动或鼠标单击之类的操作都是事件，我们可以通过设置事件侦听器来对这些事件做出反应。侦听器只是在后台运行，等待特定事件，然后在检测到事件时触发指定的操作。我们将为鼠标单击设置一个侦听器，如果检测到，我们将在单击时在鼠标位置放置一个地图标记。

使用 Google 地图 API，可以用几行代码实现这一点。首先，我们将使我们的`map`变量全局化。然后，我们将创建一个`placeMarker()`函数，该函数将引用我们的`map`变量，并在调用时在其上放置一个标记。在我们现有的`initalise()`函数中，我们将添加一个点击侦听器，当触发时将调用`placeMarker()`函数。

完整的 JavaScript 代码可以在此处查看，修改的行已突出显示：

```py
<script type="text/javascript"
  src="img/js">
</script>

<script type="text/javascript">

 var map;
  function initialize() { 
  var mapOptions = {
    center: new google.maps.LatLng(-33.30578381949298, 26.523442268371582),
    zoom: 15
  };
 map = new google.maps.Map(document.getElementById("map- canvas"), mapOptions);
 google.maps.event.addListener(map, 'click', function(event){ 
 placeMarker(event.latLng);
 });
  }

 function placeMarker(location) {
 var marker = new google.maps.Marker({
 position: location, 
 map: map
 });
  }
</script>
```

特别注意从`var map = new google.maps.Map`到`map = new google.maps.Map`的更改。我们删除了`var`声明，这意味着我们将新的地图分配给我们的全局`map`变量，而不是创建一个新的局部变量。

下一行调用了`addListener()`，这可能看起来有点奇怪。`addListener()`函数接受一个`map`、`event`和`function`，当监听器被触发时调用。与 Python 一样，JavaScript 有一流的函数，这意味着我们可以将函数作为参数传递给其他函数。与 Python 不同的是，我们不需要使用`lambda`关键字来创建匿名函数；我们可以简单地声明我们想要传递的函数，而不是参数。在这种情况下，我们创建了一个匿名函数，它接受一个`event`参数，然后调用我们的`placeMarker()`函数，将`event`的`latLng`属性传递给它。在我们的情况下，`event`是监听器捕获的鼠标点击，`latLng`属性是鼠标点击的位置。

在我们的`placeMarker()`函数中，我们接受一个位置并创建一个新的`Marker`对象，将其放置在我们地图上传入的位置（这就是为什么我们将地图设为全局的；现在我们可以在这个新函数中引用它）。

总之，当页面加载时，我们将添加一个监听器，它会在后台等待点击。当检测到点击时，监听器会调用`placeMarker()`，传入它检测到的点击的坐标。`placeMarker()`函数然后在指定的坐标处添加一个标记，这意味着用户在点击地图时会看到一个标记出现在地图上。如果出现意外情况，请像之前一样在浏览器中使用控制台和调试器进行尝试。您应该看到每次点击地图都会放置一个新的标记，并且能够生成类似于以下截图的地图：

![添加标记](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_03.jpg)

### 使用单个标记

为每次点击创建一个新标记并不理想。实际上，我们希望用户能够在每次点击时移动标记，而不是创建一个新的标记。一次添加多个犯罪将会变得过于复杂，也不是特别有用。

为了实现这一点，在现有的全局`map`变量下创建另一个全局`marker`变量。然后，在`placeMarker()`函数中添加一个简单的条件，只有在没有标记时才创建一个新的标记，否则移动现有标记的位置。

完整的代码，再次突出显示修改的行，如下所示。再次注意，我们从创建新的`marker`变量的行中删除了`var`，因此使用全局变量而不是创建一个局部变量。有了这些改变，每次点击地图时都应该移动标记，而不是创建一个新的标记。试一试：

```py
<script type="text/javascript"
  src="img/js">
</script>

<script type="text/javascript">

  var map;
 var marker;
  function initialize() { 
    var mapOptions = {
    center: new google.maps.LatLng(-33.30578381949298, 26.523442268371582),
    zoom: 15
    };
    map = new google.maps.Map(document.getElementById("map- canvas"), mapOptions);
    google.maps.event.addListener(map, 'click', function(event){  
      placeMarker(event.latLng);
    });
  }

  function placeMarker(location) {
 if (marker) {
 marker.setPosition(location);
 } else {
 marker = new google.maps.Marker({
       position: location,
       map: map
     });
    }
  }
</script>
```

# 为新犯罪添加输入表单

我们希望用户能够指定比简单位置更多的信息。下一步是创建一个表单，用户可以使用该表单向犯罪提交添加日期、类别和描述数据。这些信息中的每一个都将存储在我们在上一章中创建的数据库列中。创建网络表单是一个很常见的任务，有许多框架和插件可以帮助尽可能自动化这个过程，因为大多数表单都需要一个漂亮的前端，其中包括错误消息，如果用户输入了意外的输入，以及后端逻辑来处理数据并进行更彻底的验证，以防止格式不正确或不正确的数据污染数据库。

然而，为了学习的目的，我们现在将从头开始创建一个网络表单的后端和前端。在我们的下一个项目中，我们将看看如何使用各种工具来做类似的事情，以使这个过程不那么费力。

我们的目标是在地图的右侧有一些输入字段，允许用户指定关于目击或经历的犯罪的详细信息，并将其提交以包含在我们现有的数据中。表单应该有以下输入：

+   **类别**：一个下拉菜单，允许用户选择犯罪属于哪个类别

+   **日期**：一个允许用户轻松输入犯罪日期和时间的日历

+   **描述**：一个更大的文本框，允许用户以自由形式描述犯罪

+   **纬度和经度**：根据使用标记选择的位置自动填充的文本框

在填写前面的字段后，用户应该能够单击**提交**按钮，并查看刚刚提交的犯罪在地图上显示出来。

## 表单的 HTML 代码

我们表单所需的 HTML 代码与我们之前项目中创建的表单非常相似，但也有一些新元素，即`<textarea>`和`<label>`以及一个带有`type="date"`的输入。`<textarea>`元素与我们之前注意到的标准文本字段非常相似，但显示为更大的正方形，以鼓励用户输入更多文本。标签元素可以定义一个`for`属性来指定我们要标记的内容。在开放和关闭的`label`标签之间的文本将显示在要标记的元素附近。

这对我们的表单很有用，因为我们可以提示用户在每个字段中输入什么数据。日期字段将提供一个漂亮的日历下拉菜单来选择日期。不幸的是，这是 HTML 的一个相当新的添加，不是所有浏览器都支持。在不支持的浏览器（包括 Firefox）中，这将与文本输入相同，因此我们将在本章末尾讨论如何处理用户输入的日期。

另外，请注意，我们将表单放在一个`<div>`元素中，以便更容易地在页面上进行样式和定位（我们稍后也会这样做）。我们的 HTML 页面的完整`<body>`元素现在如下所示（请注意，我们在地图上方添加了一个标题和段落，而表单是在地图下方添加的）。看一下以下代码：

```py
<body onload="initialize()">
  <h1>CrimeMap</h1>
  <p>A map of recent criminal activity in the Grahamstown area.</p>
  <div id="map-canvas" style="width:70%; height:500px"></div>

  <div id="newcrimeform">
   <h2>Submit new crime</h2>
   <form action="/submitcrime" method="POST">
    <label for="category">Category</label>
    <select name="category" id="category">
     <option value="mugging">Mugging</option>
     <option value="breakin">Break-in</option>
    </select>
    <label for="date">Date</label>
    <input name="date" id="date" type="date">
    <label for="latitude">Latitude</label>
    <input name="latitude" id="latitude" type="text">
    <label for="longitude">Longitude</label>
    <input name="longitude" id="longitude" type="text">
    <label for="description">Description</label>
    <textarea name="description" id="description" placeholder="A brief but detailed  description of the crime"></textarea>
    <input type="submit" value="Submit">
    </form></div>
</body>
```

刷新页面以查看地图下方的表单。您会注意到它看起来非常糟糕，字段大小不同，布局水平，如下面的截图所示：

![表单的 HTML 代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_04.jpg)

让我们添加一些 CSS 来修复这个问题。

## 将外部 CSS 添加到我们的 Web 应用程序

为了使表单出现在地图的右侧，我们将使用 CSS。我们已经为我们的地图添加了一些 CSS，我们可以以类似的方式添加更多的 CSS。但是，请参考我们在第五章中对内联、内部和外部 CSS 的讨论，*改进我们的头条项目的用户体验*，在*向我们的头条应用程序添加 CSS*部分，记住将所有 CSS 放在一个单独的文件中是最佳实践。因此，我们将创建一个`style.css`文件，并考虑如何将其链接到我们的 Flask 应用程序。

### 在我们的目录结构中创建 CSS 文件

在 Flask 中，默认情况下，我们的静态文件应该保存在一个名为`static`的目录中。我们最终会想在这里保存各种文件，如图像、JavaScript 和 CSS，因此我们将创建一个名为`CSS`的子目录，并在其中创建我们的`style.css`文件。在终端中导航到您的项目目录，并运行以下命令将此目录结构和文件添加到我们的项目中：

```py
mkdir –p static/css
touch static/css/style.css

```

### 添加 CSS 代码

将以下 CSS 代码插入到这个新文件中：

```py
body {
 font-family: sans-serif;
 background: #eee;
}

input, select, textarea {
 display: block;
 color: grey;
 border: 1px solid lightsteelblue;
 line-height: 15px;
 margin: 2px 6px 16px 0px;
 width: 100%;
}

input[type="submit"] {
 padding: 5px 10px 5px 10px;
 color: black;
 background: lightsteelblue;
 border: none;
 box-shadow: 1px 1px 1px #4C6E91;
}

input[type="submit"]:hover {
 background: steelblue;
}

#map-canvas {
 width: 70%;
 height: 500px;
 float: left;
}

#newcrimeform {
 float: right;
 width: 25%;
}
```

您可能会注意到我们在头条项目中使用的 CSS 代码的相似之处。但是，仍然有一些重要的要点需要注意：

+   我们在这里定义了具有 ID`map-canvas`的任何元素的“宽度”和“高度”（在倒数第二个块中），因此我们可以从我们的`body.html`文件中删除内联样式。

+   我们使用了 CSS 的浮动功能，将我们的表单显示在地图的右侧而不是下方。地图占页面宽度的`70%`，表单占`25%`（最后的 5%留下了地图和表单之间的一些空间。我们的地图浮动到页面的左侧，而表单浮动到右侧。因为它们的宽度加起来不到 100%，所以它们将在浏览器中并排显示。

### 配置 Flask 使用 CSS

通常在 HTML 页面中，我们可以通过给出样式表的相对路径来链接到外部 CSS 文件。由于我们使用的是 Flask，我们需要配置我们的应用程序将 CSS 文件作为静态文件返回。默认情况下，Flask 从项目根目录中名为`static`的目录中提供文件，这就是为什么将 CSS 文件放在这里很重要，就像之前描述的那样。Flask 可以使用`url_for`函数为我们需要链接到的 CSS 文件生成 URL。在`home.html`模板中，在`<head>`部分的顶部添加以下行：

```py
<link type="text/css" rel="stylesheet" href="{{url_for('static', filename='css/style.css') }}" />
```

这创建了我们的 HTML 和 CSS 之间的链接。我们使用属性来描述链接为`text/css`文件，并且它是一个样式表。然后使用`url_for()`函数给出了它的位置。

我们还需要添加一行 JavaScript 代码，以便在地图上的标记被创建或移动时自动填充位置输入。通过在`placeMarker()`函数中添加以下突出显示的行来实现这一点：

```py
function placeMarker(location) {
 if (marker) {
  marker.setPosition(location);
 } else {
  marker = new google.maps.Marker({
   position: location,
   map: map
  });
 }
 document.getElementById('latitude').value = location.lat();
 document.getElementById('longitude').value = location.lng();
}
```

这些行只是找到纬度和经度框（通过它们的`id`属性标识）并插入用于放置标记的位置。当我们将表单`POST`到服务器时，我们将能够在后端读取这些值。

最后，删除我们之前添加的内联 CSS，因为这个功能现在是我们外部样式表的责任。查看`home.html`文件中的以下行：

```py
<div id="map-canvas" style="width:70%; height:500px"></div>
```

前面的行可以修改为以下内容：

```py
<div id="map-canvas"></div>
```

### 查看结果

重新加载浏览器中的页面以查看结果。请记住，浏览器通常会缓存 CSS 和 JavaScript，因此如果看到意外行为，请按*Ctrl* + *R*进行强制刷新。如果*Ctrl* + *R*不起作用，请尝试按*Ctrl* + *Shift* + *Delete*，然后在浏览器菜单中选择**缓存**选项并清除浏览数据，然后再次刷新。

带有表单的样式地图应该类似于以下屏幕截图：

![查看结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_05.jpg)

请注意，现在单击地图会用标记的坐标填充纬度和经度框。

### 发布结果

我们有表单、地图和一些 CSS，现在是将结果推送到我们的 VPS 的好时机，这样我们就可以看到它在不同设备上的外观，或者向人们征求反馈意见。

要推送我们的更改，打开终端，将目录更改为根文件夹，然后运行以下命令：

```py
git add crimemap.py
git add templates/home.html
git add static
git commit –m "Map with form and CSS"
git push origin master

```

然后，通过运行以下命令，SSH 进入您的 VPS 并拉取新代码：

```py
cd /var/www/crimemap
git pull origin master
sudo service apache2 reload

```

访问您的 VPS 的 IP，检查页面是否正常工作并且外观正确。如果发生意外情况，请查看`/var/log/apache2/error.log`。

## 将表单链接到后端

拥有漂亮的表单来接受用户输入是很好的，但目前，我们只是丢弃任何提交的数据。与我们在头条应用程序中实时处理输入不同，我们希望捕获输入并将其存储在我们的数据库中。让我们看看如何实现这一点。

### 设置 URL 以收集 POST 数据

与我们的头条项目一样，第一步是在我们的服务器上设置一个 URL，以便可以将数据发布到该 URL。在我们创建的 HTML 表单中，我们将此 URL 设置为`/submitcrime`，因此让我们在 Flask 应用程序中创建这个路由。在`crimemap.py`中，添加以下函数：

```py
@app.route("/submitcrime", methods=['POST'])
def submitcrime():
 category = request.form.get("category")
 date = request.form.get("date")
 latitude = float(request.form.get("latitude"))
 longitude = float(request.form.get("longitude"))
 description = request.form.get("description")
 DB.add_crime(category, date, latitude, longitude, description)
 return home()
```

在这里，我们只是获取用户输入的所有数据并将其传递给我们的数据库助手。在前面的代码中，我们使用了`DB.add_crime()`函数，但这个函数还不存在。我们需要它来真正将新数据添加到我们的数据库中，对于我们真正的`DBHelper`，我们还需要这个函数的存根。让我们看看如何添加这些。

### 添加数据库方法

在`MockDBHelper.py`中，这个函数很简单。它需要接受相同的参数，然后不执行任何操作。将以下内容添加到`mockdbhelper.py`中：

```py
def add_crime(self, category, date, latitude, longitude, description):
  pass
```

真实的功能需要添加到`dbhelper.py`中，而且涉及的内容更多。它看起来像这样：

```py
def add_crime(self, category, date, latitude, longitude, description):
  connection = self.connect()
  try:
    query = "INSERT INTO crimes (category, date, latitude, longitude, description) \
      VALUES (%s, %s, %s, %s, %s)"
    with connection.cursor() as cursor:
      cursor.execute(query, (category, date, latitude, longitude, description))
      connection.commit()
  except Exception as e:
    print(e)
  finally:
    connection.close()
```

在这里我们没有看到任何新东西。我们使用了占位符值，并且只在`cursor.execute()`语句中填充它们，以避免 SQL 注入，并且我们在`finally`块中关闭了连接，以确保它总是发生。

### 在服务器上测试代码

现在是提交所有更改到存储库并快速检查错误的好时机。一旦新代码在您的 VPS 上运行，尝试通过访问您的 IP 地址并填写我们制作的表单向数据库添加犯罪记录。在您的 VPS 上，您可以通过运行以下命令来检查数据是否成功添加。请注意，这将启动一个实时的 SQL shell——直接连接到您的数据库，应谨慎使用。输入错误的命令可能导致数据不可挽回地丢失或损坏。运行以下命令：

```py
mysql –p
<your database password>
use database crimemap
select * from crimes;

```

您将看到 MySQL 打印了一个漂亮的 ASCII 表，显示了数据库中数据的摘要，如下面的屏幕截图所示（在这种情况下，显示了`crimemap`数据库的`crimes`表中的所有记录和列）：

![在服务器上测试代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_06.jpg)

# 在地图上显示现有的犯罪记录

现在，用户可以向我们的犯罪数据库添加新的犯罪记录，但我们也希望地图显示已经添加的犯罪记录。为了实现这一点，每当页面加载时，我们的应用程序需要调用数据库以获取最新的犯罪数据。然后，我们需要将这些数据传递给我们的模板文件，循环遍历每个犯罪记录，并在地图上的正确位置放置一个标记。

现在，我们的数据存储在 MySQL 数据库中。我们将在服务器端使用 Python 访问它，并希望在客户端使用 JavaScript 显示它；因此，我们需要花一些时间将我们的数据转换为适当的格式。当我们通过 Python 的`pymysql`驱动访问数据时，我们将收到一个元组。为了使用 JavaScript 显示数据，我们希望将其转换为 JSON。你可能还记得我们在 Headlines 项目中提到过 JSON，它是 JavaScript 对象表示法，是一种 JavaScript 可以轻松读取和操作的结构化数据格式。与我们之前的项目一样，我们将利用 Python 字典与 JSON 非常相似的事实。我们将从我们的数据库中获取的元组创建一个 Python 字典，将其转换为 JSON 字符串，并将其传递给我们的模板，模板将使用 JavaScript 将数据显示为地图上的标记。

## 从 SQL 获取数据

我们将从我们的`DBHelper`类开始——添加一个方法来返回我们在数据库中每个犯罪记录所需的字段。将以下方法添加到您的`dbhelper.py`文件中：

```py
def get_all_crimes(self):
 connection = self.connect()
 try:
  query = "SELECT latitude, longitude, date, category, description FROM crimes;"
  with connection.cursor() as cursor:
   cursor.execute(query)
  named_crimes = []
  for crime in cursor:
   named_crime = {
    'latitude': crime[0],
    'longitude': crime[1],
    'date': datetime.datetime.strftime(crime[2], '%Y- %m-%d'),
    'category': crime[3],
    'description': crime[4]
   }
   named_crimes.append(named_crime)
  return named_crimes
 finally:
  connection.close()
```

此外，通过以下方式将我们需要的`datetime`模块的新`import`添加到`dbhelper.py`的顶部：

```py
import datetime
```

我们忽略了`id`和`updated_at`字段，因为用户对这些不感兴趣，使用`SELECT`操作符选择所有其他字段。由于我们没有`WHERE`子句，这个查询将返回我们数据库中的所有犯罪。一旦我们有了所有的犯罪，我们可以简单地以它们的默认表示形式返回它们，即元组的元组。然而，这会使我们的应用程序的维护变得困难。我们不想记住`latitude`是我们元组的第一个元素，`longitude`是第二个元素，依此类推。这将使得开发我们应用程序的 JavaScript 部分变得痛苦，因为我们不得不不断地参考我们的`DBHelper`，以了解如何准确地获取，例如，我们数据的`category`元素。如果我们将来想要对我们的应用程序进行更改，可能需要在这里和我们的 JavaScript 代码中进行相同的更改。

相反，我们将从我们的每条记录中创建一个字典并返回这些字典。这有两个优点：首先，这样开发会更容易，因为我们可以通过名称而不是索引来引用我们数据的元素；其次，我们可以轻松地将我们的字典转换为 JSON，以在我们的 JavaScript 代码中使用。对于我们字典中的大多数项目，我们将简单地使用数据库列名作为键，数据本身作为值。唯一的例外是日期；我们的数据库驱动程序将其返回为 Python 的`datetime`对象，但我们希望将其显示为一个字符串供用户使用，因此我们将在存储到字典中之前将其格式化为"yyyy-mm-dd"。

我们可以向我们的`MockDBHelper`中添加这个方法的存根，以便我们可以继续在本地运行我们的代码而不需要数据库。在这种情况下，我们不仅返回一个空列表，还会返回一个模拟犯罪，格式与我们真正的`DBHelper`所期望的相同。制作任何模拟类时，让你创建的模拟类的行为类似于它们的真实等价物是一个好的做法，因为这可以帮助我们在本地测试时捕捉开发错误。

将以下函数添加到`mockdbhelper.py`中：

```py
def get_all_crimes(self):
 return [{ 'latitude': -33.301304,
    'longitude': 26.523355,
    'date': "2000-01-01",
    'category': "mugging",
    'description': "mock description" }]
```

## 将数据传递给我们的模板

现在我们有了通过调用单个函数从数据库中检索所需数据的能力，让我们看看我们将如何在我们的主要 Flask 应用程序中使用它，并将其传递到我们的模板文件中。

每当用户访问我们的主页时，我们希望从数据库中获取犯罪数据，并以 JSON 格式将其传递给模板，以便在用户的浏览器中使用 JavaScript 显示。由于大部分工作都是在我们的`DBHelper`类中完成的，我们可以保持我们的`home()`函数相当整洁。整个函数如下所示：

```py
@app.route("/")
def home():
 crimes = DB.get_all_crimes()
 crimes = json.dumps(crimes)
 return render_template("home.html", crimes=crimes)
```

我们将使用`json.dumps()`函数，这是我们在第一个项目中使用的`json.loads()`的相反操作，用于为我们的字典创建一个 JSON 字符串（`dumps`中的字母"`s`"代表"string"），然后将 JSON 字符串传递给我们的模板，以便它可以用它来填充地图。

我们还需要为 JSON 库添加一个导入。在`crimemap.py`的顶部附近，添加以下行：

```py
import json
```

## 在我们的模板中使用数据

我们的模板现在可以访问我们数据库中所有犯罪的 JSON 格式化列表，并且我们可以使用这个列表在地图上显示标记——每个现有犯罪一个标记。我们希望使用位置数据来选择放置标记的位置，然后我们希望将`category`、`date`和`description`嵌入到我们的标记上作为标签。这意味着当用户将鼠标移动到标记中的一个时，将显示有关这个标记所代表的犯罪的信息。

我们需要在`home.html`文件中的 JavaScript 代码中添加一个新的函数。在`initialize()`函数下面，添加以下内容：

```py
function placeCrimes(crimes) {
 for (i=0; i<crimes.length; i++) {
  crime = new google.maps.Marker( {
   position: new google.maps.LatLng(crimes[i].latitude, crimes[i].longitude),
   map: map,
   title: crimes[i].date + "\n" + 
    crimes[i].category + "\n" + crimes[i].description
   }
  );
 }
}
```

此函数将`crimes`作为参数，循环遍历它，并为列表中的每个犯罪在我们的地图上创建一个新标记（我们现在可以引用它，因为我们之前将其作为全局变量）。我们使用调用`google.maps.Marker()`来创建标记，并传递参数字典（在本例中是`google.maps.LatLng()` "`position`"，我们从我们的`latitude`和`longitude`参数构造）；我们的地图的引用，即`map`；以及我们的`date`、`category`和`description`的连接，用换行字符分隔作为`title`。

### 提示

**自定义 Google 地图标记**

我们放置的标记可以进行相当大的定制。我们可以传递的所有选项的完整列表可以在[`developers.google.com/maps/documentation/javascript/reference?hl=en#MarkerOptions`](https://developers.google.com/maps/documentation/javascript/reference?hl=en#MarkerOptions)上看到。

现在要做的就是在我们的`initialize()`函数中调用我们的新函数，并传入我们在 Python 中构建的 JSON 地图列表。整个`initialize()`函数如下所示，其中突出显示了新部分：

```py
function initialize() { 
 var mapOptions = {
  center: new google.maps.LatLng(-33.30578381949298, 26.523442268371582),
  zoom: 15
 };
 map = new google.maps.Map(document.getElementById("map- canvas"), mapOptions);
 google.maps.event.addListener(map, 'click', function(event){  
  placeMarker(event.latLng);
 });
 placeCrimes({{crimes | safe}});
}
```

我们只是调用了我们的`placeCrimes()`函数并传入了犯罪。请注意，我们使用了 Jinja 内置的`safe`函数，通过使用`|`（管道）符号并传入我们的`crimes`数据。这是必要的，因为默认情况下，Jinja 会转义大多数特殊字符，但我们需要我们的 JSON 字符串以原始形式解释，所有特殊字符都是原样的。

但是，通过使用`safe`函数，我们告诉 Jinja 我们知道我们的数据是安全的，但在这个阶段，情况并非一定如此。仅仅因为我们没有恶意意图，并不意味着我们所有的数据都是绝对安全的。请记住，我们的大多数数据都是由用户提交的，因此我们的数据绝对不安全。在确保它按预期工作（正常预期使用）之后，我们将看一下我们在应用程序中打开的重大安全漏洞。

### 注意

如果您熟悉*nix shell，`|`或管道应该是非常简单的语法。如果不熟悉，请将其视为具有输入和输出的常规函数。我们不是通过括号中的参数传递输入，并使用某种形式的`return`函数来获取输出，而是将我们的输入放在`|`符号的左侧，并将函数名称放在右侧（在本例中为`safe`）。输入通过函数进行传递，我们得到输出。这种语法可以非常有用，可以将许多函数链接在一起，因为每个外部函数都简单地放在另一个`|`符号之后的右侧。

## 查看结果

首先，在本地测试代码。这将确保一切仍然运行，并可能会捕捉一些更微妙的错误。由于我们在数据库函数中使用了模拟，因此在 VPS 上运行之前，我们对此的工作没有太多信心。

在终端中运行`python crimemap.py`并在浏览器中访问`localhost:5000`后，您应该会看到以下内容：

![查看结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_07.jpg)

我们可以注意到一个单一的标记，其中包含我们在`MockDBHelper`中指定的细节。在截图中，我们将鼠标移动到标记上，使`title`显示出犯罪的所有细节。

现在是时候`commit`到`git`并推送到我们的 VPS 了。从您的`crimemap`目录中在本地运行以下命令：

```py
git add crimemap.py
git add dbhelper.py
git add mockdbhelper.py
git add templates/home.html
git commit –m "add new crimes functionality"
git push origin master

```

然后，SSH 到您的 VPS 以拉取新更改：

```py
ssh username@123.456.789.123
cd /var/www/crimemap
git pull origin master
sudo service apache2 reload

```

如果现在访问 VPS 的 IP 地址，我们应该会看到我们在能够显示它们之前添加的两起犯罪。由于我们在生产站点上使用了真实的`DBHelper`和我们的 MySQL 数据库，因此我们应该能够使用表单添加犯罪，并实时将每起犯罪添加为地图上的标记。希望您会得到类似以下截图的结果：

![查看结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_07_08.jpg)

如果事情不如预期那样顺利，像往常一样在您的 VPS 上运行以下命令，并在访问网站时查看输出：

```py
tail –f /var/log/apache2/error.log

```

此外，通过按下*Ctrl* + *Shift* + *C* 使用浏览器的调试器来捕获可能出现的任何 JavaScript 错误。

我们的犯罪地图现在已经可以使用，可以开始跟踪城镇的犯罪并让人们保持知情。然而，在进行最终项目之前，我们还将在下一章中添加一些最后的修饰。

# 摘要

在本章中，我们学习了如何在 Python 中创建一个模拟数据库，以便我们可以开发我们的应用程序而不需要访问真实的数据库。我们还向我们的应用程序添加了一个谷歌地图小部件，并允许用户通过单击地图轻松提交纬度和经度，同时能够查看现有犯罪的位置和描述。

在下一章中，我们将看看另一个注入漏洞，XSS，并讨论如何保护以及输入验证。


# 第八章：在我们的犯罪地图项目中验证用户输入

用户总是以你意想不到或意料之外的方式使用你的应用程序，无论是出于无知还是恶意意图。用户有任何控制权的输入都应该经过验证，以确保其符合预期。

通过确保用户无法意外或通过恶意输入破坏我们的第二个项目。

在本章中，我们将涵盖以下主题：

+   选择在哪里进行验证

+   尝试 XSS 示例

+   验证和清理

# 选择在哪里进行验证

在验证用户输入和提供帮助他们纠正任何错误的反馈时，有一些选择要做。主要选择是在*哪里*进行验证：在浏览器中，在服务器上，或两者兼顾。

我们可以在用户的浏览器中使用 JavaScript 进行验证。这种方法的优点是用户会得到更快的反馈（他们不必等待将数据发送到我们的服务器，进行验证，然后再发送响应），而且还减轻了我们服务器的负担；如果我们不使用 CPU 周期和网络带宽来验证用户数据，这意味着我们在运行服务器时有更低的成本。这种方法的缺点是我们无法保证用户不会绕过这些检查；如果检查在用户的浏览器中运行，那么用户就完全控制它们。这意味着经过客户端检查验证的数据仍然不能保证是我们期望的。

我们可以在用户提交数据后在服务器上进行验证。这种方法的优缺点与前面描述的相反。我们使用了更多的处理时间，但我们对检查的完整性有额外的保证。另一方面，用户通常需要等待更长时间才能得到有关合法（而非恶意）错误的反馈。

最后的选择是两者兼顾。这样可以让我们兼顾各方面的利益；我们可以在 JavaScript 中快速向用户提供反馈，然后在服务器端重新检查结果，以确保没有绕过客户端检查。另一方面，这样做的缺点是我们最终会浪费 CPU 周期来检查合法数据两次，而且我们还需要在开发中付出更多的努力，因为我们需要在 JavaScript 和 Python 中编写验证检查。

在这个项目中，由于我们将从头开始实现表单管理，我们只会在服务器端进行一些非常基本的检查，而不会在客户端进行检查。在我们下一个项目中，当我们使用框架来处理用户输入时，我们将讨论如何轻松使用一些更复杂的验证方法。

## 识别需要验证的输入

我们已经注意到，并非所有浏览器都支持 HTML5 的`"date"`类型输入。这意味着，就我们的网站而言，一些用户可能会手动输入犯罪日期，这意味着我们需要能够处理用户以各种格式输入日期。我们的数据库期望 yyyy-mm-dd（例如，2015-10-10 代表 2015 年 10 月 10 日），但我们的用户不一定会遵守这个格式，即使我们告诉他们。因此，“日期”字段是我们希望验证的输入之一。

我们的“纬度”和“经度”字段也可以由用户编辑，因此用户可能会在其中输入文本或其他无效的坐标。我们可以为这些字段添加验证检查，但是，由于用户实际上不应该需要编辑这些值，我们将考虑如何将它们设置为*只读*。我们将添加验证检查，以确保用户没有将它们留空。

**描述**是最明显危险的字段。用户可以在这里自由输入文本，这意味着用户有机会*注入*代码到我们的应用中。这意味着用户可以在这里输入干扰我们期望运行的代码的 JavaScript 或 HTML 代码，而不是填写文本描述，正如我们可能期望的那样。这样做将是所谓的 XSS 或跨站点脚本攻击的一个例子，我们将看一些用户可能在这里使用的恶意输入。

我们的最后一个输入是**类别**。这可能看起来非常安全，因为用户必须从下拉列表中进行选择。然而，重要的是下拉列表只是一种便利，实际上，具有一些基本知识的用户也可以在这里使用自由格式的文本。这是因为浏览器使用表单中的信息创建`POST`请求，然后将其发送到我们的服务器。由于`POST`请求只是以某种方式结构化并通过 HTTP 发送的文本，所以我们的技术娴熟的用户可以构造`POST`请求而不使用 Web 浏览器（他们可以使用 Python 或其他编程语言，甚至一些更专门的，但免费提供的软件，如 BURP Suite）。

正如我们所看到的，我们所有的输入都需要以某种形式进行验证。在我们看一下如何验证输入之前，让我们简要看一下如果我们决定不实施验证，恶意用户可能会做些什么。

# 尝试 XSS 示例

恶意用户最渴望的攻击之一是所谓的*持久性* XSS 攻击。这意味着攻击者不仅成功地将代码注入到您的 Web 应用程序中，而且这些注入的代码还会在较长时间内保留。通常情况下，这是通过欺骗应用程序将恶意注入的代码存储在数据库中，然后在后续访问页面时运行代码来实现的。

### 注意

在接下来的示例中，我们将*破坏*我们的应用程序，特定输入到我们的表单。然后，您需要登录到 VPS 上的数据库，手动清除这些使我们的应用程序处于破碎状态的输入。

就我们目前的应用而言，攻击者可以通过填写**类别**、**日期**、**纬度**和**经度**字段，然后在**描述**字段中使用以下内容来进行持久性 XSS 攻击：

```py
</script><script>alert(1);</script>
```

这可能看起来有点奇怪，但试一试。你应该会看到以下内容：

![尝试 XSS 示例](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_08_01.jpg)

在你点击弹出窗口上的**确定**后，你可能会注意到页面顶部的 JavaScript 代码片段（你的`longitude`值将不同，取决于你放置标记的位置）。

```py
", "longitude": 26.52799}]); } function placeCrimes(crimes) { for (i=0; i
```

让我们看看这里发生了什么。如果我们查看页面的完整源代码，就会更清楚地理解。右键单击页面，然后单击**查看页面源代码**或等效选项。

我们的 JavaScript 代码中`initialize`函数中的`placecrimes()`调用现在看起来如下：

```py
placeCrimes([{"latitude": -33.305645, "date": "2015-10-10", "category": "mugging", "description": "</script><script>alert(1);</script>", "longitude": 26.52799}]);
```

如果您的浏览器使用任何形式的代码高亮，那么更容易看到发生了什么。在我们页面开头附近的开放`<script>`标签现在被我们第一个犯罪的描述所关闭，因为我们的浏览器知道要解释`<script>`和`</script>`之间的任何内容为 JavaScript 代码。由于我们在`"description"`的开头有`</script>`，浏览器关闭了这部分 JavaScript。紧接着，新的 JavaScript 部分由`<script>`打开，这是我们描述的下一部分。接着，我们有`alert(1);`，它只是创建了我们之前注意到的带有**1**的弹出框。这个脚本部分再次关闭，我们页面的其余部分现在被我们的浏览器解释为一团糟。我们可以看到我们 JSON 的其余部分(`"longitude": …` )直到我们`for`循环的一半被显示给用户，而`i<crimes.length`中的"`<`"符号现在被浏览器解释为另一个开放标签，因此随后的 JavaScript 再次被隐藏。

为了修复我们的应用程序，请使用以下命令从数据库中删除所有犯罪数据（您应该在 VPS 上运行这些命令）：

```py
mysql crimemap –p
<your database password>
delete from crimes;

```

您应该看到有关从`crimes`表中删除了多少犯罪记录的消息，类似于以下截图中看到的消息：

![尝试 XSS 示例](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_08_02.jpg)

## 持久性 XSS 的潜力

我们的网络应用程序出现故障似乎很糟糕。更糟糕的是，重新加载页面并不是一个解决方案。由于恶意描述存储在我们的数据库中，无论我们多少次重新加载页面，都会出现相同的问题。更糟糕的是，"`alert(1);`"示例就是这样一个示例，用来显示攻击者有权利运行任何他或她想要的代码。通常，攻击者利用这一点来诱使用户访问另一个（恶意）页面，因为用户相信原始页面，因此更有可能相信其中的内容。可能性实际上只受到我们攻击者想象力的限制。

# 验证和清理

为了防止上述情况发生，我们已经选择在服务器端检查数据，并确保其符合我们的期望。不过，我们还有一些选择要做。

## 白名单和黑名单

我们需要创建一些规则来选择可接受的输入和不可接受的输入，有两种主要方法可以做到这一点。一种方法是*黑名单*输入看起来恶意。使用这种方法，我们将创建一个可能被恶意使用的字符列表，比如"`<`"和"`>`"，并且我们将拒绝包含这些字符的输入。另一种方法是使用*白名单*方法。这与黑名单相反，我们可以选择一个我们*允许*的字符列表，而不是选择我们不允许的字符。

这似乎是一个微不足道的区别，但它仍然很重要。如果我们选择黑名单方法，我们更有可能被恶意用户智能地使用我们没有添加到禁止列表的字符来注入代码。

另一方面，使用白名单方法，我们更有可能让想要使用我们没有考虑添加到白名单的字符的用户感到沮丧。

由于我们的应用程序只需要一个`"description"`输入来进行自由文本，并且因为我们的应用程序是本地化的（在我们使用的示例中，该应用程序是特定于南非格雷厄姆斯敦，因此我们预计我们的用户只需要普通的拉丁字符，而不是例如中文字符），我们应该能够在不妨碍用户的情况下使用白名单。

## 验证与清理

接下来，我们必须决定如何处理无效输入。我们是完全拒绝它并要求用户重试，还是只剥离用户输入的无效部分并保留其余部分？删除或修改用户输入（例如添加转义字符）被称为*净化*输入。这种方法的优势是用户通常对此毫不知情；如果他或她在犯罪描述中无意中包含特殊字符，而我们将其删除，这不太可能使描述的其余部分变得难以理解或毫无价值。缺点是，如果用户最终依赖我们列入黑名单的太多字符，它可能会使信息损坏到无法使用甚至误解用户的本意。

## 实施验证

考虑到所有前述内容，我们希望：

+   检查用户提交的类别，并确保它在我们期望的类别列表中

+   检查用户提交的日期，并确保我们可以正确理解它作为日期。

+   检查用户提交的纬度和经度，并确保这些可以解析为浮点数

+   检查用户提交的描述，并剥离除了字母数字字符或基本标点字符预选列表之外的所有字符

尽管我们会悄悄编辑“描述”以删除非白名单字符，但如果其他字段不符合我们的预期，我们希望拒绝整个提交并让用户重新开始。因此，我们还希望在用户提交表单后添加一种显示自定义错误消息的方法。让我们添加一些 Python 函数来帮助我们完成所有这些。我们还将重构一些代码以符合*不要重复自己（DRY）*原则。

## 验证类别

以前，当我们为“类别”创建下拉列表时，我们在模板中硬编码了我们想要的两个“类别”。这已经不理想，因为这意味着如果我们想要添加或编辑“类别”，我们必须编写更多样板代码（如 HTML 标记）。现在我们还想在 Python 中访问“类别”列表，以便我们可以验证用户是否偷偷使用了不在我们列表中的类别，因此重构一下是有道理的，这样我们只定义一次我们的“类别”列表。

我们将在 Python 代码中定义列表，然后我们可以将其传递给模板以构建下拉列表，并在用户提交表单时使用相同的列表进行验证。在`crimemap.py`的顶部，与其他全局变量一起，添加以下内容：

```py
categories = ['mugging', 'break-in']
```

在`home()`函数的`return`语句中，将此列表作为命名参数传递。该行现在应该类似于这样：

```py
return render_template("home.html", crimes=crimes, categories=categories)
```

在`home.html`中，更改`<select>`块以使用 Jinja 的`for`循环，如下所示：

```py
<select name="category" id="category">
    {% for category in categories %}
        <option value="{{category}}">{{category}}</option>
    {% endfor %}
</select>
```

通过这些小修改，我们有了一种更容易维护我们的“类别”列表的方法。我们现在还可以使用新列表进行验证。由于类别是由下拉列表提供的，普通用户在这里不会输入无效值，因此我们不必太担心提供礼貌的反馈。在这种情况下，我们将忽略提交并再次返回主页。

在`submitcrime()`函数中加载类别数据到变量中的位置下方直接添加以下`if`语句：

```py
category = request.form.get("category")
if category not in categories:
    return home()
```

如果触发了这个“返回”，它会在我们向数据库添加任何内容之前发生，并且我们用户尝试的输入将被丢弃。

## 验证位置

由于我们的位置数据应该由用户在地图上放置的标记自动填充，我们希望将这些字段设置为`readonly`。这意味着我们的 JavaScript 仍然可以修改值，因为标记被使用，但字段将拒绝用户键盘的输入或修改。要做到这一点，只需在`home.html`模板中定义表单的地方添加`readonly`属性。更新后的`input`定义应如下所示：

```py
<label for="latitude">Latitude</label>
<input name="latitude" id="latitude" type="text" readonly>
<label for="longitude">Longitude</label>
<input name="longitude" id="longitude" type="text" readonly>
```

与下拉列表一样，`readonly`属性仅在浏览器级别执行，并且很容易被绕过。因此，我们还希望添加服务器端检查。为此，我们将使用 Python 的哲学“宁可请求原谅，而不是征得许可”，换句话说，假设一切都会没问题，并在`except`块中处理其他情况，而不是使用太多的`if`语句。

如果我们可以将用户的位置数据解析为浮点数，那几乎肯定是安全的，因为只用数字很难做一些事情，比如修改 HTML、JavaScript 或 SQL 代码。在我们解析位置输入的`submitcrime()`函数部分周围添加以下代码：

```py
try:
    latitude = float(request.form.get("latitude"))
    longitude = float(request.form.get("longitude"))
except ValueError:
    return home()
```

如果`latitude`或`longitude`输入中有任何意外的文本，在我们尝试转换为浮点类型时，将抛出`ValueError`，然后我们将返回到主页，而不会将任何潜在危险的数据放入我们的数据库。

## 验证日期

对于`date`输入，我们可以采取与`category`相同的方法。大多数情况下，用户将从日历选择器中选择日期，因此将无法输入无效日期。但是，由于并非所有浏览器都支持`date`输入类型，有时普通用户会手动输入日期，这可能会导致意外错误。

因此，在这种情况下，我们不仅要拒绝无效的输入。我们希望尽可能弄清楚用户的意图，如果我们不能，我们希望向用户显示一条消息，指出需要修复的地方。

为了允许更灵活的输入，我们将使用一个名为`dateparser`的 Python 模块。该模块允许我们将格式不一致的日期转换为准确的 Python `datetime`对象。我们需要做的第一件事是通过`pip`安装它。在本地和 VPS 上运行以下命令：

```py
pip install --user dateparser
```

如果您以前没有使用过它，您可能会喜欢尝试一下它的可能性。以下独立脚本演示了`dateparser`提供的一些魔力：

```py
import dateparser
print dateparser.parse("1-jan/15")
print dateparser.parse("1 week and 3 days ago")
print(dateparser.parse("3/4/15")
```

所有前面的字符串都被正确解析为`datetime`对象，最后一个可能是例外，因为`dateparser`使用美国格式，并将其解释为 2015 年 3 月 4 日，而不是 2015 年 4 月 3 日。

还可以在 PyPI 上找到更多示例以及关于`dateparser`模块的其他信息[`pypi.python.org/pypi/dateparser`](https://pypi.python.org/pypi/dateparser)。

仅使用此软件包将解决我们很多问题，因为我们现在可以将无效输入转换为有效输入，而无需用户的任何帮助。稍微不方便的是，我们已经设置了数据库接受以"*yyyy-mm-dd*"格式插入的日期；但是，为了利用我们的新`dateparser`模块，我们将希望将用户的输入转换为`datetime`对象。稍微反直觉的解决方法是将我们从用户那里收到的字符串输入转换为`datetime`对象，然后再转换为字符串（始终以正确的格式），然后将其传递到我们的数据库代码中存储在 MySQL 中。

首先，在您的`crimemap.py`文件中添加以下辅助函数：

```py
def format_date(userdate):
    date = dateparser.parse(userdate)
    try:
        return datetime.datetime.strftime(date, "%Y-%m-%d")
    except TypeError:
        return None    
```

此外，将`crimemap.py`的顶部添加`datetime`和`dateparser`模块的导入，如下所示：

```py
import datetime
import dateparser
```

我们将通过用户输入的`date`（`userdate`）传递给这个函数，并使用我们的`dateparser`模块进行解析。如果日期完全无法解析（例如，“`aaaaa`”），`dateparser.parse`函数将返回空而不是抛出错误。因此，我们将调用`strftime`，它将以正确的格式将日期格式化为字符串，放入`try except`块中；如果我们的`date`变量为空，我们将得到`TypeError`，在这种情况下，我们的辅助函数也将返回`None`。

现在，我们需要决定如果无法解析日期该怎么办。与我们之前看到的其他验证情况不同，在这种情况下，我们希望向用户提示一条消息，说明我们无法理解他或她的输入。为了实现这一点，我们将在`home()`函数中添加一个错误消息参数，并从`submitcrime()`函数中传递相关的错误消息。修改`home()`函数以添加参数，并将参数传递到我们的模板中，如下所示：

```py
@app.route("/")
def home(error_message=None):
    crimes = DB.get_all_crimes()
    crimes = json.dumps(crimes)
 return render_template("home.html", crimes=crimes, categories=categories, error_message=error_message)

```

然后，修改`submitcrime()`函数，添加一些逻辑来解析用户输入的日期，并在无法解析`date`时向我们的`home()`函数传递错误消息，如下所示：

```py
if category not in categories:
    return home()
date = format_date(request.form.get("date"))
if not date:
 return home("Invalid date. Please use yyyy-mm-dd format")

```

我们还需要在模板文件中添加一个部分来显示错误消息（如果存在的话）。我们将把它添加到表单的顶部，通过以下代码引起用户的注意：

```py
<div id="newcrimeform">
    <h2>Submit new crime</h2>
 {% if error_message %}
 <div id="error"><p>{{error_message}}</p></div>
 {% endif %}
    <form action="/submitcrime" method="POST">
```

我们将添加前面的`if`语句，否则当`error_message`变量具有默认值`None`时，我们将在表单上方看到单词“`None`”。另外，请注意，消息本身出现在具有 ID 为 error 的`<div>`标签中。这允许我们添加一些 CSS 使错误消息以红色显示。在您的静态目录中的`style.css`文件中添加以下块：

```py
#error {
    color: red;
}
```

这就是我们验证日期的方法。如果您的浏览器不支持`date`输入，请尝试创建一个新的犯罪，并输入一个连`dateparser`也无法解释为合法日期的字符串，以确保您看到预期的错误。它应该看起来类似于以下图片：

![验证日期](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_08_03.jpg)

### 注意

Flask 提供了一些非常方便的消息*闪烁*功能，即在页面的特定位置显示可选文本。这比我们讨论的基本示例具有更强大和灵活的功能，并且应该在类似的情况下予以考虑。有关 Flask 中消息闪烁的信息可以在[`flask.pocoo.org/docs/0.10/patterns/flashing/`](http://flask.pocoo.org/docs/0.10/patterns/flashing/)找到。

## 验证描述

我们可以假设用户只能使用数字、字母（大写和小写）和一些基本的标点符号来传达有关犯罪的基本信息，因此让我们创建一个简单的 Python 函数，过滤掉除了我们已确定为安全的字符之外的所有字符。在您的`crimemap.py`文件中添加以下`sanitize()`函数：

```py
def sanitize_string(userinput):
    whitelist = string.letters + string.digits + " !?$.,;:-'()&"
    return filter(lambda x: x in whitelist, userinput)
```

然后，在`crimemap.py`的导入部分添加字符串的导入，如下所示：

```py
import string
```

我们的`sanitize_string()`函数非常简洁，并使用了 Python 的一些函数式编程潜力。`filter`函数对列表中的每个元素重复应用另一个函数，并基于“通过”的元素构建一个新列表。在这种情况下，我们将传递给`filter()`的函数是一个简单的`lambda`函数，用于检查字母是否属于我们的白名单。我们函数的结果是一个类似于输入的字符串，但删除了不属于我们白名单的所有字符。

我们的白名单是由所有字母（大写和小写）、数字一到九以及一些基本的标点符号构建而成，人们在输入事件的非正式描述时可能会使用这些标点符号。

要使用我们的新函数，只需将`crimemap.py`中`submitcrime()`函数末尾的行从以下内容更改为以下内容：

```py
description = request.form.get("description")
description = sanitize_string(request.form.get("description"))
```

请注意，由于我们的 SQL 驱动程序可以减轻 SQL 注入，而我们的`json.dumps()`函数可以转义双引号，因此我们只需在黑名单中列出一些字符，比如尖括号，我们就可以基本上安全了，我们用它来演示 XSS 攻击。这将为我们的用户提供更多的灵活性，但是恶意用户可能会决心并且有创造力地制作输入，以绕过我们设置的过滤器。参考[`www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet`](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)获取一些例子。首先在本地尝试验证更改，然后，如果一切看起来都很好，就提交到`git`，将存储库推送到远程，并将其拉到 VPS 上。重新启动 Apache 并访问您的 IP 地址。尝试在`description`中提交一个使用`</script>`的犯罪，当您将光标悬停在这个犯罪的标记上时，您会注意到我们存储的只是"`script`"。我们将删除斜杠和尖括号，从而确保防止 XSS 攻击。

我们已经讨论了黑名单和白名单的利弊，但是为了强调白名单并不是一个完美的方法，看一下这里关于开发人员在为用户的名称设置白名单时经常犯的错误的帖子：[`www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/`](http://www.kalzumeus.com/2010/06/17/falsehoods-programmers-believe-about-names/)

我们可以对我们的`dbhelper.py`、`mockdbhelper.py`和`crimemap.py`文件进行的最后一个更改是删除我们不再需要的函数。当我们有一个不特定于犯罪的基本数据库应用程序时，我们在我们的`DBHelper`类中有`get_all_inputs()`、`add_input()`和`clear_all()`函数，在我们的`crimemap.py`文件中有`add()`和`clear()`函数。所有这些都可以被移除。

# 总结

我们已经花了一整章的时间来研究验证，但是如果你看一下过去几年面临信息安全漏洞的主要公司，你会同意安全是值得花一些时间的。我们特别关注了跨站脚本攻击或 XSS 攻击，但我们也讨论了一些更一般的输入验证要点。这让我们来到了我们第二个项目的结束。

一个明显缺失的事情是弄清楚是谁添加了哪些犯罪。如果一个恶意用户向我们的数据库添加了一堆虚假的犯罪，他们可能会搞乱我们整个数据集！

在我们的下一个项目中，我们将研究通过用户帐户控制系统对用户进行身份验证，这将使我们对我们允许在我们的网站上的用户以及他们可以做什么有更多的控制。


# 第九章：建立服务员呼叫应用程序

在经历了头条项目之后，你学习了 Flask 的基础知识，以及 Crimemap 项目，其中你学习了一些更有用的 Flask 功能，比如如何使用数据库和如何编写一些基本的 JavaScript 代码，我们现在准备进行我们迄今为止最复杂的项目！我们将建立一个服务员呼叫网络应用程序，允许餐厅顾客轻松地呼叫服务员到他们的桌子上。餐厅经理将能够轻松注册并开始使用我们的应用程序，而无需投资昂贵的硬件。

我们将深入研究 Flask 世界，看看一些 Flask 扩展，帮助我们进行用户账户控制和网络表单，并且我们还将看看如何在 Jinja 中使用模板继承。我们还将使用 Bootstrap 前端框架，这样我们就不必从头开始编写太多 HTML 和 CSS 代码。

与我们之前应用程序使用的 MySQL 数据库相比，我们将看看一个有争议的替代方案：MongoDB。MongoDB 是一个 NoSQL 数据库，这意味着我们在其中不处理表、行和列。我们还将讨论这究竟意味着什么。

对于服务员来说，最困难的任务之一就是知道顾客需要什么。要么顾客抱怨等待服务员来询问甜点选择的时间太长，要么他们抱怨服务员不断打断对话来询问一切是否顺利。为了解决这个问题，一些餐厅在每张桌子上安装了专用按钮，当按下时，通知服务员需要他的注意。然而，对于规模较小的餐厅来说，专门硬件和安装的成本是不可承受的，对于规模较大的餐厅来说，这往往只是太麻烦了。

在我们现代的时代，几乎所有的餐厅顾客都有智能手机，我们可以利用这一事实为餐厅提供一个成本更低的解决方案。当顾客需要服务时，他们只需在手机上访问一个简短的 URL，服务员就会在一个集中的屏幕上收到通知。

我们希望该应用程序允许多个不相关的餐厅使用同一个网络应用程序，因此每个餐厅都应该有我们系统的私人登录账户。我们希望餐厅经理能够轻松设置；也就是说，当一个新餐厅加入系统时，我们作为开发人员不需要参与其中。

我们应用程序所需的设置如下：

+   餐厅经理在我们的网络应用程序上注册一个新账户

+   餐厅经理提供了关于餐厅有多少张桌子的基本信息

+   网络应用程序为每张桌子提供一个独特的 URL

+   餐厅经理打印出这些 URL，并确保相关的 URL 可以轻松从每张桌子上访问

我们的应用程序使用应该具有以下功能：

+   餐厅员工应该能够从一个集中的屏幕登录到网络应用程序并看到一个简单的通知页面。

+   一些顾客希望通过智能手机获得服务，并访问与他们的桌子相关的 URL，因此这应该是可能的。

+   服务员应该实时看到通知出现在一个集中的屏幕上。然后服务员会在屏幕上确认通知并为顾客提供服务。

+   如果在第一个通知被确认之前出现更多通知，后来的通知应该出现在先前的通知下方。

在接下来的三章中，我们将实现一个具有所有前述功能的 Flask 应用程序。我们将拥有一个数据库，用于存储注册使用我们的应用程序的所有个别餐厅的帐户信息，以便我们可以为每个餐厅单独处理顾客的请求。顾客将能够发出请求，这些请求将在数据库中注册，而餐厅工作人员将能够查看他们餐厅的当前关注请求。我们将构建一个用户帐户控制系统，以便餐厅可以为我们的应用程序拥有自己的受密码保护的帐户。

首先，我们将设置一个新的 Flask 应用程序、Git 存储库和 Apache 配置来提供我们的新项目。我们将引入 Twitter 的 Bootstrap 框架作为我们在前端使用的框架。我们将下载一个基本的 Bootstrap 模板作为我们应用程序前端的起点，并对其进行一些更改以将其整合到一个基本的 Flask 应用程序中。然后，我们将设置一个用户帐户控制系统，允许用户通过提供电子邮件地址和密码在我们的应用程序中注册、登录和注销。

在本章中，我们将涵盖以下主题：

+   设置新的`git`存储库

+   使用 Bootstrap 启动我们的应用程序

+   将用户帐户控制添加到我们的应用程序

# 设置新的 Git 存储库

与以前一样，我们需要创建一个新的`git`存储库来托管我们的新项目。第一步是登录 BitBucket 或您正在使用的任何代码存储库主机的 Web 界面，选择**创建新存储库**选项，并选择**Git**单选按钮，注意它提供给您的 URL。由于接下来的步骤与以前的项目相同，我们只会给您一个摘要。如果您需要更详细的指导，请参考第一章 *安装和使用 git*部分，*你好，世界！*。

## 在本地设置新项目

为了设置本地项目结构，请在本地运行以下命令：

```py
mkdir waitercaller
cd waitercaller
git init
git remote add origin <new-repository-url>
mkdir templates
mkdir static
touch waitercaller.py
touch templates/home.html
touch .gitignore

```

我们希望为这个项目获得最小的运行应用程序，以便在开始开发之前解决任何配置问题。将以下内容添加到您的`waitercaller.py`文件中：

```py
from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
   return "Under construction"

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```

然后，使用以下命令将项目概述推送到存储库：

```py
git add .
git commit –m "Initial commit"
git push origin master

```

## 在我们的 VPS 上设置项目

在您的 VPS 上，运行以下命令来克隆存储库，并设置 Apache2 以将我们的新项目作为默认网站提供服务：

```py
cd /var/www/
git clone <new-repository-url>
cd waitercaller
nano waitercaller.wsgi

```

将以下代码添加到我们最近创建的`.wsgi`文件中：

```py
import sys
sys.path.insert(0, "/var/www/waitercaller")
from waitercaller import app as application
```

现在，按下*Ctrl* + *X*，并在提示时选择*Y*退出 Nano。

最后，通过运行以下命令创建 Apache 配置文件：

```py
cd /etc/apache2/sites-available
nano waitercaller.conf

```

将以下配置数据添加到我们刚创建的`waitercaller.conf`文件中：

```py
<VirtualHost *>

    WSGIScriptAlias / /var/www/waitercaller/waitercaller.wsgi
    WSGIDaemonProcess waitercaller
    <Directory /var/www/waitercaller>
       WSGIProcessGroup waitercaller
       WSGIApplicationGroup %{GLOBAL}
        Order deny,allow
        Allow from all
    </Directory>
</VirtualHost>
```

退出 Nano，保存新文件。现在，为了禁用我们的`crimemap`项目作为默认站点，并启用我们的新项目，运行以下命令：

```py
sudo a2dissite crimemap.conf
sudo a2ensite waitercaller.conf
sudo service apache2 reload

```

通过在 Web 浏览器中访问您的 VPS 的 IP 地址来验证一切是否正常。您应该看到**正在建设中**字符串。如果事情不如预期那样工作，请再次查看您的配置和日志文件。

# 使用 Bootstrap 启动我们的应用程序

在我们以前的项目中，我们花了相当多的时间在前端工作上，摆弄 CSS 和 HTML，并且甚至没有触及到 Web 应用程序开发人员需要注意的一些前端问题，比如确保我们的内容在任何操作系统上的任何浏览器上的所有屏幕尺寸的所有设备上看起来好看并且功能正常。浏览器和设备的多样性以及它们各自实现某些 JavaScript、HTML 和 CSS 功能的不一致方式是 Web 开发的最大挑战之一，没有解决问题的银弹。然而，像 Bootstrap 这样的前端框架可以减轻一些痛苦，为开发人员提供改进用户体验的捷径。

## 介绍 Bootstrap

Bootstrap 由 Twitter 开发，并在开放许可下发布。它可以极大地加快 CSS 开发，因为它为不同的 HTML 布局和表单输入提供了许多样式。它还可以提供*响应性*；也就是说，它可以根据用户设备的屏幕大小自动更改某些元素的布局。我们将在本章后面讨论这对我们和这个项目的确切意义。

### 注意

Bootstrap 受到了一些批评，但它仍然保持着它的流行度。有许多具有不同优势和劣势的替代品。随着现代网页开发的快速发展，也会定期出现许多新的框架。现有的框架经常会进行重大更新，并且不提供向旧版本的向后兼容性。对于重要的生产网页应用程序，当前研究什么最适合这个项目的特定需求总是至关重要的。

Bootstrap 的主要提供的是可重复使用的 CSS 和 JavaScript 模块。我们主要会用它的 CSS 组件。

查看 Bootstrap 的主页[`getbootstrap.com/`](http://getbootstrap.com/)，以及子页面[`getbootstrap.com/getting-started/#examples`](http://getbootstrap.com/getting-started/#examples)和[`getbootstrap.com/components/`](http://getbootstrap.com/components/)，以了解 Bootstrap 提供了什么。

与从头开始编写 CSS 不同，Bootstrap 允许我们使用各种输入、图标、导航栏和其他经常需要的网站组件，默认情况下看起来很好。

## 下载 Bootstrap

有几种安装 Bootstrap 的方法，但要记住 Bootstrap 可以被视为一组 JavaScript、CSS 和图标文件的集合，我们不会做太复杂的事情。我们可以简单地下载编译后的代码文件的`.zip`文件，并在我们的本地项目中使用这些文件。我们将在我们的`git`存储库中包含 bootstrap，因此无需在我们的 VPS 上安装它。执行以下步骤：

1.  转到[`getbootstrap.com/getting-started/#download`](http://getbootstrap.com/getting-started/#download)，选择**下载 Bootstrap**选项，这应该是已编译和压缩的版本，没有文档。

1.  解压您下载的文件，您会发现一个名为`bootstrap-3.x.x`的单个目录（这里，重复的字母 x 代表包含的 Bootstrap 版本的数字）。在目录内，可能会有一些子目录，可能是`js`、`css`和`fonts`。

1.  将`js`、`css`和`fonts`目录复制到`waitercaller`项目的`static`目录中。您的项目现在应该具有以下结构：

```py
waitercaller/
templates
    home.html
static
    css/
    fonts/
    js
.gitignore
waitercaller.py
```

由于定期的 Bootstrap 更新，我们在附带的代码包中包含了 Bootstrap 3.3.5 的完整代码副本（在撰写本书时的最新版本）。虽然最新版本可能更好，但它可能与我们提供的示例不兼容。您可以选择使用我们提供的版本来测试，知道示例应该按预期工作，或者直接尝试适应更新的 Bootstrap 代码，必要时尝试适应示例。

### Bootstrap 模板

Bootstrap 强烈鼓励用户构建定制的前端页面，而不是简单地使用现有的模板。你可能已经注意到很多现代网页看起来非常相似；这是因为前端设计很困难，人们喜欢走捷径。由于本书侧重于 Flask 开发，我们也会采取一些前端的捷径，并从 Bootstrap 提供的示例模板文件开始。我们将使用的模板文件可以在[`getbootstrap.com/examples/jumbotron/`](http://getbootstrap.com/examples/jumbotron/)中找到，我们项目的适配可以在本章的附带代码包中的`tempates/home.html`中找到。你可以注意到这两个文件的相似之处，我们并没有做太多的工作来获得一个基本的网页，看起来也很好。

从代码包中的`templates/home.html`文件中复制代码到您之前创建的项目目录中的相同位置。如果您在`static`文件夹中正确地包含了所有的 Bootstrap 文件，直接在 Web 浏览器中打开这个新文件将会得到一个类似于以下屏幕截图的页面。（请注意，在这个阶段，我们仍然使用纯 HTML，没有使用 Jinja 功能，所以您可以直接在 Web 浏览器中打开文件，而不是从 Flask 应用程序中提供服务。）

![Bootstrap templates](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_01.jpg)

我们可以注意到，我们可以用很少的代码实现输入、标题、导航栏和 Jumbotron（靠近顶部的灰色条，上面有超大的**服务员呼叫**文本）的样式的优势。然而，使用 Bootstrap 最显著的节省时间的元素可能是我们网站的*响应性*。Bootstrap 基于网格布局，这意味着网格的不同元素可以重新排列以更好地适应任何设备。注意模板中的 HTML 的这一部分：

```py
<div class="row">
 <div class="col-md-4">
 <h2>Simple</h2>

```

一个`"row"`有 12 列的空间。我们的 Jumbotron 下面的三个主要内容元素每个占据四列，因此填满了整行（*4 x 3 = 12*）。我们使用`class="col-md-4"`属性来指定这一点。可以将其视为大小为四的中等（`md`）列。您可以在[`getbootstrap.com/css/`](http://getbootstrap.com/css/)上阅读有关网格系统如何工作的更多信息，并查看一些示例。

在前面的屏幕截图中还有一些看起来没有使用的代码，类似于这样：

```py
<button type="button" class="navbar-toggle collapsed" data- toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">

```

前面的两个摘录可能是使我们的网络应用程序响应的最重要的组成部分。要理解这意味着什么，可以在页面打开时调整浏览器窗口大小。这模拟了我们的页面在较小设备上（如手机和平板电脑）上的显示方式。它应该看起来类似于以下的屏幕截图：

![Bootstrap templates](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_02.jpg)

我们可以注意到，我们使用 Bootstrap 网格功能的三个主要内容元素现在排列在彼此下方，而不是并排。这对于较小的设备来说是理想的，用户更习惯于向下滚动，而不是在侧边寻找更多的内容。我们的导航栏也变得更加简洁，登录输入现在被隐藏了。

这些可以通过选择右上角的*汉堡包*图标来显示；这是一个有争议但非常普遍的网页开发元素。大多数用户本能地知道他们可以触摸图标以获得某种形式的菜单或扩展，但是有许多批评使用这种技术。目前，我们只接受这种正常的做法，不去深究它背后的问题。这绝对比尝试在任何屏幕大小上显示完全相同的内容，并且让我们的用户根据需要逐个部分地放大页面要好得多。

# 向我们的应用程序添加用户帐户控制

对于用户帐户控制，预期用户将使用密码登录和进行身份验证。例如，当您登录到您的网络邮件帐户时，您在访问页面时输入密码。此后，所有您的操作都将被视为经过身份验证；也就是说，当您发送电子邮件时，您不必再次输入密码。网络邮件客户端*记住*您已登录，因此允许您完成某些操作。

然而，HTTP 是一种无状态协议，这意味着我们无法直接知道登录的用户是否是发送电子邮件请求的同一用户。为了解决这个问题，我们将在用户最初登录时给用户一个 cookie，然后用户的浏览器将在*每个*后续请求中将此 cookie 发送给我们。我们将使用我们的数据库来跟踪当前已登录的用户。这使我们能够在每个请求中对用户进行身份验证，而无需多次请求用户的密码。

我们可以使用 Flask cookie 从头开始实现这一点，方式类似于我们在 Headlines 项目中看到的方式。但是，我们需要实现许多步骤，例如选择应用程序中哪些页面需要身份验证，并确保 cookie 是安全的，并参与决定在 cookie 中存储什么信息。

相反，我们将提高一级抽象，并使用`Flask-Login`扩展。

## 介绍 Flask-Login

`Flask-Login`是一个 Flask 扩展，实现了所有用户帐户控制系统所需的基础工作。要使用此功能，我们需要通过`pip`安装它，然后创建一个遵循特定模式的用户类。您可以在[`flask-login.readthedocs.org/en/latest/`](https://flask-login.readthedocs.org/en/latest/)找到`Flask-Login`的摘要以及全面的文档。

## 安装和导入 Flask-Login

要安装`Flask-Login`，运行以下命令：

```py
pip install --user flask-login

```

与我们安装的所有 Python 模块一样，请记住在本地和 VPS 上都要这样做。

首先，我们将添加可能的最基本的登录功能。我们的应用程序将为经过身份验证的用户显示**您已登录**，但未输入正确密码的用户将无法看到消息。

## 使用 Flask 扩展

当我们安装 Flask 扩展时，我们可以通过`flask.ext`路径自动访问它们。我们将从`Flask-Login`扩展中使用的第一个类是所谓的`LoginManager`类。我们还将使用`@login_required`装饰器指定哪些路由受限于已登录用户。将以下导入添加到您的`waitercaller.py`文件中：

```py
from flask.ext.login import LoginManager
from flask.ext.login import login_required
```

现在，我们需要将扩展连接到我们的 Flask 应用程序。在我们使用更多 Flask 扩展时将变得熟悉的模式中，将以下行直接添加到`waitercaller.py`中创建`app`变量的位置下面：

```py
app = Flask(__name__)
login_manager = LoginManager(app)

```

我们实例化的`LoginManager`类现在引用了我们的应用程序。我们将使用这个新的`LoginManager`类来管理我们应用程序的登录。

## 添加受限路由

现在，让我们在`/account`上为我们的应用程序添加一个路由，并确保只有经过身份验证的用户才能查看此页面。这一步的简单部分是确保*非*经过身份验证的用户*不能*看到页面，因此我们将从这里开始。

首先，我们希望我们的应用程序默认呈现我们的 Bootstrap 模板。将以下路由添加到`waitercaller.py`文件中：

```py
@app.route("/")
def home():
    return render_template("home.html")
```

现在，我们将添加一个受限路由，未登录的用户无法看到。将以下函数添加到`waitercaller.py`：

```py
@app.route("/account")
@login_required
def account():
   return "You are logged in"
```

请注意，我们正在使用`@login_required`装饰器。类似于`@app.route`装饰器，这是一个接受下面的函数作为输入并返回修改后的函数的函数。在这种情况下，它不是路由魔法，而是验证用户是否已登录，如果没有，它将重定向用户到一个**未经授权**页面，而不是返回我们在`return`语句中指定的内容。重要的是`@app.route`装饰器首先出现，`@login_required`装饰器在其下面，就像前面的例子一样。

### 注意

在浏览网页时，你可能会有时看到**404 页面未找到**错误。虽然**404**尤为臭名昭著，但有许多错误代码是 HTTP 规范的一部分。不同的浏览器在接收到这些错误时可能会显示不同的默认错误消息，也可以定义自定义错误页面在指定错误发生时显示。

由于我们还没有设置任何登录逻辑，没有用户应该能够验证并查看我们创建的新路由。在本地启动你的 Flask 应用程序，尝试访问`localhost:5000/account`的账户路由。如果一切顺利，你应该会看到类似以下截图的未经授权的错误消息：

![添加受限路由](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_03.jpg)

## 验证用户

互联网可能是一个黑暗和可怕的地方。这就是为什么你需要在许多网络应用程序中输入密码；密码证明你是你所声称的人。通过告诉我们只有你知道的东西，网络应用程序知道你是“你”，而不是冒名顶替者。

实现密码检查系统的最简单方法是在数据库中存储与用户名关联的密码。当用户登录时，你需要首先验证用户名是否存在，如果存在，你需要验证用户刚刚给出的密码是否与注册时使用的密码匹配。

实际上，这是一个糟糕的主意。数据库可能被任意数量的人访问，包括运行网络应用程序的公司的员工，可能还有黑客。相反，我们最终将存储用户密码的加密哈希；但是现在，为了确保我们的登录系统正常工作，我们将使用明文密码。

我们将建立一个模拟数据库，这个数据库与我们在犯罪地图项目中使用的数据库非常相似，并检查是否允许模拟用户查看我们的“账户”页面，只有在输入正确的密码时才允许。

### 创建一个用户类

由于我们正在使用`Flask-Login`模块，我们需要创建一个符合严格格式的`User`类。`Flask-Login`足够灵活，可以允许一些更高级的登录功能，比如区分*活跃*和*非活跃*账户以及匿名用户。我们不会使用这些功能，但我们需要创建一个能够与`Flask-Login`一起工作的`User`类，因此我们将有一些看起来多余的方法。

在你的`waitercaller`目录中创建一个名为`user.py`的新文件。将以下代码添加到其中：

```py
class User:
   def __init__(self, email):
      self.email = email

   def get_id(self):
      return self.email

   def is_active(self):
      return True

   def is_anonymous(self):
      return False

   def is_authenticated(self):
      return True
```

`Flask-Login`要求我们在我们的`User`类中实现一个`get_id()`方法，返回用户的唯一标识符。我们将使用用户的电子邮件地址，因此在`get_id()`函数中，我们可以简单地返回它。

我们将把所有用户视为活跃账户；因此，在这个方法中，我们将简单地返回`True`。对于`is_anonymous()`函数也是如此；虽然这也是必需的，但我们不会在我们的应用程序中处理匿名登录的概念，所以我们将始终返回`False`。

最后一个函数可能看起来有点奇怪；我们将始终为`is_authenticated()`返回`True`。这是因为只有在输入正确的用户名和密码组合时才会创建用户对象，所以如果用户对象存在，它将被验证。

## 模拟我们的用户数据库

我们将再次创建一个`MockDBHelper`类，并创建一个配置文件，指示在测试应用程序时应在本地使用它，而不需要访问数据库。它需要有一个函数，接受用户名和密码，并检查它们是否存在于数据库中，并且彼此关联。

首先，在您的`waitercaller`目录中创建一个名为`mockdbhelper.py`的文件，并添加以下代码：

```py
MOCK_USERS = {'test@example.com': '123456'}

class MockDBHelper:

   def get_user(self, email):
      if email in MOCK_USERS:
         return MOCK_USERS[email]
      return None
```

在顶部，我们有一个充当数据库存储的字典。我们有一个单独的`get_user()`方法，检查用户是否存在于我们的数据库中，并在存在时返回密码。

现在，在`waitercaller`目录中创建一个`config.py`文件，并添加以下单行：

```py
test = True
```

与上一个项目一样，此文件将让我们的应用程序知道它是在我们的测试（本地）环境中运行还是在我们的生产（VPS）环境中运行。与以前的项目不同，我们将稍后向此文件添加其他不涉及数据库的信息，这就是为什么我们将其称为`config.py`而不是`dbconfig.py`。我们不希望将此文件检入我们的`git`存储库，因为它在我们的 VPS 上会有所不同，并且还将包含我们不希望存储的敏感数据库凭据；因此，在您的`waitercaller`目录中创建一个`.gitignore`文件，并添加以下行：

```py
config.py
*.pyc
```

## 登录用户

我们的模板已经设置了一个登录表单，允许用户输入电子邮件和密码。现在，我们将设置功能，允许我们输入并检查此表单中的输入是否与我们的模拟数据库匹配。如果我们输入的电子邮件和密码存在于我们的模拟数据库中，我们将登录用户并允许访问我们的`/account`路由。如果不是，我们将重定向回主页（我们将在下一章节的*使用 WTForms 添加用户反馈*部分中查看向输入无效信息的用户显示反馈）。

### 添加导入和配置

我们需要导入`Flask-Login`扩展的`login_user`函数，以及我们的新`User`类代码和数据库助手。在`waitercaller.py`的导入中添加以下行：

```py
from flask.ext.login import login_user

from mockdbhelper import MockDBHelper as DBHelper
from user import User
```

由于目前除了我们的模拟数据库助手外，我们没有其他数据库助手，所以我们将始终导入模拟数据库助手。稍后，我们将使用`config.py`中的值来决定要`import`哪个数据库助手-真实的还是模拟的，就像我们在以前的项目中所做的那样。

我们还需要创建一个`DBHelper`全局类，以便我们的应用程序代码可以轻松地与我们的数据库交流。在`waitercaller.py`的导入部分下面添加以下行：

```py
DB = DBHelper()
```

最后，我们还需要为我们的应用程序配置一个秘密密钥。这用于对`Flask-Login`在用户登录时分发的会话信息 cookie 进行加密签名。签署 cookie 可以防止用户手动编辑它们，有助于防止欺诈登录。对于这一步，您应该创建一个长而安全的秘密密钥；您永远不必记住它，所以不要把它当作密码或口令来考虑。尽管随机按键盘应该足够，但人类通常很难创建无偏见的随机性，因此您也可以使用以下命令使用`/dev/urandom`创建一个随机字符串（将`100`更改为您想要的字符数）：

```py
cat /dev/urandom | base64 | head -c 100 ; echo

```

一旦您有了一长串随机字符，将以下行添加到您的`waitercaller.py`文件中，在您声明`app`变量的位置下，用您自己的随机字符替换它：

```py
app.secret_key = 'tPXJY3X37Qybz4QykV+hOyUxVQeEXf1Ao2C8upz+fGQXKsM'
```

### 添加登录功能

登录用户有两个主要部分需要考虑。第一部分是用户输入电子邮件地址和密码进行身份验证，第二部分是用户通过发送所需的 cookie 进行身份验证，即他或她仍然处于与成功登录完成时相同的浏览器*会话*中。

#### 编写登录功能

我们已经为第一个案例创建了登录路由的存根，现在，我们将稍微完善一下，检查输入信息与我们的数据库匹配，并使用`Flask-Login`来登录用户，如果电子邮件和密码匹配的话。

我们还将介绍一种更清晰的方式，从一个单独的 Flask 路由调用另一个。将以下行添加到`waitercaller.py`的导入部分：

```py
from flask import redirect
from flask import url_for
```

第一个函数接受一个 URL，并为一个简单重定向用户到指定 URL 的路由创建一个响应。第二个函数从一个函数名构建一个 URL。在 Flask 应用程序中，你经常会看到这两个函数一起使用，就像下面的例子一样。

在`waitercaller.py`中编写登录函数，以匹配以下代码：

```py
@app.route("/login", methods=["POST"])
def login():
   email = request.form.get("email")
   password = request.form.get("password")
   user_password = DB.get_user(email)
   if user_password and user_password == password:
      user = User(email)
      login_user(user)
      return redirect(url_for('account'))
   return home()
```

我们还需要为`request`库添加`import`。将以下行添加到`waitercaller.py`的`import`部分：

```py
from flask import request 
```

我们将用户的输入加载到`email`和`password`变量中，然后将存储的密码加载到`user_password`变量中。`if`语句很冗长，因为我们明确验证了是否返回了密码（也就是说，我们验证了用户是否存在），以及密码是否正确，尽管第二个条件暗示了第一个条件。稍后，我们将讨论在向用户提供反馈时区分这两个条件的权衡。

如果一切有效，我们将从电子邮件地址创建一个`User`对象，现在使用电子邮件地址作为 Flask 登录所需的唯一标识符。然后，我们将把我们的`User`对象传递给`Flask-Login`模块的`login_user()`函数，以便它可以处理认证操作。如果登录成功，我们将重定向用户到账户页面。由于用户现在已经登录，这将返回`"You are logged in"`字符串，而不是之前得到的`"Unauthorized"`错误。

请注意，我们将使用`url_for()`函数为我们的账户页面创建一个 URL。我们将把这个结果传递给`redirect()`函数，以便用户从`/login`路由被带到`/account`路由。这比简单地使用以下方式更可取：

```py
return account()
```

我们的意图更加明确，用户将在浏览器中看到正确的 URL（也就是说，两者都会把用户带到`/account`页面），但如果我们不使用`redirect()`函数，即使在`/account`页面上，浏览器中仍然会显示`/login`。

#### 创建`load_user`函数

如果用户已经登录，他们的浏览器将通过`Flask-Login`在我们调用`login_user`函数时给他们的 cookie 发送信息。这个 cookie 包含了我们在创建`User`对象时指定的唯一标识符的引用，即在我们的情况下是电子邮件地址。

`Flask-Login`有一个现有的函数，我们称之为`user_loader`，它将为我们处理这个问题；我们只需要将它作为我们自己的函数的装饰器，检查数据库以确保用户存在，并从我们得到的标识符创建一个`User`对象。

将以下函数添加到你的`waitercaller.py`文件中：

```py
@login_manager.user_loader
def load_user(user_id):
    user_password = DB.get_user(user_id)
    if user_password:
       return User(user_id)
```

装饰器指示`Flask-Login`这是我们要用来处理已经分配了 cookie 的用户的函数，每当一个用户访问我们的网站时，它都会把 cookie 中的`user_id`变量传递给这个函数，这个用户已经有了一个。类似于之前的操作，我们将检查用户是否在我们的数据库中（如果`user_id`无效，`user_password`将为空），如果是，我们将重新创建`User`对象。我们永远不会显式调用这个函数或使用结果，因为它只会被`Flask-Login`代码使用，但是如果我们的应用程序通过我们的`login()`函数给用户分配了一个 cookie，当用户访问网站时`Flask-Login`找不到这个`user_loader()`函数的实现，我们的应用程序将抛出一个错误。

在这一步中检查数据库似乎是不必要的，因为我们给用户一个据称是防篡改的令牌，证明他或她是一个有效的用户，但实际上是必要的，因为自用户上次登录以来数据库可能已经更新。如果我们使用户的会话令牌有效时间很长（回想一下，在我们的 Headlines 项目中，我们让 cookies 持续了一年），那么用户的帐户在分配 cookie 后可能已经被修改或删除。

### 检查登录功能

是时候尝试我们的新登录功能了！在本地启动`waitercaller.py`文件，并在 Web 浏览器中访问`localhost:5000`。在我们的模拟数据库中输入电子邮件 ID`test@example.com`和密码`123456`，然后点击登录按钮。您应该会被重定向到`http://localhost:5000/account`，并看到**您已登录**的消息。

关闭浏览器，然后重新打开，这次直接访问`localhost:5000/account`。由于我们没有告诉`Flask-Login`记住用户，您现在应该再次看到**未经授权**的错误。

由于我们应用程序的性质，我们预计大多数用户都希望保持登录状态，以便餐厅员工可以在早上简单地打开页面并立即使用功能。`Flask-Login`使这个改变非常简单。只需更改`login()`函数中的以下行：

```py
 login_user(user)
```

您的新`login()`函数现在应该是这样的：

```py
login_user(user, remember=True)
```

现在，如果您重复前面的步骤，即使重新启动浏览器，您也应该看到**您已登录**的消息，如下面的屏幕截图所示：

![检查登录功能](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_04.jpg)

现在我们可以登录用户，让我们看看如何让用户注销。

## 注销用户

`Flask-Login`提供了一个直接可用的注销功能。我们所要做的就是将其链接到一个路由上。在您的`waitercaller.py`文件中添加以下路由：

```py
@app.route("/logout")
def logout():
   logout_user()
   return redirect(url_for("home"))
```

然后，在`waitercaller.py`的导入部分添加`logout_user()`函数的`import`：

```py
from flask.ext.login import logout_user
```

请注意，在此调用中不需要将`User`对象传递给`Flask-Login`；`logout()`函数只是从用户的浏览器中删除会话 cookie。一旦用户注销，我们就可以将他们重定向回主页。

在浏览器中访问`localhost:5000/logout`，然后尝试再次访问`localhost:5000/account`。您应该会再次看到**未经授权**的错误，因为`test@example.com`用户已注销。

## 注册用户

我们可以登录用户是很好的，但目前我们只能使用硬编码到我们数据库中的模拟用户来这样做。当注册表格被填写时，我们需要能够将新用户添加到我们的数据库中。我们仍然会通过我们的模拟数据库来完成所有这些工作，因此每次应用程序重新启动时，所有用户都将丢失（它们只会保存在本地 Python 字典变量中，在应用程序终止时丢失）。

我们提到存储用户密码是一个非常糟糕的主意；因此，首先，我们将简要介绍密码哈希的工作原理以及如何更安全地管理密码。

### 使用密码进行密码管理的密码哈希

我们不想存储密码，而是想存储*从*密码派生出的东西。当用户注册并给我们一个密码时，我们将对其进行一些修改，并存储修改的结果。然后，用户下次访问我们的网站并使用密码登录时，我们可以对输入密码进行相同的修改，并验证结果是否与我们存储的匹配。

问题在于我们希望我们的修改是不可逆的；也就是说，有权访问修改后的密码的人不应该能够推断出原始密码。

输入哈希函数。这些小片段的数学魔法将字符串作为输入并返回（大）数字作为输出。相同的字符串输入将始终产生相同的输出，但几乎不可能使两个不同的输入产生相同的输出。哈希函数被称为*单向*函数，因为如果您只有输出，则无法推断输入是可以证明的。

### 注意

密码存储和管理是一个大课题，我们在这个项目中只能触及一点。有关信息安全的大多数事项的更多信息，请访问[www.owasp.org](http://www.owasp.org)。他们关于安全存储密码的全面指南可以在[`www.owasp.org/index.php/Password_Storage_Cheat_Sheet`](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet)找到。

#### Python hashlib

让我们看看如何在 Python 中使用哈希函数。在 Python shell 中运行以下命令：

```py
import hashlib
hashlib.sha512('123456').hexdigest()

```

作为输出，您应该看到哈希**ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413**，如下面的屏幕截图所示：

![Python hashlib](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_05.jpg)

十六进制字符的随机字符串是`sha512`哈希值的`'123456'`字符串，这是我们将存储在数据库中的内容。每当用户输入明文密码时，我们将通过哈希函数运行它，并验证这两个哈希是否匹配。如果攻击者或员工在数据库中看到哈希值，他们无法冒充用户，因为他们无法从哈希中推断出`'123456'`。

#### 反向哈希

实际上，这一部分的标题并不完全正确。虽然没有办法*反向*哈希并编写一个函数，该函数以前面的十六进制字符串作为输入并产生`'123456'`作为输出，但人们可能会非常坚决。黑客可能仍然尝试每种可能的输入，并通过相同的哈希函数运行它，并继续这样做，直到哈希匹配。当黑客遇到一个输入，产生的输出为**ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413**时，他已成功破解了密码。

然而，哈希函数往往需要大量的处理能力，因此通过大量输入（称为*暴力破解*）并不实际。人们还创建了所谓的彩虹表，其中包含所有常见输入的预先计算和存储在数据库中，以便可以立即找到结果。这是计算机科学中经常看到的经典*空间-时间*权衡。如果我们计算所有可能的输入的哈希值，将需要很长时间；如果我们想要预先计算每种可能的组合，以便我们可以立即查找结果，我们需要大量的存储空间。

如果您转到哈希反转网站，例如[`md5decrypt.net/en/Sha512/`](http://md5decrypt.net/en/Sha512/)，并输入您在此处注意到的确切十六进制字符串，它会告诉您解密版本为**123456**。

![反向哈希](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_09_06.jpg)

在所声称的 0.143 秒内，它实际上并没有尝试每种可能的输入组合，但它存储了以前计算哈希时的答案。这样的网站有一个包含映射和明文字符串以及它们的哈希等效项的大型数据库。

如果您对字符串进行哈希处理，例如`b⁷⁸asdflkjwe@#xx...&AFs--l`，并将生成的哈希粘贴到 md5decrypt 网站上，您会注意到该字符串对于该特定网站来说并不常见，而不是再次获得纯文本，您将看到一个类似于以下屏幕截图的屏幕：

![反向哈希

我们希望我们存储的所有密码都足够复杂，以至于在预先计算的哈希表中不存在。然而，我们的用户更有可能选择常见到已经被预先计算的密码。解决方案是在存储密码之前添加所谓的*盐*。

#### 给密码加盐

由于用户往往使用弱密码，比如 `123456`，这些密码很可能存在于预先计算的哈希表中，我们希望为我们的用户做一些好事，并在存储密码时为其添加一些随机值。这样，即使恶意攻击者能够访问存储的哈希值，也更难以获取用户的私人密码，尽管我们将存储与密码一起使用的随机值。这就是所谓的*给密码加盐*；类似于给食物加盐，我们很容易给密码加一些盐，但希望去除盐是不可能的。

总之，我们想要：

+   在注册时接受用户的明文密码

+   为这个密码添加一些随机值（盐）以加强它

+   对密码和盐的连接进行哈希处理

+   存储哈希和盐

当用户登录时，我们需要：

+   从用户那里获取明文密码

+   查找我们数据库中存储的盐，并将其添加到用户的输入中

+   对密码和盐的连接进行哈希处理

+   验证结果是否与我们之前存储的相匹配

### 在 Python 中实现安全的密码存储

为了实现上述内容，我们将创建一个非常小的 `PasswordHelper` 类，它将负责哈希处理和生成随机盐。尽管这是非常少量的代码，但当我们使用标准的 `hashlib`、`os` 和 `base64` Python 库时，将所有加密逻辑抽象到自己的类中是一个良好的实践。这样，如果我们改变了密码管理的实现方式，我们可以将大部分更改都应用到这个新类中，而不必触及主应用程序代码。

我们还需要对我们的 `login()` 函数进行一些更改，完善我们的 `registration()` 函数，并为我们的数据库辅助代码创建一个新的方法，用于向我们的模拟数据库中添加新用户。

#### 创建 PasswordHelper 类

让我们从 `PasswordHelper` 开始。在您的 `waitercaller` 目录中创建一个名为 `passwordhelper.py` 的文件，并将以下代码添加到其中：

```py
import hashlib
import os
import base64

class PasswordHelper:

   def get_hash(self, plain):
      return hashlib.sha512(plain).hexdigest()

   def get_salt(self):
      return base64.b64encode(os.urandom(20))

   def validate_password(self, plain, salt, expected):
      return self.get_hash(plain + salt) == expected
```

前两种方法用于用户首次注册时，并可以解释如下：

+   `get_hash()` 方法只是我们之前看过的 `sha512` 哈希函数的包装器。我们将使用它来创建最终存储在我们数据库中的哈希值。

+   `get_salt()` 方法使用 `os.urandom()` 生成一个密码学上安全的随机字符串。我们将把它编码为 `base64` 字符串，因为随机字符串可能包含任何字节，其中一些可能会在我们的数据库中存储时出现问题。

`validate_password()` 方法在用户登录时使用，并再次给出原始明文密码。我们将传入用户给我们的内容（`plain` 参数），他们注册时存储的盐，并验证对这两者进行哈希处理是否产生了我们存储的相同哈希值（`expected` 参数）。

#### 更新我们的数据库代码

现在我们需要为每个用户存储一个密码和盐；我们不能再使用之前的简单电子邮件和密码字典。相反，对于我们的模拟数据库，我们将使用一个字典列表，其中我们需要存储的每个信息都有一个键和值。

我们还将更新 `mockdbhelper.py` 中的代码如下：

```py
MOCK_USERS = [{"email": "test@example.com", "salt": 
 "8Fb23mMNHD5Zb8pr2qWA3PE9bH0=", "hashed":
  "1736f83698df3f8153c1fbd6ce2840f8aace4f200771a46672635374073cc876c  "f0aa6a31f780e576578f791b5555b50df46303f0c3a7f2d21f91aa1429ac22e"}]

class MockDBHelper:
    def get_user(self, email):
        user = [x for x in MOCK_USERS if x.get("email") == email]
        if user:
            return user[0]
        return None

 def add_user(self, email, salt, hashed):
MOCK_USERS.append({"email": email, "salt": salt, "hashed":hashed})
```

我们的模拟用户仍然使用密码`123456`，但潜在的攻击者不再能够通过查找彩虹表中的哈希值来破解密码。我们还创建了`add_user()`函数，该函数接受新用户的`email`、`salt`和`hashed`密码，并存储这些记录。我们的`get_user()`方法现在需要循环遍历所有模拟用户，以找出是否有任何匹配输入电子邮件地址的用户。这是低效的，但将由我们的数据库更有效地处理，并且由于我们永远不会有数百个模拟用户，所以我们不需要担心这一点。

#### 更新我们的应用程序代码

在我们的主要`waitercaller.py`文件中，我们需要为密码助手添加另一个`import`，并实例化密码助手类的全局实例，以便我们可以在`register()`和`login()`函数中使用它。我们还需要修改我们的`login()`函数以适应新的数据库模型，并完善我们的`register()`函数以执行一些验证，并调用数据库代码来添加新用户。

在`waitercaller.py`的导入部分添加以下行：

```py
from passwordhelper import PasswordHelper
```

然后，在创建`DBHelper()`对象的地方附近添加以下内容：

```py
PH = PasswordHelper()
```

现在，修改`login()`函数如下：

```py
@app.route("/login", methods=["POST"])
def login():
   email = request.form.get("email")
   password = request.form.get("password")
 stored_user = DB.get_user(email)
 if stored_user and PH.validate_password(password, stored_user['salt'], stored_user['hashed']):
      user = User(email)
      login_user(user, remember=True)
      return redirect(url_for('account'))
   return home()
```

唯一的真正变化在`if`语句中，我们现在将使用密码助手使用盐和用户提供的密码来验证密码。我们还将用户的变量名称更改为`stored_user`，因为现在这是一个字典，而不仅仅是以前的密码值。

最后，我们需要构建`register()`函数。这将使用密码和数据库助手来创建一个新的加盐和哈希密码，并将其与用户的电子邮件地址一起存储在我们的数据库中。

在`waitercaller.py`文件中添加`/register`路由和相关函数，代码如下：

```py
@app.route("/register", methods=["POST"])
def register():
   email = request.form.get("email")
   pw1 = request.form.get("password")
   pw2 = request.form.get("password2")
   if not pw1 == pw2:
      return redirect(url_for('home'))
   if DB.get_user(email):
      return redirect(url_for('home'))
   salt = PH.get_salt()
   hashed = PH.get_hash(pw1 + salt)
   DB.add_user(email, salt, hashed)
   return redirect(url_for('home'))
```

我们要求用户在注册表单上两次输入他们的密码，因为用户在注册时很容易出现输入错误，然后无法访问他们的帐户（因为他们使用了与他们打算使用的密码不同的密码）。因此，在这一步中，我们可以确认用户输入的两个密码是相同的。

我们还验证了用户是否已经存在，因为每个用户都需要使用唯一的电子邮件地址。

最后，我们生成了一个盐，从密码和盐创建了一个哈希，并将其存储在我们的数据库中。然后，我们将用户重定向回主页，测试我们的注册功能。

现在是时候再次对应用程序进行测试了。关闭浏览器并在本地重新启动应用程序。访问主页并通过选择电子邮件和密码注册一个帐户。注册后，使用刚刚注册的相同用户名和密码登录。如果一切顺利，您将看到**您已登录**消息。然后再次访问`http://localhost:5000/logout`以注销。

# 总结

在本章中，我们学习了如何使用 Bootstrap 使我们的应用程序在开箱即用时看起来很好，并根据用户的屏幕大小进行响应。我们建立了一个基本的用户帐户控制系统，我们可以注册用户，登录用户，然后再次注销用户。

我们还花了一些时间研究如何使用加密哈希函数和盐来安全存储密码。

在下一章中，我们将构建应用程序的功能，这些功能在本章开头的项目概述中讨论过。我们还将看一种更简单的方法来创建访问者将用来与我们的应用程序交互的表单。


# 第十章：在服务员呼叫项目中使用模板继承和 WTForms

在上一章中，我们创建了一个基本的用户账户系统。然而，我们只是做了一个非常简单的路由访问控制——只是简单地显示字符串“您已登录”。在本章中，我们将添加一些更多的期望功能，并允许已登录用户添加餐厅桌子，查看与这些桌子相关的 URL，并查看顾客的关注请求。我们将遇到的一个问题是希望在我们的应用程序的不同页面上重用相同的元素。您将看到如何通过使用 Jinja 的继承系统来解决这个问题，而不会出现代码重复。正如在上一章中提到的，当出现错误时，比如输入了错误的密码，我们与用户的沟通并不是很好。为了解决这个问题，我们将看一下另一个 Flask 扩展，WTForms，并看看它如何简化创建和验证表单。

在这一章中，我们将涵盖以下主题：

+   将账户和仪表板页面添加到我们的应用程序中

+   使用 bitly API 缩短 URL

+   添加处理关注请求的功能

+   通过 WTForms 添加用户反馈

# 添加账户和仪表板页面

我们想要在我们的应用程序中添加两个新页面：'仪表板'，在这里可以看到特定餐厅的所有顾客请求，以及'账户'，在这里餐厅可以管理他们的桌子并查看他们需要在桌子上提供的 URL。

我们可以简单地在我们的`templates`目录中创建两个新的`.html`文件，并从头开始编写 HTML。但很快我们会发现，我们需要从我们的主页中使用许多相同的元素（至少包括和配置 Bootstrap 的部分）。然后我们会忍不住只是复制粘贴主页的 HTML，并从那里开始处理我们的新页面。

## 介绍 Jinja 模板

复制和粘贴代码通常意味着有些地方出了问题。在应用程序代码中，这意味着您没有很好地模块化您的代码，并且需要创建一些更多的类，并可能添加一些`import`语句来包含重用的代码。使用 Jinja，我们可以遵循一个非常相似的模式，通过使用*模板继承*。我们首先将我们的主页分成两个单独的模板文件，`base.html`和`home.html`，其中包含我们想要在基本文件中重用的所有元素。然后我们可以让我们的其他三个页面（主页、账户和仪表板）都继承自*基本模板*，并且只编写在这三个页面之间有所不同的代码。

Jinja 通过使用*blocks*的概念来处理继承。每个父模板都可以有命名块，而扩展父模板的子模板可以用自己的自定义内容填充这些块。Jinja 继承系统非常强大，可以处理嵌套块和覆盖现有块。然而，我们只会浅尝其功能。我们的基本模板将包含所有可重用的代码，并包含一个名为`content`的空块和一个名为`navbar`的块。我们的三个页面将从基本模板扩展，提供它们自己版本的内容块（用于主页面内容）和导航栏。我们需要使导航栏动态化，因为页面顶部的**登录**字段只有在用户未登录时才会出现。

### 创建基本模板

在您的`templates`目录中创建一个名为`base.html`的新文件，并插入以下代码：

```py
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <title>Waiter Caller</title>

    <!-- Bootstrap core CSS -->
    <link href="../static/css/bootstrap.min.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="img/html5shiv.min.js"></script>
      <script src="img/respond.min.js"></script>
    <![endif]-->

  </head>
  <body>

    {% block navbar %}
    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/dashboard">Dashboard</a>
          <a class="navbar-brand" href="/account">Account</a>
        </div>
      </div>
    </nav>
    {% endblock %}

    {% block content %}
    {% endblock %}

    <div class="container">

      <hr>
      <footer>
        <p>&copy; A. Non 2015</p>
      </footer>
    </div>
  <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script   src="img/jquery.min.js"></script>
    <script src="img/bootstrap.min.js"></script>
  </body>
</html>
```

在上面的代码中，我们在一个文件中拥有所有的页眉和页脚代码——这些元素将在所有页面中共同存在。我们使用 Jinja 语法定义了两个块，这与我们之前看到的其他 Jinja 语句类似，即：

```py
{% block content %}
{% endblock %}
```

和

```py
{% block navbar %}
[...]
{% endblock %}
```

在这个例子中，`content`和`navbar`是我们块的名称，我们可以自由选择这些名称，而`block`和`endblock`是 Jinja 关键字，`{% %}`符号用于指示 Jinja 语句，就像之前的例子中一样。这本身就是一个完全有效的 Jinja 模板；即使内容块是空的，我们也可以直接从我们的 Flask 应用程序中呈现模板，我们会看到一个页面，它只是假装内容块不存在。

我们还可以扩展这个模板；也就是说，我们可以使用它作为父模板创建子模板。子模板可以通过再次声明来*覆盖*任何指定的块。我们将`navbar`声明为一个块，因为我们的主页将使用我们之前编写的导航栏——包括登录表单。然而，一旦登录，我们的仪表板和账户页面将具有完全相同的导航栏——这是我们在基本模板中定义的导航栏。

### 创建仪表板模板

我们的仪表板页面最终将显示所有客户的服务请求，以便服务员可以轻松地看到哪些桌子需要关注。不过，现在我们只是创建页面的大纲。在您的`templates`目录中创建一个名为`dashboard.html`的新文件，并添加以下代码：

```py
{% extends "base.html" %}

{% block content %}
    <div class="jumbotron">
      <div class="container">
        <h1>Dashboard</h1>
        <p>View all patron requests below</p>
      </div>
    </div>

    <div class="container">
      <div class="row">
        <div class="col-md-12">
          <h2>Requests</h2>
          <p>All your customers are currently satisfied - no requests</p>
        </div>    
      </div>
    </div>
{% endblock %}
```

在前面的代码片段中，最重要的一行是第一行——我们使用 Jinja 的`extends`关键字来指示这个模板应该继承另一个模板中包含的所有代码。关键字后面跟着要继承的模板的文件名，包含在引号中。

接下来，我们只需以与基本模板相同的方式创建内容块。这一次，我们不是留空，而是添加一些 HTML 来显示在我们的仪表板页面上。

### 创建账户模板

账户页面将是用户可以添加新表格、删除表格或获取现有表格的 URL 的页面。同样，由于我们还没有任何应用程序代码来表示表格，我们将只是创建页面的大纲。在您的`templates`目录中创建一个名为`account.html`的文件，并添加以下代码：

```py
{% extends "base.html" %}

{% block content %}
    <div class="jumbotron">
      <div class="container">
        <h1>Account</h1>
        <p>Manage tables and get URLs</p>
      </div>
    </div>

    <div class="container">
      <div class="row">
        <div class="col-md-12">
          <h2>Tables</h2>

        </div>    
      </div>
    </div>
{% endblock %}
```

### 创建主页模板

`home.html`模板包含了我们主页的整个特定代码，它不是基本模板的一部分。代码可以在代码包中的`templates/home_1.html`中看到，但这里没有包含，因为它太长了。看一下它，看看我们如何定义一个包含`login`表单的新`navbar`块，并覆盖了基本模板中提供的默认块。同样，它定义了内容块，替换了我们在基本模板中定义的空内容块。最终结果并没有改变——我们仍然会看到完全相同的主页，但现在代码分为`base.html`和`home.html`文件，允许我们重用它的大部分内容，用于我们之前创建的新页面。

### 添加路由代码

当访问`/account`和`/dashboard`时，我们需要我们的 Python 代码返回新的模板文件。在您的`waitercaller.py`文件中添加`dashboard()`函数，并修改账户`function()`如下：

```py
@app.route("/dashboard")
@login_required
def dashboard():
  return render_template("dashboard.html")

@app.route("/account")
@login_required
def account():
  return render_template("account.html")
```

尝试新页面！像以前一样在本地运行应用程序：

```py
python waitercaller.py

```

转到`http://localhost:5000`查看主页。使用表单登录，现在，您应该看到一个更漂亮的**账户**页面的骨架，如下图所示：

![添加路由代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_01.jpg)

在顶部的导航栏中点击**仪表板**链接，您也应该看到该页面的骨架，如下图所示：

![添加路由代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_02.jpg)

## 创建餐厅桌子

现在我们需要向我们的应用程序引入*表*的概念，并且能够在我们的数据库和应用程序代码中表示它。一个表应该具有以下属性：

+   唯一标识我们应用程序所有用户中的该表的 ID 号

+   一个用户可定义且在特定用户的表格中唯一的名称

+   一个所有者，以便我们知道表格属于哪个用户

如果我们严格遵循面向对象编程的风格，我们将创建一个`Table`类，其中包含这些属性。然后，我们还将为应用程序中的所有内容创建一堆其他类。按照这种方法，我们还将创建方法来将我们的每个对象序列化为可以存储在数据库中的内容，并创建更多的方法来*反序列化*它们，从数据库中恢复为对象。

为了简洁起见，并且因为我们的模型足够简单，我们将采取一种捷径，这肯定会冒犯一些人，简单地使用 Python 字典来表示我们大部分的对象。当我们将 MongoDB 添加到我们的应用程序时，我们将看到这些字典将很容易地写入和从数据库中读取。

### 编写餐厅表格代码

让我们简要看一下我们的表需要做什么。首先，我们的应用用户需要能够在“账户”页面上添加和删除新表格，无论是最初注册账户时还是以后需要进行更改时。其次，用户应该能够查看与每个表格相关联的 URL，以便这些 URL 可以被打印并在实际表格上提供。当添加新表格时，我们需要创建一个模拟数据库。

我们将从在“账户”页面上为用户提供一个输入框开始，他们可以在其中输入新表格的名称或编号以创建它。创建新表格时，我们将创建一个唯一的 ID 号，并使用它来创建一个新的 URL。然后，我们将使用 bitly API 来创建 URL 的缩短版本，这样我们的用户的顾客将更容易地在智能手机上输入。然后，我们将在我们的模拟数据库中存储表格名称、ID 和缩短的 URL。

#### 添加创建表单

在`account.html`模板中，在`<h2>Tables</h2>`下面直接添加以下内容：

```py
<h2>Add new table</h2>
<form class="form-inline" action="/account/createtable" method="POST">
  <input type="text" name="tablenumber" placeholder="Table number or name" class="form-control">
  <input type="submit" value="Create" class="btn btn-primary">
</form>
```

这是一个非常基本的表单，只有一个输入框用于输入新表格的名称和一个提交表单的按钮。如果您加载应用程序并导航到“账户”页面，您现在应该看到类似以下图片的东西：

![添加创建表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_03.jpg)

#### 添加创建表路由

创建表格后端并不太复杂，但有一些重要的细节需要理解。首先，我们的用户可以给表格任何他们想要的名称。对于大多数用户，这些名称可能只是从 1 开始递增的数字，以餐厅中的表格数量结束，因为这是餐厅命名表格的常见方式。因为许多餐厅经理将使用我们的应用程序，我们不能假设这些名称在所有账户中是唯一的。我们应用程序的大多数用户可能会有一个名为`1`的表格。因此，当餐厅顾客表示他或她在 1 号桌上并需要服务时，我们必须能够从潜在的许多餐厅中选择正确的 1 号桌。为了解决这个问题，我们数据库中的每个表格都将有一个唯一的 ID，我们将使用它来在 URL 中标识表格，但我们将在“账户”页面上显示用户选择的名称（例如`1`），以便我们的用户可以轻松管理他们的个人表格列表。

当我们向数据库中插入新项目时，我们将获得该项目的唯一 ID。但是，因为我们想要将 ID 作为 URL 的一部分使用，我们陷入了一种先有鸡还是先有蛋的情况，我们需要将表格插入数据库以获得 ID，但我们也需要 ID 以便在正确地将表格插入数据库之前创建 URL。

为了解决这个问题，我们必须将一个半创建的表格插入到我们的数据库中以获得 ID，然后使用 ID 创建 URL，然后更新我们刚刚创建的表格以将其与 URL 关联起来。

将以下路由添加到`waitercaller.py`文件中，以执行此操作（或者说，一旦我们在数据库代码中创建了所需的函数，它将执行此操作）：

```py
@app.route("/account/createtable", methods=["POST"])
@login_required
def account_createtable():
  tablename = request.form.get("tablenumber")
  tableid = DB.add_table(tablename, current_user.get_id())
  new_url = config.base_url + "newrequest/" + tableid
  DB.update_table(tableid, new_url)
  return redirect(url_for('account'))
```

请注意，我们将与账户页面相关的应用程序功能结构化为`子路由/account/`。我们在属于账户的路由的函数名称前加上`account_`。这有助于我们在应用程序代码中拥有更清晰的部分，随着我们添加更多路由，代码可能会变得混乱和难以维护。

我们必须将每个表与所有者关联起来，因此我们使用`FlaskLogin current_user`功能来获取当前登录用户的 ID。我们还将使用我们的`config.py`文件来定义要与表关联的基本 URL。

将以下导入添加到`waitercaller.py`中，以使用`current_user`功能并访问我们的`config`：

```py
from flask.ext.login import current_user
import config
```

将以下内容添加到`config.py`文件中（请记住，这不是 Git 存储库的一部分，因此此值仅用于本地开发）：

```py
base_url = "http://127.0.0.1:5000/"
```

上述 URL 与我们一直在使用的`localhost:5000`完全相同，因为`127.0.0.1`是一个特殊的 IP 地址，总是指向自己的机器。但是，我们将在`config`中使用 IP 地址而不是`localhost`，以保持与我们将在本章的下一节中使用的 Bitly API 的兼容性，即缩短 URL。

#### 添加创建表数据库代码

我们的表的模拟数据库代码类似于我们的用户和密码的模拟数据库代码。在`mockdbhelper.py`文件的顶部创建以下字典列表，用于存储您的表：

```py
MOCK_TABLES = [{"_id": "1", "number": "1", "owner": "test@example.com","url": "mockurl"}]
```

上述代码还创建了一个单一的表`1`，并将其分配给我们的模拟用户。请注意，`1`是`_id`键的值，对于我们的生产系统，它将是所有用户帐户中唯一的 ID 号。`number`键的值为`1`是用户选择的值，可能会在系统的不同用户之间重复。因为我们只有一个测试用户，我们将简化我们的模拟代码，并始终为唯一 ID 和用户选择的数字使用相同的值。

对于我们的模拟数据库，添加表就是简单地将代表表的新字典附加到现有的模拟表列表中。将以下方法添加到`mockdbhelper.py`文件中：

```py
def add_table(self, number, owner):
    MOCK_TABLES.append({"_id": number, "number": number, "owner":owner})
    return number
```

我们从此函数返回`number`，这是模拟 ID。在我们的测试代码中，这是输入到此函数的相同值。在我们的真实代码中，这个数字将是生成的 ID，并且将与输入不同。

最后，我们需要添加`update_table()`方法，这将允许我们将 URL 与表关联起来。将以下方法添加到`mockdbhelper.py`中：

```py
def update_table(self, _id, url):
    for table in MOCK_TABLES:
        if table.get("_id") == _id:
            table["url"] = url
            break
```

我们的应用程序代码为上述方法提供了由`add_table()`方法生成的表 ID 以及要与表关联的 URL。然后，`update_table()`方法找到正确的表并将 URL 与表关联起来。再次强调，通过列表进行循环可能看起来效率低下，而不是使用字典，但对于我们的模拟数据库代码来说，使用与我们将在下一章中编写的真实数据库代码相同的思想是很重要的。因为我们的真实数据库将存储一系列表，我们的模拟代码通过将它们存储在列表中来模拟这一点。

#### 添加查看表数据库代码

我们现在已经具备了添加新表的功能，但我们还看不到它们。我们希望在账户页面上列出所有现有的表，以便我们可以看到存在哪些表，有能力删除它们，并查看它们的 URL。

将以下方法添加到`mockdbhelper.py`中，将允许我们访问特定用户的现有表：

```py
  def get_tables(self, owner_id):
    return MOCK_TABLES
```

再次简化并让我们的测试代码忽略`owner_id`参数并返回所有表（因为我们只有一个测试用户）。但是，我们的模拟方法必须接受与我们真实方法相同的输入和输出，因为我们不希望我们的应用程序代码知道它是在运行生产代码还是测试代码。

#### 修改账户路由以传递表格数据

我们应该从数据库中获取有关表的最新信息，并在每次加载我们的账户页面时向用户显示这些表。修改`waitercaller.py`中的`/account`路由如下：

```py
@app.route("/account")
@login_required
def account():
    tables = DB.get_tables(current_user.get_id())
    return render_template("account.html", tables=tables)
```

上述方法现在从数据库获取表，并将数据传递给模板。

#### 修改模板以显示表格

我们的模板现在可以访问表格数据，所以我们只需要循环遍历每个表并显示相关信息。此时使用的术语可能会有点令人困惑，因为我们将使用 HTML 表来显示有关我们虚拟餐厅桌子的信息，即使表的用法是不相关的。HTML 表是一种显示表格数据的方式，在我们的情况下是有关餐厅桌子的数据。

在`account.html`文件中，在`<h2>tables</h2>`行下面添加以下代码：

```py
<table class="table table-striped">
  <tr>
    <th>No.</th>
    <th>URL</th>
    <th>Delete</th>
  </tr>
  {% for table in tables %}
    <form class="form-inline" action="/account/deletetable">
      <tr>
        <td>{{table.number}}</td>
        <td>{{table.url}}</td>
        <td><input type="submit" value="Delete" class="form-control"></td>
        <input type="text" name="tableid" value="{{table._id}}" hidden>
      </tr>
    </form>
  {% endfor %}
</table>
```

上述代码创建了一个简单的表格，显示了表格编号（用户选择）、URL 和每个表的删除按钮。实际上，每个表都是一个提交请求以删除特定表的表单。为了做到这一点，我们还使用了包含每个表的唯一 ID 的隐藏输入。此 ID 将随着`delete`请求一起传递，以便我们的应用程序代码知道从数据库中删除哪个表。

#### 在后端代码中添加删除表路由

在您的`waitercaller.py`文件中添加以下路由，它只接受需要删除的表 ID，然后要求数据库删除它：

```py
@app.route("/account/deletetable")
@login_required
def account_deletetable():
  tableid = request.args.get("tableid")
  DB.delete_table(tableid)
  return redirect(url_for('account'))
```

在`mockdbhelper.py`中创建以下方法，它接受一个表 ID 并删除该表：

```py
    def delete_table(self, table_id):
        for i, table in enumerate(MOCK_TABLES):
            if table.get("_id") == table_id:
                del MOCK_TABLES[i]
             break
```

与我们之前编写的更新代码类似，必须在删除之前循环遍历模拟表以找到具有正确 ID 的表。

### 测试餐厅桌子代码

我们已经在我们的应用程序中添加了相当多的代码。由于我们添加的许多不同代码部分彼此依赖，因此在编写代码时实际运行代码是困难的。但是，现在我们有了创建、查看和删除表的功能，所以我们现在可以再次测试我们的应用程序。启动应用程序，登录，并导航到**账户**页面。您应该看到单个模拟表，并能够使用创建表单添加更多表。通过添加新表和删除现有表来进行操作。当您添加表时，它们应该根据其编号获得与它们相关联的 URL（请记住，对于我们的生产应用程序，此编号将是一个长的唯一标识符，而不仅仅是我们为表选择的编号）。界面应该如下图所示：

![测试餐厅桌子代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_04.jpg)

还要通过调整浏览器窗口的大小来再次查看此页面的移动视图，使其变窄以触发布局切换。请注意，由于我们使用了 Bootstrap 的响应式布局功能，**删除**按钮会靠近 URL，**创建**按钮会移动到文本输入下方，如下图所示：

![测试餐厅桌子代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_05.jpg)

这可能看起来不如全尺寸视图那么好，但对于我们的访问者来说肯定会很有帮助，他们想要从手机上使用我们的网站，因为他们不需要担心放大或横向滚动来访问我们网站的所有功能。

# 使用 bitly API 缩短 URL

我们的用户不想输入我们目前提供的长 URL 来呼叫服务员到他们的桌子。我们现在将使用 bitly API 来创建我们已经创建的 URL 的更短的等价物。这些更短的 URL 可以更容易地输入到地址栏中（特别是在移动设备上），然后将显示为与当前更长的 URL 相关联的相应桌子。

## 介绍 Bitly

Bitly 及许多类似服务背后的原理很简单。给定任意长度的 URL，该服务返回形式为`bit.ly/XySDj72`的更短 URL。Bitly 和类似服务通常具有非常短的根域（bit.ly 是五个字母），它们只是维护一个数据库，将用户输入的长 URL 链接到它们创建的短 URL。因为它们使用大小写字母和数字的组合来创建缩短的 URL，所以即使保持 URL 的总长度非常短，也不会缺乏组合。

## 使用 bitly API

与我们使用过的其他 API 一样，bitly 是免费使用的，但在一定的限制内需要注册才能获得 API 令牌。bitly API 通过 HTTPS 访问，并返回 JSON 响应（与我们之前看到的类似）。为了与 API 进行交互，我们将使用几行 Python 代码以及`urllib2`和`json`标准库。

## 获取 bitly oauth 令牌

在撰写本文时，bitly 提供了两种验证其 API 的方式。第一种是在注册时给你的 API 令牌。第二种方式是使用 oauth 令牌。由于 bitly 正在淘汰 API 令牌，我们将使用 oauth 令牌。

第一步是在[bitly.com](http://bitly.com)上注册一个帐户并确认您的电子邮件地址。只需转到[bitly.com](http://bitly.com)，点击**注册**按钮，然后提供用户名、电子邮件地址和密码。点击他们发送到提供的电子邮件的确认链接，并登录到您的 bitly 帐户。

要注册 oauth 令牌，请转到[`bitly.com/a/oauth_apps`](https://bitly.com/a/oauth_apps)，并在提示时再次输入密码。现在您应该在屏幕上看到您的新 oauth 令牌。复制这个，因为我们将在接下来要编写的 Python 代码中需要它。它应该看起来像这样：`ad922578a7a1c6065a3bb91bd62b02e52199afdb`

## 创建 bitlyhelper 文件

按照我们在构建这个 Web 应用程序的整个过程中使用的模式，我们将创建一个`BitlyHelper`类来缩短 URL。同样，这是一个很好的做法，因为它允许我们在需要时轻松地用另一个链接缩短服务替换这个模块。在您的`waitercaller`目录中创建一个名为`bitlyhelper.py`的文件，并添加以下代码，根据需要替换您的 bitly oauth 令牌。以下代码片段中的令牌对于此 Waiter Caller 应用程序是有效的。您应该按照上述步骤获得的令牌进行替换。

```py
import urllib2
import json

TOKEN = "cc922578a7a1c6065a2aa91bc62b02e41a99afdb"
ROOT_URL = "https://api-ssl.bitly.com"
SHORTEN = "/v3/shorten?access_token={}&longUrl={}"

class BitlyHelper:

    def shorten_url(self, longurl):
        try:
            url = ROOT_URL + SHORTEN.format(TOKEN, longurl)
            response = urllib2.urlopen(url).read()
            jr = json.loads(response)
            return jr['data']['url']
        except Exception as e:
            print e
```

这个`BitlyHelper`类提供了一个方法，它接受一个长 URL 并返回一个短 URL。关于最后一个代码片段没有什么难以理解的地方，因为它只是使用了我们在使用基于 JSON 的 API 通过 HTTP 时已经看到的想法。

## 使用 bitly 模块

要使用我们的 bitly 代码，我们只需要在我们的主应用程序代码中创建一个`BitlyHelper`对象，然后在每次创建新的餐厅桌子时使用它来创建一个短 URL。修改`waitercaller.py`的全局部分如下：

```py
DB = DBHelper()
PH = PasswordHelper()
BH = BitlyHelper()

```

并将`BitlyHelper()`的导入添加到`waitercaller.py`的导入部分：

```py
from bitlyhelper import BitlyHelper
```

现在修改`createtable`方法如下：

```py
@app.route("/account/createtable", methods=["POST"])
@login_required
def account_createtable():
  tablename = request.form.get("tablenumber")
  tableid = DB.add_table(tablename, current_user.get_id())
 new_url = BH.shorten_url(config.base_url + "newrequest/" + tableid)
  DB.update_table(tableid, new_url)
  return redirect(url_for('account'))
```

启动应用程序并再次转到账户页面。创建一个新表，你会看到新表的 URL 是一个 bitly URL。如果你在浏览器中访问这个 URL，你会发现它会自动重定向到类似`http://127.0.0.1/newrequest/2`的东西（这时应该会抛出服务器错误）。

现在我们可以将短网址与每个新创建的表关联起来，我们需要在我们的应用程序中添加*请求*的概念，这样当我们的用户的顾客访问这些网址时，我们就会通知餐厅需要关注的请求。

# 添加处理关注请求的功能

我们需要处理关注请求的两个方面。第一个，正如前面讨论的，是当用户访问 URL 时创建新的请求。第二个是允许餐厅的服务员查看这些请求并将它们标记为已解决。

## 编写关注请求代码

当用户访问 URL 时，我们应该创建一个关注请求并将其存储在数据库中。这个关注请求应该包含：

+   请求发出的时间

+   发出请求的桌子

和以前一样，我们将使用 Python 字典来表示*关注请求对象*。我们需要让我们的应用程序代码创建新的关注请求，并允许这些请求被添加、检索和从数据库中删除。

### 添加关注请求路由

在`waitercaller.py`中添加以下路由：

```py
@app.route("/newrequest/<tid>")
def new_request(tid):
  DB.add_request(tid, datetime.datetime.now())
  return "Your request has been logged and a waiter will be withyou shortly"
```

这个路由匹配一个动态的表 ID。由于我们的 URL 使用全局唯一的表 ID 而不是用户选择的表号，我们不需要担心哪个餐厅拥有这张桌子。我们告诉我们的数据库创建一个新的请求，其中包含表 ID 和当前时间。然后我们向顾客显示一条消息，通知他或她请求已成功发出。请注意，这是我们的用户的顾客将使用的应用程序的唯一路由。其余的路由都只用于餐厅经理或服务员自己使用。

我们还需要 Python 的`datetime`模块来获取当前时间。在`waitercaller.py`的导入部分添加以下行：

```py
import datetime
```

### 添加关注请求数据库代码

关注请求的数据库代码使用了与我们最近添加的处理餐厅桌子的代码相同的思想。在`mockdbhelper.py`的顶部添加以下全局变量：

```py
MOCK_REQUESTS = [{"_id": "1", "table_number": "1","table_id": "1", "time": datetime.datetime.now()}]
```

前面的全局变量为表号 1（现有的模拟表）创建了一个单独的模拟关注请求，并将请求时间设置为我们启动`waitercaller`应用程序时的时间。

```py
python waitercaller.py

```

每当我们在开发过程中对我们的应用程序进行更改时，服务器都会重新启动，这时的时间也会更新为当前时间。

我们还需要在`dbconfig.py`文件的顶部添加`datetime`模块的导入：

```py
import datetime
```

对于实际的`add_request()`方法，重要的是要区分表号（用户选择的）和表 ID（在我们所有用户中全局唯一）。用于创建请求的 URL 使用了全局唯一 ID，但服务员希望在请求通知旁边看到可读的表名。因此，在添加请求时，我们找到与表 ID 相关联的表号，并将其包含在存储的请求中。

在`mockdbhelper.py`中添加以下方法：

```py
    def add_table(self, number, owner):
        MOCK_TABLES.append(
            {"_id": str(number), "number": number, "owner": owner})
        return number
```

同样，我们使用`table_id`作为表示请求的字典的唯一 ID。和以前一样，当我们添加一个真正的数据库时，我们会在这里生成一个新的请求 ID，这个 ID 不会和我们的表 ID 相同。

### 添加关注请求的获取和删除方法

在编辑数据库代码的同时，也添加以下方法：

```py
def get_requests(self, owner_id):
    return MOCK_REQUESTS

def delete_request(self, request_id):
    for i, request [...]
        if requests [...]
            del MOCK_REQUESTS[i]
            break
```

第一个方法获取特定用户的所有关注请求，将用于在我们的仪表板页面上填充所有需要服务员关注的未解决请求。第二个删除特定的请求，并将用于（同样是从仪表板页面）当服务员标记请求为已解决时。

### 注意

如果我们的 Waiter Caller 应用旨在提供更高级的功能，我们可能会向请求添加一个属性，将它们标记为已解决，而不是直接删除它们。如果我们想要提供有关有多少请求正在进行，平均需要多长时间才能解决等分析，那么保留已解决的请求将是必不可少的。对于我们简单的实现来说，已解决的请求没有进一步的用处，我们只是删除它们。

### 修改仪表板路由以使用关注请求

当餐厅经理或服务员打开应用程序的仪表板时，他们应该看到所有当前的关注请求以及请求被发出的时间（以便可以优先处理等待时间更长的顾客）。我们有请求被记录的时间，所以我们将计算自请求被发出以来经过的时间。

修改`waitercaller.py`中的`dashboard()`路由如下所示：

```py
@app.route("/dashboard")
@login_required
def dashboard():
    now = datetime.datetime.now()
    requests = DB.get_requests(current_user.get_id())
    for req in requests:
        deltaseconds = (now - req['time']).seconds
        req['wait_minutes'] = "{}.{}".format((deltaseconds/60), str(deltaseconds % 60).zfill(2))
    return render_template("dashboard.html", requests=requests)
```

修改后的`dashboard()`路由会获取属于当前登录用户的所有关注请求，使用`current_user.get_id()`和以前一样。我们为每个请求计算一个*时间差*（当前时间减去请求时间），并将其添加为我们请求列表中每个请求的属性。然后我们将更新后的列表传递到模板中。

### 修改模板代码以显示关注请求

我们希望我们的仪表板代码检查是否存在任何关注请求，然后以类似于账户页面上显示表格的方式显示每个请求。每个关注请求都应该有一个**解决**按钮，允许服务员指示他已处理该请求。

如果不存在关注请求，我们应该显示与之前在仪表板页面上显示的相同消息，指示当前所有顾客都满意。

将以下代码添加到`dashboard.html`的主体中，删除我们之前添加的占位符语句：

```py
<h2>Requests</h2>
{% if requests %}
  <table class="table table-striped">
    <tr>
      <th>No.</th>
      <th>Wait</th>
      <th>Resolve</th>
    </tr>
    {% for request in requests %}
      <tr>
        <form class="form-inline" action="/dashboard/resolve">
          <td>{{request.table_number}}</td>
          <td>{{request.wait_minutes}}</td> 
          <input type="text" name="request_id" value="{{request._id}}" hidden>
          <td><input type="submit" value="Resolve" class="btn btn-primary"></td>
        </form>
      </tr>
    {% endfor %}
  </table>
{% else %}
  <p>All your customers are currently satisfied - no requests</p>
{% endif %}
```

上述代码与我们在`accounts`模板中看到的表格代码非常相似。我们没有**删除**按钮，而是有一个**解决**按钮，类似地使用包含请求 ID 的隐藏文本输入来解决正确的关注请求。

### 添加解决请求应用程序代码

让我们添加应用程序代码来处理解决请求。类似于我们在所有账户功能中使用子路由`/account`的方式，我们在`/dashboard`中使用了前面讨论过的形式。将以下路由添加到`waitercaller.py`中：

```py
@app.route("/dashboard/resolve")
@login_required
def dashboard_resolve():
  request_id = request.args.get("request_id")
  DB.delete_request(request_id)
  return redirect(url_for('dashboard'))
```

我们已经添加了数据库代码来删除关注请求，所以在这里我们只需要使用正确的请求 ID 调用该代码，我们可以从模板中的隐藏字段中获取。

有了这个，我们应用程序的大部分功能应该是可测试的。让我们试试看！

### 测试关注请求代码

启动应用程序，测试所有新功能。首先，导航到**账户**页面，然后在新标签中导航到测试表格的 URL（或添加新表格并使用新 URL 重新测试先前的代码）。您应该看到'**您的请求已被记录，服务员将很快与您联系**'的消息，如下图所示：

![测试关注请求代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_06.jpg)

现在返回应用程序并导航到**仪表板**页面。您应该看到模拟请求以及您刚刚通过访问 URL 创建的新请求，如下截图所示：

![测试关注请求代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_07.jpg)

刷新页面并注意'**等待**'列中的值适当增加（每次刷新都会重新计算应用程序代码中的时间差）。

### 自动刷新仪表板页面

服务员不希望不断刷新仪表板以检查新请求并更新现有请求的等待时间。我们将添加一个元 HTML 标签，告诉浏览器页面应定期刷新。我们将在基本模板中添加一个通用的元标签占位符，然后在我们的`dashboard.html`模板中用刷新标签覆盖它。

在`dashboard.html`文件中，添加一个包含元 HTML 标签的 Jinja 块，位于内容块上方：

```py
{% extends "base.html" %}
{% block metarefresh %} <meta http-equiv="refresh" content="10" > {% endblock %}
{% block content %}
```

元 HTML 标签指示与我们提供的内容没有直接关系的消息。它们也可以用来添加关于页面作者的信息，或者给出搜索引擎在索引页面时可能使用的关键词列表。在我们的情况下，我们正在指定一个要求浏览器每十秒刷新一次的元标签。

在`base.html`文件中，创建一个等效的空占位符：

```py
 {% block metarefresh %} {% endblock %}
    <title>Waiter Caller</title>
```

现在再次在浏览器中打开应用程序并导航到仪表板页面。每 10 秒，您应该看到页面刷新并等待时间更新。如果您创建新的关注请求，您还将在自动刷新后看到这些请求。

# 使用 WTForms 添加用户反馈

现在我们有一个基本上功能齐全的 Web 应用程序，但在提交 Web 表单时仍未能为用户提供有用的反馈。让我们看看如何通过在用户成功或失败完成各种操作时提供反馈来使我们的应用程序更直观。

为了让我们的生活更轻松，我们将使用另一个 Flask 附加组件 WTForms，它让我们通过使用预定义模式或创建自己的模式来验证输入。我们将使用 WTForms 来实现所有我们的 Web 表单，即：

+   注册表格

+   登录表格

+   创建表格表单

## 引入 WTForms

您可能已经注意到，为新用户创建注册表格以注册我们的 Web 应用程序有点麻烦。我们不得不在模板文件中创建 HTML 表单，然后在表单提交时在我们的 Python 后端代码中获取所有输入数据。为了做到这一点，我们不得不在我们的 HTML 代码（用于`name`属性）和我们的 Python 代码（将数据从各个字段加载到变量中）中使用相同的字符串，如`email`和`password`。这些字符串`email`和`password`是有时被称为*魔术字符串*的例子。对于我们来说，创建应用程序时，这些字符串必须在两个文件中相同可能是显而易见的，但对于将来可能需要维护应用程序的另一个开发人员，甚至对于我们自己的未来，这种隐含的联系可能会变得不那么明显和更加令人困惑。

此外，我们不得不在应用程序代码中使用相当丑陋的`if`语句来确保密码匹配。事实证明，我们希望对用户输入进行更多验证，而不仅仅是检查密码是否匹配。我们可能还希望验证电子邮件地址是否看起来像电子邮件地址，密码是否不太短，以及可能还有其他验证。随着用户输入表单变得越来越长，验证规则变得更加复杂，我们可以看到，如果我们继续像迄今为止那样开发表单，我们的应用程序代码很快就会变得非常混乱。

最后，正如前面提到的，当事情出错时，我们的表单未能为用户提供有用的反馈。

WTForms 以一种简单直观的方式解决了所有这些问题。我们很快将解释如何创建代表表单的 Python 类。这些类将包含验证规则、字段类型、字段名称和反馈消息，所有这些都在同一个地方。然后我们的 Jinja 模板和应用程序代码可以使用*相同的对象*来呈现表单（当用户查看页面时）和处理输入（当用户提交表单时）。因此，使用 WTForms 可以使我们的代码更清晰，并加快开发速度。在深入了解如何使用它来改进我们的应用程序之前，我们将快速了解如何为 Flask 安装 WTForms。

请注意，WTForms 是一个通用的 Python Web 开发附加组件，可以与许多不同的 Python Web 开发框架（如 Flask、Django 等）和模板管理器（如 Jinja2、Mako 等）一起使用。我们将安装一个特定于 Flask 的扩展，该扩展将安装 WTForms 并使其易于与我们的 Flask 应用程序进行交互。

## 安装 Flask-WTF

我们需要为 Flask 安装 WTForms 附加组件。这与我们之前的扩展相同。只需运行以下命令（如往常一样，请记住在本地和 VPS 上都要运行）：

```py
pip install --user Flask-WTF

```

## 创建注册表单

现在让我们来看看如何构建表单。我们将构建一些表单，因此我们将在项目中创建一个新的 Python 文件来保存所有这些内容。在您的`waitercaller`目录中，创建一个名为`forms.py`的文件，并添加以下代码：

```py
from flask_wtf import Form
from wtforms import PasswordField
from wtforms import SubmitField
from wtforms.fields.html5 import EmailField
from wtforms import validators

class RegistrationForm(Form):
    email = EmailField('email', validators=[validators.DataRequired(), validators.Email()])
    password = PasswordField('password', validators=[validators.DataRequired(), validators.Length(min=8, message="Please choose a password of at least 8 characters")])
    password2 = PasswordField('password2', validators=[validators.DataRequired(), validators.EqualTo('password', message='Passwords must match')])
    submit = SubmitField('submit', [validators.DataRequired()])
```

类`RegistrationForm`继承自`Form`，这是我们在`flask_wtf`扩展中找到的通用表单对象。其他所有内容都直接来自`wtforms`模块（而不是来自特定于 Flask 的扩展）。表单由许多不同的字段构建 - 在我们的情况下，一个`EmailField`，两个`PasswordField`和一个`Submit`字段。所有这些都将在我们的模板中呈现为它们的 HTML 等效项。我们将每个所需字段分配给变量。

我们将使用这些变量来呈现字段并从字段中检索数据。每次创建字段时，我们传入一些参数。第一个是一个字符串参数，用于命名表单。第二个参数是验证器列表。**验证器**是一组规则，我们可以使用它们来区分有效输入和无效输入。WTForms 提供了我们需要的所有验证器，但编写自定义验证器也很容易。我们使用以下验证器：

+   `DataRequired`：这意味着如果字段为空，表单对所有字段都无效。

+   `Email`：这使用正则表达式来确保电子邮件地址由字母数字字符组成，并且@符号和句点在适当的位置。（有趣的事实：这是一个令人惊讶地复杂的问题！请参阅[`www.regular-expressions.info/email.html`](http://www.regular-expressions.info/email.html)。）

+   `EqualTo`：这确保在字段中输入的数据与输入到另一个字段中的数据相同。

+   `Length`：此验证器采用可选的最小和最大参数来定义数据应包含的字符数。我们将其设置为最小 8 个以确保我们的用户不选择非常弱的密码。

回想一下我们对后端和前端验证之间的权衡讨论，并注意这些都是后端验证方法，完成在服务器端。因此，即使用户的浏览器支持 HTML5，仍然值得添加`Email`验证器；它是一个`email`字段将阻止用户提交无效的电子邮件地址（使用前端验证检查）。

关于验证器的另一点是，我们可以为每个验证器添加一个消息参数，而不仅仅是为每个字段，每个字段可以有多个验证器。稍后我们将看到如何在特定的验证检查失败时向用户显示此消息。

重要的是要注意，您为每个表单字段选择的变量名（在我们之前创建的注册表单中为`email`，`password`和`password2`）比大多数变量名更重要，因为最终 HTML 字段的`name`和`id`属性将从变量名中获取。

## 渲染注册表单

下一步是使用我们的表单对象来呈现一个空的注册表单，当用户加载我们的主页时。为此，我们必须修改我们的应用程序代码（创建注册表单类的实例并将其传递给模板）和我们的前端代码（从类的变量中呈现我们的字段，而不是在 HTML 中硬编码它们）。

### 更新应用程序代码

在我们的`waitercaller.py`文件中，我们需要导入我们创建的表单，实例化它，并将其传递给我们的模板。

添加我们的注册表单的导入：

```py
from forms import RegistrationForm
```

现在在我们的`home()`函数中实例化表单并将表单传递给模板。最终的`home()`函数应该如下所示：

```py
@app.route("/")
def home():
  registrationform = RegistrationForm()
  return render_template("home.html", registrationform=registrationform)
```

### 更新模板代码

现在，我们的模板可以访问一个实例化的`RegistrationForm`对象，我们可以使用 Jinja 来呈现我们表单的字段。更新`home.html`中的注册表单如下：

```py
<h2>Register now</h2>
<form class="form-horizontal" action="/register" method="POST">
  {{ registrationform.csrf_token }}
    <div class="form-group">
      <div class="col-sm-9">
        {{ registrationform.email(class="form-control", placeholder="Email Address" )}}
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-9">
        {{ registrationform.password(class="form-control", placeholder="Password" )}}
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-9">
        {{ registrationform.password2(class="form-control", placeholder="Confirm Password" )}}
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-9">
        {{ registrationform.submit(class="btn btn-primary btn-block")}}
      </div>
    </div>
</form>
```

Bootstrap 样板（指定 Bootstrap 类的 div 标签）保持不变，但现在，我们不再在 HTML 中创建输入字段，而是调用属于从`home()`路由传入的`registrationform`变量的函数。我们在`RegistrationForm`类中声明的每个变量（`email`，`password`，`password2`和`submit`）都可以作为函数使用，我们可以将额外的 HTML 属性作为参数传递给这些函数。`name`和`id`属性将根据我们在编写表单时提供的变量名自动设置，我们还可以通过在这里传递它们来添加其他属性，例如`class`和`placeholder`。与以前一样，我们使用“`form-control`”作为输入的类，并指定“`placeholder`”值以提示用户输入信息。

我们还在新代码的开头呈现了`csrf_token`字段。这是 WTForms 提供的一个非常有用的安全默认值。其中一个更常见的 Web 应用程序漏洞称为**跨站请求伪造**（**CSRF**）。虽然对这种漏洞的详细描述超出了本书的范围，但简而言之，它利用了 cookie 是在浏览器级别而不是在网页级别实现的事实。因为 cookie 用于身份验证，如果您登录到一个容易受到 CSRF 攻击的站点，然后在新标签页中导航到一个可以利用 CSRF 漏洞的恶意站点，那么恶意站点可以代表您在易受攻击的站点上执行操作。这是通过发送合法的 cookie（您在登录到易受攻击的站点时创建的）以及需要身份验证的操作来实现的。在最坏的情况下，易受攻击的站点是您的在线银行，而恶意站点会利用 CSRF 漏洞代表您执行财务交易，而您并不知情。CSRF 令牌通过向每个表单添加一个隐藏字段，其中包含一组加密安全的随机生成的字符，来减轻这种漏洞。因为恶意站点无法访问这个隐藏字段（即使它可以访问我们的 cookie），我们知道包含这些字符的 POST 请求来自我们的站点，而不是来自恶意的第三方站点。如果您对这种级别的 Web 应用程序安全感兴趣，请在**开放 Web 应用程序安全项目**（**OWASP**）网站上阅读有关 CSRF 漏洞的更多信息（[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)））。无论如何，您应该始终在所有表单中包含 CSRF 字段，事实上，如果您省略它，验证步骤将失败。

### 测试新表单

因为我们在表单中使用了与之前相同的 Id 和 name 属性，所以当表单提交时处理数据的应用程序代码仍然有效。因此，启动应用程序，确保在这一点上一切仍然正常工作。如果一切顺利，应用程序的主页将与我们上次测试应用程序时看到的完全相同。您还可以使用浏览器的“查看源代码”功能来检查各种表单字段是否按预期转换为各种 HTML 输入类型。

### 在我们的应用程序代码中使用 WTForms

下一步是更新我们的应用程序代码，使用 WTForms 来捕获通过表单输入的数据。现在，我们不必记住使用了哪些“name”属性，而是可以简单地实例化一个新的`RegistrationForm`对象，并从后端接收的 post 数据填充它。我们还可以轻松运行所有的验证规则，并获得每个字段的错误列表。

在`waitercaller.py`中，修改`register()`函数如下：

```py
@app.route("/register", methods=["POST"])
def register():
  form = RegistrationForm(request.form)
  if form.validate():
    if DB.get_user(form.email.data):
      form.email.errors.append("Email address already registered")
      return render_template('home.html', registrationform=form)
    salt = PH.get_salt()
    hashed = PH.get_hash(form.password2.data + salt)
    DB.add_user(form.email.data, salt, hashed)
    return redirect(url_for("home"))
  return render_template("home.html", registrationform=form)
```

在上述代码中，第一个更改是函数的第一行。我们实例化了一个新的`RegistrationForm`，并通过传入`request.form`对象来填充它，以前我们是从中逐个提取每个字段的。如前所述，现在我们不必硬编码字段名称了！相反，我们可以通过表单属性访问用户的输入数据，比如`form.email.data`。

第二行也是一个重大变化。我们可以调用`form.validate()`来运行所有的验证规则，只有当所有规则通过时它才会返回`True`，否则它将填充表单对象的所有相关失败消息。因此，函数的最后一行只有在有验证错误时才会被调用。在这种情况下，我们现在重新渲染我们的主页模板，传递一个新的表单副本（现在有一个指向错误的引用。我们将看到如何在下一步中显示这些错误）。

如果在我们的数据库中找到电子邮件地址，我们现在会向电子邮件字段的错误消息中追加一个错误消息，并重新渲染模板以将此错误传递回前端。

请注意，以前，我们的三个返回选项都只是简单地重定向到主页，使用了 Flask 的`redirect()`函数。现在我们已经用`render_template()`调用替换了它们所有，因为我们需要将新的表单（带有添加的错误消息）传递到前端。

### 向用户显示错误

新注册表单的最后一步是向用户显示任何错误，以便用户可以修复它们并重新提交表单。为此，我们将在我们的模板中添加一些 Jinja `if`语句，检查表单对象中是否存在任何错误，并在存在时显示它们。然后我们将添加一些 CSS 使这些错误显示为红色。最后，我们将看看如果我们有更多和更大的表单，我们如何更简洁地完成所有这些（如果我们有更多和更大的表单，我们肯定会希望如此）。

#### 在我们的模板中显示错误

要显示错误，我们只需要在每个输入字段上方添加一个`if`语句，检查是否有任何错误要显示在该字段上（记住 WTForms 在我们运行`validate()`方法时会自动填充表单对象的错误列表）。如果我们发现要显示在该字段上的错误，我们需要循环遍历所有错误并显示每一个。虽然在我们的情况下，每个字段只能有一个错误，但请记住我们可以为每个字段添加多个验证器，因此每个字段可能有多个错误。我们不希望用户修复一个错误并重新提交，然后发现仍然有其他错误，而是希望用户在一次提交表单后就被告知所有错误。

修改`home.html`中的注册表单如下：

```py
<div class="form-group">
  <div class="col-sm-9">
 {% if registrationform.email.errors %}
 <ul class="errors">{% for error in registrationform.email.errors %}<li>{{ error }}</li>{% endfor %}</ul>
 {% endif %}
    {{ registrationform.email(class="form-control", placeholder="Email Address" )}}
  </div>
</div>
<div class="form-group">
  <div class="col-sm-9">
 {% if registrationform.password.errors %}
 <ul class="errors">{% for error in registrationform.password.errors %}<li>{{ error }}</li>{% endfor %}</ul>
 {% endif %}
    {{ registrationform.password(class="form-control", placeholder="Password" )}}
  </div>
</div>
<div class="form-group">
  <div class="col-sm-9">
 {% if registrationform.password2.errors %}
 <ul class="errors">{% for error in registrationform.password2.errors %}<li>{{ error }}</li>{% endfor %}</ul>
 {% endif %}
    {{ registrationform.password2(class="form-control", placeholder="Confirm Password" )}}
  </div>
</div>
```

请注意，我们通过构建列表（在`<ul>`标签内），并将这些列表分配给`errors`类属性来显示我们的错误。我们还没有任何 CSS 代码来定义错误列表的外观，所以让我们快速解决这个问题。

#### 为错误添加 CSS

错误的 CSS 代码是我们在项目中将使用的唯一自定义 CSS 代码（我们的其余 CSS 都是使用 Bootstrap 免费提供的）。因此，将我们的 CSS 直接添加到`base.html`模板文件中是可以的（我们将在其他模板中也使用它），而不是创建一个新的外部 CSS 文件或编辑 Bootstrap 文件。

如果您感兴趣，请查看`static/css`目录中的`bootstrap.min.css`文件，并注意它非常难以阅读和修改（它全部都在一行中！）。这是为了使页面加载更快——每个空格和换行符都会使文件变得稍微更大，这意味着我们的用户的浏览器需要更长时间来下载显示网页所需的 CSS 文件。这就是为什么大型 CSS 和 JavaScript 库（如 Bootstrap）都带有*minified*版本（这就是`bootstrap.min.css`中的'min'代表的含义）。如果我们想要将新的 CSS 代码添加到 Bootstrap 文件中，我们可能会将其添加到非 minified 版本中，然后重新 minify 它以创建我们在生产中使用的 minified 版本。

在`base.html`文件的`<head>`标签之间添加以下样式：

```py
<style type="text/css">
  ul.errors {
    list-style-type: none;
    padding: 0;
    color: red;
  }
</style>
```

上述样式代码中的第一行意味着它只适用于具有错误类的`<ul>`元素（即我们刚刚添加到主页的反馈消息）。接下来的三行删除了默认使用的列表项目符号，删除了默认使用的缩进，并将字体颜色设置为红色。

### 测试最终的注册表单

我们的注册表现在已经完成。现在它使用了 WTForms，因此更清洁，更容易维护，我们不必依赖开发人员知道 HTML 的`name`属性必须与 Python 代码匹配。让我们来看看确保一切仍然正常工作，并且我们的新错误消息在我们期望它们显示时显示，并且在我们不希望它们显示时不显示。

再次运行应用程序，尝试注册一个新帐户。尝试各种错误组合，例如使用已注册的电子邮件地址（请记住，我们的测试数据库在每次重新启动应用程序时都会被清除），使用太短的密码，使用两个`password`字段的不匹配字符串，或使用无效的电子邮件地址。如果一切按计划进行，您的带有错误的表单应该看起来与下面的表单类似：

![测试最终的注册表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_08.jpg)

关于最后一张图片有几件有趣的事情需要注意。首先，请注意 HTML5 输入框将电子邮件地址`g@1`视为有效（前端验证），但`Email()`验证器不认为它是有效的（后端验证）。这就是为什么我可以提交表单，即使我使用支持 HTML5 电子邮件字段的浏览器，只有在数据传输到后端后才被告知电子邮件地址无效。其次，请注意在提交表单后，电子邮件地址会自动重新填充，而密码字段现在为空。这是大多数浏览器的有用默认设置。我们可能希望在第二次提交类似的信息时，修复错误后，但出于安全原因，我们总是希望尽快摆脱密码。

请注意上图中的“**无效的电子邮件地址**”消息。在我们的`forms.py`文件中，我们只为密码太短的情况指定了错误消息，但 WTForms 为其内置验证器提供了默认消息。同样，如果您将密码字段留空，您将看到消息“**此字段为必填项**”——这是另一个有用的默认消息，我们不需要编写。

这是表单验证和用户反馈的大部分工作。现在你已经对所有东西的工作原理有了很好的概念，我们将快速地再次概述一下：

+   在用户注册成功时显示反馈（目前，我们似乎只确认失败，但用户会想知道如果一切顺利地注册了一个帐户）。

+   将我们的登录表单移动到 WTForms，并在用户登录失败时添加反馈。

+   将我们的“新表格”表单移动到 WTForms，并在必要时添加反馈。

### 添加成功的注册通知

通常，我们会在成功注册后向用户显示一个新页面，感谢他们注册并告知他们一切都成功了（如果我们是为生产环境编写此应用程序，而不是将其用作教育项目，我们将在下一章中列出我们可以改进的更完整的事项列表）。为了使我们的应用程序尽可能少地使用页面，并防止本书变得太长，我们将向用户显示一个 JavaScript 弹出框。通常，在创建用户界面时，我们希望尽可能避免使用弹出框，因为用户会觉得它们很烦人。然而，有时是必要的，所以在这里使用一个将有助于使我们的应用程序简单，并给我们一个机会学习更多 JavaScript。

JavaScript 是基于事件的。这意味着我们可以编写由用户操作（如鼠标点击）或其他事件（如`onload`事件，当特定资源在用户的浏览器中加载时触发）触发的代码。在我们的犯罪地图项目中，我们曾经使用它在`<body>`标签加载后初始化 JavaScript Google 地图小部件。现在我们将做类似的事情，但使用它来显示 JavaScript 警报框。我们还将使我们的消息动态化，并从后端代码传递到前端。

#### 从应用程序代码传递消息

这方面的后端更改很容易。只需将`register()`函数更改为在处理所有输入数据时传递适当的消息。在`waitercaller.py`中，更新`register()`函数如下：

```py
hashed = PH.get_hash(form.password2.data + salt)
DB.add_user(form.email.data, salt, hashed)
return render_template("home.html", registrationform=form, onloadmessage="Registration successful. Please log in.")
return render_template("home.html", registrationform=form)
```

#### 在模板代码中使用消息

更改在我们的模板中实现起来稍微棘手，因为我们实际上没有访问`<body>`标签（我们希望在其中指定 JavaScript 警报）在我们的`home.html`模板中。相反，我们的`<body>`是在我们的`base.html`骨架模板中定义的，所有其他模板都继承自它。

要仅在我们的`home.html`模板中修改`<body>`标签，我们需要使`<body>`标签出现在可继承的 Jinja 块内，类似于我们的内容块。为此，我们需要对我们的`base.html`模板和我们的`home.html`模板进行更改。

在`base.html`中，当创建`<body>`标签时进行以下更改：

```py
  </head>
 {% block bodytag %}
  <body>
 {% endblock %}

```

现在`<body>`标签可以被子模板覆盖，因为它出现在一个可配置的块内。在`home.html`中，如果指定了警报消息，我们将在第一行后直接覆盖`<body>`块。请记住，如果没有指定此消息，`home.html`模板将简单地继承`base.html`模板的默认`<body>`标签。在`home.html`中，在第一行后直接添加以下代码：

```py
{% block bodytag %}
  <body {% if onloadmessage %} onload="alert('{{onloadmessage}}');" {% endif %}>
{% endblock %}
```

唯一稍微棘手的部分是匹配`onload`属性中的所有引号和括号。整个`alert`函数（我们要运行的 JavaScript）应该出现在双引号内。`alert`函数内的字符串（实际显示给用户的消息）应该在单引号内。最后，`onloadmessage`变量应该在双括号内，这样我们可以得到变量的内容而不是变量名的字符串。

现在，在成功注册后，用户将看到一个确认一切顺利进行并且可以登录的警报，如下图所示。最好添加一个新页面，以便向用户正确地通知成功注册，但为了保持我们的应用程序简单（因此我们可以引入通常有用的 onload 功能），我们选择了一种稍微混乱的通信方式。

![在模板代码中使用消息](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_09.jpg)

## 修改登录表单

将登录表单移动到 WTForms 所需的更改与我们为注册表单所做的更改非常相似，因此我们将提供最少讨论的代码。如果您不确定在哪里插入代码或进行更改，请参考代码包。

### 在应用程序代码中创建新的 LoginForm

在`forms.py`中，添加`LoginForm`类：

```py
class LoginForm(Form):
    loginemail = EmailField('email', validators=[validators.DataRequired(), validators.Email()])
    loginpassword = PasswordField('password', validators=[validators.DataRequired(message="Password field is required")])
    submit = SubmitField('submit', [validators.DataRequired()])
```

在这里，我们为密码字段的`DataRequired`验证器指定了自定义消息，因为错误消息与注册表单的字段不会像注册表单那样对齐。我们还使用变量名`loginemail`和`loginpassword`，因为这些将成为 HTML 元素的`id`和`name`属性，最好不要被同一页上注册表单中的`login`和`password`字段覆盖。

在`waitercaller.py`中，添加登录表单的导入：

```py
from forms import LoginForm
```

并将`login()`函数重写如下：

```py
@app.route("/login", methods=["POST"])
def login():
    form = LoginForm(request.form)
    if form.validate():
        stored_user = DB.get_user(form.loginemail.data)
        if stored_user and PH.validate_password(form.loginpassword.data, stored_user['salt'], stored_user['hashed']):
            user = User(form.loginemail.data)
            login_user(user, remember=True)
            return redirect(url_for('account'))
        form.loginemail.errors.append("Email or password invalid")
    return render_template("home.html", loginform=form, registrationform=RegistrationForm())
```

“**电子邮件或密码无效**”错误似乎相当模糊，可能需要更具体。用户可能会发现知道错误所在很有帮助，因为许多人使用许多不同的电子邮件地址和不同的密码。因此，知道您作为用户是输入了错误的电子邮件并需要尝试记住您注册的电子邮件地址，还是您输入了正确的电子邮件地址但是错误地记住了您的纪念日或出生日期或您用来记住密码的任何助记符，这将是方便的。然而，这种便利性又会带来另一个安全问题。如果用户输入了正确的电子邮件地址但是错误的密码，我们显示“**无效密码**”，这将允许恶意攻击者对我们的网站尝试大量的电子邮件地址，并慢慢建立属于我们用户的电子邮件地址列表。攻击者随后可以利用这些用户是我们的客户的知识，对这些用户进行网络钓鱼攻击。这是另一个案例，显示了开发人员必须不断警惕他们可能允许攻击者推断出的信息，即使这些信息并不是直接提供的。

我们需要进行的最后一个后端更改是在每次呈现`home.html`模板时初始化并传递一个新的`LoginForm`对象。必须进行以下更改：

+   一旦在`home()`函数中

+   在`register()`函数中三次

将`home()`函数更改为如下所示：

```py
@app.route("/")
def home():
  return render_template("home.html", loginform=LoginForm(), registrationform=RegistrationForm())
```

将`register()`函数的最后两行更改为：

```py
  return render_template("home.html", loginform=LoginForm(), registrationform=form, onloadmessage="Registration successful. Please log in.")
  return render_template("home.html", loginform=LoginForm(), registrationform=form)
```

并且在`register()`函数中间的`return`语句为：

```py
  return render_template("home.html", loginform=LoginForm(), registrationform=form)
```

### 在模板中使用新的 LoginForm

对于模板更改，`home.html`现在应该使用以下`login`表单：

```py
<form class="navbar-form navbar-right" action="/login" method="POST">
  {% if loginform.errors %}
    <ul class="errors">
      {% for field_name, field_errors in loginform.errors|dictsort if field_errors %}
        {% for error in field_errors %}
          <li>{{ error }}</li>
        {% endfor %}
      {% endfor %}
    </ul>
  {% endif %}
  {{ loginform.csrf_token}}
  <div class="form-group">
    {{ loginform.email(class="form-control", placeholder="Email Address")}}
  </div>
  <div class="form-group">
    {{ loginform.password(class="form-control", placeholder="Password")}}
  </div>
  <div class="form-group">
    {{ loginform.submit(value="Sign in", class="btn btn-success")}}
  </div>
</form>
```

与我们为注册表单所做的方式不同，我们不会在每个字段上方显示错误，而是只会在登录表单上方显示所有错误。为此，我们可以使用`loginform.errors`属性，它是每个字段到其错误列表的映射字典。因此，错误显示代码稍微更冗长，因为它必须循环遍历此字典的所有键和值，并且我们使用`convenient |dictsort` Jinja 标记在显示错误之前对字典进行排序。

## 修改创建表单

我们需要进行的最后一个表单更改是创建表单表单，当已登录用户向其帐户添加新的餐厅桌子时。要添加到`forms.py`的新表单如下所示：

```py
class CreateTableForm(Form):
  tablenumber = TextField('tablenumber', validators=[validators.DataRequired()])
  submit = SubmitField('createtablesubmit', validators=[validators.DataRequired()])
```

这也需要在`forms.py`中进行新的导入：

```py
from wtforms import TextField
```

在`waitercaller.py`中，我们需要导入新的表单：

```py
from forms import CreateTableForm
```

更新`account_createtable()`函数为：

```py
@app.route("/account/createtable", methods=["POST"])
@login_required
def account_createtable():
  form = CreateTableForm(request.form)
  if form.validate():
    tableid = DB.add_table(form.tablenumber.data, current_user.get_id())
    new_url = BH.shorten_url(config.base_url + "newrequest/" + tableid)
    DB.update_table(tableid, new_url)
    return redirect(url_for('account'))

  return render_template("account.html", createtableform=form, tables=DB.get_tables(current_user.get_id()))
```

`account()`路由变为：

```py
@app.route("/account")
@login_required
def account():
    tables = DB.get_tables(current_user.get_id())
    return render_template("account.html", createtableform=CreateTableForm(), tables=tables)
```

最后，`account.html`模板中的表单应该更改为：

```py
<form class="form-inline" action="/account/createtable" method="POST">
  <div class="form-group">
    {% if createtableform.tablenumber.errors %}
      <ul class="errors"> 
        {% for error in createtableform.tablenumber.errors %}
          <li>{{error}}</li> 
        {% endfor %} 
      </ul> 
    {% endif %}
    {{ createtableform.csrf_token}}
    {{ createtableform.tablenumber(class="form-control", placeholder="Table number or name")}}
    {{ createtableform.submit(value="Create", class="btn btn-primary") }}
  </div>
</form>
```

目前，如果用户将字段留空并点击**创建**按钮，我们在`创建表格`表单上只能显示一个错误，即“**此字段为必填项**”，如下截图所示：

![修改创建表格表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_10_10.jpg)

考虑到这一点，可以讨论的是 for 循环是否应该循环遍历所有错误消息。一方面，过度“未来证明”是不好的，因为你会留下一个包含大量不必要且过于复杂的代码的代码库。另一方面，我们可能会向 WTForm 添加更多的错误消息（例如，如果用户尝试使用已经存在的数字创建表），因此，可以说值得添加 for 循环。

我们还没有将 WTForms 转换为的最后一个表单是`删除表格`表单。由于这只是一个单独的**提交**按钮，因此留作练习（将此表单移至 WTForms 仍然是一个值得的收获）。

# 总结

我们完善了应用程序的功能，现在它更加强大。我们添加了**仪表板**和**账户**页面，并编写了处理我们需求的所有应用程序代码、数据库代码和前端代码。

我们研究了 Jinja 模板作为避免重复前端代码的一种方法，还学习了如何使用 bitly API 来缩短链接。

然后我们添加了 WTForms，并看到这如何使我们的用户反馈更容易，我们的表单更容易验证，我们的 Web 应用程序更安全。我们的用户现在可以随时了解他们的注册、登录和应用程序的使用情况。

在下一章中，我们将为我们的代码添加一个真正的数据库，然后进行一些最后的润色。
