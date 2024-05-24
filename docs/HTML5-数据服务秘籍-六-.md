# HTML5 数据服务秘籍（六）

> 原文：[`zh.annas-archive.org/md5/1753B09CD35CEC6FE2CC3F9B8DA85828`](https://zh.annas-archive.org/md5/1753B09CD35CEC6FE2CC3F9B8DA85828)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：数据存储

本章涵盖以下配方：

+   Data URI

+   会话和本地存储

+   从文件中读取数据

+   使用 IndexedDB

+   存储的限制以及如何请求更多

+   操作浏览器历史记录

# 介绍

当我们谈论存储时，大多数开发人员会考虑将数据存储在服务器上的某个数据库中。HTML5 确实在可以传递和保存到客户端方面取得了长足的进步。无论是用于临时使用、缓存，还是完全离线使用整个应用程序，客户端存储正在变得越来越普遍。

所有这些伟大的功能使我们能够在客户端存储数据，从而使应用程序变得更快、更易用和更可达。即使在基于云的解决方案中，我们仍然需要一些本地数据，这将使用户体验更好。

本章涵盖了一些与 HTML5 相关的特性，涉及数据存储。

# Data URI

我们已经在本书中的多个场合使用了 Data **URI**（**统一资源标识符**），但从未详细介绍过我们可以用它做什么，以及有什么限制。Data URI 通常被称为 Data **URL**（**统一资源定位符**），尽管从技术上讲，它们实际上并没有从远程站点定位任何内容。

在这个例子中，我们将使用不同的媒体类型并检查大小约束。

## 准备工作

对于这个例子，我们只需要浏览器和一些样本文本文件。这些文件可以作为示例文件中的`files`文件夹的一部分下载。

## 如何做...

为了查看一些可用的选项，我们将创建一个简单的 HTML 文件，其中包含几种不同的使用场景：

1.  `head`部分将包括`example.css`文件：

```html
<head>
<title>Data URI example</title>
<link rel="stylesheet" type="text/css" href="example.css">
</head>
```

1.  在`body`部分，我们添加一个`div`元素，用作 CSS 图像 Data URI 的容器：

```html
<div id="someImage">
CSS image
</div>
```

1.  通过使用 Data URI，我们可以创建一个简单的编辑器，通过点击链接打开：

```html
<a href="data:text/html,<body contenteditable>write here">open editor</a>
```

1.  base64 是可选的，可以使用字符集：

```html
<a href="data:text/plain;charset=utf-8,програмерите%20ќе%20го%20населат%20светот">this is some UTF-8 text </a>
```

1.  Data URI 可以是原始 SVG：

```html
<p>Image tag </p>
<imgsrc='data:image/svg+xml,<svg version="1.1"><circle cx="100" cy="50" r="40" stroke="black" stroke-width="1" fill="red" /></svg>' />
```

1.  使用 Data URI 的伴随 CSS 代码用于表示`background-image`：

```html
img {
  width: 300px;
  height: 110px;
}

#someImage {
  background-image : url('data:image/svg+xml,<svg version="1.1"><path d="M 100,100 l150,0a150,150 0 0,0 -37,-97 z" fill="green" stroke="black" stroke-width="2" stroke-linejoin="round" /></svg>');
}
```

这将显示两个图像和链接到简单编辑器和一个小文本文件：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_11_01.jpg)

## 它是如何工作的...

一个常见的误解是 Data URI 只能用来表示图像。正如我们在例子中看到的，这并不是这样。严格来说，Data URI 不是 HTML5 的特性，而是在 RFC-2397（[`tools.ietf.org/html/rfc2397`](http://tools.ietf.org/html/rfc2397)）中包含的，1998 年指定，最初在 1995 年提出了这个想法。其背后的想法是直接内联嵌入数据。URI 形式被指定为：

```html
data:[<mediatype>][;base64],<data>
```

`mediatype`属性是 Internet 媒体类型，或者它的旧名称是 MIME。如果我们不指定它，它默认为`text/plain;charset=US-ASCII`。

除了酷和不同之外，我们为什么要使用 Data URI？

一个很好的理由是从当前显示的文档中派生数据。例如，我们可以从`canvas`元素创建图像，或者从当前表格生成 CSV 文件。

另一个原因是网页加载速度。这是矛盾的，因为 Data URI 通常是 base64 编码的，这会增加文档的大小到 1/3。加快速度的原则是减少请求的数量。这对于传输应该小于几千字节的小文件是有意义的，否则，不再发出另一个请求的收益很小，如果有的话。这种方法的另一个问题是，我们正在失去单独资源的缓存。否则将被单独缓存的文件，现在具有与嵌入它的文档相同的属性。如果该文档经常更改，则嵌入的数据将每次重新加载。

其他用例是对各种资源有限制的环境。电子邮件就是这种情况的一个例子，在这种情况下，为了实现单一文档体验而不必将图像作为附件，可以使用 Data URI。

## 还有更多...

在一些数据 URI 的应用中，安全性可能是一个问题，但如果大多数浏览器中的客户端应用程序遵循规范，那么只有允许的`mediatype`数据将被处理。

HTML5 中的属性有大小限制。HTML 4 有`ATTSPLEN`限制，其中指定属性的最大长度为`65536`个字符。HTML5 不是这种情况，目前每个浏览器版本都有不同的状态。对于 Firefox 3.x，它是 600 KB，对于 Chrome 19，它是 2 MB，IE 8 的限制是 32 KB。可以肯定地说，这只对较小的资源有意义。

# 会话和本地存储

Cookie 是保存应用程序状态的常用方式，可能是一些选中的复选框或某种临时数据，例如，向导应用程序中的当前流程，甚至是会话标识符。

这是一个经过验证的方法已经有一段时间了，但有一些使用情况是不舒服创建 Cookie 并且它们会施加一定的限制和开销，这是可以避免的。

会话和本地存储解决了一些 Cookie 的问题，并且使数据在客户端上的简单存储成为可能。在这个示例中，我们将创建一个简单的表单，利用 HTML5 存储 API。

## 准备工作

在这个示例中，我们将使用可以从`images`文件夹中检索的几个图像，或者您可以使用自己的选择。此外，由于我们将使用来自 JSON 对象的 REST API 的模拟响应，我们需要启动一个本地 HTTP 服务器来提供我们的静态文件。

## 如何做到这一点...

我们可以先创建一个表单，其中包含狗的选择和留下评论的区域。当我们在表单中点击一个按钮时，将显示所选狗的图像。除此之外，我们还将有一个输出字段，用于显示当前用户的访问次数：

1.  我们在`head`部分链接一个简单的 CSS 类：

```html
<meta charset="utf-8">
<title>Session and storage</title>
<link rel="stylesheet" type="text/css" href="example.css" />
```

1.  表单将包含以下单选按钮和文本区域：

```html
<form id="dogPicker">
<fieldset>
<legend>Pick a dog</legend>
<div id="imageList"></div>
<p>The best is:</p>
<p>
<input id="dog1" type="radio" name="dog" value="dog1" />
<label for="dog1">small dog</label>

<input id="dog2" type="radio" name="dog" value="dog2" />
<label for="dog2">doggy</label>

<input id="dog3" type="radio" name="dog" value="dog3" />
<label for="dog3">other dog</label>
</p>
</fieldset>

<label for="comment">Leave a comment</label>
<textarea id="comment" name="comment" ></textarea>
<button id="send" type="button">Pick</button>
</form>
```

1.  我们添加一个访问次数的计数器如下：

```html
<p>
      You have opened this page <output id="counter">0</output> times
</p>
```

1.  还有一个简单的`div`元素作为所选狗图片的占位符和对 jQuery 的依赖，以及包括我们稍后将编写的`example.js`文件：

```html
<div id="selectedImage"></div>
<script src="img/jquery.min.js"></script>
<script src="img/example.js" ></script>
```

1.  对于`example.js`文件，我们创建一个函数，将在点击按钮时将评论存储在会话中。如果数据不可用，将对`"dogs.json"`变量进行请求：

```html
$(function() {
  $('#send').click(function() {
vardogId = $("#dogPicker :radio:checked").val();
var comment = $('#comment').val();
    //different ways to set data
sessionStorage.comment = comment;
    // if no data available do AJAX call
    if (localStorage.dogData) {
showSelectedImage(dogId);
    } else {
      $.ajax({
url: "dogs.json",
      }).done(function(data){
localStorage.dogData = JSON.stringify(data);
showSelectedImage(dogId);
      });
    }
  });
```

### 提示

使用`#dogPicker :radio:checked`，我们选择`dogPicker`ID 的元素的所有选中输入`radio`子元素。

1.  由于评论的数据存储在会话中，点击后我们可以有一种加载它的方式，以备下次使用：

```html
  if (sessionStorage.comment) {
    $('#comment').val(sessionStorage.comment);
  }
```

1.  但是使用`localStorage`，我们可以递增`viewCount`变量，或者首次初始化它：

```html
  if (localStorage.viewCount) {
localStorage.viewCount++;
    $('#counter').val(localStorage.viewCount);
  } else {
localStorage.viewCount = 1;
  }
```

1.  `showSelectedImages`方法遍历每个狗对象，在我们的`localStorage`列表中创建一个带有所选文件的图像元素：

```html
 function showSelectedImage(dogId){
vardogList = JSON.parse(localStorage.dogData);
vardogFile;
    $.each(dogList.dogs, function(i,e){
      if(e.id === dogId){
dogFile = e.file;
      };
    });
      $('#selectedImage').html("<imgsrc='images/" + dogFile + "'></img>");
  }
```

如果我们选择一个单选按钮并单击它，狗的图像应该显示出来，如果我们尝试重新加载缓存，那么（*Ctrl* + *F5*）在大多数浏览器中，评论数据仍然会保留。如果我们在另一个标签中打开相同的 URL，那么评论就不应该存在，这意味着会话与单个浏览器窗口或标签相关联。另一方面，计数器应该每次递增，而且不会为`dogs.json`文件执行额外的请求。

## 它是如何工作的...

`sessionStorage`和`localStorage`共享通用的`Storage`接口，并且它们被定义为[`www.w3.org/TR/webstorage/`](http://www.w3.org/TR/webstorage/)的一部分。我们可以使用点表示法来读取或写入存储，例如`storage.key = someValue`和`someValue = storage.key`。更长的形式是使用方法调用访问数据，`storage.setItem(key, value)`和`storage.getItem(key)`。

这里对键和值的限制是它们必须是“字符串”。在我们的例子中，我们需要存储 JSON，所以为了使其与值兼容，我们使用了`JSON.stringify`和`JSON.parse`。还有一个方法`storage.removeItem(key)`来删除一个项目，或者用`storage.clear()`来清除整个存储。

`sessionStorage`是一个用于存储在浏览器会话期间持续存在的信息的对象，这就是名称的由来。即使重新加载后信息仍然保留，使其成为会话 cookie 的强大替代品。存储的项目的有效上下文是当前网站域，在当前打开的选项卡的会话期间。例如，如果我们在域[`example.com/1.html`](http://example.com/1.html)上存储一个项目，它将在[`example.com/2.html`](http://example.com/2.html)或同一域的任何其他页面上都可以访问。

`LocalStorage`是一种持久存储，与`sessionStorage`不同，它在会话结束后仍然有效。这类似于标准 cookie 的行为，但与 cookie 不同的是，cookie 只能保存非常有限的数据。`localStorage`在大多数浏览器上默认为 5MB，在 IE 上为 10MB。需要记住的是，我们将数据存储为字符串而不是它们的原始形式，例如整数或浮点数，因此最终存储的表示将更大。如果我们超出存储限制，那么将抛出一个带有`QUOTA_EXCEEDED_ERR`错误消息的异常。

在我们的代码中，我们使用`localStorage`来缓存 JSON 资源，从而完全控制了失效。此外，我们为给定用户的访问次数创建了一个简单的计数器。

显而易见的隔离是`hostname`和`port`的组合，需要单独存储。较少人知道的是，Web 存储还取决于`scheme/host/port`的元组。Scheme 包含子域和协议。因此，如果页面加载了混合类型的资源，有些是用`https`，有些是用`http`，你可能得不到那么明显的结果。虽然混合资源不是一个好的安全实践，但它经常发生。无论哪种情况，敏感数据都不应存储在本地或会话存储中。

另一种情况是大多数现代浏览器都有的私人/无痕模式。在该模式下打开页面时，将使用一个新的临时数据库来存储这些值。在此模式下存储的所有内容只会成为该会话的一部分。

## 还有更多...

**本地存储**使用一个在浏览器的主 UI 线程上运行的同步 API。因此，如果我们在多个不同的窗口上打开相同的网站，就有很小的可能发生竞争条件。对于大多数用例来说，这并不是一个真正的问题。要从客户端清除数据，我们可以随时调用`storage.clear()`，但大多数浏览器现在都有开发者工具来简化操作：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_11_02.jpg)

在填充方面有很多可用的，例如[`code.google.com/p/sessionstorage/`](https://code.google.com/p/sessionstorage/)或[`gist.github.com/remy/350433`](https://gist.github.com/remy/350433)。您可能想知道它们是如何工作的，因为存储是添加到浏览器的新功能。它们大多使用 cookie 来存储数据，因此通常受到 2 KB 的限制，即 cookie 的最大大小。其他使用 IE userData([`msdn.microsoft.com/en-us/library/ms531424%28VS.85%29.aspx`](http://msdn.microsoft.com/en-us/library/ms531424%28VS.85%29.aspx))对象在旧版本的 IE 上启用其使用。还有一些库，例如[`www.jstorage.info/`](http://www.jstorage.info/)，为多个浏览器版本提供相同的接口。此外，还有`Persists.js`，它可以启用多种不同的回退解决方案：flash - Flash 8 持久存储，gears - 基于 Google gears 的持久存储，localstorage - HTML5 草案存储，whatwg_db - HTML5 草案数据库存储，globalstorage - HTML5 草案存储（现已过时），IE - Internet Explorer 用户数据行为，和 cookie - 基于 cookie 的持久存储。

### 注意

还有一个基于自定义对象的回退，可以创建以在旧浏览器上启用`localStorage`。有关更多信息，请访问 MDN 的[`developer.mozilla.org/en-US/docs/DOM/Storage#Compatibility`](https://developer.mozilla.org/en-US/docs/DOM/Storage#Compatibility)。

`globalStorage`在几个版本的 Firefox 中实现了，但由于与实现相关的混乱很多，它已经从 Firefox 13 中移除，以及 Web 存储的规范。

在安全性方面，将敏感数据存储在客户端存储中从来都不是一个好主意。如果您的站点存在 XSS 漏洞，那么存储可以被读取。使用服务器端密钥加密数据并没有太多意义，因为这将使我们依赖于服务器数据。在非 TLS 站点上还可能发生 DNS 欺骗攻击。如果域名被欺骗，浏览器将无法判断数据是否是从“错误”的站点访问的。

对 Web 存储提出了很多批评，主要是由于用户跟踪。如果我们在几个不同的站点中有相同的广告商，那么他可以轻松地跟踪用户在这些站点上的访问。这使得用户的匿名性大大降低，成为易受攻击的目标。有几种提出的解决方案来解决这个问题，例如，对第三方`iframes`进行限制和创建此类数据的域名黑名单，但目前没有一种完全解决问题。

# 从文件中读取数据

我们已经使用文件输入来读取一些数据，但从未详细介绍过文件读取和可用于我们的对象。在这个示例中，我们将使用输入文件创建一个简单的文件阅读器，它将作为文件 API 提供的一些选项的迷你演示：目录和系统，[`www.w3.org/TR/file-system-api/`](http://www.w3.org/TR/file-system-api/)。

## 如何做到...

我们将创建一个包含文件输入控件和上传状态的进度输出的 HTML 文件：

1.  我们创建控件和一些输出占位符：

```html
<body>
<p>
<progress id="progress" value="0" max="100"></progress>
<output id="percent" for="progress">0</output>
</p>
<p>
<div id="fileInfo"></div>
</p>
<input type="file" id="file" value="Choose text file">
<button type="button" id="abort">Abort</button>
<button type="button" id="slice">Read 5 bytes</button>
<div id="state"></div>
<br />
<label>
        Contents:
<div id="content"></div>
</label>
```

1.  添加依赖项到 jQuery 和我们的`example.js`：

```html
<script src="img/jquery.min.js"></script>
<script type="text/javascript" src="img/example.js"></script>
```

1.  我们可以继续创建`example.js`文件；在这里，我们在`abort`按钮上附加一个事件处理程序，并使用`FileReader`对象：

```html
$(function() {

varfr = new FileReader();

  $('#abort').click(function(){
fr.abort();
console.log('aborting file change');
  });
```

1.  从所选的文件输入中，我们将使用当前配置项迭代上传的文件，并为一些常见事件添加事件处理程序：

```html
$('#file').on('change', function(e) {
    for (var i = 0; i <this.files.length; i++) {
var f = this.files[i];
fr = new FileReader();

fr.onerror = function (e) {
        $('#state').append('error happened<br />').append(e).append('\n');
      }

fr.onprogress = function (e) {
var percent = (e.loaded * 100 / e.total).toFixed(1);
        $('#progress').attr('max', e.total).attr('value', e.loaded);
        $('#percent').val(percent + ' %');
      }
fr.onabort = function() {
        $('#state').append('aborted<br />');
      }

fr.onloadstart = function (e) {
        $('#state').append('started loading<br />');
      }

      if (f.type&& (f.type.match('image/.+')) || (f.type.match('video/.+'))) {
fr.readAsDataURL(f);
      } else if (f.type.match('text/.+')) {
fr.readAsText(f);
      } else {
        $('#state').append('unknown type of file loaded, reading first 30 bytes <br />');
      }

fr.onload = function(e) {
        $('#state').append('finished reading <br />');
appendContents(f,e);
      }
      $('#fileInfo').html(getMetaData(f));
    }
  });
```

1.  `getMetaData`函数将从`file`对象中读取可用的元数据，并创建一个简单的 HTML 表示：

```html
function getMetaData(file){
var text = "<b>file: </b>" + file.name + " <br />";
    text += "<b>size: </b>" + file.size + " <br />";
    text += "<b>type: </b>" + file.type + " <br />";
    text += "<b>last modified: </b>" + file.lastModifiedDate.toString() + " <br />";
    return text;
  }
```

### 注意

您可以在 W3C 文件 API 规范的[`www.w3.org/TR/FileAPI/#dfn-file`](http://www.w3.org/TR/FileAPI/#dfn-file)中阅读有关文件接口的更多信息。

1.  通过读取文件类型，我们还可以确定输出内容。在我们的情况下，如果我们有文件，即图像，我们将数据附加为`img`标签上的`src`，另一方面，对于其他文件类型，我们只是打印文本表示：

```html
function appendContents(f,e) {
    if (f.type&&f.type.match('image/.+')){
      $("<img />").attr('src', e.target.result).appendTo("#content");
    } else {
      $("<pre />").text(e.target.result).appendTo("#content");
    }
  }
```

1.  还有另一种通过访问属性文件来读取文件输入中的文件列表的方法。`slice`按钮将仅从文件中读取前 15 个字节：

```html
$('#slice').click(function(){
varfileList = $('#file').prop('files');
    $.each(fileList, function(i,file) {
fr = new FileReader();
var blob = file.slice(0, 15);
fr.readAsBinaryString(blob);
fr.onload = function(e) {
        $("<pre />").text(e.target.result).appendTo("#content");
      }
    });
   });
  });
```

到目前为止，我们应该有一个正在运行的网站，一旦上传文件，文件将被读取和显示。为了查看进度事件，您可以尝试使用大文件，否则它可能会立即运行。至于`slice`按钮，最好尝试使用一个简单的`.txt`文件，以便您可以查看内容。

## 工作原理...

这些规范背后的主要思想是在客户端实现完整功能的文件系统 API。关于当前状态的不幸之处在于，只有 Chrome 实现了大多数来自文件系统和 FileWriter API 的功能，而其他浏览器支持 FileReader 和 File API。这就是为什么我们决定使用在所有主要浏览器中都受支持并使用最常见功能的工作示例。

对于读取和简单操作，我们使用包含可以使用`FileReader`读取的`File`对象的`FileList`。HTML5 在`<input type="file">`控件上定义了一个文件属性，可以使用 jQuery（`$('#file').prop('files'))`）或直接从所选的 HTML 元素中访问，就像我们在`this.files.length`的情况下所做的那样。此属性实际上是一个称为`FileList`的类似数组的对象，其中包含`File`对象。`FileList`实例具有一个方法`item(index)`和一个属性`length`。每个项目都是一个`File`对象，一个扩展了`Blob`的接口，不可变的原始二进制数据。文件是一个表示，并具有以下属性：

+   `name`：此属性表示文件的名称。

+   `lastModifiedDate`：此属性表示文件的最后修改日期。如果浏览器无法获取此信息，则将当前日期和时间设置为`Date`对象。

但除此之外，还有来自`Blob`接口的方法，如下所示：

+   `size`：此属性表示文件的大小（以字节为单位）

+   `type`：MIME 类型。此元数据可以直接读取，就像我们在`getMetaData`函数中所做的那样。元数据可以以各种不同的方式使用，例如在我们的情况下，根据文件类型匹配图像`f.type&&f.type.match('image/.+')`，然后显示`img`标签或其他文本。

`Blob`类型还包含`slice`方法的定义，由于`File`扩展了`Blob`，因此也可以在那里使用。`slice(start, end, contentType)`方法返回一个新对象，其中新的`contentType`属性被切片，新文件将从原始文件中切片。

### 提示

在较旧的浏览器版本中，例如，Firefox 版本小于 12 和 Chrome 版本小于 21，您需要使用`slice`方法的前缀版本。对于 Chrome，它是`File.webkitSlice()`，对于 Firefox，它是`File.mozSlice()`。`Blob`对象也可以从字节数组创建。

`FileReader`对象实际上是执行文件中包含的数据读取的对象，因为`File`对象本身只是对真实数据的引用。在`FileReader`中有用于从`Blob`中读取的方法，如下所示：

+   `void readAsArrayBuffer(blob)`: 此方法将文件读取为二进制数组

+   `void readAsText(blog, optionalEncoding)`: 此方法将文件读取为文本，其中可以添加可选的编码字符串名称以指定应使用的编码。如果省略编码，则将使用编码确定算法自动选择编码，如规范中所定义的，在大多数情况下应该足够。

+   `void readAsDataUrl(blob)`: 该方法从给定的文件创建一个数据 URL

您可能会注意到，这些方法实际上并不返回读取的数据。这是因为`FileReader`对象是异步读取数据的，所以一旦数据被读取，就会运行回调函数。还有一个`abort`方法，可以在调用后停止文件的读取，这是我们在示例中点击`abort`按钮时调用的方法。

可以附加到文件读取器的事件处理程序可能会在某些情况下触发。在我们的示例中，我们只打印文件读取器的状态。以下事件可以被处理：

+   `onabort`: 一旦读取操作被中止，就会触发此事件。

+   `onerror`: 当发生错误时调用此事件。这是我们经常想要处理或至少知道何时发生的事件，尽管处理程序是可选的。错误可能发生在各种不同的原因，我们的处理程序可以接受一个参数来检查`FileError`错误代码。例如，处理程序可以执行以下操作：

```html
fr.onerror = function (err){
  switch(err.code){
    case FileError.ENCODING_ERR:
      // handle encoding error
      break;
    case FileError.SYNTAX_ERR:
      // handle invalid line ending
      break;
    case FileError.ABORT_ERR:
    // handle abort error
    break;
    default :
    //handle all other errors , or unknown one
    break;
  }
}
```

`FileError`对象包含已发生的相应错误，但我们只处理给定情况下的一些情况。

+   onload – 一旦读取操作成功完成，就会调用此事件。处理程序接受并处理事件，从中我们可以读取数据：

```html
fr.onload = function (e){
    // e.target.result contains the data from the file.
}
```

+   `onloadstart`: 此方法在读取过程的最开始调用。

+   `onloadend`: 当我们成功读取时调用此方法，但即使发生错误，它也是一个很好的清理资源的候选者。

+   `onprogress`: 在读取数据时定期调用此方法。在进度处理程序中，我们可以读取几个对我们有用的属性，以便在`progress`元素上进行更新。我们可以读取已读取该文件的总字节数，这意味着我们可以简单地计算数据的百分比：

```html
fr.onprogress = function (e) {
var percent = (e.loaded * 100 / e.total).toFixed(1);
        $('#progress').attr('max', e.total).attr('value', e.loaded);
        $('#percent').val(percent + ' %');
      }
```

在大多数情况下，`onload`和`onerror`就足够了，但我们可能需要向用户显示视觉显示或通知他们读取状态。

要检查浏览器是否支持我们使用的功能，我们可以使用：

```html
if (window.File&&window.FileReader&&window.FileList&&window.Blob) {
   // has support for File API
}
```

## 还有更多...

对于更高级的逻辑和文件写入，有`FileWriter`、`DirectoryReader`、`FileEntry`、`DirectoryEntry`、`LocalFileSystem`等等。问题在于，目前只有 Chrome 支持它们。

要请求受限文件系统，我们调用`window.requestFileSystem(type, size, successCallback, errorCallback)`，这是 FileSystem API 的一部分。受限环境意味着这个文件系统与用户的文件系统是分开的，所以你不能随意写入任何地方。

自 Chrome 12 以来，文件系统已经被添加前缀，当前版本的 Chrome 25 仍在使用该版本。一个简单的文件系统请求可能是：

```html
window.webkitRequestFileSystem(
window.TEMPORARY,
  2*1024*1024,
  function (fs){
console.log("Successfully opened file system " + fs.name);
  });
```

受限环境中的文件用`FileEntry`表示，目录用`DirectoryEntry`表示。

一旦我们成功打开了文件系统，我们就可以读取`FileEntries`：

```html
function (fs){
fs.root.getFile(
    "awesome.txt",
     { create : true },
     function (fileEntry) {
console.log(fileEntry.isDirectory); // false
console.log(fileEntry.fullPath); // '/awesome.txt'
    }
   );
}
```

这个`fs.root`调用是对文件系统根目录的引用，至于`fileEntry`参数，有很多方法可以用于移动文件、删除文件、将其转换为 URL、复制以及您可能期望从文件系统中获得的所有其他功能。这些 URL 是相对于给定的受限文件系统的，因此我们可以期望在特定受限文件系统的`root`目录中有类似`/docs/books/dragon/`的内容。

Erick Bidelman 是 FileSystem API 背后的程序员之一，他实现了一个使用众所周知的 UNIX 命令（如`cp`，`mv`，`ls`）的功能的包装器。该库称为`filer.js`，[`github.com/ebidel/filer.js`](https://github.com/ebidel/filer.js)。他还有一个名为`ibd.filesystem.js`的 FileSystem API polyfill，([`github.com/ebidel/idb.filesystem.js`](https://github.com/ebidel/idb.filesystem.js))，它使用 IndexedDB 在其他浏览器中模拟功能。

还有一个 API 的同步版本，我们使用`webkitRequestFileSystemSync`调用它。我们希望使用同步读取的原因是 Web workers，因为这样做是有意义的，因为我们不会像那样阻塞主应用程序。

规范中提到了几种用例，因此这些用例的概述版本如下：

+   持久上传器是一种一次上传一个文件块到服务器的方式，因此当服务器或浏览器发生故障时，它可以继续使用服务器接收到的最后一个文件块，而不是重新上传整个文件。

+   游戏或富媒体应用程序中，资源作为 tarballs 下载并在本地展开，相同的资源可以预取，只需一个请求而不是许多小请求，这可以减少查找时间。

+   应用程序创建的文件，如离线视频、音频或任何其他类型的二进制文件查看器和编辑器，可以保存在本地系统中以供进一步处理。

# 使用 IndexedDB

除了本地和会话存储外，IndexedDB 还为我们提供了一种在浏览器中存储用户数据的方式。IndexedDB 比本地存储更先进：它允许我们在对象存储中存储数据，并支持对数据进行索引。

在这个示例中，我们将创建一个简单的待办事项列表应用程序，它将其数据存储在 IndexedDB 中。我们将使用第十章中介绍的 Angular 框架，*数据绑定框架*来简化我们的代码。我们将找出 IndexedDB 是否是更适合更大、更复杂的数据模型和更复杂的搜索和检索需求的选择。

待办事项列表应用程序将支持当前和已归档的项目，并允许按日期筛选项目。

## 如何做...

让我们写代码：

1.  创建`index.html`。为了简化我们的应用程序代码，我们将使用`angular.js`模板。我们的模板将包含以下元素：

+   选择以在当前和已归档的待办事项之间进行选择

+   使用 HTML5 日期组件的日期范围过滤器

+   带有复选框和每个项目的年龄的待办事项列表

+   添加新项目的表单

+   对已完成的当前项目进行归档的归档按钮

```html
<!doctype html>
<html ng-app="todo">
<head>
<script src="img/angular.min.js"></script>
<script src="img/example.js"></script>
<script src="img/service.js"></script>
<meta charset="utf8">
<style type="text/css">
        .todo-text {
            display: inline-block;
            width: 340px;
vertical-align:top;
        }
</style>
</head>
<body>
<div ng-controller="TodoController">
<select ng-model="archive">
<option value="0">Current</option>
<option value="1">Archived</option>
</select>
        From: <input type="date" ng-model="from">
        To: <input type="date" ng-model="to">
<ul>
<li ng-repeat="todo in todos | filter:{archived:archive}">
<input type="checkbox" ng-model="todo.done"
ng-disabled="todo.archived"
ng-click="updateItem(todo)">
<span class="todo-text">{{todo.text}}</span>
<span class="todo-age">{{todo.date | age}}</span>
</li>
</ul>
<form ng-submit="addItem()">
<input ng-model="text">
<input type="submit" value="Add">
</form>
<input type="button" ng-click="archiveDone()"
            value="Archive done">
<div ng-show="svc.error">{{svc.error}}</div>
</div>
</body>
</html>
```

1.  创建`example.js`，它将定义设置和操作`index.html`模板范围的控制器，并为日期定义年龄过滤器：

```html
var app = angular.module('todo', []);

app.filter('age', function() {
    return function(timestamp) {
var s = (Date.now() - timestamp) / 1000 / 3600;
        if (s < 1) return "now";
        if (s < 24) return s.toFixed(0) + 'h';
        if (s < 24*7) return (s / 24).toFixed(0) + 'd';
        return (s /24/7).toFixed(0) + 'w';
    };
});
var DAY = 1000*3600*24;

function TodoController($scope, DBTodo) {
    $scope.svc = DBTodo.data;
    $scope.archive = 0;
    $scope.from = new Date(Date.now() - 3*DAY)
        .toISOString().substr(0, 10);
    $scope.to = new Date(Date.now() + 1*DAY)
        .toISOString().substr(0, 10);
    $scope.todos = [];

    function updateItems() {
DBTodo.getItems(
            new Date($scope.from).getTime(),
            new Date($scope.to).getTime(),
            function(err, items) {
                $scope.todos = items;
            });
    };
    $scope.addItem = function() {
DBTodo.addItem({
            date: Date.now(),
            text: $scope.text,
            archived: 0,
            done: false
        }, function() {
            $scope.text = "";
updateItems();
        });
    };
    $scope.updateItem = function(item) {
DBTodo.updateItem(item);
    };
    $scope.archiveDone = function(item) {
DBTodo.archive(updateItems);
    };
    $scope.$watch('from',updateItems);
    $scope.$watch('to', updateItems);
}
```

1.  在`service.js`中定义控制器所需的`DBTodo`服务：

```html
angular.module('todo').factory('DBTodo', function($rootScope) {
```

首先，我们需要从全局定义中删除前缀：

```html
window.indexedDB = window.indexedDB || window.mozIndexedDB ||
window.webkitIndexedDB || window.msIndexedDB;
window.IDBTransaction = window.IDBTransaction ||
window.webkitIDBTransaction || window.msIDBTransaction;
window.IDBKeyRange = window.IDBKeyRange ||
window.webkitIDBKeyRange || window.msIDBKeyRange;

var self = {}, db = null;
self.data = {error: null};
```

我们的初始化函数打开数据库并指定请求的版本。当数据库不存在时，将调用`onupgradeneeded`函数，我们可以使用它来创建我们的对象存储和索引。我们还使用一些随机生成的项目填充数据库：

```html
    function initialize(done) {

varreq = window.indexedDB.open("todos", "1");
varneedsPopulate = false;
req.onupgradeneeded = function(e) {
db = e.currentTarget.result;
varos = db.createObjectStore(
                "todos", {autoIncrement: true});
os.createIndex(
                "date", "date", {unique: false});
os.createIndex(
                "archived", "archived", {unique: false});
needsPopulate = true;
        }
req.onsuccess = function(e) {
db = this.result;
            if (needsPopulate) populate(done);
            else done();
        };
req.onerror = function(e) {
self.data.error = e.target.error;
        };
    }

Random item generator
    function pickRandomText(k) {
var texts = ["Buy groceries",
            "Clean the car",
            "Mow the lawn",
            "Wash the dishes",
            "Clean the room",
            "Do some repairs"],
            selected = texts[(Math.random() * texts.length)
                .toFixed(0)];
            return selected + " " + k;
    }
```

该函数用`25`天内分布的`50`个随机项目填充数据库：

```html
    function populate(done) {
var now = Date.now();
var t = db.transaction('todos', 'readwrite');
t.oncomplete = done;

vartbl = t.objectStore('todos');
var N = 50;
        for (var k = N; k > 0; --k) {
tbl.add({
                text: pickRandomText(k),
                date: Date.now() - (k / 2) * DAY,
                archived: k > 5 ? 1 : 0,
                done: (k > 5 || Math.random() < 0.5)
            });
        }
    }
```

`withDB`是一个辅助函数，确保在执行指定函数之前初始化数据库：

```html
    function withDB(fn) {
        return function() {
varargs = arguments, self = this;
            if (!db) initialize(function() {
fn.apply(self, args);
            });
            else fn.apply(self, args);            
        };
    }
```

`withScope`是一个辅助函数，它创建一个函数，在其中调用`$rootScope.$apply`来指示 angular 范围对象的更新：

```html
    function withScope(fn) {
        return function() {
varargs = arguments, self = this;
            $rootScope.$apply(function() {
fn.apply(self, args);
            });
        };
    }
```

最后，`getItems`，`updateItem`，`archive`和`addItem`是`DBTodo`服务的公共 API：

```html
self.getItems = withDB(function(from, to, cb) {
var list = [];
var index = db.transaction('todos')
            .objectStore('todos').index('date');
varreq = index.openCursor(IDBKeyRange.bound(from, to, true, true));
req.onsuccess = function(e) {
var cursor = e.target.result;
            if (!cursor)
                return withScope(function() {
cb(null, list);
                })();
list.push(cursor.value);
cursor.continue();
        };
    });

self.updateItem = withDB(function(item, done) {
var t = db.transaction('todos', 'readwrite'),
            ix = t.objectStore('todos').index('date'),
req = ix.openCursor(IDBKeyRange.only(item.date));
t.oncomplete = done &&withScope(done);
req.onsuccess = function(e) {
var cursor = e.target.result;
            if (cursor) cursor.update(item);
        };            
    });

self.archive = withDB(function(done) {
var current = IDBKeyRange.only(0);
var t = db.transaction('todos', 'readwrite'),
req = t.objectStore('todos')
            .index("archived")
            .openCursor(current);

t.oncomplete = withScope(done);

req.onsuccess = function(e) {
var cursor = e.target.result;
            if (!cursor) return;
            if (cursor.value.done) {
cursor.value.archived = 1;
cursor.update(cursor.value);
            }
cursor.continue();
        };

    });

self.addItem = withDB(function(item, done) {         
var t = db.transaction('todos', 'readwrite'),
os = t.objectStore('todos');
t.oncomplete = withScope(done);
os.add(item);
    });

    return self;
});
```

1.  在支持 IndexedDB 和日期输入（例如 Google Chrome）的浏览器中打开`index.html`。

## 它是如何工作的...

与普通的 JavaScript API 相比，IndexedDB API 相当冗长。IndexedDB 使用 DOM 事件来表示异步任务的完成。大多数 API 调用都会返回一个请求对象。要获取结果，我们需要将事件监听器附加到这个对象上。

例如，打开数据库的结果是一个请求对象。我们可以将三个事件监听器附加到这个对象上：

+   `onsuccess`: 当数据库成功打开时调用

+   `onerror`: 当发生错误时调用

+   `onupgradeneeded`: 当数据库不是指定版本或尚不存在时调用

IndexedDB 数据库是一个包含一个或多个对象存储的面向对象数据库。

对象存储具有主键索引。在我们的例子中，主键是自动生成的，但我们也可以指定一个现有属性作为主键。

每个对象存储可能有一个或多个索引。索引可以通过指定应该被索引的属性路径来添加 - 在我们的例子中，我们为`todos`存储在日期和归档字段上定义了两个索引。

所有对数据库的查询都在事务中执行。创建事务时，我们定义将在事务中使用的对象存储。与请求一样，事务也有事件监听器：

+   `oncomplete`: 当事务完成时调用

+   `onerror`: 如果发生错误，则调用此方法

+   `onabort`: 如果事务被中止，则调用此方法

在事务中，我们可以通过调用`transaction.objectStore('name')`来访问对象存储。对该对象存储的所有操作都将在事务内完成。

对象存储支持多种方法来添加、获取和删除项目，以及访问索引的方法。要添加项目，我们使用`add`方法。要访问需要显示或更新的项目，我们使用索引，通过调用`objectStore.index('name')`。

索引提供了对象存储 API 的子集，用于检索数据，如`get`、`count`和`openCursor`。

要更新项目或获取多个项目，我们使用`openCursor`方法。它返回一个`request`，我们可以将`onsuccess`监听器附加到该请求上。该监听器将对游标访问的每个项目调用。可以通过`request.result`访问游标。

当我们处理完访问的项目后，可以调用`cursor.continue`来前进到下一个项目。`onsuccess`监听器将再次被调用，这次游标指向下一个项目。

我们可以通过指定键范围和方向（升序或降序）来限制游标的访问。键范围可以使用`IDBKeyRange`方法生成：

+   `upperBound`: 该方法用于指定上限范围

+   `lowerBound`: 该方法用于指定下限范围

+   `bound`: 该方法用于指定上限和下限范围

+   `only`: 该方法用于指定仅包含一个键的范围。

除了指定边界`upperBound`、`lowerBound`和`bound`之外，它们还支持额外的布尔参数，允许我们指定边界是否包含。

总而言之，当我们实现`getItems`方法来获取指定日期之间的所有项目时，我们需要：

+   打开一个到 todos 对象存储的事务

+   从事务中打开 todos 对象存储

+   从对象存储中打开`date`索引

+   创建一个`IDBKeyRange`边界，指定第一个日期作为下限，第二个日期作为上限（并指示边界包含两个 true 参数）

+   使用创建的键范围从`date`索引中打开游标

+   使用游标请求来迭代所有项目并将它们添加到数组中

+   使用事务的`oncomplete`处理程序在添加所有项目时调用回调函数

## 还有更多...

IndexedDB API 非常冗长和低级。它不是用于直接被 Web 应用程序使用的；相反，它旨在提供手段在其上编写更高级的数据库实现。

但更重要的是，IndexedDB 不支持一些我们已经接受为标准的真实数据库中的一些基本功能：

+   没有复合索引，这意味着我们无法编写有效的查询来绑定对象的多个属性。

+   如果我们希望按照与索引键提供的顺序不同的顺序对项目进行排序，我们将不得不填充一个数组并手动对结果进行排序。

+   没有连接，这意味着我们需要手动编写代码来连接两个对象存储，并选择最合适的索引来最小化工作量。

因此，我们不建议在 IndexedDB API 成熟之前使用它，或者在其上编写更完整和不那么冗长的数据库实现。

### 注意

查看 PouchDB ([`pouchdb.com/`](http://pouchdb.com/))以获取更完整的解决方案，或者查看`db.js` ([`aaronpowell.github.com/db.js/`](http://aaronpowell.github.com/db.js/))以获取更简洁的 API。

# 存储的限制以及如何请求更多

到目前为止，我们已经看到了在客户端有多种不同的方式来存储和访问数据。所有这些方式都给了我们在客户端存储大量数据的选择。问题是为什么没有一种方法可以填满所有设备的存储空间？

我们将看到为什么这并不是无处不在的，至少不是没有一些浏览器漏洞。为了做到这一点，我们将创建一个简单的案例，我们将使用`localStorage`将数据存储到浏览器中，只要用户代理允许。

## 如何做...

1.  我们可以开始创建一个名为`example.js`的文件，在那里我们将生成大小为`1k`和大小为`100k`的数据。1k 的数据可以通过创建一个包含`1025`个元素的数组来生成，然后我们将其与字母`"a"`连接，得到一个包含`1024`个字符的字符串`"a"`。

```html
var testing = (function (me) {
me.data1k =  new Array(1025).join("a"); // about 1k
me.data100k = new Array((1024*100)+1).join("b");// about 100k
```

1.  接下来，我们将创建一个简单的函数，该函数将接受条目数量和每个条目的数据：

```html
me.run = function (max, data) {
var el = document.getElementById('status');
el.setAttribute('max', max);
    try {
      for (i = 0; i < max; i++) {
console.log(i);
el.setAttribute('value', 1+i);
localStorage.setItem(i, data);
    }
    } catch (err) {
maxReached(i, err);
    }
}
The maxReached function will display the last entry that was successfully stored:
  function maxReached(i, err) {
console.log("max reached");
console.log(err);
var div = document.getElementById('max');
div.innerHTML = "Reached max " + i + " entry";
  }
```

1.  我们还将添加一个函数，用于清除整个`localStorage`对象：

```html
me.clear = function() {
var progress = document.getElementById('status');
progress.setAttribute('value','0');
localStorage.clear();
console.log("removed all data from localStorage");
  }
```

1.  在这之后，我们可以创建一个 HTML 文件，在那里我们将有几个按钮，一个用于清除所有数据，其他用于填充生成的数据到存储中：

```html
<body>
<progress id="status" value="0" max="100"></progress>
<div id="max">have not reached max</div>
<button type="button" onclick="testing.clear()" >clear</button>
<button type="button" onclick="testing.run(100,testing.data1k)" >100 entries 1K</button>
<button type="button" onclick="testing.run(500,testing.data100k)" >500 entries 100K</button>
<script src="img/example.js"></script>
</body>
```

## 它是如何工作的...

存储限制以及行为取决于浏览器。规范本身说用户代理应该限制存储区域的总空间量。此外，他们应该为每个子域（例如`a.example.com`，`b.example.com`等）提供相同数量的存储空间。还有一个选项可以提示用户请求更多的存储空间；不幸的是，目前只有 Opera 才这样做。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_11_03.jpg)

在 Firefox 中有一个名为`dom.storage.default_quota`的可配置属性，可以在`about:config`中找到，但你不能真的指望用户在那里手动设置一个增加的值。对于 IndexDB，存储大小没有限制，但初始配额设置为 50MB。

## 还有更多...

如果我们谈论 HTML5 文件系统 API 中的限制，我们有几种存储类型定义。

临时存储是基本的，所以我们不需要特殊权限来获取它；这使得它成为缓存的一个不错的选择。Chrome 目前有一个 1GB 的临时池，并且计划将 IndexedDB 和 WebSQL 纳入相同的池中。对于临时存储，没有持久性的保证，因此它可以随时被移除。

### 注意

有关 WebSQL 的更多信息可以在 W3C 上找到，尽管该规范已不再开发或维护[`www.w3.org/TR/webdatabase/`](http://www.w3.org/TR/webdatabase/)。

另一方面，持久存储是持久的。数据在重新启动后仍然存在，并且直到用户或我们的应用手动删除为止。当我们进行请求文件系统调用时，浏览器将提示我们是否同意，如果我们同意，我们将收到`QUOTA_EXCEEDE_ERR`。

还有一种类型为无限的存储，但这是 Chrome 特有的，并且旨在从扩展和 Chrome 应用中使用。

已经采取了一些努力来标准化存储请求的方式，因此为此目的创建了 Quota API 规范，[`www.w3.org/TR/quota-api/`](http://www.w3.org/TR/quota-api/)。规范本身定义了一个 API，用于管理各种持久 API 的本地存储资源的使用和可用性。

有一个`StorageQuota`接口，描述了获取更多`PERSISTENT`数据的过程。Chrome 中提供了实现的带前缀版本：

```html
window.webkitStorageInfo.requestQuota(PERSISTENT, 10*1024*1024, function(bytes){
console.log(bytes);
}, function (error){
console.log(error);
});
```

通过调用该方法，将出现提示要求用户请求权限。

# 操纵浏览器历史

历史 API 允许您使用 JavaScript 操纵浏览器历史。一些操作在用户代理中很长时间以来就已经可用了。一个新功能是可以在历史中添加新条目，更改在位置栏中显示的 URL 等。

这意味着我们可以创建一个遵守 REST 方式的单页面应用。现在页面可以具有唯一的标识符，将直接导航到具有特定状态的特定视图，而无需进行页面重新加载或进行一些客户端端的黑客攻击。

## 准备就绪

在这个示例中，我们将使用一些图片，因此您可以选择自己的选择，或者使用位于`img/`文件夹下的示例文件中提供的图片。这些图片也将在我们的网页中的`img/`中提供，因此您应该运行 HTTP 服务器。

## 如何做到...

让我们开始吧：

1.  我们为猫查看器创建 HTML 代码：

```html
<div>
<nav>
<ul>
<li><div data-id="0" data-url="/mycat.html">A cat</div></li>
<li><div data-id="1" data-url="/awesome.html">Some cat</div></li>
<li><div data-id="2" data-url="/somecat.html">The cat</div></li>
</ul>
</nav>
<div id="image">
</div>
</div>
```

1.  我们包含了对 jQuery 和我们的脚本`example.js`的依赖：

```html
<script src="img/jquery.min.js"></script>
<script src="img/example.js"></script>
```

1.  可选地，我们可以添加一些非常基本的样式，使 div 元素的行为更像链接，尽管在一般情况下我们也可以使用`<a>`元素，但覆盖锚点的点击行为并不总是最佳主意。样式可能类似于以下内容：

```html
<style>
nav div {
text-decoration:underline;
      cursor: pointer;
    }
</style>
```

1.  至于`example.js`文件，我们有一个称为`catson`的小型类似 JSON 的结构，描述了我们的数据：

```html
varcatson = [
  {
  "name":"Awesome cat",
  "url":"1.jpg"
  },
  {
  "name":"Crazy cat",
  "url":"2.jpg"
  },
  {
  "name":"Great cat",
  "url":"3.jpg"
  }
];
```

1.  文档加载时，我们检查当前用户代理中是否支持历史 API：

```html
$(document).ready( function() {
  function hasSupportForHistory() {
    return window.history&&history.pushState;
  }

  if ( !hasSupportForHistory() ) {
    $('body').text('Browser does not have support for History fall backing');
    return;
  }
```

1.  接下来，我们为我们的导航元素添加一个点击处理程序：

```html
  $("nav div").click( function(e) {
console.log('clicking');

var title = $(this).text(),
url = document.URL.substring(0, document.URL.lastIndexOf('/')) + $(this).data('url'),
        id = $(this).data('id'),
img = '<imgsrc="img/'+ catson[id].url +'" />',
        text = '<h1>'+catson[id].name+'</h1>';

    // change the displayed url
history.pushState(null, title, url);
    $('#image').html(text + img);
    // stop default propagation of event
e.preventDefault();
  })
```

此时，您应该有一个运行中的示例，如果您点击周围，您会注意到浏览器 URL 已更改，但我们依赖于只有一个页面。

如果您刷新一些其他生成的 URL，您应该会收到类似的消息：

```html
Error code 404.
Message: File not found.
Error code explanation: 404 = Nothing matches the given URI.

```

这是因为我们只是模拟网页，而页面本身并不存在。

## 它是如何工作的...

历史 API 背后的思想很简单。它是一个允许我们通过`window.history`对象操纵浏览器历史的对象。

如果我们想回到上一页，我们只需调用：

```html
window.history.back();
```

或者前往下一页：

```html
window.history.forward();
```

还有一个更一般的方法，允许我们在历史中向前或向后移动`n`页，例如，要后退三页，我们调用：

```html
window.history.go(-3);
```

这个 API 提供的所有方法中最有趣的可能是`pushState(state`，`title`，`url)`和`replaceState(state`，`title`，`url)`。我们在示例中使用的第一个方法将具有给定状态对象的 URL 添加到历史堆栈中。为了完全符合规则，我们应该使用方法的第一个参数，即代表当前文档状态的状态对象。在我们的例子中，这将是`catison`列表的一个 cat 对象。

与`pushState`类似，`replaceState`方法是更新而不是使用相同参数在历史堆栈上添加新状态。

状态对象本身可以通过`history.state`变量访问，类似于`history.state`变量，当前堆栈的大小也有一个`history.length`变量。`history.state`变量可用于存储给定段的数据，这使得它成为浏览器中存储数据的另一个选项。

### 注意

您可以在 WHATWG 的实时规范中阅读有关 History API 的更多信息：[`www.whatwg.org/specs/web-apps/current-work/multipage/history.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/history.html)。

你需要考虑的第一件事是制定一个聪明的路由，这样你就不会有损坏和不存在的 URL。这意味着我们可能需要在服务器端做一些工作，以便 URL 的状态可用于呈现。主要目标是提高可用性，而不是过度使用新功能，所以要小心在哪里真正需要这个功能。

对于旧版浏览器，有一个名为`history.js`的出色 polyfill，（[`github.com/browserstate/history.js`](https://github.com/browserstate/history.js)），它还为开发添加了一些其他不错的功能。

还有一个名为`Path.js`的库，它使用 History API 进行高级路由，但也滥用`hashbangs`（`#`）来实现良好的功能。

当我们谈论完全滥用时，有一个整个游戏是使用`history.replaceState`来使 URL 栏成为一个屏幕。这个游戏叫做 Abaroids，可以在[`www.thegillowfamily.co.uk/`](http://www.thegillowfamily.co.uk/)找到。


# 第十二章：多媒体

在本章中，我们将涵盖以下配方：

+   播放音频文件

+   播放视频文件

+   自定义媒体元素的控件

+   向您的视频添加文本

+   多媒体嵌入

+   使用 HTML5 音频将文本转换为语音

# 介绍

HTML5 添加了两个元素音频和视频，它们提供了以前使用浏览器插件完成的功能。在大多数情况下，我们发现的播放器都是基于 Flash 的，但最近情况正在改变。大多数浏览器现在对基本的 HTML5 媒体元素相关功能有很好的支持。

播放器的自定义选项非常有限，并且是特定于供应商的。大多数网站都有一些仍然使用 Flash 制作的自定义播放器，因为这是完成工作的最佳方式。

Flash 本身不会突然消失，但是使用开放标准的替代方案总是有说服力的理由。同样的情况也发生在网络游戏行业，HTML5 正在逐渐取代基于 Flash 的游戏市场。

# 播放音频文件

音频元素使得在浏览器中播放音频文件变得简单。这个元素的采用引起了很多争议，主要是因为缺乏格式的共同基础。最初，W3C 规范建议使用 Ogg Vorbis ([`www.vorbis.com/`](http://www.vorbis.com/))格式。

### 注意

有关不同格式的浏览器支持的最新信息可以在`www.caniuse.com`上找到。

在这个配方中，我们将看一下元素和一些可以应用在它上面的基本属性。

## 准备工作

为了播放音频，我们需要一个实际的音频文件。您可以自己选择一个，或者使用示例中附带的文件。该文件将从音乐文件夹中提供。我们将使用 Jason Weinberger & the WCFSO 在免费音乐档案馆[`freemusicarchive.org/music/Jason_Weinberger__the_WCFSO/Jason_Weinberger__the_Waterloo-Cedar_Falls_Symphony_Orchestra/`](http://freemusicarchive.org/music/Jason_Weinberger__the_WCFSO/Jason_Weinberger__the_Waterloo-Cedar_Falls_Symphony_Orchestra/)提供的 Mozart—Clarinet Concerto in A K. 622, II. Adagio。

该文件的类型是`.mp3`，但是为了这个例子，我们还需要一个`.ogg`文件。有很多在线和离线的转换器可用，所以我们可以使用[`media.io`](http://media.io)。例如。如果您不想麻烦，示例文件中还有一个转换后的`song.ogg`文件可用。

## 如何做...

我们将创建一个包含音频播放器的 HTML 文件：

1.  body 部分将包含以下内容：

```html
    <p>
      <audio id="mulipleSrc" controls preload loop>
          Audio not supported
        <source src="img/Jason_Weinberger__the_WCFSO_-_04_-_Mozart_-_Clarinet_Concerto_in_A_K_622_II_Adagio.mp3"type="audio/mpeg" />
        <source src="img/song.ogg" type="audio/ogg" />
    <a href="music/song.ogg">download file </a>
      </audio>
    <p>
```

1.  归因的一小段文字：

```html
    Mozart - Clarinet Concerto in A K. 622, II. Adagio by <a href="http://freemusicarchive.org/music/Jason_Weinberger__the_WCFSO/Jason_Weinberger__the_Waterloo-Cedar_Falls_Symphony_Orchestra/">Jason Weinberger</a> & the WCFSO is licensed under a Creative Commons Attribution License.
    </p>
```

就是这样，您应该在浏览器中有一个可访问的音频播放器。

## 它是如何工作的...

旧的方法是使用`<object>`和`<embed>`，并传递了许多特定于播放器的参数给嵌入的`.swf`文件，看起来像下面的代码：

```html
<object data="somePlayer.swf">
  <param name="quality" value="medium">
</object>
```

新的方法相当简单，我们可以添加一个带有指定`src`属性的音频元素：

```html
<audio src="img/myFile.ogg" autoplay>
  Some fallback HTML code
</audio>
```

这将自动在页面上播放文件，而不给用户关于停止音乐的选项。为了让用户代理呈现播放器，我们添加了属性控件。我们通过设置`src`属性施加的另一个限制是只播放该文件。你可能会想为什么我们需要多个来源，但原因很简单。在当前状态下，一些浏览器支持某些格式，而其他浏览器不支持。如果我们想要在所有现代浏览器中获得支持，那么我们就提供了多个来源的选项。

### 注意

在撰写本文时，这是使用 Windows 操作系统的浏览器格式支持的大致情况。

| 浏览器/功能 | WAV | Opus | Ogg | MP3 | ACC |
| --- | --- | --- | --- | --- | --- |
| Firefox 20 | 是 | 是 | 是 | 否 | 否 |
| Chrome 26 | 是 | 是 | 是 | 是 | 是 |
| IE 9 | 否 | 否 | 否 | 是 | 是 |
| Opera | 是 | 否 | 是 | 否 | 否 |

### 注意

除了提供浏览器支持统计数据的标准网站外，您还可以使用 SoundCloud 完成的测试套件来检查[`areweplayingyet.org/`](http://areweplayingyet.org/)上的各个功能，或者在[`github.com/soundcloud/areweplayingyet`](https://github.com/soundcloud/areweplayingyet)上查看源代码。

源元素允许我们为任何媒体元素指定多个备用资源。它本身没有意义，因此应该是某些媒体标签的一部分。我们可以有多个具有不同`src`、类型和媒体属性的源元素。例如，我们可以有以下元素：

```html
<source src='audio.oga' type='audio/ogg; codecs=flac'>
```

如果您不确定您提供的任何源是否可以在用户的浏览器中使用，您可以在`source`元素上附加`onerror`事件侦听器。这个处理程序可以用来执行一个回退。

还有一些其他属性可以用于媒体元素。除了全局属性外，媒体指定的属性包括：

+   `autoplay`属性：它是一个布尔值属性，定义了浏览器是否应该在具有足够大的媒体文件部分时立即开始播放。该元素的默认状态是缺失，这意味着我们默认情况下没有自动播放。

+   `preload`属性：它向浏览器提供提示，即使用户尚未点击播放，源文件也应该被下载。这里的想法是我们期望将来某个时候会播放文件，相当于将值设置为`auto`。该值也可以设置为`none`，这表明浏览器应该暂停预加载，因为我们不希望用户按下播放按钮。还有一个选项是将值设置为 metadata，这意味着只加载媒体文件的元数据，比如长度。

+   `muted`属性：它也是一个基于布尔值的属性，默认值为 false，表示将没有声音。

+   `loop`属性：它在完成后将音频设置为重新开始。

+   `controls`属性：它简单地添加了播放器控件。

+   `mediagroup`属性：它用于对多个媒体元素进行分组，例如，如果我们希望两个元素使用相同的控件，我们可以设置它们使用相同的媒体组。

+   `crossorigin`属性：它可以指定限制`src`属性符合**跨域资源共享**（**CORS**）。

大多数其他的自定义和 JavaScript 访问将在以下教程中介绍。如果我们使用没有设置控件属性的元素，最好将音频元素的 CSS 设置为`display:none`，以确保它不会占用页面空间。

# 播放视频文件

为了在浏览器中添加对视频的本地支持，HTML5 引入了视频元素。这与音频元素非常相似，因为它们共享共同的接口，所以相同的属性适用。还有一些其他属性仅适用于视频元素。此外，源的编解码器大多不同，对于视频，我们有 H.264/MPEG-4、VP8、VP9 和 Theora。

在这个教程中，我们将看到如何通过创建一个简单的页面来使用内置播放器。

### 注意

HTML5 媒体元素的规范可以在[`www.whatwg.org/specs/web-apps/current-work/multipage/the-video-element.html`](http://www.whatwg.org/specs/web-apps/current-work/multipage/the-video-element.html)找到。

## 准备工作

我们需要一个视频文件来使用我们的播放器，所以您可以自己选择一个。我们选择使用[`archive.org/details/animationandcartoons`](http://archive.org/details/animationandcartoons)上提供的视频之一。

这个视频叫做《Boogie Woogie Bugle Boy》，由《Walter Lantz Productions》制作，在 1941 年被提名奥斯卡奖。

### 注意

Archive.org，也称为互联网档案馆，是一个非营利数字图书馆，其使命是“普遍获取所有知识”。除了是一个图书馆之外，它还托管了各种多媒体。更著名的子项目之一是 wayback machine，[`archive.org/web/web.php`](http://archive.org/web/web.php)，这是一个网站过去状态的快照存档。还有一个名为[nasaimages.org](http://nasaimages.org)的子项目，旨在使 NASA 的图像和视频更接近公众。互联网档案馆提供的数据量非常庞大，使其成为一个很好的信息来源。

此外，我们将使用一个海报图像，在视频开始之前显示该图像；图像名为`poster.png`，是示例源的一部分，但您可以使用任何您喜欢的图像。

## 如何做...

我们创建一个简单的 HTML，其中包含视频元素，并为我们的视频提供一个源：

1.  body 部分将包含以下代码：

```html
    <p>
      <video width="640" height="360" poster="poster.png" controls preload loop>
          Video not supported <a href="http://archive.org/download/WalterLantz-BoogieWoogieBugleBoy1941/WalterLantz-BoogieWoogieBugleBoy1941.ogv"> download </a> instead
        <source src="img/WalterLantz-BoogieWoogieBugleBoy1941.ogv" type="video/ogg" />
      </video>
```

1.  并且归因将包含以下代码：

```html
    <p>
    Video is part of animation shorts on <a href="http://archive.org/details/more_animation"> archive.org</a>. The video
    is titled : Walter Lantz - Boogie Woogie Bugle Boy
    </p>
```

打开后，我们应该有一个运行中的视频播放器，就像以下截图一样：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_12_01.jpg)

## 它是如何工作的...

视频元素与音频元素非常相似，所有音频元素的属性都适用于视频元素。视频特定的属性包括：

+   `Width`和`height`：它们表示元素的宽度和高度。控制将调整视频大小以适应指定的大小。视频的实际大小取决于正在播放的文件。

+   `poster`：这是一个属性，使我们能够在用户决定播放视频之前在视频元素上显示静态图像。

通过向视频添加各种属性的组合，我们可以使用户体验更好；在我们的代码示例中，视频将居中显示，因为宽度和高度属性与视频的实际宽度和高度不匹配。

如果我们想要播放视频的特定范围，也有内置的支持。例如，我们可能希望从第 30 秒播放到第 40 秒。要在`src`属性的 URL 中执行此操作，我们在哈希（`#`）后附加一个片段定义，如以下代码所示：

```html
<source src="img/myvideo.ogv#t=30,40" />
```

通用定义如下：

```html
#t=[starttime],[endtime]
```

变量`starttime`和`endtime`是可选的，可以是指定从开始的秒数，也可以是`小时:分钟:秒`的格式。

如果我们想要从第 80 秒播放到视频结束，源将如下所示：

```html
<source src="img/myvideo.ogv#t=80" />
```

视频通常以一些有损压缩格式编码，因为它们作为原始格式传输时非常大。

### 注意

您可以在以下链接中了解有关有损压缩的更多信息[`en.wikipedia.org/wiki/Lossy_compression`](https://en.wikipedia.org/wiki/Lossy_compression)。其主要思想是通过牺牲一定程度的信息和质量来显著减小原始视频的大小。

微软和苹果拥有使用 H.264 的许可证，或者更常见的是通过扩展名`.mp4`或`.m4v`。该编解码器有许多不同的版本和组合，此外，它受 YouTube 和 iTunes 的支持，使其成为一个非常受欢迎的选择。Firefox 和 Chrome 原本计划放弃对其的支持，因为该格式是专有的，并且必须支付一定的特许费，这使得它成为一个非常有争议的选择。Firefox 计划在将来支持该编解码器，但前提是有第三方解码器可用。

### 注意

有关 H.264 的更多信息，请访问[`en.wikipedia.org/wiki/H.264/MPEG-4_AVC`](http://en.wikipedia.org/wiki/H.264/MPEG-4_AVC)。

Ogg Theora 来自[Xiph.org](http://Xiph.org)，这个组织提供了我们在音频元素配方中使用的`.ogg`容器和 Vorbis 音频编解码器，以及其他贡献。这受到 Firefox、Opera 和 Chrome 的支持，但至少默认情况下不受 IE 和 Safari 的支持。

### 注意

有关 Ogg Theora 的更多信息，请访问[`www.theora.org/`](http://www.theora.org/)。

WebM 支持 Vorbis 作为音频编解码器，支持 VP8 作为视频编解码器。VP8 是由一家名为 On2 的公司开发的编解码器，后来被 Google 收购。此外，WebM 原生支持 Chrome、Opera 和 Firefox，至于 IE 和 Safari，用户需要下载额外的插件。

### 注意

有关 WebM 的更多信息，包括格式、工具和相关文档，请访问[`www.webmproject.org/`](http://www.webmproject.org/)。

## 还有更多...

拥有多个来源是好的，但并不总是一个选择。我们还希望为旧浏览器提供备用方案，为此我们必须依赖插件。

如果您引用来自 YouTube 或 Vimeo 等第三方付费网站的视频，您可以简单地放置嵌入播放器的`iframe`：

```html
<iframe width="420" height="345"src="img/WEbzZP-_Ssc">
</iframe>
```

还有一些服务器 JavaScript 库可以使备用过程变得简单。其中之一是[`mediaelementjs.com/`](http://mediaelementjs.com/)。

安装很简单，因为我们只需要包含`.js`和`.css`文件作为依赖项，如下所示：

```html
<code><script src="img/jquery.js"></script>
  <script src="img/mediaelement-and-player.min.js"></script>
  <link rel="stylesheet" href="mediaelementplayer.css" />
</code>
```

至于备用播放器：

```html
<video src="img/myvideo.ogv" />
  <!-- other sources -->
  <object width="320" height="240" type="application/x-shockwave-flash" data="flashmediaelement.swf">
    <param name="movie" value="flashmediaelement.swf" />
    <param name="flashvars" value="controls=true&file=myvideo.mp4" />
    <img src="img/myvideo.jpg" width="320" height="240" title="No video playback capabilities" />
  </object>
</video>
```

备用播放器只是`mediaelement.js`的众多功能之一；移动浏览器有很多选项，API 也有很多简化。

### 注意

如果您对可能的转换工具或编解码器背后的政策以及对它们的详细解释感兴趣，请查看 Mark Pilgram 的书*Dive into HTML5*，可在[`fortuito.us/diveintohtml5/video.html`](http://fortuito.us/diveintohtml5/video.html)上找到。

还有一篇有趣的文章，标题为“面向所有人的视频”，讨论了在不同浏览器上启用视频支持的主题，[`camendesign.com/code/video_for_everybody`](http://camendesign.com/code/video_for_everybody)。

# 自定义媒体元素的控件

媒体元素，目前是视频和音频，可以使用 JavaScript 进行控制，因为这些元素本身包含有用的方法和属性。在这个配方中，我们将介绍一些最基本的功能和方法，这些功能和方法可以应用在具有`HTMLMediaElement`接口的元素上。

### 注意

HTML5 媒体元素的规范可以在[`www.w3.org/TR/html5/embedded-content-0.html#htmlmediaelement`](http://www.w3.org/TR/html5/embedded-content-0.html#htmlmediaelement)找到。

## 准备工作

在这个配方中，我们还需要一个视频文件，所以我们可以使用上一个配方中的相同视频。

## 如何做...

我们首先创建一个 JavaScript 控制器，它将具有媒体播放器的非常基本的功能。

1.  我们的控制器方法将接受一个命令的选择器并执行该命令，我们需要以下内容：

```html
var videoController = (function () {
  var my = {};
  function findElement(selector){
   var result = document.querySelector(selector);
   if (!result) {
    throw "element " + selector + " not found ";
   }
   return result;
  }

  function updatePlaybackRate(el, speed) {
   el.playbackRate += speed;
  }

  function updateVolume(el, amount) {
   el.volume += amount;
  }

  my.play = function(video) {
   var el = findElement(video);
   el.play();
  }

  my.pause = function(video) {
   var el = findElement(video);
   el.pause();
  }

  my.toggleMute = function(video) {
   var el = findElement(video);
    el.muted = !el.muted;
  }

  my.increasePlaybackRate = function(video, speed) {
   var el = findElement(video);
   updatePlaybackRate(el, speed);
  }

  my.decreasePlaybackRate = function(video, speed) {
   var el = findElement(video);
   updatePlaybackRate(el, -speed);
  }

  my.increaseVolume = function(video, amount) {
   var el = findElement(video);
   updateVolume(el, amount)
  }
  return my;
}());
```

现在在一个简单的场景中，我们可能只需使用标准方法而不添加另一层，但这里的想法是，我们可以根据需要扩展功能，因为我们可以从 JavaScript 中访问元素。

1.  对于 HTML，我们将拥有与播放视频配方中相似的版本。我们将有一些按钮，这些按钮将使用我们的视频控制器，并额外添加一个简单的样式。让我们在头部添加以下内容：

```html
  <head>
    <title>Video custom controls</title>
    <style>
      video {
        box-shadow: 0 0 10px #11b;
      }
    </style>
  </head>
```

1.  身体部分将包含控制按钮：

```html
    <p>
      <video id="theVideo" width="640" height="480" poster="poster.png" preload loop>
          Video playback not supported <a href="http://archive.org/download/WalterLantz-BoogieWoogieBugleBoy1941/WalterLantz-BoogieWoogieBugleBoy1941.ogv"> download </a>
        <source src="img/WalterLantz-BoogieWoogieBugleBoy1941.ogv" type="video/ogg" />
      </video>
    </body>
    <p>
    The Dashboard: <br/>
      <button onclick="videoController.play('#theVideo')">Play</button>
      <button onclick="videoController.pause('#theVideo')">Pause</button>
      <button onclick="videoController.increasePlaybackRate('#theVideo',0.1)">Speed++</button>
      <button onclick="videoController.decreasePlaybackRate('#theVideo',0.1)">Speed-- </button>
      <button onclick="videoController.decreaseVolume('#theVideo', 0.2) ">Vol-</button>
      <button onclick="videoController.increaseVolume('#theVideo', 0.2) ">Vol+</button>
      <button onclick="videoController.toggleMute('#theVideo')">Toggle Mute</button>
    <p>
    Video is part of animation shorts on <a href="http://archive.org/details/more_animation"> archive.org</a>. The video
    is titled : Walter Lantz - Boogie Woogie Bugle Boy
    </p>
```

1.  然后我们将依赖项添加到我们的`example.js`文件中。

```html
<script src="img/example.js"> </script>
```

之后我们应该有一个完全运行的视频播放器。

## 它是如何工作的...

使用 JavaScript，我们可以访问和操作任何媒体元素的属性。这个选项使我们能够对标准元素进行许多不同类型的定制。这些属性大多数在`HTMLMediaElement`中定义；在那里我们可以读取和写入`currentTime`、`playbackRate`、`volume`、`muted`、`defaultMuted`等等。

### 注意

有关更全面的`HTMLMediaElement`属性以及只读属性，请参考[`www.w3.org/TR/html5/embedded-content-0.html#media-elements`](http://www.w3.org/TR/html5/embedded-content-0.html#media-elements)上可用的规范。

通过更改属性，我们可以制作自定义播放器，以及各种不同的视觉更新。媒体元素会触发大量不同的事件。在这些事件上，我们可以附加事件侦听器，并根据状态更改进行更新。以下事件会被触发：`loadstart`、`abort`、`canplay`、`canplaythrough`、`durationchange`、`emptied`、`ended`、`error`、`loadeddata`、`loadedmetadata`、`pause`、`play`、`playing`、`progress`、`ratechange`、`seeked`、`seeking`、`stalled`、`suspend`、`timeupdate`、`volumechange`和`waiting`。

### 注意

事件的名称是不言自明的，如果您对特定事件感兴趣，可以阅读文档了解它们的用途，文档位于[`www.w3.org/TR/html5/embedded-content-0.html#mediaevents`](http://www.w3.org/TR/html5/embedded-content-0.html#mediaevents)。

在我们的示例中，我们可以添加一个监听器来显示当前速率的速率：

```html
  my.displayRate = function (video, output) {
   var vid = findElement(video),
       out = findElement(output);

   vid.addEventListener('ratechange', function(e) {
     console.log(e);
     out.innerHTML = 'Speed x' + this.playbackRate;
   }, false);
  }
```

然后在 HTML 中添加一个输出元素，并调用我们新添加的方法：

```html
    <output id="speed"></output>
    <script>
      videoController.displayRate("#theVideo","#speed");
    </script>
```

现在，第一次播放视频时，速率更改事件会被触发，并且速率设置为`1`。每次连续的速率更改都会触发相同的事件。

### 注意

W3C 在[`www.w3.org/2010/05/video/mediaevents.html`](http://www.w3.org/2010/05/video/mediaevents.html)上有一个关于媒体元素触发的事件的很好的演示。

这里还有一件有趣的事情要注意，`<audio>`元素也可以用于视频文件，但只会播放文件中的音频流。

# 向您的视频添加文本

在显示多语言视频时，我们经常希望为讲其他语言的人提供文本。这是许多会议演讲以及许多电影和电视节目的常见做法。为了在视频中启用外部文本轨道资源，创建了 WebVTT（[`dev.w3.org/html5/webvtt/`](http://dev.w3.org/html5/webvtt/)）标准。

## 准备工作

为简单起见，我们将使用与其他示例中相同的视频以及海报图像。至于其他文件，我们将自己创建它们。您也可以自己选择其他视频，因为视频本身并不那么重要。

## 如何做...

我们从 HTML 开始，其中包括视频元素，另外还添加了轨道元素以及简单的`example.js`。执行以下步骤：

1.  在 body 元素中包括：

```html
    <p>
      <video width="640" height="360" poster="poster.png" controls preload loop>
     Video playback not supported <a href="http://archive.org/download/WalterLantz-BoogieWoogieBugleBoy1941/WalterLantz-BoogieWoogieBugleBoy1941.ogv"> download</a> instead
        <source
        src="img/WalterLantz-BoogieWoogieBugleBoy1941.ogv" type="video/ogg" />
        <track src="img/video.vtt" kind="subtitles" srclang="en" label="English" default />
        <track src="img/karaoke.vtt" kind="captions" srclang="gb" label="Other" />
      </video>
    <p>
    Video is part of animation shorts on <a href="http://archive.org/details/more_animation"> archive.org</a>. The video
    is titled : Walter Lantz - Boogie Woogie Bugle Boy
    </p>
    <script src="img/example.js"></script>
```

1.  JavaScript 只会记录我们的视频元素可用的对象。这里的想法是展示可以通过代码访问和操作轨道。脚本将包含以下内容：

```html
(function(){
  var video = document.getElementById('theVideo'),
      textTracks = video.textTracks;

   for(var i=0; i < textTracks.length; i++){
    console.log(textTracks[i]);
   }
}())
```

1.  至于我们为轨道创建的`.vtt`文件，我们将手动创建它们。文件`video.vtt`将包含以下内容：

```html
WEBVTT

1
00:00:01.000 --> 00:00:13.000
this is the video introduction

2
00:00:15.000 --> 00:00:40.000
There is also some awesome info in
multiple lines.
Why you ask?
Why not ...

3
00:00:42.000 --> 00:01:40.000
We can use <b>HTML</b> as well
<i> Why not?</i>

4
00:01:42.000 --> 00:02:40.000
{
"name": "Some JSON data",
"other": "it should be good for meta data"
}

5
00:02:41.000 --> 00:03:40.000 vertical:lr
text can be vertical

6
00:03:42.000 --> 00:04:40.000 align:start size:50%
text can have different size relative to frame
```

1.  至于`karaoke.vtt`，它将包含以下代码：

```html
WEBVTT

1
00:00:01.000 --> 00:00:10.000
This is some karaoke style  <00:00:01.000>And more <00:00:03.000> even more  <00:00:07.000>  
```

运行示例后，我们应该在给定范围内有字幕。

### 提示

如果您手动构建 WebVTT 文件，您会注意到很容易出错。有一个很好的验证器可用于[`quuz.org/webvtt/`](http://quuz.org/webvtt)，源代码在[`github.com/annevk/webvtt`](https://github.com/annevk/webvtt)上。

## 它是如何工作的...

视频已经有一段时间了，但添加字幕并不是一个选择。轨道元素以标准方式使我们能够向视频添加信息。轨道不仅用于字幕，还可以用于其他类型的定时提示。

### 注意

*cue*这个词的一般定义是，它代表了一个说或做的事情，作为一个信号，让演员或其他表演者进入或开始他们的讲话或表演。

Cues 可以包含其他数据格式，如 JSON、XML 或 CSV。在我们的示例中，我们包含了一个小的 JSON 数据片段。这些数据可以以许多不同的方式使用，因为它与特定时间段相关联，但字幕并不是它的真正用途。

轨道元素的`kind`属性可以包含以下值：

+   **字幕**：这是给定语言的转录或翻译。

+   **字幕**：它与字幕非常相似，但也可以包括音效或其他音频。这种类型的主要意图是用于音频不可用的情况。

+   **描述**：这是视频的文本描述，用于在视觉部分不可用的情况下使用。例如，它可以为盲人或无法跟随屏幕的用户提供描述。

+   **章节**：此轨道可以包含给定时期的章节标题。

+   **元数据**：这是一个非常有用的轨道，用于存储以后可以由脚本使用的元数据。

除了`kind`属性之外，还有`src`属性是必需的，并显示轨道源的 URL。轨道元素还可以包含`srclang`，其中包含定时轨道的语言标签。

### 注意

语言标签通常具有两个字母的唯一键，用于表示特定语言。有关更多详细信息，您可以查看[`tools.ietf.org/html/bcp47`](http://tools.ietf.org/html/bcp47)。

还有一个`default`属性，如果在轨道上存在，则该轨道将成为默认显示的轨道。

此外，我们还可以使用`label`属性，该属性可以具有自由文本值，用于指定元素的唯一标签。

### 注意

轨道元素的一个巧妙用法可以在以下网址找到：[`www.samdutton.net/mapTrack/`](http://www.samdutton.net/mapTrack/)。

WebVTT 标准定义了文件需要以字符串"WEBVTT"开头。在此之后，我们有提示定义，零个或多个此类元素。

每个提示元素具有以下形式：

```html
[idstring]
[hh:]mm:ss.ttt --> [hh:]mm:ss.ttt [cue settings]
Text string
```

`idstring`是一个可选元素，但如果我们需要使用脚本访问提示，则最好指定它。至于`timestamp`，我们有一个标准格式，其中小时是可选的。第二个`timestamp`必须大于第一个。

文本字符串允许包含简单的 HTML 格式，如`<b>`，`<i>`和`<u>`元素。还有一个选项可以添加`<c>`元素，用于为文本的部分添加 CSS 类，例如`<c.className>styled text </c>`。还有一个选项可以添加所谓的语音标签`<v someLabel> the awesome text </v>`。

提示设置也是可选的，并且在时间范围之后附加。在此设置中，我们可以选择文本是水平显示还是垂直显示。设置是区分大小写的，因此它们必须像示例中显示的那样小写。可以应用以下设置：

+   **垂直**：它与值`vertical:rl`一起使用，其中`rl`代表从右到左的书写，`vertical:lr`代表从左到右。

+   **行**：此设置指定文本将在垂直方向显示的位置，或者在我们已经使用垂直时，它指定水平位置。该值用百分比或数字指定，其中正值表示顶部，负值表示底部。例如，`line:0`和`line:0%`表示顶部，`line:-1%`或`line:100%`表示底部。

+   **位置**：这是一个设置，用于指定文本在水平方向上显示的位置，或者如果我们已经设置了垂直属性，则指定文本在垂直方向上显示的位置。它的值应该在 0 到 100 之间。例如，可以是`position:100%`表示右侧。

+   **大小**：它指定文本区域的宽度/高度，以百分比表示，具体取决于附加的垂直设置。例如，`size:100%`表示文本区域将显示。

+   **对齐**：这是一个属性，用于设置文本在由大小设置定义的区域内的对齐方式。它可以具有以下值`align:start`，`align:middle`和`align:end`。

在文本字符串中，我们还可以按照给定单词的更详细的出现顺序，以一种卡拉 OK 的风格。例如，参见以下内容：

```html
This is some karaoke style  <00:00:02.000>And more <00:00:03.000>
```

它说明在 2 秒之前我们有一些文本，活动提示`And more`在 2 到 3 秒之间。

关于文本字符串的另一点是，它不能包含字符串`-->`，和字符`<`，因为它们是保留字符。但不用担心，我们总是可以使用转义版本，例如`&amp;`代替`&`。

如果我们使用文件进行元数据跟踪，则不适用这些限制。

## 还有更多...

我们还可以使用 CSS 样式文本。如前所述，VTT 文件可以包含带有`<c.someClass>`的轨道，以进行更精细的样式设置，但在一般情况下，我们希望对整个轨道应用样式。可以对所有提示应用样式：

```html
::cue  {
        color: black;
        text-transform: lowercase;
        font-family: "Comic Sans";
}
```

但是，通过将他们的字幕设置为 Comic Sans，您可能会使用户感到疏远。

过去的提示`::cue:past{}`和`::cue:future{}`也有选择器，对于制作卡拉 OK 式的渲染很有用。我们还可以使用`::cue(selector)`伪选择器来定位匹配某些条件的节点。

并非所有功能在现代浏览器中都完全可用，目前写作时最兼容的是 Chrome，因此对于其他浏览器来说，使用 polyfill 是一个好主意。一个这样的库是[`captionatorjs.com/`](http://captionatorjs.com/)，它为所有现代浏览器添加了支持。除了为 WebVTT 添加支持外，它还支持格式如`.sub`、`.srt`和 YouTube 的`.sbv`。

还有另一种为视频轨道开发的格式。它的名字是**定时文本标记语言**（**TTML**）1.0 [`www.w3.org/TR/ttaf1-dfxp/`](http://www.w3.org/TR/ttaf1-dfxp/)，目前只有 IE 支持，没有计划在其他浏览器中获得支持。这个标准更复杂，基于 XML，因此更加冗长。

# 嵌入多媒体

媒体元素可以与其他元素合作并组合在一起。各种 CSS 属性可以应用于元素，并且有选项将视频与 SVG 组合。我们可以在画布元素中嵌入视频，并对渲染的图像应用处理。

在这个示例中，我们将创建一个简单的情况，其中我们在画布中嵌入一个视频。

## 准备工作

在这个示例中，我们将需要一个视频用于我们的视频元素，另一个要求是视频具有跨域资源共享支持，或者位于我们的本地服务器上。确保这一点的最简单方法是使用我们本地运行的服务器上的视频。

### 注意

在[`www.spacetelescope.org/videos/astro_bw/`](http://www.spacetelescope.org/videos/astro_bw/)的 NASA 和 ESA 提供了许多不同格式的视频。

## 如何做到...

我们将通过以下步骤在画布元素上渲染视频：

1.  首先从 HTML 文件开始，我们添加一个视频元素和一个画布：

```html
      <video id="myVideo" width="640" height="360" poster="poster.png" controls preload>
          Video not supported
        <source src="img/video.mp4" type="video/mp4" />
      </video>
        <canvas id="myCanvas" width="640" height="360"> </canvas>
        <button id="start">start showing canvas </button>
    <script src="img/example.js"> </script>
```

1.  我们的 JavaScript 代码示例将附加事件处理程序，以在画布元素上开始渲染视频的灰度版本：

```html
(function (){
  var button = document.getElementById('start'),
      video = document.getElementById('myVideo'),
      canvas = document.getElementById('myCanvas');

  button.addEventListener("click", function() {
    console.log('started drawing video');
    drawVideo();
  },false);

  function drawVideo(){
   var context = canvas.getContext('2d');
   // 0,0 means to right corner
  context.drawImage(video, 0, 0);
   var pixels = context.getImageData(0,0,640,480);
   pixels = toGrayScale(pixels);
   context.putImageData(pixels,0,0);
   // re-draw
   setTimeout(drawVideo,10);
  }

  function toGrayScale(pixels) {
    var d = pixels.data;
    for (var i=0; i<d.length; i+=4) {
      var r = d[i],
          g = d[i+1],
          b = d[i+2],
          v = 0.2126*r + 0.7152*g + 0.0722*b;
      d[i] = d[i+1] = d[i+2] = v
    }
    return pixels;
  };
}())
```

我们应该有一个运行的示例。这里的另一个附加说明是，我们的原始视频应该是彩色的，以便注意到差异。

## 它是如何工作的...

视频元素应该在这一点上是清晰的，至于画布，我们将从限制开始。在画布上绘制图像有 CORS 限制。这种安全约束实际上是有道理的，因为我们正在从图像中读取数据并根据此执行代码。这可能会被一些恶意来源利用，因此添加了这些约束。

使用`canvas.getContext('2d')`，我们可以获得一个绘图上下文，可以在其中绘制来自视频元素的当前图像。在绘制图像时，我们可以修改单个像素。这使我们有可能在视频上创建滤镜。

对于我们的示例，我们创建了一个简单的灰度滤镜。滤镜函数`toGrayScale`遍历像素数据，因为每三个值代表 RGB 中像素的颜色，我们读取它们的数据并创建一个调整后的值：

```html
  v = 0.2126*r + 0.7152*g + 0.0722*b;
```

接下来，我们将调整后的值应用于所有三个值。这些魔术数字被选择为了补偿红色和蓝色值，因为人眼对它们的平均值不太敏感。我们可以在这里使用三个值的平均值，结果会类似。

### 注意

如果您对其他滤镜感兴趣，可以在[`www.html5rocks.com/en/tutorials/canvas/imagefilters/`](http://www.html5rocks.com/en/tutorials/canvas/imagefilters/)上找到一篇关于这个主题的好文章，这些滤镜适用于图像，但同样适用于视频。

## 还有更多...

另一个值得一看的有趣演示是类似立方体的视频播放器，[`html5playbook.appspot.com/#Cube`](http://html5playbook.appspot.com/#Cube)，它使用各种不同的方式来创建酷炫的效果。

如果您对在 HTML5 应用程序中处理和合成音频感兴趣，可以在[`www.w3.org/TR/webaudio/`](http://www.w3.org/TR/webaudio/)上找到一个新的高级 API，可以实现这一点。

# 使用 HTML5 音频将文本转换为语音

如果我们今天要构建基于网络的导航应用程序，大部分组件已经可以使用。有 Google 地图或开放街道地图组件来显示地图，以及提供驾驶路线的 API 服务。

但是关于基于语音的导航指引呢？那不是需要另一个将文本转换为语音的 API 服务吗？

由于 HTML5 音频和 Emscripten（一个 C 到 JavaScript 编译器），我们现在可以在浏览器中完全使用名为 espeak 的免费文本到语音引擎。

在这个例子中，我们将使用 espeak 来生成用户在简单页面上输入的文本。大部分工作将包括准备工作-我们需要设置`espeak.js`。

## 准备好了

我们需要从([`github.com/html5-ds-book/speak-js`](http://github.com/html5-ds-book/speak-js))下载 speak.js。单击下载 zip 按钮并将存档下载到新创建的文件夹中。在该文件夹中提取存档-它应该创建一个名为`speak-js-master`的子文件夹。

## 如何做...

执行以下步骤：

1.  创建包含文本输入字段和“说话”按钮的页面`index.html`：

```html
<!doctype html>
<html>
  <head>
    <script src="img/jquery.min.js"></script>
    <script src="img/speakClient.js"></script>
    <script src="img/example.js"></script>
    <meta charset="utf8">    
  </head>
  <body>
    <div id="audio"></div>
    <input type="text" id="text" value="" placeholder="Enter text here">
    <button id="speak">Speak</button>
  </body>
</html>
```

1.  创建`example.js`并为按钮添加点击操作：

```html
$(function() {
    $("#speak").on('click', function(){
        speak($("#text").val());
    });
});
```

1.  从命令行安装`http-server`（如果尚未安装），然后启动服务器：

```html
npm install -g http-server
http-server
```

1.  在浏览器中打开[`localhost:8080`](http://localhost:8080)并测试演示。

## 它是如何工作的...

将文本转换为语音的引擎是 eSpeak ([`espeak.sourceforge.net/`](http://espeak.sourceforge.net/))。这个引擎是用 C 编写的，然而，浏览器原生支持的唯一语言是 JavaScript。我们如何在浏览器中使用这个引擎？

Emscripten 是一个旨在解决这一限制的编译器。它接受由 LLVM 编译器从 C 或 C++源代码生成的 LLVM 字节码，并将其转换为 JavaScript。Emscripen 利用了许多现代 JavaScript 特性，如类型化数组，并依赖于现代优化 JavaScript JIT 编译器的出色性能。

为了避免阻塞浏览器，语音生成器是从在`speakClient.js`中创建的 Web Worker 中调用的。生成的 WAV 数据由工作线程传回，转换为 base64 编码，并作为数据 URL 传递给新创建的音频元素。然后，该元素被附加到页面上的#audio 元素上，并通过调用`play`方法来激活播放。

## 还有更多...

Espeak 根据 GNU GPL v3 许可证授权。因此，它可能不适用于专有项目。

有关 Emscripten 的更多信息可以在 Emscripten 维基上找到：[`github.com/kripken/emscripten/wiki`](https://github.com/kripken/emscripten/wiki)。


# 附录 A. 安装 Node.js 和使用 npm

# 介绍

Node.js 是建立在 Google Chrome 的 V8 JavaScript 引擎之上的事件驱动平台。该平台为 V8 实现了完全非阻塞的 I/O，并主要用于构建实时 I/O 密集型的 Web 应用程序。

Node.js 安装程序提供以下两个主要组件：

+   node 二进制文件，可用于运行为该平台编写的 JavaScript 文件

+   node 包管理器**npm**，可用于安装由 node 社区编写的 node 库和工具

# 安装 Node.js

Node.js 的安装程序和分发程序可以在其官方网站[`nodejs.org/`](http://nodejs.org/)上找到。安装过程因操作系统而异。

在 Windows 上，提供了两个基于 MSI 的安装程序，一个用于 32 位操作系统，另一个用于 64 位操作系统。要在 Windows 上安装 Node.js，只需下载并执行安装程序。

对于 Mac OS X，同一位置提供了一个`pkg`安装程序；下载并运行 PKG 文件将允许您使用 Apple 安装程序安装 Node.js。

在 Linux 上，安装过程取决于发行版。许多流行发行版的说明可在 node 维基上找到[`github.com/joyent/node/wiki/Installing-Node.js-via-package-manager`](https://github.com/joyent/node/wiki/Installing-Node.js-via-package-manager)。

# 使用 npm

Node.js 安装程序附带了 node 包管理器 npm。npm 用于命令行；要使用它，我们需要运行一个终端程序（命令提示符）。

在 Windows 上，我们可以使用基本的`cmd.exe`，或者我们可以从[`sourceforge.net/projects/console/`](http://sourceforge.net/projects/console/)下载并安装 Console。

在 Mac OS X 上，`Terminal.app`可用于运行命令。

在 Linux 上，使用您喜欢的终端。Ubuntu Linux 上的默认终端是 gnome 终端。

打开终端并输入：`npm`。此命令运行 npm 而不带任何参数。结果，npm 将打印一个列出可用子命令的一般使用概述。

## 安装本地包

让我们为名为`test`的项目创建一个空目录，转到该目录，并在那里使用 npm 安装`underscore`库。运行以下命令：

```html
mkdir test
cd test
npm install underscore

```

最后一个命令将告诉 npm 运行带有参数`underscore`的`install`子命令，这将在本地安装 underscore 包。npm 将在下载和安装包时输出一些进度信息。

在安装包时，npm 会在当前目录中创建一个名为`node_modules`的子目录。在该目录中，它会为安装的包创建另一个目录。在这种情况下，underscore 包将放置在`underscore`目录中。

## 安装全局包

一些 npm 包设计为全局安装。全局包为操作系统添加新功能。例如，可以全局安装 coffee-script 包，这将使`coffee`命令在我们的系统上可用。

要安装全局包，我们使用-g 开关。看下面的例子：

```html
npm install -g coffee-script

```

在某些系统上，需要请求管理员权限来运行此程序。您可以使用`sudo`命令来做到这一点：

```html
sudo npm install -g coffee-script

```

npm 将下载并安装 coffee-script 以及其所有依赖项。完成后，我们可以开始使用`coffee`命令，在系统上现在可用。我们现在可以运行 coffee-script 代码。假设我们想要运行一个简单的内联 hello-world 脚本；我们可以使用`-e`开关。看下面的例子：

```html
coffee -e "echo 'Hello world'"

```

要了解有关 npm 子命令的全局包的更多信息，我们可以使用 npm 的 help 子命令。例如，要了解有关`install`子命令的更多信息，请运行以下命令：

```html
npm help install

```

有关最新版本的 npm 的更多信息可以在官方 npm 文档[`npmjs.org/doc/`](https://npmjs.org/doc/)中找到。
