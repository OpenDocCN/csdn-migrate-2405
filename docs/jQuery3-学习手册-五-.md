# jQuery3 学习手册（五）

> 原文：[`zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C`](https://zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：高级 Ajax

许多 Web 应用程序需要频繁的网络通信。使用 jQuery，我们的网页可以与服务器交换信息，而无需在浏览器中加载新页面。

在第六章 *使用 Ajax 发送数据* 中，你学会了与服务器异步交互的简单方法。在这一更高级的章节中，我们将包括：

+   处理网络中断的错误处理技术

+   Ajax 和 jQuery 延迟对象系统之间的交互

+   使用缓存和节流技术来减少网络流量

+   使用传输器、预过滤器和数据类型转换器扩展 Ajax 系统的内部工作方式的方法

# 使用 Ajax 实现渐进增强

在整本书中，我们遇到了 *渐进增强* 的概念。重申一下，这一理念确保所有用户都能获得积极的用户体验，要先确保有一个可用的产品，然后再为使用现代浏览器的用户添加额外的装饰。

举例来说，我们将构建一个搜索 GitHub 代码库的表单：

```js
<form id="ajax-form" action="https://github.com/search" method="get"> 
  <fieldset> 
    <div class="text"> 
      <label for="title">Search</label> 
      <input type="text" id="title" name="q"> 
    </div> 

    <div class="actions"> 
      <button type="submit">Request</button> 
    </div> 
  </fieldset> 
</form> 

```

获取示例代码

你可以从以下 GitHub 代码库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

搜索表单是一个普通的表单元素，包括一个文本输入和一个标有请求的提交按钮：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-04-13-at-10.35.47-AM.png)

当点击该表单的请求按钮时，表单会像平常一样提交；用户的浏览器会被重定向到[`github.com/search`](https://github.com/search)，并显示结果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-27-at-4.46.23-PM.png)

然而，我们希望将这些内容加载到我们搜索页面的 `#response` 容器中，而不是离开页面。如果数据存储在与我们的搜索表单相同的服务器上，我们可以使用 `.load()` 方法提取页面的相关部分：

```js
$(() => {
  $('#ajax-form')
    .on('submit', (e) => {
      e.preventDefault();
      $('#response')
        .load(
          'https://github.com/search .container',
          $(e.target).serialize()
        );
    });
});

```

列表 13.1

然而，由于 GitHub 在不同的主机名下，浏览器的默认跨域策略将阻止这个请求的发生。

# 获取 JSONP 数据

在第六章 *使用 Ajax 发送数据* 中，我们看到 JSONP 只是 JSON 加上了允许从不同站点进行请求的服务器行为的一个附加层。当请求 JSONP 数据时，提供了一个特殊的查询字符串参数，允许请求脚本处理数据。这个参数可以被 JSONP 服务器命名任何名称；在 GitHub API 的情况下，该参数使用默认名称 `callback`。

因为使用了默认的 `callback` 名称，使得要进行 JSONP 请求唯一需要的设置就是告诉 jQuery `jsonp` 是我们期望的数据类型：

```js
$(() => {
  $('#ajax-form')
    .on('submit', (e) => {
      e.preventDefault();

      $.ajax({
        url: 'https://api.github.com/search/repositories',
        dataType: 'jsonp',
        data: { q: $('#title').val() },
        success(data) {
          console.log(data);
        }
      });
    });
}); 

```

列表 13.2

现在，我们可以在控制台中检查 JSON 数据。在这种情况下，数据是一个对象数组，每个对象描述一个 GitHub 代码库：

```js
{
  "id": 167174,
  "name": "jquery",
  "open_issues": 78,
  "open_issues_count": 78,
  "pulls_url: "https://api.github.com/repos/jquery/jquery/pulls{/number}",
  "pushed_at": "2017-03-27T15:50:12Z",
  "releases_url": "https://api.github.com/repos/jquery/jquery/releases{/id}",
  "score": 138.81496,
  "size": 27250,
  "ssh_url": "git@github.com:jquery/jquery.git",
  "stargazers_count": 44069,
  "updated_at": "2017-03-27T20:59:42Z",
  "url": "https://api.github.com/repos/jquery/jquery",
  "watchers": 44069,
  // ...
} 

```

关于一个仓库的所有我们需要显示的数据都包含在这个对象中。我们只需要适当地对其进行格式化以进行显示。为一个项目创建 HTML 有点复杂，所以我们将这一步拆分成自己的辅助函数：

```js
const buildItem = item =>
  `
    <li>
      <h3><a href="${item.html_url}">${item.name}</a></h3>
      <div>★ ${item.stargazers_count}</div>
      <div>${item.description}</div>
    </li>
  `;

```

第 13.3 节

`buildItem()`函数将 JSON 对象转换为 HTML 列表项。这包括一个指向主 GitHub 仓库页面的链接，后跟描述。

在这一点上，我们有一个函数来为单个项目创建 HTML。当我们的 Ajax 调用完成时，我们需要在每个返回的对象上调用此函数，并显示所有结果：

```js
$(() => {
  $('#ajax-form')
    .on('submit', (e) => {
      e.preventDefault();

      $.ajax({
        url: 'https://api.github.com/search/repositories',
        dataType: 'jsonp',
        data: { q: $('#title').val() },
        success(json) {
          var output = json.data.items.map(buildItem);
          output = output.length ?
          output.join('') : 'no results found';

          $('#response').html(`<ol>${output}</ol>`);
        }
      });
    });
}); 

```

第 13.4 节

现在我们有一个功能性的`success`处理程序，在搜索时，会将结果很好地显示在我们表单旁边的一列中：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-28-at-12.32.43-AM.png)

# 处理 Ajax 错误

将任何类型的网络交互引入应用程序都会带来一定程度的不确定性。用户的连接可能会在操作过程中断开，或者临时服务器问题可能会中断通信。由于这些可靠性问题，我们应该始终为最坏的情况做准备，并准备好处理错误情况。

`$.ajax()`函数可以接受一个名为`error`的回调函数，在这些情况下调用。在这个回调中，我们应该向用户提供某种反馈，指示发生了错误：

```js
$(() => {
  $('#ajax-form')
    .on('submit', (e) => {
      e.preventDefault();

      $.ajax({
        url: 'https://api.github.com/search/repositories',
        dataType: 'jsonp',
        data: { q: $('#title').val() },
        error() {
          $('#response').html('Oops. Something went wrong...');
        }
      });
    });
}); 

```

第 13.5 节

错误回调可能由多种原因触发。其中包括：

+   服务器返回了错误状态码，例如 403 Forbidden、404 Not Found 或 500 Internal Server Error。

+   服务器返回了重定向状态码，例如 301 Moved Permanently。一个例外是 304 Not Modified，它不会触发错误，因为浏览器可以正确处理这种情况。

+   服务器返回的数据无法按照指定的方式解析（例如，在`dataType`为`json`时，它不是有效的 JSON 数据）。

+   在`XMLHttpRequest`对象上调用了`.abort()`方法。

检测和响应这些条件对提供最佳用户体验非常重要。我们在第六章中看到，*通过 Ajax 发送数据*，如果有的话，错误代码是通过传递给错误回调的`jqXHR`对象的`.status`属性提供给我们的。如果合适的话，我们可以使用`jqXHR.status`的值对不同类型的错误做出不同的反应。

然而，服务器错误只有在实际观察到时才有用。有些错误会立即被检测到，但其他情况可能导致请求和最终错误响应之间的长时间延迟。

当可靠的服务器超时机制不可用时，我们可以强制执行自己的客户端请求超时。通过向超时选项提供以毫秒为单位的时间，我们告诉`$.ajax()`在收到响应之前超过该时间量时自行触发`.abort()`：

```js
$.ajax({
  url: 'https://api.github.com/search/repositories',
  dataType: 'jsonp',
  data: { q: $('#title').val() },
  timeout: 10000,
  error() {
    $('#response').html('Oops. Something went wrong...');
  }
});

```

第 13.6 节

有了超时设置，我们可以确保在 10 秒内要么加载数据，要么用户会收到错误消息。

# 使用 jqXHR 对象

当发出 Ajax 请求时，jQuery 会确定获取数据的最佳机制。这个传输可以是标准的`XMLHttpRequest`对象，Microsoft ActiveX 的`XMLHTTP`对象或者`<script>`标签。

因为使用的传输方式可能会因请求而异，所以我们需要一个通用接口来与通信进行交互。`jqXHR`对象为我们提供了这个接口。当使用该传输方式时，它是`XMLHttpRequest`对象的包装器，在其他情况下，它会尽可能模拟`XMLHttpRequest`。它暴露的属性和方法包括：

+   `.responseText`或`.responseXML`，包含返回的数据

+   `.status`和`.statusText`，包含状态代码和描述

+   `.setRequestHeader()`以操作与请求一起发送的 HTTP 头部。

+   `.abort()`以过早终止事务

所有 jQuery 的 Ajax 方法都会返回这个`jqXHR`对象，因此，如果我们需要访问这些属性或方法，我们可以存储结果。

# Ajax promises

然而，比`XMLHttpRequest`接口更重要的是，`jqXHR`还充当了一个 promise。在第十一章的*高级特效*中，你了解了 deferred 对象，它允许我们设置在某些操作完成时触发回调。Ajax 调用就是这样一种操作的示例，`jqXHR`对象提供了我们从 deferred 对象的 promise 中期望的方法。

使用 promise 的方法，我们可以重写我们的`$.ajax()`调用，以替换成功和错误回调的替代语法：

```js
$.ajax({
  url: 'https://api.github.com/search/repositories',
  dataType: 'jsonp',
  data: { q: $('#title').val() },
  timeout: 10000,
}).then((json) => {
  var output = json.data.items.map(buildItem);
  output = output.length ?
    output.join('') : 'no results found';

  $('#response').html(`<ol>${output}</ol>`);
}).catch(() => {
  $('#response').html('Oops. Something went wrong...');
});

```

列表 13.7

乍一看，调用`.then()`和`.catch()`似乎并不比我们之前使用的回调语法更有用。然而，promise 方法提供了几个优点。首先，这些方法可以被多次调用以添加更多的处理程序（handlers）（如果需要的话）。其次，如果我们将`$.ajax()`调用的结果存储在一个常量中，我们可以稍后调用处理程序，如果这样做能够使我们的代码结构更易读。第三，如果在附加处理程序时 Ajax 操作已经完成，处理程序将立即被调用。最后，我们不应忽视使用与 jQuery 库其他部分和本机 JavaScript promises 一致的语法的可读性优势。

另一个使用 promise 方法的例子，我们可以在发出请求时添加一个加载指示器。由于我们希望在请求完成时隐藏指示器，无论成功与否，`.always()`方法将非常有用：

```js
$('#ajax-form')
  .on('submit', (e) => {
    e.preventDefault();

    $('#response')
      .addClass('loading')
      .empty();

    $.ajax({
      url: 'https://api.github.com/search/repositories',
      dataType: 'jsonp',
      data: { q: $('#title').val() },
      timeout: 10000,
    }).then((json) => {
      var output = json.data.items.map(buildItem);
      output = output.length ?
      output.join('') : 'no results found';

      $('#response').html(`<ol>${output}</ol>`);
    }).catch(() => {
      $('#response').html('Oops. Something went wrong...');
    }).always(() => {
      $('#response').removeClass('loading');
    });
}); 

```

列表 13.8

在发出 `$.ajax()` 调用之前，我们将 `loading` 类添加到响应容器中。加载完成后，我们再次将其删除。通过这样做，我们进一步增强了用户体验，因为现在有一个视觉指示器表明后台正在发生某事。

要真正掌握 promise 行为如何帮助我们，我们需要看看如果将 `$.ajax()` 调用的结果存储起来供以后使用时我们可以做什么。

# 缓存响应

如果我们需要重复使用相同的数据片段，每次都进行 Ajax 请求是低效的。为了防止这种情况，我们可以将返回的数据缓存在一个变量中。当我们需要使用某些数据时，我们可以检查数据是否已经在缓存中。如果是，我们就对这些数据采取行动。如果没有，我们需要进行 Ajax 请求，在其 `.done()` 处理程序中，我们将数据存储在缓存中并对返回的数据进行操作。

如果我们利用 promise 的特性，事情会变得相当简单：

```js
$(() => {
  const cache = new Map();

  $('#ajax-form')
    .on('submit', (e) => {
      e.preventDefault();

      const search = $('#title').val();

      if (search == '') {
        return;
      }

      $('#response')
        .addClass('loading')
        .empty();

      cache.set(search, cache.has(search) ?
        cache.get(search) :
        $.ajax({
          url: 'https://api.github.com/search/repositories',
          dataType: 'jsonp',
          data: { q: search },
          timeout: 10000,
        })
      ).get(search).then((json) => {
        var output = json.data.items.map(buildItem);
        output = output.length ?
          output.join('') : 'no results found';

        $('#response').html(`<ol>${output}</ol>`);
      }).catch(() => {
        $('#response').html('Oops. Something went wrong...');
      }).always(() => {
        $('#response').removeClass('loading');
      });
    });
}); 

```

列表 13.9

我们引入了一个名为 `cache` 的新的 `Map` 常量，用于保存我们创建的 `jqXHR` promises。这个映射的键对应于正在执行的搜索。当提交表单时，我们会查看是否已经为该键存储了一个 `jqXHR` promise。如果没有，我们像以前一样执行查询，将结果对象存储在 `api` 中。

`.then()`、`.catch()` 和 `.always()` 处理程序然后附加到 `jqXHR` promise。请注意，无论是否进行了 Ajax 请求，这都会发生。这里有两种可能的情况需要考虑。

首先，如果之前还没有发送过 Ajax 请求，就会发送 Ajax 请求。这与以前的行为完全一样：发出请求，然后我们使用 promise 方法将处理程序附加到 `jqXHR` 对象上。当服务器返回响应时，会触发适当的回调，并将结果打印到屏幕上。

另一方面，如果我们过去执行过此搜索，则 `cache` 中已经存储了 `jqXHR` promise。在这种情况下，不会执行新的搜索，但我们仍然在存储的对象上调用 promise 方法。这会将新的处理程序附加到对象上，但由于延迟对象已经解决，因此相关的处理程序会立即触发。

jQuery 延迟对象系统为我们处理了所有繁重的工作。几行代码，我们就消除了应用程序中的重复网络请求。

# 限制 Ajax 请求速率

搜索的常见功能是在用户输入时显示动态结果列表。我们可以通过将处理程序绑定到 `keyup` 事件来模拟这个“实时搜索”功能，用于我们的 jQuery API 搜索：

```js
$('#title')
  .on('keyup', (e) => {
    $(e.target.form).triggerHandler('submit');
  });

```

列表 13.10

在这里，我们只需在用户在搜索字段中键入任何内容时触发表单的提交处理程序。这可能导致快速连续发送许多请求到网络，这取决于用户输入的速度。这种行为可能会降低 JavaScript 的性能；它可能会堵塞网络连接，而服务器可能无法处理这种需求。

我们已经通过刚刚实施的请求缓存来限制请求的数量。然而，我们可以通过对请求进行限速来进一步减轻服务器的负担。在第十章中，*高级事件*，我们介绍了当我们创建一个特殊的 `throttledScroll` 事件以减少原生滚动事件触发的次数时，引入了节流的概念。在这种情况下，我们希望类似地减少活动; 这次是使用 `keyup` 事件：

```js
const searchDelay = 300;
var searchTimeout;

$('#title')
  .on('keyup', (e) => {
    clearTimeout(searchTimeout);

    searchTimeout = setTimeout(() => {
      $(e.target.form).triggerHandler('submit');
    }, searchDelay);
  });

```

列表 13.11

我们在这里使用的技术有时被称为防抖动，与我们在第十章中使用的技术有所不同。在那个例子中，我们需要我们的 `scroll` 处理程序在滚动继续时多次生效，而在这里，我们只需要在输入停止后一次发生 `keyup` 行为。为了实现这一点，我们跟踪一个 JavaScript 计时器，该计时器在用户按键时启动。每次按键都会重置该计时器，因此只有当用户停止输入指定的时间（300 毫秒）后，`submit` 处理程序才会被触发，然后执行 Ajax 请求。

# 扩展 Ajax 功能

jQuery Ajax 框架是强大的，正如我们所见，但即使如此，有时我们可能想要改变它的行为方式。毫不奇怪，它提供了多个钩子，可以被插件使用，为框架提供全新的功能。

# 数据类型转换器

在第六章中，*使用 Ajax 发送数据*，我们看到 `$.ajaxSetup()` 函数允许我们更改 `$.ajax()` 使用的默认值，从而可能影响许多 Ajax 操作只需一次语句。这个相同的函数也可以用于扩展 `$.ajax()` 可以请求和解释的数据类型范围。

举个例子，我们可以添加一个理解 YAML 数据格式的转换器。YAML（[`www.yaml.org/`](http://www.yaml.org/)）是一种流行的数据表示，许多编程语言都有实现。如果我们的代码需要与这样的替代格式交互，jQuery 允许我们将其兼容性构建到本地 Ajax 函数中。

包含 GitHub 仓库搜索条件的简单 YAML 文件：

```js
Language:
 - JavaScript
 - HTML
 - CSS
Star Count:
 - 5000+
 - 10000+
 - 20000+

```

我们可以将 jQuery 与现有的 YAML 解析器（如 Diogo Costa 的 [`code.google.com/p/javascript-yaml-parser/`](http://code.google.com/p/javascript-yaml-parser/)）结合起来，使 `$.ajax()` 也能够使用这种语言。

定义一个新的 Ajax 数据类型涉及将三个属性传递给`$.ajaxSetup()`：`accepts`、`contents`和`converters`。`accepts`属性添加要发送到服务器的头，声明服务器理解我们的脚本的特定 MIME 类型。`contents`属性处理交易的另一侧，提供一个与响应 MIME 类型匹配的正则表达式，尝试从此元数据中自动检测数据类型。最后，`converters`包含解析返回数据的实际函数：

```js
$.ajaxSetup({ 
  accepts: { 
    yaml: 'application/x-yaml, text/yaml' 
  }, 
  contents: { 
    yaml: /yaml/ 
  }, 
  converters: { 
    'text yaml': (textValue) => { 
      console.log(textValue); 
      return ''; 
    } 
  } 
}); 

$.ajax({ 
  url: 'categories.yml', 
  dataType: 'yaml' 
}); 

```

列表 13.12

*列表 13.12*中的部分实现使用`$.ajax()`来读取 YAML 文件，并将其数据类型声明为`yaml`。因为传入的数据被解析为`text`，jQuery 需要一种方法将一个数据类型转换为另一个。`'text yaml'`的`converters`键告诉 jQuery，此转换函数将接受作为`text`接收的数据，并将其重新解释为`yaml`。

在转换函数内部，我们只是记录文本内容以确保函数被正确调用。要执行转换，我们需要加载第三方 YAML 解析库（`yaml.js`）并调用其方法：

```js
$.ajaxSetup({
  accepts: {
    yaml: 'application/x-yaml, text/yaml'
  },
  contents: {
    yaml: /yaml/
  },
  converters: {
    'text yaml': (textValue) => YAML.eval(textValue)
  }
});

Promise.all([
  $.getScript('yaml.js')
    .then(() =>
      $.ajax({
        url: 'categories.yml',
        dataType: 'yaml'
      })),
  $.ready
]).then(([data]) => {
  const output = Object.keys(data).reduce((result, key) =>
    result.concat(
      `<li><strong>${key}</strong></li>`,
      data[key].map(i => `<li> <a href="#">${i}</a></li>`)
    ),
    []
  ).join('');

  $('#categories')
    .removeClass('hide')
    .html(`<ul>${output}</ul>`);
}); 

```

列表 13.13

`yaml.js`文件包含一个名为`YAML`的对象，带有一个`.eval()`方法。我们使用这个方法来解析传入的文本并返回结果，这是一个包含`categories.yml`文件所有数据的 JavaScript 对象，以便轻松遍历结构。由于我们正在加载的文件包含 GitHub 仓库搜索字段，我们使用解析后的结构打印出顶级字段，稍后将允许用户通过点击它们来过滤其搜索结果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-28-at-4.27.45-PM.png)

Ajax 操作可能会立即运行，而无需访问 DOM，但一旦我们从中获得结果，我们需要等待 DOM 可用才能继续。将代码结构化为使用`Promise.all()`允许尽早执行网络调用，提高用户对页面加载时间的感知。

接下来，我们需要处理类别链接的点击：

```js
$(document)
  .on('click', '#categories a', (e) => {
    e.preventDefault();

    $(e.target)
      .parent()
      .toggleClass('active')
      .siblings('.active')
      .removeClass('active');
    $('#ajax-form')
      .triggerHandler('submit');
  }); 

```

列表 13.14

通过将我们的`click`处理程序绑定到`document`并依赖事件委托，我们避免了一些昂贵的重复工作，而且我们也可以立即运行代码，而不必担心等待 Ajax 调用完成。

在处理程序中，我们确保正确的类别被突出显示，然后触发表单上的`submit`处理程序。我们还没有让表单理解我们的类别列表，但高亮显示已经起作用：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-30-at-12.05.37-PM.png)

最后，我们需要更新表单的`submit`处理程序以尊重活动类别（如果有的话）：

```js
$('#ajax-form')
  .on('submit', (e) => {
    e.preventDefault();

    const search = [
      $('#title').val(),
      new Map([
        ['JavaScript', 'language:"JavaScript"'],
        ['HTML', 'language:"HTML"'],
        ['CSS', 'language:"CSS"'],
        ['5000+', 'stars:">=5000"'],
        ['10000+', 'stars:">=10000"'],
        ['20000+', 'stars:">=20000"'],
        ['', '']
      ]).get($.trim(
        $('#categories')
          .find('li.active')
          .text()
      ))
    ].join('');

    if (search == '' && category == '') {
      return;
    }

    $('#response')
      .addClass('loading')
      .empty();

    cache.set(search, cache.has(search) ?
      cache.get(search) :
      $.ajax({
        url: 'https://api.github.com/search/repositories',
        dataType: 'jsonp',
        data: { q: search },
        timeout: 10000,
      })).get(search).then((json) => {
        var output = json.data.items.map(buildItem);
        output = output.length ?
          output.join('') : 'no results found';

        $('#response').html(`<ol>${output}</ol>`);
      }).catch(() => {
        $('#response').html('Oops. Something went wrong...');
      }).always(() => {
        $('#response').removeClass('loading');
      });
  }); 

```

列表 13.15

现在，我们不仅仅获取搜索字段的值，还获取活动语言或星星数量的文本，通过 Ajax 调用传递这两个信息。我们使用`Map`实例将链接文本映射到适当的 GitHub API 语法。

现在，我们可以按主要语言或按星星数量查看仓库。一旦我们应用了这些过滤器，我们可以通过在搜索框中输入来进一步细化显示的内容：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-30-at-12.29.13-PM.png)

每当我们需要支持 jQuery 尚未处理的新数据类型时，我们可以以类似于此 YAML 示例的方式定义它们。因此，我们可以根据我们的项目特定需求来塑造 jQuery 的 Ajax 库。

# 添加 Ajax 预过滤器

`$.ajaxPrefilter()`函数可以添加预过滤器，这是回调函数，允许我们在发送请求之前对其进行操作。预过滤器在`$.ajax()`更改或使用任何选项之前调用，因此它们是更改选项或对新的自定义选项进行操作的好地方。

预过滤器还可以通过简单地返回要使用的新数据类型的名称来操作请求的数据类型。在我们的 YAML 示例中，我们指定了`yaml`作为数据类型，因为我们不希望依赖服务器提供正确的响应 MIME 类型。但是，我们可以提供一个预过滤器，如果 URL 中包含相应的文件扩展名（`.yml`），则确保数据类型为`yaml`：

```js
$.ajaxPrefilter(({ url }) =>
  /.yml$/.test(url) ? 'yaml' : null
);

$.getScript('yaml.js')
  .then(() =>
    $.ajax({ url: 'categories.yml' })
  ); 

```

列表 13.16

一个简短的正则表达式测试`options.url`末尾是否是`.yml`，如果是，则将数据类型定义为`yaml`。有了这个预过滤器，我们用于获取 YAML 文档的 Ajax 调用不再需要明确地定义其数据类型。

# 定义替代传输

我们已经看到 jQuery 使用`XMLHttpRequest`、`ActiveX`或`<script>`标签来适当处理 Ajax 事务。如果愿意，我们可以通过新的传输进一步扩展这个工具库。

**传输**是一个处理实际 Ajax 数据传输的对象。新的传输被定义为工厂函数，返回一个包含`.send()`和`.abort()`方法的对象。`.send()`方法负责发出请求，处理响应，并通过回调函数将数据发送回来。`.abort()`方法应立即停止请求。

自定义传输可以，例如，使用`<img>`元素来获取外部数据。这使得图像加载可以像其他 Ajax 请求一样处理，这有助于使我们的代码在内部更一致。创建这样一个传输所需的 JavaScript 代码有点复杂，所以我们将先看一下最终的产品，然后再讨论它的组成部分：

```js
$.ajaxTransport('img', ({ url }) => {
  var $img, img, prop;

  return {
    send(headers, complete) {
      const callback = (success) => {
        if (success) {
          complete(200, 'OK', { img });
        } else {
          $img.remove();
          complete(404, 'Not Found');
        }
      }

      $img = $('<img>', { src: url });
      img = $img[0];
      prop = typeof img.naturalWidth === 'undefined' ?
        'width' : 'naturalWidth';

      if (img.complete) {
        callback(!!img[prop]);
      } else {
        $img.on('load error', ({ type }) => {
          callback(type == 'load');
        });
      }
    },

    abort() {
      if ($img) {
        $img.remove();
      } 
    }
  };
}); 

```

列表 13.17

在定义传输时，我们首先将数据类型名称传递给`$.ajaxTransport()`。这告诉 jQuery 何时使用我们的传输而不是内置机制。然后，我们提供一个返回包含适当的`.send()`和`.abort()`方法的新传输对象的函数。

对于我们的`img`传输，`.send()`方法需要创建一个新的`<img>`元素，我们给它一个`src`属性。这个属性的值来自于 jQuery 从`$.ajax()`调用中传递过来的`url`。浏览器将通过加载引用的图像文件的`<img>`元素的创建做出反应，所以我们只需检测这个加载何时完成并触发完成回调。

如果我们希望处理各种浏览器和版本的图像加载完成的情况，正确检测图像加载完成就会变得棘手。在某些浏览器中，我们可以简单地将`load`和`error`事件处理程序附加到图像元素上。但在其他浏览器中，当图像被缓存时，`load`和`error`不会按预期触发。

我们 *清单 13.17* 中的代码处理了这些不同的浏览器行为，通过检查`.complete`、`.width`和`.naturalWidth`属性的值，适当地处理每个浏览器的情况。一旦我们检测到图像加载已经成功完成或失败，我们调用`callback()`函数，该函数反过来调用`.send()`传递的`complete()`函数。这允许`$.ajax()`对图像加载做出反应。

处理中止加载要简单得多。我们的`.abort()`方法只需通过移除已创建的`<img>`元素来清理`send()`后的情况。

接下来，我们需要编写使用新传输的`$.ajax()`调用：

```js
$.ajax({
  url: 'missing.jpg',
  dataType: 'img'
}).then((img) => {
  $('<div/>', {
    id: 'picture',
    html: img
  }).appendTo('body');
}).catch((xhr, textStatus, msg) => {
  $('<div/>', {
    id: 'picture',
    html: `${textStatus}: ${msg}`
  }).appendTo('body');
}); 

```

清单 13.18

要使用特定的传输，`$.ajax()`需要给出相应的`dataType`值。然后，成功和失败处理程序需要考虑到传递给它们的数据类型。我们的`img`传输在成功时返回一个`<img>`DOM 元素，因此我们的`.done()`处理程序将使用该元素作为新创建的`<div>`元素的 HTML 内容，该元素将插入到文档中。

然而在这种情况下，指定的图像文件（`missing.jpg`）实际上不存在。我们通过适当的`.catch()`处理程序考虑了此种可能性，它将错误消息插入`<div>`，在这个`<div>`中原本应该放置图像：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_13_07.png)

我们可以通过引用存在的图像来纠正这个错误：

```js
$.ajax({
  url: 'sunset.jpg',
  dataType: 'img'
}).then((img) => {
  $('<div/>', {
    id: 'picture',
    html: img
  }).appendTo('body');
}).catch((xhr, textStatus, msg) => {
  $('<div/>', {
    id: 'picture',
    html: `${textStatus}: ${msg}`
  }).appendTo('body');
}); 

```

清单 13.19

现在，我们的传输已成功加载图像，我们在页面上看到了这个结果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_13_08.png)

创建新传输是不常见的，但即使在这种情况下，jQuery 的 Ajax 功能也可以满足我们的需求。例如，将图像加载视为一个 promise 的能力意味着我们可以使用这个 Ajax 调用来与其他异步行为同步，使用`Promise.all()`。

# 总结

在本章的最后，我们深入了解了 jQuery 的 Ajax 框架。现在我们可以在单个页面上打造无缝的用户体验，在需要时获取外部资源，并且注意到错误处理、缓存和节流的相关问题。我们探讨了 Ajax 框架的内部运作细节，包括 promises，transports，prefilters 和 converters。你还学会了如何扩展这些机制来满足我们脚本的需求。

# 进一步阅读

完整的*Ajax 方法*列表可以在本书的 附录 B *快速参考* 中找到，或者在官方 jQuery 文档 [`api.jquery.com/`](http://api.jquery.com/) 上找到。

# 练习

挑战练习可能需要使用官方 jQuery 文档 [`api.jquery.com/`](http://api.jquery.com/) ：

1.  修改`buildItem()`函数，使其包含每个 jQuery 方法的长描述。

1.  这里有一个挑战给你。向页面添加指向 Flickr 公共照片搜索([`www.flickr.com/search/`](http://www.flickr.com/search/))的表单，并确保它具有`<input name="q">`和一个提交按钮。使用渐进增强从 Flickr 的 JSONP 反馈服务 [`api.flickr.com/services/feeds/photos_public.gne`](http://api.flickr.com/services/feeds/photos_public.gne) 检索照片，然后将它们插入页面的内容区域。向这个服务发送数据时，使用`tags`而不是`q`，并将`format`设置为`json`。还要注意，该服务希望 JSONP 回调名称为`jsoncallback`，而不是`callback`。

1.  这里有另一个挑战给你。在 Flickr 请求产生`parsererror`时为其添加错误处理。通过将 JSONP 回调名称设置回`callback`来测试它。


# 附录 A：使用 QUnit 测试 JavaScript

在本书中，我们写了很多 JavaScript 代码，我们已经看到了 jQuery 如何帮助我们相对轻松地编写这些代码的许多方式。然而，每当我们添加新功能时，我们都必须额外的手动检查我们的网页，以确保一切如预期般运作。虽然这个过程对于简单的任务可能有效，但随着项目规模和复杂性的增长，手动测试可能变得相当繁琐。新的要求可能引入*回归错误*，破坏先前良好运作的脚本部分。很容易忽略这些与最新代码更改无关的错误，因为我们自然只测试我们刚刚完成的部分。

我们需要的是一个自动化系统来为我们运行测试。**QUnit** 测试框架就是这样一个系统。虽然有许多其他的测试框架，它们都有各自的好处，但我们推荐在大多数 jQuery 项目中使用 QUnit，因为它是由 jQuery 项目编写和维护的。事实上，jQuery 本身就使用 QUnit。在这个附录中，我们将介绍：

+   如何在项目中设置 QUnit 测试框架

+   单元测试组织以帮助代码覆盖和维护

+   各种 QUnit 可用的测试类型

+   保证测试可靠指示成功代码的常见实践

+   对 QUnit 所提供的以外的其他测试类型的建议

# 下载 QUnit

QUnit 框架可从官方 QUnit 网站[`qunitjs.com/`](http://qunitjs.com/)下载。在那里，我们可以找到到稳定版本的链接（当前为 2.3.0）以及开发版本（qunit-git）。这两个版本都包括一个样式表以及用于格式化测试输出的 JavaScript 文件。

# 设置文档

一旦我们把 QUnit 文件放好，我们就可以设置测试 HTML 文档了。在一个典型的项目中，这个文件通常会命名为 `index.html`，并放在与 `qunit.js` 和 `qunit.css` 相同的测试子文件夹中。然而，为了演示，我们将把它放在父目录中。

文档的 `<head>` 元素包含了一个用于 CSS 文件的 `<link>` 标签和用于 jQuery、QUnit、我们将进行测试的 JavaScript 文件（`A.js`）以及测试本身（`listings/A.*.js`）的 `<script>` 标签。`<body>` 标签包含了两个主要元素用于运行和显示测试结果。

要演示 QUnit，我们将使用第二章，*选择元素*，和第六章，*使用 Ajax 发送数据*中的部分内容：

```js
<!DOCTYPE html> 
<html> 
<head> 
  <meta charset="utf-8"> 
  <title>Appendix A Tests</title> 
  <link rel="stylesheet" href="qunit.css" media="screen"> 
  <script src="img/jquery.js"></script> 
  <script src="img/qunit.js"></script> 
  <script src="img/A.js"></script> 
  <script src="img/test.js"></script> 
</head> 
<body> 
  <div id="qunit"></div> 
  <div id="qunit-fixture"> 
    <!-- Test Markup Goes Here --> 
  </div> 
</body> 
</html> 

```

自第二章，*选择元素*之后，我们要测试的代码取决于 DOM；我们希望测试标记与我们在实际页面上使用的内容匹配。我们可以简单地复制并粘贴我们在第二章中使用的 HTML 内容，这将替换`<!--测试标记在这里-->`注释。

# 组织测试

QUnit 提供两个级别的测试分组，其名称分别根据其各自的函数调用命名：`QUnit.module()`和`QUnit.test()`。**模块**就像一个将运行测试的一般类别；测试实际上是*一组*测试；该函数取一个回调，在其中运行所有该测试的特定**单元测试**。我们将通过章节主题对我们的测试进行分组，并将代码放在我们的`test/test.js`文件中：

```js
QUnit.module('Selecting');

QUnit.test('Child Selector', (assert) => {
  assert.expect(0);
});

QUnit.test('Attribute Selectors', (assert) => {
  assert.expect(0);
});

QUnit.module('Ajax'); 

```

列表 A.1

不需要使用此测试结构设置文件，但心中有一些整体结构是很好的。除了`QUnit.module()`和`QUnit.test()`分组外，我们还需要告诉测试要期望多少断言。由于我们只是在组织，我们需要告诉测试尚未有任何断言（`assert.expect(0)`）以便进行测试。

请注意，我们的模块和测试不需要放在`$(() => {})`调用内，因为 QUnit 默认会等到窗口加载完毕后才开始运行测试。通过这个非常简单的设置，加载测试 HTML 会导致页面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/3145OS_AppB_01.png)

请注意，模块名称为浅蓝色，测试名称为深蓝色。单击任一将展开该组测试的结果，这些结果在通过该组的所有测试时，默认情况下是折叠的。Ajax 模块尚未出现，因为我们还没有为其编写任何测试。

# 添加和运行测试

在**测试驱动开发**中，我们在编写代码之前编写测试。这样，当测试失败时，我们可以添加新代码，然后看到测试通过，验证我们的更改具有预期效果。

让我们从测试我们在第二章中使用的子选择器开始，*选择元素*，向所有`<ul id="selected-plays">`的子元素`<li>`添加`horizontal`类：

```js
QUnit.test('Child Selector', (assert) => {
  assert.expect(1);
  const topLis = $('#selected-plays > li.horizontal');
  assert.equal(topLis.length, 3, 'Top LIs have horizontal class');
}); 

```

列表 A.2

我们正在测试我们选择页面上元素的能力，因此我们使用断言 `assert.equal()` 测试来比较顶级`<li>`元素的数量是否等于数字`3`。如果两者相等，测试成功，并添加到通过测试的数量中。如果不相等，则测试失败：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-31-at-2.39.49-PM.png)

当然，测试失败了，因为我们还没有编写代码将`horizontal`类添加到元素中。尽管如此，添加该代码非常简单。我们在页面的主脚本文件中执行，我们将其称为`A.js`：

```js
$(() => { 
  $('#selected-plays > li').addClass('horizontal'); 
}); 

```

列表 A.3

现在运行测试时，测试如预期般通过：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-31-at-4.19.27-PM.png)

现在选择：子选择器测试显示圆括号中的 1，表示总测试数为一。 现在我们可以进一步测试，通过添加一些属性选择器测试：

```js
QUnit.module('Selecting', { 
  beforeEach() { 
    this.topLis = $('#selected-plays > li.horizontal'); 
  } 
}); 

QUnit.test('Child Selector', function(assert) { 
  assert.expect(1); 
  assert.equal(this.topLis.length, 3,  
    'Top LIs have horizontal class'); 
}); 

QUnit.test('Attribute Selectors', function(assert) { 
  assert.expect(2); 
  assert.ok(this.topLis.find('.mailto').length == 1, 'a.mailto'); 
  assert.equal(this.topLis.find('.pdflink').length, 1, 'a.pdflink'); 
}); 

```

A.4 清单

在这里，我们介绍了另一种类型的测试：`ok()`。 这个函数接受两个参数：一个表达式，如果成功则应评估为 `true`，以及一个描述。 还要注意，我们将本地的 `topLis` 变量从子选择器测试中移到了*清单 A.2*中，并将其放入模块的`beforeEach()`回调函数中。 `QUnit.module()` 函数接受一个可选的第二个参数，这是一个普通对象，可以包含一个 `beforeEach()` 和一个 `afterEach()` 函数。 在这些函数内部，我们可以使用`this`作为模块所有测试的共享上下文。

再次，如果没有相应的工作代码，新测试将失败：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-31-at-5.18.31-PM.png)

在这里，我们可以看到`assert.ok()`测试和`assert.equal()`测试之间的测试失败输出的差异，`assert.ok()`测试仅显示测试的标签（a.mailto）和源，而`assert.equal()`测试还详细说明了预期的结果（而不总是期望`true`）。 因为它为测试失败提供了更多信息，通常优先使用`assert.equal()`而不是`assert.ok()`。

让我们包含必要的代码：

```js
$(() => { 
  $('#selected-plays > li').addClass('horizontal'); 
  $('a[href^="mailto:"]').addClass('mailto'); 
  $('a[href$=".pdf"]').addClass('pdflink'); 
}); 

```

A.5 清单

现在两个测试通过了，我们可以通过扩展集来看到：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-03-31-at-5.36.30-PM.png)

在失败时，`assert.equal()` 提供了比`assert.ok()`更多的信息。 成功时，两个测试只显示标签。

# 异步测试

测试异步代码，如 Ajax 请求，提供了额外的挑战。 其余测试必须在异步测试发生时暂停，然后在完成时重新开始。 这种类型的场景现在非常熟悉； 我们在特效队列、Ajax 回调函数和 promise 对象中看到了这样的异步操作。 QUnit 中的异步测试与常规的 `QUnit.test()` 函数类似，只是它将暂停测试的运行，直到我们使用由 `assert.async()` 函数创建的函数调用恢复它们：

```js
QUnit.test('JSON', (assert) => {
  assert.expect(0);
  const done = assert.async();

  $.getJSON('A.json', (json, textStatus) => {
    // add tests here
  }).always(done);
});

```

A.6 清单

这里我们只是从`a.json`请求 JSON，并且在请求完成后允许测试继续，无论成功与否，都会在`.always()`回调函数内调用`done()`。 对于实际的测试，我们将检查`textStatus`值以确保请求成功，并检查响应 JSON 数组中一个对象的值：

```js
QUnit.test('JSON', (assert) => {
  const backbite = {
    term: 'BACKBITE',
    part: 'v.t.',
    definition: 'To speak of a man as you find him when he can't find you.'
  };

  assert.expect(2);
  const done = assert.async();

  $.getJSON('A.json', (json, textStatus) => {
    assert.equal(textStatus, 'success', 'Request successful');
    assert.deepEqual(
      json[1],
      backbite,
      'result array matches "backbite" map'
    );
  }).always(done);
}); 

```

A.7 清单

为了测试响应值，我们使用另一个测试函数：`assert.deepEqual()`。通常当比较两个对象时，除非它们实际上指向内存中的相同位置，否则它们被认为不相等。如果我们想要比较对象的内容，应使用 `assert.deepEqual()`。这个函数会遍历两个对象，确保它们具有相同的属性，并且这些属性具有相同的值。

# 其他类型的测试

QUnit 还配备了其他一些测试函数。其中有些函数，比如`notEqual()`和`notDeepEqual()`，只是我们使用的函数的反义，而另一些函数，比如`strictEqual()`和`throws()`，具有更明显的用途。有关这些函数的更多信息，以及有关 QUnit 的概述和其他示例的详细信息，可以在 QUnit 网站([`qunitjs.com/`](http://qunitjs.com/))以及 QUnit API 网站([`api.qunitjs.com/`](http://api.qunitjs.com/))上找到。

# 实际考虑

本附录中的示例必须是简单的。在实践中，我们可以编写确保相当复杂行为的正确操作的测试。

理想情况下，我们尽量使我们的测试尽可能简洁和简单，即使它们测试的行为很复杂。通过为一些特定的场景编写测试，我们可以相当确定地确保我们完全测试了行为，即使我们并没有针对每一种可能的输入情况编写测试。

然而，即使我们已经为其编写了测试，可能会在我们的代码中观察到一个错误。当测试通过但出现错误时，正确的响应不是立即修复问题，而是首先为失败的行为编写一个新的测试。这样，我们不仅可以在纠正代码时验证问题是否解决，还可以引入额外的测试，帮助我们避免将来出现回归问题。

QUnit 除了**单元测试**之外，还可以用于**功能测试**。单元测试旨在确认代码单元（方法和函数）的正确运行，而功能测试则旨在确保用户输入的适当接口响应。例如，在第十二章中的*高级 DOM 操作*中，我们实现了表格排序行为。我们可以为排序方法编写一个单元测试，验证一旦调用方法表格就排序了。另外，功能测试可以模拟用户点击表头，然后观察结果以检查表格是否确实已排序。

与 QUnit 配合使用的功能测试框架，例如 dominator.js ([`mwbrooks.github.io/dominator.js/`](http://mwbrooks.github.io/dominator.js/)) 和 FuncUnit ([`funcunit.com/`](http://funcunit.com/))，可以帮助更轻松地编写功能测试和模拟事件。为了在各种浏览器中进一步自动化测试，可以将 **Selenium** ([`seleniumhq.org/`](http://seleniumhq.org/)) 套件与这些框架一起使用。

为了确保我们的测试结果一致，我们需要使用可靠且不变的样本数据进行工作。当测试应用于动态站点的 jQuery 代码时，捕获和存储页面的静态版本以运行测试可能是有益的。这种方法还可以隔离您的代码组件，使得更容易确定错误是由服务器端代码还是浏览器端代码引起的。

# 进一步阅读

这些考虑肯定不是一个详尽的列表。测试驱动开发是一个深入的话题，一个简短的附录是不足以完全涵盖的。一些在线资源包含有关该主题的更多信息，包括：

+   单元测试介绍 ([`qunitjs.com/intro/`](http://qunitjs.com/intro/))。

+   *QUnit Cookbook* ([`qunitjs.com/cookbook/`](http://qunitjs.com/cookbook/))。

+   Elijah Manor 撰写的 *jQuery 测试驱动开发* 文章 ([`msdn.microsoft.com/en-us/scriptjunkie/ff452703.aspx`](http://msdn.microsoft.com/en-us/scriptjunkie/ff452703.aspx))。

+   *单元测试最佳实践* 文章由 Bob McCune ([`www.bobmccune.com/2006/12/09/unit-testing-best-practices/`](http://www.bobmccune.com/2006/12/09/unit-testing-best-practices/)) 撰写。

这个主题也有很多书籍，比如：

+   *以示例驱动的测试*, *Kent Beck*。

+   *Addison Wesley Signature Series*

+   *Test-Driven JavaScript Development*, *Christian Johansen*, *Addison Wesley*。

# 摘要

使用 QUnit 进行测试可以有效地帮助我们保持 jQuery 代码的清洁和可维护性。我们已经看到了一些在项目中实现测试以确保我们的代码按照我们意图的方式运行的方法。通过测试代码的小、独立单元，我们可以减轻项目变得更复杂时出现的一些问题。同时，我们可以更有效地在整个项目中测试回归，节省宝贵的编程时间。


# 附录 B：快速参考

本附录旨在快速参考 jQuery API，包括其选择器表达式和方法。每个方法和选择器的更详细讨论可在 jQuery 文档站点[`api.jquery.com`](http://api.jquery.com)上找到。

# 选择器表达式

jQuery 工厂函数`$()`用于查找页面上要处理的元素。此函数采用由类似 CSS 语法构成的字符串，称为选择器表达式。选择器表达式在第二章*选择元素*中有详细讨论。

# 简单 CSS

| **选择器** | **匹配** |
| --- | --- |
| `*` | 所有元素。 |
| `#id` | 具有给定 ID 的元素。 |
| `element` | 给定类型的所有元素。 |
| `.class` | 所有具有给定类的元素。 |
| `a, b` | 被`a`或`b`匹配的元素。 |
| `a b` | 是`a`后代的元素`b`。 |
| `a > b` | 是`a`的子元素`b`。 |
| `a + b` | 紧接着`a`的元素`b`。 |
| `a ~ b` | 是`a`兄弟且在`a`之后的元素`b`。 |

# 兄弟节点位置

| **选择器** | **匹配** |
| --- | --- |
| `:nth-child(index)` | 是其父元素的`index`子元素（基于 1）。 |
| `:nth-child(even)` | 是其父元素的偶数子元素（基于 1）。 |
| `:nth-child(odd)` | 元素是其父元素的奇数子元素（基于 1）。 |
| `:nth-child(formula)` | 是其父元素的第 n 个子元素（基于 1）。公式的形式为`an+b`，其中`a`和`b`为整数。 |
| `:nth-last-child()` | 与`:nth-child()`相同，但从最后一个元素向第一个元素计数。 |
| `:first-child` | 其父元素的第一个子元素。 |
| `:last-child` | 其父元素的最后一个子元素。 |
| `:only-child` | 其父元素的唯一子元素。 |
| `:nth-of-type()` | 与`:nth-child()`相同，但仅计算相同元素名称的元素。 |
| `:nth-last-of-type()` | 与`:nth-last-child()`相同，但仅计算相同元素名称的元素。 |
| `:first-of-type` | 是其兄弟中相同元素名称的第一个子元素。 |
| `:last-of-type` | 是其兄弟元素中相同元素名称的最后一个子元素。 |
| `:only-of-type()` | 是其兄弟中相同元素名称的唯一子元素。 |

# 匹配元素位置

| **选择器** | **匹配** |
| --- | --- |
| `:first` | 结果集中的第一个元素。 |
| `:last` | 结果集中的最后一个元素。 |
| `:not(a)` | 结果集中不与`a`匹配的所有元素。 |
| `:even` | 结果集中的偶数元素（基于 0）。 |
| `:odd` | 结果集中的奇数元素（基于 0）。 |
| `:eq(index)` | 结果集中的编号元素（基于 0）。 |
| `:gt(index)` | 结果集中给定索引（基于 0）之后的所有元素。 |
| `:lt(index)` | 在给定索引（基于 0）之前（小于）结果集中的所有元素。 |

# 属性

| **选择器** | **匹配** |
| --- | --- |
| `[attr]` | 具有`attr`属性的元素。 |
| `[attr="value"]` | `attr`属性为`value`的元素。 |
| `[attr!="value"]` | `attr`属性不是`value`的元素。 |
| `[attr^="value"]` | `attr`属性以`value`开头的元素。 |
| `[attr$="value"]` | `attr`属性以`value`结束的元素。 |
| `[attr*="value"]` | 包含子字符串`value`的`attr`属性的元素。 |
| `[attr~="value"]` | `attr`属性是一个以空格分隔的字符串集，其中之一是`value`的元素。 |
| `[attr&#124;="value"]` | 其`attr`属性等于`value`或以`value`连字符后跟的元素。 |

# 表单

| **选择器** | **匹配** |
| --- | --- |
| `:input` | 所有`<input>`、`<select>`、`<textarea>`和`<button>`元素。 |
| `:text` | `type="text"`的`<input>`元素。 |
| `:password` | `type="password"`的`<input>`元素。 |
| `:file` | `type="file"`的`<input>`元素。 |
| `:radio` | `type="radio"`的`<input>`元素。 |
| `:checkbox` | `type="checkbox"`的`<input>`元素。 |
| `:submit` | `type="submit"`的`<input>`元素。 |
| `:image` | `type="image"`的`<input>`元素。 |
| `:reset` | `type="reset"`的`<input>`元素。 |
| `:button` | `type="button"`的`<input>`元素和`<button>`元素。 |
| `:enabled` | 启用的表单元素。 |
| `:disabled` | 禁用的表单元素。 |
| `:checked` | 已选中的复选框和单选按钮。 |
| `:selected` | 已选中的`<option>`元素。 |

# 杂项选择器

| **选择器** | **匹配** |
| --- | --- |
| `:root` | 文档的根元素。 |
| `:header` | 标题元素（例如，`<h1>`、`<h2>`）。 |
| `:animated` | 正在进行动画的元素。 |
| `:contains(text)` | 包含给定文本的元素。 |
| `:empty` | 没有子节点的元素。 |
| `:has(a)` | 包含匹配`a`的后代元素。 |
| `:parent` | 具有子节点的元素。 |
| `:hidden` | 被隐藏的元素，无论是通过 CSS 还是因为它们是`<input type="hidden" />`。 |
| `:visible` | `:hidden`的反义。 |
| `:focus` | 具有键盘焦点的元素。 |
| `:lang(language)` | 具有给定语言代码的元素（可能是由元素或祖先上的`lang`属性或`<meta>`声明引起的）。 |
| `:target` | 如果有，URI 片段标识符指定的元素。 |

# DOM 遍历方法

使用`$()`创建 jQuery 对象后，我们可以通过调用其中一个 DOM 遍历方法来修改我们正在处理的匹配元素集。DOM 遍历方法在第二章 *选择元素*中有详细讨论。

# 过滤

| **遍历方法** | **返回一个包含...的 jQuery 对象** |
| --- | --- |
| `.filter(selector)` | 匹配给定选择器的选定元素。 |
| `.filter(callback)` | 回调函数返回 `true` 的选定元素。 |
| `.eq(index)` | 给定基于 0 的索引处的选定元素。 |
| `.first()` | 第一个选定元素。 |
| `.last()` | 最后一个选定元素。 |
| `.slice(start, [end])` | 在给定的以 0 为基础的索引范围内选择元素。 |
| `.not(selector)` | 不匹配给定选择器的选定元素。 |
| `.has(selector)` | 具有与 `selector` 匹配的后代元素的选定元素。 |

# 后代

| **遍历方法** | **返回一个包含...的 jQuery 对象** |
| --- | --- |
| `.find(selector)` | 与选择器匹配的后代元素。 |
| `.contents()` | 子节点（包括文本节点）。 |
| `.children([selector])` | 子节点，可选择由选择器进行过滤。 |

# 兄弟

| **遍历方法** | **返回一个包含...的 jQuery 对象** |
| --- | --- |
| `.next([selector])` | 每个选定元素后面紧邻的兄弟元素，可选择由选择器进行过滤。 |
| `.nextAll([selector])` | 每个选定元素后面的所有兄弟元素，可选择由选择器进行过滤。 |
| `.nextUntil([selector], [filter])` | 每个选定元素后面的所有兄弟元素，直到但不包括第一个匹配 `selector` 的元素，可选择由附加选择器进行过滤。 |
| `.prev([selector])` | 每个选定元素前面紧邻的兄弟元素，可选择由选择器进行过滤。 |
| `.prevAll([selector])` | 每个选定元素之前的所有兄弟元素，可选择由选择器进行过滤。 |
| `.prevUntil([selector], [filter])` | 每个选定元素前面的所有兄弟元素，直到但不包括第一个匹配 `selector` 的元素，可选择由附加选择器进行过滤。 |
| `.siblings([selector])` | 所有兄弟元素，可选择由选择器进行过滤。 |

# 祖先

| **遍历方法** | **返回一个包含...的 jQuery 对象** |
| --- | --- |
| `.parent([selector])` | 每个选定元素的父元素，可选择由选择器进行过滤。 |
| `.parents([selector])` | 所有祖先元素，可选择由选择器进行过滤。 |
| `.parentsUntil([selector], [filter])` | 每个选定元素的所有祖先元素，直到但不包括第一个匹配 `selector` 的元素，可选择由附加选择器进行过滤。 |
| `.closest(selector)` | 从选定元素开始，并在 DOM 树中沿着其祖先移动，找到与选择器匹配的第一个元素。 |
| `.offsetParent()` | 第一个选定元素的定位父元素，可以是相对定位或绝对定位。 |

# 集合操作

| **遍历方法** | **返回一个包含...的 jQuery 对象** |
| --- | --- |
| `.add(selector)` | 选定的元素，加上与给定选择器匹配的任何其他元素。 |
| `.addBack()` | 选定的元素，加上内部 jQuery 堆栈上先前选择的一组元素。 |
| `.end()` | 内部 jQuery 堆栈上先前选择的一组元素。 |
| `.map(callback)` | 在每个选定元素上调用回调函数的结果。 |
| `.pushStack(elements)` | 指定的元素。 |

# 处理选定元素

| **穿越方法** | **描述** |
| --- | --- |
| `.is(selector)` | 确定任何匹配元素是否被给定的选择器表达式匹配。 |
| `.index()` | 获取匹配元素相对于其兄弟元素的索引。 |
| `.index(element)` | 获取给定 DOM 节点在匹配元素集合中的索引。 |
| `$.contains(a, b)` | 确定 DOM 节点`b`是否包含 DOM 节点`a`。 |
| `.each(callback)` | 遍历匹配的元素，为每个元素执行`callback`。 |
| `.length` | 获取匹配元素的数量。 |
| `.get()` | 获取与匹配元素对应的 DOM 节点数组。 |
| `.get(index)` | 获取给定索引处匹配元素对应的 DOM 节点。 |
| `.toArray()` | 获取与匹配元素对应的 DOM 节点数组。 |

# 事件方法

为了对用户行为做出反应，我们需要使用这些事件方法注册我们的处理程序。请注意，许多 DOM 事件仅适用于特定的元素类型；这些细微之处在此未涉及。事件方法在第三章中详细讨论，*处理事件*。

# 绑定

| **事件方法** | **描述** |
| --- | --- |
| `.ready(handler)` | 绑定`handler`以在 DOM 和 CSS 完全加载时调用。 |
| `.on(type, [selector], [data], handler)` | 绑定`handler`以在给定类型的事件发送到元素时调用。如果提供了`selector`，则执行事件委托。 |
| `.on(events, [selector], [data])` | 根据`events`对象参数中指定的多个事件为事件绑定多个处理程序。 |
| `.off(type, [selector], [handler])` | 删除元素上的绑定。 |
| `.one(type, [data], handler)` | 绑定`handler`以在给定类型的事件发送到元素时调用。在处理程序被调用时删除绑定。 |

# 缩略绑定

| **事件方法** | **描述** |
| --- | --- |
| `.blur(handler)` | 绑定`handler`以在元素失去键盘焦点时调用。 |
| `.change(handler)` | 绑定`handler`以在元素的值更改时调用。 |
| `.click(handler)` | 绑定`handler`以在单击元素时调用。 |
| `.dblclick(handler)` | 绑定`handler`以在元素被双击时调用。 |
| `.focus(handler)` | 绑定`handler`以在元素获得键盘焦点时调用。 |
| `.focusin(handler)` | 绑定`handler`以在元素或后代获得键盘焦点时调用。 |
| `.focusout(handler)` | 绑定`handler`以在元素或后代失去键盘焦点时调用。 |
| `.keydown(handler)` | 绑定`handler`以在按键按下且元素具有键盘焦点时调用。 |
| `.keypress(handler)` | 绑定`handler`以在发生按键事件且元素具有键盘焦点时调用。 |
| `.keyup(handler)` | 当释放按键且元素具有键盘焦点时调用`handler`。 |
| `.mousedown(handler)` | 当鼠标按钮在元素内按下时调用`handler`。 |
| `.mouseenter(handler)` | 当鼠标指针进入元素时调用`handler`。不受事件冒泡影响。 |
| `.mouseleave(handler)` | 当鼠标指针离开元素时调用`handler`。不受事件冒泡影响。 |
| `.mousemove(handler)` | 当鼠标指针在元素内移动时调用`handler`。 |
| `.mouseout(handler)` | 当鼠标指针离开元素时调用`handler`。 |
| `.mouseover(handler)` | 当鼠标指针进入元素时调用`handler`。 |
| `.mouseup(handler)` | 当鼠标按钮在元素内释放时调用`handler`。 |
| `.resize(handler)` | 当元素大小改变时调用`handler`。 |
| `.scroll(handler)` | 当元素的滚动位置发生变化时调用`handler`。 |
| `.select(handler)` | 当元素中的文本被选择时绑定`handler`。 |
| `.submit(handler)` | 当表单元素提交时调用`handler`。 |
| `.hover(enter, leave)` | 当鼠标进入元素时绑定`enter`，当鼠标离开时绑定`leave`。 |

# 触发

| **事件方法** | **描述** |
| --- | --- |
| `.trigger(type, [data])` | 在元素上触发事件的处理程序，并执行事件的默认操作。 |
| `.triggerHandler(type, [data])` | 在元素上触发事件的处理程序，而不执行任何默认操作。 |

# 简写触发

| **事件方法** | **描述** |
| --- | --- |
| `.blur()` | 触发`blur`事件。 |
| `.change()` | 触发`change`事件。 |
| `.click()` | 触发`click`事件。 |
| `.dblclick()` | 触发`dblclick`事件。 |
| `.error()` | 触发`error`事件。 |
| `.focus()` | 触发`focus`事件。 |
| `.keydown()` | 触发`keydown`事件。 |
| `.keypress()` | 触发`keypress`事件。 |
| `.keyup()` | 触发`keyup`事件。 |
| `.select()` | 触发`select`事件。 |
| `.submit()` | 触发`submit`事件。 |

# 实用程序

| **事件方法** | **描述** |
| --- | --- |
| `$.proxy(fn, context)` | 创建一个以给定上下文执行的新函数。 |

# 效果方法

这些效果方法可用于对 DOM 元素执行动画。有关详细信息，请参阅第四章 *样式和动画*。

# 预定义效果

| **效果方法** | **描述** |
| --- | --- |
| `.show()` | 显示匹配的元素。 |
| `.hide()` | 隐藏匹配的元素。 |
| `.show(speed, [callback])` | 通过动画`height`、`width`和`opacity`显示匹配的元素。 |
| `.hide(speed, [callback])` | 通过动画`height`，`width`和`opacity`隐藏匹配元素。 |
| `.slideDown([speed], [callback])` | 通过滑动动作显示匹配元素。 |
| `.slideUp([speed], [callback])` | 通过滑动动作隐藏匹配元素。 |
| `.slideToggle([speed], [callback])` | 显示或隐藏匹配元素并带有滑动动作。 |
| `.fadeIn([speed], [callback])` | 通过使元素淡入到不透明来显示匹配元素。 |
| `.fadeOut([speed], [callback])` | 通过使元素淡出到透明来隐藏匹配元素。 |
| `.fadeToggle([speed], [callback])` | 显示或隐藏匹配元素并带有幻灯片动画。 |
| `.fadeTo(speed, opacity, [callback])` | 调整匹配元素的不透明度。 |

# 自定义动画

| **效果方法** | **描述** |
| --- | --- |
| `.animate(properties, [speed], [easing], [callback])` | 执行指定 CSS 属性的自定义动画。 |
| `.animate(properties, options)` | 一个更低层次的`.animate()`接口，允许控制动画队列。 |

# 队列操作

| **效果方法** | **描述** |
| --- | --- |
| `.queue([queueName])` | 检索第一个匹配元素上的函数队列。 |
| `.queue([queueName], callback)` | 将`callback`添加到队列的末尾。 |
| `.queue([queueName], newQueue)` | 用新队列替换当前队列。 |
| `.dequeue([queueName])` | 在队列上执行下一个函数。 |
| `.clearQueue([queueName])` | 清空所有待处理函数的队列。 |
| `.stop([clearQueue], [jumpToEnd])` | 停止当前运行的动画，然后启动排队的动画（如果有的话）。 |
| `.finish([queueName])` | 停止当前运行的动画，立即将所有排队的动画推进到它们的目标值。 |
| `.delay(duration, [queueName])` | 在执行队列中的下一项之前等待`duration`毫秒。 |
| `.promise([queueName], [target])` | 返回一个 Promise 对象，一旦集合上的所有排队动作完成，就会被解析。 |

# DOM 操作方法

DOM 操作方法在第五章中详细讨论，*操作 DOM*。

# 属性和属性

| **操作方法** | **描述** |
| --- | --- |
| `.attr(key)` | 获取名为`key`的属性。 |
| `.attr(key, value)` | 将名为`key`的属性设置为`value`。 |
| `.attr(key, fn)` | 将名为`key`的属性设置为`fn`的结果（分别在每个匹配元素上调用）。 |
| `.attr(obj)` | 设置以键值对形式给出的属性值。 |
| `.removeAttr(key)` | 删除名为`key`的属性。 |
| `.prop(key)` | 获取名为`key`的属性。 |
| `.prop(key, value)` | 设置名为`key`的属性为`value`。 |
| `.prop(key, fn)` | 将名为`key`的属性设置为`fn`的结果（分别在每个匹配元素上调用）。 |
| `.prop(obj)` | 设置以键值对形式给出的属性值。 |
| `.removeProp(key)` | 移除名为`key`的属性。 |
| `.addClass(class)` | 将给定的类添加到每个匹配元素中。 |
| `.removeClass(class)` | 从每个匹配元素中删除给定的类。 |
| `.toggleClass(class)` | 如果存在，则从每个匹配元素中删除给定的类，并在不存在时添加。 |
| `.hasClass(class)` | 如果任何匹配的元素具有给定的类，则返回`true`。 |
| `.val()` | 获取第一个匹配元素的值属性。 |
| `.val(value)` | 将每个元素的值属性设置为`value`。 |

# 内容

| **操作方法** | **描述** |
| --- | --- |
| `.html()` | 获取第一个匹配元素的 HTML 内容。 |
| `.html(value)` | 将每个匹配元素的 HTML 内容设置为 value。 |
| `.text()` | 将所有匹配元素的文本内容作为单个字符串获取。 |
| `.text(value)` | 将每个匹配元素的文本内容设置为`value`。 |

# CSS

| **操作方法** | **描述** |
| --- | --- |
| `.css(key)` | 获取名为`key`的 CSS 属性。 |
| `.css(key, value)` | 将名为`key`的 CSS 属性设置为`value`。 |
| `.css(obj)` | 设置以键值对给出的 CSS 属性值。 |

# 尺寸

| **操作方法** | **描述** |
| --- | --- |
| `.offset()` | 获取第一个匹配元素相对于视口的顶部和左侧像素坐标。 |
| `.position()` | 获取第一个匹配元素相对于`.offsetParent()`返回的元素的顶部和左侧像素坐标。 |
| `.scrollTop()` | 获取第一个匹配元素的垂直滚动位置。 |
| `.scrollTop(value)` | 将所有匹配元素的垂直滚动位置设置为`value`。 |
| `.scrollLeft()` | 获取第一个匹配元素的水平滚动位置。 |
| `.scrollLeft(value)` | 将所有匹配元素的水平滚动位置设置为`value`。 |
| `.height()` | 获取第一个匹配元素的高度。 |
| `.height(value)` | 将所有匹配元素的高度设置为`value`。 |
| `.width()` | 获取第一个匹配元素的宽度。 |
| `.width(value)` | 将所有匹配元素的宽度设置为`value`。 |
| `.innerHeight()` | 获取第一个匹配元素的高度，包括填充，但不包括边框。 |
| `.innerWidth()` | 获取第一个匹配元素的宽度，包括填充，但不包括边框。 |
| `.outerHeight(includeMargin)` | 获取第一个匹配元素的高度，包括填充，边框和可选的外边距。 |
| `.outerWidth(includeMargin)` | 获取第一个匹配元素的宽度，包括填充，边框和可选的外边距。 |

# 插入

| **操作方法** | **描述** |
| --- | --- |
| `.append(content)` | 将`content`插入到每个匹配元素的内部末尾。 |
| `.appendTo(selector)` | 将匹配的元素插入到由`selector`匹配的元素内部的末尾。 |
| `.prepend(content)` | 将`content`插入到每个匹配元素的内部开头。 |
| `.prependTo(selector)` | 将匹配的元素插入到由`selector`匹配的元素的内部开头。 |
| `.after(content)` | 在每个匹配的元素之后插入`content`。 |
| `.insertAfter(selector)` | 在每个由`selector`匹配的元素之后插入匹配的元素。 |
| `.before(content)` | 在每个匹配的元素之前插入`content`。 |
| `.insertBefore(selector)` | 将匹配的元素插入到由`selector`匹配的每个元素之前。 |
| `.wrap(content)` | 将每个匹配的元素包裹在`content`中。 |
| `.wrapAll(content)` | 将所有匹配的元素作为单个单元包裹在`content`中。 |
| `.wrapInner(content)` | 将每个匹配元素的内部内容包裹在`content`中。 |

# 替换

| **操作方法** | **描述** |
| --- | --- |
| `.replaceWith(content)` | 用`content`替换匹配的元素。 |
| `.replaceAll(selector)` | 用匹配的元素替换由`selector`匹配的元素。 |

# 移除

| **操作方法** | **描述** |
| --- | --- |
| `.empty()` | 移除每个匹配元素的子节点。 |
| `.remove([selector])` | 从 DOM 中删除匹配的节点（可选地通过`selector`过滤）。 |
| `.detach([selector])` | 从 DOM 中删除匹配的节点（可选地通过`selector`过滤），保留附加到它们的 jQuery 数据。 |
| `.unwrap()` | 删除元素的父元素。 |

# 复制

| **操作方法** | **描述** |
| --- | --- |
| `.clone([withHandlers], [deepWithHandlers])` | 复制所有匹配的元素，可选择地也复制事件处理程序。 |

# 数据

| **操作方法** | **描述** |
| --- | --- |
| `.data(key)` | 获取第一个匹配元素关联的名为`key`的数据项。 |
| `.data(key, value)` | 将名为`key`的数据项与每个匹配的元素关联到`value`。 |
| `.removeData(key)` | 删除与每个匹配元素关联的名为`key`的数据项。 |

# Ajax 方法

通过调用其中一个 Ajax 方法，我们可以在不需要页面刷新的情况下从服务器检索信息。Ajax 方法在第六章中详细讨论，*使用 Ajax 发送数据*。

# 发出请求

| **Ajax 方法** | **描述** |
| --- | --- |
| `$.ajax([url], options)` | 使用提供的选项集进行 Ajax 请求。这是一个低级方法，通常通过其他便利方法调用。 |
| `.load(url, [data], [callback])` | 发送 Ajax 请求到`url`，并将响应放入匹配的元素中。 |
| `$.get(url, [data], [callback], [returnType])` | 使用`GET`方法向`url`发出 Ajax 请求。 |
| `$.getJSON(url, [data], [callback])` | 发送 Ajax 请求到`url`，将响应解释为 JSON 数据结构。 |
| `$.getScript(url, [callback])` | 发送 Ajax 请求到`url`，执行响应作为 JavaScript。 |
| `$.post(url, [data], [callback], [returnType])` | 使用`POST`方法向`url`发出 Ajax 请求。 |

# 请求监控

| **Ajax 方法** | **描述** |
| --- | --- |
| `.ajaxComplete(handler)` | 将`handler`绑定到在任何 Ajax 事务完成时调用。 |
| `.ajaxError(handler)` | 将`handler`绑定到任何 Ajax 事务以错误完成时调用。 |
| `.ajaxSend(handler)` | 将`handler`绑定到在任何 Ajax 事务开始时调用。 |
| `.ajaxStart(handler)` | 将`handler`绑定到在任何 Ajax 事务开始且没有其他事务活动时调用。 |
| `.ajaxStop(handler)` | 将`handler`绑定到在任何 Ajax 事务结束且没有其他事务仍在进行时调用。 |
| `.ajaxSuccess(handler)` | 将`handler`绑定到在任何 Ajax 事务成功完成时调用。 |

# 配置

| **Ajax 方法** | **描述** |
| --- | --- |
| `$.ajaxSetup(options)` | 为所有后续 Ajax 事务设置默认选项。 |
| `$.ajaxPrefilter([dataTypes], handler)` | 在`$.ajax()`处理之前修改每个 Ajax 请求的选项。 |
| `$.ajaxTransport(transportFunction)` | 定义 Ajax 事务的新传输机制。 |

# 实用工具

| **Ajax 方法** | **描述** |
| --- | --- |
| `.serialize()` | 将一组表单控件的值编码为查询字符串。 |
| `.serializeArray()` | 将一组表单控件的值编码为 JavaScript 数据结构。 |
| `$.param(obj)` | 将键值对的任意对象编码为查询字符串。 |
| `$.globalEval(code)` | 在全局上下文中评估给定的 JavaScript 字符串。 |
| `$.parseJSON(json)` | 将给定的 JSON 字符串转换为 JavaScript 对象。 |
| `$.parseXML(xml)` | 将给定的 XML 字符串转换为 XML 文档。 |
| `$.parseHTML(html)` | 将给定的 HTML 字符串转换为一组 DOM 元素。 |

# 延迟对象

延迟对象及其承诺使我们能够以方便的语法对长时间运行的任务的完成做出反应。它们在第十一章，*高级效果*中详细讨论。

# 对象创建

| **函数** | **描述** |
| --- | --- |
| `$.Deferred([setupFunction])` | 返回一个新的延迟对象。 |
| `$.when(deferreds)` | 返回一个承诺对象，以便在给定的延迟对象解决时解决。 |

# Deferred 对象的方法

| **方法** | **描述** |
| --- | --- |
| `.resolve([args])` | 将对象的状态设置为已解决。 |
| `.resolveWith(context, [args])` | 将对象的状态设置为已解决，同时使关键字`this`在回调中指向`context`。 |
| `.reject([args])` | 将对象的状态设置为被拒绝。 |
| `.rejectWith(context, [args])` | 将对象的状态设置为被拒绝，同时使关键字`this`在回调中指向`context`。 |
| `.notify([args])` | 执行任何进度回调。 |
| `.notifyWith(context, [args])` | 在执行任何进度回调时，使关键字`this`指向`context`。 |
| `.promise([target])` | 返回与此延迟对象对应的 promise 对象。 |

# promise 对象的方法

| **方法** | **描述** |
| --- | --- |
| `.done(callback)` | 在对象被解决时执行`callback`。 |
| `.fail(callback)` | 在对象被拒绝时执行`callback`。 |
| `.catch(callback)` | 在对象被拒绝时执行**`callback`**。 |
| `.always(callback)` | 在对象被解决或被拒绝时执行`callback`。 |
| `.then(doneCallbacks, failCallbacks)` | 当对象被解决时执行`doneCallbacks`，或当对象被拒绝时执行`failCallbacks`。 |
| `.progress(callback)` | 每次对象接收到进度通知时执行`callback`。 |
| `.state()` | 根据当前状态返回`'pending'`、`'resolved'`或`'rejected'`。 |

# 杂项属性和函数

这些实用方法不能很好地归入之前的类别，但在使用 jQuery 编写脚本时通常非常有用。

# jQuery 对象的属性

| **属性** | **描述** |
| --- | --- |
| `$.ready` | 一个 promise 实例，一旦 DOM 准备就绪就解决。 |

# 数组和对象

| **函数** | **描述** |
| --- | --- |
| `$.each(collection, callback)` | 遍历`collection`，为每个项执行`callback`。 |
| `$.extend(target, addition, ...)` | 通过从其他提供的对象中添加属性修改对象`target`。 |
| `$.grep(array, callback, [invert])` | 使用`callback`作为测试过滤`array`。 |
| `$.makeArray(object)` | 将`object`转换为数组。 |
| `$.map(array, callback)` | 构造由对每个项调用`callback`的结果组成的新数组。 |
| `$.inArray(value, array)` | 判断`value`是否在`array`中。 |
| `$.merge(array1, array2)` | 合并`array1`和`array2`的内容。 |
| `$.unique(array)` | 从`array`中删除任何重复的 DOM 元素。 |

# 对象内省

| **函数** | **描述** |
| --- | --- |
| `$.isArray(object)` | 判断`object`是否为真正的 JavaScript 数组。 |
| `$.isEmptyObject(object)` | 判断`object`是否为空。 |
| `$.isFunction(object)` | 判断`object`是否为函数。 |
| `$.isPlainObject(object)` | 判断`object`是否以对象字面量形式创建或使用`new Object`创建。 |
| `$.isNumeric(object)` | 判断`object`是否为数值标量。 |
| `$.isWindow(object)` | 判断`object`是否表示浏览器窗口。 |
| `$.isXMLDoc(object)` | 判断`object`是否为 XML 节点。 |
| `$.type(object)` | 获取`object`的 JavaScript 类。 |

# 其他

| **函数** | **描述** |
| --- | --- |
| `$.trim(string)` | 从`string`的两端删除空格。 |
| `$.noConflict([removeAll])` | 将`$`恢复到其 jQuery 前定义。 |
| `$.noop()` | 一个什么也不做的函数。 |
| `$.now()` | 自纪元以来的当前时间（毫秒）。 |
| `$.holdReady(hold)` | 阻止`ready`事件的触发，或释放此保持。 |
