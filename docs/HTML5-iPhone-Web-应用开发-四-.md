# HTML5 iPhone Web 应用开发（四）

> 原文：[`zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5`](https://zh.annas-archive.org/md5/C42FBB1BF1A841DF79FD9C30381620A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：离线应用程序

在本章中，我们将介绍离线应用程序开发的基础知识。具体来说，我们将讨论应用程序清单，包括其优缺点，并看看我们如何处理离线交互。然后我们将深入研究如何使用`localStorage`和`IndexedDB`在客户端临时存储数据。本章的内容将以基本示例进行补充，这将帮助您快速上手。因此，让我们首先来看看应用程序清单对我们有什么好处。

本章将涵盖以下主题：

+   应用程序清单

+   处理离线交互

+   `localStorage`和`IndexedDB`API

# 应用程序缓存

**应用程序缓存**，又称为**AppCache**，允许您定义应该在离线使用期间缓存和可用的资源。这基本上使您的 Web 应用程序在用户离线时可用，因此失去网络连接甚至刷新页面都不会影响用户的连接，他们仍然能够与您的应用程序进行交互。让我们首先来看看应用程序缓存清单是什么样子。

## 清单文件

我们的应用程序清单文件包含了有关哪些资源将被文件缓存的信息。它明确告知浏览器您希望离线使用的资源，使其可供离线使用，同时通过缓存加快页面加载速度。以下代码展示了本章附带示例的缓存清单的基本示例：

```html
 CACHE MANIFEST

index.html

# stylesheets
../css/normalize.css
../css/main.css
../css/offline.css

# javascripts
../js/vendor/modernizr-2.6.1.min.js
../js/vendor/zepto.min.js
../js/helper.js
../js/App/App.js
../js/App/App.Nav.js
../js/App/App.Offline.js
../js/main.js
```

在上面的例子中，发生了一些事情。首先，我们使用全大写单词`CACHE MANIFEST`来标识缓存清单。这一行是必需的，并且被浏览器读取为确切的缓存清单。接下来的一行定义了一个我们想要缓存的文件，`index.html`。现在，有一件事情我们需要记住；这个清单文件是相对于我们所在的位置的。这意味着我们的文件位于`index.html`所在的目录中（例如，`offline.appcache`位于`localhost/`，就像`index.html`一样）。

接下来，我们发现我们可以在我们的清单文件中包含注释，只需在前面加上井号（`#stylesheets`）。这有助于我们跟踪这个文件中发生的事情。从这里开始，我们定义我们想要相对于正在查看的页面定义的样式表和脚本。此时，我们正在查看一个真正的清单文件，并对其进行分解以理解它。随着我们在本章中的进展，我们将回到这个文件，看看它如何影响本章中构建的示例。

## 清单实现

为了有效地使用我们的缓存清单，我们需要能够将其与当前页面关联起来。但是为了做到这一点，我们还需要设置我们的服务器以正确处理清单，通过发送正确的 MIME 类型。每种类型的服务器处理方式都有些不同，指令可能看起来不同，但它们都能实现相同的结果——发送与该文件相关联的正确类型的标头。

在 Apache 中，我们的配置看起来可能是这样的：

```html
AddType text/cache-manifest .appcache
```

正如您所看到的，我们已经定义了所有类型为`.appcache`的文件以`text`/`cache-manifest`的内容类型进行传递。这使得浏览器能够正确解释文件，因此浏览器将其关联为`cache-manifest`。尽管这很好，但我们还没有完成。为了完成，我们需要让我们的页面定义这个文件，以便它能够正确关联。

将我们的缓存清单与我们的页面相关联，我们需要在我们的 HTML 标签上设置`manifest`属性，如下所示：

```html
<html manifest=”offline.appcache”>
```

我们现在已经定义了我们的应用程序缓存清单，并将其与相关页面一起交付，但我们只是简要地涉及了这项技术。要充分理解其功能，我们需要看到它的使用。因此，我们将继续创建一个简单的示例，让我们使用到目前为止学到的知识。

## 一个简单的例子

本章的示例将基于上一章。因此，我们不会详细介绍用于创建此示例的结构、样式或脚本。但是，它将被简化为一个基本的个人资料视图，让您能够理解离线应用程序，而无需从前几章获取额外的知识。首先，让我们看看我们的标记。

### 标记

与本书一起提供的源代码包含了您开始本章目标所需的一切。因此，让我们看看这个示例的实质，并检查这个示例将如何运行，从标记开始。如果您打开位于`offline`目录中的索引文件，您会注意到我们的内容应该看起来像这样：

```html
<div class=”site-wrapper”>
    <section class=”view-profile”>
        <header>
            <h1>John’s Profile</h1>
            <a href=”#edit”>Edit</a>
        </header>
        <dl>
            <dt>Bio</dt>
            <dd>This is a little bit about myself; I like iphone web apps and development in general.</dd>
            <dt>Age</dt>
            <dd>26</dd>
            <dt>Birthdate</dt>
            <dd>January 1st, 1987</dd>
        </dl>
        <form>
            <div class=”field”>
                <label for=”bio”>Bio</label>
                <textarea id=”bio”>
                    This is a little bit about me; I like iphone web apps and development in general.
                </textarea>
            </div>
            <div class=”field”>
                <label for=”age”>Age</label>
                <input id=”age” type=”number” value=”26”>
            </div>
            <div class=”field”>
                <label>Birthdate</label>
                <input type=”date” value=”1987-01-01”>
            </div>
        </form>
    </section>
</div>
```

与任何网页应用程序一样，特别是本书中编写的应用程序，这只是整体应用架构的一部分，其中包括页眉、页脚、样式表和脚本。但是，前面的标记描述了一个显示用户信息的个人资料视图，包括简短的个人简介、年龄和出生日期。除了这些信息外，还有一个表单，允许您更新这些信息。

这个应用程序的体验如下。首先，当用户加载页面时，他们应该看到与他们相关的所有信息。其次，他们将有选择使用文本**编辑**的超链接来编辑这些信息。当单击超链接时，将出现一个表单，允许用户编辑他们的信息。相应地，**编辑**超链接将更新为**查看个人资料**。最后，当用户单击**查看个人资料**时，表单将隐藏，用户信息的显示将重新出现。

### JavaScript

这并不像听起来那么复杂。事实上，用于创建页面功能的脚本依赖于以下脚本：

```html
var $viewProfile = $(‘.view-profile’),
    $form = $viewProfile.find(‘form’),
    $dl = $viewProfile.find(‘dl’),
    $p = $(‘<p />’);

function onEditClick(e) {
    e.preventDefault();
    e.stopImmediatePropagation();

    $form.show();
    $dl.hide();
    $(this).text(‘View Profile’).attr(‘href’, ‘#view’);
}

function onViewClick(e) {
    e.preventDefault();
    e.stopImmediatePropagation();

    $form.hide();
    $dl.show();
    $(this).text(‘Edit’).attr(‘href’, ‘#edit’);
}

$viewProfile.
    on(‘click’, ‘a[href=”#edit”]’, onEditClick).
    on(‘click’, ‘a[href=”#view”]’, onViewClick);
```

让我们看看前面的代码中发生了什么，以确保没有人迷失方向。首先，我们缓存适合我们页面的元素。通过这种方式，我们通过不是每次需要查找东西时都遍历 DOM 来优化性能。然后，我们定义了`onEditClick`和`onViewClick`事件处理程序，它们显示或隐藏适当的内容块，然后更新与之相关的锚点标签的`text`和`href`属性。最后，我们将`click`事件附加到缓存的`$viewProfile`元素上。

### 注意

请注意，前面的 JavaScript 是本章书籍附带源代码的一部分。为了更好地解释正在构建的应用程序的实质，我们已经删除了闭包和`Offline`类。当然，您可以选择使用前面的代码，或者继续使用本书的源代码。无论您选择哪种方式，期望的结果都将是一个根据当前状态显示或隐藏内容的应用程序。

当执行前面的代码并加载页面时，应用程序的状态如下：

![JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_08_01.jpg)

初始应用程序状态和应用程序编辑状态

现在，我们已经建立了应用程序与交互时应该看起来的坚实基础，我们希望确保它被缓存。通过实施我们应用程序开头给出的技术，我们现在应该有一个可以离线运行的应用程序。

请记住，我们需要将应用程序缓存清单放在与正在构建的示例应用程序相同的目录中。因此，我们的应用程序清单需要存在于离线目录中，与我们的`index.html`文件一起。如果您查看本章的源代码，您应该会看到我们的清单和源文件的结构和布局的工作示例。在正确配置的服务器上运行此应用程序将使我们的页面离线呈现。但问题是，我们如何调试这样的东西呢？好吧，这就是下一节要解决的问题。

# 调试缓存清单

调试我们的离线应用程序非常重要，毕竟，如果我们的应用程序依赖于网络连接，我们必须提供一个成功的替代体验给我们的用户。然而，调试离线应用程序并不容易。有几个原因，但主要是基于应用程序缓存接口的实现。

> 当 Safari 重新访问您的站点时，站点将从缓存中加载。如果缓存清单已更改，Safari 将检查声明缓存的 HTML 文件，以及清单中列出的每个资源，以查看它们是否有任何更改。
> 
> 如果文件与先前版本的文件在字节上完全相同，则认为文件未更改；更改文件的修改日期不会触发更新。您必须更改文件的内容。（更改注释就足够了。）

这可以在苹果文档中找到：[`developer.apple.com/library/safari/#documentation/iPhone/Conceptual/SafariJSDatabaseGuide/OfflineApplicationCache/OfflineApplicationCache.html#//apple_ref/doc/uid/TP40007256-CH7-SW5`](https://developer.apple.com/library/safari/#documentation/iPhone/Conceptual/SafariJSDatabaseGuide/OfflineApplicationCache/OfflineApplicationCache.html)

## 在浏览器中调试

根据先前的文档，我们可以通过清除具有更新资源的缓存来改进调试过程。这可能只是在我们的代码中更新注释，但为了确保正确的资产被缓存，我们可以使用现代浏览器和调试器工具来查看被缓存的资产。查看以下截图，了解如何测试您的资产是否被缓存：

![在浏览器中调试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_08_02.jpg)

Safari 开发者工具 - 资源

Safari 中的开发者工具（如前面的截图所示）通过提供一个**资源**选项卡来帮助我们调试应用程序缓存，允许我们分析多个域的应用程序缓存。在这个例子中，我们可以看到与我们示例应用程序域相关的资源。当我们审查应用程序缓存时，我们可以看到与缓存相关的文件列表在右侧。此外，我们还可以看到文件的位置和用户的状态；在这种情况下，我们是在线且空闲。

![在浏览器中调试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_08_03.jpg)

Chrome 开发者工具 - 资源

Chrome 开发者工具同样有助于显示与应用程序缓存相关的信息。虽然用户界面有点不同，但它包含了审查与您的应用程序缓存相关的所有必要组件。此视图还包括您的应用程序的在线状态；在这个例子中，我们不在线且空闲。

## 使用 JavaScript 进行调试

应用程序缓存也可以使用 JavaScript 进行调试，幸运的是，应用程序缓存清单的实现非常容易与之交互。我们可以监听多个事件，包括`progress`、`error`和`updateready`。当我们监听这些事件时，我们可以选择实现一个补充体验，但在这里，我们只是记录事件。

```html
window.applicationCache.addEventListener(‘cached’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘checking’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘downloading’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘error’, handleCacheError, false);
window.applicationCache.addEventListener(‘noupdate’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘obsolete’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘progress’, handleCacheEvent, false);
window.applicationCache.addEventListener(‘updateready’, handleCacheEvent, false);

function handleCacheEvent(e) {
  console.log(e);
}

function handleCacheError(e) {
  console.log(e);

}
```

在上面的脚本中，我们监听规范定义的事件（[`www.whatwg.org/specs/web-apps/current-work/#appcacheevents`](http://www.whatwg.org/specs/web-apps/current-work/#appcacheevents)），并调用`handleCacheEvent`或`handleCacheError`方法。在这些方法中，我们只是记录事件本身；但是，如果我们愿意，我们可以创建一种替代体验。

在应用程序缓存过程的实施过程中还有许多可以使用的操作方法。例如，我们可以使用`update`方法手动更新缓存。

```html
window.applicationCache.update();
```

尽管前面的方法对我们可能有所帮助，但请记住，只有内容本身发生了变化，缓存才会更新。实际上，`update`方法触发了下载过程（[`www.whatwg.org/specs/web-apps/current-work/#application-cache-download-process`](http://www.whatwg.org/specs/web-apps/current-work/#application-cache-download-process)），这并不会告诉浏览器获取最新的缓存。 `swapCache`方法是另一个可以用来调试我们的应用程序的操作调用，它将缓存切换到最新版本。

```html
window.applicationCache.swapCache();
```

请记住，如果我们进行此调用，资产不会自动更新。获取更新后的资产的方法是刷新页面。根据规范，实现我们需要的更简单的方法是执行`location.reload()`（[`www.whatwg.org/specs/web-apps/current-work/#dom-appcache-swapcache`](http://www.whatwg.org/specs/web-apps/current-work/#dom-appcache-swapcache)）。

到目前为止，我们对应用程序缓存清单有了一个很好的了解，包括它的功能、实施细节以及最终如何调试它。现在我们需要知道如何使用前面的方法以及更多方法来处理离线交互。当我们对这两个方面有了很好的理解后，我们就能够创建利用这项技术的简单离线应用程序。

# 处理离线应用程序

到目前为止，我们已经学会了如何使用应用程序清单接口在客户端缓存我们的文件，以加快网站速度，同时使其在用户离线时可用。然而，这种技术并没有考虑到用户交互时应该做些什么。在这种情况下，我们需要确保我们的应用程序具有可用的部分，以使应用程序在失去连接时无缝运行。

## 一个简单的用例

在我们继续之前，让我们定义一个简单的用例，说明为什么处理离线应用对用户和我们都有用。假设我们有一个名叫约翰的用户，约翰正在通勤上班，目前正在 iPhone 上的 Web 应用程序中更新他的个人资料。通勤途中的网络连接有时不太稳定，有时会失去连接。他希望能够在上班途中继续使用应用程序，而不是等到上班后再使用。

考虑到我们今天生活的世界，一个不稳定的交互可能会让公司失去一个客户，我们肯定希望能够优雅地处理这种情况。这并不意味着我们会在用户离线时为其提供所有服务，那是不合理的。这意味着我们需要告知用户他们处于离线状态，由于这个原因，某些功能目前被禁用。

## 检测网络连接

现在，你可能会问：“如何检测网络连接？”嗯，实际上很简单。让我们看一下下面的代码：

```html
var $p = $(‘<p />’);
if(!navigator.onLine) {
  $p.
    text(‘NOTICE: You are currently offline. Your data will sync with the server when reconnected.’);

  $(‘.view-profile’).
    before($p);
}
```

让我们简要回顾一下前面的代码。这段代码的第一部分在内存中创建了一个缓存元素，并将其存储在变量`$p`中。接下来的一行是最重要的，它通过检查`navigator`对象的`onLine`属性来检测在线连接。如果用户不在线，我们最终设置了缓存元素的文本，并将其附加到我们之前的代码中。

如果我们的应用程序处于离线状态，它将如下所示：

![检测网络连接](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_08_04.jpg)

检测网络连接

当然，这只是你在现实世界应用中处理网络连接的简化版本，但它展示了你可以获取网络状态并确定离线体验。这对我们来说很棒，因为它为我们打开了一个我们以前无法探索的网络开发新世界。但当然，这也需要一些复杂的预先考虑，以确定如何处理这样的体验。

回到我们定义的用例，用户想要更新他/她的个人资料信息，显然如果没有必要的资源，这将是非常困难的。幸运的是，我们有两种新技术可以用来完成类似这个用例的简单任务。因此，让我们简要地介绍一下这两种技术。

## localStorage API

尽管离线状态是新的 HTML5 规范的一个特性，但它与 HTML5 的另一个特性——存储（[`dev.w3.org/html5/webstorage/`](http://dev.w3.org/html5/webstorage/)）密切相关。存储是许多开发人员之前认为与后端系统有一对一关系的东西。这不再是真的，因为现在我们能够使用`localStorage`API 在客户端设备上保存数据。

让我们通过一个简短的例子来使用`localStorage`，看看它是如何工作的：

```html
localStorage.setItem(‘name’, ‘John Smith’);
```

我们刚刚写的代码有多个部分。首先，有一个名为`localStorage`的全局对象。这个对象有开发人员可以交互的方法，包括`setItem`方法。最后，`setItem`方法接受两个参数，都是字符串。

要检索我们刚刚设置的项目的值，我们会这样做：

```html
localStorage.getItem(‘name’);
```

很酷，对吧？唯一的缺点是，当前的实现描述了 API 只接受每个键/值对的字符串，类似于 JavaScript 对象。然而，我们可以通过以下方式克服这个限制：

```html
localStorage.setItem(‘name’, JSON.stringify({ ‘first’: ‘John’, ‘last’: ‘Smith’ }));
```

这里的区别在于，我们还访问了内置的`JSON`对象，将对象转换为字符串，以便`localStorage`API 可以高效地将其存储为纯字符串。否则，你会存储`[object Object]`，这只是对象的类型。

要访问这些信息，我们需要做以下操作：

```html
JSON.parse(localStorage.getItem(‘name’));
```

当你在控制台中运行这段代码时，你应该会看到一个对象。`JSON`功能所做的是将“字符串化”的对象转换为传统的 JavaScript 对象。这使得访问我们存储的数据变得简单和高效。

正如你开始了解的那样，我们有能力在客户端存储信息，这是过去无法做到的，这使得我们能够在应用离线时暂时允许用户与网站的某些方面进行交互。结合 HTML5 的存储和离线功能，使我们能够为我们的应用带来更深入的交互，同时满足客户和用户的期望。

然而，`localStorage`的限制在于可以存储的信息量。因此，另一种技术被称为`IndexedDB`。尽管它的支持在各个浏览器中并不一致，而且技术仍处于实验阶段，但它值得一看。不幸的是，由于在 iOS Safari 中缺乏支持，我们在本书中不会涉及这项技术，但它仍然值得一些审查（[`developer.mozilla.org/en-US/docs/IndexedDB`](https://developer.mozilla.org/en-US/docs/IndexedDB)）。

# 总结

在本章中，我们介绍了应用程序缓存的基础知识，包括其实施示例。我们的回顾指出了使用这项新技术的好处，但也讨论了缺点，比如不一致的支持，主要是在旧版浏览器中，以及在测试时面临的问题。我们学会了如何处理离线交互，以及`localStorage`和`IndexedDB`如何允许我们在客户端临时存储信息作为解决方案。在下一章中，我们将讨论性能优化，并看看这在本书中开发的应用程序中是如何发挥作用的。


# 第九章：清洁和优化代码的原则

在整本书中，我们都强调了从应用程序开发的最开始就进行优化的重要性。尽管我们已经从 JavaScript 中缓存元素到模块化我们的样式等主题，但在本章中，我们想总结一下书中使用的技术。毕竟，性能对于我们的移动应用程序来说是非常重要的。在本章中，我们将涵盖优化我们的样式、脚本和媒体。除了涵盖优化技术之外，我们还将讨论增强代码可维护性的良好编码标准，同时也提高性能。我们将从讨论样式表开始。

在本章中，我们将涵盖以下主题：

+   验证 CSS

+   分析 CSS

+   CSS 最佳实践

+   验证 JavaScript

+   分析 JavaScript

+   JavaScript 最佳实践

# 优化样式表

传统上，样式被“随意”地添加到 Web 应用程序中而没有任何预见性。通常，我们只是为我们的页面添加样式，而没有考虑模块化、可重用性和可维护性。然而，由于今天 Web 应用程序的广泛性质，这种做法已不再可接受。

在本书中，我们努力遵守了一些行业标准，比如模块化。然而，现在我们有工具可以帮助我们验证和分析我们的样式。从分析样本 CSS 文件开始，我们可以优化这些样式；这就是我们在本章节中的目标。

## 验证我们的 CSS

为了优化我们的样式表，我们需要首先验证我们的 CSS 是否有效，并符合当今的标准。我们可以使用各种工具来验证我们的样式，包括 W3C CSS 验证器和一个名为**CSS Lint**的工具。这些工具都会检查您的样式表，并为您总结出错的地方、为什么出错以及您应该怎么做。

### W3C CSS 验证器

要访问 W3C CSS 验证器，您可以访问以下 URL：

[`jigsaw.w3.org/css-validator/`](http://jigsaw.w3.org/css-validator/)

以下屏幕截图显示了 W3C 验证器的默认视图，允许您输入包含样式的页面的 URI。它将根据 W3C 规范自动获取您的样式表并对其进行验证。然而，我们不仅仅局限于在现场或生产就绪的网站上让我们的页面可爬行。我们还可以选择上传我们的样式表，或直接将它们放入这个应用程序中。

![W3C CSS 验证器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_01.jpg)

W3C CSS 验证器-URI 视图

在以下视图中，您可以看到我们可以通过文件上传过程验证样式。这将简单地通过后端处理器运行这些样式表，以检查样式是否有效；一旦这个过程完成，我们就会得到结果。

![W3C CSS 验证器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_02.jpg)

W3C CSS 验证器-文件上传视图

最后，我们有直接将我们的样式插入到工具中的选项，这可能是根据项目和团队或个人的需求最快速、最简单的解决方案。我们不必担心样式被剥离或以任何方式修改；文本字段将正确处理您的所有输入。与其他视图类似，一旦单击**检查**按钮，输入将通过处理器运行并向您呈现结果。

![W3C CSS 验证器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_03.jpg)

W3C CSS 验证器-直接输入视图

### 可定制选项

与任何优质保证工具一样，我们需要有能力定制此工具的选项以适应我们的需求。在这种情况下，我们有各种可用的选项，包括：

+   **配置文件**：此选项指定验证样式时要使用的配置文件，例如 CSS Level 1、CSS Level 2、CSS Level 3 等。

+   **警告**：此选项指定报告中要呈现的警告，例如 Normal、Most Important、No Warnings 等。

+   **介质**：此选项指定了样式表应该表示的介质，例如屏幕、打印、手持设备等。

+   **供应商扩展**：此选项指定了供应商扩展（`-webkit-`、`-moz-`、`-o-`）在报告中的处理方式，例如警告或错误。

### 验证一个成功的例子

让我们看一个成功的验证例子。首先，让我们使用我们在之前章节中创建的一些样式来查看 CSS 是否通过验证；特别是，让我们使用`singlepage.css`文件的内容，并将其粘贴到 W3C 验证器的直接输入视图中，并使用默认选项运行它。

当我们运行验证器时，我们的结果应该是这样的：

![验证一个成功的例子](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_04.jpg)

W3C CSS 验证器 - 成功验证

如您所见，输出是成功的，并通过了 CSS Level 3 规范。令人惊讶的是，我们甚至可以从验证器那里得到徽章放在我们的网站上！但不要这样做；尽管您应该对自己的工作感到满意，但这是我们大多数人不太喜欢在我们的网站上看到的东西。现在让我们看一个不成功的例子。

### 验证一个不成功的例子

编程中经常出现错误，因此在我们的样式、脚本和标记中遇到验证错误是很自然的。因此，让我们看一下 W3C CSS 验证器中验证错误的示例是什么样子。在这个例子中，我们将使用我们在第二章中创建的`video.css`文件的变体，*集成 HTML5 视频*。为了这个例子，我引入了一些错误，包括以下样式：

```html
video {
  display: block;
  width: 100%;
  max-width: 640px;
  margin: 0 auto;
  font-size: 2px;
  font-style: italics;
}

.video-container {
  width: 100;
}

.video-controls {
  margin: 12px auto;
  width: 100%;
  text-align:;
}

.video-controls .vc-state,
.video-controls .vc-track,
.video-controls .vc-volume,
.video-controls .vc-fullscreen, {
  display: inline-block;
  margin-right: 10px;
}

.video-controls .vc-fullscreen {
  margin-right: 0;
}

.video-controls .vc-state-pause,
.video-controls .vc-volume-unmute {
  display: none;
```

当我们通过 W3C CSS 验证器传递前面的样式时，我们得到以下结果：

![验证一个不成功的例子](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_05.jpg)

W3C CSS 验证器 - 不成功的验证

在上面的例子中，我们得到了一些值、属性和解析错误，所有这些都可以通过此不成功的验证示例中给出的参考轻松解决。这样做的好处是，不用试图弄清楚可能破坏布局的原因，屏幕截图中显示的错误可能解决所有问题。

从某种意义上说，这基本上是您需要确保您的 CSS 在多个浏览器中有效和符合规范的所有内容。但是，如果您能够防止这些错误发生呢？好吧，有一个工具可以做到，那就是 CSS Lint。

### CSS Lint

在大多数情况下，我们在编码时希望尽量避免出现错误，并且使用某种工具及早捕捉这些错误将会很有帮助。CSS Lint 就是这样一个工具，实际上可以直接在您选择的文本编辑器或 IDE 中使用。CSS Lint 不仅检查您的样式是否符合 CSS 的某些原则（如盒模型），还进行了大量的语法检查，帮助您有效地调试样式。

> CSS Lint 指出了 CSS 代码的问题。它进行基本的语法检查，并应用一组规则来查找问题模式或低效迹象。这些规则都是可插拔的，因此您可以轻松编写自己的规则或省略您不想要的规则。

有关 CSS Lint 的详细信息可以在[`github.com/stubbornella/csslint/wiki/About`](https://github.com/stubbornella/csslint/wiki/About)找到。

与 W3C CSS 验证器类似，CSS Lint 有自己的网站，您可以将样式复制粘贴到文本区域中，让处理器检查您的样式。我们与之交互的页面如下所示：

![CSS Lint](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_06.jpg)

CSS Lint

### 可定制选项

CSS Lint 还带有可定制的选项，这些选项非常广泛，您可以根据自己或团队的需要进行定制。可定制选项有六个部分，包括**错误**、**可维护性和重复性**、**兼容性**、**可访问性**、**性能**和**OOCSS**（**面向对象的 CSS**）。

可定制的选项位于**Lint!**按钮的正下方：

![可定制的选项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_07.jpg)

CSS Lint 选项

检查适当的选项使引擎能够根据这些属性进行验证。通常这些选项在项目之间会有所不同；例如，您可能正在开发一个需要在某些元素上设置填充和宽度的应用程序，因此，取消选中**注意破碎的框尺寸**选项可能更适合您，这样您就不会看到多个错误。

#### 使用 CSS Lint 验证成功的示例

当我们自定义选项并通过 CSS Lint 传递页面时，如果样式表符合标准，同时也满足团队的需求，我们应该收到一个成功的验证，如下面的截图所示：

![使用 CSS Lint 验证成功示例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_08.jpg)

CSS Lint – 成功的验证

在上述情况下，我们的 CSS 样式通过了，不需要额外的信息。但是，当我们的 CSS 未通过验证时会发生什么呢？

#### 使用 CSS Lint 验证不成功的示例

如果我们将在上一节中为 W3C CSS 验证器创建的备用视频样式通过 CSS Lint，我们会得到以下结果：

![使用 CSS Lint 验证不成功的示例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_09.jpg)

CSS Lint – 未成功的验证

然而，仅仅因为我们收到了四个错误和两个警告并不意味着我们无助。事实上，当我们向下滚动页面时，我们会看到需要处理的项目列表；它还包括问题类型，描述以及错误发生的行：

![使用 CSS Lint 验证不成功的示例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_10.jpg)

CSS Lint – 未成功的验证列表

#### 集成 CSS Lint

尽管我们有一个可以用来验证我们的样式的**图形用户界面**（**GUI**），但如果我们能够简化我们的个人开发工作流程，那将会更容易。例如，如果我们可以在文本编辑器或**集成开发环境**（**IDE**）中保存样式表时验证我们的 CSS，那将会很好。CSS Lint 非常灵活，允许我们实现这些集成的工作流程。

一些集成开发环境和文本编辑器供应商已经实现了 CSS Lint，包括 Sublime Text，Cloud 9，Microsoft Visual Studio 和 Eclipse Orion。虽然将 CSS Lint 安装和设置到您喜欢的工具中超出了本书的范围，但您可以在这里查找所有所需的信息：

[`github.com/stubbornella/csslint/wiki/IDE-integration`](https://github.com/stubbornella/csslint/wiki/IDE-integration)

## 分析我们的 CSS

以前很难对 CSS 进行分析，事实上可能是不可能的。但是随着浏览器调试工具的进步，我们现在能够在一定程度上对样式表进行分析。在本节中，我们将回顾如何对我们的样式进行分析，并阅读 Safari 浏览器在 Mac 上向我们呈现的信息。

在接下来的屏幕中，我们将简要介绍如何使用分析来分析样式以及 Safari 浏览器如何向我们呈现这些信息。我们只会查看我们的样式的布局和渲染。使用我们之前构建的单页面应用程序，我们将查看我们的样式的有效性，并查看我们的样式在与应用程序的呈现层相关的方面的弱点和优势。

让我们从查看我们的单页面应用程序的仪表板视图开始，Safari 调试工具已打开，并处于配置文件选项卡（时钟符号）上。

![分析我们的 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_16.jpg)

Safari 分析工具

当我们首次加载我们的单页面应用程序并查看页面加载的分析时，我们会看到三个不同的时间轴，包括**网络请求**，**布局和渲染**和**JavaScript 和事件**。对于我们的目的，让我们看看**布局和渲染**。

当我们查看**布局和渲染**时间轴时，我们可以看到重绘和重排计算是在页面加载时进行的。调试器还让我们知道运行了什么类型的进程，何时运行以及更改了哪些属性，包括其开始时间和持续时间。在寻找页面性能泄漏时，这些都非常有帮助。但是，运行时分析呢？嗯，调试器也有这个功能。

实际上，在我们的左侧边栏上有一个圆圈，与**Profiles**选项卡在同一行，它允许我们对 JavaScript 或 CSS 进行分析。这很棒，因为当我们启用它时，我们将开始对应用程序进行运行时分析。因此，假设我们启用了对 CSS 的分析，然后在应用程序中点击**Profile**选项卡以切换页面视图；我们肯定会执行一些更改，使我们的样式发生变化。当我们这样做并停止我们的 CSS 分析时，我们会得到以下结果：

![分析我们的 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_17.jpg)

Safari 分析工具-运行时分析

当我们分析我们的分析时，我们可以看到正在使用的选择器，它们渲染的总时间，页面上的匹配数以及它们的来源。这是对发生了什么样的处理进行了很好的分解，并让我们对每个选择器查找和渲染所花费的时间有了一个很好的概念，从而让我们知道可以改进什么。鉴于我们为本书的应用程序很小，但如果你正在开发一个包括复杂动画或渲染数千行数据的应用程序，这将在调试您的移动应用程序时非常有用。

一旦我们对我们的应用程序的瓶颈有了一个很好的想法，我们就需要采取一些行动。拥有这些信息为我们提供了关于应用程序性能的关键信息以及我们应该关注的内容。优化阶段是基于每个团队或个人面临的问题和项目需求的，因此在下一节中，我们将讨论一些用于更快渲染和匹配我们样式的优化技术。

## 优化我们的 CSS

在这一部分，我们简要介绍了一些行业标准，这些标准通过提供高效、可维护和精心制作的模块化样式来帮助我们优化应用程序的渲染时间。这些标准已经被业内知名的个人和组织广泛讨论，并最终被各种框架采纳。当然，这里讨论的标准可能随着时间的推移和浏览器实现更好的处理方法而发生变化，使新技术更快、更高效，但这应该是任何希望创建符合当今需求的样式表的人的良好起点指南。

### 避免通用规则

不要在规则中使用`*`选择器。这会选择 DOM 中的每个元素，因此它们的遍历方法是低效的。

例如，以下是极其低效的：

```html
header > *
```

前面的代码之所以效率低，是因为它使用了通用选择器。因为 CSS 是从右到左读取的，引擎会说“让我们选择所有元素，然后看它们是否与标题元素直接相关”。因为我们需要遍历整个 DOM，所以这个选择器的渲染比像这样的东西要慢得多：

```html
header > h1
```

## 不要限定 ID 或类规则

限定 ID 或类涉及直接将标签名称与适当的选择器相结合，但出于与前一条规则相同的原因，这是极其低效的。

例如，以下所有选择器都是不好的：

```html
input#name-text-field

.text-field#name-text-field

input.text-field

.text-field.address-text-field
```

尽管其中一些可能看起来很诱人，但它们是不必要和低效的。但是，这里有一个例外；如果我们想通过向元素添加类来更改样式，那么限定类可能是必要的。无论如何，我们可以通过以下方式来纠正前面的限定 ID 或类。

```html
#name-text-field

.text-field

.text-field.address-text-field
```

正如前一段提到的，最后一个选择器在通过 JavaScript 基于用户操作更改元素样式时可能更有用。

### 永远不要使用!important

这条规则相当不言自明。使用它来覆盖样式肯定很诱人，但不要这样做；随着您的应用程序变得更加复杂，这只会带来麻烦。因此，请查看下一条规则。

### 模块化样式

创建通用于 Web 应用程序或网站的样式非常容易；然而，如果我们开始以模块化的方式思考，我们就会开始创建专门用于该应用程序部分的样式。例如，考虑一个表单及其输入，假设我们希望网站上的所有表单都包含具有棕色边框的文本字段。我们可以这样做：

```html
form .text-field { border: 1px solid brown; }
```

现在我们已经将所有包含在`form`元素内的类为`.text-field`的字段保留为这种样式。因此，如果任何类为`.text-field`的输入字段在此选择器之外，我们可以按照自己的方式进行样式设置。或者，我们也可以这样覆盖样式：

```html
form .personal-information .text-field { border: 1px solid blue; }
```

现在，如果我们在原始样式之后包含这个样式，它将优先使用，因为我们实际上使用了使我们的样式更高效和更易管理的级联原则。

### 提示

请记住，后代选择器是最昂贵的选择器。然而，它们非常灵活，因此我们不应该为了高效的 CSS 而牺牲可维护性或语义。

在大多数情况下，这些规则应该足够了，但您很可能会发现实施一些其他行业中已经写过的最佳实践是有用的。当然，您应该使用您所使用的框架采用的最佳实践，或者更好的是适合您的团队。我发现这些对我非常有帮助，是一个很好的起点，我鼓励您根据需要进行研究和实验。现在，让我们看看如何优化我们的应用的 JavaScript。

# 优化 JavaScript

现在我们已经涵盖了样式表的优化，让我们看看我们的脚本。JavaScript 也曾经被毫无考虑或计划地放在页面上，总的来说给这门语言带来了不好的声誉。但是，由于 Web 应用程序的复杂性，开源社区已经帮助塑造了这门语言。

在整本书中，我们采用了几个行业标准，包括命名空间、闭包、缓存变量等。然而，验证和分析我们的脚本也是必不可少的，以便进行优化。在本节中，我们将介绍这一点，并希望涵盖制作高性能移动应用所需的主要要点。

## 使用 JSLint 验证 JavaScript

近年来，出现了各种工具来帮助我们验证 JavaScript。诸如 JSLint 和 JSHint 之类的工具已经被创建，以帮助我们编码，类似于 CSS Lint。但为什么我们应该使用这些工具，特别是对于 JavaScript 呢？JSLint 的网站（[`www.jslint.com/lint.html`](http://www.jslint.com/lint.html)）提到了工具背后的原因：

> JavaScript 是一种年轻但成熟的语言。最初，它是用来在网页中执行一些小任务的，这些任务对于 Java 来说太笨重、太笨拙了。但 JavaScript 是一种令人惊讶的功能强大的语言，现在它也被用于更大的项目中。许多旨在使语言易于使用的功能在项目变得复杂时会带来麻烦。JavaScript 需要一个语法检查器和验证器：JSLint。

JSLint 的网站还提到了以下内容：

> JavaScript 是一种松散的语言，但在其中有一种更优雅、更好的语言。JSLint 可以帮助您使用更好的语言进行编程，并避免大部分松散。JSLint 会拒绝浏览器会接受的程序，因为 JSLint 关心您的代码质量，而浏览器不关心。您应该接受 JSLint 的所有建议。

要测试我们的 JavaScript，我们可以轻松访问 JSLint 的网站（[`www.jslint.com/`](http://www.jslint.com/)）：

![使用 JSLint 验证 JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_11.jpg)

JSLint 网站

正如您所看到的，JSLint 与 CSS Lint 非常相似，您只需要将 JavaScript 输入到页面上，结果就会显示出来。让我们看看成功和失败的输出会是什么样子。

### 使用 JSLint 验证成功的例子

在我们的例子中，我们将利用我们的`App.js` JavaScript 来测试 JSLint 实用程序。当我们运行这个文件时，成功的输出将详细列出闭包中使用的方法、变量和属性。让我们看看以下截图：

![使用 JSLint 验证成功的例子](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_12.jpg)

使用 JSLint 进行成功验证 - 方法和变量

前面的例子是使用 JSLint 进行成功验证的顶视图。验证器将返回一个以所有全局对象列表开头的列表。然后它将继续列出方法、变量以及每个的一些细节。例如，`initVideo`返回`this`或`App`的一个实例等等。

![使用 JSLint 验证成功的例子](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_13.jpg)

使用 JSLint 进行成功验证 - 属性

### 验证失败的例子

如果不修改 JSLint 选项，使用与前一个相同的例子将产生多个错误。这些错误主要是空格、间距和处理器不知道的全局对象。

![验证失败的例子](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_14.jpg)

JSLint - 验证失败

根据前面的输出，错误以红色列出，包括描述、示例代码和错误发生的行号，让您轻松调试应用程序。现在，假设我们不希望空格或间距实际影响验证结果；那么我们可以定制 JSLint 的选项。

### 可定制选项

与本章讨论的大多数工具一样，JSLint 也提供了可以根据我们的需求定制的选项。让我们简要回顾一下网站上提供给我们的一些选项。

![可定制选项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_15.jpg)

JSLint - 选项屏幕

对我们可用的选项非常广泛，从空格格式到对我们所有放在 JavaScript 中的`TODO`注释的正确性的容忍。当然，其中一些选项可能在测试时不符合我们的需求，但总的来说，它们非常有助于保持一致的编码标准，提供跨平台有效的脚本。

### 集成 JSLint

与 CSS Lint 类似，JSLint 可以在您喜欢的 IDE 或文本编辑器中使用。许多供应商已经创建了插件或扩展工具，使您可以在输入或保存代码时轻松进行代码检查。例如，Sublime Text 有一个`SublimeLinter`包，其中包括 CSS Lint、JSLint 以及其他一些可以帮助您更高效编码的工具。这是如何可能的？

*JSLint 可以在任何可以运行 JavaScript（或 Java）的地方运行。例如* [`github.com/douglascrockford/JSLint/wiki/JSLINT`](https://github.com/douglascrockford/JSLint/wiki/JSLINT)。

有关更多详细信息，请参考以下内容：

[`github.com/douglascrockford/JSLint`](https://github.com/douglascrockford/JSLint)

JSLint 本质上是一个 JavaScript 方法，可以传入代码，然后由 JavaScript 本身进行评估，使其非常高效地处理您的代码并集成到其他环境中。因此，如果您的文本编辑器或 IDE 中还没有它，您可以轻松创建一个扩展，帮助您使用 JSLint 编写高质量的代码。

## 对我们的 JavaScript 进行分析

与 CSS 性能分析一样，在 Web 的旧时代，测试 JavaScript 的性能是非常困难的。然而，这些天我们不需要太担心这个问题，因为几乎每个浏览器调试器都实现了一种对脚本进行性能分析的方法。使用 Safari 内置的调试工具，我们将了解如何调试我们应用程序的脚本性能。

在以下示例中，我们将仅仅讨论我们之前构建的单页面应用程序中 JavaScript 的性能分析，类似于我们在上一节中对样式进行性能分析的做法。

![对我们的 JavaScript 进行性能分析](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_18.jpg)

Safari 性能分析工具- JavaScript

前面的截图是页面加载时脚本的回顾。当我们查看“JavaScript & Events”时间轴时，我们可以得到每个脚本的类型、细节、位置、开始时间和持续时间的详细信息，这些都对脚本时间轴的结果有所贡献。虽然开始时间是我们肯定想要知道的，以便查看可能阻塞脚本（其他脚本），但持续时间可能更重要，因为如果每个脚本不是异步加载的话，它们可能会阻塞页面渲染的过程。

除了查看脚本对页面加载的影响之外，我们还可以对脚本执行的功能进行性能分析。例如，假设我们想要检测当我们在应用程序中点击“Profile”按钮时我们的方法的执行情况。这可以很容易地通过与对 CSS 进行性能分析相同的技术来实现，点击“Profile”选项卡中的圆圈并启用 JavaScript 的性能分析；我们将能够看到所有调用的方法及其性能。

![对我们的 JavaScript 进行性能分析](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_09_19.jpg)

Safari 性能分析工具- JavaScript 运行时

根据我们之前的用例，我们可以很容易地详细了解我们应用程序的性能。从这个例子中我们可以得知，我们的`onProfileClick`事件大约需要 8.40 毫秒来执行，并且只调用了一次。然而，更重要的是，我们可以看到所有被调用的方法以及执行顺序，这是非常有用的信息，可以帮助我们检测内存泄漏和性能优化，这对我们的应用程序是必要的。

从这些非常基本的示例中，我们可以看到调试我们的应用程序性能比以往任何时候都更容易。我们可以对 JavaScript 进行性能分析，了解我们的应用程序的运行情况和代码的效率。但是既然我们有了这些信息，我们可以做些什么来改进我们的代码库呢？这就是我们在下一节要解决的问题，一些通用的优化技巧，我们都可以使用这些技巧来提高我们的应用程序的性能，而不会牺牲代码质量。

## 优化我们的 JavaScript

JavaScript 是高度可扩展的，允许我们几乎做任何我们想做的事情-这很棒，但也可能非常有害。例如，你可以很容易地忘记在变量前使用关键字`var`。然而，我们不希望这样做，因为这会使我们的变量在全局范围内可用，这可能会与其他脚本发生冲突，这些脚本可能使用完全相同的变量名。我们也可以很容易地将我们的 JavaScript 包装在`try...catch`语句中，这并不是最佳实践，因为我们并没有找出问题所在。或者，如果我们想的话，我们可以很容易地使用`eval`来评估一串 JavaScript，而不进行任何错误检查。

因此，该行业已经采用了多种经过验证的最佳实践，这些最佳实践由最常用的开源库实施，包括 jQuery、Backbone 和 Underscore。在本节中，我们简要介绍了我所基于的书籍的最佳实践，以及我认为对任何应用程序的成功至关重要的最佳实践。

### 避免全局变量

在全局范围内或在我们应用程序中创建的闭包之外创建所有变量和函数非常容易且诱人。但不要这样做；这是一个糟糕的想法，并且因为几个原因而受到社区的鄙视。例如，如果一个变量保留在全局范围内，它必须在整个应用程序的执行过程中进行维护，从而降低应用程序的性能。

所以，而不是这样做：

```html
Var Modal = function(){};
```

你应该这样做：

```html
(function(){ function Modal(){} }());
```

前面的技术与我们一直在做的非常相似。实际上，这就是我们所谓的闭包或**立即调用的函数表达式**（**IIFE**）。当我们将一个方法包装在括号内，然后使用`()`调用它时，我们立即调用该方法并创建一个新的包含范围，因此括号内的任何内容在全局范围内不可用，使我们的代码更易管理。

### 不要触及 DOM

嗯，我们可能不会这样做，但我们肯定应该尽量减少。访问 DOM 是昂贵的，并且在应用程序性能方面存在问题。因此，让我们来看一个用例，比如更新信息列表。

避免这样做：

```html
var $list = $('ul');

for (var i; i < 100; i++) {
  var li = '<li>' + i + '</li>';

  $list.append(li);
}
```

相反，你应该这样做：

```html
var $list = $('ul'),
  liArray = [];

for (var i; i < 100; i++) {
  liArray.push('<li>' + i + '</li>');
}

$list.append(liArray.join(''));
```

两者之间的区别在于前者每次创建列表项时都会触及 DOM，而后者会将每个项目推到一个数组中，当涉及到追加时，将数组与空字符串连接，只触及 DOM 一次。

### 使用文字

这可以在我们整本书的代码库中看到。这更有效，因为我们不使用`new`关键字。例如，我们可以使用`Array`文字，而不是通过新关键字声明一个新变量，就像这样：

```html
var arr = []; // not new Array();
var str = ''; // not new String('');
```

### 模块化功能

为了保持代码的模块化，您需要确保每个函数或类都有特定的功能集合。大多数情况下，每个函数可能应该是大约 10 到 15 行代码，实现特定的目标。

例如，您可以编写以下功能：

```html
function init() {
  var $list = $('ul'),
    liArray = [];

  for (var i; i < 100; i++) {
    liArray.push('<li>' + i + '</li>');
  }

  $list.append(liArray.join(''));	

  $list.on('click', function() {
    // do something
  });
}
```

而不是编写前面的代码，我们可以这样做：

```html
function populateLists() {
  var $list = $('ul'),
    liArray = [];

  for (var i; i < 100; i++) {
    liArray.push('<li>' + i + '</li>');
  }

  $list.append(liArray.join(''));	

  return $list;
}

function attachListsEvents($list) {
  $list.on('click', doSomething);
}

function doSomething(e) {
  // do something
}

function init() {
  var $list = populateLists();

  attachListsEvents($list);
}
```

正如您所看到的，代码已经模块化，以执行特定的功能集，使我们能够创建运行特定指令集的方法，每个方法都以名称描述。这对于维护我们的代码库并提供有效的功能非常有用。

# 总结

在这一章中，我们考虑了优化应用程序各个部分的性能，包括样式、脚本和媒体。我们讨论了验证、优化和分析我们的样式和脚本。此外，我们简要介绍了如何优化我们的媒体，包括图像、音频和视频。现在我们对本书中用于优化应用程序的技术有了坚实的理解，下一章中，我们将看看可以帮助我们使用 HTML5、CSS3 和 JavaScript 交付原生应用程序的框架。


# 第十章：创建本机 iPhone Web 应用程序

在本章中，我们将研究如何使用 PhoneGap 框架将我们的 iOS Safari 本机应用程序转移到本机环境。我们将深入设置我们的开发环境，包括设置 Xcode IDE 和使用 iOS 模拟器。我们将构建一个`HelloWorld`示例，以演示快速入门的简单性，然后转移我们在第七章构建的单页应用程序，*单页应用程序*。一旦我们在本机应用程序开发上有了坚实的基础，我们将通过使用 PhoneGap 的联系人 API 来绑定本机功能，从而增强单页应用程序，以引入我们的联系人并显示其中一些信息。

我们的目标是帮助您使用单一代码库实现本机应用程序的一致外观和感觉。这里的目标是让您开始使用您已经喜爱和理解的 Web 编程语言进行本机应用程序开发。考虑到这一点，让我们从设置我们的开发环境开始。

在本章中，我们将涵盖：

+   Xcode 安装

+   使用 iOS 模拟器

+   实施 PhoneGap

+   创建`HelloWorld`示例

+   转移当前应用程序，包括 CSS、JavaScript、HTML 和资产

+   使用 PhoneGap 在 iOS 中绑定本机功能的联系人 API

# 设置开发环境

与创建软件的任何工作流程一样，我们的开发环境至关重要。因此，让我们花些时间设置许多工程师喜欢的环境，以创建本机应用程序。在本节中，我们将介绍 Xcode 的安装和集成开发环境（IDE）的概述。我们将继续设置 PhoneGap 框架，最后看看 iOS 模拟器如何在测试我们的应用程序中发挥关键作用。作为一个额外的奖励，我们将在本章中看看如何配置我们的应用程序以满足我们的需求。所以让我们开始吧。

## 开始使用 Xcode

Xcode 是 iOS 操作系统上本机应用程序开发的首选 IDE，因为它得到了苹果的积极支持，并专门针对 OS X 和 iOS 操作系统进行了定制。这个 IDE 由苹果提供，可以用来创建 Mac OS X、iPhone 和 iPad 应用程序。虽然它也可以用于其他各种类型的开发，但这三个平台最常与 Xcode 相关。默认情况下，您的 Mac 没有预装 Xcode，所以我们需要安装它。

### 安装 Xcode

幸运的是，Xcode 非常容易安装。我们可以通过 Mac App Store（[`itunes.apple.com/us/app/xcode/id497799835?ls=1&mt=12`](https://itunes.apple.com/us/app/xcode/id497799835?ls=1&mt=12)）安装这个 IDE。安装完成后，我们的计算机上将安装各种软件，包括 Instruments 分析工具、iOS 模拟器和最新的**Mac OS X 和 iOS 软件开发工具包**（**SDK**）。

### Xcode IDE 概述-基础知识

默认情况下，Xcode IDE 安装在应用程序目录中；双击显示的图标启动它。图标是一个对角放置在蓝色技术图纸上的锤子，上面有一个形成字母 A 的铅笔、刷子和尺子。应用程序启动时，我们将看到欢迎屏幕。

![Xcode IDE 概述-基础知识](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_01.jpg)

欢迎屏幕

这是 Xcode 的欢迎屏幕，列出了最近的项目和创建新项目、连接到存储库、了解 Xcode 或查看苹果开发者门户网站的能力。在您的屏幕上，您很可能不会看到前面截图中列出的`HelloWorld`项目，这是我们将要构建的项目，如果这是您第一次，它应该是空的。

### 提示

因为这一部分是让我们熟悉 Xcode 本身，不要担心接下来的几个屏幕。接下来的屏幕是我们要构建的，但只是为了帮助我们识别 Xcode 应用程序的某些部分，以便更容易使用。

#### Xcode 工作区

现在，让我们了解 Xcode 的用户界面，以了解如何利用这个强大的工具。首先，正如我们已经知道的，当我们打开应用程序时，会看到欢迎屏幕。您可以选择通过在欢迎屏幕上取消选中**Xcode 启动时显示此窗口**复选框来禁用此功能。但是当我们打开一个已创建的项目时，它看起来是这样的：

![Xcode 工作区](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_02.jpg)

项目显示

看起来很简单对吧？这很好，因为这被称为工作区，这很关键，因为 Xcode 旨在使所有开发工作都集中在 IDE 的一个中心窗口中，帮助我们整合和加快开发过程。但要认识到这个工作区的两个关键方面：左侧的导航器区域，其中包含我们所有的文件，以及我们可以编辑所在项目的编辑器区域。

![Xcode 工作区](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_03.jpg)

导航器和编辑器区域

前面的截图有助于演示 Xcode 在开发应用程序时的两个最关键的方面。请记住，根据所选的文件，您的编辑器区域会发生变化。例如，在前面的截图中，我们有一个 GUI，可以让我们设置项目的属性。

#### Xcode 工具栏

Xcode 工具栏具有各种功能，我们在开发原生应用程序时会经常使用。例如，在下面的截图中，有**Run**、**Stop**和**Breakpoints**按钮，以及**Scheme**选择器。在调试应用程序时，这些操作非常重要。**Run**按钮会运行您的应用程序。另一方面，**Stop**按钮将停止运行应用程序的所有活动。**Breakpoints**按钮将在编辑器区域显示我们的断点。

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_04.jpg)

显示运行、Scheme 和断点的工具栏

**Scheme**选择器允许您选择要测试的应用程序以及要测试的环境。在我们的示例应用程序中，`HelloWorld`将使用 iPhone 6.0 模拟器进行测试，但我们有各种选项可供选择。从下面的截图中可以看到，如果安装了，我们可以使用 iPad 模拟器和各个版本以及 iPhone 模拟器来测试我们的应用程序。

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_05.jpg)

工具栏 Scheme 选择器

工具栏还有各种操作，位于 IDE 右侧，包括编辑器视图、常规视图和组织者。默认的编辑器视图是文本编辑器组件，允许我们对源文件进行基本编辑。中间的编辑器视图是助理编辑器，我们不会涉及。最后的编辑器视图是版本编辑器。

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_06.jpg)

工具栏项目显示选项

版本编辑器对于我们作为开发人员来说非常有用，可以让我们立即编辑文件并查看版本变化。例如，在下面的截图中，我们可以看到添加了注释，并且原始版本文件通知用户更改发生的位置，让我们可以看到同一文件的实时编辑。

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_07.jpg)

项目版本显示

继续讨论**View**工具栏部分，我们有三个按钮。每个按钮根据情况显示对我们有用的编辑器的某个部分。第一个按钮默认选中，因为它显示了左侧的导航器区域。中间的按钮显示了调试区域，如下面的截图所示：

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_08.jpg)

项目调试显示

这很好，因为我们现在可以在应用程序运行时调试应用程序并查看日志。记得我们在应用程序中使用的所有日志吗？它们会显示在这里；如果我们的浏览器中没有非常有用的开发者控制台，它们非常有用。工具栏中的最后一个按钮控制工具。这些工具帮助我们控制当前文件的各种设置；从名称到源代码控制，我们可以定制文件的各种细节。

![Xcode 工具栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_09.jpg)

项目文件配置显示

好的，我们知道了 Xcode 的基本功能，还有很多可以探索的地方，而且作为开发者，它对我们来说既伟大又有益。我们可以继续介绍 Xcode 的所有非常有用的功能，但为了我们的利益，让我们转向 PhoneGap，毕竟我们更感兴趣的是学习如何构建原生应用程序。工具总是可以根据我们的需求使用和定制。

## 设置 PhoneGap

Xcode 在应用程序开发环境中非常好用。然而，PhoneGap 才是魔法发生的地方。它是一个框架，使我们能够基于我们已经用 HTML、CSS 和 JavaScript 编写的代码创建原生应用程序。因此，让我们回顾一下如何安装它，创建一个项目，并简要介绍它的支持和许可，以便为我们自己的应用程序利用其能力做好准备。

### 安装 PhoneGap

PhoneGap 非常容易上手；首先让我们从 PhoneGap 的网站安装它，网址是：[`phonegap.com/download/`](http://phonegap.com/download/)。当 ZIP 文件完全下载完成后，我们需要提取其内容。现在当您开始检查提取的内容时，您会注意到有很多内容，特别是在`lib`目录中列出了多个操作系统。这很好，因为 PhoneGap 支持多个平台，但我们想要的是特别针对 iOS 的。我们的重点应该放在以下内容上：

![安装 PhoneGap](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_10.jpg)

PhoneGap 目录结构

请注意，在 iOS 目录中，我们有多个文件，所有这些文件对于创建我们的第一个 PhoneGap 项目至关重要。在接下来的部分中，我们将使用这个经过简化的 PhoneGap 框架创建我们的第一个 PhoneGap 项目。

### 创建一个 PhoneGap 项目

现在我们已经下载并简化了 PhoneGap 框架以满足我们的需求，我们想要使用这个框架创建我们的第一个项目。为了做到这一点，我们需要我们值得信赖的**命令行界面**（**CLI**）的帮助。默认情况下，所有 Mac 操作系统都带有**终端**，但我们也可以使用 iTerm（免费）。无论哪种方式，启动该应用程序，它位于`/Applications/Utilities/`。

当您打开终端时，我们需要导航到 PhoneGap 文件所在的目录。默认情况下，这应该在我们的`Downloads`目录中，具体取决于您的浏览器设置。在这种情况下，我会使用`cd`命令导航到`/Users/acresp/Downloads`，如下所示：

```html
cd /Users/acresp/Downloads
```

一旦我们进入 PhoneGap 解压到的目录，我们需要导航到`phonegap`文件夹内`iOS`文件夹内的`bin`目录以查看。为此，我们可以输入以下内容：

```html
cd phonegap-2.5.0/lib/ios/bin/
```

现在我们可以使用`bin`文件夹内的`create` shell 脚本构建我们的 PhoneGap 应用程序。该脚本的文档如下：

```html
#
# create a Cordova/iOS project
#
# USAGE
#   ./create <path_to_new_project> <package_name> <project_name>
#
# EXAMPLE
#  ./create ~/Desktop/radness org.apache.cordova.radness Radness
#
```

这对我们来说非常好，因为我们知道可以轻松创建我们的应用程序。但在这之前，让我们确保我们的应用程序目录已经在我们的项目中创建了。在本章中，我创建了一个`cordova250`目录，其中包含我们的`HelloWorld`应用程序，可能还包含其他 PhoneGap 项目。

现在我们已经确保我们的应用程序目录存在，我们可以运行以下命令来确保我们的应用程序被创建：

```html
./create ~/Sites/HTML5-iPhone-Web-App/cordova250/HelloWorld .org.apache.cordova.HelloWorld HelloWorld
```

这将在`cordova250`文件夹内产生一个名为`HelloWorld`的目录，其中包含我们启动所需的所有必要文件。我们现在已经创建了我们的第一个 PhoneGap 项目。目前还没有太多的事情发生，但让我们继续；我们很快就会开始开发原生应用程序。首先，让我们回顾一下这个框架的支持以及支持它的许可证。

### PhoneGap 许可证

您可能会对 PhoneGap 许可证感到好奇，特别是因为我们在创建应用程序的过程中使用了许多开源项目。PhoneGap 基于 Apache 许可证（[`phonegap.com/about/license/`](http://phonegap.com/about/license/)）。对我们来说更好的是，Apache 基金会为我们提供了清晰简明的关于允许、禁止和要求的信息。直接来自*常见问题*部分的*这意味着什么？*部分（可在[`www.apache.org/foundation/license-faq.html#WhatDoesItMEAN`](http://www.apache.org/foundation/license-faq.html#WhatDoesItMEAN)找到），我们得到了所有我们需要的细节：

> 它允许您：
> 
> 自由下载和使用 Apache 软件，全部或部分，用于个人、公司内部或商业目的；
> 
> 在您创建的软件包或分发中使用 Apache 软件。
> 
> 它禁止你：
> 
> 在没有适当归属的情况下重新分发任何 Apache 来源的软件;
> 
> 以任何方式使用 Apache 软件基金会拥有的标记，可能会声明或暗示基金会支持您的分发;
> 
> 以任何方式使用 Apache 软件基金会拥有的标记，可能会声明或暗示您创建了相关的 Apache 软件。
> 
> 它要求你：
> 
> 在任何包含 Apache 软件的重新分发中包含许可证的副本;
> 
> 为包含 Apache 软件的任何分发提供清晰的归属于 Apache 软件基金会。
> 
> 它不要求你：
> 
> 在任何包含 Apache 软件的重新分发中，包括 Apache 软件本身的源代码，或者您对其进行的任何修改;
> 
> 提交您对软件所做的更改给 Apache 软件基金会（尽管鼓励这样的反馈）。

基于这些参数，我们可以继续使用 PhoneGap 创建开源软件，只要我们在每次重新分发时包含许可证的副本，同时清晰地归属于 Apache 软件基金会。如果您有任何与 PhoneGap 许可证或 Apache 2.0 许可证相关的其他问题，可以在上述链接和 PhoneGap 许可证页面（[`phonegap.com/about/license/`](http://phonegap.com/about/license/)）上找到更多信息。

## 配置我们的项目

我们的项目可以配置以满足我们的需求，同时也满足我们的用户需求。这个过程非常简单，并且在 PhoneGap API 文档网站（[`docs.phonegap.com/en/2.5.0/guide_project-settings_index.md.html#Project%20Settings`](http://docs.phonegap.com/en/2.5.0/guide_project-settings_index.md.html#Project%20Settings)）上有很好的文档。大多数这些设置都可以通过我们项目目录`/cordovar250/HelloWorld/HelloWorld/config.xml`中的`config.xml`文件轻松修改。

以下是可以定制的当前列表：

| 首选项 | 描述 |
| --- | --- |
| `UIWebViewBounce`（布尔值，默认为**true**） | 这设置了橡皮筋类型的交互/弹跳动画的属性。 |
| `TopActivityIndicator`（字符串，默认为**gray**） | 这设置了状态/电池栏中旋转的指示器的颜色，有效值为**whiteLarge**、**white**和**gray**。 |
| `EnableLocation` (布尔值，默认为**false**) | 这确定是否在启动时初始化地理位置插件，使您的位置在启动时更准确。 |
| `EnableViewportScale` (布尔值，默认为**false**) | 这启用/禁用视口缩放。 |
| `AutoHideSplashScreen` (布尔值，默认为**true**) | 这控制着是否通过 JavaScript API 隐藏启动画面。 |
| `FadeSplashScreen` (布尔值，默认为**true**) | 这使启动画面淡入淡出。 |
| `FadeSplashScreenDuration` (浮点数，默认为**2**) | 这表示启动画面的淡入淡出持续时间（以秒为单位）。 |
| `ShowSplashScreenSpinner` (布尔值，默认为**true**) | 这显示或隐藏启动画面的加载旋转器。 |
| `MediaPlaybackRequiresUserAction` (布尔值，默认为**false**) | 这允许 HTML5 自动播放。 |
| `AllowInlineMediaPlayback` (布尔值，默认为**false**) | 这控制内联 HTML5 媒体播放。HTML 文档中的`video`元素还必须包括`webkit-playsinline`属性。 |
| `BackupWebStorage` (字符串，默认为**cloud**) | 如果设置为**cloud**，存储数据将备份到 iCloud。如果设置为**local**，只会进行本地备份。如果设置为**none**，则不会发生任何备份。 |
| `KeyboardDisplayRequiresUserAction` (布尔值，默认为**true**) | 如果设置为**false**，当通过 JavaScript 的`focus()`调用`form`元素时，键盘将打开。 |
| `SuppressesIncrementalRendering` (布尔值，默认为**false**) | 这允许在渲染之前接收内容。 |

# 转移网络应用

此时，我们已经使用 PhoneGap 和 Xcode 创建了一个名为`HelloWorld`的示例应用程序。现在，我们将通过回顾从第七章*单页应用程序*转移我们的单页应用程序。在本节中，我们将介绍如何转移我们的资产，包括我们的标记、样式和脚本，然后学习如何调试我们的应用程序。最后，我们将通过使用 PhoneGap 允许我们利用已经编写的代码来扩展我们的单页应用程序，使用本机功能来扩展我们的单页应用程序。

## 转移我们的资产

让我们开始转移我们的资产。本节将简要介绍如何以最小的努力转移我们所写的内容。这里的目标基本上是拥有与本地运行的相同应用程序。我们暂时不会使用 PhoneGap 的内置功能，但我们将很快拥有一个正在运行的应用程序。

### 包括我们的标记

我们要做的第一件事是打开之前使用 PhoneGap 生成的 Xcode 项目。为此，我们首先在 Finder 中找到我们的项目，在我的情况下是`~/Sites/HTML5-iPhone-Web-App/cordova250/HelloWorld/`。一旦找到我们的项目，双击`HelloWorld.xcodeproj`文件；这将在 Xcode 中启动项目。

一旦 Xcode 启动了我们的项目，我们将看到它索引我们的文件。在索引过程中，它不会阻止您与项目进行交互，因此您可以开始编辑文件。因此，让我们继续查看位于`www`目录中的`index.html`文件。

![包括我们的标记](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_11.jpg)

我们项目的初步 HelloWorld 标记

正如您所看到的，我们已经为我们设置了一个基本模板。让我们运行这个`HelloWorld`标记，看看结果。您应该首先看到的是一个带有默认 PhoneGap 图像的启动画面，紧接着是设备准备好的介绍。以下是显示结果的屏幕截图：

![包括我们的标记](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_12.jpg)

启动画面和设备准备好画面

现在我们知道我们的应用程序正在使用默认的标记和样式运行，我们应该能够相当快地移动。因此，首要任务是从第七章 *单页应用*中看到的单页应用程序屏幕中带有完成标记的导入。我们不会在这里回顾为该章节编写的代码，但这是模板：

```html
<!DOCTYPE html>
<html class="no-js">
<head>
    <meta charset="utf-8">
    <title></title>

    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="format-detection" content="telephone=no" />
    <meta name="viewport" content="user-scalable=no, initial-scale=1, maximum-scale=1, minimum-scale=1, width=device-width, height=device-height, target-densitydpi=device-dpi" />

    <link rel="stylesheet" href="css/normalize.css">
    <link rel="stylesheet" href="css/main.css">
    <link rel="stylesheet" href="css/singlepage.css">
    <script src="img/modernizr-2.6.1.min.js"></script>
</head>
    <body>
        <div class="app">
            <div id="deviceready" class="blink">
                <p class="event listening">Connecting to Device</p>
                <div class="event received site-wrapper">
                    <header>
                        <hgroup>
                            <h1>iPhone Web Application Development</h1>
                            <h2>Single Page Applications</h2>
                        </hgroup>
                    </header>
                    <div class="content"></div>
                    <footer>
                        <p>iPhone Web Application Development &copy; 2013</p>
                    </footer>
                </div>
            </div>
        </div>
    </body>
</html>
```

请记住，我们已经进行了一些修改，以适应这个目录结构。例如，我们不再使用`../css/somefile.css`来引用我们的 CSS 文件，而是使用`css/somefile.css`，其他资产也是如此。您还会注意到，前面的代码模板不包括我们从第七章 *单页应用*中创建的模板；这是为了使前面的模板在如何导入资产到您自己的 PhoneGap 项目方面保持简短和简单。

在这一点上，我们不会测试我们的应用程序，因为我们还没有导入我们的资产，包括样式和脚本，但我们现在应该还不错。我们想要在这里得到的是，导入现有的静态 Web 应用程序就像复制和粘贴一样简单，但不要被这个愚弄；大多数应用程序并不像这样简单，这个例子只是为了演示开始的简单。现在让我们继续导入我们的样式。

### 整合我们的样式

我们现在在我们的项目`index.html`文件中设置了标记。这很容易；这部分也将很容易。我们需要做的就是包含用于此项目的 CSS 文件。为了简化，我只是将我们以前的所有样式表都包含到 Xcode 项目的 CSS 目录中。您的项目现在应该是这样的：

![整合我们的样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_13.jpg)

我们导入的样式表

现在我们已经将我们的样式表导入到 Xcode 项目中，我们已经完成了一半。在这一点上，我们需要导入我们的脚本。同样，在这里不要测试您的应用程序，因为它可能不起作用。这最后一点将使我们达到我们需要的地方，所以让我们开始导入我们的脚本。

### 插入我们的脚本

好的，我们已经导入了我们的标记和样式表，这很棒。但还有最后一部分，我们的 JavaScript。这最后一部分对于使我们的应用程序运行至关重要。因此，让我们开始做与我们的样式相同的事情；只需将所有脚本导入 Xcode 项目的`js`目录中。当您这样做时，结果将如下所示：

![插入我们的脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_14.jpg)

我们导入的脚本

我们的脚本在 Xcode 项目中。但我们仍然需要进行一些配置，包括在`index.html`文件中正确引用我们的脚本，并确保我们的应用程序将按预期启动。让我们首先在`index.html`文件中正确引用我们的脚本。

还记得两节前我们转移过的标记，展示了一个默认模板吗？我们要退一步再次看看那个模板，除了我们只会看标记底部在`body`标签关闭之前。这是我们的应用程序以前包含 JavaScript 的地方；所以这里没有什么新的，我们只是想确保文件被正确引用。只需确保在您的`index.html`文件中，您的脚本看起来像这样：

```html
        <!-- BEGIN: LIBRARIES / UTILITIES-->
        <script src="img/cordova-2.5.0.js"></script>
        <script src="img/zepto.min.js"></script>
        <script src="img/underscore-1.4.3.js"></script>
        <script src="img/backbone-0.9.10.js"></script>
        <script src="img/helper.js"></script>
        <!-- END: LIBRARIES / UTILITIES-->
        <!-- BEGIN: FRAMEWORK -->
        <script src="img/App.js"></script>
        <script src="img/App.Nav.js"></script>
        <script src="img/BaseView.js"></script>
        <!-- END: FRAMEWORK -->
        <!-- BEGIN: MUSIC PLAYLIST APPLICATION -->
        <script src="img/Music.js"></script>
        <script src="img/SongModel.js"></script>
        <script src="img/SongCollection.js"></script>
        <script src="img/SongView.js"></script>
        <script src="img/PlayListView.js"></script>
        <script src="img/AudioPlayerView.js"></script>
        <!-- END: MUSIC PLAYLIST APPLICATION -->
        <!-- BEGIN: USER APPLICATION -->
        <script src="img/User.js"></script>
        <script src="img/UserModel.js"></script>
        <script src="img/DashboardView.js"></script>
        <script src="img/ProfileView.js"></script>
  <!-- END: USER APPLICATION -->
        <script src="img/main.js"></script>
        <!-- END: BACKBONE APPLICATION -->
    </body>
</html>
```

注意这里发生的一些事情。首先，我们在最顶部包含了 PhoneGap 提供的`cordova`库；当我们尝试检测`deviceready`事件时，这将是至关重要的。接下来，我们将所有 JavaScript 源文件引用到 Xcode 项目中的`js`目录，而不是`../js`。现在，我们需要做的最后一件事是确保我们的代码在设备准备就绪时运行，这意味着我们需要修改我们的单页应用程序的启动方式。

为了确保我们的应用程序启动，我们需要监听 PhoneGap 事件提供的`deviceready`事件（[`docs.phonegap.com/en/2.5.0/cordova_events_events.md.html#deviceready`](http://docs.phonegap.com/en/2.5.0/cordova_events_events.md.html#deviceready)）。一旦 Cordova 完全加载，就会触发此事件。这是至关重要的，因为在本地代码加载时 DOM 没有加载，并且启动画面被显示。因此，当 DOM 加载之前需要 Cordova 函数时，我们可能会遇到问题。因此，为了我们的目的，我们将监听`deviceready`事件，然后启动我们的应用程序。可以使用以下代码完成：

```html
<script>
    (function(){
     document.addEventListener('deviceready', onDeviceReady, false);

     function onDeviceReady(){
        console.log("onDeviceReady");
        var parentElement,
            listeningElement,
            receivedElement;

        parentElement = document.getElementById('deviceready');
        listeningElement = parentElement.querySelector('.listening');
        receivedElement = parentElement.querySelector('.received');

        listeningElement.setAttribute('style', 'display:none;');
        receivedElement.setAttribute('style', 'display:block;');

        // Start our application
        Backbone.history.start();
     }
    }());
</script>
```

让我们逐行检查这段代码。首先，我们创建一个立即执行的闭包。在这个范围内，我们监听`deviceready`事件并分配`onDeviceReady`回调函数。然后，我们定义了`onDeviceReady`回调，显示和隐藏我们的应用程序。这个方法创建了三个变量，`parentElement`，`listeningElement`和`receivedElement`。我们缓存了`deviceready` DOM 元素并将其分配给`parentElement`，我们对`listeningElement`和`receivedElement`也做了同样的事情。接下来，我们在适当的元素上设置`style`属性，显示应用程序并隐藏启动画面。最后，我们启动基于 Backbone 的单页应用程序。

让我们将前面的脚本放在`index.html`文件中所有脚本之后。现在，我们应该能够成功运行我们的应用程序并导航到仪表板、个人资料和播放列表视图。如果之前讨论的一切都正确地完成了，您应该能够像这样本地使用您的单页应用程序：

![插入我们的脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_15.jpg)

本地单页应用程序

### 注意

请注意，在前面的屏幕截图中，我们有一个**联系人**导航项。这尚未构建，将成为本章最后一部分的一部分。

到目前为止，我们已经创建了一个本地应用程序，展示了使用 PhoneGap 转移当前 Web 应用程序的简单性。是的，我们没有充分利用 PhoneGap 或 Xcode，但我们现在明白了启动流程是相当容易的。我们将暂时绕过来理解调试我们的应用程序，并最终使用 PhoneGap 的 API 构建本地组件到我们的应用程序中。

## 调试我们的应用程序

调试应用程序对于任何工作流程或流程都是至关重要的；因此，我们需要知道调试基于 Web 技术构建的本地应用程序是什么样的。这并不像你想象的那样复杂或容易。但它仍然是可行的，并且在撰写本文时，这是调试应用程序的最佳方式之一。所以让我们开始吧。

### 记录我们的代码

我们都熟悉通过 JavaScript 可用的控制台对象。这对我们仍然可用，但在创建本地应用程序时，尝试找到日志输出的位置时会有些困惑。传统上，我们在模拟器或实际设备上有一个可用于调试错误的控制台工具；然而，现在不再是这样。

首先，让我们看看 Xcode 中的日志记录是如何进行的。还记得本章前面讨论过的调试视图吗？好吧，这就是我们想要使用它的地方。所以首先，让我们启用调试视图。现在，让我们运行我们目前拥有的应用程序。

当我们运行您的应用程序时，我们应该在调试器区域看到以下内容：

```html
2013-03-16 14:24:43.732 HelloWorld[2322:c07] Multi-tasking -> Device: YES, App: YES
2013-03-16 14:24:44.624 HelloWorld[2322:c07] Resetting plugins due to page load.
2013-03-16 14:24:45.196 HelloWorld[2322:c07] Finished load of: file:///Users/acresp/Library/Application%20Support/iPhone%20Simulator/6.0/Applications/DEEABC2E-C2D6-40F3-A19E-43E4F7F5EB47/HelloWorld.app/www/index.html
2013-03-16 14:24:45.243 HelloWorld[2322:c07] [LOG] onDeviceReady
```

我们应该关注最后一行，即`[LOG]`发生的地方。这是使用`console.log()`生成的输出，目前在我们的`onDeviceReady`回调中。这对我们来说很好，因为我们可以积极地看到我们创建的日志。这样做的负面影响是，我们没有在其他浏览器中找到的典型开发人员工具。但是最近的发展使我们现在可以使用 Safari 内置的开发人员工具来调试在模拟器中运行的 iOS 应用程序。

### 使用 Safari 开发人员工具

正如我之前提到的，我们现在能够使用 Safari 的开发者工具调试基于 PhoneGap 构建的 Web 应用程序。所以让我们快速尝试一下，打开我们电脑上的 Safari。如果您还没有启用开发者工具，请进入 Safari 的偏好设置，并在**高级**选项卡下选择**在菜单栏中显示开发菜单**复选框。

![使用 Safari 开发者工具](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_16.jpg)

Safari 偏好设置的高级选项卡

一旦我们启用了开发者工具，我们可以从 Safari 的**开发**菜单中访问它们。如果我们的应用程序在 iOS 模拟器中运行，那么我们应该能够通过从 iPhone 模拟器子菜单中选择`index.html`来调试我们的应用程序。然后这将在 Safari 中启动本机开发者工具。

![使用 Safari 开发者工具](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_17.jpg)

调试环境

现在我们能够使用 Safari 开发者工具完全调试本机应用程序。拥有一个完全集成的开发环境，模拟和调试都是这个过程的一部分，这真的很容易。虽然我们可以进一步详细讨论调试，但这超出了本书的范围。然而，让我们继续本书的最后一部分，我们将学习如何利用 PhoneGap 的内置 API 来连接到我们单页应用程序的本机功能。

## 扩展我们的应用程序与本机功能

恭喜！我们已经能够使用我们已经创建的 HTML5、CSS 和 JavaScript 创建我们的第一个本机应用程序。这是令人兴奋的事情，但我们还没有完成。现在让我们利用 PhoneGap 的 API 之一来利用本机功能。

从更高的层次上，我们希望我们的应用程序显示我们手机上的联系人。当我们点击应用程序导航中的**联系人**按钮时，我们希望能够访问这些信息。在这个例子中，我们只想显示我们联系人的全名。为了实现这些目标，我们将使用 PhoneGap 的 Contacts API ([`docs.phonegap.com/en/2.5.0/cordova_contacts_contacts.md.html#Contacts`](http://docs.phonegap.com/en/2.5.0/cordova_contacts_contacts.md.html#Contacts))。为此，我们将确保在我们的应用程序中进行了配置，然后编写适当的代码来处理这个问题，已经存在的应用程序框架中。让我们从配置开始。

### 配置我们的应用程序

我们已经在之前讨论了配置我们的应用程序的基础知识，但让我们再次看一下以确保完全理解。首先，让我们打开位于项目顶部的`config.xml`文件。然后通过将其值设置为`CDVContacts`来启用 Contacts API。完成后，您的`config.xml`文件应包含以下内容：

![配置我们的应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_18.jpg)

项目配置

### 设置我们的联系人功能

在本章的这一部分，我们将看看如何连接到我们的联系人信息以在我们的本机应用程序中显示。首先我们将创建视图，然后模板，最后是随 PhoneGap 提供的实际 API。完成后，我们应该对如何利用这些 API 来为 iOS 创建本机 Web 应用程序有一个很好的想法。

#### 创建 ContactsView 类

一旦我们为这个应用程序设置了配置，我们需要设置其他一切以使联系人视图正常工作。首先，让我们创建一个联系人视图，添加到我们的用户目录中。我们稍后会扩展其功能，但现在这是我们将使用的模板：

```html
(function(window, document, $, Backbone, _){

  var ContactsView = App.BaseView.extend({
    'template': _.template($('#tmpl-user-contacts').html()),

    'initialize': function() {

      this.render();
    },

    'render': function() {

      return this;
    }
  });

  window.User.ContactsView = ContactsView;

}(window, document, Zepto, Backbone, _));
```

上述代码并没有什么新东西。我们基本上正在创建一个遵循我们之前设置的约定的`ContactsView`类，没有任何额外的功能。请注意，我们已经为此视图设置了一个尚不存在的模板。让我们在`index.html`中包含此文件，并将其添加到最后一个被包含的视图中。现在，让我们创建与此视图相关联的模板。

#### 实现 ContactsView 模板

使用我们已经为播放列表构建的内容，我们将简单地复制播放列表视图的模板并更改其标题。与此同时，我们还将将无序列表的类更改为`contacts-list`。完成后，我们的模板将如下所示：

```html
<script type="tmpl/User" id="tmpl-user-contacts">
    <section class="view-contacts">
    <header>
    <h1><%= name + "'s" %> Contacts</h1>
    <% print(_.template($('#tmpl-user-nav').html(), {})); %>
    </header>
    <ul class="contacts-list"></ul>
    </section>
</script>
```

在我们创建的其他模板之后包含此模板。此时，我们应该已经完成了 50%。现在，您可能会遇到一些样式问题，但请确保将`contacts-list`类添加到与播放列表使用的相同样式中。我们不会在这里详细介绍，因为这相当简短；因此，我们将继续编写联系人实现。

#### 集成联系人 API

查找用户的联系人使用 PhoneGap API 非常简单。实际上，我们的示例将基于文档中的`Navigator`对象`contacts`。但首先，我们需要创建一个`ContactFindOptions`的新实例（[`docs.phonegap.com/en/2.5.0/cordova_contacts_contacts.md.html#ContactFindOptions`](http://docs.phonegap.com/en/2.5.0/cordova_contacts_contacts.md.html#ContactFindOptions)），它将在查找联系人时保存我们的过滤选项。

```html
'initialize': function() {

  // Filter options
  this.contactOptions = new ContactFindOptions();
  this.contactOptions.filter = "";
  this.contactOptions.multiple = true;

  this.render();
},
```

上述代码在`ContactFindOptions`的实例上设置了`filter`和`multiple`属性。默认情况下，`filter`为空，表示没有限制，`multiple`设置为`true`，允许多个联系人通过。接下来，当我们获取联系人时，我们希望找到两个字段，它们的`displayName`和`name`。这些字段将在一个数组中，我们很快会用到。

```html
'initialize': function() {

  // Filter options
  this.contactOptions = new ContactFindOptions();
  this.contactOptions.filter = "";
  this.contactOptions.multiple = true;

  // Fileds we want back from query
  this.contactFields = ['displayName', 'name'];

  this.render();
},
```

接下来，我们希望在视图渲染时找到联系人。因此，在我们的渲染视图中，我们希望传入前面的选项。

```html
'render': function() {
    // Find user contacts
    navigator.contacts.find(this.contactFields, this.onContactsSuccess, this.onContactsError, this.contactOptions);

    this.$template = $(this.template(this.model.attributes));

    this.$el.prepend(this.$template);
  }

  return this;
},
```

请注意，我们尚未创建我们的`onContactsError`或`onContactsSuccess`方法。此外，您将看到我们创建模板并将其附加到 DOM 的方式与我们为所有其他视图所做的方式相同。这个方法没有太多要做的事情，所以让我们看看我们的回调，从`onContactSuccess`开始。

`onContactSuccess`回调是我们所有魔法发生的地方。我们将在内存中创建一个`div`元素，然后循环遍历结果，将每个元素作为列表项添加到`div`中。一旦完成所有操作，我们将获取`div`元素的内容并将其添加到我们的`contacts-list`无序列表中。

```html
'onContactsSuccess': function(contacts) {
  console.log('onContactsSuccess');
  // Temporary Div
  var $div = $('<div />');
  if (contacts.length !== 0) {
    console.log('contacts length greater than 0');
    _.each(contacts, function(contact){
      console.log(contact.name);
      $div.append($('<li>' + contact.name.formatted + '</li>'));
    });
  } else {
    alert("No contacts found!");
  }

  $('.contacts-list').append($div.html());
},
```

正如您在这里看到的，我们使用**underscore**方法`each`来循环遍历结果。正如我们之前提到的，我们创建一个包含用户姓名的列表项作为其文本内容。这里的行为非常简单，没有太复杂的东西。现在，让我们来看看我们的`onContactsError`回调：

```html
'onContactsError': function(contactsError) {
  alert('onContactsError!');
}
```

在这个回调中，我们只是警告发生了错误。当然，在我们的真实应用程序中，我们会创建更全面的内容，但对于我们的目的来说，这已经足够了。如果我们现在运行我们的应用程序，我们应该会得到以下结果：

![集成联系人 API](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-iph-webapp-dev/img/1024OT_10_19.jpg)

联系人 API 实现

给自己一个鼓励！您已经到达本节的末尾，现在已成功集成了 PhoneGap API，并利用了本地功能。非常酷，不是吗？

### 注意

请注意，本书提供的源代码进行了一些检查，确保用户每次访问**联系人**视图时不会添加相同的联系人。这样做是为了节省一些时间，真正专注于解决方案的核心。

# 摘要

在本章中，我们介绍了使用与我们用于 Web 应用程序相同的编程语言进行本机应用程序开发。使用流行的开源 PhoneGap 框架，我们实现了创建单页面应用程序的能力，在第七章中构建的*单页应用程序*，作为 iOS 的本机应用程序。我们通过使用 PhoneGap 中的联系人 API 来扩展单页面应用程序，将其与本机功能联系起来，列出我们的联系人和一些信息。现在我们应该有一个创建本机应用程序的基础，使我们能够使用 Web 技术来分发 iOS Safari 和 iOS 操作系统的 Web 应用程序。
