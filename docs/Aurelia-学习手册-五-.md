# Aurelia 学习手册（五）

> 原文：[`zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F`](https://zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：国际化

当涉及到 JavaScript 国际化时，`i18next`是最知名、最广泛使用的库之一。它提供了一系列功能，如可插拔的翻译加载器、缓存、用户语言检测和复数形式。也许这就是 Aurelia 团队在它之上构建`aurelia-i18n`库的原因。

本章的目的并不是要详细解释`i18next`，而是更多地探索`aurelia-i18n`层本身。至于`i18next`的详细信息，官方网站有广泛的文档，如果你不熟悉它，我强烈建议你查阅： [`i18next.com/`](http://i18next.com/)。

# 设置事情

`aurelia-i18n`库和底层`i18next`库在使用之前都需要安装和配置。让我们看看这个过程如何进行。

## 安装库

首先，需要通过在项目目录中打开控制台并运行以下命令来安装`aurelia-i18n`和`i18next`：

```js
> npm install aurelia-i18n i18next --save

```

`i18next`库使用一个抽象层来加载翻译数据。在`i18next`术语中，这被称为后端。这个抽象层允许不同的翻译加载策略。

存储和检索翻译数据的最常见方法是在应用程序文件的某个地方使用 JSON 文件。因此，我们将安装`i18next-xhr-backend`实现，它使用`XMLHttpRequest`从服务器获取包含翻译的 JSON 文件：

```js
> npm install i18next-xhr-backend --save

```

当然，打包器需要知道这些新库。因此，在`aurelia_project/aurelia.json`文件中，在`build`部分，在`bundles`下的`vendor-bundle.js`的`dependencies`中，让我们添加以下条目：

```js
{ 
  "name": "aurelia-i18n", 
  "path": "../node_modules/aurelia-i18n/dist/amd", 
  "main": "aurelia-i18n" 
}, 
{ 
  "name": "i18next", 
  "path": "../node_modules/i18next/dist/umd", 
  "main": "i18next" 
}, 
{ 
  "name": "i18next-xhr-backend", 
  "path": "../node_modules/i18next-xhr-backend/dist/umd", 
  "main": "i18nextXHRBackend" 
}, 

```

## 配置插件

我们还需要在我们的主`configure`函数中加载和配置插件：

`src/main.js`

```js
import Backend from 'i18next-xhr-backend'; 
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .feature('validation') 
    .feature('resources') 
    .feature('contacts') 
 .plugin('aurelia-i18n', (i18n) => { 
      i18n.i18next.use(Backend); 

      return i18n.setup({ 
        backend: { 
          loadPath: './locales/{{lng}}/{{ns}}.json',  
        }, 
        lng : 'en', 
        fallbackLng : 'en', 
        debug : environment.debug 
      }); 
    }); 
  //Omitted snippet... 
}); 

```

在此，我们首先从`i18next-xhr-backend`库中导入`Backend`类。然后，我们调用`plugin`函数来加载`aurelia-i18n`并对其进行配置。

配置函数接收`aurelia-i18n`类的单个实例`I18N`，作为外观，分组和标准化 API。它首先告诉`i18next`使用`i18next-xhr-backend`的`Backend`类，该类负责从服务器获取 JSON 翻译文件。然后，它调用`I18N`类的`setup`方法，带有一组选项。这些选项将用于配置插件，但也将用于后台配置`i18next`。这意味着您通常会传递给`i18next`的`init`方法的任何选项，都可以传递给这个`setup`方法。

以下是最重要的选项：

+   `backend.loadPath`：用于加载翻译文件的路径。`{{lng}}`占位符将被替换为必须加载翻译的语言，`{{ns}}`占位符将被替换为必须加载翻译的命名空间。

+   `lng`：默认语言。

+   `fallbackLng`：如果在当前语言中找不到给定键，则回退到该语言。

+   `debug`：设置为`true`时，浏览器控制台中的日志将更加详细。

## 创建翻译文件

`i18next`库允许我们将翻译按命名空间隔离，这些命名空间是逻辑翻译组。其默认命名空间名为`translation`。如果我们看看`backend.loadPath`选项，我们可以很容易地看出我们的翻译文件应该放在哪里：

`locales/en/translation.json`

```js
{} 

```

在这里，我们简单地创建一个包含空对象的 JSON 文件。我们稍后向其中添加翻译。

## 填充 Intl API

`aurelia-i18n`插件使用`i18next`进行翻译，但依赖原生 Intl API 进行一些其他任务，如数字和日期格式化。然而，一些浏览器（主要是移动浏览器）还不支持这个 API。因此，如果您想要支持这些浏览器，可能需要添加一个填充物。 [`github.com/andyearnshaw/Intl.js/`](https://github.com/andyearnshaw/Intl.js/) 是官方文档中推荐的一个。

# 获取和设置当前区域设置

除了各种视图资源，我们将在本章后面看到，`aurelia-i18n`还导出一个`I18N`类，它作为各种 API（如`i18next`和原生 Intl API）的门面。

让我们看看我们如何使用这个 API 来获取和设置当前区域设置，通过创建一个`locale-picker`自定义元素，用户可以更改当前区域设置：

`src/resources/elements/locale-picker.html`

```js
<template> 
  <select class="navbar-btn form-control"  
          value.bind="selectedLocale"  
          disabled.bind="isChangingLocale"> 
    <option repeat.for="locale of locales" value.bind="locale"> 
      ${locale} 
    </option> 
  </select> 
</template> 

```

在此模板中，我们首先添加一个`select`元素，其值将绑定到`selectedLocale`属性，当`isChangingLocale`属性为`true`时，该元素将被禁用。在`select`元素中，我们为`locales`数组中的每个值渲染一个`option`。每个`option`的`value`绑定到其`locale`值，每个选项的文本将是本身使用字符串插值表达式渲染的`locale`。

接下来，我们需要添加视图模型，这将使这个模板与`I18N` API 相连接：

`src/resources/elements/locale-picker.js`

```js
import {inject, bindable} from 'aurelia-framework'; 
import {I18N} from 'aurelia-i18n'; 

@inject(I18N) 
export class LocalePickerCustomElement { 

  @bindable selectedLocale; 
  @bindable locales = ['en', 'fr']; 

  constructor(i18n) { 
    this.i18n = i18n; 

    this.selectedLocale = this.i18n.getLocale(); 
    this.isChangingLocale = false; 
  } 

  selectedLocaleChanged() { 
    this.isChangingLocale = true; 
    this.i18n.setLocale(this.selectedLocale).then(() => { 
      this.isChangingLocale = false; 
    }); 
  } 
} 

```

首先，这个类的构造函数从接收`I18N`实例开始，然后使用其`getLocale`方法检索当前区域设置并初始化`selectedLocale`属性。由于这个属性是可绑定的，所以声明实例的模板可以对其默认值进行数据绑定。

接下来，属性更改处理程序`selectedLocaleChanged`将在`selectedLocale`属性发生变化时由模板引擎调用，将`isChangingLocale`设置为`true`，以便禁用`select`元素，然后调用`I18N`的`setLocale`方法。由于它可能需要从服务器加载新的翻译文件，所以这个方法是异步的，返回一个`Promise`，我们监听其完成以将`isChangingLocale`恢复为`false`，以便重新启用`select`元素。

由于我们的本地化选择器默认支持英语和法语，因此我们需要为法语添加另一个翻译文件，其中包含一个空对象：

`locales/fr/translation.json`

```js
{} 

```

我们现在可以使用这个自定义元素在`app`组件中：

`src/app.html`

```js
<!-- Omitted snippet...--> 
<form class="navbar-search pull-right"> 
  <locale-picker></locale-picker> 
</form> 
<ul class="nav navbar-nav navbar-right"> 
  <!-- Omitted snippet...--> 
</ul> 
<!-- Omitted snippet...--> 

```

当然，如果你在这个时候运行应用程序，当你改变当前的本地化设置时，什么也不会被翻译；必须首先向模板中添加文本翻译。

# 翻译

`aurelia-i18n`库提供了许多不同的翻译文本的方法。在本节中，我们将了解我们的选择有哪些。

## 使用属性

在模板中翻译文本的最简单方法是使用名为`t`的翻译属性。让我们通过翻译我们的**未找到**页面来说明这一点。

我们将从将文本移动到翻译文件开始：

`locales/en/translation.js`

```js
{ 
  "404": { 
    "explanation": "The page cannot be found.", 
    "title": "Something is broken..." 
  } 
} 

```

`locales/fr/translation.js`

```js
{ 
  "404": { 
    "explanation": "La page est introuvable.", 
    "title": "Quelque-chose ne fonctionne pas..." 
  } 
} 

```

正如你所见，由于翻译是 JSON 结构，我们完全可以没有任何问题地使用嵌套键。

要在元素内静态显示翻译后的文本，你只需要向元素添加`t`属性，并将其值设置为翻译键的路径：

`src/not-found.html`

```js
<template> 
  <h1 t="404.title"></h1> 
  <p t="404.explanation"></p> 
</template> 

```

渲染后，属性将在当前本地化的翻译文件中查找键，并将翻译值分配给元素的文本内容。如果当前本地化是英语，渲染后的 DOM 将看起来像这样：

```js
<h1 t="404.title">The page cannot be found.</h1> 
<p t="404.explanation">Something is broken...</p> 

```

也可以使用`t`来翻译属性的值：

```js
<input type="text" value.bind="contact.firstName"  
       t="[placeholder]contacts.firstName"> 

```

通过在方括号内加上属性的名称来前缀键，`t`属性将为这个属性分配翻译值，而不是元素的文本内容。在这里，翻译键`contacts.firstName`的值将被分配给`input`的`placeholder`属性。

此外，可以在单个元素上翻译多个目标，通过用分号分隔指令来实现：

```js
<label t="[title] help; text"> 

```

在这里，`help`键的值将被分配给`title`属性，`text`的值将被分配给元素的文本内容。当然，使用相同的技术翻译多个属性也是可能的。

最后，`t`属性监控当前的本地化设置。当它改变时，输出会自动使用新的本地化设置进行更新。

### 传递参数

由于`i18next`支持向翻译传递参数，你可以将对象绑定到`t-params`属性以传递翻译的参数。

让我们想象一下以下的翻译：

```js
{ "message": "Hi {{name}}, welcome back!" } 

```

使用属性将`name`参数传递给这个翻译看起来像这样：

```js
<p t="message" t-params.bind="{ name: 'Chuck' }"></p> 

```

渲染后，`p`元素将包含文本`Hi Chuck, welcome back!`。

## 使用值转换器

`t`属性的一种替代方案是`t`值转换器。它可以在任何绑定表达式中使用，包括字符串插值，所以在某些情况下它比属性更方便：

```js
<p>${'explanation' | t}</p> 

```

在这里，`t`值转换器将在翻译文件中查找`explanation`翻译键并输出其值。

它的使用不仅限于字符串插值。它还适用于其他绑定表达式：

```js
<p title.bind=" 'explanation' | t "></p> 

```

在这里，`title`属性将包含`explanation`键的翻译。

### 传递参数

值转换器接受一个包含翻译参数的对象作为其第一个参数。

让我们假设以下的翻译：

```js
{ "message": "Hi {{name}}, welcome back!" } 

```

使用这个翻译与值转换器的效果是这样的：

```js
<p>${'message' | t: { name: 'Chuck' } }</p> 

```

渲染后，`p`元素将包含文本`Hi Chuck, welcome back!`。

## 使用绑定行为

然而，如果你的应用程序允许你在其生命周期内更改语言，那么值转换器根本就没有用。由于值转换器的工作方式，`t`值转换器不知道它必须重新评估其值，因为它不能在当前区域更改时得到通知。

这就是`t`绑定行为发挥作用的地方。当应用`t`绑定行为时，它简单地将`t`值转换器装饰在其绑定指示上。那么，为什么不用值转换器呢？

记得我们在第三章中看到的`signal`绑定行为吗？*显示数据*？好吧，`I18N`的`setLocale`方法实际上触发了`aurelia-translation-signal`绑定信号，而`t`绑定行为监听它。当当前区域更改时，所有活动的`t`绑定行为强制其绑定表达式重新评估，所以每个绑定表达式的底层值转换器可以使用新的区域。

### 传递参数

传递给绑定行为的任何参数对象都将传递给底层的值转换器，所以值转换器示例也适用于绑定行为：

```js
<p ></p> 

```

## 使用代码

当然，翻译一个键的所有这些不同方式都依赖于同一个`I18N`方法：

```js
tr(key: string, parameters?: object): string 

```

例如，假设`i18n`是`I18N`的一个实例，在 JS 代码中翻译同一个`message`键就像这样：

```js
let message = i18n.tr('message', { name: 'Chuck' }); 

```

## 选择一种技术胜过另一种

我们刚刚看到了四种不同的做事方式。一开始可能很难决定在哪种情况下一种技术最适合胜过其他技术。

`t`属性是来自`i18next`的一个遗留问题。当独立使用，在 Aurelia 之外时，`i18next`使用这个属性在 DOM 树内翻译文本。`aurelia-i18n`库可能支持它，只是为了让有`i18next`经验的人可以像往常一样使用它。然而，在一个 Aurelia 应用内部，它并不能在每种情况下使用；例如，它在与自定义元素一起使用时表现不佳，因为它会覆盖元素的内容。

作为一个经验法则，在模板内翻译时，我总是选择绑定行为技术。由于`t`属性和`t`值转换器有如此重要的限制，这种技术是最灵活的，我可以通过在整个应用程序中使用相同的技术来保持一致性。

如果应用程序只有一种语言，或者如果用户在应用程序启动后不能更改当前语言，那么可以使用值转换器技术。然而，我看不出真正的益处。尽管它的内存占用可能比绑定行为略小一些，但收益不会很大，而且如果上下文发生变化，应用程序突然需要支持区域设置变化，每个值转换器实例都不得不被绑定行为替换，到处都是。因此，在大多数情况下，使用值转换器可能是一种相当鲁莽的赌博。

最后，当需要在 JS 代码中翻译文本时，我会直接使用 API，在这种情况下，`I18N`实例可以很容易地被注入到需要它的类中。

这些指南适用于翻译，也适用于以下各节中描述的格式化特性。

# 格式化数字

如前所述，`aurelia-i18n`也依赖于本地 Intl API 提供数字格式化功能。

### 注意

由于库使用了 Intl API，如果你不熟悉它，我强烈建议你查阅相关资料。Mozilla 开发者网络提供了关于该主题的详尽文档：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl)

## 使用值转换器

格式化数字的最简单方法是使用`nf`值转换器：

```js
${1234 | nf} 

```

它只是使用当前区域设置创建一个`Intl.NumberFormat`实例，并调用其`format`方法，将`1234`值传递给它。

它也可以直接传递一个`Intl.NumberFormat`实例：

```js
${1234 | nf: myNumberFormat} 

```

在这种情况下，直接使用传递的`Intl.NumberFormat`实例来`format`值。

最后，它可以传递一个选项对象，可选地传递一个区域设置或区域设置数组：

```js
${1234 | nf: { currency: 'EUR' }} 
${1234 | nf: { currency: 'EUR' }: 'fr'} 

```

在这种情况下，将创建一个`Intl.NumberFormat`实例，使用选项和区域设置来`format`值。如果没有传递区域设置，将使用当前区域设置。

## 使用绑定行为

`nf`值转换器有一个与`t`值转换器相同的问题：如果当前区域设置发生变化，它没有办法得到通知。因此，如果应用程序在其生命周期内允许您更改语言，应使用`nf`绑定行为：

```js
${1234 & nf} 

```

它的运作方式与`t`绑定行为完全相同，监听`aurelia-translation-signal`绑定信号，并在信号发出时强制重新评估其绑定表达式。

它也是通过在幕后用`nf`值转换器装饰其绑定指令，并将所有参数传递给它，因此它支持与值转换器相同的参数。

## 使用代码

在幕后，值转换器依赖于`I18N`的`nf`方法：

```js
nf(options?: object, locales?: string | string[]): Intl.NumberFormat 

```

这个方法简单地使用提供的选项和区域设置创建一个`Intl.NumberFormat`实例，并返回它。如果没有传递区域设置，将使用当前区域设置：

```js
let value = i18n.nf({ currency: 'EUR' }).format(1234); 

```

在这里，我们调用`nf`方法使用提供的选项和当前区域设置创建一个`Intl.NumberFormat`实例，然后我们调用结果`Intl.NumberFormat`对象的`format`方法。

# 格式化日期

国际化的 Intl API 还包括日期格式化功能。因此，`aurelia-i18n`封装了这些功能，使其更简单地与当前区域设置一起工作。

## 使用值转换器

`df`值转换器的工作方式与`nf`值转换器几乎相同：

```js
${contact.birthday | df} 

```

它应用的值预期要么是一个`Date`对象，要么是一个`string`，该`string`将使用`Date(string)`构造函数转换为`Date`对象。

`df`值转换器在幕后的工作方式与`nf`基本相同，不同之处在于它使用`Intl.DateTimeFormat`类。这意味着它可以接受一个`Intl.DateTimeFormat`实例作为参数：

```js
${contact.birthday | df: myDateTimeFormat} 

```

在这种情况下，`format`方法将直接在提供的`Intl.DateTimeFormat`实例上调用。

它还可以接受一个选项对象，以及可选的区域设置或区域设置数组：

```js
${contact.birthday | df: { timeZone: 'UTC' }} 
${contact.birthday | df: { timeZone: 'UTC' }: 'fr'} 

```

在这种情况下，将使用选项和区域设置创建一个`Intl.DateTimeFormat`实例来`format`值。如果没有传递区域设置，将使用当前区域设置。

## 使用绑定行为

`df`值转换器与`t`和`nf`值转换器有同样的问题：它无法知道当前区域设置何时发生变化，因此无法重新评估其输出。因此，当应用程序生命周期中区域设置可以发生变化时，应使用`df`绑定行为：

```js
${contact.birthday & df} 

```

它的工作方式与`t`和`nf`绑定行为相同，它用`df`值转换器装饰其绑定表达式，并在`aurelia-translation-signal`发出时强制它重新评估其值：

此外，它将其参数传递给其底层值转换器，因此它支持与`df`值转换器相同的签名。

## 使用代码

值转换器依赖于`I18N`类的`df`方法来格式化日期：

```js
df(options?: object, locales?: string | string[]): Intl.DateTimeFormat 

```

与`nf`方法类似，它简单地使用提供的选项和区域设置创建一个`Intl.DateTimeFormat`实例，并返回它。如果没有提供区域设置，将使用当前区域设置：

```js
let value = i18n.df({ timeZone: 'UTC' }).format(new Date()); 

```

在这里，我们调用`df`方法使用提供的选项和当前区域设置创建一个`Intl.DateTimeFormat`实例，然后我们调用结果`Intl.DateTimeFormat`对象的`format`方法。

# 格式化相对时间

`aurelia-i18n`库还提供了一个服务，用于将时间相对于当前系统时间格式化。它允许你输出类似于`now`、`5 seconds ago`、`2 days ago`等人友好的时间差。

## 使用值转换器

显示人类友好时间差的最简单方法是使用`rt`值转换器：

`src/contacts/components/details.html`

```js
//Omitted snippet... 
${contact.modifiedAt | rt} 
//Omitted snippet... 

```

在这里，输出可能是类似于`5 days ago`，这取决于`contact.modifiedAt`的值和当前系统时间。

转换器应用的值预期要么是一个`Date`对象，要么是一个`string`，它将使用`Date(string)`构造函数转换为`Date`对象。

### 周期性地刷新值

之前的例子有一个小问题：`rt`的输出相对于当前时间，但从不更新。如果永远显示`5 秒钟前`，用户可能会觉得有些奇怪。

通常，`rt`值转换器将与`signal`绑定行为一起使用：

`src/contacts/components/details.html`

```js
//Omitted snippet... 
${contact.modifiedAt | rt & signal: 'rt-update'} 
//Omitted snippet... 

```

当然，这意味着我们需要在某个地方发出`rt-update`信号，可能是在视图模型中：

`src/contacts/components/details.js`

```js
import {inject} from 'aurelia-framework';  
import {Router} from 'aurelia-router'; 
import {BindingSignaler} from 'aurelia-templating-resources';   
import {ContactGateway} from '../services/gateway'; 
import {Contact} from '../models/contact'; 

@inject(ContactGateway, Router, BindingSignaler) 
export class ContactDetails { 

  constructor(contactGateway, router, signaler) { 
    this.contactGateway = contactGateway; 
    this.router = router; 
    this.signaler = signaler; 
  } 

  activate(params, config) { 
    return this.contactGateway.getById(params.id) 
      .then(contact => { 
        this.contact = Contact.fromObject(contact); 
        config.navModel.setTitle(this.contact.fullName); 
        this.rtUpdater = setInterval( 
          () => this.signaler.signal('rt-update'), 1000); 
      }); 
  } 

  //Omitted snippet... 

  deactivate() { 
    if (this.rtUpdater) { 
      clearInterval(this.rtUpdater); 
      this.rtUpdater = null; 
    } 
  } 
} 

```

在这里，我们首先在视图模型中注入一个`BindingSignaler`实例。然后，一旦联系人加载完成，我们使用`setInterval`函数每秒发出一个`rt-update`信号。每次发出信号时，视图中的`signal`绑定行为将刷新绑定并重新应用`rt`值转换器到`contact.modifiedAt`。

我们通过使用`clearInterval`函数在组件停用时停止信号的发出，从而防止内存泄漏。

这段代码仍然有一个问题：如果当前区域更改，绑定将会有延迟地刷新。这个问题很容易解决：

`src/contacts/components/details.html`

```js
//Omitted snippet... 
${contact.modifiedAt | rt  
  & signal:'rt-update':'aurelia-translation-signal'} 
//Omitted snippet... 

```

我们只需要监听`aurelia-translation-signal`信号，以及`rt-update`信号。前者是由`I18N`在当前区域每次更改时发出的信号。

现在`contact.modifiedAt`显示的时间差将每秒刷新，并且在当前区域更改时也会更新。

## 使用代码

值转换器依赖于一个独特的类，名为`RelativeTime`，该类由`aurelia-i18n`导出，并提供以下方法：

```js
getRelativeTime(time: Date): string 

```

这个方法简单地计算提供的`time`和当前系统时间之间的差异，并使用内置的翻译集合，返回当前区域的人友好的文本。

如果你需要从一些 JS 代码中转换日期为人友好的相对时间，你可以在你的类中轻松注入`RelativeTime`的一个实例并使用其`getRelativeTime`方法。

# 翻译我们的联系人管理应用程序

在此阶段，您已经拥有完全国际化我们的联系人管理应用程序所需的所有工具，除了验证消息和文档标题，它们需要与`aurelia-validation`和`aurelia-router`集成，这部分内容将在接下来的章节中详细介绍。

展示如何国际化应用程序中的每个模板会花费太长时间并且相当繁琐，所以我会留给读者作为一个练习。像往常一样，本章的示例应用程序可以作为参考。

下面的章节假设您已经国际化了您工作副本中应用程序中可以国际化的所有内容。如果您跳过手动执行此操作，我强烈建议您从书籍资源中的`chapter-8/samples/app-translated`目录获取最新的代码副本。

# 与验证集成

如果您向使用`aurelia-validation`的应用程序添加国际化，您将希望翻译错误消息。本节解释了如何将这两个库结合起来实现这一点。

## 覆盖 ValidationMessageProvider

验证库使用一个`ValidationMessageProvider`类来获取错误消息。让我们扩展这个类，并使用`I18N`从翻译文件中获取消息：

`src/validation/i18n-validation-message-provider.js`

```js
import {inject} from 'aurelia-framework'; 
import {I18N} from 'aurelia-i18n'; 
import {ValidationParser, ValidationMessageProvider}  
  from 'aurelia-validation'; 

@inject(ValidationParser, I18N) 
export class I18nValidationMessageProvider  
  extends ValidationMessageProvider { 

  options = { 
    messageKeyPrefix: 'validation.messages.', 
    propertyNameKeyPrefix: 'validation.properties.' 
  }; 

  constructor(parser, i18n) { 
    super(parser); 
    this.i18n = i18n; 
  } 

  getMessage(key) { 
    let translationKey = key.includes('.') || key.includes(':')  
      ? key  
      : `${this.options.messageKeyPrefix}${key}`; 
    let translation = this.i18n.tr(translationKey); 
    if (translation !== translationKey) { 
      return this.parser.parseMessage(translation); 
    } 
    return super.getMessage(key); 
  } 

  getDisplayName(propertyName) { 
    let translationKey =  
      `${this.options.propertyNameKeyPrefix}${propertyName}`; 
    let translation = this.i18n.tr(translationKey); 
    if (translation !== translationKey) { 
      return translation; 
    } 
    return super.getDisplayName(propertyName); 
  } 
} 

```

在这里，我们首先创建一个`ValidationParser`实例，这是`ValidationMessageProvider`基类所需的，并在构造函数中注入一个`I18N`实例。我们还定义了`options`，在执行翻译前用于构建键的前缀。

接下来，我们覆盖了`getMessage`方法，在其中我们构建了一个翻译键，然后请求`I18N`实例对其进行翻译。由于`tr`方法最终如果没有找到对应的翻译，就会返回键，所以我们只有在找到翻译时才使用翻译，否则我们退回到`getMessage`的基础实现。

构建翻译键时，如果键不包含任何点或冒号，我们会在其前面加上`options`的默认前缀，因为我们认为这个键将是验证规则的名称，这是默认行为。然而，我们的`getMessage`实现允许验证规则定义一个自定义消息键，这可以是一个自定义的翻译路径，从翻译文件中的另一个区域或命名空间获取消息文本。

`getDisplayName`方法遵循一个类似的过程：我们在键前面加上`options`的默认前缀，翻译它，然后使用翻译（如果找到了的话），或者如果没有找到，就退回到基础实现。

默认情况下，我们会认为所有的验证翻译都会存放在一个共同的`validation`对象下，该对象将在一个`messages`对象下包含所有错误消息，在`properties`对象下包含所有属性显示名称。这些路径前缀是存储在`options`对象中的默认值。

这个`options`对象如果应用程序的某个部分需要在其翻译文件的不同部分查找验证键时可能很有用；在这种情况下，应用程序的这部分可以定义自己的、定制的`I18nValidationMessageProvider`实例，使用不同的`options`值。

下一步是告诉验证系统使用这个类而不是默认的`ValidationMessageProvider`。在`validation`特性的`configure`函数中执行这个操作最合适：

`src/validation/index.js`

```js
import {ValidationMessageProvider} from 'aurelia-validation'; 
import './rules'; 
import {BootstrapFormValidationRenderer}  
  from './bootstrap-form-validation-renderer'; 
import {I18nValidationMessageProvider}  
  from './i18n-validation-message-provider'; 

export function configure(config) { 
  config.plugin('aurelia-validation'); 
  config.container.registerHandler('bootstrap-form',  
    container => container.get(BootstrapFormValidationRenderer)); 

 config.container.registerSingleton( 
    ValidationMessageProvider, I18nValidationMessageProvider); 
} 

```

在这里，我们只需告诉 DI 容器使用`I18nValidationMessageProvider`实例代替`ValidationMessageProvider`。

## 添加翻译

现在验证系统已经知道去哪里获取翻译后的错误消息和属性显示名称，接下来让我们添加正确的翻译：

`locales/en/translation.json`

```js
{ 
  //Omitted snippet... 
  "validation": { 
    "default": "${$displayName} is invalid.", 
    "required": "${$displayName} is required.", 
    "matches": "${$displayName} is not correctly formatted.", 
    "email": "${$displayName} is not a valid email.", 
    "minLength": "${$displayName} must be at least ${$config.length} character${$config.length === 1 ? '' : 's'}.", 
    "maxLength": "${$displayName} cannot be longer than ${$config.length} character${$config.length === 1 ? '' : 's'}.", 
    "minItems": "${$displayName} must contain at least ${$config.count} item${$config.count === 1 ? '' : 's'}.", 
    "maxItems": "${$displayName} cannot contain more than ${$config.count} item${$config.count === 1 ? '' : 's'}.", 
    "equals": "${$displayName} must be ${$config.expectedValue}.", 
    "date": "${$displayName} must be a valid date.", 
    "notEmpty": "${$displayName} must contain at least one item.", 
    "maxFileSize": "${$displayName} must be smaller than ${$config.maxSize} bytes.", 
    "fileExtension": "${$displayName} must have one of the following extensions: ${$config.extensions.join(', ')}." 
  },  
  "properties": { 
    "address": "Address", 
    "birthday": "Birthday", 
    "city": "City", 
    "company": "Company", 
    "country": "Country", 
    "firstName": "First name", 
    "lastName": "Last name", 
    "note": "Note", 
    "number": "Number", 
    "postalCode": "Postal code",  
    "state": "State", 
    "street": "Street", 
    "username": "Username" 
  }, 
  //Omitted snippet... 
} 

```

`messages`下的键是`aurelia-validation`在撰写本文时支持的标准规则，以及我们在`validation`特性中定义的自定义规则的消息。那些在`properties`下的键是应用程序中使用的每个属性的显示名称。至于法语翻译，您可以从本章的示例应用程序中获得。

在此阶段，如果您运行应用程序，点击**新建**按钮，例如在**生日**文本框中输入胡言乱语然后尝试保存，您应该会看到一条翻译后的错误消息出现。然而，如果您使用视图区域右上角的地区选择器更改当前语言环境，验证错误将不会随新语言环境刷新。

为了实现这一点，`ValidationController`实例需要被告知在当前语言环境发生变化时重新验证。

## 刷新验证错误

为了刷新验证错误，联系人创建视图模型必须订阅一个名为`i18n:locale:changed`的事件，当当前语言环境发生变化时，通过应用程序的事件聚合器由`I18N`实例发布。

事件聚合器是 Aurelia 默认配置的一部分，已经安装并加载，因此在我们的应用程序中使用它时，我们不需要做任何事情。我们可以直接更新我们的`creation`视图模型：

`src/contacts/components/creation.js`

```js
import {EventAggregator} from 'aurelia-event-aggregator'; 
//Omitted snippet... 
@inject(ContactGateway, NewInstance.of(ValidationController),  
  Router, EventAggregator) 
export class ContactCreation { 

  contact = new Contact(); 

  constructor(contactGateway, validationController,  
              router, events) { 
    this.contactGateway = contactGateway; 
    this.validationController = validationController; 
    this.router = router; 
    this.events = events; 
  } 

  activate() { 
    this.i18nChangedSubscription = this.events.subscribe( 
      'i18n:locale:changed',  
      () => { this.validationController.validate(); }); 
  }
 deactivate() { 
    if (this.i18nChangedSubscription) { 
      this.i18nChangedSubscription.dispose(); 
      this.i18nChangedSubscription = null; 
    } 
  } 
  //Omitted snippet... 
} 

```

在这里，我们只需订阅正确的事件，在当前语言环境发生变化时触发验证。当然，当组件被停用时，我们也需要处理订阅，以防止内存泄漏。

如果您再次尝试保存带有无效数据的新联系人，然后在显示验证错误时更改语言环境，您应该会看到错误消息随着新语言环境实时刷新。

# 整合路由器

您可能注意到我们完全忽略了文档标题的翻译，即在浏览器顶部栏显示的标题。由于这个标题由`aurelia-router`库控制，我们需要找到一种将路由器与`I18N`服务集成的方法。

实际上，这样做相当简单。`Router`类提供了一个专门为此类场景设计的集成点：

`src/main.js`

```js
import {Router} from 'aurelia-router';  
import {EventAggregator} from 'aurelia-event-aggregator'; 
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .feature('validation') 
    .feature('resources') 
    .feature('contacts') 
    .plugin('aurelia-i18n', (i18n) => { 
      i18n.i18next.use(Backend); 

      return i18n.setup({ 
        backend: { 
          loadPath: './locales/{{lng}}/{{ns}}.json',  
        }, 
        lng : 'en', 
        fallbackLng : 'en', 
        debug : environment.debug 
      }).then(() => { 
        const router = aurelia.container.get(Router);  
        const events = aurelia.container.get(EventAggregator); 
        router.transformTitle = title => i18n.tr(title);  
        events.subscribe('i18n:locale:changed', () => { 
          router.updateTitle(); 
        }); 
      }); 
    }); 
  //Omitted snippet... 
}); 

```

这里，我们首先从`aurelia-router`库导入`Router`类和从`aurelia-event-aggregator`库导入`EventAggregator`类。接下来，当`I18N`的`setup`方法返回的`Promise`解决时，我们检索应用程序的根路由器实例，并将其`transformTitle`属性设置为一个函数，该函数将接收一个路由的标题并使用`I18N`的`tr`方法对其进行翻译。我们还检索事件聚合器并订阅`i18n:locale:changed`事件。当这个事件发布时，我们调用路由器的`updateTitle`方法。

当然，我们需要将所有标题替换为翻译键，并将这些添加到翻译文件中。我将留这作为读者的练习；不过，这里有一个快速列表，列出了那些标题必须更改的地方：

+   应用程序的主标题，在`src/app.js`中的`app`组件的`configureRouter`方法中设置。

+   `contacts`功能的主路由的标题，在`src/contacts/index.js`中的联系人的`configure`函数中添加到路由器。

+   在`src/contacts/main.js`中定义的第一个两个路由的标题。

本章完成的示例可以作为参考。

如果您继续测试这个，文档标题应该被正确翻译。当更改当前区域设置时，它也应该相应地更新。

# 按功能分割翻译

从书的开头，我们的一个目标就是尽可能保持应用程序中的特性解耦。本章中我们国际化的方式完全违反了这条规则。

有方法通过使用命名空间来按照功能分割翻译文件，这是`i18next`的一个特性。然而，这为我们的应用程序增加了另一层复杂性。这应该让我们重新评估我们的架构选择。我们从拥有解耦特性的好处是否值得它们不断增加的复杂性？这个问题非常值得提出。

如果您对这个问题答案仍然是肯定的，并且您对如何做到这一点感到好奇，您可以查看本书资源中的`chapter-8/samples/app-translations-by-feature`下的示例应用程序，它实现了这种分割。

# 摘要

国际化和被认为是简单话题常常被忽视，但正如本章所看到，在应用程序中它在很多层面都有影响。如果在一个项目后期添加翻译，它可能会迫使一个团队重新思考一些架构决策。

然而，一个设计良好且功能强大的国际化库可以极大地帮助这些任务。建立在著名的翻译库`i18next`和新的网络标准 Intl API 之上，`aurelia-i18n`是这样的一个库。


# 第九章：动画

应用程序中的动画现在是常见的。动画视觉转换通常会给人一种流畅感，而且很好地使用动画可以是向用户传达某事最好的方式，比图标、图片或又是另一段文字。

Aurelia 的模板引擎已被设计来支持动画。它使用一个抽象层，允许可插拔的动画库，而 Aurelia 生态系统已经提供了多个实现。

在本章中，我们将首先了解动画师 API，并看看模板引擎是如何与其交互的。然后，我们将向我们的联系管理应用程序添加一些简单的基于 CSS 的动画，以了解它是如何工作的。

# 动画师 API

在`aurelia-templating`库中，`TemplatingEngine`类需要与动画服务一起工作以执行视图转换。默认情况下，它使用一个名为`Animator`的类，该类作为空对象，顺便说一下，描述了`Animator`期望的接口。

### 注意

**空对象**设计模式描述了一个作为接口的空实现的对象或类。这个对象可以用作 null 引用，并消除了在引用之前检查 null 的需要。您可以在[`sourcemaking.com/design_patterns/null_object`](https://sourcemaking.com/design_patterns/null_object)上获取有关此模式的更多信息。

以下是从动画师 API 中最常用的方法：

+   `enter(element: HTMLElement): Promise<boolean>`: 在 DOM 中添加元素的动画效果

+   `leave(element: HTMLElement): Promise<boolean>`: 将元素从 DOM 中移除的动画效果

+   `addClass(element: HTMLElement, className: string): Promise<boolean>`: 为元素添加 CSS 类，这可以根据实现方式触发动画

+   `removeClass(element: HTMLElement, className: string): Promise<boolean>`: 从元素中移除 CSS 类，这可以根据实现方式触发动画

+   `animate(element: HTMLElement|HTMLElement[], className: string): Promise<boolean>`: 在一个元素或元素数组上执行单个动画。`className`要么是触发动画的 CSS 类，要么是应用的效果名称，要么是动画的属性，这取决于动画师实现方式

+   `runSequence(animations: CssAnimation[]): Promise<boolean>`: 按顺序运行一系列动画。`CssAnimation`是一个由具有`element: HTMLElement`和`className: string`属性的对象实现的接口。对于每个动画，`className`要么是触发动画的 CSS 类，要么是应用的效果名称，要么是动画的属性，这取决于动画师实现方式

所有这些方法都返回一个`Promise`，其解决值为一个`boolean`值。这个值通常是`true`，当确实执行了动画时，以及`false`，当没有执行动画时。最后一个场景可能会发生，例如，尝试使用不定义任何动画的 CSS 类来动画化一个元素。

在撰写本文时，模板引擎对动画师的调用仅限于在将元素添加到 DOM 时调用其`enter`方法，然后在移除它时调用其`leave`方法。其他方法不被框架使用，但将由我们自己的代码使用。

最后，对元素的动画转换是可选的。模板引擎在渲染元素时调用`enter`方法，在从 DOM 中移除它时调用`leave`方法，但仅当元素具有`au-animate`CSS 类。这是出于性能原因；如果没有这个可选机制，每次渲染和卸载任何元素时都会执行大量无用的代码，而通常，只有少数选定的元素具有动画转换。

# CSS 动画师

`aurelia-animator-css`库是基于 CSS 的动画师实现。我们将安装它，并使用它为我们的联系人管理应用程序添加简单的基于 CSS 的动画。

## 安装插件

首先，在项目目录中打开一个控制台，并运行以下命令：

```js
> npm install aurelia-animator-css --save

```

像往常一样，它需要添加到供应商包中。在`aurelia_project/aurelia.json`文件中，在`build`下的`bundles`部分，添加到名为`vendor-bundle.js`的包的`dependencies`下列：

```js
"aurelia-animator-css", 

```

最后，我们需要加载插件，以便模板引擎使用它而不是默认的`Animator`：

`src/main.js`

```js
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .plugin('aurelia-animator-css') 
    .feature('validation') 
  //Omitted snippet... 
} 

```

至此，一切就绪，可以处理 CSS 动画。

## 动画视图转换

然而，在动手之前，让我们快速了解一下高级算法，并看看基于 CSS 的动画师的`enter`和`leave`方法是如何工作的。

当模板引擎将渲染的元素添加到 DOM 时，以下过程会发生：

1.  模板引擎将元素添加到 DOM。

1.  模板引擎检查元素是否具有`au-animate`类。如果有，它调用动画师的`enter`方法。如果没有，动画师完全被绕过，过程到这里结束。

1.  动画师为元素添加`au-enter`类。这个类可以在描述元素在整个动画过程中将保持不变的样式的 CSS 规则中使用。

1.  动画师为元素添加`au-enter-active`类。这个类应该在触发动画的 CSS 规则中使用。

1.  动画师检查元素的计算样式是否包含动画。如果不包含，它会从其中移除`au-enter`和`au-enter-active`类，并使用`false`解决产生的`Promise`。到这里过程结束。如果包含，它开始监听浏览器上的`animationend`事件。

1.  当收到`animationend`事件时，动画师将元素的`au-enter`和`au-enter-active`类移除，并将产生的`Promise`解决为`true`。

从 DOM 中删除元素的流程非常相似，但顺序相反：

1.  模板引擎检查元素是否具有`au-animate`类。如果有，它调用动画师的`leave`方法。如果没有，动画师完全被绕过，过程直接跳到第 6 步。

1.  动画师给元素添加了`au-leave`类。这个类可以在描述元素在整个动画期间将保持不变的样式的 CSS 规则中使用。

1.  动画师给元素添加了`au-leave-active`类。这个类应该用在触发动画的 CSS 规则中。

1.  动画师检查元素的计算样式是否包含动画。如果有，它开始监听浏览器的一个`animationend`事件。如果没有，它将`au-leave`和`au-leave-active`类从其中移除，并将产生的`Promise`解决为`false`。过程直接跳到第 6 步。

1.  当收到`animationend`事件时，动画师将元素的`au-leave`和`au-leave-active`类移除，并将产生的`Promise`解决为`true`。

1.  模板引擎将元素从 DOM 中移除。

既然我们已经理解了基于 CSS 的动画师是如何处理事情的，让我们先来动画化`list-editor`组件。

### 列表编辑器动画

我们在第五章*制作可复用的组件*中编写的`list-editor`组件具有允许用户添加和删除项目的特性。让添加的项目出现，比如窗帘被拉下，和删除的项目消失，比如窗帘被拉上，应该不会很难。

为了这样做，我们首先需要为组件定义 CSS 动画：

`src/resources/elements/list-editor.css`

```js
list-editor .le-item.au-enter-active { 
  animation: blindDown 0.2s; 
  overflow: hidden; 
} 

@keyframes blindDown { 
  0% { max-height: 0px; } 
  100% { max-height: 80px; } 
} 

list-editor .le-item.au-leave-active { 
  animation: blindUp 0.2s; 
  overflow: hidden; 
} 

@keyframes blindUp { 
  0% { max-height: 80px; } 
  100% { max-height: 0px; } 
} 

```

在这里，我们首先定义了用于添加项目的 CSS 规则；项目的`max-height`将在 0.2 秒内从 0 动画到 80 像素，在此期间，其溢出内容将被隐藏。

然后，我们定义了用于删除项目的 CSS 规则。这与添加项目非常相似，但顺序相反；它的`max-height`在 0.2 秒内从 80 像素动画到 0。在这个动画期间，它的溢出内容也将被隐藏。

当然，我们需要用组件加载这个新的 CSS 文件：

`src/resources/elements/list-editor.html`

```js
<template> 
  <require from="./list-editor.css"></require> 
  <!-- Omitted snippet... --> 
</template> 

```

我们还需要提示模板引擎项目应该被动画化：

`src/resources/elements/list-editor.html`

```js
<!-- Omitted snippet... --> 
<div class="form-group le-item ${animated ? 'au-animate' : ''}"  
     repeat.for="item of items"> 
  <!-- Omitted snippet... --> 
</div> 
<!-- Omitted snippet... --> 

```

在这里，我们在`class`属性中添加了一个字符串插值表达式，只有在`animated`属性为真时，才会给项目的`div`元素添加`au-animate`类。

在视图模型中，`animated`属性将初始设置为`false`，因此在组件渲染时项目不会被动画化。只有在组件完全附加到 DOM 时，该属性才会被设置为`true`，因此添加新项目或移除现有项目的操作才能正确动画化：

`src/resources/elements/list-editor.js`

```js
// Omitted snippet... 
export class ListEditorCustomElement { 
  // Omitted snippet... 

  animated = false; 

  attached() { 
    setTimeout(() => { this.animated = true; }); 
  } 
} 

```

为什么我们不在`attached`回调方法中直接将`animated`设置为`true`？为什么要用`setTimeout`类？嗯，如果你记得前一部分中描述的动画过程，首先元素被附加到 DOM，这意味着`attached`回调在同一时间被调用，然后动画师检查`au-animate`CSS 类。如果在`attached`回调中同步地将`animated`设置为`true`，当动画师检查是否需要对元素进行动画化时，`au-animate`CSS 类将出现在元素上，在初始渲染期间项目将被动画化，这是我们想要防止的。相反，我们将`animated`设置为`true`推送到浏览器的事件队列中，这样当`au-animate`CSS 类添加到项目的`div`元素时，组件的渲染已完成。

至此，如果你运行应用程序，导航到联系人`creation`或`edition`组件，并尝试编辑列表编辑器；你应该看到动画播放。

## 手动触发动画

除了动画过渡效果，动画师还支持手动触发的动画。与动画过渡不同，手动动画没有`au-enter`或`au-leave`这样的 CSS 类。相反，动画是通过使用用户自定义的 CSS 类来手动触发的。

用于手动触发动画的基本方法是 addClass 和 removeClass。这些方法允许你向元素添加或移除 CSS 类，并在两个状态之间实现动画过渡。

例如，假设我们有一个名为`A`的 CSS 类。如果我们调用`animator.addClass('A')`，以下过程会发生：

1.  动画师将`A-add`类添加到元素上。

1.  动画师检查元素的计算样式是否包含动画。如果不包含，它将`A`类添加到元素上，然后将其上的`A-add`类移除，并以`false`解析结果`Promise`。在此处结束该过程。如果包含动画，它开始监听浏览器上的`animationend`事件。

1.  当接收到`animationend`事件时，动画师将`A`类添加到元素上，然后将其上的`A-add`类移除。

正如你所看到的，这个过程允许你向元素添加一个 CSS 类，并在没有该类的元素和具有该类的元素之间实现动画状态过渡，该过程应由带有`-add`后缀的中间类触发。

此外，当在同一元素上调用`animator.removeClass('A')`时，以下过程会发生：

1.  动画师将`A`类从元素中移除。

1.  动画师将`A-remove`类添加到元素上。

1.  动画师检查元素的计算样式是否包含动画。如果不包含，它会从其中移除`A-remove`类，并用`false`解析产生的`Promise`。流程在这里结束。如果包含，它开始监听浏览器上的`animationend`事件。

1.  当收到`animationend`事件时，动画师从元素中移除`A-remove`类，并用`true`解析产生的`Promise`。

这个过程允许您从一个元素中移除 CSS 类，在带有类和不带类的元素之间进行带有动画的状态转换，该状态转换应由带有`-remove`后缀的中间类触发。

最后，`animate`方法允许按顺序触发`addClass`和`removeClass`。在这种情况下，动画可以由`-add`类、`-remove`类或两者同时触发。

### 强调验证错误

让我们在我们的联系人管理应用程序中尝试这个功能，通过添加一个动画，当用户尝试保存一个联系人并且表单无效时，验证错误会闪烁几次。

首先，我们需要创建一个 CSS 动画：

`src/contacts/components/form.css`

```js
.blink-add { 
  animation: blink 0.5s; 
} 

@keyframes blink { 
  0% { opacity: 1; } 
  25% { opacity: 0; } 
  50% { opacity: 1; } 
  75% { opacity: 0; } 
  100% { opacity: 1; } 
} 

```

这里，我们简单地定义了一个 CSS 规则，使匹配的元素在半秒内闪烁两次。触发动画的类名为`blink-add`，所以我们可以通过调用`addClass`来触发它。然而，由于使错误信息闪烁不是一个状态转换，并且我们不想让我们的错误信息带有`blink`类，我们将通过调用`animate`来触发它，这样我们就可以确保`blink`在动画结束时被移除。

为了促进代码重用，让我们将当前仅作为模板的联系人`form`组件转换为完整的组件。为此，我们需要为表单创建一个视图模型。在这个视图模型中，我们将添加一个通过使它们闪烁来强调错误的方法：

`src/contacts/components/form.js`

```js
import {inject, bindable, DOM} from 'aurelia-framework'; 
import {Animator} from 'aurelia-templating'; 

@inject(DOM.Element, Animator) 
export class ContactFormCustomElement { 

  @bindable contact; 

  constructor(element, animator) { 
    this.element = element; 
    this.animator = animator; 
  } 

  emphasizeErrors() { 
    const errors = this.element 
      .querySelectorAll('.validation-message'); 
    return this.animator.animate(Array.from(errors), 'blink'); 
  } 
} 

```

首先，我们定义视图模型，在其中移动`bindable` `contact`属性的声明；然后我们注入组件的 DOM 元素和`animator`实例。接下来，我们定义一个`emphasizeErrors`方法，该方法检索元素内的所有验证错误并使用`blink`效果调用它们。

当调用`animate`时，`animator`将遍历向元素添加`blink-add`的过程，这将触发动画。动画完成后，它将移除`blink`，添加`blink-remove`，并且由于`blink-remove`不触发任何动画，它将立即移除它，使元素回到过程开始时的状态。

接下来，我们需要从模板中移除`bindable`属性，因为`contact`现在是由视图模型定义的，并且加载包含新动画的 CSS 文件：

`src/contacts/components/form.html`

```js
<template> 
  <require from="./form.css"></require> 
  <!-- Omitted snippet... --> 
</template> 

```

最后，让我们更新一下`creation`组件。我们首先需要更改`form`的`require`语句，去掉`.html`后缀，这样模板引擎就知道该组件不仅仅是一个模板，还包含一个视图模型。我们还需要在`creation`组件的模板中获取`form`视图模型的引用：

`src/contacts/components/creation.html`

```js
<template> 
  <require from="./form"></require> 
  <!-- Omitted snippet... --> 
  <contact-form contact.bind="contact"  
    view-model.ref="form"></contact-form> 
  <!-- Omitted snippet... --> 
</template> 

```

通过在`contact-form`自定义元素上添加`view-model.ref="form"`属性，将`form`视图模型的引用分配给`creation`视图模型作为一个新的`form`属性。

我们现在可以使用这个`form`属性在验证失败时调用`emphasizeErrors`方法：

`src/contacts/components/creation.js`

```js
//Omitted snippet... 
save() { 
  return this.validationController.validate().then(errors => { 
    if (errors.length > 0) { 
      this.form.emphasizeErrors(); 
      return; 
    } 
    //Omitted snippet... 
  } 
} 
//Omitted snippet... 

```

至此，如果您运行应用程序，点击`New`按钮，在**Birthday**字段中输入胡言乱语，然后点击**Save**，验证错误信息应该出现并闪烁两次。每次点击**Save**按钮时，它应该再次闪烁。

当然，`edition`组件也应该以同样的方式进行修改。我将留给读者作为练习。本章节的示例应用程序可以作为参考。

## 动画路由转换

另一个可能从动画转换中受益的区域是路由器。让我们给路由转换添加一个简单的淡入/淡出动画：

`src/app.css`

```js
/* Omitted snippet... */ 

section.au-enter-active { 
  animation: fadeIn 0.2s; 
} 

section.au-leave-active { 
  animation: fadeOut 0.2s; 
} 

@keyframes fadeIn { 
  0% { opacity: 0; } 
  100% { opacity: 1; } 
} 

@keyframes fadeOut { 
  0% { opacity: 1; } 
  100% { opacity: 0; } 
} 

```

在这里，我们创建 CSS 规则，使`section`元素在进入时淡入，在离开时淡出。

接下来，我们只需向每个路由组件的`section`元素添加`au-animate`类。

如果您在此时运行应用程序，路由更改应该使用新动画平滑过渡。

### 交换顺序

当执行路由转换时，`router-view`元素用新视图替换旧视图。默认情况下，这个交换过程首先动画化旧视图的移除，然后是新视图的插入。如果没有视图动画，过程是立即的。如果两个视图都有动画，动画一个接一个地运行。

`router-view`处理视图交换的方式称为交换策略，可以是以下之一：

+   `before`：首先添加新视图，然后移除旧视图。如果新视图有动画，则等待其`enter`动画完成后再动画化旧视图的移除。

+   `with`：新视图添加，旧视图移除同时进行。两个动画并行运行。

+   `after`：默认的交换策略。先移除旧视图，然后添加新视图。如果旧视图有动画，新视图的插入仅在旧视图的移除动画完成后进行一次动画化。

我们的淡入/淡出转换之所以正常工作，是因为它遵循了默认的交换策略：首先将旧视图动画化移出，然后将新视图动画化进入。然而，某些动画可能需要不同的交换策略。

例如，如果你在从一个路由跳转到另一个路由时希望看到新视图从右侧滑入，而旧视图向左滑出，那么你需要旧视图的移除动画和新视图的添加动画同时运行，因此你需要使用`with`交换策略。

因此，`router-view`元素的交换策略可以通过将其`swap-order`属性设置为适当策略的名称来更改：

```js
<router-view swap-order="with"></router-view> 

```

# 摘要

为 Aurelia 应用程序添加动画相当简单。基于 CSS 的实现允许您轻松快速地为现有应用程序添加动画。

当需要更复杂的动画时，如果它不存在，可以很容易地编写您最喜欢的动画库的适配器插件。在撰写本文时，官方 Aurelia 库包括`aurelia-velocity`，它是流行的`velocity.js`库的适配器插件。我确信社区最终会提出其他动画解决方案的适配器，所以我强烈建议您密切关注它。


# 第十章 生产环境的打包

将 JavaScript 应用程序部署到生产环境时，打包是一个重要的性能实践。通过将资源（主要是 JavaScript 代码、HTML 模板和 CSS 表单）合并成单个文件，我们可以大大减少浏览器为服务应用程序而必须进行的 HTTP 调用次数。

CLI 总是打包它运行的应用程序，即使在开发环境中也是如此。这使得将应用程序部署到服务器变得相当简单；只需构建它，然后复制一堆文件即可。

然而随后版本控制问题出现了。当部署我们应用程序的新版本时，如果打包文件保持相同的名称，缓存的打包文件可能不会刷新，导致用户运行我们应用程序的过时版本。我们如何处理这个问题？

在本章中，我们将了解如何自定义联系人管理应用程序的打包。我们还将了解如何利用 CLI 的修订功能对打包文件进行版本控制，以便我们可以充分利用 HTTP 缓存。最后，我们将向项目中添加一个新的构建任务，以方便部署。

# 配置打包

默认情况下，使用 CLI 创建的项目包含两个打包文件：第一个名为`vendor-bundle.js`，其中包含应用程序使用的所有外部库；第二个名为`app-bundle.js`，其中包含应用程序本身。

打包配置在`aurelia_project/aurelia.json`文件中的构建部分。以下是在典型应用程序中的样子：

```js
"bundles": [ 
  { 
    "name": "app-bundle.js", 
    "source": [ 
      "[**/*.js]", 
      "**/*.{css,html}" 
    ] 
  }, 
  { 
    "name": "vendor-bundle.js", 
    "prepend": [ 
      "node_modules/bluebird/js/browser/bluebird.core.js", 
      "scripts/require.js" 
    ], 
    "dependencies": [ 
      "aurelia-binding", 
      "aurelia-bootstrapper", 
      "aurelia-dependency-injection", 
      "aurelia-framework", 
      //Omitted snippet... 
    ] 
  } 
] 

```

每个打包文件都有一个唯一的名称，必须定义其内容，这些内容可以来自应用程序和外部依赖项。通常，`app-bundle`包括应用程序源中的所有 JS、HTML 和 CSS，而`vendor-bundle`包括外部依赖项。

这通常是小到中等应用程序的最佳配置。外部依赖项通常不会经常更改，它们被组合在它们自己的打包文件中，因此用户在新版本的应用程序发布时不需要下载这些依赖项。在大多数情况下，他们只需要下载新的`app-bundle`。

## 将应用程序合并到单一打包中

然而，如果您出于某种原因希望将应用程序及其依赖项打包成一个单一的包，这样做是相当简单的。您只需要定义一个包含应用程序源代码和外部依赖项的单一打包文件：

### 注意

以下部分代码片段摘自本书资源中的`chapter-10/samples/app-single-bundle`示例。

`aurelia_project/aurelia.json`

```js
"bundles": [ 
  { 
    "name": "app-bundle.js", 
    "prepend": [ 
      "node_modules/bluebird/js/browser/bluebird.core.js", 
      "scripts/require.js" 
    ], 
    "source": [ 
      "[**/*.js]", 
      "**/*.{css,html}" 
    ], 
    "dependencies": [ 
      "aurelia-binding", 
      "aurelia-bootstrapper", 
      //Omitted snippet... 
    ] 
  } 
] 

```

由于 Aurelia 应用程序的入口点是`aurelia-bootstrapper`库，入口点打包文件必须包含`bootstrapper`。默认情况下，这是`vendor-bundle`。如果您在此处更改入口点打包文件，它将成为`app-bundle`；您需要更改几件事。

首先，仍然在`aurelia_project/aurelia.json`的`build`下，加载器的`configTarget`属性必须改为新的入口点捆绑文件：

`aurelia_project/aurelia.json`

```js
"loader": { 
  "type": "require", 
  "configTarget": "app-bundle.js", 
  // Omitted snippet... 
}, 

```

此外，`index.html`的主要`script`标签也必须引用新的入口点捆绑文件：

`index.html`

```js
<!-- Omitted snippet... --> 
<body aurelia-app="main"> 
  <script src="img/app-bundle.js" 
          data-main="aurelia-bootstrapper"></script> 
</body> 
<!-- Omitted snippet... --> 

```

如果你在此时运行应用程序，你会看到生成了一个单一的捆绑文件，浏览器在启动应用程序时只加载这个文件。

## 将应用程序拆分为多个捆绑文件

在某些情况下，将整个应用程序源代码放在一个`app-bundle`中是不理想的。我们很容易想象一个基于高度分隔的用户故事构建的应用程序。用户，根据他们的角色，只使用这个应用程序的特定部分。

这样的应用程序可以被拆分为多个较小的捆绑文件，每个文件对应一个与角色相关的部分。这样，用户就不会下载他们从未使用的应用程序部分的捆绑文件。

以下部分中的示例是从书籍资源中的`chapter-10/samples/ app-with-home` `sample`中摘录的。

让我们尝试通过将我们应用程序中的`contacts`特性移动到其自己的捆绑文件中来尝试这个方法。为此，我们首先需要从`app-bundle`中排除`contacts`目录中的所有内容：

`aurelia_project/aurelia.json`

```js
{ 
  "name": "app-bundle.js", 
  "source": { 
    "include": [ 
      "[**/*.js]", 
      "**/*.{css,html}" 
    ], 
    "exclude": [ 
      "**/contacts/**/*" 
    ] 
  } 
} 

```

`source`属性支持数组形式的通配符模式，或者一个对象，该对象具有`include`和可选的`exclude`属性，都预期包含一个通配符模式的数组。

在这里，我们只是将`source`的先前值移动到`include`属性中，并添加一个匹配`contacts`目录中所有内容的`exclude`属性。

接下来，我们需要定义新的捆绑文件：

`aurelia_project/aurelia.json`

```js
{ 
  "name": "app-bundle.js", 
  //Omitted snippet... 
}, 
{ 
  "name": "contacts-bundle.js", 
  "source": [ 
    "[**/contacts/**/*.js]", 
    "**/contacts/**/*.{css,html}" 
  ] 
},

```

这个名为`contacts-bundle.js`的新捆绑文件将包括`contacts`目录中的所有 JS、HTML 和 CSS 文件。

如果你在此时运行应用程序，你应该首先看到`scripts`目录现在包含了三个捆绑文件：`app-bundle.js`、`contacts-bundle.js`和`vendor-bundle.js`。如果你在浏览器中打开应用程序并检查调试控制台，你应该看到在加载应用程序时，浏览器首先加载`vendor-bundle`，然后是`app-bundle`，最后是`contacts-bundle`。

当主`configure`函数在应用程序启动过程中加载`contacts`特性时，会加载`contact-bundle`。Aurelia 的特性有一个局限性：很难将一个特性隔离在一个单独的捆绑文件中。实际上，一个特性的`index`文件以及它所有的依赖项应该被包含在`app-bundle`中。将其单独打包是没有用的，因为另一个捆绑文件在启动时会被加载。然而，特性中的其他所有内容都可以单独打包。

在我们应用程序中，即使你做了这个改动，当应用程序启动时`contacts-bundle`仍然会被加载，因为`app`组件会自动将用户重定向到联系人的默认路由，即联系人列表。

如果你在应用程序中添加一个主页组件作为默认路由，并确保这个主页组件包含在`app-bundle`中，你应该可以看到只有在导航到它时才会加载`contacts-bundle`。

# 版本化捆绑包

默认情况下，捆绑包是使用静态名称生成的。这意味着一个已经缓存了捆绑包的浏览器无法知道其缓存是否最新。如果应用程序发布了新版本怎么办？

为了解决这个问题，一个（糟糕）的解决方案是设置缓存持续时间到一个很短的时间段，这会强制所有用户频繁地下载所有捆绑包，或者接受一些用户可能运行我们应用程序的过时版本，这意味着相应地管理后端、网络服务等的兼容性。这似乎是一个导致噩梦的好配方。

一个更好的解决方案是在每个捆绑包的名称中添加某种修订号，并将缓存时间设置为让`index.html`的缓存时间非常短，甚至完全禁用其缓存。由于`index.html`与捆绑包相比非常小，这是一个有趣的选择，因为每次给定用户访问应用程序时，他会下载`index.html`的最新副本，该副本又会引用最新版本的捆绑包。这意味着捆绑包可以永久缓存，因为给定捆绑包名称的内容永远不会改变。用户永远不会下载某个捆绑包版本超过一次。

Aurelia CLI 通过在文件名后添加后缀来支持捆绑包版本化。这个后缀是文件内容计算出的哈希值。默认情况下，版本化是禁用的。要启用它，请打开`aurelia_project/aurelia.json`文件，在`build`部分的`options`设置`rev`属性：

`aurelia_project/aurelia.json`

```js
"options": { 
  "minify": "stage & prod", 
  "sourcemaps": "dev & stage", 
  "rev": "stage & prod" 
}, 

```

修订机制是按环境单独启用的。通常，它会在 staging 和 production 环境中启用。然而，它不应该在开发环境中使用，因为它与浏览器重新加载以及使用`watch`开关时的捆绑重建机制不太友好。此外，由于大多数开发人员系统地在与缓存禁用的浏览器中进行测试，它将没有多大价值。

你还需要始终确保在`aurelia_project/aurelia.json`文件中，在`build`部分下`targets`的第一个条目有一个`index`属性，其值为`index.html`：

`aurelia_project/aurelia.json`

```js
"targets": [ 
  { 
    "id": "web", 
    "displayName": "Web", 
    "output": "scripts", 
    "index": "index.html" 
  } 
], 

```

这使得捆绑器知道加载应用程序的 HTML 文件的名称，因此它可以更新加载入口点捆绑的`script`标签。

现在，你可以通过在项目目录中打开控制台并运行以下命令来测试这个：

```js
> au build --env stage

```

一旦命令完成，你应该在 `scripts` 目录下看到现在包含在其名称中的哈希的包。你应该看到类似于 `app-bundle-ea03d27d90.js` 和 `vendor-bundle-efd8bd9cd8.js` 的文件，哈希可能不同。

此外，在 `index.html` 中，`script` 标签内的 `src` 属性现在应该指的是带有哈希的 `vendor-bundle` 文件名称。

# 部署应用程序

此时，部署我们的应用程序相当简单。我们需要将以下文件复制到托管它的服务器上：

+   `index.html`

+   `favicon.ico`

+   `locales/`

+   `styles/`

+   `scripts/`

+   `node_modules/bootstrap/`

+   `node_modules/font-awesome/`

现在，大多数项目都会使用某种软件工厂来构建和部署应用程序。当然，我们可以在工厂的构建任务中轻松地放置这些文件列表。然而，这意味着每次我们向该列表添加一个文件或目录时，都需要更改构建任务。

当我在一个 Aurelia 项目中工作时，我喜欢做的一件事是在 `aurelia_project/aurelia.json` 文件中创建一个新的 `deploy` 部分，将其设置为匹配部署包中要包含的文件的 glob 模式列表：

`aurelia_project/aurelia.json`

```js
{ 
  //Omitted snippet... 
  "build": { 
    //Omitted snippet... 
  }, 
  "deploy": { 
    "sources": [ 
      "index.html", 
      "favicon.ico", 
      "locales/**/*", 
      "scripts/*-bundle*.{js,map}", 
      "node_modules/bootstrap/dist/**/*", 
      "node_modules/font-awesome/{css,fonts}/**/*" 
    ] 
  } 
} 

```

除此之外，我通常还在项目中创建一个 `deploy` 任务。这个任务只是构建应用程序，然后将文件复制到要部署的目标目录，该目标目录作为任务的一个参数传递。

让我们首先创建任务定义：

`aurelia_project/tasks/deploy.json`

```js
{ 
  "name": "deploy", 
  "description": "Builds, processes and deploy all application assets.", 
  "flags": [ 
    { 
      "name": "out", 
      "description": "Sets the output directory (required)", 
      "type": "string" 
    }, 
    { 
      "name": "env", 
      "description": "Sets the build environment (uses debug by default).", 
      "type": "string" 
    } 
  ] 
} 

```

接下来，让我们创建一个 `copy` 任务，该任务将由 `deploy` 任务使用：

`aurelia_project/tasks/copy.js`

```js
import gulp from 'gulp'; 
import {CLIOptions} from 'aurelia-cli'; 
import project from '../aurelia.json'; 

export default function copy() { 
  const output = CLIOptions.getFlagValue('out', 'o'); 
  if (!output) { 
    throw new Error('--out argument is required'); 
  } 

  return gulp.src(project.deploy.sources, { base: './' }) 
    .pipe(gulp.dest(output)); 
} 

```

这个任务首先检索作为 `out` 参数传递的目标目录，如果省略则失败，然后使用来自 `aurelia_project/aurelia.json` 中新 `deploy` 部分的 glob 模式列表，并将每个匹配的文件复制到提供的目标目录中。

最后，我们可以创建部署任务本身：

`aurelia_project/tasks/deploy.js`

```js
import gulp from 'gulp'; 
import build from './build'; 
import copy from './copy'; 

export default gulp.series( 
  build, 
  copy 
); 

```

这个任务只是依次执行 `build` 和 `copy`。我们甚至可以在 `build` 和 `copy` 之间运行单元测试任务。

这个 `gulp` 任务极大地简化了软件工厂中的构建任务。典型的软件工厂构建过程首先从版本控制中检出代码，然后运行以下命令：

```js
> npm install
> au deploy --env $(env) --out $(build-artifacts)

```

最后，它会将 `$(build-artifacts)` 下的所有内容复制到 Web 服务器上。

在这个场景中，`$(env)` 和 `$(build-artifacts)` 是一些环境或系统变量。第一个包含了构建所针对的环境，比如 `stage` 或 `prod`，而第二个包含了一些临时文件夹，从中复制要部署到 Web 服务器的工件。例如，它可能仅仅是工作目录中的一个 `dist` 文件夹。

这种解决方案的一个优点是，现在与构建和部署我们的应用程序相关的大多数细节都在项目本身之内。软件工厂不再依赖于应用程序源代码的文件结构和文件名，而是仅依赖于`gulp`任务。

# 总结

由于命令行界面（CLI）始终以捆绑模式运行应用程序，所以最初看起来部署 Aurelia 应用程序相当简单。然后你开始考虑 HTTP 缓存过期的问题，事情就变得有点复杂了。

幸运的是，CLI 已经提供了解决这些问题的工具。再加上一些良好实践，使将应用程序准备部署到现实世界变得足够简单。


# 第十一章．与其他库集成

UI 框架永远不会独自存在，尤其是 Web 框架。由于 Web 是一个丰富的平台，并且由一个充满活力的社区推动，因此有数千个库、小部件和组件可以在这个平台上无数的场景中 leverage，这大大节省了开发人员的时间。

在本章中，我们将了解如何将各种库集成到我们的联系人管理应用程序中。我们将添加来自 Bootstrap 和 jQuery UI 的 UI 小部件，使用`sortable.js`提供一些拖放支持，以及使用 D3 的图表。我们还将了解如何利用 SASS 而不是 CSS。最后，我们甚至将了解如何集成 Polymer 组件。

# 使用 Bootstrap 小部件

从这本书的开头到现在，我们一直依赖于 Bootstrap 来为我们的应用程序样式和布局。然而，我们还没有使用库的 JS 小部件。让我们看看我们如何可以将此类小部件集成到我们的应用程序中。

## 加载库

由于 Bootstrap 的 JS 小部件使用 jQuery，所以我们首先需要安装它：

```js
> npm install jquery --save

```

接下来，我们需要将 jQuery 和 Bootstrap JS 资源添加到供应商包中：

`aurelia_project/aurelia.json`

```js
{ 
  //Omitted snippet... 
  { 
    "name": "vendor-bundle.js", 
    "prepend": [ 
      "node_modules/bluebird/js/browser/bluebird.core.js", 
      "scripts/require.js" 
    ], 
    "dependencies": [ 
      //Omitted snippet... 
      "jquery", 
      { 
        "name": "bootstrap", 
        "path": "../node_modules/bootstrap/dist", 
        "main": "js/bootstrap.min", 
        "deps": ["jquery"], 
        "exports": "$", 
        "resources": [ 
          "css/bootstrap.min.css" 
        ] 
      }, 
      //Omitted snippet... 
    ] 
    //Omitted snippet... 
  } 
  //Omitted snippet... 
} 

```

在这里，我们在包的依赖项中添加了 jQuery，然后更新了 Bootstrap 的条目，以便在 jQuery 之后加载 JS 小部件。

应用程序中的`bootstrap`模块也配置为导出全局`jQuery`对象。这意味着我们可以在 JS 代码中从`bootstrap`导入`jQuery`对象，并确保 Bootstrap 小部件已经注册到 jQuery 上。

## 创建一个 bs-tooltip 属性

让我们通过一个简单的例子来看看如何使用 Bootstrap JS 小部件与 Aurelia 配合。我们将创建一个自定义属性，它将封装 Bootstrap 的`tooltip`小部件：

`src/resources/attributes/bs-tooltip.js`

```js
import {inject, DOM, dynamicOptions} from 'aurelia-framework'; 
import $ from 'bootstrap'; 

const properties = [ 
  'animation', 'container', 'delay', 'html',  
  'placement', 'title', 'trigger', 'viewport' 
]; 

@dynamicOptions 
@inject(DOM.Element) 
export class BsTooltipCustomAttribute { 

  isAttached = false; 

  constructor(element) { 
    this.element = element; 
  } 

  attached() { 
    const init = {}; 
    for (let property of properties) { 
      init[property] = this[property]; 
    } 
    $(this.element).tooltip(init); 
    this.isAttached = true; 
  } 

  detached() { 
    this.isAttached = false; 
    $(this.element).tooltip('destroy'); 
  } 
} 

```

在这里，我们首先从 Bootstrap 中导入 jQuery 全局对象。这将确保 Bootstrap JS 库已正确加载并注册到 jQuery 命名空间中。我们还声明了`tooltip`小部件支持的属性列表，因此属性可以使用动态选项，并忽略不支持的选项。

我们将使用动态选项而不是显式选项，只是为了少写一些代码。我们接下来会写一些更改处理方法，如果我们使用一个显式的属性列表，在`BsTooltipCustomAttribute`类中全部声明为可绑定的，我们将为每个属性编写一个不同的更改处理器。所有这些更改处理器都会做几乎相同的事情：更新 Bootstrap 小部件的相应选项。相反，由于我们使用动态选项，我们可以为所有选项编写一个单一的更改处理器。

现在我们可以创建一个名为`bs-tooltip`的自定义属性。它作为构造函数参数接收放置它的 DOM 元素。当附加到 DOM 时，它将传递给属性的每个支持属性的值分配给一个`init`对象。然后这个对象被传递到`tooltip`初始化方法，该方法在属性托管的元素上调用。最后一行将创建`tooltip`小部件。

最后，当从 DOM 中分离时，它只是调用`tooltip`小部件的`destroy`方法。

`bs-tooltip`属性的这个第一个版本不支持更新属性。这可以通过使用`propertyChanged`回调方法来更新`tooltip`小部件来实现：

`src/resources/attributes/bs-tooltip.js`

```js
//Omitted snippet... 
export class BsTooltipCustomAttribute { 
  //Omitted snippet... 

  propertyChanged(name) { 
    if (this.isAttached && properties.indexOf(name) >= 0) { 
      $(this.element).data('bs.tooltip').options[name] = this[name]; 
    } 
  } 
} 

```

在这里，当属性值发生变化且属性当前附加到 DOM 时，我们首先确保属性被小部件支持，然后我们简单地更新小部件的属性。

### 使用属性

现在我们可以向任何元素添加 Bootstrap`tooltip`。让我们在`list-editor`组件中将**移除**按钮的`title`属性替换为 Bootstrap`tooltip`：

`src/resources/elements/list-editor.html`

```js
<!-- Omitted snippet... --> 
<button type="button" class="btn btn-danger le-remove-btn"  
        click.delegate="removeItem($index)"  
        bs-tooltip="title.bind: 'resources.actions.remove' & t;  
                    placement: right"> 
    <i class="fa fa-times"></i> 
  </button> 
  <!-- Omitted snippet... --> 

```

在这里，我们只是将**移除**按钮的`t="[title]..."`属性删除，并用`bs-tooltip`属性替换它。在这个属性中，我们定义了一个`title`选项，将其绑定到前面相同的翻译结果。我们使用`.bind`命令和`t`绑定行为，当当前区域发生变化时，将更新工具提示的`title`。我们还指定`tooltip`应该放置在托管元素的`right`侧，使用`placement`选项。

不要忘记加载`bs-tooltip`属性，可以作为`resources`特性中的`configure`函数的全球资源，或者在`list-editor`模板中使用`require`语句来加载。

如果你在这个时候运行应用程序，并用鼠标悬停在一个`list-editor`实例中的**移除**按钮上，应该会出现一个 Bootstrap`tooltip`小部件。

## 创建 bs-datepicker 元素

我们联系人管理应用程序可以极大地受益于的一个小部件是一个日期选择器。这会让大多数用户输入生日变得更加方便。

Bootstrap 本身并不包括日期选择器，但有些作为插件提供。在本节中，我们将安装`bootstrap-datepicker`插件，加载它，并创建一个新的自定义元素，该元素将封装一个包含日期选择器的`input`元素。

### 安装 bootstrap-datepicker 插件

我们首先安装 Bootstrap 插件：

```js
> npm install bootstrap-datepicker --save

```

接下来，我们需要将其添加到供应商包中：

`aurelia_project/aurelia.json`

```js
{ 
  //Omitted snippet... 
  { 
    "name": "vendor-bundle.js", 
    "prepend": [ 
      "node_modules/bluebird/js/browser/bluebird.core.js", 
      "scripts/require.js" 
    ], 
    "dependencies": [ 
      //Omitted snippet... 
      { 
        "name": "bootstrap-datepicker", 
        "path": "../node_modules/bootstrap-datepicker/dist", 
        "main": "js/bootstrap-datepicker.min", 
        "deps": ["jquery"], 
        "resources": [ 
          "css/bootstrap-datepicker3.standalone.css" 
        ] 
      }, 
      //Omitted snippet... 
    ] 
  } 
  //Omitted snippet... 
} 

```

在这里，我们将`bootstrap-datepicker`库添加到供应商包中。与标准的 Bootstrap 小部件一样，这个插件在 jQuery 对象上添加了新的函数，所以它需要有一个对 jQuery 的依赖，这样它才能注册自己。它还作为额外的资源加载自己的样式表。

### 创建自定义元素

现在插件已经准备好使用，我们可以开始构建自定义元素了。我们的`bs-datepicker`元素将暴露一个双向绑定的`date`属性，它将分配选定的日期作为`Date`对象。它还将暴露一个可绑定的`options`属性，我们将用它来提供传递给底层`bootstrap-datepicker`小部件实例的选项。

首先，让我们编写它的模板：

`src/resources/elements/bs-datepicker.html`

```js
<template> 
  <require from="bootstrap-datepicker/css/ 
                 bootstrap-datepicker3.standalone.css"></require> 
  <input ref="input" class="form-control" /> 
</template> 

```

这个模板只需要样式表`bootstrap-datepicker`，然后声明一个`input`元素。这个`input`的引用将被分配给绑定上下文的`input`属性，以便视图模型可以使用它来托管日期选择器。

接下来，让我们编写视图模型类：

`src/resources/elements/bs-datepicker.js`

```js
import {bindable, bindingMode} from 'aurelia-framework'; 
import $ from 'bootstrap'; 
import 'bootstrap-datepicker'; 

export class BsDatepickerCustomElement { 

  static defaultOptions = { autoclose: true, zIndexOffset: 1050 }; 

  @bindable({ defaultBindingMode: bindingMode.twoWay }) date; 
  @bindable options; 

  isAttached = false; 
  isUpdating = false; 

  createDatepicker() { 
    const options = Object.assign({},  
      BsDatepickerCustomElement.defaultOptions,  
      this.options); 
    $(this.input).datepicker(options) 
      .on('clearDate', this.updateDate) 
      .on('changeDate', this.updateDate); 
    if (this.date) { 
      this.updateDatepickerDate(); 
    } 
  } 

  destroyDatepicker() { 
    $(this.input) 
      .datepicker() 
      .off('clearDate', this.updateDate) 
      .off('changeDate', this.updateDate) 
      .datepicker('destroy'); 
  } 

  updateDate = function() { 
    if (!this.isUpdating) { 
      this.date = $(this.input).datepicker('getUTCDate'); 
    } 
  }.bind(this); 

  updateDatepickerDate() { 
    $(this.input).datepicker('setUTCDate', this.date); 
  } 

  optionsChanged() { 
    if (this.isAttached) { 
      this.destroyDatepicker(); 
      this.createDatepicker(); 
    } 
  } 

  dateChanged() { 
    if (this.isAttached) { 
      this.isUpdating = true; 
      this.updateDatepickerDate(); 
      this.isUpdating = false; 
    } 
  } 

  attached() { 
    this.createDatepicker(); 
    this.isAttached = true; 
  } 

  detached() { 
    this.isAttached = false; 
    this.destroyDatepicker(); 
  } 
} 

```

我们首先需要从 Bootstrap 中导入全局 jQuery 对象；记住，我们在将 Bootstrap 库添加到 vendor bundle 中时，它导出了 jQuery 对象，以便我们编写`bs-tooltip`属性。

接下来，我们加载`bootstrap-datepicker`插件，使其正确注册到 jQuery 中，然后创建自定义元素的类。

它首先声明一个静态的`defaultOptions`属性，用于在创建小部件时设置选项的默认值。

当元素附加到 DOM 时，它在`input`上创建一个`datepicker`小部件实例。它还订阅了小部件的`clearDate`和`changeDate`事件，这样当小部件的选定日期发生变化时，它可以更新自己的`date`属性；然后初始化小部件的选定日期。

您可能想知道我们为什么添加这些事件监听器，为什么不直接绑定到`input`的值。那是因为小部件已经处理了`input`值的验证及其作为`Date`对象的解析，所以我们的自定义元素只需依赖于日历的选定日期即可。基本上，我们的自定义元素只是将其`date`可绑定属性与日历的选定日期桥接起来。当小部件的选定日期发生变化时，其中一个事件监听器会被触发，并将小部件的新值分配给元素的`date`属性。同样，由于元素的`date`属性默认使用双向绑定，当`date`属性发生变化时，通常是在模板中使用元素时进行初始化，绑定系统将调用`dateChanged`方法，并更新小部件的选定日期。此外，我们使用一个`isUpdating`属性来防止元素和小部件之间发生无限循环更新。

当元素从 DOM 中分离时，它首先取消订阅小部件的`clearDate`和`changeDate`事件，然后调用其`destroy`方法。

最后，当元素的`options`属性发生变化时，小部件会被销毁然后重新创建。这是因为，在撰写本文时，`bootstrap-datepicker`插件没有提供任何 API 来更新小部件的选项。

### 注意

正如你所看到的，这个元素手动处理了 Aurelia 与 Bootstrap 小部件之间的数据绑定。这里看到的模式，在小部件上注册事件处理程序，以及前后同步数据，都是在 Aurelia 中整合外部 UI 库时相当常见的。

Aurelia 社区中的一群人在这个领域做一些非常有趣的工作。他们开发了一种他们称之为桥梁的东西，允许我们在 Aurelia 应用程序中使用各种 UI 框架。他们已经发布了一个针对 Kendo UI 的桥梁，正在为 Bootstrap 和 Materialize 等开发桥梁。如果你对这个问题感兴趣，我建议你看看他们的工作：[`github.com/aurelia-ui-toolkits`](https://github.com/aurelia-ui-toolkits)。

### 使用元素

现在我们可以轻松地将`form`组件中绑定到联系人生日的`input`替换为我们新的`bs-datepicker`元素：

`src/contacts/components/form.html`

```js
<!-- Omitted snippet... --> 
<div class="form-group"> 
  <label class="col-sm-3 control-label"  
         t="contacts.birthday"></label> 
  <div class="col-sm-9"> 
    <bs-datepicker date.bind="contact.birthday & validate"> 
    </bs-datepicker> 
  </div> 
</div> 
<!-- Omitted snippet... --> 

```

在这里，我们简单地将之前的`input`元素替换为`bs-datepicker`元素。我们将元素的`date`属性绑定到`contact`的`birthday`属性上，用`validate`绑定行为装饰这个绑定，以便属性仍然受到验证。

由于我们新元素的这个`date`属性期待的是一个`Date`对象，而不是一个字符串值，我们需要改变`Contact`模型类，使其在从 JS 对象创建时解析它的`birthday`属性为一个`Date`实例。另外，我们需要将`birthday`的默认值从空字符串改为`null`：

`src/contacts/models/contact.js`

```js
//Omitted snippet... 
export class Contact { 

  static fromObject(src) { 
    const contact = Object.assign(new Contact(), src); 
    if (contact.birthday) { 
      contact.birthday = new Date(contact.birthday); 
    } 
    //Omitted snippet... 
  } 

  //Omitted snippet... 
  birthday = null; 
  //Omitted snippet... 
} 

```

现在，`Contact`实例的`birthday`属性将是`null`值或`Date`对象。

此时，如果你运行应用程序，导航到创建或编辑组件，并将焦点给予生日的`input`，日历选择器应该会出现。你应该能够导航日历并选择一个日期。

不要忘记加载`bs-datepicker`元素，无论是作为`resources`特性中的`configure`函数中的全局资源，还是在`form`模板中使用`require`语句。

## 国际化 bs-datepicker 元素

至此，我们的`bs-datepicker`元素还不支持国际化。在典型的实际应用中，输入中显示的日期的格式，以及日历中的文本和属性，如一周的第一天，应该是本地化的。

幸运的是，`bootstrap-datepicker`包含作为额外 JS 模块的本地化数据。我们只需要在捆绑包中包含我们需要本地化的模块。

### 重新配置 jQuery 和 Bootstrap 的捆绑

然而，在撰写本文时，本地化的模块不支持模块加载机制，而完全依赖于 jQuery 对象处于全局作用域中。因此，我们需要改变使用 jQuery 及 Bootstrap 小部件的方式，不是作为 AMD 模块加载，而是作为全局库加载，利用供应商捆绑包的`prepend`属性：

`aurelia_project/aurelia.json`

```js
//Omitted snippet... 
{ 
  "name": "vendor-bundle.js", 
  "prepend": [ 
    "node_modules/bluebird/js/browser/bluebird.core.js", 
    "node_modules/jquery/dist/jquery.min.js", 
    "node_modules/bootstrap/dist/js/bootstrap.min.js", 
    "node_modules/bootstrap-datepicker/dist/js/bootstrap-datepicker.min.js", 
    "node_modules/bootstrap-datepicker/dist/locales/ 
       bootstrap-datepicker.fr.min.js", 
    "scripts/require.js" 
  ], 
  "dependencies": [ 
    //Omitted snippet... 
  ] 
} 
//Omitted snippet... 

```

在这里，我们向捆绑包的预加载库中添加了 jQuery、Bootstrap 小部件、`bootstrap-datepicker`插件及其法语本地化模块（英语本地化数据已内置在插件本身中，因此我们不需要包含它）。这意味着那些库将简单地合并到捆绑包的开头，而不是作为 AMD 模块加载，而是使用全局`window`作用域。当然，这意味着必须从`dependencies`数组中删除 jQuery、Bootstrap 和日期选择器插件的条目。

由于预加载的库只能是 JS 文件，这也意味着我们必须改变加载 Bootstrap 样式表的方式：

`index.html`

```js
<!-- Omitted snippet... --> 
<head> 
    <title>Learning Aurelia</title> 
    <link href="node_modules/bootstrap/dist/css/bootstrap.min.css"  
          rel="stylesheet"> 
    <link href="node_modules/bootstrap-datepicker/dist/css/ 
                bootstrap-datepicker3.standalone.css"  
          rel="stylesheet"> 
  <!-- Omitted snippet... --> 
<head> 
<!-- Omitted snippet... --> 

```

当然，必须分别从`src/app.html`和`src/resources/elements/bs-datepicker.html`模板中删除对`bootstrap.css`和`bootstrap-datepicker3.standalone.css`的`require`声明。

最后，必须从`bs-tooltip.js`和`bs-datepicker.js`文件中删除对`bootstrap`和`bootstrap-datepicker`的`import`声明，因为 jQuery、Bootstrap 和日期选择器插件将从全局作用域访问。

### 更新元素

要本地化日期选择器小部件，我们只需设置`language`选项：

`src/contacts/components/form.html`

```js
<!-- Omitted snippet... --> 
<bs-datepicker date.bind="contact.birthday & validate" 
               options.bind="{ language: locale }"> 
</bs-datepicker> 
<!-- Omitted snippet... --> 

```

这意味着我们需要将这个`locale`属性添加到`form`的视图模型中。我们还需要订阅适当的事件，这样我们可以在当前语言环境发生变化时更新属性：

`src/contacts/components/form.js`

```js
//Omitted snippet... 
import {I18N} from 'aurelia-i18n'; 
import {EventAggregator} from 'aurelia-event-aggregator'; 

@inject(DOM.Element, Animator, I18N, EventAggregator) 
export class ContactForm { 

@bindable contact; 

constructor(element, animator, i18n, eventAggregator) { 
    this.element = element; 
    this.animator = animator; 
    this.i18n = i18n; 
    this.eventAggregator = eventAggregator; 
  } 

  bind() { 
    this.locale = this.i18n.getLocale(); 
    this._localeChangedSubscription = this.eventAggregator 
      .subscribe('i18n:locale:changed', () => { 
        this.locale = this.i18n.getLocale(); 
      }); 
  } 

  unbind() { 
    this._localeChangedSubscription.dispose(); 
    this._localeChangedSubscription = null; 
  } 

  //Omitted snippet... 
} 

```

在这里，我们首先从`aurelia-i18n`库导入`I18N`类和从`aurelia-event-aggregator`库导入`EventAggregator`类。然后我们向 DIC 暗示它们应该都被注入到视图模型的构造函数中。

当组件进行数据绑定时，我们使用`I18N`实例的`getLocale`方法初始化`locale`属性，并订阅`i18n:locale:changed`事件，这样我们就可以保持`locale`属性的最新。

最后，当组件解绑时，我们取消事件订阅。

在此阶段，如果您运行应用程序并在切换当前语言环境（在法语和英语之间）的同时尝试生日日期选择器，`input`中显示的日期格式以及日历的文本和设置应该相应地更新。

# 使用 jQuery UI 小部件

jQuery UI 小部件库仍然相当受欢迎。将那些小部件集成到 Aurelia 应用程序中与刚刚与 Bootstrap 小部件进行的操作相当相似，尽管不如 Bootstrap 小部件那样无痛，正如我们将在下一节中看到的那样。

让我们使用 jQuery UI 创建一个`tooltip`属性，以便我们可以与 Bootstrap 的属性进行比较。

### 注意

以下代码段是从书籍资源中的`chapter-11/samples/using-jqueryui`示例中摘录的。

## 安装库

我们首先需要通过在项目目录中打开控制台并运行以下命令来安装 jQuery 和 jQuery UI：

```js
> npm install jquery --save
> npm install github:components/jqueryui#1.12.1 --save

```

接下来，我们需要将这些库添加到供应商包中。最简单的方法是将它们放入`prepend`部分：

`aurelia_project/aurelia.json`

```js
//Omitted snippet... 
{ 
  "name": "vendor-bundle.js", 
  "prepend": [ 
    "node_modules/bluebird/js/browser/bluebird.core.js", 
    "node_modules/jquery/dist/jquery.min.js", 
    "node_modules/components-jqueryui/jquery-ui.min.js", 
    "scripts/require.js" 
  ], 
  "dependencies": [ 
    //Omitted snippet... 
  ] 
} 
//Omitted snippet... 

```

由于 CSS 文件不能全局加载到`prepend`部分，所以让我们将它们加载到`index.html`文件中：

`index.html`

```js
<!-- Omitted snippet... --> 
<head> 
<title>Aurelia</title> 
  <link href="node_modules/bootstrap/dist/css/bootstrap.min.css"  
        rel="stylesheet"> 
  <link href="node_modules/components-jqueryui/themes/base/all.css"  
        rel="stylesheet"> 
  <!-- Omitted snippet... --> 
</head> 
<!-- Omitted snippet... --> 

```

此时，我们现在可以创建我们的属性。

## 创建一个 jq-tooltip 属性

一开始，我们的新属性将与使用 Bootstrap 的那个非常相似：

`src/resources/attributes/jq-tooltip.js`

```js
import {inject, DOM, dynamicOptions} from 'aurelia-framework'; 

const properties = [ 
  'classes', 'content', 'disabled', 'hide', 'position', 
  'show', 'track',  
]; 

@dynamicOptions 
@inject(DOM.Element) 
export class JqTooltipCustomAttribute { 

  isAttached = false; 

  constructor(element) { 
    this.element = element; 
  } 

  attached() { 
    const options = {}; 
    for (let property of properties) { 
      options[property] = this[property]; 
    } 
    $(this.element).tooltip(options); 
    this.isAttached = true; 
  }   

  detached() { 
    this.isAttached = false; 
    $(this.element).tooltip('destroy'); 
  } 
} 

```

我们首先定义了`jq-tooltip`组件支持的`options`，这样属性就可以使用动态选项并忽略那些在此不支持的属性；`jq-tooltip`属性表现得与我们在上一节创建的`bs-tooltip`属性一模一样。接下来，我们提示 DI 容器，应该将包含属性的 DOM 元素注入到构造函数中。

当属性附加到 DOM 时，它检索绑定到属性实例的每个支持属性的值，以构建一个`options`对象。然后将这个对象传递给`tooltip`初始化方法，该方法应用于包含属性的元素。

当属性从 DOM 中移除时，在包含属性的元素上调用了小部件的`destroy`方法。

此时，属性不支持属性更改。由于 jQuery 的`tooltip`小部件提供了一个 API 来更新选项，这个实现不需要销毁并重新创建小部件来更新属性，就像`bs-tooltip`属性一样：

`src/resources/attributes/jq-tooltip.js`

```js
//Omitted snippet... 
propertyChanged(name) { 
  if (this.isAttached && properties.indexOf(name) >= 0) { 
    $(this.element).tooltip('option', name, this[name]); 
  } 
} 
//Omitted snippet... 

```

在这里，我们简单地添加了`propertyChanged`回调方法，如果属性附加到 DOM 并且更新后的属性被小部件支持，它将更新小部件实例。

现在我们的属性已经准备好了，让我们在`list-editor`组件中将**移除**按钮的`title`属性替换为`jq-tooltip`自定义属性：

`src/resources/elements/list-editor.html`

```js
<!-- Omitted snippet.. --> 
<button type="button" class="btn btn-danger le-remove-btn"  
        click.delegate="removeItem($index)" 
        jq-tooltip="content.bind: 'resources.actions.remove' & t"> 
  <i class="fa fa-times"></i> 
</button> 
<!-- Omitted snippet.. --> 

```

在这里，我们只是在正确的`button`元素上放置了一个`jq-tooltip`属性。我们将它的`content`属性绑定到正确的翻译，这被`t`绑定行为修饰。

不要忘记加载`jq-tooltip`属性，要么作为`resources`特性中的`configure`函数中的全局资源，要么在`list-editor`模板中使用`require`语句加载。

然而，如果你运行应用程序，并将鼠标悬停在`list-editor`元素的**移除**按钮上，你会发现`tooltip`没有显示。

这是由一个众所周知的长久限制造成的；社区中的一些人会说这是一个 bug（我会同意）在`tooltip`小部件中，它强制宿主元素具有一个`title`属性，即使它没有被使用。

因此，让我们更新属性并添加一个方法，如果宿主元素上不存在`title`属性，则创建一个空的`title`属性：

`src/resources/attributes/jq-tooltip.js`

```js
//Omitted snippet... 
attached() { 
  if (!this.element.hasAttribute('title')) { 
    this.element.setAttribute('title', ''); 
  } 
  //Omitted snippet... 
} 
//Omitted snippet... 

```

现在你可以运行应用程序，`tooltip`应该正确显示。

# 使用 SASS 而不是 CSS

**SASS**，代表 Syntactically Awesome Stylesheets，根据他们的网站，是世界上最为成熟、稳定、强大的专业级 CSS 扩展语言。无论这一说法是否真实，它都是非常受欢迎的，至少我可以肯定地说我使用得很多。

在 Aurelia 应用中使用 SASS 而不是 CSS 相当简单，至少对于基于 CLI 的项目来说是这样。CLI 已经提供了许多 CSS 处理器的支持，比如 SASS、LESS 和 Stylus。

让我们使用 CLI 重新创建我们的联系人管理应用，并在创建过程中启用 SASS 处理器：

![使用 SASS 代替 CSS](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/lrn-aurelia/img/image_00_001.jpg)

你可以为所有其他问题选择默认值。

一旦项目创建完成并且已经获取了依赖项，我们就可以把我们应用的工作副本中的以下目录和文件移动到新创建的项目中：

+   `aurelia_project/environments`

+   `locales`

+   `src`

+   `index.html`

我们还需要从`package.json`文件中复制`dependencies`，并运行另一个`npm install`以获取所有的应用依赖。最后，我们需要复制`aurelia_project/aurelia.json`文件中的 vendor-bundle 配置。

你可以参考书籍资源中的`chapter-11/samples/using-sass`示例。

## 用 SASS 替换 CSS

让我们通过将`.css`扩展名替换为`.scss`扩展名，将应用中的 CSS 文件转换为 SASS 文件：

`src/resources/elements/list-editor.scss`

```js
list-editor .animated .le-item { 
  &.au-enter-active { 
    animation: blindDown 0.2s; 
    overflow: hidden; 
  } 

  &.au-leave-active { 
    animation: blindUp 0.2s; 
    overflow: hidden; 
  } 
} 

@keyframes blindDown { 
  0% { max-height: 0px; } 
  100% { max-height: 80px; } 
} 

@keyframes blindUp { 
  0% { max-height: 80px; } 
  100% { max-height: 0px; } 
} 

```

由于 CLI 创建的构建任务现在包括一个 SASS 处理器，`src`目录中的每个`.scss`文件都将被转换成具有相同路径的`.css`文件，并且会包含在`app-bundle`中该路径下。

例如，`resources/elements/list-editor.scss`文件将被转换成 CSS，结果将被打包成`app-bundle`中的`resources/elements/list-editor.css`。

这意味着`require`语句必须保持使用`.css`扩展名引用样式表：

`src/resources/elements/list-editor.html`

```js
<template> 
  <require from="./list-editor.css"></require> 
  <!-- Omitted snippet... --> 
</template> 

```

如果你在这个时候运行应用程序，一切应该都会像以前一样进行样式设计。

# 拖放与可排序

可排序（Sortable）（[`github.com/RubaXa/Sortable`](https://github.com/RubaXa/Sortable)）是一个知名的拖放库。其简单而强大的 API 使得集成变得非常容易。

我们可以在我们的联系人管理应用中使用它，允许用户使用拖放来重新排序`list-editor`元素的项。

## 安装库

首先，我们需要通过在项目目录中打开控制台并运行以下命令来安装库：

```js
> npm install sortablejs --save

```

接下来，我们需要将其添加到 vendor bundle 中：

`aurelia_project/aurelia.json`

```js
//Omitted snippet... 
{ 
  "name": "vendor-bundle.js", 
  "prepend": [ 
    //Omitted snippet... 
  ], 
  "dependencies": [ 
    "sortablejs", 
    //Omitted snippet... 
  ] 
}, 
//Omitted snippet... 

```

此时，我们可以在我们的应用中使用这个库。

## 给 list-editor 添加拖放

让我们首先给列表项添加一个处理程序。这个处理程序将是用户能够拖动项目上下列表的区域。此外，我们还需要添加一个`div`元素，它将作为可排序项目的容器：

`src/resources/elements/list-editor.html`

```js
<!-- Omitted snippet... --> 
<div ref="container"> 
  <div class="form-group le-item ${animated ? 'au-animate' : ''}"  
       repeat.for="item of items"> 
    <template with.bind="item"> 
      <div class="col-sm-1"> 
        <i class="fa fa-bars fa-2x sort-handle pull-right"></i> 
      </div> 
      <template replaceable part="item"> 
        <div class="col-sm-2"> 
          <template replaceable part="label"></template> 
        </div> 
        <!-- Omitted snippet... --> 
      </template> 
      <!-- Omitted snippet... --> 
    </template> 
  </div> 
</div> 
<!-- Omitted snippet... --> 

```

这里，我们首先在包含列表项的`div`元素上为视图模型的`container`属性分配一个引用。这个`container`将由`sortable` API 用来启用其子元素的拖放。接下来，我们移除了标签列上的`col-sm-offset-1` CSS 类，并添加了一个大小为 1 的列，使用 Bootstrap 的`col-sm-1` CSS 类包含一个`bars` Font Awesome 图标并作为`sort-handle`，使用相同名称的 CSS 类。

让我们也添加一个 CSS 规则来改变拖动处理器的鼠标光标：

`src/resources/elements/list-editor.css`

```js
/* Omitted snippet... */ 
list-editor .sort-handle { 
 cursor: move; 
} 

```

我们现在可以使用`sortable`来添加拖放支持：

`src/resources/elements/list-editor.js`

```js
//Omitted snippet... 
import sortable from 'sortablejs'; 

export class ListEditor { 
  //Omitted snippet... 
 moveItem(oldIndex, newIndex) { 
    const item = this.items[oldIndex]; 
    this.items.splice(oldIndex, 1); 
    this.items.splice(newIndex, 0, item); 
  } 

 attached() { 
    this.sortable = sortable.create(this.container, { 
      sort: true, 
      draggable: '.le-item', 
      handle: '.sort-handle',  
      animation: 150, 
      onUpdate: (e) => { 
        if (e.newIndex != e.oldIndex) { 
          this.animated = false; 
          this.moveItem(e.oldIndex, e.newIndex);  
          setTimeout(() => { this.animated = true; }); 
        } 
      } 
    }); 
    setTimeout(() => { this.animated = true; }); 
  } 

 detached() { 
    this.sortable.destroy(); 
    this.sortable = null; 
  } 
  //Omitted snippet... 
} 

```

这里，我们首先导入了`sortable` API。然后，当元素附着到 DOM 上时，我们在具有`le-item` CSS 类的`container`元素上创建一个`sortable`实例。我们指定`sortable`应该使用具有`sort-handle` CSS 类的项目的子元素作为拖动处理程序。最后，当一个项目在列表的不同位置被放下时，触发`onUpdate`回调，在其中我们从`items`数组中删除被放下项目的前一个位置，然后将其放回新的位置。

我们需要使用`splice`来删除然后添加移动的项目，因为 Aurelia 无法观察数组的索引设置器。它只能通过覆盖`Array.prototype`的方法来反应数组的变化，比如`splice`。

此外，在移动项目之前，我们还需要删除项目上的`animated` CSS 类，这样就不会触发动画的 CSS 规则。我们然后使用`setTimeout`将其加回来，这样只有在模板引擎完成移除旧视图并添加新视图后，它才会被添加。这样，在拖动和放下项目时，不会播放添加或删除项目的动画，这看起来会很奇怪。

最后，当`list-editor`从 DOM 中分离时，我们在`sortable`实例上调用`destroy`方法，以防止内存泄漏。

到此为止，您可以运行应用程序，为联系人列表属性中的一个项目重新排序，并保存表单。在详细视图中，项目应该按照您放置的顺序出现。

# 使用 D3 绘制图表

以图形的形式呈现数据是现代应用程序中另一个常见的需要。当涉及到 Web 时，**D3.js**是一个众所周知的光库，它提供了一个非常强大的 API，用于在 DOM 中显示数据。

在下一节中，我们将向我们的联系人管理应用程序添加一个树视图，该视图将按地址部分显示联系人分组。取所有联系人的所有地址，节点的第一个层次将是国家，然后每个国家将有自己的州作为子节点，然后是每个城市，依此类推。

### 注意

本节我们将要构建的树视图只是用 D3 能够实现功能的一个简单、拙劣的示例。访问[`d3js.org/`](https://d3js.org/)，浏览数百个示例，亲自体验这个库的强大功能。

## 安装库

首先，通过在项目目录中打开控制台并运行以下命令来安装库：

```js
> npm install d3 --save

```

像往常一样，我们需要将其添加到供应商包中：

`aurelia_project/aurelia.json`

```js
//Omitted snippet... 
{ 
  "name": "vendor-bundle.js", 
  "prepend": [ 
    //Omitted snippet... 
  ], 
  "dependencies": [ 
    { 
      "name": "d3", 
      "path": "../node_modules/d3/build", 
      "main": "d3.min" 
    }, 
    //Omitted snippet... 
  ] 
} 
//Omitted snippet... 

```

至此，D3 已准备好使用。

## 准备应用程序

在创建树本身之前，让我们先为它周围的应用程序做好准备。我们将添加一个`route`组件，使用网关加载联系人，在其中显示树。我们还将为这个组件在联系人`main`中添加一个`route`，然后添加允许在列表和树之间导航的链接。

我们先从`route`开始：

`src/contacts/main.js`

```js
//Omitted snippet... 
config.map([ 
  { route: '', name: 'contacts', moduleId: './components/list',  
    title: 'contacts.contacts' }, 
  { route: 'by-address', name: 'contacts-by-address',  
    moduleId: './components/by-address',  
    title: 'contacts.byAddress' }, 
  { route: 'new', name: 'contact-creation',  
    moduleId: './components/creation',  
    title: 'contacts.newContact' }, 
  { route: ':id', name: 'contact-details',  
    moduleId: './components/details' }, 
  { route: ':id/edit', name: 'contact-edition',  
    moduleId: './components/edition' }, 
  { route: ':id/photo', name: 'contact-photo',  
    moduleId: './components/photo' }, 
]); 
//Omitted snippet... 

```

这里，我们简单地添加了一个名为`contacts-by-address`的`route`，匹配`by-address`路径，并指向我们将在一分钟内创建的`by-address`组件。

接下来，让我们在列表组件中添加一个链接，该链接指向尚不存在的树组件：

`src/contacts/components/list.html`

```js
<template> 
  <section class="container au-animate"> 
    <h1 t="contacts.contacts"></h1> 
    <p> 
      <a route-href="route: contacts-by-address"  
         t="contacts.viewByAddress"></a> 
    </p> 
    <!-- Omitted snippet... --> 
  </section> 
</template> 

```

### 注意

你可能注意到新`route`的`title`属性和新链接的文本都使用了新的翻译，增加的内容留给读者作为练习。像往常一样，本章节的示例应用程序可以作为参考。

最后，我们将创建`by-address`组件。为了使事情尽可能解耦，我们将 D3 相关代码隔离在一个名为`contact-address-tree`的自定义元素中。`by-address`组件的唯一责任将是将这个自定义元素与应用程序的其他部分连接起来。

让我们先从视图模型开始：

`src/contacts/components/by-address.js`

```js
import {inject} from 'aurelia-framework'; 
import {Router} from 'aurelia-router'; 
import {ContactGateway} from '../services/gateway'; 

@inject(ContactGateway, Router) 
export class ContactsByAddress { 

  contacts = []; 

  constructor(contactGateway, router) { 
    this.contactGateway = contactGateway; 
    this.router = router; 
  } 

  activate() { 
    return this.contactGateway.getAll().then(contacts => { 
      this.contacts.splice(0); 
      this.contacts.push.apply(this.contacts, contacts);  
    }); 
  } 

  navigateToDetails(contact) { 
    this.router 
      .navigateToRoute('contact-details', { id: contact.id }); 
  } 
} 

```

这个视图模型相当直接。当激活时，它使用注入的网关检索联系人的完整列表。它还暴露了一个触发导航到给定联系人的详细信息组件的方法。当在树中点击一个联系节点时，将调用这个方法。

模板相当简单，正如您所想象的：

`src/contacts/components/by-address.html`

```js
<template>  
  <require from="./by-address.css"></require> 
  <require from="../elements/address-tree"></require> 

  <section class="container au-animate"> 
    <h1 t="contacts.byAddress"></h1> 

    <p> 
      <a route-href="route: contacts" t="contacts.viewByName"></a> 
    </p> 

    <contact-address-tree contacts.bind="contacts"  
                          click.call="navigateToDetails(contact)"> 
    </contact-address-tree> 
  </section> 
</template> 

```

这个模板简单地声明了一个`contact-address-tree`元素，绑定加载的`contacts`，并在点击联系节点时调用`navigateToDetails`。

CSS 文件简单地设置了`contact-address-tree`元素的大小：

`src/contacts/components/by-address.css`

```js
contact-address-tree { 
  display: block; 
  width: 100%; 
  min-height: 400px; 
} 

```

## 创建`contact-address-tree`自定义元素

一切准备就绪，我们可以使用我们新的元素了，现在让我们创建它。

### 注意

由于我们正在添加更多专门针对联系人的自定义元素，我建议我们在`contacts`特性中创建一个新的`elements`目录，将联系人`form`移动到那里，并在其中创建这些新元素。本章完成的应用程序示例可以作为参考。

我们首先通过一些 CSS 规则来布局，这些规则将样式化树的各个部分，如分支节点、叶节点和链接：

`src/contacts/elements/address-tree.css`

```js
contact-address-tree .node circle { 
  fill: #d9edf7; 
  stroke: #337ab7; 
  stroke-width: 1.5px; 
} 

contact-address-tree .node text { 
  font: 15px; 
} 

contact-address-tree .node text { 
  text-shadow: 0 1px 0 #fff, 0 -1px 0 #fff, 1px 0 0 #fff, -1px 0 0 #fff; 
} 

contact-address-tree .leaf { 
  cursor: pointer; 
} 

contact-address-tree .leaf circle { 
  fill: #337ab7; 
} 

contact-address-tree .leaf text { 
  font-weight: bold; 
} 

contact-address-tree .link { 
  fill: none; 
  stroke: #777; 
  stroke-width: 1.5px; 
} 

```

由于树视图的渲染将由 D3 API 处理，自定义元素不需要模板。因此，它将被声明为带有`noView`装饰器，传递 CSS 文件的路径给它，以便作为资源加载：

`src/contacts/elements/address-tree.js`

```js
import {inject, DOM, noView, bindable} from 'aurelia-framework'; 
import * as d3 from 'd3'; 

@inject(DOM.Element) 
@noView(['./address-tree.css']) 
export class ContactAddressTreeCustomElement {      

  @bindable contacts; 
  @bindable click; 

  constructor(element) { 
    this.element = element; 
  } 
} 

```

此外，视图模型的构造函数将被注入到 DOM 元素本身，因此 D3 API 可以用它作为视口来渲染树。它还暴露了一个`contacts`和一个`click`可绑定属性。

这是 Aurelia 部分的内容。现在，我们添加一个`attached`方法，它将在元素内部渲染树。这个方法里面的代码将完全不知道 Aurelia，只是简单地与`d3` API 和 DOM `element`本身一起工作：

`src/contacts/elements/address-tree.js`

```js
//Omitted snippet... 
export class ContactAddressTreeCustomElement { 
  //Omitted snippet... 

 attached() { 
    // Calculate the size of the viewport 
    const margin = { top: 20, right: 200, bottom: 20, left: 12 }; 
    const height = this.element.clientHeight  
      - margin.top - margin.bottom; 
    const width = this.element.clientWidth  
      - margin.right - margin.left; 

    // Create the host elements and the tree factory 
    const tree = d3.tree().size([height, width]); 
    const svg = d3.select(this.element).append('svg') 
        .attr('width', width + margin.right + margin.left) 
        .attr('height', height + margin.top + margin.bottom); 
    const g = svg.append('g') 
        .attr('transform',  
              `translate(${margin.left}, ${margin.top})`); 

    // Create the hierarchy, then initialize the tree from it 
    const rootNode = this.createAddressTree(this.contacts); 
    const hierarchy = d3.hierarchy(rootNode); 
    tree(hierarchy); 

    // Render the nodes and links 
    const link = g.selectAll('.link') 
      .data(hierarchy.descendants().slice(1)) 
      .enter().append('path') 
      .attr('class', 'link') 
      .attr('d', d => `M${d.y},${d.x}C${(d.y + d.parent.y) / 2}, 
                       ${d.x} ${(d.y + d.parent.y) / 2}, 
                       ${d.parent.x} ${d.parent.y}, 
                       ${d.parent.x}`); 

    const node = g.selectAll('.node') 
      .data(hierarchy.descendants()) 
      .enter().append('g') 
      .attr('class', d => 'node ' + (d.children ? 'branch' : 'leaf')) 
      .attr('transform', d => `translate(${d.y}, ${d.x})`) 
      .on('click', e => { this.onNodeClicked(e); }); 

    node.append('title') 
      .text(d => d.data.name); 

    node.append('circle') 
      .attr('r', 10); 

    node.append('text') 
      .attr('dy', 5) 
      .attr('x', d => d.children ? -15 : 15) 
      .style('text-anchor', d => d.children ? 'end' : 'start') 
      .text(d => d.data.name); 
  } 
} 

```

### 注意

这段代码是 Mike Bostock 示例的简化改编，可以在[`bl.ocks.org/mbostock/4339083`](https://bl.ocks.org/mbostock/4339083)找到。

详细解释`d3` API 如何工作超出了本书的范围。然而，前一个代码片段中的内联注释可以让你对它如何工作有一个大致的了解。

你可能注意到了一些缺失的部分：`createAddressTree`和`onNodeClicked`方法还没有存在。

后者相当简单：

`src/contacts/elements/address-tree.js`

```js
//Omitted snippet... 
export class ContactAddressTreeCustomElement { 
  //Omitted snippet... 

 onNodeClicked(node) { 
    if (node.data.contact && this.click) { 
      this.click({ contact: node.data.contact }); 
    } 
  } 
} 

```

这个方法只是确保被点击的节点是联系人节点，并且`click`属性已经被正确绑定，然后用被点击的`contact`对象调用它。这将执行用`.call`命令绑定到`click`属性的表达式，把它作为`contact`参数传递给属性。

前者要稍微复杂一点。它的任务是将联系人列表转换为树数据结构，这将作为`d3` API 的数据源：

`src/contacts/elements/address-tree.js`

```js
//Omitted snippet... 
export class ContactAddressTreeCustomElement { 
  //Omitted snippet... 

 createAddressTree(contacts) { 
    const rootNode = { name: '', children: [] }; 
    for (let contact of contacts) { 
      for (let address of contact.addresses) { 
        const path = this.getOrCreateAddressPath( 
          rootNode, address); 
        const pathTail = path[path.length - 1]; 
        pathTail.children.push({ 
          name: contact.fullName,  
          contact 
        }); 
      } 
    } 
    return rootNode; 
  } 

  getOrCreateAddressPath(rootNode, address) { 
    const countryNode = this.getOrCreateNode( 
      rootNode, address.country); 
    const stateNode = this.getOrCreateNode( 
      countryNode, address.state); 
    const cityNode = this.getOrCreateNode( 
      stateNode, address.city); 
    const streetNode = this.getOrCreateNode( 
      cityNode, address.street); 
    const numberNode = this.getOrCreateNode( 
      streetNode, address.number); 
    return [countryNode, stateNode, cityNode,  
      streetNode, numberNode]; 
  } 

  getOrCreateNode(parentNode, name) { 
    name = name || '?'; 

    const normalizedName = this.normalizeNodeName(name); 
    let node = parentNode.children 
      .find(n => n.normalizedName === normalizedName); 
    if (!node) { 
      node = { name, normalizedName, children: [] }; 
      parentNode.children.push(node); 
    } 
    return node; 
  } 

  normalizeNodeName(name) { 
    return name.toLowerCase().trim().replace(/\s+/, ' '); 
  } 
} 

```

在这里，`createAddressTree`方法首先创建一个带有空`children`列表的根节点。然后，它遍历每个联系人的`addresses`，为每个地址创建一个节点路径，从国家开始，一直深入到街道号码。整个路径或其中一部分如果已经存在，就不会再次创建节点，而是简单地检索。最后，一个代表联系人的叶节点被附加到路径中的最后一个节点，即街道号码节点。

在此阶段，如果你运行应用程序并前往地址树视图，你应该能看到联系人显示出来，以树状布局。

# 使用 Polymer 组件

**Polymer**是一个流行的库，严重倾向于 web 组件。它的社区提供了各种各样的组件，其中包括一个`google-map`元素，它封装了 Google Maps API，以便在 HTML 中声明性地显示地图。

Aurelia 提供了一个名为`aurelia-polymer`的集成库，它允许在 Aurelia 应用程序中使用 Polymer 组件。在下一节中，我们将将其集成到我们的联系人管理应用程序中。在详细信息组件中，我们将显示一个显示联系人地址的小地图。

## 安装库

Polymer 及其库通常使用**Bower**进行安装。Bower 和 NPM 可以毫无问题地并行使用，因此让我们首先安装它，如果你还没有在开发环境中安装它，那么通过打开一个控制台并运行以下命令：

```js
> npm install -g bower

```

Bower 是另一个用于网络库的包管理器，可以在[`bower.io/`](https://bower.io/)找到。

完成这些之后，让我们创建 Bower 的项目文件：

`bower.json`

```js
{ 
  "name": "learning-aurelia", 
  "private": true, 
  "dependencies": { 
    "polymer": "Polymer/polymer#¹.2.0", 
    "google-map": "GoogleWebComponents/google-map#¹.1.13", 
    "webcomponentsjs": "webcomponents/webcomponentsjs#⁰.7.20" 
  } 
} 

```

这个文件与`package.json`非常相似。它描述了由 Bower 管理的项目的依赖关系。在这里，我们包括了 Polymer 和 Google Maps 组件。

我们还包含了`webcomponentjs`，这是各种 web 组件 API 的 polyfill，例如自定义元素 API 和 HTML Imports API。由于这两个 API 是 Polymer 所必需的，如果目标浏览器不支持这些 API，则需要这个 polyfill。

### 注意

你可以在这里检查你最喜欢的浏览器是否支持所需的 API：[`caniuse.com/#feat=custom-elementsv1`](http://caniuse.com/#feat=custom-elementsv1)和[`caniuse.com/#feat=imports`](http://caniuse.com/#feat=imports)。

就像 NPM 一样，项目文件中列出的包必须被安装。因此，在项目目录中打开一个控制台并运行以下命令：

```js
> bower install

```

完成这些之后，我们需要安装的最后一样东西是 Polymer 和 Aurelia 之间的桥梁，通过在项目目录中打开一个控制台并运行以下命令来完成：

```js
> npm install aurelia-polymer --save

```

## 配置应用程序

现在一切都安装好了，我们需要配置我们的应用程序，使其可以加载 Polymer 组件。

首先，我们需要将`aurelia-polymer`库添加到供应商捆绑包中：

`aurelia_project/aurelia.json`

```js
//Omitted snippet... 
{ 
  "name": "vendor-bundle.js", 
  "prepend": [ 
    //Omitted snippet... 
  ], 
  "dependencies": [ 
    { 
      "name": "aurelia-polymer", 
      "path": "../node_modules/aurelia-polymer/dist/amd", 
      "main": "index" 
    }, 
    //Omitted snippet... 
  ] 
} 
//Omitted snippet... 

```

当然，由于这个库是一个 Aurelia 插件，我们需要将其加载到我们应用程序的主要`configure`函数中：

`src/main.js`

```js
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .plugin('aurelia-polymer')  
    .plugin('aurelia-animator-css') 
  //Omitted snippet... 
} 

```

如前所述，Polymer 依赖于 HTML Imports。在撰写本文时，基于 CLI 的 Aurelia 应用程序不支持使用 HTML Imports 加载视图。因此，我们将无法在需要它们的模板中加载组件。我们别无选择，只能将它们加载到`index.html`文件中：

`index.html`

```js
<!-- Omitted snippet... --> 
<head> 
  <!-- Omitted snippet... --> 
  <script src="bower_components/webcomponentsjs/ 
               webcomponents-lite.js"></script> 
  <link rel="import" href="bower_components/polymer/polymer.html"> 
  <link rel="import"  
        href="bower_components/google-map/google-map.html"> 
</head> 
<!-- Omitted snippet... --> 

```

在这里，我们首先加载 Web Components API polyfill。如果不需要 polyfill，可以删除这一行。接下来，我们导入 Polymer 和`google-map`组件。

在一个准备生产的应用程序中，分别导入 Polymer 和每个组件是不理想的。强烈建议将组件进行融合，生成一个单一的包，在`index.html`文件中加载： [`github.com/Polymer/vulcanize`](https://github.com/Polymer/vulcanize)。

至此，与 Polymer 的集成已经运行起来。`google-map`元素已经可以使用。

## 显示 Google 地图

让我们先确保一切都能正常工作，通过创建一个自定义元素来显示一个带有单个地址标记的地图：

`src/contacts/elements/address-map.html`

```js
<template> 
  <button class="btn btn-default"  
          click.delegate="isMapVisible = !isMapVisible"> 
    ${isMapVisible ? 'contacts.hideMap' : 'contacts.showMap' & t} 
  </button> 
  <google-map if.bind="isMapVisible"  
              style="display: block; height: 400px;"  
              api-key="your_key"> 
  </google-map> 
</template> 

```

### 注意

`google-map` Polymer 组件在幕后加载了 Google Maps API。为了使其正确加载，你需要一个 Google Maps API 密钥。你可以通过遵循在 [`developers.google.com/maps/documentation/javascript/get-api-key#key`](https://developers.google.com/maps/documentation/javascript/get-api-key#key) 找到的说明来创建一个。

在这里，我们首先添加一个切换`isMapVisible`属性的按钮。接下来，我们添加一个`google-map` Polymer 元素。其`api-key`属性应该设置为你的 Google Maps API 密钥。

至于视图模型，现在几乎为空：

`src/contacts/elements/address-map.js`

```js
export class AddressMapCustomElement {  
  isMapVisible = false; 
} 

```

最后，我们需要将这个`address-map`元素添加到联系人的`details`组件中：

`src/contacts/components/details.html`

```js
<!-- Omitted snippet... --> 
<div class="form-group" repeat.for="address of contact.addresses"> 
  <label class="col-sm-2 control-label"> 
    ${'contacts.types.' + address.type & t} 
  </label> 
  <div class="col-sm-10"> 
    <p class="form-control-static"> 
      ${address.number} ${address.street}</p> 
    <p class="form-control-static"> 
      ${address.postalCode} ${address.city}</p> 
    <p class="form-control-static"> 
      ${address.state} ${address.country}</p> 
    <address-map address.bind="address"></address-map> 
  </div> 
</div> 
<!-- Omitted snippet... --> 

```

在这个阶段，如果你运行应用程序并导航到一个联系人的详情，你应该看到每个地址下都有一个按钮。如果你点击它，应该会弹出一个地图。

## 地址编码

为了在地图上显示地址作为标记，我们需要获取该地址的地理坐标。因此，我们将创建一个名为`Geocoder`的新服务，它将使用基于`OpenStreetMap`数据的搜索服务**Nominatim**（[`www.openstreetmap.org/`](http://www.openstreetmap.org/)），以找到给定地址的纬度和经度：

`src/contacts/services/geocoder.js`

```js
import {HttpClient} from 'aurelia-fetch-client'; 

export class Geocoder { 

  http = new HttpClient().configure(config => { 
    config 
      .useStandardConfiguration() 
      .withBaseUrl('http://nominatim.openstreetmap.org/'); 
  }); 

  search(address) { 
    const query = { 
      format: 'json', 
      street: `${address.number} ${address.street}`, 
      city: address.city, 
      state: address.state, 
      country: address.country, 
      postalcode: address.postalCode, 
      limit: 1, 
    }; 
    return this.http.fetch(`search?${toQueryString(query)}`) 
      .then(response => response.json()) 
      .then(dto => dto.length === 0 ? null : dtoToResult(dto[0])); 
  } 
} 

function toQueryString(query) { 
  return Object.getOwnPropertyNames(query) 
    .map(name => { 
      const key = encodeURIComponent(name); 
      const value = encodeURIComponent(query[name]); 
      return `${key}=${value}`; 
    }) 
    .join('&'); 
} 

function dtoToResult(dto) { 
  return { 
    latitude: parseFloat(dto.lat), 
    longitude: parseFloat(dto.lon) 
  }; 
} 

```

这个类首先创建一个`HttpClient`实例，使用 Nominatim 的 URL 和标准配置。然后暴露一个`search`方法，该方法期望一个`Address`对象作为参数，向 Nominatim 端点发送请求并返回结果`Promise`。这个`Promise`如果找不到地址就解决为`null`，或者包含匹配位置的`latitude`和`longitude`的对象。

## 显示标记

既然我们现在可以进行地址编码，那就让我们更新一下`address-map`元素，显示一个标记：

`src/contacts/elements/address-map.js`

```js
import {inject, bindable} from 'aurelia-framework'; 
import {Geocoder} from '../services/geocoder'; 

@inject(Geocoder) 
export class AddressMapCustomElement { 

  @bindable address; 

  isAttached = false; 
  isMapVisible = false; 
  isGeocoded = false; 
  latitude = null; 
  longitude = null; 

  constructor(geocoder) { 
    this.geocoder = geocoder; 
  } 

  addressChanged() { 
    if (this.isAttached) { 
      this.geocode(); 
    } 
  } 

  attached() { 
    this.isAttached = true; 
    this.geocode(); 
  } 

  detached() { 
    this.isAttached = false; 
  } 

  geocode() { 
    if (this.address) { 
      this.geocoder.search(this.address).then(position => { 
        if (position) { 
          this.latitude = position.latitude; 
          this.longitude = position.longitude; 
          this.isGeocoded = true; 
        } else { 
          this.isMapVisible = false; 
          this.isGeocoded = false;  
          this.latitude = null; 
          this.longitude = null; 
        } 
      }); 
    } 
  } 
} 

```

在这里，我们首先将一个`Geocoder`实例注入到视图模型中。我们还添加了一个可绑定的`address`属性。当元素附加到 DOM 时，我们进行地理编码，如果找到其坐标，我们设置`latitude`和`longitude`属性的值。我们还设置`isGeocoded`为`true`。这个标志最初设置为`false`，如果地址无法定位，我们将用来禁用切换按钮。如果找不到地址，我们隐藏地图，禁用切换按钮，并将`latitude`和`longitude`重置为`null`。

在元素附加到 DOM 之后，每次`address`发生变化时，我们还进行地理编码，以保持`latitude`和`longitude`属性的最新。

至于模板，我们不需要做太多更改：

`src/contacts/elements/address-map.html`

```js
<template> 
  <button class="btn btn-default"  
          click.delegate="isMapVisible = !isMapVisible"  
          disabled.bind="!isGeocoded"> 
    ${isMapVisible ? 'contacts.hideMap' : 'contacts.showMap' & t} 
  </button> 
  <google-map if.bind="isMapVisible"  
              latitude.bind="latitude"  
              longitude.bind="longitude"  
              zoom="15"  
              style="display: block; height: 400px;" 
             api-key="your_key"> 
    <google-map-marker latitude.bind="latitude"  
                       longitude.bind="longitude"  
                       open="true"> 
      ${address.number} ${address.street}  
      ${address.postalCode} ${address.city}  
      ${address.state} ${address.country} 
    </google-map-marker> 
  </google-map> 
</template> 

```

在这里，我们首先在`isGeocoded`为`false`时禁用切换按钮。接下来，我们将`google-map`元素的`latitude`和`longitude`进行绑定，并将它的`zoom`设置为`15`，以便它显示在地址位置的中心。

最后，我们在`google-map`元素内部添加一个`google-map-marker`元素。我们还绑定这个标记的`latitude`和`longitude`，并将其`open`属性设置为`true`，以便在渲染时打开其信息窗口。在标记内部，我们显示完整的地址作为文本，它将在信息窗口内渲染。

你可能会好奇这个`google-map-marker`元素是从哪里来的。实际上，HTML Imports 机制允许从单个文件中加载多个组件。当我们 在`index.html`中导入`bower_components/google-map/google-map.html`文件时，许多组件被注册到 Polymer 中，其中就包括地图和标记。

如果你在这个时候运行应用程序，导航到联系人的详细信息，然后点击地址的**查看地图**按钮，应该会出现一个带有标记在正确位置的地图，并且一个信息窗口会显示完整的地址。

# 总结

将一个 UI 库集成到 Aurelia 应用程序中几乎总是遵循相同的流程：你围绕它创建一个自定义元素或属性。利用 Aurelia 的双向数据绑定，大多数时候并不太复杂。

这对于遵循良好实践和社区标准库来说尤其如此，比如支持常见模块加载器、暴露数据变更事件，并在其公共 API 中有一个析构器。那些较老，或者不遵循这些标准的库，集成就更痛苦。Aurelia 在这方面尽其所能简化。
