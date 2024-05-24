# JavaScript 示例（二）

> 原文：[`zh.annas-archive.org/md5/7B2D5876FA8197B4A2F4F8B32190F638`](https://zh.annas-archive.org/md5/7B2D5876FA8197B4A2F4F8B32190F638)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：活动注册应用程序

希望您在创建表情并与朋友分享时玩得很开心！您在上一个项目中成功使用 HTML5 画布构建了一个表情创作器。您还使用了 flexbox 来设计页面布局，并学习了有关 ES6 模块的一些知识。

上一章最重要的部分是我们使用 Webpack 创建的开发环境。它让我们可以使用`HotModuleReplacement`更快地开发应用程序，创建具有单个文件资产和减小代码大小的优化生产构建，并且还可以隐藏原始源代码，同时我们可以使用源映射来调试原始代码。

现在我们有了模块支持，我们可以使用它来创建模块化函数，这将允许我们编写可重用的代码，可以在项目的不同部分之间使用，也可以在不同的项目中使用。在本章中，您将构建一个活动注册应用程序，同时学习以下概念：

+   编写 ES6 模块

+   使用 JavaScript 进行表单验证

+   使用动态数据（从服务器加载的数据）

+   使用 fetch 进行 AJAX 请求

+   使用 Promises 处理异步函数

+   使用 Chart.js 创建图表

# 活动 - JS 聚会

以下是我们项目的情景：

您正在本地组织一个 JavaScript 聚会。您邀请了来自学校、大学和办公室的对 JavaScript 感兴趣的人。您需要为与会者创建一个注册活动的网站。该网站应具有以下功能：

+   帮助用户注册活动的表单

+   显示对活动感兴趣的用户数量的统计数据页面

+   关于页面，包括活动详情和活动位置的 Google 地图嵌入

此外，大多数人将使用手机注册活动。因此，应用程序应完全响应。

这是应用程序在手机上的样子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00020.jpeg)

# 初始项目设置

要开始项目，请在 VSCode 中打开第三章的起始文件。创建一个`.env`文件，并使用`.env.example`文件中的值。为每个环境变量分配以下值：

+   `NODE_ENV=dev`：在生成构建时应设置为`production`。

+   `SERVER_URL=http://localhost:3000`：我们很快将在此 URL 上运行服务器。

+   `GMAP_KEY`：我们将在此项目中使用 Google Maps API。您需要生成自己的唯一 API 密钥以使用 Google Maps。请参阅：[`developers.google.com/maps/documentation/javascript/get-api-key`](https://developers.google.com/maps/documentation/javascript/get-api-key) 生成您的 API 密钥，并将密钥添加到此环境变量中。

在第二章中，*构建表情创作器*，我提到当模块与 Webpack 捆绑在一起时，您无法在 HTML 中访问 JavaScript 变量。在第一章中，*构建待办事项列表*，我们使用 HTML 属性调用 JavaScript 函数。这看起来可能很有用，但它也会向用户（我指的是访问您页面的其他开发人员）公开我们的对象结构。用户可以通过检查 Chrome DevTools 来清楚地了解`ToDoClass`类的结构。在构建大型应用程序时应该防止这种情况发生。因此，Webpack 不允许变量存在于全局范围内。

一些插件需要全局范围内存在变量或对象（比如我们将要使用的 Google Maps API）。为此，Webpack 提供了一个选项，可以将一些选定的对象作为库暴露到全局范围内（在 HTML 内）。查看起始文件中的`webpack.config.js`文件。在`output`部分，我已经添加了`library: 'bundle'`，这意味着如果我们向任何函数、变量或对象添加`export`关键字，它们将在全局范围内的`bundle`对象中可访问。我们将看到如何在向我们的应用程序添加 Google Maps 时使用它。

现在我们已经准备好环境变量，打开项目根文件夹中的终端并运行`npm install`来安装所有依赖项。一旦依赖项安装完成，在终端中输入`npm run watch`来启动 Webpack 开发服务器。您现在可以在控制台中由 Webpack 打印的本地主机 URL（`http://localhost:8080/`）上查看页面。查看所有页面。

# 向页面添加样式

目前，页面是响应式的，因为它是使用 Bootstrap 构建的。然而，我们仍然需要对表单进行一些样式更改。在桌面屏幕上，它目前非常大。此外，我们需要将标题对齐到页面中央。让我们为`index.html`页面添加样式。

将表单及其标题居中对齐到页面中央，在`styles.css`文件（`src/css/styles.css`）中添加以下代码（确保 Webpack 开发服务器正在运行）：

```js
.form-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}
```

由于 Webpack 中启用了`HotModuleReplacement`，样式将立即反映在页面上（不再重新加载！）。现在，给标题添加一些边距，并为表单设置最小宽度：

```js
.title {
  margin: 20px;
}
.form-group {
  min-width: 500px;
}
```

现在表单的最小宽度将为`500px`。然而，我们面临另一个问题！由于表单将始终为`500px`，在移动设备上（移动用户是我们的主要受众）将超出屏幕。我们需要使用媒体查询来解决这个问题。媒体查询允许我们根据页面所在的媒介类型添加 CSS。在我们的情况下，我们需要在移动设备上更改`min-width`。要查询移动设备，请在先前的样式下方添加以下样式：

```js
@media only screen and (max-width: 736px) {
  .form-group {
    min-width: 90vw;
  }
}
```

这将检查设备宽度是否小于`736px`（通常，移动设备属于此类别），然后添加`90vw`的`min-width`。`vw`代表视口宽度。`90vw`表示视口宽度的大小的 90%（这里，视口是屏幕）。

有关使用媒体查询的更多信息，请访问 w3schools 页面：[`www.w3schools.com/css/css_rwd_mediaqueries.asp`](https://www.w3schools.com/css/css_rwd_mediaqueries.asp)。

我在`index.html`和`status.html`页面上使用了加载指示器图像。要指定图像的大小而不破坏其原始宽高比，使用`max-width`和`max-height`如下：

```js
.loading-indicator {
  max-height: 50px;
  max-width: 50px;
}
```

查看状态页面。加载指示器的大小将被减小。我们已经为我们的应用程序添加了必要的样式。现在，是时候使用 JavaScript 使其工作了。

# 使用 JavaScript 验证和提交表单

HTML 表单是 Web 应用程序中最重要的部分，用户输入会被记录下来。在我们的 JS Meetup 应用程序中，我们使用 Bootstrap 构建了一个漂亮的表单。让我们使用`index.html`文件来探索表单包含的内容。表单包含四个必填字段：

+   姓名

+   电子邮件地址

+   电话号码

+   年龄

它还包含三个可选字段（其中两个的值已经预先选择）：

+   用户的职业

+   他在 JavaScript 方面的经验水平

+   对他对这次活动期望学到的内容进行评论

由于职业和经验水平选项已预先选择了默认值，因此它们不会被标记为用户必填。但是，在验证期间，我们需要将它们视为必填字段。只有评论字段是可选的。

这是我们的表单应该如何工作的：

+   用户填写所有表单细节并点击提交

+   表单详细信息将被验证，如果缺少任何必填字段，它将用红色边框突出显示这些字段

+   如果表单值有效，它将继续将表单提交到服务器

+   提交表单后，用户将收到通知表单已成功提交，并且表单条目将被清除

JavaScript 最初用作在 HTML 中进行表单验证的语言。随着时间的推移，它已经发展成为一个完整的 Web 应用程序开发语言。使用 JavaScript 构建的 Web 应用程序会向服务器发出许多请求，以向用户提供动态数据。这些网络请求始终是异步的，需要正确处理。

# HTML 表单

在我们实现表单验证逻辑之前，让我们先了解表单的正常工作方式。单击当前表单中的提交。您应该会看到一个空白页面，并显示消息“无法 POST /register”。这是 Webpack 开发服务器的消息，表示没有为`/register`配置`POST`方法的路由。这是因为在`index.html`中，表单是使用以下属性创建的：

```js
<form action="/register" method="post" id="registrationForm">
```

这意味着当单击提交按钮发送数据到`/register`页面时，使用`POST`方法。在进行网络请求时，`GET`和`POST`是两种常用的 HTTP 方法或动词。`GET`方法不能有请求正文，因此所有数据都通过 URL 作为查询参数传输。但是，`POST`方法可以有请求正文，其中数据可以作为表单数据或 JSON 对象发送。

有不同的 HTTP 方法用于与服务器通信。查看以下 REST API 教程页面，了解有关 HTTP 方法的更多信息：[`www.restapitutorial.com/lessons/httpmethods.html`](http://www.restapitutorial.com/lessons/httpmethods.html)。

当前，表单以`POST`方法使用表单数据发送数据。在您的`index.html`文件中，将表单方法属性更改为`get`并重新加载页面（Webpack 开发服务器不会自动重新加载 HTML 文件的更改）。现在，单击提交。您应该看到类似的空白页面，但是现在表单详细信息正在发送到 URL 本身。现在 URL 将如下所示：

```js
http://localhost:8080/register?username=&email=&phone=&age=&profession=school&experience=1&comment=
```

所有字段都为空，除了职业和经验，因为它们是预先选择的。表单值添加在路由`/register`的末尾，后跟一个`?`符号，指定下一个文本是查询参数，表单值使用`&`符号分隔。由于`GET`请求会将数据发送到 URL 本身，因此不适合发送机密数据，例如登录详细信息或我们将在此表单中发送的用户详细信息。因此，选择`POST`方法进行表单提交。在您的`index.html`文件中将方法更改为 post。

让我们看看如何检查使用`POST`请求发送的数据。打开 Chrome DevTools 并选择网络选项卡。现在在表单中输入一些详细信息，然后单击提交。您应该在网络请求列表中看到一个名为`register`的新条目。如果单击它，它将打开一个新面板，其中包含请求详细信息。请求数据将出现在表单数据部分的标头选项卡中。请参考以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00021.jpeg)

Chrome DevTools 具有许多用于处理网络请求的工具。我们只使用它来检查我们发送的数据。但是您还可以做更多的事情。根据上图，您可以在标头选项卡的表单数据部分中看到我在表单中输入的表单值。

访问以下 Google 开发者页面：[`developers.google.com/web/tools/chrome-devtools/`](https://developers.google.com/web/tools/chrome-devtools/) 以了解更多关于使用 Chrome DevTools 的信息。

现在你对提交表单的工作原理有了一个很好的了解。我们在`/register`路由中没有创建任何页面，并且通过将表单重定向到单独的页面进行提交不再是一个好的用户体验（我们处于**单页应用程序**（**SPA**）的时代）。考虑到这一点，我创建了一个小的 Node.js 服务器应用程序，可以接收表单请求。我们将禁用默认的表单提交操作，并将使用 JavaScript 作为 AJAX 请求提交表单。

# 在 JavaScript 中读取表单数据

是时候编码了！使用`npm run watch`命令保持 Webpack 开发服务器运行（`NODE_ENV`变量应为`dev`）。在 VSCode 中打开项目文件夹，并从`src/js/`目录中打开`home.js`文件。我已经在`index.html`文件中添加了对`dist/home.js`的引用。我还将在`home.js`中添加代码来导入`general.js`文件。现在，在导入语句下面添加以下代码：

```js
class Home {
  constructor() {

  }

}

window.addEventListener("load", () => {
 new Home();
});
```

这将创建一个新的`Home`类，并在页面加载完成时创建一个新的实例。我们不需要将实例对象分配给任何变量，因为我们不会像在 ToDo 列表应用程序中那样在 HTML 文件中使用它。一切都将从 JavaScript 本身处理。

我们的第一步是创建对表单中所有输入字段和表单本身的引用。这包括表单本身和当前在页面中使用`.hidden` Bootstrap 类隐藏的加载指示器。将以下代码添加到类的构造函数中：

```js
 this.$form = document.querySelector('#registrationForm');
 this.$username = document.querySelector('#username');
 this.$email = document.querySelector('#email');
 this.$phone = document.querySelector('#phone');
 this.$age = document.querySelector('#age');
 this.$profession = document.querySelector('#profession');
 this.$experience = document.querySelector('#experience');
 this.$comment = document.querySelector('#comment');
 this.$submit = document.querySelector('#submit');
 this.$loadingIndicator = document.querySelector('#loadingIndicator');
```

就像我在构建 Meme Creator 时提到的，最好将对 DOM 元素的引用存储在以`$`符号为前缀的变量中。现在，我们可以轻松地从其他变量中识别具有对 DOM 元素的引用的变量。这纯粹是为了开发效率，不是你需要遵循的严格规则。在前面的代码中，对于体验单选按钮，只存储了第一个单选按钮的引用。这是为了重置单选按钮；要读取所选单选按钮的值，需要使用不同的方法。

现在我们可以在`Home`类中访问所有的 DOM 元素。触发整个表单验证过程的事件是表单提交时发生的。表单提交事件发生在`<form>`元素内部带有属性`type="submit"`的 DOM 元素被点击时。在我们的情况下，`<button>`元素包含这个属性，并且被引用为`$submit`变量。尽管`$submit`触发了提交事件，但事件属于整个表单，也就是`$form`变量。因此，我们需要在我们的类中为`this.$form`添加一个事件监听器。

我们只会有一个事件监听器。因此，在声明前面的变量之后，只需将以下代码添加到构造函数中：

```js
this.$form.addEventListener('submit', event => {
  this.onFormSubmit(event);
});
```

这将为表单附加一个事件监听器，并在表单提交时调用类的`onFormSubmit()`方法，以表单提交事件作为其参数。因此，让我们在`Home`类中创建`onFormSubmit()`方法：

```js
onFormSubmit(event) {
  event.preventDefault();
}
```

`event.preventDefault()`将阻止默认事件动作发生。在我们的情况下，它将阻止表单的提交。在 Chrome 中打开页面（`http://localhost:8080/`）并尝试点击提交。如果没有任何动作发生，那太好了！我们的 JavaScript 代码正在阻止表单提交。

我们可以使用这个函数来启动表单验证。表单验证的第一步是读取表单中所有输入元素的值。在`Home`类中创建一个新的方法`getFormValues()`，它将以 JSON 对象的形式返回表单字段的值：

```js
getFormValues() {
  return {
    username: this.$username.value,
    email: this.$email.value,
    phone: this.$phone.value,
    age: this.$age.value,
    profession: this.$profession.value,
    experience: parseInt(document.querySelector('input[name="experience"]:checked').value),
    comment: this.$comment.value,
  };
}
```

看到我如何使用`document.querySelector()`来读取选中的单选按钮的值了吗？该函数本身就是不言自明的。我添加了`parseInt()`，因为该值将作为字符串返回，并且需要转换为 Int 以进行验证。在`onFormSubmit()`方法中创建一个变量来存储表单中所有字段的值。您的`onFormSubmit()`方法现在将如下所示：

```js
onFormSubmit(event) {
  event.preventDefault();
  const formValues = this.getFormValues();
}
```

尝试使用`console.log(formValues)`在 Chrome DevTools 控制台中打印`formValues`变量。您应该看到一个 JSON 对象中的所有字段及其相应的值。现在我们有了所需的值，下一步是验证数据。

在我们的 JS Meetup 应用程序中，我们只有一个表单。但在更大的应用程序中，您可能会在应用程序的不同部分中有多个表单执行相同的操作。但是，由于设计目的，表单将具有不同的 HTML 类和 ID，但表单值将保持不变。在这种情况下，验证逻辑可以在整个应用程序中重复使用。这是构建您的第一个可重用 JavaScript 模块的绝佳机会。

# 表单验证模块

通过使用 Webpack，我们现在有能力创建单独的模块并在 JavaScript 中导入它们。但是，我们需要某种方法来组织我们创建的模块。随着应用程序的规模增长，您可能会有数十甚至数百个模块。以便能够轻松识别它们的方式来组织它们将极大地帮助您的团队，因为他们将能够在需要时轻松找到模块，而不是重新创建具有相同功能的模块。

在我们的应用程序中，让我们在`src/js/`目录中创建一个名为`services`的新文件夹。该目录将包含所有可重用的模块。现在，在`services`目录中，创建另一个名为`formValidation`的目录，在其中我们将创建`validateRegistrationForm.js`文件。您的项目`src/js/`目录现在将如下所示：

```js
.
├── about.js
├── general.js
├── home.js
├── services
│   └── formValidation
│       └── validateRegistrationForm.js
└── status.js
```

现在，想象自己是一个第一次看到这段代码的不同开发人员。在`js`目录中，有另一个名为`services`的目录。在其中，`formValidation`作为一个服务可用。您现在知道有一个用于表单验证的服务。如果您查看此目录，它将具有`validateRegistrationForm.js`文件，该文件仅凭其文件名就告诉您此模块的目的。

如果您想为登录表单创建一个验证模块（只是一个想象的场景），只需在`formValidation`目录中创建另一个名为`validateLoginForm.js`的文件。这样，您的代码将易于维护，并通过最大程度地重用所有模块来扩展。

不要担心文件名太长！可维护的代码更重要，但如果文件名太长，它会更容易理解该文件的目的。但是，如果您在团队中工作，请遵守团队使用的 lint 工具的规则。

是时候构建模块了！在您刚刚创建的`validateRegistrationForm.js`文件中，添加以下代码：

```js
export default function validateRegistrationForm(formValues) {
}
```

使用模块文件和其默认导出项相同的名称将使导入语句看起来更容易理解。当您将此模块导入到您的`home.js`文件中时，您将看到这一点。前面的函数将接受`formValues`（我们从上一节中的表单中读取的）JSON 对象作为参数。

在编写此函数之前，我们需要为每个输入字段设置验证逻辑为单独的函数。当输入满足验证条件时，这些函数将返回 true。让我们从验证用户名开始。在`validateRegistrationForm()`下面，创建一个名为`validateUserName()`的新函数，如下所示：

```js
function validateUserName(name) {
  return name.length > 3 ? true: false;
}
```

我们使用此函数来检查用户名是否至少为`3`个字符长。我们使用条件运算符，如果长度大于`3`则返回`true`，如果长度小于`3`则返回`false`。

我们之前在 ToDo 列表应用程序中使用了条件运算符`()?:`。如果您仍然对这个运算符有困难，可以访问以下 MDN 页面进行了解：[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Conditional_Operator`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Operators/Conditional_Operator)。

我们可以使这个函数更加简洁：

```js
function validateUserName(name) {
  return name.length > 3;
}
```

这样，JavaScript 将自动评估长度是否大于三，并根据结果分配 true 或 false。现在，要验证电子邮件地址，我们需要使用正则表达式。我们曾经使用正则表达式来更改 Meme Creator 应用程序中图像的 MIME 类型。这一次，我们将研究正则表达式的工作原理。

# 在 JavaScript 中使用正则表达式

正则表达式（RegExp）基本上是一个模式的定义（例如一系列字符、数字等），可以在其他文本中进行搜索。例如，假设您需要找到段落中以字母*a*开头的所有单词。然后，在 JavaScript 中，您将模式定义为：

```js
const pattern = /^a+/
```

正则表达式总是在`/ /`内定义。在前面的代码片段中，我们有以下内容：

+   `^`表示在开头

+   `+`表示至少有一个

这个正则表达式将匹配以字母*a*开头的字符串。您可以在以下网址测试这些语句：[`jsfiddle.net/`](https://jsfiddle.net/)。要使用这个正则表达式验证一个字符串，请执行以下操作：

```js
pattern.test('alpha') // this will return true
pattern.test('beta') // this will return false
```

要验证电子邮件地址，请使用以下函数，其中包含一个用于验证电子邮件地址的正则表达式：

```js
function validateEmail(email) {
  const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\ [\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return emailRegex.test(email);
}
```

不要被正则表达式所压倒，它是互联网上常见的东西。每当您需要常见格式的正则表达式，比如电子邮件地址或电话号码，您都可以在互联网上找到它们。要验证手机号码，请执行以下操作：

```js
function validatePhone(phone) {
  const phoneRegex = /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/;
  return phoneRegex.test(phone);
}
```

这将验证电话号码是否符合`XXX-XXX-XXXX`的格式（此格式在表单的占位符中给出）。

如果您的要求非常具体，您将不得不编写自己的正则表达式。那时，请参考以下页面：[`developer.mozilla.org/en/docs/Web/JavaScript/Guide/Regular_Expressions`](https://developer.mozilla.org/en/docs/Web/JavaScript/Guide/Regular_Expressions)。

电子邮件地址在表单中默认验证，因为电子邮件输入字段的类型属性设置为电子邮件。但是，有必要在 JavaScript 中验证它，因为并非所有浏览器都可能支持此属性，而且 HTML 可以很容易地从 Chrome DevTools 进行编辑。其他字段也是一样。

要验证年龄，假设用户应该在 10-25 岁的年龄组中：

```js
function validateAge(age) {
  return age >= 10 && age <= 25;
}
```

要验证职业，职业的接受值为`school`、`college`、`trainee`和`employee`。它们是`index.html`文件中职业选择字段的`<option>`元素的值。要验证`profession`，请执行以下操作：

```js
function validateProfession(profession) {
  const acceptedValues = ['school','college','trainee','employee'];
  return acceptedValues.indexOf(profession) > -1;
}
```

JavaScript 数组有一个名为`indexOf()`的方法。它接受一个数组元素作为参数，并返回该元素在数组中的索引。但是，如果数组中不存在该元素，则返回`-1`。我们可以使用这个函数来检查职业的值是否是接受的值之一，方法是找到它在数组中的索引，并检查索引是否大于`-1`。

最后，要验证经验，经验单选按钮的值为 1、2 和 3。因此，经验应该是 0-4 之间的数字：

```js
function validateExperience(experience) {
  return experience > 0 && experience < 4;
}
```

由于评论字段是可选的，我们不需要为该字段编写验证逻辑。现在，在我们最初创建的`validateRegistrationForm()`函数中，添加以下代码：

```js
export default function validateRegistrationForm(formValues) {

  const result = {
    username: validateUserName(formValues.username),
    email: validateEmail(formValues.email),
    phone: validatePhone(formValues.phone),
    age: validateAge(formValues.age),
    profession: validateProfession(formValues.profession),
    experience: validateExperience(formValues.experience),
  };

}
```

现在，结果对象包含每个表单输入的验证状态（`true`/`false`）。检查整个表单是否有效。只有当结果对象的所有属性都为`true`时，表单才有效。要检查结果对象的所有属性是否都为`true`，我们需要使用`for`/`in`循环。

`for`/`in`循环遍历对象的属性。由于`result`对象的所有属性都需要为`true`，因此创建一个初始值为`true`的变量`isValid`。现在，遍历`result`对象的所有属性，并将值与`isValid`变量进行逻辑与（`&&`）操作：

```js
let field, isValid = true;
for(field in result) {
  isValid = isValid && result[field];
}
```

通常，您可以使用点符号（`.`）访问对象的属性。但是，由于我们使用了`for`/`in`循环，属性名称存储在变量`field`中。在这种情况下，如果`field`包含值`age`，我们需要使用方括号表示法`result[field]`来访问属性；这相当于点表示法中的`result.age`。

只有当结果对象的所有属性都为`true`时，`isValid`变量才为`true`。这样，我们既有表单的验证状态，又有各个字段的状态。`validateRegistrationForm()`函数将作为另一个对象的属性返回`isValid`变量和`result`对象：

```js
export default function validateRegistrationForm(formValues) {
  ...
  ...
  return { isValid, result };
}
```

我们在这里使用了 ES6 的对象字面量属性值简写特性。我们的表单验证模块已经准备好了！我们可以将这个模块导入到我们的`home.js`文件中，并在事件注册应用程序中使用它。

在你的`home.js`文件中，在`Home`类之前，添加以下行：

```js
import validateRegistrationForm from './services/formValidation/validateRegistrationForm';
```

然后，在`Home`类的`onFormSubmit()`方法中，添加以下代码：

```js
onFormSubmit(event) {
  event.preventDefault();

  const formValues = this.getFormValues();
  const formStatus = validateRegistrationForm(formValues);

  if(formStatus.isValid) {
    this.clearErrors();
    this.submitForm(formValues);
  } else {
    this.clearErrors();
    this.highlightErrors(formStatus.result);
  }
}
```

上述代码执行以下操作：

+   它调用我们之前创建的`validateRegistrationForm()`模块，并将`formValues`作为其参数，并将返回的值存储在`formStatus`对象中。

+   首先，它检查整个表单是否有效，使用`formStatus.isValid`的值。

+   如果为`true`，则调用`clearErrors()`方法清除 UI（我们的 HTML 表单）中的所有错误高亮，并调用另一个方法`submitForm()`提交表单。

+   如果为`false`（表单无效），则调用`clearErrors()`方法清除表单，然后使用`formStatus.result`调用`highlightErrors()`方法，该方法作为参数包含各个字段的验证详细信息，以突出显示具有错误的字段。

我们需要在`Home`类中创建在上述代码中调用的方法，因为它们是`Home`类的方法。`clearErrors()`和`highlightErrors()`方法的工作很简单。`clearErrors`只是从输入字段的父`<div>`中移除`.has-error`类。而`highlightError`如果输入字段未通过验证（字段的结果为`false`），则将`.has-error`类添加到父`<div>`中。

`clearErrors()`方法的代码如下：

```js
clearErrors() {
  this.$username.parentElement.classList.remove('has-error');
  this.$phone.parentElement.classList.remove('has-error');
  this.$email.parentElement.classList.remove('has-error');
  this.$age.parentElement.classList.remove('has-error');
  this.$profession.parentElement.classList.remove('has-error');
  this.$experience.parentElement.classList.remove('has-error');
}
```

`highlightErrors()`方法的代码如下：

```js
highlightErrors(result) {
  if(!result.username) {
    this.$username.parentElement.classList.add('has-error');
  }
  if(!result.phone) {
    this.$phone.parentElement.classList.add('has-error');
  }
  if(!result.email) {
    this.$email.parentElement.classList.add('has-error');
  }
  if(!result.age) {
    this.$age.parentElement.classList.add('has-error');
  }
  if(!result.profession) {
    this.$profession.parentElement.classList.add('has-error');
  }
  if(!result.experience) {
    this.$experience.parentElement.classList.add('has-error');
  }
}
```

目前，将`submitForm()`方法留空：

```js
submitForm(formValues) {
}
```

在浏览器中打开表单（希望您保持 Webpack 开发服务器运行）。尝试在输入字段中输入一些值，然后单击提交。如果输入了有效的输入值，它不应执行任何操作。如果输入了无效的输入条目（根据我们的验证逻辑），则输入字段将以红色边框突出显示，因为我们向字段的父元素添加了`.has-error` Bootstrap 类。如果您更正了具有有效值的字段，然后再次单击提交，错误应该消失，因为我们使用了`clearErrors()`方法来清除所有旧的错误高亮。

# 使用 AJAX 提交表单

现在我们进入表单部分的第二部分，提交表单。我们已经禁用了表单的默认提交行为，现在需要实现一个用于提交逻辑的 AJAX 表单。

AJAX 是**异步 JavaScript 和 XML**（**AJAX**）的缩写。它不是一个编程工具，而是一个概念，通过它你可以发出网络请求，从服务器获取数据，并更新网站的某些部分，而无需重新加载整个页面。

异步 JavaScript 和 XML 这个名字可能听起来有点困惑，但最初 XML 被广泛用于与服务器交换数据。我们也可以使用 JSON/普通文本与服务器交换数据。

为了将表单提交到服务器，我创建了一个小的 Node.js 服务器（使用 express 框架构建），假装保存你的表单详情并返回一个成功消息。服务器在代码文件的`Chapter03`文件夹中。要启动服务器，只需在服务器目录中运行`npm install`，然后运行`npm start`命令。这将在`http://localhost:3000/`URL 上启动服务器。如果你在浏览器中打开这个 URL，你会看到一个空白页面，上面显示着消息 Cannot GET /;这意味着服务器正常运行。

服务器有两个 API 端点，我们需要与其中一个通信以发送用户的详情。这就是注册 API 端点的工作方式：

```js
Route: /registration,
Method: POST,
Body: the form data in JSON format
{
  "username":"Test User",
  "email":"mail@test.com",
  "phone":"123-456-7890",
  "age":"16",
  "profession":"school",
  "experience":"1",
  "comment":"Some comment from user"
} If registration is success:
status code: 200
response: { "message": "Test User is Registered Successfully" }
```

在真实的 JavaScript 应用中，你将不得不处理很多像这样的网络请求。大部分用户操作都会触发需要服务器处理的 API 调用。在我们的场景中，我们需要调用前面的 API 来注册用户。

让我们来规划一下 API 调用应该如何工作：

+   正如其名称所示，这个事件将是异步的。我们需要使用 ES6 的一个新概念，叫做 Promises，来处理这个 API 调用。

+   在下一节中，我们将有另一个 API 调用。最好将 API 调用创建为类似模块验证模块的形式。

+   我们必须验证服务器是否成功注册了用户。

+   由于整个 API 调用会花费一些时间，我们应该在过程中向用户显示一个加载指示器。

+   最后，如果注册成功，我们应该立即通知用户并清空表单。

# 在 JavaScript 中进行网络请求

JavaScript 有`XMLHttpRequest`用于进行 AJAX 网络请求。ES6 引入了一个叫做 fetch 的新规范，它通过 Promises 支持使得处理网络请求更加现代和高效。除了这两种方法，jQuery 还有`$.ajax()`方法，广泛用于进行网络请求。`Axios.js`是另一个广泛用于进行网络请求的`npm`包。

我们将在我们的应用中使用 fetch 进行网络请求。

Fetch 在 Internet Explorer 中不起作用，需要使用 polyfills。查看：[`caniuse.com/`](https://caniuse.com/)来了解任何你想使用的新的`HTML/CSS/Javascript`组件的浏览器兼容性。

# 什么是 Promise？

到现在为止，你可能会想知道我所说的 Promise 是什么？嗯，Promise，顾名思义，是 JavaScript 做出的一个承诺，即异步函数将在某个时刻完成执行。

在上一章中，我们遇到了一个异步事件：使用`FileReader`读取文件内容。这就是`FileReader`的工作方式：

+   它开始读取文件。由于读取是一个异步事件，其他 JavaScript 代码在读取仍在进行时会继续执行。

你可能会想，*如果我需要在事件完成后执行一些代码怎么办？*这就是`FileReader`处理的方式：

+   一旦读取完成，`FileReader`会触发一个`load`事件。

+   它还有一个`onload()`方法来监听`load`事件，当`load`事件被触发时，`onload()`方法将开始执行。

+   因此，我们需要将我们需要的代码放在`onload()`方法中，它只会在`FileReader`完成读取文件内容后执行。

这可能看起来是处理异步事件的更简单方式，但想象一下如果有多个需要依次发生的异步事件！你将不得不触发多少事件，需要跟踪多少事件监听器？这将导致非常难以理解的代码。此外，JavaScript 中的事件监听器是昂贵的资源（它们消耗大量内存），必须尽量减少。

回调函数经常用于处理异步事件。但是，如果有很多异步函数依次发生，您的代码将看起来像这样：

```js
asyncOne('one', () => {
  ...
  asyncTwo('two', () => {
    ...
    asyncThree('three', () => {
      ...
      asyncFour('four', () => {
      });
    });
  });
});
```

在编写了很多回调之后，您的闭合括号将被排列成金字塔形。这被称为回调地狱。回调地狱很混乱，构建应用程序时应该避免。因此，回调在这里没有用处。

进入 Promises，一种处理异步事件的新方法。这是 JavaScript `Promise`的工作方式：

```js
new Promise((resolve, reject) => {
  // Some asynchronous logic
  resolve(5);
});
```

`Promise`构造函数创建一个具有两个参数的函数，resolve 和 reject，它们都是函数。然后，`Promise`只有在调用 resolve 或 reject 时才会返回值。当异步代码成功执行时，调用 resolve，当发生错误时调用 reject。在这里，`Promise`在异步逻辑执行时返回一个值`5`。

假设您有一个名为`theAsyncCode()`的函数，它执行一些异步操作。您还有另一个函数`onlyAfterAsync()`，它需要严格在`theAsyncCode()`之后运行，并使用`theAsyncCode()`返回的值。

以下是如何使用 Promises 处理这两个函数：

```js
function theAsyncCode() {
  return new Promise((resolve, reject) => {
    console.log('The Async Code executed!');
    resolve(5);
  });
}
```

首先，`theAsyncCode()`应该返回一个`Promise`而不是一个值。您的异步代码应该写在那个`Promise`里。然后，您编写`onlyAfterAsync()`函数：

```js
function onlyAfterAsync(result) {
  console.log('Now onlyAfterAsync is executing...');
  console.log(`Final result of execution - ${result}`);
}
```

要依次执行前面的函数，我们需要使用`Promise.then().catch()`语句将它们链接起来。在这里，`Promise`由`theAsyncCode()`函数返回。因此，代码应该是：

```js
theAsyncCode()
.then(result => onlyAfterAsync(result))
.catch(error => console.error(error))
```

当`theAsyncCode()`执行`resolve(5)`时，`then`方法会自动以解析值作为其参数调用。现在我们可以在`then`方法中执行`onlyAfterAsync()`方法。如果`theAsyncCode()`执行的是`reject('an error')`而不是`resolve(5)`，它将触发`catch`方法而不是`then`。

如果您有另一个函数`theAsyncCode2()`，它使用`theAsyncCode()`返回的数据，那么它应该在`onlyAfterAsync()`函数之前执行：

```js
function theAsyncCode2(data) {
  return new Promise((resolve, reject) => {
    console.log('The Async Code 2 executed');
    resolve(data);
  });
}
```

您只需要更新您的`.then().catch()`链，如下所示：

```js
theAsyncCode()
.then(data => theAsyncCode2(data))
.then(result => onlyAfterAsync(result))
.catch(error => console.error(error));
```

这样，所有三个函数将依次执行。如果`theAsyncCode()`或`theAsyncCode2()`中的任何一个返回`reject()`，那么将调用`catch`语句。

如果我们只需要使用链中前一个函数的解析值作为参数调用函数，我们可以进一步简化链：

```js
theAsyncCode()
.then(theAsyncCode2)
.then(onlyAfterAsync)
.catch(console.error);
```

这将得到相同的结果。我在[`jsfiddle.net/jjq60Ly6/4/`](https://jsfiddle.net/jjq60Ly6/4/)上设置了一个小的 JS fiddle，您可以在那里体验 Promises 的工作。访问 JS fiddle，打开 Chrome DevTools 控制台，然后单击 JS fiddle 页面左上角的 Run。您应该看到按顺序从三个函数中打印出`console.log`语句。随意编辑 fiddle 并尝试使用 Promises 进行实验。

在完成本章后不久，ES8 被宣布，确认了`async`函数是 JavaScript 语言的一部分。ES8 的`async`和`await`关键字提供了一种更简单的方式来解决 Promise，而不是 ES6 中使用的`.then().catch()`链。要学习使用`async`函数，请访问以下 MDN 页面：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/async_function)。

# 创建 API 调用模块

我们将使用 POST API 调用来注册我们的用户。但是，在应用程序的状态部分，我们需要使用`GET`请求来显示对活动感兴趣的人的统计数据。因此，我们将构建一个通用的 API 调用模块。

要创建 API 调用模块，在`services`目录内，创建另一个名为`api`的目录，并在其中创建`apiCall.js`。您的`services`目录的结构应如下所示：

```js
.
├── api
│   └── apiCall.js
└── formValidation
    └── validateRegistrationForm.js
```

在`apiCall.js`文件中创建以下函数：

```js
export default function apiCall(route, body = {}, method='GET') {
}
```

在前面的函数中，路由是一个必需的参数，而`body`和`method`有其默认值。这意味着它们是可选的。如果您只使用一个参数调用该函数，则另外两个参数将使用它们的默认值：

```js
apiCall('/registration) // values of body = {} and method = 'GET' 
```

如果您使用所有三个参数调用该函数，它将像普通函数一样工作：

```js
apiCall('/registration', {'a': 5}, 'POST'); // values of body = {'a': 5} and method = 'POST'
```

默认参数仅在 ES6 中引入。我们使用默认参数是因为`GET`请求不需要`body`属性。它只将数据作为查询参数发送到 URL 中。

我们已经在默认表单的提交部分看到了`GET`和`POST`请求的工作原理。让我们构建一个`apiCall`函数，可以执行`GET`和`POST`请求：

在`apiCall`函数内，创建一个名为`request`的新`Promise`对象：

```js
export default function apiCall(route, body = {}, method='GET') {

  const request = new Promise((resolve, reject) => {
    // Code for fetch will be written here
  });

}
```

fetch API 接受两个参数作为输入，并返回`Promise`，当网络请求完成时解析。第一个参数是请求 URL，第二个参数包含有关请求的信息的对象，如`headers`，`cors`，`method`，`body`等。

# 构建请求详细信息

将以下代码写入请求`Promise`内。首先，因为我们正在处理 JSON 数据，我们需要创建一个带有内容类型`application/json`的标头。我们可以使用`Headers`构造函数来实现这一目的：

```js
const headers = new Headers({
  'Content-Type': 'application/json',
});
```

现在，使用之前创建的`headers`和参数中的`method`变量，我们创建`requestDetails`对象：

```js
const requestDetails = {
  method,
  mode: 'cors',
  headers,
};
```

请注意，我已在`requestDetails`中包含了`mode: 'cors'`。**跨域资源共享**（**CORS**）允许服务器安全地进行跨域数据传输。假设您有一个运行在`www.mysite.org`上的网站。您需要向在`www.anothersite.org`上运行的另一个服务器发出 API 调用（网络请求）。

然后，这是一个跨域请求。要进行跨域请求，`www.anothersite.org`上的服务器必须设置`Access-Control-Allow-Origin`标头以允许`www.mysite.org`。否则，浏览器将阻止跨域请求，以防止未经授权访问另一个服务器。来自`www.mysite.org`的请求还应在其请求详细信息中包含`mode: 'cors'`。

在我们的事件注册应用程序中，Webpack 开发服务器正在`http://localhost:8080/`上运行，而 Node.js 服务器正在`http://localhost:3000/`上运行。因此，这是一个跨域请求。我已经启用了`Access-Control-Allow-Origin`并设置了`Access-Control-Allow-Headers`，以便它不会对`apiCall`函数造成任何问题。

有关 CORS 请求的详细信息可以在以下 MDN 页面找到：[`developer.mozilla.org/en/docs/Web/HTTP/Access_control_CORS`](https://developer.mozilla.org/en/docs/Web/HTTP/Access_control_CORS)。

我们的`requestDetails`对象还应包括请求的`body`。但是，`body`应仅包括在`POST`请求中。因此，可以在`requestDetails`对象声明下面编写，如下所示：

```js
if(method !== 'GET') requestDetails.body = JSON.stringify(body);
```

这将为`POST`请求添加`body`属性。要进行 fetch 请求，我们需要构建请求 URL。我们已经设置了环境变量`SERVER_URL=http://localhost:3000`，Webpack 将其转换为全局变量`SERVER_URL`，可在 JavaScript 代码的任何地方访问。路由传递给`apiCall()`函数的参数。fetch 请求可以构建如下：

```js
function handleErrors(response) {
  if(response.ok) {
    return response.json();
  } else {
    throw Error(response.statusText);
  }
}

fetch(`${SERVER_URL}/${route}`, requestDetails)
  .then(response => handleErrors(response))
  .then(data => resolve(data))
  .catch(err => reject(err));
```

`handleErrors` 函数的作用是什么？它将检查服务器返回的响应是否成功（`response.ok`）。如果是，它将解码响应并返回它（`response.json()`）。否则，它将抛出一个错误。

我们可以使用我们之前讨论的方法进一步简化 Promise 链：

```js
fetch(`${SERVER_URL}/${route}`, requestDetails)
  .then(handleErrors)
  .then(resolve)
  .catch(reject);
```

Fetch 有一个小问题。它无法自行处理超时。想象一下服务器遇到问题，无法返回请求。在这种情况下，fetch 将永远不会解决。为了避免这种情况，我们需要做一些变通。在 `request` Promise 之后，创建另一个名为 `timeout` 的 `Promise`：

```js
const request = new Promise((resolve, reject) => {
....
});

const timeout = new Promise((request, reject) => {
  setTimeout(reject, timeoutDuration, `Request timed out!`);
});
```

在 `apiCall.js` 文件的 `apicall()` 函数之外创建一个名为 `timeoutDuration` 的常量，如下所示：

```js
const  timeoutDuration = 5000;
```

将此常量放在文件顶部，以便我们可以在将来轻松更改超时持续时间（更易于代码维护）。`timeout` 是一个简单的 Promise，它在 5 秒后自动拒绝（来自 `timeoutDuration` 常量）。我已经创建了服务器，以便在 3 秒后响应。

现在，JavaScript 有一种很酷的方法来解决多个 Promises，即 `Promise.race()` 方法。正如其名字所示，这将使两个 Promises 同时运行，并接受首先解决/拒绝的那个的值。这样，如果服务器在 3 秒内没有响应，5 秒后就会发生超时，`apiCall` 将被拒绝并显示超时！为此，在 `apiCall()` 函数中的 `request` 和 `timeout` Promises 之后添加以下代码：

```js
return new Promise((resolve, reject) => {
  Promise.race([request, timeout])
    .then(resolve)
    .catch(reject);
});
```

`apiCall()` 函数作为一个整体返回一个 Promise，该 Promise 是 `request` 或 `timeout` Promise 的解决值（取决于它们中哪一个更快执行）。就是这样！我们的 `apiCall` 模块现在已经准备好在我们的事件注册应用程序中使用。

如果您觉得 `apiCall` 函数难以理解和跟踪，请再次阅读 `Chapter03` 完整代码文件中的 `apiCall.js` 文件，以便更简单地解释。要详细了解 Promise 并带有更多示例，请阅读以下 Google Developers 页面：[`developers.google.com/web/fundamentals/getting-started/primers/promises`](https://developers.google.com/web/fundamentals/getting-started/primers/promises) 和 MDN 页面：[`developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Promise`](https://developer.mozilla.org/en/docs/Web/JavaScript/Reference/Global_Objects/Promise)。

# 其他网络请求方法

点击这些链接了解 JavaScript 中进行网络请求的其他插件/API：

+   jQuery，`$.ajax()` 方法：[`api.jquery.com/jquery.ajax/`](http://api.jquery.com/jquery.ajax/)

+   `XMLHttpRequest`: [`developer.mozilla.org/en/docs/Web/API/XMLHttpRequest`](https://developer.mozilla.org/en/docs/Web/API/XMLHttpRequest)

+   Axios.js: [`github.com/mzabriskie/axios`](https://github.com/mzabriskie/axios)

要使 fetch 在 Internet Explorer 中工作，请阅读以下页面，了解如何为 fetch 添加 `polyfill`：[`github.com/github/fetch/`](https://github.com/github/fetch/)。

# 回到表单

开始提交的第一步是隐藏提交按钮并用加载指示器替换它。这样，用户就不会意外地点击两次提交。此外，加载指示器还表示后台正在进行某个过程。在 `home.js` 文件的 `submitForm()` 方法中，添加以下代码：

```js
submitForm(formValues) {
  this.$submit.classList.add('hidden');
  this.$loadingIndicator.classList.remove('hidden');
}
```

这将隐藏提交按钮并显示加载指示器。要进行 `apiCall`，我们需要导入 `apiCall` 函数并通知用户请求已完成。我在 `package.json` 文件中添加了一个名为 `toastr` 的包。当您运行 `npm install` 命令时，它应该已经安装。

在 `home.js` 文件的顶部，添加以下导入语句：

```js
import apiCall from './services/api/apiCall';
import toastr from 'toastr';
import '../../node_modules/toastr/toastr.less';
```

这将导入`toastr`及其样式文件（`toastr.less`），以及最近创建的`apiCall`模块。现在，在`submitForm()`方法中，添加以下代码：

```js
apiCall('registration', formValues, 'POST')
  .then(response => {
    this.$submit.classList.remove('hidden');
    this.$loadingIndicator.classList.add('hidden');
    toastr.success(response.message);
    this.resetForm(); // For clearing the form
  })
  .catch(() => {
    this.$submit.classList.remove('hidden');
    this.$loadingIndicator.classList.add('hidden');
    toastr.error('Error!');
  });
```

由于`apiCall()`返回一个 Promise，我们在这里使用`Promise.then().catch()`链。当注册成功时，`toastr`将在页面的右上角显示一个成功的提示，其中包含服务器发送的消息。如果出现问题，它将简单地显示一个错误提示。此外，我们需要使用`this.resetForm()`方法清除表单。在`Home`类中添加`resetForm()`方法，代码如下：

```js
resetForm() {
  this.$username.value = '';
  this.$email.value = '';
  this.$phone.value = '';
  this.$age.value = '';
  this.$profession.value = 'school';
  this.$experience.checked = true;
  this.$comment.value = '';
}
```

在 Chrome 中返回到活动注册页面，尝试提交表单。如果所有值都有效，它应该成功提交表单并显示成功的提示消息，表单值将被重置为初始值。在现实世界的应用中，服务器将向用户发送确认邮件。然而，服务器端编码超出了本书的范围。但我想在下一章中稍微解释一下这个。

尝试关闭 Node.js 服务器并提交表单。它应该会抛出一个错误。在学习 JavaScript 的一些高级概念的同时，您已经成功完成了构建您的活动注册表单。现在，让我们继续进行我们应用程序的第二页——状态页面，我们需要显示一个注册用户统计图表。

# 使用 Chart.js 向网站添加图表

我们刚刚为用户创建了一个不错的注册表单。现在是时候处理我们活动注册应用程序的第二部分了。状态页面显示了一个图表，显示了对活动感兴趣的人数，根据经验、职业和年龄。如果现在打开状态页面，它应该显示一个数据加载中...的消息和加载指示器图像。但我已经在`status.html`文件中构建了所有这个页面所需的组件。它们都使用 Bootstrap 的`.hidden`类当前隐藏。

让我们看看`status.html`文件中有什么。尝试从以下每个部分中删除`.hidden`类，看看它们在 Web 应用程序中的外观。

首先是加载指示器部分，它目前显示在页面上：

```js
<div id="loadingIndicator">
  <p>Data loading...</p>
  <image src="./src/assets/images/loading.gif" class="loading-indicator"></image>
</div>
```

接下来是一个包含错误消息的部分，当 API 调用失败时显示：

```js
<div id="loadingError" class="hidden">
  <h3>Unable to load data...Try refreshing the page.</h3>
</div>
```

在前面的部分之后，我们有一个选项卡部分，它将为用户提供在不同图表之间切换的选项。代码如下所示：

```js
<ul class="nav nav-tabs hidden" id="tabArea">
  <li role="presentation" class="active"><a href="" id="experienceTab">Experience</a></li>
  <li role="presentation"><a href="" id="professionTab">Profession</a></li>
  <li role="presentation"><a href="" id="ageTab">Age</a></li>
</ul>
```

选项卡只是一个带有`.nav`和`.nav-tabs`类的无序列表，由 Bootstrap 样式为选项卡。选项卡部分是带有`.active`类的列表项，用于突出显示所选的选项卡部分（`role="presentation"`用于辅助选项）。在列表项内，有一个空的`href`属性的锚标签。

最后，我们有我们的图表区域，有三个画布元素，用于显示前面选项卡中提到的三个不同类别的图表：

```js
<div class="chart-area hidden" id="chartArea">
  <canvas id="experienceChart"></canvas>
  <canvas id="professionChart"></canvas>
  <canvas id="ageChart"></canvas>
</div>
```

正如我们在上一章中看到的，画布元素最适合在网页上显示图形，因为编辑 DOM 元素是一项昂贵的操作。Chart.js 使用画布元素来显示给定数据的图表。让我们制定状态页面应该如何工作的策略：

+   在从服务器获取统计数据的 API 调用时，应该显示加载指示器

+   如果数据成功检索，则加载指示器应该被隐藏，选项卡部分和图表区域应该变得可见

+   只有与所选选项卡对应的画布应该可见；其他画布元素应该被隐藏

+   应该使用 Chart.js 插件向画布添加饼图

+   如果数据检索失败，则所有部分应该被隐藏，错误部分应该被显示

好了！让我们开始工作。打开我已经在`status.html`中添加为参考的`status.js`文件。创建一个`Status`类，并在其构造函数中引用所有所需的 DOM 元素，如下所示：

```js
class Status {
  constructor() {
    this.$experienceTab = document.querySelector('#experienceTab');
    this.$professionTab = document.querySelector('#professionTab');
    this.$ageTab = document.querySelector('#ageTab');

    this.$ageCanvas = document.querySelector('#ageChart');
    this.$professionCanvas = document.querySelector('#professionChart');
    this.$experienceCanvas = document.querySelector('#experienceChart');

    this.$loadingIndicator = document.querySelector('#loadingIndicator');
    this.$tabArea = document.querySelector('#tabArea');
    this.$chartArea = document.querySelector('#chartArea');

    this.$errorMessage = document.querySelector('#loadingError');

    this.statisticData; // variable to store data from the server
 }

}
```

我还创建了一个类变量`statisticData`，用于存储从 API 调用中检索到的数据。此外，在页面加载时添加创建类的实例的代码：

```js
window.addEventListener("load", () => {
  new Status();
});
```

我们状态页面的第一步是向服务器发出网络请求，以获取所需的数据。我已在 Node.js 服务器中创建了以下 API 端点：

```js
Route: /statistics,
Method: GET,  Server Response on Success:
status code: 200
response: {"experience":[35,40,25],"profession":[30,40,20,10],"age":[30,60,10]}
```

服务器将以适合与 Chart.js 一起使用的格式返回包含基于其经验、职业和年龄感兴趣的人数的数据。让我们使用之前构建的`apiCall`模块来进行网络请求。在您的`status.js`文件中，首先在`Status`类上面添加以下导入语句：

```js
import apiCall from './services/api/apiCall';
```

之后，在`Status`类中添加以下方法：

```js
loadData() {
  apiCall('statistics')
    .then(response => {
      this.statisticData = response;

      this.$loadingIndicator.classList.add('hidden');
      this.$tabArea.classList.remove('hidden');
      this.$chartArea.classList.remove('hidden');
    })
    .catch(() => {
      this.$loadingIndicator.classList.add('hidden');
      this.$errorMessage.classList.remove('hidden');
    });
}
```

这次，我们可以只使用一个参数调用`apiCall()`函数，因为我们正在进行`GET`请求，并且我们已经将`apiCall()`函数的默认参数定义为`body = {}`和`method = 'GET'`。这样，我们在进行`GET`请求时就不必指定 body 和 method 参数。在您的构造函数中，添加`this.loadData()`方法，这样当页面加载时它将自动进行网络请求：

```js
constructor() {
  ...
  this.loadData();
}
```

现在，在 Chrome 中查看网页。三秒后，应该显示选项卡。目前，单击选项卡只会重新加载页面。我们将在创建图表后处理这个问题。

# 将图表添加到画布元素

我们的类变量`statisticData`中有所需的数据，应该用它来渲染图表。我已经在`package.json`文件中添加了 Chart.js 作为项目依赖项，当您执行`npm install`命令时，它应该已经安装。让我们通过在`status.js`文件顶部添加以下代码来将 Chart.js 导入我们的项目中：

```js
import Chart from 'chart.js';
```

不一定要在文件顶部添加`import`语句。但是，在顶部添加`import`语句可以清晰地看到当前文件中模块的所有依赖关系。

Chart.js 提供了一个构造函数，我们可以使用它来创建一个新的图表。`Chart`构造函数的语法如下：

```js
new Chart($canvas, {type: 'pie', data});
```

`Chart`构造函数的第一个参数应该是对 canvas 元素的引用，第二个参数是具有两个属性的 JSON 对象：

+   `type`属性应该包含我们在项目中需要使用的图表类型。我们需要在项目中使用饼图。

+   `data`属性应该包含作为基于图表类型的格式的对象所需的数据集。在我们的情况下，对于饼图，所需的格式在 Chart.js 文档的以下页面上指定：[`www.chartjs.org/docs/latest/charts/doughnut.html`](http://www.chartjs.org/docs/latest/charts/doughnut.html)。

数据对象将具有以下格式：

```js
{
  datasets: [{
    data: [],
    backgroundColor: [],
    borderColor: [],
  }],
  labels: []
}
```

数据对象具有以下属性：

+   一个`datasets`属性，其中包含另一个对象的数组，该对象具有`data`、`backgroundColor`和`borderColor`作为数组

+   `labels`属性是一个标签数组，顺序与数据数组相同

创建的图表将自动占据其父元素提供的整个空间。在`Status`类内部创建以下函数，将`Chart`加载到状态页面中：

您可以根据经验创建一个图表，如下所示：

```js
loadExperience() {
  const data = {
    datasets: [{
      data: this.statisticData.experience,
      backgroundColor:[
        'rgba(255, 99, 132, 0.6)',
        'rgba(54, 162, 235, 0.6)',
        'rgba(255, 206, 86, 0.6)',
      ],
      borderColor: [
        'white',
        'white',
        'white',
      ]
    }],
    labels: [
      'Beginner',
      'Intermediate',
      'Advanced'
    ]
  };
  new Chart(this.$experienceCanvas,{
    type: 'pie',
    data,
  });
}
```

您可以根据职业创建一个图表，如下所示：

```js
loadProfession() {
  const data = {
    datasets: [{
      data: this.statisticData.profession,
      backgroundColor:[
        'rgba(255, 99, 132, 0.6)',
        'rgba(54, 162, 235, 0.6)',
        'rgba(255, 206, 86, 0.6)',
        'rgba(75, 192, 192, 0.6)',
      ],
      borderColor: [
        'white',
        'white',
        'white',
        'white',
      ]
    }],
    labels: [
      'School Students',
      'College Students',
      'Trainees',
      'Employees'
    ]
  };
  new Chart(this.$professionCanvas,{
    type: 'pie',
    data,
  });
}
```

您可以根据年龄创建一个图表，如下所示：

```js
loadAge() {
  const data = {
    datasets: [{
      data: this.statisticData.age,
      backgroundColor:[
        'rgba(255, 99, 132, 0.6)',
        'rgba(54, 162, 235, 0.6)',
        'rgba(255, 206, 86, 0.6)',
      ],
      borderColor: [
        'white',
        'white',
        'white',
      ]
    }],
    labels: [
      '10-15 years',
      '15-20 years',
      '20-25 years'
    ]
  };
  new Chart(this.$ageCanvas,{
    type: 'pie',
    data,
  });
}
```

这些函数应在数据加载到`statisticData`变量中时调用。因此，在 API 调用成功后调用它们的最佳位置是在`loadData()`方法中添加以下代码，如下所示：

```js
loadData() {
  apiCall('statistics')
    .then(response => {
      ...
      this.loadAge();
      this.loadExperience();
      this.loadProfession();
     })
...
}
```

现在，在 Chrome 中打开状态页面。您应该看到页面上呈现了三个图表。图表已经占据了其父元素的整个宽度。要减小它们的大小，请在您的`styles.css`文件中添加以下样式：

```js
.chart-area {
  margin: 25px;
  max-width: 600px;
}
```

这将减小图表的尺寸。Chart.js 最好的部分是它默认是响应式的。尝试在 Chrome 的响应式设计模式下调整页面大小。当页面的高度和宽度改变时，你应该看到图表被重新调整大小。我们现在在我们的状态页面上添加了三个图表。

对于我们的最后一步，我们需要选项卡来切换图表的外观，以便一次只有一个图表可见。

# 设置选项卡部分

选项卡应该工作，以便在任何给定时间只有一个图表可见。此外，所选选项卡应使用 `.active` 类标记为活动状态。这个问题的一个简单解决方案是隐藏所有图表，从所有选项卡项目中移除 `.active`，然后只向点击的选项卡项目添加 `.active` 并显示所需的图表。这样，我们可以轻松获得所需的选项卡功能。

首先，在 `Status` 类中创建一个方法来清除选定的选项卡并隐藏所有图表：

```js
hideCharts() {
  this.$experienceTab.parentElement.classList.remove('active');
  this.$professionTab.parentElement.classList.remove('active');
  this.$ageTab.parentElement.classList.remove('active');
  this.$ageCanvas.classList.add('hidden');
  this.$professionCanvas.classList.add('hidden');
  this.$experienceCanvas.classList.add('hidden');
}
```

创建一个方法来为点击的选项卡项目添加事件监听器：

```js
addEventListeners() {
  this.$experienceTab.addEventListener('click', this.loadExperience.bind(this));
  this.$professionTab.addEventListener('click', this.loadProfession.bind(this));
  this.$ageTab.addEventListener('click', this.loadAge.bind(this));
}
```

还要在 `constructor` 中使用 `this.addEventListeners();` 调用前面的方法，以便在页面加载时附加事件监听器。

每当我们点击选项卡项目中的一个时，它将调用相应的加载图表函数。比如我们点击了 Experience 选项卡。这将使用 `event` 作为参数调用 `loadExperience()` 方法。但是我们可能希望在 API 调用后调用此函数以加载图表，而不带有事件参数。为了使 `loadExperience()` 在两种情况下都能工作，修改该方法如下：

```js
loadExperience(event = null) {
  if(event) event.preventDefault();
  this.hideCharts();
  this.$experienceCanvas.classList.remove('hidden');
  this.$experienceTab.parentElement.classList.add('active');

  const data = {...}
  ...
}
```

在前面的函数中：

+   事件参数被定义为默认值 `null`。如果使用事件参数调用 `loadExperience()`（当用户点击选项卡时），`if(event)` 条件将通过，`event.preventDefault()` 将停止锚标签的默认点击操作。这将防止页面重新加载。

+   如果从 `apiCall` 的 promise 链中调用 `this.loadExperience()`，它将不具有 `event` 参数，事件的值默认为 `null`。`if(event)` 条件将失败（因为 `null` 是一个假值），`event.preventDefault()` 将不会被执行。这将防止异常，因为在这种情况下 `event` 未定义。

+   之后，调用 `this.hideCharts()`，这将隐藏所有图表并从所有选项卡中移除 `.active`。

+   接下来的两行将从经验图表的画布中移除 `.hidden` 并向 Experience 选项卡添加 `.active` 类。

在 `apiCall` 函数的 `then` 链中，移除 `this.loadAge()` 和 `this.loadProfession()`，这样只有经验图表会首先加载（因为它是第一个选项卡）。

如果你在 Google Chrome 中打开并点击 Experience 选项卡，它应该重新渲染图表而不刷新页面。这是因为我们在 `loadExperience()` 方法中添加了 `event.preventDefault()` 来阻止默认操作，并使用 Chart.js 在点击选项卡时渲染图表。

通过在 `loadAge()` 和 `loadProfession()` 中使用相同的逻辑，我们现在可以轻松使选项卡按预期工作。在你的 `loadAge()` 方法中添加以下事件处理代码：

```js
loadAge(event = null) {
  if(event) event.preventDefault();
  this.hideCharts();
  this.$ageCanvas.classList.remove('hidden');
  this.$ageTab.parentElement.classList.add('active');

  const data = {...}
  ...
}
```

同样，在 `loadProfession()` 方法中添加以下代码：

```js
loadProfession(event = null) {
  if(event) event.preventDefault();
  this.hideCharts();
  this.$professionCanvas.classList.remove('hidden');
  this.$professionTab.parentElement.classList.add('active');

  const data = {...}
  ...
}
```

打开 Chrome。点击选项卡以检查它们是否都正常工作。如果是，你已成功完成了状态页面！Chart.js 默认是响应式的；因此，如果你调整页面大小，它将自动调整饼图的大小。现在，还有最后一页，你需要添加谷歌地图来显示事件位置。在普通的 JavaScript 中，添加谷歌地图很简单。但是，在我们的情况下，因为我们使用 Webpack 来捆绑我们的 JavaScript 代码，我们需要在正常流程中添加一个小步骤（谷歌地图需要在 HTML 中访问 JavaScript 变量！）。

Chart.js 有八种类型的图表。请尝试访问：[`www.chartjs.org/`](http://www.chartjs.org/)，如果你正在寻找更高级的图表和图形库，请查看`D3.js`（**数据驱动文档**）：[`d3js.org/`](https://d3js.org/)。

# 在网页中添加谷歌地图

在 VSCode 或文本编辑器中打开`about.html`文件。它将有两个`<p>`标签，你可以在其中添加有关活动的一些信息。之后，将会有一个 ID 为`#map`的`<div>`元素，它应该显示活动在地图中的位置。

我之前已经要求你生成一个 API 密钥来使用谷歌地图。如果你还没有生成，请从以下网址获取：[`developers.google.com/maps/documentation/javascript/get-api-key`](https://developers.google.com/maps/documentation/javascript/get-api-key)，并将其添加到你的`.env`文件的`GMAP_KEY`变量中。根据谷歌地图的文档，要在网页上添加一个带有标记的地图，你必须在页面上包含以下脚本：

```js
<script  async  defer src="https://maps.googleapis.com/maps/api/js?key=API_KEY&callback=**initMap**">
```

在这里，`<script>`标签的`async`和`defer`属性将异步加载脚本，并确保它仅在文档加载后执行。

要了解有关`async`和`defer`的工作原理的更多信息，请参考以下 w3schools 页面。有关 Async: [`www.w3schools.com/tags/att_script_async.asp`](https://www.w3schools.com/tags/att_script_async.asp)，有关 Defer: [`www.w3schools.com/tags/att_script_defer.asp`](https://www.w3schools.com/tags/att_script_defer.asp)。

让我们来看看`src`属性。在这里，有一个 URL，后面跟着两个查询参数，key 和 callback。Key 是你需要包含你的谷歌地图 API 密钥的地方，callback 应该是一个需要在脚本加载完成后执行的函数（脚本是异步加载的）。挑战在于脚本需要包含在我们的 JavaScript 变量不可访问的 HTML 中（我们现在是 Webpack 用户！）。

但是，正如我之前解释的，在`webpack.config.js`文件中，我已经添加了`output.library`属性，它将通过将它们的作用域从`const`或`let`更改为`var`，将使用`export`关键字标记的对象、函数或变量暴露给 HTML（但它们不能直接通过它们的名称访问）。我给出的`output.library`的值是`bundle`。因此，使用`export`关键字标记的东西将作为`bundle`对象的属性可用。

在 Chrome 中打开事件注册应用程序，并打开 Chrome DevTools 控制台。如果你在控制台中输入`bundle`，你会发现它打印出一个空对象。这是因为我们还没有从*Webpack 的入口文件*中进行任何导出（我们在`apiCall.js`和`registrationForm.js`中进行了一些导出，但这些文件不在`webpack.config.js`的入口属性中）。因此，目前我们只有一个空的 bundle 对象。

让我们想一种成功将谷歌地图脚本包含在我们的 Web 应用程序中的方法：

+   API 密钥当前在我们的 JavaScript 代码中作为全局变量`GMAP_KEY`可用。因此，最好是在页面加载完成后从 JavaScript 创建脚本元素并将其附加到 HTML 中。这样，我们就不必导出 API 密钥。

+   对于回调函数，我们将创建一个 JavaScript 函数并导出它。

在 VSCode 中打开`about.js`文件并添加以下代码：

```js
export function initMap() {
}

window.addEventListener("load", () => {
  const $script = document.createElement('script');
  $script.src = `https://maps.googleapis.com/maps/api/js?key=${GMAP_KEY}&callback=bundle.initMap`;
  document.querySelector('body').appendChild($script);
});
```

上述代码执行以下操作：

+   当页面加载完成时，它将创建一个新的脚本元素`document.createElement('script')`并将其存储在`$script`常量对象中。

+   现在，我们将`src`属性添加到`$script`对象中，并将值设置为所需的脚本 URL。请注意，我已经在密钥中包含了`GMAP_KEY`变量，并将`bundle.initMap`作为回调函数（因为我们在`about.js`中导出了`initMap`）。

+   最后，它将把脚本作为子元素附加到 body 元素。这将使 Google Maps 脚本按预期工作。

+   我们这里不需要`async`或`defer`，因为只有在页面加载完成后才加载脚本。

在你的 Chrome DevTools 控制台上，当你在 about 页面上时，尝试再次输入`bundle`。这一次，你应该看到一个打印出`initMap`作为其属性之一的对象。

在我们的 ToDo List 应用中，我们通过直接在模板字符串中编写 HTML 代码来创建 HTML 元素。这对于构建大量 HTML 元素非常有效。然而，对于较小的元素，最好使用`document.createElement()`方法，因为当该元素有很多需要动态值的属性时，这样做会使代码更易读和易懂。

# 添加带有标记的 Google 地图

我们已经成功在页面上包含了 Google Maps 脚本。当 Google Maps 脚本加载完成时，它将调用我们在`about.js`文件中声明的`initMap`函数。现在，我们将使用该函数来创建一个指向 JS Meetup 活动位置的地图标记。

添加 Google 地图标记和更多功能的过程在 Google 地图文档中有很好的解释，可在以下链接找到：[`developers.google.com/maps/documentation/javascript/adding-a-google-map`](https://developers.google.com/maps/documentation/javascript/adding-a-google-map)。

我们之前包含的 Google Maps 脚本为我们提供了一些构造函数，可以创建`map`、`Marker`和`infowindow`。要添加一个带有`marker`的简单 Google 地图，请在`initMap()`函数内添加以下代码：

```js
export function initMap() {
  const map = new google.maps.Map(document.getElementById('map'), {
    zoom: 13,
    center: {lat: 59.325, lng: 18.070}
  });

  const marker = new google.maps.Marker({
    map,
    draggable: true,
    animation: google.maps.Animation.DROP,
    position: {lat: 59.325, lng: 18.070}
  });

  marker.addListener('click', () => {
    infowindow.open(map,marker);
  });

  const infowindow = new google.maps.InfoWindow({
    content: `<h3>Event Location</h3><p>Event Address with all the contact details</p>`
  });

  infowindow.open(map,marker);
}
```

用你的活动地点的纬度和经度替换上述代码中的`lat`和`lng`值，并将`infowindow`对象的内容更改为活动地点的地址和联系方式。现在，在 Google Chrome 上打开`about.html`页面；你应该看到地图上有一个标记指向你的活动地点。信息窗口将默认打开。

恭喜！你已经成功构建了你的 Event Registration 应用！但是，在我们开始邀请人们参加活动之前，你的应用还有一件事情需要做。

# 生成生产构建

你可能已经注意到了关于 Meme Creator 和 Event Registration 应用的一些问题。这些应用首先加载纯 HTML；之后加载样式。这使得应用在一段时间内看起来很普通。在 ToDo List 应用中不存在这个问题，因为我们首先加载了 CSS。在 Meme Creator 应用中，有一个名为*为不同环境优化 Webpack 构建*的可选部分。现在可能是阅读它的好时机。如果你还没有阅读过，请回去，阅读一下那部分内容，然后回来生成生产构建。

到目前为止，我们的应用一直在开发环境中运行。记得吗？在`.env`文件中，我告诉你要设置`NODE_ENV=dev`。这是因为，当你按照我创建的`webpack.config.js`文件设置`NODE_ENV=production`时，Webpack 将进入生产模式。`npm run watch`命令用于运行 Webpack 开发服务器，为我们提供一个开发服务器。在你的`package.json`文件中，应该有另一个名为`webpack`的命令。这个命令用于生成生产构建。

这个项目中包含的`webpack.config.js`文件有很多插件，用于优化代码，使应用加载时间更快。只有当`NODE_ENV`为 production 时，`npm run watch`才能正常工作，因为有很多插件用于进行生产优化。要为你的 Event Registration 应用生成生产构建，请按照以下步骤进行：

1.  将`.env`文件中`NODE_ENV`变量的值更改为`production`。

1.  在终端中从项目根文件夹运行以下命令`npm run webpack`。

命令执行需要一段时间，但一旦完成，你应该在项目的`/dist`文件夹中看到许多文件。那里会有 JS 文件、CSS 文件和包含生成的 CSS 和 JS 文件的`.map`文件的源映射信息。JS 文件将被压缩和精简，以便加载和执行时间非常快。还会有一个包含 Bootstrap 使用的字体的字体目录。

到目前为止，我们只在 HTML 中包含了 JS 文件，因为它也包含了 CSS 代码。然而，这就是为什么页面在开始加载时显示空白的 HTML 而没有 CSS 的原因。CSS 文件应该在`<body>`元素之前包含，这样它将首先加载，页面样式在加载时将是统一的（看看我们在第一章中如何包含 CSS 文件，*构建一个待办事项列表应用*）。对于生产构建，我们需要删除对旧 JS 文件的引用，并包含新生成的 CSS 和 JS 文件。

在你的`dist/`目录中，会有一个`manifest.json`文件，其中包含了 Webpack 每个入口生成的文件列表。`manifest.json`应该看起来像这样：

```js
{
  "status": [
    "16f9901e75ba0ce6ed9c.status.js",
    "16f9901e75ba0ce6ed9c.status.css",
    "16f9901e75ba0ce6ed9c.status.js.map",
    "16f9901e75ba0ce6ed9c.status.css.map"
  ],
  "home": [
    "756fc66292dc44426e28.home.js",
    "756fc66292dc44426e28.home.css",
    "756fc66292dc44426e28.home.js.map",
    "756fc66292dc44426e28.home.css.map"
  ],
  "about": [
    "1b4af260a87818dfb51f.about.js",
    "1b4af260a87818dfb51f.about.css",
    "1b4af260a87818dfb51f.about.js.map",
    "1b4af260a87818dfb51f.about.css.map"
  ]
}
```

前缀数字只是哈希值，它们可能对你来说是不同的；不用担心。现在，为每个 HTML 文件包含 CSS 和 JS 文件。例如，取`status.html`文件，并在前面的`manifest.json`文件的 status 属性中添加 CSS 和 JS 文件，如下所示：

```js
...
<head>
  ...
  <link rel="stylesheet" href="dist/16f9901e75ba0ce6ed9c.status.css">
</head>
<body>
  ...
  <script src="dist/16f9901e75ba0ce6ed9c.status.js"></script>
</body>
...
```

对其他 HTML 文件重复相同的过程，然后你的生产构建就准备好了！现在不能使用 Webpack 开发服务器，所以你可以使用`http-server`工具打开网页，或者直接用 Chrome 打开 HTML 文件（我建议使用`http-server`）。这一次，在页面加载时，你不会看到没有样式的 HTML 页面，因为 CSS 会在 body 元素之前加载。

# 发布代码

现在你已经学会了如何生成生产构建，如果你想把这段代码发送给其他人呢？比如 DevOps 团队或服务器管理员。在这种情况下，如果你正在使用版本控制，将`dist/`目录、`node_modules/`目录和`.env`文件添加到你的忽略列表中。发送代码时不包括这两个目录和`.env`文件。其他人应该能够使用`.env.example`文件找出要使用的环境变量，创建`.env`文件，并使用`npm install`和`npm run webpack`命令生成`node_modules/`和`dist/`目录。

对于所有其他步骤，将过程整齐地记录在项目根目录的`README.md`文件中，并将其与其他文件一起发送。

共享`.env`文件应该避免的主要原因是环境变量可能包含敏感信息，不应以明文形式在版本控制中传输或存储。

你现在已经学会了如何为使用 Webpack 构建的应用生成生产构建。现在，Meme Creator 应用还没有生产构建！我会让你使用本章中使用的`webpack.config.js`文件作为参考。所以，继续为你的 Meme Creator 创建一个生产构建。

# 摘要

干得好！你刚刚构建了一个非常有用的活动注册应用。在这个过程中，你学到了一些 JavaScript 的高级概念，比如构建可重用代码的 ES6 模块，使用 fetch 进行异步 AJAX 调用，并使用 Promises 处理异步代码。你还使用 Chart.js 库构建图表来直观显示数据，最后使用 Webpack 创建了一个生产就绪的构建。

学会了所有这些概念，你不再是 JavaScript 的初学者；你可以自豪地称自己为专家！但是，除了这些概念，现代 JavaScript 还有很多其他内容。正如我之前告诉过你的，JavaScript 不再仅仅是用于浏览器表单验证的脚本语言。在下一章中，我们将使用 JavaScript 构建一个点对点视频通话应用程序。


`# 使用 WebRTC 进行实时视频通话应用

嘿！只是想告诉你，JS Meetup 在找到后端开发人员完成应用程序的服务器端之后取得了巨大成功。但是你很棒，完成了整个应用程序的前端。你创建了一个完整的活动注册网站，让用户报名参加活动，同时学习了一些非常重要的概念，比如构建可重用的 ES6 模块，使用 Promises 处理异步代码进行 AJAX 请求，从数据创建美丽的图表，当然还有经典的表单验证与验证服务。

后端代码也是用 JavaScript（Node.js）编写的，所以你可能真的对编写服务器端代码感兴趣。但遗憾的是，正如我之前提到的，Node.js 超出了本书的范围。实际上，你可以用纯 JavaScript 做一些非常酷的事情，尽管很多人认为，“*它需要大量的服务器端代码！*”因为你已经读过本章的标题 - 是的！我们将在本章中构建一个真正的视频通话应用程序，几乎没有服务器端代码。最好的部分是，就像我们的其他应用程序一样，这个应用程序也将是响应式的，并且将与大多数移动浏览器兼容。

让我们首先看一下我们将在本章学习的概念清单：

+   WebRTC 介绍

+   JavaScript 中的 WebRTC API

+   使用 SimpleWebRTC 框架进行工作

+   构建视频通话应用程序

除了这些主要概念，本章还有很多东西要学习。因此，在我们开始之前，请确保你有以下硬件：

+   带有网络摄像头和麦克风的台式机或笔记本电脑（你可能想使用另一台计算机来体验视频通话的实际效果）

+   安卓或 iPhone 设备（可选）

+   局域网连接，以便所有设备都在同一局域网上进行开发应用程序的测试（可以是 Wi-Fi 或有线以太网）

这个项目中使用的一个依赖项要求你的系统中安装了 Python 2.7.x。Linux 和 Mac 用户已经预装了 Python。Windows 用户可以从[`www.python.org/downloads/`](https://www.python.org/downloads/)下载 Python 2.7.x 版本。

# 第四章：WebRTC 介绍

在我们开始构建应用程序之前，最好先了解一些关于 WebRTC 的知识，以便你对应用程序的工作原理有一个很好的了解。

# WebRTC 的历史

实时通信能力已经成为我们现在使用的许多应用程序的常见功能。比如你想和朋友聊天或者观看现场足球比赛。这些应用程序必须具备实时通信功能。然而，在过去在浏览器上进行实时视频通话对用户来说是一项相当困难的任务，因为他们必须为不同的应用程序在 Web 浏览器上使用视频通话安装插件，而插件会带来漏洞，因此需要定期更新。

为了解决这个问题，谷歌于 2011 年 5 月发布了一个开源项目，用于基于浏览器的实时通信标准，名为 WebRTC。WebRTC 的概念很简单。它定义了一套标准，应该在所有应用程序中使用，以便应用程序可以直接相互通信（点对点通信）。通过实现 WebRTC，将不再需要插件，因为通信平台是标准化的。

目前，WebRTC 正在由**万维网联盟**（**W3C**）和**互联网工程任务组**（**IETF**）进行标准化。WebRTC 正在被大多数浏览器供应商积极实施，并且它也将与原生的 Android 和 iOS 应用程序一起工作。如果你想知道你的浏览器是否准备支持 WebRTC，你可以访问：[`iswebrtcreadyyet.com/`](http://iswebrtcreadyyet.com/)。

在撰写本书时，浏览器支持状态如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00022.jpeg)

尽管大多数常用的浏览器都支持 WebRTC，除了 Safari，但实现中仍然存在许多问题和错误，因此建议使用适配器（如`adapter.js`）（[`github.com/webrtc/adapter`](https://github.com/webrtc/adapter)），以便应用程序在规范或供应商前缀发生变化时不会遇到任何问题。当我们研究 WebRTC 的 JavaScript API 时，我们将更多地了解这一点。

WebRTC 也支持 Chrome 和 Firefox 的移动版本；因此，即使在没有插件的移动浏览器中，你也可以进行视频通话。

对于 iPhone 用户，iPhone 上的 Safari 移动浏览器或 Chrome 尚不支持 WebRTC。因此，你必须安装 Firefox 或来自应用商店的 Bowser 应用。Bowser 的链接：[`itunes.apple.com/app/bowser/id560478358?mt=8`](https://itunes.apple.com/app/bowser/id560478358?mt=8)。

# JavaScript WebAPIs

到目前为止，我们已经使用了一些 WebAPIs，比如`FileReader`，文档（在`document.querySelector()`方法中使用），`HTMLImageElement`（我们在 Meme Creator 中使用的`new Image()`构造函数），等等。它们不是 JavaScript 语言的一部分，但它们是 WebAPIs 的一部分。在浏览器中运行 JavaScript 时，将提供一个包含所有 WebAPIs 方法的`window`对象。`window`对象的范围是全局的，`window`对象的属性和方法也是全局的。这意味着，如果你想使用 navigator WebAPI，你可以这样做：

```js
window.navigator.getUserMedia()
```

或者，你可以简单地这样做：

```js
navigator.getUserMedia();
```

两者都可以正常工作并实现相同的方法。但是请注意，WebAPI（`window`对象）仅在浏览器中运行 JavaScript 时才可用。如果你在其他平台上使用 JavaScript，比如 Node.js 或 React Native，你将无法使用 WebAPIs。

现在 WebAPIs 变得越来越强大，为 JavaScript 提供了更多的功能，比如直接从浏览器录制视频和音频。渐进式 Web 应用程序就是这样的一个例子，由`ServiceWorker` WebAPI 提供支持。

本章和接下来的章节中，我们将使用大量的 WebAPIs。有关 JavaScript 可用的 WebAPIs 的完整列表，请访问以下 MDN 页面：[`developer.mozilla.org/en-US/docs/Web/API`](https://developer.mozilla.org/en-US/docs/Web/API)。

# JavaScript WebRTC API

由于浏览器原生支持 WebRTC，因此浏览器供应商创建了 JavaScript WebAPIs，以便开发人员可以轻松构建应用程序。目前，WebRTC 实现了以下三个 JavaScript 使用的 API：

+   MediaStream

+   RTCPeerConnection

+   RTCDataChannel

# MediaStream

MediaStream API 用于获取用户的视频和音频设备的访问权限。通常，浏览器会提示用户是否允许网站访问他/她设备的摄像头和麦克风。尽管 MediaStream API 的基本概念是相同的，但不同的浏览器供应商对 API 的实现方式有所不同。

在使用`getUserMedia()`方法时，使用`{audio: true}`来访问你自己的麦克风时，*要么将扬声器静音，要么将 HTML 视频元素静音*。否则，*可能会导致反馈，损坏你的扬声器*。

例如，在 Chrome 中，要使用 MediaStream API，你需要使用`navigator.getUserMedia()`方法。此外，Chrome 只允许 MediaStream 在 localhost 或 HTTPS URL 中工作。

`navigator.getUserMedia()`接受三个参数。第一个是配置对象，告诉浏览器网站需要访问什么。另外两个是成功或失败响应的回调函数。

创建一个简单的 HTML 文件，比如`chrome.html`，放在一个空目录中。在 HTML 文件中，添加以下代码：

```js
<video></video>
<script>
const $video = document.querySelector('video');
if (navigator.getUserMedia) {
  navigator.getUserMedia(
    {audio: true, video: true},
    stream => {
      $video.srcObject = stream;
      $video.muted = true; // Video muted to avoid feedback
      $video.onloadedmetadata = () => {
        $video.play();
      };
    },
    error => console.error(error)
  );
}
</script>
```

这段代码做了以下几件事：

+   它将在`$video`对象中创建对`<video>`元素的引用。

+   然后，它检查`navigator.getUserMedia`是否可用。这样做是为了避免在使用不兼容 WebRTC 的浏览器时出现错误。

+   然后，它使用以下三个参数调用`navigator.getUserMedia()`方法：

+   第一个参数指定网站对浏览器的需求。在我们的例子中，需要音频和视频。因此，我们应该传递`{audio: true, video: true}`。

+   第二个参数是成功的回调函数。用户接收的视频和音频流在传递给此函数的`stream`对象中可用。它将`srcObject`属性添加到`<video>`元素，其值为从用户输入设备接收的视频和音频的`stream`对象。当流加载时，将调用`$video.onloadedmetadata`，并且它将开始播放视频，因为我们在其回调函数中添加了`$video.play()`。

+   第三个参数是当用户拒绝网站访问摄像头或麦克风，或者发生其他错误且无法检索媒体流时调用的函数。此函数的参数是一个`error`对象，其中包含错误详细信息。

现在，使用`http-server`在本地主机中的 Chrome 中打开文件。首先，Chrome 将提示您允许访问设备的摄像头和麦克风。它应该如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00023.jpeg)

如果您点击允许，您应该看到通过前置摄像头传输的视频。我已经在以下网址设置了一个 JS fiddle：[`jsfiddle.net/1odpck45/`](https://jsfiddle.net/1odpck45/)，您可以在其中玩弄视频流。

一旦您点击允许或阻止，Chrome 将记住网站的偏好设置。要更改网站的权限，您必须点击地址栏左侧的锁定或信息图标，它将显示一个菜单，如下所示，您可以再次更改权限：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00024.jpeg)由于我们使用 http-server 或 Webpack 开发服务器进行开发，这些服务器在本地主机上运行，因此我们可以在 Chrome 中开发 WebRTC 应用程序。但是，如果要在生产环境中部署应用程序，则需要使用 HTTPS URL 进行部署。否则，应用程序将无法在 Chrome 上运行。

我们在 Chrome 上创建的视频在 Chrome 上运行得很好，但是如果您尝试在不同的浏览器 Firefox 上运行此代码，它将无法运行。这是因为 Firefox 对 MediaStream API 有不同的实现。

在 Firefox 中，您需要使用`navigator.mediaDevices.getUserMedia()`方法，该方法返回一个 Promise。可以使用`.then().catch()`链使用`stream`对象。

Firefox 的代码如下：

```js
<video></video>
<script>
const $video = document.querySelector('video');
navigator.mediaDevices.getUserMedia({audio: true, video: true})
.then(stream => {
  $video.srcObject = stream;
  $video.muted = true;
  $video.onloadedmetadata = function(e) {
    $video.play();
  };
})
.catch(console.error);
</script>
```

您可以在 Firefox 中运行此代码，方法是在与您创建`chrome.html`文件相同的目录中创建一个`firefox.html`文件，或者在您的 Firefox 浏览器中打开以下 JS fiddle：[`jsfiddle.net/hc39mL5g/`](https://jsfiddle.net/hc39mL5g/)。

为了生产环境设置 HTTPS 服务器超出了本书的范围。但是，根据您想要使用的服务器类型，可以很容易地在互联网上找到说明。

# 使用 Adapter.js 库

由于 WebRTC 在不同浏览器之间的实现不同，建议使用适配器（例如`adapter.js`库([`github.com/webrtc/adapter`](https://github.com/webrtc/adapter)））来隔离代码与浏览器实现的差异。通过包含`adapter.js`库，您可以在 Firefox 浏览器中运行为 Chrome 编写的 WebRTC 代码。尝试在 Firefox 中运行以下 JS fiddle，其中包含适用于 Chrome 的 WebRTC 代码，但包括`adapter.js`：[`jsfiddle.net/1ydwr4tt/`](https://jsfiddle.net/1ydwr4tt/)。

如果您想了解`<video>`元素，它是在 HTML5 中引入的。要了解有关使用视频元素的更多信息，请访问 w3schools 页面：[`www.w3schools.com/html/html5_video.asp`](https://www.w3schools.com/html/html5_video.asp)或 MDN 页面：[`developer.mozilla.org/en/docs/Web/HTML/Element/video`](https://developer.mozilla.org/en/docs/Web/HTML/Element/video)。

# RTCPeerConnection 和 RTCDataChannel

虽然 MediaStream API 用于从用户设备检索视频和音频流，但 RTCPeerConnection 和 RTCDataChannel API 用于建立对等连接并在它们之间传输数据。在我们的视频通话应用程序中，我们将使用 SimpleWebRTC 框架，它将抽象这些 API 并为我们提供一个更简单的对象来与其他设备建立连接。因此，我们不打算深入研究这两个 API。

然而，在使用 WebRTC 时有一件重要的事情要知道。尽管 WebRTC 是为了使设备直接连接而无需任何服务器而创建的，但目前不可能实现这一点，因为要连接到设备，您需要知道设备在互联网上的位置，即设备在互联网上的 IP 地址。但是，一般来说，设备只会知道它们的本地 IP 地址（类似于 192.168.1.x）。公共 IP 地址由防火墙或路由器管理。为了克服这个问题并将确切的 IP 地址发送给其他设备，我们需要信令服务器，例如**STUN**或**TURN**。

设备将向 STUN 服务器发送请求，以检索其公共 IP 地址，并将该信息发送给其他设备。这是广泛使用的，并适用于大多数情况。但是，如果路由器或防火墙的 NAT 服务为设备的每个连接分配不同的端口号，或者设备的本地地址不断变化，那么从 STUN 服务器接收的数据可能不足，因此必须使用 TURN 服务器。TURN 服务器充当两个设备之间的中继，即设备将数据发送到 TURN 服务器，然后 TURN 服务器将数据中继到其他设备。但是，TURN 服务器不像 STUN 服务器那样高效，因为它消耗了大量服务器端资源。

通常会使用**ICE**实现，它确定两台设备之间是否需要 STUN 或 TURN 服务器（在大多数情况下会选择 STUN，而使用 TURN 作为最后的手段），从而保持连接更有效和稳定。

使用 WebRTC 进行实时通信是一个很大的主题，但如果您有兴趣了解更多关于 WebRTC 的信息，可以访问 WebRTC 的官方网站[`webrtc.org/`](https://webrtc.org/)，查看一些可用于开始使用 WebRTC 的各种资源。

# 构建视频通话应用程序

我们将在本章中构建的应用程序是一个简单的视频会议应用程序，您可以在其中创建一个房间，然后将房间 URL 分享给其他人。谁点击 URL 将能够加入通话。对于 UI 部分，我们可以将参与者的视频排列在小框中，当您点击参与者时，我们可以放大视频。这种类型的视频通话应用程序现在广泛使用。以下是应用程序在桌面浏览器上的外观：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00025.jpeg)

蓝色框将显示您的视频，而其他框应显示其他参与者的视频。当参与者数量增加时，行将自动换行到新行（flex-wrap）。在移动设备上，我们可以将视频显示为列而不是行，因为对于较小的屏幕来说，这样会更有效。因此，对于手机，应用程序应如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00026.jpeg)

这些框只是占位符。对于真实的视频，我们可以使用 margin/padding 在每个视频之间留出间距。此外，为了分享链接，我们可以使用一个点击复制按钮，这将非常用户友好。现在你已经很好地理解了我们要构建的内容，让我们开始吧！

# 初始项目设置

初始设置与我们在之前的活动注册应用程序中所做的并没有太大的不同。在 VSCode 的`Chapter04`文件夹中打开起始文件并创建一个`.env`文件。从`.env.example`文件中，你应该知道，对于这个应用程序，我们只需要一个环境变量`NODE_ENV`，其值只在生产环境下为`production`。对于开发，我们可以简单地为其分配其他值，比如`dev`。

创建了`.env`文件后，在 VSCode 的终端或本机终端（导航到项目根文件夹）中运行`npm install`来安装项目的所有依赖项。之后，在终端中运行`npm run webpack`，这应该会启动 Webpack 开发服务器。

# 为页面添加样式

你知道如何使用 Webpack 开发服务器。所以，让我们继续添加样式到我们的页面。首先，浏览`index.html`文件，了解页面的基本结构。

页面的主体分为两个部分：

+   导航栏

+   容器

容器进一步分为三个部分：

1.  首先是`create-room-area`，其中包含创建具有房间名称的新房间所需的输入字段。

1.  其次是`info-area`，其中包含有关房间的信息（房间名称和房间 URL）。它还有两个按钮，用于复制房间 URL（当前使用`.hidden` Bootstrap 样式类进行隐藏）。

1.  最后是`video-area`，用于显示所有参与者的视频。

首先，在`src/css/styles.css`文件中添加以下代码，以防止容器部分与导航栏重叠：

```js
body {
  padding-top: 65px;
}
```

启用 Webpack 热重载后，你应该立即看到 CSS 的更改。`create-room-area`使用默认的 Bootstrap 样式看起来很好。所以，让我们继续进行第二部分，info-area。要处理`info-area`，暂时从 HTML 中删除`.hidden`类。还要从两个按钮中删除`.hidden`，并在段落元素中添加一些文本，其中包含房间 URL。如果房间 URL 和按钮在同一行对齐会很好。为了对齐它们，在`styles.css`文件中添加以下 CSS：

```js
.room-text {
  display: flex;
  flex-direction: row;
  padding: 10px;
  justify-content: flex-start;
  align-items: center;
  align-content: center;
}
.room-url {
  padding: 10px;
}
.copy {
  margin-left: 10px;
}
.copied {
  margin-left: 10px;
}
```

对于`video-area`，视频需要在移动设备上以列的形式排列，而在桌面上应以行的形式排列。因此，我们可以使用媒体查询为其分配不同的样式。此外，对于视频元素（`.video-player`）的大小，我们可以将`max-width`和`max-height`设置为 25 视口宽度，以使其在所有设备上具有响应性的尺寸。在你的`styles.css`文件中，添加以下样式：

```js
@media only screen and (max-width: 736px) {
  .video-area {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
}
@media only screen and (min-width: 736px) {
  .video-area {
    display: flex;
    flex-direction: row;
    flex-wrap: wrap;
  }
}
.video-player {
  max-height: 25vh;
  max-width: 25vh;
  margin: 20px;
}
```

现在所需的样式就是这些。所以，让我们开始编写应用程序的 JavaScript。

# 构建视频通话应用程序

一切就绪，让我们开始编码。像以前的应用程序一样，打开你的`home.js`文件并创建你的`Home`类和构造函数：

```js
class Home {
  constructor() {

  }
}
```

之后，创建`Home`类的一个实例，并将其分配给一个对象`home`，如下所示：

```js
const home = new Home();
```

我们以后会用到 home 对象。现在，通过在项目根文件夹的终端中运行以下命令，将`SimpleWebRTC`包添加到我们的项目中：

```js
npm install -S simplewebrtc
```

并在你的`home.js`文件顶部添加以下导入语句：

```js
import SimpleWebRTC from 'simplewebrtc';
```

根据`SimpleWebRTC`文档，我们需要创建一个`SimpleWebRTC`类的实例，并进行一些配置以在我们的应用程序中使用它。在你的`home.js`文件中，在`Home`类之前，添加以下代码：

```js
const webrtc = new SimpleWebRTC({
  localVideoEl: 'localVideo',
  remoteVideosEl: '',
  autoRequestMedia: true,
  debug: false,
});
```

您的应用程序现在应该请求权限来访问摄像头和麦克风。这是因为在幕后，`SimpleWebRTC`已经开始设置一切需要启动视频通话的工作。如果您点击“允许”，您应该会看到您的视频出现在一个小矩形框中。这就是您在之前的代码中添加的对象中的配置所做的事情：

+   `localVideoEl`：包含应该包含您本地视频的元素的 ID。在这里，我们的`index.html`文件中的`video#localVideo`元素将显示我们自己的视频，因此选择它作为其值。

+   `remoteVideosEl`：包含需要添加远程视频的容器的 ID。我们还没有创建该元素，最好稍后再添加视频，所以将其留空。

+   `autoRequestMedia`：用于提示用户允许访问摄像头和麦克风的权限，需要设置为`true`。

+   `debug`：如果为 true，它将在控制台中打印所有的`webrtc`事件。我已将其设置为`false`，但在您的系统上将其设置为 true 以查看事件发生。

默认情况下，`SimpleWebRTC`使用由 Google 提供的免费 STUN 服务器，即`stun.l.google.com:19302`。在大多数情况下，这个 STUN 服务器就足够了，除非您身处一些具有复杂路由协议的企业防火墙之后。否则，您可以设置自己的 ICE 配置，包括 STUN 和 TURN 服务器。为此，您需要安装 signalmaster（[`github.com/andyet/signalmaster`](https://github.com/andyet/signalmaster)），并将 ICE 配置详细信息添加到前面提到的构造函数中。然而，这超出了本书的范围。我们将简单地继续使用默认配置。

对于我们的第一步，我们将在构造函数中创建类变量和对 DOM 元素的引用：

```js
constructor() {
  this.roomName = '';

  this.$createRoomSection = document.querySelector('#createRoomSection');
  this.$createRoomButton = document.querySelector('#createRoom');
  this.$roomNameInput = document.querySelector('#roomNameInput');

  this.$infoSection = document.querySelector('#infoSection');
  this.$roomName = document.querySelector('#roomNameText');
  this.$roomUrl = document.querySelector('#roomUrl');
  this.$buttonArea = document.querySelector('.room-text');
  this.$copy = document.querySelector('.copy');
  this.$copied = document.querySelector('.copied');

  this.$remotes = document.querySelector('.video-area');
  this.$localVideo = document.querySelector('#localVideo');
}
```

这很多，但它们都是我们应用程序不同步骤所需的。我们在这里创建的唯一变量是`roomName`，正如其名称所示，它包含了房间的名称。其他的都是对 DOM 元素的引用。

# 创建房间

该应用的第一步是创建一个房间，以便其他成员可以加入房间进行通话。根据当前的 UI 设计，当用户点击“创建房间”按钮时，我们需要创建房间。因此，让我们在该按钮上注册一个点击事件处理程序。

到目前为止，我们一直在使用不同的方法来处理事件：

+   在我们的待办事项列表应用程序中，我们在 HTML 中添加了`onclick`属性来调用 JavaScript 函数的`onclick`事件。

+   在 Meme Creator 中，我们为每个元素附加了事件侦听器，我们希望监听特定事件的发生（keyup、change 和 click 事件）。在事件注册表单中也是如此，我们添加了一个事件侦听器来监听表单提交操作。

+   还有另一种方法，即将回调函数添加到 DOM 元素的引用的事件属性中。在我们的情况下，我们需要检测“创建房间”按钮的点击事件。我们可以这样处理：

```js
this.$createRoomButton.onclick  = () => { }
```

因此，每当单击“创建房间”按钮时，它将执行前述函数中编写的代码。完全取决于您和您的要求来决定使用哪种事件处理程序。通常，第一种方法会被避免，因为它会将您的 JavaScript 代码暴露在 HTML 中，并且在大型项目中难以跟踪 HTML 中调用的所有 JavaScript 函数。

如果您有大量的元素，比如表格中的 100 行，为每一行附加 100 个事件侦听器是低效的。您可以使用第三种方法，通过将函数附加到每行 DOM 元素的引用的`onclick`方法，或者您可以将单个事件侦听器附加到行的父元素，并使用该事件侦听器来监听其子元素的事件。

有关所有 DOM 事件的列表，请访问 W3Schools 页面：[`www.w3schools.com/jsref/dom_obj_event.asp`](https://www.w3schools.com/jsref/dom_obj_event.asp)。

在我们的应用程序中，我们需要处理很多点击事件。因此，让我们在`Home`类中创建一个方法来注册所有的点击事件：

```js
registerClicks() {
}
```

并在构造函数中调用此方法：

```js
constructor() {
  ...
  this.registerClicks();
}
```

在`registerClicks()`方法中，添加以下代码：

```js
this.$createRoomButton.onclick  = () => { }
```

当用户单击“创建房间”按钮时，需要执行一些操作：

+   获取房间名称。但是房间名称不能包含任何会导致 URL 出现问题的特殊字符

+   使用`SimpleWebRTC`创建一个房间

+   将用户重定向到为房间创建的 URL（带有房间名称作为查询字符串的 URL）

+   显示他/她可以与其他需要参与通话的人分享的 URL

您应该在您在上述代码中创建的`onclick`方法中编写以下代码：

```js
this.roomName  =  this.$roomNameInput.value.toLowerCase().replace(/\s/g, '-').replace(/[^A-Za-z0-9_\-]/g, '');
```

这将获取在输入字段中键入的房间名称，并使用正则表达式将其转换为 URL 友好的字符。如果房间名称不为空，我们可以继续在`SimpleWebRTC`中创建房间：

```js
if(this.roomName) {  webrtc.createRoom(this.roomName, (err, name) => {
    if(!err) {
      // room created
    } else {
      // unable to create room
      console.error(err);
    }
  });
}
```

上述代码执行以下操作：

+   `if`条件将检查房间名称是否不为空（空字符串为假）。

+   `webrtc.createRoom()`将创建房间。它接受两个参数：第一个是房间名称字符串，第二个是在创建房间时执行的回调函数。

+   回调函数具有参数`err`和`name`。通常，我们应该检查过程是否成功。因此，`if(!err) {}`将包含在过程成功时执行的代码。`name`是由`SimpleWebRTC`创建的房间名称。

在`if(!err)`条件中，添加以下代码：

```js
const  newUrl  =  location.pathname  +  '?'  +  name; history.replaceState({}, '', newUrl);
this.roomName = name; this.roomCreated();
```

`location`对象包含有关当前 URL 的信息。`location.pathname`用于设置或获取网页的当前 URL。因此，我们可以通过将房间名称附加到其中来构造 URL。因此，如果您当前的 URL 是`http://localhost:8080/`，那么在创建房间后，您的 URL 应该变为`http://localhost:8080/?roomName`。

要替换 URL 而不影响当前页面，我们可以使用 History Web API 提供的`history`对象。`history`对象用于操作浏览器的历史记录。如果要执行用户单击浏览器后退按钮时发生的后退操作，可以按照以下步骤进行：

```js
history.back();
```

同样，要前进，可以按照以下步骤进行：

```js
history.forward();
```

但是我们在应用程序中需要做的是在不影响浏览器历史记录的情况下更改当前的 URL。也就是说，我们需要将 URL 从`http://localhost:8080/`更改为`http://localhost:8080/?roomName`，而不影响浏览器的后退或前进按钮。

对于这样复杂的操作，您可以使用 HTML5 中引入的`pushState()`和`replaceState()`方法来处理历史对象。`pushState()`在浏览器上创建一个新的历史记录条目，并更改页面的 URL，而不影响当前页面。`replaceState()`也是一样，但是它替换当前条目，非常适合我们的目的。

`pushState()`和`replaceState()`方法都接受三个参数。第一个是`state`（一个 JSON 对象），第二个是`title`（字符串），第三个是新的 URL。这就是`pushState()`和`replaceState()`的工作原理：

+   每次调用`pushState()`或`replaceState()`时，都会触发`window`对象中的`popstate`事件。第一个参数，状态对象，由该事件的回调函数使用。我们现在用不到它，所以将其设置为空对象。

+   目前，大多数浏览器都会忽略第二个参数，所以我们将其设置为空字符串。

+   第三个参数 URL 是我们真正需要的。它将浏览器的 URL 更改为提供的 URL 字符串。

由于房间已创建并且 URL 已更改，我们需要隐藏`.create-room-area` div 并显示`.info-area` div。这就是为什么我添加了`this.roomCreated()`方法。在`Home`类中，创建新方法：

```js
roomCreated() {
  this.$infoSection.classList.remove('hidden');
  this.$createRoomSection.classList.add('hidden');
  this.$roomName.textContent = `Room Name: ${this.roomName}`;
  this.$roomUrl.textContent = window.location.href;
}
```

这个方法将显示信息部分，同时隐藏创建房间部分。此外，它将使用`textContent()`方法更改房间名称和 URL，该方法更改了相应 DOM 元素中的文本。

有关位置对象的更多信息可以在 w3schools 页面上找到：[`www.w3schools.com/jsref/obj_location.asp`](https://www.w3schools.com/jsref/obj_location.asp)。有关历史对象的更多信息可以在 MDN 页面上找到：[`developer.mozilla.org/en-US/docs/Web/API/History`](https://developer.mozilla.org/en-US/docs/Web/API/History)。此外，如果你想学习如何操纵浏览器历史记录，可以访问[`developer.mozilla.org/en-US/docs/Web/API/History_API`](https://developer.mozilla.org/en-US/docs/Web/API/History_API)。

# 向你的房间添加参与者

你有一个活跃的房间和房间 URL，你需要邀请其他人。但是如果有一个点击复制功能来复制 URL，那不是更方便吗？这实际上是一个非常好的功能。因此，在我们向房间添加参与者之前，让我们构建一个点击复制功能。

# 点击复制文本

目前，信息区的外观是这样的：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00027.jpeg)

对于点击复制功能，如果你将鼠标悬停在房间 URL 上，它应该显示一个复制按钮：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00028.jpeg)

如果你点击复制按钮，它应该复制文本并变成已复制按钮：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00029.jpeg)

对于这个功能，我们需要添加一些事件监听器。因此，在你的 home 类中，创建一个新的方法`addEventListeners()`，并在构造函数中调用它：

```js
class Home {
  constructor() {
    ...
    this.addEventListeners();
  }

  addEventListeners() {
  }
}
```

包含复制按钮的 div 的引用存储在`this.$buttonArea`变量中。每当鼠标进入 div 时，它将触发一个`mouseenter`事件。当这个事件发生在`$buttonArea`中时，我们需要从复制按钮中移除`.hidden`类。

在你的`addEventListeners()`方法中，添加以下代码：

```js
this.$buttonArea.addEventListener('mouseenter', () => {
  this.$copy.classList.remove('hidden');
});
```

页面将重新加载，你将不得不再次创建一个房间。如果你现在将鼠标指针悬停在房间 URL 上，它应该会显示复制按钮。当指针离开`div`时，我们还需要隐藏按钮。类似于`mouseenter`，当指针离开`div`时，`div`将触发一个`mouseout`事件。因此，再次在前面的代码旁边添加以下代码：

```js
this.$buttonArea.addEventListener('mouseout', event => {
  this.$copy.classList.add('hidden');
  this.$copied.classList.add('hidden');
});
```

现在，再次尝试将鼠标指针悬停在房间 URL 上。令人惊讶的是，它并没有按预期工作。它应该有作用，但它没有。这是因为`mouseout`事件，当你的指针进入`$buttonArea`的子元素时，它也会触发。它将子元素视为`div`的`外部`。为了解决这个问题，我们需要过滤传递给回调函数的`event`对象，这样如果指针通过进入子元素而移动到`外部`，就不会发生任何操作。

这个有点棘手，但是如果你在控制台中打印事件对象，你会看到有很多属性和方法包含了事件的所有细节。`toElement`属性或`relatedTarget`属性将包含指针移动到的元素，具体取决于浏览器。因此，我们需要检查该元素的父元素是否是`$buttonArea`。如果是，我们应该阻止任何操作发生。为了做到这一点，将前面的代码更改为以下内容：

```js
this.$buttonArea.addEventListener('mouseout', event => {
  const e = event.toElement || event.relatedTarget;
  if(e) {
    if (e.parentNode == this.$buttonArea || e == this.$buttonArea) {
      return;
    }
  }
  this.$copy.classList.add('hidden');
  this.$copied.classList.add('hidden');
});
```

注意这一行：

```js
const e = event.toElement || event.relatedTarget;
```

这是一个短路评估。它的作用是，如果第一个值为真，它将把它赋给常量`e`。如果它为假，或运算符将评估第二个值，并将其值赋给`e`。你可以声明任意数量的值。比如：

```js
const fun = false || '' || true || 'test';
```

在这里，fun 的值将是列表中第一个真值语句，因此它的值将为 true。`'test'`也是一个真值，但它不会被评估，因为在它之前有一个真值。这种类型的赋值通常被使用，对于某些任务来说非常方便。

现在，`e`对象包含目标元素。所以，我们只需要检查`e`是否存在（以防止异常），如果存在，是否其父元素或元素本身是`$buttonArea`。如果是真的，我们只需返回。这样，回调函数在不隐藏复制和已复制按钮的情况下停止执行。我们也隐藏已复制按钮，因为当用户点击复制按钮时，我们将使其可见。

尝试在应用程序中再次悬停在房间 URL 上，应该按预期工作。最后一步是在用户点击复制按钮时复制 URL。因此，让我们在我们的`Home`类中早期创建的`registerClicks()`方法中注册点击。在`registerClicks()`方法中，添加处理点击复制和已复制按钮的代码，并在`Home`类中创建一个新方法`copyUrl()`来执行复制操作：

```js
registerClicks() {
  ...
  this.$copy.onclick = () => {
    this.copyUrl();
  };
  this.$copied.onclick = () => {
    this.copyUrl();
  };
}

copyUrl() {

}
```

在前面的代码中，在`registerClicks()`方法中，点击复制按钮和已复制按钮都将调用类的`copyUrl()`方法。我们需要在`copyUrl()`方法中添加复制文本的代码。

要复制文本，首先，我们需要从中复制文本的节点（DOM 元素）的范围。为此，创建一个范围对象并选择包含房间 URL 文本的`this.$roomUrl`节点。在`copyUrl()`方法中，添加以下代码：

```js
const range = document.createRange();
range.selectNode(this.$roomUrl);
```

现在，范围对象包含元素`$roomUrl`作为所选节点。然后，我们需要选择节点中的文本，就像用户通常使用光标选择文本一样。`window`对象有`getSelection()`方法，我们可以用于此目的。我们必须删除所有范围以清除先前的选择，然后选择一个新范围（即我们之前创建的范围对象）。在前面的代码中添加以下代码：

```js
window.getSelection().removeAllRanges();
window.getSelection().addRange(range);
```

最后，我们不知道用户的浏览器是否支持执行复制命令，所以我们在`try{} catch(err){}`语句中进行复制，以便如果发生任何错误，可以在 catch 语句中处理。`document.execCommand('copy')`方法将复制所选范围内的文本并将其作为字符串返回。此外，我们需要在复制成功时隐藏复制按钮并显示已复制按钮。复制的代码如下：

```js
try {
  const successful = document.execCommand('copy');
  const msg = successful ? 'successful' : 'unsuccessful';
  console.log('Copying text command was ' + msg);
  this.$copy.classList.add('hidden');
  this.$copied.classList.remove('hidden');
} catch(err) {
  console.error(err);
}
```

在添加了前面的代码之后，在应用程序中创建一个房间，然后尝试再次点击复制。它应该变成已复制按钮，并且房间 URL 文本将被突出显示，因为我们选择了文本，就像我们用 JavaScript 和光标选择文本一样。但是，一旦复制完成，清除选择会更好。因此，在`copyUrl()`方法的末尾添加这行：

```js
window.getSelection().removeAllRanges();
```

这将清除选择，所以下次点击复制时，房间 URL 文本将不会被突出显示。然后，您可以简单地粘贴所选的 URL 到任何您想要分享的地方。

# 加入房间

现在您有了一个链接，我们需要让用户使用该链接加入房间。这个过程很简单：当用户打开链接时，他会加入房间，并且所有参与者的视频都会显示给他。要让用户加入房间，`SimpleWebRTC`有`joinRoom('roomName')`方法，其中房间名称字符串作为参数传递。一旦用户在房间里，它将寻找房间中连接的其他用户的视频，并为它找到的每个视频触发`videoAdded`事件，以及一个回调函数，其中包含视频对象和该用户的对等对象。

让我们制定一下过程应该如何工作：

+   首先，我们需要检查用户输入的 URL 是否在其查询字符串中包含房间名称。也就是说，如果以`'?roomName'`结尾。

+   如果房间名称存在，那么我们应该让用户加入房间，同时隐藏`.create-room-area` div，并显示`.info-area` div 以显示房间详情。

+   然后，我们需要监听`videoAdded`事件，如果触发了事件，我们将视频添加到`.video-area div`中。

`SimpleWebRTC`在加载完成后会触发`readyToCall`事件。它还有`on()`方法来监听触发的事件。我们可以使用`readyToCall`事件来检查 URL 中的房间名称。这段代码应该在`Home`类之外。因此，在调用`Home`类构造函数的那一行之后，添加以下代码：

```js
webrtc.on('readyToCall', () => {
  if(location.search) {
    const locationArray = location.search.split('?');
    const room = locationArray[1];
  }
});
```

我们使用 location 对象来获取 URL。首先，我们需要检查 URL 是否包含查询字符串，使用`location.search`。因此，我们在 if 条件中使用它，如果它包含查询字符串，我们可以继续进行处理。

`split()`方法将字符串拆分为由传递给它的值分隔的子字符串数组。URL 将如下所示：

```js
http://localhost:8080/?myRoom
```

`location.search`将返回 URL 的查询字符串部分：

```js
'?myRoom'
```

因此，`location.search.split('?')`将把字符串转换为以下数组：

```js
[ '', 'myRoom']
```

我们在数组的索引 1 处有房间名称。像这样写是可以的，但是在这里我们可以使用短路评估。我们之前使用了 OR 运算符进行评估，它将获取第一个真值。在这种情况下，我们可以使用 AND 运算符，它将获取第一个假值，或者如果没有假值，则获取最后一个真值。上述代码将简化为以下形式：

```js
webrtc.on('readyToCall', () => {
  const room = location.search && location.search.split('?')[1];
});
```

如果 URL 不包含查询字符串，`location.search`将是一个空字符串（`""`），这是一个假值。因此，房间的值将是一个空字符串。

如果 URL 包含带有房间名称的查询字符串，那么`location.search`将返回`'?roomName'`，这是一个真值，所以下一个语句`location.search.split('?')[1]`将被评估，它执行分割并返回数组中的第一个索引（房间名称）。由于它是最后一个真值，room 常量现在将包含房间名称字符串！我们使用短路评估将三行代码简化为一行代码。

关于短路评估的详细信息可以在以下网址找到：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_Operators#Short-circuit_evaluation`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Logical_Operators#Short-circuit_evaluation)。

# 设置器和获取器

我们只需要添加一行代码来让用户加入房间：

```js
webrtc.joinRoom(room);
```

这将使用户加入房间，但是一旦用户进入房间，我们需要隐藏`.create-room-area` div 并显示`.info-area` div。这些都在`Home`类的`roomCreated()`方法中。但是该方法依赖于`this.roomName`类变量，该变量应该包含房间名称。因此，我们需要更新一个类变量并从类外部调用`class`方法。

尽管我们可以使用之前创建的`home`对象来做到这一点，但如果我们只能更新类的 room 属性并且它将自动执行操作，那将更有意义。为此，我们可以使用设置器。设置器是用于为对象的属性分配新值的特殊方法。我们以前已经多次使用过获取器和设置器。还记得我们如何获取输入字段的值吗？

```js
const inputValue = this.$roomNameInput.value
```

在这里，值属性是一个获取器。它从`$roomNameInput`对象返回一个值。但是，如果我们这样做：

```js
$roomNameInput.value = 'New Room Name'
```

然后，它将把输入字段的值更改为`'New Room Name'`。这是因为值现在充当设置器，并更新了`$roomNameInput`对象内的属性。

我们将为我们的`Home`类创建一个设置器来加入一个房间。创建一个设置器很简单；我们只需创建一个以`set`关键字为前缀的方法，该方法应该有*正好一个参数*。在您的`Home`类中，添加以下代码：

```js
set room(room) {
  webrtc.joinRoom(room);
  this.roomName = room;
  this.roomCreated();
}
```

现在，在您的`readyToCall`事件处理程序中使用设置器（仅当房间不是空字符串时）：

```js
const home = new Home();

webrtc.on('readyToCall', () => {
  const room = location.search && location.search.split('?')[1];
  if(room) home.room = room;
});
```

添加代码后，在视频通话应用中创建一个房间，然后复制 URL 并粘贴到新标签中。它应该会自动从 URL 获取房间名称并加入房间。如果您能看到房间信息，那么您就可以开始了。我们正接近应用程序的最后阶段--添加和删除视频。

如果和 else 条件后面只有一个语句，不需要`{}`大括号。也就是说，`if (true) console.log('true'); else console.log('false');`将正常工作！但应该避免这样做，因为最好始终使用带有`{}`大括号的`if else`条件。

要创建一个 getter，您只需在方法前面加上`get`而不是`set`，但是该方法不应包含*参数*，并且应*返回一个值*。比如，在您的`Home`类中，您需要使用 getter 知道房间名称。然后，您可以添加以下方法：

```js
get room() {
  return this.roomName;
}
```

如果您尝试在类外部使用`console.log(home.room)`，您应该会得到存储在`roomName`类变量中的值。

# 添加和删除视频

类似于`readyToCall`事件，`SimpleWebRTC`将为在房间中找到的每个视频触发`videoAdded`事件，具有具有视频对象和包含 ID（该用户的唯一 ID）的对等对象的回调函数。

为了测试多个视频，我们将在同一系统的同一浏览器中打开两个标签。这可能会导致反馈损坏您的音频设备，所以保持音量静音！

在`Home`类中创建一个新方法`addRemoteVideo($video, peer)`，如下所示：

```js
class Home {
  ...
  addRemoteVideo($video, peer) {
  }
}
```

让我们为`videoAdded`事件添加另一个事件处理程序，就像我们为`readToCall`事件所做的那样：

```js
webrtc.on('videoAdded', ($video, peer) =>  home.addRemoteVideo($video, peer)); 
```

每当添加视频时，它将调用`Home`类的`addRemoteVideo`方法，并传入视频对象和对等对象。我们有一个`.video-area`的 div，它应该包含所有的视频。因此，我们需要构建一个类似于用于本地视频的新 div 元素，例如：

```js
<div class="video-container" id="container_peerid">
  <video class="video-player"></video>
</div>
```

然后，我们应该将此元素附加到`.video-area` div，它当前由`this.$remotes`变量引用。这很简单，就像我们在上一章中添加`script`元素一样。在您的`addRemoteVideo()`方法中，添加以下代码：

```js
addRemoteVideo($video, peer) {
  const $container = document.createElement('div');
  $container.className = 'video-container';
  $container.id = 'container_' + webrtc.getDomId(peer);

  $video.className = 'video-player';

  $container.appendChild($video);

  this.$remotes.appendChild($container);
}
```

上述代码执行以下操作：

+   首先，我们使用`document.createElement('div')`方法创建一个`div`元素，并将其分配给`$container`对象。

+   然后，我们将`$container`的类名设置为`'video-container'`，ID 设置为`'container_peerid'`。我们可以使用`webrtc.getDomId()`方法从我们收到的对等对象中获取对等 ID。

+   我们收到的`$video`对象是一个 HTML 元素，就像`$container`一样。因此，我们将其分配为类名`'video-player'`。

+   然后，作为最后一步，我们将`$video`作为子元素附加到`$container`中，最后将`$container`作为子元素附加到`this.$remotes`中。

这将使用类和 ID 构造我们需要的 HTML。当用户离开房间时，将触发`videoRemoved`事件，这类似于`videoAdded`事件。每当用户离开房间时，我们需要使用对等 ID 来删除包含 ID`'container_peerid'`的 div，其中`peerid`是离开的用户的 ID。为此，请添加以下代码：

```js
class Home {
  ...

  removeRemoteVideo(peer) {
    const $removedVideo = document.getElementById(peer ? 'container_' + webrtc.getDomId(peer) : 'no-video-found');
    if ($removedVideo) {
      this.$remotes.removeChild($removedVideo);
    }
  }

}
...

webrtc.on('videoRemoved', ($video, peer) => home.removeRemoteVideo(peer));
```

`removeRemoteVideo()`方法将使用对等 ID 查找包含远程视频的 div，并使用`removeChild()`方法从`this.$remotes`对象中删除它。

是时候测试我们的视频通话应用了。在 Chrome 中打开应用程序并创建房间。复制房间 URL 并粘贴到新标签中（保持音量静音！）。可能需要几秒钟，但除非 STUN 对您不起作用，否则您应该在每个标签中看到两个视频。您正在在标签之间传输视频。

第一个视频是你的视频。如果你关闭其中一个标签，你会看到第二个视频会从另一个标签中移除。在我们在其他设备上测试这个应用之前，还有一个功能会让这个应用看起来更棒。那就是增加所选视频的大小。

# 选择视频

目前，所有的视频都很小。因此，我们需要一个功能来放大视频，比如：

+   在桌面上，点击视频将增加视频的大小，并将其移动到视频列表的第一个位置

+   在手机上，点击视频只会增加视频的大小

这听起来不错。为了实现这一点，让我们在我们的`styles.css`文件中添加一些样式：

```js
@media only screen and (max-width: 736px) {
  .video-selected {
    max-height: 70vw;
    max-width: 70vw;
  }
}
@media only screen and (min-width: 736px) {
  .video-selected {
    max-height: 50vh;
    max-width: 50vh;
  }
  .container-selected {
    order: -1;
  }
}
```

我们使用媒体查询添加了两组样式。一组用于手机（`max-width: 736px`），另一组用于桌面（`min-width: 736px`）。

对于每次点击视频，我们应该为该视频添加`.video-selected`类，并为该视频的父 div 添加`.container-selected`类：

+   在手机上，它将把视频的大小增加到视口宽度的 70%。

+   在桌面上，它将把大小增加到视口宽度的 50%，并且还会给其父 div 分配`order: -1`。这样，由于父 div 是 flex 的一部分，它将成为 flex 元素的第一个项目（但其他元素不应该在其样式中包含 order）。

在你的`Home`类中，添加以下方法：

```js
clearSelected() {
  let $selectedVideo = document.querySelector('.video-selected');
  if($selectedVideo) {
    $selectedVideo.classList.remove('video-selected');
    $selectedVideo.parentElement.classList.remove('container-selected');
  }
}
```

这将找到包含`.video-selected`类的视频，并从该视频和该视频的父 div 中移除`.video-selected`类和`.container-selected`类。这很有用，因为我们可以在选择另一个视频之前调用它来清除已选择的视频。

我们可以在`registerClicks()`方法中为本地视频注册点击事件。在`registerClicks()`方法中，添加以下代码：

```js
this.$localVideo.onclick = () => {
  this.clearSelected();
  this.$localVideo.parentElement.classList.add('container-selected');
  this.$localVideo.classList.add('video-selected');
};
```

这将为视频元素及其父级 div 添加所需的类。对于远程视频，我们不能在这里注册点击，因为我们动态创建这些元素。因此，我们要么创建一个事件监听器，要么在创建远程视频元素时注册点击事件。

在这里为每个视频创建一个事件监听器并不太有效，因为当用户离开时，视频将被移除，所以我们将有不需要的事件监听器运行在每个视频上。我们将不得不使用`removeEventListener()`方法来移除这些事件监听器，或者通过在父 div`.video-area`上创建一个事件监听器来避免这种情况。不过，这意味着我们需要筛选`.video-area`内的每次点击，以检查该点击是否是在视频上进行的。

显然，当视频元素被创建时，使用`onclick()`方法注册点击更简单。这样可以避免处理事件监听器的麻烦。在你的`addRemoteVideo()`方法中，在现有代码之后添加以下代码：

```js
$video.onclick = () => {
  this.clearSelected();
  $container.classList.add('container-selected');
  $video.classList.add('video-selected');
};
```

现在尝试在 Chrome 中点击视频。你应该看到视频会增大并移动到列表的第一个位置。恭喜！你已经成功构建了你的视频通话应用！是时候测试视频通话了。

# 视频通话

你已经准备好应用程序了，所以让我们在本地测试一下。首先，为你的应用生成生产构建。你之前在事件注册应用中已经做过这个了。你需要在你的`.env`文件中设置`NODE_ENV=production`。

之后，在你的项目根目录中，关闭 Webpack 开发服务器，运行`npm run webpack`命令。它应该会为你的 JS 和 CSS 文件生成生产构建。文件名将在`dist/manifest.json`文件中。在你的`index.html`页面中包含这些 CSS 和 JS 文件。

现在，在您的项目根文件夹中运行`http-server`。它应该打印出两个 IP 地址。在浏览器中打开以 192 开头的那个。这个 IP 地址对您局域网中的所有设备都是可访问的，除非您使用防火墙阻止了端口。然而，Chrome 将无法显示您的视频！这是因为`getUserMedia()`方法只能在本地主机和 HTTPS URL 中工作。由于我们的本地地址只使用 HTTP，视频将无法工作。

我们可以通过在公共服务器上部署我们的 WebRTC 应用程序并使用来自证书颁发机构的 SSL 证书来添加 HTTPS。然而，对于我们的本地开发环境，我们可以使用自签名证书。来自证书颁发机构的 SSL 证书将受到所有浏览器的信任，但自签名证书将不受信任，因此会显示警告，我们应该在浏览器上手动选择信任该网站的选项。因此，自签名证书不适用于生产，只应用于开发目的。

创建自签名证书是一个复杂的过程，但幸运的是，有一个`npm`包可以在一行命令中完成这个过程。我们需要全局安装这个包，因为它像`http-server`一样是一个命令行工具。在您的终端中运行以下命令：

```js
npm install -g local-ssl-proxy
```

Linux 用户可能需要在他们的命令中添加`sudo`以全局安装软件包。默认情况下，`http-server`将从端口号`8080`提供您的文件。比如，如果您当前的 URL 如下：

```js
http://192.168.1.8:8080
```

然后，打开另一个终端并运行以下命令：

```js
local-ssl-proxy --source 8081 --target 8080
```

在这里，源是新的端口号，目标是 http-server 正在运行的端口号。然后，您应该在 Chrome 中使用新的端口号和`https://`前缀打开相同的 IP 地址，如下面的代码块所示：

```js
https://192.168.1.8:8081
```

如果您在 Chrome 中打开此页面，您应该会收到类似以下截图的警告。在这种情况下，请选择高级，如下图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00030.jpeg)

点击高级后，您将看到一个类似以下图像的页面，您应该点击继续链接：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-ex/img/00031.jpeg)

您现在可以使用这个 HTTPS URL 在连接到您的局域网的任何设备上打开应用程序。确保设备之间有足够的距离，以免造成反馈。

# 总结

希望您在构建视频通话应用程序时度过了愉快的时光。在本章中，我们使用 JavaScript 做了一些新的事情，并学习了一些新概念，如 JavaScript WebRTC API 和 SimpleWebRTC 框架。在这个过程中，我们做了很多很酷的事情，比如操纵浏览器历史记录，使用 JavaScript 选择文本，以及处理 URL。此外，我们使用短路评估缩短了一些代码，并学习了在 JavaScript 中操纵类变量的设置器和获取器。

`SimpleWebRTC`还带有许多其他事件和操作，允许您在应用程序中执行更多操作，例如静音麦克风，静音其他人的音频等。如果您感兴趣，可以查看 SimpleWebRTC 主页获取更多示例。

我们知道如何创建可重用的 JavaScript 模块，这是我们在上一章中做的。在下一章中，我们将进一步迈出一步，使用 Web 组件构建我们自己的可重用的 HTML 元素。
