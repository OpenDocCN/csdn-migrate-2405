# jQuery2 开发秘籍（三）

> 原文：[`zh.annas-archive.org/md5/44BEA83CD04274AA076F60D831F59B04`](https://zh.annas-archive.org/md5/44BEA83CD04274AA076F60D831F59B04)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：表单处理

在本章中，我们将探讨如何创建具有动画、验证和用户反馈的健壮而引人入胜的网络表单。我们将涵盖：

+   实施基本表单验证

+   添加数字验证

+   添加信用卡号验证

+   添加日期验证

+   添加电子邮件地址验证

+   实施实时表单验证

+   添加密码强度指示器

+   添加反垃圾邮件措施

+   实施输入字符限制

# 介绍

收集用户数据是许多网站和网络应用程序的基本功能，从简单的数据收集技术，如注册或登录信息，到更复杂的情景，如付款或账单信息。重要的是只收集来自用户的相关和完整信息。为了确保这一点，Web 开发人员必须对所有数据输入进行验证。在执行数据完整性的同时提供良好的用户体验也很重要。这可以通过向用户提供有关其数据可能引起的任何验证错误的有用反馈来实现。本章将向您展示如何创建一个引人入胜的网络表单，同时保持高质量的用户体验。

非常重要的一点是，任何 JavaScript 或 jQuery 验证都容易被用户操纵。JavaScript 和 jQuery 位于 Web 浏览器中，所以用户可以轻松修改代码以绕过任何客户端验证技术。这意味着不能完全依赖客户端验证来防止用户提交无效数据。在客户端进行的任何验证都必须在服务器上进行复制，服务器不容易被用户操纵。

我们使用客户端验证来提高用户体验。因此，用户不需要等待服务器响应。

# 实施基本表单验证

在最基本的表单验证级别上，您需要能够阻止用户提交空值。本教程将为本章的第 1 至 8 个配方提供用于网络表单的 HTML 和 CSS 代码。

## 准备工作

使用您喜欢的文本编辑器或 IDE，在易于访问的位置创建一个空白的 HTML 页面，并将此文件保存为`recipe-1.html`。确保您已将最新版本的 jQuery 下载到与此 HTML 文件相同的位置。

这个 HTML 页面将成为本章大部分内容的基础，请在完成本教程后记得保存它。

## 如何做...

通过执行以下步骤学习如何使用 jQuery 实现基本表单验证：

1.  将以下 HTML 代码添加到`index.html`中。确保更改包含 jQuery 库的 JavaScript 的源位置，指向您计算机上下载的 jQuery 的最新版本所在位置。

    ```js
    <!DOCTYPE html>
    <html >
    <head>
       <title>Chapter 5 :: Recipe 1</title>
       <link type="text/css" media="screen" rel="stylesheet" href="styles.css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/validation.js"></script>
    </head>
    <body>
       <form id="webForm" method="POST">
          <div class="header">
             <h1>Register</h1>
          </div>
          <div class="input-frame">
             <label for="firstName">First Name:</label>
             <input name="firstName" id="firstName" type="text" class="required" />
          </div>
          <div class="input-frame">
             <label for="lastName">Last Name:</label>
             <input name="lastName" id="lastName" type="text" class="required" />
          </div>
          <div class="input-frame">
             <label for="email">Email:</label>
             <input name="email" id="email" type="text" class="required email" />
          </div>
          <div class="input-frame">
             <label for="number">Telephone:</label>
             <input name="number" id="number" type="text" class="number" />
          </div>
          <div class="input-frame">
             <label for="dob">Date of Birth:</label>
             <input name="dob" id="dob" type="text" class="required date" placeholder="DD/MM/YYYY"/>
          </div>
          <div class="input-frame">
             <label for="creditCard">Credit Card #:</label>
             <input name="creditCard" id="creditCard" type="text" class="required credit-card" />
          </div>
          <div class="input-frame">
             <label for="password">Password:</label>
             <input name="password" id="password" type="password" class="required" />
          </div>
          <div class="input-frame">
             <label for="confirmPassword">Confirm Password:</label>
                <input name="confirmPassword" id="confirmPassword" type="password" class="required" />
          </div>
          <div class="actions">
             <button class="submit-btn">Submit</button>
          </div>
       </form>
    </body>
    </html>
    ```

1.  在同一目录下创建名为`styles.css`的 CSS 文件，并添加以下 CSS 代码以为我们的 HTML 页面和表单添加样式：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Ubuntu);
    body {
       background-color: #FFF;
       font-family: 'Ubuntu', sans-serif;
    }
    form {
       width: 500px;
       padding: 20px;
       background-color: #333;
       border-radius: 5px;
       margin: 10px auto auto auto;
       color: #747474;
       border: solid 2px #000;
    }
    form label {
       font-size: 14px;
       line-height: 30px;
       width: 27%;
       display: inline-block;
       text-align: right;
    }
    .input-frame {
       clear: both;
       margin-bottom: 25px;
       position: relative;
    }
    form input {
       height: 30px;
       width: 330px;
       margin-left: 10px;
       background-color: #191919;
       border: solid 1px #404040;
       padding-left: 10px;
       color: #DB7400;
    }
    form input:hover {
       background-color: #262626;
    }
    form input:focus {
       border-color: #DB7400;
    }
    form .header {
       margin: -20px -20px 25px -20px;
       padding: 10px 10px 10px 20px;
       position: relative;
       background-color: #DB7400;
       border-top-left-radius: 4px;
       border-top-right-radius: 4px;
    }
    form .header h1 {
       line-height: 50px;
       margin: 0px;
       padding: 0px;
       color: #FFF;
       font-weight: normal;
    }
    .actions {
       text-align: right;
    }
    .submit-btn {
       background-color: #DB7400;
       border: solid 1px #000;
       border-radius: 5px;
       color: #FFF;
       padding: 10px 20px 10px 20px;
       text-decoration: none;
       cursor: pointer;
    }
    .error input {
       border-color: red;
    }
    .error-data {
       color: red;
       font-size: 11px;
       position: absolute;
       bottom: -15px;
       left: 30%;
    }
    ```

1.  除了 jQuery 库外，先前的 HTML 页面还使用了另一个 JavaScript 文件。在保存`index.html`文件的目录中创建一个空白的 JavaScript 文件。将该文件保存为`validation.js`，并添加以下 JavaScript 代码：

    ```js
    $(function(){
       $('.submit-btn').click(function(event){
          //Prevent form submission
          event.preventDefault();
          var inputs = $('input');
          var isError = false;
          //Remove old errors
          $('.input-frame').removeClass('error');
          $('.error-data').remove();
          for (var i = 0; i < inputs.length; i++) {
             var input = inputs[i];
             if ($(input).hasClass('required') && !validateRequired($(input).val())) {
                addErrorData($(input), "This is a required field");
                isError = true;
             }

          }
          if (isError === false) {
             //No errors, submit the form
             $('#webForm').submit();
          }
       });
    });

    function validateRequired(value) {
       if (value == "") return false;
       return true;
    }

    function addErrorData(element, error) {
       element.parent().addClass("error");
       element.after("<div class='error-data'>" + error + "</div>");
    }
    ```

1.  在网络浏览器中打开`index.html`，您应该会看到一个类似下面截图的表单：![如何操作…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_05_01.jpg)

1.  如果您单击**提交**按钮提交一个空表单，将会在必填字段下方显示错误消息。

## 工作原理…

现在，让我们详细了解之前执行的步骤。

### HTML

HTML 创建了一个包含各种字段的网络表单，这些字段将接受一系列数据输入，包括文本、出生日期和信用卡号码。该页面构成了本章大部分内容的基础。每个输入元素都被赋予了不同的类，具体取决于它们需要什么类型的验证。对于本示例，我们的 JavaScript 只会查看`required`类，该类表示必填字段，因此不能为空。其他类已添加到输入字段中，例如`date`和`number`，这些类将在本章后续示例中使用。

### CSS

已添加基本 CSS 以创建吸引人的网络表单。CSS 代码为输入字段添加样式，使其与表单本身融为一体，并添加了悬停效果。还使用了谷歌 Web 字体 Ubuntu 来改善表单的外观。

### jQuery

jQuery 代码的第一部分被包裹在`$(function(){});`中，这将确保代码在页面加载时执行。在这个包装器内部，我们将点击事件处理程序附加到表单提交按钮，如下所示：

```js
$(function(){
    $('.submit-btn').click(function(event){
        //Prevent form submission
        event.preventDefault();

    });
});
```

由于我们希望根据是否提供了有效数据来处理表单提交，所以我们使用`event.preventDefault();`来最初阻止表单提交，从而允许我们首先执行验证，如下所示：

```js
var inputs = $('input');
var isError = false;
```

在`preventDefault`代码之后，声明了一个`inputs`变量，用于保存页面内所有输入元素，使用`$('input')`来选择它们。此外，我们创建了一个`isError`变量，并将其设置为`false`。这将是一个标志，用于确定我们的验证代码是否在表单中发现了错误。这些变量声明如上所示。通过`inputs`变量的长度，我们能够循环遍历页面上的所有输入。我们为每个迭代的输入创建一个输入变量，该变量可用于使用 jQuery 对当前输入元素执行操作。使用以下代码完成此操作：

```js
for (var i = 0; i < inputs.length; i++) {
var input = inputs[i];
}
```

在输入变量被声明并分配了当前输入后，使用以下代码从元素中移除任何先前的错误类或数据：

```js
$(input).parent().removeClass('error');
$(input).next('.error-data').remove();
```

第一行代码从输入框的父元素（`.input-frame`）中移除了`error`类，该类将为输入元素添加红色边框。第二行代码会移除在输入数据验证检查确定该输入数据无效时在输入框下方显示的错误信息。

接下来，使用 jQuery 的`hasClass()`函数来确定当前输入元素是否具有`required`类。如果当前元素确实具有这个类，我们需要执行所需的验证以确保该字段包含数据。我们在`if`语句内调用`validateRequired()`函数，并通过当前输入的值，如下所示：

```js
if ($(input).hasClass('required') && !validateRequired($(input).val())) {
addErrorData($(input), "This is a required field");
   isError = true;
}
```

我们使用感叹号 `!` 前置调用`validateRequired()`函数来检查是否该函数的结果等于`false`；因此，如果当前输入具有`required`类且`validateRequired()`返回`false`，则当前输入的值无效。如果是这种情况，我们在`if`语句内调用`addErrorData()`函数，并传递当前输入和错误消息，该消息将显示在输入框下方。我们还将`isError`变量设置为`true`，以便在之后的代码中我们将知道发生了验证错误。

JavaScript 的`for`循环将对页面上选择的每个输入元素重复执行这些步骤。`for`循环完成后，我们检查`isError`标志是否仍然设置为`false`。如果是，我们使用 jQuery 手动提交表单，如下所示：

```js
if (isError === false) {
   //No errors, submit the form
   $('#webForm').submit();
}
```

请注意，运算符`===`用于比较`isError`的变量类型（即`Boolean`）及其值。在 JavaScript 文件的底部，我们声明了之前在脚本中调用的两个函数。第一个函数`validateRequired()`简单地获取输入值并检查它是否为空。如果值为空，函数返回`false`，表示验证失败；否则，函数返回`true`。可以编码如下：

```js
function validateRequired(value) {
    if (value == "") return false;
    return true;
}
```

使用的第二个函数是`addErrorData()`函数，它接受当前输入和错误消息。它使用 jQuery 的`addClass()`函数将错误类添加到输入的父级，这将使用 CSS 在输入元素上显示红色边框。然后，它使用 jQuery 的`after()`函数将一个`<div>`元素插入到 DOM 中，在当前输入字段下方显示指定的错误消息，如下所示：

```js
function validateRequired(value) {
   if (value == "") return false;
   return true;
}
function addErrorData(element, error) {
   element.parent().addClass("error");
   element.after("<div class='error-data'>" + error + "</div>");
}
```

## 还有更多内容...

这个结构使我们能够轻松地为我们的 Web 表单添加附加的验证。因为 JavaScript 正在迭代表单中所有的输入字段，我们可以轻松地检查附加的类，比如`date`、`number`和`credit-card`，并调用额外的函数来提供替代验证。本章其他的示例将详细讨论附加的验证类型，并将这些函数添加到当前的`validation.js`文件中。

## 另请参阅

+   *实施输入字符限制*

# 添加数字验证

当从用户那里收集数据时，有许多情况下您只想允许表单字段中的数字。例如，这可能是电话号码、PIN 码或邮政编码等。本配方将向您展示如何验证前一个配方中创建的表单中的电话号码字段。

## 准备工作

确保您已经完成了上一个配方，并且有相同的文件可用。在您选择的文本编辑器或 IDE 中打开`validation.js`。

## 如何做…

通过执行以下步骤将数字验证添加到前一个配方中创建的表单中：

1.  将`validation.js`更新如下，添加`valdiateNumber()`函数并在`for`循环内部添加额外的`hasClass('number')`检查：

    ```js
    $(function(){
       $('.submit-btn').click(function(event){
          //Prevent form submission
          event.preventDefault();
          var inputs = $('input');
          var isError = false;
          //Remove old errors
          $('.input-frame').removeClass('error');
          $('.error-data').remove();
          for (var i = 0; i < inputs.length; i++) {
             var input = inputs[i];

             if ($(input).hasClass('required') && !validateRequired($(input).val())) {
                   addErrorData($(input), "This is a required field");
                   isError = true;
                }
    /* Code for this recipe */
             if ($(input).hasClass('number') && !validateNumber($(input).val())) {
                   addErrorData($(input), "This field can only contain numbers");
                   isError = true;
                }
    /* --- */

          }
          if (isError === false) {
             //No errors, submit the form
             $('#webForm').submit();
          }
       });
    });

    function validateRequired(value) {
       if (value == "") return false;
       return true;
    }

    /* Code for this recipe */
    function validateNumber(value) {
       if (value != "") {
          return !isNaN(parseInt(value, 10)) && isFinite(value);
          //isFinite, in case letter is on the end
       }
       return true;
    }
    /* --- */
    function addErrorData(element, error) {
       element.parent().addClass("error");
       element.after("<div class='error-data'>" + error + "</div>");
    } 
    ```

1.  在 Web 浏览器中打开`index.html`，在电话号码字段中输入除了有效整数以外的内容，然后单击**提交**按钮。您将看到一个类似以下截图的表单:![如何做…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_05_02.jpg)

## 工作原理…

首先，我们在`validation.js`的主`for`循环中添加了额外的`if`语句，以检查当前输入字段是否具有`number`类，如下所示：

```js
if ($(input).hasClass('number') && !validateNumber($(input).val())) {
   addErrorData($(input), "This field can only contain numbers");
   isError = true;
}
```

如果是这样，此输入值需要验证为数字。为此，在`if`语句内联调用`validateNumber`函数：

```js
function validateNumber(value) {
   if (value != "") {
      return !isNaN(parseInt(value, 10)) && isFinite(value);
      //isFinite, in case letter is on the end
   }
   return true;
}
```

此函数将当前输入字段的值作为参数。它首先检查值是否为空。如果是，我们就不需要在这里执行任何验证，因为这是由本章第一个配方中的`validateRequired()`函数处理的。

如果有值需要验证，在`return`语句上执行一系列操作。首先，该值被解析为整数并传递给`isNaN()`函数。JavaScript 的`isNaN()`函数简单地检查提供的值是否为**NaN**（**Not a Number**）。在 JavaScript 中，如果尝试将一个值解析为整数，并且该值实际上不是整数，则会得到`NaN`值。`return`语句的第一部分是确保提供的值是有效的整数。然而，这并不阻止用户输入无效字符。如果用户输入`12345ABCD`，`parseInt`函数将忽略`ABCD`，只解析`12345`，因此验证将通过。为了防止这种情况，我们还使用`isFinite`函数，如果提供`12345ABCD`，则返回`false`。

## 另请参阅

+   *添加信用卡号码验证*

# 添加信用卡号码验证

数字验证可能足以验证信用卡号码；然而，使用正则表达式，可以检查数字组合以匹配 Visa、MasterCard、American Express 等信用卡号码。

## 准备工作

确保您已经打开并准备修改本章前两个配方中的`validation.js`。

## 如何做…

使用 jQuery 执行以下逐步说明，为信用卡号提供表单输入验证：

1.  更新`validation.js`以添加信用卡验证函数和在输入字段上进行额外的类检查：

    ```js
    $(function(){
       $('.submit-btn').click(function(event){
          //Prevent form submission
          event.preventDefault();
          var inputs = $('input');
          var isError = false;
          for (var i = 0; i < inputs.length; i++) {

    // -- JavaScript from previous two recipes hidden            

             if ($(input).hasClass('credit-card') && !validateCreditCard($(input).val())) {
                addErrorData($(input), "Invalid credit card number");
                isError = true;
             }

          }
    // -- JavaScript from previous two recipes hidden
       });
    });

    // -- JavaScript from previous two recipes hidden

    function validateCreditCard(value) {
       if (value != "") {
          return /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/.test(value);
       }
       return true;
    }
    // -- JavaScript from previous two recipes hidden
    } 
    ```

1.  打开`index.html`，输入无效的信用卡号。你将看到表单中呈现以下错误信息：![操作步骤…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_05_03.jpg)

## 运作原理…

要添加信用卡验证，与前两个示例一样，在主`for`循环中添加额外的检查来查找输入元素上的`credit-card`类，如下所示：

```js
if ($(input).hasClass('credit-card') && !validateCreditCard($(input).val())) {
   addErrorData($(input), "Invalid credit card number");
   isError = true;
}
```

此处还添加了`validateCreditCard`函数，该函数使用正则表达式验证输入值，如下所示：

```js
function validateCreditCard(value) {
   if (value != "") {
      return /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$/.test(value);
   }
   return true;
}
```

此函数的第一部分确定提供的值是否为空。如果不为空，函数将执行进一步的验证；否则，它将返回`true`。大多数信用卡号以前缀开头，这使我们能够在数值验证之上添加额外的验证。此函数中使用的正则表达式将允许 Visa、MasterCard、American Express、Diners Club、Discover 和 JCB 卡。

## 也可以参考

+   *添加数字验证*

# 添加日期验证

日期是常见的数据项，用户能够轻松地在您的 Web 表单中输入日期非常重要。通常，您会使用包含日期验证的日期选择器来提供简单的输入方法。本示例向您展示如何手动验证英国格式的日期（即`DD/MM/YYYY`）。日期选择器在第九章中进行了讨论，*jQuery UI*，使用流行的 jQuery UI 框架。有关更多信息，请参阅本示例的*也可以参考*部分。

## 准备工作

继续本章前几个示例的趋势，确保你已经打开并准备修改`validation.js`，并且已经完成了前三个示例。

## 操作步骤…

通过以下简单的步骤为您的 Web 表单添加日期验证：

1.  更新`validation.js`以添加附加的日期验证函数和在主`for`循环内进行类检查，如下所示：

    ```js
    $(function(){
       $('.submit-btn').click(function(event){

    // -- JavaScript from previous three recipes hidden

          for (var i = 0; i < inputs.length; i++) {

    // -- JavaScript from previous three recipes hidden

             if ($(input).hasClass('date') && !validateDate($(input).val())) {
                addErrorData($(input), "Invalid date provided");
                isError = true;
             }

             // -- JavaScript from previous three recipes hidden

          }
          // -- JavaScript from previous three recipes hidden    });
    });

    // -- JavaScript from previous three recipes hidden

    function validateDate(value) {
       if (value != "") {
          if (/^\d{2}([.\/-])\d{2}\1\d{4}$/.test(value)) {
             // Remove leading zeros
             value = value.replace(/0*(\d*)/gi,"$1");
             var dateValues = value.split(/[\.|\/|-]/);
             // Correct the month value as month index starts at 0 now 1 (e.g. 0 = Jan, 1 = Feb)
             dateValues[1]--;
             var date = new Date(dateValues[2], dateValues[1], dateValues[0]);
             if (
                date.getDate() == dateValues[0] && date.getMonth() == dateValues[1] &&
                date.getFullYear() == dateValues[2]
                ) {
                return true;
             }
          }
          return false;
       } else {
          return true;
       }
    }
    // -- JavaScript from previous three recipes hidden
    ```

1.  在 Web 浏览器中打开`index.html`，输入一个无效的日期，并点击**提交**以生成无效日期错误，如下图所示：![操作步骤…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_05_04.jpg)

## 运作原理…

再次，在主`for`循环中添加一个额外的类检查，以查看当前输入是否需要应用日期验证。如果需要，将调用`validateDate()`函数。

就像其他验证函数一样，我们首先检查值是否为空。如果不为空，则可以验证该值。使用正则表达式来确定提供的字符串值是否是有效的日期格式，如下所示：

```js
if (/^\d{2}([.\/-])\d{2}\1\d{4}$/.test(value)) {
```

如果提供的值以斜杠、连字符或句点分隔，并且前两部分由两个数字组成，最后一部分由四个数字组成，则此测试将通过。这将确保提供的值是`DD/MM/YYYY`，符合要求。

如果此测试通过，则下一步是删除所有前导零，以便将提供的日期字符串转换为 JavaScript 的日期对象（例如，`08-08-1989` 将变为 `8-8-1989`）。相同的代码如下所示：

```js
value = value.replace(/0*(\d*)/gi,"$1");
```

之后，创建一个数组，将日期字符串分割为`-`、`/` 或：

```js
var dateValues = value.split(/[\.|\/|-]/);
```

现在，可以使用这些日期值来创建 JavaScript 日期对象并测试其有效性。在此之前，我们必须转换月份值。JavaScript 月份从`0`开始，而我们的用户将从`1`开始。例如，用户将使用`1`表示一月，`2`表示二月，依此类推，而 JavaScript 使用`0`表示一月，`1`表示二月，依此类推。为此，我们只需从提供的日期值中减去`1`，如下所示：

```js
dateValues[1]--;
```

这样做后，就可以创建 JavaScript 日期对象并检查结果是否与输入日期匹配，从而证明其有效性：

```js
var date = new Date(dateValues[2], dateValues[1], dateValues[0]);
if (
   date.getDate() == dateValues[0] &&
   date.getMonth() == dateValues[1] &&
   date.getFullYear() == dateValues[2]
) {
   return true;
}
```

## 另请参阅

+   在 第九章 的 *快速向输入框添加日期选择器界面* 配方中，*jQuery UI*

# 添加电子邮件地址验证

电子邮件地址验证是网络上最常见的验证类型之一。大多数人会认为有效的电子邮件地址只包含字母数字字符，除了`@`符号和句点。虽然大多数电子邮件地址通常是这种格式，但实际上有效的电子邮件地址可能包含各种其他字符。本文将向您展示如何将电子邮件验证添加到我们在过去四个配方中使用的 Web 表单中。

## 如何执行…

通过执行以下说明，创建可以反复使用的电子邮件验证：

1.  在 `validation.js` 主 `for` 循环中添加额外的 `hasClass` 检查和 `if` 语句，如下所示：

    ```js
    if ($(input).hasClass('email') && !validateEmail($($(input)).val())) {
       addErrorData($(input), "Invalid email address provided");
       isError = true;
    }
    ```

1.  在 `validation.js` 末尾添加以下 `validateEmail()` 函数：

    ```js
    function validateEmail(value) {
       if (value != "") {
          return /[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:a-z0-9?\.)+a-z0-9?/i.test(value);
       }
       return true;
    }
    ```

1.  在网络浏览器中打开 `index.html`，输入一个无效的电子邮件地址，并提交表单。您将以与其他类型验证错误相同的方式收到适当的错误提示。

## 工作原理…

然而简单的电子邮件验证函数包含一个复杂的正则表达式，用于将电子邮件地址验证为 RFC 5322 标准的实用版本，该版本由 [`www.regular-expressions.info/email.html`](http://www.regular-expressions.info/email.html) 提供。

`validateEmail()` 函数的第一部分检查是否有值可验证。如果有，它将使用复杂的正则表达式测试字符串值的有效性，并相应地返回`true`或`false`。

最后，与其他验证函数一样，主`for`循环中有一个类检查，用于确定哪些输入需要对电子邮件地址进行验证。如果这些输入字段未通过验证，则会在屏幕上提供相应的错误输出。

## 还有更多…

重要的是要理解，此电子邮件验证方法仅验证语法，以减少用户提供的垃圾数据量。要真正验证电子邮件地址，您必须实际发送电子邮件以验证其是否存在并准备接收电子邮件。

# 实现实时表单验证

对于用户在网页表单中输入时即时获取验证错误的反馈非常有用。如果您同时执行客户端验证和服务器端验证，那么这可以轻松实现，因为您不需要每次用户在输入时发送请求到服务器，您可以在客户端内完成所有操作。再次强调，相同的数据在服务器端进行额外验证非常重要。然后可以在用户提交表单后将服务器端验证结果反馈给网页表单。

## 准备工作

本示例将调整作为前五个示例的一部分创建的客户端验证。确保您在此之前已经完成了这些示例。

## 如何做…

通过执行以下步骤为用户提供实时验证：

1.  首先，我们需要将`for`循环中的所有类检查移到它们自己的函数中，以便它们可以被重复使用。将执行`required`、`email`、`number`、`date`和`credit-card`的`hasClass`检查的所有`if`语句移动到一个名为`doValidation()`的函数中，如下所示：

    ```js
    // --- Hidden JavaScript from previous recipes

    function doValidation(input) {
       //Remove old errors
       $(input).parent().removeClass('error');
       $(input).next('.error-data').remove();
       if ($(input).hasClass('required') && !validateRequired($(input).val())) {
          addErrorData($(input), "This is a required field");
       }
       if ($(input).hasClass('email') && !validateEmail($($(input)).val())) {
          addErrorData($(input), "Invalid email address provided");
       }
       if ($(input).hasClass('number') && !validateNumber($(input).val())) {
          addErrorData($(input), "This field can only contain numbers");
       }
       if ($(input).hasClass('date') && !validateDate($(input).val())) {
          addErrorData($(input), "Invalid date provided");
       }
       if ($(input).hasClass('credit-card') && !validateCreditCard($(input).val())) {
          addErrorData($(input), "Invalid credit card number");
       }
    }

    // --- Hidden JavaScript
    ```

1.  现在，我们需要更新主`for`循环以使用此函数，以便当用户单击提交按钮时仍执行表单验证，如下所示：

    ```js
    for (var i = 0; i < inputs.length; i++) {
       var input = inputs[i];
       doValidation(input);
    }
    ```

1.  在`for`循环后更新`isError`检查，以使用另一种方法来确定是否存在错误，以便仍然可以提交表单，如下所示：

    ```js
    if ($('.error-data').length == 0) {
       //No errors, submit the form
       $('#webForm').submit();
    }
    ```

1.  要对用户正在输入的字段执行验证，我们需要在`keyup`事件上调用`doValidation()`函数。将以下代码添加到`$(function(){});`块中，以将`keyup`事件处理程序附加到每个表单输入：

    ```js
    $('input').on("keyup", function(){
       doValidation($(this));
    });
    ```

1.  在 Web 浏览器中打开`index.html`，在电子邮件字段中开始输入，您将在输入时提供适当的错误消息，直到输入有效的电子邮件地址。

## 工作原理…

将之前的验证代码适应为为用户提供实时验证非常容易。将主验证触发器移动到另一个函数意味着可以重复使用代码而无需重复。包含这些触发器的函数接受一个参数，即它需要执行验证检查的输入。仍然使用`for`循环提供此输入，如下所示：

```js
for (var i = 0; i < inputs.length; i++) {
   var input = inputs[i];
   doValidation(input);
}
```

不再依赖`doValidation`函数返回`isError`值，我们直接查看 DOM，通过查找带有`error-data`类的任何元素来查看屏幕上是否显示了任何错误，如下所示：

```js
if ($('.error-data').length == 0) {
   //No errors, submit the form
   $('#webForm').submit();
}
```

如果没有错误，则如前所述手动提交表单。

为了提供实时验证，使用以下 jQuery 代码为每个表单输入附加一个`keyup`事件处理程序：

```js
$('input').on("keyup", function(){
   doValidation($(this));
});
```

`on()`方法的回调函数将在用户在输入字段内按下并释放键时每次执行。然后可以使用`$(this)`，它引用触发事件的输入，从而为`doValidation()`函数提供所需的输入对象来执行验证检查。

# 添加密码强度指示器

用户喜欢创建一个非常简单的密码，如 cat、john 或甚至 password，以便记住。然而，大多数人，特别是 Web 开发人员，知道这些类型的密码太不安全了，并且使用技术如字典攻击非常容易从加密数据库中解密出来。例如，密码强度指示器对于引导用户使用更复杂的密码非常有用。

## 准备工作

为了能够验证密码强度，我们需要创建一些规则供我们的代码使用。关于最佳密码类型有很多在线信息，但没有硬性规定。我们将为密码打分，根据以下每个规则得分一分：

+   长度超过六个字符

+   长度超过八个字符

+   同时包含大写和小写字符

+   至少包含一个数字

+   它包含以下符号之一：`@`、`$`、`!`、`&` 和 `^`

此处的配方将在过去六个配方中创建的 Web 表单中添加密码强度指示器。在开始此步骤之前，请确保您已经获取了这些配方中的代码。

## 如何做…

为 Web 表单创建一个有效的密码强度指示器，需执行以下每个步骤：

1.  更新`index.html`，为密码表单元素添加一些额外的类，并添加一些额外的 HTML，这将创建密码强度指示器，如下所示：

    ```js
    // --- ADDITIONAL HTML HIDDEN
    <div class="input-frame">
    <label for="password">Password:</label>
    <input name="password" id="password" type="password" class="required password" />
    <div class="password-strength">
       <div class="inner"></div>
       <div class="text"></div>
    </div>
    </div>
    <div class="input-frame">
    <label for="confirmPassword">Confirm Password:</label>
    <input name="confirmPassword" id="confirmPassword" type="password" class="confirm-password" />
    </div>
    // --- ADDITIONAL HTML HIDDEN
    ```

1.  将以下样式添加到`styles.css`的末尾，以将强度指示器定位在密码字段下方。这些样式还将允许强度指示器作为显示密码强度百分比的加载条。

    ```js
    .password-strength {
       position: absolute;
       width: 150px;
       height: 20px;
       left: 69%;
       top: 35px;
       line-height: 20px;
       border: solid 1px #191919;
    }
    .password-strength .inner {
       position: absolute;
       left: 0;
       top: 0;
    }
    .password-strength .text {
       font-size: 11px;
       color: #FFF;
       text-align: center;
       position: relative;
       z-index: 10;
    }
    ```

1.  将`validatePasswords()`函数添加到`validation.js`的末尾，用于确保输入了两个密码并确保它们匹配，如下所示：

    ```js
    // --- HIDDEN JAVASCRIPT
    function validatePasswords(value) {
       var password = $('.password').val();
       if (value == "") {
          return "Both passwords are required";
       } else if (value != password) {
          return "Passwords do not match";
       }
       return true;
    }
    ```

1.  将以下代码添加到`doValidation()`函数的末尾，以在`confirm-password`输入上运行`validatePasswords()`函数：

    ```js
    function doValidation(input) {
    // --- HIDDEN JAVASCRIPT
    if ($(input).hasClass('confirm-password')) {
       var result = validatePasswords($(input).val());
          if (result != true) {
             addErrorData($(input), result);
          }
       }
    }
    ```

1.  在 `validation.js` 中的 `$(function(){});` 块内添加以下 `keyup` 事件处理程序，以在用户在第一个密码字段中输入时评分密码强度：

    ```js
    $('.password').on("keyup", function(){
       var score = 0;
       var password = $('.password');
       var passwordAgain = $('.confirm-password');
       //Remove any old errors for the password fields
       password.parent().removeClass('error');
       password.next('.error-data').remove();
       passwordAgain.parent().removeClass('error');
       passwordAgain.next('.error-data').remove();
       //Password is greater than 6 characters
       if (password.val().length > 6) {
          score++;
       }
       //Password is greater than 8 characters
       if (password.val().length > 8) {
          score++;
       }
       //Password has both uppercase and lowercase characters
       if (/(?=.*[A-Z])(?=.*[a-z])/.test(password.val())) {
          score++;
       }
       //Password has at least one number
       if (/(?=.*[0-9])/.test(password.val())) {
          score++;
       }
       //Password has at least one symbol (@$!&^) character
       if (/@|\$|\!|&|\^/.test(password.val())) {
          score++;
       }
       var fill = (100 - ((score * 2) * 10));
       var percent = (100 - fill);
       var level,
       colour;
       switch (score) {
       case 0:
       case 1:
       level = "Weak";
       colour = "green";
       break;
       case 2:
       case 3:
       level = "Medium";
       colour = "orange";
       break;
       case 4:
       level = "Strong";
       colour = "red";
       break;
       case 5:
       level = "Excellent";
       colour = "purple";
       break;
       }
       $('.password-strength .inner').css('right', fill + "%").css('background-color', colour);
       $('.password-strength .text').html(level + " (" + percent + "%)");
       });
    ```

1.  在 Web 浏览器中打开 `index.html`，您会看到在第一个密码字段下方出现了一个额外的黑色框。开始输入密码，这个字段会在您输入时提供有关密码强度的信息。如下截图所示：

## 工作原理...

指示器本身的 HTML 具有 `inner` 元素和 `text` 元素。`text` 元素由 jQuery 用于显示基于输入密码的计算得分的密码强度和百分比。`inner` 元素用于形成彩色条。根据计算得分，jQuery 用于更改 `inner` 元素的颜色和定位，从而创建加载条效果，如前述截图所示。

使用的 CSS 需要很少的解释，因为它提供了基本的样式和定位。`inner` 元素具有绝对位置，以便在不同百分比下填充 `password-strength` 元素。`text` 分区具有设置了 `z-index` 参数，以确保文本始终显示在 `inner` 元素之上。

`validatePasswords` 函数是作为本篇配方的一部分创建的，它简单地为我们的应用程序添加了基本的密码验证。它检查确认密码字段是否已填写，并且该值是否与第一个密码字段匹配。在 `doValdiation` 函数中添加了额外的检查，以确保此验证与早期配方中创建的其他验证方法一起应用。

为了在用户在密码字段中输入时更新密码强度指示器，使用与 *实施实时表单验证* 配方中使用的相同方法，即使用 `keyup` 事件。使用 jQuery `on()` 函数将事件处理程序附加到 `password` 字段，如下所示：

```js
$('.password').on("keyup", function(){
});
```

用于计算得分并更新 `password-strength` HTML 元素的代码随后放置在此事件处理程序的回调函数中。此代码的第一部分是删除密码字段当前显示的任何错误。

之后，有一系列的 `if` 语句，用于根据在本篇配方开始时定义的规则验证密码。首先是密码长度的基本验证，如下所示：

```js
//Password is greater than 6 characters
if (password.val().length > 6) {
   score++;
}
//Password is greater than 8 characters
if (password.val().length > 8) {
   score++;
}
```

每次满足验证条件时，使用 `score++` 将 score 变量递增 `1`。

更复杂的规则使用正则表达式来确定密码值是否符合额外得分点的要求，如下所示：

```js
//Password has both uppercase and lowercase characters
if (/(?=.*[A-Z])(?=.*[a-z])/.test(password.val())) {
   score++;
}
//Password has at least one number
if (/(?=.*[0-9])/.test(password.val())) {
   score++;
}
//Password has at least one symbol (@$!&^) character
if (/@|\$|\!|&|\^/.test(password.val())) {
   score++;
}
```

在考虑了五条规则后，最终分数用于计算填充值。填充值是需要从强度指示器右侧填充的`inner`元素的百分比。这允许我们创建加载条效果。除了填充值，还计算出一个普通百分比，以与强度级别文字一起显示，如下所示：

```js
var fill = (100 - ((score * 2) * 10));
var percent = (100 - fill);
```

之后，分数值再次被用来确定`inner`元素的背景颜色和强度级别文字，如下所示：

```js
var level,
colour;
switch (score) {
case 0:
case 1:
   level = "Weak";
   colour = "green";
break;
case 2:
case 3:
   level = "Medium";
   colour = "orange";
   break;
case 4:
   level = "Strong";
   colour = "red";
break;
case 5:
   level = "Excellent";
   colour = "purple";
break;
}
```

最后，使用 jQuery `password-strength`，HTML 代码更新为获取的信息，以向用户显示结果，如下所示：

```js
$('.password-strength .inner').css('right', fill + "%").css('background-color', colour);
$('.password-strength .text').html(level + " (" + percent + "%)");
```

## 还有更多…

这段代码应该很容易调整，这样你就可以添加自己关于密码强度的规则。在网上有很多讨论和资源可以告诉你一个强密码应该是什么样子的。

## 另请参阅

+   *实现实时表单验证*

# 添加反垃圾邮件措施

大多数网页开发者都会知道，如果你的网站上有联系表单或任何类型的网页表单公开可用，就会有网页机器人提交和大量垃圾邮件。在过去的七个配方中，我们一直在创建仅使用 JavaScript 的网页表单来阻挡大多数网页机器人，但随着浏览器自动化和网页机器人变得更加聪明，向你的网页表单添加反垃圾邮件措施仍然很重要。

## 准备工作

确保你已经完成了最后七个配方，并且代码随时可用。记住，如果你只想使用代码而不完全理解它是如何工作的，跳到本章末尾的*它是如何工作的...*部分，获取所有内容。

## 如何去做…

通过执行以下每个步骤，向你的网页表单添加简单的反垃圾邮件措施：

1.  更新`index.html`，在标记为`确认密码`的输入下添加一个额外的表单输入，如下所示：

    ```js
    <!-- HIDDEN HTML CODE -->
    <div class="input-frame">
       <label>Confirm Password:</label>
       <input type="password" class="confirm-password" />
    </div>
    <div class="input-frame">
       <label>Enter the number <span class="anti-spam-number"></span>:</label>
       <input type="text" class="required anti-spam-input" />
    </div>
    <!-- HIDDEN HTML CODE -->
    ```

1.  使用 JavaScript，在`validation.js`顶部使用以下代码生成一个介于`1`和`100`之间的随机数：

    ```js
    var spamNumber = Math.floor(Math.random() * (100 - 1 + 1)) + 1;
    $(function(){
    // --- HIDDEN JAVASCRIPT CODE
    ```

1.  在`$(function(){});` jQuery 区块的最后，添加以下代码，以更新 HTML 的`anti-spam-number` span 元素为随机数字：

    ```js
    // --- HIDDEN JAVASCRIPT CODE
    $('.anti-spam-number').html(spamNumber);
    });
    ```

1.  在`doValidation()`函数的末尾添加以下附加验证检查：

    ```js
    if ($(input).hasClass('anti-spam-input') && !validateAntiSpam($(input).val())) {
       addErrorData($(input), "Incorrect Anti-Spam answer");
    }
    ```

1.  最后，在`validation.js`的末尾，添加`validateAntiSpam()`函数，之前的代码调用该函数：

    ```js
    // --- HIDDEN JAVASCRIPT CODE
    function validateAntiSpam(value) {
       if (value != "") {
          if (parseInt(value)!= spamNumber) return false;
       }
       return true;
    }
    ```

1.  在 web 浏览器中打开`index.html`，你会看到额外的反垃圾邮件表单输入字段。每次刷新页面，它会要求你输入不同的数字。

## 它是如何工作的…

通过将`spamNumber`全局变量声明在任何函数之外，它可供整个 JavaScript 文件使用。在每次页面加载时，生成一个介于`1`和`100`之间的新数字，这样网页机器人就不能存储答案并提交表单。在 HTML 代码中，有一个具有类`anti-spam-number`的`span`元素，使用以下代码在页面加载时更新为随机数字：

```js
$('.anti-spam-number').html(spamNumber);
```

这将确保用户被告知输入正确的数字。我们创建了一个额外的验证函数，名为`validateAntiSpam`，并从`doValidation()`函数中调用所有具有`anti-spam-input`类的输入。然后，这将使用全局可用的`spamNumber`变量验证用户输入的数字，如下所示：

```js
function validateAntiSpam(value) {
   if (value != "") {
      if (parseInt(value)!= spamNumber) return false;
   }
   return true;
}
```

请注意，将输入解析为整数以确保数字之间的比较。如果值不匹配，这个函数将返回`false`，以便`doValidation()`函数可以为用户在屏幕上创建适当的错误消息。

## 还有更多…

这种客户端垃圾邮件验证不能完全信赖。它对一般网页机器人有效，但不能对直接针对你的网站的机器人起作用。如果有人想要为你的网站编写一个特定的机器人脚本，那么绕过这个 JavaScript 并不是一个困难的过程。如果你觉得这是可能的，那么必须使用更极端的服务器端垃圾邮件预防方法。

在互联网上有许多有效的防垃圾邮件方法可以免费获得。最流行的是 CAPTCHA。最流行的 CAPTCHA 之一是谷歌在[`www.google.com/recaptcha`](http://www.google.com/recaptcha)上免费提供的。

## 另请参阅

+   *添加密码强度指示器*

# 实现输入字符限制

到目前为止，本章中的所有示例都集中在输入验证和向用户提供适当反馈的方面。有些情况下，最好是阻止用户根本不输入无效的字符。通常不会使用这种方法，因为对于一些用户来说这可能会很令人困惑；例如，如果他们不被告知为什么不能输入*％*。这种方法适用的情况是登录表单。如果你知道你的注册系统不允许用户名中含有*％*，你就知道用户输入*％*是错误的，因此阻止输入是可以接受的。这个示例提供了一种方法，可以防止用户在输入字段中输入非字母数字字符。

## 准备工作

这个示例不使用前八个示例中的代码；不过，CSS 代码中有相似之处。完成这个示例，你将需要三个文件。在存储最新版本的 jQuery 的同一目录中创建`recipe-9.html`、`recipe-9.js`和`recipe-9.css`。

## 如何做…

使用 jQuery 来防止用户通过以下步骤在文本输入中输入无效的章节：

1.  将以下 HTML 代码添加到`recipe-9.html`中。这将创建一个基本的登录表单，并包括另外两个文件以及 jQuery 库：

    ```js
    <!DOCTYPE html>
    <html >
    <head>
       <title>Chapter 5 :: Recipe 7</title>
       <link type="text/css" media="screen" rel="stylesheet" href="recipe-9.css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-9.js"></script>
    </head>
    <body>
    <form id="webForm" method="POST">
       <div class="header">
          <h1>Register</h1>
       </div>
       <div class="input-frame">
          <label for="username">Username:</label>
          <input name="username" id="username" type="text" class="username" />
       </div>
       <div class="input-frame">
          <label for="password">Password:</label>
          <input name="password" id="password" type="text" class="required" />
       </div>
       <div class="actions">
          <button class="submit-btn">Submit</button>
       </div>
    </form>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-9.css`中，为登录表单添加样式：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Ubuntu);
    body {
       background-color: #FFF;
       font-family: 'Ubuntu', sans-serif;
    }
    form {
       width: 500px;
       margin: 10px auto auto auto;
       padding: 20px;
       background-color: #333;
       border-radius: 5px;
       color: #747474;
       border: solid 2px #000;
    }
    form label {
       font-size: 14px;
       line-height: 30px;
       padding-bottom: 8px;
       width: 140px;
       display: inline-block;
       text-align: right;
    }
    .input-frame {
       clear: both;
       margin-bottom: 25px;
       position: relative;
    }
    form input {
       height: 30px;
       width: 330px;
       margin-left: 10px;
       background-color: #191919;
       border: solid 1px #404040;
       padding-left: 10px;
       color: #DB7400;
    }
    form input:hover {
       background-color: #262626;
    }
    form input:focus {
       border-color: #DB7400;
    }
    form .header {
       margin: -20px -20px 25px -20px;
       padding: 10px 10px 10px 20px;
       position: relative;
       background-color: #DB7400;
       border-top-left-radius: 4px;
       border-top-right-radius: 4px;
    }
    form .header h1 {
       line-height: 50px;
       margin: 0;
       padding: 0;
       color: #FFF;
       font-weight: normal;
    }
    .actions {
       text-align: right;
    }
    .submit-btn {
       background-color: #DB7400;
       border: solid 1px #000;
       border-radius: 5px;
       color: #FFF;
       padding: 10px 20px 10px 20px;
       text-decoration: none;
       cursor: pointer;
    }
    ```

1.  将以下 JavaScript 代码添加到`recipe-9.js`中，以监视`username`字段上的用户输入，并确保不输入非字母数字字符：

    ```js
    $(function(){
        $('.username').on("keypress", function(event){
            //Get key press character code
            var key = String.fromCharCode(event.which);
            if (/[^a-zA-Z\d\s:]/.test(key)) {
                event.preventDefault();
                return false;
            }
        });
    });
    ```

1.  在 Web 浏览器中打开 `recipe-9.html` 并尝试在 `username` 字段中输入非字母数字字符（例如，`$`）。你会发现它不会被放置在字段中。

## 工作原理…

页面加载时将键按下事件处理程序附加到 `username` 字段。此事件处理程序的回调函数有一个参数，即 `event` 对象。此 `event` 对象提供对用户按下的键的键码的访问。当 `username` 字段具有焦点并且用户按下键时，将执行回调函数。

首先，`String.fromCharCode(event.which);` 用于获取按下键的字符串值；例如，`D`、`H` 和 `4`。然后使用正则表达式来确定该字符是否是字母数字字符。如果不是，则使用以下代码阻止该字符输入到表单字段中：

```js
if (/[^a-zA-Z\d\s:]/.test(key)) {
   event.preventDefault();
   return false;
}
```

## 更多内容…

确保此示例中使用的事件是 `keypress` 事件。如果使用了替代事件，如 `keydown`，可能无法达到预期的结果。如果使用 `keydown` 事件，当用户按下 *Shift* + *4* 来输入 `$` 符号时，`keydown` 事件将以 `4` 而不是 `$` 提供其事件处理程序，因此未通过验证。


# 第六章：用户界面

在本章中，我们将涵盖以下主题：

+   操纵元素的 CSS

+   创建一个新闻滚动条

+   创建固定元素

+   实现平滑滚动

+   创建一个动态目录表

+   创建基本的拖放功能

+   创建一个动态动画树形菜单

+   创建一个手风琴内容滑块

+   创建标签式内容

+   创建一个模态框弹出窗口

+   创建一个可拖动的内容弹出窗口

# 介绍

jQuery 赋予开发人员轻松创建复杂用户界面元素的能力。正因为如此，有大量的 jQuery 插件允许开发人员快速将这些界面添加到其网站中。另外，jQuery 的 UI 框架还拥有许多热门界面元素，如手风琴、表格内容、模态框等。如果您想了解如何在自己的网站上使用 jQuery UI，请直接跳转至第九章，*jQuery UI*。本章将专注于从头开始开发一些这些常见的 UI 元素，提供无限的定制性，并让您了解其他插件的工作原理。

# 操纵元素的 CSS

jQuery 允许开发者直接访问 DOM 元素的 CSS 属性。这为您基于 JavaScript 中的数据轻松改变应用程序的外观和感觉提供了一种简单的方式。本教程将向您展示如何在各种元素中操纵 DOM CSS。

## 准备工作

对于这个教程，您将需要三个文件。使用您选择的编辑器，在与最新版本的 jQuery 库相同的目录中创建`recipe-1.html`、`recipe-1.js`和`recipe-1.css`。

## 如何做…

在您刚刚创建的三个文件中，打开每个文件进行编辑，并执行以下步骤：

1.  将以下 HTML 代码添加到`recipe-1.html`；确保更改包含 jQuery 库的 JavaScript 的源位置，将其指向您计算机上下载的最新版本的 jQuery：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 1</title>
        <link href="recipe-1.css" rel="stylesheet" 
              type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-1.js"></script>
    </head>
    <body>
        <div class="header">
            <h1>ALTER ELEMENT CSS WITH JQUERY</h1>
        </div>
        <div class="content-frame">
            <div class="left">
                <h1>SOME TITLE HERE</h1>
                <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                <h2>SOME KIND OF SUBTITLE HERE</h2>
                <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
            </div>
            <div class="right">
                <h3>TITLE COLOUR</h3>
                <select class="title-colour">
                    <option value="#">Default</option>
                    <option value="red">Red</option>
                    <option value="green">Green</option>
                    <option value="orange">Orange</option>
                    <option value="blue">Blue</option>
                </select>
                <h3>PARAGRAPH SIZE</h3>
                <select class="p-size">
                    <option value="#">Default</option>
                    <option value="10px">10px</option>
                    <option value="15px">15px</option>
                    <option value="20px">20px</option>
                    <option value="25px">25px</option>
                </select>
            </div>
        </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-1.css`：

    ```js
    body {
        margin: 0;
        background-color: #5dace7;
    }
    .header {
        height: 150px;
        background-color: #0174cd;
    }
    .header h1 {
        margin: 0 50px 0 50px;
        padding: 0;
        line-height: 100px;
        font-size: 40px;
        color: #FFFFFF;
    }
    .content-frame {
        margin: -50px 50px 0 50px;
        background-color: #FFFFFF;
        border-radius: 10px;
        min-height: 500px;
        position: relative;
    }
    .content-frame .left {
        margin-right: 20%;
        padding: 20px;
    }
    .content-frame .left h1 {
        margin: 0;
    }
    .content-frame .right {
        width: 16%;
        padding: 2%;
        position: absolute;
        top: 0;
        right: 0;
        background-color: #F1F1F1;
        border-top-right-radius: 10px;
        border-bottom-right-radius: 10px;
    }
    .content-frame .right h3 {
        margin: 0;
        line-height: 30px;
        color: #333333;
    }
    .content-frame .right select {
        width: 100%;
    }
    ```

1.  将以下 jQuery 代码添加到`recipe-1.js`中，以为 HTML 代码中的 select 下拉框添加功能：

    ```js
    $(function(){
        $('.title-colour').on("change", function(){
            var colour = $(this).val();
            if (colour == "#") {
                colour = "";
            }
            $('h1, h2').css("color", colour);
        });
        $('.p-size').on("change", function(){
            var size = $(this).val();
            if (size == "#") {
                size = "";
            }
            $('p').css("font-size", size);
        });
    });
    ```

1.  在 web 浏览器中打开`recipe-1.html`，您应该会看到以下简单的网页：![如何做…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/recipe-1.jpg)

1.  使用右侧的下拉菜单来修改标题和段落元素的 CSS。

## 它是如何工作的…

HTML 创建了一个基本的网页，提供这样的元素，以便它们的 CSS 可以被 jQuery 操纵，并提供一个简单的界面来启动这些更改。`recipe-1.css`中的 CSS 代码添加了基本的样式来创建我们的网页布局。

要更改元素的 CSS，将`change`事件处理程序附加到两个 select 下拉框，使用它们各自的类名：

```js
$(function(){
   $('.title-colour').on("change", function(){

});
$('.p-size').on("change", function(){

});
});
```

这将允许我们在用户更改标题颜色 (`title-colour`) 或段落大小 (`p-size`) 下拉菜单的值时执行一些代码。使用 `$(this).val()`，可以获取所选选项的值，如下面的代码片段所示：

```js
$(function(){
    $('.title-colour').on("change", function(){
        var colour = $(this).val();
        if (colour == "#") {
            colour = "";
        }
        $('h1, h2').css("color", colour);
    });
    $('.p-size').on("change", function(){
        var size = $(this).val();
        if (size == "#") {
            size = "";
        }
        $('p').css("font-size", size);
    });
});
```

使用 `colour` 或 `size` 变量（它们保存了各自下拉菜单中选定的值），我们确定默认选项是否已被选中，使用其值 `#`。如果已选择，则我们将 `colour` 或 `size` 值设置为空，允许用户将操纵的 CSS 重置为默认值。

如果选择了除默认选项之外的选项，则该值将与 jQuery 的 `css()` 函数中的相应 CSS 选项一起使用，如下面的代码片段中所示：

```js
$(function(){
    $('.title-colour').on("change", function(){
        var colour = $(this).val();
        if (colour == "#") colour = "";
        $('h1, h2').css("color", colour);
    });
    $('.p-size').on("change", function(){
        var size = $(this).val();
        if (size == "#") size = "";
        $('p').css("font-size", size);
    });
});
```

# 创建一个新闻滚动条

本教程将向您展示如何创建一个带有停止/暂停功能的简单新闻滚动条。新闻滚动条是在小空间中显示大量信息（如推文、引用语或一般新闻项目）的绝佳方式。

## 准备工作

再次，您需要创建三个文件。在与最新版本的 jQuery 相同的目录中创建 `recipe-2.html`、`recipe-2.css` 和 `recipe-2.js`。

## 如何操作…

按照以下逐步说明创建一个动画新闻滚动条：

1.  将以下 HTML 代码添加到 `recipe-2.html` 中，以创建一个简单的网页和我们的滚动条内容：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 2</title>
        <link href="recipe-2.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-2.js"></script>
    </head>
    <body>
    <div class="header">
        <h1>CONTENT TICKER</h1>
    </div>
    <div class="content-frame">
        <ul id="ticker">
            <li>Learn from yesterday, live for today, hope for tomorrow. The important thing is not to stop questioning</li>
            <li>Try not to become a man of success, but rather try to become a man of value</li>
            <li>Logic will get you from A to B. Imagination will take you everywhere</li>
            <li>Reality is merely an illusion, albeit a very persistent one</li>
        </ul>
    </div>
    </body>
    </html>
    ```

1.  将以下简单的 CSS 添加到 `recipe-2.css` 中，为我们的网页添加样式：

    ```js
    body {
        margin: 0;
        background-color: #5dace7;
    }
    .header {
        height: 130px;
        background-color: #0174cd;
    }
    .header h1 {
        margin: 0 50px 0 50px;
        padding: 0;
        line-height: 100px;
        font-size: 40px;
        color: #FFFFFF;
    }
    .content-frame {
        margin: -30px 50px 0 50px;
        background-color: #FFFFFF;
        border-radius: 10px;
        height: 50px;
        position: relative;
        padding: 0 20px 0 20px;
        overflow: hidden;
    }
    .content-frame ul {
        list-style: none;
        margin: 0;
        padding: 0;
    }
    .content-frame ul li {
        line-height: 50px;
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-2.js` 中，使我们的滚动条生效：

    ```js
    var tick = null;
    var interval = 2000;
    $(function(){
        tick = setInterval(function(){
            ticker()
        }, interval);
        $('.content-frame').on("mouseover", function(){
            clearInterval(tick);
        });
        $('.content-frame').on("mouseout", function(){
            tick = setInterval(function(){
                ticker()
            }, interval);
        });
    });
    function ticker() {
        $('#ticker li:first-child').slideUp(function(){
            $(this).appendTo($('#ticker')).slideDown();
        });
    }
    ```

1.  在网络浏览器中打开 `recipe-2.html` 将呈现一个简单的网页和一个动画滚动条，每两秒显示爱因斯坦的不同引用语。

## 工作原理…

由于 HTML 和 CSS 代码非常简单，因此唯一需要解释的是 jQuery 代码。请注意，HTML 网页包含一个无序列表元素，其中包含四条爱因斯坦的引用语，位于名为 `content-frame` 的 division 元素内。`content-frame` 元素的 `overflow` 属性设置为 `hidden`，以便一次只显示一个引用语。

在 `recipe-2.js` 文件的顶部声明了两个变量：`tick` 和 `interval`。`tick` 变量是 JavaScript 的 `setInterval()` 函数将要声明的地方。JavaScript 的 `setInterval()` 函数允许我们指定一个函数和一个间隔。然后，指定的函数将在指定的间隔内再次调用。这使我们能够循环遍历新闻滚动条内容。

通过在 JavaScript 文件顶部声明 `tick` 变量，我们可以在以后的某个时间点停止间隔以添加暂停功能。`interval` 变量只是保存我们希望 `setInterval()` 函数在再次调用指定函数之前等待的毫秒数：

```js
var tick = null;
var interval = 2000;
$(function(){

});
```

在 jQuery 的加载函数内部，我们将`tick`变量分配给`setInterval()`函数，指定函数再次调用，然后使用`interval`变量设置间隔持续时间，如以下代码段所示：

```js
$(function(){
    tick = setInterval(function(){
        ticker();
    }, interval);
});
```

要添加停止/启动功能，根据用户将鼠标悬停在滚动条上时停止滚动并在将鼠标移开时重新启动滚动的要求，我们需要为`content-frame`部分元素附加两个事件处理程序，如下所示：

```js
$(function(){
    tick = setInterval(function(){
        ticker()
    }, interval);
    $('.content-frame').on("mouseover", function(){
        clearInterval(tick);
    });
    $('.content-frame').on("mouseout", function(){
        tick = setInterval(function(){
            ticker()
        }, interval);
    });
});
```

`mouseover`事件处理程序使用 JavaScript 的`clearInterval()`函数，并将`tick`变量作为参数传递。当用户将鼠标悬停在`content-frame`元素上时，这将阻止`setInterval()`函数再次调用`ticker()`函数。在`mouseout`事件的回调函数中，使用相同的`setInterval()`函数重新声明`tick`变量，重新初始化新闻滚动条并再次启动它。

最后，还有`ticker()`函数本身。此函数使用 jQuery 的`slideUp()`函数将第一个列表元素向上滑动。这提供了下一个元素进入视图的效果。然后，它使用`appendTo()`将使用`slideUp()`函数隐藏的元素移动到滚动条列表的末尾。最后，它使用`slideDown()`将此元素再次滑动下来，以便在最终再次移动到列表顶部时准备显示。如以下代码段所示：

```js
function ticker() {
    $('#ticker li:first-child').slideUp(function(){
        $(this).appendTo($('#ticker')).slideDown();
    });
}
```

## 更多内容…

可以以任何你喜欢的方式采用启动和停止功能，例如，使用启动和停止按钮，或者甚至一个单独的暂停按钮，以便更明显地表明可以暂停滚动。本示例中使用的方法的好处是，链接通常会显示在滚动内容中。当用户试图点击滚动内容中的链接时，滚动将停止，允许他们点击链接，而不是在他们点击之前链接就移开。

## 另请参阅

+   *创建动态目录*

# 创建固定元素

固定元素是页面元素，在用户滚动时会固定在浏览器中的位置。固定元素用于始终保持内容在用户视线内。这些内容可以是导航、重要信息，甚至是广告。本示例将展示如何创建固定元素，并且使用 jQuery 在用户滚动到页面上某一点时激活它们。

## 准备工作

使用你喜欢的编辑器，在与你的 jQuery 库相同的目录下创建三个文件，分别命名为`recipe-3.html`、`recipe-3.css`和`recipe-3.js`。

## 如何做…

对于每个新创建的文件，执行以下步骤：

1.  将以下 HTML 代码添加到`recipe-3.html`中；它创建了一个长网页，可以滚动，并且一个`div`元素，其中包含一些重要内容需要始终保持在用户视线内：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 3</title>
        <link href="recipe-3.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-3.js"></script>
    </head>
    <body>
    <div class="header">
        <h1>STICKY ELEMENTS RECIPE</h1>
    </div>
    <div class="content-frame">
        <div class="left">
            <h1>STICKY ELEMENTS</h1>
            <p>Sticky elements are great to keep important content within the users view, such as share buttons, navigation and also table of contents.</p>
            <p>Scroll down this page and when you are about to go past the important content on the right hand side, it will start to follow you down the screen.</p>
        </div>
        <div class="right">
            <ul>
                <li><a href="#">Navigation Item 1</a></li>
                <li><a href="#">Navigation Item 2</a></li>
                <li><a href="#">Navigation Item 3</a></li>
                <li><a href="#">Navigation Item 4</a></li>
                <li><a href="#">Navigation Item 5</a></li>
                <li><a href="#">Navigation Item 6</a></li>
            </ul>
            <div class="important">
                <p>Here is some important content.</p>
            </div>
        </div>
    </div>
    </body>
    </html>
    ```

1.  为了给这个页面添加样式，将以下 CSS 代码添加到 `recipe-3.css` 文件中；代码中还包含一个 `sticky` 类，在用户滚动页面时会被 jQuery 应用到重要元素上：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Ubuntu);
    body {
        margin: 0;
        background-color: #5dace7;
        font-family: 'Ubuntu', sans-serif;
    }
    .header {
        height: 150px;
        background-color: #0174cd;
    }
    .header h1 {
        width: 1000px;
        margin: auto;
        padding: 0;
        line-height: 100px;
        font-size: 40px;
        color: #FFFFFF;
    }
    .content-frame {
        margin: -50px auto auto auto;
        width: 1000px;
        background-color: #FFFFFF;
        border-radius: 10px;
        min-height: 1300px;
        position: relative;
    }
    .content-frame .left {
        margin-right: 240px;
        padding: 20px;
    }
    .content-frame .left h1 {
        margin: 0;
    }
    .content-frame .right {
        width: 200px;
        padding: 10px;
        position: absolute;
        top: 0;
        right: 0;
        background-color: #F1F1F1;
        border-top-right-radius: 10px;
        border-bottom-right-radius: 10px;
    }
    .content-frame .right .important {
        border: solid 1px #CCCCCC;
        text-align: center;
        width: 200px;
    }
    .sticky {
        position: fixed;
        top: 10px;
    }
    ```

1.  最后，将以下 jQuery 代码添加到 `recipe-3.js` 中，当用户试图滚过时，将激活固定元素：

    ```js
    var importantOrigin = {};
    $(function(){
        importantOrigin = $('.important').offset();
        $(window).scroll(function(){
            sticky();
        });
    });
    function sticky() {
        var _important = $('.important');
        var scrollPosition = $('body, html').scrollTop();
        if (importantOrigin.top < scrollPosition) {
            _important.addClass("sticky");
        } else {
            _important.removeClass("sticky");
        }
    }
    ```

## 工作原理...

在 `recipe-3.js` 的顶部，有一个名为 `importantOrigin` 的变量，它将用于存储重要部分元素的原始位置。在 jQuery 的加载块中，使用 `$('.important').offset()` 获取重要元素的顶部和左侧位置，并将这些值存储在先前创建的 `importantOrigin` 变量中。如下面的代码片段所示：

```js
var importantOrigin = {};
$(function(){
    importantOrigin = $('.important').offset();
    $(window).scroll(function(){
        sticky();
    });
});
```

jQuery 的 `scroll()` 函数用于在用户滚动页面时执行 `sticky()` 方法：

```js
function sticky() {
    var _important = $('.important');
    var scrollPosition = $('body, html').scrollTop();
    if (importantOrigin.top < scrollPosition) {
        _important.addClass("sticky");
    } else {
        _important.removeClass("sticky");
    }
}
```

`sticky()` 方法使用 `$('body, html').scrollTop()` 获取页面的当前垂直位置，然后将其与重要元素的顶部位置进行比较。如果用户滚过了重要元素，则使用 `addClass()` 方法将 `sticky` CSS 类应用于重要元素：

```js
.sticky {
    position: fixed;
    top: 10px;
}
```

如果页面的当前垂直位置低于 `sticky` 元素的顶部，则使用 `removeClass()` 将 `sticky` 类移除，将重要元素恢复到其原始状态。在 CSS 中使用 `position: fixed;`，可以使元素固定在页面的某一点。使用 jQuery 条件性地应用此 CSS，我们可以控制何时应用元素固定，因为通常直到用户滚动过元素，使其不再在屏幕上可见，才希望这样做。

## 还有更多...

有一个流行的 jQuery 插件叫做 `sticky.js`，可以在 [`stickyjs.com/`](http://stickyjs.com/) 找到。该插件使用了您在本文档中学到的相同原理，并将所有功能打包成插件，以便于重用。

## 参见

+   *创建一个动态目录表*

# 实现平滑滚动

锚点链接用于导航到页面的不同部分，使用户能够轻松地跳过他们不感兴趣的信息，直接进入感兴趣的部分。然而，当屏幕上有大量文本数据时，在这些不同部分之间跳转通常会让用户感到困惑。使用平滑滚动并将屏幕动画地缓慢向上或向下移动到所选部分，用户可以更容易地可视化自己导航到的位置，而不会感到迷失方向。

## 准备工作

只需创建三个标准的配方文件，`recipe-4.html`、`recipe-4.css` 和 `recipe-4.js`，并将它们保存到与最新版本的 jQuery 库相同的目录中。

## 实现方法...

执行以下简单步骤，为网站或网页添加平滑滚动效果：

1.  通过将以下 HTML 代码添加到 `recipe-4.html` 文件中，可以创建一个较长的网页：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 4</title>
        <link href="recipe-4.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-4.js"></script>
    </head>
    <body>
    <div class="header">
        <h1 id="top">SMOOTH SCROLLING RECIPE</h1>
    </div>
    <div class="content-frame">
        <div class="left">
            <h2 id="one">SECTION 1 <a href="#top" class="top-link">[TOP]</a></h2>
            <div class="section"></div>
            <h2 id="two">SECTION 2 <a href="#top" class="top-link">[TOP]</a></h2>
            <div class="section"></div>
            <h2 id="three">SECTION 3 <a href="#top" class="top-link">[TOP]</a></h2>
            <div class="section"></div>
            <h2 id="four">SECTION 4 <a href="#top" class="top-link">[TOP]</a></h2>
            <div class="section"></div>
        </div>
        <div class="right">
            <h2>NAVIGATION</h2>
            <ul>
                <li><a href="#one">SECTION ONE</a></li>
                <li><a href="#two">SECTION TWO</a></li>
                <li><a href="#three">SECTION THREE</a></li>
                <li><a href="#four">SECTION FOUR</a></li>
                <li><a href="http://www.google.com" target="_blank">EXTERNAL LINK</a></li>
                <li><a href="#">EMPTY LINK</a></li>
            </ul>
        </div>
    </div>
    </body>
    </html>
    ```

1.  通过将以下 CSS 代码添加到`recipe-4.css`中（此文件在前面的 HTML 页面中已经包含）来为这个页面添加样式：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Ubuntu);
    body {
        margin: 0;
        background-color: #5dace7;
        font-family: 'Ubuntu', sans-serif;
    }
    .header {
        height: 150px;
        background-color: #0174cd;
    }
    .header h1 {
        width: 1000px;
        margin: auto;
        padding: 0;
        line-height: 100px;
        font-size: 40px;
        color: #FFFFFF;
    }
    .content-frame {
        margin: -50px auto auto auto;
        width: 1000px;
        background-color: #FFFFFF;
        border-radius: 10px;
        min-height: 1300px;
        position: relative;
    }
    .content-frame .left {
        margin-right: 240px;
        padding: 20px;
    }
    .content-frame .left h1 {
        margin: 0;
    }
    .content-frame .right {
        width: 200px;
        padding: 10px;
        position: absolute;
        top: 0; 
        right: 0;
        background-color: #F1F1F1;
        border-top-right-radius: 10px;
        border-bottom-right-radius: 10px;
    }
    .content-frame .right h2 {
        margin: 0;
        padding: 0;
    }
    .section {
        height: 400px;
        background-color: #CCCCCC;
        margin-bottom: 20px;
    }
    .top-link {
        width: 50px;
        text-align: right;
        float: right;
        font-size: 12px;
    }
    ```

1.  将以下 jQuery 代码添加到`recipe-4.js`以捕捉锚点元素点击并提供平滑滚动效果：

    ```js
    $(function(){
        $('a[href*=#]:not([href=#])').click(function(){
            if (this.hash.length > 0) {
                $('body, html').animate({
                    scrollTop: $(this.hash).offset().top
                }, 1000);
            }
            return false;
        });
    });
    ```

## 工作原理…

jQuery 代码首先将`click`事件处理程序附加到某些锚点元素上：

```js
$(function(){
    $('a[href*=#]:not([href=#])').click(function(){

    });
});
```

前面的代码将仅将`click`事件处理程序附加到其`href`属性中具有哈希（`#`）的锚点。还使用`:not([href=#])`，以便不会将事件处理程序附加到其`href`属性只有一个哈希的锚点。现在，我们可以指定要执行的代码，以便在页面上导航到其他部分的链接。空白和外部链接将被忽略并像往常一样运行。

在`click`事件处理程序的`callback()`函数内，我们可以使用`this.hash`来检索点击的锚点元素的`href`属性中的哈希值。如果锚点链接到`#two`，我们会收到字符串值`"#two"`。使用`this.hash.length`，我们可以确保值是有效的，并且我们可以继续提供平滑滚动动画：

```js
$(function(){
    $('a[href*=#]:not([href=#])').click(function(){
        if (this.hash.length > 0) {

        }
        return false;
    });
});
```

在`this.hash.length`的`if`语句内，我们使用 jQuery 的`animate()`函数如下来动画和滚动用户到锚点目标的位置：

```js
$('body, html').animate({
   scrollTop: $(this.hash).offset().top
}, 1000);
```

`scrollTop`参数是动画应该滚动到的位置。我们通过使用`$(this.hash)`选择目标元素，然后使用 jQuery 的`offset()`函数获取其顶部位置。

最后，在`this.hash.length`的`if`语句之后返回`false`，以防止点击事件的默认操作。如果去掉`return false`，在动画开始之前会出现屏幕闪烁，因为点击事件的默认操作（将用户发送到链接的部分）发生在动画开始之前。

## 另见

+   *创建一个动态目录*

# 创建一个动态目录

目录是让用户快速找到他们正在寻找的内容部分的常见方式。使用 jQuery，可以根据页面上的 HTML 标题元素动态创建目录。这对于博客文章或其他拥有许多不同内容页面的网站非常有用。

## 准备工作

创建`recipe-5.html`、`recipe-5.css`和`recipe-5.js`，并像以前一样都准备好进行编辑。

## 如何做…

创建了必需的文件之后，按照以下步骤创建一个动态目录：

1.  使用以下 HTML 代码创建一个基本网页，并将其添加到`recipe-5.html`中：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 5</title>
        <link href="recipe-5.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-5.js"></script>
    </head>
    <body>
    </body>
    </html>
    ```

1.  将以下 HTML 代码添加到刚刚添加的 `body` 标签内的 `recipe-5.html` 中；这将创建一个带有分节内容和有序列表元素的页面，可以填充内容：

    ```js
    <div class="header">
        <h1>DYNAMIC TABLE OF CONTENTS</h1>
    </div>
    <div class="content-frame">
        <div class="left">
            <h1 id="one">MAIN HEADING</h1>
            <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <h2 id="two">SUBTITLE</h2>
            <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.</p>
            <h3 id="three">SUB-SUBTITLE</h3>
            <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <h2 id="four">SUBTITLE</h2>
            <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <h3 id="five">SUB-SUBTITLE</h3>
            <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
            <h4 id="six">SUB-SUB-SUBTITLE</h4>
            <p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
        </div>
        <div class="right">
            <h2>CONTENTS</h2>
            <ol class="contents"></ol>
        </div>
    </div>
    ```

1.  将以下 CSS 添加到`recipe-5.css`以向此页面添加基本样式。这段 CSS 代码再次与本章前两个示例中的代码非常相似：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Ubuntu);
    body {
        margin: 0;
        background-color: #5dace7;
        font-family: 'Ubuntu', sans-serif;
    }
    .header {
        height: 150px;
        background-color: #0174cd;
    }
    .header h1 {
        width: 1000px;
        margin: auto;
        padding: 0;
        line-height: 100px;
        font-size: 40px;
        color: #FFFFFF;
    }
    .content-frame {
        margin: -50px auto auto auto;
        width: 1000px;
        background-color: #FFFFFF;
        border-radius: 10px;
        min-height: 1300px;
        position: relative;
    }
    .content-frame .left {
        margin-right: 240px;
        padding: 20px;
    }
    .content-frame .left h1 {
        margin: 0;
    }
    .content-frame .right {
        width: 200px;
        padding: 10px;
        position: absolute;
        top: 0;
        bottom: 0;
        right: 0;
        background-color: #F1F1F1;
        border-top-right-radius: 10px;
        border-bottom-right-radius: 10px;
    }
    .content-frame .right h2 {
        margin: 0;
        padding: 0;
    }
    ```

1.  将以下 jQuery 代码添加到`recipe-5.js`中，它将根据我们刚刚创建的 HTML 页面中的标题部分填充有序列表：

    ```js
    $(function(){
        var _contents = $('.content-frame .left');
        var _headers = _contents.find("h1, h2, h3, h4");
        _headers.each(function(index, value){
            var _header = $(value);
            var level = parseInt(_header.context.localName.replace("h", ""));
            if (typeof _header.attr("id") != "undefined") {
                var listItem = $("<li><a href='#" + _header.attr("id") + "'>" + _header.html() + "</a></li>");
            } else {
                var listItem = $("<li>" + _header.html() + "</li>");
            }
            listItem.css("padding-left", (level * 5));
            $('.contents').append($(listItem));
        });
    });
    ```

1.  在网页中打开`recipe-5.html`将向您展示内容在屏幕左侧，动态生成的内容列表在右侧，如下截图所示：![如何做…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/recipe-5.jpg)

## 它是如何运行的...

HTML 代码提供了一个包含由`h1`、`h2`、`h3`和`h4`标签标头的各种部分以及一个空的有序列表元素的内容窗格。

我们的 jQuery 代码首先选择内容部分，然后使用 jQuery `find()`函数找到其中的所有标题元素，并指定`h1, h2, h3, h4`作为唯一参数。这将创建一个找到的元素数组，并将它们存储在`_headers`数组中，如下代码片段所示：

```js
$(function(){
    var _contents = $('.content-frame .left');
    var _headers = _contents.find("h1, h2, h3, h4");
// --- HIDDEN CODE
});
```

然后使用 jQuery `each()`函数，可以遍历找到的所有标题元素并构建目录。首先声明本地变量`_header`，并将当前标题元素存储在此变量中。

为了能够缩进目录中的子节，使用户更容易看到内容结构，代码需要确定当前标题的级别：`h1`为顶级，`h5`为底级。使用`_header.context.localName`，我们可以获取标题元素的标签（例如，`h1`）并使用 JavaScript 的`replace()`删除"`h`"。然后，我们可以使用`parseInt()`将剩余值转换为整数。我们得到一个值，可以用来确定标题元素的级别。这个过程在以下代码片段中显示：

```js
$(function(){
    var _contents = $('.content-frame .left');
    var _headers = _contents.find("h1, h2, h3, h4");
    _headers.each(function(index, value){
        var _header = $(value);
        var level = parseInt(_header.context.localName.replace("h", ""));
        // --- HIDDEN CODE
    });
});
```

现在我们可以创建列表元素，并将其插入有序列表中。为了将目录中的项目链接到内容的适当部分，我们需要检查标题元素是否有我们可以链接到的 ID。如果有，我们通过执行以下代码创建带有链接的列表元素；否则，我们通过执行以下代码创建基本列表元素：

```js
$(function(){
    var _contents = $('.content-frame .left');
    var _headers = _contents.find("h1, h2, h3, h4");
    _headers.each(function(index, value){
        var _header = $(value);
        var level = parseInt(_header.context.localName.replace("h", ""));
        if (typeof _header.attr("id") != "undefined") {
            var listItem = $("<li><a href='#" + _header.attr("id") + "'>" + _header.html() + "</a></li>");
        } else {
            var listItem = $("<li>" + _header.html() + "</li>");
        }
        listItem.css("padding-left", (level * 5));
        $('.contents').append($(listItem));
    });
});
```

最后，创建完列表项后，使用`css()`函数和`level`变量添加所需的缩进填充，并将创建的列表项附加到内容的有序列表中。

## 还有更多...

您可以将此配方与*实现平滑滚动*和*创建粘性元素*配方结合使用，迫使目录随用户向下滚动页面并为更好的用户体验提供滚动动画。

## 参见

+   *创建粘性元素*

+   *实现平滑滚动*

# 创建基本的拖放功能

通过向网站添加拖放元素，可以创建有趣且直观的界面。jQuery UI 带有内置插件，用于拖放界面。本产品介绍将向您展示如何创建基本的拖放功能，而无需使用任何插件，从而为您扩展代码提供自由和理解。

## 准备工作

创建一个名为`recipe-6.html`的空白 HTML 页面，并将`recipe-6.css`和`recipe-6.js`文件放在与最新版本 jQuery 库相同的目录中。

## 如何做…

按照以下分步说明执行以下操作完成此步骤：

1.  将以下 HTML 代码添加到`recipe-6.html`中，在容器`div`中创建一个基本的 HTML 页面，其中包含三个`draggable`元素：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 6</title>
        <link href="recipe-6.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-6.js"></script>
    </head>
    <body>
        <div class="container">
            <div class="draggable"></div>
            <div class="draggable"></div>
            <div class="draggable"></div>
        </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-6.css`中，为 HTML 页面和`draggable`元素添加样式：

    ```js
    .container {
        width: 800px;
        height: 500px;
        border: solid 2px #333333;
        margin: 20px auto auto auto;
    }
    .draggable {
        width: 120px;
        height: 120px;
        margin: 10px;
        background-color: darkred;
           cursor: pointer;
    }
    .draggable.dragging {
        box-shadow: 5px 5px 5px #CCC;
    }
    ```

1.  将以下 jQuery 代码插入`recipe-6.js`中，为`draggable`元素应用拖放功能：

    ```js
    $(function(){
        $('.draggable').on("mousedown", function(){
           $(this).addClass('dragging');
        }).on("mousemove mouseout", function(event){
                if ($(this).hasClass("dragging")) {
                    //Get the parents position
                    var parentPosition = $(this).parent().offset();

                    //Don't allow the draggable element to go over the parent's left and right
                    var left = (event.pageX - ($(this).width() / 2));
                    var parentRight = parentPosition.left + $(this).parent().width();
                   if (left > (parentRight - $(this).width())){
                        left = (parentRight - $(this).width());
                    } else if(left <= parentPosition.left) {
                        left = parentPosition.left;
                    }

                    //Don't allow the draggable element to go over the parent's top and bottom
                    var top = (event.pageY - ($(this).height() / 2));
                    var parentBottom = parentPosition.top + $(this).parent().height();
                    if (top > (parentBottom - $(this).height())) {
                        top = (parentBottom - $(this).height());
                    } else if (top <= parentPosition.top) {
                        top = parentPosition.top;
                    }

                    //Set new position
                    $(this).css({
                        top: top + "px",
                        left: left + "px",
                        position: "absolute"
                    });
                }
        }).on("mouseup", function(){
            $(this).removeClass('dragging');
        });
    });
    ```

1.  在 Web 浏览器中打开`recipe-6.html`并单击其中一个红色框。这将向元素应用`dragging` CSS 类，允许您在页面内的框划分中移动它。

## 运作原理…

HTML 页面提供一个充当`draggable`元素容器的`div`元素。`frame`元素内有三个额外的`div`元素。这三个元素具有`draggable`类，jQuery 将使用这个类应用拖放功能。

配方中使用的 CSS 代码在`frame`元素上创建边框，并为`draggable`元素设置高度、宽度和背景颜色。还有一个`dragging`类，当移动`draggable`元素时，会为其应用阴影。

在 jQuery 代码本身中，使用一系列鼠标事件来创建拖放功能。使用 jQuery 的`on()`函数将不同的事件处理程序应用于`draggable`元素。应用在`draggable`元素上的第一个事件处理程序是`mousedown`事件，如下所示：

```js
$('.draggable').on("mousedown", function(){
       $(this).addClass('dragging');
})
```

这只是向刚刚被点击的元素（`mousedown`）添加`dragging`类。

接下来要绑定的事件处理程序是`mousemove`和`mouseout`事件。这允许我们根据用户在点击选定元素的同时移动鼠标指针时，根据鼠标位置更新点击元素的位置。我们还针对用户移动太快并将鼠标指针移出选定的`draggable`框时使用相同的代码来处理`mouseout`事件。由于相同的代码附加到`mouseout`事件上，框的位置将被更新为鼠标的位置。

```js
.on("mousemove mouseout", function(event){
            if ($(this).hasClass("dragging")) {
                //Get the parents position
                var parentPosition = $(this).parent().offset();

                //Don't allow the draggable element to over the parent's left and right
                var left = (event.pageX - ($(this).width() / 2));
                var parentRight = parentPosition.left + $(this).parent().width();
                if (left > (parentRight - $(this).width())) {
                    left = (parentRight - $(this).width());
                } else if(left <= parentPosition.left) {
                    left = parentPosition.left;
                }

                //Don't allow the draggable element to go over the parent's top and bottom
                var top = (event.pageY - ($(this).height() / 2));
                var parentBottom = parentPosition.top + $(this).parent().height();
                if (top > (parentBottom - $(this).height())) {
                    top = (parentBottom - $(this).height());
                } else if (top <= parentPosition.top) {
                    top = parentPosition.top;
                }

                //Set new position
                $(this).css({
                    top: top + "px",
                    left: left + "px",
                    position: "absolute"
                });
            }
    })
```

这两个事件的回调函数是添加主要功能的地方。这段代码看起来很复杂，但一旦我们将它分解开来，就很容易理解。首要的是，除非点击的元素有`dragging`类，否则什么也不会发生。这是通过以下`if`语句来实现的，它检查`dragging`类：

```js
if ($(this).hasClass("dragging")) {
   //MAIN FUNCTIONALITY HERE
}
```

在这个`if`语句内，首先获取了点击元素的父元素位置（`frame`元素），这样我们就可以计算出`draggable`元素的边界：

```js
var parentPosition = $(this).parent().offset();
```

下一块代码查看了点击元素的位置，并确定了它是否小于`frame`元素的左侧位置或大于容器元素的右侧位置。如果是其中一个，`dragging`元素的位置被设置为边界限制，而不是鼠标指针的位置，从而阻止用户能够将元素拖到容器元素的左右边界之外：

```js
//Don't allow the draggable element to over the parent's left and right
var left = (event.pageX - ($(this).width() / 2));
var parentRight = parentPosition.left + $(this).parent().width();
if (left > (parentRight - $(this).width())) {
left = (parentRight - $(this).width());
} else if(left <= parentPosition.left) {
left = parentPosition.left;
}
```

如果`draggable`元素的位置不在边界上方，那么它的位置将被更新为鼠标指针的左侧位置减去`dragging`元素的宽度，以便在拖动时鼠标指针始终在元素的中心。

接下来，相同的逻辑应用于顶部和底部的边界：

```js
//Don't allow the draggable element to go over the parent's top and bottom
var top = (event.pageY - ($(this).height() / 2));
var parentBottom = parentPosition.top + $(this).parent().height();
if (top > (parentBottom - $(this).height())) {
    top = (parentBottom - $(this).height());
} else if (top <= parentPosition.top) {
    top = parentPosition.top;
}
```

最后，现在`draggable`元素的新顶部和左侧位置已经计算出来，知道它是鼠标指针的位置减去`draggable`元素的宽度/高度除以二或边界限制，就可以使用 jQuery CSS 函数应用这些位置，并同时将 CSS`position`属性设置为`absolute`：

```js
//Set new position
$(this).css({
top: top + "px",
left: left + "px",
position: "absolute"
});
```

最后，使用了最后一个事件——`mouseup`事件——当用户释放鼠标指针时触发，这时将从`dragging`元素中移除`dragging` CSS 类：

```js
.on("mouseup", function(){
        $(this).removeClass('dragging');
});
```

## 另请参见

+   *创建一个可拖动的内容弹出窗口*

# 创建一个动态的动画树状菜单

树状菜单是在有限的空间内显示大量信息并允许用户选择他们希望看到的信息的好方法。这个配方将向你展示如何基于一组 JSON 对象动态创建具有上下滑动效果的树状菜单。

## 准备工作

为了这个配方创建`recipe-7.html`、`recipe-7.js`和`recipe-7.css`，并确保它们保存在与 jQuery 的最新版本相同的目录中。

## 如何操作…

为了创建一个动态的动画树状菜单，请确保您完成以下所有指示：

1.  在`recipe-7.html`中添加以下 HTML 代码，以创建此配方所需的基本网页：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 7</title>
        <link href="recipe-7.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-7.js"></script>
    </head>
    <body>
    <div class="container">
        <div class="list-container"></div>
    </div>
    </body>
    </html>
    ```

1.  在`recipe-7.css`中添加以下样式：

    ```js
    .list-container {
        width: 800px;
        margin: 20px auto auto auto;
    }
    ul {
        margin: 0;
        padding: 0;
        list-style: none;
    }
    ul li {
        line-height: 25px;
        margin: 5px 0 5px 0;
        position: relative;
        padding: 0 0 0 5px;
        color: #666;
    }
    ul li a {
        display: block;
        background-color: #333;
        padding: 0 0 0 30px;
        margin-left: -5px;
        text-decoration: none;
        color: #FFF;
    }
    .arrow {
        position: absolute;
        width: 20px;
        height: 20px;
        left: 5px;
        top: 2px;
    }
    .right-arrow {
        width: 0;
        height: 0;
        border-top: 10px solid transparent;
        border-bottom: 10px solid transparent;
        border-left: 10px solid white;
    }
    .down-arrow {
        width: 0;
        border-left: 10px solid transparent;
        border-right: 10px solid transparent;
        border-top: 10px solid white;
        top: 7px;
    }
    .list-bg {
        background-color: #F1F1F1;
    }
    ```

1.  在`recipe-7.js`中添加以下 jQuery 代码，该代码提供了创建动态树菜单的数据和功能：

    ```js
    var tree = [
        {
            name: "Fastolph Bolger",
            children: []
        },
        {
            name: "Laura Grubb",
            children: [
                {
                    name: "Bungo",
                    children: [
                        {
                            name: "Bilbo",
                            children: []
                        }
                    ]
                },
                {
                    name: "Belba",
                    children: []
                },
                {
                    name: "Longo",
                    children: [
                        {
                            name: "Otho Sackville-Baggins",
                            children: [
                                {
                                    name: "Lotho",
                                    children: []
                                }
                            ]
                        }
                    ]
                }
            ]
        },
        {
            name: "Ponto",
            children: [
                {
                    name: "Rosa",
                    children: [
                        {
                            name: "Peregrin Took",
                            children: []
                        }
                    ]
                }
            ]
        }
    ];
    $(function(){
        var list = createList(tree, 1);
        $('.list-container').html(list);
        $(document).on('click', '.show-children', function(){
            $(this).next('ul').slideToggle();
            $(this).find('.right-arrow').toggleClass('down-arrow');
        });
    });

    function createList(children, level) {
        var style = "margin-left: " + (10 * level) + "px;"
        if (level > 1) {
            style += "display: none;";
        }
        var list = "<ul style='" + style + "'>";
        level++;
        for (var i = 0; i < children.length; i++) {
            if (children[i].children.length > 0) {
                list += "<li><a href='javascript:void(0)' class='show-children'><div class='arrow right-arrow'></div> " + children[i].name + "</a>";
                list += createList(children[i].children, level);
                list += "</li>";
            } else {
                list += "<li class='list-bg'>" + children[i].name + "</li>";
            }
        }
        list += "</ul>";
        return list;
    }
    ```

1.  在 web 浏览器中打开`recipe-7.html`并单击突出显示的列表项，以展开具有子项的列表，如下图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/recipe-7.jpg)

## 如何运作…

HTML 代码仅包含有效 HTML 页面和`list-container`分区元素的基本元素，jQuery 代码将使用该元素在创建后将列表 HTML 插入其中。CSS 代码包含基本列表样式以及一些样式以创建右箭头和向下箭头，如上一个屏幕截图所示。

JavaScript 代码的第一部分是一个对象数组，代表了一个家族谱系。家族谱中的每个人都可以有子女，并且树的深度没有限制。

jQuery 代码的主要功能在`createList()`函数中。此函数接受两个参数：对象数组（子女）和当前列表级别。在此函数内，根据`level`的值计算了一些内联样式。如果当前的`level`值不是`1`，这意味着当前级别不是最顶层级别，则列表默认隐藏。还根据级别应用左边距，以便每个较低级别时，列表都会向右移动，以创建您在应用程序中看到的典型树视图。创建一个`list`变量，并将无序列表元素的 HTML 添加到其中。接下来，循环遍历提供的每个对象，并为每个对象创建一个列表项。检查对象的`children`属性的长度以确定当前对象是否具有子女。如果有子女，则将链接和右箭头添加到列表中。然后，递归调用`createList()`函数，传入更新后的级别和当前对象自己的子女。此函数将返回一个填充有对象自己的子女的无序列表的 HTML。这将在树变量中的每个对象中发生，直到完全创建列表。然后，使用`$('.list-container').html(list);`将列表插入到 DOM 中，并将在页面上可见。

因为除了顶级项目之外的所有项目都是隐藏的，所以需要将`click`事件处理程序附加到每个具有子女的项目上，如下所示：

```js
$(document).on('click', '.show-children', function(){
        $(this).next('ul').slideToggle();
        $(this).find('.right-arrow').toggleClass('down-arrow');
});
```

一个单独的事件将监听任何具有`show-children`类的元素上的点击，并附加到文档上。当这些项目中的一个被点击时，`slideToggle()`函数将用于下一个无序列表元素（子女列表）以将其上下滑动。当子女列表打开时，`toggleClass()`函数也会用于`arrow`元素以使箭头向下指。

## 还有更多...

此示例使用静态 JavaScript 数组，但可以轻松地改为从 Web 服务器加载一组 JSON 对象。

## 另请参阅

+   *创建手风琴内容滑块*

+   *创建选项卡内容*

# 创建一个手风琴内容滑块

折叠内容允许用户轻松地跳过内容。有许多提供折叠功能的 jQuery 插件。但是，本示例将向您展示如何从头开始创建一个简单且吸引人的 jQuery 折叠内容滑块。

## 准备工作

在与 jQuery 库相同的目录中创建`recipe-8.html`、`recipe-8.css`和`recipe-8.js`。

## 如何做……

使用您新创建的文件，按照以下逐步说明完成操作：

1.  将以下 HTML 代码添加到`recipe-8.html`中，以创建一个包含折叠和内容的基本网页：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 8</title>
        <link href="recipe-8.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"script>
        <script src="img/recipe-8.js"></script>
    </head>
    <body>
    <div class="container">
        <div class="accordion">
            <section>
                <a href="#" class="header"><div class='arrow right-arrow down-arrow'></div> Section 1</a>
                <div class="content">
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
            </section>
            <section>
                <a href="#" class="header"><div class='arrow right-arrow'></div> Section 2</a>
                <div class="content">
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
            </section>
            <section>
                <a href="#" class="header"><div class='arrow right-arrow'></div> Section 3</a>
                <div class="content">
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
            </section>
        </div>
    </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-8.css`中，以为折叠添加样式：

    ```js
    .container {
        width: 800px;
        margin: 20px auto auto auto;
    }
    .accordion section a.header {
        display: block;
        line-height: 30px;
        /* fallback */
        background-color: #333333;
        background-repeat: repeat-x;
        /* Safari 4-5, Chrome 1-9 */
        background: -webkit-gradient(linear, 0% 0%, 0% 100%, from(#666666), to(#333333));
        /* Safari 5.1, Chrome 10+ */
        background: -webkit-linear-gradient(top, #666666, #333333);
        /* Firefox 3.6+ */
        background: -moz-linear-gradient(top, #666666, #333333);
        /* IE 10 */
        background: -ms-linear-gradient(top, #666666, #333333);
        /* Opera 11.10+ */
        background: -o-linear-gradient(top, #666666, #333333);
        padding: 0 10px 0 30px;
        position: relative;
        text-decoration: none;
        color: #FFFFFF;
        border-radius: 5px;
    }
    .accordion section .content {
        padding: 10px;
        margin: 0 3px 0 3px;
        background-color: #F1F1F1;
        color: #333333;
    }

    .accordion section .content p {
        margin-top: 0;
    }

    .arrow {
        position: absolute;
        width: 20px;
        height: 20px;
        left: 10px;
        top: 5px;
    }
    .right-arrow {
        width: 0;
        height: 0;
        border-top: 10px solid transparent;
        border-bottom: 10px solid transparent;
        border-left: 10px solid white;
    }
    .down-arrow {
        width: 0;
        border-left: 10px solid transparent;
        border-right: 10px solid transparent;
        border-top: 10px solid white;
        top: 10px;
        left: 6px;
    }
    ```

1.  将以下 jQuery 代码添加到`recipe-8.js`中，以启动折叠内容滑块的操作：

    ```js
    $(function(){
        //Hide all accordion content except the first one
        $('.accordion section:not(:first-child) .content').hide();
        $(document).on("click", ".accordion a.header", function(){
            var _contents = $('.accordion section .content');
            var _currentContent = $(this).parent().find('.content');
            for (var i = 0; i < _contents.length; i++) {
                var content = $(_contents[i]);
                //Only slide the element up if its not the currently selected element
                if (content[0] != _currentContent[0]) {
                    content.slideUp();
                    content.parent().find('.right-arrow').removeClass('down-arrow');
                }
            }
            _currentContent.slideDown();
            _currentContent.parent().find('.right-arrow').addClass('down-arrow');
        });
    });
    ```

1.  在网络浏览器中打开`recipe-8.html`，您将看到以下截图中显示的交互式折叠内容滑块：

## 它是如何工作的……

此示例中使用的 HTML 代码创建了一个包含主要折叠标记的基本网页。有一个包含多个部分的主折叠部分元素。每个部分都包含一个带有类`header`的锚标签和一个包含折叠内容的内容部分元素。jQuery 代码使用头部锚元素根据用户点击的锚元素来隐藏和显示内容部分。

CSS 代码非常简单，为折叠添加了基本样式。与前一个示例一样，我们使用 CSS 中的右箭头和下箭头来指示某个部分是否打开或关闭。我们还使用 CSS3 渐变将渐变背景添加到折叠标题中。

由于 jQuery 的性质，我们能够仅使用 18 行 JavaScript 创建整个折叠。 jQuery 代码的第一部分隐藏了除第一个以外的所有折叠内容部分：

```js
$('.accordion .section:not(:first-child) .content').hide();
```

然后，将一个`click`事件处理程序附加到文档上，以监听折叠内容标题的点击，如下面的代码片段所示：

```js
$(document).on("click", ".accordion a.header", function(){
});
```

在此事件的回调函数内部，我们选择所有折叠内容部分，并获取属于当前点击的标题元素的部分：

```js
var _contents = $('.accordion .section .content');
var _currentContent = $(this).parent().find('.content');
```

选定折叠部分时，我们只想显示其中一个。为此，循环遍历以下代码中的所有内容部分以隐藏它们，除了所选部分：

```js
for (var i = 0; i < _contents.length; i++) {
var content = $(_contents[i]);
//Only slide the element up if it's not the currently selected element
if (content[0] != _currentContent[0]) {
     content.slideUp();
     content.parent().find('.right-arrow').removeClass('down-arrow');
}
}
```

使用 jQuery 的`slideUp()`函数，我们可以隐藏带有滑动效果的元素。标题中的箭头也更改为右箭头，表示内容尚未展开。

最后，扩展所选的内容部分，并添加向下箭头以指示内容已展开，如下代码所示：

```js
_currentContent.slideDown();
_currentContent.parent().find('.right-arrow').addClass('down-arrow');
```

## 另请参阅

+   *创建动态动画树菜单*

+   *创建选项卡内容*

# 创建选项卡内容

类似于手风琴，选项卡式内容是在单个页面上显示大量信息的另一种好方法，允许用户跳转到对他们重要的部分。与前一示例类似，有许多提供此功能的 jQuery 插件。本示例将向您展示如何从头开始创建此功能，使您更深入地了解这些类型的用户界面的内部工作原理。

## 准备工作

在与 jQuery 库相同的目录中创建用于示例的常规文件，`recipe-9.html`、`recipe-9.css` 和 `recipe-9.js`。

## 如何做…

按照以下逐步说明完成所有步骤：

1.  使用以下 HTML 代码在`recipe-9.html`中创建一个基本的网页：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 9</title>
        <link href="recipe-9.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-9.js"></script>
    </head>
    <body>
    </body>
    </html>
    ```

1.  在您刚创建的 HTML 页面的`body`标签中，添加以下 HTML 代码以创建选项卡式内容：

    ```js
    <div class="container">
        <div class="tabs">
            <ul class="tab-nav">
                <li><a href="#section1" class="active">Section 1</a></li><li><a href="#section2">Section 2</a></li><li><a href="#section3">Section 3</a></li>
            </ul>
            <div class="tab-content">
                <div class="section" id="section1">
                    <p><strong>Section 1 content...</strong></p>
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
                <div class="section" id="section2">
                    <p><strong>Section 2 content...</strong></p>
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
                <div class="section" id="section3">
                    <p><strong>Section 3 content...</strong></p>
                    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
                </div>
            </div>
        </div>
    </div>
    ```

1.  打开`recipe-9.css`，添加以下 CSS 代码以样式化选项卡式内容，并在页面加载时显示第一组内容：

    ```js
    .container {
        width: 800px;
        margin: 20px auto auto auto;
    }
    .tabs .tab-nav {
        margin: 0;
        padding: 0;
        list-style: none;
        background-color: #E1E1E1;
        border-top-right-radius: 5px;
        border-top-left-radius: 5px;
    }
    .tabs .tab-nav li {
        display: inline-block;
    }
    .tabs .tab-nav li a {
        display: block;
        text-decoration: none;
        text-align: center;
        line-height: 50px;
        color: #FFF;
        background-color: #333;
        padding: 0 20px 0 20px;
        border-right: solid 1px #5c5c5c;
    }
    .tabs .tab-nav li a:hover, .tabs .tab-nav li a.active {
        background-color: #5c5c5c;
    }
    .tabs .tab-nav li:first-child a {
        border-top-left-radius: 5px;
    }
    .tabs .tab-nav li:last-child a {
        border-top-right-radius: 5px;
        border-right: none;
    }
    .tabs .section {
        padding: 10px;
        background-color: #F1F1F1;
        border-bottom-right-radius: 5px;
        border-bottom-left-radius: 5px;
    }
    .tabs .section p {
        margin-top: 0;
    }

    .tabs .section:not(:first-child) {
        display: none;
    }
    ```

1.  在`recipe-9.js`中插入以下 jQuery 代码：

    ```js
    $(function(){
        $(document).on("click", ".tabs .tab-nav a", function(){
            var contentId = this.hash;
            $('.tab-nav a').removeClass("active");
            $(this).addClass("active");
            $('.tab-content .section').hide();
            $(contentId).fadeIn();
        });
    });
    ```

1.  在 Web 浏览器中打开`recipe-9.html`，单击部分选项卡以在内容部分之间切换。

## 工作原理…

这是一个快速简单的示例，但却具有强大的结果。此示例中的 HTML 代码创建了包含导航和内容的选项卡部分。每个内容分区元素都有一个与导航中的链接相对应的 ID。例如，要链接到`section1`内容，需要在导航中有一个相应的链接链接到`#content1`，如下所示：`<a href='#content1'>标题在此</a>`。这使得 jQuery 知道在点击选项卡时要显示哪个内容部分。

此示例中的 CSS 非常简单，无需进一步解释。

仅用了九行 JavaScript，这是一个非常简单的示例。jQuery 代码将点击事件处理程序附加到文档主体，监听对选项卡导航的点击。当点击其中一个选项卡时，将从锚哈希中收集内容部分 ID，如下所示：

```js
$(document).on("click", ".tabs .tab-nav a", function(){
        var contentId = this.hash;
});
```

接下来，从所有选项卡导航项中删除活动类，并将其添加到点击的项目中。此类用于通过 CSS 更改背景颜色来显示当前活动的选项卡，如下所示：

```js
$('.tab-nav a').removeClass("active");
$(this).addClass("active");
```

最后，隐藏所有内容部分，然后使用最近获取的选定选项卡的内容 ID，使用`fadeIn()`函数使所选内容可见，当内容出现时应用动画：

```js
$('.tab-content .section').hide();
$(contentId).fadeIn();
```

## 还有更多…

此示例使用了 jQuery 提供的淡入动画来显示所选内容。通过回顾第四章中的内容，*使用 jQuery 效果添加吸引人的视觉效果*，你可以使用该章节中描述的任何效果和动画来显示和隐藏此示例中的内容。

# 创建一个模态弹出框

模态是网页内的一个弹出窗口，覆盖在所有其他内容之上，引起读者的注意。模态通常是基于用户交互而打开的，例如点击按钮。本示例将展示如何创建一个简单的模态，该模态在按下按钮时打开，并可以在模态内部关闭。

## 准备工作

再次，在开始此示例之前，创建 `recipe-10.html`、`recipe-10.css` 和 `recipe-10.js`，确保最新版本的 jQuery 可用于与这些文件相同的目录中。

## 如何实现…

执行以下步骤创建模态弹出框：

1.  将以下 HTML 添加到 `recipe-10.html` 中，以创建一个基本的网页和构建模态弹出框的代码：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 10</title>
        <link href="recipe-10.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-10.js"></script>
    </head>
    <body>
        <button class="openModal">Open Modal</button>
        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
        <div class="modal">
            <div class="modal-header">
                <h3>Modal Header Text <a class="close-modal" href="#">&times;</a></h3>
            </div>
            <div class="modal-body">
                <p>This is some modal content text.</p>
            </div>
            <div class="modal-footer">
                <button class="modalOK close-modal">OK</button>
            </div>
        </div>
        <div class="modal-backdrop"></div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到 `recipe-10.css` 中，以样式化模态框并允许其覆盖页面上的所有其他内容：

    ```js
    .modal-backdrop {
        background-color: rgba(0, 0, 0, 0.61);
        position: absolute;
        top: 0;
        bottom: 0;
        left: 0;
        right: 0;
        display: none;
    }
    .modal {
        width: 500px;
        position: absolute;
        top: 25%;
        z-index: 1020;
        background-color: #FFF;
        border-radius: 6px;
        display: none;
    }
    .modal-header {
        background-color: #333;
        color: #FFF;
        border-top-right-radius: 5px;
        border-top-left-radius: 5px;
    }
    .modal-header h3 {
        margin: 0;
        padding: 0 10px 0 10px;
        line-height: 40px;
    }
    .modal-header h3 .close-modal {
        float: right;
        text-decoration: none;
        color: #FFF;
    }
    .modal-footer {
        background-color: #F1F1F1;
        padding: 0 10px 0 10px;
        line-height: 40px;
        text-align: right;
        border-bottom-right-radius: 5px;
        border-bottom-left-radius: 5px;
        border-top: solid 1px #CCC;
    }
    .modal-body {
        padding: 0 10px 0 10px;
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-10.js` 中，以打开模态、将其居中并允许用户关闭它：

    ```js
    $(function(){
        modalPosition();
        $(window).resize(function(){
            modalPosition();
        });
        $('.openModal').click(function(){
            $('.modal, .modal-backdrop').fadeIn('fast');
        });
        $('.close-modal').click(function(){
            $('.modal, .modal-backdrop').fadeOut('fast');
        });
    });
    function modalPosition() {
        var width = $('.modal').width();
        var pageWidth = $(window).width();
        var x = (pageWidth / 2) - (width / 2);
        $('.modal').css({left: x + "px"});
    }
    ```

1.  在 Web 浏览器中打开 `recipe-10.html`，然后点击 **打开模态框** 按钮。你将会看到如下截图中显示的模态弹出框：![如何实现…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/recipe-10.jpg)

## 如何运作…

HTML 创建了基本的网页和创建模态的代码。模态本身包含一个主模态容器、一个标题、一个主体和一个页脚。页脚包含操作，本例中是 **确定** 按钮，标题包含标题和关闭按钮，主体包含模态内容。

CSS 应用了绝对定位样式到模态，使其可以自由移动到页面上而不受其他内容的干扰。为了创建模态背景，其位置被设置为 `absolute`，其左、右、上和下位置被设置为 `0`，使其可以扩展并覆盖整个页面。模态和其背景元素上设置了 `z-index` 值，确保它们始终位于其他内容之上，并且模态位于背景之上。

jQuery 代码将点击事件处理程序应用于模态打开按钮和任何具有 `close-modal` 类的元素。使用 jQuery 提供的 `fadeIn()` 和 `fadeOut()` 函数来显示模态。对这两个函数都传递了 `fast` 参数，以加快动画速度。

此外，jQuery 代码用于计算模态的左侧位置，使其始终位于屏幕中心。当页面加载时和当浏览器窗口大小调整时，调用 `modalPosition()` 函数如下：

```js
$(function(){
   modalPosition();
   $(window).resize(function(){
    modalPosition();
});
});
```

这样可以确保无论用户如何改变窗口的宽度，模态都将保持在浏览器窗口的中心。

`modalPosition()` 函数使用模态的宽度和浏览器窗口的宽度来计算模态的左侧位置。然后，该函数使用 jQuery 的 `css()` 函数将此值设置为模态的位置。

## 更多内容…

Twitter Bootstrap 是一个非常受欢迎的 HTML 框架，它带有一个非常出色的模态框实现，可以立即使用。现在你已经了解了模态框的工作原理，你可以受益于 Twitter Bootstrap 提供的完整解决方案。

## 另请参见

+   *创建一个可拖动的内容弹出框*

# 创建一个可拖动的内容弹出框

可拖动的内容弹出框类似于模态窗口。然而，它可以被用户移动，不会带有背景来引起用户的注意，可以让他们同时查看其他内容。这个教程将适配前一个教程中使用的模态框代码和本章前面看到的 *创建基本的拖放功能* 教程中的 jQuery 代码。

## 准备就绪

即使我们将重用之前章节中的代码，也确保你已经创建并准备好`recipe-11.html`、`recipe-11.css`和`recipe-11.js`。

## 如何做…

执行以下步骤：

1.  将以下 HTML 代码添加到`recipe-11.html`中，以创建一个模态框和一个基本的网页：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 6 :: Recipe 11</title>
        <link href="recipe-11.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/recipe-11.js"></script>
    </head>
    <body>
    <button class="openModal">Open Modal</button>
    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
    <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
    <div class="modal draggable">
        <div class="modal-header">
            <h3>Modal Header Text <a class="close-modal" href="#">&times;</a></h3>
        </div>
        <div class="modal-body">
            <p>This is some modal content text.</p>
        </div>
        <div class="modal-footer">
            <button class="modalOK close-modal">OK</button>
        </div>
    </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-11.css`中以样式化模态框：

    ```js
    .modal {
        width: 500px;
        position: absolute;
        top: 25%;
        z-index: 600;
        background-color: #FFF;
        border-radius: 6px;
        display: none;
        box-shadow: 3px 3px 5px #CCC;
    }
    .modal-header {
        background-color: #333;
        color: #FFF;
        border-top-right-radius: 5px;
        border-top-left-radius: 5px;
    }
    .modal-header h3 {
        margin: 0;
        padding: 0 10px 0 10px;
        line-height: 40px;
    }
    .modal-header h3 .close-modal {
        float: right;
        text-decoration: none;
        color: #FFF;
    }
    .modal-footer {
        background-color: #F1F1F1;
        padding: 0 10px 0 10px;
        line-height: 40px;
        text-align: right;
        border-bottom-right-radius: 5px;
        border-bottom-left-radius: 5px;
        border-top: solid 1px #CCC;
    }
    .modal-body {
        padding: 0 10px 0 10px;
    }
    ```

1.  将以下 jQuery 代码插入`recipe-11.js`中，以允许打开、关闭和拖动模态框：

    ```js
    $(function(){
        modalPosition();
        $('.openModal').click(function(){
            $('.modal, .modal-backdrop').fadeIn('fast');
        });
        $('.close-modal').click(function(){
            $('.modal, .modal-backdrop').fadeOut('fast');
        });
        $('.draggable').on("mousedown", function(){
            $(this).addClass('dragging');
        }).on("mousemove mouseout", function(event){
            if ($(this).hasClass("dragging")) {
                //Don't allow the draggable element to go over the parent's left and right
                var left = (event.pageX - ($(this).width() / 2));
                if (left > ($(window).width() - $(this).width())) {
                    left = ($(window).width() - $(this).width());
                } else if(left <= 0) {
                    left = 0;
                }
                //Don't allow the draggable element to go over the parent's top and bottom
                var top = (event.pageY - ($(this).height() / 2));
                if (top > ($(window).height() - $(this).height())) {
                    top = ($(window).height() - $(this).height());
                } else if (top <= 0) {
                    top = 0;
                }
                //Set new position
                $(this).css({
                    top: top + "px",
                    left: left + "px",
                    position: "absolute"
                });
            }
        }).on("mouseup", function(){
            $(this).removeClass('dragging');
        });
    });
    function modalPosition() {
        var width = $('.modal').width();
        var pageWidth = $(window).width();
        var x = (pageWidth / 2) - (width / 2);
        $('.modal').css({left: x + "px"});
    }
    ```

1.  在 Web 浏览器中打开`recipe-11.html`，并像在前一个教程中一样点击**打开模态框**按钮。然后你将看到同样的模态弹出框，没有背景，可以清楚地看到页面的其他内容。你还可以通过点击和拖动鼠标指针来在页面上移动模态框。

## 工作原理...

之前的一些适配过的食谱已经详细解释了模态框和`draggable`元素的工作原理，因此在本节中不会重复介绍。

与前一个模态框食谱的 HTML 的主要区别是没有模态背景，而模态元素具有额外的`draggable`类，这是 jQuery 用于对元素应用拖放功能的。

CSS 仍然非常相似，只是背景的代码已被移除，并且使用 CSS `box-shadow`属性向模态框添加了阴影。

jQuery 使用与前一个模态框教程相同的代码，只是移除了窗口调整大小事件处理程序。这个事件处理程序被移除，因为模态框可以被用户移动，所以没有必要保持模态框处于页面中心。`modalPosition()`函数只在页面加载时被调用，这样当首次打开模态框时，它就处于页面的中心位置。

从基本的拖放食谱中使用的代码非常相似，唯一的区别是不再使用`draggable`元素的父元素作为边界，而是使用浏览器窗口。这消除了一些复杂性，因为我们知道窗口的左右位置始终是`0`。

## 另请参见

+   *创建基本的拖放功能*

+   *创建一个模态弹出框*
