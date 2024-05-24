# JavaScript 专家级编程（五）

> 原文：[`zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD`](https://zh.annas-archive.org/md5/918F303F1357704D1EED66C3323DB7DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：异步编程

## 学习目标

在本章结束时，你将能够：

+   描述异步操作的工作原理

+   使用回调处理异步操作

+   演示回调和事件循环

+   实现承诺来处理异步操作

+   使用承诺重写带有回调的异步代码

+   重构您的传统代码，使用 async 和 await 函数

在本章中，我们将探讨 JavaScript 的异步（后面简称为 async）特性。重点将放在传统语言如何处理需要时间完成的操作以及 JavaScript 如何处理这些操作上。之后，我们将讨论在 JavaScript 中处理这些情况的各种方法。

## 介绍

在上一章中，我们学习了如何使用数组和对象以及它们的辅助函数。在本章中，我们将更多地了解 JavaScript 的运行方式以及如何处理耗时操作。

在处理 JavaScript 的大型项目时，通常我们必须处理网络请求、磁盘 IO 和数据处理。许多这些操作需要时间完成，对于刚开始使用 JavaScript 的初学者来说，很难理解如何检索这些耗时操作的结果。这是因为，与其他语言不同，JavaScript 有一种特殊的处理这些操作的方式。在编写程序时，我们习惯于线性思维；也就是说，程序逐行执行，只有在有循环或分支时才会打破这种流程。例如，如果你想在 Java 中进行简单的网络请求，你将不得不做类似于下面代码中所示的事情：

```js
import java.net.*;
import java.io.*;
public class SynchronousFetch{
  public static void main(String[] args){
   StringBuilder content = new StringBuilder();
   try {
    URL url = new URL("https://www.packtpub.com");
    URLConnection urlConnection = url.openConnection();
    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
    String line;
    while ((line = bufferedReader.readLine()) != null){
      content.append(line + "\n");
    }
    bufferedReader.close();
   } catch(Exception e) {
    e.printStackTrace();
   }
   System.out.println(content.toString());
   System.exit(0);
  }//end main
}//end class SynchronousFetch 
```

理解起来很简单：你创建一个 HTTP 客户端，并在客户端内调用一个方法来请求该 URL 的内容。一旦请求被发出并收到响应，它将继续运行返回响应主体的下一行代码。在此期间，整个函数将暂停并等待`fetch`，只有在请求完成后才会继续。这是其他语言中处理这些操作的正常方式。处理耗时操作的这种方式称为**同步处理**，因为它强制程序暂停，只有在操作完成后才会恢复。

由于这种线性思维，许多开发人员（包括我）在开始使用 JavaScript 编码时会感到非常困惑。大多数人会开始编写这样的代码：

```js
const request = require('request');
let response;
request('SOMEURL', (err, res) => {
   response = res.body;
});
console.log(response);
```

从代码的外观来看，它应该像我们之前的代码一样运行。它将发出请求，一旦完成，将响应变量设置为响应主体，然后输出响应。大多数尝试过这种方法的开发人员都会知道，这不是 JavaScript 的工作方式；代码将运行，产生'undefined'输出，然后退出。

### JavaScript 如何处理耗时操作

在 JavaScript 中，这些操作通常使用异步编程来处理。在 JavaScript 中有多种方法可以做到这一点；最常用的方法，也是你在传统程序中最常见的方法，就是**回调**。回调只是一个传递包含应用程序其余逻辑的函数给另一个函数的花哨术语；它们实际上非常容易理解。考虑传统函数在逻辑完成后返回它们的值。在异步编程中，它们通常不返回值；相反，它们将它们的结果传递给调用者提供的回调函数。考虑以下代码：

```js
const request = require('request');
let response;
request('SOMEURL', (err, res) => {
   response = res.body;
});
console.log(response);
```

让我们看看为什么这不会产生我们想要的结果。我们使用的`request`库可以被视为执行一些耗时操作逻辑的函数。`request`函数希望你传递一个回调函数作为参数，该回调函数包括你接下来要做的一切。在回调函数中，我们接受两个参数，`err`和`res`；在函数内部，我们将之前声明的响应变量赋值给`res`体（响应体）。在`request`函数外部，我们有`console.log`来记录响应。因为回调函数将在将来的某个时刻被调用，所以我们会在给它设置任何值之前记录响应的值。大多数开发人员在处理 JavaScript 时会感到非常沮丧，因为上面的代码不是线性的。执行的顺序如下：

```js
1const request = require('request');
2 let response;
3 request('SOMEURL', (err, res) => {
   5 response = res.body;
});
4 console.log(response);
```

从上面的代码执行顺序可以看出，前三行的工作正如我们所期望的那样。我们导入了`request`库并声明了一个响应变量，然后调用了带有回调的`request`库。因为回调只有在网络请求完成时才会被调用，程序将继续执行其余的代码，输出响应。

最后，当网络请求完成时，它将调用我们的回调函数并运行将体分配给我们的响应的行。为了使这段代码表现如我们所期望的那样，我们需要修改代码如下：

```js
const request = require('request');
let response;
request('SOMEURL', (err, res) => {
   response = res.body;
   console.log(response);
});
```

在上面的代码中，我们将`console.log`放在回调函数内部，这样它只有在赋值完成后才会被执行。现在，当我们运行这段代码时，它将输出实际的响应体。

### 使用回调处理异步操作

在介绍中，我们谈到了 JavaScript 如何与其他语言不同地处理异步操作。在本章中，我们将探讨如何使用回调方法编写包含许多异步操作的复杂 JavaScript 应用程序。

### 练习 61：编写您的第一个回调

在这个练习中，我们将首先编写一个模拟需要一段时间才能完成的函数。之后，我们将编写另一个消耗我们异步函数的函数。

#### 注意

此练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise61`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise61)找到。

执行以下步骤完成练习：

1.  创建一个`slowAPI`对象来创建一个模拟 API 库；它的目的是在合理的时间内返回结果。我们首先编写这个来介绍如何模拟异步函数而无需执行异步操作。

```js
const slowAPI = {}
```

1.  在我们刚刚定义的`slowAPI`对象中创建一个`getUsers`函数，它不返回任何内容，需要一个回调函数。在`getUsers`内部调用`setTimeout`函数，用于在需要时给我们的代码添加 1 秒的延迟：

```js
slowAPI.getUsers = (callback) => {
      setTimeout(() => {
        callback(null, {
           status: 'OK',
           data: {
              users: [
                {
                   name: 'Miku'
                }, 
                {
                   name: 'Len'
                }
              ]
           }
        });
      }, 1000);
}
```

1.  在`slowAPI`对象中创建一个`getCart`函数，并在函数内部创建一个`if-else`循环，匹配用户名并在不匹配时返回错误：

```js
slowAPI.getCart = (username, callback) => {
      setTimeout(() => {
        if (username === 'Miku') {
           callback(null, {
              status: 'OK',
              data: {
                cart: ['Leek', 'Cake']
              }
           })
        } else {
           callback(new Error('User not found'));
        }
      }, 500);
}
```

1.  创建一个`runRequests`函数，调用`getUsers`来获取用户列表。在回调函数内部，我们将打印出响应或错误：

```js
function runRequests() {
   slowAPI.getUsers((error, response) => {
      if (error) {
        console.error('Error occurred when running getUsers');
        throw new Error('Error occurred');
      }
      console.log(response);
   });
}
```

1.  调用`run Request`函数：

```js
runRequests();
```

输出应该如下：

![图 8.1：runRequest 的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_01.jpg)

###### 图 8.1：runRequest 的输出

我们可以看到`runRequest`函数已经运行完毕，我们的响应被正确打印出来。

1.  修改`runRequest`函数以调用`getCart`：

```js
function runRequests() {
   slowAPI.getUsers((error, response) => {
      if (error) {
        console.error('Error occurred when running getUsers');
        throw new Error('Error occurred');
      }
      console.log(response);
   });
   slowAPI.getCart('Miku', (error, result) => {
        if (error) {
           console.error(error);
           throw new Error('Error occurred');
        }
        console.log(result);
   });
}
```

在这里，我们在`runRequest`函数内部放置了一个类似的对`slowAPI`的调用；其他都没有改变。当我们运行这个时，我们得到了一个非常有趣的输出，如下所示：

![图 8.2：修改 runRequest 函数后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_02.jpg)

###### 图 8.2：修改 runRequest 函数后的输出

这非常有趣，因为它首先输出了`getCart`的结果，然后是`getUsers`的结果。程序之所以表现如此，是因为 JavaScript 的异步和非阻塞特性。在我们的操作中，因为`getCart`函数只需要 500 毫秒就能完成，所以它将是第一个输出。

1.  修改前面的函数以输出第一个用户的购物车：

```js
function runRequests() {
   slowAPI.getUsers((error, response) => {
      if (error) {
        console.error('Error occurred when running getUsers');
        throw new Error('Error occurred');
      }
      slowAPI.getCart(response.data.users[0].name,(error,result) => {
        if (error) {
           console.error(error);
           throw new Error('Error occurred');
        }
        console.log(result);
     });
   });
}
```

输出应该如下所示：

![图 8.3：第一个用户的购物车输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_03.jpg)

###### 图 8.3：第一个用户的购物车输出

因为我们将使用第一个请求的数据，所以我们必须在第一个请求的回调函数中编写我们下一个请求的逻辑。

1.  在访问未知用户的购物车时触发错误：

```js
function runRequests() {
   slowAPI.getUsers((error, response) => {
    if (error) {
        console.error('Error occurred when running getUsers');
        throw new Error('Error occurred');
      }
      slowAPI.getCart(response.data.users[1].name,(error,result) => {
        if (error) {
           console.error(error);
           throw new Error('Error occurred');
        }
        console.log(result);
      });
   });
}
```

我们知道从`getCart`返回的数据是，最后一个用户不匹配任何`if`语句。因此，在调用时会抛出错误。当我们运行代码时，将会看到以下错误：

![图 8.4：打印错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_04.jpg)

###### 图 8.4：打印错误

我们在白色中看到的第一个错误输出是通过`console.error`输出的错误。这可以根据您的喜好定制为特定格式的错误消息或输出，使用日志框架。第二个错误是由于我们在`console.log`后立即抛出新错误导致进程崩溃。

在这个练习中，我们检查了如何使用`setTimeout`模拟异步函数。`setTimeout`是一个非常有用的函数。虽然在实际代码中并不推荐使用，但在测试中需要模拟需要时间的网络请求或在调试软件时产生竞争条件时，它非常有用。之后，我们讨论了使用回调函数使用异步函数的方法以及异步函数中的错误处理方式。

接下来，我们将简要讨论为什么回调函数正在逐渐过时，以及如果不正确使用回调函数会发生什么。

### 事件循环

您可能以前听说过这个术语，指的是 JavaScript 如何处理耗时操作。了解事件循环在底层是如何工作也非常重要。

当考虑 JavaScript 最常用于什么时，它用于制作动态网站，主要在浏览器中使用。让很多人惊讶的是，JavaScript 代码在单个线程中运行，这简化了开发人员的很多工作，但在处理同时发生的多个操作时会带来挑战。在 JavaScript 运行时，后台运行一个无限循环，用于管理代码的消息和处理事件。事件循环负责消耗回调队列中的回调、运行堆栈中的函数和调用 Web API。JavaScript 中大多数操作可分为两种类型：阻塞和非阻塞。阻塞意味着阻塞事件循环（您可以将其视为其他语言的正常 UI 线程）。当事件循环被阻塞时，它无法处理来自应用程序其他部分的更多事件，应用程序将冻结直到解除阻塞。以下是示例操作及其分类的列表：

![图 8.5：带有示例操作及其分类的表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_05.jpg)

###### 图 8.5：带有示例操作及其分类的表

从前面的列表中可以看到，几乎所有 JavaScript 中的 I/O 都是非阻塞的，这意味着即使完成时间比预期时间长，也不会阻塞事件循环。像任何语言一样，阻塞事件循环是一件糟糕的事情，因为它会使应用程序不稳定和无响应。这带来了一个问题：我们如何知道非阻塞操作是否已完成。

### JavaScript 如何执行代码

当 JavaScript 执行阻塞代码时，它会阻塞循环并在程序继续执行之前完成操作。如果你运行一个迭代 100 万次的循环，你的其余代码必须等待该循环完成才能继续。因此，在你的代码中不建议有大量阻塞操作，因为它们会影响性能、稳定性和用户体验。当 JavaScript 执行非阻塞代码时，它通过将进程交给 Web API 来进行获取、超时和休息。一旦操作完成，回调将被推送到回调队列中，以便稍后被事件循环消耗。

在现代浏览器中，这是如何实现的，我们有一个堆来存储大部分对象分配，和一个用于函数调用的堆栈。在每个事件循环周期中，事件循环首先优先处理堆栈，并通过调用适当的 Web API 来执行这些事件。一旦操作完成，该操作的回调将被推送到回调队列中，稍后会被事件循环消耗：

![图 8.6：事件循环周期](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_06.jpg)

###### 图 8.6：事件循环周期

为了了解一切是如何在幕后运作的，让我们考虑以下代码：

```js
setTimeout(() => {console.log('hi')}, 2000)
while(true) {
   ;
}
```

从外观上看，这段代码做了两件事：创建一个在 2 秒后打印`hi`的超时，以及一个什么都不做的无限循环。当你运行上述代码时，它会表现得有点奇怪 - 什么都不会被打印出来，程序就会挂起。它表现得像这样的原因是事件循环更偏向于堆栈中的项目，而不是回调队列中的项目。因为我们有一个无限的`while`循环不断推入调用堆栈，事件循环忙于运行循环并忽略了回调队列中已完成的`setTimeout`回调。关于`setTimeout`工作方式的另一个有趣事实是，我们可以使用它来延迟我们的函数到事件循环的下一个周期。考虑以下代码：

```js
setTimeout(() => {console.log('hi again')}, 0)
console.log('hi');
```

在这里，我们有`setTimeout`后面跟着`console.log`，但这里我们使用`0`作为超时，意味着我们希望立即完成。一旦超时完成并且回调被推送到回调队列，由于我们的事件循环优先处理调用堆栈，你可以期待这样的输出：

![图 8.7：超时完成后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_07.jpg)

###### 图 8.7：超时完成后的输出

我们看到`hi`在`hi again`之前被打印出来，因为即使我们将超时设置为零，它仍然会最后执行，因为事件循环会在调用堆栈中的项目之前执行回调队列中的项目。

### 活动 11：使用回调接收结果

在这个活动中，我们将使用回调来接收结果。假设你正在为一家当地燃气公司担任软件工程师，并且他们希望你为他们编写一个新功能：

+   你有一个客户端 API 库，可以用来请求本地用户列表。

+   你需要实现一个功能，计算这些用户的账单，并以以下格式返回结果：

```js
{
   id: 'XXXXX',
   address: '2323 sxsssssss',
   due: 236.6
}
```

+   你需要实现一个`calculateBill`函数，它接受`id`并计算该用户的燃气费用。

为了实现这一点，你需要请求用户列表并获取这些用户的费率和使用情况。最后，计算最终应付金额并返回合并结果。

#### 注意

这个活动的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Activity11`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Activity11)找到。

执行以下步骤完成这个活动：

1.  创建一个`calculate`函数，它接受`id`和回调函数作为参数。

1.  调用`getUsers`来获取所有用户，这将给我们需要的地址。

1.  调用`getUsage`来获取我们用户的使用情况。

1.  最后，调用`getRate`来获取我们正在为其计算的用户的费率。

1.  使用现有 ID 调用`calculate`函数。

1.  使用不存在的 ID 调用`calculate`函数以检查返回的错误。

您应该看到返回的错误如下：

![图 8.8：使用不存在的 ID 调用函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_08.jpg)

###### 图 8.8：使用不存在的 ID 调用函数

#### 注意

此活动的解决方案可在第 613 页找到。

在这个活动中，我们实现的功能与实际世界中可能看到的非常相似。我们在一个函数中处理了多个异步操作。接下来，我们将讨论回调地狱以及在处理多个异步操作时可能出现的问题。

## 回调地狱

回调地狱指的是 JavaScript 开发人员在处理大型项目时遇到的障碍。回调地狱的原因并不完全是开发人员的错，部分原因是 JavaScript 处理异步操作的方式。通过使用回调来处理多个异步操作，很容易让事情失控。以下代码举例说明了回调地狱的例子：

```js
request('url', (error, response) => {
   // Do something here
   request('another url', (error, response) => {
      disk.write('filename', (result) => {
        if (result.this) {
           process(something, (result) => {
              request('another url', (error, response) => {
                if (response.this) {
                   request('this', (error, response) => {
                      // Do something for this
                   })
                } else {
                   request('that', (error, response) => {
                      if (error) {
                        request('error fallback', (error, response) => {
                           // Error fallback
                        })
                      }
                      if (response.this) {
                      }
                   })
                }
              });
           })
        } else {
           process(otherthing, (result) => {
              // Do something else
           })
        }
      })
   })
})
```

前面的代码示例是回调地狱的典型例子。虽然这段代码比实际世界中找到的回调地狱代码要短，但同样糟糕。回调地狱是指一段代码中嵌套了太多回调，使得开发人员难以理解、维护甚至调试代码。如果前面的代码被用来实现实际的业务逻辑，它将会扩展到超过 200 行。有这么多行和这么多层嵌套，会产生以下问题：

+   很难弄清楚你当前在哪个回调中。

+   它可能会导致变量名冲突和覆盖。

+   几乎不可能调试和断点代码。

+   代码将非常难以重用。

+   代码将无法进行测试。

这些问题只是由回调地狱引起的问题清单中的一部分。这些问题是为什么许多公司甚至在面试问题中包括关于回调地狱的问题的原因。有许多提出的方法可以使代码比前面的代码更可读。一种方法是将几乎每个回调都作为单独的函数提取出来。使用这种技术，前面的代码可以修改如下：

```js
function doAnotherUrl(error, response) {
   if (response.this) {
      request('this', (error, response) => {
        // Do something for this
      })
   } else {
      request('that', (error, response) => {
        if (error) {
           request('error fallback', (error, response) => {
              // Error fallback
           })
        }
        if (response.this) {
        }
      })
   }
}
function process(result) {
   request('another url', doAnotherUrl);
}
function afterWrite(result) {
   if (result.this) {
      process(something, afterProcess)
   } else {
      process(otherthing, afterProcess)
   }
}
function doAnotherThing(error, response) {
   disk.write('filename', afterWrite)
}
function doFirstThing(error, response) {
   // Do something here
   request('another url', doAnotherThing)
}
request('url', doFirstThing)
```

当代码像这样重写时，我们可以看到所有的处理函数都被分开了。稍后，我们可以将它们放在一个单独的文件中，并使用`require()`来引用它们。这解决了将所有代码放在一个地方和可测试性问题。但它也使代码库变得不必要地庞大和分散。在 ES6 中，引入了承诺。它开辟了一种全新的处理异步操作的方式。在下一节中，我们将讨论承诺的工作原理以及如何使用它们来摆脱回调地狱。

### 承诺

在 JavaScript 中，承诺是代表将来某个值的对象。通常，它是异步操作的包装器。承诺也可以在函数中传递并用作承诺的返回值。因为承诺代表一个异步操作，它可以有以下状态之一：

+   待定，意味着承诺正在等待，这意味着可能仍有异步操作正在运行，没有办法确定其结果。

+   实现，意味着异步操作已经完成，没有错误，值已准备好接收。

+   拒绝，意味着异步操作以错误完成。

承诺只能有前面三种状态之一。当承诺被实现时，它将调用提供给`.then`承诺函数的处理程序，当它被拒绝时，它将调用提供给`.catch`承诺函数的处理程序。

要创建一个 promise，我们在`Promise`构造函数中使用`new`关键字。构造函数接受一个包含异步操作代码的函数。它还将两个函数作为参数传递，`resolve`和`reject`。当异步操作完成并且值准备好被传递时，将调用`resolve`。当异步操作失败并且你想要返回失败原因时，通常是一个错误对象，将调用`reject`：

```js
 const myPromise = new Promise((resolve, reject) => {

});
```

以下代码使用 Promise.resolve 返回一个 promise：

```js
const myPromiseValue = Promise.resolve(12);
```

`Promise.resolve`返回一个解析为你传递的值的 promise。当你想要保持代码库一致，或者不确定一个值是否是 promise 时，它非常有用。一旦你使用`Promise.resolve`包装值，你可以使用`then`处理程序开始处理 promise 的值。

在下一个练习中，我们将看看如何使用 promise 处理异步操作，以及如何在不导致回调地狱的情况下将多个异步操作与 promise 结合起来。

### 练习 62：使用 Promise 作为回调的替代方案

在上一个活动中，我们讨论了如何将多个异步操作组合成一个单一的结果。这很容易理解，但也会使代码变得很长并且难以管理。我们讨论了回调地狱以及如何避免它。我们可以做的一件事是利用 ES6 中引入的`Promise`对象。在这个练习中，我们将讨论如何在我们的应用程序中使用 promise。

#### 注意

此练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise62`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise62)找到。

执行以下步骤完成练习：

1.  创建一个 promise：

```js
const myPromise = new Promise(() => {

});
```

创建 promise 时，我们需要在`Promise`构造函数中使用`new`关键字。`Promise`构造函数要求你提供一个解析器函数来执行异步操作。当创建 promise 时，它将自动调用解析器函数。

1.  向解析器函数添加一个操作：

```js
const myPromise = new Promise(() => {
   console.log('hi');
});
```

输出应该如下所示：

![图 8.9：向解析器函数添加一个操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_09.jpg)

###### 图 8.9：向解析器函数添加一个操作

即使`console.log`不是一个异步操作，当我们创建一个 promise 时，它将自动执行我们的解析器函数并打印出`hi`。

1.  使用`resolve`解决 promise：

```js
const myPromise = new Promise((resolve) => {
   resolve(12);
});
myPromise
```

当调用函数时，会将一个`resolve`函数传递给我们的解析器函数。当它被调用时，promise 将被解决：

![图 8.10：调用函数后解决的 promise](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_10.jpg)

###### 图 8.10：调用函数后解决的 promise

1.  使用`then()`函数检索值。通过附加一个`then`处理程序，你期望从回调中读取解析的 promise 值：

```js
const myPromise = new Promise((resolve) => {
   resolve(12);
}).then((value) => {
   console.log(value);
});
```

输出应该如下所示：

![图 8.11：使用 then 函数检索值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_11.jpg)

###### 图 8.11：使用 then 函数检索值

每当你创建一个 promise 时，你期望异步函数完成并返回一个值。

1.  创建一个立即解决的 promise：

```js
const myPromiseValue = Promise.resolve(12);
```

1.  创建一个立即被拒绝的 promise：

```js
const myRejectedPromise = Promise.reject(new Error('rejected'));
```

输出应该如下所示：

![图 8.12：立即被拒绝的 promise 创建](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_12.jpg)

###### 图 8.12：立即被拒绝的 promise 创建

就像`Promise.resolve`一样，使用`Promise.reject`创建 promise 将返回一个被提供的原因拒绝的 promise。

1.  使用`catch`在 promise 中处理`error`：

```js
myRejectedPromise.catch((error) => {
   console.log(error);
});
```

你可以使用`catch`提供一个错误处理程序。这会向 promise 添加一个拒绝回调。当你提供一个 catch 处理程序时，从 promise 返回的错误将作为处理程序的参数传递：

图 8.13：使用 catch 处理 promise 中的错误

](Images/C14587_08_13.jpg)

###### 图 8.13：使用 catch 处理 promise 中的错误

1.  创建一个返回 promise 的`wait`函数：

```js
function wait(seconds) {
   return new Promise((resolve) => {
      setTimeout(() => {
        resolve(seconds);
      }, seconds * 1000);
   })
}
```

1.  使用`async`函数延迟我们的控制台日志：

```js
wait(2).then((seconds) => {
   console.log('i waited ' + seconds + ' seconds');
});
```

输出应该如下所示：

![图 8.14：使用异步函数延迟控制台日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_14.jpg)

###### 图 8.14：使用异步函数延迟控制台日志

如你所见，使用它非常简单。我们的`wait`函数每次调用时都返回一个新的 promise。在操作完成后运行我们的代码，将其传递给`then`处理程序。

1.  使用`then`函数链式调用 promise：

```js
wait(2)
   .then(() => wait(2))
   .then(() => {
      console.log('i waited 4 seconds');
   });
```

输出应该如下所示：

![图 8.15：使用 then 函数链接的 Promise](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_15.jpg)

###### 图 8.15：使用 then 函数链式调用的 Promise

例如，当我们想要将两个 promise 链在一起时，我们只需要将它们传递到`then`处理程序中，并确保结果也是一个 promise。在这里，我们看到在调用`wait`等待 2 秒后，我们调用另一个`wait`等待 2 秒，并确保计时器在第一个完成后开始。

在这个练习中，我们讨论了几种创建 promise 的方法，以及如何创建一个使用 promise 而不是回调处理操作的异步函数。最后，我们使用`then`函数链式调用了 promise。这些都是使用 promise 的非常简单的方法。在下一章中，我们将讨论如何有效地链式调用它们以及如何处理 promise 的错误。

### 链式调用 Promise

在上一个练习中，我们看了一种非常简单的方法来链式调用 promise。Promise 链式调用也可能很复杂，正确地使用它可以避免代码中的许多潜在问题。当你设计一个需要同时执行多个异步操作的复杂应用程序时，使用回调时很容易陷入回调地狱。使用 promise 解决了与回调地狱相关的一些问题，但它并不是万能的。通常，你会看到像这样编写的代码：

```js
getUser('name').then((user) => {
   increaseLike(user.id).then((result) => {
      readUser(user.id).then((user) => {
        if (user.like !== result.like) {
           generateErrorLog(user, 'LIKE').then((result) => {
              response.send(403);
           })
        } else {
           updateAvatar(user).then((result) => {
              optimizeImage(result.image).then(() => {
                response.send(200);
              })
           })
        }
      });
   });
}).catch((error) => {
   response.send(403);
});
```

当你看到像这样编写的代码时，很难判断是否转换为 promise 解决了任何问题。前面的代码与我们的回调地狱代码有相同的问题；所有逻辑都是分散和嵌套的。我们还有其他问题，比如上层作用域的值可能会被意外覆盖。

当我们编写带有 promise 的代码时，我们应该考虑尽可能使代码模块化，并将操作集合视为管道。对于我们前面的示例，管道将如下所示：

![图 8.16：示例管道（一系列操作）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_16.jpg)

###### 图 8.16：示例管道（一系列操作）

你会发现我们希望将值从一个过程传递到下一个过程。这有助于我们链式调用 promise，并且可以使我们的代码非常清晰和易于维护。我们可以将前面的代码重写为以下内容：

```js
function increaseLike(user) {
   return new Promise((resolve) => {
      resolve({
        // Some result
      })
   });
};
function readUser(result) {
   return new Promise((resolve) => {
      resolve({
        // Return user
      })
   });
}
function updateAvatar(user) {
   return new Promise((resolve) => {
      resolve({
        // Return updated avatar
      })
   });
}
function optimizeImage(user) {
   return new Promise((resolve) => {
      resolve({
        // Return optimized images
      })
   });
}
function generateErrorLog(error) {
   // Handle some error
}
readUser('name')
   .then(increaseLike)
   .then(readUser)
   .then(updateAvatar)
   .then(optimizeImage)
   .catch(generateErrorLog)
```

正如你所看到的，重写的代码更易读，任何查看这段代码的人都会准确知道将会发生什么。当我们以这种方式链式调用 promise 时，我们基本上是将值从一个过程传递到另一个过程。通过使用这种方法，我们不仅解决了回调地狱的问题，而且使代码更具可测试性，因为这些辅助函数中的每一个都是完全独立的，它们不需要任何比传递给它们的参数更多的东西。更不用说，如果你的应用程序中有任何部分想要执行类似的操作（例如，`optimizeImage`），你可以轻松地重用代码的这部分。在下一个练习中，我们将讨论如何使用 promise 链式调用编写具有多个异步操作的复杂功能。

### 练习 63：高级 JavaScript Promise

在这个练习中，我们将编写一个简单的程序，运行多个异步操作，并使用 promise 链式调用它们的结果。之后，我们还将使用`Promise`类的有用静态方法来帮助我们同时管理多个 promise。

#### 注意

此活动的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise63`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise63)找到。

执行以下步骤完成练习：

1.  创建`getProfile`和`getCart`函数，它们返回一个 promise。`getProfile`应该以`id`字符串作为输入，并根据输入解析不同的结果：

```js
function getProfile(id) {
   return new Promise((resolve, reject) => {
      switch(id) {
        case 'P6HB0O':
           resolve({ id: 'P6HB0O', name: 'Miku', age: 16, dob: '0831' });
        break;
        case '2ADN23':
           resolve({ id: '2ADN23', name: 'Rin', age: 14, dob: '1227' });
        break;
        case '6FFQTU':
           resolve({ id:'6FFQTU', name: 'Luka', age: 20, dob: '0130' });
        break;
        default:
           reject(new Error('user not found'));
      }
   });
}
function getCart(user) {
   return new Promise((resolve, reject) => {
      switch(user.id) {
        case 'P6HB0O':
           resolve(['leek', 'cake', 'notebook']);
        break;
        case '2ADN23':
           resolve(['ice cream', 'banana']);
        break;
        case '6FFQTU':
           resolve(['tuna', 'tako']);
        break;
        default:
           reject(new Error('user not found'));
      }
   });
}
```

1.  创建另一个异步函数`getSubscription`，它接受一个 ID 并为该 ID 解析`true`和`false`值：

```js
function getSubscription(id) {
   return new Promise((resolve, reject) => {
      switch(id) {
        case 'P6HB0O':
           resolve(true);
        break;
        case '2ADN23':
           resolve(false);
        break;
        case '6FFQTU':
           resolve(false);
        break;
        default:
           reject(new Error('user not found'));
      }
   });
}
```

在这里，函数只接受一个字符串 ID 作为输入。如果我们想在我们的 promise 链中链接它，我们需要确保提供给该函数的 promise 解析为单个字符串值。

1.  创建`getFullRecord`，它返回`id`的组合记录：

```js
function getFullRecord(id) {
   return {
      id: '',
      age: 0,
      dob: '',
      name: '',
      cart: [],
      subscription: true
   };
}
```

在`getFullRecord`函数中，我们希望调用所有前面的函数并将记录组合成前面代码中显示的返回值。

1.  调用我们之前在`getFullRecord`中声明的函数，并返回`getProfile`，`getCart`和`getSubscription`的组合结果：

```js
function getFullRecord(id) {
   return getProfile(id).then((user) => {
      return getCart(user).then((cart) => {
        return getSubscription(user.id).then((subscription) => {
           return {
              ...user,
              cart: cart,
              subscription
           };
        });
      });
   });
}
```

这个函数也返回一个 promise。我们可以调用该函数并打印出它的值：

```js
getFullRecord('P6HB0O').then(console.log);
```

这将返回以下输出：

![图 8.17：在 getFullRecord 中调用已声明的函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_17.jpg)

###### 图 8.17：在`getFullRecord`中调用已声明的函数

但是我们的代码非常混乱，并且并没有真正利用我们之前提到的 promise 链式调用。为了解决这个问题，我们需要对`getCart`和`getSubscription`进行修改。

1.  更新`getCart`函数，该函数返回一个新对象，包括`user`对象的每个属性和`cart`项，而不仅仅返回`cart`项：

```js
function getCart(user) {
   return new Promise((resolve, reject) => {
      switch(user.id) {
        case 'P6HB0O':
           resolve({ ...user, cart: ['leek', 'cake', 'notebook'] });
        break;
        case '2ADN23':
           resolve({ ...user, cart: ['ice cream', 'banana'] });
        break;
        case '6FFQTU':
           resolve({ ...user, cart: ['tuna', 'tako'] });
        break;
        default:
           reject(new Error('user not found'));
      }
   });
}
```

1.  更新`getSubscription`函数，该函数以`user`对象作为输入并返回一个对象，而不是单个值：

```js
function getSubscription(user) {
   return new Promise((resolve, reject) => {
      switch (user.id) {
        case 'P6HB0O':
           resolve({ ...user, subscription: true });
           break;
        case '2ADN23':
           resolve({ ...user, subscription: false });
           break;
        case '6FFQTU':
           resolve({ ...user, subscription: false });
           break;
        default:
           reject(new Error('user not found'));
      }
   });
}
```

1.  更新`getFullRecord`函数：

```js
function getFullRecord(id) {
   return getProfile(id)
      .then(getCart)
      .then(getSubscription);
}
```

现在，这比以前的所有嵌套要可读得多。我们只是通过对之前的两个函数进行最小的更改，大大减少了`getFullRecord`。当我们再次调用此函数时，它应该产生完全相同的结果：

![图 8.18：更新的 getFullRecord 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_18.jpg)

###### 图 8.18：更新的 getFullRecord 函数

1.  创建`getFullRecords`函数，我们将使用它来调用多个记录并将它们组合成一个数组：

```js
function getFullRecords() {
   // Return an array of all the combined user record in our system
   return [
      {
        // Record 1
      },
      {
        // Record 2
      }
   ]
}
```

1.  使用`array.map`生成 promise 列表：

```js
function getFullRecords() {
   const ids = ['P6HB0O', '2ADN23', '6FFQTU'];
   const promises = ids.map(getFullRecord);
}
```

在这里，我们利用了`array.map`函数来迭代数组并返回一个新数组。因为数组只包含 ID，所以我们可以简单地传递`getFullRecord`函数。

1.  使用`Promise.all`来合并一系列 promise 的结果：

```js
function getFullRecords() {
   const ids = ['P6HB0O', '2ADN23', '6FFQTU'];
   const promises = ids.map(getFullRecord);
   return Promise.all(promises);
}
```

`Promise.all`只是接受一个 promise 数组并返回一个等待所有 promise 解析的 promise。一旦数组中的所有 promise 都解析了，它将解析为这些 promise 的结果数组。因为我们的目标是返回完整记录列表，这正是我们想要的。

1.  测试`getFullRecords`：

```js
getFullRecords().then(console.log);
```

输出应该如下所示：

![图 8.19：测试 getFullRecords 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_19.jpg)

###### 图 8.19：测试 getFullRecords 函数

在这个练习中，我们使用了多个异步函数和它们的 promise 返回来实现复杂的逻辑。我们还尝试链式调用它们，并修改了一些函数以便于链式调用。最后，我们使用了`array.map`和`Promise.all`来使用数组创建多个 promise 并等待它们全部解析。这有助于我们管理多个 promise 并跟踪它们的结果。接下来，我们将讨论 promise 中的错误处理。

### Promise 中的错误处理

当我们向 web 服务器发出请求或访问磁盘上的文件时，不能保证我们要执行的操作会 100%成功。当它不按我们想要的方式工作时，我们需要确保我们的应用程序能够处理这些错误，以便它不会意外退出或损坏我们的数据。在以前编写异步函数的处理程序时，我们可以简单地从错误参数中获取返回的错误。当我们使用 promises 时，我们也可以从`catch`处理程序中获取错误。

但当我们处理错误时，我们不仅仅是在尝试防止发生对我们或用户有害的事情；我们还需要确保我们的错误足够有意义，以便我们使用这些信息并防止该错误再次发生。通常，如果我们想要处理 promises 中的错误，我们可以简单地这样做：

```js
aFunctionReturnsPromise()
   .then(dosomething)
   .catch((error) => {
   // Handle some error here
});
```

当我们想要处理某种类型的错误时，我们可以调用`catch`函数并传递一个错误处理程序。但如果我们同时处理多个 promises 呢？如果我们使用 promise 链呢？当处理多个 promises 时，你可能会认为我们需要做类似这样的事情：

```js
aFunctionReturnsPromise().then((result) => {
   anotherFunctionReturnsPromise().then((anotherResult) => {
   }).catch((error) => {
      // Handle error here
   });
}).catch((error) => {
   // handle error
})
```

在这里，我们处理了`aFunctionReturnsPromise`函数返回的 promise 的任何类型的错误。在该 promise 的`then`处理程序中，我们调用`anotherFunctionReturnsPromise`，在其`then`处理程序中，我们处理了该 promise 的错误。这看起来并不太糟糕，因为我们只使用了两个嵌套的 promises，所以严格来说不需要链式调用，而且我们分别处理了每个错误。但通常，当你看到人们写这样的代码时，你也会看到类似这样的东西：

```js
aFunctionReturnsPromise().then((result) => {
   return anotherFunctionReturnsPromise().then((anotherResult) => {
      // Do operation here
   }).catch((error) => {
      // Handle error here
      logError(error);
      throw new Error ('something else');
   });
}).catch((error) => {
   // handle error
   logError(error);
   throw new Error ('something else');
});
```

我甚至看到过像这样写的生产级代码。虽然这看起来对很多开发者来说是个好主意，但这并不是处理 promises 中错误的理想方式。有一些使用情况适合这种错误处理方式。其中一种情况是，如果你确定了你将要得到的错误类型，并且想要为每种不同类型做自定义处理。当你的代码像这样时，很容易在日志文件中出现重复，因为你可以从前面的代码中看到，错误被记录了两次：一次在嵌套 promise 的 catch 处理程序中，一次在父 promise 中。为了减少错误处理的重复，你可以简单地移除嵌套 promise 中的任何处理程序，这样前面的代码看起来会像这样：

```js
aFunctionReturnsPromise().then((result) => {
   return anotherFunctionReturnsPromise().then((anotherResult) => {
      // Do operation here
   });
}).catch((error) => {
   // handle error
   logError(error);
   throw new Error ('something else');
});
```

你不必担心嵌套 promise 中的错误没有被处理 - 因为我们在`then`处理程序中返回了 promise，并且传递了状态而不是值。所以，当嵌套 promise 遇到错误时，最终会被父错误处理程序中的`catch`处理程序捕获。

我们必须记住的一件事是，当我们使用 promises 时，当出现错误时，`then`处理程序不会被调用。考虑以下例子：

```js
processSomeFile().then(() => {
   // Cleanup temp files
   console.log('cleaning up');
}).catch((error) => {
   console.log('oh no');
});
```

假设你正在创建一个文件处理函数，并且在处理完成后，在`then`处理程序中运行清理逻辑。当出现错误时，这会创建一个问题，因为当该 promise 被拒绝时，清理过程将永远不会被调用。这可能会引起很多问题。我们可能会因为临时文件没有被删除而耗尽磁盘空间。如果我们没有正确关闭连接，我们也可能会面临内存泄漏的风险。为了解决这个问题，一些开发者采取了简单的方法并复制了清理逻辑：

```js
processSomeFile().then(() => {
   // Cleanup temp files
   console.log('cleaning up');
}).catch((error) => {
   // Cleanup temp files
   console.log('cleaning up');
   console.log('oh no');
})
```

虽然这解决了我们的问题，但也创建了一个重复的代码块，所以最终，当我们想要更改清理过程中的某些逻辑时，我们需要记住在两个地方都进行更改。幸运的是，`Promise`类给了我们一个非常有用的处理程序，我们可以设置它以确保无论状态如何，处理程序都会被调用：

```js
   processSomeFile().then(() => {
}).catch((error) => {

   console.log('oh no');
}).finally(() => {
   // Cleanup temp files
   console.log('cleaning up');
})
```

在这里，我们正在附加一种新类型的处理程序到我们的 promise。`.finally`处理程序将在 promise 被`settled`时始终被调用，无论它是解决还是被拒绝。这是一个非常有用的处理程序，我们可以在我们的 promises 上设置它，以确保我们正确清理连接或删除文件。

在上一个练习中，我们设法使用`Promise.all`从一系列 promises 中获取结果列表。在我们的示例中，所有 promises 最终都解决了，并且我们得到了一个非常干净的数组返回给我们。我们如何处理我们不确定 promises 结果的情况？考虑上一个练习中的`getFullRecords`函数；当我们运行该函数时，它执行以下操作：

![图 8.20：执行 getFullRecords 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_20.jpg)

###### 图 8.20：执行 getFullRecords 函数

该函数同时执行所有三个操作，并在它们解决时解决。让我们修改`getFullRecords`函数以使其输出错误：

```js
function getFullRecords() {
   const ids = ['P6HB0O', '2ADN23', 'Not here'];
   const promises = ids.map(getFullRecord);
   return Promise.all(promises);
}
```

我们知道我们提供的第三个 ID 在我们的`getProfile`函数中不存在，因此它将被拒绝。当我们运行此函数时，我们将得到如下输出：

![图 8.21：运行 getProfile 函数时出错](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_21.jpg)

###### 图 8.21：运行 getProfile 函数时出错

`Promise.all`等待数组中的所有 promises 解决，并且如果其中一个请求被拒绝，它将返回一个拒绝的 promise。在处理多个 promises 时，请记住这一点；如果一个 promise 请求被拒绝，请确保您在错误消息中包含尽可能多的信息，以便您可以知道哪个操作被拒绝。

### 练习 64：使用 Promises 重构账单计算器

在上一个练习中，我们使用回调函数编写了账单计算逻辑。假设您工作的公司现在升级了他们的 Node.js 运行时，并且要求您使用 promises 重写该部分逻辑。打开`promises.js`文件，您将看到使用 promises 重写的更新后的`clientApi`：

#### 注意

Promises.js 可在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise64`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise64)找到。

+   您已经得到了支持 promises 的`clientApi`。

+   您需要实现一个功能，该功能计算用户的账单并以此格式返回结果：

```js
{
   id: 'XXXXX',
   address: '2323 sxsssssss',
   due: 236.6
}
```

+   您需要实现一个`calculateBill`函数，该函数接受一个 ID 并计算该用户的燃气账单。

+   您需要实现一个新的`calculateAll`函数来计算从`getUsers`获取的所有用户的账单。

我们将打开包含`clientApi`的文件并在那里进行工作。

执行以下步骤来实现练习：

1.  我们将首先创建`calculate`函数。这次，我们只会传递`id`：

```js
function calculate(id) {}
```

1.  在`calculate`中，我们将首先调用`getUsers`：

```js
function calculate(id) {
return clientApi.getUsers().then((result) => {
   const currentUser = result.users.find((user) => user.id === id);
   if (!currentUser) { throw Error('user not found'); }
}
}
```

因为我们想要计算并返回一个 promise，并且`getUsers`返回一个 promise，所以当我们调用`getUsers`时，我们将简单地返回 promise。在这里，我们将运行相同的`find`方法来找到我们当前正在计算的用户。然后，如果用户不存在，我们可以在`then`处理程序中直接抛出错误。

1.  在`getUsers`的`then`处理程序中调用`getUsage`：

```js
function calculate(id) {
return clientApi.getUsers().then((result) => {
   const currentUser = result.users.find((user) => user.id === id);
   if (!currentUser) { throw Error('user not found'); }
return clientApi.getUsage(currentUser.id).then((usage) => {
});
}
}
```

在这里，我们返回`clientApi`，因为我们想要链接我们的 promise，并且希望最内层的 promise 出现并被解决。

1.  在`getUsage`的`then`处理程序中调用`getRate`：

```js
function calculate(id) {
   return clientApi.getUsers().then((result) => {
      const currentUser = result.users.find((user) => user.id === id);
      if (!currentUser) { throw Error('user not found'); }
      return clientApi.getUsage(currentUser.id).then((usage) => {
         return clientApi.getRate(currentUser.id).then((rate) => {
   return {
      id,
      address: currentUser.address,
      due: (rate * usage.reduce((prev, curr) => curr + prev)).toFixed(2)
   };
});
});
}
}
```

这是我们需要调用的最后一个函数。我们也将在这里使用`return`。在我们的`then`处理程序中，我们将拥有所有我们需要的信息。在这里，我们可以直接运行我们的计算并直接返回值。该值将是我们返回的 promise 的解决值。

1.  创建一个`calculateAll`函数：

```js
function calculateAll() {}
```

1.  调用`getUsers`以获取我们用户的列表：

```js
function calculateAll() {
   return clientApi.getUsers().then((result) => {});
}
```

1.  在这里，结果将是我们系统中用户的列表。然后，我们将在每个用户上运行`calculate`。使用`Promise.all`和一个 map 数组来调用`calculate`函数对每个用户进行计算：

```js
function calculateAll() {
   return clientApi.getUsers().then((result) => {
      return Promise.all(result.users.map((user) => calculate(user.id)));
});
}
```

我们使用一个 map 数组来返回一个新的 promise 数组。当我们调用现有的`calculate`函数时，返回的 promise 数组将是 promise。当我们将该数组传递给`Promise.all`时，它将返回一个 promise，该 promise 将解析为来自 promise 列表的结果列表。

1.  在我们的一个用户上调用`calculate`：

```js
calculate('DDW2AU').then(console.log)
```

输出应该如下：

![图 8.22：调用我们的一个用户上的 calculate](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_22.jpg)

###### 图 8.22：在我们的一个用户上调用 calculate

1.  调用`calculateAll`函数：

```js
calculateAll().then(console.log)
```

输出应该如下：

![图 8.23：调用 calculateAll 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_23.jpg)

###### 图 8.23：调用 calculateAll 函数

在以前的练习和活动中，我们创建了函数，使用回调从多个异步函数计算结果，然后使用 promise 重写了这些函数。现在，您知道如何使用 promise 重构旧的回调风格代码。当您在重构需要您开始使用 promise 的大型项目时，这是非常有用的。在下一章中，我们将介绍一种新的方法，可以用来处理异步函数。

## 异步和等待

JavaScript 开发人员一直梦想着处理异步函数而无需在其周围编写包装器。然后，引入了一个新功能，这改变了我们对 JavaScript 异步操作的认识。考虑我们在上一个练习中使用的代码：

```js
function getFullRecord(id) {
   return getProfile(id)
      .then(getCart)
      .then(getSubscription);
}
```

这很简单，因为我们使用了 promise 链式调用，但它并没有告诉我们更多的信息，看起来我们只是调用了一堆函数。如果我们可以有这样的东西会怎样：

```js
function getFullRecord(id) {
   const profile = getProfile(id);
   const cart = getCart(id);
   const subscription = getSubscription(id);
   return {
      ...profile,
      cart,
      subscription
   };
}
```

现在，当你看前面的代码时，它就更有意义了，看起来就像我们只是调用一些非异步函数来获取数据，然后返回组合数据。这就是 async 和 await 可以实现的。通过使用 async 和 await，我们可以像这样编写我们的代码，同时保持对异步操作的完全控制。考虑一个简单的`async`函数，它返回一个 promise：

```js
function sayHello() {
   return Promise.resolve('hello world');
}
```

这只是一个简单的`async`函数，就像我们在以前的练习和活动中使用的那样。通常，如果我们想调用这个函数并获取返回的 promise 的值，我们需要执行以下命令：

```js
sayHello().then(console.log)
```

输出应该如下：

![图 8.24：获取返回的 promise 的值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_24.jpg)

###### 图 8.24：获取返回的 promise 的值

这种方法并不新鲜；我们仍然调用函数返回一个 promise，然后通过`then`处理程序获取解析后的值。如果我们想要使用新的 async 和 await 功能，我们首先创建一个将运行操作的函数：

```js
async function printHello() {
   // Operation here
}
```

我们所做的就是在`function`关键字之前添加`async`。我们这样做是为了将这个函数标记为`async`函数，这样我们就可以在`printHello()`函数中使用`await`来调用`sayHello`函数，而不需要使用`then`处理程序：

```js
async function printHello() {
   // Operation here
   const message = await sayHello();
   console.log(message);
}
```

在这个`async`函数中，我们调用了我们的`sayHello`函数，它返回一个 promise。因为我们在之前使用了`await`关键字，它将尝试解析该 promise 并将解析后的值传递给我们声明为消息的常量。通过使用这个，我们让我们的`async`函数看起来像一个同步函数。稍后，我们可以像调用普通函数一样调用该函数：

```js
printHello();
```

输出应该如下：

![图 8.25：调用 printHello 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_25.jpg)

###### 图 8.25：调用 printHello 函数

### 练习 65：异步和等待函数

在这个练习中，我们将学习创建 async 函数并在其他 async 函数中调用它们。在单个函数中处理大量的 async 操作时，使用 async 和 await 可以帮助我们。我们将一起编写我们的第一个`async`函数，并探索在应用程序中处理 async 和 await 时需要牢记的一些事情。

#### 注意

此活动的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise65`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise65)找到。

执行以下步骤完成练习：

1.  创建一个`getConcertList`函数：

```js
function getConcertList() {
   return Promise.resolve([
      'Magical Mirai 2018',
      'Magical Mirai 2019'
   ]);
}
```

1.  调用函数并使用`await`：

```js
const concerts = await getConcertList();
```

当我们运行上述代码时，我们将会得到如下错误：

![图 8.26：使用 await 调用函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_26.jpg)

###### 图 8.26：使用 await 调用函数

我们会得到这个错误的原因是我们只能在`async`函数内部使用`await`关键字。如果我们想使用它，我们必须将语句包装在`async`函数中。

1.  修改语句并将其包装在`async`函数中：

```js
async function printList() {
   const concerts = await getConcertList();
   console.log(concerts);
}
printList();
```

输出应该如下：

![图 8.27：修改语句并将其包装在 async 函数中](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_27.jpg)

###### 图 8.27：修改语句并将其包装在 async 函数中

当我们运行这个函数时，我们将看到列表被打印出来，一切都运行正常。我们也可以将`async`函数视为返回 promise 的函数，因此如果我们想在操作结束后运行代码，我们可以使用`then`处理程序。

1.  使用`async`函数的`then()`函数调用处理程序：

```js
printList().then(() => {
   console.log('I am going to both of them.')
});
```

输出应该如下：

![图 8.28：使用 async 函数的 then 函数调用处理程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_28.jpg)

###### 图 8.28：使用 async 函数的 then 函数调用处理程序

现在，我们知道`async`函数的行为就像返回 promise 的普通函数一样。

1.  创建一个`getPrice`函数来获取音乐会的价格：

```js
function getPrice(i) {
   const prices = [9900, 9000];
   return Promise.resolve(prices[i]);
}
```

1.  修改`printList`以包括从`getPrice`获取的价格：

```js
async function printList() {
   const concerts = await getConcertList();
   const prices = await Promise.all(concerts.map((c, i) => getPrice(i)));
   return {
      concerts,
      prices
   };
}
printList().then(console.log);
```

在这个函数中，我们只是尝试使用`getPrice`函数获取所有的价格。在上一节中，我们提到了如何使用`Promise.all`将一个 promise 数组包装在一个 promise 中，该 promise 只有在数组中的每个 promise 都解析后才会解析。因为`await`关键字可以用于返回 promise 并解析其值的任何函数，我们可以使用它来获取一个价格数组。当我们运行上述代码时，我们将看到这个函数解析为以下内容：

![图 8.29：修改 printList 以包括从 getPrice 获取的价格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_29.jpg)

###### 图 8.29：修改 printList 以包括从 getPrice 获取的价格

这意味着如果我们有一个返回 promise 的函数，我们不再需要使用`then`处理程序。在`async`函数中，我们可以简单地使用`await`关键字来获取解析后的值。但是，在`async`函数中处理错误的方式有点不同。

1.  创建一个返回 rejected promise 的`buggyCode`函数：

```js
function buggyCode() {
   return Promise.reject(new Error('computer: dont feel like working today'));
}
```

1.  在`printList`中调用`buggyCode`：

```js
async function printList() {
   const concerts = await getConcertList();
   const prices = await Promise.all(concerts.map((c, i) => getPrice(i)));
   await buggyCode();
   return {
      concerts,
      prices
   };
}
printList().then(console.log);
```

输出应该如下：

![图 8.30：在 printList 中调用 buggyCode](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_30.jpg)

###### 图 8.30：在 printList 中调用 buggyCode

因为`buggyCode`抛出了一个错误，这会停止我们的函数执行，并且将来甚至可能终止我们的进程。为了处理这种类型的错误，我们需要捕获它。

1.  在 buggyCode 上使用`catch`处理程序：

```js
async function printList() {
   const concerts = await getConcertList();
   const prices = await Promise.all(concerts.map((c, i) => getPrice(i)));
   await buggyCode().catch((error) => {
      console.log('computer produced error');
      console.log(error);
   });
   return {
      concerts,
      prices
   };
}
printList().then(console.log);
```

我们可以像处理常规 promise 一样处理`buggyCode`的错误，并传递一个`catch`处理程序。这样，promise rejection 将被标记为已处理，并且不会返回`UnhandledPromiseRejectionWarning`：

![图 8.31：在 buggyCode 上使用 catch 处理程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_31.jpg)

###### 图 8.31：在 buggyCode 上使用 catch 处理程序

这是处理`async`函数中的 promise rejection 的一种方法。还有一种更常见的方法。

1.  使用`try`…`catch`修改错误处理：

```js
async function printList() {
   const concerts = await getConcertList();
   const prices = await Promise.all(concerts.map((c, i) => getPrice(i)));
   try {
      await buggyCode();
   } catch (error) {
      console.log('computer produced error');
      console.log(error);
   }
   return {
      concerts,
      prices
   };
}
printList().then(console.log);
```

输出应该如下所示：

![图 8.32：使用 try…catch 修改错误处理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_32.jpg)

###### 图 8.32：使用 try…catch 修改错误处理

使用`try`…`catch`是许多开发人员在处理可能抛出错误的函数时熟悉的。使用`try`…`catch`块来处理我们的`buggyCode`的错误将使代码更易读，并实现异步的目标，即消除传递 promise 处理程序。接下来，我们将讨论如何正确处理多个 promise 和并发性。

### 异步等待并发性

在处理 JavaScript 中的多个异步操作时，了解你想要运行的操作的顺序至关重要。你编写代码的方式可以很大程度上改变应用程序的行为。让我们看一个例子：

```js
function wait(seconds) {
   return new Promise((resolve) => {
      setTimeout(() => {
        resolve();
      }, seconds * 1000);
   });
}
```

这是一个非常简单的函数，它返回一个 promise，只有在经过`n`秒后才会解析。为了可视化并发性，我们声明了`runAsync`函数：

```js
async function runAsync() {
   console.log('starting', new Date());
   await wait(1);
   console.log('i waited 1 second', new Date());
   await wait(2);
   console.log('i waited another 2 seconds', new Date());
}
```

当我们运行这个函数时，我们会看到我们的程序会等待 1 秒并打印出第一条语句，然后在 2 秒后打印出另一条语句。总等待时间将是 3 秒：

![图 8.33：返回在 n 秒后解析的 promise 的函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_33.jpg)

###### 图 8.33：返回在 n 秒后解析的 promise 的函数

如果我们想要同时运行两个`wait`函数呢？在这里，我们可以使用`Promise.all`：

```js
async function runAsync() {
   console.log('starting', new Date());
   await Promise.all([wait(1), wait(2)]);
   console.log('i waited total 2 seconds', new Date());
}
```

输出应该如下所示：

![图 8.34：使用 Promise.all 运行两个等待函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_34.jpg)

###### 图 8.34：使用 Promise.all 运行两个等待函数

我们在这里做的是移除了`await`，并将`wait`函数返回的两个 promise 放入数组中，然后将其传递给`Promise.all`。当我们移除`await`关键字并使用`Promise.all`时，我们可以确保代码不会失控并将继续执行。如果你在循环中处理 promise，就像下面的代码一样：

```js
async function runAsync() {
   console.log('starting', new Date());
   for (let i = 0; i < 2; i++) {
      await wait(1);
   }
   console.log('i waited another 2 seconds', new Date());
}
```

这不提供并发性。想象一下，我们不是在等待，而是从数据库中获取用户信息：

```js
async function runAsync() {
   const userProfiles = [];
   for (let i = 0; i < 2; i++) {
      const profile = await getProfile(i);
      userProfiles.push(profile);
   }
   return userProfiles;
}
```

在这里，我们的用例是从数据库中获取多个用户配置文件。虽然前面的代码可以工作，但它不是最高效的实现。正如我们之前提到的，这段代码会等到最后一个请求完成后才会获取下一个请求。为了优化这段代码，我们可以简单地使用`array.map`和`Promise.all`结合使用：

```js
async function runAsync() {
   return await Promise.all([0, 1].map(getProfile));
}
```

这样，我们不是等待每个操作完成；我们只是等待包装 promise 被解析。在 map 数组中，我们只是生成了 promises，一旦它们被创建，它将执行我们的操作。与`for`循环方法相比，我们不需要等待前一个 promise 在执行下一个 promise 之前解决。我们将在下一章讨论它们的区别。

### 何时使用 await

在之前的例子中，我们讨论了在我们的`async`函数中使用`await`关键字。但是什么时候应该使用`await`，什么时候应该避免呢？在上一节中，我们讨论了当我们想要启用并发并确保操作不会互相等待时，应避免使用`await`。考虑以下代码示例：

```js
async function example() {
   const result1 = await operation1();
   const result2 = await operation2(result1.something);
   return result2;
}
```

在这个例子中，`operation2`函数只有在`operation1`完成后才会执行。当你有依赖关系并且`result2`依赖于`result1`中的某些内容时，这是很有用的，就像例子中所示的那样。如果它们之间没有相互依赖，你可以利用`Promise.all`来确保并发性：

```js
async function example() {
   const result1 = operation1();
   const result2 = operation2();
   return await Promise.all([result1, result2]);
}
```

没有`await`关键字，代码只是将从两个操作返回的 promise 分配给我们声明的常量。这确保了`operation2`在`operation1`之后立即触发，并且没有等待。我们还需要注意的另一点是错误处理。考虑我们在上一个练习中使用的`buggyCode`：

```js
function buggyCode() {
   return Promise.reject(new Error('computer: dont feel like working today'));
}
```

这个函数只是返回一个被拒绝的 promise。在使用它时，我们应该使用`catch`来处理 promise 的错误：

```js
async function printList() {
   try {
      await buggyCode();
   } catch (error) {
      console.log('computer produced error');
      console.log(error);
   }
}
```

当我们运行这段代码时，我们会看到我们的错误被很好地处理，并且错误消息被记录下来。在这里，我们在运行`buggyCode`函数时使用了`await`，但是当我们删除`await`关键字时，我们将看到以下内容：

![图 8.35：删除 await 关键字后运行 buggyCode 函数

将以下文本按行翻译成中文：

###### 图 8.35：删除 await 关键字后运行 buggyCode 函数

您会看到我们有一个未处理的 promise 拒绝；它似乎没有出现，因为我们的`try`…`catch`什么也没做。这是因为没有`await`关键字，JavaScript 不会尝试等待 promise 解析；因此，它不知道将来会抛出错误。这个`try`…`catch`块将捕获的是在执行函数时抛出的错误。这是我们在使用`async`和`await`编写代码时需要牢记的事情。在下一个练习中，我们将编写一个调用多个`async`函数并能够从错误中恢复的复杂函数。

### 练习 66：复杂的异步实现

在这个练习中，我们将构建一个非常复杂的`async`函数，并使用我们之前学到的一切来确保函数具有高性能并对错误具有弹性。

#### 注意

此活动的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise66`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson08/Exercise66)找到。

完成练习的步骤如下：

1.  创建一个`getPlaylists`函数，根据播放列表名称返回一个 ID 数组：

```js
function getPlaylist(id) {
   const playLists = {
      'On the road': [0, 6, 5, 2],
      'Favorites' : [1, 4, 2],
      'Corrupted': [2, 4, 7, 1]
   };
   const playList = playLists[id];
   if (!playList) {
      throw new Error('Playlist does not exist');
   }
   return Promise.resolve(playLists[id]);
}
```

该函数将返回一个歌曲 ID 数组作为播放列表。如果未找到，它将简单地返回`null`。

1.  创建一个`getSongUrl`函数，根据编号`id`返回一个歌曲 URL：

```js
function getSongUrl(id) {
   const songUrls = [
      'http://example.com/1.mp3',
      'http://example.com/2.mp3',
      'http://example.com/3.mp3',
      'http://example.com/4.mp3',
      'http://example.com/5.mp3',
      'http://example.com/6.mp3',
      'http://example.com/7.mp3',
   ];
   const url = songUrls[id];
   if (!url) {
      throw new Error('Song does not exist');
   }
   return Promise.resolve(url); // Promise.resolve returns a promise that is resolved with the value given
}
```

1.  创建一个`playSong`异步函数，该函数接受歌曲的 ID 并生成两个输出-一个显示正在播放的歌曲，另一个通知用户歌曲已经完成：

```js
async function playSong(id) {
   const url = await getSongUrl(id);
   console.log(`playing song #${id} from ${url}`);
   return new Promise((resolve) => {
      setTimeout(() => {
        console.log(`song #${id} finished playing`);
        resolve();
      }, Math.random() * 3 * 1000);
   });
}
```

1.  创建一个`playPlaylist`函数，该函数接受一个播放列表 ID，并在播放列表中的每首歌曲上调用`playSong`：

```js
async function playPlaylist(id) {
   const playList = await getPlayLlist(id);
   await Promise.all(playList.map(playSong));
}
```

这是一个简单的实现，没有进行错误处理。

1.  运行`playPlaylist`函数：

```js
playPlaylist('On the road').then(() => {
   console.log('finished playing playlist');
});
```

输出应该如下：

![图 8.36：运行 playPlaylist 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_36.jpg)

###### 图 8.36：运行 playPlaylist 函数

我们得到了一个非常有趣的输出；它同时播放所有歌曲。而且，它没有优雅地处理错误。

1.  不带参数调用`playPlaylist`：

```js
playPlaylist().then(() => {
   console.log('finished playing playlist');
});
```

输出应该如下：

![图 8.37：不带参数调用 playPlaylist](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_37.jpg)

###### 图 8.37：不带参数调用 playPlaylist

我们之所以出现这个错误是因为当`getPlaylist`抛出错误时，我们没有处理错误。

1.  修改`playPlaylist`以处理错误：

```js
async function playPlaylist(id) {
   try {
      const playList = await getPlaylist(id);
      return await Promise.all(playList.map(playSong));
   } catch (error) {
      console.log(error);
   }
}
```

我们在这里没有做任何特别的事情；我们只是在`getPlaylist`周围添加了一个`try…catch`块，这样当 promise 被拒绝时，它将被正确处理。更新后，当我们再次运行我们的代码时，我们将收到以下输出：

![图 8.38：修改 playPlaylist 以处理错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_38.jpg)

###### 图 8.38：修改`playPlaylist`以处理错误

我们看到错误已经被正确处理，但是我们仍然在最后得到了`finished`消息。这是我们不想要的，因为当发生错误时，我们不希望 promise 链继续。

1.  修改`playPlaylist`函数和调用者：

```js
async function playPlaylist(id) {
   const playList = await getPlaylist(id);
   return await Promise.all(playList.map(playSong));
}
playPlaylist().then(() => {
   console.log('finished playing playlist');
}).catch((error) => {
   console.log(error);
});
```

在编写`async`代码时，最好将 promise 处理放在父级，并让错误冒泡。这样，我们可以为此操作只有一个错误处理程序，并能够一次处理多个错误。

1.  尝试调用一个损坏的播放列表：

```js
playPlaylist('Corrupted').then(() => {
   console.log('finished playing playlist');
}).catch((error) => {
   console.log(error);
});
```

](Images/C14587_08_35.jpg)

![图 8.39：调用一个损坏的播放列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_39.jpg)

###### 图 8.39：调用损坏的播放列表

这段代码运行良好，并且错误已经处理，但仍然一起播放。我们想要显示`finished`消息，因为`歌曲不存在`错误是一个小错误，我们想要抑制它。

1.  修改`playPlaylist`以按顺序播放歌曲：

```js
async function playPlaylist(id) {
   const playList = await getPlaylist(id);
   for (const songId of playList) {
      await playSong(songId);
   }
}
```

输出应如下所示：

![图 8.40：修改后的 playPlaylist 以按顺序播放歌曲](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_40.jpg)

###### 图 8.40：修改`playPlaylist`以按顺序播放歌曲

在修改中，我们删除了`Promise.all`，并用`for`循环替换了它，对每首歌曲使用`await`。这确保我们在继续下一首歌曲之前等待每首歌曲完成。

1.  修改`playSong`以抑制`未找到`错误：

```js
async function playSong(id) {
   try {
      const url = await getSongUrl(id);
      console.log('playing song #${id} from ${url}');
      return new Promise((resolve) => {
        setTimeout(() => {
           console.log('song #${id} finished playing');
           resolve();
        }, Math.random() * 3 * 1000);
      });
   } catch (error) {
      console.log('song not found');
   }
}
```

输出应如下所示：

![图 8.41：修改后的 playSong 以抑制未找到的错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_41.jpg)

###### 图 8.41：修改`playSong`以抑制未找到的错误

我们在这里做的是用`try`...`catch`块包装我们的逻辑。这使我们能够抑制代码生成的任何错误。当`getSongUrl`抛出错误时，它不会上升到父级；它将被`catch`块捕获。

在这个练习中，我们使用`async`和`await`实现了一个播放列表播放器，并使用了我们对`Promise.all`和`async`并发的了解来优化我们的播放列表播放器，使其一次只播放一首歌曲。这使我们能够更深入地了解 async 和 await，并在将来实现我们自己的`async`函数。在下一节中，我们将讨论如何将现有的基于 promise 或回调的代码迁移到 async 和 await。

### 活动 12：使用 Async 和 Await 重构账单计算器

您的公司再次更新了其 Node.js 运行时。在此活动中，我们将使用 async 和 await 重构之前创建的账单计算器：

+   您获得了使用承诺实现的`clientApi`。

+   您需要将`calculate()`更新为`async`函数。

+   您需要将`calculateAll()`更新为`async`函数。

+   `calculateAll()`需要使用`Promise.all`一次获取所有结果。

打开`async.js`文件，使用`async`和`await`实现`calculate`和`calculateAll`函数。

#### 注意

此活动的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson08/Activity12/Activity12.js`](https://github.com/TrainingByPackt/Professional-JavaScript/blob/master/Lesson08/Activity12/Activity12.js)找到。

执行以下步骤完成活动：

1.  创建一个`calculate`函数，以 ID 作为输入。 

1.  在`calculate`中，使用`await`调用`clientApi.getUsers()`来检索所有用户。

1.  使用`array.find()`使用`id`参数找到`currentUser`。

1.  使用`await`调用`getUsage()`来获取该用户的使用情况。

1.  使用`await`调用`getRate`以获取用户的费率。

1.  返回一个新对象，其中包括`id`、`address`和总应付金额。

1.  将`calculateAll`函数编写为`async`函数。

1.  使用`await`调用`getUsers`以检索所有用户。

1.  使用数组映射创建一个承诺列表，并使用`Promise.all`将它们包装起来。然后，在由`Promise.all`返回的承诺上使用等待，并返回其值。

1.  在一个用户上调用`calculate`。

1.  调用`calculateAll`。

输出应如下所示：

![图 8.42：调用 calculateAll 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_08_42.jpg)

###### 图 8.42：调用 calculateAll 函数

#### 注意

此活动的解决方案可在第 615 页找到。

### 将回调和 Promise-Based 代码迁移到 Async 和 Await

在处理大型项目时，经常需要使用 async 和 await 重构现有代码。在进行这些重构时，我们需要牢记应保持相同的功能和错误处理类型。在本节中，我们将学习如何将现有的回调和基于 promise 的代码迁移到 async 和 await。

### 将基于回调的代码迁移到 Async 和 Await

当我们迁移基于回调的代码时，我们需要重写函数，并确保它返回一个 promise 而不是使用回调。考虑以下代码：

```js
function makeRequest(param, callback) {
   request(param, (err, data) => {
      if (err) {
        return callback(err);
      }
      const users = data.users;
      callback(null, users.map((u) => u.id));
   });
}
```

上述代码接受一个参数并调用`request`模块，我们无法修改它，并返回用户 ID 的列表。一旦完成，如果出现错误，它将通过回调简单地返回。当我们想要使用 async 和 await 重构这段代码时，我们可以首先确保它返回一个 promise。这样做的同时，我们也想删除`callback`参数：

```js
function makeRequest(param) {
   return new Promise((resolve, reject) => {
      // Logic here
   });
}
```

然后，我们需要把我们的逻辑复制到：

```js
function makeRequest(param) {
   return new Promise((resolve, reject) => {
      request(param, (err, data) => {
        if (err) {
           return callback(err);
        }
        const users = data.users;
        callback(null, users.map((u) => u.id));
      });
   });
}
```

在这里，我们需要进行修改。我们需要删除所有对`callback`的引用，并改用`reject`和`resolve`：

```js
function makeRequest(param) {
   return new Promise((resolve, reject) => {
      request(param, (err, data) => {
        if (err) {
           return reject(err);
        }
        const users = data.users;
        resolve(users.map((u) => u.id));
      });
   });
}
```

您可以在这里看到，我们在调用`request`时仍在使用回调样式。那是因为我们无法控制外部库。我们能做的是确保每次调用它时，我们都返回一个 promise。现在，我们已经完全将我们的传统代码转换为现代标准。您现在可以像这样在`async`函数中使用它：

```js
async function use() {
   const userIds = await makeRequest({});
}
```

通常，代码重构要困难得多。建议从最基本的级别开始，随着重构的进行逐步提升。当处理嵌套回调时，确保使用`await`来确保保留依赖关系。

## 总结

在本章中，我们讨论了如何使用 promise 和 async 和 await 更好地管理代码中的异步操作。我们还谈到了将现有的回调代码重构为 async 和 await 的各种方法。在我们的应用程序中使用 async 和 await 不仅有助于使我们的代码更易读，还将帮助我们对实现进行未来测试。在下一章中，我们将讨论如何在我们的应用程序中使用基于事件的编程。


# 第十章：事件驱动编程和内置模块

## 学习目标

在本章结束时，您将能够：

+   在 Node.js 中使用事件模块

+   创建事件发射器以增强现有代码的功能

+   构建自定义事件发射器

+   使用内置模块和实用工具

+   实现一个计时器模块，以获得调度计时器函数的 API

在本章中，我们将使用事件发射器和内置模块，以避免创建具有紧密耦合依赖关系的项目。

## 介绍

在上一章中，我们讨论了 Node.js 中如何使用事件驱动编程，以及如何修改正常的基于回调的异步操作以使用 async-await 和 promises。我们知道 Node.js 核心 API 是建立在异步驱动架构上的。Node.js 有一个事件循环，用于处理大多数异步和基于事件的操作。

在 JavaScript 中，事件循环不断地运行并从回调队列中消化消息，以确保执行正确的函数。没有事件，我们可以看到代码非常紧密耦合。对于一个简单的聊天室应用程序，我们需要编写类似这样的东西：

```js
class Room {
    constructor() {
        this.users = [];
    }
    addUser(user) {
        this.users.push(user);
    }
    sendMessage(message) {
        this.users.forEach(user => user.sendMessage(message));
    }
}
```

正如您所看到的，因为我们没有使用事件，我们需要保留房间中所有用户的列表。当我们将用户添加到房间时，我们还需要将用户添加到我们创建的列表中。在发送消息时，我们还需要遍历我们列表中的所有用户并调用`sendMessage`方法。我们的用户类将被定义如下：

```js
class User {
    constructor() {
        this.rooms = {}
    }
    joinRoom(roomName, room) {
        this.rooms[roomName] = room;
        room.addUser(this);
    }
    sendMessage(roomName, message) {
        this.rooms[roomName].sendMessage(message);
    }
}
```

您可以看到这变得过于复杂；为了加入聊天室，我们需要同时将房间和当前用户添加到房间中。当我们的应用程序最终变得非常复杂时，我们会发现这会引发传统方法的问题。如果此应用程序需要网络请求（异步操作），它将变得非常复杂，因为我们需要用异步操作包装我们希望执行的所有代码。我们可能能够将该逻辑提取出来，但是当我们处理由未知数量的随机事件驱动的应用程序时，使用事件驱动编程的好处在于使我们的代码更易于维护。

## 传统方法与事件驱动编程

正如我们在介绍中提到的，在传统的编程模式中，当我们希望它们进行通信时，我们喜欢在组件之间建立直接的联系。这在下图中有所体现：

![图 9.1：传统编程方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_01.jpg)

###### 图 9.1：传统编程方法

对于一个简单的应用程序，允许用户更新其个人资料并接收消息，我们可以看到我们有四个组件：

+   代理

+   个人资料

+   投票

+   消息

这些组件之间的交互方式是通过调用希望通信的组件中的适当方法来实现的。通过这样做，使得代码非常易于理解，但我们可能需要传递组件引用。以我们的`Agent`类为例：

```js
class Agent {
    constructor(id, agentInfo, voteObj, messageObj) {
        this.voteObj = voteObj;
        this.messageObj = messageObj;
    }
    checkMessage() {
        if (this.messageObj.hasMessage()) {
            const message = this.messageObj.nextMessate();
            return message;
        }
        return undefined;
    }
    checkVote() {
        if (this.voteObj.hasNewVote()) {
            return true;
        }
        return false;
    }
}
```

`Agent`类必须在未来存储与其希望通信的组件的引用。如果没有，我们的组件就无法与其他组件通信。在前面的示例中，我们创建的`Agent`对象与其他所有内容都非常紧密耦合。它在创建时需要所有这些对象的引用，这使得我们的代码在未来要更改某些内容时非常难以解耦。考虑前面的`Agent`代码。如果我们要为其添加更多功能，我们希望代理类与新功能进行通信，例如社交页面、直播页面等。只要我们在我们的`constructor`中添加对这些对象的引用，这在技术上是可行的。通过这样做，我们将冒着我们的代码在未来看起来像这样的风险：

```js
class Agent {
    constructor(id, agentInfo, voteObj, messageObj, socialPage, gamePage, liveStreamPage, managerPage, paymentPage...) {
        this.voteObj = voteObj;
        this.messageObj = messageObj;
        this.socialPage = socialPage;
        this.gamePage = gamePage;
        this.liveStreamPage = liveStreamPage;
        this.managerPage = managerPage;
        this.paymentPage = paymentPage;
        ...
    }
    ...
}
```

当我们的应用程序变得越来越复杂时，我们的`Agent`类也会变得越来越复杂。因为它在`constructor`中有所有的引用，所以我们容易因为错误地传递参数类型而引起问题。当我们试图一次性在多个组件之间进行通信时，这是一个常见的问题。

## 事件

我们之前的方法——即处理组件通信的方法——是直接的，而且非常静态。我们需要存储我们想要进行通信的组件引用，并且在想要向其发送消息时编写非常特定于组件的代码。在 JavaScript 中，有一种新的通信方式，它被称为**事件**。

让我们考虑这个例子；你朋友传递给你的光是你从朋友那里接收事件的一种方式。在 JavaScript 中，我们可以拥有能够发出事件的对象。通过发出事件，我们可以创建对象之间的新通信方式。这也被称为观察者模式。以下图表描述了观察者模式：

![图 9.2：观察者模式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_02.jpg)

###### 图 9.2：观察者模式

在这种模式中，我们不是在组件中调用特定的方法，而是希望发起通信的组件只是发出一个事件。我们可以有多个观察者观察来自组件的事件。这样，我们把消费消息的责任完全放在了消费者身上。当观察者决定观察事件时，它将在组件发出事件时每次接收到事件。如果使用事件来实现前面复杂的例子，它会是这样的：

![图 9.3：使用事件的观察者模式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_03.jpg)

###### 图 9.3：使用事件的观察者模式

在这里，我们可以看到每个组件都遵循我们的观察者模式，当我们将其转换为代码时，它会看起来像这样：

```js
class Agent {
    constructor(id, agentInfo, emitter) {
        this.messages = [];
        this.vote = 0;
        emitter.on('message', (message) => {
            this.messages.push(message);
        });
        emitter.on('vote', () => {
            this.vote += 1;
        })
    }
}
```

现在，我们不再需要获取所有我们想要进行通信的组件的引用，而是只传递一个事件发射器，它处理所有的消息。这使得我们的代码与其他组件的耦合度大大降低。这基本上就是我们在代码中实现事件观察者模式的方式。在现实生活中，这可能会变得更加复杂。在下一个练习中，我们将介绍一个简单的例子，演示如何使用 Node.js 中内置的事件系统来发出事件。

### 练习 67：一个简单的事件发射器

在介绍中，我们谈到了如何使用事件观察者模式来消除我们代码中想要进行通信的所有组件的引用。在这个练习中，我们将介绍 Node.js 中内置的事件模块，我们如何创建`EventEmitter`以及如何使用它。

执行以下步骤完成这个练习：

1.  导入`events`模块：

```js
const EventEmitter = require('events');
```

我们将导入 Node.js 中内置的`events`模块。它提供了一个构造函数，我们可以用它来创建自定义的事件发射器或创建一个继承自它的类。因为这是一个内置模块，所以不需要安装它。

1.  创建一个新的`EventEmitter`：

```js
const emitter = new EventEmitter();
```

1.  尝试发出一个事件：

```js
emitter.emit('my-event', { value: 'event value' });
```

1.  附加一个事件监听器：

```js
emitter.on('my-event', (value) => {
    console.log(value);
});
```

要向我们的发射器添加事件监听器，我们需要在发射器上调用`on`方法，传入事件名称和在发出事件时要调用的函数。当我们在发出事件后添加事件监听器时，我们会发现事件监听器没有被调用。原因是在我们之前发出事件时，并没有为该事件附加事件监听器，因此它没有被调用。

1.  再发出一个事件：

```js
emitter.emit('my-event', { value: 'another value' });
```

当我们这次发出事件时，我们会看到我们的事件监听器被正确调用，并且我们的事件值被正确打印出来，就像这样：

![图 9.4：使用正确的事件值发出的事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_04.jpg)

###### 图 9.4：使用正确的事件值发出的事件

1.  为`my-event`附加另一个事件监听器：

```js
emitter.on('my-event', (value) => {
    console.log('i am handling it again');
});
```

我们不仅限于每个事件只有一个监听器 - 我们可以附加尽可能多的事件监听器。当发射事件时，它将调用所有监听器。

1.  发射另一个事件：

```js
emitter.emit('my-event', { value: 'new value' });
```

以下是上述代码的输出：

![图 9.5：多次发射事件后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_05.jpg)

###### 图 9.5：多次发射事件后的输出

当我们再次发射事件时，我们将看到我们发射的第一个事件。我们还将看到它成功地打印出我们的消息。请注意，它保持了与我们附加监听器时相同的顺序。当我们发射错误时，发射器会遍历数组并依次调用每个监听器。

1.  创建`handleEvent`函数：

```js
function handleEvent(event) {
    console.log('i am handling event type: ', event.type);
}
```

当我们设置我们的事件监听器时，我们使用了匿名函数。虽然这很容易和简单，但它并没有为我们提供`EventEmitters`提供的所有功能：

1.  将新的`handleEvent`附加到新类型的事件上：

```js
emitter.on('event-with-type', handleEvent);
```

1.  发射新的事件类型：

```js
emitter.emit('event-with-type', { type: 'sync' });
```

以下是上述代码的输出：

![图 9.6：发射新的事件类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_06.jpg)

###### 图 9.6：发射新的事件类型

1.  移除事件监听器：

```js
emitter.removeListener('event-with-type', handleEvent);
```

因为我们使用了命名函数，所以我们可以使用这个函数引用来移除监听器，一旦我们不再需要将事件传递给该监听器。

1.  在移除监听器后发射事件：

```js
emitter.emit('event-with-type', { type: 'sync2' });
```

以下是上述代码的输出：

![图 9.7：移除监听器后发射事件的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_07.jpg)

###### 图 9.7：移除监听器后发射事件的输出

因为我们刚刚移除了对`event-with-type`的监听器，当我们再次发射事件时，它将不会被调用。

在这个练习中，我们构建了一个非常简单的事件发射器，并测试了添加和移除监听器。现在，我们知道如何使用事件将消息从一个组件传递到另一个组件。接下来，我们将深入研究事件监听器方法，并看看通过调用它们我们可以实现什么。

### 事件发射器方法

在上一个练习中，我们讨论了一些可以调用的方法来发射事件和附加监听器。我们还使用了`removeListener`来移除我们附加的监听器。现在，我们将讨论我们可以在事件监听器上调用的各种方法。这将帮助我们更轻松地管理事件发射器。

### 移除监听器

有些情况下，我们希望从我们的发射器中移除监听器。就像我们在上一个练习中所做的那样，我们可以通过调用`removeListener`来简单地移除一个监听器：

```js
emitter.removeListener('event-with-type', handleEvent);
```

当我们调用`removeListener`方法时，我们必须为其提供事件名称和函数引用。当我们调用该方法时，无论事件监听器是否已设置都无关紧要；如果监听器一开始就没有设置，什么也不会发生。如果设置了，它将遍历我们的事件发射器中监听器的数组，并移除该监听器的第一次出现，就像这样：

```js
const emitter = new EventEmitter();
function handleEvent(event) {
    console.log('i am handling event type: ', event.type);
}
emitter.on('event-with-type', handleEvent);
emitter.on('event-with-type', handleEvent);
emitter.on('event-with-type', handleEvent);
emitter.emit('event-with-type', { type: 'sync' });
emitter.removeListener('event-with-type', handleEvent);
```

在这段代码中，我们三次附加了相同的监听器。在事件发射器中，当我们附加事件监听器时，允许这样做，它只是简单地追加到该事件的事件监听器数组中。当我们在`removeListener`之前发射我们的事件时，我们将看到我们的监听器被调用三次：

![图 9.8：在移除监听器之前使用 emit 事件调用三次监听器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_08.jpg)

###### 图 9.8：在移除监听器之前使用 emit 事件调用三次监听器

在这种情况下，因为我们有三个相同的监听器附加到我们的事件上，当我们调用`removeListener`时，它只会移除我们的`listener`数组中的第一个监听器。当我们再次发射相同的事件时，我们会看到它只运行两次：

![图 9.9：使用 removeListener 后，第一个监听器被移除](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_09.jpg)

###### 图 9.9：使用 removeListener 后，第一个监听器被移除

### 移除所有监听器

我们可以从我们的事件发射器中删除特定的侦听器。但通常，当我们在发射器上处理多个侦听器时，有时我们希望删除所有侦听器。`EventEmitter`类为我们提供了一个方法，我们可以使用它来删除特定事件的所有侦听器。考虑我们之前使用的相同示例：

```js
const emitter = new EventEmitter();
function handleEvent(event) {
    console.log('i am handling event type: ', event.type);
}
emitter.on('event-with-type', handleEvent);
emitter.on('event-with-type', handleEvent);
emitter.on('event-with-type', handleEvent);
```

如果我们想要删除`event-with-type`事件的所有侦听器，我们将不得不多次调用`removeListener`。有时，当我们确定所有事件侦听器都是由我们添加的，没有其他组件或模块时，我们可以使用单个方法调用来删除该事件的所有侦听器：

```js
emitter.removeAllListeners('event-with-type');
```

当我们调用`removeAllListeners`时，我们只需要提供事件名称。这将删除附加到事件的所有侦听器。调用后，事件将没有处理程序。确保您不要删除由另一个组件附加的侦听器，如果您使用此功能：

```js
emitter.emit('event-with-type', { type: 'sync' });
```

当我们在调用`removeAllListeners`后再次发出相同的事件时，我们将看到我们的程序不会输出任何内容：

![图 9.10：使用`removeAllListeners`将不会输出任何内容](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_10.jpg)

###### 图 9.10：使用`removeAllListeners`将不会输出任何内容

### 附加一次性侦听器

有时，我们希望我们的组件只接收特定事件一次。我们可以通过使用`removeListener`来确保在调用后删除侦听器：

```js
const EventEmitter = require('events');
const emitter = new EventEmitter();
function handleEvent(event) {
    console.log('i am handling event type once : ', event.type);
    emitter.removeListener('event-with-type', handleEvent);
}
emitter.on('event-with-type', handleEvent);
emitter.emit('event-with-type', { type: 'sync' });
emitter.emit('event-with-type', { type: 'sync' });
emitter.emit('event-with-type', { type: 'sync' });
```

在这里，我们可以看到，在我们的`handleEvent`侦听器中，执行后我们还删除了侦听器。这样，我们可以确保我们的事件侦听器只会被调用一次。当我们运行上述代码时，我们将看到以下输出：

![图 9.11：使用`handleEvent`侦听器后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_11.jpg)

###### 图 9.11：使用`handleEvent`侦听器后的输出

这做到了我们想要的，但还不够好。它要求我们在事件侦听器中保留发射器的引用。此外，它还不够健壮，因为我们无法将侦听器逻辑分离到不同的文件中。`EventEmitter`类为我们提供了一个非常简单的方法，可以用来附加一次性侦听器：

```js
...
emitter.once('event-with-type', handleEvent);
emitter.emit('event-with-type', { type: 'sync' });
emitter.emit('event-with-type', { type: 'sync' });
emitter.emit('event-with-type', { type: 'sync' });
```

在这里，当我们附加事件侦听器时，我们使用了`.once`方法。这告诉我们的发射器，我们传递的函数应该只被调用一次，并且在被调用后将从事件侦听器列表中删除。当我们运行它时，它将为我们提供与以前相同的输出：

图 9.12：使用`.once`方法获取一次性侦听器

](Images/C14587_09_12.jpg)

###### 图 9.12：使用`.once`方法获取一次性侦听器

这样，我们就不需要在侦听器中保留对事件发射器的引用。这使我们的代码更灵活，更容易模块化。

### 从事件发射器中读取

到目前为止，我们一直在设置和删除事件发射器的侦听器。`EventEmitter`类还为我们提供了几种读取方法，我们可以从中获取有关事件发射器的更多信息。考虑以下示例：

```js
const EventEmitter = require('events');
const emitter = new EventEmitter();
emitter.on('event 1', () => {});
emitter.on('event 2', () => {});
emitter.on('event 2', () => {});
emitter.on('event 3', () => {});
```

在这里，我们向我们的发射器添加了三种类型的事件侦听器。对于`event 2`，我们为其设置了两个侦听器。要获取我们的发射器中特定事件的事件侦听器数量，我们可以调用`listenerCount`。对于上面的示例，如果我们想要知道附加到`event 1`的事件侦听器的数量，我们可以执行以下命令：

```js
emitter.listenerCount('event 1');
```

以下是上述代码的输出：

图 9.13：输出显示附加到事件 1 的事件数量

](Images/C14587_09_13.jpg)

###### 图 9.13：输出显示附加到事件 1 的事件数量

同样，我们可以通过执行以下命令来检查附加到`event 2`的事件侦听器的数量：

```js
emitter.listenerCount('event 2');
```

以下是上述代码的输出：

![图 9.14：输出显示附加到事件 2 的事件数量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_14.jpg)

###### 图 9.14：输出显示附加到事件 2 的事件数量

有时我们想要知道已经附加到事件的事件监听器列表，以便我们可以确定某个处理程序是否已经附加，就像这样：

```js
function anotherHandler() {}
emitter.on('event 4', () => {});
emitter.on('event 4', anotherHandler);
```

在这里，我们附加了一个匿名函数到`event 4`，并使用一个命名函数附加了另一个监听器。如果我们想知道`anotherHandler`是否已经附加到`event 4`，我们可以附加一个监听器列表到该事件。`EventEmitter`类为我们提供了一个非常简单的方法来调用这个：

```js
const event4Listeners = emitter.listeners('event 4');
```

以下是前面代码的输出：

![图 9.15：使用 EventEmitter 类获取附加到事件的监听器列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_15.jpg)

###### 图 9.15：使用 EventEmitter 类获取附加到事件的监听器列表

在这里，我们可以看到我们已经附加到我们的发射器的两个监听器：一个是我们的匿名函数，另一个是我们的命名函数`anotherHandler`。要检查我们的处理程序是否已经附加到发射器，我们可以检查`event4Listeners`数组中是否有`anotherHandler`：

```js
event4Listeners.includes(anotherHandler);
```

以下是前面代码的输出：

![图 9.16：检查处理程序是否附加到发射器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_16.jpg)

###### 图 9.16：检查处理程序是否附加到发射器

通过使用这个方法和数组包含一个方法，我们可以确定一个函数是否已经附加到我们的事件。

### 获取已注册监听器的事件列表

有时我们需要获取已注册监听器的事件列表。这可以用于确定我们是否已经为事件附加了监听器，或者查看事件名称是否已经被使用。继续前面的例子，我们可以通过调用`EventEmitter`类中的另一个内部方法来获取这些信息：

```js
emitter.eventNames();
```

以下是前面代码的输出：

![图 9.17：使用 EventEmitter 类获取事件名称的信息](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_17.jpg)

###### 图 9.17：使用 EventEmitter 类获取事件名称的信息

在这里，我们可以看到我们的事件发射器已经附加到四种不同的事件类型的监听器；即事件 1-4。

### 最大监听器

默认情况下，每个事件发射器只能为任何单个事件注册最多 10 个监听器。当我们附加超过最大数量时，我们将收到类似这样的警告：

![图 9.18：为单个事件附加超过 10 个监听器时的警告](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_18.jpg)

###### 图 9.18：为单个事件附加超过 10 个监听器时的警告

这是为了确保我们不会泄漏内存而设置的预防措施，但也有时我们需要为一个事件设置超过 10 个监听器。如果我们确定了，我们可以通过调用`setMaxListeners`来更新默认的最大值：

```js
emitter.setMaxListeners(20)
```

在这里，我们将最大监听器默认设置为`20`。我们也可以将其设置为`0`或无穷大，以允许无限数量的监听器。

### 在事件之前添加监听器

当我们添加监听器时，它们被附加到监听器数组的末尾。当事件被发出时，发射器将按照它们被分配的顺序调用每个分配的监听器。在某些情况下，我们需要我们的监听器首先被调用，我们可以使用事件发射器提供的内置方法来实现这一点：

```js
const EventEmitter = require('events');
const emitter = new EventEmitter();
function handleEventSecond() {
    console.log('I should be called second');
}
function handleEventFirst() {
    console.log('I should be called first');
}
emitter.on('event', handleEventSecond);
emitter.on('event', handleEventFirst);
emitter.emit('event');
```

在这里，我们在`handleEventFirst`之前附加了`handleEventSecond`。当我们发出事件时，我们将看到以下输出：

![图 9.19：在第一个事件之前附加第二个事件后发出事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_19.jpg)

###### 图 9.19：在第一个事件之前附加第二个事件后发出事件

因为事件监听器是按照它们附加的顺序调用的，我们可以看到当我们发出事件时，`handleEventSecond`首先被调用，然后是`handleEventFirst`。如果我们希望`handleEventFirst`在使用`emitter.on()`附加它们的顺序不变的情况下首先被调用，我们可以调用`prependListener`：

```js
...
emitter.on('event', handleEventSecond);
emitter.prependListener('event', handleEventFirst);
emitter.emit('event');
```

前面的代码将产生以下输出：

![图 9.20：使用 prependListener 对事件进行排序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_20.jpg)

###### 图 9.20：使用 prependListener 对事件进行排序

这可以帮助我们保持监听器的顺序，并确保优先级较高的监听器始终首先被调用。接下来我们将讨论监听器中的并发性。

### 监听器中的并发性

在之前的章节中，我们提到了如何将多个监听器附加到我们的发射器上，以及在事件被触发时这些监听器是如何工作的。之后，我们还谈到了如何在事件被触发时添加监听器，使得它们首先被调用。我们可能想要添加监听器的原因是，当监听器被调用时，它们是同步一个接一个被调用的。考虑以下例子：

```js
const EventEmitter = require('events');
const emitter = new EventEmitter();
function slowHandle() {
    console.log('doing calculation');
    for(let i = 0; i < 10000000; i++) {
        Math.random();
    }
}
function quickHandle() {
    console.log('i am called finally.');
}
emitter.on('event', slowHandle);
emitter.on('event', quickHandle);
emitter.emit('event');
```

在这里，我们有两个附加到`event`类型的监听器。当事件被触发时，它将首先调用`slowHandle`，然后调用`quickHandle`。在`slowHandle`中，我们有一个非常大的循环，模拟一个在事件监听器中可以执行的非常耗时的操作。当我们运行前面的代码时，我们首先会看到`doing calculation`被打印出来，然后会有一个很长的等待，直到`I am called finally`被调用。我们可以看到，当发射器调用事件监听器时，它是同步进行的。这可能会给我们带来问题，因为在大多数情况下，我们不希望等待一个监听器完成后再触发另一个监听器。不过，有一种简单的解决方法：我们可以用`setImmediate`函数包装我们的耗时逻辑。`setImmediate`函数将我们的逻辑包装成一个立即执行的异步块，这意味着耗时的循环是非阻塞的。我们将在本书的后面介绍`setImmediate`函数：

```js
...
function slowHandle() {
    console.log('doing calculation');
    setImmediate(() => {
        for(let i = 0; i < 10000000; i++) {
            Math.random();
        }
    });
}
```

当我们用`setImmediate()`包装我们的耗时逻辑时，代码几乎同时输出**doing calculation**和**I am called finally**。通过用`setImmediate`包装所有逻辑，我们可以确保它是异步调用的。

### 构建自定义事件发射器

有些情况下，我们希望将事件发射功能构建到我们自己的自定义类中。我们可以通过使用**JavaScript ES6**继承来实现这一点。这允许我们创建一个自定义类，同时扩展事件发射器的所有功能。例如，假设我们正在构建一个火警类：

```js
class FireAlarm {
    constructor(modelNumber, type, cost) {
        this.modelNumber = modelNumber;
        this.type = type;
        this.cost = cost;
        this.batteryLevel = 10;
    }
    getDetail() {
        return '${this.modelNumber}:[${this.type}] - $${this.cost}';
    }
    test() {
        if (this.batteryLevel > 0) {
            this.batteryLevel -= 0.1;
            return true;
        }
        return false;
    }
}
```

在这里，我们有一个`FireAlarm`类，它有一个存储有关这个火警的信息的构造函数。它还有一些自定义方法来测试警报，比如检查电池电量，以及一个`getDetail`方法来返回表示警报信息的字符串。在定义了这个类之后，我们可以像这样使用`FireAlarm`类：

```js
const livingRoomAlarm = new FireAlarm('AX-00101', 'BATT', '20');
console.log(livingRoomAlarm.getDetail());
```

以下是前面代码的输出：

![图 9.21：定义火警类](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_21.jpg)

###### 图 9.21：定义火警类

现在，我们想在刚刚创建的火警上设置事件。我们可以通过创建一个通用事件发射器并将其存储在我们的`FireAlarm`对象中来实现这一点：

```js
class FireAlarm {
    constructor(modelNumber, type, cost) {
        this.modelNumber = modelNumber;
        this.type = type;
        this.cost = cost;
        this.batteryLevel = 10;
        this.emitter = new EventEmitter();
    }
    ...
}
```

当我们想要监视警报上的事件时，我们必须这样做：

```js
livingRoomAlarm.emitter.on('low-battery', () => {
    console.log('battery low');
});
```

虽然这是完全可以的，并且对我们的用例有效，但这显然不是最健壮的解决方案。因为我们的火警是发出事件的一方，我们希望像这样：

```js
livingRoomAlarm.on('low-battery', () => {
    console.log('battery low');
});
```

通过直接在火警上使用`.on`，我们告诉未来的开发人员，将要在这上面工作，我们的火警也是一个事件发射器。但是现在，我们的类定义不允许使用。我们可以通过使用类继承来解决这个问题，在那里我们可以使我们的`FireAlarm`类扩展`EventEmitter`类。通过这样做，它将拥有`EventEmitter`的所有功能。我们可以修改我们的类如下：

```js
class FireAlarm extends EventEmitter {
    constructor(modelNumber, type, cost) {
        this.modelNumber = modelNumber;
        this.type = type;
        this.cost = cost;
        this.batteryLevel = 10;
    }
    ...
}
```

使用`extends`关键字后跟`EventEmitter`，我们告诉 JavaScript`FireAlarm`类是`EventEmitter`的子类。因此，它将继承父类的所有属性和方法。但这本身并不能解决所有问题。当我们运行更新后的`FireAlarm`代码时，我们会看到抛出一个错误：

![图 9.22：当我们运行更新后的 FireAlarm 代码时会抛出错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_22.jpg)

###### 图 9.22：当我们运行更新后的 FireAlarm 代码时会抛出错误

这是因为我们使用了一个非常定制的类，具有自定义的构造函数，并访问`this`（这用作对当前对象的引用）。在此之前，我们需要确保在此之前调用父构造函数。为了使此错误消失，我们只需在自己的构造函数中添加对父构造函数的调用：

```js
class FireAlarm extends EventEmitter {
    constructor(modelNumber, type, cost) {
        super();
        this.modelNumber = modelNumber;
        this.type = type;
        this.cost = cost;
        this.batteryLevel = 10;
    }
    ...
}
```

现在，让我们测试我们自己的自定义`EventEmitter`：

```js
livingRoomAlarm.on('low-battery', () => {
    console.log('battery low');
});
livingRoomAlarm.emit('low-battery');
```

以下是上述代码的输出：

![图 9.23：'low-battery'事件的事件监听器被正确触发](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_23.jpg)

###### 图 9.23：'low-battery'事件的事件监听器被正确触发

在这里，我们可以看到我们将`livingRoomAlarm`视为常规的`EventEmitter`，当我们发出*low-battery*事件时，我们看到该事件的事件监听器被正确触发。在下一个练习中，我们将使用我们对`EventEmitters`的所有了解制作一个非常简单的聊天室应用程序。

### 练习 68：构建聊天室应用程序

之前，我们讨论了如何在我们的事件发射器上附加事件监听器并发出事件。在这个练习中，我们将构建一个简单的聊天室管理软件，该软件使用事件进行通信。我们将创建多个组件，并查看如何使它们相互通信。

#### 注意：

此练习的代码文件可以在[`github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson09/Exercise68`](https://github.com/TrainingByPackt/Professional-JavaScript/tree/master/Lesson09/Exercise68)找到。

执行以下步骤完成此练习：

1.  创建一个`User`类：

```js
class User {
    constructor(name) {
        this.name = name;
        this.messages = [];
        this.rooms = {};
    }
    joinRoom(room) {
        room.on('newMessage', (message) => {
            this.messages.push(message);
        });
        this.rooms[room.name] = room;
    }
    getMesssages(roomName) {
        return this.messages.filter((message) => {
            return message.roomName === roomName;
        })
    }
    printMessages(roomName) {
        this.getMesssages(roomName).forEach((message) => {
            console.log(`>> [${message.roomName}]:(${message.from}): ${message.message}`);
        });
    }
    sendMessage(roomName, message) {
        this.rooms[roomName].emit('newMessage', {
            message,
            roomName,
            from: this.name
        });
    }
}
```

在这里，我们为用户创建了一个`User`类。它有一个`joinRoom`方法，我们可以调用该方法将用户加入房间。它还有一个`sendMessage`方法，该方法将消息发送给房间中的所有人。当我们加入一个房间时，我们还会监听来自该房间的所有新消息事件，并在接收到消息时追加消息。

1.  创建一个扩展`EventEmitter`类的`Room`类：

```js
class Room extends EventEmitter {
    constructor(name) {
        super();
        this.name = name;
    }
}
```

在这里，我们通过扩展现有的`EventEmitter`类创建了一个新的`Room`类。我们这样做的原因是我们希望在我们的`room`对象上拥有自定义属性，并且这样可以增加代码的灵活性。

1.  创建两个用户，`bob`和`kevin`：

```js
const bob = new User('Bob');
const kevin = new User('Kevin');
```

1.  使用我们的`Room`类创建一个房间：

```js
const lobby = new Room('Lobby');
```

1.  将`bob`和`kevin`加入`lobby`：

```js
bob.joinRoom(lobby);
kevin.joinRoom(lobby);
```

1.  从`bob`发送几条消息：

```js
bob.sendMessage('Lobby', 'Hi all');
bob.sendMessage('Lobby', 'I am new to this room.');
```

1.  打印`bob`的消息日志：

```js
bob.printMessages('Lobby');
```

以下是上述代码的输出：

![图 9.24：打印 bob 的消息日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_24.jpg)

###### 图 9.24：打印 bob 的消息日志

在这里，您可以看到我们所有的消息都正确添加到了`bob`的日志中。接下来，我们将检查`kevin`的日志。

1.  打印`kevin`的消息日志：

```js
kevin.printMessage('Lobby');
```

以下是上述代码的输出：

![图 9.25：打印 kevin 的消息日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_25.jpg)

###### 图 9.25：打印 kevin 的消息日志

即使我们从未明确对`kevin`做过任何事情，他也会收到所有消息，因为他正在监听房间中的新消息事件。

1.  从`kevin`和`bob`发送消息：

```js
kevin.sendMessage('Lobby', 'Hi bob');
bob.sendMessage('Lobby', 'Hey kevin');
kevin.sendMessage('Lobby', 'Welcome!');
```

1.  检查`kevin`的消息日志：

```js
kevin.printMessages('Lobby');
```

以下是上述代码的输出：

![图 9.26：检查 kevin 的消息日志](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_26.jpg)

###### 图 9.26：检查 kevin 的消息日志

在这里，我们可以看到所有我们的消息都正确地添加到我们的`user`对象中。因为我们使用事件发射器，所以我们避免了在我们的接收者周围传递引用。此外，因为我们在我们的房间上发出了消息事件，而我们的用户只是监听该事件，所以我们不需要手动遍历房间中的所有用户并传递消息。

1.  让我们修改`joinRoom`和`constructor`，以便稍后可以移除监听器：

```js
class User {
    constructor(name) {
        this.name = name;
        this.messages = [];
        this.rooms = {};
        this.messageListener = (message) => {
            this.messages.push(message);
        }
    }
    joinRoom(room) {
        this.messageListener = (message) => {
            this.messages.push(message);
        }
        room.on('newMessage', this.messageListener);
        this.rooms[room.name] = room;
    }
    ...
}
```

当我们移除监听器时，我们需要传递该监听器函数的引用，因此，我们需要将该引用存储在对象中，以便稍后可以使用它来移除我们的监听器。

1.  添加`leaveRoom`：

```js
class User {
    ...
    leaveRoom(roomName) {
        this.rooms[roomName].removeListener('newMessage', this.messageListener);
delete this.rooms[roomName];
    }
}
```

在这里，我们正在使用我们在构造函数中设置的函数引用，并将其传递给我们房间的`removeListener`。我们还从对象中移除了引用，以便稍后可以释放内存。

1.  从`room`中移除`bob`：

```js
bob.leaveRoom('Lobby');
```

1.  从`kevin`发送一条消息：

```js
kevin.sendMessage('Lobby', 'I got a good news for you guys');
```

1.  检查`bob`的消息列表：

```js
bob.printMessages('Lobby');
```

以下是上述代码的输出：

![图 9.27：再次检查鲍勃的消息列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_27.jpg)

###### 图 9.27：检查鲍勃的消息列表

因为`bob`离开了房间，并且我们移除了消息监听器，所以当发出新消息事件时，`newMessage`事件处理程序不会再被调用。

1.  检查`kevin`的消息列表：

```js
kevin.printMessages('Lobby');
```

以下是上述代码的输出：

![图 9.28：再次检查 kevin 的消息列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_28.jpg)

###### 图 9.28：再次检查 kevin 的消息列表

当我们检查`kevin`的消息列表时，我们应该仍然能够看到他仍然从房间中收到新消息。如果使用传统方法来完成这项工作，我们将需要编写更多的代码来完成相同的事情，这将非常容易出错。

在这个练习中，我们使用 Node.js 构建了一个带有事件的模拟聊天应用程序。我们可以看到在 Node.js 中传递事件是多么容易，以及我们如何正确使用它。事件驱动编程并不适用于每个应用程序，但是当我们需要将多个组件连接在一起时，使用事件来实现这种逻辑要容易得多。上述代码仍然可以改进-我们可以在用户离开房间时向房间添加通知，并且我们可以在添加和移除房间时添加检查，以确保我们不会添加重复的房间，并确保我们只移除我们所在的房间。请随意自行扩展此功能。

在本章中，我们讨论了如何使用事件来管理应用程序中组件之间的通信。在下一个活动中，我们将构建一个基于事件驱动的模块。

### 活动 13：构建一个基于事件驱动的模块

假设您正在为一家构建烟雾探测器模拟器的软件公司工作。您需要构建一个烟雾探测器模拟器，当探测器的电池电量低于一定水平时会引发警报。以下是要求：

+   探测器需要发出`警报事件`。

+   当电池低于 0.5 单位时，烟雾探测器需要发出*低电量*事件。

+   每个烟雾探测器在初始创建时都有 10 个单位的电池电量。

+   烟雾探测器上的测试函数如果电池电量高于 0 则返回 true，如果低于 0 则返回 false。每次运行测试函数时，电池电量将减少 0.1 个单位。

+   您需要修改提供的`House`类以添加`addDetector`和`demoveDetector`方法。

+   `addDetector`将接受一个探测器对象，并在打印出*低电量*和*警报事件*之前，为警报事件附加一个监听器。

+   `removeDetector`方法将接受一个**探测器**对象并移除监听器。

完成此活动，执行以下步骤：

1.  打开`event.js`文件并找到现有的代码。然后，修改并添加你自己的更改。

1.  导入`events`模块。

1.  创建`SmokeDetector`类，该类扩展`EventEmitter`并将`batteryLevel`设置为`10`。

1.  在`SmokeDetector`类内创建一个`test`方法来发出*低电量*消息。

1.  创建`House`类，它将存储我们警报的实例。

1.  在`House`类中创建一个`addDetector`方法，它将附加事件监听器。

1.  创建一个`removeDetector`方法，它将帮助我们移除之前附加的*警报事件*监听器。

1.  创建一个名为`myHouse`的`House`实例。

1.  创建一个名为`detector`的`SmokeDetector`实例。

1.  将探测器添加到`myHouse`中。

1.  创建一个循环来调用测试函数 96 次。

1.  在`detector`对象上发出警报。

1.  从`myHouse`对象中移除探测器。

1.  在探测器上测试发出警报。

#### 注意

此活动的解决方案可以在第 617 页找到。

在这个活动中，我们学习了如何使用事件驱动编程来建模烟雾探测器。通过使用这种方法，我们消除了在我们的`House`对象中存储多个实例的需要，并避免使用大量代码来进行它们的交互。

在本节中，我们介绍了如何充分利用事件系统来帮助我们管理应用程序中的复杂通信。在下一节中，我们将介绍一些处理事件发射器的最佳实践。

### 事件驱动编程最佳实践

在前一章中，我们提到了使用事件发射器和事件发射器继承创建事件驱动组件的方法。但通常，您的代码需要的不仅仅是能够正确工作。拥有更好管理的代码结构不仅可以使我们的代码看起来不那么凌乱，还可以帮助我们避免将来一些可避免的错误。在本节中，我们将介绍在处理代码中的事件时的一些最佳实践。

回顾一下我们在本章开头所讨论的内容，我们可以使用`EventEmitter`对象传递事件：

```js
const EventEmitter = require('events');
const emitter = new EventEmitter();
emitter.emit('event');
```

当我们想要使用我们创建的事件发射器时，我们需要有它的引用，这样我们才能在以后想要发出事件时附加监听器并调用发射器的`emit`函数。这可能会导致我们的源代码非常庞大，这将使未来的维护非常困难：

```js
const EventEmitter = require('events');
const userEmitter = new EventEmitter();
const registrationEmitter = new EventEmitter();
const votingEmitter = new EventEmitter();
const postEmitter = new EventEmitter();
const commentEmitter = new EventEmitter();
userEmitter.on('update', (diff) => {
    userProfile.update(diff);
});
registrationEmitter.on('user registered:activated', (user) => {
    database.add(user, true);
});
registrationEmitter.on('user registered: not activated', (user) => {
    database.add(user, false);
});
votingEmitter.on('upvote', () => {
    userProfile.addVote();
});
votingEmitter.on('downvote', () => {
    userProfile.removeVote();
});
postEmitter.on('new post', (post) => {
    database.addPost(post);
});
postEmitter.on('edit post', (post) => {
    database.upsertPost(post);
});
commentEmitter.on('new comment', (comment) => {
    database.addComment(comment.post, comment);
});
```

为了能够使用我们的发射器，我们需要确保我们的发射器在当前范围内是可访问的。做到这一点的一种方法是创建一个文件来保存所有我们的发射器和附加事件监听器的逻辑。虽然这样大大简化了我们的代码，但我们将创建非常庞大的源代码，这将使未来的开发人员困惑，甚至可能连我们自己也会困惑。为了使我们的代码更模块化，我们可以开始将所有的监听器函数放入它们各自的文件中。考虑以下庞大的源代码：

```js
// index.js
const EventEmitter = require('events');
const userEmitter = new EventEmitter();
const registrationEmitter = new EventEmitter();
const votingEmitter = new EventEmitter();
const postEmitter = new EventEmitter();
const commentEmitter = new EventEmitter();
// Listeners
const updateListener = () => {};
const activationListener = () => {};
const noActivationListener = () => {};
const upvoteListener = () => {};
const downVoteListener = () => {};
const newPostListener = () => {};
const editPostListener = () => {};
const newCommentListener = () => {};
userEmitter.on('update', updateListener);
registrationEmitter.on('user registered:activated', activationListener);
registrationEmitter.on('user registered: not activated', noActivationListener);
votingEmitter.on('upvote', upvoteListener);
votingEmitter.on('downvote', downVoteListener);
postEmitter.on('new post', newPostListener);
postEmitter.on('edit post', editPostListener);
commentEmitter.on('new comment', newCommentListener);
```

仅仅通过这样做，我们已经大大减少了我们代码的文件大小。但我们可以做得更多。保持我们代码有组织的一种方法是将所有的发射器放在一个文件中，然后在需要时导入它。我们可以通过创建一个名为`emitters.js`的文件，并将所有的发射器存储在该文件中来实现这一点：

```js
// emitters.js
const EventEmitter = require('events');
const userEmitter = new EventEmitter();
const registrationEmitter = new EventEmitter();
const votingEmitter = new EventEmitter();
const postEmitter = new EventEmitter();
const commentEmitter = new EventEmitter();
module.exports = {
    userEmitter,
    registrationEmitter,
    votingEmitter,
    postEmitter,
    commentEmitter
};
```

我们在这里所做的是在一个文件中创建所有的发射器，并将该`emitter`文件设置为导出模块。通过这样做，我们可以将所有的发射器放在一个地方，然后当我们使用发射器时，我们只需导入该文件。这将改变我们的代码如下：

```js
// index.js
// Emitters
const {
    userEmitter,
    registrationEmitter,
    votingEmitter,
    postEmitter,
    commentEmitter
} = require('./emitters.js');
... rest of index.js
```

现在，当我们导入`emitter.js`时，我们可以使用对象解构来只选择我们想要的发射器。我们可以在一个文件中拥有多个发射器，然后在需要时选择我们想要的发射器。当我们想要在`userEmitter`上发出事件时，我们只需将发射器导入我们的代码并发送该事件即可：

```js
const { userEmitter } = require('./emitters.js');
function userAPIHandler(request, response) {
    const payload = request.payload;
    const event = {
        diff: payload.diff
    };
    userEmitter.emit('update', event);
}
```

我们可以看到，每当我们想要使用`userEmitter`时，我们只需导入我们的`emitter`文件。当我们想要附加监听器时，也适用这一点：

```js
const { userEmitter } = require('./emitters.js');
userEmitter.on('update', (diff) => {
    database.update(diff);
})
```

当我们将我们的发射器分成不同的文件时，我们不仅使我们的代码更小，而且使其更模块化。通过将我们的发射器拉入一个单独的文件，如果我们将来想要访问我们的发射器，那么我们可以很容易地重用该文件。通过这样做，我们不需要在函数中传递我们的发射器，从而确保我们的函数声明不会混乱。

## Node.js 内置模块

在前一节中，我们广泛讨论了`events`模块，并学习了如何使用事件来实现应用程序内的简单通信。`events`模块是 Node.js 提供的内置模块，这意味着我们不需要使用`npm`来安装它。在这个模块中，我们将讨论如何使用`fs`、`path`和`util`模块。

### path

`path`模块是一个内置模块，提供了一些工具，可以帮助我们处理文件路径和文件名。

**path.join(…paths)**

`Path.join()`是一个非常有用的函数，当我们在应用程序中处理目录和文件时。它允许我们将路径连接在一起，并输出一个路径字符串，我们可以在**fs**模块中使用。要使用`join`路径，我们可以调用`join`方法，并为其提供一组路径。让我们看下面的例子：

```js
const currentDir = '/usr/home/me/Documents/project';
const dataDir = './data';
const assetDir = './assets';
```

如果我们想要访问我们当前目录中的数据目录，我们可以使用`path.join`函数将不同的路径组合成一个字符串：

```js
const absoluteDataDir = path.join(currentDir, dataDir);
```

以下是前面代码的输出：

![图 9.29：使用 path.join 函数组合不同的路径](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_29.jpg)

###### 图 9.29：使用 path.join 函数组合不同的路径

它还可以处理`..`和`.`，如果你熟悉 POSIX 系统如何表示当前目录和父目录。`..`表示父目录，而`.`表示当前目录。例如，以下代码可以给出我们当前目录的父目录的路径：

```js
const parentOfProject = path.join(currentDir, '..');
```

以下是前面代码的输出：

![图 9.30：显示我们当前目录的父目录](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_30.jpg)

###### 图 9.30：显示我们当前目录的父目录

**path.parse(path)**

当我们想要获取有关文件路径的信息时，我们可以使用`path.parse()`函数来获取其根目录、基本目录、文件名和扩展名。让我们看下面的例子：

```js
const myData = '/usr/home/me/Documents/project/data/data.json';
```

如果我们想要解析这个文件路径，我们可以使用`path.parse`调用`myData`字符串来获取不同的路径元素：

```js
path.parse(myData);
```

这将生成以下输出：

![图 9.31：使用 path.parse 函数解析的文件路径](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_31.jpg)

###### 图 9.31：使用 path.parse 函数解析的文件路径

在这里，我们可以看到我们的文件路径包括一个文件名，基本名称为`data.json`。扩展名是`.json`，文件名是`data`。它还解析出文件所在的目录。

**path.format(path)**

在前面的`parse`函数中，我们成功地将文件路径解析为其各自的组件。我们可以使用`path.format`将这些信息组合成一个单一的字符串路径。让我们来看一下：

```js
path.format({
    dir: '/usr/home/me/Pictures',
    name: 'me',
    ext: '.jpeg'
});
```

以下是前面代码的输出：

![图 9.32：使用 path.format 将信息组合成单个字符串路径](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_32.jpg)

###### 图 9.32：使用 path.format 将信息组合成单个字符串路径

这给我们提供了从我们提供给它的组件中生成的文件路径。

### fs

**fs**模块是一个内置模块，为您提供 API，以便您可以与主机文件系统进行交互。当我们需要在应用程序中处理文件时，它非常有用。在本节中，我们将讨论如何在我们的应用程序中使用**fs**模块与`async`和`await`。稍后，我们将介绍最近添加的`fs.promises`API，它提供相同的功能，但返回一个 promise 而不是使用回调。

#### 注意

在这一部分，我们将使用 POSIX 系统。如果你使用的是 Windows 系统，请确保将文件路径更新为 Windows 的等价物。要将 fs 模块导入到你的代码中，执行以下命令：

```js
const fs = require('fs');
```

**fs.createReadStream(path, options)**

当我们在 Node.js 中处理大文件时，建议始终使用`stream`。要创建一个读取流，我们可以调用`fs.createReadStream`方法。它将返回一个流对象，我们可以将其附加到事件处理程序，以便它们获取文件的内容：

```js
const stream = fs.createReadStream('file.txt', 'utf-8');
```

**fs.createWriteStream(path, options)**

这与`createReadStream`类似，但是创建了一个可写流，我们可以用它来流式传输内容：

```js
const stream = fs.createWriteStream('output', 'utf-8');
```

**fs.stat(path, callback)**

当我们需要关于我们正在访问的文件的详细信息时，`fs.stat`方法非常有用。我们还看到许多开发人员在调用、打开、读取或写入数据之前使用`fs.stat`来检查文件的存在。虽然使用`stat`检查文件的存在不会创建任何新问题，但不建议这样做。我们应该只使用从我们使用的函数返回的错误；这将消除任何额外的逻辑层，并可以减少 API 调用的数量。

考虑以下例子：

```js
const fs = require('fs');
fs.stat('index.js', (error, stat) => {
    console.log(stat);
});
```

这将给我们一个类似以下的输出：

![图 9.33：使用 fs.stat 方法后的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_33.jpg)

###### 图 9.33：使用 fs.stat 方法后的输出

**fs.readFile(path, options, callback)**

这是大多数人熟悉的函数。当提供文件路径时，该方法将尝试以异步方式读取文件的整个内容。它将以异步方式执行，并且回调将被调用以获取文件的整个内容。当文件不存在时，回调将被调用以获取错误。

考虑以下例子：

```js
const fs = require('fs');
fs.readFile('index.js', (error, data) => {
    console.log(data);
});
```

这将给我们以下输出：

![图 9.34：使用 fs.readFile 函数读取文件的整个内容](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_34.jpg)

###### 图 9.34：使用 fs.readFile 函数读取文件的整个内容

这没有输出我们想要的结果。这是因为我们没有在选项中提供编码；要将内容读入字符串，我们需要提供编码选项。这将改变我们的代码为以下内容：

```js
fs.readFile('index.js', 'utf-8', (error, data) => {
    console.log(data);
});
```

现在，当我们运行上述代码时，它会给我们以下输出：

![图 9.35：使用 fs.readFile 函数读取文件的整个内容后编码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_35.jpg)

###### 图 9.35：使用 fs.readFile 函数读取文件的整个内容后编码

我们刚刚做了一个输出自身的程序。

**fs.readFileSync(path, options)**

这个函数和`readFile`方法做的事情一样，但是以同步的方式执行`read`函数，这意味着它会阻塞执行。在程序启动期间，建议 - 并且期望 - 只调用一次。当需要多次调用时，不建议使用同步函数。

**fs.writeFile(file, data, options, callback)**

`writeFile`函数将数据写入我们指定的文件。它还将替换现有的文件，除非你在选项中传递一个附加的`flag`。

**fs.writeFileSync()**

就像`readFileSync`一样，它和它的非同步对应物做的事情一样。它们之间的区别在于这个是同步执行操作。

### 练习 69：Fs 模块的基本用法

在这个练习中，我们将使用`fs`模块来读取和写入应用程序中的文件。我们将使用我们在前一节中介绍的方法，并将它们与回调一起使用。然后，我们将对它们进行`promisify`，这样我们就可以用`async`和`await`来使用它们。

执行以下步骤完成这个练习：

1.  创建一个名为`test.txt`的新文件：

```js
fs.writeFile('test.txt', 'Hello world', (error) => {
    if (error) {
        console.error(error);
        return;
    }
    console.log('Write complete');
});
```

如果你做对了，你会看到以下输出：

![图 9.36：创建新的 test.txt 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_36.jpg)

###### 图 9.36：创建新的 test.txt 文件

你应该能够在与源代码相同的目录中看到新文件：

![图 9.37：在与源代码相同的目录中创建新文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_37.jpg)

###### 图 9.37：在与源代码相同的目录中创建新文件

1.  读取其内容并在控制台中输出：

```js
fs.readFile('test.txt', 'utf-8', (error, data) => {
    if (error) {
        console.error(error);
    }
    console.log(data);
});
```

这只是简单地读取我们的文件；我们提供了一个编码，因为我们希望输出是一个字符串而不是一个缓冲区。这将给我们以下输出：

![图 9.38：使用 fs.readFile 读取文件内容](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_38.jpg)

###### 图 9.38：使用 fs.readFile 读取文件内容

1.  尝试读取一个不存在的文件：

```js
fs.readFile('nofile.txt', 'utf-8', (error, data) => {
    if (error) {
        console.error(error);
    }
    console.log(data);
});
```

当我们尝试打开一个不存在的文件时，我们的回调将会被调用并出现错误。建议我们在处理任何与文件相关的错误时，应该在处理程序内部处理，而不是创建一个单独的函数来检查它。当我们运行上述代码时，将会得到以下错误：

![图 9.39：尝试读取不存在的文件时抛出的错误](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_39.jpg)

###### 图 9.39：尝试读取不存在的文件时抛出的错误

1.  让我们创建自己的带有 promise 的`readFile`版本：

```js
function readFile(file, options) {
    return new Promise((resolve, reject) => {
        fs.readFile(file, options, (error, data) => {
            if (error) {
                return reject(error);
            }
            resolve(data);
        })
    })
}
```

这与我们可以使用任何基于回调的方法做的事情是一样的，如下所示：

```js
readFile('test.txt', 'utf-8').then(console.log);
```

这将生成以下输出：

![图 9.40：使用基于回调的方法创建 readFile](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_40.jpg)

###### 图 9.40：使用基于回调的方法创建 readFile

1.  让我们使用文件`stat`来获取有关我们文件的信息。在 Node.js 10.0.0 之后，引入了`fsPromises`，因此我们可以简单地导入`fsPromise`并调用 promise 的对应项，而不是手动将它们转换为 promise 并手动返回函数：

```js
const fsPromises = require('fs').promises;
fsPromises.stat('test.txt').then(console.log);
```

这将生成以下输出：

![图 9.41：通过导入 fspromise 调用 promise 的对应项](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_41.jpg)

###### 图 9.41：通过导入 fspromise 调用 promise 的对应项

在这里，你可以获取有关我们文件的大小、创建时间、修改时间和权限信息。

在这个练习中，我们介绍了**fs**模块的一些基本用法。这是 Node.js 中一个非常有用的模块。接下来，我们将讨论如何在 Node.js 中处理大文件。

## 在 Node.js 中处理大文件

在上一个练习中，我们讨论了如何使用`fs`模块在 Node.js 中读取文件内容。当处理小于 100MB 的小文件时，这很有效。当处理大文件（> 2GB）时，有时使用`fs.readFile`无法读取整个文件。考虑以下情况。

你得到了一个 20GB 的文本文件，你需要逐行处理文件中的数据，并将输出写入输出文件。你的计算机只有 8GB 的内存。

当你使用`fs.readFile`时，它会尝试将文件的整个内容读入计算机的内存中。在我们的情况下，这是不可能的，因为我们的计算机没有足够的内存来容纳我们正在处理的文件的整个内容。在这里，我们需要一个单独的方法来解决这个问题。为了处理大文件，我们需要使用流。

流是编程中一个有趣的概念。它将数据视为不是单一的内存块，而是来自源的数据流，每次一个数据块。这样，我们就不需要将所有数据都放入内存中。要创建一个文件流，我们只需使用`fs`模块中提供的方法：

```js
const fs = require('fs');
const stream = fs.createReadStream('file.txt', 'utf-8');
```

通过使用`fs.createReadStream`，我们创建了一个文件流，以便稍后可以获取文件的内容。我们像使用`fs.readFile`一样调用这个函数，传入文件路径和编码。与`fs.readFile`的区别在于，这不需要提供回调，因为它只是返回一个`stream`对象。要从流中获取文件内容，我们需要将事件处理程序附加到`stream`对象上：

```js
stream.on('data', data => {
    // Data will be the content of our file
    Console.log(data);
    // Or
    Data = data + data;
});
```

在`data`事件的事件处理程序中，我们将获得文件的内容，并且当流读取文件时，此处理程序将被多次调用。当我们完成读取文件时，流对象还会发出一个事件来处理此事件：

```js
stream.on('close', () => {
    // Process clean up process
});
```

### Util

**Util**是一个包含许多有助于 Node.js 内部 API 的函数的模块。这些也可以在我们自己的开发中很有用。

**util.callbackify(function)**

这在我们处理现有的基于回调的遗留代码时非常有用。要将我们的`async`函数用作基于回调的函数，我们可以调用`util.callbackify`函数。让我们考虑以下示例：

```js
async function outputSomething() {
    return 'Something';
}
outputSomething().then(console.log);
```

以下是前面代码的输出：

![图 9.42：将 async 函数用作基于回调的函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_42.jpg)

###### 图 9.42：将 async 函数用作基于回调的函数

要将此`async`函数与回调一起使用，只需调用`callbackify`：

```js
const callbackOutputSomething = util.callbackify(outputSomething);
```

然后，我们可以这样使用它：

```js
callbackOutputSomething((err, result) => {
    if (err) throw err;
    console.log('got result', result);
})
```

这将生成以下输出：

![图 9.43：通过调用 callbackify 函数使用 async 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_43.jpg)

###### 图 9.43：通过调用 callbackify 函数使用 async 函数

我们已成功将`async`函数转换为使用回调的遗留函数。当我们需要保持向后兼容性时，这非常有用。

**util.promisify(function)**

`util`模块中还有一个非常有用的方法，可以帮助我们将基于回调的函数转换为`promisify`函数。该方法以一个函数作为参数，并将返回一个返回 promise 的新函数，如下所示：

```js
function callbackFunction(param, callback) {
    callback(null, 'I am calling back with: ${param}');
}
```

`callbackFunction`接受一个参数，并将使用我们提供的新字符串调用回调函数。要将此函数转换为使用 promises，我们可以使用`promisify`函数：

```js
const promisifiedFunction = util.promisify(callbackFunction);
```

这将返回一个新函数。稍后，我们可以将其用作返回 promise 的函数：

```js
promisifiedFunction('hello world').then(console.log);
```

以下是前面代码的输出：

![图 9.44：使用 promisify 函数进行回调](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_44.jpg)

###### 图 9.44：使用 promisify 函数进行回调

`util`模块中还有许多类型检查方法，在我们尝试确定应用程序中变量类型时非常有用。

### Timer

计时器模块为我们提供了一个用于调度计时器函数的 API。我们可以使用它在代码的某些部分设置延迟，或者在所需的间隔执行我们的代码。与之前的模块不同，不需要在使用之前导入`timer`模块。让我们看看 Node.js 提供的所有计时器函数以及如何在我们的应用程序中使用它们。

**setInterval(callback, delay)**

当我们想要设置一个在 Node.js 中重复执行的函数时，我们可以使用`setInterval`函数，并提供一个回调和延迟。要使用它，我们调用`setInterval`函数，并提供我们想要运行的函数以及以毫秒为单位的延迟。例如，如果我们想每秒打印相同的消息，我们可以这样实现：

```js
setInterval(() => {
    console.log('I am running every second');
}, 1000);
```

当我们运行前面的代码时，将看到以下输出：

![图 9.45：使用 setInterval 函数设置重复执行的函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_45.jpg)

###### 图 9.45：使用 setInterval 函数设置重复执行的函数

在这里，我们可以看到消息每秒打印一次。

**setTimeout(callback, delay)**

使用此函数，我们可以设置一次性延迟调用函数。当我们想要在运行函数之前等待一定的时间时，我们可以使用`setTimeout`来实现这一点。在前面的部分中，我们还使用`setTimeout`来模拟测试中的网络和磁盘请求。要使用它，我们需要传递我们想要运行的函数和以毫秒为单位的延迟整数。如果我们想在 3 秒后打印一条消息，我们可以使用以下代码：

```js
setTimeout(() => {
    console.log('I waited 3 seconds to run');
}, 3000);
```

这将生成以下输出：

![图 9.46：使用 setTimeout 函数设置一次延迟调用函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_46.jpg)

###### 图 9.46：使用 setTimeout 函数设置一次延迟调用函数

您将看到消息在 3 秒后打印出。当我们需要延迟调用函数或只想在测试中使用它模拟 API 调用时，这非常有用。

**setImmediate(callback)**

通过使用这种方法，我们可以推送一个函数，在事件循环结束时执行。如果您想在当前事件循环中的所有内容完成运行后调用某段代码，可以使用`setImmediate`来实现这一点。看一下以下示例：

```js
setImmediate(() => {
    console.log('I will be printed out second');
});
console.log('I am printed out first');
```

在这里，我们创建了一个函数，打印出`I will be printed out second`，它将在事件循环结束时执行。当我们执行这个函数时，我们将看到以下输出：

![图 9.47：使用 setimmediate 推送到事件循环结束时执行的函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_47.jpg)

###### 图 9.47：使用 setimmediate 推送到事件循环结束时执行的函数

我们也可以通过使用`setTimeout`并将`0`作为延迟参数来实现相同的效果：

```js
setTimeout(() => {
    console.log('I will be printed out second');
}, 0);
console.log('I am printed out first');
```

**clearInterval(timeout)**

当我们使用`setInterval`创建一个重复的函数时，该函数还会返回表示计时器的对象。当我们想要停止间隔运行时，我们可以使用`clearInterval`来清除计时器：

```js
const myInterval = setInterval(() => {
    console.log('I am being printed out');
}, 1000);
clearInterval(myInterval);
```

当我们运行上述代码时，我们将看到没有输出产生，因为我们清除了刚刚创建的间隔，并且它从未有机会运行：

![图 9.48：使用 clearInterval 函数停止间隔运行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_48.jpg)

###### 图 9.48：使用 clearInterval 函数停止间隔运行

如果我们想要运行这个间隔 3 秒，我们可以将`clearInterval`包装在`setTimeout`内，这样它将在`3.1`秒后清除我们的间隔。我们额外给了 100 毫秒，因为我们希望第三次调用发生在我们清除间隔之前：

```js
setTimeout(() => {
    clearInterval(myInterval);
}, 3100);
```

当我们运行上述代码时，我们将看到我们的输出打印出 3 次：

![图 9.49：使用 setTimeout 在指定的秒数内包装 clearInterval](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/prof-js/img/C14587_09_49.jpg)

###### 图 9.49：使用 setTimeout 在指定的秒数内包装 clearInterval

当我们处理多个预定计时器时，这非常有用。通过清除它们，我们可以避免内存泄漏和应用程序中的意外问题。

### 活动 14：构建文件监视器

在这个活动中，我们将使用定时器函数创建一个文件监视器，该监视器将指示文件中的任何修改。这些定时器函数将在文件上设置监视，并在文件发生更改时生成输出。让我们开始吧：

+   我们需要创建一个`fileWatcher`类。

+   将创建一个带有要监视的文件的文件监视器。如果没有文件存在，它将抛出异常。

+   文件监视器将需要另一个参数来存储检查之间的时间。

+   文件监视器需要允许我们移除对文件的监视。

+   文件监视器需要在文件更改时发出文件更改事件。

+   当文件更改时，文件监视器将发出带有文件新内容的事件。

打开`filewatcher.js`文件，并在该文件中进行您的工作。执行以下步骤以完成此活动：

1.  导入我们的库；即`fs`和`events`。

1.  创建一个文件监视器类，该类扩展了`EventEmitter`类。使用`modify`时间戳来跟踪文件更改。

1.  创建`startWatch`方法以开始监视文件的更改。

1.  创建`stopWatch`方法以停止监视文件的更改。

1.  在与`filewatch.js`相同的目录中创建一个`test.txt`文件。

1.  创建一个`FileWatcher`实例并开始监视文件。

1.  修改`test.txt`中的一些内容并保存。

1.  修改`startWatch`以便还检索新内容。

1.  修改`startWatch`，使其在文件被修改时发出事件，并在遇到错误时发出错误。

1.  在`fileWatcher`中附加事件处理程序以处理错误和更改。

1.  运行代码并修改`test.txt`以查看结果。

#### 注意

这个活动的解决方案可以在第 620 页找到。

如果您看到前面的输出，这意味着您的事件系统和文件读取完全正常。请随意扩展这个功能。您也可以尝试启用监视整个文件夹或多个文件。在这个活动中，我们只是使用文件系统模块和事件驱动编程创建了一个简单的`fileWatcher`类。使用这个帮助我们创建了一个更小的代码库，并在直接阅读代码时给了我们更多的清晰度。

## 总结

在本章中，我们讨论了 JavaScript 中的事件系统，以及如何使用内置的`events`模块来创建我们自己的事件发射器。后来，我们介绍了一些有用的内置模块及其示例用法。使用事件驱动编程可以帮助我们避免在编写需要多个组件相互通信的程序时出现交织的逻辑。此外，通过使用内置模块，我们可以避免添加提供相同功能的模块，并避免创建具有巨大依赖关系的项目。我们还提到了如何使用定时器来控制程序执行，使用`fs`来操作文件，以及使用`path`来组合和获取有关我们文件路径的有用信息。这些都是非常有用的模块，可以在构建应用程序时帮助我们。在下一章中，我们将讨论如何在 JavaScript 中使用函数式编程。
