# Angular 测试驱动开发（一）

> 原文：[`zh.annas-archive.org/md5/60F96C36D64CD0F22F8885CC69A834D2`](https://zh.annas-archive.org/md5/60F96C36D64CD0F22F8885CC69A834D2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将为读者提供一个关于 JavaScript 测试驱动开发（TDD）的完整指南，然后深入探讨 Angular 的方法。它将提供清晰的、逐步的示例，不断强调 TDD 的最佳实践。本书将同时关注使用 Karma 进行单元测试和使用 Protractor 进行端到端测试，不仅关注如何使用工具，还要理解它们的构建原因以及为什么应该使用它们。在整个过程中，将重点关注何时、何地以及如何使用这些工具，不断强调测试驱动开发生命周期（测试、执行和重构）的原则。

本书中的所有示例都基于 Angular v2，并与 Angular v4 兼容。

# 本书涵盖的内容

第一章*，测试驱动开发简介*，通过解释 TDD 如何在开发过程中发挥作用，向我们介绍了测试驱动开发的基本原理。

第二章*，JavaScript 测试的细节*，涵盖了 JavaScript 环境下的 TDD。本章探讨了 JavaScript 应用程序中需要的测试类型，如单元测试、行为测试、集成测试和端到端测试。还解释了不同类型的 JavaScript 测试工具、框架及其在 Angular 应用程序中的用途。

第三章*，Karma 之道*，探讨了 Karma 的起源以及为什么在任何 Angular 项目中都必须使用它。通过本章的学习，读者不仅将了解 Karma 解决的问题，还将通过一个完整的示例来使用 Karma。

第四章*，使用 Protractor 进行端到端测试*，深入研究了端到端测试应用程序，涵盖了应用程序的所有层。本章向读者介绍了 Protractor，Angular 团队的端到端测试工具。然后解释了 Protractor 的创建原因以及它如何解决问题。最后，它逐步指导读者如何在现有的 Angular 项目中安装、配置和使用 Protractor 进行 TDD。

第五章*，Protractor，领先一步*，深入探讨了 Protractor 并探索了一些高级配置。然后，它通过示例解释了测试套件的调试过程。这还探讨了一些常用的 Protractor API，并附有相关示例。

第六章*，第一步*，介绍了如何使用 TDD 来构建具有类、组件和服务的 Angular 应用程序的入门步骤。本章帮助读者开始 TDD 之旅，并看到基本原理的实际应用。到目前为止，本书专注于 TDD 和工具的基础。然后，通过向前迈进一步，它深入探讨了与 Angular 一起使用 TDD。

第七章*，翻转*，继续扩展我们对使用 TDD 与 Angular 功能的知识，例如路由和导航，以通过我们的示例 Angular 应用程序获得结果集。除了 Angular 功能，本书还指导读者如何使用 Protractor 的帮助对这些特定功能进行端到端测试。

第八章*，告诉世界*，涵盖了示例 Angular 应用程序的更多单元测试，包括路由和导航。除此之外，本章还重构了现有代码，使其更具可测试性。然后，在重构代码的同时介绍了 Angular 服务和事件广播，并引入了 MockBackend 来测试服务中的 HTTP 请求。

# 你需要为这本书做什么

在本书中，我们使用**Node Package Manager**（**npm**）作为运行应用程序和各种测试工具的命令工具。因此，全局安装 npm 是先决条件。要安装它，必须在操作系统上安装 Node.js。

我们不会讨论如何安装 Node.js 和 npm。已经有很多资源可用于在任何操作系统上安装它们。

# 这本书适合谁

这本书适合有基本的 Angular 经验但想要了解何时、为什么以及如何应用测试技术和最佳实践来创建高质量清晰代码的开发人员。要充分利用本书，您应该对 HTML、CSS 和 JavaScript 有很好的理解，并对带有 TypeScript 的 Angular 有基本的了解。

# 规范

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："下面的代码行读取链接并将其分配给`Calculator`函数。"

代码块设置如下：

```ts
var calculator = {
   multiply : function(amount1, amount2) {
       return amount1 * amount2;
   }
};
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```ts
<!DOCTYPE html>
<html>
  <head>
    <title>Test Runner</title>
  </head>
  <body>
    // ...
 **<script src="calculator.js"></script>**
  </body>
</html>
```

任何命令行输入或输出都以以下方式编写：

```ts
**$ npm install protractor
$ npm protractor --version**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："为了下载新模块，我们将转到**文件** | **设置** | **项目名称** | **项目解释器**"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：介绍测试驱动开发

Angular 处于客户端 JavaScript 测试的前沿。每个 Angular 教程都包括相应的测试，甚至测试模块都是核心 Angular 包的一部分。Angular 团队致力于使测试成为 Web 开发的基础。

本章向您介绍了使用 Angular 进行**测试驱动开发**（**TDD**）的基础知识，包括以下主题：

+   TDD 概述

+   TDD 生命周期：先测试，使其运行，然后改进

+   常见的测试技术

# TDD 概述

TDD 是一种演进式的开发方法，您在编写足够的生产代码来满足测试及其重构之前编写测试。

本节将探讨 TDD 的基础知识。让我们以裁缝为例，看看他如何将 TDD 应用到自己的流程中。

## TDD 的基础知识

在开始编写代码之前就了解要写什么。这可能听起来陈词滥调，但这基本上就是 TDD 给您的。TDD 从定义期望开始，然后让您满足期望，最后在满足期望后强迫您对更改进行精炼。

练习 TDD 的一些明显好处如下：

+   **没有小改变**：小改变可能会在整个项目中引起许多破坏性问题。实践 TDD 是唯一可以帮助的方法，因为测试套件将捕捉破坏点并在任何更改后保存项目，从而拯救开发人员的生命。

+   **明确定义任务**：测试套件明确提供了任务的清晰视野和逐步工作流程，以便取得成功。首先设置测试允许您只关注在测试中定义的组件。

+   **重构的信心**：重构涉及移动、修复和更改项目。测试通过确保逻辑独立于代码结构的行为，保护核心逻辑免受重构的影响。

+   **前期投资，未来收益**：最初，测试似乎需要额外的时间，但当项目变得更大时，实际上会在以后得到回报，它让我们有信心扩展功能，只需运行测试就能识别出任何破坏性问题。

+   **QA 资源可能有限**：在大多数情况下，QA 资源是有限的，因为让 QA 团队手动检查一切都需要额外的时间，但编写一些测试用例并成功运行它们肯定会节省一些 QA 时间。

+   **文档化**：测试定义了特定对象或函数必须满足的期望。期望充当合同，可以用来查看方法应该或可以如何使用。这使得代码更易读和理解。

## 用不同的眼光来衡量成功

TDD 不仅是一种软件开发实践--它的基本原则也被其他工匠所共享。其中之一就是裁缝，他的成功取决于精确的测量和周密的计划。

### 分解步骤

以下是裁缝制作西装的高级步骤：

1.  **先测试**：

+   确定西装的尺寸

+   让客户确定他们想要西装的风格和材料

+   测量客户的手臂、肩膀、躯干、腰部和腿

1.  **进行裁剪**：

+   根据所需的风格选择面料

+   根据客户的身形测量面料

+   根据测量裁剪面料

1.  **重构**：

+   将裁剪和外观与客户所需的风格进行比较

+   进行调整以满足所需的风格

1.  **重复**：

+   **先测试**：确定西装的尺寸

+   **进行裁剪**：测量面料并进行裁剪

+   **重构**：根据审查进行更改

上述步骤是 TDD 方法的一个例子。裁缝必须在开始裁剪原材料之前进行测量。想象一下，如果裁缝没有使用测试驱动的方法，也没有使用测量工具（尺寸），那将是荒谬的。如果裁缝在测量之前就开始裁剪会发生什么？如果面料被剪得太短会发生什么？裁缝需要多少额外时间来裁剪？因此，要多测量，少裁剪。

作为开发者，你是否会“在测量之前就剪裁”？你会相信一个没有测量工具的裁缝吗？你会如何看待一个不进行测试的开发者？

### 多次测量，一次裁剪

裁缝总是从测量开始。如果裁缝在测量之前就开始裁剪会发生什么？如果面料被剪得太短会发生什么？裁缝需要多少额外时间来裁剪？因此，要多测量，少裁剪。

软件开发人员可以在开始开发之前选择无数种方法。一个常见的方法是根据规范进行工作。文档化的方法可能有助于定义需要构建的内容；然而，如果没有明确的标准来满足规范，实际开发的应用可能与规范完全不同。采用 TDD 方法，过程的每个阶段都验证结果是否符合规范。想象一下裁缝在整个过程中继续使用卷尺来验证西装。

TDD 体现了测试优先的方法论。TDD 使开发人员能够以明确的目标开始，并编写直接满足规范的代码，因此您可以像专业人士一样开发，并遵循有助于编写高质量软件的实践。

# JavaScript 实用 TDD

让我们深入了解 JavaScript 环境中的实际 TDD。这个演练将带领我们完成向计算器添加乘法功能的过程。

只需记住以下 TDD 生命周期：

+   先测试

+   让它运行

+   让它变得更好

## 指出开发待办事项清单

开发待办事项清单有助于组织和专注于单独的任务。它还可以在开发过程中提供一个列出想法的平台，这些想法以后可能成为单一功能。

让我们在开发待办事项清单中添加第一个功能--添加乘法功能：

*3 * 3 = 9*

上述清单描述了需要做的事情。它还清楚地说明了如何验证乘法*3 * 3 = 9*。

## 设置测试套件

为了设置测试，让我们在一个名为`calculator.js`的文件中创建初始计算器。它初始化为一个对象，如下所示：

```ts
var calculator = {}; 

```

测试将通过网页浏览器运行，作为一个简单的 HTML 页面。因此，让我们创建一个 HTML 页面，并导入`calculator.js`进行测试，并将页面保存为`testRunner.html`。

要运行测试，让我们在网页浏览器中打开`testRunner.html`文件。

`testRunner.html`文件将如下所示：

```ts
<!DOCTYPE html> 
<html> 
<head> 
  <title>Test Runner</title> 
</head> 
<body> 

<script src="calculator.js"></script> 
</body> 
</html> 

```

项目的测试套件已经准备就绪，功能的开发待办事项清单也已准备就绪。下一步是根据功能列表逐个深入 TDD 生命周期。

## 先测试

虽然编写一个乘法函数很容易，并且它将像一个非常简单的功能一样工作，但作为练习 TDD 的一部分，现在是时候遵循 TDD 生命周期了。生命周期的第一阶段是根据开发待办事项编写测试。

以下是第一次测试的步骤：

1.  打开`calculator.js`。

1.  创建一个新的函数`multipleTest1`来测试乘法*3 * 3，之后`calculator.js`文件将如下所示：

```ts
        function multipleTest1() { 
            // Test 
            var result = calculator.multiply(3, 3); 

            // Assert Result is expected 
            if (result === 9) { 
                console.log('Test Passed'); 
            } else { 
                console.log('Test Failed'); 
            } 
        };  

        multipleTest1();
```

测试调用一个尚未定义的`multiply`函数。然后通过显示通过或失败消息来断言结果是否符合预期。

### 注意

请记住，在 TDD 中，您正在考虑方法的使用，并明确编写它应该如何使用。这使您能够根据用例定义接口，而不仅仅是查看正在开发的功能的有限范围。

TDD 生命周期中的下一步是使测试运行。

## 使测试运行

在这一步中，我们将运行测试，就像裁缝对套装进行了测量一样。测试步骤中进行了测量，现在可以调整应用程序以适应这些测量。

以下是运行测试的步骤：

1.  在 Web 浏览器上打开`testRunner.html`。

1.  在浏览器中打开 JavaScript 开发者**控制台**窗口。

测试将抛出错误，这将在浏览器的开发者控制台中可见，如下截图所示：

![使测试运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/5405_01_01.jpg)

抛出的错误是预期的，因为计算器应用程序调用了尚未创建的函数--`calculator.multiply`。

在 TDD 中，重点是添加最简单的更改以使测试通过。实际上不需要实现乘法逻辑。这可能看起来不直观。关键是一旦存在通过的测试，它应该始终通过。当一个方法包含相当复杂的逻辑时，更容易运行通过的测试来确保它符合预期。

可以做的最简单的更改是什么，以使测试通过？通过返回预期值`9`，测试应该通过。虽然这不会添加乘法功能，但它将确认应用程序的连接。此外，在我们通过了测试之后，未来的更改将变得容易，因为我们只需保持测试通过即可！

现在，添加`multiply`函数，并使其返回所需的值`9`，如下所示：

```ts
var calculator = { 
    multiply : function() { 
        return 9; 
    } 
}; 

```

现在，让我们刷新页面重新运行测试，并查看 JavaScript 控制台。结果应该如下截图所示：

![使测试运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_01_002-1.jpg)

是的！没有错误了。有一条消息显示测试已经通过。

现在有了通过的测试，下一步将是从`multiply`函数中删除硬编码的值。

## 让项目变得更好

重构步骤需要从`multiply`函数中删除硬编码的`return`值，这是我们为了通过测试而添加的最简单的解决方案，并添加所需的逻辑以获得预期的结果。

所需的逻辑如下：

```ts
var calculator = { 
    multiply : function(amount1, amount2) { 
        return amount1 * amount2; 
    } 
}; 

```

现在，让我们刷新浏览器重新运行测试；它将像之前一样通过测试。太棒了！现在`multiply`函数已经完成。

`calculator.js`文件的完整代码，用于`calculator`对象及其测试，如下所示：

```ts
var calculator = { 
    multiply : function(amount1, amount2) { 
        return amount1 * amount2; 
    } 
}; 

function multipleTest1() { 
    // Test 
    var result = calculator.multiply(3, 3); 

    // Assert Result is expected 
    if (result === 9) { 
        console.log('Test Passed'); 
    } else { 
        console.log('Test Failed'); 
    } 
}

multipleTest1(); 

```

# 测试机制

要成为一个合格的 TDD 开发者，重要的是要了解一些测试技术的基本机制和测试方法。在本节中，我们将通过几个测试技术和机制的示例来介绍这本书中将要使用的。

这将主要包括以下几点：

+   使用**Jasmine**间谍进行测试替身

+   重构现有测试

+   构建模式

以下是将要使用的其他术语：

+   **被测试的函数**：这是正在测试的函数。它也被称为被测试系统、被测试对象等。

+   **3A（安排、行动和断言）**：这是一种用于设置测试的技术，最初由 Bill Wake 描述（[`xp123.com/articles/3a-arrange-act-assert/`](http://xp123.com/articles/3a-arrange-act-assert/)）。3A 将在第二章中进一步讨论，*JavaScript 测试的详细信息*。

## 使用框架进行测试

我们已经看到了在计算器应用程序上执行测试的快速简单方法，我们已经为`multiply`方法设置了测试。但在现实生活中，这将会更加复杂，应用程序也会更大，早期的技术将会过于复杂，难以管理和执行。在这种情况下，使用测试框架会更方便、更容易。测试框架提供了测试的方法和结构。这包括创建和运行测试的标准结构，创建断言/期望的能力，使用测试替身的能力，以及更多。本书使用 Jasmine 作为测试框架。Jasmine 是一个行为驱动的测试框架。它与测试 Angular 应用程序非常兼容。在第二章中，*JavaScript 测试的详细信息*，我们将深入了解 Jasmine。

以下示例代码并不完全是在 Jasmine 测试/规范运行时的运行方式，它只是关于测试替身如何工作或这些测试替身如何返回预期结果的想法。在第二章中，*JavaScript 测试的详细信息*，我们将准确展示这个测试替身应该如何与 Jasmine 规范运行器一起使用。

## 使用 Jasmine 间谍进行测试替身

测试替身是一个充当并用于代替另一个对象的对象。Jasmine 有一个测试替身函数，称为`spies`。Jasmine 间谍与`spyOn()`方法一起使用。

让我们看一下需要进行测试的`testableObject`对象。使用测试替身，我们可以确定`testableFunction`被调用的次数。

以下是测试替身的示例：

```ts
var testableObject = { 
    testableFunction : function() { } 
}; 
jasmine.spyOn(testableObject, 'testableFunction'); 

testableObject.testableFunction(); 
testableObject.testableFunction(); 
testableObject.testableFunction(); 

console.log(testableObject.testableFunction.count); 

```

上述代码使用 Jasmine 间谍(`jasmine.spyOn`)创建了一个测试替身。以下是 Jasmine 测试替身提供的一些功能：

+   函数调用次数

+   指定返回值的能力（存根返回值）

+   传递给底层函数的调用能力（传递）

在本书中，我们将进一步学习测试替身的使用经验。

### 存根返回值

使用测试替身的好处是方法的底层代码不必被调用。通过测试替身，我们可以准确指定方法在给定测试中应该返回什么。

考虑以下对象和函数的示例，其中函数返回一个字符串：

```ts
var testableObject = { 
    testableFunction : function() { return 'stub me'; } 
}; 

```

前述对象`testableObject`有一个需要存根化的函数`testableFunction`。

因此，要存根化单个返回值，需要链式调用`and.returnValue`方法，并将预期值作为`param`传递。

以下是如何将单个返回值进行间谍链以进行存根化：

```ts
jasmine.spyOn(testableObject, 'testableFunction') 
.and 
.returnValue('stubbed value'); 

```

现在，当调用`testableObject.testableFunction`时，将返回`stubbed value`。

考虑前述单个`stubbed value`的示例：

```ts
var testableObject = { 
    testableFunction : function() { return 'stub me'; } 
}; 
//before the return value is stubbed 
Console.log(testableObject.testableFunction()); 
//displays 'stub me' 

jasmine.spyOn(testableObject,'testableFunction') 
.and 
.returnValue('stubbed value'); 

//After the return value is stubbed 
Console.log(testableObject.testableFunction()); 
//displays 'stubbed value' 

```

类似地，我们可以像前面的示例一样传递多个返回值。

以下是如何将多个返回值进行间谍链以逐个进行存根化：

```ts
jasmine.spyOn(testableObject, 'testableFunction') 
.and 
.returnValues('first stubbed value', 'second stubbed value', 'third stubbed value'); 

```

因此，对于每次调用`testableObject.testableFunction`，它将按顺序返回存根化的值，直到达到返回值列表的末尾。

考虑前面多个存根化值的示例：

```ts
jasmine.spyOn(testableObject, 'testableFunction') 
.and 
.returnValue('first stubbed value', 'second stubbed value', 'third stubbed value'); 

//After the is stubbed return values 
Console.log(testableObject.testableFunction()); 
//displays 'first stubbed value' 
Console.log(testableObject.testableFunction()); 
//displays 'second stubbed value' 
Console.log(testableObject.testableFunction()); 
//displays 'third stubbed value' 

```

### 测试参数

测试替身提供了关于应用程序中方法使用方式的见解。例如，测试可能希望断言方法被调用时使用的参数，或者方法被调用的次数。以下是一个示例函数：

```ts
var testableObject = { 
    testableFunction : function(arg1, arg2) {} 
}; 

```

以下是测试调用前述函数时使用的参数的步骤：

1.  创建一个间谍，以便捕获调用的参数：

```ts
        jasmine.spyOn(testableObject, 'testableFunction'); 

```

1.  然后，要访问参数，请运行以下命令：

```ts
        //Get the arguments for the first call of the function 
        var callArgs = testableObject.testableFunction
        .call.argsFor(0); 

        console.log(callArgs); 
        //displays ['param1', 'param2'] 

```

以下是如何使用`console.log`显示参数：

```ts
var testableObject = { 
    testableFunction : function(arg1, arg2) {} 
}; 
//create the spy 
jasmine.spyOn(testableObject, 'testableFunction'); 

//Call the method with specific arguments 
  testableObject.testableFunction('param1', 'param2'); 

//Get the arguments for the first call of the function 
var callArgs = testableObject.testableFunction.call.argsFor(0); 

console.log(callArgs); 
//displays ['param1', 'param2'] 

```

## 重构

重构是重构、重写、重命名和删除代码的行为，以改善代码的设计、可读性、可维护性和整体美感。TDD 生命周期步骤*使项目变得更好*主要涉及重构。本节将通过一个重构示例引导我们。

看一下需要重构的函数的以下示例：

```ts
var abc = function(z) { 
    var x = false; 
    if(z > 10) 
        return true; 
    return x; 
} 

```

这个函数运行良好，没有包含任何语法或逻辑问题。问题在于这个函数很难阅读和理解。重构这个函数将改善其命名、结构和定义。这个练习将消除伪装的复杂性，揭示函数的真正含义和意图。

以下是步骤：

1.  重命名函数和变量名称以使其更有意义，即重命名`x`和`z`，使其有意义：

```ts
        var isTenOrGreater = function(value) { 
            var falseValue = false; 
            if(value > 10) 
                return true; 
            return falseValue; 
        } 

```

现在，函数可以轻松阅读，命名也有意义。

1.  删除任何不必要的复杂性。在这种情况下，`if`条件语句可以完全删除，如下所示：

```ts
        var isTenOrGreater = function(value) { 
            return value > 10; 
        }; 

```

1.  反思结果。

在这一点上，重构已经完成，函数的目的应该立即显现出来。接下来应该问的问题是：“为什么这个方法一开始就存在呢？”。

这个例子只是简要地介绍了如何识别代码中的问题以及如何改进它们的步骤。本书将在整个书中提供其他示例。

## 使用建造者构建

这些天，设计模式是一种常见的实践，我们遵循设计模式来使生活更轻松。出于同样的原因，这里将遵循建造者模式。

建造者模式使用`builder`对象来创建另一个对象。想象一个具有 10 个属性的对象。如何为每个属性创建测试数据？对象是否必须在每个测试中重新创建？

`builder`对象定义了一个可以在多个测试中重复使用的对象。以下代码片段提供了使用这种模式的示例。这个例子将在`validate`方法中使用`builder`对象：

```ts
var book = { 
    id : null, 
    author : null, 
    dateTime : null 
}; 

```

`book`对象有三个属性：`id`，`author`和`dateTime`。从测试的角度来看，我们希望能够创建一个有效的对象，即所有字段都已定义的对象。我们可能还希望创建一个缺少属性的无效对象，或者我们可能希望设置对象中的某些值来测试验证逻辑。就像这里`dateTime`是一个实际的日期时间，应该由建造者对象分配。

以下是为`bookBuilder`对象创建建造者的步骤：

1.  创建一个建造者函数，如下所示：

```ts
        var bookBuilder = function() {}; 

```

1.  在建造者中创建一个有效的对象，如下所示：

```ts
        var bookBuilder = function() { 
            var _resultBook = { 
                id: 1, 
                author: 'Any Author', 
                dateTime: new Date() 
            }; 
        } 

```

1.  创建一个函数来返回构建的对象：

```ts
        var bookBuilder = function() { 
            var _resultBook = { 
                id: 1, 
                author: "Any Author", 
                dateTime: new Date() 
            }; 
            this.build = function() { 
                return _resultBook; 
            } 
        } 

```

1.  如图所示，创建另一个函数来设置`_resultBook`的作者字段：

```ts
        var bookBuilder = function() { 
            var _resultBook = { 
                id: 1, 
                author: 'Any Author', 
                dateTime: new Date() 
            }; 
            this.build = function() { 
                return _resultBook; 
            }; 
            this.setAuthor = function(author){ 
                _resultBook.author = author; 
            }; 
        }; 

```

1.  更改函数定义，以便可以链接调用：

```ts
        this.setAuthor = function(author) { 
            _resultBook.author = author; 
            return this; 
        }; 

```

1.  一个设置器函数也将被创建用于`dateTime`，如下所示：

```ts
        this.setDateTime = function(dateTime) { 
            _resultBook.dateTime = dateTime; 
            return this; 
        }; 

```

现在，`bookBuilder`可以用来创建一个新的书，如下所示：

```ts
var bookBuilder = new bookBuilder(); 

var builtBook = bookBuilder.setAuthor('Ziaul Haq') 
.setDateTime(new Date()) 
.build(); 
console.log(builtBook.author); // Ziaul Haq 

```

前面的建造者现在可以在我们的测试中被用来创建一个一致的对象。

这是完整的建造者供参考：

```ts
var bookBuilder = function() { 
    var _resultBook = { 
        id: 1, 
        author: 'Any Author', 
        dateTime: new Date() 
    }; 

    this.build = function() { 
        return _resultBook; 
    }; 

    this.setAuthor = function(author) { 
        _resultBook.author = author; 
        return this; 
    }; 

    this.setDateTime = function(dateTime) { 
        _resultBook.dateTime = dateTime; 
        return this; 
    }; 
}; 

```

让我们创建`validate`方法来验证从建造者创建的书对象：

```ts
var validate = function(builtBookToValidate){ 
    if(!builtBookToValidate.author) { 
        return false; 
    } 
    if(!builtBookToValidate.dateTime) { 
        return false; 
    } 
    return true; 
}; 

```

让我们首先通过传递所有必需的信息，使用建造者创建一个有效的书对象，如果这是通过`validate`对象传递的，这应该显示一个有效的消息：

```ts
var validBuilder = new bookBuilder().setAuthor('Ziaul Haq') 
.setDateTime(new Date()) 
.build(); 

// Validate the object with validate() method 
if (validate(validBuilder)) { 
    console.log('Valid Book created'); 
} 

```

同样，让我们通过构建器创建一个无效的书籍对象，通过在必要信息中传递一些空值。通过将对象传递给`validate`方法，它应该显示解释为什么无效的消息：

```ts
var invalidBuilder = new bookBuilder().setAuthor(null).build(); 

if (!validate(invalidBuilder)) { 
    console.log('Invalid Book created as author is null'); 
} 

var invalidBuilder = new bookBuilder().setDateTime(null).build(); 

if (!validate(invalidBuilder)) { 
    console.log('Invalid Book created as dateTime is null'); 
} 

```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您从其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

# 自测问题

Q1\. 测试替身是重复测试的另一个名称。

1.  正确

1.  错误

Q2\. TDD 代表测试驱动开发。

1.  正确

1.  错误

Q3\. 重构的目的是提高代码质量。

1.  正确

1.  错误

Q4\. 测试对象构建器 consolida 了用于测试的对象的创建。

1.  正确

1.  错误

Q5\. 三个 A 是一个体育队。

1.  正确

1.  错误

# 摘要

本章介绍了 TDD。它讨论了 TDD 生命周期（先测试，使其运行，然后改进）以及这些步骤可以被任何人用于 TDD 方法，类似于我们看到裁缝使用的方式。最后，它回顾了本书中将讨论的一些测试技术，包括测试替身，重构和构建模式。

尽管 TDD 是一个庞大的主题，但本书仅专注于与 Angular 一起使用的 TDD 原则和实践。

在下一章中，我们将了解有关 JavaScript 测试的详细信息。


# 第二章：JavaScript 测试的细节

TDD 的实践是获得高质量软件和令人满意的准确性的好方法，即使人手较少。对于 Web 应用程序，JavaScript 已经成为最流行的脚本语言，测试 JavaScript 代码已经成为一个挑战。基于浏览器的测试实际上是一种浪费时间的做法，对于 TDD 来说很难跟进，但是解决这个问题的方法是使用一些支持 JavaScript 自动化测试的很酷的工具。大多数 Web 应用项目仅限于单元测试，没有自动化测试工具，端到端测试或功能测试几乎是不可能的。

许多专注于 JavaScript 测试的工具和框架正在涌现，它们提供不同的解决方案，使开发人员的生活变得更加轻松。除了发明新的 JavaScript 框架，开发人员社区还发明了一些工具集，以使测试变得更加容易。就像 Angular 团队一样，他们提供了像**Karma**这样的很酷的工具。我们还有测试框架或工具的重复，它们都以不同的方式解决了类似的问题。选择哪种工具或框架取决于开发人员；他们必须选择最适合他们要求的工具。

在本章中，我们将涵盖以下内容：

+   自动化测试的简要介绍

+   专注于 JavaScript 的不同类型的测试

+   一些测试工具和框架的简要概念

# JavaScript 测试的技艺

我们都知道 JavaScript 是一种动态类型的解释语言。因此，与 Java 等编译语言不同，没有编译步骤可以帮助您找出错误。因此，JavaScript 开发人员应该花更多的时间来测试代码。然而，现在生活变得更加容易，开发人员可以使用最新的工具技术在最少的步骤和时间内进行测试。这是自动化测试的一部分，代码在更改时将自动进行测试。在这个过程中，测试可能是在后台运行的任务，可以集成到 IDE 或 CLI 中，并且在开发过程中提供测试结果。

在接下来的章节中，我们将讨论如何使用测试运行器和无头浏览器在多个浏览器中自动化测试过程。

## 自动化测试

测试很有趣，编写测试会使代码更好；这是一个很好的实践，但是过程化的手动测试有点耗时、容易出错，并且不可重复。在这个过程中，需要编写测试规范，更改代码以通过测试，刷新浏览器以获取结果，并重复这个过程多次。作为程序员，重复相同的事情有点无聊。

除了单调乏味之外，它也大大减慢了开发过程，这让开发人员对 TDD 的实践失去了动力。因此，当手动过程减慢进度时，我们必须寻找一些自动化的过程来完成工作，并为其他可能增加更多业务价值的任务节省时间。

因此，拥有一些工具或技术可以帮助程序员摆脱这些重复乏味的手动步骤，这些步骤减慢了过程，并自动完成任务，更快地完成任务，并节省时间，使它们对业务更有价值，这将是很棒的。幸运的是，有一些工具可以自动化这些测试。我们将在其他章节中更多地介绍这些工具和技术。

除了减慢开发过程的问题之外，当我们谈论测试功能时，另一个重要的问题出现了，那就是跨浏览器兼容性问题。由于 Web 应用程序应该在现代平台和浏览器上完美运行，而逐个手动测试几乎是不可能的，自动化测试可能是一个解决方案，使用 Web 驱动程序和无头浏览器。

让我们回顾一下我们在上一章中解释的基本测试流程--测试它，使其运行，并使其更好。为了使这个过程自动化，开发人员可以在 CLI 甚至开发 IDE 中实现工具集，并且这些测试将在一个单独的进程中持续运行，而不需要开发人员的任何输入。

让我们想象一下任何应用程序的注册或注册功能，我们必须手动填写表单并每次点击提交按钮以测试该功能，并通过更改数据重复该过程。这实际上被称为功能测试（我们将在本章末讨论）。为了自动执行这些过程，我们将在 CLI 中使用工具集（测试运行器、Web 驱动程序和无头浏览器），并使用一条命令和一些参数完成整个过程。

在自动化测试中测试 JavaScript 并不是一个新概念，实际上，它是最常用的自动化浏览器。Selenium 是在 2004 年为此而发明的，之后出现了许多工具，包括 PhantomJS、Karma、Protractor 和 CasperJS。在本章中，我们将讨论其中一些。

# 测试的类型

在 TDD 中，开发人员必须遵循一种流程来实现测试的目标。在这个流程中，每一步都有一个独立的测试目标。例如，有些测试仅用于测试每个函数的行为，而有些用于测试模块/功能的流程。基于此，我们将在这里讨论两种主要类型的测试。它们如下：

+   **单元测试**：这主要用于行为测试。

+   **端到端测试**：这主要被称为 e2e 测试，用于功能测试。

## 单元测试

**单元测试**是一种软件开发过程，其中应用程序的最小可测试部分被单独称为一个单元，并且该小部分的行为应该能够在隔离的情况下进行测试，而不依赖于其他部分。如果我们将 JavaScript 应用程序视为软件，那么该应用程序的每个单独的方法/函数都将是代码的一个单元，这些方法或代码单元的行为应该能够以隔离的方式进行测试。

关于单元测试的一个重要观点是，任何代码单元都应该能够在隔离的情况下运行/进行测试，并且可以以任何顺序运行，这意味着如果单元测试在任何应用程序中成功运行，它代表了该应用程序的组件或模块的隔离。

例如，我们在上一章中已经展示了一个小的测试示例，演示了如何进行方法测试；尽管我们没有使用任何测试框架，但这个想法是一样的。我们通过传递一些参数来调用方法，得到了该方法的结果，然后将结果与预期值进行比较。

通常，我们将使用我们选择的单元测试框架编写这些测试。现在有许多测试框架和工具，我们必须根据我们的需求决定并选择最好的一个。最常用的框架是 Jasmine、Mocha 和 QUnit。我们将在本章深入讨论这些工具，并在随后的章节中涵盖真实的例子。

测试应该快速运行并且自动化，并且具有清晰的输出。例如，您可以验证如果使用特定参数调用函数，它应该返回预期的结果。

单元测试可以随时运行测试，例如在以下情况下：

+   从开发过程的最开始，即使测试失败

+   完成任何功能的开发后，验证行为是否正确

+   修改任何现有功能后，以验证行为是否发生了变化

+   在现有应用程序中添加新功能后，我们需要验证新功能是否被隔离，并且没有破坏任何其他功能

## 端到端测试

端到端测试是一种用于测试应用程序流程是否按照设计进行的方法。例如，如果用户从产品列表中点击一个产品，它应该提示模态框显示所选产品的详细信息。在这种情况下，产品/项目所有者将根据规范逐步定义项目要求。在开发过程之后，将根据规范的工作流程对项目进行测试。这被称为功能/流程测试，也是端到端测试的另一个名称。

除了单元测试之外，端到端测试对于确认各个组件作为一个应用程序一起工作，传递信息并相互通信非常重要。与单元测试的主要区别在于它不会单独测试任何组件；相反，它是对所有相关组件一起进行流程的综合测试。

考虑一个注册模块，用户应该提供一些有效信息来完成注册，该模块/应用程序的功能/流程测试应该遵循一些步骤来完成测试。

步骤如下：

1.  加载/编译表单

1.  获取表单元素的 DOM

1.  触发提交按钮的点击事件

1.  从输入字段中收集值以进行验证

1.  验证输入字段

1.  调用虚拟 API 来存储数据

在每一步中，都会有一些结果与预期结果集进行比较。

这些类型的功能/流程测试可以通过人工填写表单，点击下一步按钮，完成应用程序流程，并将结果与在实施过程中早期定义的规范进行比较来进行手动测试。

然而，有一些技术可用于以自动化方式进行功能/流测试，而无需从任何人那里获取输入，这被称为端到端测试。为了使这个测试过程更容易，有一些工具可用；最常用的是 Selenium、PhantomJS 和 Protractor。这些工具可以轻松集成到任何应用程序测试系统中。在本章中，我们将稍微详细地讨论这些测试工具，并在随后的章节中将它们集成到应用程序的测试套件中。

# 测试工具和框架

了解不同的测试工具是一大挑战。对于 Angular 测试来说，其中一些非常重要，我们将在本书中详细学习它们。然而，在本节中，我们将学习一些在不同 Web 应用程序中用于各种测试和方法的知名工具和框架。它们如下：

+   **Karma**：这是 JavaScript 的测试运行器

+   **Protractor**：这是端到端测试框架

+   **Jasmine**：这是行为驱动的 JavaScript 测试框架

+   **Mocha**：这是 JavaScript 测试框架

+   **QUnit**：这代表单元测试框架

+   **Selenium**：这是自动化 Web 浏览器的工具

+   **PhantomJS**：这是无头 Webkit 浏览器

## Karma

在讨论 Karma 是什么之前，最好先讨论它不是什么。它不是一个编写测试的框架；它是一个测试运行器。这意味着 Karma 赋予我们能力以自动化方式在多个不同的浏览器中运行测试。过去，开发人员必须手动执行以下步骤：

+   打开浏览器

+   将浏览器指向项目 URL

+   运行测试

+   确认所有测试都已通过

+   进行更改

+   刷新页面

使用 Karma，自动化使开发人员能够运行单个命令并确定整个测试套件是否通过或失败。从 TDD 的角度来看，这使我们能够快速找到并修复失败的测试。

与手动流程相比，使用 Karma 的一些优点如下：

+   在多个浏览器和设备中自动化测试的能力

+   监视文件的能力

+   在线文档和支持

+   只做一件事——运行 JavaScript 测试——并且做得很好

+   使其易于与持续集成服务器集成

使用 Karma 的缺点：

+   需要学习、配置和维护额外的工具

自动化测试和使用 Karma 的过程非常有利。在本书的 TDD 旅程中，Karma 将是我们的主要工具之一。我们将在第三章 *Karma 方式*中详细了解 Karma。

## Protractor

Protractor 是一种端到端测试工具，允许开发人员模拟用户交互。它通过与 Web 浏览器的交互自动化功能和特性的测试。Protractor 具有特定的方法来帮助测试 Angular，但它们并不专属于 Angular。

使用 Protractor 的一些优点如下：

+   可配置以测试多个环境

+   与 Angular 轻松集成

+   语法和测试可以与选择的单元测试框架类似

使用 Protractor 的缺点：

+   它的文档和示例有限

对于本书中的示例的端到端测试，Protractor 将是我们的主要框架。Protractor 将在第四章 *使用 Protractor 进行端到端测试*中进一步详细介绍。

## 茉莉花

Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。它可以轻松集成和运行网站，并且与 Angular 无关。它提供间谍和其他功能。它也可以在没有 Karma 的情况下运行。在本章中，我们将学习 Jasmine 常用的内置全局函数的详细信息，并了解 Jasmine 测试套件如何满足 Web 应用程序的测试要求。此外，在整本书中，我们将使用 Jasmine 作为我们的测试框架。

使用 Jasmine 的一些优点如下：

+   与 Karma 的默认集成

+   提供额外的功能来辅助测试，如测试间谍、伪造和传递功能

+   清晰易读的语法，允许测试以与被测试行为相关的方式格式化

+   与多个输出报告器集成

以下是使用 Jasmine 的一些缺点：

+   运行测试时没有文件监视功能。这意味着测试必须在用户更改时重新运行。

+   所有 Protractor 方法和功能的学习曲线可能会很陡峭。

## 摩卡

Mocha 是最初为 Node.js 应用程序编写的测试框架，但它也支持浏览器测试。它与 Jasmine 非常相似，并且大部分语法都是相似的。Mocha 的主要区别在于它不能作为一个独立的测试框架运行--它需要一些插件和库来作为一个测试框架运行，而 Jasmine 是独立的。它更具可配置性和灵活性。

让我们讨论一些 Mocha 的优点：

+   易安装

+   有良好的文档可用

+   有几个报告者

+   与几个 node 项目插件相匹配

以下是一些缺点：

+   需要单独的插件/模块来进行断言、间谍等

+   需要额外的配置才能与 Karma 一起使用

## QUnit

QUnit 是一个强大、易于使用的 JavaScript 单元测试套件。它被 jQuery、jQuery UI 和 jQuery Mobile 项目使用，并且能够测试任何通用的 JavaScript 代码。QUnit 专注于在浏览器中测试 JavaScript，同时尽可能为开发人员提供便利。

QUnit 的一些优点：

+   易安装

+   有良好的文档可用

使用 QUnit 的一个缺点是：

+   主要为 jQuery 开发，不适合与其他框架一起使用

## Selenium

Selenium（[`www.seleniumhq.org/`](http://www.seleniumhq.org/)）自我定义如下：

> *"Selenium 自动化浏览器。就是这样！"*

浏览器的自动化意味着开发人员可以轻松地与浏览器交互。他们可以点击按钮或链接，输入数据等。Selenium 是一个强大的工具集，当正确使用和设置时，有很多好处；然而，设置它可能会令人困惑和繁琐。

Selenium 的一些优点如下：

+   大量功能集

+   分布式测试

+   通过服务如**Sauce Labs**（[`saucelabs.com/`](https://saucelabs.com/)）支持 SaaS

+   有文档和资源可用

以下是 Selenium 的一些缺点：

+   必须作为一个单独的进程运行

+   需要几个步骤来配置

由于 Protractor 是 Selenium 的一个包装器，因此不会详细讨论。

## PhantomJS

PhantomJS 是一个可编写 JavaScript API 的无头 WebKit 脚本。它对各种 Web 标准有*快速*和*本地*支持；DOM 处理、CSS 选择器、JSON、Canvas 和 SVG。PhantomJS 用于测试工作流程。

简而言之，PhantomJS 是一个无头运行的浏览器（即不会显示屏幕）。它带来的好处是速度--如果你在计算机上控制一个实际的程序，你会有一定的开销来启动浏览器，配置配置文件等。

PhantomJS 并不意味着取代测试框架；它将与测试框架一起使用。

# 选择权在我们手中

正如我们所见，有许多用于测试 JavaScript 项目的工具集和框架：

+   对于断言框架，我们将选择 Jasmine，因为 Angular 本身使用 Jasmine 作为断言；但在某些情况下，主要是对于 Node.js 项目，Mocha 也很有趣

+   只要我们专注于自动化测试套件，测试运行器对我们来说至关重要，当涉及到 Angular 项目时，没有什么可以与 Karma 相提并论

+   对于端到端测试，Protractor 是最好的框架，我们将在本章中使用它。

+   只要是端到端测试，它必须是自动化的，而 Selenium 就在这里为我们自动化浏览器。

+   重要的是要进行跨浏览器支持的测试，并且 PhantomJS 在这里为我们提供无头浏览器。

# 向 Jasmine 测试套件打招呼

只要我们必须使用测试框架来构建测试套件，所有框架上都有一些基本和常见的断言。重要的是要理解这些断言和间谍以及何时使用它们。

在本节中，我们将解释 Jasmine 的断言和间谍，因为 Jasmine 将是本书中的测试框架。

## 套件

任何测试套件都以全局的 Jasmine `describe`函数开始，该函数接收两个参数。第一个是字符串，第二个是函数。字符串是套件名称/标题，函数是将在套件中实现的代码块。

考虑以下例子：

```ts
describe("A sample test suite to test jasmine assertion", function() {  
   // .. implemented code block 
}); 

```

## 规范

任何使用 Jasmine 的全局`it`函数定义的规范，类似于接收两个参数的套件，第一个是字符串，第二个是函数。字符串是规范名称/标题，函数是规范中将要实现的代码块。看看以下例子：

```ts
describe("A sample test suite to test jasmine assertion", function() { 
    var a; 
    it("Title for a spec", function() { 
        // .. implemented code block 
    }); 
}); 

```

## 期望

任何使用`expect`函数定义的期望，该函数接收一个称为实际的参数值。该函数是一个与匹配器函数链接的链，该匹配器函数以预期值作为参数与实际值进行匹配。

有一些常用的匹配器；它们都在实际值和预期值之间实现布尔比较。通过将`expect`方法与`not`关键字链接，任何匹配器都可以评估负值。

一些常见的匹配器包括`toBe`，`toEqual`，`toMatch`，`toBeNull`，`toBeDefined`，`toBeUndefined`和`toContain`。

考虑给定的例子：

```ts
describe("A sample test suite to test jasmine assertion", function() {  
    var a, b; 
    it("Title for a spec", function() { 
        var a = true; 
        expect(a).toBe(true); 
        expect(b).not.toBe(true); 
    }); 
}); 

```

## 设置和拆卸

为了通过 DRY（不要重复自己）来改进测试套件，消除重复的设置和拆卸代码，Jasmine 提供了一些全局函数用于设置和拆卸。这些全局函数（`beforeEach`，`afterEach`等）如下所示，并且它们按照名称的意思运行。

每个函数都针对一个测试规范运行。Jasmine 的全局设置和拆卸函数是`beforeEach`，`afterEach`，`beforeAll`和`afterAll`。

考虑以下示例：

```ts
describe("A sample test suite to test jasmine assertion", function() { 
    var a=0;    
    beforeEach(function() { 
        a +=1; 
    }); 
    afterEach(function() { 
        a =0; 
    }); 
    it("Title for a spec 1", function() { 
        expect(a).toEqual(1); 
    }); 
    it("Title for a spec 2", function() { 
        expect(a).toEqual(1); 
        expect(a).not.toEqual(0); 
    }); 
}); 

```

## 间谍

间谍是 Jasmine 中的测试双函数；它们可以替换任何函数并跟踪对它及其所有参数的调用。有一些匹配器可以跟踪间谍是否被调用。这些是`toHaveBeenCalled`，`toHaveBeenCalledTimes`等。

有一些与间谍一起使用的有用的链式方法，比如`returnValue`/`returnValues`，它们将在调用时返回一个或多个值。还有一些类似的有用方法，比如`callThrough`，`call`，`stub`，`call.allArgs`，`call.first`和`call.reset`。

考虑以下示例：

```ts
describe("A sample test suite to test jasmine assertion", function() { 
    var myObj, a, fetchA; 
    beforeEach(function() { 
        myObj = { 
            setA: function(value) { 
                a = value; 
            }, 
            getA: function(value) { 
                return a; 
            }, 
        }; 
        spyOn(myObj, "getA").and.returnValue(789); 
        myObj.setA(123); 
        fetchA = myObj.getA(); 
    }); 

    it("tracks that the spy was called", function() { 
         expect(myObj.getA).toHaveBeenCalled(); 
    }); 
    it("should not affect other functions", function() { 
        expect(a).toEqual(123); 
    }); 
    it("when called returns the requested value", function() { 
        expect(fetchA).toEqual(789); 
    }); 
}); 

```

## Jasmine 的测试套件

在前面的部分中，我们查看了一些常用的断言，所有测试框架，包括 Jasmine，在任何类型的测试套件中都会使用。

尽管在本书中，我们将为 Angular 测试构建一个自动化测试套件，让我们在 Jasmine 测试套件中尝试一些断言，并看看它是如何工作的。这个示例测试套件将让我们亲身体验断言在测试套件中的工作方式。

对于这个测试套件，我们将使用 Jasmine 的示例规范运行器项目（该项目在 Jasmine 下载包中可用），项目的文件夹结构将如下所示：

![Jasmine 的测试套件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_02_001.jpg)

让我们快速看一下我们需要在 Jasmine 的示例`SpecRunner`项目中更新的文件：

```ts
SpecRunner.html: 
<!DOCTYPE HTML> 
<html> 
<head> 
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> 
    <title>Jasmine Spec Runner v2.4.1</title> 
    <link rel="shortcut icon" type="image/png" href="lib/jasmine-2.4.1/jasmine_favicon.jpg"> 
    <link rel="stylesheet" type="text/css" href="lib/jasmine-2.4.1/jasmine.css"> 

    <script type="text/javascript" src="lib/jasmine-2.4.1/jasmine.js"></script> 
    <script type="text/javascript" src="lib/jasmine-2.4.1/jasmine-html.js"></script> 
    <script type="text/javascript" src="lib/jasmine-2.4.1/boot.js"></script> 
    <!-- include source files here... --> 
    <script type="text/javascript" src="src/mySource.js"></script> 
    <!-- include spec files here... --> 
    <script type="text/javascript" src="spec/mySpec.js"></script> 
</head> 
<body> 
</body> 
</html> 

src/mySource.js: 
var a, 
myObj = { 
    setA: function(value) { 
        a = value; 
    }, 
    getA: function(value) { 
        return a; 
    }, 
}; 

Spec/mySpec.js: 
describe("A sample test suite to test jasmine assertion", function() { 
    var fetchA; 
    beforeEach(function() { 
        spyOn(myObj, "getA").and.returnValue(789); 
        myObj.setA(123); 
        fetchA = myObj.getA(); 
    }); 

    it("tracks that the spy was called", function() { 
         expect(myObj.getA).toHaveBeenCalled(); 
    }); 
    it("should not affect other functions", function() { 
        expect(a).toEqual(123); 
    }); 
    it("when called returns the requested value", function() { 
        expect(fetchA).toEqual(789); 
    }); 
}); 

```

只要它是基于浏览器的测试套件，我们就必须将`SpecRunner.html`指向一个 web 浏览器以获取测试结果。我们将通过所有测试，并且我们的测试结果将如下截图所示：

![Jasmine 的测试套件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_02_002-1.jpg)

# Angular 的 Jasmine 测试套件

在前面的例子中，我们看到了用于 JavaScript 测试的 Jasmine 测试套件，但是对于 Angular，应该如何呢？实际上，对于 Angular 项目测试套件，没有直接的答案；我们将不使用基于浏览器的测试套件，而是使用 Karma 作为测试套件的测试运行器。但是，由于我们在前面的例子中熟悉了基于浏览器的 Jasmine 测试套件，让我们看看如果我们为 Angular 项目制作一个类似的测试套件会是什么样子。

我们将不得不在 Angular 项目中添加一个名为`src`的子文件夹用于测试规范，然后项目的文件夹结构将如下所示：

![Angular 的 Jasmine 测试套件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_02_003.jpg)

### 注意

在 Angular 项目中，我们将使用 TypeScript 而不是纯 JavaScript，因为 Angular 官方建议使用 TypeScript。因此，我们希望大家都了解 TypeScript 的语法并知道如何编译成 JS。

在这本书中，对于 Angular 测试套件，我们将使用 SystemJS 作为模块加载器，因为 Angular 官方建议使用它；我们将看一下 SystemJS。

这个示例 Angular 测试套件只是为了展示我们如何轻松地为 Angular 项目制作一个测试套件，尽管它并没有遵循最佳实践和最佳的模块加载方式。

在第三章中，*Karma 方式*，我们将使用真实的例子更新这个测试套件，并使用 SystemJS 作为模块加载器。

在 GitHub 上，Angular 团队有一个名为`Angular2-seed`的种子项目，可以为任何 Angular 项目提供测试套件；我们将为我们真正的 Angular 项目遵循这个项目。

如果我们看一下文件夹结构，它几乎与之前的相同，规范文件中也有最少的更改；规范中唯一的变化是使用 TypeScript：

```ts
src/unit-tests.html: 

<!DOCTYPE html> 
<html> 
<head> 
    <meta http-equiv="content-type" content="text/html;charset=utf-8"> 
    <title>NG2 App Unit Tests</title> 
    <link rel="stylesheet" href="node_modules/jasmine-core/lib/jasmine-core/jasmine.css"> 
    <script src="node_modules/jasmine-core/lib/jasmine-core/jasmine.js"></script> 
    <script src="node_modules/jasmine-core/lib/jasmine-core/jasmine-html.js"></script> 
    <script src="node_modules/jasmine-core/lib/jasmine-core/boot.js"></script> 
    <script src="../app/mysource.js"></script> 
    <script src="my.spec.js"></script> 

</head> 
<body> 
</body> 
</html> 

app/mysource.ts: 
export class Source { 
    // ...  
} 

src/my.spec.ts: 
describe('1st tests', () => { 
    it('true is true', () => expect(true).toEqual(true)); 

    it('null is not the same thing as undefined', 
        () => expect(null).not.toEqual(undefined) 
    ); 
}); 

```

由于这也是一个基于浏览器的测试套件，我们必须在 Web 浏览器中指向`unit-tests.html`以获取测试结果。我们将通过所有测试，并且我们的测试结果将如下所示：

![Angular 的 Jasmine 测试套件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_02_004.jpg)

# 自测问题

自测问题将帮助您进一步测试您在 JavaScript 应用程序测试中使用 TDD 的知识。

Q1\. 端到端测试意味着什么样的测试？

+   功能测试

+   行为测试

Q2\. Protractor 是一个单元测试框架。

+   正确

+   错误

Q3\. PhantomJS 是一种类型的浏览器。

+   正确

+   错误

Q4\. QUnit 是用于什么样的测试框架？

+   jQuery

+   Angular

+   NodeJS

Q5\. 设置和拆卸是 Jasmine 的一个特性。

+   正确

+   错误

# 总结

在本章中，我们回顾了 TDD 的不同测试机制，并介绍了自动化测试。我们回顾了不同类型的 JavaScript 测试框架和工具，并审查了这些框架的优缺点。我们还回顾了 Jasmine 的一些常见断言，并尝试亲自动手看它们是如何工作的。

在下一章中，我们将学习关于 Karma，并了解它如何与 Angular 测试套件配合使用。


# 第三章：Karma 的方式

由于 Karma，JavaScript 测试已经成为主流。Karma 使 JavaScript 测试变得无缝。Angular 是围绕测试创建的。

在本章中，我们将学习关于 Karma 的一些东西，包括以下内容：

+   Karma 的起源

+   为什么以及如何 Karma 将与 Angular 项目一起工作

+   在 Angular 项目中的 Karma 配置和实现

+   Travis CI 概述

# Karma 的诞生

在使用新工具时，了解其来源和构建原因非常重要。本节将为我们提供 Karma 起源的背景。

## Karma 的区别

Karma 是由 Vojta Jína 创建的。该项目最初被称为 Testacular。在 Vojtech Jína 的论文中，他讨论了 Karma 的设计、目的和实现。

在他的论文（JavasScript Test Runner，[`github.com/karma-runner/karma/raw/master/thesis.pdf`](https://github.com/karma-runner/karma/raw/master/thesis.pdf)）中，他描述了 Karma 如下：

> “……一个测试运行器，可以帮助 Web 应用程序开发人员通过使自动化测试更简单和更快速来提高生产力和效率。事实上，我有更高的抱负，这篇论文只是其中的一部分 - 我想推广测试驱动开发（TDD）作为开发 Web 应用程序的“方式”，因为我相信这是开发高质量软件的最有效方式。”

Karma 具有在真实浏览器上轻松自动运行 JavaScript 单元测试的能力。传统上，测试是通过手动启动浏览器并不断点击刷新按钮来进行的。这种方法很笨拙，通常会导致开发人员限制编写的测试数量。

使用 Karma，开发人员几乎可以在任何标准测试框架中编写测试，选择要运行的浏览器，设置要监视更改的文件，然后就可以进行持续的自动化测试了。我们只需简单地检查输出窗口以查看测试是失败还是通过。

## 结合 Karma 和 Angular 的重要性

Karma 是为 AngularJS 构建的。在 Karma 之前，缺乏面向 Web 的 JavaScript 开发人员的自动化测试工具。

记住，Karma 是一个测试运行器，而不是一个测试框架。它的工作是运行测试并报告哪些测试将通过或失败。为什么这有帮助呢？测试框架是你将编写测试的地方。除了这样做，你还需要专注于轻松运行测试并查看结果。Karma 可以轻松地在多个不同的浏览器上运行测试。它还具有一些其他功能，比如文件监视，这将在本书的后面详细讨论。

# 安装 Karma

是时候开始使用 Karma 了。安装和应用程序不断变化。以下指南旨在简要介绍；你可以去 Karma 网站[`karma-runner.github.io/`](http://karma-runner.github.io/)查找最新的说明。

本节的主要重点将是本书中使用的特定配置，而不是深入的安装指南。

## 安装前提条件

要安装 Karma，我们需要在计算机上安装 Node.js。Node.js 在 Google 的 V8 引擎上运行，并允许 JavaScript 在多个操作系统上运行。

开发人员可以使用**NPM**（**Node Package Manager**）发布节点应用程序和模块。NPM 允许开发人员快速将应用程序和模块集成到他们的应用程序中。

Karma 通过`npm`包运行和安装；因此，在使用或安装 Karma 之前，我们需要 Node.js。要安装 Node.js，请转到[`nodejs.org/`](http://nodejs.org/)并按照安装说明进行操作。

一旦我们安装了 Node.js，让我们在命令提示符中输入以下命令来安装 Karma：

```ts
**$ npm install karma -g**

```

上述命令使用`npm`全局安装 Karma 使用`-g`。这意味着我们可以在命令提示符中简单地输入以下内容来使用 Karma：

```ts
**$ karma --version**

```

默认情况下，安装 Karma 将安装`karma-chrome-launcher`和`karma-jasmine`作为依赖项。确保这些模块也全局安装。

# 配置 Karma

Karma 配备了一个自动创建配置文件的方法。要使用自动方式，请输入以下命令：

```ts
**$ karma init**

```

以下是所选选项的示例：

![配置 Karma](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_03_001.jpg)

## 自定义 Karma 的配置

以下说明描述了为项目运行 Karma 所需的特定配置。自定义包括测试框架（Jasmine）、要测试的浏览器（Chrome）和要测试的文件。要自定义配置，请打开`karma.conf.js`并执行以下步骤：

1.  确保启用的框架使用以下代码说`jasmine`：

```ts
        frameworks: ['jasmine'], 

```

1.  配置`test`目录。请注意，以下定义需要包括需要运行的测试以及可能的任何依赖项。将保存我们的测试的目录是`/test/unit/`：

```ts
        files: [ 
            'test/unit/**/*.js' 
        ], 

```

1.  将测试浏览器设置为 Chrome，如下所示。然后它将被初始化，并且在每个测试后都会弹出一个弹窗：

```ts
        browsers: ['Chrome'], 

```

## 确认 Karma 的安装和配置

要确认 Karma 的安装和配置，请执行以下步骤：

1.  运行以下命令确认 Karma 启动时没有错误：

```ts
        **$ karma start**

```

1.  输出应该是这样的：

```ts
        **$ INFO [karma]: Karma v0.12.16 server started at 
        http://localhost:9876/**

```

1.  除此之外，输出应该指出没有找到测试文件：

```ts
        **$ WARN [watcher]: Pattern "test/unit/**/*.js" does not
        match any file.**

```

输出应该这样做，还有一个失败的测试消息：

```ts
        **$ Chrome 35.0.1916 (Windows 7): Executed 0 of 0 ERROR
        (0.016 secs / 0 secs)**

```

### 注意

一个重要的要点是，我们需要在系统上全局安装`jasmine-core`，否则 Karma 将无法成功运行。

这是预期的，因为还没有创建测试。如果 Karma 启动，请继续下一步，我们将看到我们的 Chrome 浏览器显示以下输出：

![确认 Karma 的安装和配置](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_03_002.jpg)

## 常见的安装/配置问题

如果缺少 Jasmine 或 Chrome Launcher，请执行以下步骤：

1.  运行测试时，可能会出现错误，提示**缺少 Jasmine 或 Chrome Launcher**。如果出现此错误，请输入以下命令安装缺少的依赖项：

```ts
        **$ npm install karma-jasmine -g**
        **$ npm install karma-chrome-launcher -g**

```

1.  重试测试并确认错误已经解决。

在某些情况下，您可能无法使用`-g`命令全局安装`npm_modules`。这通常是由于计算机上的权限问题。以下是您需要做的以提供权限（sudo/administrator）：

1.  解决方法是直接在项目文件夹中安装 Karma。使用相同的命令而不带`-g`来执行此操作：

```ts
                **$ npm install karma**

```

1.  使用相对路径运行 Karma：

```ts
                **$ ./node_modules/karma/bin/karma --version**

```

现在 Karma 已安装并运行，是时候投入使用了。

# 使用 Karma 进行测试

在本节中，我们将创建一个测试来确认 Karma 是否按预期工作。为此，请执行以下步骤：

1.  创建测试目录。在 Karma 配置中，测试被定义在以下目录中：

```ts
        files: [ 
               'test/unit/**/*.js' 
           ], 

```

1.  继续创建`test/unit`目录。

1.  在`test/unit`目录中创建一个新的`firstTest.js`文件。

1.  编写第一个测试如下：

```ts
        describe('when testing karma', function (){ 
          it('should report a successful test', function (){ 
            expect(true).toBeTruthy(); 
              }); 
        }); 

```

前面的测试使用了 Jasmine 函数，并具有以下属性：

+   `describe`：这提供了测试套件的简短字符串描述，即将被测试的东西。

+   `it`：这提供了一个特定断言的简短字符串，称为测试规范

+   `expect`：这提供了一种断言值的方式

+   `toBeTruthy`：这是期望的几个属性之一，可用于进行断言

这个测试除了确认通过测试的输出之外没有任何实际价值。

砰！让我们检查一下控制台窗口，看看 Karma 是否执行了我们的测试。我们的命令行应该显示类似于这样的内容：

```ts
**$ INFO [watcher]: Added file "./test/unit/firstTest.js"**

```

这个输出意味着 Karma 自动识别到有一个新文件被添加了。接下来的输出应该是这样的：

```ts
**$ Chrome 35.0.1916 (Windows 7): Executed 1 of 1 SUCCESS (0.02 secs 
    / 0.015 secs)**

```

这意味着我们的测试已经通过了！

# 确认 Karma 的安装

现在，Karma 的初始设置和配置已经完成。以下是步骤的回顾：

1.  我们通过`npm`命令安装了 Karma。

1.  我们通过`karma init`命令初始化了一个默认配置。

1.  接下来，我们用 Jasmine 和一个`test/unit`测试目录配置了 Karma。

1.  我们启动了 Karma，并确认它可以在 Chrome 中打开。

1.  然后，我们在`test/unit`测试目录中添加了一个 Jasmine 测试`firstTest.js`。

1.  Karma 认识到`firstTest.js`已经被添加到了测试目录中。

1.  最后，Karma 执行了我们的`firstTest.js`并报告了我们的输出。

通过几个步骤，我们能够看到 Karma 自动运行和执行测试。从 TDD 的角度来看，我们可以专注于将测试从失败转移到通过，而不需要太多的努力。无需刷新浏览器；只需检查命令输出窗口。保持 Karma 运行，所有的测试和文件都将自动添加和运行。

在接下来的章节中，我们将看到如何将 Karma 与 TDD 方法相结合。如果你对 Karma 目前还可以，并且想继续使用 Protractor，请跳到下一章。

# 使用 Karma 与 Angular

在这里，我们将演示如何对 Angular 组件进行 TDD 方法的实践。在本章结束时，我们应该能够做到以下几点：

+   对使用 Karma 及其配置感到自信

+   了解 Jasmine 测试的基本组件

+   开始理解如何在 Angular 应用程序中集成 TDD 方法

## 获取 Angular

通过 Bower 无法安装 Angular；与 Angular1 不同，它必须通过 npm 安装。引导 Angular 应用程序不像 Angular1 那样简单，因为 Angular 不使用普通的 JavaScript。它使用 TypeScript 或 ES6（ES2015），这两者在运行之前都需要编译为普通的 JavaScript。

我们相信大多数开发人员已经了解了 Angular 的变化以及它的编译工作原理。简单回顾一下--在这里，我们将在我们的 Angular 示例项目中使用 TypeScript，因为 Angular 建议使用它，尽管也有使用 ES6 的选项。我们将使用 node/npm tsc 模块将 TypeScript 编译为普通的 JavaScript；node/npm 也将是我们的 CLI 工具，用于构建/启动项目和运行测试。

这里需要对 node/npm 模块有基本的了解，特别是 npm 命令的工作原理。

### Angular 项目

我们不会演示如何安装 Angular 以及如何从头开始构建项目，因为 Angular 文档网站已经很好地展示了这一点。因此，我们将从 Angular 团队的示例中获取一个简单的 Angular 项目，并为我们的实现更新它。

我们将从 Angular GitHub 仓库克隆`quickstart`项目，并从那个项目开始。希望除了 node/npm 之外，我们都已经全局安装了`git`。

```ts
**$ git clone https://github.com/angular/quickstart.git angular-
    karma**

```

这将把项目本地复制为`angular-karma`，文件夹结构将如图所示：

![Angular 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_03_003.jpg)

让我们继续进行并准备运行：

```ts
**$ cd angular-karma**
**$ npm install**

```

以下是准备示例项目的几个步骤。`npm install`命令将安装在项目根目录的`package.json`文件中定义的项目依赖的所需模块。

然后，我们将使用`npm start`来运行项目；在`package.json`中定义的这个脚本用于在本地服务器上运行项目。

让我们编译并运行项目：

```ts
**$ npm start**

```

如果所有必需的依赖都已安装，此命令将把 TypeScript 编译为普通的 JavaScript，并在本地服务器上运行项目。

项目将在浏览器中启动，并将如下所示：

![Angular 项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_03_004.jpg)

如果这个示例项目成功运行，那么我们就可以进行下一步了，在下一步中，我们将添加一个测试规范，其中将包括 Karma，并使用 Karma 运行这些测试。

### 准备工作

当我们克隆了示例`quickstart`项目时，它已经在项目中集成和配置了 Karma。为了学习的目的，我们想要在现有项目中集成 Karma。

为此，我们将不得不从项目根目录中删除现有的`karma.conf.js`文件。此外，我们还将从`node_modules`中删除 Karma、Jasmine 和相关模块。

有趣的是，我们可以通过一个简单的命令轻松创建基本的 Karma 配置文件，而不是手动操作。而且通过这个命令，它会询问一些基本问题，就像我们在本章的前一部分看到的那样。

## 设置 Karma

在 Angular 项目中设置 Karma，第一步是在项目根目录创建一个`karma.conf.js`文件。这个文件基本上包含一些键值对的配置。

有趣的是，我们可以通过一个简单的命令轻松创建基本的 Karma 配置文件。通过这个命令，它会询问一些基本问题，就像我们在本章的前一部分看到的那样：

```ts
**$ karma init**

```

使用默认答案。在当前目录创建了`karma.conf.js`之后，打开配置。可能需要更改一些配置，主要是 Karma 要使用的文件的定义。

在`files`部分使用以下定义，定义运行测试所需的文件：

```ts
files: [ 
        // System.js for module loading 
      'node_modules/systemjs/dist/system.src.js', 

      // Polyfills 
      'node_modules/core-js/client/shim.js', 
      'node_modules/reflect-metadata/Reflect.js', 

      // zone.js 
      'node_modules/zone.js/dist/zone.js', 
      'node_modules/zone.js/dist/long-stack-trace-zone.js', 
      'node_modules/zone.js/dist/proxy.js', 
      'node_modules/zone.js/dist/sync-test.js', 
      'node_modules/zone.js/dist/jasmine-patch.js', 
      'node_modules/zone.js/dist/async-test.js', 
      'node_modules/zone.js/dist/fake-async-test.js', 

// RxJs 
      { pattern: 'node_modules/rxjs/**/*.js', included: false,
      watched: false },      { pattern: 'node_modules/rxjs
      /**/*.js.map', included: false,        watched: false }, 

// Angular itself 
      { pattern: 'node_modules/@angular/**/*.js', included: 
      false,        watched: false }, 

{ pattern: 'systemjs.config.js', included: false, watched: false }, 
      { pattern: 'systemjs.config.extras.js', included: false,   
      watched: false }, 
      'karma-test-shim.js', 

          {pattern: 'app/**/*.js', included: false, watched: true} 
    ] 

```

### 注意

在这里，通过模式，我们传递了两个选项，`included`和`watched`。`included`指的是我们是否想要使用`<script>`标签包含文件；在这里，我们将通过 SystemJS 添加它，所以传递为`false`。`watched`指的是文件在更改时是否会被监视。我们设置为`true`，因为我们想要监视这些更改。

似乎添加了很多文件，但这些是运行测试的基本必需品。

让我们仔细看看这些文件是什么。在第一部分，这些主要是库文件，包括 SystemJS 作为模块加载器，zonejs 作为同步处理程序，RxJS 作为响应式库，以及 Angular 库本身。

重要的是，第二部分中的一个新文件是`karma-test-shim.js`，我们需要在测试套件中与 Karma 一起使用作为模块加载器，也就是说，使用 SystemJS 在 Karma 测试运行器中加载模块。我们将在本节后面看一下那个文件。

然后，这是我们所有的应用程序源文件；我们也会把测试/规范文件放在同一个目录下，这样它们就会加载所有的模块文件，包括它们的测试/规范文件。

除了文件之外，根据需求，我们可能需要更改一些配置点，如下所示：

+   `plugins`：这是必需的，因为 Karma 将使用这些`npm`模块来执行。如果我们计划使用更多的`npm`模块，我们需要在这里添加它们；例如，如果我们计划将 PhantomJS 作为我们的浏览器使用，我们需要在列表中添加`'karma-phantomjs-launcher'`：

```ts
        plugins: [ 
'karma-jasmine', 
'karma-chrome-launcher' 
   ] 

```

+   `frameworks`：目前不需要更改这个，因为默认情况下它选择 Jasmine；但是，如果我们计划使用其他框架，比如 Mocha，那么应该更新以下选项：

```ts
        frameworks: ['jasmine'], 

```

+   `browsers`：当我们需要在多个浏览器中运行测试时，这是有用的，大多数情况下，我们可能需要在 PhantomJS 中运行测试，因此我们可以添加多个浏览器，如下所示：

```ts
        browsers: ['Chrome', 'PhantomJS'] 

```

到目前为止，这些是我们在`karma.con.js`文件中需要的基本更改。

让我们来看看我们的`karma.conf.js`文件，看看它是什么样子的：

```ts
module.exports = function(config) { 

  config.set({ 
    basePath: '', 
    frameworks: ['jasmine'], 
    plugins: [ 
      require('karma-jasmine'), 
      require('karma-chrome-launcher') 
    ], 

    files: [ 
      // System.js for module loading 
      'node_modules/systemjs/dist/system.src.js', 

      // Polyfills 
      'node_modules/core-js/client/shim.js', 
      'node_modules/reflect-metadata/Reflect.js', 

      // zone.js 
      'node_modules/zone.js/dist/zone.js', 
      'node_modules/zone.js/dist/long-stack-trace-zone.js', 
      'node_modules/zone.js/dist/proxy.js', 
      'node_modules/zone.js/dist/sync-test.js', 
      'node_modules/zone.js/dist/jasmine-patch.js', 
      'node_modules/zone.js/dist/async-test.js', 
      'node_modules/zone.js/dist/fake-async-test.js', 

      // RxJs 
      { pattern: 'node_modules/rxjs/**/*.js', included: false,
      watched: false },     
      { pattern: 'node_modules/rxjs/**/*.js.map', included: 
      false,        watched: false }, 

      // Paths loaded via module imports: 
      // Angular itself 
      { pattern: 'node_modules/@angular/**/*.js', included: 
      false,        watched: false },
      { pattern: 'node_modules/@angular/**/*.js.map', included: 
      false, watched: false },
      { pattern: 'systemjs.config.js', included: false, 
      watched:        false },
      { pattern: 'systemjs.config.extras.js', included: false,
      watched: false },

      'karma-test-shim.js', 

      { pattern: 'app/**/*.js', included: false, watched: true } 
    ], 

    port: 9876, 
    colors: true, 
    autoWatch: true, 
    browsers: ['Chrome'], 
    singleRun: false 
  }) 
}
```

我们在文件列表中添加的另一个重要文件是`karma-test-shim.js`；正如我们之前提到的，这对我们使用 SystemJS（模块加载器）与 Karma 是必需的。我们从 Angular 快速启动项目中复制了该文件，根据项目结构可能需要进行更改。

让我们来看看我们的`karma.conf.js`文件：

```ts
Error.stackTraceLimit = 0; // "No stacktrace"" is usually best for app testing. 

jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000; 

var builtPath = '/base/app/'; 

__karma__.loaded = function () { }; 

function isJsFile(path) { 
  return path.slice(-3) == '.js'; 
} 

function isSpecFile(path) { 
  return /\.spec\.(.*\.)?js$/.test(path); 
} 

function isBuiltFile(path) { 
  return isJsFile(path) && (path.substr(0, builtPath.length) == 
  builtPath); 
} 

var allSpecFiles = Object.keys(window.__karma__.files) 
  .filter(isSpecFile) 
  .filter(isBuiltFile); 

System.config({ 
  baseURL: 'base', 
  // Extend usual application package list with test folder 
  packages: { 'testing': { main: 'index.js', defaultExtension: 'js' 
  } }, 

  // Assume npm: is set in `paths` in systemjs.config 
  // Map the angular testing umd bundles 
  map: { 
    '@angular/core/testing':      
'npm:@angular/core/bundles/core-testing.umd.js',    
'@angular/common/testing':      
'npm:@angular/common/bundles/common-testing.umd.js',    
'@angular/compiler/testing':      
'npm:@angular/compiler/bundles/compiler-testing.umd.js',    
'@angular/platform-browser/testing':      
'npm:@angular/platform-browser/bundles/     
platform-browser-testing.umd.js',    
'@angular/platform-browser-dynamic/testing':      'npm:@angular/platform-browser-dynamic/bundles    
 /platform-browser-dynamic-testing.umd.js',    
'@angular/http/testing':      
'npm:@angular/http/bundles/http-testing.umd.js',    
'@angular/router/testing':      
'npm:@angular/router/bundles/router-testing.umd.js',    
'@angular/forms/testing':      
'npm:@angular/forms/bundles/forms-testing.umd.js', 
  }, 
}); 

System.import('systemjs.config.js') 
  .then(importSystemJsExtras) 
  .then(initTestBed) 
  .then(initTesting); 

/** Optional SystemJS configuration extras. Keep going w/o it */ 
function importSystemJsExtras(){ 
  return System.import('systemjs.config.extras.js') 
  .catch(function(reason) { 
    console.log( 
      'Warning: System.import could not load the optional        "systemjs.config.extras.js". Did you omit it by accident?        Continuing without it.' 
    ); 
    console.log(reason); 
  }); 
} 

function initTestBed(){ 
  return Promise.all([ 
    System.import('@angular/core/testing'), 
    System.import('@angular/platform-browser-dynamic/testing') 
  ]) 

  .then(function (providers) { 
    var coreTesting    = providers[0]; 
    var browserTesting = providers[1]; 

    coreTesting.TestBed.initTestEnvironment( 
      browserTesting.BrowserDynamicTestingModule, 
      browserTesting.platformBrowserDynamicTesting()); 
  }) 
} 

// Import all spec files and start karma 
function initTesting () { 
  return Promise.all( 
    allSpecFiles.map(function (moduleName) { 
      return System.import(moduleName); 
    }) 
  ) 
  .then(__karma__.start, __karma__.error); 
} 

```

### 测试 Karma 运行器

Karma 的初始设置几乎完成了；我们将不得不运行我们的测试并查看它的进展。在我们运行之前还有一步--我们必须在`npm`脚本中添加`karma`任务以通过`npm`命令运行。为此，我们将不得不在`package.json`文件的脚本部分中添加一个名为`test`的任务。

```ts
"scripts": { 
     "test": "karma start karma.conf.js" 
  } 

```

在添加了这个片段之后，我们可以通过`npm`运行测试，使用`npm test`，这与`karma start`的方式相同：

```ts
**$ npm test**

```

因此，最终，我们准备通过 Karma 运行我们的测试。然而，糟糕，我们遇到了一些错误！它缺少运行测试所需的`jasmine-core`模块；实际上，可能还缺少更多的模块。

带有错误的输出如下：

![测试 Karma 运行器](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_03_005.jpg)

是的，我们确实缺少模块，这些实际上是我们测试套件中的开发依赖项。我们将在下一节中更多地了解它们。

### 缺少的依赖项

尽管我们正在为 Angular 构建一个基本的测试套件，但我们仍然缺少一些必需的 npm 模块，这些是我们测试套件的开发依赖项，如下所示：

+   `jasmine-core`：这表明 Jasmine 是我们的测试框架

+   `karma`：这是我们测试套件的 Karma 测试运行程序

+   `karma-chrome-launcher`：这是从 Karma 启动 Chrome 所需的，因为我们在`karma.config`中定义了 Chrome 作为我们的浏览器

+   `karma-jasmine`：这是 Jasmine 的 Karma 适配器

只要这些是依赖项，我们应该安装这些模块并在`package.json`中包含它们。

我们可以一起安装所有这些，如下所示：

```ts
**$ npm install jasmine-core karma karma-chrome-launcher karma-
    jasmine --save-dev**

```

成功安装所有必需的依赖项后，我们似乎已经完成了配置过程，准备再次运行`test`：

```ts
**$ npm test**

```

命令输出应该像这样：

```ts
**$ Chrome 39.0.2623 (Mac OS X 10.10.5): Executed 0 of 0 ERROR 
    (0.003 secs / 0 secs)** 

```

就是这样。Karma 现在正在为第一个 Angular 应用程序运行。

# 使用 Angular 和 Karma 进行测试

使用 Karma 进行的第一个测试的目的是创建一个动态的待办事项清单。这个演练将遵循我们在第一章中讨论的 TDD 步骤，*测试驱动开发简介*：先测试，使其运行，然后改进。这将使我们能够在 Angular 应用程序中使用 TDD 获得更多经验。

## 一个开发待办事项清单

在开始测试之前，让我们把注意力集中在使用开发待办事项清单需要开发的内容上。这将使我们能够组织我们的想法。

这是待办事项清单：

+   **维护项目列表**：示例列表包括 test，execute 和 refactor

+   **向列表中添加项目**：添加项目后的示例列表是 test，execute，refactor 和 repeat

+   **从列表中删除项目**：添加和删除项目后的示例列表是 test，execute 和 refactor

## 测试项目列表

第一个开发项目是为我们提供在组件上有一个项目列表的能力。接下来的几个步骤将引导我们通过使用 TDD 生命周期添加第一个功能的 TDD 过程。

### 先测试

确定从哪里开始通常是最困难的部分。最好的方法是记住三个**A**（**组装**，**行动**和**断言**）并从基本的 Jasmine 模板格式开始。要做到这一点的代码如下：

```ts
describe('Title of the test suite', () => { 
    beforeEach(() => { 
        // .... 
    }); 

    it('Title of the test spec', () => { 
        // .... 
    }); 
}); 

```

让我们来看一下解释：

+   `describe`：这定义了我们正在测试的主要功能。字符串将以可读的方式解释该功能，然后函数将遵循测试。

+   `beforeEach`：这是组装步骤。在这一步中定义的函数将在每次断言之前执行。最好在这个函数中放置每个测试之前所需的测试设置。

+   `it`：这是行动和断言步骤。在`it`部分，我们将执行正在测试的操作，然后进行一些断言。行动步骤不必进入`it`函数。根据测试的需要，它可能更适合在`beforeEach`函数中。

### 三个 A - 组装，行动和断言

现在模板准备好了，我们可以开始拼凑这些部分。我们将再次遵循三个 A 的原则。

以下是组装部分的两个部分。

在第一部分中，我们初始化组件并使用以下代码执行类的构造函数：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing'; 

import { AppComponent } from './app.component'; 

beforeEach(async(() => { 
   TestBed.configureTestingModule({ 
      declarations: [ AppComponent ] 
    }) 
    .compileComponents(); 
  })); 

beforeEach(() => { 
    fixture = TestBed.createComponent(AppComponent); 
    comp = fixture.componentInstance; 
}); 
... 

```

在这里，我们导入了一些 Angular 测试 API，例如`async`和`Testbed`。在这里，`async`用于加载所需的模块以为测试套件引导应用程序，`TestBed`是编写 Angular API 单元测试的主要 API。它具有一些服务，用于在测试套件中创建，编译和初始化组件。

我们还没有定义`AppComponent`组件，但我们会在获得失败的测试之后这样做。

第二部分讨论了`AppComponent`对象。`AppComponent`对象将在其`this`变量上包含项目列表。添加以下代码到`beforeEach`以获取组件对象：

```ts
// comp will hold the component object  
let comp: AppComponent; 
let fixture: ComponentFixture<AppComponent>; 
beforeEach(() => { 
    fixture = TestBed.createComponent(AppComponent); 
    comp = fixture.componentInstance; 
}); 

```

在断言中，再次有两个部分：

第一个断言是确保`AppComponent`对象具有定义为三个项目的`items`变量。`items`变量将用于保存所有项目的列表：

```ts
it('Should define a list object', () => { 
        expect(com.items).toBeDefined(); 
    }); 

```

第二和第三个断言将用于确认列表中的数据是否正确：

```ts
//Second test 
it('Should have 3 items in list', () => { 
        expect(com.items.length).toBe(3); 
    }); 

//Third test 
it('List items should be as expected', () => { 
        expect(com.items).toEqual(['test','execute','refactor']); 
    }); 

```

就是这样；第一个是测试，第二个是执行，第三个是重构。

### 使其运行

TDD 生命周期中的下一步是使应用程序运行并修复代码，以使测试通过。记住，考虑可以添加的最小组件，以便通过以下步骤进行测试：

1.  通过输入以下命令来运行 Karma 测试：

```ts
**$ npm start**
**$ npm test**

```

1.  如果我们遇到`TypeError: app_component_1.AppComponent is not a constructor`错误，那么可能是由于以下原因：

+   前面的错误消息表明`AppComponent`对象尚未定义。由于错误消息告诉我们需要什么，这是开始的完美地方。

1.  将`AppComponent`类添加到`app.component.ts`文件中，如下所示：

```ts
        export class AppComponent { };
```

1.  再次从`npm`控制台运行`start`和`test`命令。现在我们应该看到一个新的错误。**错误：**`预期的未定义为以下定义`

+   新的错误消息再次很清晰。我们还可以看到，代码现在已经通过了我们在以下位置的断言点：

```ts
               expect(com.items).toBeDefined();
```

+   由于对象中没有项目，我们需要添加一个。更新`app/app.component.ts`文件如下：

```ts
              export class AppComponent { 
                  items:Array<string>; 
              }; 

```

1.  让我们再次从`npm`控制台运行`start`和`test`命令。现在我们应该看到三个测试中的一个通过了！这意味着我们成功地使用了 TDD 和 Karma 来使我们的第一个测试通过了。现在，我们需要修复其他三个。

+   下一个错误是：`预期的 0 等于 3`

+   错误输出再次准确描述了需要发生的事情。我们只需要用元素测试、执行和运行初始化数组。让我们去`app/app.component.ts`并将数据添加到数组初始化：

```ts
            export class AppComponent { 
                items:Array<string>; 
                constructor() { 
                    this.items = ['test','execute','refactor']; 
                } 
            }; 

```

1.  再次从 npm 控制台运行`start`和`test`命令。太棒了！输出是绿色的，并且声明所有测试都通过了。此步骤的结果组件和类代码如下：

```ts
        import {Component} from '@angular/core'; 

        @Component({ 
            // ...  
        }) 

        export class AppComponent { 
            items:Array<string>; 
            constructor() { 
                this.items = ['test','execute','refactor']; 
            } 
        }; 

```

现在*使其运行*步骤完成了，我们可以继续下一步，使其更好。

### 使其更好

到目前为止，没有直接重构或在开发待办事项列表中标识的内容。对开发待办事项列表的审查显示可以划掉一个项目：

+   查看待办事项列表：示例列表包括测试、执行和重构

+   **向待办事项列表添加项目**：在添加项目后的示例列表将包括测试、执行、重构和新项目

接下来的要求是向列表中添加一个新项目。将再次遵循 TDD 节奏：先测试，使其运行，然后使其更好。

## 向组件类添加一个函数

下一个任务是赋予类添加项目到对象的能力。这将需要向对象添加一个方法。这个演练将遵循我们之前遵循的相同的 TDD 步骤。

### 首先测试

不要创建新文件并复制一些组装步骤，而是将以下测试插入到最后一个`it`方法下。原因是将使用相同的模块和控制器：

```ts
describe('Title of the test suite', () => { 
    let app:AppComponent; 

    beforeEach(() => { 
        // .... 
    }); 

    it('Title of the test spec', () => { 
        // .... 
    }); 

    describe('Testing add method', () => { 

    beforeEach(() => { 
        // .... 
    }); 

    it('Title of the test spec', () => { 
        // .... 
    }); 
   }); 
}); 

```

### 三个 A - 组装、行动和断言

现在模板准备好了，我们可以开始使用 3A 法则填补空白：

+   组装：组件和对象将被继承，无需初始化或设置。

+   **行动**：在这里，我们需要对`add`方法进行操作，添加一个新项目。我们将`act`函数放入`beforEach`函数中。这样可以在添加更多测试时重复相同的步骤：

```ts
        beforeEach(() => { 
             com.add('new-item') 
        }); 

```

+   **断言**：在这里，应该向列表中添加一个项目，然后确认数组中的最后一个项目是否符合预期：

```ts
        it('Should have 4 items in list', () => { 
             expect(com.items.length).toBe(4); 
        }); 
        it('Should add a new item at the end of list', () => { 
            var lastIndexOfList = com.items.length - 1; 
            expect(com.items[lastIndexOfList]).toEqual('new-item'); 
        }); 

```

### 使其运行

TDD 生命周期中的下一步是使其运行。记住，考虑可以添加以使测试通过的最小组件，如下所示：

+   确保 Karma 在我们的控制台中运行，方法是输入以下命令：

```ts
**$ npm start**
**$ npm test**

```

+   第一个错误将声明`TypeError: undefined is not a function`。

此错误是指以下代码行：

```ts
        app.add('new-item'); 

```

错误告诉我们`add`方法尚未定义。`add`函数将需要添加到`app/app.component.ts`代码中。类已经定义，因此需要将`add`函数放入类中：

```ts
        add() { 
                this.items.push('new-item'); 
        }; 

```

请注意，`add`函数不包含任何逻辑。已添加了最小的组件以使测试满足错误消息。

+   在控制台窗口查看下一个错误。

成功！现在所有五个测试都已通过。

为了使测试通过，添加的代码如下所示：

```ts
import {Component} from '@angular/core'; 

@Component({ 
    selector: 'my-app', 
    template: `<h3>MY Items</h3><ul><li *ngFor="let item of items">{{ 
    item }}</li></ul>` 
}) 

export class AppComponent { 
    items:Array<string>; 
    constructor() { 
        this.items = ['test','execute','refactor']; 
    } 
    add() { 
        this.items.push('new-item'); 
    } 
}; 

```

### 使其更好

我们需要重构的主要问题是`add`函数仍未完全实现。它包含一个硬编码的值，一旦我们将不同的项目发送到`add`函数中，测试就会失败。

保持 Karma 运行，以便在进行更改时继续通过测试。当前`add`方法的主要问题如下：

+   它不接受任何参数

+   它不会将参数推送到列表中，而是使用硬编码的值

现在，生成的`add`函数应如下所示：

```ts
        add(item) { 
            this.items.push(item); 
        }; 

```

再次从`npm`控制台运行`start`和`test`命令。确认 Karma 输出仍然显示`SUCCESS`：

```ts
**$ Chrome 49.0.2623 (Mac OS X 10.10.5): Executed 5 of 5 SUCCESS
    (0.016 secs / 0.002 secs)**

```

# 配置 Karma 与 Travis CI

**持续集成**（**CI**）是开发实践，开发人员需要将代码集成到共享存储库中。它在代码库发生任何更改时在自动化构建过程中运行测试。这可以在推送到生产环境之前及早检测到错误。有许多 CI 服务，包括 Travis CI、Jenkin CI、Circle CI 等。

在本节中，我们将看到如何将 Karma 与 Travis 集成。

## Travis CI

Travis CI 是一个流行的托管式持续集成平台，它与 GitHub 项目/仓库集成，可以在代码库的任何分支中的每次更改或者拉取请求时自动运行测试。只需在项目根目录中放置一个`.travis.yml`文件，其中包含有关项目的一些配置信息，就可以轻松获得集成系统。

那么，我们可能会问，为什么选择 Travis？还有其他几个 CI 服务。如果我们将 Travis 与其他 CI 服务进行比较，它比其他服务有一些优势：

+   这是一个托管服务；无需主机、安装和配置

+   它是免费和开源的

+   它为每个分支都有单独的测试代码，因此很容易为单个分支运行测试

## 配置 Travis

正如我们所说，我们将在项目目录中有一个`.travis.yml`文件，其中包含有关我们的项目的一些配置和信息。

以下是 YAML 文件中的基本配置：

+   **指定语言**：我们在这里使用了 Node.js：

```ts
        language: node_js 
        node_js: 
            -  "4" 

```

+   **命令或脚本**：这是在每次构建之前或之后运行的必需内容；如下所示，此脚本将在每次运行构建之前设置`git`用户名：

```ts
        before_script: 
            -  git config - -global user.name jquerygeek  

```

在前面的示例中，我们已经传递了配置，以在真实浏览器（Firefox）中使用 karma 在虚拟屏幕上运行构建过程，默认情况下使用 PhantomJS 无头浏览器运行该过程。只要 Travis 支持 PhantomJS 之外的真实浏览器，这可能会很方便：

```ts
        before_script: 
            -  export DISPLAY=:99.0 
            - sh -e /etc/init.d/xvfb start  

```

+   **通知**：这是设置电子邮件和聊天通知所必需的。在这里，我们将`email`设置为`false`，因为我们不希望收到有关构建的加班电子邮件通知：

```ts
        notifications: 
            email: false  

```

## 使用 Karma 设置测试

正如之前所见，我们猜测在 npm 包中的项目根目录中有`package.json`文件；如果没有，让我们在那里创建一个`package.json`文件并添加这些配置片段。这里，第一个是 Karma 的依赖项，第二个是为`npm test`设置所需的参数，因为 Travis 将运行此命令来触发我们的测试。这些将告诉 Travis 如何运行我们的测试：

```ts
  'devDependencies': { 
      'karma': '~0.12' 
  }, 

  'scripts': { 
      'test': 'karma start  - -single-run - -browsers PhantomJS ' 
  } 

```

我们的初始设置和配置已经准备好进行测试。我们定义了 Karma 依赖项，因为 Travis 将为每个套件运行`nmp install`，并将采取必要的步骤来添加 Karma。并且为了运行测试，它将调用`npm test`，我们定义了测试任务将如何运行测试。在这里，我们将默认浏览器设置为 PhantomJS，以便测试将使用它运行。但是，如果我们需要使用不同的浏览器运行测试，我们应该在`.travis.yml`文件中使用`before_script`命令进行定义，就像我们之前为 Firefox 所示的那样。

在这种情况下，`npm test`将不会使用自定义浏览器运行测试；为此，我们必须使用浏览器名称进行自定义调用，如下所示：

```ts
**karma start - -browsers Firefox - -single-run** 

```

# 自测问题

以下自测问题将帮助您进一步测试使用 AngularJS 和 Karma 进行 TDD 的知识：

Q1.  如何使用 Karma 创建配置文件？

1.  `karma config`

1.  `karma init`

1.  `karma -config karma.conf.js`

Q2.  Jasmine 测试方法名为`before`，在每次测试之前执行。

1.  正确

1.  错误

Q3.  Bower 用于安装 Karma。

1.  正确

1.  错误

Q4.  这三个 A 代表哪一个？

1.  一组超级英雄

1.  集合，行动和断言

1.  接受，批准和行动

# 摘要

在本章中，我们讨论了 Karma 如何变得重要。我们看到了如何安装，配置和运行 Karma。最后，我们通过一个使用 Karma 进行 TDD 的 Angular 示例项目进行了演示。

在下一章中，我们将学习如何使用 Protractor 进行端到端测试。
