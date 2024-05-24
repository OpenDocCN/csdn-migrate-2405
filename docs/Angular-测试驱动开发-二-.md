# Angular 测试驱动开发（二）

> 原文：[`zh.annas-archive.org/md5/60F96C36D64CD0F22F8885CC69A834D2`](https://zh.annas-archive.org/md5/60F96C36D64CD0F22F8885CC69A834D2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Protractor 进行端到端测试

单元测试只是测试每段代码的责任的测试的一个方面。然而，当涉及测试任何组件、模块或完整应用程序的流程和功能时，端到端测试是唯一的解决方案。

在本章中，我们将逐步查看应用程序所有层的端到端测试流程。我们将介绍 Protractor，这是 Angular 团队的端到端测试工具。我们已经知道了它的原因，它是为什么创建的，以及它解决了什么样的问题。

在本章中，我们将学习：

+   安装和配置 Protractor 的过程

+   在我们现有的 Angular 项目中实施 Protractor 端到端测试

+   e2e 测试运行

+   返回测试结果

# Protractor 概述

Protractor 是一个端到端测试工具，使用 Node.js 运行，并作为 npm 包提供。在具体讨论 Protractor 之前，我们需要了解什么是端到端测试。

我们已经在第二章中简要了解了端到端测试，但让我们快速回顾一下：

端到端测试是针对应用程序所有相互连接的移动部分和层的测试。这与单元测试不同，单元测试侧重于单个组件，如类、服务和指令。通过端到端测试，重点是应用程序或模块作为一个整体的工作方式，例如确认按钮点击触发 x、y 和 z 动作。

Protractor 允许通过与应用程序的 DOM 元素交互来对任何模块甚至任何大小的 Web 应用程序进行端到端测试。它提供了选择特定 DOM 元素、与该元素共享数据、模拟按钮点击以及与用户相同的方式与应用程序交互的能力。然后，它允许根据用户的期望设置期望。

## Protractor 的核心

在快速概述中，我们对 Protractor 有了一个基本的了解——它如何选择 DOM 元素并与它们进行交互，就像真正的用户一样，以便在任何应用程序上运行 e2e 测试。为了执行这些活动，Protractor 提供了一些全局函数；其中一些来自其核心 API，一些来自 WebDriver。我们将在第五章 *Protractor，更进一步*中详细讨论它们。

然而，让我们现在快速概述一下：

+   **浏览器**：Protractor 提供了全局函数 `browser`，它是来自 WebDriver 的全局对象，主要用于在 e2e 测试过程中与应用程序浏览器进行交互。它提供了一些有用的方法来进行交互，如下所示：

```ts
        browser.get('http://localhost:3000'); // to navigate the    
        browser to a specific url address  
        browser.getTitle(); // this will return the page title that 
        defined in the projects landing page  

```

还有许多其他内容，我们将在下一章中讨论。

+   **元素**：这是 Protractor 提供的一个全局函数；它基本上用于根据定位器查找单个元素，但它也支持多个元素选择，通过链接另一个方法 `.all` 作为 `element.all`，它还接受 `Locator` 并返回 `ElementFinderArray`。让我们看一个 `element` 的例子：

```ts
        element(Locator); // return the ElementFinder 
        element.all(Locator); // return the ElementFinderArray 
        element.all(Locator).get(position);  // will return the
        defined  position 
        element from the ElementFinderArray  
        element.all(Locator).count(); // will return the 
        total number in the select element's array   

```

还有许多其他内容，我们将在下一章中讨论。

+   **操作**：正如我们所见，`element` 方法将返回一个选定的 DOM `element` 对象，但我们需要与 DOM 进行交互，为此工作的操作方法带有一些内置方法。DOM 不会通过任何操作方法调用与浏览器单元联系。让我们看一些操作的例子：

```ts
        element(Locator).getText(); // return the ElementFinder 
        based on locator  
        element.(Locator).click(); // Will trigger the click 
        handler for that specific element  
        element.(Locator).clear(); // Clear the field's value 
        (suppose the element is input field)
```

还有许多其他内容，我们将在下一章中讨论。

+   **定位器**：这实际上告诉 Protractor 如何在 DOM 元素中找到某个元素。Protractor 将 `Locator` 导出为全局工厂函数，将与全局 `by` 对象一起使用。让我们看一些 `Locator` 的例子：

```ts
        element(by.css(cssSelector)); // select element by css 
        selector  
        element(by.id(id)); //  select element by element ID 
        element.(by.model); // select element by ng-model 

```

还有许多其他内容，我们将在下一章中讨论。

## 一个快速的例子

现在我们可以通过一个快速示例来考虑以下用户规范。

假设我在搜索框中输入 `abc`，应该发生以下情况：

+   搜索按钮应该被点击

+   至少应该收到一个结果。

上述规范描述了一个基本的搜索功能。上述规范中没有描述控制器、指令或服务；它只描述了预期的应用程序行为。如果用户要测试规范，他们可能执行以下步骤：

1.  将浏览器指向该网站。

1.  选择输入字段。

1.  在输入字段中键入`abc`。

1.  点击**搜索**按钮。

1.  确认搜索输出显示至少一个结果。

Protractor 的结构和语法与 Jasmine 以及我们在第三章中编写的测试相似，*卡尔玛方式*。我们可以将 Protractor 视为 Jasmine 的包装器，具有支持端到端测试的附加功能。要使用 Protractor 编写端到端测试，我们可以按照刚才看到的相同步骤进行，但使用代码。

以下是带有代码的步骤：

1.  将浏览器指向该网站：

```ts
        browser.get('/'); 

```

1.  选择输入字段：

```ts
        var inputField = element.all(by.css('input')); 

```

1.  在输入字段中键入`abc`：

```ts
        inputField.setText('abc'); 

```

1.  点击**搜索**按钮：

```ts
        var searchButton = element.all(by.css('#searchButton'); 
        searchButton.click(); 

```

1.  在页面上找到搜索结果的详细信息：

```ts
        var searchResults = element.all(by.css('#searchResult'); 

```

1.  最后，需要断言至少有一个或多个搜索结果在屏幕上可用：

```ts
        expect(searchResults).count() >= 1); 

```

作为完整的测试，代码将如下所示：

```ts
    describe('Given I input 'abc' into the search box',function(){ 
        //1 - Point browser to website 
        browser.get('/'); 
        //2 - Select input field 
        var inputField = element.all(by.css('input')); 
        //3 - Type abc into input field 
        inputField.setText('abc'); 
        //4 - Push search button 
        var searchButton = element.all(by.css('#searchButton'); 
        searchButton.click(); 
        it('should display search results',function(){ 
        // 5 - Find the search result details 
        var searchResults = element.all(by.css('#searchResult'); 
        //6 - Assert 
        expect(searchResults).count() >= 1); 
        }); 
    }); 

```

就是这样！当 Protractor 运行时，它将打开浏览器，转到网站，按照说明进行，最后检查期望结果。端到端测试的诀窍在于清晰地了解用户规范是什么，然后将该规范转化为代码。

前面的示例是本章将描述的内容的高层视图。现在我们已经介绍了 Protractor，本章的其余部分将展示 Protractor 在幕后的工作原理，如何安装它，并最终通过 TDD 的完整示例来引导我们。

# Protractor 的起源

Protractor 并不是 Angular 团队构建的第一个端到端测试工具。第一个工具被称为**场景运行器**。为了理解为什么要构建 Protractor，我们首先需要看看它的前身--场景运行器。

场景运行器处于维护模式，并已到达其生命周期的尽头。它已被淘汰，取而代之的是 Protractor。在本节中，我们将看看场景运行器是什么，以及这个工具存在哪些缺陷。

## Protractor 的诞生

朱莉·拉尔夫是 Protractor 的主要贡献者。根据朱莉·拉尔夫的说法，Protractor 的动机是基于她在 Google 内另一个项目中使用 Angular 场景运行器的经验（[`javascriptjabber.com/106-jsj-protractor-with-julie-ralph/`](http://javascriptjabber.com/106-jsj-protractor-with-julie-ralph/)）。

> “我们尝试使用场景运行器。我们发现它真的无法做我们需要测试的事情。我们需要测试诸如登录之类的东西。您的登录页面不是一个 Angular 页面，场景运行器无法处理。它也无法处理弹出窗口和多个窗口，浏览器历史记录导航等等。”

基于她对场景运行器的经验，朱莉·拉尔夫决定创建 Protractor 来填补空白。

Protractor 利用了 Selenium 项目的成熟性，并包装其方法，以便它可以轻松用于 Angular 项目。记住，Protractor 是通过用户的眼睛进行测试的。它旨在测试应用程序的所有层：Web UI，后端服务，持久层等等。

## 没有 Protractor 的生活

单元测试并不是唯一需要编写和维护的测试。单元测试侧重于应用程序的小个体组件。通过测试小组件，代码和逻辑的信心增强。单元测试不关注连接时完整系统的工作方式。

使用 Protractor 进行端到端测试允许开发人员专注于功能或模块的完整行为。回到搜索示例，只有当整个用户规范通过时，测试才应该通过；在搜索框中输入数据，单击“搜索”按钮，然后查看结果。Protractor 并不是唯一的端到端测试框架，但它是 Angular 应用程序的最佳选择。以下是选择 Protractor 的几个原因：

+   它在整个 Angular 教程和示例中都有文档记录

+   它可以使用多个 JavaScript 测试框架编写，包括 Jasmine 和 Mocha

+   它为 Angular 组件提供了便利的方法，包括等待页面加载，对承诺的期望等等

+   它包装了 Selenium 方法，自动等待承诺实现

+   它得到了 SaaS（软件即服务）提供商的支持，例如 Sauce Labs，可在[`saucelabs.com/`](https://saucelabs.com/)上使用

+   它得到了与维护 Angular 和 Google 相同的公司的支持和维护

# 使用 Protractor 做好准备

现在是时候开始动手安装和配置 Protractor 了。安装和应用程序不断变化。主要关注点将放在本书中使用的特定配置上，而不是深入的安装指南。有几种不同的配置，因此请查看 Protractor 网站以获取更多详细信息。要查找最新的安装和配置指南，请访问 [`angular.github.io/protractor/`](http://angular.github.io/protractor/)。

## 安装先决条件

Protractor 有以下先决条件：

+   **Node.js**：Protractor 是一个使用 npm 可用的 Node.js 模块。安装 Node.js 的最佳方法是按照官方网站上的说明进行操作 [`nodejs.org/download/`](http://nodejs.org/download/)。

+   **Chrome**：这是由 Google 构建的 Web 浏览器。它将用于在 Protractor 中运行端到端测试，而无需 Selenium 服务器。请按照官方网站上的安装说明进行安装 [`www.google.com/chrome/browser/`](http://www.google.com/chrome/browser/)。

+   **Chrome 的 Selenium WebDriver**：这是一个允许您与 Web 应用程序进行交互的工具。Selenium WebDriver 随 Protractor `npm` 模块一起提供。我们将在安装 Protractor 时按照说明进行操作。

## 安装 Protractor

以下是安装 Protractor 的步骤：

1.  一旦 Node.js 安装并在命令提示符中可用，输入以下命令在当前目录中安装 Protractor：

```ts
**$ npm install protractor**

```

1.  上述命令使用 Node 的 `npm` 命令在当前本地目录中安装 Protractor。

1.  在命令提示符中使用 Protractor，使用相对路径到 Protractor bin 目录。

1.  测试 Protractor 版本是否可以确定如下：

```ts
**$ ./node_modules/protractor/bin/protractor --version**

```

## 安装 Chrome 的 WebDriver

以下是安装 Chrome 的 WebDriver 的步骤：

1.  要安装 Chrome 的 Selenium WebDriver，请转到 Protractor `bin` 目录中的 `webdriver-manager` 可执行文件，该文件位于 `./node_modules/protractor/bin/`，然后输入以下内容：

```ts
**$ ./node_modules/protractor/bin/webdriver-manager update**

```

1.  确认目录结构。

1.  上述命令将创建一个包含项目中所需的 Chrome 驱动程序的 Selenium 目录。

安装现在已经完成。Protractor 和 Chrome 的 Selenium WebDriver 都已安装。现在我们可以继续进行配置。

## 自定义配置

在本节中，我们将使用以下步骤配置 Protractor：

1.  从标准模板配置开始。

1.  幸运的是，Protractor 安装时在其安装目录中带有一些基本配置。

1.  我们将使用的是位于 protractor/example 部分的`conf.js`。

1.  查看示例配置文件：

`capabilities`参数应该只指定浏览器的名称：

```ts
          exports.config = {  
          //...  
          capabilities: { 
            'browserName': 'chrome' 
          },   
          //... 
          }; 

```

framework 参数应该指定测试框架的名称，我们将在这里使用 Jasmine：

```ts
          exports.config = {  
          //...  
          framework: 'jasmine'   
          //... 
          };
```

最后一个重要的配置是源文件声明：

```ts
          exports.config = { 
            //... 
            specs: ['example_spec.js'], 
            //... 
          }; 

```

太棒了！现在我们已经安装和配置了 Protractor。

## 确认安装和配置

要确认安装，Protractor 需要在`specs`配置部分中至少定义一个文件。在添加真正的测试并复杂化之前，在根目录中创建一个名为`confirmConfigTest.js`的空文件。然后，编辑位于项目根目录中的`conf.js`文件，并将测试文件添加到`specs`部分，使其看起来如下：

```ts
**specs: ['confirmConfigTest.js'],**

```

要确认 Protractor 已安装，可以转到项目目录的根目录并输入以下内容来运行 Protractor：

```ts
 **$ ./node_modules/protractor/bin/protractor conf.js**

```

如果一切设置正确并安装完成，我们将在命令提示符中看到类似于这样的内容：

```ts
**Finished in 0.0002 seconds**
**0 tests, 0 assertions, 0 failures**

```

## 常见的安装和配置问题

在安装 Chrome 的 WebDriver 时，您可能会遇到一些常见问题：

| **问题** | **解决方案** |
| --- | --- |
| Selenium 未正确安装 | 如果测试与 Selenium WebDriver 位置相关的错误，您需要确保按照更新 WebDriver 的步骤进行操作。更新步骤会将 WebDriver 组件下载到本地 Protractor 安装文件夹中。在 WebDriver 更新之前，您将无法在 Protractor 配置中引用它。确认更新的简单方法是查看 Protractor 目录，并确保存在一个 Selenium 文件夹。 |
| 无法找到测试 | 当 Protractor 未执行任何测试时，这可能会令人沮丧。开始的最佳地方是在配置文件中。确保相对路径和任何文件名或扩展名都是正确的。 |

有关完整列表，请参阅官方 Protractor 网站[`angular.github.io/protractor/`](http://angular.github.io/protractor/)。

# 将 Protractor 与 Angular 集成

到目前为止，我们已经看到了如何安装和配置 Protractor，也对 Protractor 的工作原理有了基本概述。在本节中，我们将通过将 Protractor 集成到现有的 Angular 项目中的过程，来了解 Protractor 在实际的 e2e 测试中是如何使用的。

## 获取现有项目

此测试中的代码将利用第三章中经过单元测试的代码，*Karma 方式*。我们将把代码复制到一个名为 `angular-protractor` 的新目录中。

作为提醒，该应用是一个待办事项应用程序，其中有一些项目在待办事项列表中；让我们向列表中添加一些更多项目。它有一个单一的组件类 `AppComponent`，其中有一个项目列表和一个 `add` 方法。当前的代码目录应该结构如下：

![获取现有项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_04_001.jpg)

获得这个结构后，第一件事是通过运行以下命令在本地获得所需的依赖项 `node_modules`：

```ts
**$ npm install**

```

这将安装所有必需的模块；接下来，让我们使用 `npm` 命令构建和运行项目：

```ts
**$ npm start**

```

一切应该都很好；项目应该在 `http://localhost:3000` 上运行，输出应该如下：

![获取现有项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_04_002.jpg)

是的，我们已经准备好进入下一步，在我们的 Angular 项目中实现 Protractor。

## Protractor 设置流程

设置将反映我们在本章前面看到的安装和配置步骤：

1.  安装 Protractor。

1.  更新 Selenium WebDriver。

1.  根据示例配置配置 Protractor。

我们将在一个新的项目目录中按照前一节中涵盖的 Protractor 安装和配置步骤进行操作。唯一的区别是，Protractor 测试可以以 e2e 前缀命名，例如 `**.e2e.js`。这将使我们能够轻松地在项目结构中识别 Protractor 测试。

### 提示

这绝对取决于开发者的选择；有些人只是将 Protractor 测试放在一个新目录中，带有子文件夹 `spec/e2e`。这只是项目结构的一部分。

## 安装 Protractor

我们可能已经全局设置了 Protractor，也可能没有，所以最好在项目中安装 Protractor。因此，我们将在本地安装 Protractor，并在 `package.json` 中添加为 `devDependency`。

要在我们的项目中安装 Protractor，请从项目目录运行以下命令：

```ts
**$ npm install protractor -save-dev**

```

我们可以按以下方式检查 Protractor：

```ts
**$ ./node_modules/protractor/bin/protractor --version**

```

这应该提供最新版本 4.0.10，如下所示：

```ts
**Version 4.0.10**

```

### 提示

**我们将遵循的一个好的做法**

我们展示了如何在目录中设置 Protractor，但最好使用以下命令全局安装 Protractor：

```ts
**$ npm install -g protractor**

```

这样我们就可以轻松地从命令行调用 Protractor，就像使用`protractor`一样；要知道 Protractor 的版本，我们可以按照以下方式调用它：

```ts
**$ protractor -version**

```

## 更新 WebDriver

要更新 Selenium WebDriver，转到 Protractor `bin`目录中的`webdriver-manager`可执行文件，该目录可以在`./node_modules/protractor/bin/`中找到，并键入以下内容：

```ts
**$ ./node_modules/protractor/bin/webdriver-manager update**

```

根据通知，一个好的做法是全局安装 Protractor，如果这样，我们也将全局拥有`webdriver-manager`命令，这样，我们可以轻松地运行`update`，如下所示：

```ts
**$ webdriver-manager update**

```

这将更新 WebDriver 并支持最新的浏览器。

## 准备工作

由于我们克隆了示例快速启动项目，它已经在项目中集成和配置了 Protractor。为了学习的目的，我们想在现有项目中集成 Protractor。

为此，我们将不得不从项目根目录中删除现有的`protractor.config.js`文件。

## 设置核心配置

正如我们之前所看到的，Protractor 配置将存储在一个 JS 文件中。我们需要在项目根目录中创建一个配置文件；让我们将其命名为`protractor.config.js`。

目前，保持可变字段为空，因为这些字段取决于项目结构和配置。因此，初始外观可能是这样的，我们已知这些配置选项：

```ts
exports.config = { 

    baseUrl: ' ', 

    framework: 'jasmine', 

    specs: [], 

    capabilities: { 
        'browserName': 'chrome' 
    } 

}; 

```

只要我们的项目在本地端口`3000`上运行，我们的`baseUrl`变量将如下所示：

```ts
exports.config = { 
    // ....  
    baseUrl: ' http://localhost:3000', 
    // ....  
}; 

```

我们计划将 e2e 测试规范放在与单元测试文件相同的文件夹中，`app/app.component.spec.ts`。这次它将有一个新的 e2e 前缀，看起来像`app/app.component.e2e.ts`。基于此，我们的规范和配置将被更新：

```ts
exports.config = { 
    // ....  
    specs: [ 
        'app/**/*.e2e.js' 
    ], 
    // ..... 
}; 

```

只要它是一个 Angular 项目，我们需要传递额外的配置，`useAllAngular2AppRoots: true`，因为这将告诉 Protractor 等待页面上所有 Angular 应用程序的根元素，而不仅仅是匹配的一个根元素：

```ts
exports.config = { 
    // ....  
    useAllAngular2AppRoots: true, 
    // ..... 
}; 

```

我们通过节点服务器运行我们的项目；因此，我们需要传递一个配置选项，以便 Jasmine 本身支持节点。这个配置在 Jasmine 2.x 版本中是必须的，但如果我们使用 Jasmine 1.x，则可能不需要。在这里，我们已经在`jasmineNodeOpts`中添加了两个最常见的选项；根据需求，还有一些选项被使用：

```ts
exports.config = { 
    // ....  
    jasmineNodeOpts: { 
        showColors: true, 
        defaultTimeoutInterval: 30000 
    }, 
    // ..... 
}; 

```

## 深入测试细节

要运行 Protractor 测试，我们需要两个文件：一个是配置文件，我们已经在项目根目录中创建了`protractor.conf.js`，另一个是规范，我们将在 app 文件夹中定义 e2e 测试规范，该文件将位于`app/app.component.e2e.ts`。

所以，让我们看看我们应该在那里定义的文件：

```ts
describe('Title for test suite', () => { 

    beforeEach(() => { 
        // ...  
    }); 

    it('Title for test spec', () => { 
        // ... 
    }); 

});; 

```

我们应该知道这些语法，因为我们已经在单元测试套件中使用了 Jasmine 语法。

让我们快速回顾一下

+   `describe`：这包含要运行测试套件的代码块

+   `beforeEach`：这用于包含设置代码，该代码在每个测试规范中使用

+   `it`：这用于定义测试规范并包含该测试规范的特定代码以运行

对于任何网站运行 e2e 测试的主要部分是获取该网站的 DOM 元素，然后通过测试过程与这些元素进行交互。因此，我们需要获取我们运行项目的 DOM 元素。

只要当前项目在 web 浏览器中运行，我们首先必须获取浏览器本身的实例；有趣的是，Protractor 通过全局的 browser 对象提供了这一点。通过这个 browser 对象，我们可以获取所有浏览器级别的命令，比如`browser.get`，我们可以通过我们的项目 URL 进行导航：

```ts
beforeEach(() => { 
    browser.get(''); 
});; 

```

通过`browser.get('')`方法，我们将导航到我们项目的根目录。

我们有全局的 browser 对象，通过它我们可以获取正在运行页面的标题，基本上就是我们在项目`index.html`文件中定义的标题。`browser.getTitle`将提供标题，然后我们可以将其与预期进行匹配。因此，我们的测试规范将如下所示：

```ts
it('Browser should have a defined title', () => { 
       expect(browser.getTitle()).toEqual('Angular Protractor'); 
}); 

```

如果我们快速看一下，我们的短 e2e 测试规范将如下所示：

```ts
describe('AppComponent Tests', () => { 
    beforeEach(() => { 
        browser.get(''); 
    }); 

    it('Browser should have a defined title', () => { 
        expect(browser.getTitle()).toEqual('Angular Protractor'); 
    }); 
}); 

```

是时候用 Protractor 运行 e2e 测试了。命令将如下所示：

```ts
**$ protractor protractor.conf.js**

```

结果如预期--0 失败，因为我们已将`index.html`页面标题设置为**Angular Protractor**。**** 结果将如下：

```ts
1 spec, 0 failures 
Finished in 1.95 seconds 

```

是时候继续并为页面的其他 DOM 元素添加一个新的测试规格了，我们在页面上列出了列表项目；因此，我们将通过 Protractor 自动测试它们。

首先，我们将检查我们是否列出了所有三个项目。在本章的早些部分，我们已经学习了一些 Protractor 常用的 API，但是为了快速回顾，我们将使用`element.all`方法，通过传递一些定位器（`by.css`、`by.id`和`by.model`）来获取元素数组对象。然后，我们可以使用 Jasmine 匹配器来与预期值进行匹配，如下所示：

```ts
it('Should get the number of items as defined in item object', () => { 
        var todoListItems = element.all(by.css('li')); 
        expect(todoListItems.count()).toBe(3); 
    }); 

```

我们应该得到通过的结果，因为我们在 UI 中列出了三个项目。

我们可以添加一些用于测试 UI 元素的测试规格。例如，为了检查列出的项目是否按正确的顺序列出，我们可以检查它们的标签，如下所示：

```ts
it('Should get the first item text as defined', () => { 
        expect(todoListItems.first().getText()).toEqual('test'); 
    }); 

    it('Should get the last item text as defined', () => { 
        expect(todoListItems.last().getText()).toEqual('refactor'); 
    }); 

```

我们已经将第一个和最后一个项目的标签/文本与预期值进行了匹配，它也应该通过。

让我们将所有的测试规格组合在 e2e 文件中。它将如下所示：

```ts
describe('AppComponent Tests', () => { 
    var todoListItems = element.all(by.css('li')); 

    beforeEach(() => { 
        browser.get('/'); 
    }); 

    it('Browser should have a defined title', () => { 
        expect(browser.getTitle()).toEqual('Angular Protractor'); 
    }); 

    it('Should get the number of items as defined in item object', () 
    => { 
        expect(todoListItems.count()).toBe(3); 
    }); 

    it('Should get the first item text as defined', () => { 
        expect(todoListItems.first().getText()).toEqual('test'); 
    }); 

    it('Should get the last item text as defined', () => { 
        expect(todoListItems.last().getText()).toEqual('refactor'); 
    }); 
}); 

```

让我们一起运行所有的规格：

```ts
**$ protractor protractor.conf.js**

```

正如预期的那样，所有的测试都应该通过，结果将如下所示：

```ts
**4 specs, 0 failures**
**Finished in 2.991 seconds**

```

### 提示

只要我们将 Protractor 配置文件命名为`protractor.conf.js`，在运行`protractor`命令时就不需要提及配置文件名；Protractor 会自行获取其配置文件。如果使用其他名称，我们就需要在 Protractor 中提及配置文件名。

因此，在这种情况下，我们可以按照以下方式运行测试：

```ts
**$ protractor**

```

结果将与之前一样。

## 通过 NPM 运行测试

在这个项目中，我们将通过 npm 构建和运行项目。在第三章*Karma 方式*中，我们通过`npm`运行了`karma`测试；同样，我们也将通过`npm`运行`protractor`测试。为了做到这一点，我们必须在项目的`package.json`的`scripts`部分中添加`protractor`：

```ts
"scripts": { 
    // ...  
    "e2e": "protractor" 
    // .... 
  }; 

```

要在我们的项目中安装`protractor`，请从项目目录中运行：

```ts
**$ npm e2e**

```

在一些操作系统中，这个命令可能会产生一些`npm`错误。这实际上是因为`webdriver-manager`可能没有更新。为了解决这个问题，我们必须将`webdriver-manager`更新脚本添加到`npm`中，并且只在第一次运行时运行一次，就像这样：

```ts
"scripts": { 
    // ...  
    "webdriver-update": "webdriver-manager update" 
    // .... 
  }; 

```

我们还必须这样运行它：

```ts
**$ npm webdriver-update**

```

就是这样，我们已经准备好再次运行 e2e 测试，这应该与`protractor`命令完全相同。

让我们确认一下：

```ts
**$ npm run e2e**

```

预期结果将如下所示：

```ts
**4 specs, 0 failures**
**Finished in 2.991 seconds**

```

# 让测试变得更好。

本章讨论了一些需要进一步澄清的事情。这些包括以下内容：

+   异步逻辑在哪里？

+   我们如何真正实现端到端测试的 TDD？

## 异步魔术

在前面的测试中，我们看到了一些你可能会质疑的魔术。以下是我们忽略的一些魔术组件：

+   在测试执行之前加载页面

+   对在承诺中加载的元素进行断言

### 在测试执行之前加载页面

在上一个测试中，我们使用以下代码指定浏览器应该指向主页：

```ts
browser.get(''); 

```

前面的命令将启动浏览器并导航到`baseUrl`位置。一旦浏览器到达页面，它将加载 Angular，然后实现特定于 Angular 的函数。我们的测试没有任何等待逻辑，这是 Protractor 与 Angular 的美妙之处。页面加载的等待已经内置到框架中。我们的测试可以写得非常干净。

### 对在承诺中加载的元素进行断言

断言和期望已经在其中写入了承诺的实现。在我们的测试中，我们编写了断言，以便它期望计数为`3`：

```ts
expect(todoListItems.count()).toBe(3); 

```

然而，实际上，我们可能认为我们需要在断言中添加异步测试，以等待承诺被实现，涉及更复杂的东西，比如以下内容：

```ts
it('Should get the number of items as defined in item object', (done) => { 
    var todoListItems = element.all(by.css('li')); 
    todoListItems.count().then(function(count){ 
        expect(count).toBe(3); 
        done(); 
    }); 
}); 

```

前面的代码更长，更细粒度，更难阅读。Protractor 具有使测试更简洁的能力，对于某些内置到期望中的元素。

## 使用 Protractor 进行 TDD

通过我们的第一个测试，清楚地区分了端到端测试和单元测试。在单元测试中，我们专注于将测试与代码强耦合。例如，我们的单元测试对特定组件类`AppComponent`的作用域进行了监听。我们必须初始化组件以获得组件的实例，如下所示：

```ts
import {AppComponent} from "./app.component"; 

beforeEach(() => { 
    app = new AppComponent(); 
}); 

```

在 Protractor 测试中，我们不关心我们正在测试哪个组件类，我们的重点是测试的用户视角。我们从 DOM 中选择特定元素开始；在我们的情况下，该元素与 Angular 相关联。断言是特定重复器的元素数量等于预期计数。

通过端到端测试的松散耦合，我们可以编写一个专注于用户规范的测试，最初显示三个元素，然后可以自由地以我们想要的方式在页面、类、组件等中编写它。

# 自测问题

使用 Protractor 进行 TDD 来开发第三个开发待办事项。

Q1. Protractor 使用以下哪些框架？

+   Selenium

+   Unobtanium

+   Karma

Q2. 您可以在任何现有的 Angular 项目中安装 Protractor。

+   真

+   假

Q3. Karma 和 Protractor 可以在单个项目中一起运行。

+   真

+   假

Q4. 哪个团队开发了 Protractor？

+   ReactJS 团队

+   Angular 团队

+   NodeJS 团队

# 摘要

本章概述了使用 Protractor 进行端到端测试，并提供了安装、配置和应用现有 Angular 项目的端到端测试的必要思路。Protractor 是测试任何 Angular 应用程序的重要组成部分。它弥合了差距，以确保用户的规范按预期工作。当端到端测试根据用户规范编写时，应用程序的信心和重构能力会增长。在接下来的章节中，我们将看到如何以简单直接的例子更深入地应用 Karma 和 Protractor。

下一章将详细介绍 Protractor 的一些高级配置，一些 API 的细节，并对测试进行调试。


# 第五章：Protractor，更进一步

端到端测试真的很有趣，只要直接与浏览器交互，但是一个好的开发者应该了解 Protractor 的高级功能，以进行大规模的应用程序测试。此外，在端到端测试中调试是一种挑战，因为它取决于浏览器的 DOM 元素。

Protractor 有一些用于调试的 API。本章将主要涵盖这些 API 和功能，包括以下内容：

+   设置和配置 Protractor

+   一些高级的 Protractor API，比如 browser，locator 和 action

+   使用`browser.pause()`和`browser.debug()`API 来调试 Protractor

# 高级设置和配置

在上一章中，我们看到了 Protractor 的基本和常用的设置和配置。在这里，我们将看一些高级配置，使安装更简单和更强大。

## 全局安装 Protractor

以下是全局安装 Protractor 的步骤：

1.  一旦 Node.js 被安装并在命令提示符中可用，输入以下命令在系统上全局安装 Protractor：

```ts
**$ npm install -g protractor**

```

上一条命令使用了 Node 的`npm`命令全局安装 Protractor，这样我们就可以只用`protractor`命令来使用 Protractor 了。

1.  测试 Protractor 版本是否可以如下确定：

```ts
**$ protractor --version**

```

## 高级配置

在本节中，我们将使用以下步骤对 Protractor 进行更详细的配置：

1.  更新 protractor 的`config`文件以支持单个测试套件中的多个浏览器。`multiCapabilities`参数是一个数组，可以为任何测试套件传递多个`browserName`对象，如下所示：

```ts
        exports.config = {  
          //...  
        multiCapabilities: [{
         'browserName': 'firefox' 
        }, { 
         'browserName': 'chrome' 
        }]
        //... };
```

1.  我们可以在`capabilities`参数中为浏览器设置高级设置；例如，对于`chrome`，我们可以传递额外的参数作为`chromeOptions`，如下所示：

```ts
        exports.config = {  
          //...  
          capabilities: { 
            'browserName': 'chrome'
            'chromeOptions': {
              'args': ['show-fps-counter=true']
            }}]
        //... };
```

1.  有时，我们可能需要直接运行 Protractor 而不使用 Selenium 或 WebDriver。这可以通过在`config.js`文件中传递一个参数来实现。该参数是配置对象中的`directConnect: true`，如下所示：

```ts
        exports.config = { 
          //... 
          directConnect: true, 
          //... 
        }; 

```

太棒了！我们已经配置了 Protractor 更进一步。

# Protractor API

端到端测试任何网页的主要活动是获取该页面的 DOM 元素，与它们交互，为它们分配一个动作，并与它们共享信息；然后，用户可以获取网站的当前状态。为了使我们能够执行所有这些操作，Protractor 提供了各种各样的 API（其中一些来自 web driver）。在本章中，我们将看一些常用的 API。

在上一章中，我们看到了 Protractor 如何与 Angular 项目一起工作，我们需要与 UI 元素进行交互。为此，我们使用了一些 Protractor API，比如`element.all`，`by.css`，`first`，`last`和`getText`。然而，我们没有深入了解这些 API 的工作原理。要理解 Protractor 中 API 的工作原理非常简单，但在现实生活中，我们大多数时候将不得不处理更大、更复杂的项目。因此，重要的是我们了解并更多地了解这些 API，以便与 UI 进行交互并玩耍。

## 浏览器

Protractor 与 Selenium WebDriver 一起工作，后者是一个浏览器自动化框架。我们可以使用 Selenium WebDriver API 中的方法来与测试规范中的浏览器进行交互。我们将在接下来的章节中看一些这些方法。

要将浏览器导航到特定的网址并在 Angular 加载之前加载该页面的模拟模块，我们将使用`.get()`方法，通过传递特定的地址或相对路径：

```ts
browser.get(url); 
browser.get('http://localhost:3000'); // This will navigate to
the localhost:3000 and will load mock module if needed 

```

要获取当前页面的网址，使用`CurrentUrl()`方法，如下所示：

```ts
browser.getCurrentUrl(); // will return http://localhost:3000 

```

要导航到另一个页面并使用页面内导航进行浏览，使用`setLocation`，如下所示：

```ts
browser.setLocation('new-page'); // will change the url and navigate to the new url, as our current url was http://localhost:3000, now it will change and navigate to http://locahost:3000/#/new-page 

```

要获取当前页面的标题（基本上是在 HTML 页面中设置的标题），使用`getTitle`方法，如下所示：

```ts
browser.getTitle(); // will return the page title of our page, for us it will return us "Angular Protractor Debug" 

```

要在 Angular 加载之前使用模拟模块重新加载当前页面，使用`refresh()`方法，如下所示：

```ts
browser.refresh(); // this will reload the full page and definitely will load the mocks module as well. 

```

要暂停测试过程，使用`pause()`方法。这对于调试测试过程非常有用，我们将使用这个测试调试部分：

```ts
browser.pause(); 

```

为了调试测试过程，使用`debugger()`方法。这个方法是不同的，可以被认为是`pause()`方法的高级版本。这对于测试过程的高级调试以及将自定义辅助函数注入到浏览器中非常有用。我们也将使用这个测试调试部分：

```ts
browser.debugger(); 

```

要关闭当前浏览器，使用`close()`。这对于复杂的多模块测试非常有用，有时我们需要在打开新浏览器之前关闭当前浏览器：

```ts
browser.close(); 

```

为了在 Protractor 中支持 Angular，我们必须将`useAllAngularAppRoots`参数设置为`true`。这样做的逻辑是，当我们将此参数设置为`true`时，它将在元素查找器遍历页面时搜索所有 Angular 应用程序：

```ts
browser.useAllAngular2AppRoots; 

```

## Elements

### 提示

Protractor 本身暴露了一些全局函数，`element`就是其中之一。这个函数接受一个定位器（一种选择器--我们将在下一步中讨论），并返回一个`ElementFinder`。这个函数基本上是根据定位器找到单个元素，但它支持多个元素的选择，以及链式调用另一个方法`element.all`，它也接受一个定位器并返回一个`ElementFinderArray`。它们都支持链式方法进行下一步操作。

### element.all

正如我们已经知道的那样，`element.all`返回一个`ElementArrayFinder`，支持链式方法进行下一步操作。我们将看一下其中一些方法以及它们的实际工作方式：

要选择多个具有特定定位器的元素数组，我们应该使用`element.all`，如下所示：

```ts
element.all(Locator); 
var elementArr = element.all(by.css('.selector'));  // return the ElementFinderArray 

```

在将一堆元素作为数组获取之后，我们可能需要选择特定的元素。在这种情况下，我们应该通过传递特定的数组索引作为位置号来链接`get(position)`：

```ts
element.all(Locator).get(position); 
elementArr.get(0); // will return first element from the ElementFinderArray  

```

在将一堆元素作为数组获取之后，我们可能需要再次选择子元素并使用首选的定位器，为此我们可以再次使用现有元素链接`.all(locator)`方法，如下所示：

```ts
element.all(Locator).all(Locator); 
elementArr.all(by.css('.childSelector')); // will return another ElementFinderArray as child elements based on child locator  

```

获取所需的元素之后，我们可能想要检查所选择的元素数量是否符合预期。有一个名为`count()`的方法，用于链到获取所选元素的总数：

```ts
element.all(Locator).count(); 
elementArr.count(); // will return the total number in the select element's array   

```

与`get(position)`方法类似，我们可以通过链接`first()`方法从数组中获取第一个元素：

```ts
element.all(Locator).first(); 
elementArr.first(); // will return the first element from the element's array   

```

与`first()`方法类似，我们可以通过链接`last()`方法从数组中获取最后一个元素：

```ts
element.all(Locator).last(); 
elementArr.last(); // will return the last element from the element array   

```

只要我们有一堆元素作为数组，我们可能需要遍历这些元素以执行任何操作。在这种情况下，我们可能需要通过链接`each()`方法来进行循环：

```ts
element.all(Locator).each(Function) { }; 
elementArr.each( function (element, index) { 
    // ......  
}); // ... will loop through out the array elements 

```

就像`each()`方法一样，还有另一个方法`filter()`，可以与元素数组链接以遍历项目并为它们分配一个过滤器：

```ts
element.all(Locator).filter(Function) { }; 
elementArr.filter( function (element, index) { 
    // ......  
}); //... will apply filter function's action to all elements  

```

### element

`element`类返回`ElementFinder`，这意味着元素数组中的单个元素，它也支持链接方法以进行下一个操作。在前面的示例中，我们看到了如何从元素数组中获取单个选择的元素，以便所有链接方法也适用于该单个元素。有许多用于操作单个元素的链接方法，我们将看一些最常用的方法。

通过将特定的定位器作为参数传递给`element`方法，我们可以选择单个 DOM 元素，如下所示：

```ts
element(Locator); 
var elementObj = element(by.css('.selector'));  // return the ElementFinder based on locator  

```

获取特定的单个元素后，我们可能需要找到该元素的子元素，然后使用`element.all`方法与重新运行的`elementFinder`对象链接。为此，将特定的定位器传递给`elementFinderArray`以查找子元素，如下所示：

```ts
element(Locator).element.all(Locator); 
elementObj.element.all(by.css('.childSelector')); // will return another ElementFinderArray as child elements based on child locator  

```

在选择特定元素后，我们可能需要检查该元素是否存在，同时链接`isPresent()`方法，如下所示：

```ts
element(Locator).isPresent(); 
elementObj.isPresent(); // will return boolean if the selected element is exist or not.   

```

## 操作

操作主要是改变影响或触发所选 DOM 元素的方法。选择 DOM 元素的目的是通过触发一些操作与其交互，以便它可以像真正的用户一样行动。有一些常用的用于特定交互的操作。我们将在这里看一些。

要获取任何元素的内部文本或包含的文本，我们必须在选择特定元素后，将`getText()`方法与`elementFinder`对象链接，如下所示：

```ts
element(Locator).getText(); 
var elementObj = element(by.css('.selector'));  // return the ElementFinder based on locator  
elementObj.getText(); // will return the contained text of that specific selected element  

```

要获取任何元素的内部 HTML，我们必须在选择特定元素后，将`getInnerHtml()`方法与`elementFinder`对象链接，如下所示：

```ts
element.(Locator).getInnerHtml(); 
elementObj.getInnerHtml(); // will return the inner html of the selected element.  

```

通过将属性键传递给`getAttribute()`方法，我们可以找到任何元素的特定属性值，并将其与所选的`elementFinder`对象链接，如下所示：

```ts
element(Locator).getAttribute('attribute'); 
elementObj.getAttribute('data'); // will return the value of data attribute of that selected element if that have that attribute 

```

在大多数情况下，我们需要清除输入字段的值。为此，我们可以将`clear()`方法与所选的`elementFinder`对象链接，如下所示：

```ts
element.(Locator).clear(); 
elementObj.clear(); // Guessing the elementFinder is input/textarea, and after calling this clear() it will clear the value and reset it.    

```

### 提示

请记住，只有输入或文本可能具有一些值，并且需要您清除/重置该值。

当我们需要在选择特定的`elementFinder`对象后触发按钮、链接或图像的点击事件时，我们需要链接`click()`方法，它将像真正的点击那个元素一样：

```ts
element.(Locator).click(); 
elementObj.click(); // will trigger the click event as the selected element chaining it.    

```

有时，我们可能需要触发`submit()`方法进行表单提交。在这种情况下，我们必须将`submit()`方法与所选元素链接起来。所选元素应该是一个`form`元素：

```ts
element.(Locator).submit(); 
elementObj.submit(); // Will trigger the submit for the form 
element as submit() work only for form element.   

```

## 定位器

定位器告诉 Protractor 如何在 DOM 元素中找到某个元素。Protractor 将`locator`作为全局工厂函数导出，将与全局`by`对象一起使用。根据我们的 DOM，我们可以以许多方式使用它们，但让我们看看一些最常用的方式。

我们可以通过将任何 CSS 选择器之一传递给`by.css`方法来选择任何元素，如下所示：

```ts
element(by.css(cssSelector));  
element.all(by.css(cssSelector)); 
<span class="selector"></span> 
element.all(by.css('.selector'));  // return the specific DOM element/elements that will have selector class on it 

```

我们可以通过将其元素 ID 传递给`by.id`方法来选择任何元素，如下所示：

```ts
element(by.id(id)); 
<span id="selectorID"></span>   
element(by.id('selectorID')); // return the specific DOM element that will have selectorID as element id on it  

```

我们还可以通过将其传递给`by.tagName`来选择特定的元素或元素标签名，如下所示：

```ts
element(by.tagName(htmlTagName)); 
element.all(by.tagName(htmlTagName)); 
<span data="myData">Content</span> 
element.all(by.tagName('span')); // will return the DOM element/elements of all span tag.  

```

要选择任何特定输入字段的 DOM 元素，我们可以在`by.name`方法中传递名称，如下所示：

```ts
element(by.name(elementName)); 
<input type="text" name="myInput"> 
element(by.name('myInput')); // will return the specific input field's DOM element that have name attr as myInput 

```

除了 CSS 选择器或 ID 之外，我们还可以通过将其文本标签传递给`by.buttonText`来选择特定的按钮：

```ts
<button name="myButton">Click Me</button> 
element(by.buttonText('Click Me')); // will return the specific button that will have Click Me as label text  
element(by.buttonText(textLabel)); 

```

我们可以通过将模型名称定义为`ng-model`传递给`by.model`来查找元素，如下所示：

```ts
element.(by.model); 
<span ng-model="userName"></span> 
element(by.model('userName')); // will return that specific element which have defined userName as model name    

```

同样，我们可以通过在`by.bindings`中定义的绑定`ng-bind`来查找特定的 DOM 元素，如下所示：

```ts
element.(by.binding); 
<span ng-bind="email"></span> 
element(by.binding('email')); // will return the element that have email as bindings with ng-bind  

```

除了之前解释的所有定位器，还有另一种找到特定 DOM 元素的方法：自定义定位器。在这里，我们必须使用`by.addLocator`创建一个自定义定位器，通过传递定位器名称和回调。然后，我们必须通过`by.customLocatorName(args)`传递该自定义定位器，如下所示：

```ts
element.(by.locatorName(args)); 
<button ng-click="someAction()">Click Me</button> 
by.addLocator('customLocator', function(args) { 
    // .....  
}) 
element(by. customLocator(args)); // will return the element that will match with the defined logic in the custom locator. This useful mostly when user need to select dynamic generated element.  

```

# Protractor 测试-事后分析

调试 e2e 测试有点困难，因为它们依赖于应用程序的整个生态系统。有时它们依赖于先前的操作，比如登录，有时它们依赖于权限。调试 e2e 的另一个主要障碍是它依赖于 WebDriver。由于它在不同的操作系统和浏览器上的行为不同，这使得调试 e2e 变得困难。除此之外，它生成了很长的错误消息，这使得很难区分与浏览器相关的问题和测试过程中的错误。

尽管如此，我们将尝试调试所有的 e2e 测试，看看对我们的情况有何作用。

## 失败类型

测试套件失败可能有各种原因，因为它依赖于 WebDriver 和系统中的各个部分。

让我们看看一些已知的失败类型：

+   **WebDrive 失败**：当命令无法完成时，WebDriver 会抛出错误。例如，浏览器无法获取定义的地址来帮助它导航，或者可能找不到预期的元素。

+   **WebDriver 意外失败**：有时，WebDriver 会因无法更新 Web 驱动程序管理器而失败并报错。这是一个与浏览器和操作系统相关的问题，尽管不常见。

+   **Angular 的 Protractor 失败**：当 Protractor 在库中找不到预期的 Angular 时，Protractor 会失败，因为 Protractor 测试依赖于 Angular 本身。

+   **Protractor Angular2 失败**：当配置中缺少`useAllAngular2AppRoots`参数时，Protractor 将在 Angular 项目的测试规范中失败，因为没有这个参数，测试过程将只查看一个单一的根元素，而期望在过程中有更多的元素。

+   **Protractor 超时失败**：有时，当测试规范陷入循环或长时间等待并且无法及时返回数据时，Protractor 会因超时而失败。但是，超时是可配置的，因此可以根据需要增加。

+   **期望失败**：这是测试规范中常见的失败。

## 加载现有项目

本测试中使用的代码来自第四章*使用 Protractor 进行端到端测试*。我们将代码复制到一个新目录：`angular-protractor-debug`。

作为提醒，该应用程序是一个待办事项应用程序，其中有一些待办事项列表，并且我们向其中添加了一些项目。它有一个单一的组件类`AppComponent`，其中有一个项目列表和一个`add`方法。

当前目录应该按以下结构组织：

![加载现有项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_001.jpg)

在验证文件夹结构与前面截图中显示的相同之后，第一步是通过运行以下命令在本地获取所需的依赖项`node_modules`：

```ts
**$ npm install**

```

这将安装所有所需的模块。现在，让我们使用`npm`命令构建和运行项目：

```ts
**$ npm start**

```

现在一切应该都没问题了：项目应该在`http://localhost:3000`上运行，并且输出应该如下所示：

![加载现有项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_002.jpg)

有了这个，我们就可以继续实现在我们的 Angular 项目中加入调试器的下一步了。

## 在项目中包含调试器

在将调试器添加到我们的项目之前，让我们在现有项目中运行 e2e 测试。我们希望在 e2e 测试规范中没有任何失败的情况下通过。

让我们使用以下命令运行它：

```ts
**$ npm run e2e**

```

如预期，我们的测试通过了。结果如下：

![将调试器包含在项目中](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_003.jpg)

我们可以在已通过的测试规范所在的位置添加我们的调试代码，但让我们将已通过的测试用例与调试器分开，并在不同的目录中进行调试。让我们创建一个新目录，`debug/`。我们需要该目录中的两个文件：一个用于配置，另一个用于规范。

对于 Protractor 配置文件，我们可以复制`protractor.conf.js`文件并将其重命名为`debugConf.js`。

配置中的一切都与先前的配置相同。但是，我们需要增加 Jasmine 测试的默认超时时间，否则在调试过程中测试将超时。

让我们将超时时间增加到`3000000`毫秒：

```ts
exports.config = { 
    // ....  
    jasmineNodeOpts: { 
      showColors: true, 
      defaultTimeoutInterval: 3000000 
    }, 
    // ..... 
}; 

```

接下来，我们将需要一个规范文件来编写测试规范和调试测试。将新的规范文件保存为`app.debug.e2e.ts`。哦是，我们需要再次更改配置文件以定义调试的规范文件。

```ts
exports.config = { 
    // ....  
    specs: [ 
      'app.debug.e2e.js' 
    ], 
    // ..... 
}; 

```

我们可以为`app.debug.e2e.ts`创建一个简单的测试规范文件。然后，我们可以添加调试代码并进行调试。

简单的测试规范如下所示：

```ts
describe('AppComponent Tests', () => { 
    beforeEach(() => { 
        browser.get('/'); 
    }); 

    it('Test spec for debug and play', () => { 

    }); 
}); 

```

# 暂停和调试

要调试任何测试规范，我们必须暂停测试过程并逐步查看发生了什么。Protractor 也有内置方法来暂停测试过程。以下是两种暂停和调试测试过程的方法：

+   `browser.pause()`

+   `browser.debugger()`

## 使用暂停

使用`browser.pause()`命令，调试 Protractor 测试变得简单而容易。使用`pause()`方法，我们可以进入 Protractor 调试器控制流，并执行一些命令来检查测试控制流中发生了什么。大多数情况下，开发人员在测试失败并出现未知错误以及出现长错误消息时使用调试器。

使用`browser.pause()`命令后，我们可以根据需要使用更多命令。

让我们简要看一下：

+   `c`：如果我们将`c`作为一个命令输入，它将在测试中向前移动一步，我们将深入了解测试命令的工作原理。如果我们计划继续进行测试，最好快点进行，因为会有超时问题（Jasmine 默认超时），我们已经了解过了。稍后我们会看到一个例子。

+   `repl`：通过输入`repl`作为命令，我们可以进入调试的交互模式。它被称为交互模式，因为我们可以直接从终端与浏览器交互，通过输入 WebDriver 命令。浏览器的响应、结果或错误也将显示在终端上。稍后我们将看到更多实际的例子。

+   `Ctrl + C`：按下***Ctrl*** + C 退出暂停模式并继续测试。当我们使用这个时，测试将从暂停的地方继续。

### 一个快速的例子

要在测试规范中使用`browser.pause()`，我们将在测试规范中的希望暂停测试并观察控制流的地方添加该方法。在这里，我们只有一个测试规范，有一个错误/失败的测试用例，我们知道它会失败，我们将找出失败的原因。

我们将如所示将`pause()`方法添加到测试`spec it() {}`函数中：

```ts
it('Test spec for debug and play', () => { 
  browser.pause(); 
  // There is not element with the id="my_id", so this will fail
  the test 
  expect(element(by.id('my_id')).getText()).toEqual('my text') 
});  

```

现在是时候运行测试了。由于我们已经将调试器的测试规范分开，我们将通过 Protractor（而不是`npm`）运行测试。

让我们用以下命令运行测试：

```ts
**$ protractor debug/debugConf.js**

```

由于我们在`expect()`方法之前放置了`browser.pause()`方法，它将在那里暂停。我们可以看到在控制流中，这使得它等待 Angular：

![一个快速的例子](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_004.jpg)

我们将继续前进；为此，让我们输入`C`。它将运行`executeAsyncScript`并等待 Angular 加载：

![一个快速的例子](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_005.jpg)

我们将再向前迈出一步，输入`C`。它将尝试根据我们提供的定位器选择元素，即`element(by.id('my_id')`：

![一个快速的例子](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_006.jpg)

现在我们接近获得测试结果了。为此，我们将再向前迈出一步，输入`C`。现在，它将尝试根据定位器选择元素，并且将无法选择。这将产生一个带有错误消息的结果，正如预期的那样：

![一个快速的例子](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_007.jpg)

### 使用交互模式进行调试

要进入交互模式，我们必须输入`repl`，之后可以运行测试规范中使用的任何命令。

让我们找到元素及其文本：

```ts
> element(by.id('my_id')).getText() 

```

结果与之前一样，通过逐步前进，输入`C`。

**结果**：`NoSuchElementError: 使用定位器未找到元素：By (css 选择器，` `*[id="my_id"])`

现在，让我们看看当`element`将被找到时，交互模式如何为有效的定位器工作：

```ts
> element.all(by.css('li')).first().getText() 

```

**结果**：`测试`

## 使用调试器

使用 `browser.debugger()` 命令进行调试比使用 `browser.pause()` 更复杂和更高级。使用 `browser.pause()` 命令，我们可以暂停测试的控制流，并将自定义辅助函数注入到浏览器中，以便调试的方式与我们在浏览器控制台中调试的方式相同。

这种调试应该在节点调试模式下进行，就像在 Protractor 调试中一样。这种调试对于不擅长节点调试的人来说并不有用。

这是一个例子：

要在测试规范中使用 `browser.debugger()` 方法，我们将不得不在测试规范中添加该方法，以设置断点并观察控制流。

对于我们来说，我们必须添加 `debugger()` 方法，如下所示，到 `test spec it() {}` 函数中，这将是我们的断点：

```ts
it('Test spec for debug and play', () => { 
  browser.debugger(); 
  // There is not element with the id="my_id", so this will fail 
the test 
  expect(element(by.id('my_id')).getText()).toEqual('my text') 
  });   

```

现在让我们运行它：

```ts
**$ protractor debug debug/debugConf.js**

```

### 注意

要运行调试器，我们必须在 `protractor` 后面添加 `debug`。

运行命令后，我们必须输入 `C` 继续，但这里我们只需要这样做一次。输出如下：

![使用调试器](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_05_008.jpg)

# 自测问题

Q1\. `Selenium WebDriver` 是一个浏览器自动化框架。

+   真

+   假

Q2\. 使用 `browser.debugger()` 是调试 Protractor 的一种简单方法。

+   真

+   假

Q3\. `by.css()`、`by.id()` 和 `by.buttonText()` 被称为什么？

+   元素

+   定位器

+   操作

+   浏览器

# 摘要

Protractor 有各种类型的 API。在本章中，我们试图了解一些最常用的 API，并提供了一些示例。我们还详细介绍了 API 类型（如浏览器、元素、定位器和操作），以及它们如何相互链接。

在本章中介绍了调试，并尝试学习了一种简单的调试方法，使用 `browser.pause()`，然后我们转向了一种复杂的方法（`browser.debugger()`），并了解到复杂的开发人员需要节点调试器经验。

在下一章中，我们将深入研究更多的现实项目；此外，我们将学习自上而下和自下而上的方法，并学会它们。


# 第六章：第一步

第一步总是最困难的。本章提供了如何使用 TDD 构建具有组件、类和模型的 Angular 应用程序的初始介绍性漫游。我们将能够开始 TDD 之旅，并看到基本原理的实际应用。到目前为止，本书侧重于 TDD 的基础和所需的工具。现在，我们将转变思路，深入研究 Angular 中的 TDD。

本章将是 TDD 的第一步。我们已经看到如何安装 Karma 和 Protractor，以及如何应用它们的小例子和漫游。在本章中，我们将重点关注：

+   创建一个简单的评论应用程序

+   将 Karma 和 Protractor 与应用程序集成

+   涵盖测试的组件及其相关类

# 准备应用程序的规格

创建一个输入评论的应用程序。应用程序的规格如下：

+   如果我发布了一个新评论，当我点击**提交**按钮时，评论应该被添加到评论列表中

+   当我点击**喜欢**按钮时，评论的喜欢数量应该增加

现在我们有了应用程序的规格，我们可以创建我们的开发待办事项列表。创建整个应用程序的待办事项列表并不容易。根据用户的规格，我们知道需要开发什么。以下是 UI 的草图：

![准备应用程序的规格](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_06_001-1.jpg)

不要急于进行实现，考虑我们将如何使用组件类、`*ngFor`等。抵制，抵制，抵制！虽然我们可以考虑未来的开发方式，但直到我们深入代码，这一切才会变得清晰，这也是我们开始遇到麻烦的地方。TDD 及其原则在这里帮助我们将思绪和注意力放在正确的地方。

# 设置 Angular 项目

在之前的章节中，我们详细讨论了如何设置项目，查看了涉及的不同组件，并走过了整个测试过程。我们将跳过这些细节，并在下一节中提供一个列表，用于初始化操作，以便设置项目并准备好进行单元测试和端到端测试的测试配置。

## 加载现有项目

我们将从 Angular 团队的示例中获取一个简单的 Angular 项目，并对其进行修改以适应我们的实现。

我们将从 Angular GitHub 仓库克隆`quickstart`项目，并从那个开始。除了`node`/`npm`之外，我们应该在全局安装 Git。

```ts
**$ git clone https://github.com/angular/quickstart.git 
    angular-project**

```

这将把项目本地复制为`angular-project`；这个项目可能包含一些额外的文件（它们可能会不断更新），但我们将尽量保持我们的项目文件夹结构看起来像这样：

![加载现有项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_06_002.jpg)

最初我们将保持简单，然后逐步添加所需的文件。这将使我们更加自信。

让我们继续进行并运行以下命令：

```ts
**$ cd angular-project**
**$ npm install**

```

`npm install`命令将安装项目依赖项所需的模块，这些模块在项目根目录中的`package.json`文件中定义。

## 设置目录

在先前的示例中，我们将组件、单元测试规范和端到端测试规范放在同一个文件夹中，以保持简单。对于一个更大的项目，在同一个文件夹中管理所有这些是困难的。

为了使其更易管理，我们将把测试规范放在一个单独的文件夹中。在这里，我们的示例`quickstart`项目已经将测试规范放在默认文件夹中，但我们将有一个新的结构，并将我们的测试文件放在新的结构中。

让我们开始设置项目目录：

1.  导航到项目的根文件夹：

```ts
        **cd angular-project**

```

1.  初始化测试（`spec`）目录：

```ts
        **mkdir spec**

```

1.  初始化`unit`测试目录：

```ts
        **mkdir spec/unit**

```

1.  初始化端到端（`e2e`）测试目录：

```ts
        **mkdir spec/e2e**

```

初始化完成后，我们的文件夹结构应如下所示：

![设置目录](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_06_003.jpg)

## 设置 Karma

Karma 的详细信息可以在第三章中找到，*Karma 之道*。在这里，我们将主要看一下 Karma 配置文件。

在这个`quickstart`项目中，我们已经安装并配置了 Karma，并且在项目目录中有`karma.conf.js`文件。

为了确认系统中有 Karma，让我们使用以下命令在全局安装它：

```ts
**npm install -g karma**

```

如前所述，我们已经在这个项目中配置了 Karma 作为`quickstart`项目的一部分，并且我们在项目目录中有`karma.conf.js`文件。

现在我们将看一些每个人都应该知道的基本配置选项。在这个配置文件中，还有一些高级选项，比如测试报告和错误报告。我们将跳过这些，因为在这个初始阶段并不是非常重要。

让我们了解一下我们将需要进一步进行的一些配置。

当我们在服务器上有自定义路径的项目时，`basePath`应该进行更新。目前是`''`，因为该项目在根路径上运行。下一个选项是`frameworks`；默认情况下，我们在这里使用`jasmine`，但是如果我们想使用其他框架，比如`mocha`，我们可以更改框架名称。需要记住的一点是，如果我们计划使用不同的框架，我们将不得不添加相关的插件。

```ts
    basePath: '', 
        frameworks: ['jasmine'], 

```

需要插件，因为 Karma 将使用这些`npm`模块来执行操作；例如，如果我们计划使用 PhantomJS 作为浏览器，我们需要将`'karma-phantomjs-launcher'`添加到列表中：

```ts
    plugins: [ 
            'karma-jasmine', 
            'karma-chrome-launcher' 
    ] 

```

下一个最重要的选项是`files[]`；通过这个，Karma 将包含所有测试所需的文件。它根据依赖加载文件。我们将在`files[]`数组中包含所有所需的文件。

首先，我们将添加`System.js`，因为我们在应用程序中使用`systemjs`作为模块加载器。然后，添加`polyfills`以在所有浏览器上支持 shim，`zone.js`以支持应用程序中的异步操作，RxJS 作为响应式库，Angular 库文件，Karma 测试的 shim，组件文件，最后是测试规范。列表中可能还有一些其他文件用于调试和报告；我们将跳过它们的解释。

我们的`files[]`数组将如下所示：

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
          watched: false },
          { pattern: 'node_modules/rxjs/**/*.js.map', included: 
          false, watched: false },

          // Paths loaded via module imports:
          // Angular itself
          { pattern: 'node_modules/@angular/**/*.js', included: 
          false, watched: false },
          { pattern: 'node_modules/@angular/**/*.js.map', included: 
          false, watched: false },

          { pattern: 'systemjs.config.js', included: false, watched: 
          false },
          { pattern: 'systemjs.config.extras.js', included: false, 
          watched: false },
          'karma-test-shim.js',

          // transpiled application & spec code paths loaded via 
          module imports
          { pattern: appBase + '**/*.js', included: false, watched: 
          true },
          { pattern: testBase + '**/*.spec.js', included: false, 
          watched: true },
],

```

这就是我们现在在`karma.conf`文件中需要知道的全部。如果需要，我们将通过更新这些设置来进行。

让我们来看看完整的`karma.conf.js`文件：

```ts
module.exports = function(config) {

  var appBase    = 'app/';       // transpiled app JS and map files
  var appSrcBase = 'app/';       // app source TS files
  var appAssets  = 'base/app/'; // component assets fetched by 
  Angular's compiler

  var testBase    = 'spec/unit/';       // transpiled test JS and map 
  files
  var testSrcBase = 'spec/unit/';       // test source TS files

  config.set({
    basePath: '',
    frameworks: ['jasmine'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'), // click "Debug" in 
      browser to see it
      require('karma-htmlfile-reporter') // crashing w/ strange 
      socket error
    ],

    customLaunchers: {
      // From the CLI. Not used here but interesting
      // chrome setup for travis CI using chromium
      Chrome_travis_ci: {
        base: 'Chrome',
        flags: ['--no-sandbox']
      }
    },
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
      { pattern: 'node_modules/rxjs/**/*.js.map', included: false, 
      watched: false },

      // Paths loaded via module imports:
      // Angular itself
      { pattern: 'node_modules/@angular/**/*.js', included: false, 
      watched: false },
      { pattern: 'node_modules/@angular/**/*.js.map', included: 
      false, watched: false },

      { pattern: 'systemjs.config.js', included: false, watched: 
      false },
      { pattern: 'systemjs.config.extras.js', included: false, 
      watched: false },
      'karma-test-shim.js',

      // transpiled application & spec code paths loaded via module 
      imports
      { pattern: appBase + '**/*.js', included: false, watched: true 
      },
      { pattern: testBase + '**/*.spec.js', included: false, watched: 
      true },

      // Asset (HTML & CSS) paths loaded via Angular's component 
      compiler
      // (these paths need to be rewritten, see proxies section)
      { pattern: appBase + '**/*.html', included: false, watched: true 
      },
      { pattern: appBase + '**/*.css', included: false, watched: true 
      },

      // Paths for debugging with source maps in dev tools
      { pattern: appSrcBase + '**/*.ts', included: false, watched: 
      false },
      { pattern: appBase + '**/*.js.map', included: false, watched: 
      false },
      { pattern: testSrcBase + '**/*.ts', included: false, watched: 
      false },
      { pattern: testBase + '**/*.js.map', included: false, watched: 
      false }
    ],

    // Proxied base paths for loading assets
     proxies: {
       // required for component assets fetched by Angular's compiler
       "/app/": appAssets
   },

    exclude: [],
    preprocessors: {},
    // disabled HtmlReporter; suddenly crashing w/ strange socket 
    error
    reporters: ['progress', 'kjhtml'],//'html'],

    // HtmlReporter configuration
    htmlReporter: {
      // Open this file to see results in browser
      outputFile: '_test-output/tests.html',

      // Optional
      pageTitle: 'Unit Tests',
      subPageTitle: __dirname
    },

    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['Chrome'],
    singleRun: true
  })
};

```

## 测试目录已更新

我们在第三章中看到了`karma-test-shim.js`的详细信息，*Karma 方式*。这是通过 Karma 运行单元测试所需的。

我们已经更改了测试规范目录/位置，并且`karma-test-shim.js`是根据项目的默认结构进行配置的。因为我们已经将测试移动到不同的位置并且不在`app/`文件夹中，我们需要相应地更新`karma-test-shim.js`。

这是需要进行的更改：

```ts
    var builtPath = '/base/'; 

```

## 设置 Protractor

在第四章中，*使用 Protractor 进行端到端测试*，我们讨论了 Protractor 的完整安装和设置。这个示例应用程序已经安装和配置了 Protractor。因此，我们只需要查看`protractor.conf.js`文件。

配置的 Protractor 实例已实现了测试报告。我们将跳过配置文件中的这些部分，只看一下常见的设置选项。

在我们进入配置文件概述之前，为了确保，我们将在系统上全局安装 Protractor：

```ts
**$ npm install -g protractor**

```

更新 Selenium WebDriver：

```ts
**$ webdriver-manager update**

```

我们必须确保 Selenium 已安装。

如预期的那样，`protractor.conf.js`位于应用程序的根目录。这是`protractor.conf.js`文件的完整配置：

```ts
var fs = require('fs'); 
var path = require('canonical-path'); 
var _ = require('lodash'); 

exports.config = { 
  directConnect: true, 

  // Capabilities to be passed to the webdriver instance. 
  capabilities: { 
    'browserName': 'chrome' 
  }, 

  // Framework to use. Jasmine is recommended. 
  framework: 'jasmine', 

  // Spec patterns are relative to this config file 
  specs: ['**/*e2e-spec.js' ], 

  // For angular tests 
  useAllAngular2AppRoots: true, 

  // Base URL for application server 
  baseUrl: 'http://localhost:8080', 

  // doesn't seem to work. 
  // resultJsonOutputFile: "foo.json", 

  onPrepare: function() { 
    //// SpecReporter 
    //var SpecReporter = require('jasmine-spec-reporter'); 
    //jasmine.getEnv().addReporter(new 
    SpecReporter({displayStacktrace: 'none'}));  
    //// jasmine.getEnv().addReporter(new SpecReporter({
    displayStacktrace: 'all'})); 

    // debugging 
    // console.log('browser.params:' +    
    JSON.stringify(browser.params)); 
    jasmine.getEnv().addReporter(new Reporter( browser.params )) ; 

    // Allow changing bootstrap mode to NG1 for upgrade tests 
    global.setProtractorToNg1Mode = function() { 
      browser.useAllAngular2AppRoots = false; 
      browser.rootEl = 'body'; 
    }; 
  }, 

  jasmineNodeOpts: { 
    // defaultTimeoutInterval: 60000, 
    defaultTimeoutInterval: 10000, 
    showTiming: true, 
    print: function() {} 
  } 
};  

```

# 自上而下与自下而上的方法-我们使用哪种？

从开发的角度来看，我们必须确定从哪里开始。本书将讨论的方法如下：

+   **自下而上的方法**：采用这种方法，我们考虑我们将需要的不同组件（类、服务、模块等），然后选择最合乎逻辑的组件并开始编码。

+   **自上而下的方法**：采用这种方法，我们从用户场景和 UI 开始工作。然后我们围绕应用程序中的组件创建应用程序。

这两种方法都有其优点，选择可以基于您的团队、现有组件、需求等。在大多数情况下，最好根据最小阻力来做出选择。

在本章中，规范的方法是自上而下的；一切都为您准备好，从用户场景开始，将允许您有机地围绕 UI 构建应用程序。

# 测试一个组件

在进入交付功能的规范和思维方式之前，重要的是要了解测试组件类的基本知识。在大多数应用程序中，Angular 中的组件是一个关键特性。

## 准备好开始

我们的示例应用程序（`quickstart`）有一些非常基本的单元测试和端到端测试规范。我们将从一开始采用 TDD 方法，因此在实现过程中不会使用任何测试规范和现有组件的代码。

为此，我们可以做的就是清理这个示例应用程序，只保留文件夹结构和应用程序引导文件。

因此，首先，我们必须删除单元测试文件（`app.component.spec.ts`）和端到端测试文件（`app.e2e-spec.ts`）。这两个测试规范存在于应用程序结构中。

## 设置一个简单的组件测试

在测试组件时，将组件注入测试套件中，然后将组件类初始化为第二个任务非常重要。测试确认组件范围内的对象或方法是否按预期可用。

为了在测试套件中拥有组件实例，我们将在测试套件中使用简单的`import`语句，并在`beforeEach`方法中初始化组件对象，以便在测试套件中的每个测试规范中都有组件对象的新实例。以下是一个示例：

```ts
import { async, ComponentFixture, TestBed } from '@angular/core/testing'; 

import {AppComponent} from "../../app.component"; 

describe('AppComponent Tests Suite', () => { 

  let comp: AppComponent; 
  let fixture: ComponentFixture<AppComponent>; 

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
}); 

```

因此，只要为每个测试规范初始化组件类，它就会为每个规范创建一个新实例，并且内部范围将根据此进行操作。

## 初始化组件

为了测试组件，重要的是初始化组件类，以便在测试套件的范围内拥有组件对象，并且对象的所有成员都在特定的测试套件周围可用。

只要组件包含渲染 UI 的模板，就需要在开始端到端测试之前初始化组件，并且这取决于 DOM 元素。

因此，当我们计划对任何组件进行端到端测试时，我们应该在 DOM 中初始化它，如下所示：

```ts
<body> 
  <my-app></my-app> 
</body> 

```

## 端到端与组件的单元测试

在前面的示例中，我们看了组件测试套件，这是用于单元测试的，我们需要导入并创建组件类的实例作为单元测试。我们将测试组件中定义的每个方法的功能或特性。

另一方面，对于端到端测试，我们不需要导入或创建组件类的实例，因为我们不需要使用组件对象或其所有成员进行交互。相反，它需要与正在运行的应用程序的登陆页面的 DOM 元素进行交互。

因此，为此，我们需要运行应用程序并将测试套件导航到应用程序的登陆页面，我们可以使用 Protractor 本身提供的全局`browser`对象来实现这一点。

这是一个示例，它应该是这样的：

```ts
import { browser, element, by } from 'protractor'; 

describe('Test suite for e2e test', () => { 
    beforeEach(() => { 
        browser.get(''); 
    }); 
}); 

```

我们可以根据需要使用`browser.get('path')`导航到应用程序的所有 URL。

# 深入我们的评论应用程序

现在设置和方法已经确定，我们可以开始我们的第一个测试。从测试的角度来看，由于我们将使用自顶向下的方法，我们将首先编写我们的 Protractor 测试，然后构建应用程序。我们将遵循我们已经审查过的相同的 TDD 生命周期：首先测试，使其运行，然后使其更好。

## 首先测试

给定的场景已经以规范的格式给出，并符合我们的 Protractor 测试模板：

```ts
describe('', () => { 
    describe('', () => { 
     beforeEach(() => { 
     }); 

      it('', () => { 
      }); 
    }); 
}); 

```

将场景放入模板中，我们得到以下代码：

```ts
describe('Given I am posting a new comment', () => { 
    describe('When I push the submit button', () => { 
        beforeEach(() => { 
            // ...  
        }); 

        it('Should then add the comment', () => { 
            // ... 
        }); 
    }); 
}); 

```

遵循 3A 原则（组装、行动、断言），我们将把用户场景放入模板中。

### 组装

浏览器将需要指向应用程序的第一个页面。由于基本 URL 已经定义，我们可以将以下内容添加到测试中：

```ts
beforeEach(() => { 
    browser.get(''); 
}); 

```

现在测试已经准备好，我们可以继续下一步：行动。

### 行动

根据用户的规范，我们需要做的下一件事是添加一个实际的评论。最简单的方法就是将一些文本放入输入框中。对于这个测试，再次不知道元素将被称为什么或者它将做什么，我们将根据它应该是什么来编写它。

以下是为应用程序添加评论部分的代码：

```ts
beforeEach(() => { 
    ... 
    var commentInput = element(by.css('input')); 
    commentInput.sendKeys('a sample comment'); 
}); 

```

作为测试的一部分，最后一个组件是点击“提交”按钮。在 Protractor 中可以很容易地通过 `click` 函数实现这一点。即使我们还没有页面，或者任何属性，我们仍然可以命名将要创建的按钮：

```ts
beforeEach(() => { 
    ... 
    var submitButton = element(by.buttonText('Submit')).click(); 
}); 

```

最后，我们将击中测试的关键点，并断言用户的期望。

### 断言

用户期望是一旦点击“提交”按钮，评论就会被添加。这有点模糊，但我们可以确定用户需要以某种方式收到评论已添加的通知。

最简单的方法是在页面上显示所有评论。在 Angular 中，这样做的最简单方法是添加一个 `*ngFor` 对象来显示所有评论。为了测试这一点，我们将添加以下内容：

```ts
it('Should then add the comment', () => { 
    var comment = element.all(by.css('li')).first(); 
    expect(comment.getText()).toBe('a sample comment'); 
}); 

```

现在测试已经构建并满足用户的规范。它既小又简洁。以下是完成的测试：

```ts
describe('Given I am posting a new comment', () => { 
    describe('When I push the submit button', () => { 
      beforeEach(() => { 
            //Assemble 
            browser.get(''); 
            var commentInput = element(by.css('input')); 
            commentInput.sendKeys('a sample comment'); 

            //Act 
            var submitButton =  element(by.buttonText
            ('Submit')).click(); 
      }); 

       //Assert 
  it('Should then add the comment', () => { 
            var comment = element.all(by.css('li')).first(); 
            expect(comment.getText()).toBe('a sample comment'); 
  }); 
    }); 
}); 

```

## 使其运行

基于测试的错误和输出，我们将在构建应用程序的过程中进行。

使用以下命令启动 Web 服务器：

```ts
**$ npm start**

```

运行 Protractor 测试以查看第一个错误：

```ts
**$ protractor**

```

或者，我们可以运行这个：

```ts
**$ npm run e2e // run via npm** 

```

我们的第一个错误可能是没有得到定位器期望的元素：

```ts
**$ Error: Failed: No element found using locator: 
    By(css selector, input)**

```

错误的原因很简单：它没有按照定位器中定义的元素获取。我们可以看到当前的应用程序以及为什么它没有获取到元素。

### 总结当前应用程序

只要我们将示例 Angular`quickstart`项目克隆为我们要测试的应用程序，它就具有一个准备好的 Angular 环境。它使用一个简单的应用程序组件定义了“我的第一个 Angular 2 应用程序”作为输出来引导 Angular 项目。

因此，在我们的 TDD 方法中，我们不应该有任何与环境/Angular 引导相关的错误，看起来我们走在了正确的道路上。

让我们看看我们的示例应用程序现在有什么。在我们的首页`index.html`中，我们已经包含了所有必需的库文件，并实现了`system.js`来加载应用程序文件。

在`index.html`文件中的`<body>`标签中，我们已经启动了应用程序，如下所示：

```ts
<body> 
    <my-app>Loading...</my-app> 
</body> 

```

HTML 标签期望一个带有`my-app`作为该组件选择器的组件，是的，我们有`app.component.ts`如下：

```ts
import {Component} from '@angular/core'; 
@Component({ 
    selector: 'my-app', 
    template: '<h1>My First Angular 2 App</h1>' 
}) 
export class AppComponent { } 

```

Angular 引入了`ngModule`作为`appModule`，以模块化和管理每个组件的依赖关系。通过这个`appModule`，应用程序可以一目了然地定义所有所需的依赖关系。除此之外，它还帮助延迟加载模块。我们将在 Angular 文档中详细了解`ngModule`的细节。

它在应用程序中导入了所有必需的模块，从单一入口点声明了所有模块，并且还定义了引导组件。

应用程序总是基于该文件的配置进行引导。

该文件位于应用程序根目录下，名为`app.module.ts`，其内容如下：

```ts
import { NgModule }      from '@angular/core'; 
import { BrowserModule } from '@angular/platform-browser'; 

import { AppComponent }  from './app.component'; 

@NgModule({ 
  imports:      [ BrowserModule], 
  declarations: [ AppComponent ], 
  bootstrap:    [ AppComponent ] 
}) 
export class AppModule { } 

```

应用程序的入口点是`main.ts`文件，它将导入`appModule`文件，并指示根据该文件引导应用程序：

```ts
import { platformBrowserDynamic } from '@angular/platform
-browser-dynamic'; 

import { AppModule } from './app.module'; 

platformBrowserDynamic().bootstrapModule(AppModule); 

```

测试找不到我们的输入定位器。我们需要将输入添加到页面，并且我们需要通过组件的模板来做到这一点。

### 添加输入

以下是我们需要遵循的步骤来将输入添加到页面：

1.  我们将不得不在应用程序组件的模板中添加一个简单的`input`标签，如下所示：

```ts
        template: ` 
        <input type='text' />` 

```

1.  再次运行测试后，似乎与输入定位器相关的错误已经没有了，但是出现了一个新的错误，即`button`标签丢失：

```ts
        **$ Error: Failed: No element found using locator: 
        by.buttonText('Submit')**

```

1.  就像之前的错误一样，我们需要在模板中添加一个`button`，并附上适当的文本：

```ts
        template: ` ...........  
        <button type='button'>Submit</button>` 

```

1.  再次运行测试后，似乎没有与`button`定位器相关的错误，但是又出现了新的错误，如下所示，重复器定位器丢失：

```ts
        **$ Error: Failed: No element found using locator: By
        (css selector, li)**

```

这似乎是我们假设提交的评论将通过`*ngFor`在页面上可用的结果。为了将其添加到页面上，我们将在组件类中使用一个方法来为重复器提供数据。

### 组件

如前所述，错误是因为没有`comments`对象。为了添加`comments`对象，我们将使用具有`comments`数组的组件类。

执行以下步骤将`comments`对象添加到作用域中：

1.  由于我们已经在组件中有`AppComponent`作为一个类，我们需要定义评论数组，我们可以在重复器中使用：

```ts
        export class AppComponent { 
            comments:Array<string>; 
        } 

```

1.  然后，我们将在模板中为评论添加一个重复器，如下所示：

```ts
        template: `..........  
            <ul> 
              <li *ngFor="let comment of comments">{{comment}}</li> 
            </ul>` 

```

1.  让我们运行 Protractor 测试，看看我们的进展：

```ts
        **$   Error: Failed: No element found using locator: By(css
        selector, li)**

```

糟糕！我们仍然得到相同的错误。不过别担心，可能还有其他问题。

让我们看看实际呈现的页面，看看发生了什么。在 Chrome 中，导航到`http://localhost:3000`并打开控制台以查看页面源代码（*Ctrl + Shift + J*）。请注意，重复器和组件都在那里；但是，重复器被注释掉了。由于 Protractor 只查看可见元素，它不会找到列表。

太棒了！现在我们知道为什么重复列表不可见，但是我们必须修复它。为了使评论显示出来，它必须存在于组件的`comments`作用域中。

最小的更改是向数组中添加一些内容以初始化它，如下面的代码片段所示：

```ts
export class AppComponent { 
    comments:Array<string>; 
    constructor() { 
        this.comments = ['First comment', 'Second comment',
        'Third comment']; 
    } 
}; 

```

现在，如果我们运行测试，我们会得到以下输出：

```ts
**$ Expected 'First comment' to be 'a sample comment'.**

```

很好，看起来我们离成功更近了！我们已经解决了几乎所有意外错误并达到了我们的期望。

让我们来看看我们迄今为止所做的更改以及我们的代码是什么样子的。

这是`index.html`文件的`body`标签：

```ts
<body> 
    <my-app>Loading...</my-app> 
</body> 

```

应用组件文件如下：

```ts
import {Component} from '@angular/core'; 

@Component({ 
    selector: 'my-app', 
    template: `<h1>My First Angular 2 App</h1> 
    <input type='text' /> 
    <button type='button'>Submit</button> 
    <ul> 
      <li *ngFor="let comment of comments">{{comment}}</li> 
    </ul>` 
}) 
export class AppComponent { 
    comments:Array<string>; 

    constructor() { 
        this.comments = ['First comment', 'Second comment', 
        'Third comment']; 
    } 
} 

```

## 使其通过

使用 TDD，我们希望添加最小可能的组件来使测试通过。

由于我们目前已经将评论数组硬编码为初始化为三个项目，并且第一个项目为`First comment`，将`First comment`更改为`a sample comment`，这应该使测试通过。

以下是使测试通过的代码：

```ts
export class AppComponent { 
    comments:Array<string>; 
    constructor() { 
        this.comments = ['a sample comment', 'Second comment', 
        'Third comment']; 
    } 
}; 

```

运行测试，哇！我们得到了一个通过的测试：

```ts
**$ 1 test, 1 assertion, 0 failures**

```

等一下！我们还有一些工作要做。虽然我们让测试通过了，但还没有完成。我们添加了一些黑客技巧，只是为了让它通过。有两件事引人注目：

+   我们单击了实际上没有任何功能的“提交”按钮

+   我们对评论的预期值进行了硬编码初始化

在我们继续之前，上述更改是我们需要执行的关键步骤。它们将在 TDD 生命周期的下一个阶段中解决，即使其更好（重构）。

## 使其更好

需要重新设计的两个组件如下：

+   为“提交”按钮添加行为

+   删除评论的硬编码值

### 实现“提交”按钮

“提交”按钮需要实际做一些事情。我们可以通过硬编码值来绕过实现。使用我们经过验证的 TDD 技术，转而采用专注于单元测试的方法。到目前为止，重点一直放在 UI 上并将更改推送到代码上；我们还没有编写单个单元测试。

在接下来的工作中，我们将转变思路，专注于通过测试驱动“提交”按钮的开发。我们将遵循 TDD 生命周期（先测试，使其运行，然后使其更好）。

#### 配置卡尔玛

我们在第三章中为待办事项列表应用程序做了非常类似的事情，“卡尔玛方式”。我们不会花太多时间深入到代码中，所以请查看以前的章节，以深入讨论一些属性。

以下是我们需要遵循的配置卡尔玛的步骤：

1.  使用添加的文件更新`files`部分：

```ts
        files: [ 
            ... 
            // Application files 
            {pattern: 'app/**/*.js', included: false, watched: 
            true} 

            // Unit Test spec files 
            {pattern: 'spec/unit/**/*.spec.js', included: false,
            watched: true} 
            ... 
        ], 

```

1.  启动卡尔玛：

```ts
        **$ karma start**

```

1.  确认卡尔玛正在运行：

```ts
        **$ Chrome 50.0.2661 (Mac OS X 10.10.5): Executed 0 of 0 
        SUCCESS (0.003 secs / 0 secs)**

```

#### 先测试

让我们从`spec/unit`文件夹中的新文件开始，名为`app.component.spec.ts`。这将包含单元测试的测试规范。我们将使用基本模板，包括所有必要的导入，如`TestBed`：

```ts
    describe('', () => { 
     beforeEach(() => { 
     }); 

      it('', () => { 
      }); 
    }); 

```

根据规范，当单击“提交”按钮时，需要添加评论。我们需要填写测试的三个组成部分（组装、行动和断言）的空白。

组装

行为需要成为前端组件的一部分来使用。在这种情况下，测试的对象是组件的范围。我们需要将这一点添加到这个测试的组装中。就像我们在第三章中所做的那样，“卡尔玛方式”，我们将在以下代码中做同样的事情：

```ts
import {AppComponent} from "../../app/app.component"; 

describe('AppComponent Unit Test', () => { 
    let comp: AppComponent; 
    let fixture: ComponentFixture<AppComponent>; 

    beforeEach(() => { fixture = TestBed.create
    Component(AppComponent); 
      comp = fixture.componentInstance; 

    }); 
}); 

```

现在，`component`对象及其成员在测试套件中可用，并将如预期般进行测试。

**行动**

规范确定我们需要在组件对象中调用`add`方法。将以下代码添加到测试的`beforeEach`部分：

```ts
beforeEach(() => { comp.add('a sample comment'); 
}); 

```

现在，断言应该获取第一个评论进行测试。

**断言**

断言`component`对象中的评论项现在包含任何评论作为第一个元素。将以下代码添加到测试中：

```ts
it('',function(){ 
  expect(com.comments[0]).toBe('a sample comment'); 
}); 

```

保存文件，让我们继续进行生命周期的下一步并运行它（执行）。

#### 让它运行

现在我们已经准备好测试，我们需要让测试通过。查看 Karma 运行时的控制台输出，我们看到以下内容：

```ts
**$ TypeError: com.add is not a function**

```

查看我们的单元测试，我们看到这是`add`函数。让我们继续按照以下步骤将`add`函数放入控制器的`scope`对象中：

1.  打开控制器范围并创建一个名为`add`的函数：

```ts
        export class AppComponent { 
            ............. 
            add() { 
            // .... 
            } 
        } 

```

1.  检查 Karma 的输出，让我们看看我们的进展：

```ts
        **$ Expected 'First comment' to be 'a sample comment'.**

```

1.  现在，我们已经达到了期望。记住要考虑最小的改变来使其工作。修改`add`函数，将`$scope.comments`数组设置为任何评论：

```ts
        export class AppComponent { 
            ............. 
            add() { 
                this.comments.unshift('a sample comment'); 
            } 
        }; 

```

### 注意

`unshift`函数是一个标准的 JavaScript 函数，它将一个项目添加到数组的开头。

当我们检查 Karma 的输出时，我们会看到以下内容：

```ts
**$ Chrome 50.0.2661 (Mac OS X 10.10.5): Executed 1 of 1 
    SUCCESS (0.008 secs / 0.002 secs)**

```

成功！测试通过了，但还需要一些工作。让我们继续进行下一阶段并改进它（重构）。

#### 让它变得更好

需要重构的主要点是`add`函数。它不接受任何参数！这应该很容易添加，并且只是确认测试仍然运行。更新`app.component.ts`的`add`函数，以接受一个参数并使用该参数添加到`comments`数组中：

```ts
export class AppComponent { 
    ............. 
    add(comment) { 
        this.comments.unshift(comment); 
    } 
}; 

```

检查 Karma 的输出窗口，并确保测试仍然通过。完整的单元测试如下所示：

```ts
import {AppComponent} from "../../app/app.component"; 

describe('AppComponent Tests', () => { 
    let comp: AppComponent; 
    let fixture: ComponentFixture<AppComponent>; 

    beforeEach(() => { 
        fixture = TestBed.createComponent(AppComponent); 
        comp = fixture.componentInstance;         
        comp.add('a sample comment'); 
    }); 

    it('First item inthe item should match', () => { 
        expect(com.comments[0]).toBe('a sample comment'); 
    }); 
}); 

```

`AppComponent`类文件现在是这样的：

```ts
import {Component} from '@angular/core'; 

@Component({ 
    selector: 'my-app', 
    template: `<h1>My First Angular 2 App</h1> 
    <input type='text' /> 
    <button type='button'>Submit</button> 
    <ul> 
      <li *ngFor="let comment of comments">{{comment}}</li> 
    </ul>` 
}) 
export class AppComponent { 
    comments:Array<string>; 

    constructor() { 
        this.comments = ['First comment', 'Second comment', 
        'Third comment']; 
    } 
    add(comment) { 
        this.comments.unshift(comment); 
    } 
} 

```

### 备份测试链

我们完成了单元测试并添加了`add`函数。现在我们可以添加函数来指定**提交**按钮的行为。将`add`方法链接到按钮的方法是使用`(click)`事件。添加行为到**提交**按钮的步骤如下：

1.  打开`app.component.ts`文件并进行以下更新：

```ts
        @Component({ 
           template: `....... 
            <button type="button" (click)="add('a sample      
            comment')">Submit</button> 
            ...........` 
        }) 

```

等等！这个值是硬编码的吗？好吧，我们再次希望做出最小的更改，并确保测试仍然通过。我们将不断进行重构，直到代码达到我们想要的状态，但我们不想采取大爆炸的方式，而是希望进行小的、增量的改变。

1.  现在，让我们重新运行 Protractor 测试，并确保它仍然通过。输出显示它通过了，我们没问题。硬编码的值没有从注释中删除。让我们继续并立即删除它。

1.  `AppComponent` 类文件现在应该如下所示：

```ts
        constructor() { 
            this.comments = []; 
        } 

```

1.  运行测试，看到我们仍然得到一个通过的测试。

我们需要清理的最后一件事是 `(click)` 中的硬编码值。添加的评论应该由评论输入文本中的输入确定。

## 绑定输入

以下是我们需要遵循的绑定输入的步骤：

1.  为了能够将输入绑定到有意义的东西，将 `ngModel` 属性添加到 `input` 标签中：

```ts
        @Component({ 
            template: `............. 
            <input type="text" [(ngModel)]="newComment"> 
            ...........` 
        }) 

```

1.  然后，在 `(click)` 属性中，简单地使用 `newComment` 模型作为输入：

```ts
        @Component({ 
           template: `....... 
            <button type="button" (click)="add(newComment)">
            Submit</button> 
            ...........` 
        }) 

```

1.  我们将不得不在应用程序模块（`app.module.ts`）中导入表单模块，因为它是 `ngModel` 的依赖项：

```ts
        import { FormsModule }   from '@angular/forms'; 
        @NgModule({ 
        imports: [ BrowserModule, FormsModule ], 
        }) 

```

1.  运行 Protractor 测试，并确认一切都通过了，可以进行。

# 向前迈进

现在我们已经让第一个规范工作了，并且它是端到端和单元测试的，我们可以开始下一个规范。下一个规范说明用户希望能够喜欢一条评论。

我们将采用自上而下的方法，从 Protractor 开始我们的测试。我们将继续遵循 TDD 生命周期：先测试，使其运行，然后使其更好。

## 先测试

按照模式，我们将从一个基本的 Protractor 测试模板开始：

```ts
describe('', () => { 
     beforeEach(() => { 
     }); 

      it('', () => { 
      }); 
    }); 

```

当我们填写规范时，我们得到以下结果：

```ts
describe('When I like a comment', () => { 
    beforeEach(() => { 
    }); 

    it('should then be liked', () => { 
      }); 
}); 

```

有了模板，我们准备构建测试。

### 组装

这个测试的组装将需要存在一个评论。将评论放在现有的发布评论测试中。它应该看起来类似于这样：

```ts
describe(''Given I am posting a new comment', () => { 
    describe('When I like a comment', () => { 
    ... 
    }); 
}); 

```

### 行动

我们测试的用户规范是**Like**按钮对特定评论执行操作。以下是需要的步骤和执行它们所需的代码（请注意，以下步骤将添加到 `beforeEach` 文本中）：

1.  存储第一条评论，以便在测试中使用：

```ts
        var firstComment = null; 
        beforeEach(() => { 
            ... 
        } 

```

1.  找到第一条评论的 `likeButton`：

```ts
        var firstComment = element.all(by.css('li').first(); 
        var likeButton = firstComment.element(by.buttonText('like')); 

```

1.  当点击**Like**按钮时，代码如下：

```ts
        likeButton.click(); 

```

### 断言

规范的期望是一旦评论被点赞，它就会被点赞。最好的方法是通过放置点赞数量的指示器，并确保计数为`1`。然后代码将如下所示：

```ts
it('Should increase the number of likes to one', () => { 
var commentLikes = firstComment.element(by.binding('likes')); 
  expect(commentLikes.getText()).toBe(1); 
}); 

```

现在创建的测试看起来是这样的：

```ts
describe('When I like a comment', () => { 
    var firstComment = null; 
    beforeEach(() => { 

      //Assemble 
      firstComment = element.all(by.css('li').first(); 
      var likeButton = firstComment.element(by.buttonText('like')); 

      //Act 
      likeButton.click(); 
  }); 

  //Assert 
  it('Should increase the number of likes to one', () => { 
      var commentLikes = firstComment.element(by.css('#likes')); 
      expect(commentLikes.getText()).toBe(1); 
  }); 
}); 

```

## 让它运行

测试已经准备就绪，迫不及待地要运行。我们现在将运行它并修复代码，直到测试通过。以下步骤将详细说明需要进行的错误和修复循环，以使测试路径：

1.  运行 Protractor。

1.  在命令行中查看错误消息：

```ts
**$ Error: No element found using locator: by.buttonText("like")**

```

1.  正如错误所述，没有**like**按钮。继续添加按钮：

```ts
        @Component({ 
              template: `........ 
              <ul> 
              <li *ngFor="let comment of comments"> 
              {{comment}} 
            <button type="button">like</button> 
              </li> 
              </ul>` 
          }); 

```

1.  运行 Protractor。

1.  查看下一个错误消息：

```ts
**$ Expected 'a sample comment like' to be 'a sample comment'.**

```

1.  通过添加**like**按钮，我们导致其他测试失败。原因是我们使用了`getText()`方法。Protractor 的`getText()`方法获取内部文本，包括内部元素。

1.  为了解决这个问题，我们需要更新先前的测试，将**like**作为测试的一部分包括进去：

```ts
        it('Should then add the comment', () => { 
          var comments = element.all(by.css('li')).first(); 
          expect(comments.getText()).toBe('a sample comment like'); 
        }); 

```

1.  运行 Protractor。

1.  查看下一个错误消息：

```ts
**$ Error: No element found using locator: by.css("#likes")**

```

1.  现在是添加`likes`绑定的时候了。这个稍微复杂一些。`likes`需要绑定到一个评论。我们需要改变组件中保存评论的方式。评论需要保存`comment`标题和点赞数。评论应该是这样的一个对象：

```ts
        {title:'',likes:0} 

```

1.  再次强调，这一步的重点只是让测试通过。下一步是更新组件的`add`函数，以根据我们在前面步骤中描述的对象创建评论。

1.  打开`app.component.ts`并编辑`add`函数，如下所示：

```ts
        export class AppComponent { 
            ...... 
              add(comment) { 
                  var commentObj = {title: comment, likes: 0}; 
                  this.comments.unshift(commentObj); 
              } 
        } 

```

1.  更新页面以使用评论的值：

```ts
        @Component({ 
            template: `........... 
            <ul> 
              <li *ngFor="let comment of comments"> 
          {{comment.title}} 
            </li> 
            </ul>` 
        }) 

```

1.  在重新运行 Protractor 测试之前，我们需要将新的`comment.likes`绑定添加到 HTML 页面中：

```ts
        @Component({ 
            template: `........... 
            <ul> 
              <li *ngFor="let comment of comments"> 
          {{comment.title}} 
          ............. 
          <span id="likes">{{comment.likes}}</span> 
              </li> 
          </ul>` 
        }) 

```

1.  现在重新运行 Protractor 测试，让我们看看错误在哪里：

```ts
**$ Expected 'a sample comment like 0' to be 'a sample
        comment like'**

```

1.  由于评论的内部文本已更改，我们需要更改测试的期望：

```ts
        it('Should then add the comment',() => { 
        ... 
          expect(comments.getText()).toBe('a sample comment like 0'); 
        }); 

```

1.  运行 Protractor：

```ts
**$ Expected '0' to be '1'.**

```

1.  最后，我们来到了测试的期望。为了使这个测试通过，最小的更改将是使**like**按钮更新`comment`数组上的点赞数。第一步是在控制器中添加一个`like`方法，它将更新点赞数：

```ts
        export class AppComponent { 
            ...... 
              like(comment) { 
                  comment.like++; 
              } 
        } 

```

1.  将`like`方法与 HTML 页面链接，使用按钮上的`(click)`属性，如下所示：

```ts
        @Component({ 
              template: `........ 
              <ul> 
              <li *ngFor="let comment of comments"> 
              {{comment}} 
            <button type="button" (click)="like(comment)">
            like</button> 
        <span id="likes">{{comment.likes}}</span> 
              </li> 
              </ul>` 
          }); 

```

1.  运行 Protractor 并确认测试通过！

页面现在看起来如下截图：

![让它运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-test-dvn-dev/img/image_06_004.jpg)

与本章开头的图表相比，所有功能都已创建。现在我们已经让 Protractor 中的测试通过了，我们需要检查单元测试以确保我们的更改没有破坏它们。

### 修复单元测试

所需的主要更改之一是将评论作为一个包含值和点赞数量的对象。在过多考虑单元测试可能受到影响之前，让我们开始吧。执行以下命令：

```ts
**$ karma start**

```

如预期的那样，错误与新的`comment`对象有关：

```ts
**$ Expected { value : 'a sample comment', likes : 0 } to be 
    'a sample comment'.**

```

审查期望，似乎唯一需要的是在期望中使用`comment.value`，而不是`comment`对象本身。将期望更改如下：

```ts
it('',() => { 
    var firstComment = app.comments[0]; 
    expect(firstComment.title).toBe('a sample comment'); 
}) 

```

保存文件并检查 Karma 输出。确认测试通过。Karma 和 Protractor 测试都通过了，我们已经完成了添加评论和点赞的主要用户行为。现在我们可以继续下一步，让事情变得更好。

## 让它变得更好

总的来说，这种方法最终得到了我们想要的结果。用户现在可以在 UI 中点赞评论并看到点赞数量。从重构的角度来看，我们没有对`like`方法进行单元测试。

审查我们的开发待办清单，我们看到列表是我们写下的一个动作。在完全结束该功能之前，让我们讨论一下是否要为`like`功能添加单元测试的选项。

## 耦合测试

正如已经讨论过的，测试与实现紧密耦合。当涉及复杂逻辑或需要确保应用程序的某些方面以特定方式行为时，这是一件好事。重要的是要意识到耦合，并知道何时将其引入应用程序以及何时不需要。我们创建的`like`函数只是简单地增加了对象上的计数器。这可以很容易地进行测试；然而，单元测试将引入的耦合不会给我们带来额外的价值。

在这种情况下，我们不会为`like`方法添加另一个单元测试。随着应用程序的进展，我们可能会发现需要添加单元测试以开发和扩展功能。

在添加测试时，以下是我考虑的一些事项：

+   添加测试的价值是否超过了维护成本？

+   测试是否为代码增加了价值？

+   它是否帮助其他开发人员更好地理解代码？

+   功能是否以某种方式进行了测试？

根据我们的决定，不需要进行更多的重构或测试。在下一节中，我们将退一步，回顾本章的要点。

# 自测问题

Q1\. 卡尔玛需要 Selenium WebDriver 来运行测试。

+   正确

+   错误

Q2\. 鉴于以下代码片段，您将如何选择以下按钮：

```ts
    <button type="button">Click Me</button>? 

```

+   `element.all(by.button('button'))`

+   `element.all(by.css('type=button'))`

+   `element(by.buttonText('Click Me')`

# 总结

在本章中，我们介绍了使用 Protractor 和 Karma 的 TDD 技术。随着应用程序的开发，我们能够看到何时、为什么以及如何应用 TDD 测试工具和技术。

这种自上而下的方法与第三章中讨论的自下而上的方法不同，*卡尔玛方式*，以及第四章中讨论的自下而上的方法，*使用 Protractor 进行端到端测试*。在自下而上的方法中，规范用于构建单元测试，然后在其上构建 UI 层。在本章中，展示了一种自上而下的方法，重点放在用户行为上。

自上而下的方法测试 UI，然后通过其他层过滤开发。这两种方法都有其优点。在应用 TDD 时，了解如何同时使用两者是至关重要的。除了介绍不同的 TDD 方法之外，我们还看到了 Angular 的一些核心测试组件，例如以下内容：

+   从端到端和单元角度测试一个组件

+   将组件类导入测试套件并为单元测试启动它

+   Protractor 绑定到`ngModel`，向输入列发送按键，并通过其内部 HTML 代码和所有子元素获取元素的文本的能力

下一章将基于此处使用的技术，并研究无头浏览器测试、Protractor 的高级技术以及如何测试 Angular 路由。
