# Angular 秘籍（六）

> 原文：[`zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7`](https://zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：*第十一章*：使用 Cypress 在 Angular 中进行 E2E 测试

一个应用程序有几个端到端（E2E）测试，肯定比一个没有测试的应用程序更可靠，在当今世界，随着新兴企业和复杂应用程序的出现，编写端到端测试以捕获整个应用程序流程变得至关重要。Cypress 是当今用于 Web 应用程序的 E2E 测试的最佳工具之一。在本章中，您将学习如何使用 Cypress 在 Angular 应用程序中测试您的 E2E 流程。以下是本章中要涵盖的内容：

+   编写您的第一个 Cypress 测试

+   验证文档对象模型（DOM）元素是否在视图上可见

+   测试表单输入和提交

+   等待 XMLHttpRequest（XHR）完成

+   使用 Cypress 捆绑包

+   使用 Cypress fixtures 提供模拟数据。

# 技术要求

在本章的配方中，请确保您的计算机上已安装了 Git 和 Node.js。您还需要安装 `@angular/cli` 包，您可以在终端中使用 `npm install -g @angular/cli` 来完成。本章的代码可以在 [`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter11`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter11) 找到。

# 编写您的第一个 Cypress 测试

如果您已经在编写 E2E 测试，您可能已经使用 Protractor 进行了这项工作。不过，使用 Cypress 是完全不同的体验。在这个配方中，您将使用现有的 Angular 应用程序设置 Cypress，并将使用 Cypress 编写您的第一个 E2E 测试。

## 准备工作

我们要处理的项目位于克隆存储库中的 `chapter11/start_here/angular-cypress-starter` 中：

1.  在 Visual Studio Code 中打开项目（VS Code）。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

现在我们已经在本地打开了项目，让我们在下一节中看看这个配方的步骤。

## 如何做…

我们要处理的应用程序是一个简单的计数器应用程序。它有最小和最大值，以及一些按钮，可以增加、减少和重置计数器的值。我们将首先为我们的应用程序配置 Cypress，然后开始编写测试：

1.  首先，打开一个新的终端窗口/标签，并确保你在`chapter11/start_here/angular-cypress-starter`文件夹内。进入后，运行以下命令在我们的项目中安装`Cypress`和`concurrently`：

```ts
npm install -d cypress concurrently
```

1.  现在，打开你的`package.json`文件，并在`scripts`对象内添加以下脚本，如下所示：

```ts
{
  "name": "angular-cypress-starter",
  "version": "0.0.0",
  "scripts": {
    ... 
    "e2e": "ng e2e",
    "start:cypress": "cypress open",
  "cypress:test": "concurrently 'npm run start' 'npm run   start:cypress'"
  },
  ...
}
```

1.  让我们运行`cypress:test`命令，同时启动`http://localhost:4200`的 Angular 服务器，并开始 Cypress 测试，如下所示：

```ts
npm run cypress:test
```

你还应该看到 Cypress 默认创建了一个名为`cypress`的文件夹，并在其中创建了一些示例测试。Cypress 还创建了一个`cypress.json`文件来提供一些配置。我们不会删除这些默认测试，而是在下一步中忽略它们。

1.  通过修改`cypress.json`文件来忽略默认/示例测试，如下所示：

```ts
{
  "baseUrl": "http://localhost:4200",
  "ignoreTestFiles": "**/examples/*",
  "viewportHeight": 760,
  "viewportWidth": 1080
}
```

1.  如果你现在再看 Cypress 窗口，你会发现我们没有任何集成测试，如下所示：![图 11.1 - 没有集成测试可执行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.1_B15150.jpg)

图 11.1 - 没有集成测试可执行

1.  让我们现在创建我们的第一个测试。我们只需检查我们应用程序的浏览器标题是否为**编写您的第一个 Cypress 测试**。在`cypress/integration`文件夹内创建一个名为`app.spec.js`的新文件，并粘贴以下代码：

```ts
/// <reference types="cypress" />
context('App', () => {
  beforeEach(() => {
    cy.visit('/');
  });
  it('should have the title "Writing your first Cypress   test "', () => {
    // https://on.cypress.io/title
    cy.title().should('eq', 'Writing your first Cypress     test');
  });
});
```

1.  如果你再次看 Cypress 窗口，你会看到一个名为`app.spec.js`的新文件列出，如下所示：![图 11.2 - 显示的新 app.spec.js 测试文件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.2_B15150.jpg)

图 11.2 - 显示的新 app.spec.js 测试文件

1.  点击*图 11.2*中显示的窗口中的`app.spec.js`文件，你应该看到文件中编写的 Cypress 测试通过了。

砰！在几个步骤内，我们已经为我们的 Angular 应用程序设置了 Cypress，并编写了我们的第一个测试。你应该看到 Cypress 窗口，如下所示：

![图 11.3 - 我们的第一个 Cypress 测试通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.3_B15150.jpg)

图 11.3 - 我们的第一个 Cypress 测试通过

简单吧！对吧？现在你知道如何为 Angular 应用程序配置 Cypress 了，看看下一节来了解它是如何工作的。

## 它是如何工作的…

Cypress 可以与任何框架和 Web 开发项目集成。有趣的是，Cypress 在幕后使用 Mocha 作为测试运行器。Cypress 的工具会监视代码更改，这样你就不必一次又一次地重新编译测试。Cypress 还会在被测试的应用程序周围添加一个外壳，以捕获日志并在测试期间访问 DOM 元素，并提供一些用于调试测试的功能。

在我们的 `app.spec.js` 文件的顶部，我们使用 `context()` 方法来定义测试套件，基本上是定义即将在内部编写的测试的上下文。然后，我们使用 `beforeEach()` 方法来指定每个测试执行前应该发生什么。由于每个测试都从零数据开始，我们首先必须确保 Cypress 导航到我们应用程序的 `http://localhost:4200` **统一资源定位符** (**URL**)。我们之所以只指定 `cy.visit('/')` 并且它仍然有效，是因为我们已经在 `cypress.json` 文件中指定了 `baseUrl` 属性。因此，在我们的测试中只需提供相对 URL。

最后，我们使用 `it()` 方法来指定我们第一个测试的标题，然后我们使用 `cy.title()` 方法，这是一个方便的辅助工具，来获取当前正在呈现的**超文本标记语言** (**HTML**)页面的**标题**的文本值。我们使用 `'eq'` 运算符来将其值与 `'编写你的第一个 Cypress 测试'` 字符串进行比较，一切正常！

## 另请参阅

+   `cy.title()` 文档 ([`docs.cypress.io/api/commands/title.html#Syntax`](https://docs.cypress.io/api/commands/title.html#Syntax))

+   Cypress 文档—*编写你的第一个测试* ([`docs.cypress.io/guides/getting-started/writing-your-first-test.html`](https://docs.cypress.io/guides/getting-started/writing-your-first-test.html))

# 验证 DOM 元素在视图上是否可见

在上一个示例中，我们学习了如何在 Angular 应用程序中安装和配置 Cypress。在您的应用程序中可能有不同的情况，您想要查看 DOM 上的元素是否可见。在这个示例中，我们将编写一些测试来确定 DOM 上是否有任何元素可见。

## 准备工作

此示例的项目位于 `chapter11/start_here/cypress-dom-element-visibility`：

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `npm run cypress:test`。

这应该在`https://localhost:4200`上运行应用程序，并应该打开 Cypress 窗口，如下所示：

![图 11.4–Cypress 测试运行 cypress-dom-element-visibility 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.4_B15150.jpg)

图 11.4–Cypress 测试运行 cypress-dom-element-visibility 应用程序

现在我们已经在本地运行了应用程序和 Cypress 测试，让我们在下一节中看到食谱的步骤。

## 如何做…

我们有与上一个食谱相同的旧计数器应用程序。但是，有些事情已经改变。现在我们在顶部有一个按钮，可以切换计数器组件`(CounterComponent)`的可见性。此外，我们必须悬停在计数器卡上才能看到**增加**、**减少**和**重置**操作按钮。让我们开始编写一些测试来检查计数器组件`(CounterComponent)`的可见性和操作：

1.  让我们编写一个测试，检查当我们点击**切换计数器可见性**按钮以显示它时，计数器组件`(CounterComponent)`的可见性。我们将通过断言具有`.counter__heading`和`.counter`类的元素的可见性来检查它。更新`cypress/integration/app.spec.js`文件，如下所示：

```ts
...
context('App', () => {
  ...
  it('should show the counter component when the "Toggle   Counter Visibility" button is clicked', () => {
    cy.get('.counter__heading').should('have.length', 0);
    cy.get('.counter').should('have.length', 0);
    cy.contains('Toggle Counter Visibility').click();
    cy.get('.counter__heading').should('be.visible');
    cy.get('.counter').should('be.visible');
  });
});
```

1.  现在，我们将编写一个测试，检查当我们悬停在`counter`组件上时，我们的操作按钮（**增加**、**减少**和**重置**）是否显示出来。更新`app.spec.js`文件，如下所示：

```ts
...
context('App', () => {
  ...
  it('should show the action buttons on hovering the   counter card', () => {
    cy.contains('Toggle Counter Visibility').click();
    cy.get('.counter').trigger('mouseover');
    cy.get('.counter__actions__action').    should('have.length', 3);
    cy.contains('Increment').should('be.visible');
    cy.contains('Decrement').should('be.visible');
    cy.contains('Reset').should('be.visible');
  });
});
```

如果您现在查看 Cypress 窗口，您应该看到测试失败，如下所示：

![图 11.5–悬停时无法获取操作按钮](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.5_B15150.jpg)

图 11.5–悬停时无法获取操作按钮

测试失败的原因是 Cypress 目前不提供**层叠样式表**（**CSS**）悬停效果。为了解决这个问题，我们将在下一步中安装一个包。

1.  停止运行 Cypress 和 Angular 应用程序，然后安装`cypress-real-events`包，如下所示：

```ts
npm install --save-dev cypress-real-events
```

1.  现在，打开`cypress/support/index.js`文件并更新如下：

```ts
...
// Import commands.js using ES2015 syntax:
import './commands';
import 'cypress-real-events/support';
...
```

1.  现在，更新`app.spec.js`文件，使用包中的`.realHover()`方法在`.counter`元素上，如下所示：

```ts
/// <reference types="cypress" />
/// <reference types="cypress-real-events" />
context('App', () => {
  ...
  it('should show the action buttons on hovering the   counter card', () => {
    cy.contains('Toggle Counter Visibility').click();
    cy.get('.counter').realHover();
    cy.get('.counter__actions__action').    should('have.length', 3);
    ...
  });
});
```

1.  现在，再次运行`cypress:test`命令，使用`npm run cypress:test`。一旦应用程序运行并且 Cypress 窗口打开，您应该看到所有测试都通过了，如下所示：

![图 11.6–使用 cypress-real-events 包后所有测试都通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.6_B15150.jpg)

图 11.6 - 使用 cypress-real-events 包后所有测试都通过

太棒了！您刚刚学会了如何在不同场景下检查 DOM 元素的可见性。当然，这些不是唯一可用的标识和与 DOM 元素交互的选项。现在您已经完成了这个配方，请查看下一节以了解它是如何工作的。

## 它是如何工作的…

在配方的开头，在我们的第一个测试中，我们使用`.should('have.length', 0)`断言。当我们使用`'have.length'`断言时，Cypress 会检查使用`cy.get()`方法找到的 DOM 元素的`length`属性。我们使用的另一个断言是`.should('be.visible')`，它检查元素在 DOM 上是否可见。只要元素在屏幕上可见，这个断言就会通过，也就是说，父元素中没有隐藏的元素。

在后面的测试中，我们尝试悬停在具有`'.counter'`选择器的元素上，使用`cy.get('.counter').trigger('mouseover');`。这导致我们的测试失败。为什么？因为 Cypress 中的所有悬停解决方法最终都会触发 JavaScript 事件，而不会影响 CSS 伪选择器，而且由于我们的操作按钮（使用`'.counter__actions__action'`选择器）显示在具有`'.counter'`选择器的元素的`:hover`（CSS）上，我们的测试失败，因为在测试中我们的操作按钮实际上没有显示。为了解决这个问题，我们使用`cypress-real-events`包，它具有`.realHover()`方法，可以影响伪选择器，并最终显示我们的操作按钮。

## 另请参阅

+   Cypress 官方关于项目可见性的文档（[`docs.cypress.io/guides/core-concepts/interacting-with-elements.html#Visibility`](https://docs.cypress.io/guides/core-concepts/interacting-with-elements.html#Visibility)）

+   `cypress-real-events` 项目存储库（[`github.com/dmtrKovalenko/cypress-real-events`](https://github.com/dmtrKovalenko/cypress-real-events)）

# 测试表单输入和提交

如果您正在构建 Web 应用程序，很有可能您的应用程序中至少会有一个表单，当涉及到表单时，我们需要确保我们有正确的**用户体验**（**UX**）和正确的业务逻辑。有什么比编写 E2E 测试来确保一切都按预期工作更好的方法呢？在这个配方中，我们将使用 Cypress 测试登录表单。

## 做好准备

此配方的项目位于`chapter11/start_here/cy-testing-forms`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`npm run cypress:test`。

这将打开一个新的 Cypress 窗口。点击`app.spec.ts`文件，你应该看到测试，如下所示：

![图 11.7 - Cypress 测试正在运行 cy-testing-forms 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.7_B15150.jpg)

图 11.7 - Cypress 测试正在运行 cy-testing-forms 应用程序

现在我们已经运行了 Cypress 测试，让我们在下一节看看这个步骤的详细过程。

## 如何做…

我们必须确保当表单成功提交时，我们会看到一个**成功**提示。如果任何输入值无效，我们还需要确保我们看到相关的错误。让我们开始吧：

1.  让我们在`cypress/integration`文件夹中创建一个名为`login.spec.js`的新文件。

1.  首先，我们要确保除非我们有有效的表单输入，否则我们的表单不能被提交。为了做到这一点，让我们确保当没有输入值或无效值时，**提交**按钮被禁用。打开`login.spec.js`文件并添加一个测试，如下所示：

```ts
/// <reference types="cypress" />
context('Login', () => {
  beforeEach(() => {
    cy.visit('/');
  });
  it('should have the button disabled if the form inputs   are not valid', () => {
    // https://on.cypress.io/title
    // No input values
    cy.contains('Submit').should('be.disabled');
    cy.get('#passwordInput').type('password123');
    cy.contains('Submit').should('be.disabled');
    cy.get('#emailInput').type('ahsanayaz@gmail.com');
    cy.get('#passwordInput').clear();
    cy.contains('Submit').should('be.disabled');
  });
});
```

现在，在 Cypress 窗口中打开`login.spec.js`文件，你应该看到测试都通过了，如下所示：

![图 11.8 - 检查当输入无效时提交按钮是否被禁用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.8_B15150.jpg)

图 11.8 - 检查当输入无效时提交按钮是否被禁用

1.  让我们添加另一个测试，验证当输入正确的值时，我们会看到一个成功提示。在`login.spec.js`文件中添加另一个测试，如下所示：

```ts
...
context('Login', () => {
  ...
  it('should submit the form with the correct values and   show the success alert', () => {
    cy.get('#emailInput')
      .type('ahsan.ayaz@domain.com')
      .get('#passwordInput')
      .type('password123');
    cy.contains('Submit').click();
    cy.get('.alert.alert-success').should('be.visible');
  });
});
```

1.  现在我们将添加另一个测试，以确保成功提示在点击**关闭**按钮时隐藏。由于我们在成功登录时使用相同的逻辑/代码，我们将创建一个函数来重用它。让我们修改`login.spec.js`文件，如下所示：

```ts
...
context('Login', () => {
  ...
  it('should submit the form with the correct values and   show the success alert', () => {
    successfulLogin();
    cy.get('.alert.alert-success').should('be.visible');
  });
  it('should hide the success alert on clicking close   button', () => {
    successfulLogin();
    cy.get('.alert.alert-success').find('.btn-close').    click();
    cy.get('.alert.alert-success').should((domList) => {
      expect(domList.length).to.equal(0);
    });
  });
});
function successfulLogin() {
  cy.get('#emailInput')
    .type('ahsan.ayaz@domain.com')
    .get('#passwordInput')
    .type('password123');
  cy.contains('Submit').click();
}
```

1.  成功提示在输入更改时也应该隐藏。为了检查这一点，让我们添加另一个测试，如下所示：

```ts
...
context('Login', () => {
  ...
  it('should hide the success alert on changing the   input', () => {
    successfulLogin();
    cy.get('#emailInput').clear().    type('mohsin.ayaz@domain.com');
    cy.get('.alert.alert-success').should((domList) => {
      expect(domList.length).to.equal(0);
    });
  });
});
```

1.  最后，让我们编写一个测试，确保我们在输入无效时显示错误消息。在`logic.spec.js`文件中添加另一个测试，如下所示：

```ts
...
context('Login', () => {
 ...
  it('should show the (required) input errors on invalid   inputs', () => {
    ['#emailHelp', '#passwordHelp'].map((selector) => {
      cy.get(selector).should((domList) =>       expect(domList.length).to.equal(0));
    });
    cy.get('#emailInput').type(    'mohsin.ayaz@domain.com').clear().blur();
    cy.get('#emailHelp').should('be.visible');
    cy.get('#passwordInput').type(    'password123').clear().blur();
    cy.get('#passwordHelp').should('be.visible');
  });
});
```

如果你现在查看**测试**窗口，你应该看到所有的测试都通过了，如下所示：

![图 11.9 - 登录页面的所有测试都通过了](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.9_B15150.jpg)

图 11.9 - 登录页面的所有测试都通过了

太棒了！现在你知道如何使用 Cypress 来测试一些有趣的用例和断言。查看下一节以了解它是如何工作的。

## 工作原理…

由于我们应用程序的逻辑规定**提交**按钮在电子邮件和密码输入都有有效值之前应该被禁用，我们在测试中检查按钮是否被禁用。我们通过在**提交**按钮上使用`'be.disabled'`断言来实现这一点，如下所示：

```ts
cy.contains('Submit').should('be.disabled');
```

然后我们在`cy.get()`选择器上使用`.type()`方法链来依次输入两个输入，并在任何输入无效值或根本没有输入时检查按钮是否被禁用。

执行成功的登录，我们执行以下代码：

```ts
cy.get('#emailInput')
    .type('ahsan.ayaz@domain.com')
    .get('#passwordInput')
    .type('password123');
  cy.contains('Submit').click();
```

注意，我们获取每个输入并在其中输入有效值，然后在**提交**按钮上调用`.click()`方法。然后，我们使用`'.alert.alert-success'`选择器和`should('be.visible')`断言来检查成功提示是否存在。

在我们想要检查成功提示在单击警报上的**关闭**按钮或任何输入更改时是否已被解除时，我们不能只使用`should('not.be.visible')`断言。这是因为在这种情况下，Cypress 会期望警报在 DOM 中，但只是不可见，而在我们的情况下（在我们的 Angular 应用程序中），元素甚至不存在在 DOM 中，因此 Cypress 无法获取它。因此，我们使用以下代码来检查成功提示甚至不存在：

```ts
cy.get('.alert.alert-success').should((domList) => {
    expect(domList.length).to.equal(0);
});
```

最后一个有趣的事情是当我们想要检查每个输入的错误消息是否在我们在任一输入中输入内容并清除输入时显示。在这种情况下，我们使用以下代码：

```ts
cy.get('#emailInput').type('mohsin.ayaz@domain.com').clear().blur();
cy.get('#emailHelp').should('be.visible');
cy.get('#passwordInput').type('password123').clear().blur();
cy.get('#passwordHelp').should('be.visible');
```

我们使用`.blur()`方法的原因是因为当 Cypress 只清除输入时，Angular 的变化检测不会立即发生，这导致错误消息不会立即显示在视图上。由于 Angular 的变化检测对浏览器事件进行了 monkey-patching，我们在两个输入上触发`.blur()`事件来触发变化检测机制。结果，我们的错误消息会正确显示。

## 另请参阅

+   Cypress recipes: Form interactions ([`github.com/cypress-io/cypress-example-recipes/tree/master/examples/testing-dom__form-interactions`](https://github.com/cypress-io/cypress-example-recipes/tree/master/examples/testing-dom__form-interactions))

+   Cypress recipes: Login form ([`github.com/cypress-io/cypress-example-recipes/tree/master/examples/logging-in__html-web-forms`](https://github.com/cypress-io/cypress-example-recipes/tree/master/examples/logging-in__html-web-forms))

# 等待 XHR 完成

测试用户界面（UI）转换是 E2E 测试的本质。虽然测试立即预测结果的重要性很高，但实际上可能存在结果有依赖性的情况。例如，如果用户填写了登录表单，我们只有在从后端服务器成功收到响应后才能显示成功的提示，因此我们无法立即测试成功提示是否显示。在这个配方中，您将学习如何等待特定的 XHR 调用完成后再执行断言。

## 准备工作

此处的配方项目位于`chapter11/start_here/waiting-for-xhr`。

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`npm run cypress:test`。

这将打开一个新的 Cypress 窗口。点击`user.spec.ts`文件，您应该会看到测试，如下所示：

![图 11.10 - Cypress 测试正在运行等待 XHR 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.10_B15150.jpg)

图 11.10 - Cypress 测试正在运行等待 XHR 应用程序

现在我们已经让 Cypress 测试运行起来了，让我们在下一节中看看这个配方的步骤。

## 如何做…

现在所有的测试都很好，即使我们涉及 XHR 调用来获取数据。那么，这个配方到底是关于什么的呢？嗯，Cypress 在 4,000 毫秒（4 秒）的时间内尝试断言，直到断言通过。如果我们的 XHR 花费超过 4,000 毫秒呢？让我们在这个配方中试一试：

1.  首先，我们需要模拟期望结果在 4,000 毫秒后发生的情况。我们将使用`rxjs`中的`debounceTime`操作符，延迟为 5,000 毫秒。让我们将其应用于`users.component.ts`文件中`searchForm`属性的`valueChanges` Observable，如下所示：

```ts
...
import { debounceTime, takeWhile } from 'rxjs/operators';
@Component({...})
export class UsersComponent implements OnInit {
  ...
  ngOnInit() {
    ...
    this.searchForm
      .get('username')
      .valueChanges.pipe(
        takeWhile(() => !!this.componentAlive),
        debounceTime(5000)
      )
      .subscribe(() => {
        this.searchUsers();
      });
  }
  ...
}
```

如果现在检查 Cypress 测试，您应该会看到一个测试失败，如下所示：

![图 11.11 - 测试搜索特定用户失败](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.11_B15150.jpg)

图 11.11 - 测试搜索特定用户失败

1.  现在我们可以尝试修复这个问题，这样无论 XHR 花费多长时间，我们都会等待它完成后再进行断言。让我们拦截 XHR 调用并为其创建一个别名，以便稍后使用它来等待 XHR 调用。更新`users.spec.js`文件，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should get the users list on searching', () => {
    cy.intercept('https://api.randomuser.me/*')    .as('searchUsers');
    cy.get('#searchInput').type('irin');
    cy.get('app-user-card').should((domList) => {
      expect(domList.length).equal(1);
    });
  });
});
```

1.  现在，让我们使用别名在断言之前等待 XHR 调用完成。更新`users.spec.js`文件，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should get the users list on searching', () => {
    cy.intercept('https://api.randomuser.me/*')    .as('searchUsers');
    cy.get('#searchInput').type('irin');
    cy.wait('@searchUsers');
    cy.get('app-user-card').should((domList) => {
      expect(domList.length).equal(1);
    });
  });
});
```

如果现在检查`user.spec.js`的 Cypress 测试，你应该看到它们都通过了，如下所示：

![图 11.12 – 测试等待 XHR 调用完成后进行断言](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.12_B15150.jpg)

图 11.12 – 测试等待 XHR 调用完成后进行断言

太棒了！现在你知道如何使用 Cypress 实现包括等待特定 XHR 调用完成在断言之前的 E2E 测试。要了解配方背后的所有魔力，请参阅下一节。

## 工作原理…

在这个配方中，我们使用了一种叫做变量别名的东西。我们首先使用`cy.intercept()`方法，这样 Cypress 就可以监听网络调用。请注意，我们在参数中使用通配符作为 URL，使用`https://api.randomuser.me/*`，然后我们使用`.as('searchUsers')`语句为这个拦截设置一个别名。

然后，我们使用`cy.wait('@searchUsers');`语句，使用`searchUsers`别名告诉 Cypress 它必须等待直到别名的拦截发生——也就是说，直到网络调用被发出，无论需要多长时间。这使我们的测试通过，即使在实际获取网络调用之前，常规的 4,000 毫秒 Cypress 超时已经过去。神奇，不是吗？

嗯，希望你喜欢这个配方——查看下一节以查看进一步阅读的链接。

## 另请参阅

+   在 Cypress 中等待([`docs.cypress.io/guides/guides/network-requests#Waiting`](https://docs.cypress.io/guides/guides/network-requests#Waiting))

# 使用 Cypress 捆绑包

Cypress 提供了一堆捆绑工具和包，我们可以在测试中使用它们来简化事情，不是因为使用 Cypress 编写测试本来就很难，而是因为这些库已经被许多开发人员使用，所以他们对它们很熟悉。在这个配方中，我们将看看捆绑的`jQuery、Lodash 和 Minimatch`库，以测试一些我们的用例。

## 准备工作

我们要处理的项目位于`chapter11/start_here/using-cypress-bundled-packages`，在克隆的存储库中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`npm run cypress:test`。

这应该打开一个新的 Cypress 窗口。点击`users.spec.ts`文件，你应该看到测试，如下所示：

![图 11.13 - 使用 Cypress 捆绑包运行的测试](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.13_B15150.jpg)

图 11.13 - 使用 Cypress 捆绑包运行的测试

现在我们有了 Cypress 测试运行，让我们在下一节中看看这个示例的步骤。

## 如何做...

对于这个示例，我们有`users`列表和一个从**应用程序编程接口**（**API**）端点获取一些用户的搜索应用。我们将对 DOM 进行一些条件断言，验证 API 的响应，并且还会断言 URL 的变化。让我们开始吧：

1.  首先，我们将尝试使用捆绑的`jQuery`库以及 Cypress。我们可以使用`Cypress.$`来访问它。让我们添加另一个测试并记录一些 DOM 元素。更新`users.spec.js`文件，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should have the search button disabled when there   is no input', () => {
    const submitButton = Cypress.$('#userSearchSubmit');
    console.log(submitButton);
  });
});
```

如果你现在看测试，特别是控制台，你应该会看到以下日志：

![图 11.14 - 使用 jQuery 通过 Cypress.$记录的搜索按钮](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.14_B15150.jpg)

图 11.14 - 使用 jQuery 通过 Cypress.$记录的搜索按钮

1.  现在，让我们尝试记录在 HTTP 调用之后看到的用户卡。添加另一个查询和登录到相同的测试中，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should have the search button disabled when there   is no input', () => {
    const submitButton = Cypress.$('#userSearchSubmit');
    console.log(submitButton);
  const appUserCards = Cypress.$('app-user-card');
  console.log(appUserCards);
  });
});
```

如果你再次在 Cypress 窗口的测试和日志中看到，你会发现`Cypress.$('app-user-card')`查询不会返回任何 DOM 元素。这是因为当运行查询时，HTTP 调用尚未完成。那么，我们应该等待 HTTP 调用完成吗？让我们试试看。

1.  让我们添加一个`cy.wait(5000)`来等待 5 秒，期间 HTTP 调用应该已经完成，并且让我们使用`cy.wrap()`方法进行断言，检查当搜索输入没有提供值时**搜索**按钮是否被禁用。更新测试，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should have the search button disabled when there   is no input', () => {
    const submitButton = Cypress.$('#userSearchSubmit');
    cy.wrap(submitButton).should('have.attr',     'disabled');
    cy.get('#searchInput').type('irin');
    cy.wait(5000);
    const appUserCards = Cypress.$('app-user-card');
    console.log(appUserCards);
    cy.wrap(submitButton).should('not.have.attr',     'disabled');
  });
});
```

如果你看到 Cypress 测试和控制台，你会发现我们仍然没有得到`<app-user-card>`元素的 DOM 元素：

![图 11.15 - 即使使用 cy.wait（5000）也找不到使用 Cypress.$的用户卡](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.15_B15150.jpg)

图 11.15 - 即使使用 cy.wait（5000）也找不到使用 Cypress.$的用户卡

我们将在*它是如何工作的...*部分讨论为什么会发生这种情况。现在，了解你应该只对从页面加载时就存在于 DOM 中的元素使用`Cypress.$`。

1.  让我们通过删除`cy.wait()`方法和控制台日志来清理我们的测试。然后它应该看起来像这样：

```ts
...
context('Users', () => {
  ...
  it('should have the search button disabled when there   is no input', () => {
    const submitButton = Cypress.$('#userSearchSubmit');
    cy.wrap(submitButton).should('have.attr', 'disabled');
    cy.get('#searchInput').type('irin');
    cy.wrap(submitButton).should('not.have.attr',     'disabled');
  });
});
```

1.  现在我们将添加一个测试来验证，对于相同的种子字符串，我们从随机用户 API 中获取相同的用户。我们已经有了包含预期结果的`API_USERS.js`文件。让我们在下一个测试中使用捆绑的`lodash`库来断言返回用户的名字、姓氏和电子邮件的匹配值，如下所示：

```ts
...
import API_USERS from '../constants/API_USERS';
context('Users', () => {
  ...
  it('should return the same users as the seed data   every time', async () => {
    const { _ } = Cypress;
    const response = await cy.request(
      'https://api.randomuser.me/?      results=10&seed=packt'
    );
    const propsToCompare = ['name.first', 'name.last',     'email'];
    const results = _.get(response, 'body.results');
    _.each(results, (user, index) => {
      const apiUser = API_USERS[index];
      _.each(propsToCompare, (prop) => {
        const userPropVal = _.get(user, prop);
        const apiUserPropVal = _.get(apiUser, prop);
        return expect(userPropVal).        to.equal(apiUserPropVal);
      });
    });
  });
});
```

如果你现在在 Cypress 中看到测试，它应该通过，如下所示：

![图 11.16 – 使用 lodash 通过 Cypress 进行测试通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.16_B15150.jpg)

图 11.16 – 使用 lodash 通过 Cypress 进行测试通过

1.  现在我们将使用 Cypress 捆绑的`moment.js`包。让我们断言用户卡片正确显示格式化的日期，使用`moment.js`。在`users.spec.js`文件中编写另一个测试，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should show the formatted date of birth on the   user card', () => {
    const { _, moment } = Cypress;
    const apiUserDate = _.get(API_USERS[0], 'dob.date');
    const apiUserDateFormatted = moment(apiUserDate).    format(
      'dddd, MMMM D, YYYY'
    );
    cy.get('app-user-card')
      .eq(0)
      .find('#userCardDOB')
      .should((el) => {
       expect(el.text().trim()).       to.equal(apiUserDateFormatted);
      });
  });
});
```

1.  接下来我们将探索的包是`minimatch`包。当我们点击用户卡片时，它会打开用户详细信息。由于我们将时间戳作为查询参数附加到 URL 上，我们无法将 URL 作为精确匹配与我们的断言进行比较。让我们使用`minimatch`包来使用模式进行断言。添加一个新的测试，如下所示：

```ts
...
context('Users', () => {
  ...
  it('should go to the user details page with the user   uuid', () => {
    const { minimatch } = Cypress;
    cy.get('app-user-card').eq(0).click();
    const expectedURL = `http://localhost:4200/    users/${API_USERS[0].login.uuid}`;
    cy.url().should((url) => {
      const urlMatches = minimatch(url,       `${expectedURL}*`);
      expect(urlMatches).to.equal(true);
    });
  });
});
```

哇！现在我们使用 Cypress 捆绑的包都通过了所有的测试。既然我们已经完成了这个方法，让我们在下一节看看它是如何工作的。

## 它是如何工作的…

Cypress 将`jQuery`与其捆绑在一起，我们通过`Cypress.$`属性使用它。这使我们能够执行`jQuery`函数允许我们执行的一切。它使用`cy.visit()`方法自动检查视图中的哪个页面，然后使用提供的选择器查询文档。

重要提示

`Cypress.$`只能从 DOM 上立即可用的文档元素中获取。这对于在 Cypress 测试窗口中使用 Chrome DevTools 调试 DOM 非常有用。然而，重要的是要理解它对 Angular 变化检测没有任何上下文。此外，你不能查询任何在页面上一开始就不可见的元素，就像我们在遵循该方法时所经历的那样——它不会等待 XHR 调用使元素可见。

Cypress 还捆绑了`lodash`并通过`Cypress._`对象公开它。在本教程中，我们使用`_.get()`方法从`user`对象中获取嵌套属性。`_.get()`方法接受两个参数：对象和反映属性路径的字符串，例如，我们使用`_.get(response, 'body.results');`，它实质上返回`response.body.results`的值。我们还使用`_.each()`方法在本教程中迭代数组。请注意，我们可以在 Cypress 测试中使用任何`lodash`方法，而不仅仅是上述方法。

我们还使用了 Cypress 通过`Cypress.minimatch`对象公开的`minimatch`包。`minimatch`包非常适合与字符串匹配和测试 glob 模式。我们用它来测试导航到用户详细信息页面后的 URL。

最后，我们还使用了 Cypress 通过`Cypress.moment`对象公开的`moment.js`包。我们用它来确保每个用户的出生日期在视图上显示为预期格式。非常简单。

## 另请参阅

+   Cypress 捆绑工具([`docs.cypress.io/guides/references/bundled-tools`](https://docs.cypress.io/guides/references/bundled-tools))

+   Moment.js ([`momentjs.com/`](https://momentjs.com/))

+   jQuery ([`jquery.com/`](https://jquery.com/))

+   lodash ([`lodash.com`](https://lodash.com))

+   Minimatch.js ([`github.com/isaacs/minimatch`](https://github.com/isaacs/minimatch))

# 使用 Cypress fixtures 提供模拟数据

在编写端到端测试时，fixtures 在确保测试不会出现问题方面发挥了重要作用。考虑到您的测试依赖于从 API 服务器获取数据，或者您的测试包括快照测试，其中包括从内容交付网络（CDN）或第三方 API 获取图像。尽管它们在技术上是测试成功运行所必需的，但重要的是服务器数据和图像不是从原始来源获取的，因此我们可以为它们创建 fixtures。在本教程中，我们将为用户数据以及要在 UI 上显示的图像创建 fixtures。

## 准备工作

我们将要使用的项目位于克隆存储库中的`chapter11/start_here/using-cypress-fixtures`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`npm run cypress:test`。

这将打开一个新的 Cypress 窗口。点击`users.spec.ts`文件，你应该会看到测试，如下所示：

![图 11.17 - 使用 Cypress fixtures 测试在 Cypress 中运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.17_B15150.jpg)

图 11.17 - 使用 Cypress fixtures 测试在 Cypress 中运行

现在我们已经让 Cypress 测试运行了，让我们在下一节中看看这个示例的步骤。

## 如何做…

我们有与上一个示例中相同的 Angular 应用程序。但是，我们现在将使用 Cypress fixtures 来提供我们的数据和图像 fixture。让我们开始吧：

1.  我们首先为我们对`randomuser.me` API 的 HTTP 调用创建一个 fixture。在`cypress/fixtures`文件夹下创建一个名为`users.json`的新文件。然后，将代码从`chapter11/final/using-cypress-fixtures/cypress/fixtures/users.json`文件复制并粘贴到新创建的文件中。它应该看起来像这样：

```ts
{
  "fixture_version": "1",
  "results": [
    {
      "gender": "male",
      "name": { "title": "Mr", "first": "Irineu",       "last": "da Rocha" },
      ...
    },
    ...
    {
      "gender": "male",
      "name": { "title": "Mr", "first": "Justin",       "last": "Grewal" },
      ...
    }
  ]
}
```

1.  现在，让我们在`users.spec.js`文件中使用 fixture。我们将在`beforeEach()`生命周期钩子中使用它，因为我们希望在文件中的所有测试中使用 fixture。这意味着我们还将删除文件中现有的`cy.intercept()`方法的使用。更新`users.spec.js`文件，如下所示：

```ts
...
context('Users', () => {
  beforeEach(() => {
    cy.fixture('users.json')
      .then((response) => {
        cy.intercept('GET', 'https://api.randomuser.        me/*', response).as(
          'searchUsers'
        );
      })
      .visit('/users');
  });
  ...
  it('should get the users list on searching', () => {
    cy.intercept('
https://api.randomuser.me/*').as('searchUsers'); ← // REMOVE THIS
    cy.get('#searchInput').type('irin');
    cy.wait('@searchUsers');
    ...
  });
   ...
});
```

现在我们需要从项目中删除`constants/API_USERS.js`文件，因为我们现在有了 fixture。

1.  我们将创建一个新变量，其中我们将存储`users`数组的值，并将其用于替代`API_USERS`数组。让我们进一步修改`users.spec.js`文件，如下所示：

```ts
...
import API_USERS from '../constants/API_USERS'; ← // REMOVE THIS
context('Users', () => {
  let API_USERS;
  beforeEach(() => {
    cy.fixture('users.json')
      .then((response) => {
        API_USERS = response.results;
        cy.intercept('GET', 'https://api.randomuser.        me/*', response).as(
          'searchUsers'
        );
      })
      .visit('/users');
    });
  });
  ...
});
```

您会注意到，所有的测试都仍然通过了。您现在可以安全地从项目中删除`constants/API_USERS.js`文件。此外，您可以在 Cypress **Tests**窗口中查看网络调用，以验证我们使用的是 fixture 而不是实际的 API 响应，如下所示：

![图 11.18 - Cypress 测试使用 users.json fixture 作为 XHR 响应](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.18_B15150.jpg)

图 11.18 - Cypress 测试使用 users.json fixture 作为 XHR 响应

1.  现在，让我们尝试模拟我们的图像，从磁盘加载它们，而不是从`randomuser.me` API。为此，我们已经将图像存储在`fixtures/images`文件夹中。我们只需要根据特定用户的 URL 来使用它们。为此，请修改`users.spec.js`文件，如下所示：

```ts
...
context('Users', () => {
  let API_USERS;
  beforeEach(() => {
    cy.fixture('users.json')
      .then((response) => {
        API_USERS = response.results;
        ...
        API_USERS.forEach((user) => {
          const url = user.picture.large;
          const imageName = url.substr(url.          lastIndexOf('/') + 1);
          cy.intercept(url, { fixture:           `images/${imageName}` });
        });
      .visit('/users');
  });
  ...
});
```

如果您现在查看测试，所有测试都应该仍然通过，如下所示：

![图 11.19 - 使用图像 fixture 后所有测试都通过了](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.19_B15150.jpg)

图 11.19 - 使用图像 fixture 后所有测试都通过了

看着测试，你可能会想：“*这一切看起来和以前一样，阿赫桑。我怎么知道我们在模拟图像？*”好问题。我们已经有一种方法来测试这个。

1.  在`cypress/fixtures/images`文件夹中，我们有一个名为`9.jpg`的文件，另一个测试文件名为`9_test.jpg`。让我们将`9.jpg`文件的名称修改为`9_original.jpg`，将`9_test.jpg`文件的名称修改为`9.jpg`。如果你现在看到测试，你应该会看到使用替换文件的最后一个测试的结果不同，如下所示：

![图 11.20 - 使用 fixture 中的图像进行 Cypress 测试](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_11.20_B15150.jpg)

图 11.20 - 使用 fixture 中的图像进行 Cypress 测试

太棒了！现在你知道如何在 Cypress E2E 测试中使用 fixtures 了。现在你已经完成了这个教程，看看下一节关于它是如何工作的。

## 它是如何工作的...

我们使用`cy.fixture()`方法在 Cypress 测试中使用 fixtures，这允许我们使用文件中的数据。在这个教程中，我们使用 fixtures 来获取用户数据和图像的 HTTP 调用。但是它是如何工作的呢？实质上，`fixture`方法有四个重载，如下所示：

```ts
cy.fixture(filePath)
cy.fixture(filePath, encoding)
cy.fixture(filePath, options)
cy.fixture(filePath, encoding, options)
```

`filePath`参数接受一个字符串作为相对于`Fixture`文件夹的文件路径，默认为`cypress/fixture`路径，尽管我们可以通过在`cypress.json`配置文件中定义`fixturesFolder`属性来提供不同的`Fixture`文件夹。请注意，对于 HTTP 调用，我们使用`cy.fixture('users.json')`语句，它实质上指向`cypress/fixture/users.json`文件。

首先，我们在`cy.visit()`方法之前使用`cy.fixture('users.json')`方法，以确保我们在启动应用程序时触发的即时 XHR 调用使用 fixture。如果你改变代码，你会发现它不会按预期工作。然后我们使用`.then()`方法来获取`users.json`文件中的数据。一旦我们得到数据（`response`对象），我们使用`cy.intercept()`方法使用 Minimatch glob 模式拦截 HTTP 调用以获取用户数据，并且我们将 fixture 中的`response`对象作为 HTTP 调用的响应。因此，所有对与`'`[`api.randomuser.me/`](https://api.randomuser.me/)*`'` glob 匹配的端点的调用都使用我们的 fixture，即`users.json`文件。

在这个示例中，我们还做了一件有趣的事情，那就是模拟图片，以避免从原始来源获取它们。当你使用第三方 API 并且每次调用 API 都要付费时，这非常方便。我们已经将夹具图片存储在 `cypress/fixture/images` 文件夹中。因此，我们循环遍历 `API_USERS` 数组中的每个用户，并提取文件名（`imageName` 变量）。然后，我们拦截每个用于获取图片的 HTTP 调用，并在我们的测试中使用夹具图片代替原始资源。

## 另请参阅

+   Cypress 夹具文档（[`docs.cypress.io/api/commands/fixture`](https://docs.cypress.io/api/commands/fixture))

+   `cy.intercept()` 方法文档（[`docs.cypress.io/api/commands/intercept`](https://docs.cypress.io/api/commands/intercept)）


# 第十二章：*第十二章*：Angular 性能优化

性能始终是您为最终用户构建的任何产品中关注的问题。这是增加某人第一次使用您的应用程序成为客户的机会的关键因素。现在，除非我们确定了改进的潜在可能性和实现这一点的方法，否则我们无法真正提高应用程序的性能。在本章中，您将学习一些在改进 Angular 应用程序时要部署的方法。您将学习如何使用多种技术来分析、优化和改进您的 Angular 应用程序的性能。以下是本章中要涵盖的内容：

+   使用`OnPush`变更检测来修剪组件子树

+   从组件中分离变更检测器

+   使用`runOutsideAngular`在 Angular 外部运行`async`事件

+   在`*ngFor`中使用`trackBy`来处理列表

+   将重型计算移至纯管道

+   使用 Web Workers 进行重型计算

+   使用性能预算进行审计

+   使用`webpack-bundle-analyzer`分析捆绑包

# 技术要求

对于本章中的食谱，请确保您的计算机上已安装了**Git**和**Node.js**。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在以下链接找到：[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter12`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter12)。

# 使用 OnPush 变更检测来修剪组件子树

在当今现代 Web 应用程序的世界中，性能是出色的**用户体验**（**UX**）和最终业务转化的关键因素之一。在本章的第一个食谱中，我们将讨论您可以在组件中进行的基本优化，即使用`OnPush`变更检测策略。

## 准备工作

我们将要处理的项目位于`Chapter12/start_here/using-onpush-change-detection`中，位于克隆存储库内：

1.  在**Visual Studio Code** (**VS Code**)中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  运行`ng serve -o`命令启动 Angular 应用程序并在浏览器上提供服务。您应该看到以下应用程序：

![图 12.1 – 使用 OnPush 变更检测运行的应用程序，位于 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.1_B15150.jpg)

图 12.1 – 应用程序使用 OnPush 变更检测在 http://localhost:4200 上运行

现在我们已经在浏览器上提供了项目，让我们在下一节中看到食谱的步骤。

## 如何做…

我们正在处理的应用程序存在一些性能问题，特别是`UserCardComponent`类。这是因为它使用`idUsingFactorial()`方法来生成要显示在卡片上的唯一 ID。我们将尝试体验和理解这会导致的性能问题。我们将尝试使用`OnPush`变更检测策略来解决这个问题。让我们开始吧：

1.  首先，尝试在搜索框中输入名为`Elfie Siegert`的用户。您会注意到应用程序立即挂起，并且需要几秒钟才能显示用户。您还会注意到在输入时，甚至看不到在搜索框中输入的字母。

让我们向代码添加一些逻辑。我们将检查页面加载时 Angular 调用`idUsingFactorial()`方法的次数。

1.  修改`app/core/components/user-card/user-card.component.ts`文件，更新如下：

```ts
...
@Component({...})
export class UserCardComponent implements OnInit {
  ...
  constructor(private router: Router) {}
  ngOnInit(): void {
    if (!window['appLogs']) {
      window['appLogs'] = {};
    }
    if (!window['appLogs'][this.user.email]) {
      window['appLogs'][this.user.email] = 0;
    }
  }
  ...
  idUsingFactorial(num, length = 1) {
    window['appLogs'][this.user.email]++;
    if (num === 1) {...} else {...}
  }
}
```

1.  现在，刷新应用程序并打开 Chrome DevTools，在**控制台**选项卡中，输入`appLogs`并按*Enter*。您应该会看到一个对象，如下所示：![图 12.2 – 反映对 idUsingFactorial()方法调用次数的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.2_B15150.jpg)

图 12.2 – 反映对 idUsingFactorial()方法调用次数的日志

1.  现在，在搜索框中再次输入名称`Elfie Siegert`。然后，在**控制台**选项卡中再次输入`appLogs`并按*Enter*以再次查看对象。您会看到它有一些增加的数字。如果在输入名称时没有打错字，您应该会看到类似于这样的内容：![图 12.3 – 输入名称 Elfie Siegert 后的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.3_B15150.jpg)

图 12.3 – 输入名称 Elfie Siegert 后的日志

注意调用`idUsingFactorial()`方法时的计数，例如`justin.grewal@example.com`。现在，它从`40`增加到`300`，仅需按几下按键。

现在让我们使用`OnPush`变更检测策略。这将避免 Angular 变更检测机制在每个浏览器事件上运行，这目前会导致性能问题。

1.  打开`user-card.component.ts`文件并进行更新，如下所示：

```ts
import {
  ChangeDetectionStrategy,
  Component,
  ...
} from '@angular/core';
...
@Component({
  selector: 'app-user-card',
  templateUrl: './user-card.component.html',
  styleUrls: ['./user-card.component.scss'],
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class UserCardComponent implements OnInit {
  ...
}
```

1.  现在，再试着在搜索框中输入`Elfie Siegert`这个名字。你会注意到，现在你可以在搜索框中看到输入的字母，而且应用程序不会卡住那么多。另外，如果你在**控制台**选项卡中查看`appLogs`对象，你应该会看到类似下面的内容：

![图 12.4 - 使用 OnPush 策略输入 Elfie Siegert 名称后的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.4_B15150.jpg)

图 12.4 - 使用 OnPush 策略输入 Elfie Siegert 名称后的日志

请注意，即使刷新应用程序并输入`Elfie Siegert`这个名字后，对`idUsingFactorial()`方法的调用次数也大大减少了。例如，对于`justin.grewal@example.com`电子邮件地址，我们只有**20**次调用，而不是*图 12.2*中显示的初始**40**次调用，以及*图 12.3*中显示的**300**次调用。

太棒了！通过使用`OnPush`策略，我们能够在一个步骤中改善`UserCardComponent`的整体性能。现在你知道如何使用这个策略了，接下来看下一节来了解它是如何工作的。

## 它是如何工作的...

Angular 默认使用**默认**的变更检测策略 - 或者从`@angular/core`包中的`ChangeDetectionStrategy.Default`枚举来说，技术上来说是这样。由于 Angular 不知道我们创建的每个组件，它使用默认策略来避免遇到任何意外。但是作为开发人员，如果我们知道一个组件除非它的`@Input()`变量之一发生变化，否则不会改变，我们可以 - 而且应该 - 为该组件使用`OnPush`变更检测策略。为什么？因为它告诉 Angular 在组件的`@Input()`变量发生变化之前不要运行变更检测。这个策略对于**呈现**组件（有时被称为**哑**组件）来说是绝对胜利的，它们只是使用`@Input()`变量/属性来显示数据，并在交互中触发`@Output()`事件。这些呈现组件通常不包含任何业务逻辑，比如重型计算，使用服务进行**超文本传输协议**（**HTTP**）调用等。因此，对于这些组件来说，我们更容易使用`OnPush`策略，因为它们只会在父组件的`@Input()`属性发生变化时显示不同的数据。

由于我们现在在 `UserCardComponent` 上使用了 `OnPush` 策略，它只在我们替换整个数组时触发变更检测。这发生在**300ms** 的去抖之后（*`users.component.ts` 文件中的第 28 行*），因此只有在用户停止输入时才会执行。因此，在优化之前，默认的变更检测是在每次按键时触发的浏览器事件，现在不会触发。

重要提示

现在您已经知道 `OnPush` 策略仅在一个或多个 `@Input()` 绑定发生变化时触发 Angular 变更检测机制，这意味着如果我们在组件 (`UserCardComponent`) 中更改属性，它不会在视图中反映出来，因为在这种情况下变更检测机制不会运行，因为该属性不是一个 `@Input()` 绑定。您必须标记组件为脏，以便 Angular 可以检查组件并运行变更检测。您将使用 `ChangeDetectorRef` 服务来实现这一点，具体来说，使用 `.markForCheck()` 方法。

## 另请参阅

+   Angular `ChangeDetectionStrategy` 官方文档（[`angular.io/api/core/ChangeDetectionStrategy`](https://angular.io/api/core/ChangeDetectionStrategy)）

+   `markForCheck()` 方法官方文档（[`angular.io/api/core/ChangeDetectorRef#markforcheck`](https://angular.io/api/core/ChangeDetectorRef#markforcheck)）

# 从组件中分离变更检测器

在上一个示例中，我们学习了如何在组件中使用 `OnPush` 策略，以避免 Angular 变更检测运行，除非其中一个 `@Input()` 绑定发生了变化。然而，还有另一种方法可以告诉 Angular 完全不运行变更检测。当您希望完全控制何时运行变更检测时，这将非常方便。在本示例中，您将学习如何完全分离 Angular 组件的变更检测器，以获得性能改进。

## 准备工作

此示例的项目位于 `Chapter12/start_here/detaching-change-detecto`：

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  运行 `ng serve -o` 命令来启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序如下：

![图 12.5 – 应用程序 detaching-change-detector 在 http://localhost:4200 运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.5_B15150.jpg)

图 12.5 – 应用程序 detaching-change-detector 在 http://localhost:4200 运行

现在我们在浏览器上提供了项目，让我们在下一节中看一下本教程的步骤。

## 如何做…

我们有相同的用户列表应用程序，但有所不同。现在，我们有`UserSearchInputComponent`组件，其中包含搜索输入框。这是我们输入用户名以在用户列表中搜索的地方。另一方面，我们有`UserCardListComponent`组件，其中包含用户列表。我们将首先体验性能问题，然后巧妙地分离变更检测器以获得性能改进。让我们开始吧：

1.  在浏览器中刷新应用程序，然后只需点击搜索输入框内部，然后再点击搜索输入框外部，首先触发输入框上的`focus`事件，然后触发`blur`事件。重复这两次，然后在 Chrome Dev Tools 中的控制台中，检查`appLogs`对象的值。您应该会看到类似于这样的内容：![图 12.6 - 在搜索输入框上执行三次焦点和模糊后的日志

（图 12.6_B15150.jpg）

图 12.6 - 在搜索输入框上执行三次焦点和模糊后的日志

在`UserCardComponent`类中的`idUsingFactorial()`方法已经被调用了大约 100 次，仅在我们迄今为止执行的步骤中。

1.  现在，尝试快速在搜索框中输入`elfie`用户的名称进行搜索。

您会注意到应用程序立即挂起，需要几秒钟才能显示用户。您还会注意到，当您输入字母时，甚至看不到它们在搜索框中被输入。如果您已正确执行*步骤 1*和*步骤 2*，您应该会看到一个`appLogs`对象，如下所示：

![图 12.7 - 在输入搜索框中输入 elfie 后的日志

（图 12.7_B15150.jpg）

图 12.7 - 在输入搜索框中输入 elfie 后的日志

您可以在上述截图中看到，`justin.grewal@example.com`用户的`idUsingFactorial()`方法现在已经被调用了大约 220 次。

1.  为了提高性能，我们将在本教程中使用`ChangeDetectorRef`服务，从`UsersComponent`组件中完全分离变更检测器，这是我们**用户**页面的顶级组件。更新`users.component.ts`文件，如下所示：

```ts
import { ChangeDetectorRef, Component, OnInit} from '@angular/core';
...
@Component({...})
export class UsersComponent implements OnInit {
  users: IUser[];
  constructor(
    private userService: UserService,
  private cdRef: ChangeDetectorRef
  ) {}
  ngOnInit() {
    this.cdRef.detach();
    this.searchUsers();
  }
}
```

如果现在刷新应用程序，您会看到...实际上，您什么都看不到，这没关系 - 我们还有更多的步骤要遵循。

1.  现在，由于我们只想在搜索用户时运行变更检测 - 也就是当`UsersComponent`类中的`users`数组发生变化时，我们可以使用`ChangeDetectorRef`实例的`detectChanges()`方法。再次更新`users.component.ts`文件，如下所示：

```ts
...
@Component({...})
export class UsersComponent implements OnInit {
  ...
  searchUsers(searchQuery = '') {
    this.userService.searchUsers(
searchQuery).subscribe((users) => {
      this.users = users;
  this.cdRef.detectChanges();
    });
  }
  ...
}
```

1.  现在，再试着执行一遍动作 - 也就是刷新页面，聚焦输入框，失去焦点，再次聚焦，再次失去焦点，再次聚焦，再次失去焦点，然后在搜索输入框中输入`elfie`。一旦你按照这些步骤操作，你应该会看到`appLogs`对象，如下所示：

![图 12.8 - 在执行测试步骤并使用 ChangeDetectorRef.detach()后的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.8_B15150.jpg)

图 12.8 - 在执行测试步骤并使用 ChangeDetectorRef.detach()后的日志

从上面的截图中可以看到，即使在执行*步骤 1*和*步骤 2*中提到的所有操作之后，我们的变更检测运行周期非常低。

太棒了！你刚学会了如何使用`ChangeDetectorRef`服务分离 Angular 变更检测器。现在你已经完成了这个教程，看看下一节来了解它是如何工作的。

## 它是如何工作的...

`ChangeDetectorRef`服务提供了一系列重要的方法来完全控制变化检测。在这个示例中，我们在`UsersComponent`类的`ngOnInit()`方法中使用`.detach()`方法来从这个组件中分离出 Angular 变化检测机制。结果，`UsersComponent`类以及其子类都不会触发任何变化检测。这是因为每个 Angular 组件都有一个变化检测树，其中每个组件都是一个节点。当我们从变化检测树中分离一个组件时，该组件（作为树节点）以及其子组件（或节点）也会被分离。通过这样做，我们最终使`UsersComponent`类不会发生任何变化检测。因此，当我们刷新页面时，即使我们从**应用程序编程接口**（**API**）获取了用户并将它们分配给`UsersComponent`类中的`users`属性，也不会渲染任何内容。由于我们需要在视图上显示用户，这需要触发 Angular 变化检测机制，我们在将用户数据分配给`users`属性后，立即使用`ChangeDetectorRef`实例的`.detectChanges()`方法。结果，Angular 运行了变化检测机制，我们在视图上看到了用户卡片。

这意味着在整个**Users**页面（即`/users`路由）上，只有在`UsersComponent`类初始化后，当我们调用`searchUsers()`方法，从 API 获取数据并将结果分配给`users`属性时，Angular 变化检测机制才会触发，从而创建一个高度受控的变化检测周期，从而在整体上获得更好的性能。

## 参见

+   `ChangeDetectorRef`官方文档([`angular.io/api/core/ChangeDetectorRef`](https://angular.io/api/core/ChangeDetectorRef))

# 在 Angular 之外运行异步事件的 runOutsideAngular

Angular 在一些事物上运行其变更检测机制，包括但不限于所有浏览器事件，如`keyup`、`keydown`等。它还在`setTimeout`、`setInterval`和 Ajax HTTP 调用上运行变更检测。如果我们需要避免在这些事件中运行变更检测，我们需要告诉 Angular 不要在这些事件上触发变更检测 - 例如，如果您在 Angular 组件中使用`setTimeout()`方法，每次调用其回调方法时都会触发 Angular 变更检测。在这个食谱中，您将学习如何使用`runOutsideAngular()`方法在`ngZone`服务之外执行代码块。

## 准备就绪

这个食谱的项目位于`Chapter12/start_here/run-outside-angula`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  运行`ng serve -o`命令启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序，如下所示：

![图 12.9 - 在 http://localhost:4200 上运行的 App run-outside-angular](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.9_B15150.jpg)

图 12.9 - 在 http://localhost:4200 上运行的 App run-outside-angular

现在我们的应用程序正在运行，让我们在下一节中看一下食谱的步骤。

## 如何做…

我们有一个显示手表的应用程序。但是，目前应用程序中的变更检测并不理想，我们有很大的改进空间。我们将尝试使用`ngZone`中的`runOutsideAngular`方法来消除任何不必要的变更检测。让我们开始吧：

1.  时钟值不断更新。因此，我们对每个更新周期运行变更检测。打开 Chrome DevTools 并切换到**控制台**选项卡。键入`appLogs`并按*Enter*，以查看`hours`、`minutes`、`seconds`和`milliseconds`组件的变更检测运行次数。应该看起来像这样：![图 12.10 - 反映变更检测运行次数的 appLogs 对象](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.10_B15150.jpg)

图 12.10 - 反映变更检测运行次数的 appLogs 对象

1.  为了衡量性能，我们需要在固定时间段内查看数字。让我们添加一些代码，在应用程序启动后的 4 秒内关闭时钟的间隔计时器。修改`watch-box.component.ts`文件，如下所示：

```ts
...
@Component({...})
export class WatchBoxComponent implements OnInit {
  ...
  ngOnInit(): void {
    this.intervalTimer = setInterval(() => {
      this.timer();
    }, 1);
    setTimeout(() => {
      clearInterval(this.intervalTimer);
    }, 4000);
  }
  ...
}
```

1.  刷新应用程序并等待 4 秒钟以停止时钟。然后，在**控制台**选项卡中多次输入`appLogs`，按*Enter*，并查看结果。时钟停止，但动画仍在运行。您应该看到`watch`键的变更检测仍在增加，如下所示：![图 12.11 - 对手表组件的变更检测仍在运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.11_B15150.jpg)

图 12.11 - 对手表组件的变更检测仍在运行

1.  让我们在手表内部的动画运行 4 秒后停止。更新`watch.component.ts`文件如下：

```ts
...
@Component({...})
export class WatchComponent implements OnInit {
  ...
  ngOnInit(): void {
    this.intervalTimer = setInterval(() => {
      this.animate();
    }, 30);
    setTimeout(() => {
      clearInterval(this.intervalTimer);
    }, 4000);
  }
  ...
}
```

刷新应用程序并等待动画停止。查看 Chrome DevTools 中的`appLogs`对象，您应该看到`watch`键的变更检测停止，如下所示：

![图 12.12 - 停止动画间隔后变更检测停止](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.12_B15150.jpg)

图 12.12 - 停止动画间隔后变更检测停止

1.  我们希望动画运行，但不会导致额外的变更检测运行。这是因为我们希望使我们的应用程序更加高效。所以，让我们暂停时钟。为此，请更新`watch-box.component.ts`文件如下：

```ts
...
@Component({...})
export class WatchBoxComponent implements OnInit {
  ...
  ngOnInit(): void {
    // this.intervalTimer = setInterval(() => {
    //   this.timer();
    // }, 1);
    // setTimeout(() => {
    //   clearInterval(this.intervalTimer);
    // }, 4000);
  }
}
```

由于我们现在已经停止了时钟，因此`appLogs`中`watch`键的值现在仅基于这 4 秒的动画。您现在应该看到`watch`键的值在**250**和**260**之间。

1.  让我们通过在`ngZone`服务外部运行间隔来避免对动画进行变更检测。我们将使用`runOutsideAngular()`方法来实现这一点。更新`watch.component.ts`文件如下：

```ts
import {
  ...
  ViewChild,
  NgZone,
} from '@angular/core';
@Component({...})
export class WatchComponent implements OnInit {
  ...
  constructor(private zone: NgZone) {
   ...
  }
  ngOnInit(): void {
    this.zone.runOutsideAngular(() => {
      this.intervalTimer = setInterval(() => {
        this.animate();
      }, 30);
      setTimeout(() => {
        clearInterval(this.intervalTimer);
      }, 2500);
    });
  }
  ...
}
```

刷新应用程序并等待大约 5 秒钟。如果现在检查`appLogs`对象，您应该看到每个属性的变更检测运行总数减少，如下所示：

![图 12.13 - 在 WatchComponent 中使用 runOutsideAngular()后的 appLogs 对象](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.13_B15150.jpg)

图 12.13 - 在 WatchComponent 中使用 runOutsideAngular()后的 appLogs 对象

耶耶！注意`appLogs`对象中`watch`键的值已经从大约**250**减少到**4**。这意味着我们的动画现在根本不会影响变更检测。

1.  从`WatchComponent`类的动画中删除对`clearInterval()`的使用。结果，动画应该继续运行。修改`watch.component.ts`文件如下：

```ts
...
@Component({...})
export class WatchComponent implements OnInit {
  ...
  ngOnInit(): void {
    ...
    this.ngZone.runOutsideAngular(() => {
      this.intervalTimer = setInterval(() => {
        this.animate();
      }, 30);
      setTimeout(() => { // ← Remove this block
        clearInterval(this.intervalTimer);
      }, 4000);
    });
  }
  ...
}
```

1.  最后，从`WatchBoxComponent`类中删除对`clearInterval()`的使用以运行时钟。更新`watch-box.component.ts`文件如下：

```ts
import { Component, OnInit } from '@angular/core';
@Component({
  selector: 'app-watch-box',
  templateUrl: './watch-box.component.html',
  styleUrls: ['./watch-box.component.scss'],
})
export class WatchBoxComponent implements OnInit {
  name = '';
  time = {
    hours: 0,
    minutes: 0,
    seconds: 0,
    milliseconds: 0,
  };
  intervalTimer;
  constructor() {}
  ngOnInit(): void {
    this.intervalTimer = setInterval(() => {
      this.timer();
    }, 1);
    setTimeout(() => { // ← Remove this
      clearInterval(this.intervalTimer);
    }, 4000);
  }
  ...
}
```

刷新应用程序并在几秒钟后多次检查`appLogs`对象的值。你应该看到类似于这样的内容：

![图 12.14 - 使用 runOutsideAngular()进行性能优化后的 appLogs 对象](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.14_B15150.jpg)

图 12.14 - 使用 runOutsideAngular()进行性能优化后的 appLogs 对象

看着前面的截图，你可能会说：“阿赫桑！这是什么？我们对于观察键的变化检测运行次数仍然很大。这到底有多高效？”很高兴你问了。我会在“它是如何工作的…”部分告诉你*为什么*。

1.  最后一步，停止 Angular 服务器，并运行以下命令以在生产模式下启动服务器：

```ts
ng serve --prod
```

1.  再次转到[`localhost:4200`](https://localhost:4200)。等待几秒钟，然后多次检查**控制台**选项卡中的`appLogs`对象。你应该看到如下对象：

![图 12.15 - 使用生产构建的 appLogs 对象](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.15_B15150.jpg)

图 12.15 - 使用生产构建的 appLogs 对象

砰！如果你看前面的截图，你会发现`watch`键的变化检测运行次数总是比`milliseconds`键多一个周期。这意味着`WatchComponent`类几乎只在我们更新`@Input() milliseconds`绑定的值时重新渲染。

现在你已经完成了这个示例，看看下一节来了解它是如何工作的。

## 它是如何工作…

在这个示例中，我们首先查看了`appLogs`对象，其中包含一些键值对。每个键值对的值表示 Angular 为特定组件运行变化检测的次数。`hours`、`milliseconds`、`minutes`和`seconds`键分别表示时钟上显示的每个值的`WatchTimeComponent`实例。`watch`键表示`WatchComponent`实例。

在配方的开头，我们看到`watch`键的值比`milliseconds`键的值大两倍以上。我们为什么要关心`milliseconds`键呢？因为在我们的应用程序中，`@Input()`属性绑定`milliseconds`是最频繁变化的——也就是说，它每 1 毫秒（ms）就会变化一次。第二频繁变化的值是`WatchComponent`类中的`xCoordinate`和`yCoordinates`属性，它们每 30 毫秒变化一次。`xCoordinate`和`yCoordinate`的值并没有直接绑定到模板（超文本标记语言（HTML））上，因为它们会改变`stopWatch`视图子组件的层叠样式表（CSS）变量。这是在`animate()`方法内部发生的：

```ts
el.style.setProperty('--x', `${this.xCoordinate}px`);
el.style.setProperty('--y', `${this.yCoordinate}px`);
```

因此，改变这些值实际上不应该触发变化检测。我们首先通过在`WatchBoxComponent`类中使用`clearInterval()`方法来限制时钟窗口，以便时钟在 4 秒内停止，我们可以评估数字。在*图 12.11*中，我们看到即使时钟停止后，变化检测机制仍然会为`WatchComponent`类触发。随着时间的推移，这会增加`appLogs`对象中`watch`键的计数。然后我们在`WatchComponent`类中使用`clearInterval()`来停止动画。这也在 4 秒后停止动画。在*图 12.12*中，我们看到`watch`键的计数在动画停止后停止增加。

然后我们尝试只基于动画来查看变化检测的计数。在*步骤 6*中，我们停止了时钟。因此，我们只会得到`appLogs`对象中`watch`键的基于动画的计数，这个值在 250 和 260 之间。

然后我们在代码中引入了神奇的`runOutsideAngular()`方法。这个方法是`NgZone`服务的一部分。`NgZone`服务打包在`@angular/core`包中。`runOutsideAngular()`方法接受一个方法作为参数。这个方法在 Angular 区域之外执行。这意味着在`runOutsideAngular()`方法内部使用的`setTimeout()`和`setInterval()`方法不会触发 Angular 变化检测周期。在*图 12.13*中，您可以看到使用`runOutsideAngular()`方法后，计数下降到 4。

然后，我们从`WatchBoxComponent`和`WatchComponent`类中删除了`clearInterval()`的使用-也就是说，像我们在开始时那样再次运行时钟和动画。在*图 12.14*中，我们看到`watch`键的计数几乎是`milliseconds`键的两倍。现在，为什么会是两倍呢？这是因为在开发模式下，Angular 运行变更检测机制两次。因此，在*步骤 9*和*步骤 10*中，我们以生产模式运行应用程序，在*图 12.15*中，我们看到`watch`键的值仅比`milliseconds`键的值大 1，这意味着动画不再触发我们应用程序的任何变更检测。很棒，不是吗？如果您发现这个示例有用，请在我的社交媒体上告诉我。

现在您已经了解了它的工作原理，请参阅下一节以获取更多信息。

## 另请参阅

+   `NgZone`官方文档([`angular.io/api/core/NgZone`](https://angular.io/api/core/NgZone))

+   Angular `ChangeDetectorRef`官方文档([`angular.io/api/core/ChangeDetectorRef`](https://angular.io/api/core/ChangeDetectorRef))

# 使用*ngFor 为列表添加 trackBy

列表是我们今天构建的大多数应用程序的重要部分。如果您正在构建一个 Angular 应用程序，您很有可能会在某个时候使用`*ngFor`指令。我们知道`*ngFor`允许我们循环遍历数组或对象，为每个项目生成 HTML。然而，对于大型列表，使用它可能会导致性能问题，特别是当`*ngFor`的源完全改变时。在这个示例中，我们将学习如何使用`*ngFor`指令和`trackBy`函数来提高列表的性能。让我们开始吧。

## 准备工作

此示例的项目位于`Chapter12/start_here/using-ngfor-trackb:`中

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  运行`ng serve -o`命令启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序如下：

![图 12.16-应用程序使用-ngfor-trackby 在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.16_B15150.jpg)

图 12.16-应用程序使用-ngfor-trackby 在 http://localhost:4200 上运行

现在我们的应用程序正在运行，让我们在下一节中看看这个示例的步骤。

## 如何做…

我们有一个应用程序，在视图上显示了 1,000 个用户的列表。由于我们没有使用虚拟滚动和标准的`*ngFor`列表，目前我们面临一些性能问题。请注意，当您刷新应用程序时，即使加载程序隐藏了，您会在列表出现之前看到一个空白的白色框大约 2-3 秒钟。让我们开始重现性能问题并修复它们的步骤。

1.  首先，打开 Chrome DevTools 并查看**控制台**选项卡。您应该看到`ListItemComponent initiated`消息被记录了 1,000 次。每当创建/初始化列表项组件时，都会记录此消息。

1.  现在，通过使用交叉按钮删除第一项。您现在应该再次看到大约 999 次相同的消息被记录，如下截图所示。这意味着我们为剩下的 999 个项目重新创建了列表项组件：![图 12.17–删除项目后再次显示日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.17_B15150.jpg)

图 12.17–删除项目后再次显示日志

1.  现在，刷新应用程序并点击第一个列表项。您应该再次看到`ListItemComponent initiated`日志，如下截图所示。这意味着我们在项目更新时重新创建所有列表项。您会注意到在**用户界面**（**UI**）中对第一项名称的更新在大约 2-3 秒内反映出来：![图 12.18–更新项目后再次显示日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.18_B15150.jpg)

图 12.18–更新项目后再次显示日志

1.  现在，让我们通过使用`trackBy`函数来解决性能问题。打开`the-amazing-list.component.ts`文件并进行更新，如下所示：

```ts
...
@Component({...})
export class TheAmazingListComponent implements OnInit {
  ...
  ngOnInit(): void {}
  trackByFn(_, user: AppUserCard) {
    return user.email;
  }
}
```

1.  现在，更新`the-amazing-list.component.html`文件，使用我们刚刚创建的`trackByFn()`方法，如下所示：

```ts
<h4 class="heading">Our trusted customers</h4>
<div class="list list-group">
  <app-list-item
    *ngFor="let item of listItems; trackBy: trackByFn"
    [item]="item"
    (itemClicked)="itemClicked.emit(item)"
    (itemDeleted)="itemDeleted.emit(item)"
  >
  </app-list-item>
</div>
```

1.  现在，刷新应用程序，并点击第一个列表项进行更新。您会注意到项目立即更新，我们不再记录`ListItemComponent initiated`消息，如下截图所示：![图 12.19–使用 trackBy 函数更新项目后没有更多日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.19_B15150.jpg)

图 12.19–使用 trackBy 函数更新项目后没有更多日志

1.  现在也删除一个项目，您会看到在这种情况下我们不再记录`ListItemComponent initiated`消息。

太棒了！您现在知道如何使用`*ngFor`指令的`trackBy`函数来优化 Angular 中列表的性能。要了解该配方背后的所有魔力，请参阅下一节。

## 它是如何工作的…

`*ngFor`指令默认假定对象本身是其唯一标识，这意味着如果您只更改了`*ngFor`指令中使用的对象的属性，则不会重新呈现该对象的模板。但是，如果您提供一个新对象（内存中的不同引用），特定项目的内容将重新呈现。这实际上是我们在这个配方中为了重现性能问题内容所做的。在`data.service.ts`文件中，我们有`updateUser()`方法的以下代码：

```ts
updateUser(updatedUser: AppUserCard) {
    this.users = this.users.map((user) => {
      if (user.email === updatedUser.email) {
        return {
      ...updatedUser,
   };
      }
      // this tells angular that every object has now       a different reference
      return { ...user };
    });
  }
```

请注意，我们使用对象扩展运算符（`{ … }`）为数组中的每个项目返回一个新对象。这告诉`*ngFor`指令在`TheAmazingListComponent`类的`listItems`数组中的每个项目上重新呈现 UI。假设您向服务器发送查询以查找或过滤用户。服务器可能返回一个包含 100 个用户的响应。在这 100 个用户中，大约有 90 个已经在视图上呈现，只有 10 个不同。然而，由于以下潜在原因（但不限于此），Angular 将重新呈现所有列表项的 UI：

+   用户的排序/放置可能已经改变。

+   用户的长度可能已经改变。

现在，我们希望避免使用对象引用作为每个列表项的唯一标识符。对于我们的用例，我们知道每个用户的电子邮件是唯一的，因此我们使用`trackBy`函数告诉 Angular 使用用户的电子邮件作为唯一标识符。现在，即使我们在`updateUser()`方法中为每个用户返回一个新对象（如前所示），Angular 也不会重新呈现所有列表项。这是因为新对象（用户）具有相同的电子邮件，Angular 使用它来跟踪它们。很酷，对吧？

现在您已经了解了该配方的工作原理，请查看下一节以查看进一步阅读的链接。

## 另请参阅

+   `NgForOf`官方文档（[`angular.io/api/common/NgForOf`](https://angular.io/api/common/NgForOf)）

# 将重计算移动到纯管道

在 Angular 中，我们有一种特殊的编写组件的方式。由于 Angular 的观点很强烈，我们已经从社区和 Angular 团队那里得到了很多关于编写组件时要考虑的指南，例如，直接从组件中进行 HTTP 调用被认为是一个不太好的做法。同样，如果组件中有大量计算，这也被认为是一个不好的做法。当视图依赖于使用计算不断转换数据的转换版本时，使用 Angular 管道是有意义的。在这个示例中，您将学习如何使用 Angular 纯管道来避免组件内的大量计算。

## 准备工作

我们要处理的项目位于`Chapter12/start_here/using-pure-pipes`，在克隆的存储库中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  运行`ng serve -o`命令启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序如下：

![图 12.20 – 在 http://localhost:4200 上运行 using-pure-pipes 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.20_B15150.jpg)

图 12.20 – 在 http://localhost:4200 上运行 using-pure-pipes 应用程序

现在我们在浏览器上提供了项目，让我们在下一节中看看这个示例的步骤。

## 如何做…

我们正在处理的应用程序存在一些性能问题，特别是`UserCardComponent`类，因为它使用`idUsingFactorial()`方法来生成要显示在卡片上的唯一 ID。如果您尝试在搜索框中输入`'irin'`，您会注意到应用程序会暂停一段时间。我们无法立即看到在搜索框中输入的字母，并且在结果显示之前需要一段时间。我们将通过将`idUsingFactorial()`方法中的计算移动到 Angular（纯）管道中来解决这些问题。让我们开始：

1.  让我们创建一个 Angular 管道。我们将把为这个管道生成唯一 ID 的计算移到后面的代码中。在项目根目录中，在终端中运行以下命令：

```ts
ng g pipe core/pipes/unique-id
```

1.  现在，从`user-card.component.ts`文件中复制`createUniqueId()`方法的代码，并粘贴到`unique-id.pipe.ts`文件中。我们还将稍微修改代码，所以现在应该是这样的：

```ts
...
@Pipe({...})
export class UniqueIdPipe implements PipeTransform {
  characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef   ghijklmnopqrstuvwxyz0123456789';
  createUniqueId(length) {
    var result = '';
    const charactersLength = this.characters.length;
    for (let i = 0; i < length; i++) {
      result += this.characters.charAt(
        Math.floor(Math.random() * charactersLength)
      );
    }
    return result;
  }
  ...
  transform(index: unknown, ...args: unknown[]): unknown {
    return null;
  }
}
```

1.  现在，还要从`user-card.component.ts`文件中复制`idUsingFactorial()`方法到`unique-id.pipe.ts`文件，并更新文件，如下所示：

```ts
import { Pipe, PipeTransform } from '@angular/core';
@Pipe({
  name: 'uniqueId',
})
export class UniqueIdPipe implements PipeTransform {
  ...
  idUsingFactorial(num, length = 1) {
    if (num === 1) {
      return this.createUniqueId(length);
    } else {
      const fact = length * (num - 1);
      return this.idUsingFactorial(num - 1, fact);
    }
  }
  transform(index: number): string {
    return this.idUsingFactorial(index);
  }
}
```

1.  现在，更新`user-card.component.html`文件，使用`uniqueId`管道而不是组件的方法。代码应该如下所示：

```ts
<div class="user-card">
  <div class="card" *ngIf="user" (click)="cardClicked()">
    <img [src]="user.picture.large" class="card-img-top"     alt="..." />
    <div class="card-body">
      <h5 class="card-title">{{ user.name.first }}      {{ user.name.last }}</h5>
      <p class="card-text">{{ user.email }}</p>
      <p class="card-text unique-id" title="{{ index |       uniqueId }}">
        {{ index | uniqueId }}
      </p>
      <a href="tel: {{ user.phone }}" class="btn       btn-primary">{{
        user.phone
      }}</a>
    </div>
  </div>
</div>
```

1.  现在，刷新应用程序并在搜索框中输入名称`Elfie Siegert`。注意到 UI 没有被阻塞。我们能够立即看到我们输入的字母，搜索结果也更快。

砰！现在你知道了如何通过将繁重的计算移动到纯 Angular 管道来优化性能，接下来看看下一节，了解这是如何工作的。

## 它是如何工作的…

正如我们所知，Angular 默认在应用程序中触发的每个浏览器事件上运行变更检测，而且由于我们在组件模板（UI）中使用了`idUsingFactorial()`方法，这个函数会在每次 Angular 运行变更检测机制时运行，导致更多的计算和性能问题。如果我们使用 getter 而不是方法，情况也是如此。在这里，我们使用方法是因为每个唯一的 ID 都依赖于索引，当调用它时，我们需要在方法中传递索引。

我们可以从最初的实现中退一步，思考这个方法实际上是做什么。它接受一个输入，进行一些计算，并根据输入返回一个值——这是数据转换的经典例子，也是你会使用纯函数的例子。幸运的是，Angular 纯管道是纯函数，除非输入发生变化，它们不会触发变更检测。

在这个示例中，我们将计算移动到一个新创建的 Angular 管道中。管道的`transform()`方法接收我们应用管道的值，即`users`数组中每个用户卡的索引。然后管道使用`idUsingFactorial()`方法，最终使用`createUniqueId()`方法来计算一个随机的唯一 ID。当我们开始在搜索框中输入时，索引的值不会改变。这导致在我们输入到搜索框中时不会触发变更检测，从而优化性能并解除 UI 线程的阻塞。

## 另请参阅

+   Angular 纯管道和不纯管道官方文档（[`angular.io/guide/pipes#pure-and-impure-pipes`](https://angular.io/guide/pipes#pure-and-impure-pipes)）

# 使用 Web Workers 进行繁重的计算

如果您的 Angular 应用程序在执行操作期间进行了大量计算，那么它很有可能会阻塞 UI 线程。这将导致 UI 渲染出现延迟，因为它阻塞了主 JavaScript 线程。Web workers 允许我们在后台线程中运行大量计算，从而释放 UI 线程，因为它不会被阻塞。在本教程中，我们将使用一个应用程序，在`UserService`类中进行大量计算。它为每个用户卡创建一个唯一 ID，并将其保存到`localStorage`中。但是，在这样做之前，它会循环几千次，这会导致我们的应用程序暂时挂起。在本教程中，我们将把大量计算从组件移动到 web worker，并在 web worker 不可用的情况下添加一个回退。

## 准备工作

我们将要处理的项目位于克隆存储库中的`Chapter12/start_here/using-web-workers`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  运行`ng serve -o`命令启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序如下：

![图 12.21 - 应用程序 using-web-workers 在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.21_B15150.jpg)

图 12.21 - 应用程序 using-web-workers 在 http://localhost:4200 上运行

现在我们的应用程序正在运行，让我们在下一节中看看本教程的步骤。

## 操作步骤如下…

一旦您打开应用程序，您会注意到在用户卡片被渲染之前需要一些时间。这表明 UI 线程被阻塞，直到计算完成。罪魁祸首是`UserService`类中的`saveUserUniqueIdsToStorage()`方法。这在保存到`localStorage`之前会生成几千个唯一 ID。让我们开始本教程，以改善应用程序的性能。我们将首先实现 web worker：

1.  我们将首先创建一个 web worker。在项目根目录中运行以下命令：

```ts
ng generate web-worker core/workers/idGenerator
```

1.  现在，将`UserService`类中的`saveUserUniqueIdsToStorage()`方法中的`for`循环复制到新创建的`id-generator.worker.ts`文件中。代码应该如下所示：

```ts
/// <reference lib="webworker" />
import createUniqueId from '../constants/create-unique-id';
addEventListener('message', ({ data }) => {
  console.log('message received IN worker', data);
  const { index, email } = data;
  let uniqueId;
  for (let i = 0, len = (index + 1) * 100000; i < len;   ++i) {
    uniqueId = createUniqueId(50);
  }
  postMessage({ uniqueId, email });
});
```

1.  现在我们已经创建了 worker 文件，让我们创建一个 worker 的单个实例，以便在接下来的步骤中使用它。在`constants`文件夹中创建一个新文件。命名为`get-unique-id-worker.ts`，并在文件中添加以下代码：

```ts
let UNIQUE_ID_WORKER: Worker = null;
const getUniqueIdWorker = (): Worker => {
  if (typeof Worker !== 'undefined' && UNIQUE_ID_WORKER   === null) {
    UNIQUE_ID_WORKER = new Worker('../workers/    id-generator.worker', {
      type: 'module',
    });
  }
  return UNIQUE_ID_WORKER;
};
export default getUniqueIdWorker;
```

1.  现在，我们将在`user.service.ts`文件中使用 worker。更新它如下：

```ts
...
import getUniqueIdWorker from '../constants/get-unique-id-worker';
@Injectable({...})
export class UserService {
  ...
  worker: Worker = getUniqueIdWorker();
  constructor(private http: HttpClient) {
  this.worker.onmessage = ({ data: { uniqueId, email }   }) => {
      console.log('received message from worker',       uniqueId, email);
      const user = this.usersCache.find((user) => user.      email === email);
      localStorage.setItem(
        `ng_user__${user.email}`,
        JSON.stringify({
          ...user,
          uniqueId,
        })
      );
    };
  }
  ...
}
```

1.  我们将再次更新文件以修改`saveUserUniqueIdsToStorage()`方法。如果环境中有 Web 工作者可用，我们将使用工作者而不是使用现有的代码。按照以下方式更新`user.service.ts`文件：

```ts
...
@Injectable({...})
export class UserService {
  ...
  saveUserUniqueIdsToStorage(user: IUser, index) {
    let uniqueId;
    const worker: Worker = getUniqueIdWorker();
    if (worker !== null) {
      worker.postMessage({ index, email: user.email });
    } else {
      // fallback
      for(let i = 0, len = (index + 1) * 100000; i<len;       ++i) {
        uniqueId = createUniqueId(50);
      }
      localStorage.setItem(...);
    }
  }
  ...
}
```

1.  刷新应用程序，注意用户卡片渲染需要多长时间。它们应该比以前出现得快得多。此外，你应该能够看到以下日志，反映了应用程序与 Web 工作者之间的通信：

![图 12.22 - 显示应用程序与 Web 工作者之间消息的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.22_B15150.jpg)

图 12.22 - 显示应用程序与 Web 工作者之间消息的日志

哇呜！Web 工作者的力量！现在你知道如何在 Angular 应用程序中使用 Web 工作者将繁重的计算移动到它们那里了。既然你已经完成了这个教程，那就看看下一节它是如何工作的吧。

## 它是如何工作的...

正如我们在教程描述中讨论的那样，Web 工作者允许我们在与主 JavaScript（或 UI 线程）分开的线程中运行和执行代码。在教程开始时，每当我们刷新应用程序或搜索用户时，它都会阻塞 UI 线程。直到为每张卡生成一个唯一的 ID 为止。我们通过使用 Angular 的**命令行界面**（**CLI**）创建一个 Web 工作者来开始这个教程。这将创建一个`id-generator.worker.ts`文件，其中包含一些样板代码，用于接收来自 UI 线程的消息并作为响应发送消息回去。CLI 命令还通过添加`webWorkerTsConfig`属性来更新`angular.json`文件。`webWorkerTsConfig`属性的值是`tsconfig.worker.json`文件的路径，CLI 命令还创建了这个`tsconfig.worker.json`文件。如果你打开`tsconfig.worker.json`文件，你应该会看到以下代码：

```ts
/* To learn more about this file see: https://angular.io/config/tsconfig. */
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "outDir": "./out-tsc/worker",
    "lib": [
      "es2018",
      "webworker"
    ],
    "types": []
  },
  "include": [
    "src/**/*.worker.ts"
  ]
}
```

创建完 Web Worker 文件后，我们创建另一个名为`uniqueIdWorker.ts`的文件。该文件将`getUniqueIdWorker()`方法作为默认导出。当我们调用此方法时，如果尚未生成 Worker 实例，它将生成一个新的`Worker`实例。该方法使用`id-generator.worker.ts`文件来生成 Worker。我们还在 Worker 文件中使用`addEventListener()`方法来监听从 UI 线程（即`UserService`类）发送的消息。我们接收到的消息中包含用户卡的`index`和用户的`email`。然后我们使用`for`循环来生成一个唯一 ID（`uniqueId`变量），循环结束后，我们使用`postMessage()`方法将`uniqueId`变量和`email`发送回 UI 线程。

现在，在`UserService`类中，我们监听来自 Worker 的消息。在`constructor()`方法中，我们通过检查`getUniqueIdWorker()`方法的值（应该是非空值）来检查环境中是否可用 Web Workers。然后，我们使用`worker.onmessage`属性来分配一个方法。这是为了监听来自 Worker 的消息。由于我们已经知道我们从 Worker 那里得到了`uniqueId`变量和`email`，我们使用`email`来从`usersCache`变量中获取相应的用户。然后，我们将用户数据与`uniqueId`变量存储到`localStorage`中，针对用户的`email`。

最后，我们更新`saveUserUniqueIdsToStorage()`方法以使用 Worker 实例（如果可用）。请注意，我们使用`worker.postMessage()`方法来传递用户的`index`和`email`。还要注意，我们在没有启用 Web Workers 的情况下，使用先前的代码作为备用。

## 另请参阅

+   Angular 官方文档关于 Web Workers 的内容（[`angular.io/guide/web-worker`](https://angular.io/guide/web-worker)）

+   MDN 关于 Web Worker 的文档（[`developer.mozilla.org/en-US/docs/Web/API/Worker`](https://developer.mozilla.org/en-US/docs/Web/API/Worker)）

# 使用性能预算进行审核

在当今世界，大多数人口都有相当好的互联网连接，可以使用日常应用程序，无论是移动应用程序还是 Web 应用程序，令人着迷的是我们作为企业向最终用户发送了多少数据。现在向用户发送的 JavaScript 数量呈不断增长的趋势，如果你正在开发 Web 应用程序，你可能希望使用性能预算来确保捆绑包大小不超过一定限制。对于 Angular 应用程序，设置预算大小非常简单。在本教程中，您将学习如何使用 Angular CLI 为您的 Angular 应用程序设置预算。

## 准备工作

本教程的项目位于`Chapter12/start_here/angular-performance-budget`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  运行`ng build --configuration production`命令以在生产模式下构建 Angular 应用程序。注意控制台上的输出。它应该是这样的：

![图 12.23 - 以生产模式构建输出，没有性能预算](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.23_B15150.jpg)

图 12.23 - 以生产模式构建输出，没有性能预算

请注意，`main.*.js`文件的捆绑包大小目前约为 260 千字节（KB）。现在我们已经构建了应用程序，让我们在下一节中看看教程的步骤。

## 如何操作…

目前，我们的应用程序在捆绑包大小方面非常小。然而，随着即将到来的业务需求，这可能会变成一个庞大的应用程序。为了本教程的目的，我们将故意增加捆绑包大小，然后使用性能预算来阻止 Angular CLI 在捆绑包大小超过预算时构建应用程序。让我们开始教程：

1.  打开`app.component.ts`文件并进行更新，如下所示：

```ts
...
import * as moment from '../lib/moment';
import * as THREE from 'three';
@Component({...})
export class AppComponent {
  ...
  constructor(private auth: AuthService, private router:   Router) {
    const scene = new THREE.Scene();
    console.log(moment().format('MMM Do YYYY'));
  }
  ...
}
```

1.  现在，使用`ng build --configuration production`命令再次为生产构建应用程序。您会看到`main.*.js`文件的捆绑包大小现在为 1.12 兆字节（MB）。与原始的 268.05 KB 相比，这是一个巨大的增加，如下截图所示：![图 12.24 - main.*.js 的捆绑包大小增加到 1.11 MB](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.24_B15150.jpg)

图 12.24 - main.*.js 的捆绑包大小增加到 1.11 MB

假设我们的业务要求我们不要将主捆绑包大小超过 1.0 MB。为此，我们可以配置我们的 Angular 应用程序，如果达到阈值，就抛出错误。

1.  刷新应用程序，打开`angular.json`文件并进行更新。我们要定位的属性是`projects.angular-performance-budgets.architect.build.configurations.production.budgets`。文件应该如下所示：

```ts
...
{
  "budgets": [
    {
      "type": "initial",
      "maximumWarning": "800kb",
      "maximumError": "1mb"
    },
    {
      "type": "anyComponentStyle",
      "maximumWarning": "6kb",
      "maximumError": "10kb"
    }
  ]
}
...
```

1.  现在我们已经制定了预算，让我们再次使用`ng build --configuration production`命令构建应用程序。构建应该会失败，并且您应该在控制台上看到警告和错误，如下所示：![图 12.25 – Angular CLI 根据性能预算抛出错误和警告](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.25_B15150.jpg)

图 12.25 – Angular CLI 根据性能预算抛出错误和警告

1.  通过在`app.component.ts`文件中不导入整个库，并使用`date-fns`包代替`moment.js`来改进我们的应用程序。运行以下命令安装`date-fns`包：

```ts
npm install --save date-fns
```

1.  现在，按照以下步骤更新`app.component.ts`文件：

```ts
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './services/auth.service';
import { format } from 'date-fns';
import { Scene } from 'three';
@Component({...})
export class AppComponent {
  ...
  constructor(private auth: AuthService, private router:   Router) {
    console.log(format(new Date(), 'LLL do yyyy'));
    const scene = new Scene();
  }
  ...
}
```

1.  再次运行`ng build --configuration production`命令。您应该会看到捆绑包大小减小，如下所示：

![图 12.26 – 使用 date-fns 和优化导入后减小的捆绑包大小](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.26_B15150.jpg)

图 12.26 – 使用 date-fns 和优化导入后减小的捆绑包大小

砰！！你刚学会了如何使用 Angular CLI 来定义性能预算。这些预算可以根据您的配置来发出警告和错误。请注意，预算可以根据不断变化的业务需求进行修改。然而，作为工程师，我们必须谨慎地设置性能预算，以免将 JavaScript 超出一定限制发送给最终用户。

## 另请参阅

+   Angular CLI 官方文档中的性能预算（[`web.dev/performance-budgets-with-the-angular-cli/`](https://web.dev/performance-budgets-with-the-angular-cli/)）

# 使用 webpack-bundle-analyzer 分析捆绑包

在上一个示例中，我们看到了为我们的 Angular 应用程序配置预算，这很有用，因为您可以知道整体捆绑包大小是否超过了某个阈值，尽管您不知道代码的每个部分实际上对最终捆绑包的贡献有多大。这就是我们所谓的*分析*捆绑包，在本示例中，您将学习如何使用`webpack-bundle-analyzer`来审计捆绑包大小和导致它们的因素。

## 准备就绪

我们要处理的项目位于克隆存储库中的`Chapter12/start_here/using-webpack-bundle-analyzer`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  运行`ng serve -o`命令来启动 Angular 应用程序并在浏览器上提供服务。您应该看到应用程序如下所示：![图 12.27 – 使用 webpack-bundle-analyzer 运行的应用程序位于 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.27_B15150.jpg)

图 12.27 – 使用 webpack-bundle-analyzer 运行的应用程序位于 http://localhost:4200

1.  现在，使用`ng build --configuration production`命令构建 Angular 应用程序的生产模式。您应该看到以下输出：

![图 12.28 – 主捆绑包，大小为 1.11 MB](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.28_B15150.jpg)

图 12.28 – 主捆绑包，大小为 1.11 MB

现在我们已经构建了应用程序，让我们看看下一节中的步骤。

## 如何做…

正如您可能已经注意到的，我们有一个大小为 1.12 MB 的主捆绑包。这是因为我们在`app.component.ts`文件中使用了`Three.js`库和`moment.js`库，它们被导入到主捆绑包中。让我们开始分析捆绑包大小的因素：

1.  我们首先安装`webpack-bundle-analyzer`包。在项目根目录中运行以下命令：

```ts
npm install --save-dev webpack-bundle-analyzer
```

1.  现在，在`package.json`文件中创建一个脚本。我们将在接下来的步骤中使用这个脚本来分析我们的最终捆绑包。更新`package.json`文件如下：

```ts
{
  ...
  "scripts": {
    "ng": "ng",
    "start": "ng serve",
    "build": "ng build",
    "test": "ng test",
    "lint": "ng lint",
    "e2e": "ng e2e",
    "analyze-bundle": "webpack-bundle-analyzer     dist/using-webpack-bundle-analyzer/stats.json"
  },
  "private": true,
  "dependencies": {... },
  "devDependencies": {...}
}
```

1.  现在，再次构建生产捆绑包，但使用参数生成一个`stats.json`文件。从项目根目录运行以下命令：

```ts
ng build --configuration production --stats-json
```

1.  现在，运行`analyze-bundle`脚本来使用`webpack-bundle-analyzer`包。从项目根目录运行以下命令：

```ts
npm run analyze-bundle
```

这将启动一个带有捆绑包分析的服务器。您应该看到默认浏览器中打开了一个新标签页，它应该是这样的：

![图 12.29 – 使用 webpack-bundle-analyzer 进行捆绑包分析](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.29_B15150.jpg)

图 12.29 – 使用 webpack-bundle-analyzer 进行捆绑包分析

1.  注意，`lib`文件夹占据了捆绑包大小的很大一部分——确切地说是 648.29 KB，你可以通过在`lib`框上悬停鼠标来检查。让我们尝试优化捆绑包大小。让我们安装`date-fns`包，这样我们就可以使用它而不是`moment.js`。从项目根目录运行以下命令：

```ts
npm install --save date-fns
```

1.  现在，更新`app.component.ts`文件，使用`date-fns`包的`format()`方法，而不是使用`moment().format()`方法。我们还将只从`Three.js`包中导入`Scene`类，而不是导入整个库。代码应该如下所示：

```ts
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { AuthService } from './services/auth.service';
import { format } from 'date-fns';
import { Scene } from 'three';
@Component({...})
export class AppComponent {
  ...
  constructor(private auth: AuthService, private router:   Router) {
    const scene = new Scene();
    console.log(format(new Date(), 'LLL do yyyy'));
  }
  ...
}
```

1.  运行`ng build --configuration production --stats-json`命令，然后运行`npm run analyze-bundle`。

一旦`webpack-bundle-analyzer`运行，您应该会看到分析结果，如下面的屏幕截图所示。请注意，我们不再有`moment.js`文件或`lib`块，整体捆绑大小已从 1.15 MB 减少到 831.44 KB：

![图 12.30-在使用 date-fns 而不是 moment.js 之后进行捆绑分析](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_12.30_B15150.jpg)

图 12.30-在使用 date-fns 而不是 moment.js 之后进行捆绑分析

哇呜！！！您现在知道如何使用`webpack-bundle-analyzer`包来审计 Angular 应用程序中的捆绑大小。这是改善整体性能的好方法，因为您可以识别导致捆绑大小增加的块，然后优化捆绑。

## 另请参阅

+   开始使用 webpack（[`webpack.js.org/guides/getting-started/`](https://webpack.js.org/guides/getting-started/)）

+   `webpack-bundle-analyzer`—GitHub 存储库（[`github.com/webpack-contrib/webpack-bundle-analyzer`](https://github.com/webpack-contrib/webpack-bundle-analyzer))


# 第十三章：*第十三章*：使用 Angular 构建 PWAs

PWAs 或渐进式 Web 应用程序本质上是 Web 应用程序。尽管它们使用现代浏览器支持的增强功能和体验构建，但如果在不支持现代功能/增强功能的浏览器中运行 PWA，则用户仍然可以获得 Web 应用程序的核心体验。在本章中，您将学习如何将 Angular 应用程序构建为 PWA。您将学习一些技术，使您的应用程序具有可安装、功能强大、快速和可靠的特性。以下是本章中要涵盖的内容：

+   使用 Angular CLI 将现有的 Angular 应用程序转换为 PWA

+   修改您的 PWA 的主题颜色

+   在您的 PWA 中使用深色模式

+   为您的 PWA 提供自定义可安装体验

+   使用 Angular 服务工作者预缓存请求

+   为您的 PWA 创建应用程序外壳

# 技术要求

在本章的示例中，请确保您的计算机上已安装 Git 和 Node.js。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。您还需要全局安装`http-server`包。您可以在终端中运行`npm install -g http-server`来安装它。本章的代码可以在[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter13`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter13)找到。

# 使用 Angular CLI 将现有的 Angular 应用程序转换为 PWA

PWA 涉及一些有趣的组件，其中两个是服务工作者和 Web 清单文件。服务工作者有助于缓存静态资源和缓存请求，而 Web 清单文件包含有关应用程序图标、应用程序的主题颜色等信息。在本示例中，我们将把现有的 Angular 应用程序转换为 PWA。这些原则也适用于从头开始创建的新 Angular 应用程序。为了示例，我们将转换一个现有的 Angular 应用程序。我们将看到我们的 Angular Web 应用程序中发生了什么变化，以及`@angular/pwa`包如何将其转换为 PWA。还有它如何帮助缓存静态资源。

## 准备工作

我们将要处理的项目位于克隆存储库中的`chapter13/start_here/angular-pwa-app`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng build --configuration production`。

1.  现在运行`http-server dist/angular-pwa-app -p 4200`。

这应该以生产模式在`http://localhost:4200`上运行应用程序，并且应该如下所示：

![图 13.1 - angular-pwa-app 在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.01_B15150.jpg)

图 13.1 - angular-pwa-app 在 http://localhost:4200 上运行

现在我们已经在本地运行了应用程序，让我们在下一节中看到食谱的步骤。

## 如何做到

我们正在使用的应用程序是一个简单的计数器应用程序。它有一个最小值和最大值，以及一些按钮，可以增加、减少和重置计数器的值。该应用程序将计数器的值保存在`localStorage`中，但它还不是 PWA。让我们将其转换为 PWA：

1.  首先，让我们看看我们的应用程序是否根本可以离线工作，因为这是 PWA 的特征之一。为应用程序打开 Chrome DevTools。转到**网络**选项卡，并将**限速**更改为**离线**，如下所示：![图 13.2 - 将网络限速更改为离线以查看离线体验](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.2_B15150.jpg)

图 13.2 - 将网络限速更改为离线以查看离线体验

1.  现在通过退出终端中的进程停止`http`服务器。完成后，刷新应用程序的页面。您应该看到应用程序不再工作，如下图所示：![图 13.3 - 应用程序在离线状态下无法工作](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.03_B15150.jpg)

图 13.3 - 应用程序在离线状态下无法工作

1.  要将此应用程序转换为 PWA，请打开一个新的终端窗口/选项卡，并确保您在`chapter13/start_here/angular-pwa-app`文件夹内。进入后，运行以下命令：

```ts
ng add @angular/pwa
```

当命令完成时，您应该看到一堆文件被创建和更新。

1.  现在再次构建应用程序，运行`ng build --configuration production`。完成后，使用`http-server dist/angular-pwa-app -p 4200`命令进行服务。

1.  现在确保您已经通过切换到**网络**选项卡并将**无限制**设置为选择选项来关闭限速，如*图 13.4*所示。还要注意**禁用缓存**选项已关闭：![图 13.4 - 关闭网络限速](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.04_B15150.jpg)

图 13.4 - 关闭网络限速

1.  现在刷新应用程序一次。您应该看到应用程序正在工作，并且网络日志显示从服务器加载了 JavaScript 文件等资产，如*图 13.5*所示：![图 13.5 - 从源下载的资产（Angular 服务器）](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.05_B15150.jpg)

图 13.5 - 从源（Angular 服务器）下载的资产

1.  现在再次刷新应用程序，你会看到相同的资产现在是使用服务工作线程从缓存中下载的，如*图 13.6*所示：![图 13.6 - 使用服务工作线程从缓存中下载的资产](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.06_B15150.jpg)

图 13.6 - 使用服务工作线程从缓存中下载的资产

1.  现在是我们一直在等待的时刻。将网络限制改回**离线**以进入**离线**模式，然后刷新应用程序。你应该仍然看到应用程序在**离线**模式下工作，因为服务工作线程，如*图 13.7*所示：![图 13.7 - 使用服务工作线程作为 PWA 离线工作的 Angular 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.07_B15150.jpg)

图 13.7 - 使用服务工作线程作为 PWA 离线工作的 Angular 应用程序

1.  而且，你现在实际上可以在你的机器上安装这个 PWA。由于我使用的是 MacBook，它被安装为 Mac 应用程序。如果你使用的是 Chrome，安装选项应该在地址栏附近，如*图 13.8*所示：

![图 13.8 - 从 Chrome 安装 Angular PWA](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.08_B15150.jpg)

图 13.8 - 从 Chrome 安装 Angular PWA

砰！只需使用`@angular/pwa`包，我们就将现有的 Angular 应用程序转换为 PWA，而且没有进行任何配置。我们现在能够离线运行我们的应用程序，并且可以在我们的设备上安装它作为 PWA。看看*图 13.9*，看看应用程序的外观 - 就像在 macOS X 上的本机应用程序一样：

![图 13.9 - 我们的 Angular PWA 在 macOS X 上作为本机应用程序的外观](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.09_B15150.jpg)

图 13.9 - 我们的 Angular PWA 在 macOS X 上作为本机应用程序的外观

很酷，对吧？现在你知道如何使用 Angular CLI 构建 PWA 了，看看下一节，了解它是如何工作的。

## 它是如何工作的

Angular 核心团队和社区在`@angular/pwa`包以及通常的`ng add`命令方面做得非常出色，这使我们能够使用 Angular 原理图向我们的应用程序添加不同的包。在这个示例中，当我们运行`ng add @angular/pwa`时，它使用原理图生成应用程序图标以及 Web 应用程序清单。如果你查看更改的文件，你可以看到新文件，如*图 13.10*所示：

![图 13.10 - Web 清单文件和应用图标文件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.10_B15150.jpg)

图 13.10 - Web 清单文件和应用图标文件

`manifest.webmanifest`文件是一个包含 JSON 对象的文件。这个对象定义了 PWA 的清单并包含一些信息。这些信息包括应用的名称、简称、主题颜色以及不同设备的不同图标的配置。想象一下这个 PWA 安装在你的安卓手机上。你肯定需要一个图标在你的主屏幕上，点击图标打开应用。这个文件包含了关于根据不同设备尺寸使用哪个图标的信息。

我们还会看到`ngsw-config.json`文件，其中包含了服务工作者的配置。在幕后，当`ng add`命令运行原理时，它也会在我们的项目中安装`@angular/service-worker`包。如果你打开`app.module.ts`文件，你会看到注册我们服务工作者的代码如下：

```ts
...
import { ServiceWorkerModule } from '@angular/service-worker';
...
@NgModule({
  declarations: [AppComponent, CounterComponent],
  imports: [
    ...
    ServiceWorkerModule.register('ngsw-worker.js', {
      enabled: environment.production,
      // Register the ServiceWorker as soon as the app is       stable
      // or after 30 seconds (whichever comes first).
      registrationStrategy: 'registerWhenStable:30000',
    }),
  ],
  ...
})
export class AppModule {}
```

该代码注册了一个名为`ngsw-worker.js`的新服务工作者文件。这个文件使用`ngsw-config.json`文件中的配置来决定缓存哪些资源以及使用哪些策略。

现在你知道这个配方是如何工作的了，看下一节以获取更多信息。

## 另请参阅

+   Angular 服务工作者介绍（[`angular.io/guide/service-worker-intro`](https://angular.io/guide/service-worker-intro))

+   什么是 PWA？（[`web.dev/what-are-pwas/`](https://web.dev/what-are-pwas/))

# 修改 PWA 的主题颜色

在上一个配方中，我们学习了如何将一个 Angular 应用转换为 PWA。当我们这样做时，`@angular/pwa`包会创建带有默认主题颜色的 Web 应用清单文件，如*图 13.9*所示。然而，几乎每个 Web 应用都有自己的品牌和风格。如果你想根据自己的品牌主题化 PWA 的标题栏，这就是你需要的配方。我们将学习如何修改 Web 应用清单文件来自定义 PWA 的主题颜色。

## 准备工作

这个配方的项目位于`chapter13/start_here/pwa-custom-theme-color`：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng build --configuration production`。

1.  现在运行`http-server dist/pwa-custom-theme-color -p 5300`来提供服务。

1.  打开`localhost:5300`来查看应用程序。

1.  最后，按照*图 13.8*中所示安装 PWA。

如果你打开 PWA，它应该如下所示：

![图 13.11 - PWA 自定义主题颜色应用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.11_B15150.jpg)

图 13.11 - PWA 自定义主题颜色应用

现在我们的应用程序正在运行，让我们在下一节中看看食谱的步骤。

## 如何做

正如*图 13.11*中所示，应用程序的标题栏与应用程序的原生标题栏（或工具栏）颜色有些不同。由于这种差异，应用程序看起来有点奇怪。我们将修改 Web 应用程序清单以更新主题颜色。让我们开始吧：

1.  在你的编辑器中打开`src/manifest.webmanifest`文件，并按照以下方式更改主题颜色：

```ts
{
  "name": "pwa-custom-theme-color",
  "short_name": "pwa-custom-theme-color",
  "theme_color": "#8711fc",
  "background_color": "#fafafa",
  "display": "standalone",
  "scope": "./",
  "start_url": "./",
  "icons": [...]
}
```

1.  我们的`index.html`文件中也设置了`theme-color`。默认情况下，它优先于 Web 应用程序清单文件。因此，我们需要更新它。打开`index.html`文件，并按照以下方式更新它：

```ts
<!DOCTYPE html>
<html lang="en">
  <head>
    ...
    <link rel="manifest" href="manifest.webmanifest" />
  <meta name="theme-color" content="#8711fc" />
  </head>
  <body>
    ...
  </body>
</html>
```

1.  现在，使用`ng build --configuration production`命令再次构建应用程序。然后使用`http-server`进行服务，如下所示：

```ts
http-server dist/pwa-custom-theme-color -p 5300
```

1.  再次打开 PWA 应用程序，并按照*图 13.12*中所示卸载它。确保在提示时勾选“也清除 Chrome 中的数据(...)”的复选框：![图 13.12 – 卸载 pwa-custom-theme-color 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.12_B15150.jpg)

图 13.12 – 卸载 pwa-custom-theme-color 应用程序

1.  现在在新的 Chrome 标签页中打开 Angular 应用程序，网址为`http://localhost:5300`，并按照*图 13.8*中所示再次安装该应用程序作为 PWA。

1.  PWA 应该已经打开了。如果没有，请从你的应用程序中打开它，你应该会看到更新后的主题颜色，就像*图 13.13*中所示：

![图 13.13 – 带有更新主题颜色的 PWA 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.13_B15150.jpg)

图 13.13 – 带有更新主题颜色的 PWA 应用程序

太棒了！你刚刚学会了如何为 Angular PWA 更新主题颜色。完成了这个食谱后，查看下一节以获取更多阅读材料。

## 另请参阅

+   使用 Angular CLI 创建 PWA ([`web.dev/creating-pwa-with-angular-cli/`](https://web.dev/creating-pwa-with-angular-cli/))

# 在你的 PWA 中使用深色模式

在现代设备和应用程序时代，最终用户的偏好也有所发展。随着屏幕和设备的使用增加，健康成为了一个主要关注点。我们知道现在几乎所有屏幕设备都支持深色模式。考虑到这一事实，如果你正在构建一个 Web 应用程序，你可能希望为其提供深色模式支持。如果它是一个以原生应用程序形式呈现的 PWA，那责任就更大了。在这个食谱中，你将学习如何为你的 Angular PWA 提供深色模式。

## 准备工作

这个食谱的项目位于`chapter13/start_here/pwa-dark-mode`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng build --configuration production`。

1.  现在运行 `http-server dist/pwa-dark-mode -p 6100` 进行服务。

1.  最后，按照 *图 13.8* 所示安装 PWA

1.  现在确保您的计算机上启用了暗色主题。如果您正在运行 macOS X，您可以打开 **设置** | **通用** 并选择 **暗色** 外观，如 *图 13.14* 所示：![图 13.14 – 在 macOS X 中更改系统外观为暗模式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.14_B15150.jpg)

图 13.14 – 在 macOS X 中更改系统外观为暗模式

1.  完成后，以原生应用程序的形式打开 PWA，您应该会看到它如 *图 13.15* 所示：

![图 13.15 – PWA 自定义主题颜色应用程序在系统暗模式下的外观](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.15_B15150.jpg)

图 13.15 – PWA 自定义主题颜色应用程序在系统暗模式下的外观

现在我们已经将 PWA 作为原生应用程序运行，并将暗模式应用于系统，让我们在下一节中看到食谱的步骤。

## 如何操作

正如您所见，目前 Angular 应用程序不支持暗模式。我们将从以开发模式运行应用程序开始，并为暗模式添加不同的颜色。让我们开始吧：

1.  以开发模式运行应用程序，运行命令 `ng serve -o --port 9291`。

这应该会在新的浏览器选项卡中为应用程序提供服务，网址为 `http://localhost:4200`。

1.  现在，打开 `styles.scss` 文件以使用 `prefers-color-scheme` 媒体查询。我们将为全局 CSS 变量使用不同的值，以创建暗模式的不同视图。按照以下方式更新文件：

```ts
/* You can add global styles to this file, and also import other style files */
:root {...}
html,
body {...}
@media (prefers-color-scheme: dark) {
  :root {
    --main-bg: #333;
    --text-color: #fff;
    --card-bg: #000;
    --primary-btn-color: #fff;
    --primary-btn-text-color: #333;
  }
}
```

如果您在浏览器选项卡中再次刷新应用程序，您将看到基于 `prefers-color-scheme` 媒体查询的不同暗模式视图，如 *图 13.16* 所示：

![图 13.16 – 使用 prefers-color-scheme 媒体查询的暗模式视图](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.16_B15150.jpg)

图 13.16 – 使用 prefers-color-scheme 媒体查询的暗模式视图

重要提示

有可能您已经在 `localhost:4200` 上运行了 PWA；这就是为什么在 *步骤 1* 中我们将目标端口设为 `9291`。如果甚至那个端口也被使用过，请确保清除应用程序缓存，然后刷新。

1.  让我们使用 Chrome DevTools 模拟深色和浅色模式，因为它提供了一个非常好的方法来做到这一点。打开 Chrome DevTools，然后打开“命令”菜单。在 macOS 上，键是*Cmd* + *Shift* + *P*。在 Windows 上，它是*Ctrl* + *Shift* + *P*。然后输入`Render`，并选择“显示渲染”选项，如图 13.17 所示：![图 13.17 - 使用“显示渲染”选项打开渲染视图](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.17_B15150.jpg)

图 13.17 - 使用“显示渲染”选项打开渲染视图

1.  现在，在“渲染”选项卡中，切换`prefers-color-scheme`仿真为浅色和深色模式，如图 13.18 所示：![图 13.18 - 模拟 prefers-color-scheme 模式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.18_B15150.jpg)

图 13.18 - 模拟 prefers-color-scheme 模式

1.  现在我们已经测试了两种模式。我们可以创建生产版本并重新安装 PWA。运行`ng build --configuration production`命令以在生产模式下构建应用程序。

1.  现在通过打开现有的 PWA 并从“更多”菜单中选择“卸载”选项来卸载它，如图 13.12 所示。在提示时确保勾选“同时清除 Chrome 中的数据（...）”的复选框。

1.  运行以下命令在浏览器上提供构建的应用程序，然后导航到`http://localhost:6100`：

```ts
http-server dist/pwa-dark-mode -p 6100
```

1.  等待几秒钟，直到地址栏中出现“安装”按钮。然后安装 PWA，类似于图 13.8。

1.  现在，当你运行 PWA 时，如果你的系统外观设置为深色模式，你应该看到深色模式视图，如图 13.19 所示：

![图 13.19 - 我们的 PWA 支持开箱即用的深色模式](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.19_B15150.jpg)

图 13.19 - 我们的 PWA 支持开箱即用的深色模式

太棒了！如果你将系统外观从深色模式切换到浅色模式，或者反之亦然，你应该看到 PWA 反映出适当的颜色。现在你知道如何在你的 PWA 中支持深色模式了，看看下一节，看看更多阅读的链接。

## 另请参阅

+   喜欢颜色方案（[`web.dev/prefers-color-scheme/`](https://web.dev/prefers-color-scheme/)）

+   使用 prefers-color-scheme 的颜色方案（[`web.dev/color-scheme/`](https://web.dev/color-scheme/)）

# 在你的 PWA 中提供自定义可安装体验

我们知道 PWA 是可安装的。这意味着它们可以像本机应用程序一样安装在您的设备上。然而，当您首次在浏览器中打开应用时，它完全取决于浏览器如何显示**安装**选项。这因浏览器而异。而且它也可能不太及时或清晰可见。而且，您可能希望在应用程序启动之后的某个时刻显示**安装**提示，这对一些用户来说是很烦人的。幸运的是，我们有一种方法为我们的 PWA 提供自定义的安装选项对话框/提示。这就是我们将在本节中学习的内容。

## 准备工作

本配方的项目位于`chapter13/start_here/pwa-custom-install-prompt`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng build --configuration production`。

1.  现在运行`http-server dist/pwa-custom-install-prompt -p 7200`来提供服务。

1.  导航到`http://localhost:7200`。等待一会儿，您应该会看到安装提示，如*图 13.20*所示：

![图 13.20 - pwa-custom-install-prompt 在 http://localhost:7200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.20_B15150.jpg)

图 13.20 - pwa-custom-install-prompt 在 http://localhost:7200 上运行

现在我们的应用程序正在运行，让我们在下一节中看看这个配方的步骤。

## 如何做

我们有一个名为 Dice Guesser 的应用程序，您可以在其中掷骰子并猜测结果。对于本节，我们将阻止默认的安装提示，并仅在用户猜对时显示它。让我们开始吧：

1.  首先，创建一个服务，将在接下来的步骤中显示我们的自定义可安装提示。在项目根目录中，运行以下命令：

```ts
ng g service core/services/installable-prompt
```

1.  现在打开创建的文件`installable-prompt.service.ts`，并按以下方式更新代码：

```ts
import { Injectable } from '@angular/core';
@Injectable({
  providedIn: 'root',
})
export class InstallablePromptService {
  installablePrompt;
  constructor() {
    this.init();
  }
  init() {
    window.addEventListener(
      'beforeinstallprompt',
      this.handleInstallPrompt.bind(this)
    );
  }
  handleInstallPrompt(e) {
    e.preventDefault();
    // Stash the event so it can be triggered later.
    this.installablePrompt = e;
    console.log('installable prompt event fired');
    window.removeEventListener('beforeinstallprompt',     this.handleInstallPrompt);
  }
}
```

1.  现在，让我们构建我们将向用户显示的自定义对话框/提示。我们将使用`@angular/material`包中已经安装在项目中的**Material**对话框。打开`app.module.ts`文件，并按以下方式更新它：

```ts
...
import { MatDialogModule } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
@NgModule({
  declarations: [... ],
  imports: [
    ...
    BrowserAnimationsModule,
    MatDialogModule,
    MatButtonModule,
  ],
  providers: [],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

1.  让我们为**Material**对话框创建一个组件。在项目根目录中，运行以下命令：

```ts
ng g component core/components/installable-prompt
```

1.  现在我们将在`InstallablePromptService`中使用这个组件。打开`installable-prompt.service.ts`文件，并按以下方式更新代码：

```ts
...
import { MatDialog } from '@angular/material/dialog';
import { InstallablePromptComponent } from '../components/installable-prompt/installable-prompt.component';
@Injectable({...})
export class InstallablePromptService {
  installablePrompt;
  constructor(private dialog: MatDialog) {...}
...
  async showPrompt() {
    if (!this.installablePrompt) {
      return;
    }
    const dialogRef = this.dialog.    open(InstallablePromptComponent, {
      width: '300px',
    });
  }
}
```

1.  我们还需要根据我们自定义可安装提示的选择来显示浏览器的提示。例如，如果用户点击**是**按钮，这意味着他们想将应用程序安装为 PWA。在这种情况下，我们将显示浏览器的提示。按照以下方式进一步更新`installable-prompt.service.ts`文件：

```ts
...
export class InstallablePromptService {
  ...
  async showPrompt() {

    …
    const dialogRef = this.dialog.    open(InstallablePromptComponent, {
      width: '300px',
    });
    dialogRef.afterClosed().subscribe(async (result) => {
      if (!result) {
        this.installablePrompt = null;
        return;
      }
      this.installablePrompt.prompt();
      const { outcome } = await this.installablePrompt.      userChoice;
      console.log(`User response to the install prompt:       ${outcome}`);
      this.installablePrompt = null;
    });
  }
}
```

1.  现在我们已经为浏览器的提示设置了主要代码。让我们来处理我们自定义可安装提示的模板。打开`installable-prompt.component.html`文件，并用以下代码替换模板：

```ts
<h1 mat-dialog-title>Add to Home</h1>
<div mat-dialog-content>
  <p>Enjoying the game? Would you like to install the app   on your device?</p>
</div>
<div mat-dialog-actions>
  <button mat-button [mat-dialog-close]="false">No   Thanks</button>
  <button mat-button [mat-dialog-close]="true" cdkFocusInitial>Sure</button>
</div>
```

1.  最后，每当用户猜对时，让我们显示这个提示。打开`game.component.ts`文件，并按照以下方式更新它：

```ts
...
import { InstallablePromptService } from '../core/services/installable-prompt.service';
...
@Component({...})
export class GameComponent implements OnInit {
  ...
  constructor(
    private leaderboardService: LeaderboardService,
    private instPrompt: InstallablePromptService
  ) {}
  ...
  showResult(diceSide: IDiceSide) {
    ...
    this.scores = this.leaderboardService.setScores({
      name: this.nameForm.get('name').value,
      score: 50,
    });
    this.instPrompt.showPrompt();
  }
}
```

1.  现在让我们测试应用程序。使用以下命令在生产模式下构建应用程序，并使用`http-server`包在端口`7200`上提供服务：

```ts
ng build --configuration production
http-server dist/pwa-custom-install-prompt -p 7200
```

1.  在我们测试之前，您可能想要清除应用程序的缓存并注销服务工作者。您可以通过打开 Chrome DevTools 并导航到**应用程序**选项卡来执行此操作。然后点击*图 13.21*所示的**清除站点数据**按钮。确保选中**注销服务工作者**选项：![图 13.21 - 清除站点数据，包括服务工作者](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.21_B15150.jpg)

图 13.21 - 清除站点数据，包括服务工作者

1.  现在玩游戏，直到您猜对一个答案。一旦您猜对，您将看到自定义可安装提示，如*图 13.22*所示。点击**确定**按钮，您应该会看到浏览器的提示：

![图 13.22 - 我们 PWA 的自定义可安装提示](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.22_B15150.jpg)

图 13.22 - 我们 PWA 的自定义可安装提示

太棒了！现在您可以通过安装和卸载几次 PWA 应用程序并尝试用户选择安装或不安装应用程序的所有组合来玩转应用程序。这都是有趣的游戏。现在您知道如何为 Angular PWA 实现自定义安装提示，接下来请查看下一节以了解其工作原理。

## 它是如何工作的

这个示例的核心是`beforeinstallprompt`事件。这是一个标准的浏览器事件，在最新版本的 Chrome、Firefox、Safari、Opera、UC 浏览器（Android 版本）和 Samsung Internet 中都得到支持，也就是几乎所有主要浏览器。该事件有一个`prompt()`方法，在设备上显示浏览器的默认提示。在这个示例中，我们创建了`InstallablePromptService`并将事件存储在其`local`属性中。这样我们可以在用户猜对正确的值时随需使用它。请注意，一旦我们收到`beforeinstallprompt`事件，就会从`window`对象中移除事件侦听器，这样我们只保存一次事件。这是在应用程序启动时。如果用户选择不安装应用程序，我们在同一会话中不会再次显示提示。但是，如果用户刷新应用程序，他们仍然会在第一次猜对时获得一次提示。我们可以进一步将这个状态保存在`localStorage`中，以避免在页面刷新后再次显示提示，但这不是这个示例的一部分。

对于自定义安装提示，我们使用`@angular/material`包中的`MatDialog`服务。该服务有一个`open()`方法，接受两个参数：要显示为 Material 对话框的组件和`MatDialogConfig`。在这个示例中，我们创建了`InstallablePromptComponent`，它使用了来自`@angular/material/dialog`包的一些带指令的 HTML 元素。请注意，在按钮上，我们在`installable-prompt.component.html`文件中使用了属性`[mat-dialog-close]`。值分别设置为`true`和`false`，用于**确定**和**不，谢谢**按钮。这些属性帮助我们将相应的值从此模态发送到`InstallablePromptService`。请注意在`installable-prompt.service.ts`文件中使用了`dialogRef.afterClosed().subscribe()`。这是值被传递回去的地方。如果值为`true`，那么我们使用事件，也就是`this.installablePrompt`属性的`.prompt()`方法来显示浏览器的提示。请注意，在使用后我们将`installablePrompt`属性的值设置为`null`。这样我们在同一会话中不会再次显示提示，直到用户刷新页面。

现在您了解了所有的工作原理，可以查看下一节以获取进一步阅读的链接。

## 另请参阅

+   Angular Material 对话框示例（https://material.angular.io/components/dialog/examples）

+   MatDialogConfig (https://material.angular.io/components/dialog/api#MatDialogConfig)

+   如何提供自己的应用安装体验（web.dev）(https://web.dev/customize-install/)

# 使用 Angular 服务工作者预缓存请求

在我们之前的示例中添加了服务工作者，我们已经看到它们已经缓存了资产，并在**离线**模式下使用服务工作者提供它们。但是网络请求呢？如果用户离线并立即刷新应用程序，网络请求将失败，因为它们没有与服务工作者一起缓存。这导致了破碎的离线用户体验。在这个示例中，我们将配置服务工作者来预缓存网络请求，以便应用程序在**离线**模式下也能流畅运行。

## 准备工作

我们要处理的项目位于克隆存储库中的`chapter13/start_here/precaching-requests`中：

1.  在 Visual Studio Code 中打开项目。

1.  完成后，运行`ng build --configuration production`。

1.  现在运行`http-server dist/precaching-requests -p 8300`来提供服务。

1.  导航到`http://localhost:8300`。刷新应用程序一次。然后按照*图 13.2*所示切换到**离线**模式。如果您转到**网络**选项卡并使用查询`results`过滤请求，您应该看到请求失败，如*图 13.23*所示：

![图 13.23 - 由于未缓存网络请求而导致的离线体验破碎](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.23_B15150.jpg)

图 13.23 - 由于未缓存网络请求而导致的离线体验破碎

现在我们看到网络请求失败了，让我们在下一节中看看修复这个问题的步骤。

## 如何做

对于这个示例，我们有用户列表和搜索应用程序，从 API 端点获取一些用户。正如您在*图 13.23*中所看到的，如果我们进入**离线**模式，`fetch`调用以及对服务工作者的请求也会失败。这是因为服务工作者尚未配置为缓存数据请求。让我们开始修复这个问题的示例：

1.  为了缓存网络请求，打开`ngsw-config.json`文件并进行如下更新：

```ts
{
  "$schema": "./node_modules/@angular/service-worker/  config/schema.json",
  "index": "/index.html",
  "assetGroups": [...],
  "dataGroups": [
    {
      "name": "api_randomuser.me",
      "urls": ["https://api.randomuser.me/?results*"],
      "cacheConfig": {
        "strategy": "freshness",
        "maxSize": 100,
        "maxAge": "2d"
      }
    }
  ]
};
```

1.  现在让我们测试一下应用程序。使用以下命令以生产模式构建应用程序，并使用`http-server`包在端口`8300`上提供服务：

```ts
ng build --configuration production
http-server dist/precaching-requests -p 8300
```

1.  现在导航到 http://localhost:8300\. 确保此时没有使用**网络限速**。也就是说，你没有处于**离线**模式。

1.  使用 Chrome DevTools 清除应用程序数据，如*图 13.21*所示。完成后，刷新应用程序页面。

1.  在 Chrome DevTools 中，转到**网络**选项卡，并切换到**离线**模式，如*图 13.2*所示。现在使用查询`results`过滤网络请求。即使处于离线状态，您也应该看到结果。网络调用是由 service worker 提供的，如*图 13.24*所示：

![图 13.24 – 使用 service worker 离线工作的网络调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.24_B15150.jpg)

图 13.24 – 使用 service worker 离线工作的网络调用

哇！即使现在点击一个卡片，您仍然应该看到应用程序无缝运行，因为所有页面都使用相同的 API 调用，因此由 service worker 提供。通过这样，您刚刚学会了如何在 Angular 应用程序中配置 service worker 以缓存网络/数据请求。即使离线，您也可以安装 PWA 并使用它。很棒，对吧？

现在我们已经完成了这个教程，让我们在下一节中看看它是如何工作的。

## 工作原理

这个教程的核心是`ngsw-config.json`文件。当使用`@angular/service-worker`包生成 service worker 文件时，该文件将被`@angular/pwa`原理图使用时，该文件已经包含一个 JSON 对象。该 JSON 包含一个名为`assetGroups`的属性，基本上根据提供的配置来配置资产的缓存。对于这个教程，我们希望缓存网络请求以及资产。因此，我们在 JSON 对象中添加了新属性`dataGroups`。让我们看看配置：

```ts
"dataGroups": [
    {
      "name": "api_randomuser.me",
      "urls": ["https://api.randomuser.me/?results*"],
      "cacheConfig": {
        "strategy": "freshness",
        "maxSize": 100,
        "maxAge": "2d"
      }
    }
  ]
```

如您所见，`dataGroups` 是一个数组。我们可以将不同的配置对象作为其元素提供。每个配置都有一个`name`，一个`urls`数组，以及定义缓存策略的`cacheConfig`。对于我们的配置，我们使用了 API URL 的通配符，也就是说，我们使用了`urls: ["https://api.randomuser.me/?results*"]`。对于`cacheConfig`，我们使用了`"freshness"`策略，这意味着应用程序将始终首先从其原始位置获取数据。如果网络不可用，那么它将使用来自服务工作器缓存的响应。另一种策略是`"performance"`，它首先查找服务工作器以获取缓存的响应。如果缓存中没有特定 URL（或 URL）的内容，那么它将从实际原始位置获取数据。`maxSize`属性定义了可以为相同模式（或一组 URL）缓存多少个请求。`maxAge`属性定义了缓存数据在服务工作器缓存中存活多长时间。

现在您知道这个示例是如何工作的，请参阅下一节以获取进一步阅读的链接。

## 另请参阅

+   Angular Service Worker Intro (https://angular.io/guide/service-worker-intro)

+   Angular Service Worker Config (https://angular.io/guide/service-worker-config)

+   创建离线回退页面 (web.dev) (https://web.dev/offline-fallback-page/)

# 为您的 PWA 创建一个应用外壳

在构建 Web 应用程序的快速用户体验时，最大的挑战之一是最小化关键渲染路径。这包括加载目标页面的最关键资源，解析和执行 JavaScript 等。通过应用外壳，我们有能力在构建时而不是运行时渲染页面或应用的一部分。这意味着用户最初将看到预渲染的内容，直到 JavaScript 和 Angular 开始运行。这意味着浏览器不必为了第一个有意义的绘制而工作和等待一段时间。在这个示例中，您将为 Angular PWA 创建一个应用外壳。

## 准备就绪

我们要处理的项目位于克隆存储库内的`chapter13/start_here/pwa-app-shell`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该打开一个选项卡，并在`http://localhost:4200`上运行应用程序，如*图 13.25*所示：

![图 13.25 - 在 http://localhost:4200 上运行的 pwa-app-shell](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.25_B15150.jpg)

图 13.25 - pwa-app-shell 运行在 http://localhost:4200

现在我们将禁用 JavaScript 以模拟解析 JavaScript 需要很长时间。或者，模拟尚未放置 App Shell。打开 Chrome DevTools 并打开命令面板。在 macOS X 上的快捷键是*Cmd* + *Shift* + *P*，在 Windows 上是*Ctrl* + *Shift* + *P*。输入`Disable JavaScript`，选择该选项，然后按*Enter*。您应该看到以下消息：

![图 13.26 - 应用程序中没有 App Shell](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.26_B15150.jpg)

图 13.26 - 应用程序中没有 App Shell

现在我们已经检查了 App Shell 的缺失，让我们在下一节中看到该配方的步骤。

## 如何操作

我们有一个从 API 获取一些用户的 Angular 应用程序。我们将为此应用程序创建一个 App Shell，以便作为 PWA 更快地提供第一个有意义的绘制。让我们开始吧：

1.  首先，通过从项目根目录运行以下命令为应用程序创建 App Shell：

```ts
ng generate app-shell
```

1.  更新`app.module.ts`以导出组件，以便我们可以使用它们在 App Shell 中呈现**Users**页面。代码应如下所示：

```ts
...
@NgModule({
  declarations: [...],
  imports: [... ],
  providers: [],
  exports: [
    UsersComponent,
    UserCardComponent,
    UserDetailComponent,
    AppFooterComponent,
    LoaderComponent,
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

1.  现在打开`app-shell.component.html`文件，并使用`<app-users>`元素，以便在 App Shell 中呈现整个`UsersComponent`。代码应如下所示：

```ts
<app-users></app-users>
```

1.  现在我们已经为 App Shell 编写了代码。让我们创建它。运行以下命令以在开发模式下生成 App Shell：

```ts
ng run pwa-app-shell:app-shell
```

1.  一旦在*步骤 4*中生成了 App Shell，请运行以下命令使用`http-server`包来提供它：

```ts
http-server dist/pwa-app-shell/browser -p 4200
```

1.  确保应用程序的 JavaScript 仍然关闭。如果没有，请打开 Chrome DevTools，按下 macOS X 上的*Cmd* + *Shift* + *P*以打开命令面板（Windows 上的*Ctrl* + *Shift* + *P*）。然后输入`Disable Javascript`，按*Enter*选择如*图 13.27*所示的选项：![图 13.27 - 使用 Chrome DevTools 禁用 JavaScript](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.27_B15150.jpg)

图 13.27 - 使用 Chrome DevTools 禁用 JavaScript

1.  在禁用 JavaScript 的情况下刷新应用程序。现在，尽管 JavaScript 被禁用，您应该看到应用程序仍然显示了预渲染的用户页面，如*图 13.28*所示。哇哦！![图 13.28 - App Shell 显示了预渲染的用户页面](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.28_B15150.jpg)

图 13.28 - App Shell 显示了预渲染的用户页面

1.  要验证我们是否在构建时预渲染了用户页面，请检查`<project-root>/dist/pwa-app-shell/browser.index.html`中生成的代码。您应该在`<body>`标签内看到整个渲染的页面，如*图 13.29*所示：![图 13.29 - 包含预渲染用户页面的 index.html 文件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.29_B15150.jpg)

图 13.29 - 包含预渲染用户页面的 index.html 文件

1.  通过运行以下命令创建带有 App Shell 的生产构建，并在端口`1020`上提供服务：

```ts
ng run pwa-app-shell:app-shell:production
http-server dist/pwa-app-shell/browser -p 1020
```

1.  在浏览器中导航到`http://localhost:1020`，并按照*图 13.8*所示安装应用程序作为 PWA。完成后，运行 PWA，它应该如下所示：

![图 13.30 - 安装后作为本机应用程序运行的 pwa-app-shell](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_13.30_B15150.jpg)

图 13.30 - 安装后作为本机应用程序运行的 pwa-app-shell

太棒了！现在你知道如何为你的 Angular PWA 创建一个 App Shell。现在您已经完成了这个食谱，请查看下一节关于它是如何工作的。

## 它是如何工作的

该食谱始于为我们的应用程序禁用 JavaScript。这意味着当应用程序运行时，我们只显示静态的 HTML 和 CSS，因为没有 JavaScript 执行。我们看到一个关于不支持 JavaScript 的消息，如*图 13.26*所示。

然后我们运行`ng generate app-shell`命令。这个 Angular CLI 命令为我们做了以下几件事情：

+   创建一个名为`AppShellComponent`的新组件，并生成其相关文件。

+   在项目中安装了`@angular/platform-server`包。

+   更新`app.module.ts`文件以使用`BrowserModule.withServerTransition()`方法，这样我们就可以为服务器端渲染提供`appId`属性。

+   添加了一些新文件，即`main.server.ts`和`app.server.module.ts`，以启用服务器端渲染（确切地说是我们的 App Shell 的构建时渲染）。

+   最重要的是，它更新了`angular.json`文件，添加了一堆用于服务器端渲染的原理图，以及用于生成`app-shell`的原理图。

在这个食谱中，我们从`AppModule`中导出组件，这样我们就可以在应用外壳中使用它们。这是因为应用外壳不是`AppModule`的一部分。相反，它是在`app.server.module.ts`文件中新创建的`AppServerModule`的一部分。正如您所看到的，在这个文件中，我们已经导入了`AppModule`。尽管如此，除非我们从`AppModule`中导出它们，否则我们无法使用这些组件。在导出组件之后，我们更新了`app-shell.component.html`（应用外壳模板），以使用`<app-users>`选择器，这反映了`UsersComponent`类。这就是整个用户页面。

我们通过运行`ng run pwa-app-shell:app-shell`命令来验证应用外壳。这个命令会生成一个带有应用外壳（非最小化代码）的开发模式下的 Angular 构建。请注意，在通常的构建中，我们会在`dist`文件夹内生成`pwa-app-shell`文件夹。在这个文件夹内，我们会有`index.html`。然而，在这种情况下，我们在`pwa-app-shell`文件夹内创建了两个文件夹，即`browser`文件夹和`server`文件夹。我们的`index.html`位于`browser`文件夹内。如*图 13.29*所示，我们在`index.html`文件的`<body>`标签内有整个用户页面的代码。这段代码是在构建时预渲染的。这意味着 Angular 打开应用程序，进行网络调用，然后在构建时将 UI 预渲染为应用外壳。因此，一旦应用程序打开，内容就会被预渲染。

要生成带有应用外壳的生产构建，我们运行`ng run pwa-app-shell:app-shell:production`命令。这将生成带有应用外壳的生产 Angular 构建，并进行了最小化处理。最后，我们安装 PWA 进行测试。

现在您知道了这个食谱是如何工作的，请查看下一节以获取进一步阅读的链接。

## 参见

+   Angular 应用外壳指南（https://angular.io/guide/app-shell）

+   应用外壳模型（Google 的 Web 基础知识）（https://developers.google.com/web/fundamentals/architecture/app-shell）
